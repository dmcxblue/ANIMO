#include "ClientTransport.h"
#include "../../shared/Protocol.h"
#include "../../shared/TransportTls.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QJsonParseError>   // ← needed for QJsonParseError
#include <QEventLoop>
#include <QSettings>
#include <QSslCertificate>
#include <QTimer>
#include <QDebug>

ClientTransport::ClientTransport(QObject *parent)
    : QObject(parent),
      socket_(new QSslSocket(this)),
      m_autoReconnect(false),
      m_maxReconnectAttempts(5),
      m_reconnectDelayMs(3000),
      m_reconnectAttempts(0),
      m_reconnectTimer(new QTimer(this)),
      m_lastPort(0),
      m_wasAuthenticated(false)
{
    // Make this instance globally discoverable by name
    if (objectName().isEmpty())
        setObjectName(QStringLiteral("ClientTransport"));

    // "connected" means TCP only. Everything the client considers a live
    // connection hangs off "encrypted", so no protocol byte can precede the
    // TLS handshake.
    connect(socket_, &QSslSocket::encrypted,
            this, &ClientTransport::onSocketEncrypted);
    connect(socket_, &QSslSocket::sslErrors,
            this, &ClientTransport::onSslErrors);
    connect(socket_, &QTcpSocket::disconnected,
            this, &ClientTransport::onSocketDisconnected);
    connect(socket_, &QTcpSocket::readyRead,
            this, &ClientTransport::onSocketReadyRead);

#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    connect(socket_, &QTcpSocket::errorOccurred,
            this, &ClientTransport::onSocketErrorOccurred);
#else
    connect(socket_,
            QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::error),
            this, &ClientTransport::onSocketErrorOccurred);
#endif

    // Setup reconnection timer
    m_reconnectTimer->setSingleShot(true);
    connect(m_reconnectTimer, &QTimer::timeout, this, &ClientTransport::attemptReconnect);
}

ClientTransport::~ClientTransport() {
    // Scrub sensitive data from memory
    if (!m_lastPassword.isEmpty()) {
        m_lastPassword.fill(QChar(0));
        m_lastPassword.clear();
    }
    if (socket_->isOpen()) socket_->close();
}

QString ClientTransport::pinSettingsKey(const QString &host, quint16 port) {
    return QString("tls/pins/%1:%2").arg(host).arg(port);
}

QString ClientTransport::storedPin(const QString &host, quint16 port) {
    QSettings settings("ANIMO", "Client");
    return settings.value(pinSettingsKey(host, port)).toString();
}

void ClientTransport::trustPresentedCertificate() {
    if (presentedFingerprint_.isEmpty() || m_lastHost.isEmpty()) return;
    QSettings settings("ANIMO", "Client");
    settings.setValue(pinSettingsKey(m_lastHost, m_lastPort), presentedFingerprint_);
    expectedPin_ = presentedFingerprint_;
}

void ClientTransport::beginTlsAttempt(const QString &host, quint16 port) {
    tlsStatus_            = TlsStatus::NotAttempted;
    tlsErrorText_.clear();
    presentedFingerprint_.clear();
    presentedSubject_.clear();
    presentedValidity_.clear();
    expectedPin_ = storedPin(host, port);
    socket_->setSslConfiguration(TransportTls::clientConfiguration());
}

void ClientTransport::connectToServer(const QString &host, quint16 port) {
    // Save connection details for auto-reconnect
    m_lastHost = host;
    m_lastPort = port;
    m_wasAuthenticated = false;

    // Avoid "connectToHost when already connecting/connected"
    if (socket_->state() != QAbstractSocket::UnconnectedState) {
        socket_->abort(); // immediately close any pending/active connection
    }
    beginTlsAttempt(host, port);
    socket_->connectToHostEncrypted(host, port);
}

void ClientTransport::onSslErrors(const QList<QSslError> &errors) {
    const QSslCertificate cert = socket_->peerCertificate();
    presentedFingerprint_ = TransportTls::fingerprintSha256(cert);
    presentedSubject_     = cert.subjectDisplayName();
    presentedValidity_    = QString("%1 - %2")
        .arg(cert.effectiveDate().toString(Qt::ISODate),
             cert.expiryDate().toString(Qt::ISODate));

    // A fault the pin cannot excuse (expired, revoked, bad signature) fails
    // closed no matter what the operator trusted before.
    if (!TransportTls::isSelfSignedErrorSet(errors)) {
        tlsStatus_ = TlsStatus::CertRejected;
        QStringList reasons;
        for (const QSslError &e : errors) reasons << e.errorString();
        tlsErrorText_ = QString("Server certificate rejected: %1").arg(reasons.join("; "));
        emit tlsError(tlsErrorText_);
        return; // do NOT ignore - handshake aborts
    }

    if (TransportTls::fingerprintMatches(cert, expectedPin_)) {
        tlsStatus_ = TlsStatus::Ok;
        // Pass the explicit list: the argument-less overload would whitelist
        // every future error on this socket too.
        socket_->ignoreSslErrors(errors);
        return;
    }

    if (expectedPin_.isEmpty()) {
        tlsStatus_    = TlsStatus::PinUnknown;
        tlsErrorText_ = QString("Unrecognised server certificate (%1)").arg(presentedFingerprint_);
    } else {
        tlsStatus_    = TlsStatus::PinMismatch;
        tlsErrorText_ = QString(
            "Server certificate does not match the pinned one for %1:%2.\n"
            "Expected: %3\nPresented: %4")
            .arg(m_lastHost).arg(m_lastPort).arg(expectedPin_, presentedFingerprint_);
    }
    emit tlsError(tlsErrorText_);
    // Not ignoring the errors aborts the handshake: fail closed.
}

void ClientTransport::disconnectFromServer() {
    if (socket_->state() != QAbstractSocket::UnconnectedState) {
        socket_->disconnectFromHost();
        if (socket_->state() != QAbstractSocket::UnconnectedState)
            socket_->abort();
    }
}

void ClientTransport::sendJson(const QJsonObject &obj) {
    QJsonDocument d(obj);
    QByteArray bytes = d.toJson(QJsonDocument::Compact);
    bytes.append('\n'); // line-delimited protocol
    // isEncrypted(), not ConnectedState: a TLS socket reaches ConnectedState
    // while the handshake is still running, and nothing - least of all the
    // login password - may be handed to the socket before that completes.
    if (socket_->isEncrypted()) {
        socket_->write(bytes);
        socket_->flush();
    } else {
        qWarning() << "[ClientTransport] Dropped message: channel not encrypted";
    }
}

bool ClientTransport::connectAndLogin(const QString &host, quint16 port,
                                      const QString &username, const QString &password,
                                      int timeoutMs) {
    // Save connection details for auto-reconnect
    m_lastHost = host;
    m_lastPort = port;
    m_lastUsername = username;
    m_lastPassword = password;

    // Ensure socket is not already connecting/connected
    if (socket_->state() != QAbstractSocket::UnconnectedState) {
        socket_->abort();  // immediately close any ongoing or active connection
    }

    QEventLoop loop;
    bool authResult = false;
    bool gotResponse = false;

    // Temporary connections for auth signals
    QMetaObject::Connection c1 = connect(this, &ClientTransport::authSucceeded, &loop, [&](){
        authResult = true;
        gotResponse = true;
        m_wasAuthenticated = true;
        loop.quit();
    });
    QMetaObject::Connection c2 = connect(this, &ClientTransport::authFailed, &loop, [&](const QString &){
        authResult = false;
        gotResponse = true;
        loop.quit();
    });

    // Attempt to connect. Waiting on "encrypted" rather than "connected" is
    // what makes the password wait for the TLS handshake.
    beginTlsAttempt(host, port);
    socket_->connectToHostEncrypted(host, port);
    if (!socket_->waitForEncrypted(qMax(timeoutMs, 5000))) {
        if (tlsStatus_ == TlsStatus::NotAttempted)
            tlsStatus_ = TlsStatus::HandshakeFailed;
        if (tlsErrorText_.isEmpty())
            tlsErrorText_ = QString("TLS handshake failed: %1").arg(socket_->errorString());
        socket_->abort();
        emit errorOccurred(tlsErrorText_);
        // cleanup temp connections
        disconnect(c1);
        disconnect(c2);
        return false;
    }

    // Send login JSON with the operator identity used for attribution.
    QJsonObject loginObj;
    loginObj.insert(Protocol::F_ACTION,   Protocol::ACTION_LOGIN);
    loginObj.insert(Protocol::F_USERNAME, username);
    loginObj.insert(Protocol::F_PASSWORD, password);
    sendJson(loginObj);

    // Timer for login timeout
    QTimer timer;
    timer.setSingleShot(true);
    connect(&timer, &QTimer::timeout, &loop, [&]() { loop.quit(); });
    timer.start(timeoutMs);

    // Wait until login response or timeout
    loop.exec();

    // cleanup temp connections
    disconnect(c1);
    disconnect(c2);

    if (gotResponse) {
        return authResult;
    } else {
        emit errorOccurred("Login timed out");
        return false;
    }
}

void ClientTransport::onSocketEncrypted() {
    tlsStatus_ = TlsStatus::Ok;
    // Reset reconnection counter on successful connection
    resetReconnection();
    emit connected();
}

void ClientTransport::onSocketDisconnected() {
    emit disconnected();

    // Trigger auto-reconnect if enabled
    if (m_autoReconnect && !m_lastHost.isEmpty()) {
        qDebug() << "[ClientTransport] Connection lost. Starting reconnection timer...";
        m_reconnectAttempts = 0;
        m_reconnectTimer->start(m_reconnectDelayMs);
    }
}

void ClientTransport::onSocketReadyRead() {
    readBuffer_.append(socket_->readAll());

    // Parse as many newline-terminated JSON messages as possible
    while (true) {
        QJsonObject msg;
        if (!tryParseMessage(msg)) break;

        // Map ok/err to auth or generic message
        QString status;
        if (msg.contains(Protocol::F_STATUS)) {
            status = msg.value(Protocol::F_STATUS).toString();
        }

        if (status == Protocol::STATUS_OK) {
            const QString m = msg.value(Protocol::F_MESSAGE).toString().toLower();
            if (m.contains("login")) {
                emit authSucceeded();
            } else {
                emit messageReceived(msg);
            }
        } else if (status == Protocol::STATUS_ERR) {
            const QString m = msg.value(Protocol::F_MESSAGE).toString().toLower();
            if (m.contains("invalid") || m.contains("auth") || m.contains("login")) {
                emit authFailed(msg.value(Protocol::F_MESSAGE).toString());
            } else {
                emit messageReceived(msg);
            }
        } else {
            // No status field - treat as generic message
            emit messageReceived(msg);
        }
    }
}

void ClientTransport::onSocketErrorOccurred(QAbstractSocket::SocketError socketError) {
    Q_UNUSED(socketError);
    // Prefer the trust-level explanation when there is one: "certificate does
    // not match the pinned one" is far more actionable than "SSL handshake
    // failed" for the operator staring at the dialog.
    emit errorOccurred(tlsErrorText_.isEmpty() ? socket_->errorString() : tlsErrorText_);
}

bool ClientTransport::tryParseMessage(QJsonObject &out) {
    // find newline
    int idx = readBuffer_.indexOf('\n');
    if (idx == -1) return false;

    QByteArray line = readBuffer_.left(idx).trimmed();
    readBuffer_.remove(0, idx + 1);

    if (line.isEmpty()) return false;

    QJsonParseError pe;
    QJsonDocument d = QJsonDocument::fromJson(line, &pe);
    if (pe.error != QJsonParseError::NoError || !d.isObject()) {
        qWarning() << "ClientTransport: invalid json from server:" << line;
        return false;
    }
    out = d.object();
    return true;
}

// ===== Auto-Reconnect Implementation =====

void ClientTransport::enableAutoReconnect(bool enable) {
    m_autoReconnect = enable;
    if (!enable) {
        m_reconnectTimer->stop();
        resetReconnection();
    }
}

void ClientTransport::setMaxReconnectAttempts(int maxAttempts) {
    m_maxReconnectAttempts = maxAttempts;
}

void ClientTransport::setReconnectDelay(int delayMs) {
    m_reconnectDelayMs = delayMs;
}

bool ClientTransport::isConnected() const {
    // Only an encrypted channel counts as connected.
    return socket_->isEncrypted();
}

void ClientTransport::attemptReconnect() {
    if (!m_autoReconnect || m_lastHost.isEmpty()) {
        return;
    }

    m_reconnectAttempts++;

    if (m_reconnectAttempts > m_maxReconnectAttempts) {
        qWarning() << "[ClientTransport] Max reconnection attempts reached. Giving up.";
        emit reconnectFailed();
        resetReconnection();
        return;
    }

    qDebug() << "[ClientTransport] Attempting to reconnect"
             << m_reconnectAttempts << "/" << m_maxReconnectAttempts;
    emit reconnecting(m_reconnectAttempts, m_maxReconnectAttempts);

    // Attempt reconnection
    if (m_wasAuthenticated && !m_lastPassword.isEmpty()) {
        // Use authenticated reconnection
        bool success = connectAndLogin(m_lastHost, m_lastPort, m_lastUsername, m_lastPassword, 5000);

        // Trust failures are never retried and never prompt: reconnect runs
        // unattended, so a rotated or spoofed certificate must stop the loop
        // instead of producing one dialog per attempt.
        if (!success && (tlsStatus_ == TlsStatus::PinMismatch ||
                         tlsStatus_ == TlsStatus::PinUnknown  ||
                         tlsStatus_ == TlsStatus::CertRejected)) {
            qWarning() << "[ClientTransport] Reconnect aborted on TLS trust failure:"
                       << tlsErrorText_;
            emit tlsError(tlsErrorText_);
            emit reconnectFailed();
            resetReconnection();
            return;
        }

        if (!success) {
            // Exponential backoff: delay * attempts
            int delay = m_reconnectDelayMs * m_reconnectAttempts;
            qDebug() << "[ClientTransport] Reconnection failed. Retrying in" << delay << "ms";
            m_reconnectTimer->start(delay);
        }
    } else {
        // Simple reconnection without auth
        connectToServer(m_lastHost, m_lastPort);
    }
}

void ClientTransport::resetReconnection() {
    m_reconnectAttempts = 0;
    m_reconnectTimer->stop();
}
