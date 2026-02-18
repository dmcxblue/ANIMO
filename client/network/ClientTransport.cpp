#include "ClientTransport.h"
#include "../../shared/Protocol.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>   // ← needed for QJsonParseError
#include <QEventLoop>
#include <QTimer>
#include <QDebug>

ClientTransport::ClientTransport(QObject *parent)
    : QObject(parent),
      socket_(new QTcpSocket(this)),
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

    connect(socket_, &QTcpSocket::connected,
            this, &ClientTransport::onSocketConnected);
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

void ClientTransport::connectToServer(const QString &host, quint16 port) {
    // Save connection details for auto-reconnect
    m_lastHost = host;
    m_lastPort = port;
    m_wasAuthenticated = false;

    // Avoid "connectToHost when already connecting/connected"
    if (socket_->state() != QAbstractSocket::UnconnectedState) {
        socket_->abort(); // immediately close any pending/active connection
    }
    socket_->connectToHost(host, port);
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
    if (socket_->state() == QAbstractSocket::ConnectedState) {
        socket_->write(bytes);
        socket_->flush();
    }
}

bool ClientTransport::connectAndLogin(const QString &host, quint16 port,
                                      const QString &password, int timeoutMs) {
    // Save connection details for auto-reconnect
    m_lastHost = host;
    m_lastPort = port;
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

    // Attempt to connect
    socket_->connectToHost(host, port);
    if (!socket_->waitForConnected(3000)) {
        emit errorOccurred(QString("Failed to connect: %1").arg(socket_->errorString()));
        // cleanup temp connections
        disconnect(c1);
        disconnect(c2);
        return false;
    }

    // Send login JSON (username ignored by server, only password matters)
    QJsonObject loginObj;
    loginObj.insert(Protocol::F_ACTION,   Protocol::ACTION_LOGIN);
    loginObj.insert(Protocol::F_USERNAME, QString("any"));
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

void ClientTransport::onSocketConnected() {
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
            // No status field — treat as generic message
            emit messageReceived(msg);
        }
    }
}

void ClientTransport::onSocketErrorOccurred(QAbstractSocket::SocketError socketError) {
    Q_UNUSED(socketError);
    emit errorOccurred(socket_->errorString());
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
    return socket_->state() == QAbstractSocket::ConnectedState;
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
        bool success = connectAndLogin(m_lastHost, m_lastPort, m_lastPassword, 5000);
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
