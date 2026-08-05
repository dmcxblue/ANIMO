#pragma once

#include <QObject>
#include <QSslError>
#include <QSslSocket>
#include <QTcpSocket>
#include <QHostAddress>
#include <QJsonObject>
#include <QTimer>

class ClientTransport : public QObject {
    Q_OBJECT
public:
    // Outcome of the TLS handshake, so callers can tell "wrong password" apart
    // from "this is not the server you trusted".
    enum class TlsStatus {
        Ok,             // handshake completed and the pin matched
        NotAttempted,   // no connection attempt yet
        PinUnknown,     // no pin stored for this host:port - operator must confirm
        PinMismatch,    // a pin exists and the server presented a different cert
        CertRejected,   // certificate fault beyond self-signed (expired, revoked, ...)
        HandshakeFailed // transport-level failure: wrong port, plaintext peer, ...
    };
    Q_ENUM(TlsStatus)

    explicit ClientTransport(QObject *parent = nullptr);
    ~ClientTransport();

    // Connect and perform login with the operator username + password (blocking helper).
    bool connectAndLogin(const QString &host, quint16 port,
                         const QString &username, const QString &password,
                         int timeoutMs = 5000);

    // ── TLS trust ───────────────────────────────────────────────────────────
    // Why the last attempt ended the way it did.
    TlsStatus lastTlsStatus() const { return tlsStatus_; }
    QString lastTlsError() const { return tlsErrorText_; }

    // Details of the certificate the server presented on the last attempt,
    // for the trust prompt. Empty if no certificate was received.
    QString presentedFingerprint() const { return presentedFingerprint_; }
    QString presentedSubject() const { return presentedSubject_; }
    QString presentedValidity() const { return presentedValidity_; }

    // Pin the certificate from the last attempt to the last host:port, so
    // subsequent connections (including auto-reconnect) accept it silently.
    // Only ever call this after the operator has confirmed the fingerprint.
    void trustPresentedCertificate();

    // Fingerprint currently pinned for a host:port, empty when untrusted.
    static QString storedPin(const QString &host, quint16 port);

    // Existing API preserved
    void connectToServer(const QString &host, quint16 port);
    void disconnectFromServer();

    // Make this invokable so QMetaObject::invokeMethod("sendJson", ...) works
    Q_INVOKABLE void sendJson(const QJsonObject &obj);

    // Auto-reconnect configuration
    void enableAutoReconnect(bool enable);
    void setMaxReconnectAttempts(int maxAttempts);
    void setReconnectDelay(int delayMs);

    // Connection state
    bool isConnected() const;

signals:
    void connected();
    void disconnected();
    void authSucceeded();
    void authFailed(const QString &reason);
    void messageReceived(const QJsonObject &obj);
    void errorOccurred(const QString &err);
    void reconnecting(int attempt, int maxAttempts);
    void reconnectFailed();
    // Emitted when a connection is refused on trust grounds rather than
    // credentials - notably on the auto-reconnect path, which must never
    // prompt and always fails closed.
    void tlsError(const QString &message);

private slots:
    void onSocketEncrypted();
    void onSocketDisconnected();
    void onSocketReadyRead();
    void onSocketErrorOccurred(QAbstractSocket::SocketError socketError);
    void onSslErrors(const QList<QSslError> &errors);
    void attemptReconnect();

private:
    QSslSocket *socket_;
    QByteArray readBuffer_;

    // TLS trust state for the current/last attempt
    TlsStatus tlsStatus_ = TlsStatus::NotAttempted;
    QString tlsErrorText_;
    QString expectedPin_;          // pin loaded for the target host:port
    QString presentedFingerprint_;
    QString presentedSubject_;
    QString presentedValidity_;

    // Reset per-attempt TLS state and load the pin for host:port.
    void beginTlsAttempt(const QString &host, quint16 port);
    static QString pinSettingsKey(const QString &host, quint16 port);

    // Auto-reconnect members
    bool m_autoReconnect;
    int m_maxReconnectAttempts;
    int m_reconnectDelayMs;
    int m_reconnectAttempts;
    QTimer *m_reconnectTimer;
    QString m_lastHost;
    quint16 m_lastPort;
    QString m_lastUsername;
    QString m_lastPassword;
    bool m_wasAuthenticated;

    // parse a single newline-terminated JSON message from buffer; returns true if parsed
    bool tryParseMessage(QJsonObject &out);
    void resetReconnection();
};
