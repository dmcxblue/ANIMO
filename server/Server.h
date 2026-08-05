#pragma once
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSslConfiguration>
#include <QSet>
#include <QHash>
#include <QJsonObject>
#include <QString>
#include <QDir>
#include <QRegularExpression>

#include <functional>

// QTcpServer that hands the raw descriptor to a callback instead of queueing a
// plain QTcpSocket, so accepted connections can be promoted to QSslSocket.
// Intentionally has no Q_OBJECT: it declares no signals or slots, which keeps
// it out of the explicit source list in server/CMakeLists.txt.
class DescriptorTcpServer : public QTcpServer {
public:
    using QTcpServer::QTcpServer;
    std::function<void(qintptr)> onDescriptor;

protected:
    void incomingConnection(qintptr socketDescriptor) override {
        if (onDescriptor) onDescriptor(socketDescriptor);
    }
};

// Server owns all session lifecycle, PowerShell processes, and DB state.
// Clients send JSON actions; server replies + pushes async events.
class Server : public QObject {
    Q_OBJECT
public:
    explicit Server(const QString &bindIp,
                    quint16 port,
                    const QString &user,
                    const QString &pass,
                    QObject *parent = nullptr);

    // Start listening; also used to perform one-time DB init in .cpp
    bool start();

    // Update auth credential (simple shared-secret login)
    void setLoginCredential(const QString &user, const QString &pass);

    // TLS is mandatory: there is no plaintext listener. Point these at custom
    // material to override the self-signed pair ANIMO generates on first start.
    // Must be called before start().
    void setTlsPaths(const QString &certPath, const QString &keyPath);

    // SHA-256 pin of the certificate this server presents.
    QString tlsFingerprint() const { return tlsFingerprint_; }

signals:
    // Append human-friendly log lines to a UI/console
    void log(const QString &line);

private slots:
    // TCP plumbing
    void onClientReady();
    void onClientDisconnected();

private:
    // Accept path: promote the descriptor to a (TLS) socket.
    void onIncomingDescriptor(qintptr socketDescriptor);

    // Wire a socket into the protocol handlers. Called once the connection is
    // usable: after the TLS handshake completes, or immediately in plain mode.
    void registerClient(QTcpSocket *sock);

    // Load or generate cert/key and build the server SSL configuration.
    bool initTls();

    // Route a single JSON line; returns true if handled/formatted
    bool handleLine(QTcpSocket *sock, const QByteArray &line);

    // Simple password auth gate for this connection
    bool handleLogin(QTcpSocket *sock, const QJsonObject &obj);

    // Constant-time string comparison to prevent timing attacks
    static bool constantTimeCompare(const QString &a, const QString &b);

    // Listener + connected sockets
    DescriptorTcpServer tcp_;
    QSet<QTcpSocket*> clients_;
    QSet<QTcpSocket*> authed_; // sockets that passed login
    QHash<QTcpSocket*, QString> operatorBySocket_; // authed socket -> operator handle (for attribution)

    // Bind + auth config
    QString bindIp_;
    quint16 port_;
    QString allowedUser_;
    QString allowedPass_;

    // TLS transport state
    QString tlsCertPath_;
    QString tlsKeyPath_;
    QString tlsFingerprint_;
    QSslConfiguration tlsConfig_;

    // Login rate limiting per IP
    struct LoginAttempt {
        int failCount = 0;
        qint64 lastAttemptMs = 0;
        qint64 lockoutUntilMs = 0;
    };
    QHash<QString, LoginAttempt> loginAttempts_;

    // Server limits
    static constexpr int MAX_SESSIONS = 100;
    static constexpr int MAX_CMD_LENGTH = 100000; // 100KB
    static constexpr int MAX_LOGIN_FAILURES = 5;
    static constexpr qint64 LOGIN_LOCKOUT_MS = 60000; // 1 minute lockout
};
