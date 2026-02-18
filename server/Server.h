#pragma once
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSet>
#include <QHash>
#include <QJsonObject>
#include <QString>
#include <QDir>
#include <QRegularExpression>

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

signals:
    // Append human-friendly log lines to a UI/console
    void log(const QString &line);

private slots:
    // TCP plumbing
    void onNewConnection();
    void onClientReady();
    void onClientDisconnected();

private:
    // Route a single JSON line; returns true if handled/formatted
    bool handleLine(QTcpSocket *sock, const QByteArray &line);

    // Simple password auth gate for this connection
    bool handleLogin(QTcpSocket *sock, const QJsonObject &obj);

    // Constant-time string comparison to prevent timing attacks
    static bool constantTimeCompare(const QString &a, const QString &b);

    // Listener + connected sockets
    QTcpServer tcp_;
    QSet<QTcpSocket*> clients_;
    QSet<QTcpSocket*> authed_; // sockets that passed login

    // Bind + auth config
    QString bindIp_;
    quint16 port_;
    QString allowedUser_;
    QString allowedPass_;

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
