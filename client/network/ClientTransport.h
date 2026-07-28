#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QHostAddress>
#include <QJsonObject>
#include <QTimer>

class ClientTransport : public QObject {
    Q_OBJECT
public:
    explicit ClientTransport(QObject *parent = nullptr);
    ~ClientTransport();

    // Connect and perform login with the operator username + password (blocking helper).
    bool connectAndLogin(const QString &host, quint16 port,
                         const QString &username, const QString &password,
                         int timeoutMs = 5000);

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

private slots:
    void onSocketConnected();
    void onSocketDisconnected();
    void onSocketReadyRead();
    void onSocketErrorOccurred(QAbstractSocket::SocketError socketError);
    void attemptReconnect();

private:
    QTcpSocket *socket_;
    QByteArray readBuffer_;

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
