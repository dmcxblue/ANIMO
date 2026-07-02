#pragma once
#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>

class ClientIdSelector;

class RequestRefreshTokens : public QWidget {
    Q_OBJECT
public:
    explicit RequestRefreshTokens(QWidget *parent = nullptr);

private slots:
    void handleRequest();
    void handleOpenIdReply();
    void handleTokenReply();

private:
    void logTokenToServer(const QString &accessToken, const QString &refreshToken);
    QString b64UrlDecodeToJsonField(const QString &jwtToken, const QString &field);
    QObject* locateTransport();

    // UI elements
    QTextEdit *refreshInput;
    QLineEdit *domainInput;
    QLineEdit *resourceInput;
    QLineEdit *userAgentInput;
    ClientIdSelector *clientIdInput;
    QTextEdit *resultOutput;
    QPushButton *fetchBtn;

    // Network
    QNetworkAccessManager *net;
    QString refreshToken, domain, resource, clientId, userAgent;
};
