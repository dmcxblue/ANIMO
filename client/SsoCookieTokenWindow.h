// SsoCookieTokenWindow.h
#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QUrlQuery>

class SsoCookieTokenWindow : public QWidget {
    Q_OBJECT

public:
    SsoCookieTokenWindow(QWidget* parent = nullptr);

private slots:
    void handleRequest();
    void handleAuthReply(QNetworkReply* reply);
    void handleTokenReply(QNetworkReply* reply);

private:
    QString getClientRedirectUrl(const QString& clientId, const QString& resource);
    void exchangeCodeForToken(const QString& code, const QString& clientId,
                              const QString& domain, const QString& resource,
                              const QString& redirectUrl);
    void requestAuthCode();
    void logTokenToServer(const QString &accessToken, const QString &refreshToken,
                         const QString &idToken, const QString &resource);
    QObject* locateTransport() const;

    // UI elements
    QLineEdit* clientIdInput;
    QLineEdit* domainInput;
    QLineEdit* resourceInput;
    QTextEdit* cookieInput;
    QTextEdit* output;
    QPushButton* genButton;

    // Network
    QNetworkAccessManager* nam;
    QString pendingClientId;
    QString pendingResource;
    QString pendingCookie;
    QString pendingDomain;
};
