#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QUrlQuery>
#include <QRegularExpression>
#include <QUuid>

class PRTTokenExchanger : public QObject {
    Q_OBJECT
public:
    PRTTokenExchanger(const QString &clientId,
                      const QString &tenant,
                      const QString &resource,
                      const QString &prtToken,
                      QObject *parent = nullptr);

    QString getRedirectUri() const;
    QString buildAuthorizationUrl() const;
    void getAccessToken();

signals:
    void exchangeFinished(const QJsonObject &result);
    void errorOccurred(const QString &err);

private slots:
    void handleAuthReply();
    void handleTokenReply();

private:
    QString clientId;
    QString tenant;
    QString resource;
    QString prtToken;
    QString redirectUri;
    QNetworkAccessManager *net;
};
