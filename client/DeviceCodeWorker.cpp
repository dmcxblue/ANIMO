#include "DeviceCodeWorker.h"
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrlQuery>
#include <QThread>
#include <QDebug>

DeviceCodeWorker::DeviceCodeWorker(const QString &clientId,
                                   const QString &resource,
                                   const QString &userAgent,
                                   const QString &labelId)
    : clientId(clientId), resource(resource), userAgent(userAgent), labelId(labelId) {}

void DeviceCodeWorker::run() {
    try {
        QVariantMap flow = postDeviceCodeFlow();

        if (!flow.contains("user_code") || !flow.contains("device_code")) {
            qDebug() << "DeviceCode response missing fields:" << flow;
            emit errorOccurred(labelId, "Failed to initiate device flow (missing user_code or device_code).");
            return;
        }

        // Extract device_code for later polling
        QString deviceCode = flow.value("device_code").toString();

        // Stage 1: return device code flow info
        QVariantMap stage;
        stage["stage"] = "device_code";
        stage["verification_uri"] = flow.value("verification_uri").toString();
        stage["user_code"] = flow.value("user_code").toString();
        emit resultReceived(labelId, stage);

        // Stage 2: poll for token
        int interval = flow.value("interval").toInt();
        if (interval <= 0) interval = 5; // default: 5s

        bool success = false;
        for (int i = 0; i < 60; ++i) { // poll max ~5 minutes
            QThread::sleep(interval);

            QNetworkAccessManager mgr;
            QNetworkRequest req(QUrl("https://login.microsoftonline.com/organizations/oauth2/v2.0/token"));
            req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

            QUrlQuery data;
            data.addQueryItem("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
            data.addQueryItem("client_id", clientId);
            data.addQueryItem("device_code", deviceCode);

            QEventLoop loop;
            QNetworkReply *reply = mgr.post(req, data.toString(QUrl::FullyEncoded).toUtf8());
            QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
            loop.exec();

            if (reply->error() != QNetworkReply::NoError) {
                qDebug() << "Polling error:" << reply->errorString();
                reply->deleteLater();
                continue;
            }

            QByteArray response = reply->readAll();
            reply->deleteLater();

            QJsonDocument doc = QJsonDocument::fromJson(response);
            QJsonObject obj = doc.object();

            if (obj.contains("access_token")) {
                QVariantMap result;
                result["access_token"]  = obj.value("access_token").toString();
                result["scope"]         = obj.value("scope").toString();

                // Refresh token is optional; capture if returned
                if (obj.contains("refresh_token"))
                    result["refresh_token"] = obj.value("refresh_token").toString();
                else
                    result["refresh_token"] = "[No refresh token returned]";

                emit resultReceived(labelId, result);
                success = true;
                break;
            }

            QString err = obj.value("error").toString();
            if (err != "authorization_pending") {
                emit errorOccurred(labelId, "Login failed: " + err);
                break;
            }
        }

        if (!success) {
            emit errorOccurred(labelId, "Timeout waiting for user authorization.");
        }

    } catch (...) {
        emit errorOccurred(labelId, "Exception in DeviceCodeWorker.");
    }

    emit finished();
}

QVariantMap DeviceCodeWorker::postDeviceCodeFlow() {
    QNetworkAccessManager mgr;
    QNetworkRequest req(QUrl("https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    QUrlQuery data;
    data.addQueryItem("client_id", clientId);

    // Always append offline_access so refresh_token is returned
    QString scopeStr = resource.trimmed();
    if (!scopeStr.contains("offline_access"))
        scopeStr += " offline_access";
    data.addQueryItem("scope", scopeStr);

    QEventLoop loop;
    QNetworkReply *reply = mgr.post(req, data.toString(QUrl::FullyEncoded).toUtf8());
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    QVariantMap result;
    if (reply->error() == QNetworkReply::NoError) {
        QByteArray response = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(response);
        result = doc.object().toVariantMap();
    } else {
        qDebug() << "DeviceCode request failed:" << reply->errorString();
    }

    reply->deleteLater();
    return result;
}
