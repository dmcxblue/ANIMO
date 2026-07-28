#include "NetworkHelper.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

const QString NetworkHelper::GRAPH_API_BASE = "https://graph.microsoft.com/v1.0";
const QString NetworkHelper::MANAGEMENT_API_BASE = "https://management.azure.com";
const QString NetworkHelper::AZURE_LOGIN_BASE = "https://login.microsoftonline.com";

const QString NetworkHelper::AUDIENCE_GRAPH = "https://graph.microsoft.com";
const QString NetworkHelper::AUDIENCE_MANAGEMENT = "https://management.azure.com";
const QString NetworkHelper::AUDIENCE_KEY_VAULT = "https://vault.azure.net";
const QString NetworkHelper::AUDIENCE_STORAGE = "https://storage.azure.com";

QNetworkRequest NetworkHelper::bearerJsonRequest(const QUrl &url, const QString &token)
{
    QNetworkRequest req{url};
    req.setRawHeader("Authorization", QString("Bearer %1").arg(token).toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    return req;
}

QNetworkRequest NetworkHelper::bearerJsonRequest(const QString &url, const QString &token)
{
    return bearerJsonRequest(QUrl(url), token);
}

QNetworkRequest NetworkHelper::createBearerRequest(const QString &url, const QString &token, int timeoutMs)
{
    QNetworkRequest req{QUrl(url)};
    req.setRawHeader("Authorization", QString("Bearer %1").arg(token).toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setTransferTimeout(timeoutMs);
    return req;
}

QNetworkRequest NetworkHelper::outlookJsonRequest(const QUrl &url, const QString &token)
{
    QNetworkRequest req = bearerJsonRequest(url, token);
    req.setRawHeader("Prefer", "outlook.body-content-type=\"html\"");
    return req;
}

QNetworkRequest NetworkHelper::outlookJsonRequest(const QString &url, const QString &token)
{
    return outlookJsonRequest(QUrl(url), token);
}

QNetworkRequest NetworkHelper::formUrlEncodedRequest(const QUrl &url)
{
    QNetworkRequest req{url};
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    req.setRawHeader("Accept", "application/json");
    return req;
}

QNetworkRequest NetworkHelper::formUrlEncodedRequest(const QString &url)
{
    return formUrlEncodedRequest(QUrl(url));
}

QNetworkRequest NetworkHelper::genericRequest(const QUrl &url,
                                              const QMap<QString, QString> &headers,
                                              const QByteArray &contentType,
                                              int timeoutMs)
{
    QNetworkRequest req{url};
    if (!contentType.isEmpty()) {
        req.setHeader(QNetworkRequest::ContentTypeHeader, contentType);
    }
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
        req.setRawHeader(it.key().toUtf8(), it.value().toUtf8());
    }
    req.setTransferTimeout(timeoutMs);
    return req;
}

QString NetworkHelper::parseApiError(QNetworkReply *reply, const QByteArray &responseBody)
{
    if (!reply) {
        return "Network error: no response received";
    }

    QByteArray body = responseBody.isEmpty() ? reply->readAll() : responseBody;
    QString result;

    // Try to parse JSON error
    QJsonDocument doc = QJsonDocument::fromJson(body);
    if (doc.isObject()) {
        QJsonObject root = doc.object();

        // Graph API format: { "error": { "code": "...", "message": "..." } }
        if (root.contains("error")) {
            QJsonObject errorObj = root["error"].toObject();
            QString code = errorObj["code"].toString();
            QString message = errorObj["message"].toString();

            if (!code.isEmpty()) {
                result = QString("[%1] ").arg(code);
            }
            result += message;

            // Add helpful hints for common errors
            if (code == "InvalidAuthenticationToken") {
                result += " (Token may be expired or invalid)";
            } else if (code == "Authorization_RequestDenied") {
                result += " (Insufficient permissions)";
            } else if (code == "Request_ResourceNotFound") {
                result += " (Resource does not exist or no access)";
            }

            return result;
        }

        // AADSTS error format (OAuth errors)
        if (root.contains("error_description")) {
            QString desc = root["error_description"].toString();
            QString code = root["error"].toString();
            return QString("[%1] %2").arg(code, desc);
        }
    }

    // Fallback to generic error
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (status == 429) {
        return QString("Rate limited (HTTP 429) - retry after %1ms").arg(getRetryAfterMs(reply));
    }

    return reply->errorString();
}

bool NetworkHelper::isThrottled(QNetworkReply *reply)
{
    if (!reply) return false;
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    return status == 429;
}

int NetworkHelper::getRetryAfterMs(QNetworkReply *reply)
{
    if (!reply) return 1000;

    // Check Retry-After header
    QByteArray retryAfter = reply->rawHeader("Retry-After");
    if (!retryAfter.isEmpty()) {
        bool ok;
        int seconds = retryAfter.toInt(&ok);
        if (ok && seconds > 0) {
            return seconds * 1000;
        }
    }

    // Check x-ms-retry-after-ms header (Azure-specific)
    QByteArray retryAfterMs = reply->rawHeader("x-ms-retry-after-ms");
    if (!retryAfterMs.isEmpty()) {
        bool ok;
        int ms = retryAfterMs.toInt(&ok);
        if (ok && ms > 0) {
            return ms;
        }
    }

    return 1000;  // Default 1 second
}

bool NetworkHelper::validateTokenAudience(const QString &token, const QString &expectedAudience)
{
    QString aud = extractTokenAudience(token);
    if (aud.isEmpty()) return false;

    // Normalize for comparison (remove trailing slash, case-insensitive)
    QString normAud = aud.toLower().trimmed();
    QString normExpected = expectedAudience.toLower().trimmed();

    if (normAud.endsWith('/')) normAud.chop(1);
    if (normExpected.endsWith('/')) normExpected.chop(1);

    return normAud == normExpected;
}

QString NetworkHelper::extractTokenAudience(const QString &token)
{
    QStringList parts = token.split('.');
    if (parts.size() < 2) return QString();

    QByteArray payload = parts.at(1).toUtf8();

    // Add padding for base64 decoding
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));

    QByteArray decoded = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
    QJsonDocument doc = QJsonDocument::fromJson(decoded);

    if (!doc.isObject()) return QString();

    return doc.object().value("aud").toString();
}

void NetworkHelper::setRequestTimeout(QNetworkRequest &request, int timeoutMs)
{
    request.setTransferTimeout(timeoutMs);
}

bool NetworkHelper::isReplySuccess(QNetworkReply *reply, QString *errorOut)
{
    if (!reply) {
        if (errorOut) *errorOut = "Network request failed to initialize";
        return false;
    }

    if (reply->error() != QNetworkReply::NoError) {
        if (errorOut) *errorOut = parseApiError(reply);
        return false;
    }

    int status = getHttpStatus(reply);
    if (status < 200 || status >= 300) {
        if (errorOut) {
            if (status == 429) {
                *errorOut = QString("Rate limited (HTTP 429) - retry after %1ms").arg(getRetryAfterMs(reply));
            } else {
                *errorOut = parseApiError(reply);
            }
        }
        return false;
    }

    return true;
}

int NetworkHelper::getHttpStatus(QNetworkReply *reply)
{
    if (!reply) return 0;
    return reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
}

QString NetworkHelper::getAudienceMismatchError(const QString &token, const QString &expectedAudience)
{
    QString actualAudience = extractTokenAudience(token);
    if (actualAudience.isEmpty()) {
        return "Token appears to be invalid or malformed (could not extract audience)";
    }
    return QString("Token audience mismatch: expected '%1' but token is for '%2'. "
                   "Please use a token for the correct resource.")
           .arg(expectedAudience, actualAudience);
}
