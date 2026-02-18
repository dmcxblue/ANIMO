#include "TokenHelper.h"
#include "TokenStore.h"
#include "NetworkHelper.h"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

// Static resource definitions
const QString TokenHelper::RESOURCE_GRAPH = "https://graph.microsoft.com";
const QString TokenHelper::RESOURCE_MANAGEMENT = "https://management.azure.com";
const QString TokenHelper::RESOURCE_SQL_DATABASE = "https://database.windows.net";
const QString TokenHelper::RESOURCE_KEY_VAULT = "https://vault.azure.net";
const QString TokenHelper::RESOURCE_STORAGE = "https://storage.azure.com";

const QString TokenHelper::DEFAULT_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
const QString TokenHelper::AZURE_POWERSHELL_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2";

TokenHelper* TokenHelper::s_instance = nullptr;

TokenHelper* TokenHelper::instance()
{
    if (!s_instance) {
        s_instance = new TokenHelper();
    }
    return s_instance;
}

TokenHelper::TokenHelper(QObject *parent)
    : QObject(parent), m_net(new QNetworkAccessManager(this))
{
}

bool TokenHelper::hasValidToken(const QString &resource, const QString &upn) const
{
    TokenInfo token = upn.isEmpty()
        ? TokenStore::instance()->getTokenForResource(resource)
        : TokenStore::instance()->getTokenForResourceAndUser(resource, upn);
    return token.isValid() && !token.isExpired();
}

QString TokenHelper::getExistingToken(const QString &resource, const QString &upn) const
{
    TokenInfo token = upn.isEmpty()
        ? TokenStore::instance()->getTokenForResource(resource)
        : TokenStore::instance()->getTokenForResourceAndUser(resource, upn);
    if (token.isValid() && !token.isExpired()) {
        return token.accessToken;
    }
    return QString();
}

QStringList TokenHelper::getAvailableUsers() const
{
    return TokenStore::instance()->getUniqueUsers();
}

bool TokenHelper::getBestRefreshToken(QString &outRefreshToken, QString &outTenantId, QString &outUpn, const QString &filterUpn) const
{
    QList<TokenInfo> allTokens = filterUpn.isEmpty()
        ? TokenStore::instance()->getAllTokens()
        : TokenStore::instance()->getAllTokensForUser(filterUpn);

    // Prefer tokens with refresh tokens, sorted by expiry (newest first)
    TokenInfo bestToken;
    for (const TokenInfo &token : allTokens) {
        if (!token.refreshToken.isEmpty()) {
            if (!bestToken.isValid() || token.expiresAt > bestToken.expiresAt) {
                bestToken = token;
            }
        }
    }

    if (bestToken.isValid() && !bestToken.refreshToken.isEmpty()) {
        outRefreshToken = bestToken.refreshToken;
        outTenantId = bestToken.tenantId;
        outUpn = bestToken.upn;
        return true;
    }

    return false;
}

void TokenHelper::getTokenForResource(const QString &resource, TokenCallback callback, const QString &upn, const QString &clientId)
{
    // First check if we already have a valid token for this user
    QString existingToken = getExistingToken(resource, upn);
    if (!existingToken.isEmpty()) {
        // Validate that the token has the correct audience
        if (!NetworkHelper::validateTokenAudience(existingToken, resource)) {
            qDebug() << "[TokenHelper] Existing token has wrong audience. Will request new token.";
            // Continue to token exchange below instead of returning early
        } else {
            qDebug() << "[TokenHelper] Found existing valid token for:" << resource << "user:" << upn;
            callback(true, existingToken, QString());
            return;
        }
    }

    // Create a unique key for pending requests (resource + user)
    QString requestKey = upn.isEmpty() ? resource : QString("%1|%2").arg(resource, upn);

    // Check if there's already a pending request for this resource+user
    if (m_pendingRequests.contains(requestKey)) {
        m_pendingRequests[requestKey].append(callback);
        qDebug() << "[TokenHelper] Request already pending for:" << requestKey;
        return;
    }

    // Try to get a refresh token to exchange (filtered by user if specified)
    QString refreshToken, tenantId, tokenUpn;
    if (!getBestRefreshToken(refreshToken, tenantId, tokenUpn, upn)) {
        qDebug() << "[TokenHelper] No refresh token available for exchange" << (upn.isEmpty() ? "" : " for user: " + upn);
        QString errorMsg = upn.isEmpty()
            ? "No refresh token available. Please authenticate first."
            : QString("No refresh token available for user: %1").arg(upn);
        callback(false, QString(), errorMsg);
        return;
    }

    // Auto-select appropriate client ID if not specified
    QString effectiveClientId = clientId.isEmpty() ? selectClientIdForResource(resource) : clientId;

    // Add to pending requests
    m_pendingRequests[requestKey].append(callback);

    qDebug() << "[TokenHelper] Exchanging refresh token for resource:" << resource << "user:" << tokenUpn << "clientId:" << effectiveClientId;
    exchangeRefreshToken(refreshToken, tenantId, resource,
        [this, requestKey](bool success, const QString &accessToken, const QString &error) {
            // Notify all pending callbacks for this resource+user
            QList<TokenCallback> callbacks = m_pendingRequests.take(requestKey);
            for (const auto &cb : callbacks) {
                cb(success, accessToken, error);
            }
        }, effectiveClientId);
}

void TokenHelper::getTokensForResources(const QStringList &resources, MultiTokenCallback callback, const QString &upn, const QString &clientId)
{
    if (resources.isEmpty()) {
        callback(true, QMap<QString, QString>(), QString());
        return;
    }

    struct Context {
        QMap<QString, QString> tokens;
        QStringList errors;
        int remaining;
        MultiTokenCallback callback;
        QString upn;
        QString clientId;
    };

    auto ctx = std::make_shared<Context>();
    ctx->remaining = resources.size();
    ctx->callback = callback;
    ctx->upn = upn;
    ctx->clientId = clientId;

    for (const QString &resource : resources) {
        getTokenForResource(resource, [ctx, resource](bool success, const QString &token, const QString &error) {
            if (success) {
                ctx->tokens[resource] = token;
            } else {
                ctx->errors.append(QString("%1: %2").arg(resource, error));
            }

            ctx->remaining--;
            if (ctx->remaining == 0) {
                bool allSuccess = ctx->errors.isEmpty();
                ctx->callback(allSuccess, ctx->tokens, ctx->errors.join("\n"));
            }
        }, ctx->upn, ctx->clientId);
    }
}

void TokenHelper::exchangeRefreshToken(const QString &refreshToken,
                                        const QString &tenantId,
                                        const QString &resource,
                                        TokenCallback callback,
                                        const QString &clientId)
{
    if (refreshToken.isEmpty() || tenantId.isEmpty()) {
        callback(false, QString(), "Missing refresh token or tenant ID");
        return;
    }

    // Use provided clientId or fall back to auto-selection based on resource
    QString effectiveClientId = clientId.isEmpty() ? selectClientIdForResource(resource) : clientId;

    QString tokenUrl = QString("https://login.microsoftonline.com/%1/oauth2/token?api-version=1.0")
                           .arg(tenantId);

    QNetworkRequest req{QUrl(tokenUrl)};
    req.setRawHeader("User-Agent", "Mozilla/5.0");
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    NetworkHelper::setRequestTimeout(req);

    QUrlQuery form;
    form.addQueryItem("grant_type", "refresh_token");
    form.addQueryItem("refresh_token", refreshToken);
    form.addQueryItem("client_id", effectiveClientId);
    form.addQueryItem("resource", resource);
    form.addQueryItem("scope", "openid");

    QNetworkReply *reply = m_net->post(req, form.query(QUrl::FullyEncoded).toUtf8());
    if (!reply) {
        callback(false, QString(), "Failed to create network request");
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply, resource, effectiveClientId, callback]() {
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            QString error = reply->errorString();
            qDebug() << "[TokenHelper] Token exchange failed:" << error;
            callback(false, QString(), error);
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();

        if (obj.contains("error")) {
            QString error = obj.value("error_description").toString(obj.value("error").toString());
            qDebug() << "[TokenHelper] Token exchange error:" << error;
            callback(false, QString(), error);
            return;
        }

        QString accessToken = obj.value("access_token").toString();
        QString newRefreshToken = obj.value("refresh_token").toString();

        if (accessToken.isEmpty()) {
            callback(false, QString(), "No access token in response");
            return;
        }

        // Store the new token in TokenStore
        TokenInfo tokenInfo;
        tokenInfo.accessToken = accessToken;
        tokenInfo.refreshToken = newRefreshToken;
        tokenInfo.resource = resource;
        tokenInfo.clientId = effectiveClientId;

        // Parse claims from the new token
        QJsonObject claims = TokenStore::parseJwtPayload(accessToken);
        tokenInfo.tenantId = claims.value("tid").toString();
        tokenInfo.upn = claims.value("upn").toString();
        if (tokenInfo.upn.isEmpty()) {
            tokenInfo.upn = claims.value("preferred_username").toString();
        }

        // Generate a session ID based on upn and resource (replaces any prior token for same combo)
        QString sessionKey = QString("%1_%2").arg(tokenInfo.upn, resource);
        TokenStore::instance()->storeToken(sessionKey, tokenInfo);

        qDebug() << "[TokenHelper] Successfully acquired token for:" << resource
                 << "clientId:" << effectiveClientId;

        // Notify listeners for server-side token logging
        emit tokenExchanged(accessToken, newRefreshToken,
                            tokenInfo.upn, tokenInfo.tenantId, resource);

        callback(true, accessToken, QString());
    });
}

QString TokenHelper::selectClientIdForResource(const QString &resource)
{
    // Microsoft Graph and related services work best with Azure PowerShell client
    if (resource.contains("graph.microsoft.com", Qt::CaseInsensitive) ||
        resource.contains("outlook.office.com", Qt::CaseInsensitive) ||
        resource.contains("outlook.office365.com", Qt::CaseInsensitive)) {
        qDebug() << "[TokenHelper] Using Azure PowerShell client ID for Graph/Outlook resource";
        return AZURE_POWERSHELL_CLIENT_ID;
    }

    // Azure Management API works with either, but PowerShell client is more reliable
    if (resource.contains("management.azure.com", Qt::CaseInsensitive)) {
        qDebug() << "[TokenHelper] Using Azure PowerShell client ID for Management resource";
        return AZURE_POWERSHELL_CLIENT_ID;
    }

    // For other resources (Key Vault, Storage, SQL, etc.), use default Microsoft Office client
    qDebug() << "[TokenHelper] Using default Microsoft Office client ID for resource:" << resource;
    return DEFAULT_CLIENT_ID;
}
