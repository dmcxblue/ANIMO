#include "TokenHelper.h"
#include "TokenStore.h"
#include "NetworkHelper.h"
#include "PsSessionRunner.h"
#include "SpnCredentialStore.h"
#include <QCoreApplication>
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

QString TokenHelper::getExistingTokenForSession(const QString &resource, const QString &sessionId) const
{
    TokenInfo token = TokenStore::instance()->getTokenForSessionAndResource(sessionId, resource);
    return (token.isValid() && !token.isExpired()) ? token.accessToken : QString();
}

bool TokenHelper::hasValidTokenForSession(const QString &resource, const QString &sessionId) const
{
    TokenInfo token = TokenStore::instance()->getTokenForSessionAndResource(sessionId, resource);
    return token.isValid() && !token.isExpired();
}

bool TokenHelper::getRefreshTokenForSession(const QString &sessionId, QString &outRefreshToken,
                                            QString &outTenantId, QString &outUpn) const
{
    const QList<TokenInfo> toks = TokenStore::instance()->getAllTokensForSession(sessionId);
    TokenInfo best;
    bool have = false;
    for (const TokenInfo &t : toks) {
        if (t.refreshToken.isEmpty()) continue;
        if (!have || t.expiresAt > best.expiresAt) { best = t; have = true; }
    }
    if (have) {
        outRefreshToken = best.refreshToken;
        outTenantId     = best.tenantId;
        outUpn          = best.upn;
        return true;
    }
    return false;
}

void TokenHelper::getTokenForResourceBySession(const QString &resource, TokenCallback callback,
                                               const QString &sessionId, const QString &clientId)
{
    if (sessionId.isEmpty()) {
        callback(false, QString(), "No session selected. Please select a session first.");
        return;
    }

    // Reuse an existing valid token from THIS session if its audience matches.
    QString existing = getExistingTokenForSession(resource, sessionId);
    if (!existing.isEmpty() && NetworkHelper::validateTokenAudience(existing, resource)) {
        callback(true, existing, QString());
        return;
    }

    const QString requestKey = QString("%1|sess|%2").arg(resource, sessionId);
    if (m_pendingRequests.contains(requestKey)) {
        m_pendingRequests[requestKey].append(callback);
        return;
    }

    // Exchange using this session's OWN refresh token (the core fix).
    QString refreshToken, tenantId, upn;
    if (getRefreshTokenForSession(sessionId, refreshToken, tenantId, upn)) {
        const QString effectiveClientId = clientId.isEmpty() ? selectClientIdForResource(resource) : clientId;
        m_pendingRequests[requestKey].append(callback);
        exchangeRefreshToken(refreshToken, tenantId, resource,
            [this, requestKey](bool success, const QString &accessToken, const QString &error) {
                const QList<TokenCallback> callbacks = m_pendingRequests.take(requestKey);
                for (const auto &cb : callbacks) cb(success, accessToken, error);
            }, effectiveClientId, sessionId);
        return;
    }

    // SPN client_credentials sessions have no refresh token. If we stashed the
    // {appId, secret, tenantId} at login time, mint the requested token
    // directly with client_credentials. The result is stored in TokenStore
    // under the same sessionId so subsequent calls hit the cache.
    const SpnCredentials spn = SpnCredentialStore::instance()->get(sessionId);
    if (spn.isValid()) {
        m_pendingRequests[requestKey].append(callback);

        QString scope = resource;
        if (!scope.endsWith('/')) scope.append('/');
        scope.append(".default");

        QUrl url(QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(spn.tenantId));
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        NetworkHelper::setRequestTimeout(req);

        QUrlQuery form;
        form.addQueryItem("grant_type", "client_credentials");
        form.addQueryItem("client_id", spn.appId);
        form.addQueryItem("client_secret", spn.secret);
        form.addQueryItem("scope", scope);

        QNetworkReply *reply = m_net->post(req, form.query(QUrl::FullyEncoded).toUtf8());
        if (!reply) {
            const auto callbacks = m_pendingRequests.take(requestKey);
            for (const auto &cb : callbacks)
                cb(false, QString(), "Failed to send SPN token request");
            return;
        }
        connect(reply, &QNetworkReply::finished, this,
                [this, reply, requestKey, resource, sessionId, spn]() {
            reply->deleteLater();
            const QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
            const QString token   = obj.value("access_token").toString();
            const auto callbacks  = m_pendingRequests.take(requestKey);

            if (reply->error() != QNetworkReply::NoError && token.isEmpty()) {
                const QString err = obj.value("error_description")
                                       .toString(obj.value("error").toString(reply->errorString()));
                for (const auto &cb : callbacks) cb(false, QString(), err);
                return;
            }
            if (token.isEmpty()) {
                for (const auto &cb : callbacks)
                    cb(false, QString(), "SPN token response had no access_token");
                return;
            }

            // Cache into TokenStore under the same session so the next lookup
            // is instant. UPN is left as the appId for consistency with the
            // initial SPN login row.
            TokenInfo info;
            info.accessToken = token;
            info.resource    = resource;
            info.tenantId    = spn.tenantId;
            info.upn         = spn.appId;
            TokenStore::instance()->storeToken(sessionId, info);

            for (const auto &cb : callbacks) cb(true, token, QString());
        });
        return;
    }

    // Tier 4: Session-scoped mint via the running pwsh. Both Az PS and az cli
    // are logged in at session-start (see login_*.ps1); asking them for a
    // token for the requested resource is the cheapest way to satisfy
    // "give me a token for X" when no refresh token / SPN secret is on hand.
    // The one-liner tries Az PS first, then falls back to az cli.
    QString escResource = resource;
    escResource.replace('\'', QStringLiteral("''"));
    const QString script = QStringLiteral(
        "$r='%1';"
        "$t=$null;"
        "try{ $t=(Get-AzAccessToken -ResourceUrl $r -EA Stop).Token }catch{};"
        "if(-not $t){"
          "try{"
            "$t=(& az account get-access-token --resource $r -o tsv --query accessToken 2>$null);"
            "if($LASTEXITCODE -ne 0){$t=$null}"
          "}catch{}"
        "};"
        "if($t){ '{\"token\":\"'+$t+'\"}' }else{ '{}' }"
    ).arg(escResource);

    m_pendingRequests[requestKey].append(callback);
    PsSessionRunner::run(this, sessionId, script,
        [this, requestKey, sessionId, resource](bool ok, const QJsonValue &json, const QString &raw) {
        const QList<TokenCallback> callbacks = m_pendingRequests.take(requestKey);
        QString token;
        if (ok && json.isObject()) token = json.toObject().value("token").toString();
        if (!token.isEmpty()) {
            // Cache under this session so the next lookup hits Tier 1.
            TokenInfo info;
            info.accessToken = token;
            info.resource    = resource;
            info.sessionId   = sessionId;
            TokenStore::instance()->storeToken(sessionId, info);
            for (const auto &cb : callbacks) cb(true, token, QString());
        } else {
            const QString err = QString(
                "No refresh token, no stored SPN credentials, and the session's own pwsh "
                "could not mint a token for %1 (via Get-AzAccessToken or az cli). "
                "Log the same identity in again with resource = %1 to obtain a token. "
                "Raw pwsh reply: %2").arg(resource, raw.left(240));
            for (const auto &cb : callbacks) cb(false, QString(), err);
        }
    }, /*wrap=*/false);
}

void TokenHelper::getTokensForResourcesBySession(const QStringList &resources, MultiTokenCallback callback,
                                                 const QString &sessionId, const QString &clientId)
{
    if (resources.isEmpty()) { callback(true, QMap<QString, QString>(), QString()); return; }

    struct Context {
        QMap<QString, QString> tokens;
        QStringList errors;
        int remaining;
        MultiTokenCallback callback;
    };
    auto ctx = std::make_shared<Context>();
    ctx->remaining = resources.size();
    ctx->callback = callback;

    for (const QString &resource : resources) {
        getTokenForResourceBySession(resource, [ctx, resource](bool ok, const QString &token, const QString &err) {
            if (ok) ctx->tokens[resource] = token;
            else    ctx->errors.append(QString("%1: %2").arg(resource, err));
            if (--ctx->remaining == 0) {
                ctx->callback(ctx->errors.isEmpty(), ctx->tokens, ctx->errors.join("\n"));
            }
        }, sessionId, clientId);
    }
}

void TokenHelper::exchangeRefreshToken(const QString &refreshToken,
                                        const QString &tenantId,
                                        const QString &resource,
                                        TokenCallback callback,
                                        const QString &clientId,
                                        const QString &storeSessionId)
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

    connect(reply, &QNetworkReply::finished, this, [this, reply, resource, effectiveClientId, callback, storeSessionId]() {
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

        // Store under the REAL sessionId when known, so modules and the terminal
        // both find it by (sessionId, resource). Fall back to a synthetic
        // "{upn}_{resource}" key only when no sessionId was supplied (legacy paths).
        const QString storeKey = storeSessionId.isEmpty()
            ? QString("%1_%2").arg(tokenInfo.upn, resource)
            : storeSessionId;
        tokenInfo.sessionId = storeKey;
        TokenStore::instance()->storeToken(storeKey, tokenInfo);

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

    // Key Vault / Storage / SQL and everything else: use the Azure PowerShell client.
    // The session refresh tokens are minted for it (management works), and the Office
    // client (d3590ed6) gets rejected with "Bad Request" for the vault/storage audience
    // on this tenant. This also matches the server-side exchange (Config defaultClientId).
    qDebug() << "[TokenHelper] Using Azure PowerShell client ID for resource:" << resource;
    return AZURE_POWERSHELL_CLIENT_ID;
}
