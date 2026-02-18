#include "TokenStore.h"
#include <QJsonDocument>
#include <QDebug>
#include <QRegularExpression>
#include <QMutex>

// Thread-safe singleton using C++11 magic statics
TokenStore* TokenStore::s_instance = nullptr;
static QMutex s_instanceMutex;

TokenStore* TokenStore::instance()
{
    // Double-checked locking with mutex for thread safety
    if (!s_instance) {
        QMutexLocker locker(&s_instanceMutex);
        if (!s_instance) {
            s_instance = new TokenStore();
        }
    }
    return s_instance;
}

TokenStore::TokenStore(QObject *parent)
    : QObject(parent)
{
    // Start auto-cleanup timer (every 5 minutes)
    m_cleanupTimer = new QTimer(this);
    connect(m_cleanupTimer, &QTimer::timeout, this, &TokenStore::onCleanupTimer);
    m_cleanupTimer->start(5 * 60 * 1000);  // 5 minutes
}

void TokenStore::storeToken(const QString &sessionId, const TokenInfo &token)
{
    if (sessionId.isEmpty() || token.accessToken.isEmpty()) {
        return;
    }

    TokenInfo enrichedToken = token;
    enrichedToken.sessionId = sessionId;
    enrichedToken.issuedAt = QDateTime::currentDateTime();

    // Try to parse claims from JWT if not already provided
    QJsonObject claims = parseJwtPayload(token.accessToken);

    // Extract UPN if not provided
    if (enrichedToken.upn.isEmpty()) {
        enrichedToken.upn = claims.value("upn").toString();
        if (enrichedToken.upn.isEmpty()) {
            enrichedToken.upn = claims.value("preferred_username").toString();
        }
        if (enrichedToken.upn.isEmpty()) {
            enrichedToken.upn = claims.value("unique_name").toString();
        }
    }

    // Extract tenant ID if not provided
    if (enrichedToken.tenantId.isEmpty()) {
        enrichedToken.tenantId = claims.value("tid").toString();
    }

    // Extract client ID (appid for v1, azp for v2) if not provided
    if (enrichedToken.clientId.isEmpty()) {
        enrichedToken.clientId = claims.value("appid").toString();
        if (enrichedToken.clientId.isEmpty()) {
            enrichedToken.clientId = claims.value("azp").toString();
        }
    }

    // Try to parse expiry from JWT
    if (enrichedToken.expiresAt.isNull()) {
        enrichedToken.expiresAt = parseJwtExpiry(token.accessToken);
    }

    // Check if we already have a token for this session+resource
    QList<TokenInfo> &sessionTokens = m_tokens[sessionId];
    bool replaced = false;
    for (int i = 0; i < sessionTokens.size(); ++i) {
        if (sessionTokens[i].resource == token.resource) {
            sessionTokens[i] = enrichedToken;
            replaced = true;
            break;
        }
    }
    if (!replaced) {
        sessionTokens.append(enrichedToken);
    }

    // Update resource index for faster lookup
    updateResourceIndex(sessionId, token.resource);

    qDebug() << "[TokenStore] Stored token for session:" << sessionId.left(8)
             << "resource:" << token.resource
             << "upn:" << token.upn;

    emit tokenStored(sessionId, token.resource);
}

TokenInfo TokenStore::getTokenForSession(const QString &sessionId) const
{
    if (m_tokens.contains(sessionId) && !m_tokens[sessionId].isEmpty()) {
        return m_tokens[sessionId].first();
    }
    return TokenInfo();
}

TokenInfo TokenStore::getGraphToken() const
{
    return getTokenForResource("https://graph.microsoft.com");
}

TokenInfo TokenStore::getManagementToken() const
{
    return getTokenForResource("https://management.azure.com");
}

TokenInfo TokenStore::getTokenForResource(const QString &resource) const
{
    // First try exact match using the index
    QList<QString> sessionIds = m_resourceIndex.values(resource);
    for (const QString &sessionId : sessionIds) {
        if (m_tokens.contains(sessionId)) {
            for (const TokenInfo &token : m_tokens[sessionId]) {
                if (token.resource == resource && !token.isExpired()) {
                    return token;
                }
            }
        }
    }

    // Fallback: search all sessions for partial resource match
    for (auto it = m_tokens.constBegin(); it != m_tokens.constEnd(); ++it) {
        for (const TokenInfo &token : it.value()) {
            if (token.resource.contains(resource, Qt::CaseInsensitive) ||
                resource.contains(token.resource, Qt::CaseInsensitive)) {
                if (!token.isExpired()) {
                    return token;
                }
            }
        }
    }
    return TokenInfo();
}

QList<TokenInfo> TokenStore::getAllTokensForSession(const QString &sessionId) const
{
    return m_tokens.value(sessionId);
}

QList<TokenInfo> TokenStore::getAllTokens() const
{
    QList<TokenInfo> all;
    for (auto it = m_tokens.constBegin(); it != m_tokens.constEnd(); ++it) {
        all.append(it.value());
    }
    return all;
}

TokenInfo TokenStore::getTokenForResourceAndUser(const QString &resource, const QString &upn) const
{
    if (upn.isEmpty()) {
        return getTokenForResource(resource);
    }

    for (auto it = m_tokens.constBegin(); it != m_tokens.constEnd(); ++it) {
        for (const TokenInfo &token : it.value()) {
            if (token.upn.compare(upn, Qt::CaseInsensitive) == 0 &&
                (token.resource == resource ||
                 token.resource.contains(resource, Qt::CaseInsensitive) ||
                 resource.contains(token.resource, Qt::CaseInsensitive))) {
                if (!token.isExpired()) {
                    return token;
                }
            }
        }
    }
    return TokenInfo();
}

TokenInfo TokenStore::getGraphTokenForUser(const QString &upn) const
{
    return getTokenForResourceAndUser("https://graph.microsoft.com", upn);
}

TokenInfo TokenStore::getManagementTokenForUser(const QString &upn) const
{
    return getTokenForResourceAndUser("https://management.azure.com", upn);
}

QList<TokenInfo> TokenStore::getAllTokensForUser(const QString &upn) const
{
    QList<TokenInfo> result;
    for (auto it = m_tokens.constBegin(); it != m_tokens.constEnd(); ++it) {
        for (const TokenInfo &token : it.value()) {
            if (token.upn.compare(upn, Qt::CaseInsensitive) == 0) {
                result.append(token);
            }
        }
    }
    return result;
}

QStringList TokenStore::getUniqueUsers() const
{
    QSet<QString> users;
    for (auto it = m_tokens.constBegin(); it != m_tokens.constEnd(); ++it) {
        for (const TokenInfo &token : it.value()) {
            if (!token.upn.isEmpty()) {
                users.insert(token.upn.toLower());
            }
        }
    }
    return users.values();
}

void TokenStore::removeTokensForSession(const QString &sessionId)
{
    if (m_tokens.remove(sessionId) > 0) {
        removeFromResourceIndex(sessionId);
        qDebug() << "[TokenStore] Removed tokens for session:" << sessionId.left(8);
        emit tokenRemoved(sessionId);
    }
}

void TokenStore::clearAll()
{
    m_tokens.clear();
    m_resourceIndex.clear();
    qDebug() << "[TokenStore] Cleared all tokens";
    emit tokensCleared();
}

bool TokenStore::hasValidGraphToken() const
{
    TokenInfo token = getGraphToken();
    return token.isValid() && !token.isExpired();
}

bool TokenStore::hasValidManagementToken() const
{
    TokenInfo token = getManagementToken();
    return token.isValid() && !token.isExpired();
}

QDateTime TokenStore::parseJwtExpiry(const QString &jwt)
{
    QJsonObject payload = parseJwtPayload(jwt);
    if (payload.contains("exp")) {
        qint64 exp = payload["exp"].toVariant().toLongLong();
        return QDateTime::fromSecsSinceEpoch(exp);
    }
    return QDateTime();
}

bool TokenStore::isValidJwtFormat(const QString &jwt)
{
    if (jwt.isEmpty()) {
        return false;
    }

    // JWT must have exactly 3 parts: header.payload.signature
    QStringList parts = jwt.split('.');
    if (parts.size() != 3) {
        return false;
    }

    // Each part must be non-empty and contain only valid base64url characters
    static const QRegularExpression base64UrlPattern("^[A-Za-z0-9_-]+$");
    for (const QString &part : parts) {
        if (part.isEmpty() || !base64UrlPattern.match(part).hasMatch()) {
            return false;
        }
    }

    // Try to decode and parse the payload as JSON (basic sanity check)
    QByteArray payload = parts.at(1).toUtf8();
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));
    QByteArray decoded = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(decoded, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        return false;
    }

    return true;
}

QJsonObject TokenStore::parseJwtPayload(const QString &jwt)
{
    // Validate format first
    if (!isValidJwtFormat(jwt)) {
        qDebug() << "[TokenStore] Invalid JWT format";
        return QJsonObject();
    }

    QStringList parts = jwt.split('.');
    QByteArray payload = parts.at(1).toUtf8();
    // Pad for base64url decoding
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));
    payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);

    QJsonDocument doc = QJsonDocument::fromJson(payload);
    return doc.object();
}

int TokenStore::removeExpiredTokens()
{
    int removedCount = 0;
    QDateTime now = QDateTime::currentDateTime();

    for (auto it = m_tokens.begin(); it != m_tokens.end(); ) {
        QList<TokenInfo> &tokens = it.value();

        // Remove expired tokens from this session
        for (int i = tokens.size() - 1; i >= 0; --i) {
            if (tokens[i].expiresAt.isValid() && tokens[i].expiresAt < now) {
                qDebug() << "[TokenStore] Auto-removing expired token for session:"
                         << tokens[i].sessionId.left(8) << "resource:" << tokens[i].resource;
                tokens.removeAt(i);
                removedCount++;
            }
        }

        // Remove session entry if no tokens left
        if (tokens.isEmpty()) {
            QString sessionId = it.key();
            it = m_tokens.erase(it);
            emit tokenRemoved(sessionId);
        } else {
            ++it;
        }
    }

    if (removedCount > 0) {
        qDebug() << "[TokenStore] Cleanup removed" << removedCount << "expired token(s)";
    }

    return removedCount;
}

void TokenStore::onCleanupTimer()
{
    removeExpiredTokens();
}

void TokenStore::updateResourceIndex(const QString &sessionId, const QString &resource)
{
    if (resource.isEmpty() || sessionId.isEmpty()) {
        return;
    }

    // Check if this resource-session pair already exists
    QList<QString> existingSessionIds = m_resourceIndex.values(resource);
    if (!existingSessionIds.contains(sessionId)) {
        m_resourceIndex.insert(resource, sessionId);
    }
}

void TokenStore::removeFromResourceIndex(const QString &sessionId)
{
    // Remove all entries for this sessionId
    for (auto it = m_resourceIndex.begin(); it != m_resourceIndex.end(); ) {
        if (it.value() == sessionId) {
            it = m_resourceIndex.erase(it);
        } else {
            ++it;
        }
    }
}
