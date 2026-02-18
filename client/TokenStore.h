#ifndef TOKENSTORE_H
#define TOKENSTORE_H

#include <QObject>
#include <QString>
#include <QMap>
#include <QDateTime>
#include <QJsonObject>
#include <QTimer>

struct TokenInfo {
    QString accessToken;
    QString refreshToken;
    QString idToken;
    QString resource;      // e.g., "https://graph.microsoft.com"
    QString tenantId;
    QString upn;           // user principal name
    QString sessionId;
    QString clientId;      // appid/azp claim — which client ID issued this token
    QDateTime issuedAt;
    QDateTime expiresAt;   // parsed from JWT if available

    bool isValid() const { return !accessToken.isEmpty(); }
    bool isExpired() const { return expiresAt.isValid() && QDateTime::currentDateTime() > expiresAt; }
};

class TokenStore : public QObject {
    Q_OBJECT

public:
    static TokenStore* instance();

    // Store tokens for a session
    void storeToken(const QString &sessionId, const TokenInfo &token);

    // Get tokens
    TokenInfo getTokenForSession(const QString &sessionId) const;
    TokenInfo getGraphToken() const;           // Get any valid Graph token
    TokenInfo getManagementToken() const;      // Get any valid Management token
    TokenInfo getTokenForResource(const QString &resource) const;

    // Get tokens filtered by user (UPN)
    TokenInfo getTokenForResourceAndUser(const QString &resource, const QString &upn) const;
    TokenInfo getGraphTokenForUser(const QString &upn) const;
    TokenInfo getManagementTokenForUser(const QString &upn) const;

    // Get all tokens for a session
    QList<TokenInfo> getAllTokensForSession(const QString &sessionId) const;

    // Get all tokens for a specific user
    QList<TokenInfo> getAllTokensForUser(const QString &upn) const;

    // Get all stored tokens
    QList<TokenInfo> getAllTokens() const;

    // Get list of unique users (UPNs) with tokens
    QStringList getUniqueUsers() const;

    // Remove tokens
    void removeTokensForSession(const QString &sessionId);
    void clearAll();

    // Remove expired tokens from all sessions
    int removeExpiredTokens();

    // Check if we have a valid Graph token
    bool hasValidGraphToken() const;
    bool hasValidManagementToken() const;

    // Parse JWT to extract expiry
    static QDateTime parseJwtExpiry(const QString &jwt);
    static QJsonObject parseJwtPayload(const QString &jwt);

    // Validate JWT format (three base64url parts separated by dots)
    static bool isValidJwtFormat(const QString &jwt);

signals:
    void tokenStored(const QString &sessionId, const QString &resource);
    void tokenRemoved(const QString &sessionId);
    void tokensCleared();

private slots:
    void onCleanupTimer();

private:
    explicit TokenStore(QObject *parent = nullptr);
    ~TokenStore() = default;

    // Map: sessionId -> list of tokens (one session can have multiple resource tokens)
    QMap<QString, QList<TokenInfo>> m_tokens;

    // Index: resource -> sessionId for faster resource-based lookup
    QMultiMap<QString, QString> m_resourceIndex;

    // Helper to update resource index
    void updateResourceIndex(const QString &sessionId, const QString &resource);
    void removeFromResourceIndex(const QString &sessionId);

    // Auto-cleanup timer for expired tokens (runs every 5 minutes)
    QTimer *m_cleanupTimer = nullptr;

    static TokenStore *s_instance;
};

#endif // TOKENSTORE_H
