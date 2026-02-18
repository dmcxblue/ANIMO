#ifndef TOKENHELPER_H
#define TOKENHELPER_H

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <functional>

struct TokenInfo;

class TokenHelper : public QObject {
    Q_OBJECT

public:
    static TokenHelper* instance();

    // Common Azure resources
    static const QString RESOURCE_GRAPH;
    static const QString RESOURCE_MANAGEMENT;
    static const QString RESOURCE_SQL_DATABASE;
    static const QString RESOURCE_KEY_VAULT;
    static const QString RESOURCE_STORAGE;

    // Default client ID (Microsoft Office)
    static const QString DEFAULT_CLIENT_ID;

    // Microsoft Azure PowerShell client ID (for Graph API compatibility)
    static const QString AZURE_POWERSHELL_CLIENT_ID;

    // Callback types
    using TokenCallback = std::function<void(bool success, const QString &accessToken, const QString &error)>;
    using MultiTokenCallback = std::function<void(bool success, const QMap<QString, QString> &tokens, const QString &error)>;

    // Get token for a resource - checks TokenStore first, then tries refresh
    // If upn is empty, gets any available token for the resource
    // If clientId is empty, auto-selects appropriate clientId based on resource
    void getTokenForResource(const QString &resource, TokenCallback callback, const QString &upn = QString(), const QString &clientId = QString());

    // Get multiple tokens at once for a specific user
    // If clientId is empty, auto-selects appropriate clientId based on resource
    void getTokensForResources(const QStringList &resources, MultiTokenCallback callback, const QString &upn = QString(), const QString &clientId = QString());

    // Check if we have a valid token for resource (without fetching)
    bool hasValidToken(const QString &resource, const QString &upn = QString()) const;

    // Get existing token from store (returns empty string if not found/expired)
    QString getExistingToken(const QString &resource, const QString &upn = QString()) const;

    // Get the best available refresh token and tenant for token exchange
    // If upn is specified, only returns refresh token for that user
    bool getBestRefreshToken(QString &outRefreshToken, QString &outTenantId, QString &outUpn, const QString &filterUpn = QString()) const;

    // Get list of available users with tokens
    QStringList getAvailableUsers() const;

    // Exchange refresh token for new access token
    void exchangeRefreshToken(const QString &refreshToken,
                              const QString &tenantId,
                              const QString &resource,
                              TokenCallback callback,
                              const QString &clientId = QString());

signals:
    // Emitted when a token is exchanged via refresh token — allows server-side logging
    void tokenExchanged(const QString &accessToken, const QString &refreshToken,
                        const QString &upn, const QString &tenantId,
                        const QString &resource);

private:
    explicit TokenHelper(QObject *parent = nullptr);
    ~TokenHelper() = default;

    QNetworkAccessManager *m_net;
    static TokenHelper *s_instance;

    // Track pending requests to avoid duplicates
    QMap<QString, QList<TokenCallback>> m_pendingRequests;

    // Determine the best client ID for a given resource
    static QString selectClientIdForResource(const QString &resource);
};

#endif // TOKENHELPER_H
