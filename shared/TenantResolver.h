#ifndef TENANT_RESOLVER_H
#define TENANT_RESOLVER_H

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QHash>
#include <QMutex>

/**
 * Async tenant ID resolver for Azure domains
 * Caches results to avoid repeated network lookups
 */
class TenantResolver : public QObject {
    Q_OBJECT

public:
    static TenantResolver& instance();

    /**
     * Resolve tenant ID for a domain asynchronously
     * Emits tenantResolved when complete
     * @param domain The domain to resolve (e.g., "contoso.com")
     */
    void resolveTenant(const QString &domain);

    /**
     * Get cached tenant ID if available
     * @param domain The domain to look up
     * @return Cached tenant ID or empty string if not cached
     */
    QString getCachedTenant(const QString &domain) const;

    /**
     * Clear the cache
     */
    void clearCache();

signals:
    /**
     * Emitted when tenant resolution completes
     * @param domain The domain that was resolved
     * @param tenantId The resolved tenant ID (or "N/A" on failure)
     */
    void tenantResolved(const QString &domain, const QString &tenantId);

private:
    TenantResolver(QObject *parent = nullptr);
    ~TenantResolver() = default;
    TenantResolver(const TenantResolver&) = delete;
    TenantResolver& operator=(const TenantResolver&) = delete;

    QNetworkAccessManager m_nam;
    mutable QMutex m_cacheMutex;
    QHash<QString, QString> m_cache;  // domain -> tenantId
    QSet<QString> m_pendingRequests;  // domains currently being resolved
};

#endif // TENANT_RESOLVER_H
