#include "TenantResolver.h"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrl>
#include <QMutexLocker>

TenantResolver& TenantResolver::instance() {
    static TenantResolver resolver;
    return resolver;
}

TenantResolver::TenantResolver(QObject *parent)
    : QObject(parent)
{
}

void TenantResolver::resolveTenant(const QString &domain) {
    if (domain.isEmpty()) {
        emit tenantResolved(domain, "N/A");
        return;
    }

    QString normalizedDomain = domain.toLower().trimmed();

    // Check cache first
    {
        QMutexLocker lock(&m_cacheMutex);
        if (m_cache.contains(normalizedDomain)) {
            QString cached = m_cache.value(normalizedDomain);
            emit tenantResolved(domain, cached);
            return;
        }

        // Check if already pending
        if (m_pendingRequests.contains(normalizedDomain)) {
            return; // Will be resolved by existing request
        }

        m_pendingRequests.insert(normalizedDomain);
    }

    // Make async request
    QUrl url(QString("https://login.microsoftonline.com/%1/.well-known/openid-configuration")
             .arg(normalizedDomain));

    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setTransferTimeout(10000); // 10 second timeout

    QNetworkReply *reply = m_nam.get(request);

    // Store domain in reply for later retrieval
    reply->setProperty("domain", domain);
    reply->setProperty("normalizedDomain", normalizedDomain);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        QString domain = reply->property("domain").toString();
        QString normalizedDomain = reply->property("normalizedDomain").toString();
        QString tenantId = "N/A";

        if (reply->error() == QNetworkReply::NoError) {
            QByteArray data = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(data);

            if (doc.isObject()) {
                QString authEndpoint = doc.object().value("authorization_endpoint").toString();
                // Extract tenant ID from URL: https://login.microsoftonline.com/<tenantId>/oauth2/...
                QStringList parts = authEndpoint.split('/', Qt::SkipEmptyParts);
                for (int i = 0; i < parts.size(); ++i) {
                    if (parts[i].contains("login.microsoftonline.com", Qt::CaseInsensitive) &&
                        i + 1 < parts.size()) {
                        tenantId = parts[i + 1];
                        break;
                    }
                }
            }
        }

        // Update cache
        {
            QMutexLocker lock(&m_cacheMutex);
            m_cache.insert(normalizedDomain, tenantId);
            m_pendingRequests.remove(normalizedDomain);
        }

        emit tenantResolved(domain, tenantId);

        reply->deleteLater();
    });
}

QString TenantResolver::getCachedTenant(const QString &domain) const {
    QMutexLocker lock(&m_cacheMutex);
    return m_cache.value(domain.toLower().trimmed(), QString());
}

void TenantResolver::clearCache() {
    QMutexLocker lock(&m_cacheMutex);
    m_cache.clear();
}
