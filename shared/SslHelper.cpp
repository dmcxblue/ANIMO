#include "SslHelper.h"
#include "ErrorLogger.h"

#include <QSslCertificate>
#include <QCryptographicHash>

void SslHelper::configureSsl(QNetworkAccessManager *manager, bool enablePinning) {
    if (!manager) return;

    // Connect to SSL errors for logging
    QObject::connect(manager, &QNetworkAccessManager::sslErrors,
        [enablePinning](QNetworkReply *reply, const QList<QSslError> &errors) {
            QString host = reply->url().host();
            bool isMsEndpoint = isMicrosoftEndpoint(host);

            for (const QSslError &error : errors) {
                QString errorMsg = QString("[SSL] %1: %2").arg(host, error.errorString());

                // Log all SSL errors
                LOG_WARNING("SslHelper", errorMsg);

                // For Microsoft endpoints, be strict
                if (isMsEndpoint) {
                    switch (error.error()) {
                        case QSslError::CertificateExpired:
                        case QSslError::CertificateNotYetValid:
                        case QSslError::CertificateRevoked:
                        case QSslError::CertificateUntrusted:
                        case QSslError::CertificateSignatureFailed:
                            // These are serious - don't ignore
                            LOG_ERROR("SslHelper", QString("[SSL CRITICAL] Certificate error for Microsoft endpoint: %1").arg(errorMsg));
                            return; // Don't ignore, let request fail
                        default:
                            break;
                    }
                }
            }

            // For non-critical errors on non-Microsoft endpoints, we can be more lenient
            if (!enablePinning || !isMsEndpoint) {
                // Only ignore self-signed for local testing
                QList<QSslError> ignorableErrors;
                for (const QSslError &error : errors) {
                    if (error.error() == QSslError::SelfSignedCertificate ||
                        error.error() == QSslError::SelfSignedCertificateInChain) {
                        // Don't ignore self-signed for Microsoft endpoints
                        if (!isMsEndpoint) {
                            ignorableErrors.append(error);
                        }
                    }
                }
                if (!ignorableErrors.isEmpty()) {
                    reply->ignoreSslErrors(ignorableErrors);
                }
            }
        });
}

QSslConfiguration SslHelper::secureConfiguration() {
    QSslConfiguration config = QSslConfiguration::defaultConfiguration();

    // Enforce TLS 1.2 or later
    config.setProtocol(QSsl::TlsV1_2OrLater);

    // Enable OCSP stapling if available
    config.setOcspStaplingEnabled(true);

    // Peer verification
    config.setPeerVerifyMode(QSslSocket::VerifyPeer);
    config.setPeerVerifyDepth(3);

    return config;
}

bool SslHelper::isMicrosoftEndpoint(const QString &host) {
    QString lowerHost = host.toLower();

    for (const QString &domain : microsoftDomains()) {
        if (lowerHost == domain || lowerHost.endsWith("." + domain)) {
            return true;
        }
    }

    return false;
}

QStringList SslHelper::microsoftDomains() {
    return {
        // Azure AD / Entra ID
        "login.microsoftonline.com",
        "login.microsoft.com",
        "login.windows.net",
        "sts.windows.net",

        // Microsoft Graph
        "graph.microsoft.com",
        "graph.windows.net",

        // Azure Management
        "management.azure.com",
        "management.core.windows.net",

        // Azure Storage
        "blob.core.windows.net",
        "queue.core.windows.net",
        "table.core.windows.net",
        "file.core.windows.net",

        // Azure Key Vault
        "vault.azure.net",

        // Office 365 / M365
        "outlook.office365.com",
        "outlook.office.com",
        "sharepoint.com",
        "onedrive.com",
        "teams.microsoft.com",

        // Azure SQL
        "database.windows.net",

        // Azure DevOps
        "dev.azure.com",
        "visualstudio.com",

        // Other Microsoft
        "microsoft.com",
        "microsoftonline.com",
        "azure.com",
        "azure.net",
        "msauth.net",
        "msftauth.net"
    };
}

QStringList SslHelper::pinnedCertHashes() {
    // SHA-256 SPKI hashes of Microsoft's root CAs and intermediates.
    // These are the public key fingerprints used by Microsoft Azure/M365 services.
    // Update if Microsoft rotates root CAs (check https://aka.ms/RootCerts).
    return {
        // DigiCert Global Root G2 (primary CA for Azure/M365)
        "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f",
        // DigiCert Global Root CA
        "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161",
        // Baltimore CyberTrust Root (legacy Azure)
        "16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb",
        // Microsoft RSA Root Certificate Authority 2017
        "c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0",
        // Microsoft ECC Root Certificate Authority 2017
        "358df39d764af9e1b766e9c972df352ee15cfac227af6ad1d70e8e4a6edcba02",
    };
}
