#ifndef SSLHELPER_H
#define SSLHELPER_H

#include <QSslConfiguration>
#include <QSslSocket>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslError>
#include <QList>
#include <QString>
#include <QStringList>

/**
 * SslHelper - TLS/SSL security helper for Microsoft endpoint connections
 *
 * Provides:
 * - Secure SSL configuration (TLS 1.2+ only)
 * - Optional certificate pinning for Microsoft endpoints
 * - SSL error handling with security logging
 *
 * Usage:
 *   QNetworkAccessManager *net = new QNetworkAccessManager(this);
 *   SslHelper::configureSsl(net);
 */
class SslHelper {
public:
    /**
     * Configure a QNetworkAccessManager with secure SSL settings
     * @param manager The network manager to configure
     * @param enablePinning Enable certificate pinning (default: false for compatibility)
     */
    static void configureSsl(QNetworkAccessManager *manager, bool enablePinning = false);

    /**
     * Get a secure SSL configuration
     * @return QSslConfiguration with TLS 1.2+ and secure ciphers
     */
    static QSslConfiguration secureConfiguration();

    /**
     * Check if a host is a known Microsoft endpoint
     * @param host The hostname to check
     * @return true if host matches Microsoft domains
     */
    static bool isMicrosoftEndpoint(const QString &host);

    /**
     * Get list of Microsoft domains for validation
     */
    static QStringList microsoftDomains();

private:
    // Microsoft root CA certificate hashes (SHA-256 of public key)
    // These are the root CAs that sign Microsoft's certificates
    static QStringList pinnedCertHashes();
};

#endif // SSLHELPER_H
