#ifndef NETWORKHELPER_H
#define NETWORKHELPER_H

#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QString>
#include <QMap>
#include <QByteArray>
#include <functional>

/**
 * @brief Centralized network request utilities
 *
 * Provides common request creation patterns used throughout the client.
 * Reduces code duplication and ensures consistent header configuration.
 */
class NetworkHelper {
public:
    // Default timeout in milliseconds (10 seconds)
    static constexpr int DEFAULT_TIMEOUT_MS = 10000;

    // Maximum retry attempts for 429 responses
    static constexpr int MAX_RETRY_ATTEMPTS = 3;

    /**
     * @brief Create a bearer-authenticated JSON request
     *
     * Creates a QNetworkRequest with:
     * - Authorization: Bearer <token>
     * - Content-Type: application/json
     *
     * @param url The target URL
     * @param token The bearer access token
     * @return Configured QNetworkRequest
     */
    static QNetworkRequest bearerJsonRequest(const QUrl &url, const QString &token);
    static QNetworkRequest bearerJsonRequest(const QString &url, const QString &token);

    /**
     * @brief Create a bearer-authenticated JSON request with timeout
     *
     * Same as bearerJsonRequest but also sets transfer timeout
     *
     * @param url The target URL
     * @param token The bearer access token
     * @param timeoutMs Timeout in milliseconds
     * @return Configured QNetworkRequest
     */
    static QNetworkRequest createBearerRequest(const QString &url, const QString &token,
                                                int timeoutMs = DEFAULT_TIMEOUT_MS);

    /**
     * @brief Create a bearer-authenticated JSON request for Outlook/Graph
     *
     * Same as bearerJsonRequest but adds:
     * - Prefer: outlook.body-content-type="html"
     *
     * @param url The target URL
     * @param token The bearer access token
     * @return Configured QNetworkRequest for Outlook operations
     */
    static QNetworkRequest outlookJsonRequest(const QUrl &url, const QString &token);
    static QNetworkRequest outlookJsonRequest(const QString &url, const QString &token);

    /**
     * @brief Create a form-urlencoded POST request
     *
     * Creates a QNetworkRequest with:
     * - Content-Type: application/x-www-form-urlencoded
     * - Accept: application/json
     *
     * @param url The target URL
     * @return Configured QNetworkRequest
     */
    static QNetworkRequest formUrlEncodedRequest(const QUrl &url);
    static QNetworkRequest formUrlEncodedRequest(const QString &url);

    /**
     * @brief Create an arbitrary-header HTTP request (no bearer auth).
     *
     * Every other builder above hardcodes Bearer + JSON, which is fine for
     * Azure / Graph / ARM but wrong for HTTP webshells / SSTI targets. This
     * builder gives the caller full control - no auth is added, headers are
     * copied verbatim, Content-Type is whatever the caller specifies.
     *
     * @param url          Target URL (arbitrary host allowed)
     * @param headers      Raw headers (key -> value); pass empty for none
     * @param contentType  Value for Content-Type; pass empty to skip
     * @param timeoutMs    Transfer timeout in ms
     */
    static QNetworkRequest genericRequest(const QUrl &url,
                                           const QMap<QString, QString> &headers,
                                           const QByteArray &contentType,
                                           int timeoutMs = DEFAULT_TIMEOUT_MS);

    /**
     * @brief Parse Microsoft API error response
     *
     * Handles Graph API and Azure Management API error formats
     * @param reply The network reply to parse
     * @param responseBody Optional pre-read response body
     * @return Human-readable error message
     */
    static QString parseApiError(QNetworkReply *reply, const QByteArray &responseBody = QByteArray());

    /**
     * @brief Check if reply indicates rate limiting (HTTP 429)
     * @param reply The network reply
     * @return true if throttled
     */
    static bool isThrottled(QNetworkReply *reply);

    /**
     * @brief Get retry-after delay from response headers
     * @param reply The network reply
     * @return Delay in milliseconds, or 1000 if not specified
     */
    static int getRetryAfterMs(QNetworkReply *reply);

    /**
     * @brief Validate token audience matches expected resource
     * @param token JWT access token
     * @param expectedAudience Expected audience (e.g., "https://graph.microsoft.com")
     * @return true if audience matches
     */
    static bool validateTokenAudience(const QString &token, const QString &expectedAudience);

    /**
     * @brief Extract audience from JWT token
     * @param token JWT access token
     * @return Audience claim value
     */
    static QString extractTokenAudience(const QString &token);

    /**
     * @brief Add timeout to an existing QNetworkRequest
     * @param request The request to modify
     * @param timeoutMs Timeout in milliseconds (default 10000)
     */
    static void setRequestTimeout(QNetworkRequest &request, int timeoutMs = DEFAULT_TIMEOUT_MS);

    /**
     * @brief Check if a network reply is valid and successful
     * @param reply The network reply to check (can be nullptr)
     * @param errorOut Output parameter for error message if failed
     * @return true if reply is valid and HTTP status indicates success (2xx)
     */
    static bool isReplySuccess(QNetworkReply *reply, QString *errorOut = nullptr);

    /**
     * @brief Get HTTP status code from reply
     * @param reply The network reply
     * @return HTTP status code, or 0 if reply is null
     */
    static int getHttpStatus(QNetworkReply *reply);

    /**
     * @brief Get human-readable description of token audience mismatch
     * @param token The token that was provided
     * @param expectedAudience The expected audience
     * @return Error message describing the mismatch
     */
    static QString getAudienceMismatchError(const QString &token, const QString &expectedAudience);

    /**
     * @brief Common Graph API base URL
     */
    static const QString GRAPH_API_BASE;

    /**
     * @brief Common Azure Management API base URL
     */
    static const QString MANAGEMENT_API_BASE;

    /**
     * @brief Common Azure login endpoint
     */
    static const QString AZURE_LOGIN_BASE;

    /**
     * Common Azure resource audiences
     */
    static const QString AUDIENCE_GRAPH;
    static const QString AUDIENCE_MANAGEMENT;
    static const QString AUDIENCE_KEY_VAULT;
    static const QString AUDIENCE_STORAGE;
};

#endif // NETWORKHELPER_H
