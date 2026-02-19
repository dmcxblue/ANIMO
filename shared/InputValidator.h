#ifndef INPUT_VALIDATOR_H
#define INPUT_VALIDATOR_H

#include <QString>
#include <QRegularExpression>

/**
 * Input validation utilities for ANIMO
 * Provides validation for emails, UPNs, GUIDs, and other Azure-related inputs
 */
class InputValidator {
public:
    /**
     * Validate email address format
     * @param email The email to validate
     * @return true if valid email format
     */
    static bool isValidEmail(const QString &email);

    /**
     * Validate User Principal Name (UPN) format
     * UPN format is similar to email: user@domain
     * @param upn The UPN to validate
     * @return true if valid UPN format
     */
    static bool isValidUPN(const QString &upn);

    /**
     * Validate GUID/UUID format
     * Accepts formats: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     * @param guid The GUID to validate
     * @return true if valid GUID format
     */
    static bool isValidGUID(const QString &guid);

    /**
     * Validate Azure Tenant ID (GUID format)
     * @param tenantId The tenant ID to validate
     * @return true if valid tenant ID format
     */
    static bool isValidTenantId(const QString &tenantId);

    /**
     * Validate domain name format
     * @param domain The domain to validate
     * @return true if valid domain format
     */
    static bool isValidDomain(const QString &domain);

    /**
     * Validate Azure resource URL
     * @param url The resource URL to validate
     * @return true if valid Azure resource URL
     */
    static bool isValidAzureResource(const QString &url);

    /**
     * Escape string for safe use inside PowerShell single-quoted strings.
     * Doubles single quotes, strips null bytes and newlines.
     * @param input The input to escape
     * @return PowerShell-safe string (wrap in single quotes when using)
     */
    static QString escapePsString(const QString &input);

    /**
     * Sanitize input string - remove potentially dangerous characters
     * @param input The input to sanitize
     * @return Sanitized string
     */
    static QString sanitize(const QString &input);

    /**
     * Escape string for use in OData filter queries
     * Escapes single quotes by doubling them (' -> '')
     * @param input The input to escape
     * @return OData-safe string
     */
    static QString escapeOData(const QString &input);

    /**
     * Sanitize and escape for OData filter
     * Combines sanitize() and escapeOData()
     * @param input The input to sanitize and escape
     * @return Safe string for OData filters
     */
    static QString sanitizeForOData(const QString &input);

    /**
     * Validate and sanitize a list of emails (one per line)
     * @param input Multi-line string of emails
     * @param validEmails Output list of valid emails
     * @param invalidLines Output list of invalid lines (for error reporting)
     * @return Number of valid emails found
     */
    static int validateEmailList(const QString &input,
                                  QStringList &validEmails,
                                  QStringList &invalidLines);

private:
    static QRegularExpression emailRegex();
    static QRegularExpression guidRegex();
    static QRegularExpression domainRegex();
};

#endif // INPUT_VALIDATOR_H
