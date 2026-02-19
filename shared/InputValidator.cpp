#include "InputValidator.h"
#include <QStringList>

QRegularExpression InputValidator::emailRegex() {
    static QRegularExpression re(
        R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)",
        QRegularExpression::CaseInsensitiveOption
    );
    return re;
}

QRegularExpression InputValidator::guidRegex() {
    static QRegularExpression re(
        R"(^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$)"
    );
    return re;
}

QRegularExpression InputValidator::domainRegex() {
    static QRegularExpression re(
        R"(^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)"
    );
    return re;
}

bool InputValidator::isValidEmail(const QString &email) {
    if (email.isEmpty()) return false;
    return emailRegex().match(email.trimmed()).hasMatch();
}

bool InputValidator::isValidUPN(const QString &upn) {
    // UPN format is essentially the same as email
    return isValidEmail(upn);
}

bool InputValidator::isValidGUID(const QString &guid) {
    if (guid.isEmpty()) return false;
    return guidRegex().match(guid.trimmed()).hasMatch();
}

bool InputValidator::isValidTenantId(const QString &tenantId) {
    return isValidGUID(tenantId);
}

bool InputValidator::isValidDomain(const QString &domain) {
    if (domain.isEmpty()) return false;
    return domainRegex().match(domain.trimmed()).hasMatch();
}

bool InputValidator::isValidAzureResource(const QString &url) {
    if (url.isEmpty()) return false;

    QString trimmed = url.trimmed().toLower();

    // Common Azure resource URLs
    static const QStringList validResources = {
        "https://graph.microsoft.com",
        "https://management.azure.com",
        "https://management.core.windows.net",
        "https://vault.azure.net",
        "https://database.windows.net",
        "https://storage.azure.com",
        "https://outlook.office.com",
        "https://outlook.office365.com",
        "https://api.spaces.skype.com"
    };

    for (const QString &resource : validResources) {
        if (trimmed.startsWith(resource)) {
            return true;
        }
    }

    // Also accept *.microsoft.com and *.azure.com patterns
    if (trimmed.contains(".microsoft.com") || trimmed.contains(".azure.com") ||
        trimmed.contains(".windows.net") || trimmed.contains(".office.com") ||
        trimmed.contains(".office365.com")) {
        return true;
    }

    return false;
}

QString InputValidator::escapePsString(const QString &input) {
    // In PS single-quoted strings, the ONLY special character is the single quote
    // itself (doubled to escape). We also strip null bytes and newlines to prevent
    // injection via string termination.
    QString escaped;
    escaped.reserve(input.size() + 16);
    for (const QChar &ch : input) {
        if (ch == QLatin1Char('\'')) {
            escaped.append(QLatin1String("''"));
        } else if (ch == QLatin1Char('\0')) {
            continue;
        } else if (ch == QLatin1Char('\n') || ch == QLatin1Char('\r')) {
            continue;
        } else {
            escaped.append(ch);
        }
    }
    return escaped;
}

QString InputValidator::sanitize(const QString &input) {
    QString result = input;

    // Remove null bytes
    result.remove(QChar('\0'));

    // Remove control characters except newline and tab
    QString cleaned;
    cleaned.reserve(result.size());
    for (const QChar &c : result) {
        if (c.isPrint() || c == '\n' || c == '\t' || c == '\r') {
            cleaned.append(c);
        }
    }

    return cleaned.trimmed();
}

QString InputValidator::escapeOData(const QString &input) {
    // OData requires single quotes to be escaped by doubling them
    QString result = input;
    result.replace("'", "''");
    return result;
}

QString InputValidator::sanitizeForOData(const QString &input) {
    // First sanitize, then escape for OData
    return escapeOData(sanitize(input));
}

int InputValidator::validateEmailList(const QString &input,
                                       QStringList &validEmails,
                                       QStringList &invalidLines) {
    validEmails.clear();
    invalidLines.clear();

    QStringList lines = input.split(QRegularExpression("[\r\n]+"), Qt::SkipEmptyParts);

    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        if (trimmed.isEmpty()) continue;

        if (isValidEmail(trimmed)) {
            validEmails.append(trimmed);
        } else {
            invalidLines.append(trimmed);
        }
    }

    return validEmails.size();
}
