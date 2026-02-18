#include "TokenLoginWindow.h"
#include "DashboardWindow.h"
#include "TokenStore.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QApplication>
#include <QUuid>

#include "network/ClientTransport.h"
#include "../shared/Protocol.h"

// ——— helpers ———
static inline QString b64UrlDecodeToJsonField(const QString &jwt, const char *field) {
    const QStringList parts = jwt.split('.');
    if (parts.size() < 2) return QString();
    QByteArray payload = parts.at(1).toUtf8();
    // pad for base64url
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));
    payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
    QJsonObject o = QJsonDocument::fromJson(payload).object();
    return o.value(field).toString();
}

TokenLoginWindow::TokenLoginWindow(DashboardWindow *parentDashboard, QWidget *parent)
    : QWidget(parent), parentDashboard(parentDashboard) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Azure Login (Access Token)");
    setFixedSize(520, 520);
    setupUi();
    wireTransport();
}

void TokenLoginWindow::setupUi() {
    auto *layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Paste your Access Token:"));
    accessEdit = new QTextEdit(this);
    accessEdit->setPlaceholderText("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz...");
    accessEdit->setAcceptRichText(false);
    accessEdit->setMinimumHeight(90);
    layout->addWidget(accessEdit);

    layout->addWidget(new QLabel("Paste your Refresh Token (required for Connect-AzAccount):"));
    refreshEdit = new QTextEdit(this);
    refreshEdit->setPlaceholderText("Optional for Graph; required for Az.");
    refreshEdit->setAcceptRichText(false);
    refreshEdit->setMinimumHeight(70);
    layout->addWidget(refreshEdit);

    // Status
    statusLabel = new QLabel(this);
    statusLabel->setVisible(false);
    layout->addWidget(statusLabel);

    // Start
    startBtn = new QPushButton("Start Session", this);
    layout->addWidget(startBtn);

    connect(startBtn, &QPushButton::clicked, this, [this](){
        const QString access  = accessEdit->toPlainText().trimmed();
        const QString refresh = refreshEdit->toPlainText().trimmed();

        if (access.isEmpty()) {
            QMessageBox::warning(this, "Missing Token", "Please paste a valid access token.");
            return;
        }

        // Decode required claims in the background (no UI fields)
        auto safeClaim = [&](const char *name)->QString {
            QString v = b64UrlDecodeToJsonField(access, name);
            return v.trimmed();
        };

        QString aud   = safeClaim("aud");
        QString upn   = safeClaim("upn");
        QString tid   = safeClaim("tid");
        QString domain = (upn.contains('@') ? upn.section('@', 1, 1)
                                            : QStringLiteral("UnknownDomain"));

        if (aud.isEmpty() && upn.isEmpty() && tid.isEmpty()) {
            QMessageBox::critical(this, "Invalid Token",
                                  "Failed to parse required claims from the access token.");
            return;
        }

        startBtn->setEnabled(false);
        statusLabel->setText("Starting session…");
        statusLabel->setVisible(true);
        pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);

        // Store tokens for logging after session creation
        pendingAccessToken = access;
        pendingRefreshToken = refresh;
        pendingUser = upn;
        pendingTenantId = tid;
        pendingResource = aud.isEmpty() ? QStringLiteral("https://graph.microsoft.com") : aud;

        sendNewSessionWithTokens(
            access,
            refresh,
            aud,
            upn,
            tid,
            domain
        );
    });

    setLayout(layout);
}

QObject* TokenLoginWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (parentDashboard) {
        if (auto *t = parentDashboard->findChild<ClientTransport*>()) return t;
    }
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    if (parentDashboard) {
        if (auto *o = parentDashboard->findChild<QObject*>("ClientTransport", Qt::FindChildrenRecursively)) return o;
    }
    return nullptr;
}

void TokenLoginWindow::wireTransport() {
    QObject *transportObj = locateTransport();
    if (!transportObj || hookConnected) return;
    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        connect(typed, &ClientTransport::messageReceived, this,
                [this](const QJsonObject &obj) {
                    const QString act = obj.value(Protocol::F_ACTION).toString();
                    const QString status = obj.value(Protocol::F_STATUS).toString();
                    const QString respRid = obj.value("rid").toString();
                    const QString sid = obj.value("sessionId").toString();

                    // Match only our pending rid if present; allow rid-less terminal success
                    if (!pendingRid.isEmpty() && !respRid.isEmpty() && respRid != pendingRid)
                        return;

                    if (act == QStringLiteral("session_created")) {
                        // Guard against duplicate handling
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();
                        startBtn->setEnabled(true);
                        statusLabel->setVisible(false);
                        const QString user = obj.value("user").toString("Unknown");
                        const QString tenantId = obj.value("tenantId").toString("N/A");
                        const QString domain = obj.value("domain").toString("N/A");
                        const QString res = obj.value("resource").toString("N/A");

                        // Store token in TokenStore for plugin auto-linking
                        TokenInfo tokenInfo;
                        tokenInfo.accessToken = pendingAccessToken;
                        tokenInfo.refreshToken = pendingRefreshToken;
                        tokenInfo.resource = pendingResource;
                        tokenInfo.tenantId = pendingTenantId;
                        tokenInfo.upn = pendingUser;
                        TokenStore::instance()->storeToken(sid, tokenInfo);

                        // Log token to database
                        logTokenToServer(sid, pendingAccessToken, pendingRefreshToken,
                                       pendingUser, pendingTenantId, pendingResource);

                        // Set token expiry for auto-renewal tracking
                        if (parentDashboard) {
                            parentDashboard->setSessionTokenExpiry(sid, pendingAccessToken,
                                pendingRefreshToken, pendingResource, pendingTenantId);
                        }

                        // Clear pending tokens
                        pendingAccessToken.clear();
                        pendingRefreshToken.clear();
                        pendingUser.clear();
                        pendingTenantId.clear();
                        pendingResource.clear();

                        if (parentDashboard) {
                            parentDashboard->addSessionRow(sid, user, tenantId, domain, res);
                            parentDashboard->logEvent(
                                QString("[+] Session created for %1 (ID: %2)").arg(user, sid));
                            parentDashboard->logEvent("[*] Token stored for auto-linking");
                        }
                        QMessageBox::information(this, "Azure Login",
                                                 QString("Login success for %1\nTenant: %2\nSession: %3")
                                                 .arg(user, tenantId, sid));
                        close();
                        return;
                    }

                    // Check for error via action OR status field
                    const bool isError = (act == QStringLiteral("error")) ||
                                        (status == Protocol::STATUS_ERR);
                    if (isError) {
                        // Guard against duplicate handling
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();
                        startBtn->setEnabled(true);
                        statusLabel->setVisible(false);
                        const QString msg = obj.value("message").toString("Unknown error");
                        if (parentDashboard) {
                            parentDashboard->logEvent(QString("[-] Token login failed: %1").arg(msg));
                        }
                        QMessageBox::critical(this, "Login Failed", msg);
                        return;
                    }
                });
        hookConnected = true;
    }
}

void TokenLoginWindow::sendNewSessionWithTokens(const QString &accessToken,
                                                const QString &refreshToken,
                                                const QString &aud,
                                                const QString &upn,
                                                const QString &tenantId,
                                                const QString &domain)
{
    // Reset session handling guard for new login attempt
    sessionHandled = false;

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        startBtn->setEnabled(true);
        statusLabel->setVisible(false);
        QMessageBox::critical(this, "Transport Missing",
                              "No ClientTransport found. Is the server connection established?");
        return;
    }

    // Determine resource: default to Graph if aud empty
    const QString resource = aud.isEmpty() ? QStringLiteral("https://graph.microsoft.com") : aud;

    // Build request (mode = tokens)
    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_NEW_SESSION);
    req.insert("mode",            QStringLiteral("tokens"));
    req.insert("resource",        resource);
    req.insert("rid",             pendingRid);
    req.insert("accessToken",     accessToken);
    if (!refreshToken.isEmpty()) req.insert("refreshToken", refreshToken);
    if (!upn.isEmpty())          req.insert("user", upn);
    if (!tenantId.isEmpty())     req.insert("tenantId", tenantId);
    if (!domain.isEmpty())       req.insert("domain", domain);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }
}

void TokenLoginWindow::logTokenToServer(const QString &sessionId,
                                        const QString &accessToken,
                                        const QString &refreshToken,
                                        const QString &user,
                                        const QString &tenantId,
                                        const QString &resource)
{
    if (sessionId.isEmpty() || accessToken.isEmpty()) {
        return; // Nothing to log
    }

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        qWarning() << "[TokenLogin] Cannot log token: no transport found";
        return;
    }

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "token_login");
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty()) req.insert("refreshToken", refreshToken);
    if (!user.isEmpty()) req.insert("user", user);
    if (!tenantId.isEmpty()) req.insert("tenantId", tenantId);
    if (!resource.isEmpty()) req.insert("resource", resource);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }

    qDebug() << "[TokenLogin] Token logged to server for session:" << sessionId;
}
