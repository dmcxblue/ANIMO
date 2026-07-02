#include "CredentialLoginWindow.h"
#include "DashboardWindow.h"
#include "TokenStore.h"
#include "network/ClientTransport.h"
#include "../shared/Protocol.h"

#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QDebug>
#include <QApplication>
#include <QUuid>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFileInfo>
#include <QDir>
#include <QCoreApplication>

CredentialLoginWindow::CredentialLoginWindow(DashboardWindow *parentDashboard, QWidget *parent)
    : QWidget(parent), parentDashboard(parentDashboard)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Azure Login (Credentials)");
    setFixedSize(400, 250);
    setupUi();
}

void CredentialLoginWindow::setupUi() {
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel("Select resource and enter credentials"));

    resourceDropdown = new QComboBox(this);
    resourceDropdown->addItem("Azure Management (management.azure.com)");
    resourceDropdown->addItem("Microsoft Graph (graph.microsoft.com)");
    layout->addWidget(resourceDropdown);

    username = new QLineEdit(this);
    username->setPlaceholderText("e.g. alice@contoso.com");
    layout->addWidget(username);

    password = new QLineEdit(this);
    password->setEchoMode(QLineEdit::Password);
    password->setPlaceholderText("Azure Password");
    layout->addWidget(password);

    auto *loginButton = new QPushButton("Authenticate", this);
    loginButton->setObjectName(QStringLiteral("authButton"));
    connect(loginButton, &QPushButton::clicked, this, &CredentialLoginWindow::handleLogin);
    layout->addWidget(loginButton);

    auto *status = new QLabel(this);
    status->setObjectName(QStringLiteral("statusLabel"));
    status->setVisible(false);
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    layout->addWidget(status);

    setLayout(layout);
}

void CredentialLoginWindow::restoreUi() {
    if (auto *btn = findChild<QPushButton*>(QStringLiteral("authButton"))) {
        btn->setEnabled(true);
    }
    if (auto *lbl = findChild<QLabel*>(QStringLiteral("statusLabel"))) {
        lbl->setVisible(false);
        lbl->clear();
    }
    unsetCursor();
}

QObject* CredentialLoginWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (parentDashboard) {
        if (auto *t = parentDashboard->findChild<ClientTransport*>()) return t;
    }
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

QString CredentialLoginWindow::findMsalScript() const {
    // Look for the msal_auth.py script in various locations
    QString appDir = QCoreApplication::applicationDirPath();

    QStringList searchPaths = {
        // From build/client/ directory
        appDir + "/../../helpers/msal_auth.py",
        appDir + "/../helpers/msal_auth.py",
        appDir + "/helpers/msal_auth.py",
        appDir + "/msal_auth.py",
        // Relative paths from working directory
        "../../helpers/msal_auth.py",
        "../helpers/msal_auth.py",
        "helpers/msal_auth.py",
        "msal_auth.py"
    };

    for (const QString &path : searchPaths) {
        QFileInfo fi(path);
        if (fi.exists() && fi.isFile()) {
            qDebug() << "[CredentialLoginWindow] Found MSAL script at:" << fi.absoluteFilePath();
            return fi.absoluteFilePath();
        }
    }

    qWarning() << "[CredentialLoginWindow] Could not find msal_auth.py in any search path";
    qWarning() << "[CredentialLoginWindow] Application dir:" << appDir;
    return QString();
}

void CredentialLoginWindow::handleLogin() {
    const QString user = username->text().trimmed();
    const QString pass = password->text();

    if (user.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Azure Login", "Username and password required.");
        return;
    }

    // Reset session handling guard for new login attempt
    sessionHandled = false;

    // Set pendingResource based on dropdown selection
    int selectedIndex = resourceDropdown->currentIndex();
    if (selectedIndex == 1) {
        pendingResource = QStringLiteral("https://graph.microsoft.com");
    } else {
        pendingResource = QStringLiteral("https://management.azure.com");
    }

    pendingUsername = user;
    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QString resourceName = pendingResource.contains("graph") ? "Graph" : "Azure Management";
    qDebug() << "[CredentialLoginWindow] Starting MSAL auth for" << user << "resource:" << pendingResource;

    if (auto *btn = findChild<QPushButton*>(QStringLiteral("authButton"))) {
        btn->setEnabled(false);
    }
    if (auto *lbl = findChild<QLabel*>(QStringLiteral("statusLabel"))) {
        lbl->setText(QString("Authenticating %1 via %2...\n(Browser may open for MFA)").arg(user, resourceName));
        lbl->setVisible(true);
    }
    setCursor(Qt::BusyCursor);

    if (parentDashboard) {
        parentDashboard->logEvent(QString("[*] Authenticating %1 via %2 (MSAL)...").arg(user, resourceName));
    }

    launchMsalAuth();
}

void CredentialLoginWindow::launchMsalAuth() {
    QString scriptPath = findMsalScript();
    if (scriptPath.isEmpty()) {
        restoreUi();
        QMessageBox::critical(this, "Script Not Found",
            "Could not find msal_auth.py helper script.\n"
            "Make sure it exists in the helpers/ directory.");
        return;
    }

    qDebug() << "[CredentialLoginWindow] Using MSAL script:" << scriptPath;

    // Clean up any existing process
    if (msalProcess) {
        msalProcess->disconnect();
        msalProcess->kill();
        msalProcess->deleteLater();
    }

    msalProcess = new QProcess(this);

    connect(msalProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &CredentialLoginWindow::onMsalProcessFinished);
    connect(msalProcess, &QProcess::errorOccurred,
            this, &CredentialLoginWindow::onMsalProcessError);

    // Build arguments
    QStringList args;
    args << scriptPath;
    args << "--username" << pendingUsername;
    args << "--password" << password->text();
    args << "--resource" << pendingResource;

    qDebug() << "[CredentialLoginWindow] Launching:" << "python3" << args.join(" ");

    // Background process - no need to show in UI
    // if (parentDashboard) {
    //     parentDashboard->logEvent("[*] Launching Python MSAL authentication...");
    // }

    msalProcess->start("python3", args);
}

void CredentialLoginWindow::onMsalProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitStatus)

    QByteArray stdoutData = msalProcess->readAllStandardOutput();
    QByteArray stderrData = msalProcess->readAllStandardError();

    qDebug() << "[CredentialLoginWindow] MSAL process finished with exit code:" << exitCode;
    qDebug() << "[CredentialLoginWindow] stdout:" << stdoutData;
    if (!stderrData.isEmpty()) {
        qDebug() << "[CredentialLoginWindow] stderr:" << stderrData;
        // Log stderr to event log (it contains progress info)
        if (parentDashboard && !stderrData.trimmed().isEmpty()) {
            parentDashboard->logEvent(QString::fromUtf8(stderrData.trimmed()));
        }
    }

    handleMsalResult(stdoutData);
}

void CredentialLoginWindow::onMsalProcessError(QProcess::ProcessError error) {
    restoreUi();

    QString errorMsg;
    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = "Failed to start Python. Make sure python3 and msal are installed.\n"
                      "Install with: pip install msal";
            break;
        case QProcess::Crashed:
            errorMsg = "MSAL process crashed";
            break;
        case QProcess::Timedout:
            errorMsg = "MSAL process timed out";
            break;
        default:
            errorMsg = "MSAL process error";
            break;
    }

    qDebug() << "[CredentialLoginWindow] Process error:" << errorMsg;

    if (parentDashboard) {
        parentDashboard->logEvent(QString("[-] MSAL Error: %1").arg(errorMsg));
    }

    QMessageBox::critical(this, "Authentication Error", errorMsg);
}

void CredentialLoginWindow::handleMsalResult(const QByteArray &output) {
    // Parse JSON output from msal_auth.py
    QJsonDocument doc = QJsonDocument::fromJson(output);
    if (!doc.isObject()) {
        restoreUi();
        QString errorMsg = "Invalid response from MSAL script";
        if (parentDashboard) {
            parentDashboard->logEvent(QString("[-] %1").arg(errorMsg));
        }
        QMessageBox::critical(this, "Authentication Error", errorMsg);
        return;
    }

    QJsonObject obj = doc.object();
    QString status = obj.value("status").toString();

    if (status == "success") {
        QString accessToken = obj.value("access_token").toString();
        QString refreshToken = obj.value("refresh_token").toString();
        QString idToken = obj.value("id_token").toString();
        QString tenantId = obj.value("tenant_id").toString();
        QString upn = obj.value("upn").toString();

        if (upn.isEmpty()) {
            upn = pendingUsername;
        }

        qDebug() << "[CredentialLoginWindow] MSAL auth success for:" << upn;

        if (parentDashboard) {
            parentDashboard->logEvent(QString("[+] MSAL auth success for %1").arg(upn));
        }

        // Store pending tokens for logging after session creation
        pendingAccessToken = accessToken;
        pendingRefreshToken = refreshToken;
        pendingUser = upn;
        pendingTenantId = tenantId;

        if (auto *lbl = findChild<QLabel*>(QStringLiteral("statusLabel"))) {
            lbl->setText("Creating session...");
        }

        createSessionWithTokens(accessToken, refreshToken, tenantId, upn);

    } else if (status == "mfa_required") {
        // This shouldn't happen since msal_auth.py auto-fallbacks to interactive
        QString message = obj.value("message").toString("MFA required");
        restoreUi();
        if (parentDashboard) {
            parentDashboard->logEvent(QString("[!] MFA required: %1").arg(message));
        }
        QMessageBox::warning(this, "MFA Required", message);

    } else {
        // Error
        QString message = obj.value("message").toString("Authentication failed");
        restoreUi();
        if (parentDashboard) {
            parentDashboard->logEvent(QString("[-] Auth failed: %1").arg(message));
        }
        QMessageBox::critical(this, "Authentication Failed", message);
    }
}

void CredentialLoginWindow::createSessionWithTokens(const QString &accessToken,
                                                    const QString &refreshToken,
                                                    const QString &tenantId,
                                                    const QString &upn)
{
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        restoreUi();
        QMessageBox::critical(this, "Transport Missing", "No transport available.");
        return;
    }

    // Wire up response handling if not already done
    if (!hookConnected) {
        if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
            transportConnection = connect(typed, &ClientTransport::messageReceived, this,
                    [this](const QJsonObject &obj) {
                        const QString act = obj.value(Protocol::F_ACTION).toString();
                        const QString status = obj.value(Protocol::F_STATUS).toString();
                        const QString respRid = obj.value("rid").toString();
                        const QString sid = obj.value("sessionId").toString();

                        // Debug: log all received messages
                        qDebug() << "[CredentialLogin] Received message:"
                                 << "action=" << act
                                 << "status=" << status
                                 << "rid=" << respRid
                                 << "sessionId=" << sid
                                 << "pendingRid=" << pendingRid
                                 << "sessionHandled=" << sessionHandled;

                        // Filter by RID if both are present
                        if (!pendingRid.isEmpty() && !respRid.isEmpty() && respRid != pendingRid) {
                            qDebug() << "[CredentialLogin] Skipping message - RID mismatch";
                            return;
                        }

                        if (act == QStringLiteral("session_created")) {
                            // Guard against duplicate handling
                            if (sessionHandled) return;
                            sessionHandled = true;
                            pendingRid.clear();

                            // Disconnect to prevent stale connections
                            disconnect(transportConnection);
                            hookConnected = false;

                            const QString userName = obj.value("user").toString("Unknown");
                            const QString tid = obj.value("tenantId").toString("N/A");
                            const QString domain = obj.value("domain").toString("N/A");
                            const QString res = obj.value("resource").toString("N/A");

                            // Log token to server and set expiry if we have pending tokens
                            if (!pendingAccessToken.isEmpty()) {
                                logTokenToServer(sid, pendingAccessToken, pendingRefreshToken,
                                               pendingUser, pendingTenantId, pendingResource);

                                // Set token expiry for auto-renewal tracking
                                if (parentDashboard) {
                                    parentDashboard->setSessionTokenExpiry(sid, pendingAccessToken,
                                        pendingRefreshToken, pendingResource, pendingTenantId);
                                }

                                pendingAccessToken.clear();
                                pendingRefreshToken.clear();
                                pendingUser.clear();
                                pendingTenantId.clear();
                            }

                            if (parentDashboard) {
                                parentDashboard->addSessionRow(sid, userName, tid, domain, res);
                                parentDashboard->logEvent(
                                    QString("[+] Session created for %1 (ID: %2)").arg(userName, sid));
                            }
                            restoreUi();
                            QMessageBox::information(this, "Azure Login",
                                                     QString("Login success for %1\nTenant: %2\nSession: %3")
                                                     .arg(userName, tid, sid));
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

                            // Disconnect to prevent stale connections
                            disconnect(transportConnection);
                            hookConnected = false;

                            restoreUi();
                            const QString msg = obj.value("message").toString("Unknown error");
                            if (parentDashboard) {
                                parentDashboard->logEvent(QString("[-] Session creation failed: %1").arg(msg));
                            }
                            QMessageBox::critical(this, "Session Error", msg);
                            return;
                        }
                    });
            hookConnected = true;
        }
    }

    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QString domain = upn.contains('@') ? upn.section('@', 1, 1) : QStringLiteral("N/A");

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_NEW_SESSION);
    req.insert("mode",         QStringLiteral("tokens"));
    req.insert("accessToken",  accessToken);
    req.insert("refreshToken", refreshToken);
    req.insert("resource",     pendingResource);
    req.insert("user",         upn);
    req.insert("tenantId",     tenantId);
    req.insert("domain",       domain);
    req.insert("rid",          pendingRid);

    qDebug() << "[CredentialLogin] Sending new_session request:"
             << "mode=tokens"
             << "resource=" << pendingResource
             << "user=" << upn
             << "rid=" << pendingRid
             << "hasRefreshToken=" << !refreshToken.isEmpty();

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
        qDebug() << "[CredentialLogin] Request sent via typed transport";
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
        qDebug() << "[CredentialLogin] Request sent via invokeMethod";
    }
}

void CredentialLoginWindow::logTokenToServer(const QString &sessionId,
                                              const QString &accessToken,
                                              const QString &refreshToken,
                                              const QString &user,
                                              const QString &tenantId,
                                              const QString &resource)
{
    if (sessionId.isEmpty() || accessToken.isEmpty()) {
        return;
    }

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        qWarning() << "[CredentialLogin] Cannot log token: no transport found";
        return;
    }

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "msal_credential_login");
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

    // Mirror into TokenStore so plugin windows' UserSelectorWidget see this
    // user immediately, without waiting for a reconnect bootstrap.
    TokenInfo tokenInfo;
    tokenInfo.accessToken  = accessToken;
    tokenInfo.refreshToken = refreshToken;
    tokenInfo.upn          = user;
    tokenInfo.tenantId     = tenantId;
    tokenInfo.resource     = resource;
    TokenStore::instance()->storeToken(sessionId, tokenInfo);

    qDebug() << "[CredentialLogin] Token logged to server for session:" << sessionId;
}
