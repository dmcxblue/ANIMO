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
    setMinimumSize(400, 250);
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
    loginButton->setDefault(true);
    connect(loginButton, &QPushButton::clicked, this, &CredentialLoginWindow::handleLogin);
    layout->addWidget(loginButton);

    connect(username, &QLineEdit::returnPressed, this, &CredentialLoginWindow::handleLogin);
    connect(password, &QLineEdit::returnPressed, this, &CredentialLoginWindow::handleLogin);

    auto *status = new QLabel(this);
    status->setObjectName(QStringLiteral("statusLabel"));
    status->setVisible(false);
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    layout->addWidget(status);

    setLayout(layout);
}

void CredentialLoginWindow::restoreUi() {
    if (auto *btn = findChild<QPushButton*>(QStringLiteral("authButton")))
        btn->setEnabled(true);
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

// ============================================================================
// Login routing
// ============================================================================

void CredentialLoginWindow::handleLogin() {
    const QString user = username->text().trimmed();
    const QString pass = password->text();

    if (user.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Azure Login", "Username and password required.");
        return;
    }

    sessionHandled = false;

    if (resourceDropdown->currentIndex() == 1)
        pendingResource = QStringLiteral("https://graph.microsoft.com");
    else
        pendingResource = QStringLiteral("https://management.azure.com");

    pendingUsername = user;
    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QString resourceName = pendingResource.contains("graph") ? "Graph" : "Azure Management";

    if (auto *btn = findChild<QPushButton*>(QStringLiteral("authButton")))
        btn->setEnabled(false);
    if (auto *lbl = findChild<QLabel*>(QStringLiteral("statusLabel"))) {
        lbl->setText(QString("Authenticating %1 via %2...").arg(user, resourceName));
        lbl->setVisible(true);
    }
    setCursor(Qt::BusyCursor);

    if (parentDashboard)
        parentDashboard->logEvent(QString("[*] Authenticating %1 via %2 (MSAL)...").arg(user, resourceName));
    launchMsalAuth();
}

// ============================================================================
// Server-side credential login (Management)
// ============================================================================

void CredentialLoginWindow::wireTransportHook() {
    QObject *transportObj = locateTransport();
    if (!transportObj) return;
    if (hookConnected) return;

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        transportConnection = connect(typed, &ClientTransport::messageReceived, this,
                [this](const QJsonObject &obj) {
                    const QString act = obj.value(Protocol::F_ACTION).toString();
                    const QString status = obj.value(Protocol::F_STATUS).toString();
                    const QString respRid = obj.value("rid").toString();
                    const QString sid = obj.value("sessionId").toString();

                    if (!pendingRid.isEmpty() && !respRid.isEmpty() && respRid != pendingRid)
                        return;

                    if (act == QStringLiteral("session_created")) {
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();
                        disconnect(transportConnection);
                        hookConnected = false;

                        const QString userName = obj.value("user").toString("Unknown");
                        const QString tid = obj.value("tenantId").toString("N/A");
                        const QString domain = obj.value("domain").toString("N/A");
                        const QString res = obj.value("resource").toString("N/A");

                        if (!pendingAccessToken.isEmpty()) {
                            // MSAL path: log tokens captured client-side
                            logTokenToServer(sid, pendingAccessToken, pendingRefreshToken,
                                           pendingUser, pendingTenantId, pendingResource);
                            if (parentDashboard) {
                                parentDashboard->setSessionTokenExpiry(sid, pendingAccessToken,
                                    pendingRefreshToken, pendingResource, pendingTenantId);
                            }
                            pendingAccessToken.clear();
                            pendingRefreshToken.clear();
                            pendingUser.clear();
                            pendingTenantId.clear();
                        } else {
                            // Server-side credential path: the login script emits a
                            // token via __ANIMO_TOKEN__ which the server forwards here.
                            TokenInfo info;
                            info.upn       = userName;
                            info.tenantId  = tid;
                            info.resource  = res;
                            const QString serverToken = obj.value("accessToken").toString();
                            if (!serverToken.isEmpty()) {
                                info.accessToken = serverToken;
                                logTokenToServer(sid, serverToken, QString(),
                                                 userName, tid, res);
                            }
                            TokenStore::instance()->storeToken(sid, info);
                        }

                        // Store storage token if the server exchanged one via refresh
                        const QString stToken = obj.value("storageToken").toString();
                        if (!stToken.isEmpty()) {
                            TokenInfo stInfo;
                            stInfo.accessToken = stToken;
                            stInfo.upn         = userName;
                            stInfo.tenantId    = tid;
                            stInfo.resource    = QStringLiteral("https://storage.azure.com");
                            TokenStore::instance()->storeToken(sid, stInfo);
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

                    const bool isError = (act == QStringLiteral("error")) ||
                                        (status == Protocol::STATUS_ERR);
                    if (isError) {
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();
                        disconnect(transportConnection);
                        hookConnected = false;
                        restoreUi();
                        const QString msg = obj.value("message").toString("Unknown error");
                        if (parentDashboard)
                            parentDashboard->logEvent(QString("[-] Session creation failed: %1").arg(msg));
                        QMessageBox::critical(this, "Session Error", msg);
                        return;
                    }
                });
        hookConnected = true;
    }
}

void CredentialLoginWindow::sendCredentialLogin() {
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        restoreUi();
        QMessageBox::critical(this, "Transport Missing", "No transport available.");
        return;
    }

    wireTransportHook();

    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString user = username->text().trimmed();
    const QString domain = user.contains('@') ? user.section('@', 1, 1) : QStringLiteral("N/A");

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_NEW_SESSION);
    req.insert("mode",     QStringLiteral("credentials"));
    req.insert("username", user);
    req.insert("password", password->text());
    req.insert("resource", pendingResource);
    req.insert("user",     user);
    req.insert("domain",   domain);
    req.insert("rid",      pendingRid);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj))
        typed->sendJson(req);
    else
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
}

// ============================================================================
// MSAL interactive login (Graph / MFA)
// ============================================================================

QString CredentialLoginWindow::findMsalScript() const {
    QString appDir = QCoreApplication::applicationDirPath();
    QStringList searchPaths = {
        appDir + "/../../helpers/msal_auth.py",
        appDir + "/../helpers/msal_auth.py",
        appDir + "/helpers/msal_auth.py",
        appDir + "/msal_auth.py",
        "../../helpers/msal_auth.py",
        "../helpers/msal_auth.py",
        "helpers/msal_auth.py",
        "msal_auth.py"
    };
    for (const QString &path : searchPaths) {
        QFileInfo fi(path);
        if (fi.exists() && fi.isFile())
            return fi.absoluteFilePath();
    }
    return QString();
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

    QStringList args;
    args << scriptPath;
    args << "--username" << pendingUsername;
    args << "--password" << password->text();
    args << "--resource" << pendingResource;

    msalProcess->start("python3", args);
}

void CredentialLoginWindow::onMsalProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitStatus)

    QByteArray stdoutData = msalProcess->readAllStandardOutput();
    QByteArray stderrData = msalProcess->readAllStandardError();

    if (!stderrData.isEmpty() && parentDashboard && !stderrData.trimmed().isEmpty())
        parentDashboard->logEvent(QString::fromUtf8(stderrData.trimmed()));

    if (exitCode != 0 && stdoutData.isEmpty()) {
        restoreUi();
        QString err = stderrData.isEmpty() ? "MSAL process failed" : QString::fromUtf8(stderrData);
        if (parentDashboard)
            parentDashboard->logEvent(QString("[-] MSAL error: %1").arg(err));
        QMessageBox::critical(this, "Authentication Error", err);
        return;
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
        case QProcess::Crashed:  errorMsg = "MSAL process crashed"; break;
        case QProcess::Timedout: errorMsg = "MSAL process timed out"; break;
        default:                 errorMsg = "MSAL process error"; break;
    }
    if (parentDashboard)
        parentDashboard->logEvent(QString("[-] MSAL Error: %1").arg(errorMsg));
    QMessageBox::critical(this, "Authentication Error", errorMsg);
}

void CredentialLoginWindow::handleMsalResult(const QByteArray &output) {
    QJsonDocument doc = QJsonDocument::fromJson(output);
    if (!doc.isObject()) {
        restoreUi();
        if (parentDashboard)
            parentDashboard->logEvent("[-] Invalid response from MSAL script");
        QMessageBox::critical(this, "Authentication Error", "Invalid response from MSAL script");
        return;
    }

    QJsonObject obj = doc.object();
    QString status = obj.value("status").toString();

    if (status == "success") {
        QString accessToken = obj.value("access_token").toString();
        QString refreshToken = obj.value("refresh_token").toString();
        QString tenantId = obj.value("tenant_id").toString();
        QString upn = obj.value("upn").toString();
        if (upn.isEmpty()) upn = pendingUsername;

        if (parentDashboard)
            parentDashboard->logEvent(QString("[+] MSAL auth success for %1").arg(upn));

        pendingAccessToken = accessToken;
        pendingRefreshToken = refreshToken;
        pendingUser = upn;
        pendingTenantId = tenantId;

        if (auto *lbl = findChild<QLabel*>(QStringLiteral("statusLabel")))
            lbl->setText("Creating session...");

        createSessionWithTokens(accessToken, refreshToken, tenantId, upn);

    } else if (status == "mfa_required") {
        QString message = obj.value("message").toString("MFA required");
        restoreUi();
        if (parentDashboard)
            parentDashboard->logEvent(QString("[!] MFA required: %1").arg(message));
        QMessageBox::warning(this, "MFA Required", message);

    } else {
        QString message = obj.value("message").toString("Authentication failed");
        restoreUi();
        if (parentDashboard)
            parentDashboard->logEvent(QString("[-] Auth failed: %1").arg(message));
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

    wireTransportHook();

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

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj))
        typed->sendJson(req);
    else
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
}

void CredentialLoginWindow::logTokenToServer(const QString &sessionId,
                                              const QString &accessToken,
                                              const QString &refreshToken,
                                              const QString &user,
                                              const QString &tenantId,
                                              const QString &resource)
{
    if (sessionId.isEmpty() || accessToken.isEmpty())
        return;

    QObject *transportObj = locateTransport();
    if (!transportObj) return;

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "msal_credential_login");
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty()) req.insert("refreshToken", refreshToken);
    if (!user.isEmpty()) req.insert("user", user);
    if (!tenantId.isEmpty()) req.insert("tenantId", tenantId);
    if (!resource.isEmpty()) req.insert("resource", resource);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj))
        typed->sendJson(req);
    else
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));

    TokenInfo tokenInfo;
    tokenInfo.accessToken  = accessToken;
    tokenInfo.refreshToken = refreshToken;
    tokenInfo.upn          = user;
    tokenInfo.tenantId     = tenantId;
    tokenInfo.resource     = resource;
    TokenStore::instance()->storeToken(sessionId, tokenInfo);
}
