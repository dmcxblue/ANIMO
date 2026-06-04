#include "SPNLoginWindow.h"
#include "DashboardWindow.h"
#include "TokenStore.h"
#include "network/ClientTransport.h"
#include "../shared/Protocol.h"

#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QApplication>
#include <QUuid>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QJsonDocument>

SPNLoginWindow::SPNLoginWindow(DashboardWindow *parentDashboard, QWidget *parent)
    : QWidget(parent), parentDashboard(parentDashboard),
      net(new QNetworkAccessManager(this))
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Azure Login (Service Principal)");
    setFixedSize(440, 320);
    setupUi();
    wireTransport();
}

void SPNLoginWindow::closeEvent(QCloseEvent *event) {
    for (QNetworkReply *reply : activeReplies) {
        if (reply) {
            reply->abort();
            reply->deleteLater();
        }
    }
    activeReplies.clear();
    QWidget::closeEvent(event);
}

void SPNLoginWindow::setupUi() {
    auto *layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Select resource and enter Service Principal credentials:"));

    resourceDropdown = new QComboBox(this);
    resourceDropdown->addItem("Azure Management (management.azure.com)",
                              QStringLiteral("https://management.azure.com"));
    resourceDropdown->addItem("Microsoft Graph (graph.microsoft.com)",
                              QStringLiteral("https://graph.microsoft.com"));
    resourceDropdown->addItem("Key Vault (vault.azure.net)",
                              QStringLiteral("https://vault.azure.net"));
    resourceDropdown->addItem("Azure Storage (storage.azure.com)",
                              QStringLiteral("https://storage.azure.com"));
    resourceDropdown->addItem("SQL Database (database.windows.net)",
                              QStringLiteral("https://database.windows.net"));
    layout->addWidget(resourceDropdown);

    appIdEdit = new QLineEdit(this);
    appIdEdit->setPlaceholderText("Application (Client) ID");
    layout->addWidget(appIdEdit);

    secretEdit = new QLineEdit(this);
    secretEdit->setEchoMode(QLineEdit::Password);
    secretEdit->setPlaceholderText("Client Secret");
    layout->addWidget(secretEdit);

    tenantIdEdit = new QLineEdit(this);
    tenantIdEdit->setPlaceholderText("Tenant ID");
    layout->addWidget(tenantIdEdit);

    loginBtn = new QPushButton("Authenticate", this);
    layout->addWidget(loginBtn);

    statusLabel = new QLabel(this);
    statusLabel->setVisible(false);
    statusLabel->setWordWrap(true);
    layout->addWidget(statusLabel);

    connect(loginBtn, &QPushButton::clicked, this, [this]() {
        const QString appId    = appIdEdit->text().trimmed();
        const QString secret   = secretEdit->text();
        const QString tenantId = tenantIdEdit->text().trimmed();
        const QString resource = resourceDropdown->currentData().toString();

        if (appId.isEmpty() || secret.isEmpty() || tenantId.isEmpty()) {
            QMessageBox::warning(this, "SPN Login",
                                 "App ID, Client Secret, and Tenant ID are all required.");
            return;
        }

        sessionHandled = false;
        pendingResource = resource;
        pendingAppId = appId;
        pendingTenantId = tenantId;

        loginBtn->setEnabled(false);
        statusLabel->setText("Authenticating as Service Principal...");
        statusLabel->setVisible(true);
        setCursor(Qt::BusyCursor);

        if (parentDashboard) {
            QString label = resourceDropdown->currentText().section('(', 0, 0).trimmed();
            parentDashboard->logEvent(
                QString("[*] Authenticating SPN %1 → %2 in tenant %3...")
                    .arg(appId, label, tenantId));
        }

        // Azure Management uses PowerShell flow (sets up Az context for cmdlets)
        // Everything else uses direct OAuth2 client_credentials grant
        if (resource.contains("management.azure.com")) {
            authenticateViaPowerShell(appId, secret, tenantId);
        } else {
            authenticateClientCredentials(appId, secret, tenantId, resource);
        }
    });

    setLayout(layout);
}

void SPNLoginWindow::restoreUi() {
    loginBtn->setEnabled(true);
    statusLabel->setVisible(false);
    unsetCursor();
}

// ============================================================================
// OAuth2 client_credentials flow (Graph, Key Vault, Storage, SQL)
// ============================================================================

void SPNLoginWindow::authenticateClientCredentials(const QString &appId,
                                                    const QString &secret,
                                                    const QString &tenantId,
                                                    const QString &resource)
{
    // v2.0 endpoint uses scope with /.default suffix
    QString scope = resource;
    if (!scope.endsWith('/')) scope.append('/');
    scope.append(".default");

    QString tokenUrl = QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token")
                           .arg(tenantId);

    QNetworkRequest req{QUrl(tokenUrl)};
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    req.setRawHeader("User-Agent", "Mozilla/5.0");

    QUrlQuery form;
    form.addQueryItem("grant_type", "client_credentials");
    form.addQueryItem("client_id", appId);
    form.addQueryItem("client_secret", secret);
    form.addQueryItem("scope", scope);

    QNetworkReply *reply = net->post(req, form.query(QUrl::FullyEncoded).toUtf8());
    if (!reply) {
        restoreUi();
        QMessageBox::critical(this, "Network Error", "Failed to create token request.");
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, resource, appId, tenantId]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            restoreUi();
            QString err = reply->errorString();
            if (parentDashboard) {
                parentDashboard->logEvent(QString("[-] SPN token request failed: %1").arg(err));
            }
            QMessageBox::critical(this, "SPN Login Failed",
                                  QString("Network error: %1").arg(err));
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();

        if (obj.contains("error")) {
            restoreUi();
            QString errorDesc = obj.value("error_description")
                                   .toString(obj.value("error").toString());
            if (parentDashboard) {
                parentDashboard->logEvent(QString("[-] SPN auth error: %1").arg(errorDesc));
            }
            QMessageBox::critical(this, "SPN Login Failed", errorDesc);
            return;
        }

        QString accessToken = obj.value("access_token").toString();
        if (accessToken.isEmpty()) {
            restoreUi();
            QMessageBox::critical(this, "SPN Login Failed", "No access token in response.");
            return;
        }

        if (parentDashboard) {
            parentDashboard->logEvent(
                QString("[+] SPN token acquired for %1").arg(resource));
        }

        // Create session via tokens mode
        createSessionWithToken(accessToken, resource, appId, tenantId);
    });
}

void SPNLoginWindow::createSessionWithToken(const QString &accessToken,
                                             const QString &resource,
                                             const QString &appId,
                                             const QString &tenantId)
{
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        restoreUi();
        QMessageBox::critical(this, "Transport Missing",
                              "No ClientTransport found. Is the server connection established?");
        return;
    }

    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_NEW_SESSION);
    req.insert("mode",         QStringLiteral("tokens"));
    req.insert("accessToken",  accessToken);
    req.insert("resource",     resource);
    req.insert("user",         appId);
    req.insert("tenantId",     tenantId);
    req.insert("domain",       QStringLiteral("ServicePrincipal"));
    req.insert("rid",          pendingRid);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }
}

// ============================================================================
// PowerShell flow (Azure Management — sets up Az context)
// ============================================================================

void SPNLoginWindow::authenticateViaPowerShell(const QString &appId,
                                                const QString &secret,
                                                const QString &tenantId)
{
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        restoreUi();
        QMessageBox::critical(this, "Transport Missing",
                              "No ClientTransport found. Is the server connection established?");
        return;
    }

    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_NEW_SESSION);
    req.insert("mode",         QStringLiteral("spn"));
    req.insert("resource",     QStringLiteral("https://management.azure.com"));
    req.insert("appId",        appId);
    req.insert("clientSecret", secret);
    req.insert("tenantId",     tenantId);
    req.insert("rid",          pendingRid);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }
}

// ============================================================================
// Transport
// ============================================================================

QObject* SPNLoginWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (parentDashboard) {
        if (auto *t = parentDashboard->findChild<ClientTransport*>()) return t;
    }
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void SPNLoginWindow::wireTransport() {
    QObject *transportObj = locateTransport();
    if (!transportObj || hookConnected) return;

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        connect(typed, &ClientTransport::messageReceived, this,
                [this](const QJsonObject &obj) {
                    const QString act     = obj.value(Protocol::F_ACTION).toString();
                    const QString status  = obj.value(Protocol::F_STATUS).toString();
                    const QString respRid = obj.value("rid").toString();
                    const QString sid     = obj.value("sessionId").toString();

                    if (!pendingRid.isEmpty() && !respRid.isEmpty() && respRid != pendingRid)
                        return;

                    if (act == QStringLiteral("session_created")) {
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();

                        restoreUi();

                        const QString user     = obj.value("user").toString("Unknown");
                        const QString tenantId = obj.value("tenantId").toString("N/A");
                        const QString domain   = obj.value("domain").toString("N/A");
                        const QString res      = obj.value("resource").toString("N/A");
                        const QString accessToken = obj.value("accessToken").toString();

                        // Store token in TokenStore and log to server if present
                        if (!accessToken.isEmpty()) {
                            TokenInfo tokenInfo;
                            tokenInfo.accessToken = accessToken;
                            tokenInfo.resource = res;
                            tokenInfo.tenantId = tenantId;
                            tokenInfo.upn = user;
                            TokenStore::instance()->storeToken(sid, tokenInfo);

                            logTokenToServer(sid, accessToken, user, tenantId, res);

                            if (parentDashboard) {
                                parentDashboard->setSessionTokenExpiry(
                                    sid, accessToken, QString(), res, tenantId);
                            }
                        }

                        if (parentDashboard) {
                            parentDashboard->addSessionRow(sid, user, tenantId, domain, res);
                            parentDashboard->logEvent(
                                QString("[+] SPN session created for %1 (ID: %2)").arg(user, sid));
                            if (!accessToken.isEmpty()) {
                                parentDashboard->logEvent("[*] Token stored for auto-linking");
                            }
                        }

                        QMessageBox::information(this, "SPN Login",
                            QString("Login success for SPN %1\nResource: %2\nTenant: %3\nSession: %4")
                                .arg(user, res, tenantId, sid));
                        close();
                        return;
                    }

                    const bool isError = (act == QStringLiteral("error")) ||
                                         (status == Protocol::STATUS_ERR);
                    if (isError) {
                        if (sessionHandled) return;
                        sessionHandled = true;
                        pendingRid.clear();

                        restoreUi();

                        const QString msg = obj.value("message").toString("Unknown error");
                        if (parentDashboard) {
                            parentDashboard->logEvent(
                                QString("[-] SPN login failed: %1").arg(msg));
                        }
                        QMessageBox::critical(this, "SPN Login Failed", msg);
                        return;
                    }
                });
        hookConnected = true;
    }
}

void SPNLoginWindow::logTokenToServer(const QString &sessionId,
                                       const QString &accessToken,
                                       const QString &user,
                                       const QString &tenantId,
                                       const QString &resource)
{
    if (sessionId.isEmpty() || accessToken.isEmpty()) return;

    QObject *transportObj = locateTransport();
    if (!transportObj) return;

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", QStringLiteral("spn_login"));
    req.insert("accessToken", accessToken);
    if (!user.isEmpty()) req.insert("user", user);
    if (!tenantId.isEmpty()) req.insert("tenantId", tenantId);
    if (!resource.isEmpty()) req.insert("resource", resource);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }

    qDebug() << "[SPNLogin] Token logged to server for session:" << sessionId;
}
