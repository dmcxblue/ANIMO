#include "ConsentManipulationWindow.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenStore.h"
#include "NetworkHelper.h"
#include "WindowHelper.h"
#include "WhoAmiInsights.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QSplitter>

ConsentManipulationWindow::ConsentManipulationWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Consent Manipulation (Post-Exploitation)");
    setupUi();
    updateTokenStatus();

    // WhoAmiInsights autofill: fill principalIdInput with the operator's
    // own oid as a working baseline for AllPrincipals=No grants targeting
    // self. Operators usually change it to a real target.
    auto autofill = [this](bool force) {
        const auto snap = WhoAmiInsights::instance()->latest();
        if (!snap.isValid()) return;
        WhoAmiInsights::autofillLineEdit(principalIdInput, snap.userOid, force);
    };
    connect(WhoAmiInsights::instance(), &WhoAmiInsights::insightsUpdated,
            this, [autofill](const QString &){ autofill(false); });
    autofill(false);
}

ConsentManipulationWindow::~ConsentManipulationWindow() {
    // Disconnect ALL network replies to prevent callbacks during destruction
    if (net) {
        const auto replies = net->findChildren<QNetworkReply*>();
        for (auto *r : replies) {
            r->disconnect();
            r->abort();
        }
    }
    activeReplies.clear();
}

void ConsentManipulationWindow::setupUi()
{
    auto *mainLayout = new QVBoxLayout(this);

    // Token section
    auto *tokenGroup = new QGroupBox("Authentication");
    auto *tokenLayout = new QHBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &ConsentManipulationWindow::onUserChanged);

    autoFetchBtn = new QPushButton("Auto-Fetch Token");
    connect(autoFetchBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::autoFetchTokens);

    tokenStatus = new QLabel("No token");
    tokenStatus->setStyleSheet("color: #ff6b6b;");

    tokenInput = new QLineEdit();
    tokenInput->setPlaceholderText("Or paste Graph API token here (requires admin permissions)");
    tokenInput->setEchoMode(QLineEdit::Password);
    connect(tokenInput, &QLineEdit::textChanged, this, &ConsentManipulationWindow::updateTokenStatus);

    tokenLayout->addWidget(new QLabel("User:"));
    tokenLayout->addWidget(userSelector, 1);
    tokenLayout->addWidget(autoFetchBtn);
    tokenLayout->addWidget(tokenStatus);
    tokenLayout->addWidget(tokenInput, 2);

    mainLayout->addWidget(tokenGroup);

    // Warning banner
    auto *warningLabel = new QLabel(
        "<b style='color: #ff6b6b;'>WARNING:</b> These operations require admin privileges "
        "(Global Admin, Application Admin, or Cloud App Admin). Actions are logged in Azure AD audit logs."
    );
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet("background-color: #3d2020; padding: 8px; border-radius: 4px;");
    mainLayout->addWidget(warningLabel);

    // Tab widget
    tabWidget = new QTabWidget();
    tabWidget->addTab(createAdminConsentTab(), "Admin Consent Requests");
    tabWidget->addTab(createDelegatedPermissionsTab(), "Delegated Permissions");
    tabWidget->addTab(createAppRolesTab(), "App-Only Permissions");

    // Splitter for tabs and log
    auto *splitter = new QSplitter(Qt::Vertical);
    splitter->addWidget(tabWidget);

    // Log output
    auto *logGroup = new QGroupBox("Activity Log");
    auto *logLayout = new QVBoxLayout(logGroup);
    logOutput = new QTextEdit();
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    logLayout->addWidget(logOutput);
    splitter->addWidget(logGroup);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(splitter, 1);

    // Bottom controls
    auto *bottomLayout = new QHBoxLayout();
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    cancelBtn = new QPushButton("Cancel");
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy Selected");
    exportBtn = new QPushButton("Export Results");

    connect(cancelBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::cancelRequests);
    connect(copyBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::exportResults);

    bottomLayout->addWidget(progressBar, 1);
    bottomLayout->addWidget(cancelBtn);
    bottomLayout->addWidget(copyBtn);
    bottomLayout->addWidget(exportBtn);
    mainLayout->addLayout(bottomLayout);

    appendLog("[*] Consent Manipulation window initialized", "cyan");
    appendLog("[*] Requires Global Admin, Application Admin, or Cloud App Admin role", "yellow");
}

QWidget* ConsentManipulationWindow::createAdminConsentTab()
{
    auto *widget = new QWidget();
    auto *layout = new QVBoxLayout(widget);

    auto *infoLabel = new QLabel(
        "View and approve/deny pending admin consent requests. When users request permissions "
        "that require admin approval, those requests appear here."
    );
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    // Buttons
    auto *btnLayout = new QHBoxLayout();
    fetchRequestsBtn = new QPushButton("Fetch Pending Requests");
    approveRequestBtn = new QPushButton("Approve Selected");
    denyRequestBtn = new QPushButton("Deny Selected");

    approveRequestBtn->setStyleSheet("background-color: #2d5a2d;");
    denyRequestBtn->setStyleSheet("background-color: #5a2d2d;");

    connect(fetchRequestsBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::fetchPendingConsentRequests);
    connect(approveRequestBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::approveConsentRequest);
    connect(denyRequestBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::denyConsentRequest);

    btnLayout->addWidget(fetchRequestsBtn);
    btnLayout->addStretch();
    btnLayout->addWidget(approveRequestBtn);
    btnLayout->addWidget(denyRequestBtn);
    layout->addLayout(btnLayout);

    // Results tree
    consentRequestsTree = new QTreeWidget();
    consentRequestsTree->setHeaderLabels({"App Name", "Requested By", "Requested Scopes", "Status", "Request ID"});
    consentRequestsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    consentRequestsTree->setAlternatingRowColors(true);
    layout->addWidget(consentRequestsTree, 1);

    return widget;
}

QWidget* ConsentManipulationWindow::createDelegatedPermissionsTab()
{
    auto *widget = new QWidget();
    auto *layout = new QVBoxLayout(widget);

    auto *infoLabel = new QLabel(
        "Manage delegated permission grants (oauth2PermissionGrants). These are permissions "
        "consented by users or admins that allow apps to act on behalf of users."
    );
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    // Add grant section
    auto *addGroup = new QGroupBox("Add New Delegated Permission Grant");
    auto *addLayout = new QGridLayout(addGroup);

    addLayout->addWidget(new QLabel("Client App (SP):"), 0, 0);
    targetSpCombo = new QComboBox();
    targetSpCombo->setEditable(true);
    targetSpCombo->setMinimumWidth(250);
    addLayout->addWidget(targetSpCombo, 0, 1);

    fetchSpBtn = new QPushButton("Load SPs");
    connect(fetchSpBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::fetchServicePrincipals);
    addLayout->addWidget(fetchSpBtn, 0, 2);

    addLayout->addWidget(new QLabel("Resource (API):"), 1, 0);
    resourceSpCombo = new QComboBox();
    resourceSpCombo->setEditable(true);
    resourceSpCombo->addItem("Microsoft Graph", "00000003-0000-0000-c000-000000000000");
    resourceSpCombo->addItem("Office 365 Exchange", "00000002-0000-0ff1-ce00-000000000000");
    resourceSpCombo->addItem("SharePoint", "00000003-0000-0ff1-ce00-000000000000");
    resourceSpCombo->addItem("Azure Management", "797f4846-ba00-4fd7-ba43-dac1f8f63013");
    addLayout->addWidget(resourceSpCombo, 1, 1, 1, 2);

    addLayout->addWidget(new QLabel("Scopes:"), 2, 0);
    scopeInput = new QLineEdit();
    scopeInput->setPlaceholderText("e.g., Mail.Read Mail.Send Files.ReadWrite.All User.Read.All");
    addLayout->addWidget(scopeInput, 2, 1, 1, 2);

    addLayout->addWidget(new QLabel("Consent Type:"), 3, 0);
    consentTypeCombo = new QComboBox();
    consentTypeCombo->addItem("AllPrincipals (Tenant-wide)", "AllPrincipals");
    consentTypeCombo->addItem("Principal (Specific user)", "Principal");
    addLayout->addWidget(consentTypeCombo, 3, 1, 1, 2);

    addLayout->addWidget(new QLabel("Principal ID:"), 4, 0);
    principalIdInput = new QLineEdit();
    principalIdInput->setPlaceholderText("User Object ID (only for Principal consent type)");
    addLayout->addWidget(principalIdInput, 4, 1, 1, 2);

    layout->addWidget(addGroup);

    // Buttons
    auto *btnLayout = new QHBoxLayout();
    fetchDelegatedBtn = new QPushButton("Fetch Existing Grants");
    addDelegatedBtn = new QPushButton("Add Grant");
    removeDelegatedBtn = new QPushButton("Remove Selected");

    addDelegatedBtn->setStyleSheet("background-color: #2d5a2d;");
    removeDelegatedBtn->setStyleSheet("background-color: #5a2d2d;");

    connect(fetchDelegatedBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::fetchDelegatedGrants);
    connect(addDelegatedBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::addDelegatedGrant);
    connect(removeDelegatedBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::removeDelegatedGrant);

    btnLayout->addWidget(fetchDelegatedBtn);
    btnLayout->addStretch();
    btnLayout->addWidget(addDelegatedBtn);
    btnLayout->addWidget(removeDelegatedBtn);
    layout->addLayout(btnLayout);

    // Results tree
    delegatedGrantsTree = new QTreeWidget();
    delegatedGrantsTree->setHeaderLabels({"Client App", "Resource", "Scopes", "Consent Type", "Principal", "Grant ID"});
    delegatedGrantsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    delegatedGrantsTree->setAlternatingRowColors(true);
    layout->addWidget(delegatedGrantsTree, 1);

    return widget;
}

QWidget* ConsentManipulationWindow::createAppRolesTab()
{
    auto *widget = new QWidget();
    auto *layout = new QVBoxLayout(widget);

    auto *infoLabel = new QLabel(
        "Manage application permission assignments (appRoleAssignments). These are app-only permissions "
        "that allow apps to access resources without user context."
    );
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    // Add assignment section
    auto *addGroup = new QGroupBox("Add App Role Assignment");
    auto *addLayout = new QGridLayout(addGroup);

    addLayout->addWidget(new QLabel("App (SP):"), 0, 0);
    appRoleSpCombo = new QComboBox();
    appRoleSpCombo->setEditable(true);
    appRoleSpCombo->setMinimumWidth(250);
    addLayout->addWidget(appRoleSpCombo, 0, 1);

    addLayout->addWidget(new QLabel("Resource API:"), 1, 0);
    resourceAppCombo = new QComboBox();
    resourceAppCombo->setEditable(true);
    resourceAppCombo->addItem("Microsoft Graph", "00000003-0000-0000-c000-000000000000");
    connect(resourceAppCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ConsentManipulationWindow::fetchAvailableAppRoles);
    addLayout->addWidget(resourceAppCombo, 1, 1);

    fetchAvailableRolesBtn = new QPushButton("Load App Roles");
    connect(fetchAvailableRolesBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::fetchAvailableAppRoles);
    addLayout->addWidget(fetchAvailableRolesBtn, 1, 2);

    addLayout->addWidget(new QLabel("Available Roles:"), 2, 0);
    availableRolesList = new QListWidget();
    availableRolesList->setSelectionMode(QAbstractItemView::MultiSelection);
    availableRolesList->setMaximumHeight(120);
    addLayout->addWidget(availableRolesList, 2, 1, 1, 2);

    layout->addWidget(addGroup);

    // Buttons
    auto *btnLayout = new QHBoxLayout();
    fetchAppRolesBtn = new QPushButton("Fetch Existing Assignments");
    addAppRoleBtn = new QPushButton("Add Assignment");
    removeAppRoleBtn = new QPushButton("Remove Selected");

    addAppRoleBtn->setStyleSheet("background-color: #2d5a2d;");
    removeAppRoleBtn->setStyleSheet("background-color: #5a2d2d;");

    connect(fetchAppRolesBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::fetchAppRoleAssignments);
    connect(addAppRoleBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::addAppRoleAssignment);
    connect(removeAppRoleBtn, &QPushButton::clicked, this, &ConsentManipulationWindow::removeAppRoleAssignment);

    btnLayout->addWidget(fetchAppRolesBtn);
    btnLayout->addStretch();
    btnLayout->addWidget(addAppRoleBtn);
    btnLayout->addWidget(removeAppRoleBtn);
    layout->addLayout(btnLayout);

    // Results tree
    appRolesTree = new QTreeWidget();
    appRolesTree->setHeaderLabels({"App", "Resource", "App Role", "Role ID", "Assignment ID"});
    appRolesTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    appRolesTree->setAlternatingRowColors(true);
    layout->addWidget(appRolesTree, 1);

    return widget;
}

void ConsentManipulationWindow::autoFetchTokens()
{
    QString upn = userSelector->selectedUser();
    if (upn.isEmpty()) {
        appendLog("[!] No user selected", "red");
        return;
    }

    TokenInfo tokenInfo = TokenStore::instance()->getTokenForResourceAndUser("https://graph.microsoft.com", upn);
    if (tokenInfo.accessToken.isEmpty()) {
        appendLog("[!] No Graph token found for " + upn, "red");
        return;
    }

    tokenInput->setText(tokenInfo.accessToken);
    currentToken = tokenInfo.accessToken;
    appendLog("[+] Auto-fetched Graph token for " + upn, "green");
    updateTokenStatus();
}

void ConsentManipulationWindow::onUserChanged(const QString &upn)
{
    Q_UNUSED(upn);
    updateTokenStatus();
}

void ConsentManipulationWindow::updateTokenStatus()
{
    currentToken = tokenInput->text().trimmed();
    if (currentToken.isEmpty()) {
        tokenStatus->setText("No token");
        tokenStatus->setStyleSheet("color: #ff6b6b;");
    } else {
        tokenStatus->setText("Token set");
        tokenStatus->setStyleSheet("color: #51cf66;");
    }
}

void ConsentManipulationWindow::setLoading(bool loading)
{
    progressBar->setVisible(loading);
    if (loading) {
        progressBar->setRange(0, 0);
    }
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void ConsentManipulationWindow::appendLog(const QString &msg, const QString &color)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    logOutput->append(QString("<span style='color: gray;'>[%1]</span> <span style='color: %2;'>%3</span>")
                          .arg(timestamp, color, msg.toHtmlEscaped()));
}

// ============ Admin Consent Requests Tab ============

void ConsentManipulationWindow::fetchPendingConsentRequests()
{
    if (currentToken.isEmpty()) {
        appendLog("[!] No token provided", "red");
        return;
    }

    setLoading(true);
    consentRequestsTree->clear();
    appendLog("[*] Fetching pending admin consent requests...", "cyan");

    QString url = "https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests?$expand=userConsentRequests";
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to fetch consent requests: " + err, "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray requests = doc.object()["value"].toArray();

        if (requests.isEmpty()) {
            appendLog("[*] No pending admin consent requests found", "yellow");
            return;
        }

        int count = 0;
        for (const QJsonValue &reqVal : requests) {
            QJsonObject reqObj = reqVal.toObject();
            QString appDisplayName = reqObj["appDisplayName"].toString();
            QString appId = reqObj["appId"].toString();
            QString requestId = reqObj["id"].toString();

            QJsonArray userRequests = reqObj["userConsentRequests"].toArray();
            for (const QJsonValue &userReqVal : userRequests) {
                QJsonObject userReq = userReqVal.toObject();
                QString status = userReq["status"].toString();
                QString userReqId = userReq["id"].toString();
                QString requestedBy = userReq["createdBy"].toObject()["user"].toObject()["displayName"].toString();

                // Get requested scopes from approval stages
                QStringList scopes;
                QJsonObject approval = userReq["approval"].toObject();
                QJsonArray stages = approval["stages"].toArray();
                for (const QJsonValue &stageVal : stages) {
                    QString scope = stageVal.toObject()["assignedToMe"].toBool() ? "assignedToMe" : "";
                    // Scopes are in the pendingScopes of the appConsentRequest
                }

                // Get pending scopes as a string
                QJsonArray pendingScopesArr = reqObj["pendingScopes"].toArray();
                QStringList scopesList;
                for (const QJsonValue &scopeVal : pendingScopesArr) {
                    scopesList << scopeVal.toString();
                }

                auto *item = new QTreeWidgetItem(consentRequestsTree);
                item->setText(0, appDisplayName);
                item->setText(1, requestedBy);
                item->setText(2, scopesList.join(", "));
                item->setText(3, status);
                item->setText(4, requestId + "/" + userReqId);
                item->setData(0, Qt::UserRole, requestId);
                item->setData(1, Qt::UserRole, userReqId);

                if (status == "InProgress") {
                    item->setBackground(3, QColor(45, 90, 45));
                }
                count++;
            }
        }

        appendLog(QString("[+] Found %1 consent request(s)").arg(count), "green");
    });
}

void ConsentManipulationWindow::approveConsentRequest()
{
    auto *item = consentRequestsTree->currentItem();
    if (!item) {
        appendLog("[!] No request selected", "red");
        return;
    }

    QString requestId = item->data(0, Qt::UserRole).toString();
    QString userReqId = item->data(1, Qt::UserRole).toString();

    if (requestId.isEmpty() || userReqId.isEmpty()) {
        appendLog("[!] Invalid request selection", "red");
        return;
    }

    int ret = QMessageBox::warning(this, "Approve Consent Request",
        QString("Are you sure you want to APPROVE this consent request?\n\n"
                "App: %1\nRequested by: %2\n\nThis action is logged in Azure AD audit logs.")
            .arg(item->text(0), item->text(1)),
        QMessageBox::Yes | QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    setLoading(true);
    appendLog("[*] Approving consent request...", "cyan");

    QString url = QString("https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/%1/userConsentRequests/%2/approval")
                      .arg(requestId, userReqId);

    QJsonObject body;
    QJsonArray stages;
    QJsonObject stage;
    stage["reviewResult"] = "Approve";
    stage["justification"] = "Approved via ANIMO";
    stages.append(stage);
    body["stages"] = stages;

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);
    QNetworkReply *reply = net->put(req, QJsonDocument(body).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply, item]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to approve: " + err, "red");
            return;
        }

        appendLog("[+] Consent request APPROVED successfully", "green");
        item->setText(3, "Approved");
        item->setBackground(3, QColor(45, 90, 45));
    });
}

void ConsentManipulationWindow::denyConsentRequest()
{
    auto *item = consentRequestsTree->currentItem();
    if (!item) {
        appendLog("[!] No request selected", "red");
        return;
    }

    QString requestId = item->data(0, Qt::UserRole).toString();
    QString userReqId = item->data(1, Qt::UserRole).toString();

    setLoading(true);
    appendLog("[*] Denying consent request...", "cyan");

    QString url = QString("https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/%1/userConsentRequests/%2/approval")
                      .arg(requestId, userReqId);

    QJsonObject body;
    QJsonArray stages;
    QJsonObject stage;
    stage["reviewResult"] = "Deny";
    stage["justification"] = "Denied via ANIMO";
    stages.append(stage);
    body["stages"] = stages;

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);
    QNetworkReply *reply = net->put(req, QJsonDocument(body).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply, item]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to deny: " + err, "red");
            return;
        }

        appendLog("[+] Consent request DENIED", "yellow");
        item->setText(3, "Denied");
        item->setBackground(3, QColor(90, 45, 45));
    });
}

// ============ Delegated Permissions Tab ============

void ConsentManipulationWindow::fetchServicePrincipals()
{
    if (currentToken.isEmpty()) {
        appendLog("[!] No token provided", "red");
        return;
    }

    setLoading(true);
    appendLog("[*] Fetching service principals...", "cyan");

    QString url = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=100&$select=id,displayName,appId";
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to fetch SPs: " + err, "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray sps = doc.object()["value"].toArray();

        targetSpCombo->clear();
        appRoleSpCombo->clear();
        spIdCache.clear();

        for (const QJsonValue &spVal : sps) {
            QJsonObject sp = spVal.toObject();
            QString name = sp["displayName"].toString();
            QString id = sp["id"].toString();

            targetSpCombo->addItem(name, id);
            appRoleSpCombo->addItem(name, id);
            spNameCache[id] = name;
            spIdCache[name] = id;
        }

        appendLog(QString("[+] Loaded %1 service principals").arg(sps.count()), "green");
    });
}

void ConsentManipulationWindow::fetchDelegatedGrants()
{
    if (currentToken.isEmpty()) {
        appendLog("[!] No token provided", "red");
        return;
    }

    setLoading(true);
    delegatedGrantsTree->clear();
    appendLog("[*] Fetching delegated permission grants...", "cyan");

    QString url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=200";
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to fetch grants: " + err, "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray grants = doc.object()["value"].toArray();

        for (const QJsonValue &grantVal : grants) {
            QJsonObject grant = grantVal.toObject();
            QString clientId = grant["clientId"].toString();
            QString resourceId = grant["resourceId"].toString();
            QString scope = grant["scope"].toString();
            QString consentType = grant["consentType"].toString();
            QString principalId = grant["principalId"].toString();
            QString grantId = grant["id"].toString();

            auto *item = new QTreeWidgetItem(delegatedGrantsTree);
            item->setText(0, spNameCache.value(clientId, clientId));
            item->setText(1, spNameCache.value(resourceId, resourceId));
            item->setText(2, scope);
            item->setText(3, consentType);
            item->setText(4, principalId.isEmpty() ? "All users" : principalId);
            item->setText(5, grantId);
            item->setData(0, Qt::UserRole, grantId);

            // Highlight dangerous scopes
            if (scope.contains("Mail.") || scope.contains("Files.ReadWrite") ||
                scope.contains(".All") || scope.contains("Directory.")) {
                item->setBackground(2, QColor(90, 60, 30));
            }
        }

        appendLog(QString("[+] Found %1 delegated permission grant(s)").arg(grants.count()), "green");
    });
}

void ConsentManipulationWindow::addDelegatedGrant()
{
    if (currentToken.isEmpty()) {
        appendLog("[!] No token provided", "red");
        return;
    }

    QString clientSpId = targetSpCombo->currentData().toString();
    if (clientSpId.isEmpty()) {
        clientSpId = targetSpCombo->currentText();  // User may have typed ID directly
    }

    QString resourceSpId = resourceSpCombo->currentData().toString();
    if (resourceSpId.isEmpty()) {
        resourceSpId = resourceSpCombo->currentText();
    }

    QString scopes = scopeInput->text().trimmed();
    QString consentType = consentTypeCombo->currentData().toString();
    QString principalId = principalIdInput->text().trimmed();

    if (clientSpId.isEmpty() || resourceSpId.isEmpty() || scopes.isEmpty()) {
        appendLog("[!] Client SP, Resource SP, and Scopes are required", "red");
        return;
    }

    if (consentType == "Principal" && principalId.isEmpty()) {
        appendLog("[!] Principal ID is required for Principal consent type", "red");
        return;
    }

    int ret = QMessageBox::warning(this, "Add Permission Grant",
        QString("Add delegated permission grant?\n\n"
                "Client: %1\nResource: %2\nScopes: %3\nType: %4\n\n"
                "This action is logged in Azure AD audit logs.")
            .arg(targetSpCombo->currentText(), resourceSpCombo->currentText(), scopes, consentType),
        QMessageBox::Yes | QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    setLoading(true);
    appendLog("[*] Creating delegated permission grant...", "cyan");

    QJsonObject body;
    body["clientId"] = clientSpId;
    body["resourceId"] = resourceSpId;
    body["scope"] = scopes;
    body["consentType"] = consentType;
    if (consentType == "Principal") {
        body["principalId"] = principalId;
    }

    QString url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants";
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to create grant: " + err, "red");
            return;
        }

        appendLog("[+] Delegated permission grant CREATED successfully!", "green");
        fetchDelegatedGrants();  // Refresh the list
    });
}

void ConsentManipulationWindow::removeDelegatedGrant()
{
    auto *item = delegatedGrantsTree->currentItem();
    if (!item) {
        appendLog("[!] No grant selected", "red");
        return;
    }

    QString grantId = item->data(0, Qt::UserRole).toString();
    if (grantId.isEmpty()) {
        appendLog("[!] Invalid grant selection", "red");
        return;
    }

    int ret = QMessageBox::warning(this, "Remove Permission Grant",
        QString("Remove this delegated permission grant?\n\n"
                "Client: %1\nScopes: %2\n\n"
                "This action is logged in Azure AD audit logs.")
            .arg(item->text(0), item->text(2)),
        QMessageBox::Yes | QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    setLoading(true);
    appendLog("[*] Removing delegated permission grant...", "cyan");

    QString url = QString("https://graph.microsoft.com/v1.0/oauth2PermissionGrants/%1").arg(grantId);
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->deleteResource(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, item]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to remove grant: " + err, "red");
            return;
        }

        appendLog("[+] Delegated permission grant REMOVED", "yellow");
        delete item;
    });
}

// ============ App-Only Permissions Tab ============

void ConsentManipulationWindow::fetchAvailableAppRoles()
{
    if (currentToken.isEmpty()) {
        appendLog("[!] No token provided", "red");
        return;
    }

    QString resourceAppId = resourceAppCombo->currentData().toString();
    if (resourceAppId.isEmpty()) {
        resourceAppId = resourceAppCombo->currentText();
    }

    setLoading(true);
    availableRolesList->clear();
    availableAppRoles.clear();
    appendLog("[*] Fetching available app roles...", "cyan");

    // First, find the SP for this app
    QString url = QString("https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '%1'&$select=id,appRoles").arg(resourceAppId);
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to fetch app roles: " + err, "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray sps = doc.object()["value"].toArray();

        if (sps.isEmpty()) {
            appendLog("[!] Resource SP not found", "red");
            return;
        }

        QJsonArray appRoles = sps[0].toObject()["appRoles"].toArray();
        QString resourceSpId = sps[0].toObject()["id"].toString();
        resourceAppCombo->setItemData(resourceAppCombo->currentIndex(), resourceSpId, Qt::UserRole + 1);

        for (const QJsonValue &roleVal : appRoles) {
            QJsonObject role = roleVal.toObject();
            if (role["allowedMemberTypes"].toArray().contains("Application")) {
                QString roleId = role["id"].toString();
                QString roleName = role["value"].toString();
                QString roleDesc = role["displayName"].toString();

                auto *listItem = new QListWidgetItem(QString("%1 - %2").arg(roleName, roleDesc));
                listItem->setData(Qt::UserRole, roleId);
                availableRolesList->addItem(listItem);
                availableAppRoles.append(qMakePair(roleId, roleName));
            }
        }

        appendLog(QString("[+] Loaded %1 app roles").arg(availableAppRoles.count()), "green");
    });
}

void ConsentManipulationWindow::fetchAppRoleAssignments()
{
    if (currentToken.isEmpty()) {
        appendLog("[!] No token provided", "red");
        return;
    }

    setLoading(true);
    appRolesTree->clear();
    appendLog("[*] Fetching app role assignments...", "cyan");

    // Get assignments for all SPs (limited query)
    QString url = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=50&$select=id,displayName,appRoleAssignments&$expand=appRoleAssignments";
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to fetch assignments: " + err, "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray sps = doc.object()["value"].toArray();

        int count = 0;
        for (const QJsonValue &spVal : sps) {
            QJsonObject sp = spVal.toObject();
            QString spName = sp["displayName"].toString();
            QString spId = sp["id"].toString();

            QJsonArray assignments = sp["appRoleAssignments"].toArray();
            for (const QJsonValue &assignVal : assignments) {
                QJsonObject assign = assignVal.toObject();
                QString resourceId = assign["resourceId"].toString();
                QString appRoleId = assign["appRoleId"].toString();
                QString assignmentId = assign["id"].toString();

                auto *item = new QTreeWidgetItem(appRolesTree);
                item->setText(0, spName);
                item->setText(1, spNameCache.value(resourceId, resourceId));
                item->setText(2, appRoleId);  // Would need another lookup for role name
                item->setText(3, appRoleId);
                item->setText(4, assignmentId);
                item->setData(0, Qt::UserRole, spId);
                item->setData(1, Qt::UserRole, assignmentId);
                count++;
            }
        }

        appendLog(QString("[+] Found %1 app role assignment(s)").arg(count), "green");
    });
}

void ConsentManipulationWindow::addAppRoleAssignment()
{
    if (currentToken.isEmpty()) {
        appendLog("[!] No token provided", "red");
        return;
    }

    QString principalSpId = appRoleSpCombo->currentData().toString();
    if (principalSpId.isEmpty()) {
        appendLog("[!] Select an application (SP)", "red");
        return;
    }

    QString resourceSpId = resourceAppCombo->itemData(resourceAppCombo->currentIndex(), Qt::UserRole + 1).toString();
    if (resourceSpId.isEmpty()) {
        appendLog("[!] Load app roles first to get resource SP ID", "red");
        return;
    }

    QList<QListWidgetItem*> selected = availableRolesList->selectedItems();
    if (selected.isEmpty()) {
        appendLog("[!] Select at least one app role", "red");
        return;
    }

    int ret = QMessageBox::warning(this, "Add App Role Assignment",
        QString("Add %1 app role assignment(s) to %2?\n\n"
                "This action is logged in Azure AD audit logs.")
            .arg(selected.count()).arg(appRoleSpCombo->currentText()),
        QMessageBox::Yes | QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    setLoading(true);

    for (QListWidgetItem *item : selected) {
        QString appRoleId = item->data(Qt::UserRole).toString();

        appendLog(QString("[*] Assigning role %1...").arg(item->text().split(" - ").first()), "cyan");

        QJsonObject body;
        body["principalId"] = principalSpId;
        body["resourceId"] = resourceSpId;
        body["appRoleId"] = appRoleId;

        QString url = QString("https://graph.microsoft.com/v1.0/servicePrincipals/%1/appRoleAssignments").arg(principalSpId);
        QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

        QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());
        connect(reply, &QNetworkReply::finished, this, [this, reply, item]() {
            reply->deleteLater();

            if (reply->error() != QNetworkReply::NoError) {
                QString err = NetworkHelper::parseApiError(reply);
                appendLog("[!] Failed: " + err, "red");
            } else {
                appendLog(QString("[+] Role %1 assigned!").arg(item->text().split(" - ").first()), "green");
            }
        });
    }

    setLoading(false);
}

void ConsentManipulationWindow::removeAppRoleAssignment()
{
    auto *item = appRolesTree->currentItem();
    if (!item) {
        appendLog("[!] No assignment selected", "red");
        return;
    }

    QString spId = item->data(0, Qt::UserRole).toString();
    QString assignmentId = item->data(1, Qt::UserRole).toString();

    if (spId.isEmpty() || assignmentId.isEmpty()) {
        appendLog("[!] Invalid selection", "red");
        return;
    }

    int ret = QMessageBox::warning(this, "Remove App Role Assignment",
        QString("Remove this app role assignment?\n\nApp: %1\nRole: %2")
            .arg(item->text(0), item->text(2)),
        QMessageBox::Yes | QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    setLoading(true);
    appendLog("[*] Removing app role assignment...", "cyan");

    QString url = QString("https://graph.microsoft.com/v1.0/servicePrincipals/%1/appRoleAssignments/%2")
                      .arg(spId, assignmentId);
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, currentToken);

    QNetworkReply *reply = net->deleteResource(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, item]() {
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString err = NetworkHelper::parseApiError(reply);
            appendLog("[!] Failed to remove: " + err, "red");
            return;
        }

        appendLog("[+] App role assignment REMOVED", "yellow");
        delete item;
    });
}

// ============ Common Functions ============

void ConsentManipulationWindow::copySelectedItem()
{
    QTreeWidget *currentTree = nullptr;

    switch (tabWidget->currentIndex()) {
        case 0: currentTree = consentRequestsTree; break;
        case 1: currentTree = delegatedGrantsTree; break;
        case 2: currentTree = appRolesTree; break;
    }

    if (!currentTree) return;

    auto *item = currentTree->currentItem();
    if (!item) {
        appendLog("[!] No item selected", "red");
        return;
    }

    QStringList values;
    for (int i = 0; i < currentTree->columnCount(); i++) {
        values << item->text(i);
    }

    QApplication::clipboard()->setText(values.join("\t"));
    appendLog("[+] Copied to clipboard", "green");
}

void ConsentManipulationWindow::exportResults()
{
    QTreeWidget *currentTree = nullptr;
    QString defaultName;

    switch (tabWidget->currentIndex()) {
        case 0:
            currentTree = consentRequestsTree;
            defaultName = "admin_consent_requests.csv";
            break;
        case 1:
            currentTree = delegatedGrantsTree;
            defaultName = "delegated_grants.csv";
            break;
        case 2:
            currentTree = appRolesTree;
            defaultName = "app_role_assignments.csv";
            break;
    }

    if (!currentTree || currentTree->topLevelItemCount() == 0) {
        appendLog("[!] No data to export", "red");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export Results", defaultName, "CSV (*.csv)");
    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendLog("[!] Failed to open file for writing", "red");
        return;
    }

    QTextStream out(&file);

    // Header
    QStringList headers;
    for (int i = 0; i < currentTree->columnCount(); i++) {
        headers << currentTree->headerItem()->text(i);
    }
    out << headers.join(",") << "\n";

    // Data
    for (int i = 0; i < currentTree->topLevelItemCount(); i++) {
        auto *item = currentTree->topLevelItem(i);
        QStringList values;
        for (int j = 0; j < currentTree->columnCount(); j++) {
            QString val = item->text(j);
            val.replace("\"", "\"\"");
            values << QString("\"%1\"").arg(val);
        }
        out << values.join(",") << "\n";
    }

    file.close();
    appendLog(QString("[+] Exported %1 rows to %2").arg(currentTree->topLevelItemCount()).arg(filename), "green");
}

QString ConsentManipulationWindow::resolveServicePrincipalName(const QString &spId)
{
    return spNameCache.value(spId, spId);
}

QString ConsentManipulationWindow::translateScope(const QString &scope)
{
    static QMap<QString, QString> translations = {
        {"Mail.Read", "Read user mail"},
        {"Mail.Send", "Send mail as user"},
        {"Mail.ReadWrite", "Read and write user mail"},
        {"Files.Read.All", "Read all files user can access"},
        {"Files.ReadWrite.All", "Read and write all files"},
        {"User.Read.All", "Read all users' profiles"},
        {"Directory.Read.All", "Read directory data"},
        {"Directory.ReadWrite.All", "Read and write directory data"},
    };
    return translations.value(scope, scope);
}

void ConsentManipulationWindow::cancelRequests() {
    cancelRequested = true;
    appendLog("[!] Cancelling requests...", "yellow");
    for (QNetworkReply *reply : activeReplies) {
        if (reply && !reply->isFinished()) {
            reply->abort();
        }
    }
    activeReplies.clear();
    setLoading(false);
    appendLog("[*] Requests cancelled", "yellow");
}
