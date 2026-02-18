#include "DashboardWindow.h"
#include "DashboardTab.h"
#include "WindowHelper.h"
#include "TokenStore.h"
#include "TokenHelper.h"
#include "WindowFactory.h"
#include "NetworkHelper.h"

// These windows need direct includes for specific constructor arguments or signals
#include "DeviceCodeLoginWindow.h"
#include "IllicitConsentGrant.h"
#include "CredentialLoginWindow.h"
#include "TokenLoginWindow.h"
#include "SessionExportWindow.h"
#include "SessionImportWindow.h"
#include "ReportDialog.h"

#include "../shared/SessionPersistence.h"
#include "../server/SessionDBManager.h"
#include "../shared/Protocol.h"
#include "network/ClientTransport.h"

#include <QVBoxLayout>
#include <QGridLayout>
#include <QMenuBar>
#include <QApplication>
#include <QMenu>
#include <QAction>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QGraphicsDropShadowEffect>
#include <QWidgetAction>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QGroupBox>
#include <QStandardPaths>
#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QShortcut>
#include <QKeySequence>
#include <QScreen> // To Fix window centering
#include <QStyle>   
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QMetaObject>
#include <QObject>
#include <QClipboard>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrlQuery> 

// Constructor
DashboardWindow::DashboardWindow(QWidget *parent)
    : QMainWindow(parent),
      loginScript(""),
      token(""),
      resource(""),
      username("Unknown"),
      tenantId("N/A"),
      defaultDomain("N/A"),
      sessionId("")
{
    initUI();

    // It's OK to call this now; it guards when transport == nullptr
    loadExistingSessions();
}

// Save window geometry on close
void DashboardWindow::closeEvent(QCloseEvent *event)
{
    WindowHelper::saveGeometry(this, "DashboardWindow");
    QMainWindow::closeEvent(event);
}

// Register a persistent PowerShell session (legacy; safe to keep)
void DashboardWindow::registerPsSession(const QString &sessionId, QProcess *proc, const QString &token, const QString &resource) {
    if (!proc) return;

    SessionInfo info;
    info.psProc   = proc;
    info.token    = token;
    info.resource = resource;

    sessions.insert(sessionId, info);
    qDebug() << "[+] Registered PowerShell session:" << sessionId;
}

// Get session info by id (legacy local map; safe to keep)
SessionInfo* DashboardWindow::getSession(const QString &sessionId) {
    if (sessions.contains(sessionId)) {
        return &sessions[sessionId];
    }
    return nullptr;
}

void DashboardWindow::initUI() 
{
    QWidget *central = new QWidget(this);
    central->setObjectName("centralWidget");
    QVBoxLayout *outerLayout = new QVBoxLayout(central);
    outerLayout->setContentsMargins(0,0,0,0);
    outerLayout->setSpacing(0);

    // ── Menu bar ──
    QMenuBar *menuBar = new QMenuBar(this);
    outerLayout->addWidget(menuBar);

    // ============================================================
    // Menu Structure
    // ============================================================
    QMenu *sessionsMenu      = menuBar->addMenu("Sessions");
    QMenu *initialAccessMenu = menuBar->addMenu("Initial Access");
    QMenu *tokensMenu        = menuBar->addMenu("Tokens");
    QMenu *attacksMenu       = menuBar->addMenu("Credential Attacks");
    QMenu *discoveryMenu     = menuBar->addMenu("Discovery");
    QMenu *collectionMenu    = menuBar->addMenu("Collection");
    QMenu *persistenceMenu   = menuBar->addMenu("Persistence");
    QMenu *logsMenu          = menuBar->addMenu("Logs");
    QMenu *helpMenu          = menuBar->addMenu("Help");

    // === Help menu ===
    QAction *aboutAction = new QAction("About", this);
    helpMenu->addAction(aboutAction);
    connect(aboutAction, &QAction::triggered, [this]()
	{
        QMessageBox::about(this,
            "About ANIMO",
            "ANIMO 1.0.0\n\n"
            "Azure Network Intel & Mission Ops\n"
            "Released: July 2026\n\n"
            "Init1security, LLC\n\n"
            "All trademarks and registered trademarks are the property of their respective owners.\n\n"
            "ANIMO makes use of code and/or content from the following sources:\n\n"
            "- Qt6 Framework (https://www.qt.io)\n"
            "- Microsoft MSAL Python Library (https://github.com/AzureAD/microsoft-authentication-library-for-python)\n"
            "- Azure REST APIs (https://docs.microsoft.com/en-us/rest/api/azure)");
    });

    // === Sessions menu ===
    QAction *actionNewSession  = sessionsMenu->addAction("New Session");
    QAction *accessTokenAction = sessionsMenu->addAction("New Session via Access Token");
    sessionsMenu->addSeparator();

    QAction *autoRenewAction = new QAction("Auto-Renew Tokens", this);
    autoRenewAction->setCheckable(true);
    QSettings settings("ANIMO", "Client");
    autoRenewEnabled = settings.value("autoRenewTokens", true).toBool();
    autoRenewAction->setChecked(autoRenewEnabled);
    sessionsMenu->addAction(autoRenewAction);

    // Session persistence (export/import)
    sessionsMenu->addSeparator();
    QAction *exportSessionsAction = sessionsMenu->addAction("Export Sessions && Tokens...");
    QAction *importSessionsAction = sessionsMenu->addAction("Import Sessions && Tokens...");

    connect(actionNewSession,  &QAction::triggered, this, &DashboardWindow::createNewSession);
    connect(accessTokenAction, &QAction::triggered, this, &DashboardWindow::launchAccessTokenWindow);
    connect(autoRenewAction,   &QAction::toggled,   this, &DashboardWindow::toggleAutoRenew);
    connect(exportSessionsAction, &QAction::triggered, this, &DashboardWindow::openExportSessionsWindow);
    connect(importSessionsAction, &QAction::triggered, this, &DashboardWindow::openImportSessionsWindow);

    // === Initial Access menu ===
    QAction *deviceCodeAction     = initialAccessMenu->addAction("Device Code Phishing");
    QAction *illicitConsentAction = initialAccessMenu->addAction("Illicit Consent Grant");

    connect(deviceCodeAction,     &QAction::triggered, this, &DashboardWindow::launchDeviceCodeWindow);
    connect(illicitConsentAction, &QAction::triggered, this, &DashboardWindow::launchIllicitConsentWindow);

    // === Tokens menu ===
    QAction *actionOpenRefreshTokens = tokensMenu->addAction("Refresh Tokens");
    QAction *prtTokenAction          = tokensMenu->addAction("PRT Tokens");
    QAction *ssoTokenAction          = tokensMenu->addAction("SSO Tokens");

    // === Credential Attacks menu ===
    QAction *actionPasswordSpray  = attacksMenu->addAction("Password Spray");
    QAction *actionSPNSpray       = attacksMenu->addAction("SPN Secret Spray");
    QAction *actionAddAppSecret   = attacksMenu->addAction("Add App Secret");

    connect(actionOpenRefreshTokens, &QAction::triggered, this, &DashboardWindow::openRefreshTokensMenu);
    connect(prtTokenAction,          &QAction::triggered, this, &DashboardWindow::openPRTTokenMenu);
    connect(ssoTokenAction,          &QAction::triggered, this, &DashboardWindow::openSsoTokenMenu);
    connect(actionPasswordSpray,     &QAction::triggered, this, &DashboardWindow::openAttackPasswordSpray);
    connect(actionSPNSpray,          &QAction::triggered, this, &DashboardWindow::openSPNSpray);
    connect(actionAddAppSecret,      &QAction::triggered, this, &DashboardWindow::openAttackAppSecret);

    // === Discovery menu ===
    QAction *actionAzureEnum         = discoveryMenu->addAction("Subscriptions && Resources");
    QAction *actionConditionalAccess = discoveryMenu->addAction("Conditional Access Policies");
    QAction *actionCrossTenant       = discoveryMenu->addAction("Cross-Tenant Access Policies");
    QAction *actionMfaStatus         = discoveryMenu->addAction("MFA Status Checker");
    QAction *actionPwdWriteback      = discoveryMenu->addAction("Password Writeback Checker");
    QAction *actionOAuthConsent      = discoveryMenu->addAction("OAuth Consent Grants");
    QAction *actGraphQueries         = discoveryMenu->addAction("Graph Query");
    discoveryMenu->addSeparator();
    QAction *actionKeyVault          = discoveryMenu->addAction("Key Vault Explorer");
    QAction *actionSqlDatabase       = discoveryMenu->addAction("SQL Database Explorer");
    QAction *actionVMManager         = discoveryMenu->addAction("Virtual Machines");
    QAction *actionRunbooks          = discoveryMenu->addAction("Automation Runbooks");
    discoveryMenu->addSeparator();
    QAction *actionSPNEnum           = discoveryMenu->addAction("Service Principals / Apps");
    QAction *actionFunctionApps      = discoveryMenu->addAction("Function Apps");
    QAction *actionLogicApps         = discoveryMenu->addAction("Logic Apps");

    connect(actionAzureEnum,         &QAction::triggered, this, &DashboardWindow::openAzureEnumWindow);
    connect(actionConditionalAccess, &QAction::triggered, this, &DashboardWindow::openConditionalAccessWindow);
    connect(actionCrossTenant,       &QAction::triggered, this, &DashboardWindow::openCrossTenantAccessWindow);
    connect(actionMfaStatus,         &QAction::triggered, this, &DashboardWindow::openMfaStatusChecker);
    connect(actionPwdWriteback,      &QAction::triggered, this, &DashboardWindow::openPasswordWritebackChecker);
    connect(actionOAuthConsent,      &QAction::triggered, this, &DashboardWindow::openOAuthConsentEnumerator);
    connect(actGraphQueries,         &QAction::triggered, this, &DashboardWindow::openGraphQueries);
    connect(actionKeyVault,          &QAction::triggered, this, &DashboardWindow::openKeyVaultExplorer);
    connect(actionSqlDatabase,       &QAction::triggered, this, &DashboardWindow::openSqlDatabaseExplorer);
    connect(actionVMManager,         &QAction::triggered, this, &DashboardWindow::openAzureVMManager);
    connect(actionRunbooks,          &QAction::triggered, this, &DashboardWindow::openRunbookExplorer);
    connect(actionSPNEnum,           &QAction::triggered, this, &DashboardWindow::openSPNEnumWindow);
    connect(actionFunctionApps,      &QAction::triggered, this, &DashboardWindow::openFunctionAppExplorer);
    connect(actionLogicApps,         &QAction::triggered, this, &DashboardWindow::openLogicAppsViewer);

    // === Collection menu (M365 Data Harvesting) ===
    QAction *actionOpenOutlookMenu     = collectionMenu->addAction("Outlook Email");
    QAction *actionOpenOutlookCalendar = collectionMenu->addAction("Outlook Calendar");
    QAction *teamsAction               = collectionMenu->addAction("Teams Messages");
    QAction *actionOpenOnedrive        = collectionMenu->addAction("SharePoint / OneDrive Files");
    collectionMenu->addSeparator();
    QAction *actionAzureStorage        = collectionMenu->addAction("Storage Explorer");

    connect(actionOpenOutlookMenu,     &QAction::triggered, this, &DashboardWindow::openOutlookEmailWindow);
    connect(actionOpenOutlookCalendar, &QAction::triggered, this, &DashboardWindow::openOutlookCalendar);
    connect(teamsAction,               &QAction::triggered, this, &DashboardWindow::openTeamsChatWindow);
    connect(actionOpenOnedrive,        &QAction::triggered, this, &DashboardWindow::openOnedriveExplorer);
    connect(actionAzureStorage,        &QAction::triggered, this, &DashboardWindow::openAzureStorageWindow);

    // === Persistence menu ===
    QAction *actionPostExploit       = persistenceMenu->addAction("Post-Exploitation Tools");
    QAction *actionEmailRules        = persistenceMenu->addAction("Email Inbox Rules");
    QAction *actionConsentManip      = persistenceMenu->addAction("Consent Manipulation");
    QAction *actionWfh               = persistenceMenu->addAction("Windows Hello Attack");
    connect(actionPostExploit,  &QAction::triggered, this, &DashboardWindow::openPostExploitWindow);
    connect(actionEmailRules,   &QAction::triggered, this, &DashboardWindow::openEmailRulesWindow);
    connect(actionConsentManip, &QAction::triggered, this, &DashboardWindow::openConsentManipulationWindow);
    connect(actionWfh,          &QAction::triggered, this, &DashboardWindow::openAttackWfh);

    // === Logs menu ===
    QAction *tokenLogsAction = logsMenu->addAction("Token Logs");
    connect(tokenLogsAction, &QAction::triggered, this, &DashboardWindow::openTokenLogWindow);

    QAction *tokenAnalysisAction = logsMenu->addAction("Token Lifetime Analysis");
    connect(tokenAnalysisAction, &QAction::triggered, this, &DashboardWindow::openTokenAnalysisWindow);

    QAction *timelineAction = logsMenu->addAction("Session Timeline");
    connect(timelineAction, &QAction::triggered, this, &DashboardWindow::openSessionTimelineWindow);

    // === Help menu (additional items) ===
    helpMenu->addSeparator();
    QAction *generateReportAction = helpMenu->addAction("Generate Engagement Report");
    connect(generateReportAction, &QAction::triggered, this, &DashboardWindow::openReportDialog);
    

    // ── Main grid ──
    QGridLayout *mainLayout = new QGridLayout();
    mainLayout->setContentsMargins(5,5,5,5);
    mainLayout->setSpacing(10);

    // ── Active Sessions ──
    sessionTable = new QTableWidget(0, 6, this);
    sessionTable->setHorizontalHeaderLabels({"Session ID", "User", "TenantID", "Default Domain", "Resource", "Token Expiry"});
    sessionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    sessionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    sessionTable->setSelectionMode(QAbstractItemView::ExtendedSelection);  // Enable Shift+Click, Ctrl+Click
    sessionTable->setStyleSheet("background-color: transparent; border: none;");
    sessionTable->viewport()->setAutoFillBackground(false);
    sessionTable->setSortingEnabled(true);

    QHeaderView *header = sessionTable->horizontalHeader();
    header->setStretchLastSection(false);
    header->setSectionResizeMode(QHeaderView::Stretch);

    connect(sessionTable, &QTableWidget::cellDoubleClicked, this, &DashboardWindow::openUserSessionTab);
    sessionTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(sessionTable, &QTableWidget::customContextMenuRequested, this, &DashboardWindow::showSessionContextMenu);

    QGroupBox *sessionGroup = new QGroupBox(" Active Sessions");
    sessionGroup->setLayout(new QVBoxLayout());
    sessionGroup->layout()->addWidget(sessionTable);

    // ── Event Log ──
    eventLog = new QTextEdit(this);
    eventLog->setReadOnly(true);
    // Use monospace font for proper column alignment in command output
    QFont monoFont("Monospace", 9);
    monoFont.setStyleHint(QFont::Monospace);
    eventLog->setFont(monoFont);

    QGroupBox *eventGroup = new QGroupBox(" Event Log");
    eventGroup->setLayout(new QVBoxLayout());
    eventGroup->layout()->addWidget(eventLog);

    // ── Tabs ──
    tabs = new QTabWidget(this);
    tabs->setTabsClosable(true);
    connect(tabs, &QTabWidget::tabCloseRequested,
            this, &DashboardWindow::closeSessionTab);

    // Add widgets to grid
    mainLayout->addWidget(sessionGroup, 0, 0);
    mainLayout->addWidget(eventGroup,   0, 1);
    mainLayout->addWidget(tabs,         1, 0, 1, 2);

    outerLayout->addLayout(mainLayout);
    setCentralWidget(central);

    // ── Keyboard Shortcuts ──
    // Ctrl+N: New session (Device Code login)
    auto *shortcutNewSession = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_N), this);
    connect(shortcutNewSession, &QShortcut::activated, this, &DashboardWindow::launchDeviceCodeWindow);

    // F5: Refresh sessions list
    auto *shortcutRefresh = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(shortcutRefresh, &QShortcut::activated, this, &DashboardWindow::loadExistingSessions);

    // Ctrl+Q: Quit application
    auto *shortcutQuit = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Q), this);
    connect(shortcutQuit, &QShortcut::activated, this, &DashboardWindow::close);

    // Ctrl+Shift+T: Open Token Log
    auto *shortcutTokenLog = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_T), this);
    connect(shortcutTokenLog, &QShortcut::activated, this, &DashboardWindow::openTokenLogWindow);

    // Ctrl+G: Open Graph Query
    auto *shortcutGraph = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_G), this);
    connect(shortcutGraph, &QShortcut::activated, this, &DashboardWindow::openGraphQueries);

    // Ctrl+E: Open Azure Enumeration
    auto *shortcutEnum = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_E), this);
    connect(shortcutEnum, &QShortcut::activated, this, &DashboardWindow::openAzureEnumWindow);

    resize(1287, 700);

}

// ========== Slots (stubs) ==========
void DashboardWindow::launchAccessTokenWindow() {
    qDebug() << "launchAccessTokenWindow()";
    auto *w = new TokenLoginWindow(this);   // parent = dashboard for logging/callbacks
    WindowHelper::setupWindow(w, this, 500, 400, 400, 300);
    w->show();
}

// ========== Phishing ==========
void DashboardWindow::launchDeviceCodeWindow() {
    auto *dlg = new DeviceCodeLoginWindow(this, nullptr);
    WindowHelper::setupWindow(dlg, this, 700, 600, 500, 400);
    dlg->show();
}

void DashboardWindow::launchIllicitConsentWindow() {
    auto *dlg = new IllicitConsentGrant(this, nullptr);
    WindowHelper::setupWindow(dlg, this, 700, 600, 500, 400);
    dlg->show();
}

// Info
void DashboardWindow::onAzureLoginSuccess(const QString &token,const QString &resource,const QString &sessionId) {
    qDebug() << "[+] Azure login success for session:" << sessionId
             << "resource:" << resource
             << "token (truncated):" << token.left(20) << "...";
}

// Server is the authority now: request list from server
void DashboardWindow::loadExistingSessions() {
    if (sessionTable) sessionTable->setRowCount(0);
    if (!transport) 
	{ 
		//logEvent("[-] No transport: cannot list sessions."); 
		return; 
	}
    //logEvent("[*] Requesting sessions from server …");
    QJsonObject req{ { Protocol::F_ACTION, Protocol::ACTION_LIST } };
    transport->sendJson(req);
}

// ============ Buttons ===========
//void DashboardWindow::getUsers()      { qDebug() << "getUsers()"; }
//void DashboardWindow::getGroups()     { qDebug() << "getGroups()"; }
//void DashboardWindow::getUserRoles()  { qDebug() << "getUserRoles()"; }
//void DashboardWindow::getContext()    { qDebug() << "getContext()"; }
//void DashboardWindow::getAzContext()  { qDebug() << "getAzContext()"; }
//void DashboardWindow::getCurrentUser(){ qDebug() << "getCurrentUser()"; }
//void DashboardWindow::getTenantInfo() { qDebug() << "getTenantInfo()"; }
//void DashboardWindow::getTokenInfo()  { qDebug() << "getTokenInfo()"; }

// Session creation now happens on the server; this just opens the dialog
/*
void DashboardWindow::createNewSession() {
    auto *dlg = new CredentialLoginWindow(this, nullptr);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->resize(300, 150);
    dlg->show();
}
*/

void DashboardWindow::createNewSession() {
    auto *dlg = new CredentialLoginWindow(this, nullptr);
    dlg->setWindowFlag(Qt::Dialog, true);
    WindowHelper::setupWindow(dlg, this, 400, 250, 300, 200);
    dlg->show();
}



void DashboardWindow::removeSessionById(const QString &sessionId) {
    SessionInfo *info = getSession(sessionId);
    if (info && info->psProc) {
        info->psProc->kill();
        info->psProc->deleteLater();
    }
    sessions.remove(sessionId);

    // Remove row from table
    if (sessionTable) {
        sessionTable->setSortingEnabled(false);
        for (int row = 0; row < sessionTable->rowCount(); ++row) {
            QTableWidgetItem *idItem = sessionTable->item(row, 0);
            if (!idItem) continue;
            QString storedId = idItem->data(Qt::UserRole).toString();
            if (storedId == sessionId) {
                sessionTable->removeRow(row);
                break;
            }
        }
        sessionTable->setSortingEnabled(true);
    }

    // Remove any open tab linked to this session
    for (int i = 0; i < tabs->count(); ++i) {
        auto *tab = qobject_cast<DashboardTab*>(tabs->widget(i));
        if (tab && tab->getSessionId() == sessionId) {
            tabs->removeTab(i);
            tab->deleteLater();
            break;
        }
    }

    logEvent(QString("[-] Session removed: %1").arg(sessionId));
}

void DashboardWindow::addSessionRow(const QString &sessionId, const QString &username, const QString &tenantId, const QString &domain, const QString &resource, const QDateTime &expiry)
{
    if (!sessionTable) return;

    // Helper to create centered table items
    auto centeredItem = [](const QString &text) {
        auto *item = new QTableWidgetItem(text);
        item->setTextAlignment(Qt::AlignCenter);
        return item;
    };

    // Format expiry display
    QString expiryText = "N/A";
    if (expiry.isValid()) {
        expiryText = formatTimeRemaining(expiry);
    } else if (tokenExpiryMap.contains(sessionId)) {
        expiryText = formatTimeRemaining(tokenExpiryMap[sessionId].expiryTime);
    }

    // De-dupe: if the row already exists, just update it in place
    for (int row = 0; row < sessionTable->rowCount(); ++row) {
        QTableWidgetItem *idItem = sessionTable->item(row, 0);
        if (idItem && idItem->data(Qt::UserRole).toString() == sessionId) {
            sessionTable->setItem(row, 1, centeredItem(username.isEmpty() ? "Unknown" : username));
            sessionTable->setItem(row, 2, centeredItem(tenantId.isEmpty() ? "N/A" : tenantId));
            sessionTable->setItem(row, 3, centeredItem(domain.isEmpty() ? "N/A" : domain));
            sessionTable->setItem(row, 4, centeredItem(resource.isEmpty() ? "N/A" : resource));
            sessionTable->setItem(row, 5, centeredItem(expiryText));
            return;
        }
    }

    sessionTable->setSortingEnabled(false);

    const int row = sessionTable->rowCount();
    sessionTable->insertRow(row);

    auto *idItem = centeredItem(sessionId.left(8));
    idItem->setData(Qt::UserRole, sessionId);
    sessionTable->setItem(row, 0, idItem);
    sessionTable->setItem(row, 1, centeredItem(username.isEmpty() ? "Unknown" : username));
    sessionTable->setItem(row, 2, centeredItem(tenantId.isEmpty() ? "N/A" : tenantId));
    sessionTable->setItem(row, 3, centeredItem(domain.isEmpty() ? "N/A" : domain));
    sessionTable->setItem(row, 4, centeredItem(resource.isEmpty() ? "N/A" : resource));
    sessionTable->setItem(row, 5, centeredItem(expiryText));

    sessionTable->setSortingEnabled(true);
}


void DashboardWindow::updateSessionRow(const QString &sessionId, const QString &username, const QString &tenantId, const QString &defaultDomain, const QString &resource) {
    if (!sessionTable) return;

    // Helper to create centered table items
    auto centeredItem = [](const QString &text) {
        auto *item = new QTableWidgetItem(text);
        item->setTextAlignment(Qt::AlignCenter);
        return item;
    };

    for (int row = 0; row < sessionTable->rowCount(); ++row) {
        QTableWidgetItem *idItem = sessionTable->item(row, 0);
        if (idItem && idItem->data(Qt::UserRole).toString() == sessionId) {
            sessionTable->setItem(row, 1, centeredItem(username));
            sessionTable->setItem(row, 2, centeredItem(tenantId));
            sessionTable->setItem(row, 3, centeredItem(defaultDomain));
            sessionTable->setItem(row, 4, centeredItem(resource));
            break;
        }
    }
}

void DashboardWindow::openUserSessionTab(int row, int /*column*/) {
    if (!sessionTable) return;

    QTableWidgetItem *item = sessionTable->item(row, 0);
    if (!item) return;

    const QString sessionId = item->data(Qt::UserRole).toString();
    if (sessionId.isEmpty()) {
        if (eventLog) eventLog->append("[-] Missing sessionId for selected row.");
        return;
    }

    // If the tab already exists, just focus it.
    for (int i = 0; i < tabs->count(); ++i) {
        if (auto *tab = qobject_cast<DashboardTab*>(tabs->widget(i))) {
            if (tab->getSessionId() == sessionId) {
                tabs->setCurrentIndex(i);

                // Still ask the server to ensure/attach in case the process died or we reconnect
                if (!transport) {
                    if (eventLog) eventLog->append("[-] No transport: cannot reattach to existing session.");
                    return;
                }
                QJsonObject req{{Protocol::F_ACTION, "get_session"}, {"sessionId", sessionId}};
                transport->sendJson(req);
                return;
            }
        }
    }

    // No existing tab — ask the server for canonical info (+ ensure proc & subscribe)
    if (!transport) {
        if (eventLog) eventLog->append("[-] No transport: cannot open session.");
        return;
    }

    //if (eventLog) eventLog->append(QString("[*] Opening session %1 …").arg(sessionId));

    QJsonObject req{{Protocol::F_ACTION, "get_session"}, {"sessionId", sessionId}};
    transport->sendJson(req);

    // (Optional legacy fallback)
    // QJsonObject alt{{Protocol::F_ACTION, "attach"}, {"sessionId", sessionId}};
    // transport->sendJson(alt);
}

void DashboardWindow::closeSessionTab(int index) {
    if (index < 0 || index >= tabs->count()) return;

    QWidget *widget = tabs->widget(index);
    tabs->removeTab(index);
    if (widget) {
        widget->deleteLater();
    }
}

void DashboardWindow::showSessionContextMenu(const QPoint &pos) {
    if (!sessionTable) return;

    QTableWidgetItem *item = sessionTable->itemAt(pos);
    if (!item) return;

    int row = item->row();
    QTableWidgetItem *idItem = sessionTable->item(row, 0);
    if (!idItem) return;

    const QString sessionId = idItem->data(Qt::UserRole).toString();
    if (sessionId.isEmpty()) return;

    // Get session info for display
    QString username = "Unknown";
    QString tenantId = "N/A";
    QString domain = "N/A";
    QString resource = "N/A";

    if (QTableWidgetItem *userItem = sessionTable->item(row, 1))
        username = userItem->text();
    if (QTableWidgetItem *tenantItem = sessionTable->item(row, 2))
        tenantId = tenantItem->text();
    if (QTableWidgetItem *domainItem = sessionTable->item(row, 3))
        domain = domainItem->text();
    if (QTableWidgetItem *resourceItem = sessionTable->item(row, 4))
        resource = resourceItem->text();

    // Create context menu
    QMenu contextMenu(this);

    // Open Session action
    QAction *openAction = contextMenu.addAction("Open Session");
    openAction->setIcon(QIcon::fromTheme("document-open"));

    // View Details action
    QAction *detailsAction = contextMenu.addAction("View Details...");
    detailsAction->setIcon(QIcon::fromTheme("dialog-information"));

    contextMenu.addSeparator();

    // Refresh action
    QAction *refreshAction = contextMenu.addAction("Refresh Session");
    refreshAction->setIcon(QIcon::fromTheme("view-refresh"));

    contextMenu.addSeparator();

    // Copy actions
    QMenu *copyMenu = contextMenu.addMenu("Copy");
    copyMenu->setIcon(QIcon::fromTheme("edit-copy"));

    QAction *copyIdAction = copyMenu->addAction("Session ID (short)");
    QAction *copyFullIdAction = copyMenu->addAction("Session ID (full)");
    QAction *copyUserAction = copyMenu->addAction("Username");
    QAction *copyTenantAction = copyMenu->addAction("Tenant ID");
    QAction *copyDomainAction = copyMenu->addAction("Domain");

    contextMenu.addSeparator();

    // Remove action (with confirmation)
    QAction *removeAction = contextMenu.addAction("Remove Session");
    removeAction->setIcon(QIcon::fromTheme("edit-delete"));

    // Show menu and handle selection
    QAction *selectedAction = contextMenu.exec(sessionTable->viewport()->mapToGlobal(pos));

    if (!selectedAction) return;

    if (selectedAction == openAction) {
        // Open the session tab
        openUserSessionTab(row, 0);

    } else if (selectedAction == detailsAction) {
        // Show session details dialog
        QString details = QString(
            "<h3>Session Details</h3>"
            "<table style='margin-left: 10px;'>"
            "<tr><td><b>Session ID:</b></td><td style='padding-left: 10px;'>%1</td></tr>"
            "<tr><td><b>User:</b></td><td style='padding-left: 10px;'>%2</td></tr>"
            "<tr><td><b>Tenant ID:</b></td><td style='padding-left: 10px;'>%3</td></tr>"
            "<tr><td><b>Domain:</b></td><td style='padding-left: 10px;'>%4</td></tr>"
            "<tr><td><b>Resource:</b></td><td style='padding-left: 10px;'>%5</td></tr>"
            "</table>"
        ).arg(sessionId, username, tenantId, domain, resource);

        QMessageBox detailsBox(this);
        detailsBox.setWindowTitle("Session Details");
        detailsBox.setTextFormat(Qt::RichText);
        detailsBox.setText(details);
        detailsBox.setIcon(QMessageBox::Information);
        detailsBox.setStandardButtons(QMessageBox::Ok);

        // Add copy all button
        QPushButton *copyAllBtn = detailsBox.addButton("Copy All", QMessageBox::ActionRole);

        detailsBox.exec();

        if (detailsBox.clickedButton() == copyAllBtn) {
            QString allInfo = QString(
                "Session ID: %1\n"
                "User: %2\n"
                "Tenant ID: %3\n"
                "Domain: %4\n"
                "Resource: %5"
            ).arg(sessionId, username, tenantId, domain, resource);
            QApplication::clipboard()->setText(allInfo);
            logEvent("[*] Session details copied to clipboard");
        }

    } else if (selectedAction == refreshAction) {
        // Request session info refresh from server
        if (transport) {
            QJsonObject req;
            req.insert(Protocol::F_ACTION, "get_session");
            req.insert("sessionId", sessionId);
            transport->sendJson(req);
            logEvent(QString("[*] Refreshing session: %1").arg(sessionId.left(8)));
        }
        // Also reload the full sessions list
        loadExistingSessions();

    } else if (selectedAction == copyIdAction) {
        QApplication::clipboard()->setText(sessionId.left(8));
        logEvent(QString("[*] Session ID copied: %1").arg(sessionId.left(8)));

    } else if (selectedAction == copyFullIdAction) {
        QApplication::clipboard()->setText(sessionId);
        logEvent("[*] Full Session ID copied to clipboard");

    } else if (selectedAction == copyUserAction) {
        QApplication::clipboard()->setText(username);
        logEvent(QString("[*] Username copied: %1").arg(username));

    } else if (selectedAction == copyTenantAction) {
        QApplication::clipboard()->setText(tenantId);
        logEvent(QString("[*] Tenant ID copied: %1").arg(tenantId));

    } else if (selectedAction == copyDomainAction) {
        QApplication::clipboard()->setText(domain);
        logEvent(QString("[*] Domain copied: %1").arg(domain));

    } else if (selectedAction == removeAction) {
        // Confirm removal
        QMessageBox::StandardButton reply = QMessageBox::question(
            this,
            "Remove Session",
            QString("Are you sure you want to remove session for '%1'?\n\nSession ID: %2")
                .arg(username, sessionId.left(8)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No
        );

        if (reply == QMessageBox::Yes) {
            // Send remove request to server
            if (transport) {
                QJsonObject req;
                req.insert(Protocol::F_ACTION, Protocol::ACTION_REMOVE);
                req.insert("sessionId", sessionId);
                transport->sendJson(req);
                logEvent(QString("[*] Removing session: %1").arg(sessionId.left(8)));
            }

            // Remove from local state
            removeSessionById(sessionId);
        }
    }
}

void DashboardWindow::removeSessionRow(int rowIndex) {
    if (!sessionTable || rowIndex < 0 || rowIndex >= sessionTable->rowCount()) return;

    QTableWidgetItem *idItem = sessionTable->item(rowIndex, 0);
    if (idItem) {
        QString sessionId = idItem->data(Qt::UserRole).toString();
        removeSessionById(sessionId);
    }
}

// ==== Post Exploitation =====
void DashboardWindow::openTeamsChatWindow() {
    auto *dlg = WindowFactory::createTeamsChatWindow();
    WindowHelper::setupWindow(dlg, this, 900, 650, 700, 500);
    dlg->show();
}

void DashboardWindow::openOnedriveExplorer() {
    auto *dlg = WindowFactory::createSharePointBrowserWindow();
    WindowHelper::setupWindow(dlg, this, 800, 550, 600, 400);
    dlg->show();
}

void DashboardWindow::openOutlookEmailWindow() {
    auto *dlg = WindowFactory::createOutlookEmailWindow();
    WindowHelper::setupWindow(dlg, this, 1100, 700, 800, 500);
    dlg->show();
}

void DashboardWindow::openOutlookCalendar() {
    auto *win = WindowFactory::createOutlookCalendarWindow();
    WindowHelper::setupWindow(win, this, 800, 600, 600, 400);
    win->show();
}

void DashboardWindow::openRefreshTokensMenu() {
    auto *win = WindowFactory::createRequestRefreshTokens();
    WindowHelper::setupWindow(win, this, 600, 500, 400, 350);
    win->show();
}

void DashboardWindow::openPRTTokenMenu() {
    auto *win = WindowFactory::createPRTTokenUI();
    WindowHelper::setupWindow(win, this, 600, 500, 400, 350);
    win->show();
}

void DashboardWindow::openSsoTokenMenu() {
    auto *win = WindowFactory::createSsoCookieTokenWindow();
    WindowHelper::setupWindow(win, this, 600, 500, 400, 350);
    win->show();
}

// Attacks
void DashboardWindow::openAttackPasswordSpray() {
    auto *win = WindowFactory::createMSOLSprayWindow();
    WindowHelper::setupWindow(win, this, 700, 500, 500, 400);
    win->show();
}

void DashboardWindow::openAttackAppSecret() {
    auto *win = WindowFactory::createAddAzADAppSecretWindow();
    WindowHelper::setupWindow(win, this, 700, 550, 500, 400);
    win->show();
}

void DashboardWindow::openSPNSpray() {
    auto *win = WindowFactory::createSPNSpraySerialWindow();
    WindowHelper::setupWindow(win, this, 800, 600, 600, 450);
    win->show();
}

void DashboardWindow::openGraphQueries() {
    auto *win = WindowFactory::createGraphQueryWindow();
    WindowHelper::setupWindow(win, this, 900, 700, 700, 500);
    win->show();
}

void DashboardWindow::openTokenLogWindow() {
    auto *win = WindowFactory::createTokenLogWindow();
    WindowHelper::setupWindow(win, this, 1000, 700, 800, 500);
    win->show();
}

void DashboardWindow::openTokenAnalysisWindow() {
    auto *win = WindowFactory::createTokenAnalysisWindow();
    WindowHelper::setupWindow(win, this, 900, 700, 800, 500);
    win->show();
}

void DashboardWindow::openSessionTimelineWindow() {
    auto *win = WindowFactory::createSessionTimelineWindow();
    WindowHelper::setupWindow(win, this, 1000, 600, 800, 400);
    win->show();
}

void DashboardWindow::openReportDialog() {
    auto *dialog = new ReportDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    WindowHelper::centerOnParent(dialog, this);
    dialog->exec();
}

void DashboardWindow::openAttackWfh() {
    auto *win = WindowFactory::createWHfBAttackWindow();
    WindowHelper::setupWindow(win, this, 900, 700, 800, 600);
    win->show();
}

void DashboardWindow::openMfaStatusChecker() {
    auto *win = WindowFactory::createMfaStatusCheckerWindow();
    WindowHelper::setupWindow(win, this, 1100, 700, 900, 600);
    win->show();
}

void DashboardWindow::openPasswordWritebackChecker() {
    auto *win = WindowFactory::createPasswordWritebackCheckerWindow();
    WindowHelper::setupWindow(win, this, 1200, 750, 1000, 650);
    win->show();
}

void DashboardWindow::openOAuthConsentEnumerator() {
    auto *win = WindowFactory::createOAuthConsentEnumeratorWindow();
    WindowHelper::setupWindow(win, this, 1200, 800, 1000, 650);
    win->show();
}

void DashboardWindow::openAzureEnumWindow() {
    auto *win = WindowFactory::createAzureEnumWindow();
    WindowHelper::setupWindow(win, this, 900, 600, 700, 450);
    win->show();
}

void DashboardWindow::openConditionalAccessWindow() {
    auto *win = WindowFactory::createConditionalAccessWindow();
    WindowHelper::setupWindow(win, this, 1000, 600, 800, 500);
    win->show();
}

void DashboardWindow::openCrossTenantAccessWindow() {
    auto *win = WindowFactory::createCrossTenantAccessWindow();
    WindowHelper::setupWindow(win, this, 1100, 700, 900, 600);
    win->show();
}

void DashboardWindow::openAzureStorageWindow() {
    auto *win = WindowFactory::createAzureStorageWindow();
    WindowHelper::setupWindow(win, this, 900, 600, 700, 450);
    win->show();
}

void DashboardWindow::openPostExploitWindow() {
    auto *win = WindowFactory::createPostExploitWindow();
    WindowHelper::setupWindow(win, this, 800, 600, 600, 450);
    win->show();
}

// ===============================

// Event log stub
void DashboardWindow::logEvent(const QString &msg) {
    if (!eventLog) return;
    eventLog->append(msg);
}

/*
void DashboardWindow::logConnectionEvent(const QString &username, const QString &sessionId) {
    //QString message = QString("[+] Session created for user: %1 (ID: %2)").arg(username.isEmpty() ? "Unknown" : username).arg(sessionId);
    logEvent(message);
}
*/

// ===============================
// ====== Server JSON slots ======

void DashboardWindow::onServerJson(const QJsonObject &obj)
{
    const QString status  = obj.value("status").toString();
    const QString message = obj.value("message").toString();

    // 1) Open/focus a session tab (server ensures proc + subscribes)
    if (status == QLatin1String("ok") && message == QLatin1String("session_info")) {
        const QJsonObject data = obj.value("data").toObject();
        const QString sid      = data.value("sessionId").toString();
        if (sid.isEmpty()) {
            if (eventLog) eventLog->append("[-] session_info missing sessionId");
            return;
        }

        const QString resource = data.value("resource").toString("https://management.azure.com");
        const QString user     = data.value("user").toString();
        const QString domain   = data.value("domain").toString();
        const QString tenId    = data.value("tenantId").toString();
        const QString sstatus  = data.value("status").toString("pending");
        const bool    alive    = data.value("alive").toBool(true);

        // Focus existing tab if present
        for (int i = 0; i < tabs->count(); ++i) {
            if (auto *existing = qobject_cast<DashboardTab*>(tabs->widget(i))) {
                if (existing->getSessionId() == sid) {
                    tabs->setCurrentIndex(i);
                    // Optional: update tab meta if your DashboardTab exposes it
                    if (existing->metaObject()->indexOfMethod("setMeta(QString,QString,QString,QString,QString,bool)") >= 0) {
                        QMetaObject::invokeMethod(existing, "setMeta",
                            Q_ARG(QString, user),
                            Q_ARG(QString, domain),
                            Q_ARG(QString, tenId),
                            Q_ARG(QString, resource),
                            Q_ARG(QString, sstatus),
                            Q_ARG(bool,    alive));
                    }
                    //if (eventLog) eventLog->append(QString("[*] Focused tab for %1 (alive=%2, status=%3)").arg(sid.left(8)).arg(alive ? "true" : "false").arg(sstatus));
                    return;
                }
            }
        }

        // Create new tab
        QString title = QString("Session %1").arg(sid.left(8));
        if (!user.isEmpty()) title += QString(" · %1").arg(user);

        DashboardTab *tab = new DashboardTab(
            title,
            /*token*/ QString(),      // token is server-side now
            resource,
            /*loginScript*/ QString(),
            sid,
            this,
            tabs
        );

        if (tab->metaObject()->indexOfMethod("setMeta(QString,QString,QString,QString,QString,bool)") >= 0) {
            QMetaObject::invokeMethod(tab, "setMeta",
                Q_ARG(QString, user),
                Q_ARG(QString, domain),
                Q_ARG(QString, tenId),
                Q_ARG(QString, resource),
                Q_ARG(QString, sstatus),
                Q_ARG(bool,    alive));
        }

        const int idx = tabs->addTab(tab, title);
        tabs->setCurrentIndex(idx);

        //if (eventLog) eventLog->append(QString("[+] Opened tab for %1 (alive=%2, status=%3)").arg(sid.left(8)).arg(alive ? "true" : "false").arg(sstatus));
        return;
    }

    // 2) Populate/refresh the SessionTable from server DB
    if (status == QLatin1String("ok") && message == QLatin1String("list ok")) {
        const QJsonArray rows = obj.value("data").toArray();
        if (sessionTable) {
            sessionTable->setSortingEnabled(false);
            sessionTable->setRowCount(0);
        }

        for (const QJsonValue &v : rows) {
            const QJsonObject row = v.toObject();
            const QString sid     = row.value("sessionId").toString();
            const QString user    = row.value("user").toString();
            const QString ten     = row.value("tenantId").toString();
            const QString dom     = row.value("domain").toString();
            const QString res     = row.value("resource").toString("https://management.azure.com");
            addSessionRow(sid, user, ten, dom, res);
        }

        if (sessionTable) sessionTable->setSortingEnabled(true);
        //if (eventLog) eventLog->append(QString("[+] Received %1 sessions from server").arg(rows.size()));
        return;
    }

    // 3) Back-compat: treat "attach ok" with data as session_info
    if (status == QLatin1String("ok") && message == QLatin1String("attach ok")) {
        QJsonObject shim{
            {"status",  "ok"},
            {"message", "session_info"},
            {"data",    obj.value("data").toObject()}
        };
        onServerJson(shim);
        return;
    }

    // 4) Live table updates on auth success (optional)
    if (message == QLatin1String("session_created")) {
        const QString sid = obj.value("sessionId").toString();
        const QString user = obj.value("user").toString("Unknown");
        const QString dom  = obj.value("domain").toString("N/A");
        const QString ten  = obj.value("tenantId").toString("N/A");
        const QString res  = obj.value("resource").toString("https://management.azure.com");
        updateSessionRow(sid, user, ten, dom, res);
        return;
    }

    // 5) Generic error
    if (status == QLatin1String("error")) {
        const QString msg = obj.value("message").toString("request failed");
        if (eventLog) eventLog->append(QString("[-] %1").arg(msg));
        return;
    }

    // Other events (output/session_open/session_exited) handled elsewhere.
}

// -----------------------------------------------------------------------------
// Runtime injection of transport, with robust connects and initial list request
// -----------------------------------------------------------------------------
void DashboardWindow::setTransport(ClientTransport* t)
{
    // If we already had a transport, disconnect its signals first
    if (transport) {
        QObject::disconnect(transport, nullptr, this, nullptr);
    }

    transport = t;

    if (!transport) {
        if (eventLog) eventLog->append("[-] No transport; server features disabled.");
        return;
    }

    // Connect once only; Qt::UniqueConnection prevents duplicate signal hookups
    QObject::connect(transport, SIGNAL(messageReceived(QJsonObject)),
                     this,       SLOT(onServerJson(QJsonObject)),
                     Qt::UniqueConnection);

    // Log exchanged tokens to the server when TokenHelper re-exchanges with a new client ID
    connect(TokenHelper::instance(), &TokenHelper::tokenExchanged, this,
        [this](const QString &accessToken, const QString &refreshToken,
               const QString &upn, const QString &tenantId, const QString &resource) {
            if (!transport) return;
            QJsonObject req;
            req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
            req.insert("sessionId", QString("%1_%2").arg(upn, resource));
            req.insert("source", "auto_client_exchange");
            req.insert("accessToken", accessToken);
            if (!refreshToken.isEmpty())
                req.insert("refreshToken", refreshToken);
            if (!upn.isEmpty())
                req.insert("user", upn);
            if (!tenantId.isEmpty())
                req.insert("tenantId", tenantId);
            if (!resource.isEmpty())
                req.insert("resource", resource);
            transport->sendJson(req);
            logEvent(QString("[Token] Exchanged token for %1 → %2").arg(upn, resource));
        }, Qt::UniqueConnection);

    // Pull the initial list
    loadExistingSessions();

    // Start the expiry update timer (every 1 second for live countdown)
    if (!expiryUpdateTimer) {
        expiryUpdateTimer = new QTimer(this);
        connect(expiryUpdateTimer, &QTimer::timeout, this, &DashboardWindow::updateExpiryDisplay);
        expiryUpdateTimer->start(1000); // 1 second for live countdown
    }

    // Auto-restore saved sessions
    QTimer::singleShot(1000, this, &DashboardWindow::autoRestoreSessions);
}

// -----------------------------------------------------------------------------
// Token Expiry Management
// -----------------------------------------------------------------------------

QString DashboardWindow::formatTimeRemaining(const QDateTime &expiry) const {
    if (!expiry.isValid()) return "N/A";

    QDateTime now = QDateTime::currentDateTimeUtc();
    qint64 secsRemaining = now.secsTo(expiry);

    if (secsRemaining <= 0) {
        return QString("EXPIRED");
    }

    // Build remaining time string (live countdown format)
    QString remaining;
    if (secsRemaining < 60) {
        // Less than 1 minute: show seconds only
        remaining = QString("0:%1").arg(secsRemaining, 2, 10, QChar('0'));
    } else if (secsRemaining < 3600) {
        // Less than 1 hour: show mm:ss
        int mins = secsRemaining / 60;
        int secs = secsRemaining % 60;
        remaining = QString("%1:%2").arg(mins).arg(secs, 2, 10, QChar('0'));
    } else if (secsRemaining < 86400) {
        // Less than 1 day: show hh:mm:ss
        int hours = secsRemaining / 3600;
        int mins = (secsRemaining % 3600) / 60;
        int secs = secsRemaining % 60;
        remaining = QString("%1:%2:%3").arg(hours).arg(mins, 2, 10, QChar('0')).arg(secs, 2, 10, QChar('0'));
    } else {
        // More than 1 day: show days + hours
        int days = secsRemaining / 86400;
        int hours = (secsRemaining % 86400) / 3600;
        remaining = QString("%1d %2h").arg(days).arg(hours);
    }

    return remaining;
}

QDateTime DashboardWindow::parseTokenExpiry(const QString &accessToken) const {
    // JWT format: header.payload.signature
    QStringList parts = accessToken.split('.');
    if (parts.size() < 2) {
        qDebug() << "[TokenExpiry] Invalid JWT format - not enough parts";
        return QDateTime();
    }

    // Decode payload (base64url)
    QByteArray payload = parts[1].toUtf8();

    // Add padding if needed for base64
    int padding = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(padding, '='));

    // Decode base64url (replace URL-safe chars with standard base64)
    QByteArray decoded = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(decoded, &err);

    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        qDebug() << "[TokenExpiry] Failed to parse JWT payload as JSON:" << err.errorString();
        return QDateTime();
    }

    QJsonObject obj = doc.object();

    // Extract exp (expiration time) - Unix epoch timestamp
    if (!obj.contains("exp")) {
        qDebug() << "[TokenExpiry] JWT missing 'exp' claim";
        return QDateTime();
    }

    // Handle both integer and double representations of Unix timestamp
    qint64 expTimestamp = 0;
    QJsonValue expValue = obj["exp"];
    if (expValue.isDouble()) {
        expTimestamp = static_cast<qint64>(expValue.toDouble());
    } else {
        expTimestamp = expValue.toVariant().toLongLong();
    }

    // Debug: also show iat (issued at) if present
    if (obj.contains("iat")) {
        qint64 iatTimestamp = obj["iat"].toVariant().toLongLong();
        QDateTime iat = QDateTime::fromSecsSinceEpoch(iatTimestamp, QTimeZone::utc());
        qDebug() << "[TokenExpiry] Token issued at:" << iat.toString("yyyy-MM-dd hh:mm:ss UTC");
    }

    QDateTime expiry = QDateTime::fromSecsSinceEpoch(expTimestamp, QTimeZone::utc());
    qDebug() << "[TokenExpiry] Token expires at:" << expiry.toString("yyyy-MM-dd hh:mm:ss UTC")
             << "(Unix:" << expTimestamp << ")";

    return expiry;
}

void DashboardWindow::setSessionTokenExpiry(const QString &sessionId, const QString &accessToken,
                                            const QString &refreshToken, const QString &resource,
                                            const QString &tenantId) {
    QDateTime expiry = parseTokenExpiry(accessToken);

    TokenExpiry tokenExp;
    tokenExp.expiryTime = expiry;
    tokenExp.refreshToken = refreshToken;
    tokenExp.resource = resource;
    tokenExp.tenantId = tenantId;
    tokenExp.autoRenewEnabled = autoRenewEnabled;

    tokenExpiryMap[sessionId] = tokenExp;

    // Also store in TokenStore for user-scoped access in plugin windows
    if (!accessToken.isEmpty()) {
        TokenInfo tokenInfo;
        tokenInfo.accessToken = accessToken;
        tokenInfo.refreshToken = refreshToken;
        tokenInfo.resource = resource;
        tokenInfo.tenantId = tenantId;
        tokenInfo.expiresAt = expiry;
        // UPN will be auto-extracted from JWT by TokenStore::storeToken
        TokenStore::instance()->storeToken(sessionId, tokenInfo);
    }

    if (expiry.isValid()) {
        logEvent(QString("[*] Token for session %1 expires: %2")
                 .arg(sessionId.left(8), expiry.toString("yyyy-MM-dd hh:mm:ss UTC")));
    }

    // Auto-save session for persistence
    if (!refreshToken.isEmpty()) {
        autoSaveSession(sessionId);
    }

    // Update the display
    updateExpiryDisplay();
}

void DashboardWindow::updateExpiryDisplay() {
    if (!sessionTable) return;

    QDateTime now = QDateTime::currentDateTimeUtc();

    for (int row = 0; row < sessionTable->rowCount(); ++row) {
        QTableWidgetItem *idItem = sessionTable->item(row, 0);
        if (!idItem) continue;

        QString sessionId = idItem->data(Qt::UserRole).toString();
        if (!tokenExpiryMap.contains(sessionId)) continue;

        const TokenExpiry &tokenExp = tokenExpiryMap[sessionId];
        QString expiryText = formatTimeRemaining(tokenExp.expiryTime);

        // Get or create expiry item
        QTableWidgetItem *expiryItem = sessionTable->item(row, 5);
        if (!expiryItem) {
            expiryItem = new QTableWidgetItem();
            expiryItem->setTextAlignment(Qt::AlignCenter);
            sessionTable->setItem(row, 5, expiryItem);
        }
        expiryItem->setText(expiryText);

        // Color coding based on time remaining
        qint64 secsRemaining = now.secsTo(tokenExp.expiryTime);

        if (secsRemaining <= 0) {
            // Expired - red
            expiryItem->setForeground(QColor(220, 53, 69));  // Red
            expiryItem->setToolTip("Token has expired");

            // Auto-renew if enabled
            if (autoRenewEnabled && tokenExp.autoRenewEnabled && !tokenExp.refreshToken.isEmpty()) {
                refreshTokenForSession(sessionId);
            }
        } else if (secsRemaining < 300) {
            // Less than 5 minutes - orange/warning
            expiryItem->setForeground(QColor(255, 193, 7));  // Warning yellow
            expiryItem->setToolTip("Token expiring soon!");
        } else if (secsRemaining < 900) {
            // Less than 15 minutes - yellow
            expiryItem->setForeground(QColor(255, 193, 7));
            expiryItem->setToolTip("Token expires in less than 15 minutes");
        } else {
            // Valid - green
            expiryItem->setForeground(QColor(40, 167, 69));  // Green
            expiryItem->setToolTip(QString("Valid until: %1").arg(tokenExp.expiryTime.toString("yyyy-MM-dd hh:mm:ss UTC")));
        }
    }
}

void DashboardWindow::toggleAutoRenew(bool enabled) {
    autoRenewEnabled = enabled;

    // Save to settings
    QSettings settings("ANIMO", "Client");
    settings.setValue("autoRenewTokens", enabled);

    QString status = enabled ? "enabled" : "disabled";
    logEvent(QString("[*] Token auto-renewal %1").arg(status));
}

void DashboardWindow::refreshTokenForSession(const QString &sessionId) {
    if (!tokenExpiryMap.contains(sessionId)) return;

    TokenExpiry &tokenExp = tokenExpiryMap[sessionId];
    if (tokenExp.refreshToken.isEmpty()) {
        logEvent(QString("[-] Cannot refresh token for %1: no refresh token available").arg(sessionId.left(8)));
        return;
    }

    logEvent(QString("[*] Auto-refreshing token for session %1...").arg(sessionId.left(8)));

    // Mark as pending to prevent multiple refresh attempts
    tokenExp.autoRenewEnabled = false;

    // Send refresh request to server
    if (transport) {
        QJsonObject req;
        req.insert("action", "refresh_token");
        req.insert("sessionId", sessionId);
        req.insert("refreshToken", tokenExp.refreshToken);
        req.insert("resource", tokenExp.resource);
        req.insert("tenantId", tokenExp.tenantId);
        transport->sendJson(req);
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Discovery Features - Window Launchers
// ────────────────────────────────────────────────────────────────────────────────

void DashboardWindow::openKeyVaultExplorer() {
    auto *win = WindowFactory::createKeyVaultExplorerWindow();
    WindowHelper::setupWindow(win, this, 900, 700, 700, 500);
    win->show();
}

void DashboardWindow::openSqlDatabaseExplorer() {
    auto *win = WindowFactory::createSqlDatabaseWindow();
    WindowHelper::setupWindow(win, this, 1100, 750, 900, 600);
    win->show();
}

void DashboardWindow::openAzureVMManager() {
    auto *win = WindowFactory::createAzureVMManagerWindow();
    WindowHelper::setupWindow(win, this, 1000, 700, 800, 500);
    win->show();
}

void DashboardWindow::openRunbookExplorer() {
    auto *win = WindowFactory::createRunbookExplorerWindow();
    WindowHelper::setupWindow(win, this, 950, 700, 750, 500);
    win->show();
}

void DashboardWindow::openSPNEnumWindow() {
    auto *win = WindowFactory::createSPNEnumWindow();
    WindowHelper::setupWindow(win, this, 900, 700, 700, 500);
    win->show();
}

void DashboardWindow::openFunctionAppExplorer() {
    auto *win = WindowFactory::createFunctionAppExplorerWindow();
    WindowHelper::setupWindow(win, this, 950, 700, 750, 500);
    win->show();
}

void DashboardWindow::openLogicAppsViewer() {
    auto *win = WindowFactory::createLogicAppsViewerWindow();
    WindowHelper::setupWindow(win, this, 900, 700, 700, 500);
    win->show();
}

void DashboardWindow::openEmailRulesWindow() {
    auto *win = WindowFactory::createEmailRulesWindow();
    WindowHelper::setupWindow(win, this, 1000, 700, 800, 550);
    win->show();
}

void DashboardWindow::openConsentManipulationWindow() {
    auto *win = WindowFactory::createConsentManipulationWindow();
    WindowHelper::setupWindow(win, this, 1300, 850, 1100, 700);
    win->show();
}

// ────────────────────────────────────────────────────────────────────────────────
// Auto Session Persistence
// ────────────────────────────────────────────────────────────────────────────────

void DashboardWindow::autoRestoreSessions() {
    auto savedSessions = SessionPersistence::instance().loadSavedSessions();

    if (savedSessions.isEmpty()) {
        return;
    }

    logEvent(QString("[*] Auto-restoring %1 saved session(s)...").arg(savedSessions.size()));

    for (const auto &sess : savedSessions) {
        if (sess.refreshToken.isEmpty()) {
            continue;
        }

        // Use Azure AD token endpoint to refresh
        QString url = QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(sess.tenantId);

        QUrlQuery postData;
        postData.addQueryItem("client_id", "1950a258-227b-4e31-a9cf-717495945fc2");  // Azure PowerShell
        postData.addQueryItem("grant_type", "refresh_token");
        postData.addQueryItem("refresh_token", sess.refreshToken);
        postData.addQueryItem("scope", sess.resource + "/.default offline_access");

        QNetworkRequest request{QUrl(url)};
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        NetworkHelper::setRequestTimeout(request);

        // Create a temporary NAM for restore operations
        auto *nam = new QNetworkAccessManager(this);
        QNetworkReply *reply = nam->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());

        QString sessionId = sess.sessionId;
        QString resource = sess.resource;
        QString tenantId = sess.tenantId;

        if (!reply) {
            logEvent(QString("[-] Failed to create restore request for %1").arg(sessionId.left(8)));
            nam->deleteLater();
            continue;
        }

        connect(reply, &QNetworkReply::finished, this, [this, reply, nam, sessionId, resource, tenantId]() {
            reply->deleteLater();
            nam->deleteLater();

            if (reply->error() != QNetworkReply::NoError) {
                logEvent(QString("[-] Failed to restore session %1: %2").arg(sessionId.left(8), reply->errorString()));
                // Remove invalid saved session
                SessionPersistence::instance().removeSession(sessionId);
                return;
            }

            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();

            QString newAccessToken = obj.value("access_token").toString();
            QString newRefreshToken = obj.value("refresh_token").toString();

            if (newAccessToken.isEmpty()) {
                logEvent(QString("[-] No access token in response for %1").arg(sessionId.left(8)));
                SessionPersistence::instance().removeSession(sessionId);
                return;
            }

            // Store the new tokens
            TokenInfo tokenInfo;
            tokenInfo.sessionId = sessionId;
            tokenInfo.accessToken = newAccessToken;
            tokenInfo.refreshToken = newRefreshToken;
            tokenInfo.resource = resource;
            tokenInfo.tenantId = tenantId;

            // Parse UPN from new token
            QJsonObject claims = TokenStore::parseJwtPayload(newAccessToken);
            tokenInfo.upn = claims.value("upn").toString();
            if (tokenInfo.upn.isEmpty()) {
                tokenInfo.upn = claims.value("preferred_username").toString();
            }
            if (tokenInfo.upn.isEmpty()) {
                tokenInfo.upn = claims.value("unique_name").toString();
            }

            tokenInfo.expiresAt = TokenStore::parseJwtExpiry(newAccessToken);
            tokenInfo.issuedAt = QDateTime::currentDateTime();

            TokenStore::instance()->storeToken(sessionId, tokenInfo);

            // Update the saved session with new refresh token
            if (!newRefreshToken.isEmpty()) {
                SessionPersistence::SavedSession updatedSess;
                updatedSess.sessionId = sessionId;
                updatedSess.user = tokenInfo.upn;
                updatedSess.tenantId = tenantId;
                updatedSess.resource = resource;
                updatedSess.refreshToken = newRefreshToken;
                updatedSess.lastRefreshed = QDateTime::currentDateTime();
                updatedSess.savedAt = QDateTime::currentDateTime();
                updatedSess.autoRestore = true;
                SessionPersistence::instance().saveSession(updatedSess);
            }

            // Update token expiry tracking
            setSessionTokenExpiry(sessionId, newAccessToken, newRefreshToken, resource, tenantId);

            logEvent(QString("[+] Restored session: %1 (%2)").arg(sessionId.left(8), tokenInfo.upn));
        });
    }
}

void DashboardWindow::autoSaveSession(const QString &sessionId) {
    // Get token info from TokenStore
    TokenInfo token = TokenStore::instance()->getTokenForSession(sessionId);

    if (token.refreshToken.isEmpty()) {
        return;  // Can't persist without refresh token
    }

    SessionPersistence::SavedSession sess;
    sess.sessionId = sessionId;
    sess.user = token.upn;
    sess.tenantId = token.tenantId;
    sess.resource = token.resource;
    sess.refreshToken = token.refreshToken;
    sess.savedAt = QDateTime::currentDateTime();
    sess.autoRestore = true;

    if (SessionPersistence::instance().saveSession(sess)) {
        qDebug() << "[SessionPersistence] Auto-saved session:" << sessionId.left(8);
    }
}

// -----------------------------------------------------------------------------
// Session Export/Import Windows
// -----------------------------------------------------------------------------
void DashboardWindow::openExportSessionsWindow() {
    auto *win = new SessionExportWindow(transport, this);
    WindowHelper::setupWindow(win, this, 450, 500);
    win->show();
}

void DashboardWindow::openImportSessionsWindow() {
    auto *win = new SessionImportWindow(transport, this);
    WindowHelper::setupWindow(win, this, 600, 550);
    win->show();
}
