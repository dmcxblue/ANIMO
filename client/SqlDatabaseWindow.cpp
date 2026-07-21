#include "SqlDatabaseWindow.h"
#include "StyleManager.h"
#include "TokenHelper.h"
#include "TokenStore.h"
#include "NetworkHelper.h"
#include "InputValidator.h"
#include "OutputSanitizer.h"

#include <memory>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QSplitter>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QTextStream>
#include <QDateTime>
#include <QDir>
#include <QInputDialog>

SqlDatabaseWindow::SqlDatabaseWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)), pwshProcess(nullptr)
{
    setWindowTitle("Azure SQL Database Explorer");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
    checkExistingTokens();
}

SqlDatabaseWindow::~SqlDatabaseWindow() {
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

void SqlDatabaseWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // ====================================================================
    // Auth mode selector
    // ====================================================================
    auto *authModeRow = new QHBoxLayout();
    authModeRow->addWidget(new QLabel("Authentication Mode:", this));
    authModeCombo = new QComboBox(this);
    authModeCombo->addItem("Token Authentication");
    authModeCombo->addItem("SQL Credentials (Invoke-SqlCmd)");
    authModeCombo->setMinimumWidth(250);
    authModeRow->addWidget(authModeCombo);
    authModeRow->addStretch();
    mainLayout->addLayout(authModeRow);

    // ====================================================================
    // Stacked widget for auth modes
    // ====================================================================
    authStack = new QStackedWidget(this);

    // --- Page 0: Token Authentication (existing) ---
    auto *tokenPage = new QWidget(this);
    auto *tokenLayout = new QVBoxLayout(tokenPage);
    tokenLayout->setContentsMargins(0, 0, 0, 0);

    auto *tokenGroup = new QGroupBox("Token Authentication", this);
    auto *tokenGroupLayout = new QVBoxLayout(tokenGroup);

    // User selector row
    auto *userRow = new QHBoxLayout();
    userRow->addWidget(new QLabel("Active User:", this));
    userSelector = new QComboBox(this);
    userSelector->setMinimumWidth(300);
    userSelector->setPlaceholderText("Select user session...");
    userRow->addWidget(userSelector);
    auto *refreshUsersBtn = new QPushButton("Refresh", this);
    refreshUsersBtn->setFixedWidth(70);
    userRow->addWidget(refreshUsersBtn);
    userRow->addStretch();
    tokenGroupLayout->addLayout(userRow);

    // Auto-fetch button row
    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Tokens for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenGroupLayout->addLayout(autoFetchRow);

    connect(userSelector, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SqlDatabaseWindow::onUserSelected);
    connect(refreshUsersBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::refreshUserList);

    auto *mgmtRow = new QHBoxLayout();
    mgmtRow->addWidget(new QLabel("Management Token:", this));
    mgmtTokenInput = new QLineEdit(this);
    mgmtTokenInput->setPlaceholderText("Token for https://management.azure.com");
    mgmtTokenInput->setEchoMode(QLineEdit::Password);
    mgmtRow->addWidget(mgmtTokenInput);
    mgmtTokenStatus = new QLabel(this);
    mgmtTokenStatus->setFixedWidth(80);
    mgmtRow->addWidget(mgmtTokenStatus);
    tokenGroupLayout->addLayout(mgmtRow);

    auto *sqlRow = new QHBoxLayout();
    sqlRow->addWidget(new QLabel("SQL Database Token:", this));
    sqlTokenInput = new QLineEdit(this);
    sqlTokenInput->setPlaceholderText("Token for https://database.windows.net (required for schema/data)");
    sqlTokenInput->setEchoMode(QLineEdit::Password);
    sqlRow->addWidget(sqlTokenInput);
    sqlTokenStatus = new QLabel(this);
    sqlTokenStatus->setFixedWidth(80);
    sqlRow->addWidget(sqlTokenStatus);
    tokenGroupLayout->addLayout(sqlRow);

    tokenLayout->addWidget(tokenGroup);
    authStack->addWidget(tokenPage);

    connect(autoFetchBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::autoFetchTokens);

    // --- Page 1: SQL Credentials ---
    auto *credPage = new QWidget(this);
    auto *credLayout = new QVBoxLayout(credPage);
    credLayout->setContentsMargins(0, 0, 0, 0);

    auto *credGroup = new QGroupBox("SQL Credentials (Invoke-SqlCmd)", this);
    auto *credGroupLayout = new QVBoxLayout(credGroup);

    auto *serverRow = new QHBoxLayout();
    serverRow->addWidget(new QLabel("Server FQDN:", this));
    serverFqdnInput = new QLineEdit(this);
    serverFqdnInput->setPlaceholderText("e.g. myserver.database.windows.net");
    serverFqdnInput->setMinimumWidth(350);
    serverRow->addWidget(serverFqdnInput);
    credGroupLayout->addLayout(serverRow);

    auto *dbRow = new QHBoxLayout();
    dbRow->addWidget(new QLabel("Database:", this));
    credDatabaseInput = new QLineEdit(this);
    credDatabaseInput->setPlaceholderText("e.g. Finance, master");
    credDatabaseInput->setMinimumWidth(250);
    dbRow->addWidget(credDatabaseInput);
    dbRow->addStretch();
    credGroupLayout->addLayout(dbRow);

    auto *userPassRow = new QHBoxLayout();
    userPassRow->addWidget(new QLabel("Username:", this));
    sqlUsernameInput = new QLineEdit(this);
    sqlUsernameInput->setPlaceholderText("SQL username");
    sqlUsernameInput->setMinimumWidth(200);
    userPassRow->addWidget(sqlUsernameInput);
    userPassRow->addSpacing(20);
    userPassRow->addWidget(new QLabel("Password:", this));
    sqlPasswordInput = new QLineEdit(this);
    sqlPasswordInput->setPlaceholderText("SQL password");
    sqlPasswordInput->setEchoMode(QLineEdit::Password);
    sqlPasswordInput->setMinimumWidth(200);
    userPassRow->addWidget(sqlPasswordInput);
    credGroupLayout->addLayout(userPassRow);

    // Query template selector
    auto *queryRow = new QHBoxLayout();
    queryRow->addWidget(new QLabel("Query Template:", this));
    queryTemplateCombo = new QComboBox(this);
    queryTemplateCombo->addItem("Check Database Permissions", "SELECT * FROM fn_my_permissions(NULL, 'DATABASE');");
    queryTemplateCombo->addItem("Check Server Permissions", "SELECT * FROM fn_my_permissions(NULL, 'SERVER');");
    queryTemplateCombo->addItem("List Databases", "SELECT name, state_desc, recovery_model_desc FROM sys.databases;");
    queryTemplateCombo->addItem("List Tables (Schema)", "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_SCHEMA, TABLE_NAME;");
    queryTemplateCombo->addItem("Database Users & Roles", "SELECT name, type_desc, authentication_type_desc FROM sys.database_principals WHERE type NOT IN ('R') ORDER BY name;");
    queryTemplateCombo->addItem("Server Logins", "SELECT name, type_desc, is_disabled FROM sys.server_principals ORDER BY name;");
    queryTemplateCombo->addItem("Custom Query");
    queryTemplateCombo->setMinimumWidth(300);
    queryRow->addWidget(queryTemplateCombo);
    queryRow->addStretch();
    credGroupLayout->addLayout(queryRow);

    // Custom query input
    customQueryInput = new QTextEdit(this);
    customQueryInput->setPlaceholderText("Enter custom SQL query here...");
    customQueryInput->setMaximumHeight(80);
    customQueryInput->setVisible(false);
    credGroupLayout->addWidget(customQueryInput);

    // Run query button
    auto *credBtnRow = new QHBoxLayout();
    credQueryBtn = new QPushButton("Run Query", this);
    StyleManager::applyPrimaryStyle(credQueryBtn);
    credBtnRow->addWidget(credQueryBtn);
    credBtnRow->addStretch();
    credGroupLayout->addLayout(credBtnRow);

    credLayout->addWidget(credGroup);
    authStack->addWidget(credPage);

    mainLayout->addWidget(authStack);

    connect(authModeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SqlDatabaseWindow::onAuthModeChanged);
    connect(queryTemplateCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SqlDatabaseWindow::onQueryTemplateChanged);
    connect(credQueryBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::executeCredentialQuery);

    // ====================================================================
    // Controls row 1 (ARM enumeration - works in both modes if mgmt token available)
    // ====================================================================
    auto *controlLayout1 = new QHBoxLayout();
    enumServersBtn = new QPushButton("Enumerate SQL Servers", this);
    subscriptionCombo = new QComboBox(this);
    subscriptionCombo->setMinimumWidth(200);
    subscriptionCombo->setPlaceholderText("Select subscription...");
    serverCombo = new QComboBox(this);
    serverCombo->setMinimumWidth(200);
    serverCombo->setPlaceholderText("Select server...");
    serverCombo->setEnabled(false);
    databaseCombo = new QComboBox(this);
    databaseCombo->setMinimumWidth(200);
    databaseCombo->setPlaceholderText("Select database...");
    databaseCombo->setEnabled(false);

    controlLayout1->addWidget(enumServersBtn);
    controlLayout1->addWidget(subscriptionCombo);
    controlLayout1->addWidget(serverCombo);
    controlLayout1->addWidget(databaseCombo);
    controlLayout1->addStretch();
    mainLayout->addLayout(controlLayout1);

    // Controls row 2
    auto *controlLayout2 = new QHBoxLayout();
    listDatabasesBtn = new QPushButton("List Databases", this);
    listDatabasesBtn->setEnabled(false);
    listFirewallBtn = new QPushButton("Firewall Rules", this);
    listFirewallBtn->setEnabled(false);
    serverDetailsBtn = new QPushButton("Server Details", this);
    serverDetailsBtn->setEnabled(false);
    downloadSchemaBtn = new QPushButton("Download Schema", this);
    downloadSchemaBtn->setEnabled(false);
    downloadDataBtn = new QPushButton("Download Table Data", this);
    downloadDataBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy Selected", this);
    exportBtn = new QPushButton("Export All", this);

    controlLayout2->addWidget(listDatabasesBtn);
    controlLayout2->addWidget(listFirewallBtn);
    controlLayout2->addWidget(serverDetailsBtn);
    controlLayout2->addWidget(downloadSchemaBtn);
    controlLayout2->addWidget(downloadDataBtn);
    cancelBtn = new QPushButton("Cancel", this);
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    controlLayout2->addWidget(cancelBtn);
    controlLayout2->addStretch();
    controlLayout2->addWidget(copyBtn);
    controlLayout2->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout2);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);
    mainLayout->addWidget(progressBar);

    // Results splitter
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Results tree
    resultsTree = new QTreeWidget(this);
    resultsTree->setHeaderLabels({"Name", "Type", "Status/Data Type", "Location/Nullable", "Edition/Max Length", "Details"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    splitter->addWidget(resultsTree);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(300);
    splitter->addWidget(logOutput);

    mainLayout->addWidget(splitter);

    // Connections
    connect(enumServersBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::enumerateSqlServers);
    connect(serverCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SqlDatabaseWindow::onServerSelected);
    connect(listDatabasesBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::listDatabases);
    connect(listFirewallBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::listFirewallRules);
    connect(serverDetailsBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::getServerDetails);
    connect(downloadSchemaBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::downloadDatabaseSchema);
    connect(downloadDataBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::downloadTableData);
    connect(copyBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::exportResults);
    connect(cancelBtn, &QPushButton::clicked, this, &SqlDatabaseWindow::cancelRequests);

    resize(1100, 800);
}

// ============================================================================
// Auth Mode Switching
// ============================================================================

void SqlDatabaseWindow::onAuthModeChanged(int index) {
    authStack->setCurrentIndex(index);
    if (index == 0) {
        appendLog("[*] Switched to Token Authentication mode", "cyan");
    } else {
        appendLog("[*] Switched to SQL Credentials mode (Invoke-SqlCmd)", "cyan");
    }
}

void SqlDatabaseWindow::onQueryTemplateChanged(int index) {
    // Show custom query input only when "Custom Query" is selected (last item)
    bool isCustom = (index == queryTemplateCombo->count() - 1);
    customQueryInput->setVisible(isCustom);
}

bool SqlDatabaseWindow::isCredentialMode() const {
    return authModeCombo->currentIndex() == 1;
}

QString SqlDatabaseWindow::getEffectiveServerFqdn() const {
    if (isCredentialMode() && !serverFqdnInput->text().trimmed().isEmpty()) {
        return serverFqdnInput->text().trimmed();
    }
    return currentServerFqdn;
}

QString SqlDatabaseWindow::getEffectiveDatabaseName() const {
    if (isCredentialMode() && !credDatabaseInput->text().trimmed().isEmpty()) {
        return credDatabaseInput->text().trimmed();
    }
    return databaseCombo->currentText();
}

QNetworkRequest SqlDatabaseWindow::bearerRequest(const QString &url, const QString &token) {
    return NetworkHelper::createBearerRequest(url, token);
}

void SqlDatabaseWindow::appendLog(const QString &msg, const QString &color) {
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    logOutput->append(QString("<span style='color:gray'>[%1]</span> <span style='color:%2'>%3</span>")
                          .arg(timestamp, color, msg));
}

void SqlDatabaseWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    enumServersBtn->setEnabled(!loading);
    listDatabasesBtn->setEnabled(!loading && !currentServerId.isEmpty());
    listFirewallBtn->setEnabled(!loading && !currentServerId.isEmpty());
    serverDetailsBtn->setEnabled(!loading && !currentServerId.isEmpty());
    downloadSchemaBtn->setEnabled(!loading && (databaseCombo->currentIndex() >= 0 || isCredentialMode()));
    downloadDataBtn->setEnabled(!loading && (databaseCombo->currentIndex() >= 0 || isCredentialMode()));
    credQueryBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

// ============================================================================
// Auto Token Fetch
// ============================================================================

void SqlDatabaseWindow::checkExistingTokens() {
    // Populate user selector
    refreshUserList();

    // If a user is selected, check for their existing tokens
    if (!selectedUpn.isEmpty()) {
        QString mgmtToken = TokenHelper::instance()->getExistingToken(TokenHelper::RESOURCE_MANAGEMENT, selectedUpn);
        QString sqlToken = TokenHelper::instance()->getExistingToken(TokenHelper::RESOURCE_SQL_DATABASE, selectedUpn);

        if (!mgmtToken.isEmpty()) {
            mgmtTokenInput->setText(mgmtToken);
            appendLog(QString("Found existing Management token for %1").arg(selectedUpn), "lime");
        }

        if (!sqlToken.isEmpty()) {
            sqlTokenInput->setText(sqlToken);
            appendLog(QString("Found existing SQL Database token for %1").arg(selectedUpn), "lime");
        }
    }

    updateTokenStatus();
}

void SqlDatabaseWindow::refreshUserList() {
    userSelector->blockSignals(true);
    QString previousSelection = selectedUpn;
    userSelector->clear();

    QStringList users = TokenHelper::instance()->getAvailableUsers();
    if (users.isEmpty()) {
        userSelector->addItem("No authenticated sessions", "");
        appendLog("No authenticated sessions found. Please login first.", "orange");
    } else {
        userSelector->addItem("Select a user...", "");
        for (const QString &user : users) {
            userSelector->addItem(user, user);
        }

        // Restore previous selection if it still exists
        int idx = userSelector->findData(previousSelection);
        if (idx >= 0) {
            userSelector->setCurrentIndex(idx);
        } else if (users.size() == 1) {
            // Auto-select if only one user
            userSelector->setCurrentIndex(1);
            selectedUpn = users.first();
            appendLog(QString("Auto-selected user: %1").arg(selectedUpn), "cyan");
        }
    }

    userSelector->blockSignals(false);
}

void SqlDatabaseWindow::onUserSelected(int index) {
    QString newUpn = userSelector->itemData(index).toString();
    if (newUpn == selectedUpn) return;

    selectedUpn = newUpn;

    // Clear token fields when switching users
    mgmtTokenInput->clear();
    sqlTokenInput->clear();

    if (selectedUpn.isEmpty()) {
        appendLog("No user selected", "gray");
        updateTokenStatus();
        return;
    }

    appendLog(QString("Switched to user: %1").arg(selectedUpn), "cyan");

    // Check for existing tokens for this user
    QString mgmtToken = TokenHelper::instance()->getExistingToken(TokenHelper::RESOURCE_MANAGEMENT, selectedUpn);
    QString sqlToken = TokenHelper::instance()->getExistingToken(TokenHelper::RESOURCE_SQL_DATABASE, selectedUpn);

    if (!mgmtToken.isEmpty()) {
        mgmtTokenInput->setText(mgmtToken);
        appendLog("Found existing Management token", "lime");
    }

    if (!sqlToken.isEmpty()) {
        sqlTokenInput->setText(sqlToken);
        appendLog("Found existing SQL Database token", "lime");
    }

    updateTokenStatus();
}

void SqlDatabaseWindow::updateTokenStatus() {
    // Management token status
    QString mgmtToken = mgmtTokenInput->text().trimmed();
    if (mgmtToken.isEmpty()) {
        mgmtTokenStatus->setText("<span style='color:gray'>Empty</span>");
    } else {
        QString aud = getTokenAudience(mgmtToken);
        if (aud.contains("management.azure.com", Qt::CaseInsensitive)) {
            mgmtTokenStatus->setText("<span style='color:lime'>Valid</span>");
        } else {
            mgmtTokenStatus->setText("<span style='color:orange'>Wrong</span>");
        }
    }

    // SQL token status
    QString sqlToken = sqlTokenInput->text().trimmed();
    if (sqlToken.isEmpty()) {
        sqlTokenStatus->setText("<span style='color:gray'>Empty</span>");
    } else {
        QString aud = getTokenAudience(sqlToken);
        if (aud.contains("database.windows.net", Qt::CaseInsensitive)) {
            sqlTokenStatus->setText("<span style='color:lime'>Valid</span>");
        } else {
            sqlTokenStatus->setText("<span style='color:orange'>Wrong</span>");
        }
    }
}

void SqlDatabaseWindow::autoFetchTokens() {
    // Check if a user is selected
    if (selectedUpn.isEmpty()) {
        QMessageBox::warning(this, "No User Selected",
            "Please select a user from the dropdown first.\n\n"
            "If no users are available, please authenticate using:\n"
            "- Credential Login\n"
            "- Device Code Login\n"
            "- Token Login with refresh token");
        return;
    }

    // Check if we have a refresh token for the selected user
    QString refreshToken, tenantId, upn;
    if (!TokenHelper::instance()->getBestRefreshToken(refreshToken, tenantId, upn, selectedUpn)) {
        QMessageBox::warning(this, "No Refresh Token",
            QString("No refresh token available for user: %1\n\n"
                    "Please re-authenticate this user.").arg(selectedUpn));
        return;
    }

    appendLog(QString("Fetching tokens for user: %1").arg(selectedUpn), "cyan");
    setLoading(true);
    autoFetchBtn->setEnabled(false);
    autoFetchBtn->setText("Fetching tokens...");

    // Fetch both tokens for the selected user
    QStringList resources = {
        TokenHelper::RESOURCE_MANAGEMENT,
        TokenHelper::RESOURCE_SQL_DATABASE
    };

    TokenHelper::instance()->getTokensForResources(resources,
        [this](bool success, const QMap<QString, QString> &tokens, const QString &error) {
            setLoading(false);
            autoFetchBtn->setEnabled(true);
            autoFetchBtn->setText("Auto-Fetch Tokens for Selected User");

            if (!success && tokens.isEmpty()) {
                appendLog("Failed to fetch tokens: " + error, "red");
                QMessageBox::warning(this, "Token Fetch Failed",
                    "Could not acquire tokens:\n" + error);
                return;
            }

            // Apply fetched tokens
            if (tokens.contains(TokenHelper::RESOURCE_MANAGEMENT)) {
                mgmtTokenInput->setText(tokens[TokenHelper::RESOURCE_MANAGEMENT]);
                appendLog("Management token acquired", "lime");
            }

            if (tokens.contains(TokenHelper::RESOURCE_SQL_DATABASE)) {
                sqlTokenInput->setText(tokens[TokenHelper::RESOURCE_SQL_DATABASE]);
                appendLog("SQL Database token acquired", "lime");
            }

            updateTokenStatus();

            // Report partial success
            if (!error.isEmpty()) {
                appendLog("Some tokens failed: " + error, "orange");
            }
        }, selectedUpn);  // Pass the selected user
}

// ============================================================================
// Token Validation
// ============================================================================

QString SqlDatabaseWindow::getTokenClaim(const QString &token, const QString &claim) {
    QStringList parts = token.split('.');
    if (parts.size() < 2) return QString();

    QByteArray payload = parts.at(1).toUtf8();
    // Pad for base64url
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));
    payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);

    QJsonDocument doc = QJsonDocument::fromJson(payload);
    return doc.object().value(claim).toString();
}

QString SqlDatabaseWindow::getTokenAudience(const QString &token) {
    return getTokenClaim(token, "aud");
}

bool SqlDatabaseWindow::validateSqlToken(const QString &token) {
    if (token.isEmpty()) {
        appendLog("[!] SQL Database token is required for schema/data download", "red");
        QMessageBox::warning(this, "Missing Token",
            "Please enter a SQL Database access token.\n\n"
            "Required audience: https://database.windows.net\n\n"
            "You can get this token using:\n"
            "- Credential Login with 'database.windows.net' resource\n"
            "- Token Login with a token for database.windows.net\n"
            "- PowerShell: (Get-AzAccessToken -ResourceUrl https://database.windows.net).Token");
        return false;
    }

    QString audience = getTokenAudience(token);

    if (audience.isEmpty()) {
        appendLog("[!] Could not parse token audience", "yellow");
        // Allow anyway, might work
        return true;
    }

    // Check for correct SQL database audience
    bool validAudience = audience.contains("database.windows.net", Qt::CaseInsensitive) ||
                         audience == "https://sql.azuresynapse.net";

    if (!validAudience) {
        appendLog(QString("[!] Wrong token audience: %1").arg(audience), "red");
        appendLog("[!] Expected: https://database.windows.net", "red");

        QString currentResource;
        if (audience.contains("management.azure.com")) currentResource = "Azure Management";
        else if (audience.contains("graph.microsoft.com")) currentResource = "Microsoft Graph";
        else if (audience.contains("vault.azure.net")) currentResource = "Key Vault";
        else currentResource = audience;

        QMessageBox::StandardButton reply = QMessageBox::warning(this, "Wrong Token Resource",
            QString("The token you provided is for: %1\n\n"
                    "Current audience: %2\n\n"
                    "For SQL Database access, you need a token for:\n"
                    "https://database.windows.net\n\n"
                    "Would you like to continue anyway? (May fail)")
                .arg(currentResource, audience),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

        return reply == QMessageBox::Yes;
    }

    appendLog(QString("[+] Token validated - audience: %1").arg(audience), "green");
    return true;
}

// ============================================================================
// SQL Server Enumeration (ARM API - works in both modes)
// ============================================================================

void SqlDatabaseWindow::enumerateSqlServers() {
    QString token = mgmtTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.\n\n"
            "Switch to Token Authentication mode if needed.");
        return;
    }

    // Validate management token
    QString aud = getTokenAudience(token);
    if (!aud.isEmpty() && !aud.contains("management.azure.com")) {
        appendLog(QString("[!] Warning: Token audience is '%1', expected management.azure.com").arg(aud), "yellow");
    }

    setLoading(true);
    appendLog("[*] Enumerating subscriptions...", "cyan");
    resultsTree->clear();
    resultsTree->setHeaderLabels({"Name", "Type", "Status/Data Type", "Location/Nullable", "Edition/Max Length", "Details"});
    serverCombo->clear();
    databaseCombo->clear();
    sqlServers = QJsonArray();

    QString url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    QNetworkReply *reply = net->get(bearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply, token]() {
        reply->deleteLater();

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            setLoading(false);
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        subscriptions = doc.object().value("value").toArray();

        if (subscriptions.isEmpty()) {
            appendLog("[!] No subscriptions found.", "yellow");
            setLoading(false);
            return;
        }

        appendLog(QString("[+] Found %1 subscription(s), enumerating SQL Servers...").arg(subscriptions.size()), "green");

        subscriptionCombo->clear();
        for (const QJsonValue &val : subscriptions) {
            QJsonObject sub = val.toObject();
            QString name = sub.value("displayName").toString();
            QString id = sub.value("subscriptionId").toString();
            subscriptionCombo->addItem(name, id);
        }

        auto counter = std::make_shared<int>(subscriptions.size());

        for (const QJsonValue &val : subscriptions) {
            QString subId = val.toObject().value("subscriptionId").toString();
            QString sqlUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Sql/servers?api-version=2021-11-01").arg(subId);

            QNetworkReply *sqlReply = net->get(bearerRequest(sqlUrl, token));

            if (!sqlReply) {
                (*counter)--;
                if (*counter == 0) {
                    setLoading(false);
                    appendLog(QString("[+] Found %1 SQL Server(s)").arg(sqlServers.size()), sqlServers.size() > 0 ? "green" : "yellow");
                }
                return;
            }

            connect(sqlReply, &QNetworkReply::finished, this, [this, sqlReply, subId, counter]() {
                sqlReply->deleteLater();
                (*counter)--;

                if (NetworkHelper::isReplySuccess(sqlReply)) {
                    QJsonDocument doc = QJsonDocument::fromJson(sqlReply->readAll());
                    QJsonArray servers = doc.object().value("value").toArray();

                    for (const QJsonValue &v : servers) {
                        QJsonObject server = v.toObject();
                        server.insert("subscriptionId", subId);
                        sqlServers.append(server);

                        QString name = server.value("name").toString();
                        QString id = server.value("id").toString();
                        QString location = server.value("location").toString();
                        QString fqdn = server.value("properties").toObject().value("fullyQualifiedDomainName").toString();
                        QString state = server.value("properties").toObject().value("state").toString();
                        QString adminLogin = server.value("properties").toObject().value("administratorLogin").toString();
                        QString version = server.value("properties").toObject().value("version").toString();

                        serverCombo->addItem(QString("%1 (%2)").arg(name, fqdn), id);

                        auto *item = new QTreeWidgetItem(resultsTree);
                        item->setText(0, name);
                        item->setText(1, "SQL Server");
                        item->setText(2, state);
                        item->setText(3, location);
                        item->setText(4, QString("v%1").arg(version));
                        item->setText(5, QString("FQDN: %1 | Admin: %2").arg(fqdn, adminLogin));
                        item->setData(0, Qt::UserRole, id);
                        item->setData(0, Qt::UserRole + 1, fqdn);
                    }
                }

                if (*counter == 0) {
                    setLoading(false);
                    if (sqlServers.isEmpty()) {
                        appendLog("[!] No SQL Servers found.", "yellow");
                    } else {
                        appendLog(QString("[+] Found %1 SQL Server(s)").arg(sqlServers.size()), "green");
                        serverCombo->setEnabled(true);
                        if (serverCombo->count() > 0) {
                            onServerSelected(0);
                        }
                    }
                }
            });
        }
    });
}

void SqlDatabaseWindow::onServerSelected(int index) {
    if (index >= 0 && index < serverCombo->count()) {
        currentServerId = serverCombo->itemData(index).toString();

        for (const QJsonValue &val : sqlServers) {
            QJsonObject server = val.toObject();
            if (server.value("id").toString() == currentServerId) {
                currentServerName = server.value("name").toString();
                currentServerFqdn = server.value("properties").toObject().value("fullyQualifiedDomainName").toString();
                break;
            }
        }

        listDatabasesBtn->setEnabled(true);
        listFirewallBtn->setEnabled(true);
        serverDetailsBtn->setEnabled(true);
        appendLog(QString("[*] Selected server: %1").arg(currentServerName), "cyan");

        listDatabases();
    }
}

void SqlDatabaseWindow::listDatabases() {
    QString token = mgmtTokenInput->text().trimmed();
    if (token.isEmpty() || currentServerId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing databases...", "cyan");

    QString url = QString("https://management.azure.com%1/databases?api-version=2021-11-01").arg(currentServerId);
    QNetworkReply *reply = net->get(bearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        databases = doc.object().value("value").toArray();

        databaseCombo->clear();

        if (databases.isEmpty()) {
            appendLog("[!] No databases found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 database(s)").arg(databases.size()), "green");

        auto *dbGroup = new QTreeWidgetItem(resultsTree);
        dbGroup->setText(0, QString("Databases on %1").arg(currentServerName));
        dbGroup->setText(1, QString("(%1 items)").arg(databases.size()));

        for (const QJsonValue &val : databases) {
            QJsonObject db = val.toObject();
            QString name = db.value("name").toString();
            QString id = db.value("id").toString();
            QString status = db.value("properties").toObject().value("status").toString();
            QString edition = db.value("sku").toObject().value("tier").toString();
            QString sku = db.value("sku").toObject().value("name").toString();
            QString maxSize = QString::number(db.value("properties").toObject().value("maxSizeBytes").toDouble() / (1024*1024*1024), 'f', 2) + " GB";
            QString collation = db.value("properties").toObject().value("collation").toString();

            databaseCombo->addItem(name, id);

            auto *item = new QTreeWidgetItem(dbGroup);
            item->setText(0, name);
            item->setText(1, "Database");
            item->setText(2, status);
            item->setText(3, edition);
            item->setText(4, sku);
            item->setText(5, QString("Max: %1 | Collation: %2").arg(maxSize, collation));
            item->setData(0, Qt::UserRole, id);
        }

        dbGroup->setExpanded(true);
        databaseCombo->setEnabled(true);
        downloadSchemaBtn->setEnabled(true);
        downloadDataBtn->setEnabled(true);
    });
}

void SqlDatabaseWindow::listFirewallRules() {
    QString token = mgmtTokenInput->text().trimmed();
    if (token.isEmpty() || currentServerId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing firewall rules...", "cyan");

    QString url = QString("https://management.azure.com%1/firewallRules?api-version=2021-11-01").arg(currentServerId);
    QNetworkReply *reply = net->get(bearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray rules = doc.object().value("value").toArray();

        if (rules.isEmpty()) {
            appendLog("[!] No firewall rules found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 firewall rule(s)").arg(rules.size()), "green");

        auto *fwGroup = new QTreeWidgetItem(resultsTree);
        fwGroup->setText(0, QString("Firewall Rules on %1").arg(currentServerName));
        fwGroup->setText(1, QString("(%1 rules)").arg(rules.size()));

        for (const QJsonValue &val : rules) {
            QJsonObject rule = val.toObject();
            QString name = rule.value("name").toString();
            QString startIp = rule.value("properties").toObject().value("startIpAddress").toString();
            QString endIp = rule.value("properties").toObject().value("endIpAddress").toString();

            auto *item = new QTreeWidgetItem(fwGroup);
            item->setText(0, name);
            item->setText(1, "Firewall Rule");
            item->setText(2, "Active");
            item->setText(3, "-");
            item->setText(4, "-");

            QString ipRange;
            if (startIp == "0.0.0.0" && endIp == "0.0.0.0") {
                ipRange = "Azure Services (0.0.0.0)";
                item->setForeground(5, QBrush(Qt::yellow));
            } else if (startIp == "0.0.0.0" && endIp == "255.255.255.255") {
                ipRange = "ALL IPs (0.0.0.0-255.255.255.255) - DANGEROUS!";
                item->setForeground(5, QBrush(Qt::red));
            } else if (startIp == endIp) {
                ipRange = QString("Single IP: %1").arg(startIp);
            } else {
                ipRange = QString("%1 - %2").arg(startIp, endIp);
            }
            item->setText(5, ipRange);
        }

        fwGroup->setExpanded(true);
    });
}

void SqlDatabaseWindow::getServerDetails() {
    QString token = mgmtTokenInput->text().trimmed();
    if (token.isEmpty() || currentServerId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Getting server details...", "cyan");

    // Get advanced threat protection status
    QString atpUrl = QString("https://management.azure.com%1/advancedThreatProtectionSettings/Default?api-version=2021-11-01").arg(currentServerId);
    QNetworkReply *atpReply = net->get(bearerRequest(atpUrl, token));

    if (!atpReply) {
        appendLog("[-] Failed to create ATP request", "red");
    } else {
        connect(atpReply, &QNetworkReply::finished, this, [this, atpReply]() {
            atpReply->deleteLater();

            QString atpStatus = "Unknown";
            if (NetworkHelper::isReplySuccess(atpReply)) {
                QJsonDocument doc = QJsonDocument::fromJson(atpReply->readAll());
                atpStatus = doc.object().value("properties").toObject().value("state").toString();
            }

            appendLog(QString("[*] Advanced Threat Protection: %1").arg(atpStatus),
                      atpStatus == "Enabled" ? "green" : "yellow");
        });
    }

    // Get auditing settings
    QString auditUrl = QString("https://management.azure.com%1/auditingSettings/Default?api-version=2021-11-01").arg(currentServerId);
    QNetworkReply *auditReply = net->get(bearerRequest(auditUrl, token));

    if (!auditReply) {
        appendLog("[-] Failed to create auditing request", "red");
        setLoading(false);
    } else {
        connect(auditReply, &QNetworkReply::finished, this, [this, auditReply]() {
            auditReply->deleteLater();
            setLoading(false);

            if (NetworkHelper::isReplySuccess(auditReply)) {
                QJsonDocument doc = QJsonDocument::fromJson(auditReply->readAll());
                QString state = doc.object().value("properties").toObject().value("state").toString();
                appendLog(QString("[*] Auditing: %1").arg(state),
                          state == "Enabled" ? "green" : "yellow");
            }
        });
    }
}

// ============================================================================
// Credential-Based Query Execution (Invoke-SqlCmd)
// ============================================================================

void SqlDatabaseWindow::executeCredentialQuery() {
    QString server = serverFqdnInput->text().trimmed();
    QString database = credDatabaseInput->text().trimmed();
    QString username = sqlUsernameInput->text().trimmed();
    QString password = sqlPasswordInput->text();

    if (server.isEmpty()) {
        QMessageBox::warning(this, "Missing Server", "Please enter the SQL Server FQDN.\n\nExample: myserver.database.windows.net");
        return;
    }
    if (database.isEmpty()) {
        QMessageBox::warning(this, "Missing Database", "Please enter the database name.");
        return;
    }
    if (username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "Missing Credentials", "Please enter both username and password.");
        return;
    }

    // Determine query
    QString query;
    int templateIdx = queryTemplateCombo->currentIndex();
    if (templateIdx == queryTemplateCombo->count() - 1) {
        // Custom query
        query = customQueryInput->toPlainText().trimmed();
        if (query.isEmpty()) {
            QMessageBox::warning(this, "Missing Query", "Please enter a custom SQL query.");
            return;
        }
    } else {
        query = queryTemplateCombo->currentData().toString();
    }

    setLoading(true);
    appendLog(QString("[*] Executing query on %1/%2 as %3...").arg(server, database, username), "cyan");
    appendLog(QString("[*] Query: %1").arg(query.left(100)), "gray");

    // Build PowerShell script with Invoke-SqlCmd
    QString script = QString(
        "$ErrorActionPreference='Stop'\n"
        "try {\n"
        "  $secPass = ConvertTo-SecureString '%1' -AsPlainText -Force\n"
        "  $cred = New-Object System.Management.Automation.PSCredential('%2', $secPass)\n"
        "  Write-Output '__QUERY_START__'\n"
        "  $results = Invoke-SqlCmd -ServerInstance '%3' -Database '%4' -Credential $cred -Query '%5' -TrustServerCertificate -ConnectionTimeout 30 -QueryTimeout 60 -WarningAction SilentlyContinue 3>$null\n"
        "  if ($results) {\n"
        "    $results | Select-Object -Property * -ExcludeProperty RowError,RowState,Table,ItemArray,HasErrors | ConvertTo-Json -Depth 2 -Compress -WarningAction SilentlyContinue 3>$null\n"
        "  } else {\n"
        "    Write-Output '__NO_RESULTS__'\n"
        "  }\n"
        "  Write-Output ''\n"
        "  Write-Output '__QUERY_END__'\n"
        "} catch {\n"
        "  Write-Output \"__QUERY_ERROR__:$($_.Exception.Message)\"\n"
        "}\n"
    ).arg(
        InputValidator::escapePsString(password),
        InputValidator::escapePsString(username),
        InputValidator::escapePsString(server),
        InputValidator::escapePsString(database),
        InputValidator::escapePsString(query)
    );

    if (pwshProcess) {
        pwshProcess->kill();
        pwshProcess->deleteLater();
    }

    pwshProcess = new QProcess(this);
    pwshProcess->setProcessChannelMode(QProcess::MergedChannels);

    connect(pwshProcess, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
        QString output = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(pwshProcess->readAllStandardOutput()));
        setLoading(false);

        if (output.contains("__QUERY_ERROR__:")) {
            QString error = output.section("__QUERY_ERROR__:", 1).section('\n', 0, 0);
            appendLog(QString("[-] Query failed: %1").arg(error), "red");
            QMessageBox::critical(this, "Query Error", QString("Failed to execute query:\n\n%1").arg(error));
            pwshProcess->deleteLater();
            pwshProcess = nullptr;
            return;
        }

        if (output.contains("__QUERY_START__") && output.contains("__QUERY_END__")) {
            QString data = output.section("__QUERY_START__", 1).section("__QUERY_END__", 0, 0).trimmed();

            if (data.contains("__NO_RESULTS__")) {
                appendLog("[!] Query returned no results", "yellow");
            } else {
                parseCredentialQueryOutput(data);
            }
        } else {
            appendLog("[-] Unexpected output from query", "red");
            appendLog(output.left(500), "yellow");
        }

        pwshProcess->deleteLater();
        pwshProcess = nullptr;
    });

    QStringList args;
    args << "-NoProfile" << "-NonInteractive" << "-Command" << script;
    pwshProcess->start("pwsh", args);

    if (!pwshProcess->waitForStarted(5000)) {
        setLoading(false);
        appendLog("[-] Failed to start PowerShell process", "red");
        QMessageBox::critical(this, "Error", "Failed to start PowerShell. Make sure 'pwsh' is installed\n"
            "and the SqlServer module is available:\n\n  Install-Module SqlServer");
    }
}

void SqlDatabaseWindow::parseCredentialQueryOutput(const QString &output) {
    QJsonDocument doc = QJsonDocument::fromJson(output.toUtf8());

    QJsonArray rows;
    if (doc.isArray()) {
        rows = doc.array();
    } else if (doc.isObject()) {
        // Single result row comes as object
        rows.append(doc.object());
    } else {
        // Not JSON - display as raw text lines in tree
        QStringList lines = output.split('\n', Qt::SkipEmptyParts);
        auto *rawGroup = new QTreeWidgetItem(resultsTree);
        rawGroup->setText(0, QString("Query Results (%1 lines)").arg(lines.size()));
        rawGroup->setText(1, "Raw");
        for (const QString &line : lines) {
            auto *item = new QTreeWidgetItem(rawGroup);
            item->setText(0, line.trimmed());
        }
        rawGroup->setExpanded(true);
        appendLog(QString("[+] %1 line(s) returned (raw text)").arg(lines.size()), "green");
        return;
    }

    if (rows.isEmpty()) {
        appendLog("[!] Query returned empty result set", "yellow");
        return;
    }

    // Collect column names from first row
    QStringList columns = rows[0].toObject().keys();

    appendLog(QString("[+] Query returned %1 row(s), %2 column(s)").arg(rows.size()).arg(columns.size()), "green");

    // ---- Build HTML table for the log output ----
    QString html;
    html += "<br/><table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse; border-color:#555; font-size:11px;'>";

    // Header row
    html += "<tr>";
    for (const QString &col : columns) {
        html += QString("<th style='background-color:#2d5aa0; color:white; padding:4px 8px;'>%1</th>").arg(col.toHtmlEscaped());
    }
    html += "</tr>";

    // Data rows
    for (int i = 0; i < rows.size(); i++) {
        QJsonObject row = rows[i].toObject();
        QString bgColor = (i % 2 == 0) ? "#2a2a2a" : "#333333";
        html += QString("<tr style='background-color:%1;'>").arg(bgColor);
        for (const QString &col : columns) {
            QJsonValue val = row.value(col);
            QString valStr;
            if (val.isString()) valStr = val.toString();
            else if (val.isDouble()) valStr = QString::number(val.toDouble());
            else if (val.isBool()) valStr = val.toBool() ? "True" : "False";
            else if (val.isNull()) valStr = "NULL";
            else valStr = QString::fromUtf8(QJsonDocument(QJsonObject{{col, val}}).toJson(QJsonDocument::Compact));

            QString color = (valStr == "NULL") ? "#888" : "#ddd";
            html += QString("<td style='color:%1; padding:3px 6px;'>%2</td>").arg(color, valStr.toHtmlEscaped());
        }
        html += "</tr>";
    }
    html += "</table><br/>";

    logOutput->append(html);

    // ---- Populate tree with flat readable rows ----
    // Dynamically set tree columns to match query result columns
    QStringList treeHeaders;
    int maxTreeCols = qMin(columns.size(), 6); // Tree supports up to 6 columns
    for (int i = 0; i < maxTreeCols; i++) {
        treeHeaders << columns[i];
    }
    // Pad remaining columns if less than 6
    while (treeHeaders.size() < 6) {
        treeHeaders << "";
    }
    resultsTree->setHeaderLabels(treeHeaders);

    auto *resultGroup = new QTreeWidgetItem(resultsTree);
    resultGroup->setText(0, QString("Query Results (%1 rows)").arg(rows.size()));

    for (int i = 0; i < rows.size(); i++) {
        QJsonObject row = rows[i].toObject();
        auto *rowItem = new QTreeWidgetItem(resultGroup);

        for (int c = 0; c < maxTreeCols; c++) {
            QJsonValue val = row.value(columns[c]);
            QString valStr;
            if (val.isString()) valStr = val.toString();
            else if (val.isDouble()) valStr = QString::number(val.toDouble());
            else if (val.isBool()) valStr = val.toBool() ? "True" : "False";
            else if (val.isNull()) valStr = "NULL";
            else valStr = QString::fromUtf8(QJsonDocument(QJsonObject{{columns[c], val}}).toJson(QJsonDocument::Compact));

            rowItem->setText(c, valStr);
        }

        // If more than 6 columns, append overflow to a tooltip
        if (columns.size() > 6) {
            QStringList overflow;
            for (int c = 6; c < columns.size(); c++) {
                QJsonValue val = row.value(columns[c]);
                QString valStr;
                if (val.isString()) valStr = val.toString();
                else if (val.isDouble()) valStr = QString::number(val.toDouble());
                else if (val.isBool()) valStr = val.toBool() ? "True" : "False";
                else if (val.isNull()) valStr = "NULL";
                else valStr = QString::fromUtf8(QJsonDocument(QJsonObject{{columns[c], val}}).toJson(QJsonDocument::Compact));
                overflow << QString("%1: %2").arg(columns[c], valStr);
            }
            rowItem->setToolTip(0, overflow.join("\n"));
        }
    }

    resultGroup->setExpanded(true);
}

// ============================================================================
// Schema Download (supports both token and credential modes)
// ============================================================================

void SqlDatabaseWindow::downloadDatabaseSchema() {
    if (isCredentialMode()) {
        // Credential mode - use Invoke-SqlCmd
        QString server = getEffectiveServerFqdn();
        QString database = getEffectiveDatabaseName();

        if (server.isEmpty()) {
            QMessageBox::warning(this, "Missing Server", "Please enter the SQL Server FQDN.");
            return;
        }
        if (database.isEmpty()) {
            QMessageBox::warning(this, "Missing Database", "Please enter or select a database name.");
            return;
        }
        if (sqlUsernameInput->text().trimmed().isEmpty() || sqlPasswordInput->text().isEmpty()) {
            QMessageBox::warning(this, "Missing Credentials", "Please enter SQL credentials.");
            return;
        }

        appendLog(QString("[*] Downloading schema for %1/%2 via credentials...").arg(server, database), "cyan");
        executeCredentialSchemaQuery(database);
    } else {
        // Token mode - existing behavior
        if (databaseCombo->currentIndex() < 0) {
            QMessageBox::warning(this, "No Database", "Please select a database first.");
            return;
        }

        QString token = sqlTokenInput->text().trimmed();
        if (!validateSqlToken(token)) {
            return;
        }

        currentDbName = databaseCombo->currentText();
        appendLog(QString("[*] Downloading schema for database: %1").arg(currentDbName), "cyan");
        executeSchemaQuery(currentDbName);
    }
}

void SqlDatabaseWindow::executeCredentialSchemaQuery(const QString &dbName) {
    setLoading(true);

    QString server = getEffectiveServerFqdn();
    QString username = sqlUsernameInput->text().trimmed();
    QString password = sqlPasswordInput->text();

    QString schemaQuery =
        "SELECT t.TABLE_SCHEMA, t.TABLE_NAME, t.TABLE_TYPE, "
        "c.COLUMN_NAME, c.DATA_TYPE, c.IS_NULLABLE, "
        "c.CHARACTER_MAXIMUM_LENGTH, c.NUMERIC_PRECISION "
        "FROM INFORMATION_SCHEMA.TABLES t "
        "LEFT JOIN INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA "
        "ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.ORDINAL_POSITION";

    QString script = QString(
        "$ErrorActionPreference='Stop'\n"
        "try {\n"
        "  $secPass = ConvertTo-SecureString '%1' -AsPlainText -Force\n"
        "  $cred = New-Object System.Management.Automation.PSCredential('%2', $secPass)\n"
        "  Write-Output '__SCHEMA_START__'\n"
        "  $results = Invoke-SqlCmd -ServerInstance '%3' -Database '%4' -Credential $cred -Query '%5' -TrustServerCertificate -ConnectionTimeout 30 -QueryTimeout 120 -WarningAction SilentlyContinue 3>$null\n"
        "  foreach ($row in $results) {\n"
        "    $schema = $row.TABLE_SCHEMA\n"
        "    $table = $row.TABLE_NAME\n"
        "    $type = $row.TABLE_TYPE\n"
        "    $col = $row.COLUMN_NAME\n"
        "    $dtype = $row.DATA_TYPE\n"
        "    $nullable = $row.IS_NULLABLE\n"
        "    $maxlen = $row.CHARACTER_MAXIMUM_LENGTH\n"
        "    $precision = $row.NUMERIC_PRECISION\n"
        "    Write-Output \"$schema|$table|$type|$col|$dtype|$nullable|$maxlen|$precision\"\n"
        "  }\n"
        "  Write-Output '__SCHEMA_END__'\n"
        "} catch {\n"
        "  Write-Output \"__SCHEMA_ERROR__:$($_.Exception.Message)\"\n"
        "}\n"
    ).arg(
        InputValidator::escapePsString(password),
        InputValidator::escapePsString(username),
        InputValidator::escapePsString(server),
        InputValidator::escapePsString(dbName),
        InputValidator::escapePsString(schemaQuery)
    );

    if (pwshProcess) {
        pwshProcess->kill();
        pwshProcess->deleteLater();
    }

    pwshProcess = new QProcess(this);
    pwshProcess->setProcessChannelMode(QProcess::MergedChannels);
    currentDbName = dbName;

    connect(pwshProcess, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
        QString output = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(pwshProcess->readAllStandardOutput()));
        setLoading(false);

        if (output.contains("__SCHEMA_ERROR__:")) {
            QString error = output.section("__SCHEMA_ERROR__:", 1).section('\n', 0, 0);
            appendLog(QString("[-] Schema query failed: %1").arg(error), "red");
            QMessageBox::critical(this, "Schema Error", QString("Failed to query schema:\n\n%1").arg(error));
            pwshProcess->deleteLater();
            pwshProcess = nullptr;
            return;
        }

        if (output.contains("__SCHEMA_START__") && output.contains("__SCHEMA_END__")) {
            QString schemaData = output.section("__SCHEMA_START__", 1).section("__SCHEMA_END__", 0, 0).trimmed();
            parseSchemaOutput(schemaData);
        } else {
            appendLog("[-] Unexpected output from schema query", "red");
            appendLog(output.left(500), "yellow");
        }

        pwshProcess->deleteLater();
        pwshProcess = nullptr;
    });

    QStringList args;
    args << "-NoProfile" << "-NonInteractive" << "-Command" << script;
    pwshProcess->start("pwsh", args);

    if (!pwshProcess->waitForStarted(5000)) {
        setLoading(false);
        appendLog("[-] Failed to start PowerShell process", "red");
        QMessageBox::critical(this, "Error", "Failed to start PowerShell. Make sure 'pwsh' and SqlServer module are installed.");
    }
}

// ============================================================================
// Token-Based Schema Download (existing)
// ============================================================================

void SqlDatabaseWindow::executeSchemaQuery(const QString &dbName) {
    setLoading(true);

    QString token = sqlTokenInput->text().trimmed();

    // Build PowerShell script to connect and query schema
    QString script = QString(
        "$ErrorActionPreference='Stop'\n"
        "$token = @'\n%1\n'@\n"
        "$server = '%2'\n"
        "$database = '%3'\n"
        "try {\n"
        "  $conn = New-Object System.Data.SqlClient.SqlConnection\n"
        "  $conn.ConnectionString = \"Server=tcp:$server,1433;Initial Catalog=$database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;\"\n"
        "  $conn.AccessToken = $token\n"
        "  $conn.Open()\n"
        "  Write-Output '__SCHEMA_START__'\n"
        "  $cmd = $conn.CreateCommand()\n"
        "  $cmd.CommandText = @'\n"
        "SELECT \n"
        "    t.TABLE_SCHEMA,\n"
        "    t.TABLE_NAME,\n"
        "    t.TABLE_TYPE,\n"
        "    c.COLUMN_NAME,\n"
        "    c.DATA_TYPE,\n"
        "    c.IS_NULLABLE,\n"
        "    c.CHARACTER_MAXIMUM_LENGTH,\n"
        "    c.NUMERIC_PRECISION\n"
        "FROM INFORMATION_SCHEMA.TABLES t\n"
        "LEFT JOIN INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA\n"
        "ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.ORDINAL_POSITION\n"
        "'@\n"
        "  $reader = $cmd.ExecuteReader()\n"
        "  while ($reader.Read()) {\n"
        "    $schema = $reader['TABLE_SCHEMA']\n"
        "    $table = $reader['TABLE_NAME']\n"
        "    $type = $reader['TABLE_TYPE']\n"
        "    $col = $reader['COLUMN_NAME']\n"
        "    $dtype = $reader['DATA_TYPE']\n"
        "    $nullable = $reader['IS_NULLABLE']\n"
        "    $maxlen = $reader['CHARACTER_MAXIMUM_LENGTH']\n"
        "    $precision = $reader['NUMERIC_PRECISION']\n"
        "    Write-Output \"$schema|$table|$type|$col|$dtype|$nullable|$maxlen|$precision\"\n"
        "  }\n"
        "  $reader.Close()\n"
        "  $conn.Close()\n"
        "  Write-Output '__SCHEMA_END__'\n"
        "} catch {\n"
        "  Write-Output \"__SCHEMA_ERROR__:$($_.Exception.Message)\"\n"
        "}\n"
    ).arg(token, currentServerFqdn, dbName);

    if (pwshProcess) {
        pwshProcess->kill();
        pwshProcess->deleteLater();
    }

    pwshProcess = new QProcess(this);
    pwshProcess->setProcessChannelMode(QProcess::MergedChannels);

    connect(pwshProcess, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus) {
        QString output = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(pwshProcess->readAllStandardOutput()));
        setLoading(false);

        if (output.contains("__SCHEMA_ERROR__:")) {
            QString error = output.section("__SCHEMA_ERROR__:", 1).section('\n', 0, 0);
            appendLog(QString("[-] Schema query failed: %1").arg(error), "red");
            QMessageBox::critical(this, "Schema Error", QString("Failed to query schema:\n\n%1").arg(error));
            return;
        }

        if (output.contains("__SCHEMA_START__") && output.contains("__SCHEMA_END__")) {
            QString schemaData = output.section("__SCHEMA_START__", 1).section("__SCHEMA_END__", 0, 0).trimmed();
            parseSchemaOutput(schemaData);
        } else {
            appendLog("[-] Unexpected output from schema query", "red");
            appendLog(output.left(500), "yellow");
        }

        pwshProcess->deleteLater();
        pwshProcess = nullptr;
    });

    QStringList args;
    args << "-NoProfile" << "-NonInteractive" << "-Command" << script;
    pwshProcess->start("pwsh", args);

    if (!pwshProcess->waitForStarted(5000)) {
        setLoading(false);
        appendLog("[-] Failed to start PowerShell process", "red");
        QMessageBox::critical(this, "Error", "Failed to start PowerShell. Make sure 'pwsh' is installed.");
    }
}

void SqlDatabaseWindow::parseSchemaOutput(const QString &output) {
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);

    if (lines.isEmpty()) {
        appendLog("[!] No schema data returned", "yellow");
        return;
    }

    // Group by table
    QMap<QString, QTreeWidgetItem*> tableItems;
    int columnCount = 0;

    auto *schemaGroup = new QTreeWidgetItem(resultsTree);
    schemaGroup->setText(0, QString("Schema: %1").arg(currentDbName));
    schemaGroup->setText(1, "Database Schema");

    for (const QString &line : lines) {
        QStringList parts = line.split('|');
        if (parts.size() < 8) continue;

        QString schema = parts[0].trimmed();
        QString table = parts[1].trimmed();
        QString tableType = parts[2].trimmed();
        QString column = parts[3].trimmed();
        QString dataType = parts[4].trimmed();
        QString nullable = parts[5].trimmed();
        QString maxLen = parts[6].trimmed();
        QString precision = parts[7].trimmed();

        QString tableKey = QString("%1.%2").arg(schema, table);

        // Create table node if not exists
        if (!tableItems.contains(tableKey)) {
            auto *tableItem = new QTreeWidgetItem(schemaGroup);
            tableItem->setText(0, tableKey);
            tableItem->setText(1, tableType == "BASE TABLE" ? "Table" : "View");
            tableItem->setText(2, "-");
            tableItem->setText(3, "-");
            tableItem->setText(4, "-");
            tableItem->setText(5, QString("Schema: %1").arg(schema));
            tableItems[tableKey] = tableItem;
        }

        // Add column
        if (!column.isEmpty() && column != "NULL") {
            auto *colItem = new QTreeWidgetItem(tableItems[tableKey]);
            colItem->setText(0, column);
            colItem->setText(1, "Column");
            colItem->setText(2, dataType);
            colItem->setText(3, nullable == "YES" ? "Nullable" : "NOT NULL");

            QString sizeInfo;
            if (maxLen != "NULL" && !maxLen.isEmpty() && maxLen != "-1") {
                sizeInfo = QString("Max: %1").arg(maxLen);
            } else if (precision != "NULL" && !precision.isEmpty()) {
                sizeInfo = QString("Precision: %1").arg(precision);
            }
            colItem->setText(4, sizeInfo);
            columnCount++;
        }
    }

    schemaGroup->setText(2, QString("%1 tables").arg(tableItems.size()));
    schemaGroup->setExpanded(true);

    // Expand first few tables
    int expanded = 0;
    for (auto *item : tableItems) {
        if (expanded++ < 5) item->setExpanded(true);
    }

    appendLog(QString("[+] Schema loaded: %1 tables, %2 columns").arg(tableItems.size()).arg(columnCount), "green");
}

// ============================================================================
// Table Data Download (supports both token and credential modes)
// ============================================================================

void SqlDatabaseWindow::downloadTableData() {
    auto *item = resultsTree->currentItem();
    if (!item) {
        QMessageBox::information(this, "No Selection", "Please select a table from the schema to download data.");
        return;
    }

    // Check if it's a table item
    if (item->text(1) != "Table" && item->text(1) != "View") {
        // Maybe selected a column, get parent
        if (item->parent() && (item->parent()->text(1) == "Table" || item->parent()->text(1) == "View")) {
            item = item->parent();
        } else {
            QMessageBox::information(this, "Select Table", "Please select a table or view to download data.");
            return;
        }
    }

    QString tableName = item->text(0); // schema.table format

    // Ask for row limit
    bool ok;
    int rowLimit = QInputDialog::getInt(this, "Row Limit",
        QString("How many rows to download from %1?").arg(tableName),
        100, 1, 10000, 100, &ok);
    if (!ok) return;

    if (isCredentialMode()) {
        QString server = getEffectiveServerFqdn();
        if (server.isEmpty()) {
            QMessageBox::warning(this, "Missing Server", "Please enter the SQL Server FQDN.");
            return;
        }
        if (sqlUsernameInput->text().trimmed().isEmpty() || sqlPasswordInput->text().isEmpty()) {
            QMessageBox::warning(this, "Missing Credentials", "Please enter SQL credentials.");
            return;
        }
        executeCredentialDataQuery(tableName, rowLimit);
    } else {
        // Token mode - existing behavior
        QString token = sqlTokenInput->text().trimmed();
        if (!validateSqlToken(token)) {
            return;
        }

        setLoading(true);
        appendLog(QString("[*] Downloading top %1 rows from %2...").arg(rowLimit).arg(tableName), "cyan");

        QString script = QString(
            "$ErrorActionPreference='Stop'\n"
            "$token = @'\n%1\n'@\n"
            "$server = '%2'\n"
            "$database = '%3'\n"
            "try {\n"
            "  $conn = New-Object System.Data.SqlClient.SqlConnection\n"
            "  $conn.ConnectionString = \"Server=tcp:$server,1433;Initial Catalog=$database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;\"\n"
            "  $conn.AccessToken = $token\n"
            "  $conn.Open()\n"
            "  Write-Output '__DATA_START__'\n"
            "  $cmd = $conn.CreateCommand()\n"
            "  $cmd.CommandText = 'SELECT TOP %4 * FROM %5'\n"
            "  $reader = $cmd.ExecuteReader()\n"
            "  # Output column headers\n"
            "  $cols = @()\n"
            "  for ($i = 0; $i -lt $reader.FieldCount; $i++) { $cols += $reader.GetName($i) }\n"
            "  Write-Output ($cols -join '|')\n"
            "  Write-Output '__HEADER_END__'\n"
            "  while ($reader.Read()) {\n"
            "    $row = @()\n"
            "    for ($i = 0; $i -lt $reader.FieldCount; $i++) {\n"
            "      $val = $reader.GetValue($i)\n"
            "      if ($val -eq [DBNull]::Value) { $val = 'NULL' }\n"
            "      $row += [string]$val -replace '\\|',';'\n"
            "    }\n"
            "    Write-Output ($row -join '|')\n"
            "  }\n"
            "  $reader.Close()\n"
            "  $conn.Close()\n"
            "  Write-Output '__DATA_END__'\n"
            "} catch {\n"
            "  Write-Output \"__DATA_ERROR__:$($_.Exception.Message)\"\n"
            "}\n"
        ).arg(token, currentServerFqdn, currentDbName, QString::number(rowLimit), tableName);

        QProcess *dataProcess = new QProcess(this);
        dataProcess->setProcessChannelMode(QProcess::MergedChannels);

        connect(dataProcess, &QProcess::finished, this, [this, dataProcess, tableName](int, QProcess::ExitStatus) {
            QString output = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(dataProcess->readAllStandardOutput()));
            setLoading(false);

            if (output.contains("__DATA_ERROR__:")) {
                QString error = output.section("__DATA_ERROR__:", 1).section('\n', 0, 0);
                appendLog(QString("[-] Data query failed: %1").arg(error), "red");
                QMessageBox::critical(this, "Query Error", QString("Failed to query data:\n\n%1").arg(error));
                dataProcess->deleteLater();
                return;
            }

            if (output.contains("__DATA_START__") && output.contains("__DATA_END__")) {
                QString data = output.section("__DATA_START__", 1).section("__DATA_END__", 0, 0).trimmed();

                // Save to file
                QString safeTableName = QString(tableName).replace('.', '_');
                QString filePath = QFileDialog::getSaveFileName(this, "Save Table Data",
                    QDir::homePath() + QString("/%1_data.csv").arg(safeTableName),
                    "CSV Files (*.csv);;All Files (*)");

                if (!filePath.isEmpty()) {
                    QFile file(filePath);
                    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                        QTextStream out(&file);
                        // Convert pipe-delimited to comma-delimited for CSV
                        QStringList lines = data.split('\n');
                        for (const QString &line : lines) {
                            if (line == "__HEADER_END__") continue;
                            out << "\"" << line.split('|').join("\",\"") << "\"\n";
                        }
                        file.close();
                        appendLog(QString("[+] Data saved to: %1").arg(filePath), "green");
                    }
                }
            }

            dataProcess->deleteLater();
        });

        QStringList args;
        args << "-NoProfile" << "-NonInteractive" << "-Command" << script;
        dataProcess->start("pwsh", args);
    }
}

void SqlDatabaseWindow::executeCredentialDataQuery(const QString &tableName, int rowLimit) {
    setLoading(true);

    QString server = getEffectiveServerFqdn();
    QString database = getEffectiveDatabaseName();
    QString username = sqlUsernameInput->text().trimmed();
    QString password = sqlPasswordInput->text();

    appendLog(QString("[*] Downloading top %1 rows from %2 via credentials...").arg(rowLimit).arg(tableName), "cyan");

    QString query = QString("SELECT TOP %1 * FROM %2").arg(rowLimit).arg(tableName);

    QString script = QString(
        "$ErrorActionPreference='Stop'\n"
        "try {\n"
        "  $secPass = ConvertTo-SecureString '%1' -AsPlainText -Force\n"
        "  $cred = New-Object System.Management.Automation.PSCredential('%2', $secPass)\n"
        "  Write-Output '__DATA_START__'\n"
        "  $results = Invoke-SqlCmd -ServerInstance '%3' -Database '%4' -Credential $cred -Query '%5' -TrustServerCertificate -ConnectionTimeout 30 -QueryTimeout 120 -WarningAction SilentlyContinue 3>$null\n"
        "  if ($results) {\n"
        "    # Output headers\n"
        "    $cols = $results[0].PSObject.Properties | Where-Object { $_.Name -notlike 'RowError*' -and $_.Name -notlike 'RowState*' -and $_.Name -notlike 'Table*' -and $_.Name -notlike 'HasErrors*' -and $_.Name -notlike 'ItemArray*' } | ForEach-Object { $_.Name }\n"
        "    Write-Output ($cols -join '|')\n"
        "    Write-Output '__HEADER_END__'\n"
        "    foreach ($row in $results) {\n"
        "      $vals = @()\n"
        "      foreach ($col in $cols) {\n"
        "        $val = $row.$col\n"
        "        if ($null -eq $val -or $val -is [DBNull]) { $val = 'NULL' }\n"
        "        $vals += [string]$val -replace '\\|',';'\n"
        "      }\n"
        "      Write-Output ($vals -join '|')\n"
        "    }\n"
        "  }\n"
        "  Write-Output '__DATA_END__'\n"
        "} catch {\n"
        "  Write-Output \"__DATA_ERROR__:$($_.Exception.Message)\"\n"
        "}\n"
    ).arg(
        InputValidator::escapePsString(password),
        InputValidator::escapePsString(username),
        InputValidator::escapePsString(server),
        InputValidator::escapePsString(database),
        InputValidator::escapePsString(query)
    );

    QProcess *dataProcess = new QProcess(this);
    dataProcess->setProcessChannelMode(QProcess::MergedChannels);

    connect(dataProcess, &QProcess::finished, this, [this, dataProcess, tableName](int, QProcess::ExitStatus) {
        QString output = QString::fromUtf8(dataProcess->readAllStandardOutput());
        setLoading(false);

        if (output.contains("__DATA_ERROR__:")) {
            QString error = output.section("__DATA_ERROR__:", 1).section('\n', 0, 0);
            appendLog(QString("[-] Data query failed: %1").arg(error), "red");
            QMessageBox::critical(this, "Query Error", QString("Failed to query data:\n\n%1").arg(error));
            dataProcess->deleteLater();
            return;
        }

        if (output.contains("__DATA_START__") && output.contains("__DATA_END__")) {
            QString data = output.section("__DATA_START__", 1).section("__DATA_END__", 0, 0).trimmed();

            // Save to file
            QString safeTableName = QString(tableName).replace('.', '_');
            QString filePath = QFileDialog::getSaveFileName(this, "Save Table Data",
                QDir::homePath() + QString("/%1_data.csv").arg(safeTableName),
                "CSV Files (*.csv);;All Files (*)");

            if (!filePath.isEmpty()) {
                QFile file(filePath);
                if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    QTextStream out(&file);
                    QStringList lines = data.split('\n');
                    for (const QString &line : lines) {
                        if (line == "__HEADER_END__") continue;
                        out << "\"" << line.split('|').join("\",\"") << "\"\n";
                    }
                    file.close();
                    appendLog(QString("[+] Data saved to: %1").arg(filePath), "green");
                }
            }
        }

        dataProcess->deleteLater();
    });

    QStringList args;
    args << "-NoProfile" << "-NonInteractive" << "-Command" << script;
    dataProcess->start("pwsh", args);

    if (!dataProcess->waitForStarted(5000)) {
        setLoading(false);
        appendLog("[-] Failed to start PowerShell process", "red");
    }
}

// ============================================================================
// Export Functions
// ============================================================================

void SqlDatabaseWindow::copySelectedItem() {
    auto *item = resultsTree->currentItem();
    if (!item) {
        QMessageBox::information(this, "No Selection", "Please select an item to copy.");
        return;
    }

    QString text = QString("Name: %1\nType: %2\nStatus: %3\nLocation: %4\nSKU: %5\nDetails: %6")
                       .arg(item->text(0), item->text(1), item->text(2),
                            item->text(3), item->text(4), item->text(5));

    QApplication::clipboard()->setText(text);
    appendLog("[+] Copied to clipboard", "green");
}

void SqlDatabaseWindow::exportResults() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export Results",
        QDir::homePath() + "/sql_database_export.csv", "CSV Files (*.csv);;Text Files (*.txt);;All Files (*)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);

    if (filePath.endsWith(".csv")) {
        out << "Name,Type,Status,Location,SKU,Details\n";
        QTreeWidgetItemIterator it(resultsTree);
        while (*it) {
            out << QString("\"%1\",\"%2\",\"%3\",\"%4\",\"%5\",\"%6\"\n")
                   .arg((*it)->text(0), (*it)->text(1), (*it)->text(2),
                        (*it)->text(3), (*it)->text(4), (*it)->text(5));
            ++it;
        }
    } else {
        out << "Azure SQL Database Export\n";
        out << "=========================\n";
        out << QString("Generated: %1\n\n").arg(QDateTime::currentDateTime().toString());

        QTreeWidgetItemIterator it(resultsTree);
        while (*it) {
            QString indent = (*it)->parent() ? "  " : "";
            out << QString("%1%2 [%3] - %4\n")
                   .arg(indent, (*it)->text(0), (*it)->text(1), (*it)->text(5));
            ++it;
        }
    }

    file.close();
    appendLog(QString("[+] Exported to %1").arg(filePath), "green");
}

void SqlDatabaseWindow::cancelRequests() {
    cancelRequested = true;
    appendLog("[!] Cancelling requests...", "yellow");
    for (QNetworkReply *reply : activeReplies) {
        if (reply && !reply->isFinished()) {
            reply->abort();
        }
    }
    activeReplies.clear();
    if (pwshProcess && pwshProcess->state() != QProcess::NotRunning) {
        pwshProcess->kill();
        appendLog("[*] PowerShell process terminated", "yellow");
    }
    setLoading(false);
    appendLog("[*] Requests cancelled", "yellow");
}
