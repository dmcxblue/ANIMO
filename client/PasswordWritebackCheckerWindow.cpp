#include "PasswordWritebackCheckerWindow.h"
#include "UserSelectorWidget.h"
#include "StyleManager.h"
#include "NetworkHelper.h"

#include <QHBoxLayout>
#include <QGroupBox>
#include <QSplitter>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDateTime>

PasswordWritebackCheckerWindow::PasswordWritebackCheckerWindow(QWidget *parent)
    : EnumerationWindowBase(parent),
      usersProcessed(0), usersTotal(0), targetCount(0), protectedCount(0),
      scanning(false), writebackEnabled(false), pendingRequests(0)
{
    setWindowTitle("Password Writeback Abuse Checker");
    setupUi();
}

void PasswordWritebackCheckerWindow::setupUi() {
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required: Directory.Read.All, User.Read.All, RoleManagement.Read.Directory");

    // Writeback status display
    auto *statusGroup = new QGroupBox("Password Writeback Status", this);
    auto *statusLayout = new QHBoxLayout(statusGroup);
    writebackStatusLabel = new QLabel("Not checked yet", this);
    writebackStatusLabel->setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px;");
    statusLayout->addWidget(writebackStatusLabel);
    mainLayout->addWidget(statusGroup);

    // Controls
    auto *controlLayout = new QHBoxLayout();

    startBtn = new QPushButton("Start Scan", this);
    StyleManager::applySuccessStyle(startBtn);

    auto *maxUsersLabel = new QLabel("Max Users:", this);
    maxUsersSpinBox = new QSpinBox(this);
    maxUsersSpinBox->setRange(10, 10000);
    maxUsersSpinBox->setValue(500);
    maxUsersSpinBox->setToolTip("Maximum number of synced users to enumerate");

    targetsOnlyCheckbox = new QCheckBox("Show Targets Only", this);
    targetsOnlyCheckbox->setToolTip("Hide protected admin accounts");

    exportBtn = new QPushButton("Export CSV", this);
    copyBtn = new QPushButton("Copy Selected", this);

    controlLayout->addWidget(startBtn);
    controlLayout->addSpacing(20);
    controlLayout->addWidget(maxUsersLabel);
    controlLayout->addWidget(maxUsersSpinBox);
    controlLayout->addWidget(targetsOnlyCheckbox);
    controlLayout->addStretch();
    controlLayout->addWidget(copyBtn);
    controlLayout->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout);

    // Results splitter
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Results table
    resultsTable = new QTableWidget(this);
    resultsTable->setColumnCount(6);
    resultsTable->setHorizontalHeaderLabels({
        "User Principal Name", "Display Name", "Status", "On-Prem DN", "Sync Enabled", "User ID"
    });
    resultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTable->horizontalHeader()->setStretchLastSection(true);
    resultsTable->setAlternatingRowColors(true);
    resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    resultsTable->setSortingEnabled(true);
    splitter->addWidget(resultsTable);

    mainLayout->addWidget(splitter, 1);

    setupBottomUi();

    // Connections
    connect(startBtn, &QPushButton::clicked, this, &PasswordWritebackCheckerWindow::startScan);
    connect(exportBtn, &QPushButton::clicked, this, &PasswordWritebackCheckerWindow::exportResults);
    connect(copyBtn, &QPushButton::clicked, this, &PasswordWritebackCheckerWindow::copySelectedRows);
    connect(targetsOnlyCheckbox, &QCheckBox::toggled, this, [this](bool checked) {
        for (int i = 0; i < resultsTable->rowCount(); ++i) {
            auto *statusItem = resultsTable->item(i, 2);
            if (statusItem) {
                bool isTarget = statusItem->text() == "TARGET";
                resultsTable->setRowHidden(i, checked && !isTarget);
            }
        }
    });

    resize(1200, 750);
}

QList<QPushButton*> PasswordWritebackCheckerWindow::getOperationButtons() {
    return {startBtn, exportBtn, copyBtn};
}

void PasswordWritebackCheckerWindow::onCancelOperation() {
    scanning = false;
    pendingRequests = 0;
}

void PasswordWritebackCheckerWindow::startScan() {
    currentToken = getToken();
    if (!validateToken(currentToken, "graph.microsoft.com")) {
        return;
    }

    // Reset state
    resultsTable->setRowCount(0);
    allSyncedUsers = QJsonArray();
    adminUserIds.clear();
    usersProcessed = 0;
    usersTotal = 0;
    targetCount = 0;
    protectedCount = 0;
    scanning = true;
    writebackEnabled = false;
    pendingRequests = 0;

    writebackStatusLabel->setText("Checking...");
    writebackStatusLabel->setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px; color: yellow;");

    setLoading(true);
    logInfo("Starting Password Writeback abuse scan...");

    checkWritebackStatus();
}

void PasswordWritebackCheckerWindow::checkWritebackStatus() {
    logInfo("Checking Password Writeback configuration...");

    QString url = "https://graph.microsoft.com/v1.0/organization?$select=onPremisesSyncEnabled";
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError("Failed to create network request for organization sync check");
        finishScan();
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            finishScan();
            return;
        }

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("Error checking organization sync: %1").arg(NetworkHelper::parseApiError(reply)));
            logWarning("Continuing with synced user enumeration...");
            writebackStatusLabel->setText("Unknown (check manually)");
            writebackStatusLabel->setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px; color: orange;");
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonArray orgs = doc.object().value("value").toArray();

            if (!orgs.isEmpty()) {
                QJsonObject org = orgs.first().toObject();
                bool syncEnabled = org.value("onPremisesSyncEnabled").toBool(false);

                if (syncEnabled) {
                    logSuccess("Azure AD Connect sync is ENABLED");
                    logWarning("Password Writeback may be configured (requires AD Connect check)");
                    writebackStatusLabel->setText("AD Sync ENABLED - Writeback Possible");
                    writebackStatusLabel->setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px; color: #ff6b6b; background-color: #400000;");
                    writebackEnabled = true;
                } else {
                    logInfo("Azure AD Connect sync is not enabled");
                    writebackStatusLabel->setText("AD Sync Not Enabled");
                    writebackStatusLabel->setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px; color: lightgreen;");
                }
            }
        }

        fetchAdminRoles();
    });
}

void PasswordWritebackCheckerWindow::fetchAdminRoles() {
    if (cancelRequested) {
        finishScan();
        return;
    }

    logInfo("Fetching directory roles to identify protected admins...");

    QString url = "https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName,roleTemplateId";
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError("Failed to create network request for directory roles");
        fetchSyncedUsers();
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            finishScan();
            return;
        }

        if (!NetworkHelper::isReplySuccess(reply)) {
            int status = NetworkHelper::getHttpStatus(reply);
            if (status == 403) {
                logWarning("Cannot read directory roles - will mark all synced users as potential targets");
            } else {
                logError(QString("Error fetching roles: %1").arg(NetworkHelper::parseApiError(reply)));
            }
            fetchSyncedUsers();
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray roles = doc.object().value("value").toArray();

        QStringList protectedRoleTemplates = {
            "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
            "966707d0-3269-4727-9be2-8c3a10f19b9d", // Password Administrator
            "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
            "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
            "158c047a-c907-4556-b7ef-446551a6b5f7", // Cloud Application Administrator
            "b0f54661-2d74-4c50-afa3-1ec803f12efe", // Billing Administrator
        };

        logSuccess(QString("Found %1 active directory roles").arg(roles.size()));

        pendingRequests = 0;
        for (const QJsonValue &val : roles) {
            QJsonObject role = val.toObject();
            QString roleTemplateId = role.value("roleTemplateId").toString();

            if (protectedRoleTemplates.contains(roleTemplateId)) {
                QString roleId = role.value("id").toString();
                QString roleName = role.value("displayName").toString();
                pendingRequests++;
                fetchAdminMembers(roleId, roleName);
            }
        }

        if (pendingRequests == 0) {
            fetchSyncedUsers();
        }
    });
}

void PasswordWritebackCheckerWindow::fetchAdminMembers(const QString &roleId, const QString &roleName) {
    QString url = QString("https://graph.microsoft.com/v1.0/directoryRoles/%1/members?$select=id,userPrincipalName").arg(roleId);
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError(QString("Failed to create network request for role members: %1").arg(roleName));
        pendingRequests--;
        if (pendingRequests == 0) {
            logSuccess(QString("Identified %1 protected admin accounts").arg(adminUserIds.size()));
            fetchSyncedUsers();
        }
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, roleName]() {
        untrackReply(reply);
        reply->deleteLater();
        pendingRequests--;

        if (NetworkHelper::isReplySuccess(reply)) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonArray members = doc.object().value("value").toArray();

            for (const QJsonValue &val : members) {
                QJsonObject member = val.toObject();
                QString userId = member.value("id").toString();
                if (!userId.isEmpty()) {
                    adminUserIds.insert(userId);
                }
            }

            if (!members.isEmpty()) {
                logInfo(QString("%1: %2 members (protected)").arg(roleName).arg(members.size()));
            }
        }

        if (pendingRequests == 0) {
            logSuccess(QString("Identified %1 protected admin accounts").arg(adminUserIds.size()));
            fetchSyncedUsers();
        }
    });
}

void PasswordWritebackCheckerWindow::fetchSyncedUsers(const QString &nextLink) {
    if (cancelRequested) {
        finishScan();
        return;
    }

    QString url = nextLink.isEmpty()
        ? "https://graph.microsoft.com/v1.0/users?$filter=onPremisesSyncEnabled%20eq%20true&$select=id,userPrincipalName,displayName,onPremisesDistinguishedName,onPremisesSyncEnabled,onPremisesSamAccountName&$top=100"
        : nextLink;

    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError("Failed to create network request for synced users");
        if (allSyncedUsers.isEmpty()) {
            finishScan();
        } else {
            processUserResults();
        }
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            processUserResults();
            return;
        }

        if (!NetworkHelper::isReplySuccess(reply)) {
            int status = NetworkHelper::getHttpStatus(reply);
            logError(QString("Error fetching synced users: %1").arg(NetworkHelper::parseApiError(reply)));

            if (status == 403) {
                logWarning("Access denied. Token may lack User.Read.All permission.");
            }

            if (allSyncedUsers.isEmpty()) {
                finishScan();
                return;
            }
            processUserResults();
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();
        QJsonArray users = obj.value("value").toArray();

        int maxUsers = maxUsersSpinBox->value();
        for (const QJsonValue &val : users) {
            if (allSyncedUsers.size() >= maxUsers) break;
            allSyncedUsers.append(val);
        }

        logSuccess(QString("Fetched %1 synced users (total: %2)").arg(users.size()).arg(allSyncedUsers.size()));

        QString nextUrl = obj.value("@odata.nextLink").toString();
        if (!nextUrl.isEmpty() && allSyncedUsers.size() < maxUsers && !cancelRequested) {
            fetchSyncedUsers(nextUrl);
        } else {
            processUserResults();
        }
    });
}

void PasswordWritebackCheckerWindow::processUserResults() {
    usersTotal = allSyncedUsers.size();
    updateProgress(0, usersTotal);

    logInfo(QString("Processing %1 synced users...").arg(usersTotal));

    for (const QJsonValue &val : allSyncedUsers) {
        if (cancelRequested) break;

        QJsonObject user = val.toObject();
        QString userId = user.value("id").toString();
        QString upn = user.value("userPrincipalName").toString();
        QString displayName = user.value("displayName").toString();
        QString onPremDN = user.value("onPremisesDistinguishedName").toString();
        bool syncEnabled = user.value("onPremisesSyncEnabled").toBool();

        bool isAdmin = adminUserIds.contains(userId);
        QString status = isAdmin ? "PROTECTED" : "TARGET";

        int row = resultsTable->rowCount();
        resultsTable->insertRow(row);

        auto *upnItem = new QTableWidgetItem(upn);
        auto *nameItem = new QTableWidgetItem(displayName);
        auto *statusItem = new QTableWidgetItem(status);
        auto *dnItem = new QTableWidgetItem(onPremDN);
        auto *syncItem = new QTableWidgetItem(syncEnabled ? "Yes" : "No");
        auto *idItem = new QTableWidgetItem(userId);

        if (isAdmin) {
            statusItem->setForeground(QBrush(QColor("lightgreen")));
            protectedCount++;
        } else {
            statusItem->setForeground(QBrush(QColor("#ff6b6b")));
            statusItem->setBackground(QBrush(QColor(80, 0, 0)));
            targetCount++;
        }

        resultsTable->setItem(row, 0, upnItem);
        resultsTable->setItem(row, 1, nameItem);
        resultsTable->setItem(row, 2, statusItem);
        resultsTable->setItem(row, 3, dnItem);
        resultsTable->setItem(row, 4, syncItem);
        resultsTable->setItem(row, 5, idItem);

        if (targetsOnlyCheckbox->isChecked() && isAdmin) {
            resultsTable->setRowHidden(row, true);
        }

        usersProcessed++;
        updateProgress(usersProcessed, usersTotal);
    }

    finishScan();
}

void PasswordWritebackCheckerWindow::finishScan() {
    scanning = false;
    setLoading(false);

    if (cancelRequested) {
        logWarning("Scan stopped by user.");
    } else {
        logSuccess(QString("Scan complete! Found %1 synced users.").arg(usersProcessed));
    }

    if (targetCount > 0) {
        logWarning(QString("Results: %1 TARGETS, %2 PROTECTED (admins)").arg(targetCount).arg(protectedCount));
    } else {
        logSuccess(QString("Results: %1 TARGETS, %2 PROTECTED (admins)").arg(targetCount).arg(protectedCount));
    }

    if (writebackEnabled && targetCount > 0) {
        logError("PASSWORD WRITEBACK ATTACK POSSIBLE!");
        logWarning(QString("%1 synced non-admin users can have passwords reset from cloud!").arg(targetCount));
        logInfo("Attack: Compromise Password/User Admin -> Reset synced user password -> Syncs to on-prem AD");
    } else if (!writebackEnabled) {
        logInfo("AD Sync not detected. Password writeback attack may not be viable.");
    }

    statsLabel->setText(QString("Complete: %1 synced users | Targets: %2 | Protected: %3")
        .arg(usersProcessed).arg(targetCount).arg(protectedCount));
}

void PasswordWritebackCheckerWindow::exportResults() {
    if (resultsTable->rowCount() == 0) {
        QMessageBox::warning(this, "No Data", "No results to export.");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export Password Writeback Targets",
        QString("writeback_targets_%1.csv").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        "CSV Files (*.csv)");

    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "User Principal Name,Display Name,Status,On-Prem DN,Sync Enabled,User ID\n";

    for (int i = 0; i < resultsTable->rowCount(); ++i) {
        if (!resultsTable->isRowHidden(i)) {
            QStringList row;
            for (int j = 0; j < resultsTable->columnCount(); ++j) {
                auto *item = resultsTable->item(i, j);
                QString cell = item ? item->text() : "";
                if (cell.contains(',') || cell.contains('"') || cell.contains('\n')) {
                    cell = "\"" + cell.replace("\"", "\"\"") + "\"";
                }
                row << cell;
            }
            out << row.join(",") << "\n";
        }
    }

    file.close();
    logSuccess(QString("Exported results to %1").arg(filename));
}

void PasswordWritebackCheckerWindow::copySelectedRows() {
    auto selected = resultsTable->selectedItems();
    if (selected.isEmpty()) {
        QMessageBox::information(this, "No Selection", "Please select rows to copy.");
        return;
    }

    QSet<int> rows;
    for (auto *item : selected) {
        rows.insert(item->row());
    }

    QStringList lines;
    lines << "UPN\tDisplay Name\tStatus\tOn-Prem DN\tSync Enabled\tUser ID";

    for (int row : rows) {
        QStringList cols;
        for (int j = 0; j < resultsTable->columnCount(); ++j) {
            auto *item = resultsTable->item(row, j);
            cols << (item ? item->text() : "");
        }
        lines << cols.join("\t");
    }

    QApplication::clipboard()->setText(lines.join("\n"));
    logSuccess(QString("Copied %1 rows to clipboard").arg(rows.size()));
}
