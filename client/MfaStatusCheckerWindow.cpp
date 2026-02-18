#include "MfaStatusCheckerWindow.h"
#include "StyleManager.h"
#include "NetworkHelper.h"

#include <QHBoxLayout>
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

MfaStatusCheckerWindow::MfaStatusCheckerWindow(QWidget *parent)
    : EnumerationWindowBase(parent),
      usersProcessed(0), usersTotal(0), vulnerableCount(0), protectedCount(0),
      scanning(false), pendingRequests(0)
{
    setWindowTitle("MFA Status Checker");
    setupUi();
}

void MfaStatusCheckerWindow::setupUi() {
    // Setup base UI (token input, user selector, etc.)
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required permissions: UserAuthenticationMethod.Read.All, User.Read.All");

    // Controls row
    auto *controlLayout = new QHBoxLayout();

    startBtn = new QPushButton("Start Scan", this);
    StyleManager::applySuccessStyle(startBtn);

    auto *maxUsersLabel = new QLabel("Max Users:", this);
    maxUsersSpinBox = new QSpinBox(this);
    maxUsersSpinBox->setRange(10, 10000);
    maxUsersSpinBox->setValue(100);
    maxUsersSpinBox->setToolTip("Maximum number of users to check");

    vulnerableOnlyCheckbox = new QCheckBox("Show Vulnerable Only", this);

    exportBtn = new QPushButton("Export CSV", this);
    copyBtn = new QPushButton("Copy Selected", this);

    controlLayout->addWidget(startBtn);
    controlLayout->addSpacing(20);
    controlLayout->addWidget(maxUsersLabel);
    controlLayout->addWidget(maxUsersSpinBox);
    controlLayout->addWidget(vulnerableOnlyCheckbox);
    controlLayout->addStretch();
    controlLayout->addWidget(copyBtn);
    controlLayout->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout);

    // Results splitter
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Results table
    resultsTable = new QTableWidget(this);
    resultsTable->setColumnCount(5);
    resultsTable->setHorizontalHeaderLabels({"User Principal Name", "Display Name", "MFA Status", "Auth Methods", "User ID"});
    resultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTable->horizontalHeader()->setStretchLastSection(true);
    resultsTable->setAlternatingRowColors(true);
    resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    resultsTable->setSortingEnabled(true);
    splitter->addWidget(resultsTable);

    mainLayout->addWidget(splitter, 1);  // Give table stretch factor

    // Setup bottom UI (progress bar, log output, cancel button)
    setupBottomUi();

    // Connections
    connect(startBtn, &QPushButton::clicked, this, &MfaStatusCheckerWindow::startScan);
    connect(exportBtn, &QPushButton::clicked, this, &MfaStatusCheckerWindow::exportResults);
    connect(copyBtn, &QPushButton::clicked, this, &MfaStatusCheckerWindow::copySelectedRows);
    connect(vulnerableOnlyCheckbox, &QCheckBox::toggled, this, [this](bool checked) {
        for (int i = 0; i < resultsTable->rowCount(); ++i) {
            auto *statusItem = resultsTable->item(i, 2);
            if (statusItem) {
                bool isVulnerable = statusItem->text() == "VULNERABLE";
                resultsTable->setRowHidden(i, checked && !isVulnerable);
            }
        }
    });

    resize(1100, 700);
}

QList<QPushButton*> MfaStatusCheckerWindow::getOperationButtons() {
    return {startBtn, exportBtn, copyBtn};
}

void MfaStatusCheckerWindow::onCancelOperation() {
    scanning = false;
    pendingRequests = 0;
}

void MfaStatusCheckerWindow::startScan() {
    currentToken = getToken();
    if (!validateToken(currentToken, "graph.microsoft.com")) {
        return;
    }

    // Reset state
    resultsTable->setRowCount(0);
    allUsers = QJsonArray();
    usersProcessed = 0;
    usersTotal = 0;
    vulnerableCount = 0;
    protectedCount = 0;
    scanning = true;
    pendingRequests = 0;

    setLoading(true);
    logInfo("Starting MFA status scan...");
    logInfo(QString("Max users to check: %1").arg(maxUsersSpinBox->value()));

    // Start fetching users
    fetchUsers();
}

void MfaStatusCheckerWindow::fetchUsers(const QString &nextLink) {
    if (cancelRequested) {
        finishScan();
        return;
    }

    QString url = nextLink.isEmpty()
        ? "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName&$top=100"
        : nextLink;

    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError("Failed to create network request for fetching users");
        finishScan();
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            logError(QString("Error fetching users: %1").arg(NetworkHelper::parseApiError(reply)));

            // Check for rate limiting
            if (NetworkHelper::isThrottled(reply)) {
                int retryMs = NetworkHelper::getRetryAfterMs(reply);
                logWarning(QString("Rate limited. Retry after %1ms").arg(retryMs));
            }

            finishScan();
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();
        QJsonArray users = obj.value("value").toArray();

        int maxUsers = maxUsersSpinBox->value();
        for (const QJsonValue &val : users) {
            if (allUsers.size() >= maxUsers) break;
            allUsers.append(val);
        }

        logSuccess(QString("Fetched %1 users (total: %2)").arg(users.size()).arg(allUsers.size()));

        // Check if we need more users and there's a next page
        QString next = obj.value("@odata.nextLink").toString();
        if (!next.isEmpty() && allUsers.size() < maxUsers && !cancelRequested) {
            fetchUsers(next);
        } else {
            // Start checking MFA for all users
            usersTotal = allUsers.size();
            updateProgress(0, usersTotal);

            logInfo(QString("Checking MFA status for %1 users...").arg(usersTotal));

            // Process users in batches to avoid overwhelming the API
            int batchSize = 10;
            for (int i = 0; i < qMin(batchSize, allUsers.size()); ++i) {
                QJsonObject user = allUsers[i].toObject();
                checkUserMfa(user["id"].toString(), user["userPrincipalName"].toString(), user["displayName"].toString());
            }
        }
    });
}

void MfaStatusCheckerWindow::checkUserMfa(const QString &userId, const QString &upn, const QString &displayName) {
    if (cancelRequested) {
        return;
    }

    pendingRequests++;

    QString url = QString("https://graph.microsoft.com/v1.0/users/%1/authentication/methods").arg(userId);
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError(QString("Failed to create network request for %1").arg(upn));
        pendingRequests--;
        updateScanProgress();
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, userId, upn, displayName]() {
        untrackReply(reply);
        reply->deleteLater();
        pendingRequests--;

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            int status = NetworkHelper::getHttpStatus(reply);

            // Check for rate limiting
            if (NetworkHelper::isThrottled(reply)) {
                int retryMs = NetworkHelper::getRetryAfterMs(reply);
                logWarning(QString("Rate limited on %1. Retry after %2ms").arg(upn).arg(retryMs));
            } else if (status == 403) {
                logError(QString("Access denied for %1 - need UserAuthenticationMethod.Read.All").arg(upn));
            } else if (status == 404) {
                // User not found or no auth methods
                processAuthMethods(userId, upn, displayName, QJsonArray());
            } else {
                logError(QString("Error checking %1: %2").arg(upn, NetworkHelper::parseApiError(reply)));
            }
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonArray methods = doc.object().value("value").toArray();
            processAuthMethods(userId, upn, displayName, methods);
        }

        updateScanProgress();
    });
}

void MfaStatusCheckerWindow::processAuthMethods(const QString &userId, const QString &upn,
                                                  const QString &displayName, const QJsonArray &methods) {
    QStringList mfaMethods;
    bool hasMfa = false;

    for (const QJsonValue &val : methods) {
        QJsonObject method = val.toObject();
        QString odataType = method["@odata.type"].toString();

        // Check for MFA-capable methods
        if (odataType.contains("phoneAuthenticationMethod")) {
            QString phoneType = method["phoneType"].toString();
            mfaMethods << QString("Phone (%1)").arg(phoneType);
            hasMfa = true;
        } else if (odataType.contains("microsoftAuthenticatorAuthenticationMethod")) {
            QString deviceTag = method["displayName"].toString();
            mfaMethods << QString("Authenticator (%1)").arg(deviceTag.isEmpty() ? "device" : deviceTag);
            hasMfa = true;
        } else if (odataType.contains("fido2AuthenticationMethod")) {
            mfaMethods << "FIDO2 Security Key";
            hasMfa = true;
        } else if (odataType.contains("windowsHelloForBusinessAuthenticationMethod")) {
            mfaMethods << "Windows Hello";
            hasMfa = true;
        } else if (odataType.contains("softwareOathAuthenticationMethod")) {
            mfaMethods << "Software OATH Token";
            hasMfa = true;
        } else if (odataType.contains("temporaryAccessPassAuthenticationMethod")) {
            mfaMethods << "Temporary Access Pass";
            // TAP alone doesn't count as persistent MFA
        } else if (odataType.contains("passwordAuthenticationMethod")) {
            // Password is not MFA
        } else if (odataType.contains("emailAuthenticationMethod")) {
            mfaMethods << "Email";
            // Email alone is weak MFA
        }
    }

    // Add row to table
    int row = resultsTable->rowCount();
    resultsTable->insertRow(row);

    auto *upnItem = new QTableWidgetItem(upn);
    auto *nameItem = new QTableWidgetItem(displayName);
    auto *statusItem = new QTableWidgetItem(hasMfa ? "PROTECTED" : "VULNERABLE");
    auto *methodsItem = new QTableWidgetItem(mfaMethods.isEmpty() ? "Password only" : mfaMethods.join(", "));
    auto *idItem = new QTableWidgetItem(userId);

    // Color code status
    if (hasMfa) {
        statusItem->setForeground(QBrush(QColor("lightgreen")));
        protectedCount++;
    } else {
        statusItem->setForeground(QBrush(QColor("#ff6b6b")));
        statusItem->setBackground(QBrush(QColor(80, 0, 0)));
        vulnerableCount++;
    }

    resultsTable->setItem(row, 0, upnItem);
    resultsTable->setItem(row, 1, nameItem);
    resultsTable->setItem(row, 2, statusItem);
    resultsTable->setItem(row, 3, methodsItem);
    resultsTable->setItem(row, 4, idItem);

    // Apply filter if needed
    if (vulnerableOnlyCheckbox->isChecked() && hasMfa) {
        resultsTable->setRowHidden(row, true);
    }
}

void MfaStatusCheckerWindow::updateScanProgress() {
    usersProcessed++;
    updateProgress(usersProcessed, usersTotal);

    statsLabel->setText(QString("Progress: %1/%2 | Vulnerable: %3 | Protected: %4")
        .arg(usersProcessed).arg(usersTotal).arg(vulnerableCount).arg(protectedCount));

    // Start next batch
    if (usersProcessed < usersTotal && !cancelRequested) {
        int nextIndex = usersProcessed + pendingRequests;
        if (nextIndex < allUsers.size() && pendingRequests < 10) {
            QJsonObject user = allUsers[nextIndex].toObject();
            checkUserMfa(user["id"].toString(), user["userPrincipalName"].toString(), user["displayName"].toString());
        }
    }

    // Check if done
    if (usersProcessed >= usersTotal || (cancelRequested && pendingRequests == 0)) {
        finishScan();
    }
}

void MfaStatusCheckerWindow::finishScan() {
    scanning = false;
    setLoading(false);

    if (cancelRequested) {
        logWarning("Scan stopped by user.");
    } else {
        logSuccess(QString("Scan complete! Checked %1 users.").arg(usersProcessed));
    }

    if (vulnerableCount > 0) {
        logWarning(QString("Results: %1 VULNERABLE, %2 PROTECTED").arg(vulnerableCount).arg(protectedCount));
        logWarning(QString("Found %1 users without MFA - prime targets for password spray!").arg(vulnerableCount));
    } else {
        logSuccess(QString("Results: %1 VULNERABLE, %2 PROTECTED").arg(vulnerableCount).arg(protectedCount));
    }

    statsLabel->setText(QString("Complete: %1 users | Vulnerable: %2 | Protected: %3")
        .arg(usersProcessed).arg(vulnerableCount).arg(protectedCount));
}

void MfaStatusCheckerWindow::exportResults() {
    if (resultsTable->rowCount() == 0) {
        QMessageBox::warning(this, "No Data", "No results to export.");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export MFA Status",
        QString("mfa_status_%1.csv").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        "CSV Files (*.csv)");

    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "User Principal Name,Display Name,MFA Status,Auth Methods,User ID\n";

    for (int i = 0; i < resultsTable->rowCount(); ++i) {
        if (!resultsTable->isRowHidden(i)) {
            QStringList row;
            for (int j = 0; j < resultsTable->columnCount(); ++j) {
                auto *item = resultsTable->item(i, j);
                QString cell = item ? item->text() : "";
                // Escape CSV
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

void MfaStatusCheckerWindow::copySelectedRows() {
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
    lines << "UPN\tDisplay Name\tMFA Status\tAuth Methods\tUser ID";

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
