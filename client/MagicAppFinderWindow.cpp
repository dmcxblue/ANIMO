#include "MagicAppFinderWindow.h"
#include "UserSelectorWidget.h"
#include "StyleManager.h"
#include "NetworkHelper.h"

#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QClipboard>
#include <QApplication>
#include <QFileDialog>
#include <QTextStream>
#include <QMessageBox>

MagicAppFinderWindow::MagicAppFinderWindow(QWidget *parent)
    : EnumerationWindowBase(parent), pendingChecks(0), grantsProcessed(0), totalGrants(0)
{
    setWindowTitle("Magic App Finder");
    setupUi();
}

void MagicAppFinderWindow::setupUi()
{
    // Setup base UI first (creates mainLayout)
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required: Directory.Read.All or Application.Read.All");

    // Insert info banner at the top
    auto *infoLabel = new QLabel(
        "<b>Magic App Finder</b> - Discover applications vulnerable to OAuth consent abuse<br>"
        "<i>Finds apps with:</i> AllPrincipals consent + appRoleAssignmentRequired=false + public redirect URIs<br>"
        "<i>Red Team Value:</i> These apps can be used for illicit consent attacks without admin approval.", this);
    infoLabel->setStyleSheet("color: #ffc107; padding: 8px; background: #2a2a2a; border-radius: 3px;");
    infoLabel->setWordWrap(true);
    mainLayout->insertWidget(0, infoLabel);

    // Control buttons
    auto *controlGroup = new QGroupBox("Scan Controls", this);
    auto *controlLayout = new QHBoxLayout(controlGroup);

    scanBtn = new QPushButton("Start Scan", this);
    scanBtn->setToolTip("Scan tenant for vulnerable applications");
    StyleManager::applyPrimaryStyle(scanBtn);
    connect(scanBtn, &QPushButton::clicked, this, &MagicAppFinderWindow::startScan);

    exportBtn = new QPushButton("Export CSV", this);
    exportBtn->setEnabled(false);
    connect(exportBtn, &QPushButton::clicked, this, &MagicAppFinderWindow::exportResults);

    copyBtn = new QPushButton("Copy Selected", this);
    connect(copyBtn, &QPushButton::clicked, this, &MagicAppFinderWindow::copySelected);

    controlLayout->addWidget(scanBtn);
    controlLayout->addWidget(cancelBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(exportBtn);
    controlLayout->addWidget(copyBtn);

    mainLayout->addWidget(controlGroup);

    // Results table
    auto *resultsGroup = new QGroupBox("Vulnerable Applications", this);
    auto *resultsLayout = new QVBoxLayout(resultsGroup);

    resultsTable = new QTableWidget(0, 5, this);
    resultsTable->setHorizontalHeaderLabels({"App Name", "App ID", "Consent Type", "Scope Type", "Redirect URIs"});
    resultsTable->horizontalHeader()->setStretchLastSection(true);
    resultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable->setAlternatingRowColors(true);
    resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    resultsLayout->addWidget(resultsTable);
    mainLayout->addWidget(resultsGroup);

    setupBottomUi();
}

QList<QPushButton*> MagicAppFinderWindow::getOperationButtons()
{
    return {scanBtn};
}

void MagicAppFinderWindow::startScan()
{
    QString token = getToken();
    if (token.isEmpty()) {
        logError("Please provide an access token");
        return;
    }

    if (!validateToken(token, "https://graph.microsoft.com")) {
        return;
    }

    resultsTable->setRowCount(0);
    allPrincipalsClients.clear();
    pendingChecks = 0;
    grantsProcessed = 0;
    totalGrants = 0;
    exportBtn->setEnabled(false);

    setLoading(true);
    logInfo("Starting Magic App scan...");
    logInfo("Step 1: Fetching all OAuth permission grants...");

    fetchOAuthGrants();
}

void MagicAppFinderWindow::fetchOAuthGrants()
{
    if (cancelRequested) {
        setLoading(false);
        return;
    }

    QString token = getToken();
    QNetworkRequest req = createBearerRequest(
        "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999",
        token);

    QNetworkReply *reply = net->get(req);
    trackReply(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            setLoading(false);
            return;
        }

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("Failed to fetch grants: %1").arg(NetworkHelper::parseApiError(reply)));
            setLoading(false);
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();
        QJsonArray grants = obj["value"].toArray();

        totalGrants += grants.size();
        logInfo(QString("Fetched %1 grants (total: %2)").arg(grants.size()).arg(totalGrants));

        // Collect AllPrincipals grants
        for (const QJsonValue &v : grants) {
            QJsonObject grant = v.toObject();
            if (grant["consentType"].toString() == "AllPrincipals") {
                QString clientId = grant["clientId"].toString();
                if (!allPrincipalsClients.contains(clientId)) {
                    allPrincipalsClients.append(clientId);
                }
            }
        }

        // Check for pagination
        QString nextLink = obj["@odata.nextLink"].toString();
        if (!nextLink.isEmpty() && !cancelRequested) {
            QString token = getToken();
            QNetworkRequest nextReq = createBearerRequest(nextLink, token);
            QNetworkReply *nextReply = net->get(nextReq);
            trackReply(nextReply);

            connect(nextReply, &QNetworkReply::finished, this, [this, nextReply]() {
                untrackReply(nextReply);
                // Re-process with new data
                QJsonDocument doc = QJsonDocument::fromJson(nextReply->readAll());
                processGrants(doc.object()["value"].toArray());
                nextReply->deleteLater();
            });
        } else {
            processGrants(QJsonArray());
        }
    });
}

void MagicAppFinderWindow::processGrants(const QJsonArray &grants)
{
    // Add any new AllPrincipals grants
    for (const QJsonValue &v : grants) {
        QJsonObject grant = v.toObject();
        if (grant["consentType"].toString() == "AllPrincipals") {
            QString clientId = grant["clientId"].toString();
            if (!allPrincipalsClients.contains(clientId)) {
                allPrincipalsClients.append(clientId);
            }
        }
    }

    logSuccess(QString("Found %1 apps with AllPrincipals consent").arg(allPrincipalsClients.size()));

    if (allPrincipalsClients.isEmpty()) {
        logInfo("No vulnerable applications found");
        setLoading(false);
        return;
    }

    logInfo("Step 2: Checking service principals for appRoleAssignmentRequired=false...");
    pendingChecks = allPrincipalsClients.size();
    updateProgress(0, pendingChecks);

    for (const QString &clientId : allPrincipalsClients) {
        if (cancelRequested) break;
        checkServicePrincipal(clientId);
    }
}

void MagicAppFinderWindow::checkServicePrincipal(const QString &clientId)
{
    if (cancelRequested) {
        setLoading(false);
        return;
    }

    QString token = getToken();
    QString url = QString("https://graph.microsoft.com/v1.0/servicePrincipals/%1").arg(clientId);
    QNetworkRequest req = createBearerRequest(url, token);

    QNetworkReply *reply = net->get(req);
    trackReply(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, clientId]() {
        untrackReply(reply);
        reply->deleteLater();

        pendingChecks--;
        updateProgress(allPrincipalsClients.size() - pendingChecks, allPrincipalsClients.size());

        if (cancelRequested) {
            if (pendingChecks == 0) setLoading(false);
            return;
        }

        if (!NetworkHelper::isReplySuccess(reply)) {
            if (pendingChecks == 0) {
                logInfo("Scan complete");
                setLoading(false);
                exportBtn->setEnabled(resultsTable->rowCount() > 0);
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject sp = doc.object();

        bool appRoleRequired = sp["appRoleAssignmentRequired"].toBool();
        if (!appRoleRequired) {
            QString appId = sp["appId"].toString();
            QString displayName = sp["displayName"].toString();
            checkApplication(appId, displayName);
        } else {
            if (pendingChecks == 0) {
                logInfo("Scan complete");
                setLoading(false);
                exportBtn->setEnabled(resultsTable->rowCount() > 0);
            }
        }
    });
}

void MagicAppFinderWindow::checkApplication(const QString &appId, const QString &spDisplayName)
{
    if (cancelRequested) return;

    QString token = getToken();
    QString url = QString("https://graph.microsoft.com/v1.0/applications(appId='%1')").arg(appId);
    QNetworkRequest req = createBearerRequest(url, token);

    QNetworkReply *reply = net->get(req);
    trackReply(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, appId, spDisplayName]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            if (pendingChecks == 0) setLoading(false);
            return;
        }

        if (NetworkHelper::isReplySuccess(reply)) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject app = doc.object();

            QJsonObject api = app["api"].toObject();
            QJsonArray scopes = api["oauth2PermissionScopes"].toArray();

            if (!scopes.isEmpty()) {
                QString scopeType = scopes[0].toObject()["type"].toString();
                if (scopeType == "User") {
                    QJsonObject publicClient = app["publicClient"].toObject();
                    QJsonArray redirectUris = publicClient["redirectUris"].toArray();

                    if (!redirectUris.isEmpty()) {
                        QStringList uris;
                        for (const QJsonValue &uri : redirectUris) {
                            uris.append(uri.toString());
                        }

                        QString displayName = app["displayName"].toString();
                        if (displayName.isEmpty()) displayName = spDisplayName;

                        addVulnerableApp(displayName, appId, "AllPrincipals", uris, scopeType);
                        logSuccess(QString("FOUND: %1 (%2)").arg(displayName, appId));
                    }
                }
            }
        }

        if (pendingChecks == 0) {
            logInfo(QString("Scan complete. Found %1 vulnerable apps").arg(resultsTable->rowCount()));
            setLoading(false);
            exportBtn->setEnabled(resultsTable->rowCount() > 0);
        }
    });
}

void MagicAppFinderWindow::addVulnerableApp(const QString &displayName, const QString &appId,
                                             const QString &consentType, const QStringList &redirectUris,
                                             const QString &scopeType)
{
    int row = resultsTable->rowCount();
    resultsTable->insertRow(row);

    auto *nameItem = new QTableWidgetItem(displayName);
    nameItem->setForeground(QColor("#00ff00"));
    resultsTable->setItem(row, 0, nameItem);

    resultsTable->setItem(row, 1, new QTableWidgetItem(appId));
    resultsTable->setItem(row, 2, new QTableWidgetItem(consentType));
    resultsTable->setItem(row, 3, new QTableWidgetItem(scopeType));
    resultsTable->setItem(row, 4, new QTableWidgetItem(redirectUris.join(", ")));
}

void MagicAppFinderWindow::exportResults()
{
    if (resultsTable->rowCount() == 0) {
        QMessageBox::information(this, "Export", "No results to export");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export Results", "magic_apps.csv", "CSV Files (*.csv)");
    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing");
        return;
    }

    QTextStream out(&file);
    out << "App Name,App ID,Consent Type,Scope Type,Redirect URIs\n";

    for (int row = 0; row < resultsTable->rowCount(); row++) {
        QStringList cols;
        for (int col = 0; col < resultsTable->columnCount(); col++) {
            QString cell = resultsTable->item(row, col)->text();
            cell.replace("\"", "\"\"");
            cols.append(QString("\"%1\"").arg(cell));
        }
        out << cols.join(",") << "\n";
    }

    file.close();
    logSuccess(QString("Exported %1 results to %2").arg(resultsTable->rowCount()).arg(filename));
}

void MagicAppFinderWindow::copySelected()
{
    QList<QTableWidgetItem*> selected = resultsTable->selectedItems();
    if (selected.isEmpty()) {
        QMessageBox::information(this, "Copy", "Please select rows to copy");
        return;
    }

    QSet<int> rows;
    for (auto *item : selected) {
        rows.insert(item->row());
    }

    QStringList lines;
    for (int row : rows) {
        QString appId = resultsTable->item(row, 1)->text();
        lines.append(appId);
    }

    QApplication::clipboard()->setText(lines.join("\n"));
    logInfo(QString("Copied %1 app IDs to clipboard").arg(lines.size()));
}
