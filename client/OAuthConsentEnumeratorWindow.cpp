#include "OAuthConsentEnumeratorWindow.h"
#include "TablePlaceholder.h"
#include "UserSelectorWidget.h"
#include "StyleManager.h"
#include "NetworkHelper.h"

#include <QHBoxLayout>
#include <QGroupBox>
#include <QSplitter>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QTextStream>
#include <QDateTime>

OAuthConsentEnumeratorWindow::OAuthConsentEnumeratorWindow(QWidget *parent)
    : EnumerationWindowBase(parent), pendingResolutions(0)
{
    setWindowTitle("OAuth Consent Enumeration");
    setupUi();
}

void OAuthConsentEnumeratorWindow::setupUi() {
    // Info banner
    auto *infoLabel = new QLabel(
        "<b>OAuth Consent Enumeration</b> - Discover what permissions users have granted to applications<br>"
        "<i>Red Team Value:</i> Users are more likely to approve scopes they've approved before. "
        "Use this to identify phishing targets and over-permissioned apps.", this);
    infoLabel->setStyleSheet("color: #ffc107; padding: 8px; background: #2a2a2a; border-radius: 3px;");
    infoLabel->setWordWrap(true);
    mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(infoLabel);

    // Setup base UI (token input, user selector, etc.)
    auto *tokenGroup = new QGroupBox("Microsoft Graph Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, [this](const QString &upn) {
        tokenInput->clear();
        updateTokenStatus();
        logInfo(QString("Switched to user: %1").arg(upn));
    });
    connect(userSelector, &UserSelectorWidget::logMessage, this, [this](const QString &msg, const QString &color) {
        appendLog(msg, color);
    });

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, [this]() {
        if (!userSelector->hasSelection()) {
            logError("Please select a user first");
            return;
        }
        logInfo("Fetching Graph token for selected user...");
        userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &token, const QString &error) {
            if (success) {
                tokenInput->setText(token);
                updateTokenStatus();
                logSuccess("Graph token acquired");
            } else {
                logError(QString("Failed to fetch token: %1").arg(error));
            }
        });
    });

    auto *tokenRow = new QHBoxLayout();
    tokenInput = new QLineEdit(this);
    tokenInput->setPlaceholderText("Paste access token for https://graph.microsoft.com");
    tokenInput->setEchoMode(QLineEdit::Password);
    tokenRow->addWidget(tokenInput);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    tokenRow->addWidget(tokenStatus);
    tokenLayout->addLayout(tokenRow);

    auto *permNote = new QLabel("<i>Required: DelegatedPermissionGrant.ReadWrite.All or Directory.Read.All</i>", this);
    permNote->setStyleSheet(StyleManager::permissionNoteStyle());
    tokenLayout->addWidget(permNote);

    mainLayout->addWidget(tokenGroup);

    // Controls
    auto *controlGroup = new QGroupBox("Enumeration Options", this);
    auto *controlLayout = new QVBoxLayout(controlGroup);

    auto *btnRow1 = new QHBoxLayout();
    enumMyConsentsBtn = new QPushButton("My Consents", this);
    enumMyConsentsBtn->setToolTip("List permissions the current user has consented to");
    enumAllConsentsBtn = new QPushButton("All Tenant Consents", this);
    enumAllConsentsBtn->setToolTip("List all oauth2PermissionGrants in the tenant (requires admin)");
    StyleManager::applyDangerStyle(enumAllConsentsBtn);
    btnRow1->addWidget(enumMyConsentsBtn);
    btnRow1->addWidget(enumAllConsentsBtn);
    btnRow1->addStretch();
    controlLayout->addLayout(btnRow1);

    auto *btnRow2 = new QHBoxLayout();
    btnRow2->addWidget(new QLabel("App/SPN ID:", this));
    appIdInput = new QLineEdit(this);
    appIdInput->setPlaceholderText("Service Principal Object ID (optional)");
    appIdInput->setMinimumWidth(300);
    btnRow2->addWidget(appIdInput);
    enumAppConsentsBtn = new QPushButton("Consents for App", this);
    enumAppConsentsBtn->setToolTip("List permissions granted to a specific application");
    btnRow2->addWidget(enumAppConsentsBtn);
    btnRow2->addStretch();
    controlLayout->addLayout(btnRow2);

    auto *optRow = new QHBoxLayout();
    resolveNamesCheckbox = new QCheckBox("Resolve app names (slower)", this);
    resolveNamesCheckbox->setChecked(true);
    optRow->addWidget(resolveNamesCheckbox);
    optRow->addStretch();
    controlLayout->addLayout(optRow);

    mainLayout->addWidget(controlGroup);

    // Results splitter
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Results tree
    resultsTree = new QTreeWidget(this);
    new TablePlaceholder(resultsTree, "No consent grants yet - run enumeration.");
    resultsTree->setHeaderLabels({"Principal/App", "Resource", "Scope", "Consent Type", "ID"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->header()->setStretchLastSection(true);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    splitter->addWidget(resultsTree);

    mainLayout->addWidget(splitter, 1);

    // Setup bottom UI (progress bar, log output, cancel button)
    setupBottomUi();

    // Bottom buttons row
    auto *bottomRow = new QHBoxLayout();
    copyBtn = new QPushButton("Copy Selected", this);
    exportBtn = new QPushButton("Export CSV", this);
    bottomRow->addStretch();
    bottomRow->addWidget(copyBtn);
    bottomRow->addWidget(exportBtn);
    mainLayout->addLayout(bottomRow);

    // Connections
    connect(enumMyConsentsBtn, &QPushButton::clicked, this, &OAuthConsentEnumeratorWindow::enumerateMyConsents);
    connect(enumAllConsentsBtn, &QPushButton::clicked, this, &OAuthConsentEnumeratorWindow::enumerateAllConsents);
    connect(enumAppConsentsBtn, &QPushButton::clicked, this, &OAuthConsentEnumeratorWindow::enumerateAppConsents);
    connect(copyBtn, &QPushButton::clicked, this, &OAuthConsentEnumeratorWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &OAuthConsentEnumeratorWindow::exportResults);

    updateTokenStatus();
    resize(1000, 700);
}

QList<QPushButton*> OAuthConsentEnumeratorWindow::getOperationButtons() {
    return {enumMyConsentsBtn, enumAllConsentsBtn, enumAppConsentsBtn, copyBtn, exportBtn};
}

void OAuthConsentEnumeratorWindow::onCancelOperation() {
    pendingResolutions = 0;
}

void OAuthConsentEnumeratorWindow::enumerateMyConsents() {
    currentToken = getToken();
    if (!validateToken(currentToken, "graph.microsoft.com")) {
        return;
    }

    setLoading(true);
    resultsTree->clear();
    logInfo("Enumerating OAuth consents for current user...");

    QString url = "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants";
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError("Failed to create network request");
        setLoading(false);
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);

        if (cancelRequested) return;

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(NetworkHelper::parseApiError(reply));
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray grants = doc.object().value("value").toArray();

        if (grants.isEmpty()) {
            logWarning("No OAuth permission grants found for current user.");
            return;
        }

        logSuccess(QString("Found %1 permission grant(s)").arg(grants.size()));

        for (const QJsonValue &val : grants) {
            QJsonObject grant = val.toObject();
            QString clientId = grant.value("clientId").toString();
            QString resourceId = grant.value("resourceId").toString();
            QString scope = grant.value("scope").toString();
            QString consentType = grant.value("consentType").toString();
            QString id = grant.value("id").toString();

            auto *item = new QTreeWidgetItem(resultsTree);
            item->setText(0, clientId);
            item->setText(1, resourceId);
            item->setText(2, scope);
            item->setText(3, consentType);
            item->setText(4, id);

            // Highlight dangerous scopes
            if (scope.contains("Mail.Read") || scope.contains("Mail.Send") ||
                scope.contains("Files.ReadWrite") || scope.contains("Directory.ReadWrite")) {
                item->setForeground(2, QBrush(QColor("orange")));
                item->setToolTip(2, "High-value scope - good phishing target");
            }

            // Resolve names if checkbox is checked
            if (resolveNamesCheckbox->isChecked()) {
                resolveServicePrincipal(clientId, item);
            }
        }

        logWarning("Tip: Scopes highlighted in orange are high-value targets for consent phishing");
    });
}

void OAuthConsentEnumeratorWindow::enumerateAllConsents() {
    currentToken = getToken();
    if (!validateToken(currentToken, "graph.microsoft.com")) {
        return;
    }

    setLoading(true);
    resultsTree->clear();
    logInfo("Enumerating ALL OAuth consents in tenant (requires admin)...");

    QString url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999";
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError("Failed to create network request");
        setLoading(false);
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);

        if (cancelRequested) return;

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(NetworkHelper::parseApiError(reply));
            int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (status == 403) {
                logWarning("Access denied. Requires DelegatedPermissionGrant.ReadWrite.All or admin consent.");
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray grants = doc.object().value("value").toArray();

        if (grants.isEmpty()) {
            logWarning("No OAuth permission grants found in tenant.");
            return;
        }

        logSuccess(QString("Found %1 permission grant(s) in tenant").arg(grants.size()));

        // Group by consentType
        QMap<QString, QTreeWidgetItem*> groups;

        for (const QJsonValue &val : grants) {
            QJsonObject grant = val.toObject();
            QString clientId = grant.value("clientId").toString();
            QString resourceId = grant.value("resourceId").toString();
            QString scope = grant.value("scope").toString();
            QString consentType = grant.value("consentType").toString();
            QString principalId = grant.value("principalId").toString();
            QString id = grant.value("id").toString();

            // Create group if needed
            QString groupKey = consentType == "AllPrincipals" ? "Admin Consents (All Users)" : "User Consents";
            if (!groups.contains(groupKey)) {
                auto *group = new QTreeWidgetItem(resultsTree);
                group->setText(0, groupKey);
                group->setFirstColumnSpanned(true);
                groups[groupKey] = group;
            }

            auto *item = new QTreeWidgetItem(groups[groupKey]);
            item->setText(0, clientId);
            item->setText(1, resourceId);
            item->setText(2, scope);
            item->setText(3, consentType == "AllPrincipals" ? "Admin (tenant-wide)" : QString("User: %1").arg(principalId.left(8) + "..."));
            item->setText(4, id);

            // Highlight admin consents with dangerous scopes
            if (consentType == "AllPrincipals") {
                item->setForeground(3, QBrush(QColor("#ff6b6b")));
                if (scope.contains("ReadWrite") || scope.contains("FullControl")) {
                    item->setForeground(2, QBrush(QColor("orange")));
                    item->setToolTip(2, "Admin-consented dangerous scope!");
                }
            }

            // Resolve names if checkbox is checked (limit to avoid rate limiting)
            if (resolveNamesCheckbox->isChecked() && pendingResolutions < 20) {
                resolveServicePrincipal(clientId, item);
            }
        }

        // Expand groups
        for (auto *group : groups) {
            group->setExpanded(true);
            group->setText(0, QString("%1 (%2)").arg(group->text(0)).arg(group->childCount()));
        }

        logWarning("Admin consents (AllPrincipals) apply to ALL users - high value!");
    });
}

void OAuthConsentEnumeratorWindow::enumerateAppConsents() {
    currentToken = getToken();
    QString appId = appIdInput->text().trimmed();

    if (!validateToken(currentToken, "graph.microsoft.com")) {
        return;
    }

    if (appId.isEmpty()) {
        QMessageBox::warning(this, "Missing App ID", "Please enter a Service Principal Object ID.");
        return;
    }

    setLoading(true);
    resultsTree->clear();
    logInfo(QString("Enumerating consents for app: %1").arg(appId));

    QString url = QString("https://graph.microsoft.com/v1.0/servicePrincipals/%1/oauth2PermissionGrants").arg(appId);
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        logError("Failed to create network request");
        setLoading(false);
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, appId]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);

        if (cancelRequested) return;

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(NetworkHelper::parseApiError(reply));
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray grants = doc.object().value("value").toArray();

        if (grants.isEmpty()) {
            logWarning(QString("No OAuth permission grants found for app %1").arg(appId));
            return;
        }

        logSuccess(QString("Found %1 permission grant(s) for app").arg(grants.size()));

        for (const QJsonValue &val : grants) {
            QJsonObject grant = val.toObject();
            QString resourceId = grant.value("resourceId").toString();
            QString scope = grant.value("scope").toString();
            QString consentType = grant.value("consentType").toString();
            QString principalId = grant.value("principalId").toString();
            QString id = grant.value("id").toString();

            auto *item = new QTreeWidgetItem(resultsTree);
            item->setText(0, appId);
            item->setText(1, resourceId);
            item->setText(2, scope);
            item->setText(3, consentType == "AllPrincipals" ? "Admin (tenant-wide)" : QString("User: %1").arg(principalId.left(8) + "..."));
            item->setText(4, id);

            if (resolveNamesCheckbox->isChecked()) {
                resolveServicePrincipal(resourceId, item);
            }
        }

        logInfo("These are the permissions this app has been granted access to");
    });
}

void OAuthConsentEnumeratorWindow::resolveServicePrincipal(const QString &spId, QTreeWidgetItem *item) {
    if (spId.isEmpty() || currentToken.isEmpty()) return;

    pendingResolutions++;

    QString url = QString("https://graph.microsoft.com/v1.0/servicePrincipals/%1?$select=displayName,appId").arg(spId);
    QNetworkReply *reply = net->get(createBearerRequest(url, currentToken));

    if (!reply) {
        pendingResolutions--;
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, item, spId]() {
        untrackReply(reply);
        reply->deleteLater();
        pendingResolutions--;

        if (NetworkHelper::isReplySuccess(reply)) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QString displayName = doc.object().value("displayName").toString();
            if (!displayName.isEmpty()) {
                // Update the item text to show resolved name
                QString currentText = item->text(0);
                if (currentText == spId) {
                    item->setText(0, QString("%1 (%2)").arg(displayName, spId.left(8) + "..."));
                }
                // Also resolve resource column if it matches
                if (item->text(1) == spId) {
                    item->setText(1, QString("%1 (%2)").arg(displayName, spId.left(8) + "..."));
                }
            }
        }
    });
}

void OAuthConsentEnumeratorWindow::copySelectedItem() {
    auto selected = resultsTree->selectedItems();
    if (selected.isEmpty()) {
        QMessageBox::information(this, "No Selection", "Please select item(s) to copy.");
        return;
    }

    QStringList lines;
    lines << "Principal/App\tResource\tScope\tConsent Type\tID";

    for (auto *item : selected) {
        if (item->childCount() > 0) continue; // Skip group headers
        QStringList cols;
        for (int i = 0; i < resultsTree->columnCount(); ++i) {
            cols << item->text(i);
        }
        lines << cols.join("\t");
    }

    QApplication::clipboard()->setText(lines.join("\n"));
    logSuccess(QString("Copied %1 item(s) to clipboard").arg(selected.size()));
}

void OAuthConsentEnumeratorWindow::exportResults() {
    if (resultsTree->topLevelItemCount() == 0) {
        QMessageBox::warning(this, "No Data", "No results to export.");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export OAuth Consents",
        QString("oauth_consents_%1.csv").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        "CSV Files (*.csv)");

    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "Principal/App,Resource,Scope,Consent Type,ID\n";

    std::function<void(QTreeWidgetItem*)> exportItem = [&](QTreeWidgetItem *item) {
        if (item->childCount() > 0) {
            // Group header - export children
            for (int i = 0; i < item->childCount(); ++i) {
                exportItem(item->child(i));
            }
        } else {
            QStringList row;
            for (int i = 0; i < resultsTree->columnCount(); ++i) {
                QString cell = item->text(i);
                if (cell.contains(',') || cell.contains('"') || cell.contains('\n')) {
                    cell = "\"" + cell.replace("\"", "\"\"") + "\"";
                }
                row << cell;
            }
            out << row.join(",") << "\n";
        }
    };

    for (int i = 0; i < resultsTree->topLevelItemCount(); ++i) {
        exportItem(resultsTree->topLevelItem(i));
    }

    file.close();
    logSuccess(QString("Exported results to %1").arg(filename));
}
