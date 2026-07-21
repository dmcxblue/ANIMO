#include "SPNEnumWindow.h"
#include "TablePlaceholder.h"
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
#include <QTextStream>
#include <QDir>

SPNEnumWindow::SPNEnumWindow(QWidget *parent)
    : EnumerationWindowBase(parent)
{
    setWindowTitle("Service Principal / App Registration Enumeration");
    setupUi();
}

void SPNEnumWindow::setupUi() {
    // Setup base UI (token input, user selector, etc.)
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com");

    // Controls row
    auto *controlLayout = new QHBoxLayout();
    enumSPNBtn = new QPushButton("Enumerate Service Principals", this);
    enumAppsBtn = new QPushButton("Enumerate App Registrations", this);
    getCredsBtn = new QPushButton("Get Credentials", this);
    getCredsBtn->setEnabled(false);
    getPermsBtn = new QPushButton("Get Permissions", this);
    getPermsBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy", this);
    exportBtn = new QPushButton("Export", this);

    controlLayout->addWidget(enumSPNBtn);
    controlLayout->addWidget(enumAppsBtn);
    controlLayout->addWidget(getCredsBtn);
    controlLayout->addWidget(getPermsBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(copyBtn);
    controlLayout->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout);

    // Main splitter
    auto *splitter = new QSplitter(Qt::Horizontal, this);

    // Results tree
    resultsTree = new QTreeWidget(this);
    new TablePlaceholder(resultsTree, "No service principals yet — run enumeration.");
    resultsTree->setHeaderLabels({"Display Name", "App ID", "Type", "Sign-In Audience", "Created"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setMinimumWidth(500);
    splitter->addWidget(resultsTree);

    // Details area
    detailsArea = new QTextEdit(this);
    detailsArea->setReadOnly(true);
    detailsArea->setPlaceholderText("Select an item to view details...");
    splitter->addWidget(detailsArea);

    mainLayout->addWidget(splitter, 1);

    // Setup bottom UI (progress bar, log output, cancel button)
    setupBottomUi();

    // Connections
    connect(enumSPNBtn, &QPushButton::clicked, this, &SPNEnumWindow::enumerateServicePrincipals);
    connect(enumAppsBtn, &QPushButton::clicked, this, &SPNEnumWindow::enumerateAppRegistrations);
    connect(getCredsBtn, &QPushButton::clicked, this, &SPNEnumWindow::getAppCredentials);
    connect(getPermsBtn, &QPushButton::clicked, this, &SPNEnumWindow::getPermissions);
    connect(resultsTree, &QTreeWidget::itemSelectionChanged, this, &SPNEnumWindow::onItemSelected);
    connect(copyBtn, &QPushButton::clicked, this, &SPNEnumWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &SPNEnumWindow::exportResults);

    resize(1100, 700);
}

QList<QPushButton*> SPNEnumWindow::getOperationButtons() {
    return {enumSPNBtn, enumAppsBtn, getCredsBtn, getPermsBtn, copyBtn, exportBtn};
}

void SPNEnumWindow::onCancelOperation() {
    servicePrincipals = QJsonArray();
    appRegistrations = QJsonArray();
}

void SPNEnumWindow::enumerateServicePrincipals() {
    QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) {
        return;
    }

    setLoading(true);
    logInfo("Enumerating Service Principals...");
    resultsTree->clear();
    servicePrincipals = QJsonArray();

    QString url = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=999&$select=id,appId,displayName,servicePrincipalType,signInAudience,createdDateTime,accountEnabled";
    QNetworkReply *reply = net->get(createBearerRequest(url, token));
    if (!reply) {
        logError("Failed to create network request");
        setLoading(false);
        return;
    }
    trackReply(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            return;
        }

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            logError(QString("Error: %1").arg(NetworkHelper::parseApiError(reply)));
            setLoading(false);
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();
        QJsonArray spns = obj.value("value").toArray();

        for (const QJsonValue &val : spns) {
            servicePrincipals.append(val);
            QJsonObject spn = val.toObject();

            auto *item = new QTreeWidgetItem(resultsTree);
            item->setText(0, spn.value("displayName").toString());
            item->setText(1, spn.value("appId").toString());
            item->setText(2, spn.value("servicePrincipalType").toString());
            item->setText(3, spn.value("signInAudience").toString());
            item->setText(4, spn.value("createdDateTime").toString());
            item->setData(0, Qt::UserRole, spn.value("id").toString());
            item->setData(0, Qt::UserRole + 1, "servicePrincipal");
            item->setData(0, Qt::UserRole + 2, spn.value("appId").toString());

            // Color code by type
            if (spn.value("servicePrincipalType").toString() == "Application") {
                item->setForeground(0, QColor(100, 200, 100));
            } else if (spn.value("servicePrincipalType").toString() == "ManagedIdentity") {
                item->setForeground(0, QColor(100, 150, 255));
            }
        }

        logSuccess(QString("Found %1 Service Principal(s)").arg(servicePrincipals.size()));

        // Check for pagination
        QString nextLink = obj.value("@odata.nextLink").toString();
        if (!nextLink.isEmpty()) {
            fetchNextPage(nextLink);
        } else {
            setLoading(false);
        }
    });
}

void SPNEnumWindow::fetchNextPage(const QString &nextLink) {
    if (cancelRequested) {
        setLoading(false);
        return;
    }

    QString token = getToken();
    QNetworkReply *reply = net->get(createBearerRequest(nextLink, token));
    if (!reply) {
        logError("Failed to create network request");
        setLoading(false);
        return;
    }
    trackReply(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            return;
        }

        if (!NetworkHelper::isReplySuccess(reply)) {
            setLoading(false);
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();
        QJsonArray items = obj.value("value").toArray();

        for (const QJsonValue &val : items) {
            servicePrincipals.append(val);
            QJsonObject spn = val.toObject();

            auto *item = new QTreeWidgetItem(resultsTree);
            item->setText(0, spn.value("displayName").toString());
            item->setText(1, spn.value("appId").toString());
            item->setText(2, spn.value("servicePrincipalType").toString());
            item->setText(3, spn.value("signInAudience").toString());
            item->setText(4, spn.value("createdDateTime").toString());
            item->setData(0, Qt::UserRole, spn.value("id").toString());
            item->setData(0, Qt::UserRole + 1, "servicePrincipal");
        }

        logSuccess(QString("Total: %1 Service Principal(s)").arg(servicePrincipals.size()));

        QString next = obj.value("@odata.nextLink").toString();
        if (!next.isEmpty()) {
            fetchNextPage(next);
        } else {
            setLoading(false);
        }
    });
}

void SPNEnumWindow::enumerateAppRegistrations() {
    QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) {
        return;
    }

    setLoading(true);
    logInfo("Enumerating App Registrations...");
    resultsTree->clear();
    appRegistrations = QJsonArray();

    QString url = "https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials";
    QNetworkReply *reply = net->get(createBearerRequest(url, token));
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

        if (cancelRequested) {
            return;
        }

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("Error: %1").arg(NetworkHelper::parseApiError(reply)));
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray apps = doc.object().value("value").toArray();

        for (const QJsonValue &val : apps) {
            appRegistrations.append(val);
            QJsonObject app = val.toObject();

            auto *item = new QTreeWidgetItem(resultsTree);
            item->setText(0, app.value("displayName").toString());
            item->setText(1, app.value("appId").toString());
            item->setText(2, "Application");
            item->setText(3, app.value("signInAudience").toString());
            item->setText(4, app.value("createdDateTime").toString());
            item->setData(0, Qt::UserRole, app.value("id").toString());
            item->setData(0, Qt::UserRole + 1, "application");
            item->setData(0, Qt::UserRole + 2, app.value("appId").toString());

            // Check for credentials
            QJsonArray passwords = app.value("passwordCredentials").toArray();
            QJsonArray keys = app.value("keyCredentials").toArray();
            if (!passwords.isEmpty() || !keys.isEmpty()) {
                item->setForeground(0, QColor(255, 200, 100));  // Highlight apps with credentials
            }
        }

        logSuccess(QString("Found %1 App Registration(s)").arg(appRegistrations.size()));
    });
}

void SPNEnumWindow::onItemSelected() {
    auto items = resultsTree->selectedItems();
    if (items.isEmpty()) {
        getCredsBtn->setEnabled(false);
        getPermsBtn->setEnabled(false);
        return;
    }

    auto *item = items.first();
    currentObjectId = item->data(0, Qt::UserRole).toString();
    currentObjectType = item->data(0, Qt::UserRole + 1).toString();
    currentAppId = item->data(0, Qt::UserRole + 2).toString();

    if (!currentObjectId.isEmpty()) {
        getCredsBtn->setEnabled(currentObjectType == "application");
        getPermsBtn->setEnabled(true);

        // Show basic details
        QString details;
        details += QString("Display Name: %1\n").arg(item->text(0));
        details += QString("App ID: %1\n").arg(item->text(1));
        details += QString("Type: %1\n").arg(item->text(2));
        details += QString("Sign-In Audience: %1\n").arg(item->text(3));
        details += QString("Created: %1\n").arg(item->text(4));
        details += QString("\nObject ID: %1\n").arg(currentObjectId);
        detailsArea->setText(details);
    }
}

void SPNEnumWindow::getAppCredentials() {
    if (currentObjectId.isEmpty() || currentObjectType != "application") return;

    QString token = getToken();
    if (token.isEmpty()) return;

    setLoading(true);
    logInfo(QString("Getting credentials for app: %1").arg(currentObjectId));

    QString url = QString("https://graph.microsoft.com/v1.0/applications/%1?$select=passwordCredentials,keyCredentials").arg(currentObjectId);
    QNetworkReply *reply = net->get(createBearerRequest(url, token));
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

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("Error: %1").arg(NetworkHelper::parseApiError(reply)));
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject app = doc.object();

        QString details = detailsArea->toPlainText();
        details += "\n=== Credentials ===\n";

        QJsonArray passwords = app.value("passwordCredentials").toArray();
        if (!passwords.isEmpty()) {
            details += QString("\nPassword Credentials (%1):\n").arg(passwords.size());
            for (const QJsonValue &val : passwords) {
                QJsonObject pwd = val.toObject();
                details += QString("  - Key ID: %1\n").arg(pwd.value("keyId").toString());
                details += QString("    Display Name: %1\n").arg(pwd.value("displayName").toString());
                details += QString("    Start: %1\n").arg(pwd.value("startDateTime").toString());
                details += QString("    End: %1\n").arg(pwd.value("endDateTime").toString());
                details += QString("    Hint: %1\n\n").arg(pwd.value("hint").toString());
            }
        } else {
            details += "\nNo password credentials.\n";
        }

        QJsonArray keys = app.value("keyCredentials").toArray();
        if (!keys.isEmpty()) {
            details += QString("\nKey Credentials (%1):\n").arg(keys.size());
            for (const QJsonValue &val : keys) {
                QJsonObject key = val.toObject();
                details += QString("  - Key ID: %1\n").arg(key.value("keyId").toString());
                details += QString("    Type: %1\n").arg(key.value("type").toString());
                details += QString("    Usage: %1\n").arg(key.value("usage").toString());
                details += QString("    Start: %1\n").arg(key.value("startDateTime").toString());
                details += QString("    End: %1\n\n").arg(key.value("endDateTime").toString());
            }
        } else {
            details += "\nNo key credentials.\n";
        }

        detailsArea->setText(details);
        logSuccess("Credentials retrieved");
    });
}

void SPNEnumWindow::getPermissions() {
    if (currentObjectId.isEmpty()) return;

    QString token = getToken();
    if (token.isEmpty()) return;

    setLoading(true);
    logInfo(QString("Getting permissions for: %1").arg(currentObjectId));

    QString url;
    if (currentObjectType == "servicePrincipal") {
        url = QString("https://graph.microsoft.com/v1.0/servicePrincipals/%1/appRoleAssignments").arg(currentObjectId);
    } else {
        url = QString("https://graph.microsoft.com/v1.0/applications/%1?$select=requiredResourceAccess").arg(currentObjectId);
    }

    QNetworkReply *reply = net->get(createBearerRequest(url, token));
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

        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("Error: %1").arg(NetworkHelper::parseApiError(reply)));
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();

        QString details = detailsArea->toPlainText();
        details += "\n=== Permissions ===\n";

        if (currentObjectType == "servicePrincipal") {
            QJsonArray roles = obj.value("value").toArray();
            if (!roles.isEmpty()) {
                details += QString("\nApp Role Assignments (%1):\n").arg(roles.size());
                for (const QJsonValue &val : roles) {
                    QJsonObject role = val.toObject();
                    details += QString("  - Resource: %1\n").arg(role.value("resourceDisplayName").toString());
                    details += QString("    Role ID: %1\n").arg(role.value("appRoleId").toString());
                    details += QString("    Created: %1\n\n").arg(role.value("createdDateTime").toString());
                }
            } else {
                details += "\nNo app role assignments.\n";
            }
        } else {
            QJsonArray resources = obj.value("requiredResourceAccess").toArray();
            if (!resources.isEmpty()) {
                details += QString("\nRequired Resource Access (%1):\n").arg(resources.size());
                for (const QJsonValue &val : resources) {
                    QJsonObject res = val.toObject();
                    details += QString("  - Resource App ID: %1\n").arg(res.value("resourceAppId").toString());
                    QJsonArray accesses = res.value("resourceAccess").toArray();
                    for (const QJsonValue &a : accesses) {
                        QJsonObject acc = a.toObject();
                        details += QString("      %1: %2\n").arg(acc.value("type").toString(), acc.value("id").toString());
                    }
                    details += "\n";
                }
            } else {
                details += "\nNo required resource access configured.\n";
            }
        }

        detailsArea->setText(details);
        logSuccess("Permissions retrieved");
    });
}

void SPNEnumWindow::copySelectedItem() {
    QString text = detailsArea->toPlainText();
    if (!text.isEmpty()) {
        QApplication::clipboard()->setText(text);
        logSuccess("Copied to clipboard");
    }
}

void SPNEnumWindow::exportResults() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export Results",
        QDir::homePath() + "/spn_export.txt", "Text Files (*.txt);;All Files (*)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "Service Principal / App Registration Export\n";
    out << "============================================\n\n";

    QTreeWidgetItemIterator it(resultsTree);
    while (*it) {
        out << QString("Display Name: %1\n").arg((*it)->text(0));
        out << QString("App ID: %1\n").arg((*it)->text(1));
        out << QString("Type: %1\n").arg((*it)->text(2));
        out << QString("Sign-In Audience: %1\n").arg((*it)->text(3));
        out << QString("Object ID: %1\n\n").arg((*it)->data(0, Qt::UserRole).toString());
        ++it;
    }

    file.close();
    logSuccess(QString("Exported to %1").arg(filePath));
}
