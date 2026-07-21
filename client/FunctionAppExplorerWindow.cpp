#include "FunctionAppExplorerWindow.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "NetworkHelper.h"

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

FunctionAppExplorerWindow::FunctionAppExplorerWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Azure Function App Explorer");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

FunctionAppExplorerWindow::~FunctionAppExplorerWindow() {
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

void FunctionAppExplorerWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token input
    auto *tokenGroup = new QGroupBox("Azure Management Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &FunctionAppExplorerWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &FunctionAppExplorerWindow::appendLog);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::autoFetchTokens);

    auto *tokenRow = new QHBoxLayout();
    tokenInput = new QLineEdit(this);
    tokenInput->setPlaceholderText("Paste access token for https://management.azure.com");
    tokenInput->setEchoMode(QLineEdit::Password);
    tokenRow->addWidget(tokenInput);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    tokenRow->addWidget(tokenStatus);
    tokenLayout->addLayout(tokenRow);

    mainLayout->addWidget(tokenGroup);

    // Controls row 1
    auto *controlLayout1 = new QHBoxLayout();
    enumAppsBtn = new QPushButton("Enumerate Function Apps", this);
    subscriptionCombo = new QComboBox(this);
    subscriptionCombo->setMinimumWidth(200);
    subscriptionCombo->setPlaceholderText("Subscription...");
    appCombo = new QComboBox(this);
    appCombo->setMinimumWidth(200);
    appCombo->setPlaceholderText("Function App...");
    appCombo->setEnabled(false);

    controlLayout1->addWidget(enumAppsBtn);
    controlLayout1->addWidget(subscriptionCombo);
    controlLayout1->addWidget(appCombo);
    controlLayout1->addStretch();
    mainLayout->addLayout(controlLayout1);

    // Controls row 2
    auto *controlLayout2 = new QHBoxLayout();
    listFuncsBtn = new QPushButton("List Functions", this);
    listFuncsBtn->setEnabled(false);
    getSettingsBtn = new QPushButton("Get App Settings", this);
    getSettingsBtn->setEnabled(false);
    getConnStrBtn = new QPushButton("Get Connection Strings", this);
    getConnStrBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy", this);
    exportBtn = new QPushButton("Export", this);

    controlLayout2->addWidget(listFuncsBtn);
    controlLayout2->addWidget(getSettingsBtn);
    controlLayout2->addWidget(getConnStrBtn);
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

    // Main splitter
    auto *splitter = new QSplitter(Qt::Horizontal, this);

    // Results tree
    resultsTree = new QTreeWidget(this);
    resultsTree->setHeaderLabels({"Name", "Type", "Runtime", "State", "Location"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setMinimumWidth(400);
    splitter->addWidget(resultsTree);

    // Content area
    contentArea = new QPlainTextEdit(this);
    contentArea->setReadOnly(true);
    contentArea->setPlaceholderText("Select an app and click a button to view details...");
    splitter->addWidget(contentArea);

    mainLayout->addWidget(splitter);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(120);
    mainLayout->addWidget(logOutput);

    // Connections
    connect(enumAppsBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::enumerateFunctionApps);
    connect(appCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &FunctionAppExplorerWindow::onAppSelected);
    connect(listFuncsBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::listFunctions);
    connect(getSettingsBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::getAppSettings);
    connect(getConnStrBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::getConnectionStrings);
    connect(copyBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::exportResults);
    connect(cancelBtn, &QPushButton::clicked, this, &FunctionAppExplorerWindow::cancelRequests);

    resize(1100, 700);
}

QNetworkRequest FunctionAppExplorerWindow::bearerRequest(const QString &url, const QString &token) {
    return NetworkHelper::createBearerRequest(url, token);
}

void FunctionAppExplorerWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void FunctionAppExplorerWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    enumAppsBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void FunctionAppExplorerWindow::enumerateFunctionApps() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    setLoading(true);
    appendLog("[*] Enumerating subscriptions...", "cyan");
    resultsTree->clear();
    appCombo->clear();
    functionApps = QJsonArray();

    // First get subscriptions
    QString url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    QNetworkReply *reply = net->get(bearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, token]() {
        activeReplies.removeAll(reply);
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

        appendLog(QString("[+] Found %1 subscription(s), enumerating Function Apps...").arg(subscriptions.size()), "green");

        subscriptionCombo->clear();
        for (const QJsonValue &val : subscriptions) {
            QJsonObject sub = val.toObject();
            subscriptionCombo->addItem(sub.value("displayName").toString(), sub.value("subscriptionId").toString());
        }

        // Enumerate Function Apps across all subscriptions
        auto counter = std::make_shared<int>(subscriptions.size());

        for (const QJsonValue &val : subscriptions) {
            QString subId = val.toObject().value("subscriptionId").toString();
            // Filter for Function Apps (kind contains 'functionapp')
            QString appUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Web/sites?api-version=2022-03-01").arg(subId);

            QNetworkReply *appReply = net->get(bearerRequest(appUrl, token));

            if (!appReply) {
                (*counter)--;
                if (*counter == 0) {
                    setLoading(false);
                    appendLog("[!] Some requests failed to create", "yellow");
                }
                return;
            }
            activeReplies.append(appReply);

            connect(appReply, &QNetworkReply::finished, this, [this, appReply, subId, counter]() {
                activeReplies.removeAll(appReply);
                appReply->deleteLater();
                (*counter)--;

                QString errorMsg;
                if (NetworkHelper::isReplySuccess(appReply, &errorMsg)) {
                    QJsonDocument doc = QJsonDocument::fromJson(appReply->readAll());
                    QJsonArray sites = doc.object().value("value").toArray();

                    for (const QJsonValue &s : sites) {
                        QJsonObject site = s.toObject();
                        QString kind = site.value("kind").toString().toLower();

                        // Filter for function apps only
                        if (kind.contains("functionapp")) {
                            site.insert("subscriptionId", subId);
                            functionApps.append(site);

                            QString name = site.value("name").toString();
                            QString id = site.value("id").toString();
                            QString location = site.value("location").toString();
                            QJsonObject props = site.value("properties").toObject();
                            QString state = props.value("state").toString();

                            appCombo->addItem(name, id);

                            auto *item = new QTreeWidgetItem(resultsTree);
                            item->setText(0, name);
                            item->setText(1, kind);
                            item->setText(2, props.value("runtimeVersion").toString());
                            item->setText(3, state);
                            item->setText(4, location);
                            item->setData(0, Qt::UserRole, id);
                        }
                    }
                }

                if (*counter == 0) {
                    setLoading(false);
                    if (functionApps.isEmpty()) {
                        appendLog("[!] No Function Apps found.", "yellow");
                    } else {
                        appendLog(QString("[+] Found %1 Function App(s)").arg(functionApps.size()), "green");
                        appCombo->setEnabled(true);
                        if (appCombo->count() > 0) {
                            onAppSelected(0);
                        }
                    }
                }
            });
        }
    });
}

void FunctionAppExplorerWindow::onAppSelected(int index) {
    if (index >= 0 && index < appCombo->count()) {
        currentAppId = appCombo->itemData(index).toString();
        currentAppName = appCombo->itemText(index);

        // Parse resource group from ID
        QStringList idParts = currentAppId.split('/');
        for (int i = 0; i < idParts.size(); i++) {
            if (idParts[i].toLower() == "resourcegroups" && i + 1 < idParts.size()) {
                currentResourceGroup = idParts[i + 1];
            }
            if (idParts[i].toLower() == "subscriptions" && i + 1 < idParts.size()) {
                currentSubscriptionId = idParts[i + 1];
            }
        }

        listFuncsBtn->setEnabled(true);
        getSettingsBtn->setEnabled(true);
        getConnStrBtn->setEnabled(true);
        appendLog(QString("[*] Selected app: %1").arg(currentAppName), "cyan");
    }
}

void FunctionAppExplorerWindow::listFunctions() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAppId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing functions...", "cyan");

    QString url = QString("https://management.azure.com%1/functions?api-version=2022-03-01").arg(currentAppId);
    QNetworkReply *reply = net->get(bearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray funcs = doc.object().value("value").toArray();

        if (funcs.isEmpty()) {
            appendLog("[!] No functions found.", "yellow");
            contentArea->setPlainText("No functions found in this Function App.");
            return;
        }

        appendLog(QString("[+] Found %1 function(s)").arg(funcs.size()), "green");

        QString content = QString("Functions in %1:\n").arg(currentAppName);
        content += QString("=").repeated(40) + "\n\n";

        auto *group = new QTreeWidgetItem(resultsTree);
        group->setText(0, QString("Functions (%1)").arg(funcs.size()));
        group->setText(1, "Collection");

        for (const QJsonValue &val : funcs) {
            QJsonObject func = val.toObject();
            QJsonObject props = func.value("properties").toObject();
            QJsonObject config = props.value("config").toObject();

            QString name = func.value("name").toString();
            QString invokeUrl = props.value("invoke_url_template").toString();

            auto *item = new QTreeWidgetItem(group);
            item->setText(0, name);
            item->setText(1, "Function");
            item->setText(2, config.value("language").toString());

            content += QString("Function: %1\n").arg(name);
            content += QString("  Language: %1\n").arg(config.value("language").toString());
            content += QString("  Invoke URL: %1\n").arg(invokeUrl);

            // List bindings
            QJsonArray bindings = config.value("bindings").toArray();
            if (!bindings.isEmpty()) {
                content += "  Bindings:\n";
                for (const QJsonValue &b : bindings) {
                    QJsonObject binding = b.toObject();
                    content += QString("    - %1 (%2)\n").arg(binding.value("name").toString(), binding.value("type").toString());
                }
            }
            content += "\n";
        }

        group->setExpanded(true);
        contentArea->setPlainText(content);
    });
}

void FunctionAppExplorerWindow::getAppSettings() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAppId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Getting app settings...", "cyan");

    QString url = QString("https://management.azure.com%1/config/appsettings/list?api-version=2022-03-01").arg(currentAppId);

    QNetworkRequest req = bearerRequest(url, token);
    QNetworkReply *reply = net->post(req, QByteArray());

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject props = doc.object().value("properties").toObject();

        if (props.isEmpty()) {
            appendLog("[!] No app settings found.", "yellow");
            contentArea->setPlainText("No app settings found.");
            return;
        }

        appendLog(QString("[+] Found %1 app setting(s)").arg(props.keys().size()), "green");

        QString content = QString("App Settings for %1:\n").arg(currentAppName);
        content += QString("=").repeated(40) + "\n\n";

        for (const QString &key : props.keys()) {
            QString value = props.value(key).toString();
            content += QString("%1 = %2\n").arg(key, value);

            // Highlight potentially sensitive settings
            if (key.toLower().contains("password") ||
                key.toLower().contains("secret") ||
                key.toLower().contains("key") ||
                key.toLower().contains("connection")) {
                content += "  ^^^ POTENTIALLY SENSITIVE ^^^\n";
            }
        }

        contentArea->setPlainText(content);
    });
}

void FunctionAppExplorerWindow::getConnectionStrings() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAppId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Getting connection strings...", "cyan");

    QString url = QString("https://management.azure.com%1/config/connectionstrings/list?api-version=2022-03-01").arg(currentAppId);

    QNetworkRequest req = bearerRequest(url, token);
    QNetworkReply *reply = net->post(req, QByteArray());

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject props = doc.object().value("properties").toObject();

        if (props.isEmpty()) {
            appendLog("[!] No connection strings found.", "yellow");
            contentArea->setPlainText("No connection strings found.");
            return;
        }

        appendLog(QString("[+] Found %1 connection string(s)").arg(props.keys().size()), "green");

        QString content = QString("Connection Strings for %1:\n").arg(currentAppName);
        content += QString("=").repeated(40) + "\n\n";
        content += "!!! SENSITIVE DATA - HANDLE WITH CARE !!!\n\n";

        for (const QString &key : props.keys()) {
            QJsonObject connObj = props.value(key).toObject();
            QString value = connObj.value("value").toString();
            QString type = connObj.value("type").toString();

            content += QString("Name: %1\n").arg(key);
            content += QString("Type: %1\n").arg(type);
            content += QString("Value: %1\n\n").arg(value);
        }

        contentArea->setPlainText(content);
    });
}

void FunctionAppExplorerWindow::copySelectedItem() {
    QString content = contentArea->toPlainText();
    if (!content.isEmpty()) {
        QApplication::clipboard()->setText(content);
        appendLog("[+] Content copied to clipboard", "green");
    }
}

void FunctionAppExplorerWindow::exportResults() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export Results",
        QDir::homePath() + "/functionapp_export.txt", "Text Files (*.txt);;All Files (*)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "Azure Function App Export\n";
    out << "=========================\n\n";

    QTreeWidgetItemIterator it(resultsTree);
    while (*it) {
        out << QString("Name: %1 | Type: %2 | State: %3 | Location: %4\n")
               .arg((*it)->text(0), (*it)->text(1), (*it)->text(3), (*it)->text(4));
        ++it;
    }

    if (!contentArea->toPlainText().isEmpty()) {
        out << "\n\n=== Details ===\n";
        out << contentArea->toPlainText();
    }

    file.close();
    appendLog(QString("[+] Exported to %1").arg(filePath), "green");
}

void FunctionAppExplorerWindow::onUserChanged(const QString &upn) {
    tokenInput->clear();
    updateTokenStatus();
    appendLog(QString("[*] Switched to user: %1").arg(upn), "cyan");
}

void FunctionAppExplorerWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        appendLog("[-] Please select a user first", "red");
        return;
    }

    appendLog("[*] Fetching management token for selected user...", "cyan");
    userSelector->fetchToken("https://management.azure.com", [this](bool success, const QString &token, const QString &error) {
        if (success) {
            tokenInput->setText(token);
            updateTokenStatus();
            appendLog("[+] Management token acquired", "green");
        } else {
            appendLog(QString("[-] Failed to fetch token: %1").arg(error), "red");
        }
    });
}

void FunctionAppExplorerWindow::updateTokenStatus() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

void FunctionAppExplorerWindow::cancelRequests() {
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
