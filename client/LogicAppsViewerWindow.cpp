#include "LogicAppsViewerWindow.h"
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

LogicAppsViewerWindow::LogicAppsViewerWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Azure Logic Apps Viewer");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

LogicAppsViewerWindow::~LogicAppsViewerWindow() {
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

void LogicAppsViewerWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token input
    auto *tokenGroup = new QGroupBox("Azure Management Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &LogicAppsViewerWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &LogicAppsViewerWindow::appendLog);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::autoFetchTokens);

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
    enumAppsBtn = new QPushButton("Enumerate Logic Apps", this);
    subscriptionCombo = new QComboBox(this);
    subscriptionCombo->setMinimumWidth(200);
    subscriptionCombo->setPlaceholderText("Subscription...");
    appCombo = new QComboBox(this);
    appCombo->setMinimumWidth(200);
    appCombo->setPlaceholderText("Logic App...");
    appCombo->setEnabled(false);

    controlLayout1->addWidget(enumAppsBtn);
    controlLayout1->addWidget(subscriptionCombo);
    controlLayout1->addWidget(appCombo);
    controlLayout1->addStretch();
    mainLayout->addLayout(controlLayout1);

    // Controls row 2
    auto *controlLayout2 = new QHBoxLayout();
    getDefBtn = new QPushButton("Get Workflow Definition", this);
    getDefBtn->setEnabled(false);
    triggersBtn = new QPushButton("List Triggers", this);
    triggersBtn->setEnabled(false);
    historyBtn = new QPushButton("Run History", this);
    historyBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy", this);
    exportBtn = new QPushButton("Export", this);

    controlLayout2->addWidget(getDefBtn);
    controlLayout2->addWidget(triggersBtn);
    controlLayout2->addWidget(historyBtn);
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
    resultsTree->setHeaderLabels({"Name", "Type", "State", "SKU", "Location"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setMinimumWidth(400);
    splitter->addWidget(resultsTree);

    // Content area (for workflow JSON)
    contentArea = new QPlainTextEdit(this);
    contentArea->setReadOnly(true);
    contentArea->setPlaceholderText("Select an app and click 'Get Workflow Definition' to view...");
    splitter->addWidget(contentArea);

    mainLayout->addWidget(splitter);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(120);
    mainLayout->addWidget(logOutput);

    // Connections
    connect(enumAppsBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::enumerateLogicApps);
    connect(appCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LogicAppsViewerWindow::onAppSelected);
    connect(getDefBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::getWorkflowDefinition);
    connect(triggersBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::listTriggers);
    connect(historyBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::listRunHistory);
    connect(copyBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::exportResults);
    connect(cancelBtn, &QPushButton::clicked, this, &LogicAppsViewerWindow::cancelRequests);

    resize(1200, 700);
}

QNetworkRequest LogicAppsViewerWindow::bearerRequest(const QString &url, const QString &token) {
    return NetworkHelper::createBearerRequest(url, token);
}

void LogicAppsViewerWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void LogicAppsViewerWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    enumAppsBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void LogicAppsViewerWindow::enumerateLogicApps() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    setLoading(true);
    appendLog("[*] Enumerating subscriptions...", "cyan");
    resultsTree->clear();
    appCombo->clear();
    logicApps = QJsonArray();

    // First get subscriptions
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

        appendLog(QString("[+] Found %1 subscription(s), enumerating Logic Apps...").arg(subscriptions.size()), "green");

        subscriptionCombo->clear();
        for (const QJsonValue &val : subscriptions) {
            QJsonObject sub = val.toObject();
            subscriptionCombo->addItem(sub.value("displayName").toString(), sub.value("subscriptionId").toString());
        }

        // Enumerate Logic Apps across all subscriptions
        auto counter = std::make_shared<int>(subscriptions.size());

        for (const QJsonValue &val : subscriptions) {
            QString subId = val.toObject().value("subscriptionId").toString();
            QString appUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Logic/workflows?api-version=2019-05-01").arg(subId);

            QNetworkReply *appReply = net->get(bearerRequest(appUrl, token));
            if (!appReply) {
                (*counter)--;
                return;
            }

            connect(appReply, &QNetworkReply::finished, this, [this, appReply, subId, counter]() {
                appReply->deleteLater();
                (*counter)--;

                if (NetworkHelper::isReplySuccess(appReply)) {
                    QJsonDocument doc = QJsonDocument::fromJson(appReply->readAll());
                    QJsonArray apps = doc.object().value("value").toArray();

                    for (const QJsonValue &a : apps) {
                        QJsonObject app = a.toObject();
                        app.insert("subscriptionId", subId);
                        logicApps.append(app);

                        QString name = app.value("name").toString();
                        QString id = app.value("id").toString();
                        QString location = app.value("location").toString();
                        QJsonObject props = app.value("properties").toObject();
                        QString state = props.value("state").toString();
                        QString sku = app.value("sku").toObject().value("name").toString();

                        appCombo->addItem(name, id);

                        auto *item = new QTreeWidgetItem(resultsTree);
                        item->setText(0, name);
                        item->setText(1, "Logic App");
                        item->setText(2, state);
                        item->setText(3, sku.isEmpty() ? "Consumption" : sku);
                        item->setText(4, location);
                        item->setData(0, Qt::UserRole, id);

                        // Color code by state
                        if (state == "Enabled") {
                            item->setForeground(2, QColor(100, 200, 100));
                        } else {
                            item->setForeground(2, QColor(200, 100, 100));
                        }
                    }
                }

                if (*counter == 0) {
                    setLoading(false);
                    if (logicApps.isEmpty()) {
                        appendLog("[!] No Logic Apps found.", "yellow");
                    } else {
                        appendLog(QString("[+] Found %1 Logic App(s)").arg(logicApps.size()), "green");
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

void LogicAppsViewerWindow::onAppSelected(int index) {
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

        getDefBtn->setEnabled(true);
        triggersBtn->setEnabled(true);
        historyBtn->setEnabled(true);
        appendLog(QString("[*] Selected app: %1").arg(currentAppName), "cyan");
    }
}

void LogicAppsViewerWindow::getWorkflowDefinition() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAppId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Getting workflow definition...", "cyan");

    QString url = QString("https://management.azure.com%1?api-version=2019-05-01").arg(currentAppId);
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
        QJsonObject app = doc.object();
        QJsonObject props = app.value("properties").toObject();
        QJsonObject definition = props.value("definition").toObject();
        QJsonObject parameters = props.value("parameters").toObject();

        // Format the definition nicely
        QJsonDocument defDoc(definition);
        QString defJson = QString::fromUtf8(defDoc.toJson(QJsonDocument::Indented));

        QString content = QString("=== Workflow Definition for %1 ===\n\n").arg(currentAppName);

        // Check for hardcoded secrets in parameters
        if (!parameters.isEmpty()) {
            content += "!!! PARAMETERS (may contain secrets) !!!\n";
            QJsonDocument paramDoc(parameters);
            content += QString::fromUtf8(paramDoc.toJson(QJsonDocument::Indented));
            content += "\n\n";
        }

        content += "=== Definition ===\n";
        content += defJson;

        // Scan for potential secrets
        if (defJson.contains("password", Qt::CaseInsensitive) ||
            defJson.contains("secret", Qt::CaseInsensitive) ||
            defJson.contains("apikey", Qt::CaseInsensitive) ||
            defJson.contains("connectionString", Qt::CaseInsensitive)) {
            appendLog("[!] Potential secrets detected in workflow definition!", "yellow");
        }

        contentArea->setPlainText(content);
        appendLog("[+] Workflow definition retrieved", "green");
    });
}

void LogicAppsViewerWindow::listTriggers() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAppId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing triggers...", "cyan");

    QString url = QString("https://management.azure.com%1/triggers?api-version=2019-05-01").arg(currentAppId);
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
        QJsonArray triggers = doc.object().value("value").toArray();

        if (triggers.isEmpty()) {
            appendLog("[!] No triggers found.", "yellow");
            contentArea->setPlainText("No triggers found.");
            return;
        }

        appendLog(QString("[+] Found %1 trigger(s)").arg(triggers.size()), "green");

        QString content = QString("Triggers for %1:\n").arg(currentAppName);
        content += QString("=").repeated(40) + "\n\n";

        auto *group = new QTreeWidgetItem(resultsTree);
        group->setText(0, QString("Triggers (%1)").arg(triggers.size()));
        group->setText(1, "Collection");

        for (const QJsonValue &val : triggers) {
            QJsonObject trigger = val.toObject();
            QJsonObject props = trigger.value("properties").toObject();

            QString name = trigger.value("name").toString();
            QString state = props.value("state").toString();
            QString lastFired = props.value("lastFireTime").toString();

            auto *item = new QTreeWidgetItem(group);
            item->setText(0, name);
            item->setText(1, "Trigger");
            item->setText(2, state);

            content += QString("Trigger: %1\n").arg(name);
            content += QString("  State: %1\n").arg(state);
            content += QString("  Last Fired: %1\n").arg(lastFired.isEmpty() ? "Never" : lastFired);

            // Check for callback URL (potential security issue)
            QString callbackUrl = props.value("callbackUrl").toString();
            if (!callbackUrl.isEmpty()) {
                content += QString("  Callback URL: %1\n").arg(callbackUrl);
                content += "  ^^^ This URL can trigger the workflow! ^^^\n";
            }
            content += "\n";
        }

        group->setExpanded(true);
        contentArea->setPlainText(content);
    });
}

void LogicAppsViewerWindow::listRunHistory() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAppId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Getting run history...", "cyan");

    QString url = QString("https://management.azure.com%1/runs?api-version=2019-05-01&$top=20").arg(currentAppId);
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
        QJsonArray runs = doc.object().value("value").toArray();

        if (runs.isEmpty()) {
            appendLog("[!] No run history found.", "yellow");
            contentArea->setPlainText("No run history found.");
            return;
        }

        appendLog(QString("[+] Found %1 run(s)").arg(runs.size()), "green");

        QString content = QString("Run History for %1 (last 20):\n").arg(currentAppName);
        content += QString("=").repeated(40) + "\n\n";

        for (const QJsonValue &val : runs) {
            QJsonObject run = val.toObject();
            QJsonObject props = run.value("properties").toObject();

            QString name = run.value("name").toString();
            QString status = props.value("status").toString();
            QString startTime = props.value("startTime").toString();
            QString endTime = props.value("endTime").toString();

            content += QString("Run: %1\n").arg(name);
            content += QString("  Status: %1\n").arg(status);
            content += QString("  Start: %1\n").arg(startTime);
            content += QString("  End: %1\n").arg(endTime);

            // Show trigger info
            QJsonObject trigger = props.value("trigger").toObject();
            if (!trigger.isEmpty()) {
                content += QString("  Trigger: %1\n").arg(trigger.value("name").toString());
            }
            content += "\n";
        }

        contentArea->setPlainText(content);
    });
}

void LogicAppsViewerWindow::copySelectedItem() {
    QString content = contentArea->toPlainText();
    if (!content.isEmpty()) {
        QApplication::clipboard()->setText(content);
        appendLog("[+] Content copied to clipboard", "green");
    }
}

void LogicAppsViewerWindow::exportResults() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export Results",
        QDir::homePath() + "/logicapp_export.json", "JSON Files (*.json);;Text Files (*.txt);;All Files (*)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << contentArea->toPlainText();

    file.close();
    appendLog(QString("[+] Exported to %1").arg(filePath), "green");
}

void LogicAppsViewerWindow::onUserChanged(const QString &upn) {
    tokenInput->clear();
    updateTokenStatus();
    appendLog(QString("[*] Switched to user: %1").arg(upn), "cyan");
}

void LogicAppsViewerWindow::autoFetchTokens() {
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

void LogicAppsViewerWindow::updateTokenStatus() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

void LogicAppsViewerWindow::cancelRequests() {
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
