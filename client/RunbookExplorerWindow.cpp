#include "RunbookExplorerWindow.h"
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

RunbookExplorerWindow::RunbookExplorerWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Azure Automation Runbook Explorer");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

RunbookExplorerWindow::~RunbookExplorerWindow() {
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

void RunbookExplorerWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token input
    auto *tokenGroup = new QGroupBox("Azure Management Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &RunbookExplorerWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &RunbookExplorerWindow::appendLog);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::autoFetchTokens);

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
    enumAccountsBtn = new QPushButton("Enumerate Automation Accounts", this);
    subscriptionCombo = new QComboBox(this);
    subscriptionCombo->setMinimumWidth(200);
    subscriptionCombo->setPlaceholderText("Subscription...");
    accountCombo = new QComboBox(this);
    accountCombo->setMinimumWidth(200);
    accountCombo->setPlaceholderText("Automation Account...");
    accountCombo->setEnabled(false);

    controlLayout1->addWidget(enumAccountsBtn);
    controlLayout1->addWidget(subscriptionCombo);
    controlLayout1->addWidget(accountCombo);
    controlLayout1->addStretch();
    mainLayout->addLayout(controlLayout1);

    // Controls row 2
    auto *controlLayout2 = new QHBoxLayout();
    listRunbooksBtn = new QPushButton("Runbooks", this);
    listRunbooksBtn->setEnabled(false);
    listVarsBtn = new QPushButton("Variables", this);
    listVarsBtn->setEnabled(false);
    listCredsBtn = new QPushButton("Credentials", this);
    listCredsBtn->setEnabled(false);
    listConnsBtn = new QPushButton("Connections", this);
    listConnsBtn->setEnabled(false);
    getContentBtn = new QPushButton("Get Runbook Content", this);
    getContentBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy", this);
    exportBtn = new QPushButton("Export", this);

    controlLayout2->addWidget(listRunbooksBtn);
    controlLayout2->addWidget(listVarsBtn);
    controlLayout2->addWidget(listCredsBtn);
    controlLayout2->addWidget(listConnsBtn);
    controlLayout2->addWidget(getContentBtn);
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
    resultsTree->setHeaderLabels({"Name", "Type", "State", "Description", "Last Modified"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setMinimumWidth(400);
    splitter->addWidget(resultsTree);

    // Content area
    contentArea = new QPlainTextEdit(this);
    contentArea->setReadOnly(true);
    contentArea->setPlaceholderText("Select a runbook and click 'Get Runbook Content' to view its script...");
    splitter->addWidget(contentArea);

    mainLayout->addWidget(splitter);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(120);
    mainLayout->addWidget(logOutput);

    // Connections
    connect(enumAccountsBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::enumerateAutomationAccounts);
    connect(accountCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RunbookExplorerWindow::onAccountSelected);
    connect(listRunbooksBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::listRunbooks);
    connect(listVarsBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::listVariables);
    connect(listCredsBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::listCredentials);
    connect(listConnsBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::listConnections);
    connect(getContentBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::getRunbookContent);
    connect(copyBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::exportResults);
    connect(cancelBtn, &QPushButton::clicked, this, &RunbookExplorerWindow::cancelRequests);

    resize(1200, 700);
}

QNetworkRequest RunbookExplorerWindow::bearerRequest(const QString &url, const QString &token) {
    return NetworkHelper::createBearerRequest(url, token);
}

void RunbookExplorerWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void RunbookExplorerWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    enumAccountsBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void RunbookExplorerWindow::enumerateAutomationAccounts() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    setLoading(true);
    appendLog("[*] Enumerating subscriptions...", "cyan");
    resultsTree->clear();
    accountCombo->clear();
    automationAccounts = QJsonArray();

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

        appendLog(QString("[+] Found %1 subscription(s), enumerating Automation Accounts...").arg(subscriptions.size()), "green");

        subscriptionCombo->clear();
        for (const QJsonValue &val : subscriptions) {
            QJsonObject sub = val.toObject();
            subscriptionCombo->addItem(sub.value("displayName").toString(), sub.value("subscriptionId").toString());
        }

        // Enumerate Automation Accounts across all subscriptions
        auto counter = std::make_shared<int>(subscriptions.size());

        for (const QJsonValue &val : subscriptions) {
            QString subId = val.toObject().value("subscriptionId").toString();
            QString accountUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Automation/automationAccounts?api-version=2022-08-08").arg(subId);

            QNetworkReply *accountReply = net->get(bearerRequest(accountUrl, token));
            if (!accountReply) {
                (*counter)--;
                if (*counter == 0) {
                    setLoading(false);
                    appendLog("[!] Failed to enumerate some subscriptions", "yellow");
                }
                return;
            }

            connect(accountReply, &QNetworkReply::finished, this, [this, accountReply, subId, counter]() {
                accountReply->deleteLater();
                (*counter)--;

                QString errorMsg;
                if (NetworkHelper::isReplySuccess(accountReply, &errorMsg)) {
                    QJsonDocument doc = QJsonDocument::fromJson(accountReply->readAll());
                    QJsonArray accounts = doc.object().value("value").toArray();

                    for (const QJsonValue &a : accounts) {
                        QJsonObject account = a.toObject();
                        account.insert("subscriptionId", subId);
                        automationAccounts.append(account);

                        QString name = account.value("name").toString();
                        QString id = account.value("id").toString();
                        QString location = account.value("location").toString();

                        accountCombo->addItem(name, id);

                        auto *item = new QTreeWidgetItem(resultsTree);
                        item->setText(0, name);
                        item->setText(1, "Automation Account");
                        item->setText(2, account.value("properties").toObject().value("state").toString());
                        item->setText(3, location);
                        item->setData(0, Qt::UserRole, id);
                    }
                }

                if (*counter == 0) {
                    setLoading(false);
                    if (automationAccounts.isEmpty()) {
                        appendLog("[!] No Automation Accounts found.", "yellow");
                    } else {
                        appendLog(QString("[+] Found %1 Automation Account(s)").arg(automationAccounts.size()), "green");
                        accountCombo->setEnabled(true);
                        if (accountCombo->count() > 0) {
                            onAccountSelected(0);
                        }
                    }
                }
            });
        }
    });
}

void RunbookExplorerWindow::onAccountSelected(int index) {
    if (index >= 0 && index < accountCombo->count()) {
        currentAccountId = accountCombo->itemData(index).toString();
        currentAccountName = accountCombo->itemText(index);

        // Parse resource group from ID
        QStringList idParts = currentAccountId.split('/');
        for (int i = 0; i < idParts.size(); i++) {
            if (idParts[i].toLower() == "resourcegroups" && i + 1 < idParts.size()) {
                currentResourceGroup = idParts[i + 1];
                break;
            }
            if (idParts[i].toLower() == "subscriptions" && i + 1 < idParts.size()) {
                currentSubscriptionId = idParts[i + 1];
            }
        }

        listRunbooksBtn->setEnabled(true);
        listVarsBtn->setEnabled(true);
        listCredsBtn->setEnabled(true);
        listConnsBtn->setEnabled(true);
        appendLog(QString("[*] Selected account: %1").arg(currentAccountName), "cyan");
    }
}

void RunbookExplorerWindow::listRunbooks() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAccountId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing runbooks...", "cyan");

    QString url = QString("https://management.azure.com%1/runbooks?api-version=2022-08-08").arg(currentAccountId);
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
        QJsonArray runbooks = doc.object().value("value").toArray();

        if (runbooks.isEmpty()) {
            appendLog("[!] No runbooks found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 runbook(s)").arg(runbooks.size()), "green");

        auto *group = new QTreeWidgetItem(resultsTree);
        group->setText(0, QString("Runbooks (%1)").arg(runbooks.size()));
        group->setText(1, "Collection");

        for (const QJsonValue &val : runbooks) {
            QJsonObject rb = val.toObject();
            QJsonObject props = rb.value("properties").toObject();

            auto *item = new QTreeWidgetItem(group);
            item->setText(0, rb.value("name").toString());
            item->setText(1, props.value("runbookType").toString());
            item->setText(2, props.value("state").toString());
            item->setText(3, props.value("description").toString());
            item->setText(4, props.value("lastModifiedTime").toString());
            item->setData(0, Qt::UserRole, rb.value("name").toString());
            item->setData(0, Qt::UserRole + 1, "runbook");
        }

        group->setExpanded(true);
        getContentBtn->setEnabled(true);
    });
}

void RunbookExplorerWindow::listVariables() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAccountId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing variables...", "cyan");

    QString url = QString("https://management.azure.com%1/variables?api-version=2022-08-08").arg(currentAccountId);
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
        QJsonArray vars = doc.object().value("value").toArray();

        if (vars.isEmpty()) {
            appendLog("[!] No variables found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 variable(s)").arg(vars.size()), "green");

        auto *group = new QTreeWidgetItem(resultsTree);
        group->setText(0, QString("Variables (%1)").arg(vars.size()));
        group->setText(1, "Collection");

        for (const QJsonValue &val : vars) {
            QJsonObject v = val.toObject();
            QJsonObject props = v.value("properties").toObject();

            auto *item = new QTreeWidgetItem(group);
            item->setText(0, v.value("name").toString());
            item->setText(1, "Variable");
            item->setText(2, props.value("isEncrypted").toBool() ? "Encrypted" : "Plain");
            item->setText(3, props.value("value").toString());
        }

        group->setExpanded(true);
    });
}

void RunbookExplorerWindow::listCredentials() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAccountId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing credentials...", "cyan");

    QString url = QString("https://management.azure.com%1/credentials?api-version=2022-08-08").arg(currentAccountId);
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
        QJsonArray creds = doc.object().value("value").toArray();

        if (creds.isEmpty()) {
            appendLog("[!] No credentials found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 credential(s)").arg(creds.size()), "green");

        auto *group = new QTreeWidgetItem(resultsTree);
        group->setText(0, QString("Credentials (%1)").arg(creds.size()));
        group->setText(1, "Collection");

        for (const QJsonValue &val : creds) {
            QJsonObject c = val.toObject();
            QJsonObject props = c.value("properties").toObject();

            auto *item = new QTreeWidgetItem(group);
            item->setText(0, c.value("name").toString());
            item->setText(1, "Credential");
            item->setText(2, "Stored");
            item->setText(3, props.value("userName").toString());
            item->setText(4, props.value("lastModifiedTime").toString());
        }

        group->setExpanded(true);
    });
}

void RunbookExplorerWindow::listConnections() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentAccountId.isEmpty()) return;

    setLoading(true);
    appendLog("[*] Listing connections...", "cyan");

    QString url = QString("https://management.azure.com%1/connections?api-version=2022-08-08").arg(currentAccountId);
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
        QJsonArray conns = doc.object().value("value").toArray();

        if (conns.isEmpty()) {
            appendLog("[!] No connections found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 connection(s)").arg(conns.size()), "green");

        auto *group = new QTreeWidgetItem(resultsTree);
        group->setText(0, QString("Connections (%1)").arg(conns.size()));
        group->setText(1, "Collection");

        for (const QJsonValue &val : conns) {
            QJsonObject conn = val.toObject();
            QJsonObject props = conn.value("properties").toObject();

            auto *item = new QTreeWidgetItem(group);
            item->setText(0, conn.value("name").toString());
            item->setText(1, "Connection");
            item->setText(2, props.value("connectionType").toObject().value("name").toString());
            item->setText(4, props.value("lastModifiedTime").toString());
        }

        group->setExpanded(true);
    });
}

void RunbookExplorerWindow::getRunbookContent() {
    auto *item = resultsTree->currentItem();
    if (!item || item->data(0, Qt::UserRole + 1).toString() != "runbook") {
        QMessageBox::warning(this, "No Selection", "Please select a runbook to view its content.");
        return;
    }

    QString token = tokenInput->text().trimmed();
    QString runbookName = item->data(0, Qt::UserRole).toString();

    if (token.isEmpty() || runbookName.isEmpty()) return;

    setLoading(true);
    appendLog(QString("[*] Retrieving runbook content: %1").arg(runbookName), "cyan");

    QString url = QString("https://management.azure.com%1/runbooks/%2/content?api-version=2022-08-08")
                      .arg(currentAccountId, runbookName);
    QNetworkReply *reply = net->get(bearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        setLoading(false);
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply, runbookName]() {
        reply->deleteLater();
        setLoading(false);

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            QString error = NetworkHelper::parseApiError(reply);
            appendLog(QString("[-] Error: %1").arg(error), "red");
            contentArea->setPlainText(QString("Error retrieving content: %1").arg(error));
            return;
        }

        QString content = QString::fromUtf8(reply->readAll());
        contentArea->setPlainText(content);
        appendLog(QString("[+] Retrieved %1 bytes of content").arg(content.size()), "green");
    });
}

void RunbookExplorerWindow::copySelectedItem() {
    QString content = contentArea->toPlainText();
    if (!content.isEmpty()) {
        QApplication::clipboard()->setText(content);
        appendLog("[+] Content copied to clipboard", "green");
        return;
    }

    auto *item = resultsTree->currentItem();
    if (item) {
        QString text = QString("Name: %1\nType: %2\nState: %3\nDescription: %4")
                           .arg(item->text(0), item->text(1), item->text(2), item->text(3));
        QApplication::clipboard()->setText(text);
        appendLog("[+] Copied to clipboard", "green");
    }
}

void RunbookExplorerWindow::exportResults() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export Results",
        QDir::homePath() + "/runbook_export.txt", "Text Files (*.txt);;All Files (*)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "Azure Automation Runbook Export\n";
    out << "================================\n\n";

    QTreeWidgetItemIterator it(resultsTree);
    while (*it) {
        out << QString("Name: %1 | Type: %2 | State: %3\n")
               .arg((*it)->text(0), (*it)->text(1), (*it)->text(2));
        if (!(*it)->text(3).isEmpty()) {
            out << QString("  Description: %1\n").arg((*it)->text(3));
        }
        ++it;
    }

    if (!contentArea->toPlainText().isEmpty()) {
        out << "\n\n=== Current Runbook Content ===\n";
        out << contentArea->toPlainText();
    }

    file.close();
    appendLog(QString("[+] Exported to %1").arg(filePath), "green");
}

void RunbookExplorerWindow::onUserChanged(const QString &upn) {
    tokenInput->clear();
    updateTokenStatus();
    appendLog(QString("[*] Switched to user: %1").arg(upn), "cyan");
}

void RunbookExplorerWindow::autoFetchTokens() {
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

void RunbookExplorerWindow::updateTokenStatus() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

void RunbookExplorerWindow::cancelRequests() {
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
