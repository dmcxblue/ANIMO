#include "AzureEnumWindow.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "NetworkHelper.h"

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

AzureEnumWindow::AzureEnumWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Subscriptions and Resources");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

AzureEnumWindow::~AzureEnumWindow() {
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

void AzureEnumWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token input group
    auto *tokenGroup = new QGroupBox("Azure Management Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    // User selector
    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &AzureEnumWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &AzureEnumWindow::appendLog);

    // Auto-fetch row
    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &AzureEnumWindow::autoFetchTokens);

    // Token input row
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

    // Controls
    auto *controlLayout = new QHBoxLayout();
    enumSubsBtn = new QPushButton("Enumerate Subscriptions", this);
    subscriptionCombo = new QComboBox(this);
    subscriptionCombo->setMinimumWidth(300);
    subscriptionCombo->setEnabled(false);
    enumResourcesBtn = new QPushButton("Enumerate Resources", this);
    enumResourcesBtn->setEnabled(false);
    enumManagedIdBtn = new QPushButton("Find Managed Identities", this);
    enumManagedIdBtn->setEnabled(false);
    enumManagedIdBtn->setToolTip("Find VMs and other resources with managed identities (potential for token theft)");
    cancelBtn = new QPushButton("Cancel", this);
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy Selected", this);

    controlLayout->addWidget(enumSubsBtn);
    controlLayout->addWidget(subscriptionCombo);
    controlLayout->addWidget(enumResourcesBtn);
    controlLayout->addWidget(enumManagedIdBtn);
    controlLayout->addWidget(cancelBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(copyBtn);
    mainLayout->addLayout(controlLayout);

    // Results splitter
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Results tree
    resultsTree = new QTreeWidget(this);
    resultsTree->setHeaderLabels({"Name", "Type", "Location", "ID"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setSelectionMode(QAbstractItemView::ExtendedSelection);  // Enable Shift+Click, Ctrl+Click
    splitter->addWidget(resultsTree);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    splitter->addWidget(logOutput);

    mainLayout->addWidget(splitter);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);  // Indeterminate mode
    mainLayout->addWidget(progressBar);

    // Connections
    connect(enumSubsBtn, &QPushButton::clicked, this, &AzureEnumWindow::enumerateSubscriptions);
    connect(enumResourcesBtn, &QPushButton::clicked, this, &AzureEnumWindow::enumerateResources);
    connect(enumManagedIdBtn, &QPushButton::clicked, this, &AzureEnumWindow::enumerateManagedIdentities);
    connect(subscriptionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AzureEnumWindow::onSubscriptionSelected);
    connect(copyBtn, &QPushButton::clicked, this, &AzureEnumWindow::copySelectedItem);
    connect(cancelBtn, &QPushButton::clicked, this, &AzureEnumWindow::cancelRequests);

    resize(900, 600);
}

QNetworkRequest AzureEnumWindow::bearerRequest(const QString &url, const QString &token) {
    QNetworkRequest req{QUrl(url)};
    req.setRawHeader("Authorization", QString("Bearer %1").arg(token).toUtf8());
    req.setRawHeader("Content-Type", "application/json");
    return req;
}

void AzureEnumWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void AzureEnumWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    enumSubsBtn->setEnabled(!loading);
    enumResourcesBtn->setEnabled(!loading && !currentSubscriptionId.isEmpty());
    enumManagedIdBtn->setEnabled(!loading && !currentSubscriptionId.isEmpty());
    tokenInput->setEnabled(!loading);
    autoFetchBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void AzureEnumWindow::cancelRequests() {
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

void AzureEnumWindow::updateTokenStatus() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

void AzureEnumWindow::onUserChanged(const QString &upn) {
    tokenInput->clear();
    updateTokenStatus();
    appendLog(QString("[*] Switched to user: %1").arg(upn), "cyan");
}

void AzureEnumWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        appendLog("[-] Please select a user first", "red");
        return;
    }

    appendLog("[*] Fetching Management token for selected user...", "cyan");
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

void AzureEnumWindow::enumerateSubscriptions() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    setLoading(true);
    cancelRequested = false;
    appendLog("[*] Enumerating subscriptions...", "cyan");
    resultsTree->clear();
    subscriptionCombo->clear();
    subscriptions = QJsonArray();

    QString url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    QNetworkReply *reply = net->get(bearerRequest(url, token));
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();

        if (cancelRequested) {
            return;
        }

        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            if (reply->error() != QNetworkReply::OperationCanceledError) {
                appendLog(QString("[-] Error: %1").arg(reply->errorString()), "red");
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray subs = doc.object().value("value").toArray();
        subscriptions = subs;

        if (subs.isEmpty()) {
            appendLog("[!] No subscriptions found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 subscription(s)").arg(subs.size()), "green");

        for (const QJsonValue &val : subs) {
            QJsonObject sub = val.toObject();
            QString name = sub.value("displayName").toString();
            QString id = sub.value("subscriptionId").toString();
            QString state = sub.value("state").toString();

            subscriptionCombo->addItem(QString("%1 (%2)").arg(name, state), id);

            auto *item = new QTreeWidgetItem(resultsTree);
            item->setText(0, name);
            item->setText(1, "Subscription");
            item->setText(2, state);
            item->setText(3, id);
        }

        subscriptionCombo->setEnabled(true);
        enumResourcesBtn->setEnabled(true);
        enumManagedIdBtn->setEnabled(true);
        onSubscriptionSelected(0);
    });
}

void AzureEnumWindow::onSubscriptionSelected(int index) {
    if (index >= 0 && index < subscriptionCombo->count()) {
        currentSubscriptionId = subscriptionCombo->itemData(index).toString();
    }
}

void AzureEnumWindow::enumerateResources() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentSubscriptionId.isEmpty()) {
        QMessageBox::warning(this, "Missing Data", "Please enumerate subscriptions first.");
        return;
    }

    setLoading(true);
    cancelRequested = false;
    appendLog(QString("[*] Enumerating resources in subscription %1...").arg(currentSubscriptionId), "cyan");

    QString url = QString("https://management.azure.com/subscriptions/%1/resources?api-version=2021-04-01")
                      .arg(currentSubscriptionId);

    QNetworkReply *reply = net->get(bearerRequest(url, token));
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();

        if (cancelRequested) {
            return;
        }

        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            if (reply->error() != QNetworkReply::OperationCanceledError) {
                appendLog(QString("[-] Error: %1").arg(reply->errorString()), "red");
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray resources = doc.object().value("value").toArray();

        if (resources.isEmpty()) {
            appendLog("[!] No resources found in this subscription.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 resource(s)").arg(resources.size()), "green");

        // Group by resource type
        QMap<QString, QTreeWidgetItem*> typeGroups;

        for (const QJsonValue &val : resources) {
            QJsonObject res = val.toObject();
            QString name = res.value("name").toString();
            QString type = res.value("type").toString();
            QString location = res.value("location").toString();
            QString id = res.value("id").toString();

            // Get or create group
            if (!typeGroups.contains(type)) {
                auto *group = new QTreeWidgetItem(resultsTree);
                group->setText(0, type);
                group->setText(1, "Resource Type");
                typeGroups[type] = group;
            }

            auto *item = new QTreeWidgetItem(typeGroups[type]);
            item->setText(0, name);
            item->setText(1, type.split('/').last());
            item->setText(2, location);
            item->setText(3, id);
        }

        resultsTree->expandAll();
    });
}

void AzureEnumWindow::enumerateManagedIdentities() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty() || currentSubscriptionId.isEmpty()) {
        QMessageBox::warning(this, "Missing Data", "Please enumerate subscriptions first.");
        return;
    }

    // Validate token audience
    if (!NetworkHelper::validateTokenAudience(token, NetworkHelper::AUDIENCE_MANAGEMENT)) {
        appendLog("[-] Warning: Token may not be for Management API", "orange");
    }

    setLoading(true);
    cancelRequested = false;
    appendLog(QString("[*] Searching for resources with managed identities in %1...").arg(currentSubscriptionId), "cyan");

    // Get VMs first (most common)
    QString vmUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01")
                        .arg(currentSubscriptionId);

    QNetworkRequest req = NetworkHelper::createBearerRequest(vmUrl, token);
    QNetworkReply *reply = net->get(req);
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, token]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();

        if (cancelRequested) {
            setLoading(false);
            return;
        }

        if (reply->error() != QNetworkReply::NoError) {
            if (reply->error() != QNetworkReply::OperationCanceledError) {
                appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
            }
            setLoading(false);
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray vms = doc.object().value("value").toArray();

        // Create group for managed identities
        auto *miGroup = new QTreeWidgetItem(resultsTree);
        miGroup->setText(0, "Managed Identities");
        miGroup->setText(1, "Security Target");

        int systemAssignedCount = 0;
        int userAssignedCount = 0;

        for (const QJsonValue &val : vms) {
            QJsonObject vm = val.toObject();
            QString name = vm.value("name").toString();
            QString location = vm.value("location").toString();
            QString id = vm.value("id").toString();
            QJsonObject identity = vm.value("identity").toObject();

            if (identity.isEmpty()) continue;

            QString identityType = identity.value("type").toString();
            QString principalId = identity.value("principalId").toString();
            QString tenantId = identity.value("tenantId").toString();
            QJsonObject userIdentities = identity.value("userAssignedIdentities").toObject();

            if (identityType.contains("SystemAssigned")) {
                systemAssignedCount++;

                auto *item = new QTreeWidgetItem(miGroup);
                item->setText(0, name);
                item->setText(1, "VM (System-Assigned)");
                item->setText(2, location);
                item->setText(3, principalId);
                item->setForeground(1, QBrush(QColor("orange")));
                item->setToolTip(0, QString("Resource ID: %1\nPrincipal ID: %2\nTenant: %3").arg(id, principalId, tenantId));
                item->setToolTip(1, "System-assigned MI: If you have access to this VM, you can steal tokens from IMDS (169.254.169.254)");
            }

            if (identityType.contains("UserAssigned") && !userIdentities.isEmpty()) {
                for (const QString &uaKey : userIdentities.keys()) {
                    userAssignedCount++;
                    QJsonObject uaId = userIdentities.value(uaKey).toObject();
                    QString uaPrincipalId = uaId.value("principalId").toString();
                    QString uaClientId = uaId.value("clientId").toString();

                    auto *item = new QTreeWidgetItem(miGroup);
                    item->setText(0, name);
                    item->setText(1, "VM (User-Assigned)");
                    item->setText(2, uaKey.split('/').last());  // Identity name
                    item->setText(3, uaPrincipalId);
                    item->setForeground(1, QBrush(QColor("#ff6b6b")));
                    item->setToolTip(0, QString("VM: %1\nIdentity: %2\nClient ID: %3").arg(name, uaKey, uaClientId));
                    item->setToolTip(1, "User-assigned MI: High value - can be used across multiple resources");
                }
            }
        }

        // Also check for other resource types with managed identities
        appendLog(QString("[*] Checking other resource types..."), "cyan");

        // Check Function Apps
        QString funcUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Web/sites?api-version=2022-03-01")
                              .arg(currentSubscriptionId);

        QNetworkRequest funcReq = NetworkHelper::createBearerRequest(funcUrl, token);
        QNetworkReply *funcReply = net->get(funcReq);
        activeReplies.append(funcReply);

        connect(funcReply, &QNetworkReply::finished, this, [this, funcReply, miGroup, &systemAssignedCount, &userAssignedCount]() {
            activeReplies.removeAll(funcReply);
            funcReply->deleteLater();

            if (funcReply->error() == QNetworkReply::NoError) {
                QJsonDocument doc = QJsonDocument::fromJson(funcReply->readAll());
                QJsonArray sites = doc.object().value("value").toArray();

                for (const QJsonValue &val : sites) {
                    QJsonObject site = val.toObject();
                    QJsonObject identity = site.value("identity").toObject();

                    if (identity.isEmpty()) continue;

                    QString name = site.value("name").toString();
                    QString kind = site.value("kind").toString();
                    QString identityType = identity.value("type").toString();
                    QString principalId = identity.value("principalId").toString();

                    QString typeLabel = kind.contains("function") ? "Function App" : "Web App";

                    if (identityType.contains("SystemAssigned")) {
                        auto *item = new QTreeWidgetItem(miGroup);
                        item->setText(0, name);
                        item->setText(1, QString("%1 (System-Assigned)").arg(typeLabel));
                        item->setText(2, kind);
                        item->setText(3, principalId);
                        item->setForeground(1, QBrush(QColor("orange")));
                    }
                }
            }

            setLoading(false);

            int total = miGroup->childCount();
            if (total == 0) {
                appendLog("[!] No resources with managed identities found.", "yellow");
                delete miGroup;
            } else {
                miGroup->setText(1, QString("(%1 resources)").arg(total));
                miGroup->setExpanded(true);
                appendLog(QString("[+] Found %1 resource(s) with managed identities").arg(total), "green");
                appendLog("[!] Managed identities can be exploited via IMDS on the target resource", "yellow");
                appendLog("[!] GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "yellow");
            }
        });
    });
}

void AzureEnumWindow::copySelectedItem() {
    auto *item = resultsTree->currentItem();
    if (!item) {
        QMessageBox::information(this, "No Selection", "Please select an item to copy.");
        return;
    }

    QString text = QString("Name: %1\nType: %2\nLocation: %3\nID: %4")
                       .arg(item->text(0), item->text(1), item->text(2), item->text(3));

    QApplication::clipboard()->setText(text);
    appendLog("[+] Copied to clipboard", "green");
}
