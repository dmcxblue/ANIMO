#include "AzureVMManagerWindow.h"
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
#include <QTabWidget>
#include <QTimer>

AzureVMManagerWindow::AzureVMManagerWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Azure VM Manager");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

AzureVMManagerWindow::~AzureVMManagerWindow() {
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

void AzureVMManagerWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token input
    auto *tokenGroup = new QGroupBox("Azure Management Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    // User selector
    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &AzureVMManagerWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &AzureVMManagerWindow::appendLog);

    // Auto-fetch button
    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    autoFetchBtn->setStyleSheet("QPushButton { background-color: #2d5aa0; color: white; font-weight: bold; padding: 6px 12px; }");
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &AzureVMManagerWindow::autoFetchTokens);

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
    enumVMsBtn = new QPushButton("Enumerate VMs", this);
    subscriptionCombo = new QComboBox(this);
    subscriptionCombo->setMinimumWidth(250);
    subscriptionCombo->setPlaceholderText("Select subscription...");
    detailsBtn = new QPushButton("Get VM Details", this);
    detailsBtn->setEnabled(false);
    runCmdBtn = new QPushButton("Run Command", this);
    runCmdBtn->setEnabled(false);
    copyBtn = new QPushButton("Copy", this);
    exportBtn = new QPushButton("Export", this);

    controlLayout->addWidget(enumVMsBtn);
    controlLayout->addWidget(subscriptionCombo);
    controlLayout->addWidget(detailsBtn);
    controlLayout->addWidget(runCmdBtn);
    cancelBtn = new QPushButton("Cancel", this);
    cancelBtn->setStyleSheet("QPushButton { background-color: #dc3545; color: white; font-weight: bold; }");
    cancelBtn->setEnabled(false);
    controlLayout->addWidget(cancelBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(copyBtn);
    controlLayout->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);
    mainLayout->addWidget(progressBar);

    // Main splitter
    auto *splitter = new QSplitter(Qt::Horizontal, this);

    // Left side: VM Tree
    vmTree = new QTreeWidget(this);
    vmTree->setHeaderLabels({"Name", "Status", "OS", "Size", "Location", "Resource Group"});
    vmTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    vmTree->setAlternatingRowColors(true);
    vmTree->setMinimumWidth(400);
    splitter->addWidget(vmTree);

    // Right side: Tabs for Command/Output
    auto *rightWidget = new QWidget(this);
    auto *rightLayout = new QVBoxLayout(rightWidget);

    auto *tabs = new QTabWidget(this);

    // Command tab
    auto *commandWidget = new QWidget(this);
    auto *commandLayout = new QVBoxLayout(commandWidget);
    commandLayout->addWidget(new QLabel("PowerShell/Bash Command:", this));
    commandInput = new QPlainTextEdit(this);
    commandInput->setPlaceholderText("Enter command to run on VM...\nExample: Get-Process | Select-Object -First 10");
    commandInput->setMaximumHeight(150);
    commandLayout->addWidget(commandInput);
    commandLayout->addWidget(new QLabel("Output:", this));
    outputArea = new QTextEdit(this);
    outputArea->setReadOnly(true);
    commandLayout->addWidget(outputArea);
    tabs->addTab(commandWidget, "Run Command");

    rightLayout->addWidget(tabs);
    splitter->addWidget(rightWidget);

    mainLayout->addWidget(splitter);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(120);
    mainLayout->addWidget(logOutput);

    // Connections
    connect(enumVMsBtn, &QPushButton::clicked, this, &AzureVMManagerWindow::enumerateVMs);
    connect(vmTree, &QTreeWidget::itemSelectionChanged, this, &AzureVMManagerWindow::onVMSelected);
    connect(detailsBtn, &QPushButton::clicked, this, &AzureVMManagerWindow::getVMDetails);
    connect(runCmdBtn, &QPushButton::clicked, this, &AzureVMManagerWindow::runCommand);
    connect(copyBtn, &QPushButton::clicked, this, &AzureVMManagerWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &AzureVMManagerWindow::exportResults);
    connect(cancelBtn, &QPushButton::clicked, this, &AzureVMManagerWindow::cancelRequests);

    resize(1200, 700);
}

QNetworkRequest AzureVMManagerWindow::bearerRequest(const QString &url, const QString &token) {
    // Deprecated: Use NetworkHelper::createBearerRequest instead
    return NetworkHelper::createBearerRequest(url, token);
}

void AzureVMManagerWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void AzureVMManagerWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    enumVMsBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void AzureVMManagerWindow::enumerateVMs() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    setLoading(true);
    appendLog("[*] Enumerating subscriptions...", "cyan");
    vmTree->clear();
    virtualMachines = QJsonArray();

    // First get subscriptions
    QString url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    QNetworkReply *reply = net->get(NetworkHelper::createBearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Error: Failed to create network request", "red");
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

        appendLog(QString("[+] Found %1 subscription(s), enumerating VMs...").arg(subscriptions.size()), "green");

        subscriptionCombo->clear();
        for (const QJsonValue &val : subscriptions) {
            QJsonObject sub = val.toObject();
            QString name = sub.value("displayName").toString();
            QString id = sub.value("subscriptionId").toString();
            subscriptionCombo->addItem(name, id);
        }

        // Enumerate VMs across all subscriptions
        auto counter = std::make_shared<int>(subscriptions.size());

        for (const QJsonValue &val : subscriptions) {
            QString subId = val.toObject().value("subscriptionId").toString();
            QString subName = val.toObject().value("displayName").toString();
            QString vmUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01").arg(subId);

            QNetworkReply *vmReply = net->get(NetworkHelper::createBearerRequest(vmUrl, token));
            if (!vmReply) {
                appendLog(QString("[-] Failed to create request for subscription: %1").arg(subName), "red");
                (*counter)--;
                if (*counter == 0) {
                    setLoading(false);
                }
                continue;
            }

            connect(vmReply, &QNetworkReply::finished, this, [this, vmReply, subId, subName, counter]() {
                vmReply->deleteLater();
                (*counter)--;

                if (NetworkHelper::isReplySuccess(vmReply)) {
                    QJsonDocument doc = QJsonDocument::fromJson(vmReply->readAll());
                    QJsonArray vms = doc.object().value("value").toArray();

                    if (!vms.isEmpty()) {
                        auto *subItem = new QTreeWidgetItem(vmTree);
                        subItem->setText(0, subName);
                        subItem->setText(1, QString("(%1 VMs)").arg(vms.size()));

                        for (const QJsonValue &v : vms) {
                            QJsonObject vm = v.toObject();
                            vm.insert("subscriptionId", subId);
                            virtualMachines.append(vm);

                            QString name = vm.value("name").toString();
                            QString id = vm.value("id").toString();
                            QString location = vm.value("location").toString();

                            // Parse resource group from ID
                            QStringList idParts = id.split('/');
                            QString resourceGroup;
                            for (int i = 0; i < idParts.size(); i++) {
                                if (idParts[i].toLower() == "resourcegroups" && i + 1 < idParts.size()) {
                                    resourceGroup = idParts[i + 1];
                                    break;
                                }
                            }

                            QJsonObject props = vm.value("properties").toObject();
                            QString vmSize = props.value("hardwareProfile").toObject().value("vmSize").toString();
                            QString osType = props.value("storageProfile").toObject()
                                                .value("osDisk").toObject()
                                                .value("osType").toString();

                            auto *item = new QTreeWidgetItem(subItem);
                            item->setText(0, name);
                            item->setText(1, "Unknown");  // Status requires separate call
                            item->setText(2, osType);
                            item->setText(3, vmSize);
                            item->setText(4, location);
                            item->setText(5, resourceGroup);
                            item->setData(0, Qt::UserRole, id);
                        }
                        subItem->setExpanded(true);
                    }
                }

                if (*counter == 0) {
                    setLoading(false);
                    if (virtualMachines.isEmpty()) {
                        appendLog("[!] No VMs found.", "yellow");
                    } else {
                        appendLog(QString("[+] Found %1 VM(s)").arg(virtualMachines.size()), "green");
                    }
                }
            });
        }
    });
}

void AzureVMManagerWindow::onVMSelected() {
    auto items = vmTree->selectedItems();
    if (items.isEmpty()) {
        detailsBtn->setEnabled(false);
        runCmdBtn->setEnabled(false);
        return;
    }

    auto *item = items.first();
    QString vmId = item->data(0, Qt::UserRole).toString();

    if (!vmId.isEmpty()) {
        currentVMId = vmId;
        currentVMName = item->text(0);
        currentVMResourceGroup = item->text(5);

        // Extract subscription ID from VM ID
        QStringList idParts = vmId.split('/');
        for (int i = 0; i < idParts.size(); i++) {
            if (idParts[i].toLower() == "subscriptions" && i + 1 < idParts.size()) {
                currentSubscriptionId = idParts[i + 1];
                break;
            }
        }

        detailsBtn->setEnabled(true);
        runCmdBtn->setEnabled(true);
    } else {
        detailsBtn->setEnabled(false);
        runCmdBtn->setEnabled(false);
    }
}

void AzureVMManagerWindow::getVMDetails() {
    if (currentVMId.isEmpty()) return;

    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    setLoading(true);
    appendLog(QString("[*] Getting details for VM: %1").arg(currentVMName), "cyan");

    QString url = QString("https://management.azure.com%1?api-version=2023-07-01&$expand=instanceView").arg(currentVMId);
    QNetworkReply *reply = net->get(NetworkHelper::createBearerRequest(url, token));

    if (!reply) {
        appendLog("[-] Error: Failed to create network request", "red");
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
        QJsonObject vm = doc.object();

        QString details;
        details += QString("Name: %1\n").arg(vm.value("name").toString());
        details += QString("Location: %1\n").arg(vm.value("location").toString());
        details += QString("VM ID: %1\n\n").arg(vm.value("vmId").toString());

        QJsonObject props = vm.value("properties").toObject();

        // Hardware
        details += "=== Hardware ===\n";
        details += QString("VM Size: %1\n\n").arg(props.value("hardwareProfile").toObject().value("vmSize").toString());

        // OS
        details += "=== OS Profile ===\n";
        QJsonObject osProfile = props.value("osProfile").toObject();
        details += QString("Computer Name: %1\n").arg(osProfile.value("computerName").toString());
        details += QString("Admin Username: %1\n\n").arg(osProfile.value("adminUsername").toString());

        // Network
        details += "=== Network Interfaces ===\n";
        QJsonArray nics = props.value("networkProfile").toObject().value("networkInterfaces").toArray();
        for (const QJsonValue &nic : nics) {
            details += QString("NIC: %1\n").arg(nic.toObject().value("id").toString().split('/').last());
        }
        details += "\n";

        // Instance View (status)
        QJsonObject instanceView = props.value("instanceView").toObject();
        details += "=== Status ===\n";
        QJsonArray statuses = instanceView.value("statuses").toArray();
        for (const QJsonValue &s : statuses) {
            QJsonObject status = s.toObject();
            details += QString("%1: %2\n").arg(status.value("code").toString(), status.value("displayStatus").toString());
        }

        outputArea->setText(details);
        appendLog("[+] VM details retrieved", "green");
    });
}

void AzureVMManagerWindow::runCommand() {
    if (currentVMId.isEmpty()) return;

    QString token = tokenInput->text().trimmed();
    QString command = commandInput->toPlainText().trimmed();

    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    if (command.isEmpty()) {
        QMessageBox::warning(this, "Missing Command", "Please enter a command to run.");
        return;
    }

    setLoading(true);
    appendLog(QString("[*] Running command on VM: %1").arg(currentVMName), "cyan");
    outputArea->setText("Executing command...\n");

    // Determine command type based on OS
    auto *selectedItem = vmTree->currentItem();
    QString osType = selectedItem ? selectedItem->text(2) : "Windows";
    QString commandId = osType.toLower() == "linux" ? "RunShellScript" : "RunPowerShellScript";

    QString url = QString("https://management.azure.com%1/runCommand?api-version=2023-07-01").arg(currentVMId);

    QJsonObject body;
    body.insert("commandId", commandId);
    body.insert("script", QJsonArray{command});

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);
    QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());

    if (!reply) {
        appendLog("[-] Error: Failed to create network request", "red");
        outputArea->append("Error: Failed to create network request");
        setLoading(false);
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        setLoading(false);

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            QString detailedError = NetworkHelper::parseApiError(reply);
            appendLog(QString("[-] Error: %1").arg(detailedError), "red");
            outputArea->append(QString("Error: %1").arg(detailedError));
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject result = doc.object();

        // Parse output
        QJsonArray outputs = result.value("value").toArray();
        QString outputText;
        for (const QJsonValue &v : outputs) {
            QJsonObject out = v.toObject();
            QString code = out.value("code").toString();
            QString message = out.value("message").toString();
            outputText += QString("[%1]\n%2\n").arg(code, message);
        }

        if (outputText.isEmpty()) {
            outputText = "Command executed (no output)";
        }

        outputArea->setText(outputText);
        appendLog("[+] Command executed successfully", "green");
    });
}

void AzureVMManagerWindow::copySelectedItem() {
    auto *item = vmTree->currentItem();
    if (!item) {
        // Copy output area if no VM selected
        QApplication::clipboard()->setText(outputArea->toPlainText());
        appendLog("[+] Output copied to clipboard", "green");
        return;
    }

    QString vmId = item->data(0, Qt::UserRole).toString();
    QString text = QString("Name: %1\nStatus: %2\nOS: %3\nSize: %4\nLocation: %5\nResource Group: %6\nID: %7")
                       .arg(item->text(0), item->text(1), item->text(2),
                            item->text(3), item->text(4), item->text(5), vmId);

    QApplication::clipboard()->setText(text);
    appendLog("[+] Copied to clipboard", "green");
}

void AzureVMManagerWindow::exportResults() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export Results",
        QDir::homePath() + "/vm_export.txt", "Text Files (*.txt);;All Files (*)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "Azure VM Export\n";
    out << "===============\n\n";

    QTreeWidgetItemIterator it(vmTree);
    while (*it) {
        QString vmId = (*it)->data(0, Qt::UserRole).toString();
        if (!vmId.isEmpty()) {
            out << QString("Name: %1 | OS: %2 | Size: %3 | Location: %4 | RG: %5\n")
                   .arg((*it)->text(0), (*it)->text(2), (*it)->text(3),
                        (*it)->text(4), (*it)->text(5));
            out << QString("  ID: %1\n\n").arg(vmId);
        }
        ++it;
    }

    file.close();
    appendLog(QString("[+] Exported to %1").arg(filePath), "green");
}

void AzureVMManagerWindow::onUserChanged(const QString &upn) {
    tokenInput->clear();
    if (upn.isEmpty()) {
        updateTokenStatus();
        return;
    }
    QString token = userSelector->getExistingToken(TokenHelper::RESOURCE_MANAGEMENT);
    if (!token.isEmpty()) {
        tokenInput->setText(token);
        appendLog("Found existing Management token", "lime");
    }
    updateTokenStatus();
}

void AzureVMManagerWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        QMessageBox::warning(this, "No User Selected", "Please select a user from the dropdown first.");
        return;
    }
    appendLog(QString("Fetching token for user: %1").arg(userSelector->selectedUser()), "cyan");
    setLoading(true);
    autoFetchBtn->setEnabled(false);

    userSelector->fetchToken(TokenHelper::RESOURCE_MANAGEMENT,
        [this](bool success, const QString &token, const QString &error) {
            setLoading(false);
            autoFetchBtn->setEnabled(true);
            if (success) {
                tokenInput->setText(token);
                appendLog("Management token acquired", "lime");
            } else {
                appendLog("Failed: " + error, "red");
                QMessageBox::warning(this, "Token Fetch Failed", error);
            }
            updateTokenStatus();
        });
}

void AzureVMManagerWindow::updateTokenStatus() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        tokenStatus->setText("<span style='color:gray'>Empty</span>");
    } else {
        QStringList parts = token.split('.');
        if (parts.size() >= 2) {
            QByteArray payload = parts.at(1).toUtf8();
            int pad = (4 - (payload.size() % 4)) % 4;
            payload.append(QByteArray(pad, '='));
            payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
            QJsonDocument doc = QJsonDocument::fromJson(payload);
            QString aud = doc.object().value("aud").toString();
            if (aud.contains("management.azure.com", Qt::CaseInsensitive)) {
                tokenStatus->setText("<span style='color:lime'>Valid</span>");
            } else {
                tokenStatus->setText("<span style='color:orange'>Wrong</span>");
            }
        } else {
            tokenStatus->setText("<span style='color:red'>Invalid</span>");
        }
    }
}

void AzureVMManagerWindow::cancelRequests() {
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
