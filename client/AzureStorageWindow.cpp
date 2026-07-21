#include "AzureStorageWindow.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "NetworkHelper.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
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
#include <QFile>
#include <QRegularExpression>

AzureStorageWindow::AzureStorageWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Azure Storage Explorer");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

AzureStorageWindow::~AzureStorageWindow() {
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

void AzureStorageWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token inputs
    auto *tokenGroup = new QGroupBox("Authentication", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    // User selector
    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &AzureStorageWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &AzureStorageWindow::appendLog);

    // Auto-fetch button
    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Tokens for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &AzureStorageWindow::autoFetchTokens);

    auto *gridLayout = new QGridLayout();
    gridLayout->addWidget(new QLabel("Management Token:", this), 0, 0);
    mgmtTokenInput = new QLineEdit(this);
    mgmtTokenInput->setPlaceholderText("Token for https://management.azure.com");
    mgmtTokenInput->setEchoMode(QLineEdit::Password);
    gridLayout->addWidget(mgmtTokenInput, 0, 1);
    mgmtTokenStatus = new QLabel(this);
    mgmtTokenStatus->setFixedWidth(80);
    gridLayout->addWidget(mgmtTokenStatus, 0, 2);

    gridLayout->addWidget(new QLabel("Storage Token:", this), 1, 0);
    storageTokenInput = new QLineEdit(this);
    storageTokenInput->setPlaceholderText("Token for https://storage.azure.com");
    storageTokenInput->setEchoMode(QLineEdit::Password);
    gridLayout->addWidget(storageTokenInput, 1, 1);
    storageTokenStatus = new QLabel(this);
    storageTokenStatus->setFixedWidth(80);
    gridLayout->addWidget(storageTokenStatus, 1, 2);

    gridLayout->addWidget(new QLabel("Subscription ID:", this), 2, 0);
    subscriptionInput = new QLineEdit(this);
    subscriptionInput->setPlaceholderText("Enter subscription ID");
    gridLayout->addWidget(subscriptionInput, 2, 1);

    tokenLayout->addLayout(gridLayout);
    mainLayout->addWidget(tokenGroup);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);
    mainLayout->addWidget(progressBar);

    // Storage account selection
    auto *accountLayout = new QHBoxLayout();
    listAccountsBtn = new QPushButton("List Storage Accounts", this);
    storageAccountCombo = new QComboBox(this);
    storageAccountCombo->setMinimumWidth(300);
    storageAccountCombo->setEnabled(false);
    listContainersBtn = new QPushButton("List Containers", this);
    listContainersBtn->setEnabled(false);

    accountLayout->addWidget(listAccountsBtn);
    accountLayout->addWidget(storageAccountCombo);
    accountLayout->addWidget(listContainersBtn);
    cancelBtn = new QPushButton("Cancel", this);
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    accountLayout->addWidget(cancelBtn);
    accountLayout->addStretch();
    mainLayout->addLayout(accountLayout);

    // Splitter for tree and log
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Storage tree
    storageTree = new QTreeWidget(this);
    storageTree->setHeaderLabels({"Name", "Type", "Size", "Last Modified"});
    storageTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    storageTree->setAlternatingRowColors(true);
    storageTree->setSelectionMode(QAbstractItemView::ExtendedSelection);  // Enable Shift+Click, Ctrl+Click
    splitter->addWidget(storageTree);

    // Action buttons
    auto *actionWidget = new QWidget(this);
    auto *actionLayout = new QHBoxLayout(actionWidget);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    downloadBtn = new QPushButton("Download Selected", this);
    copyUrlBtn = new QPushButton("Copy Blob URL", this);
    actionLayout->addWidget(downloadBtn);
    actionLayout->addWidget(copyUrlBtn);
    actionLayout->addStretch();
    splitter->addWidget(actionWidget);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    splitter->addWidget(logOutput);

    mainLayout->addWidget(splitter);

    // Connections
    connect(listAccountsBtn, &QPushButton::clicked, this, &AzureStorageWindow::listStorageAccounts);
    connect(storageAccountCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AzureStorageWindow::onStorageAccountSelected);
    connect(listContainersBtn, &QPushButton::clicked, this, &AzureStorageWindow::listContainers);
    connect(storageTree, &QTreeWidget::itemClicked, this, &AzureStorageWindow::onContainerSelected);
    connect(storageTree, &QTreeWidget::itemDoubleClicked, this, &AzureStorageWindow::listBlobs);
    connect(downloadBtn, &QPushButton::clicked, this, &AzureStorageWindow::downloadBlob);
    connect(copyUrlBtn, &QPushButton::clicked, this, &AzureStorageWindow::copyBlobUrl);
    connect(cancelBtn, &QPushButton::clicked, this, &AzureStorageWindow::cancelRequests);

    resize(900, 600);
}

QNetworkRequest AzureStorageWindow::armRequest(const QString &url, const QString &token) {
    return NetworkHelper::createBearerRequest(url, token);
}

QNetworkRequest AzureStorageWindow::storageRequest(const QString &url, const QString &token) {
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);
    req.setRawHeader("x-ms-version", "2020-10-02");
    return req;
}

void AzureStorageWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void AzureStorageWindow::listStorageAccounts() {
    QString token = mgmtTokenInput->text().trimmed();
    QString subId = subscriptionInput->text().trimmed();

    if (token.isEmpty() || subId.isEmpty()) {
        QMessageBox::warning(this, "Missing Input", "Please enter management token and subscription ID.");
        return;
    }

    appendLog("[*] Listing storage accounts...", "cyan");
    storageAccountCombo->clear();
    storageTree->clear();
    storageAccounts = QJsonArray();

    QString url = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01")
                      .arg(subId);

    QNetworkReply *reply = net->get(armRequest(url, token));
    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray accounts = doc.object().value("value").toArray();
        storageAccounts = accounts;

        if (accounts.isEmpty()) {
            appendLog("[!] No storage accounts found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 storage account(s)").arg(accounts.size()), "green");

        for (const QJsonValue &val : accounts) {
            QJsonObject acc = val.toObject();
            QString name = acc.value("name").toString();
            QString location = acc.value("location").toString();
            QString kind = acc.value("kind").toString();

            storageAccountCombo->addItem(QString("%1 (%2, %3)").arg(name, location, kind), name);
        }

        storageAccountCombo->setEnabled(true);
        listContainersBtn->setEnabled(true);
        onStorageAccountSelected(0);
    });
}

void AzureStorageWindow::onStorageAccountSelected(int index) {
    if (index >= 0 && index < storageAccountCombo->count()) {
        currentStorageAccount = storageAccountCombo->itemData(index).toString();
    }
}

void AzureStorageWindow::listContainers() {
    QString token = storageTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a storage token.");
        return;
    }

    if (currentStorageAccount.isEmpty()) {
        QMessageBox::warning(this, "No Selection", "Please select a storage account.");
        return;
    }

    appendLog(QString("[*] Listing containers in %1...").arg(currentStorageAccount), "cyan");
    storageTree->clear();

    QString url = QString("https://%1.blob.core.windows.net/?comp=list").arg(currentStorageAccount);

    QNetworkReply *reply = net->get(storageRequest(url, token));
    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");

            int status = NetworkHelper::getHttpStatus(reply);
            if (status == 403) {
                appendLog("[!] Access denied. Check storage token permissions.", "yellow");
            }
            return;
        }

        // Parse XML response
        QByteArray data = reply->readAll();
        QString xml = QString::fromUtf8(data);

        // Simple XML parsing for containers
        QRegularExpression containerRe("<Name>([^<]+)</Name>");
        QRegularExpressionMatchIterator i = containerRe.globalMatch(xml);

        int count = 0;
        while (i.hasNext()) {
            QRegularExpressionMatch match = i.next();
            QString containerName = match.captured(1);

            auto *item = new QTreeWidgetItem(storageTree);
            item->setText(0, containerName);
            item->setText(1, "Container");
            item->setData(0, Qt::UserRole, "container");
            count++;
        }

        if (count == 0) {
            appendLog("[!] No containers found.", "yellow");
        } else {
            appendLog(QString("[+] Found %1 container(s)").arg(count), "green");
        }
    });
}

void AzureStorageWindow::onContainerSelected(QTreeWidgetItem *item, int column) {
    Q_UNUSED(column);
    if (!item) return;

    QString type = item->data(0, Qt::UserRole).toString();
    if (type == "container") {
        currentContainer = item->text(0);
    }
}

void AzureStorageWindow::listBlobs() {
    auto *item = storageTree->currentItem();
    if (!item) return;

    QString type = item->data(0, Qt::UserRole).toString();
    if (type != "container") return;

    QString token = storageTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a storage token.");
        return;
    }

    QString containerName = item->text(0);
    appendLog(QString("[*] Listing blobs in %1/%2...").arg(currentStorageAccount, containerName), "cyan");

    // Clear existing children
    while (item->childCount() > 0) {
        delete item->takeChild(0);
    }

    QString url = QString("https://%1.blob.core.windows.net/%2?restype=container&comp=list")
                      .arg(currentStorageAccount, containerName);

    QNetworkReply *reply = net->get(storageRequest(url, token));
    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply, item]() {
        reply->deleteLater();

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Error: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QByteArray data = reply->readAll();
        QString xml = QString::fromUtf8(data);

        // Parse blob entries
        QRegularExpression blobRe("<Blob>([\\s\\S]*?)</Blob>");
        QRegularExpression nameRe("<Name>([^<]+)</Name>");
        QRegularExpression sizeRe("<Content-Length>([^<]+)</Content-Length>");
        QRegularExpression modifiedRe("<Last-Modified>([^<]+)</Last-Modified>");

        QRegularExpressionMatchIterator i = blobRe.globalMatch(xml);

        int count = 0;
        while (i.hasNext()) {
            QRegularExpressionMatch match = i.next();
            QString blobXml = match.captured(1);

            QString blobName = nameRe.match(blobXml).captured(1);
            QString size = sizeRe.match(blobXml).captured(1);
            QString modified = modifiedRe.match(blobXml).captured(1);

            // Format size
            qint64 bytes = size.toLongLong();
            QString sizeStr;
            if (bytes < 1024) {
                sizeStr = QString("%1 B").arg(bytes);
            } else if (bytes < 1024 * 1024) {
                sizeStr = QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
            } else if (bytes < 1024 * 1024 * 1024) {
                sizeStr = QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
            } else {
                sizeStr = QString("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
            }

            auto *blobItem = new QTreeWidgetItem(item);
            blobItem->setText(0, blobName);
            blobItem->setText(1, "Blob");
            blobItem->setText(2, sizeStr);
            blobItem->setText(3, modified);
            blobItem->setData(0, Qt::UserRole, "blob");
            count++;
        }

        if (count == 0) {
            appendLog("[!] No blobs found in container.", "yellow");
        } else {
            appendLog(QString("[+] Found %1 blob(s)").arg(count), "green");
            item->setExpanded(true);
        }
    });
}

void AzureStorageWindow::downloadBlob() {
    auto *item = storageTree->currentItem();
    if (!item) {
        QMessageBox::information(this, "No Selection", "Please select a blob to download.");
        return;
    }

    QString type = item->data(0, Qt::UserRole).toString();
    if (type != "blob") {
        QMessageBox::information(this, "Invalid Selection", "Please select a blob, not a container.");
        return;
    }

    QString token = storageTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a storage token.");
        return;
    }

    // Get container name from parent
    QTreeWidgetItem *parent = item->parent();
    if (!parent) return;
    QString containerName = parent->text(0);
    QString blobName = item->text(0);

    QString savePath = QFileDialog::getSaveFileName(this, "Save Blob",
        blobName.split('/').last(), "All Files (*)");

    if (savePath.isEmpty()) return;

    appendLog(QString("[*] Downloading %1...").arg(blobName), "cyan");

    QString url = QString("https://%1.blob.core.windows.net/%2/%3")
                      .arg(currentStorageAccount, containerName, blobName);

    QNetworkReply *reply = net->get(storageRequest(url, token));
    if (!reply) {
        appendLog("[-] Failed to create network request", "red");
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply, savePath, blobName]() {
        reply->deleteLater();

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            appendLog(QString("[-] Download failed: %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QFile file(savePath);
        if (!file.open(QIODevice::WriteOnly)) {
            appendLog("[-] Could not open file for writing.", "red");
            return;
        }

        file.write(reply->readAll());
        file.close();

        appendLog(QString("[+] Downloaded %1 to %2").arg(blobName, savePath), "green");
    });
}

void AzureStorageWindow::copyBlobUrl() {
    auto *item = storageTree->currentItem();
    if (!item) {
        QMessageBox::information(this, "No Selection", "Please select a blob.");
        return;
    }

    QString type = item->data(0, Qt::UserRole).toString();
    QString url;

    if (type == "container") {
        url = QString("https://%1.blob.core.windows.net/%2")
                  .arg(currentStorageAccount, item->text(0));
    } else if (type == "blob") {
        QTreeWidgetItem *parent = item->parent();
        if (!parent) return;
        url = QString("https://%1.blob.core.windows.net/%2/%3")
                  .arg(currentStorageAccount, parent->text(0), item->text(0));
    } else {
        return;
    }

    QApplication::clipboard()->setText(url);
    appendLog("[+] URL copied to clipboard", "green");
}

void AzureStorageWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    listAccountsBtn->setEnabled(!loading);
    listContainersBtn->setEnabled(!loading && storageAccountCombo->currentIndex() >= 0);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void AzureStorageWindow::onUserChanged(const QString &upn) {
    mgmtTokenInput->clear();
    storageTokenInput->clear();
    if (upn.isEmpty()) {
        updateTokenStatus();
        return;
    }
    QString mgmtToken = userSelector->getExistingToken(TokenHelper::RESOURCE_MANAGEMENT);
    QString storageToken = userSelector->getExistingToken(TokenHelper::RESOURCE_STORAGE);
    if (!mgmtToken.isEmpty()) {
        mgmtTokenInput->setText(mgmtToken);
        appendLog("Found existing Management token", "lime");
    }
    if (!storageToken.isEmpty()) {
        storageTokenInput->setText(storageToken);
        appendLog("Found existing Storage token", "lime");
    }
    updateTokenStatus();
}

void AzureStorageWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        QMessageBox::warning(this, "No User Selected", "Please select a user from the dropdown first.");
        return;
    }
    appendLog(QString("Fetching tokens for user: %1").arg(userSelector->selectedUser()), "cyan");
    setLoading(true);
    autoFetchBtn->setEnabled(false);

    QStringList resources = {TokenHelper::RESOURCE_MANAGEMENT, TokenHelper::RESOURCE_STORAGE};
    userSelector->fetchTokens(resources,
        [this](bool success, const QMap<QString, QString> &tokens, const QString &error) {
            setLoading(false);
            autoFetchBtn->setEnabled(true);
            if (!success && tokens.isEmpty()) {
                appendLog("Failed: " + error, "red");
                QMessageBox::warning(this, "Token Fetch Failed", error);
                return;
            }
            if (tokens.contains(TokenHelper::RESOURCE_MANAGEMENT)) {
                mgmtTokenInput->setText(tokens[TokenHelper::RESOURCE_MANAGEMENT]);
                appendLog("Management token acquired", "lime");
            }
            if (tokens.contains(TokenHelper::RESOURCE_STORAGE)) {
                storageTokenInput->setText(tokens[TokenHelper::RESOURCE_STORAGE]);
                appendLog("Storage token acquired", "lime");
            }
            updateTokenStatus();
            if (!error.isEmpty()) appendLog("Some tokens failed: " + error, "orange");
        });
}

void AzureStorageWindow::updateTokenStatus() {
    auto getAudience = [](const QString &token) -> QString {
        QStringList parts = token.split('.');
        if (parts.size() < 2) return QString();
        QByteArray payload = parts.at(1).toUtf8();
        int pad = (4 - (payload.size() % 4)) % 4;
        payload.append(QByteArray(pad, '='));
        payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
        return QJsonDocument::fromJson(payload).object().value("aud").toString();
    };

    QString mgmtToken = mgmtTokenInput->text().trimmed();
    if (mgmtToken.isEmpty()) {
        mgmtTokenStatus->setText("<span style='color:gray'>Empty</span>");
    } else {
        QString aud = getAudience(mgmtToken);
        mgmtTokenStatus->setText(aud.contains("management.azure.com", Qt::CaseInsensitive)
            ? "<span style='color:lime'>Valid</span>" : "<span style='color:orange'>Wrong</span>");
    }

    QString storageToken = storageTokenInput->text().trimmed();
    if (storageToken.isEmpty()) {
        storageTokenStatus->setText("<span style='color:gray'>Empty</span>");
    } else {
        QString aud = getAudience(storageToken);
        storageTokenStatus->setText(aud.contains("storage.azure.com", Qt::CaseInsensitive)
            ? "<span style='color:lime'>Valid</span>" : "<span style='color:orange'>Wrong</span>");
    }
}

void AzureStorageWindow::cancelRequests() {
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
