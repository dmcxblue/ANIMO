#include "KeyVaultExplorerWindow.h"
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
#include <QDir>

KeyVaultExplorerWindow::KeyVaultExplorerWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Azure Key Vault Explorer");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

KeyVaultExplorerWindow::~KeyVaultExplorerWindow() {
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

void KeyVaultExplorerWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Token inputs
    auto *tokenGroup = new QGroupBox("Authentication Tokens", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    // User selector
    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &KeyVaultExplorerWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &KeyVaultExplorerWindow::appendLog);

    // Auto-fetch button
    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Tokens for Selected User", this);
    autoFetchBtn->setStyleSheet("QPushButton { background-color: #2d5aa0; color: white; font-weight: bold; padding: 6px 12px; }");
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::autoFetchTokens);

    auto *mgmtRow = new QHBoxLayout();
    mgmtRow->addWidget(new QLabel("Management Token:", this));
    mgmtTokenInput = new QLineEdit(this);
    mgmtTokenInput->setPlaceholderText("Token for https://management.azure.com (enumerate vaults)");
    mgmtTokenInput->setEchoMode(QLineEdit::Password);
    mgmtRow->addWidget(mgmtTokenInput);
    mgmtTokenStatus = new QLabel(this);
    mgmtTokenStatus->setFixedWidth(80);
    mgmtRow->addWidget(mgmtTokenStatus);
    tokenLayout->addLayout(mgmtRow);

    auto *vaultRow = new QHBoxLayout();
    vaultRow->addWidget(new QLabel("Vault Token:", this));
    vaultTokenInput = new QLineEdit(this);
    vaultTokenInput->setPlaceholderText("Token for https://vault.azure.net (access secrets/keys)");
    vaultTokenInput->setEchoMode(QLineEdit::Password);
    vaultRow->addWidget(vaultTokenInput);
    vaultTokenStatus = new QLabel(this);
    vaultTokenStatus->setFixedWidth(80);
    vaultRow->addWidget(vaultTokenStatus);
    tokenLayout->addLayout(vaultRow);

    mainLayout->addWidget(tokenGroup);

    // Controls row 1
    auto *controlLayout1 = new QHBoxLayout();
    enumVaultsBtn = new QPushButton("Enumerate Key Vaults", this);
    subscriptionCombo = new QComboBox(this);
    subscriptionCombo->setMinimumWidth(250);
    subscriptionCombo->setPlaceholderText("Select subscription...");
    vaultCombo = new QComboBox(this);
    vaultCombo->setMinimumWidth(250);
    vaultCombo->setPlaceholderText("Select vault...");
    vaultCombo->setEnabled(false);

    controlLayout1->addWidget(enumVaultsBtn);
    controlLayout1->addWidget(subscriptionCombo);
    controlLayout1->addWidget(vaultCombo);
    controlLayout1->addStretch();
    mainLayout->addLayout(controlLayout1);

    // Controls row 2
    auto *controlLayout2 = new QHBoxLayout();
    listSecretsBtn = new QPushButton("List Secrets", this);
    listSecretsBtn->setEnabled(false);
    listKeysBtn = new QPushButton("List Keys", this);
    listKeysBtn->setEnabled(false);
    listCertsBtn = new QPushButton("List Certificates", this);
    listCertsBtn->setEnabled(false);
    getSecretBtn = new QPushButton("Get Secret Value", this);
    getSecretBtn->setEnabled(false);
    exportCertBtn = new QPushButton("Export Certificate", this);
    exportCertBtn->setEnabled(false);
    exportCertBtn->setToolTip("Export selected certificate with private key (requires get permission on secrets)");

    controlLayout2->addWidget(listSecretsBtn);
    controlLayout2->addWidget(listKeysBtn);
    controlLayout2->addWidget(listCertsBtn);
    controlLayout2->addWidget(getSecretBtn);
    controlLayout2->addWidget(exportCertBtn);
    controlLayout2->addStretch();
    mainLayout->addLayout(controlLayout2);

    // Controls row 3
    auto *controlLayout3 = new QHBoxLayout();
    accessPoliciesBtn = new QPushButton("List Access Policies", this);
    accessPoliciesBtn->setEnabled(false);
    accessPoliciesBtn->setToolTip("Enumerate identities with access to this vault (requires Management token)");
    copyBtn = new QPushButton("Copy Selected", this);
    exportBtn = new QPushButton("Export", this);

    cancelBtn = new QPushButton("Cancel", this);
    cancelBtn->setStyleSheet("QPushButton { background-color: #dc3545; color: white; font-weight: bold; }");
    cancelBtn->setEnabled(false);

    controlLayout3->addWidget(accessPoliciesBtn);
    controlLayout3->addWidget(cancelBtn);
    controlLayout3->addStretch();
    controlLayout3->addWidget(copyBtn);
    controlLayout3->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout3);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);
    mainLayout->addWidget(progressBar);

    // Results splitter
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Results tree
    resultsTree = new QTreeWidget(this);
    resultsTree->setHeaderLabels({"Name", "Type", "Enabled", "Created", "Updated", "ID/Value"});
    resultsTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    splitter->addWidget(resultsTree);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    splitter->addWidget(logOutput);

    mainLayout->addWidget(splitter);

    // Connections
    connect(enumVaultsBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::enumerateKeyVaults);
    connect(vaultCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &KeyVaultExplorerWindow::onVaultSelected);
    connect(listSecretsBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::listSecrets);
    connect(listKeysBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::listKeys);
    connect(listCertsBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::listCertificates);
    connect(getSecretBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::getSecretValue);
    connect(exportCertBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::exportCertificate);
    connect(accessPoliciesBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::listAccessPolicies);
    connect(copyBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::copySelectedItem);
    connect(exportBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::exportResults);
    connect(cancelBtn, &QPushButton::clicked, this, &KeyVaultExplorerWindow::cancelRequests);

    resize(1000, 700);
}

QNetworkRequest KeyVaultExplorerWindow::bearerRequest(const QString &url, const QString &token) {
    QNetworkRequest req{QUrl(url)};
    req.setRawHeader("Authorization", QString("Bearer %1").arg(token).toUtf8());
    req.setRawHeader("Content-Type", "application/json");
    return req;
}

void KeyVaultExplorerWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void KeyVaultExplorerWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    enumVaultsBtn->setEnabled(!loading);
    listSecretsBtn->setEnabled(!loading && !currentVaultUrl.isEmpty());
    listKeysBtn->setEnabled(!loading && !currentVaultUrl.isEmpty());
    listCertsBtn->setEnabled(!loading && !currentVaultUrl.isEmpty());
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void KeyVaultExplorerWindow::cancelRequests() {
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

void KeyVaultExplorerWindow::enumerateKeyVaults() {
    QString token = mgmtTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter an Azure Management access token.");
        return;
    }

    setLoading(true);
    appendLog("[*] Enumerating subscriptions...", "cyan");
    resultsTree->clear();
    vaultCombo->clear();
    keyVaults = QJsonArray();

    // First get subscriptions
    QString url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    QNetworkReply *reply = net->get(bearerRequest(url, token));
    if (!reply) {
        appendLog("[-] Network request failed", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, token]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
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

        appendLog(QString("[+] Found %1 subscription(s), enumerating Key Vaults...").arg(subscriptions.size()), "green");

        subscriptionCombo->clear();
        for (const QJsonValue &val : subscriptions) {
            QJsonObject sub = val.toObject();
            QString name = sub.value("displayName").toString();
            QString id = sub.value("subscriptionId").toString();
            subscriptionCombo->addItem(name, id);
        }

        // Enumerate Key Vaults across all subscriptions
        auto counter = std::make_shared<int>(subscriptions.size());

        for (const QJsonValue &val : subscriptions) {
            QString subId = val.toObject().value("subscriptionId").toString();
            QString vaultUrl = QString("https://management.azure.com/subscriptions/%1/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01").arg(subId);

            QNetworkReply *vaultReply = net->get(bearerRequest(vaultUrl, token));
            if (!vaultReply) {
                (*counter)--;
                appendLog("[-] Network request failed for subscription " + subId, "red");
                if (*counter == 0) setLoading(false);
                continue;
            }
            activeReplies.append(vaultReply);
            connect(vaultReply, &QNetworkReply::finished, this, [this, vaultReply, subId, counter]() {
                activeReplies.removeAll(vaultReply);
                vaultReply->deleteLater();
                (*counter)--;

                if (vaultReply->error() == QNetworkReply::NoError) {
                    QJsonDocument doc = QJsonDocument::fromJson(vaultReply->readAll());
                    QJsonArray vaults = doc.object().value("value").toArray();

                    for (const QJsonValue &v : vaults) {
                        QJsonObject vault = v.toObject();
                        vault.insert("subscriptionId", subId);
                        keyVaults.append(vault);

                        QString name = vault.value("name").toString();
                        QString vaultUri = vault.value("properties").toObject().value("vaultUri").toString();
                        QString location = vault.value("location").toString();

                        vaultCombo->addItem(name, vaultUri);

                        auto *item = new QTreeWidgetItem(resultsTree);
                        item->setText(0, name);
                        item->setText(1, "Key Vault");
                        item->setText(2, "Yes");
                        item->setText(3, location);
                        item->setText(4, "-");
                        item->setText(5, vaultUri);
                    }
                } else {
                    appendLog(QString("[-] Failed to enumerate vaults for subscription %1: %2")
                              .arg(subId, NetworkHelper::parseApiError(vaultReply)), "red");
                }

                if (*counter == 0) {
                    setLoading(false);
                    if (keyVaults.isEmpty()) {
                        appendLog("[!] No Key Vaults found.", "yellow");
                    } else {
                        appendLog(QString("[+] Found %1 Key Vault(s)").arg(keyVaults.size()), "green");
                        vaultCombo->setEnabled(true);
                        if (vaultCombo->count() > 0) {
                            onVaultSelected(0);
                        }
                    }
                }
            });
        }
    });
}

void KeyVaultExplorerWindow::onVaultSelected(int index) {
    if (index >= 0 && index < vaultCombo->count()) {
        currentVaultUrl = vaultCombo->itemData(index).toString();
        if (!currentVaultUrl.endsWith('/')) currentVaultUrl += '/';
        listSecretsBtn->setEnabled(true);
        listKeysBtn->setEnabled(true);
        listCertsBtn->setEnabled(true);
        accessPoliciesBtn->setEnabled(true);
        appendLog(QString("[*] Selected vault: %1").arg(currentVaultUrl), "cyan");
    }
}

void KeyVaultExplorerWindow::listSecrets() {
    QString token = vaultTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Key Vault access token (https://vault.azure.net).");
        return;
    }

    if (currentVaultUrl.isEmpty()) {
        QMessageBox::warning(this, "No Vault", "Please select a Key Vault first.");
        return;
    }

    setLoading(true);
    appendLog("[*] Listing secrets...", "cyan");

    QString url = currentVaultUrl + "secrets?api-version=7.4";
    QNetworkReply *reply = net->get(bearerRequest(url, token));
    if (!reply) {
        appendLog("[-] Network request failed", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray secrets = doc.object().value("value").toArray();

        if (secrets.isEmpty()) {
            appendLog("[!] No secrets found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 secret(s)").arg(secrets.size()), "green");

        auto *secretsGroup = new QTreeWidgetItem(resultsTree);
        secretsGroup->setText(0, "Secrets");
        secretsGroup->setText(1, QString("(%1 items)").arg(secrets.size()));

        for (const QJsonValue &val : secrets) {
            QJsonObject secret = val.toObject();
            QString id = secret.value("id").toString();
            QString name = id.split('/').last();
            bool enabled = secret.value("attributes").toObject().value("enabled").toBool();
            QString created = secret.value("attributes").toObject().value("created").toString();
            QString updated = secret.value("attributes").toObject().value("updated").toString();

            auto *item = new QTreeWidgetItem(secretsGroup);
            item->setText(0, name);
            item->setText(1, "Secret");
            item->setText(2, enabled ? "Yes" : "No");
            item->setText(3, created);
            item->setText(4, updated);
            item->setText(5, id);
        }

        secretsGroup->setExpanded(true);
        getSecretBtn->setEnabled(true);
    });
}

void KeyVaultExplorerWindow::listKeys() {
    QString token = vaultTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Key Vault access token.");
        return;
    }

    if (currentVaultUrl.isEmpty()) {
        QMessageBox::warning(this, "No Vault", "Please select a Key Vault first.");
        return;
    }

    setLoading(true);
    appendLog("[*] Listing keys...", "cyan");

    QString url = currentVaultUrl + "keys?api-version=7.4";
    QNetworkReply *reply = net->get(bearerRequest(url, token));
    if (!reply) {
        appendLog("[-] Network request failed", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray keys = doc.object().value("value").toArray();

        if (keys.isEmpty()) {
            appendLog("[!] No keys found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 key(s)").arg(keys.size()), "green");

        auto *keysGroup = new QTreeWidgetItem(resultsTree);
        keysGroup->setText(0, "Keys");
        keysGroup->setText(1, QString("(%1 items)").arg(keys.size()));

        for (const QJsonValue &val : keys) {
            QJsonObject key = val.toObject();
            QString kid = key.value("kid").toString();
            QString name = kid.split('/').last();
            bool enabled = key.value("attributes").toObject().value("enabled").toBool();

            auto *item = new QTreeWidgetItem(keysGroup);
            item->setText(0, name);
            item->setText(1, "Key");
            item->setText(2, enabled ? "Yes" : "No");
            item->setText(5, kid);
        }

        keysGroup->setExpanded(true);
    });
}

void KeyVaultExplorerWindow::listCertificates() {
    QString token = vaultTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Key Vault access token.");
        return;
    }

    if (currentVaultUrl.isEmpty()) {
        QMessageBox::warning(this, "No Vault", "Please select a Key Vault first.");
        return;
    }

    setLoading(true);
    appendLog("[*] Listing certificates...", "cyan");

    QString url = currentVaultUrl + "certificates?api-version=7.4";
    QNetworkReply *reply = net->get(bearerRequest(url, token));
    if (!reply) {
        appendLog("[-] Network request failed", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray certs = doc.object().value("value").toArray();

        if (certs.isEmpty()) {
            appendLog("[!] No certificates found.", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 certificate(s)").arg(certs.size()), "green");

        auto *certsGroup = new QTreeWidgetItem(resultsTree);
        certsGroup->setText(0, "Certificates");
        certsGroup->setText(1, QString("(%1 items)").arg(certs.size()));

        for (const QJsonValue &val : certs) {
            QJsonObject cert = val.toObject();
            QString id = cert.value("id").toString();
            QString name = id.split('/').last();
            bool enabled = cert.value("attributes").toObject().value("enabled").toBool();

            auto *item = new QTreeWidgetItem(certsGroup);
            item->setText(0, name);
            item->setText(1, "Certificate");
            item->setText(2, enabled ? "Yes" : "No");
            item->setText(5, id);
        }

        certsGroup->setExpanded(true);
        exportCertBtn->setEnabled(true);
    });
}

void KeyVaultExplorerWindow::getSecretValue() {
    auto *item = resultsTree->currentItem();
    if (!item || item->text(1) != "Secret") {
        QMessageBox::warning(this, "No Selection", "Please select a secret to retrieve its value.");
        return;
    }

    QString token = vaultTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Key Vault access token.");
        return;
    }

    QString secretId = item->text(5);
    if (secretId.isEmpty()) return;

    setLoading(true);
    appendLog(QString("[*] Retrieving secret value: %1").arg(item->text(0)), "cyan");

    QString url = secretId + "?api-version=7.4";
    QNetworkReply *reply = net->get(bearerRequest(url, token));
    if (!reply) {
        appendLog("[-] Network request failed", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, item]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QString value = doc.object().value("value").toString();

        appendLog(QString("[+] Secret '%1' = %2").arg(item->text(0), value), "green");

        // Update the tree item with the value
        item->setText(5, value);

        QMessageBox::information(this, "Secret Value",
            QString("Secret: %1\n\nValue: %2").arg(item->text(0), value));
    });
}

void KeyVaultExplorerWindow::exportCertificate() {
    auto *item = resultsTree->currentItem();
    if (!item || item->text(1) != "Certificate") {
        QMessageBox::warning(this, "No Selection", "Please select a certificate to export.");
        return;
    }

    QString token = vaultTokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Key Vault access token.");
        return;
    }

    QString certId = item->text(5);
    QString certName = item->text(0);
    if (certId.isEmpty()) return;

    setLoading(true);
    appendLog(QString("[*] Exporting certificate: %1").arg(certName), "cyan");
    appendLog("[*] Attempting to retrieve certificate with private key...", "cyan");

    // To get the private key, we need to get the certificate as a secret
    // The certificate secret contains the full PFX/PEM including private key
    QString secretUrl = currentVaultUrl + "secrets/" + certName + "?api-version=7.4";
    QNetworkRequest req = NetworkHelper::createBearerRequest(secretUrl, token);
    QNetworkReply *reply = net->get(req);
    if (!reply) {
        appendLog("[-] Network request failed", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, certName]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (status == 403) {
                appendLog("[-] Access denied. Need 'get' permission on secrets to export with private key.", "red");
                appendLog("[*] Falling back to public certificate only...", "yellow");
                // Could add fallback to get just the public cert here
            } else {
                appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();
        QString value = obj.value("value").toString();
        QString contentType = obj.value("contentType").toString();

        if (value.isEmpty()) {
            appendLog("[-] Certificate value is empty.", "red");
            return;
        }

        // Determine format and save
        QString ext = ".pem";
        QByteArray data;

        if (contentType.contains("pkcs12") || contentType.contains("pfx")) {
            ext = ".pfx";
            data = QByteArray::fromBase64(value.toUtf8());
            appendLog("[+] Certificate is in PKCS#12/PFX format", "green");
        } else {
            // Assume PEM format
            data = value.toUtf8();
            appendLog("[+] Certificate is in PEM format", "green");
        }

        QString filePath = QFileDialog::getSaveFileName(this, "Save Certificate",
            QDir::homePath() + "/" + certName + ext,
            ext == ".pfx" ? "PKCS#12 (*.pfx *.p12)" : "PEM (*.pem *.crt)");

        if (filePath.isEmpty()) return;

        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(this, "Error", "Could not write to file.");
            return;
        }

        file.write(data);
        file.close();

        appendLog(QString("[+] Certificate exported to: %1").arg(filePath), "green");
        appendLog("[!] IMPORTANT: This certificate includes the PRIVATE KEY!", "yellow");

        QMessageBox::information(this, "Export Complete",
            QString("Certificate exported to:\n%1\n\nThis includes the private key.").arg(filePath));
    });
}

void KeyVaultExplorerWindow::listAccessPolicies() {
    QString mgmtToken = mgmtTokenInput->text().trimmed();
    if (mgmtToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please enter a Management token to view access policies.");
        return;
    }

    if (currentVaultUrl.isEmpty()) {
        QMessageBox::warning(this, "No Vault", "Please select a Key Vault first.");
        return;
    }

    // Find the vault resource ID from our stored data
    QString vaultName = vaultCombo->currentText();
    QString vaultResourceId;

    for (const QJsonValue &val : keyVaults) {
        QJsonObject vault = val.toObject();
        if (vault.value("name").toString() == vaultName) {
            vaultResourceId = vault.value("id").toString();
            break;
        }
    }

    if (vaultResourceId.isEmpty()) {
        appendLog("[-] Could not find vault resource ID. Re-enumerate vaults.", "red");
        return;
    }

    setLoading(true);
    appendLog(QString("[*] Enumerating access policies for %1...").arg(vaultName), "cyan");

    // Get the full vault resource to see access policies
    QString url = QString("https://management.azure.com%1?api-version=2022-07-01").arg(vaultResourceId);
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, mgmtToken);
    QNetworkReply *reply = net->get(req);
    if (!reply) {
        appendLog("[-] Network request failed", "red");
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, vaultName]() {
        activeReplies.removeAll(reply);
        reply->deleteLater();
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            appendLog(QString("[-] %1").arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject vault = doc.object();
        QJsonObject props = vault.value("properties").toObject();
        QJsonArray policies = props.value("accessPolicies").toArray();

        if (policies.isEmpty()) {
            appendLog("[!] No access policies found (vault may use RBAC instead).", "yellow");
            return;
        }

        appendLog(QString("[+] Found %1 access policy/policies").arg(policies.size()), "green");

        auto *policiesGroup = new QTreeWidgetItem(resultsTree);
        policiesGroup->setText(0, "Access Policies");
        policiesGroup->setText(1, QString("(%1 policies)").arg(policies.size()));

        for (const QJsonValue &val : policies) {
            QJsonObject policy = val.toObject();
            QString tenantId = policy.value("tenantId").toString();
            QString objectId = policy.value("objectId").toString();
            QJsonObject perms = policy.value("permissions").toObject();

            // Get permissions summary
            QStringList permsList;
            QJsonArray keys = perms.value("keys").toArray();
            QJsonArray secrets = perms.value("secrets").toArray();
            QJsonArray certs = perms.value("certificates").toArray();

            if (!keys.isEmpty()) {
                QStringList keyPerms;
                for (const QJsonValue &p : keys) keyPerms << p.toString();
                permsList << QString("Keys: %1").arg(keyPerms.join(", "));
            }
            if (!secrets.isEmpty()) {
                QStringList secretPerms;
                for (const QJsonValue &p : secrets) secretPerms << p.toString();
                permsList << QString("Secrets: %1").arg(secretPerms.join(", "));
            }
            if (!certs.isEmpty()) {
                QStringList certPerms;
                for (const QJsonValue &p : certs) certPerms << p.toString();
                permsList << QString("Certificates: %1").arg(certPerms.join(", "));
            }

            auto *item = new QTreeWidgetItem(policiesGroup);
            item->setText(0, objectId.left(8) + "...");
            item->setText(1, "Access Policy");
            item->setText(2, tenantId.left(8) + "...");
            item->setText(5, permsList.join(" | "));
            item->setToolTip(0, QString("Object ID: %1\nTenant ID: %2").arg(objectId, tenantId));

            // Highlight dangerous permissions
            QString allPerms = permsList.join(" ");
            if (allPerms.contains("all") || allPerms.contains("purge")) {
                item->setForeground(0, QBrush(QColor("orange")));
                item->setToolTip(5, "HIGH PRIVILEGE: Has 'all' or 'purge' permissions");
            }
        }

        policiesGroup->setExpanded(true);
        appendLog("[*] Note: Object IDs need to be resolved via Graph API to see names", "yellow");
    });
}

void KeyVaultExplorerWindow::copySelectedItem() {
    auto *item = resultsTree->currentItem();
    if (!item) {
        QMessageBox::information(this, "No Selection", "Please select an item to copy.");
        return;
    }

    QString text = QString("Name: %1\nType: %2\nEnabled: %3\nID/Value: %4")
                       .arg(item->text(0), item->text(1), item->text(2), item->text(5));

    QApplication::clipboard()->setText(text);
    appendLog("[+] Copied to clipboard", "green");
}

void KeyVaultExplorerWindow::exportResults() {
    QString filePath = QFileDialog::getSaveFileName(this, "Export Results",
        QDir::homePath() + "/keyvault_export.txt", "Text Files (*.txt);;All Files (*)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "Azure Key Vault Export\n";
    out << "======================\n\n";

    QTreeWidgetItemIterator it(resultsTree);
    while (*it) {
        out << QString("Name: %1 | Type: %2 | Enabled: %3 | ID: %4\n")
               .arg((*it)->text(0), (*it)->text(1), (*it)->text(2), (*it)->text(5));
        ++it;
    }

    file.close();
    appendLog(QString("[+] Exported to %1").arg(filePath), "green");
}

void KeyVaultExplorerWindow::onUserChanged(const QString &upn) {
    // Clear tokens when user changes
    mgmtTokenInput->clear();
    vaultTokenInput->clear();

    if (upn.isEmpty()) {
        updateTokenStatus();
        return;
    }

    // Check for existing tokens for this user
    QString mgmtToken = userSelector->getExistingToken(TokenHelper::RESOURCE_MANAGEMENT);
    QString vaultToken = userSelector->getExistingToken(TokenHelper::RESOURCE_KEY_VAULT);

    if (!mgmtToken.isEmpty()) {
        mgmtTokenInput->setText(mgmtToken);
        appendLog("Found existing Management token", "lime");
    }

    if (!vaultToken.isEmpty()) {
        vaultTokenInput->setText(vaultToken);
        appendLog("Found existing Key Vault token", "lime");
    }

    updateTokenStatus();
}

void KeyVaultExplorerWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        QMessageBox::warning(this, "No User Selected",
            "Please select a user from the dropdown first.");
        return;
    }

    appendLog(QString("Fetching tokens for user: %1").arg(userSelector->selectedUser()), "cyan");
    setLoading(true);
    autoFetchBtn->setEnabled(false);
    autoFetchBtn->setText("Fetching tokens...");

    QStringList resources = {
        TokenHelper::RESOURCE_MANAGEMENT,
        TokenHelper::RESOURCE_KEY_VAULT
    };

    userSelector->fetchTokens(resources,
        [this](bool success, const QMap<QString, QString> &tokens, const QString &error) {
            setLoading(false);
            autoFetchBtn->setEnabled(true);
            autoFetchBtn->setText("Auto-Fetch Tokens for Selected User");

            if (!success && tokens.isEmpty()) {
                appendLog("Failed to fetch tokens: " + error, "red");
                QMessageBox::warning(this, "Token Fetch Failed", error);
                return;
            }

            if (tokens.contains(TokenHelper::RESOURCE_MANAGEMENT)) {
                mgmtTokenInput->setText(tokens[TokenHelper::RESOURCE_MANAGEMENT]);
                appendLog("Management token acquired", "lime");
            }

            if (tokens.contains(TokenHelper::RESOURCE_KEY_VAULT)) {
                vaultTokenInput->setText(tokens[TokenHelper::RESOURCE_KEY_VAULT]);
                appendLog("Key Vault token acquired", "lime");
            }

            updateTokenStatus();

            if (!error.isEmpty()) {
                appendLog("Some tokens failed: " + error, "orange");
            }
        });
}

void KeyVaultExplorerWindow::updateTokenStatus() {
    auto getAudience = [](const QString &token) -> QString {
        QStringList parts = token.split('.');
        if (parts.size() < 2) return QString();
        QByteArray payload = parts.at(1).toUtf8();
        int pad = (4 - (payload.size() % 4)) % 4;
        payload.append(QByteArray(pad, '='));
        payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
        QJsonDocument doc = QJsonDocument::fromJson(payload);
        return doc.object().value("aud").toString();
    };

    QString mgmtToken = mgmtTokenInput->text().trimmed();
    if (mgmtToken.isEmpty()) {
        mgmtTokenStatus->setText("<span style='color:gray'>Empty</span>");
    } else {
        QString aud = getAudience(mgmtToken);
        if (aud.contains("management.azure.com", Qt::CaseInsensitive)) {
            mgmtTokenStatus->setText("<span style='color:lime'>Valid</span>");
        } else {
            mgmtTokenStatus->setText("<span style='color:orange'>Wrong</span>");
        }
    }

    QString vaultToken = vaultTokenInput->text().trimmed();
    if (vaultToken.isEmpty()) {
        vaultTokenStatus->setText("<span style='color:gray'>Empty</span>");
    } else {
        QString aud = getAudience(vaultToken);
        if (aud.contains("vault.azure.net", Qt::CaseInsensitive)) {
            vaultTokenStatus->setText("<span style='color:lime'>Valid</span>");
        } else {
            vaultTokenStatus->setText("<span style='color:orange'>Wrong</span>");
        }
    }
}
