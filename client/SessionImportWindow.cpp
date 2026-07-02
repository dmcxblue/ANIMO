#include "SessionImportWindow.h"
#include "TokenStore.h"
#include "network/ClientTransport.h"
#include "../shared/CryptoHelper.h"
#include "../shared/Protocol.h"
#include "../shared/ErrorLogger.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QFile>
#include <QHeaderView>

SessionImportWindow::SessionImportWindow(ClientTransport *transport, QWidget *parent)
    : QDialog(parent)
    , m_transport(transport)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Import Sessions & Tokens");
    setMinimumSize(600, 500);
    setModal(true);
    setupUi();

    // Connect to transport for server responses
    if (m_transport) {
        connect(m_transport, &ClientTransport::messageReceived,
                this, &SessionImportWindow::onServerResponse);
    }
}

void SessionImportWindow::setupUi() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(12);

    // File selection group
    QGroupBox *fileGroup = new QGroupBox("Select Export File", this);
    QHBoxLayout *fileLayout = new QHBoxLayout(fileGroup);

    m_filePathEdit = new QLineEdit(this);
    m_filePathEdit->setPlaceholderText("Select an .animo export file...");
    m_filePathEdit->setReadOnly(true);
    fileLayout->addWidget(m_filePathEdit, 1);

    m_browseButton = new QPushButton("Browse...", this);
    connect(m_browseButton, &QPushButton::clicked, this, &SessionImportWindow::onBrowseClicked);
    fileLayout->addWidget(m_browseButton);

    mainLayout->addWidget(fileGroup);

    // File info label
    m_fileInfoLabel = new QLabel(this);
    m_fileInfoLabel->setStyleSheet("color: gray; padding: 4px;");
    m_fileInfoLabel->setWordWrap(true);
    mainLayout->addWidget(m_fileInfoLabel);

    // Password group
    QGroupBox *passwordGroup = new QGroupBox("Decryption", this);
    QHBoxLayout *passwordLayout = new QHBoxLayout(passwordGroup);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText("Enter export password");
    m_passwordEdit->setEnabled(false);
    passwordLayout->addWidget(m_passwordEdit, 1);

    m_decryptButton = new QPushButton("Decrypt", this);
    m_decryptButton->setEnabled(false);
    connect(m_decryptButton, &QPushButton::clicked, this, &SessionImportWindow::onDecryptClicked);
    passwordLayout->addWidget(m_decryptButton);

    mainLayout->addWidget(passwordGroup);

    // Preview table
    QGroupBox *previewGroup = new QGroupBox("Preview", this);
    QVBoxLayout *previewLayout = new QVBoxLayout(previewGroup);

    m_previewTable = new QTableWidget(this);
    m_previewTable->setColumnCount(4);
    m_previewTable->setHorizontalHeaderLabels({"Type", "ID/User", "Tenant", "Resource"});
    m_previewTable->horizontalHeader()->setStretchLastSection(true);
    m_previewTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_previewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_previewTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_previewTable->setAlternatingRowColors(true);
    previewLayout->addWidget(m_previewTable);

    mainLayout->addWidget(previewGroup, 1);

    // Import options
    QGroupBox *optionsGroup = new QGroupBox("Import Options", this);
    QFormLayout *optionsLayout = new QFormLayout(optionsGroup);

    m_mergeStrategyCombo = new QComboBox(this);
    m_mergeStrategyCombo->addItem("Skip existing (keep current)", "skip");
    m_mergeStrategyCombo->addItem("Overwrite existing", "overwrite");
    m_mergeStrategyCombo->addItem("Import all (may create duplicates)", "all");
    m_mergeStrategyCombo->setEnabled(false);
    optionsLayout->addRow("Merge Strategy:", m_mergeStrategyCombo);

    mainLayout->addWidget(optionsGroup);

    // Status and progress
    m_statusLabel = new QLabel("Select an export file to begin", this);
    m_statusLabel->setStyleSheet("color: gray;");
    mainLayout->addWidget(m_statusLabel);

    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    mainLayout->addWidget(m_progressBar);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    m_cancelButton = new QPushButton("Cancel", this);
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(m_cancelButton);

    m_importButton = new QPushButton("Import", this);
    m_importButton->setEnabled(false);
    m_importButton->setDefault(true);
    connect(m_importButton, &QPushButton::clicked, this, &SessionImportWindow::onImportClicked);
    buttonLayout->addWidget(m_importButton);

    mainLayout->addLayout(buttonLayout);
}

void SessionImportWindow::onBrowseClicked() {
    QString filePath = QFileDialog::getOpenFileName(
        this,
        "Select Export File",
        QString(),
        "ANIMO Export Files (*.animo);;All Files (*)"
    );

    if (filePath.isEmpty()) return;

    if (loadFile(filePath)) {
        m_filePathEdit->setText(filePath);
        m_passwordEdit->setEnabled(true);
        m_decryptButton->setEnabled(true);
        m_passwordEdit->setFocus();
    }
}

bool SessionImportWindow::loadFile(const QString &filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Error", "Could not open file: " + filePath);
        return false;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);

    if (error.error != QJsonParseError::NoError) {
        QMessageBox::critical(this, "Error",
                              "Invalid file format: " + error.errorString());
        return false;
    }

    m_fileData = doc.object();
    m_loadedFilePath = filePath;

    // Check file type
    if (m_fileData.value("file_type").toString() != "animo_export") {
        QMessageBox::warning(this, "Warning",
                             "This doesn't appear to be an ANIMO export file.");
    }

    // Display header info (unencrypted)
    QJsonObject header = m_fileData.value("header").toObject();
    QString info = QString(
        "Exported: %1\n"
        "Operator: %2\n"
        "Contains tokens: %3\n"
        "Contains history: %4"
    ).arg(header.value("exported_at").toString())
     .arg(header.value("operator").toString())
     .arg(header.value("include_tokens").toBool() ? "Yes" : "No")
     .arg(header.value("include_history").toBool() ? "Yes" : "No");

    m_fileInfoLabel->setText(info);
    m_statusLabel->setText("File loaded. Enter password to decrypt.");

    // Reset state
    m_isDecrypted = false;
    m_decryptedData = QJsonObject();
    m_previewTable->setRowCount(0);
    m_importButton->setEnabled(false);
    m_mergeStrategyCombo->setEnabled(false);

    return true;
}

void SessionImportWindow::onDecryptClicked() {
    QString password = m_passwordEdit->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please enter the password");
        return;
    }

    m_statusLabel->setText("Decrypting...");
    m_decryptButton->setEnabled(false);

    if (decryptFile(password)) {
        m_statusLabel->setText("Decryption successful. Review and import.");
        m_statusLabel->setStyleSheet("color: green;");
        displayPreview();
        m_importButton->setEnabled(true);
        m_mergeStrategyCombo->setEnabled(true);
    } else {
        m_statusLabel->setText("Decryption failed - wrong password?");
        m_statusLabel->setStyleSheet("color: red;");
        m_decryptButton->setEnabled(true);
    }
}

bool SessionImportWindow::decryptFile(const QString &password) {
    // Parse encrypted data
    CryptoHelper::EncryptedData encrypted = CryptoHelper::fromJson(m_fileData);
    if (!encrypted.success) {
        QMessageBox::critical(this, "Error", encrypted.errorMessage);
        return false;
    }

    // Decrypt
    CryptoHelper::DecryptedData decrypted = CryptoHelper::decrypt(
        encrypted.salt,
        encrypted.iv,
        encrypted.ciphertext,
        encrypted.tag,
        password
    );

    if (!decrypted.success) {
        QMessageBox::critical(this, "Decryption Failed", decrypted.errorMessage);
        return false;
    }

    // Parse decrypted JSON
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(decrypted.plaintext, &error);

    if (error.error != QJsonParseError::NoError) {
        QMessageBox::critical(this, "Error",
                              "Decrypted data is corrupted: " + error.errorString());
        return false;
    }

    m_decryptedData = doc.object();
    m_isDecrypted = true;

    LOG_INFO("SessionImport", "Successfully decrypted export file");
    return true;
}

void SessionImportWindow::displayPreview() {
    m_previewTable->setRowCount(0);

    // Add sessions
    QJsonArray sessions = m_decryptedData.value("sessions").toArray();
    for (const QJsonValue &val : sessions) {
        QJsonObject sess = val.toObject();
        int row = m_previewTable->rowCount();
        m_previewTable->insertRow(row);

        m_previewTable->setItem(row, 0, new QTableWidgetItem("Session"));
        m_previewTable->setItem(row, 1, new QTableWidgetItem(sess.value("user").toString()));
        m_previewTable->setItem(row, 2, new QTableWidgetItem(sess.value("tenantId").toString()));
        m_previewTable->setItem(row, 3, new QTableWidgetItem(sess.value("resource").toString()));

        // Color code
        m_previewTable->item(row, 0)->setBackground(QColor(200, 230, 255));
    }

    // Add tokens
    QJsonArray tokens = m_decryptedData.value("tokens").toArray();
    for (const QJsonValue &val : tokens) {
        QJsonObject tok = val.toObject();
        int row = m_previewTable->rowCount();
        m_previewTable->insertRow(row);

        m_previewTable->setItem(row, 0, new QTableWidgetItem("Token"));
        m_previewTable->setItem(row, 1, new QTableWidgetItem(tok.value("user").toString()));
        m_previewTable->setItem(row, 2, new QTableWidgetItem(tok.value("tenant_id").toString()));
        m_previewTable->setItem(row, 3, new QTableWidgetItem(tok.value("resource").toString()));

        // Color code
        m_previewTable->item(row, 0)->setBackground(QColor(255, 230, 200));
    }

    // Add commands count
    QJsonArray commands = m_decryptedData.value("commands").toArray();
    if (!commands.isEmpty()) {
        int row = m_previewTable->rowCount();
        m_previewTable->insertRow(row);
        m_previewTable->setItem(row, 0, new QTableWidgetItem("Commands"));
        m_previewTable->setItem(row, 1, new QTableWidgetItem(QString("%1 entries").arg(commands.size())));
        m_previewTable->setItem(row, 2, new QTableWidgetItem("-"));
        m_previewTable->setItem(row, 3, new QTableWidgetItem("-"));
        m_previewTable->item(row, 0)->setBackground(QColor(230, 255, 200));
    }

    m_statusLabel->setText(QString("Found: %1 sessions, %2 tokens, %3 commands")
                           .arg(sessions.size())
                           .arg(tokens.size())
                           .arg(commands.size()));
}

void SessionImportWindow::onImportClicked() {
    if (!m_isDecrypted || !m_transport) {
        QMessageBox::critical(this, "Error", "Not ready to import");
        return;
    }

    int reply = QMessageBox::question(this, "Confirm Import",
                                      "Import the selected sessions and tokens?",
                                      QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    m_importButton->setEnabled(false);
    m_cancelButton->setEnabled(false);
    m_progressBar->setVisible(true);
    m_statusLabel->setText("Importing...");

    sendImportData();
}

void SessionImportWindow::sendImportData() {
    m_pendingImports = 0;
    m_successCount = 0;
    m_failCount = 0;

    QJsonArray sessions = m_decryptedData.value("sessions").toArray();
    QJsonArray tokens = m_decryptedData.value("tokens").toArray();

    int totalItems = sessions.size() + tokens.size();
    m_progressBar->setRange(0, totalItems);
    m_progressBar->setValue(0);

    // Import sessions first
    for (const QJsonValue &val : sessions) {
        QJsonObject sess = val.toObject();

        QJsonObject request;
        request[Protocol::F_ACTION] = Protocol::ACTION_IMPORT_SESSION;
        request["sessionId"] = sess.value("sessionId").toString();
        request["user"] = sess.value("user").toString();
        request["tenantId"] = sess.value("tenantId").toString();
        request["defaultDomain"] = sess.value("defaultDomain").toString();
        request["resource"] = sess.value("resource").toString();

        m_transport->sendJson(request);
        m_pendingImports++;
    }

    // Import tokens
    for (const QJsonValue &val : tokens) {
        QJsonObject tok = val.toObject();

        QJsonObject request;
        request[Protocol::F_ACTION] = Protocol::ACTION_LOG_TOKEN;
        request["session_id"] = tok.value("session_id").toString();
        request["source"] = tok.value("source").toString() + "_imported";
        request["access_token"] = tok.value("access_token").toString();
        request["refresh_token"] = tok.value("refresh_token").toString();
        request["id_token"] = tok.value("id_token").toString();
        request["user"] = tok.value("user").toString();
        request["tenant_id"] = tok.value("tenant_id").toString();
        request["resource"] = tok.value("resource").toString();
        request["scope"] = tok.value("scope").toString();
        request["expires_in"] = tok.value("expires_in").toInt();

        m_transport->sendJson(request);
        m_pendingImports++;

        // Mirror into TokenStore so imported users show up in every plugin
        // window's UserSelectorWidget without needing to reconnect.
        const QString sessionId = tok.value("session_id").toString();
        if (!sessionId.isEmpty() && !tok.value("access_token").toString().isEmpty()) {
            TokenInfo tokenInfo;
            tokenInfo.accessToken  = tok.value("access_token").toString();
            tokenInfo.refreshToken = tok.value("refresh_token").toString();
            tokenInfo.idToken      = tok.value("id_token").toString();
            tokenInfo.upn          = tok.value("user").toString();
            tokenInfo.tenantId     = tok.value("tenant_id").toString();
            tokenInfo.resource     = tok.value("resource").toString();
            TokenStore::instance()->storeToken(sessionId, tokenInfo);
        }
    }

    if (m_pendingImports == 0) {
        m_statusLabel->setText("Nothing to import");
        m_progressBar->setVisible(false);
        m_cancelButton->setEnabled(true);
    }
}

void SessionImportWindow::onServerResponse(const QJsonObject &response) {
    if (m_pendingImports <= 0) return;

    QString status = response.value(Protocol::F_STATUS).toString();
    QString action = response.value(Protocol::F_ACTION).toString();

    // Check if this is a response to our import actions
    if (response.contains("sessionId") || response.contains("tokenId") ||
        status == Protocol::STATUS_OK || status == Protocol::STATUS_ERR) {

        m_pendingImports--;

        if (status == Protocol::STATUS_OK) {
            m_successCount++;
        } else {
            m_failCount++;
        }

        m_progressBar->setValue(m_successCount + m_failCount);

        // All done?
        if (m_pendingImports <= 0) {
            m_progressBar->setVisible(false);
            m_cancelButton->setEnabled(true);

            QString summary = QString(
                "Import complete!\n\n"
                "Successful: %1\n"
                "Failed: %2"
            ).arg(m_successCount).arg(m_failCount);

            if (m_failCount > 0) {
                m_statusLabel->setText(QString("Import complete with %1 errors").arg(m_failCount));
                m_statusLabel->setStyleSheet("color: orange;");
            } else {
                m_statusLabel->setText("Import complete!");
                m_statusLabel->setStyleSheet("color: green;");
            }

            LOG_INFO("SessionImport", QString("Import complete: %1 success, %2 failed")
                     .arg(m_successCount).arg(m_failCount));

            QMessageBox::information(this, "Import Complete", summary);

            if (m_failCount == 0) {
                accept(); // Close on success
            }
        }
    }
}
