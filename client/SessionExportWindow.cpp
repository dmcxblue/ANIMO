#include "SessionExportWindow.h"
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

SessionExportWindow::SessionExportWindow(ClientTransport *transport, QWidget *parent)
    : QDialog(parent)
    , m_transport(transport)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Export Sessions & Tokens");
    setMinimumWidth(450);
    setModal(true);
    setupUi();

    // Connect to transport for server responses
    if (m_transport) {
        connect(m_transport, &ClientTransport::messageReceived,
                this, &SessionExportWindow::onServerResponse);
    }
}

void SessionExportWindow::setupUi() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(12);

    // What to export group
    QGroupBox *contentGroup = new QGroupBox("Export Contents", this);
    QVBoxLayout *contentLayout = new QVBoxLayout(contentGroup);

    m_includeSessions = new QCheckBox("Sessions (metadata, tenant info)", this);
    m_includeSessions->setChecked(true);
    m_includeSessions->setEnabled(false); // Always include sessions

    m_includeTokens = new QCheckBox("Tokens (access, refresh, ID tokens)", this);
    m_includeTokens->setChecked(true);

    m_includeHistory = new QCheckBox("Command History", this);
    m_includeHistory->setChecked(false);

    contentLayout->addWidget(m_includeSessions);
    contentLayout->addWidget(m_includeTokens);
    contentLayout->addWidget(m_includeHistory);
    mainLayout->addWidget(contentGroup);

    // Encryption settings group
    QGroupBox *encryptionGroup = new QGroupBox("Encryption Settings", this);
    QFormLayout *encryptionLayout = new QFormLayout(encryptionGroup);

    m_operatorNameEdit = new QLineEdit(this);
    m_operatorNameEdit->setPlaceholderText("e.g., operator1, redteam");
    encryptionLayout->addRow("Operator Name:", m_operatorNameEdit);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText("Minimum 8 characters");
    connect(m_passwordEdit, &QLineEdit::textChanged, this, &SessionExportWindow::validateInputs);
    encryptionLayout->addRow("Password:", m_passwordEdit);

    m_confirmPasswordEdit = new QLineEdit(this);
    m_confirmPasswordEdit->setEchoMode(QLineEdit::Password);
    m_confirmPasswordEdit->setPlaceholderText("Confirm password");
    connect(m_confirmPasswordEdit, &QLineEdit::textChanged, this, &SessionExportWindow::validateInputs);
    encryptionLayout->addRow("Confirm:", m_confirmPasswordEdit);

    m_passwordMatchLabel = new QLabel(this);
    m_passwordMatchLabel->setStyleSheet("color: gray;");
    encryptionLayout->addRow("", m_passwordMatchLabel);

    mainLayout->addWidget(encryptionGroup);

    // Status and progress
    m_statusLabel = new QLabel("Ready to export", this);
    m_statusLabel->setStyleSheet("color: gray;");
    mainLayout->addWidget(m_statusLabel);

    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setRange(0, 0); // Indeterminate
    mainLayout->addWidget(m_progressBar);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    m_cancelButton = new QPushButton("Cancel", this);
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(m_cancelButton);

    m_exportButton = new QPushButton("Export...", this);
    m_exportButton->setEnabled(false);
    m_exportButton->setDefault(true);
    connect(m_exportButton, &QPushButton::clicked, this, &SessionExportWindow::onExportClicked);
    buttonLayout->addWidget(m_exportButton);

    mainLayout->addLayout(buttonLayout);

    // Info label
    QLabel *infoLabel = new QLabel(
        "<small>Export file will be encrypted with AES-256-GCM.<br>"
        "Share the password securely with other operators.</small>", this);
    infoLabel->setStyleSheet("color: gray;");
    infoLabel->setWordWrap(true);
    mainLayout->addWidget(infoLabel);
}

void SessionExportWindow::validateInputs() {
    QString password = m_passwordEdit->text();
    QString confirm = m_confirmPasswordEdit->text();

    bool valid = true;

    if (password.length() < 8) {
        m_passwordMatchLabel->setText("Password must be at least 8 characters");
        m_passwordMatchLabel->setStyleSheet("color: orange;");
        valid = false;
    } else if (password != confirm) {
        m_passwordMatchLabel->setText("Passwords do not match");
        m_passwordMatchLabel->setStyleSheet("color: red;");
        valid = false;
    } else {
        m_passwordMatchLabel->setText("Passwords match");
        m_passwordMatchLabel->setStyleSheet("color: green;");
    }

    m_exportButton->setEnabled(valid && !m_waitingForData);
}

void SessionExportWindow::onExportClicked() {
    // Request data from server first
    requestExportData();
}

void SessionExportWindow::requestExportData() {
    if (!m_transport) {
        QMessageBox::critical(this, "Error", "Not connected to server");
        return;
    }

    m_waitingForData = true;
    m_exportButton->setEnabled(false);
    m_progressBar->setVisible(true);
    m_statusLabel->setText("Requesting data from server...");

    QJsonObject request;
    request[Protocol::F_ACTION] = Protocol::ACTION_GET_REPORT_DATA;
    m_transport->sendJson(request);
}

void SessionExportWindow::onServerResponse(const QJsonObject &response) {
    if (!m_waitingForData) return;

    QString action = response.value(Protocol::F_ACTION).toString();
    QString status = response.value(Protocol::F_STATUS).toString();

    // Check if this is the report data response
    if (response.contains("sessions") || response.contains("tokens")) {
        m_waitingForData = false;
        m_exportData = response;
        performExport(response);
    } else if (status == Protocol::STATUS_ERR) {
        m_waitingForData = false;
        m_progressBar->setVisible(false);
        m_exportButton->setEnabled(true);
        m_statusLabel->setText("Failed to get data from server");
        QMessageBox::critical(this, "Export Failed",
                              response.value(Protocol::F_MESSAGE).toString("Unknown error"));
    }
}

void SessionExportWindow::performExport(const QJsonObject &data) {
    m_statusLabel->setText("Preparing export data...");

    // Build export payload
    QJsonObject exportPayload;

    // Header information
    QJsonObject header;
    header["version"] = "1.0";
    header["exported_at"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    header["operator"] = m_operatorNameEdit->text().trimmed();
    header["include_tokens"] = m_includeTokens->isChecked();
    header["include_history"] = m_includeHistory->isChecked();
    exportPayload["header"] = header;

    // Sessions (always included)
    QJsonArray sessions = data.value("sessions").toArray();
    exportPayload["sessions"] = sessions;
    int sessionCount = sessions.size();

    // Tokens (optional)
    int tokenCount = 0;
    if (m_includeTokens->isChecked()) {
        QJsonArray tokens = data.value("tokens").toArray();
        exportPayload["tokens"] = tokens;
        tokenCount = tokens.size();
    }

    // Command history (optional)
    int commandCount = 0;
    if (m_includeHistory->isChecked()) {
        QJsonArray commands = data.value("commands").toArray();
        exportPayload["commands"] = commands;
        commandCount = commands.size();
    }

    // Serialize to JSON
    QJsonDocument doc(exportPayload);
    QByteArray plaintext = doc.toJson(QJsonDocument::Compact);

    m_statusLabel->setText("Encrypting data...");

    // Encrypt the payload
    QString password = m_passwordEdit->text();
    CryptoHelper::EncryptedData encrypted = CryptoHelper::encrypt(plaintext, password);

    if (!encrypted.success) {
        m_progressBar->setVisible(false);
        m_exportButton->setEnabled(true);
        m_statusLabel->setText("Encryption failed");
        QMessageBox::critical(this, "Encryption Failed", encrypted.errorMessage);
        return;
    }

    // Build the final file structure
    QJsonObject fileData = CryptoHelper::toJson(encrypted);
    fileData["file_type"] = "animo_export";
    fileData["header"] = header; // Include unencrypted header for preview

    // Ask for save location
    QString defaultName = QString("animo_export_%1.animo")
                              .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));

    QString filePath = QFileDialog::getSaveFileName(
        this,
        "Save Encrypted Export",
        defaultName,
        "ANIMO Export Files (*.animo);;All Files (*)"
    );

    if (filePath.isEmpty()) {
        m_progressBar->setVisible(false);
        m_exportButton->setEnabled(true);
        m_statusLabel->setText("Export cancelled");
        return;
    }

    // Ensure .animo extension
    if (!filePath.endsWith(".animo", Qt::CaseInsensitive)) {
        filePath += ".animo";
    }

    m_statusLabel->setText("Saving file...");

    if (saveEncryptedFile(filePath, fileData)) {
        m_progressBar->setVisible(false);
        m_statusLabel->setText("Export complete!");
        m_statusLabel->setStyleSheet("color: green;");

        QString summary = QString(
            "Export saved successfully!\n\n"
            "File: %1\n\n"
            "Contents:\n"
            "- %2 session(s)\n"
            "- %3 token(s)\n"
            "- %4 command(s)\n\n"
            "Remember to share the password securely with other operators."
        ).arg(filePath)
         .arg(sessionCount)
         .arg(tokenCount)
         .arg(commandCount);

        QMessageBox::information(this, "Export Complete", summary);

        LOG_INFO("SessionExport", QString("Exported %1 sessions, %2 tokens, %3 commands to %4")
                 .arg(sessionCount).arg(tokenCount).arg(commandCount).arg(filePath));

        accept(); // Close dialog
    } else {
        m_progressBar->setVisible(false);
        m_exportButton->setEnabled(true);
        m_statusLabel->setText("Failed to save file");
        QMessageBox::critical(this, "Save Failed", "Could not write to file: " + filePath);
    }
}

bool SessionExportWindow::saveEncryptedFile(const QString &filePath, const QJsonObject &encryptedData) {
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        LOG_ERROR("SessionExport", "Failed to open file for writing: " + filePath);
        return false;
    }

    QJsonDocument doc(encryptedData);
    QByteArray data = doc.toJson(QJsonDocument::Indented);
    qint64 written = file.write(data);
    file.close();

    return written == data.size();
}
