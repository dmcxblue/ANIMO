#include "ReportDialog.h"
#include "DashboardWindow.h"
#include "ReportGenerator.h"
#include "network/ClientTransport.h"
#include "../shared/Protocol.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDateTime>
#include <QApplication>

ReportDialog::ReportDialog(DashboardWindow *parent)
    : QDialog(parent),
      m_parentDashboard(parent)
{
    setWindowTitle("Generate Engagement Report");
    setMinimumWidth(600);
    setupUI();
}

void ReportDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Report Information Group
    QGroupBox *infoGroup = new QGroupBox("Report Information", this);
    QFormLayout *infoLayout = new QFormLayout(infoGroup);

    m_engagementNameEdit = new QLineEdit(this);
    m_engagementNameEdit->setPlaceholderText("e.g., Azure AD Security Assessment");
    infoLayout->addRow("Engagement Name:", m_engagementNameEdit);

    m_operatorNameEdit = new QLineEdit(this);
    m_operatorNameEdit->setPlaceholderText("e.g., John Doe");
    infoLayout->addRow("Operator:", m_operatorNameEdit);

    m_clientNameEdit = new QLineEdit(this);
    m_clientNameEdit->setPlaceholderText("e.g., Acme Corporation");
    infoLayout->addRow("Client:", m_clientNameEdit);

    m_startDateEdit = new QDateTimeEdit(QDateTime::currentDateTime().addDays(-7), this);
    m_startDateEdit->setCalendarPopup(true);
    m_startDateEdit->setDisplayFormat("yyyy-MM-dd HH:mm");
    infoLayout->addRow("Start Date:", m_startDateEdit);

    m_endDateEdit = new QDateTimeEdit(QDateTime::currentDateTime(), this);
    m_endDateEdit->setCalendarPopup(true);
    m_endDateEdit->setDisplayFormat("yyyy-MM-dd HH:mm");
    infoLayout->addRow("End Date:", m_endDateEdit);

    mainLayout->addWidget(infoGroup);

    // Include Sections Group
    QGroupBox *sectionsGroup = new QGroupBox("Report Sections", this);
    QVBoxLayout *sectionsLayout = new QVBoxLayout(sectionsGroup);

    m_includeSessions = new QCheckBox("Include Sessions", this);
    m_includeSessions->setChecked(true);
    sectionsLayout->addWidget(m_includeSessions);

    m_includeTokens = new QCheckBox("Include Captured Tokens", this);
    m_includeTokens->setChecked(true);
    sectionsLayout->addWidget(m_includeTokens);

    m_includeCommands = new QCheckBox("Include Command History", this);
    m_includeCommands->setChecked(true);
    sectionsLayout->addWidget(m_includeCommands);

    m_includeTimeline = new QCheckBox("Include Timeline", this);
    m_includeTimeline->setChecked(true);
    sectionsLayout->addWidget(m_includeTimeline);

    mainLayout->addWidget(sectionsGroup);

    // Export Options Group
    QGroupBox *exportGroup = new QGroupBox("Quick Export", this);
    QVBoxLayout *exportLayout = new QVBoxLayout(exportGroup);

    QLabel *exportLabel = new QLabel("Export specific data without generating full report:", this);
    exportLabel->setWordWrap(true);
    exportLayout->addWidget(exportLabel);

    QHBoxLayout *exportButtonsLayout = new QHBoxLayout();

    m_exportSessionsButton = new QPushButton("Export Sessions (JSON)", this);
    connect(m_exportSessionsButton, &QPushButton::clicked, this, &ReportDialog::onExportSessions);
    exportButtonsLayout->addWidget(m_exportSessionsButton);

    m_exportTokensButton = new QPushButton("Export Tokens (CSV)", this);
    connect(m_exportTokensButton, &QPushButton::clicked, this, &ReportDialog::onExportTokens);
    exportButtonsLayout->addWidget(m_exportTokensButton);

    m_exportCommandsButton = new QPushButton("Export Commands (CSV)", this);
    connect(m_exportCommandsButton, &QPushButton::clicked, this, &ReportDialog::onExportCommands);
    exportButtonsLayout->addWidget(m_exportCommandsButton);

    exportLayout->addLayout(exportButtonsLayout);
    mainLayout->addWidget(exportGroup);

    // Status and Progress
    m_statusLabel = new QLabel("Ready to generate report", this);
    mainLayout->addWidget(m_statusLabel);

    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    mainLayout->addWidget(m_progressBar);

    // Action Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    m_generateButton = new QPushButton("Generate HTML Report", this);
    m_generateButton->setDefault(true);
    connect(m_generateButton, &QPushButton::clicked, this, &ReportDialog::onGenerateReport);
    buttonLayout->addWidget(m_generateButton);

    m_closeButton = new QPushButton("Close", this);
    connect(m_closeButton, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(m_closeButton);

    mainLayout->addLayout(buttonLayout);
}

void ReportDialog::onGenerateReport() {
    // Validate inputs
    if (m_engagementNameEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please enter an engagement name.");
        return;
    }

    // Ask user where to save the report
    QString fileName = QFileDialog::getSaveFileName(
        this,
        "Save Report",
        "ANIMO_Report_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".html",
        "HTML Files (*.html);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;
    }

    m_statusLabel->setText("Fetching report data...");
    m_progressBar->setVisible(true);
    m_progressBar->setValue(10);
    m_generateButton->setEnabled(false);

    // Store the pending file path and fetch data from server
    m_pendingReportPath = fileName;

    m_progressBar->setValue(20);

    // Fetch real data from the server
    fetchReportData();
}

void ReportDialog::onExportSessions() {
    QString fileName = QFileDialog::getSaveFileName(
        this,
        "Export Sessions",
        "sessions_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".json",
        "JSON Files (*.json);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;
    }

    // Use cached data if available
    QJsonArray sessions = m_sessions;
    if (sessions.isEmpty() && !m_reportData.isEmpty()) {
        sessions = m_reportData.value("sessions").toArray();
    }

    if (sessions.isEmpty()) {
        QMessageBox::warning(this, "No Data",
            "No session data available. Generate a report first to fetch data.");
        return;
    }

    QString jsonData = ReportGenerator::exportSessionsToJSON(sessions);

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << jsonData;
        file.close();
        QMessageBox::information(this, "Success", "Sessions exported successfully!");
    } else {
        QMessageBox::critical(this, "Error", "Failed to export sessions.");
    }
}

void ReportDialog::onExportTokens() {
    QString fileName = QFileDialog::getSaveFileName(
        this,
        "Export Tokens",
        "tokens_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".csv",
        "CSV Files (*.csv);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;
    }

    // Use cached data if available
    QJsonArray tokens = m_tokens;
    if (tokens.isEmpty() && !m_reportData.isEmpty()) {
        tokens = m_reportData.value("tokens").toArray();
    }

    if (tokens.isEmpty()) {
        QMessageBox::warning(this, "No Data",
            "No token data available. Generate a report first to fetch data.");
        return;
    }

    QString csvData = ReportGenerator::exportTokensToCSV(tokens);

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << csvData;
        file.close();
        QMessageBox::information(this, "Success", "Tokens exported to CSV successfully!");
    } else {
        QMessageBox::critical(this, "Error", "Failed to export tokens.");
    }
}

void ReportDialog::onExportCommands() {
    QString fileName = QFileDialog::getSaveFileName(
        this,
        "Export Commands",
        "commands_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".csv",
        "CSV Files (*.csv);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;
    }

    // Use cached data if available, otherwise fetch
    QJsonArray commands = m_commands;
    if (commands.isEmpty() && !m_reportData.isEmpty()) {
        commands = m_reportData.value("commands").toArray();
    }

    if (commands.isEmpty()) {
        QMessageBox::warning(this, "No Data",
            "No command data available. Generate a report first to fetch data.");
        return;
    }

    QString csvData = ReportGenerator::exportCommandsToCSV(commands);

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << csvData;
        file.close();
        QMessageBox::information(this, "Success", "Commands exported to CSV successfully!");
    } else {
        QMessageBox::critical(this, "Error", "Failed to export commands.");
    }
}

QObject* ReportDialog::locateTransport() {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (m_parentDashboard) {
        if (auto *t = m_parentDashboard->findChild<ClientTransport*>()) return t;
    }
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    if (m_parentDashboard) {
        if (auto *o = m_parentDashboard->findChild<QObject*>("ClientTransport", Qt::FindChildrenRecursively))
            return o;
    }
    return nullptr;
}

void ReportDialog::fetchReportData() {
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        m_statusLabel->setText("Error: No server connection");
        QMessageBox::warning(this, "Connection Error",
            "No server connection found. Please ensure you are connected to the server.");
        m_generateButton->setEnabled(true);
        m_progressBar->setVisible(false);
        return;
    }

    // Build request with date filters
    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_GET_REPORT_DATA);
    req.insert("start_date", m_startDateEdit->dateTime().toString(Qt::ISODate));
    req.insert("end_date", m_endDateEdit->dateTime().toString(Qt::ISODate));

    // Connect to receive response
    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        // Disconnect any previous connections
        disconnect(typed, &ClientTransport::messageReceived, this, nullptr);

        connect(typed, &ClientTransport::messageReceived, this,
            [this](const QJsonObject &msg) {
                QString status = msg.value(Protocol::F_STATUS).toString();
                QString message = msg.value(Protocol::F_MESSAGE).toString();
                if (status == Protocol::STATUS_OK && message == "report data retrieved") {
                    onReportDataReceived(msg);
                }
            });

        typed->sendJson(req);
        m_statusLabel->setText("Fetching report data from server...");
    } else {
        // Fallback: invoke sendJson via meta-object
        bool ok = QMetaObject::invokeMethod(transportObj, "sendJson",
                                            Q_ARG(QJsonObject, req));
        if (!ok) {
            m_statusLabel->setText("Error: Failed to send request");
            m_generateButton->setEnabled(true);
            m_progressBar->setVisible(false);
        } else {
            m_statusLabel->setText("Fetching report data from server...");
        }
    }
}

void ReportDialog::onReportDataReceived(const QJsonObject &data) {
    m_progressBar->setValue(60);

    // Check for error status (server sends "status": "ok" or "status": "error")
    QString status = data.value(Protocol::F_STATUS).toString();
    if (status == Protocol::STATUS_ERR) {
        QString error = data.value(Protocol::F_MESSAGE).toString("Unknown error");
        m_statusLabel->setText("Error: " + error);
        QMessageBox::critical(this, "Error", "Failed to fetch report data: " + error);
        m_generateButton->setEnabled(true);
        m_progressBar->setVisible(false);
        return;
    }

    // The report data is inside the "report" key
    QJsonObject reportObj = data.value("report").toObject();

    // Cache the report data
    m_reportData = reportObj;
    m_sessions = reportObj.value("sessions").toArray();
    m_tokens = reportObj.value("tokens").toArray();
    m_commands = reportObj.value("commands").toArray();

    m_statusLabel->setText("Data received. Generating report...");
    m_progressBar->setValue(70);

    // Now generate the report with the fetched data
    if (!m_pendingReportPath.isEmpty()) {
        generateReportWithData(reportObj);
    }
}

void ReportDialog::generateReportWithData(const QJsonObject &reportData) {
    ReportGenerator generator;
    generator.setTitle("ANIMO Engagement Report");
    generator.setEngagementName(m_engagementNameEdit->text());
    generator.setOperatorName(m_operatorNameEdit->text().isEmpty() ? "Unknown" : m_operatorNameEdit->text());
    generator.setClientName(m_clientNameEdit->text().isEmpty() ? "Unknown" : m_clientNameEdit->text());
    generator.setDateRange(m_startDateEdit->dateTime(), m_endDateEdit->dateTime());

    m_progressBar->setValue(75);

    // Add sessions
    if (m_includeSessions->isChecked()) {
        QJsonArray sessions = reportData.value("sessions").toArray();
        generator.addSessions(sessions);
    }

    // Add tokens
    if (m_includeTokens->isChecked()) {
        QJsonArray tokens = reportData.value("tokens").toArray();
        generator.addTokens(tokens);
    }

    m_progressBar->setValue(80);

    // Add commands
    if (m_includeCommands->isChecked()) {
        QJsonArray commands = reportData.value("commands").toArray();
        generator.addCommandHistory(commands);
    }

    // Add timeline
    if (m_includeTimeline->isChecked()) {
        QJsonArray timeline = reportData.value("timeline").toArray();
        generator.addTimeline(timeline);
    }

    m_progressBar->setValue(85);

    // Add techniques (categorized attack types)
    QJsonObject techniques = reportData.value("techniques").toObject();
    generator.addTechniques(techniques);

    // Add unique users and tenants
    QJsonArray uniqueUsers = reportData.value("unique_users").toArray();
    QJsonArray uniqueTenants = reportData.value("unique_tenants").toArray();
    generator.addUniqueUsers(uniqueUsers);
    generator.addUniqueTenants(uniqueTenants);

    m_progressBar->setValue(90);

    // Generate and save report
    bool success = generator.saveHTMLReport(m_pendingReportPath);

    m_progressBar->setValue(100);

    if (success) {
        m_statusLabel->setText("Report generated successfully!");

        // Build summary
        QJsonObject summary = reportData.value("summary").toObject();
        QString summaryText = QString(
            "Report saved to:\n%1\n\n"
            "Summary:\n"
            "- Sessions: %2\n"
            "- Tokens captured: %3\n"
            "- Commands executed: %4\n"
            "- Unique users: %5\n"
            "- Unique tenants: %6"
        ).arg(m_pendingReportPath)
         .arg(summary.value("total_sessions").toInt())
         .arg(summary.value("total_tokens").toInt())
         .arg(summary.value("total_commands").toInt())
         .arg(uniqueUsers.size())
         .arg(uniqueTenants.size());

        QMessageBox::information(this, "Success", summaryText);
    } else {
        m_statusLabel->setText("Failed to generate report");
        QMessageBox::critical(this, "Error", "Failed to save report. Check permissions.");
    }

    m_progressBar->setVisible(false);
    m_generateButton->setEnabled(true);
    m_pendingReportPath.clear();
}
