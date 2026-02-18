#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QDateTimeEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QLabel>
#include <QProgressBar>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>

class DashboardWindow;
class ClientTransport;

/**
 * Dialog for generating engagement reports
 * Allows user to configure report parameters and export data
 */
class ReportDialog : public QDialog {
    Q_OBJECT

public:
    explicit ReportDialog(DashboardWindow *parent = nullptr);

private slots:
    void onGenerateReport();
    void onExportSessions();
    void onExportTokens();
    void onExportCommands();
    void onReportDataReceived(const QJsonObject &data);

private:
    void setupUI();
    void fetchReportData();
    QObject* locateTransport();
    void generateReportWithData(const QJsonObject &reportData);

    DashboardWindow *m_parentDashboard;
    QString m_pendingReportPath;

    // Cached report data
    QJsonObject m_reportData;
    QJsonArray m_sessions;
    QJsonArray m_tokens;
    QJsonArray m_commands;

    // UI Components
    QLineEdit *m_engagementNameEdit;
    QLineEdit *m_operatorNameEdit;
    QLineEdit *m_clientNameEdit;
    QDateTimeEdit *m_startDateEdit;
    QDateTimeEdit *m_endDateEdit;

    QCheckBox *m_includeSessions;
    QCheckBox *m_includeTokens;
    QCheckBox *m_includeCommands;
    QCheckBox *m_includeTimeline;

    QPushButton *m_generateButton;
    QPushButton *m_exportSessionsButton;
    QPushButton *m_exportTokensButton;
    QPushButton *m_exportCommandsButton;
    QPushButton *m_closeButton;

    QLabel *m_statusLabel;
    QProgressBar *m_progressBar;
};
