#ifndef SESSIONEXPORTWINDOW_H
#define SESSIONEXPORTWINDOW_H

#include <QDialog>
#include <QCheckBox>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QJsonObject>
#include <QJsonArray>

class ClientTransport;

/**
 * SessionExportWindow - Export sessions and tokens to encrypted file
 *
 * Allows operators to create encrypted backups of:
 * - Sessions (session metadata)
 * - Tokens (access/refresh/id tokens in clear text within encrypted blob)
 * - Command history (optional)
 *
 * Uses AES-256-GCM encryption with password-derived key (PBKDF2)
 */
class SessionExportWindow : public QDialog {
    Q_OBJECT

public:
    explicit SessionExportWindow(ClientTransport *transport, QWidget *parent = nullptr);

private slots:
    void onExportClicked();
    void onServerResponse(const QJsonObject &response);
    void validateInputs();

private:
    void setupUi();
    void requestExportData();
    void performExport(const QJsonObject &data);
    bool saveEncryptedFile(const QString &filePath, const QJsonObject &encryptedData);

    ClientTransport *m_transport;

    // UI elements
    QCheckBox *m_includeSessions;
    QCheckBox *m_includeTokens;
    QCheckBox *m_includeHistory;
    QLineEdit *m_passwordEdit;
    QLineEdit *m_confirmPasswordEdit;
    QLineEdit *m_operatorNameEdit;
    QLabel *m_statusLabel;
    QLabel *m_passwordMatchLabel;
    QPushButton *m_exportButton;
    QPushButton *m_cancelButton;
    QProgressBar *m_progressBar;

    // Export data
    QJsonObject m_exportData;
    bool m_waitingForData = false;
};

#endif // SESSIONEXPORTWINDOW_H
