#ifndef SESSIONIMPORTWINDOW_H
#define SESSIONIMPORTWINDOW_H

#include <QDialog>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTableWidget>
#include <QComboBox>
#include <QJsonObject>
#include <QJsonArray>

class ClientTransport;

/**
 * SessionImportWindow - Import sessions and tokens from encrypted file
 *
 * Allows operators to restore encrypted backups containing:
 * - Sessions (session metadata)
 * - Tokens (access/refresh/id tokens)
 * - Command history (if included)
 *
 * Supports merge strategies for existing sessions
 */
class SessionImportWindow : public QDialog {
    Q_OBJECT

public:
    explicit SessionImportWindow(ClientTransport *transport, QWidget *parent = nullptr);

private slots:
    void onBrowseClicked();
    void onDecryptClicked();
    void onImportClicked();
    void onServerResponse(const QJsonObject &response);

private:
    void setupUi();
    bool loadFile(const QString &filePath);
    bool decryptFile(const QString &password);
    void displayPreview();
    void sendImportData();

    ClientTransport *m_transport;

    // UI elements
    QLineEdit *m_filePathEdit;
    QPushButton *m_browseButton;
    QLineEdit *m_passwordEdit;
    QPushButton *m_decryptButton;
    QLabel *m_fileInfoLabel;
    QTableWidget *m_previewTable;
    QComboBox *m_mergeStrategyCombo;
    QLabel *m_statusLabel;
    QPushButton *m_importButton;
    QPushButton *m_cancelButton;
    QProgressBar *m_progressBar;

    // File data
    QString m_loadedFilePath;
    QJsonObject m_fileData;        // Raw file (encrypted)
    QJsonObject m_decryptedData;   // Decrypted payload
    bool m_isDecrypted = false;

    // Import tracking
    int m_pendingImports = 0;
    int m_successCount = 0;
    int m_failCount = 0;
};

#endif // SESSIONIMPORTWINDOW_H
