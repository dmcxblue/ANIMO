#ifndef AZURESTORAGEWINDOW_H
#define AZURESTORAGEWINDOW_H

#include <QWidget>
#include <atomic>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidget>
#include <QTextEdit>
#include <QComboBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonArray>
#include <QLabel>
#include <QProgressBar>

class UserSelectorWidget;

class AzureStorageWindow : public QWidget {
    Q_OBJECT

public:
    explicit AzureStorageWindow(QWidget *parent = nullptr);
    ~AzureStorageWindow();

private slots:
    void listStorageAccounts();
    void onStorageAccountSelected(int index);
    void listContainers();
    void listBlobs();
    void onContainerSelected(QTreeWidgetItem *item, int column);
    void downloadBlob();
    void copyBlobUrl();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void cancelRequests();

private:
    void setupUi();
    void updateTokenStatus();
    QNetworkRequest armRequest(const QString &url, const QString &token);
    QNetworkRequest storageRequest(const QString &url, const QString &token);
    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);

    UserSelectorWidget *userSelector;
    QLineEdit *mgmtTokenInput;
    QLineEdit *storageTokenInput;
    QPushButton *autoFetchBtn;
    QLabel *mgmtTokenStatus;
    QLabel *storageTokenStatus;
    QProgressBar *progressBar;
    QLineEdit *subscriptionInput;
    QComboBox *storageAccountCombo;
    QPushButton *listAccountsBtn;
    QPushButton *listContainersBtn;
    QPushButton *downloadBtn;
    QPushButton *copyUrlBtn;
    QTreeWidget *storageTree;
    QTextEdit *logOutput;
    QNetworkAccessManager *net;

    QString currentStorageAccount;
    QString currentContainer;
    QJsonArray storageAccounts;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // AZURESTORAGEWINDOW_H
