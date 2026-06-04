#ifndef AZUREVMMANAGERWINDOW_H
#define AZUREVMMANAGERWINDOW_H

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
#include <QProgressBar>
#include <QPlainTextEdit>
#include <QLabel>

class UserSelectorWidget;

class AzureVMManagerWindow : public QWidget {
    Q_OBJECT

public:
    explicit AzureVMManagerWindow(QWidget *parent = nullptr);
    ~AzureVMManagerWindow();

private slots:
    void enumerateVMs();
    void onVMSelected();
    void getVMDetails();
    void runCommand();
    void copySelectedItem();
    void exportResults();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void cancelRequests();

private:
    void setupUi();
    void updateTokenStatus();
    QNetworkRequest bearerRequest(const QString &url, const QString &token);
    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);

    UserSelectorWidget *userSelector;
    QLineEdit *tokenInput;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;
    QComboBox *subscriptionCombo;
    QPushButton *enumVMsBtn;
    QPushButton *detailsBtn;
    QPushButton *runCmdBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *vmTree;
    QPlainTextEdit *commandInput;
    QTextEdit *outputArea;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;

    QJsonArray subscriptions;
    QJsonArray virtualMachines;
    QString currentSubscriptionId;
    QString currentVMId;
    QString currentVMResourceGroup;
    QString currentVMName;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // AZUREVMMANAGERWINDOW_H
