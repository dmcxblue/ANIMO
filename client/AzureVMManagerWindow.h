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
    // Issues the runCommand POST; retries itself on HTTP 409 (VM busy).
    void postRunCommand(const QString &token, const QString &url, const QJsonObject &body);
    // Polls the ARM async-operation URL until the runCommand completes and
    // renders the final output. Azure's runCommand is a long-running op:
    // the initial POST returns 202 + Azure-AsyncOperation header, and the
    // script output only shows up in the poll response once status=Succeeded.
    void pollRunCommand(const QString &token, const QString &asyncUrl, int attempt);

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

    // Azure allows only ONE runCommand at a time per VM; guard against concurrent
    // invocations (which return HTTP 409) and auto-retry once after a short wait.
    bool runCommandInProgress = false;
    int  runCommandRetries = 0;
};

#endif // AZUREVMMANAGERWINDOW_H
