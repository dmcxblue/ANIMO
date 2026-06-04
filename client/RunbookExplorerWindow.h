#ifndef RUNBOOKEXPLORERWINDOW_H
#define RUNBOOKEXPLORERWINDOW_H

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

class RunbookExplorerWindow : public QWidget {
    Q_OBJECT

public:
    explicit RunbookExplorerWindow(QWidget *parent = nullptr);
    ~RunbookExplorerWindow();

private slots:
    void enumerateAutomationAccounts();
    void onAccountSelected(int index);
    void listRunbooks();
    void listVariables();
    void listCredentials();
    void listConnections();
    void getRunbookContent();
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
    QComboBox *accountCombo;
    QPushButton *enumAccountsBtn;
    QPushButton *listRunbooksBtn;
    QPushButton *listVarsBtn;
    QPushButton *listCredsBtn;
    QPushButton *listConnsBtn;
    QPushButton *getContentBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *resultsTree;
    QPlainTextEdit *contentArea;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;

    QJsonArray subscriptions;
    QJsonArray automationAccounts;
    QString currentSubscriptionId;
    QString currentAccountId;
    QString currentAccountName;
    QString currentResourceGroup;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // RUNBOOKEXPLORERWINDOW_H
