#ifndef LOGICAPPSVIEWERWINDOW_H
#define LOGICAPPSVIEWERWINDOW_H

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

class LogicAppsViewerWindow : public QWidget {
    Q_OBJECT

public:
    explicit LogicAppsViewerWindow(QWidget *parent = nullptr);
    ~LogicAppsViewerWindow();

private slots:
    void enumerateLogicApps();
    void onAppSelected(int index);
    void getWorkflowDefinition();
    void listTriggers();
    void listRunHistory();
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
    QComboBox *appCombo;
    QPushButton *enumAppsBtn;
    QPushButton *getDefBtn;
    QPushButton *triggersBtn;
    QPushButton *historyBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *resultsTree;
    QPlainTextEdit *contentArea;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;

    QJsonArray subscriptions;
    QJsonArray logicApps;
    QString currentSubscriptionId;
    QString currentAppId;
    QString currentAppName;
    QString currentResourceGroup;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // LOGICAPPSVIEWERWINDOW_H
