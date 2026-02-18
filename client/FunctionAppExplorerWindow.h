#ifndef FUNCTIONAPPEXPLORERWINDOW_H
#define FUNCTIONAPPEXPLORERWINDOW_H

#include <QWidget>
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

class FunctionAppExplorerWindow : public QWidget {
    Q_OBJECT

public:
    explicit FunctionAppExplorerWindow(QWidget *parent = nullptr);
    ~FunctionAppExplorerWindow();

private slots:
    void enumerateFunctionApps();
    void onAppSelected(int index);
    void listFunctions();
    void getAppSettings();
    void getConnectionStrings();
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
    QPushButton *listFuncsBtn;
    QPushButton *getSettingsBtn;
    QPushButton *getConnStrBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *resultsTree;
    QPlainTextEdit *contentArea;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;

    QJsonArray subscriptions;
    QJsonArray functionApps;
    QString currentSubscriptionId;
    QString currentAppId;
    QString currentAppName;
    QString currentResourceGroup;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    bool cancelRequested = false;
};

#endif // FUNCTIONAPPEXPLORERWINDOW_H
