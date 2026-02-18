#ifndef SQLDATABASEWINDOW_H
#define SQLDATABASEWINDOW_H

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
#include <QProcess>
#include <QLabel>

class SqlDatabaseWindow : public QWidget {
    Q_OBJECT

public:
    explicit SqlDatabaseWindow(QWidget *parent = nullptr);
    ~SqlDatabaseWindow();

private slots:
    void enumerateSqlServers();
    void onServerSelected(int index);
    void listDatabases();
    void listFirewallRules();
    void getServerDetails();
    void copySelectedItem();
    void exportResults();
    void downloadDatabaseSchema();
    void downloadTableData();
    void autoFetchTokens();
    void onUserSelected(int index);
    void refreshUserList();
    void cancelRequests();

private:
    void setupUi();
    void checkExistingTokens();
    void updateTokenStatus();
    QNetworkRequest bearerRequest(const QString &url, const QString &token);
    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);

    // Token validation
    QString getTokenAudience(const QString &token);
    QString getTokenClaim(const QString &token, const QString &claim);
    bool validateSqlToken(const QString &token);

    // Schema download
    void executeSchemaQuery(const QString &dbName);
    void parseSchemaOutput(const QString &output);

    // UI elements
    QComboBox *userSelector;
    QLineEdit *mgmtTokenInput;
    QLineEdit *sqlTokenInput;
    QPushButton *autoFetchBtn;
    QLabel *mgmtTokenStatus;
    QLabel *sqlTokenStatus;

    // Current user context
    QString selectedUpn;
    QComboBox *subscriptionCombo;
    QComboBox *serverCombo;
    QComboBox *databaseCombo;
    QPushButton *enumServersBtn;
    QPushButton *listDatabasesBtn;
    QPushButton *listFirewallBtn;
    QPushButton *serverDetailsBtn;
    QPushButton *downloadSchemaBtn;
    QPushButton *downloadDataBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *resultsTree;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;
    QProcess *pwshProcess;

    // Data storage
    QJsonArray subscriptions;
    QJsonArray sqlServers;
    QJsonArray databases;
    QString currentSubscriptionId;
    QString currentServerId;
    QString currentServerName;
    QString currentServerFqdn;
    QString currentDbName;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    bool cancelRequested = false;
};

#endif // SQLDATABASEWINDOW_H
