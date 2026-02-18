#ifndef AZUREENUMWINDOW_H
#define AZUREENUMWINDOW_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidget>
#include <QTextEdit>
#include <QComboBox>
#include <QProgressBar>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonArray>
#include <QList>

class UserSelectorWidget;

class AzureEnumWindow : public QWidget {
    Q_OBJECT

public:
    explicit AzureEnumWindow(QWidget *parent = nullptr);
    ~AzureEnumWindow();

private slots:
    void enumerateSubscriptions();
    void enumerateResources();
    void enumerateManagedIdentities();
    void onSubscriptionSelected(int index);
    void copySelectedItem();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void cancelRequests();

private:
    void setupUi();
    QNetworkRequest bearerRequest(const QString &url, const QString &token);
    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);
    void updateTokenStatus();

    // User selection
    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;

    QLineEdit *tokenInput;
    QComboBox *subscriptionCombo;
    QPushButton *enumSubsBtn;
    QPushButton *enumResourcesBtn;
    QPushButton *enumManagedIdBtn;
    QPushButton *cancelBtn;
    QPushButton *copyBtn;
    QTreeWidget *resultsTree;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;

    QJsonArray subscriptions;
    QString currentSubscriptionId;
    QList<QNetworkReply*> activeReplies;
    bool cancelRequested = false;
};

#endif // AZUREENUMWINDOW_H
