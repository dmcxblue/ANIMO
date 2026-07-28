#ifndef ADDAZADAPPSECRET_H
#define ADDAZADAPPSECRET_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QLabel>
#include <QScrollBar>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QUrlQuery>

class UserSelectorWidget;

class AddAzADAppSecret : public QWidget {
    Q_OBJECT

public:
    explicit AddAzADAppSecret(QWidget *parent = nullptr);

private slots:
    void startAttack();
    void handleListAppsReply();
    void autoFetchTokens();

private:
    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLineEdit *tokenInput;
    QPushButton *startButton;
    QTextEdit *outputBox;
    QNetworkAccessManager *net;

    QString currentToken;
    QList<QJsonObject> applications; // Cached list of applications
    int currentIndex = 0;
    int pendingRequests = 0;

    void log(const QString &text);
    void listApps(const QString &token);
    void processNextApp();
    void addPassword(const QString &token, const QString &appId,
                     const QString &appName, const QString &appAppId);
    QString parseJwtAud(const QString &token);
};

#endif // ADDAZADAPPSECRET_H
