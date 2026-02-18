#pragma once
#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QJsonObject>
#include <QLabel>  

class DashboardWindow;

class TokenLoginWindow : public QWidget {
    Q_OBJECT
public:
    explicit TokenLoginWindow(DashboardWindow *parentDashboard, QWidget *parent = nullptr);

private:
    void setupUi();
    void wireTransport();
    QObject* locateTransport() const;
    void sendNewSessionWithTokens(const QString &accessToken,
                                  const QString &refreshToken,
                                  const QString &aud,
                                  const QString &upn,
                                  const QString &tenantId,
                                  const QString &domain);
    void logTokenToServer(const QString &sessionId,
                         const QString &accessToken,
                         const QString &refreshToken,
                         const QString &user,
                         const QString &tenantId,
                         const QString &resource);

private:
    DashboardWindow *parentDashboard = nullptr;

    // UI
    QTextEdit   *accessEdit   = nullptr;
    QTextEdit   *refreshEdit  = nullptr;
    QLineEdit   *audLine      = nullptr;
    QLineEdit   *upnLine      = nullptr;
    QLineEdit   *tidLine      = nullptr;
    QLineEdit   *domainLine   = nullptr;
    QPushButton *startBtn     = nullptr;
    QLabel      *statusLabel  = nullptr;

    // Protocol
    QString pendingRid;
    bool hookConnected = false;

    // Token logging
    QString pendingAccessToken;
    QString pendingRefreshToken;
    QString pendingUser;
    QString pendingTenantId;
    QString pendingResource;

    // Guard against duplicate session_created handling
    bool sessionHandled = false;
};
