#ifndef CREDENTIALLOGINWINDOW_H
#define CREDENTIALLOGINWINDOW_H

#include <QWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QString>
#include <QProcess>

class DashboardWindow;

class CredentialLoginWindow : public QWidget {
    Q_OBJECT
public:
    explicit CredentialLoginWindow(DashboardWindow *parentDashboard,
                                   QWidget *parent = nullptr);

private slots:
    void handleLogin();
    void onMsalProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onMsalProcessError(QProcess::ProcessError error);

private:
    void setupUi();
    void restoreUi();
    void launchMsalAuth();
    void handleMsalResult(const QByteArray &output);
    void createSessionWithTokens(const QString &accessToken,
                                 const QString &refreshToken,
                                 const QString &tenantId,
                                 const QString &upn);
    void logTokenToServer(const QString &sessionId,
                         const QString &accessToken,
                         const QString &refreshToken,
                         const QString &user,
                         const QString &tenantId,
                         const QString &resource);
    QObject* locateTransport() const;
    QString findMsalScript() const;

private:
    DashboardWindow *parentDashboard = nullptr;
    QComboBox *resourceDropdown = nullptr;
    QLineEdit *username = nullptr;
    QLineEdit *password = nullptr;

    QString pendingRid;
    QString pendingResource;
    QString pendingUsername;
    bool    hookConnected = false;
    QProcess *msalProcess = nullptr;

    // Token logging
    QString pendingAccessToken;
    QString pendingRefreshToken;
    QString pendingUser;
    QString pendingTenantId;

    // Guard against duplicate session_created handling
    bool sessionHandled = false;

    // Store connection for cleanup
    QMetaObject::Connection transportConnection;
};

#endif // CREDENTIALLOGINWINDOW_H
