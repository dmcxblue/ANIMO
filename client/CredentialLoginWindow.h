#ifndef CREDENTIALLOGINWINDOW_H
#define CREDENTIALLOGINWINDOW_H

#include <QWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QString>
#include <QProcess>
#include <QCheckBox>

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
    QObject* locateTransport() const;

    // Server-side credential login (Connect-AzAccount -Credential, full token cache)
    void sendCredentialLogin();

    // MSAL interactive login (handles MFA, browser-based)
    QString findMsalScript() const;
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

    void wireTransportHook();

private:
    DashboardWindow *parentDashboard = nullptr;
    QComboBox *resourceDropdown = nullptr;
    QLineEdit *customResource = nullptr;   // Shown only when "Other..." is picked
    QLineEdit *username = nullptr;
    QLineEdit *password = nullptr;

    QString pendingRid;
    QString pendingResource;
    QString pendingUsername;
    bool    hookConnected = false;
    bool    sessionHandled = false;
    QProcess *msalProcess = nullptr;

    // Token logging (MSAL path)
    QString pendingAccessToken;
    QString pendingRefreshToken;
    QString pendingUser;
    QString pendingTenantId;

    QMetaObject::Connection transportConnection;
};

#endif // CREDENTIALLOGINWINDOW_H
