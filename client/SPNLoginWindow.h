#ifndef SPNLOGINWINDOW_H
#define SPNLOGINWINDOW_H

#include <QWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QCloseEvent>

class DashboardWindow;

class SPNLoginWindow : public QWidget {
    Q_OBJECT
public:
    explicit SPNLoginWindow(DashboardWindow *parentDashboard, QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void setupUi();
    void wireTransport();
    void restoreUi();
    QObject* locateTransport() const;
    void logTokenToServer(const QString &sessionId,
                          const QString &accessToken,
                          const QString &user,
                          const QString &tenantId,
                          const QString &resource);

    // Client-credentials OAuth2 flow (for Graph + other non-Az resources)
    // Convert a tenant domain (e.g. "contoso.com" or "contoso.onmicrosoft.com")
    // into the tenant GUID via login.microsoftonline.com/<x>/.well-known/openid-configuration.
    // Fires the callback with the GUID on success, or an empty string on failure.
    // If the input already looks like a GUID it is returned as-is (no network call).
    void resolveTenantIdAsync(const QString &tenantOrDomain,
                              std::function<void(const QString &tenantId, const QString &err)> then);

    void authenticateClientCredentials(const QString &appId,
                                       const QString &secret,
                                       const QString &tenantId,
                                       const QString &resource);
    void createSessionWithToken(const QString &accessToken,
                                const QString &resource,
                                const QString &appId,
                                const QString &tenantId);

    // Server-side PowerShell flow (for Azure Management)
    void authenticateViaPowerShell(const QString &appId,
                                   const QString &secret,
                                   const QString &tenantId);

private:
    DashboardWindow *parentDashboard = nullptr;
    QNetworkAccessManager *net = nullptr;

    QComboBox   *resourceDropdown = nullptr;
    QLineEdit   *appIdEdit      = nullptr;
    QLineEdit   *secretEdit     = nullptr;
    QLineEdit   *tenantIdEdit   = nullptr;
    QLineEdit   *accessTokenEdit = nullptr;  // optional: log in directly with an SPN access token
    QPushButton *loginBtn       = nullptr;
    QLabel      *statusLabel    = nullptr;

    QString pendingRid;
    QString pendingResource;
    QString pendingAppId;
    QString pendingTenantId;
    QString pendingSecret;  // stashed for SpnCredentialStore once session_created lands
    bool hookConnected   = false;
    bool sessionHandled  = false;

    // Request tracking for cleanup on close
    QList<QNetworkReply*> activeReplies;
};

#endif // SPNLOGINWINDOW_H
