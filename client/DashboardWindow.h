#ifndef DASHBOARDWINDOW_H
#define DASHBOARDWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QTextEdit>
#include <QTabWidget>
#include <QDebug>
#include <QMap>
#include <QString>
#include <QProcess>
#include <QJsonObject>
#include <QByteArray>
#include <QCloseEvent>
#include <QTimer>
#include <QDateTime>
#include <QTimeZone>
#include <QSettings>

class ClientTransport;
class GraphQueryWindow;
class QLabel;

struct SessionInfo {
    QProcess *psProc = nullptr;
    QString token;
    QString resource;
};

struct TokenExpiry {
    QDateTime expiryTime;
    QString refreshToken;
    QString resource;
    QString tenantId;
    bool autoRenewEnabled = true;
    bool refreshInFlight = false;  // guards against overlapping auto-refreshes
};

class DashboardWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit DashboardWindow(QWidget *parent = nullptr);
    ~DashboardWindow() override = default;

    void setTransport(ClientTransport* t);
    void setOperator(const QString &op);   // show the logged-in operator, colored

    void registerPsSession(const QString &sessionId, QProcess *proc, const QString &token, const QString &resource);
    SessionInfo *getSession(const QString &sessionId);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    QString loginScript;
    QString token;
    QString resource;
    QString username;
    QString tenantId;
    QString defaultDomain;
    QString sessionId;

    QMap<QString, SessionInfo> sessions;

    QTableWidget *sessionTable = nullptr;
    QLabel *operatorChip_ = nullptr;
    QTextEdit *eventLog = nullptr;
    QTabWidget *tabs = nullptr;

    ClientTransport* transport = nullptr;
    GraphQueryWindow* m_graphQueryWindow = nullptr;

    // Token expiry tracking
    QMap<QString, TokenExpiry> tokenExpiryMap;
    QTimer *expiryUpdateTimer = nullptr;
    bool autoRenewEnabled = true;  // Global setting
    bool tokenHelperConnected = false;  // Track TokenHelper signal connection

    void initUI();
    void updateExpiryDisplay();
    void refreshTokenForSession(const QString &sessionId);
    // WS5: after renewing, mint fresh Graph/KeyVault tokens and push them into the
    // session's terminal Az context (server no-ops for full/live sessions).
    void reinjectTerminalTokens(const QString &sessionId, const QString &armToken,
                                const QString &refreshToken, const QString &tenantId);
    QString formatTimeRemaining(const QDateTime &expiry) const;
    QDateTime parseTokenExpiry(const QString &accessToken) const;

public slots:
    void onServerJson(const QJsonObject &obj);

    void launchAccessTokenWindow();
    void launchSPNLoginWindow();
    void launchDeviceCodeWindow();
    void launchIllicitConsentWindow();
    void launchWebhookCaptureWindow();
    void createNewSession();
    void addSessionRow(const QString &sessionId, const QString &username, const QString &tenantId, const QString &domain, const QString &resource, const QDateTime &expiry = QDateTime(), const QString &createdBy = QString());

    void logEvent(const QString &msg);
    void updateSessionRow(const QString &sessionId, const QString &username, const QString &tenantId, const QString &defaultDomain, const QString &resource);
    void removeSessionById(const QString &sessionId);
    void setSessionTokenExpiry(const QString &sessionId, const QString &accessToken, const QString &refreshToken, const QString &resource, const QString &tenantId);
    void toggleAutoRenew(bool enabled);

    void onAzureLoginSuccess(const QString &token, const QString &resource, const QString &sessionId);

    void loadExistingSessions();

    void openUserSessionTab(int row, int column);
    void closeSessionTab(int index);
    void showSessionContextMenu(const QPoint &pos);
    void removeSessionRow(int rowIndex);
	void openGraphQueries();
    void openOnedriveExplorer();
    void openRefreshTokensMenu();
    void openOutlookEmailWindow();
    void openOutlookCalendar();
    void openTeamsChatWindow();
    void openPRTTokenMenu();
    void openSsoTokenMenu();
    void openAttackPasswordSpray();
    void openAttackWfh();
    void openAttackAppSecret();
    void openSPNSpray();
    void openRefreshTokenSpray();
    void openMagicAppFinder();
    void openGatherAllWindow();
    void openTokenLogWindow();
    void openActivityWindow();
    void openTokenAnalysisWindow();
    void openSessionTimelineWindow();
    void openReportDialog();
    void openAzureEnumWindow();
    void openConditionalAccessWindow();
    void openCrossTenantAccessWindow();
    void openMfaStatusChecker();
    void openPasswordWritebackChecker();
    void openOAuthConsentEnumerator();
    void openAzureStorageWindow();
    void openPostExploitWindow();

    // New Discovery features
    void openKeyVaultExplorer();
    void openSqlDatabaseExplorer();
    void openAzureVMManager();
    void openRunbookExplorer();
    void openSPNEnumWindow();
    void openFunctionAppExplorer();
    void openLogicAppsViewer();
    void openWhoAmIWindow();
    void openTenantSearchWindow();

    // Persistence features
    void openEmailRulesWindow();
    void openConsentManipulationWindow();

    // Auto session persistence
    void autoRestoreSessions();
    void autoSaveSession(const QString &sessionId);

    // Session migration (token exchange to different resource)
    void migrateSession(const QString &sourceSessionId, const QString &username,
                        const QString &tenantId, const QString &targetResource);

    // Session export/import
    void openExportSessionsWindow();
    void openImportSessionsWindow();

};

#endif // DASHBOARDWINDOW_H
