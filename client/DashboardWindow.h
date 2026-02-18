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
};

class DashboardWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit DashboardWindow(QWidget *parent = nullptr);
    ~DashboardWindow() override = default;

    void setTransport(ClientTransport* t);

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
    QTextEdit *eventLog = nullptr;
    QTabWidget *tabs = nullptr;

    ClientTransport* transport = nullptr;
    GraphQueryWindow* m_graphQueryWindow = nullptr;

    // Token expiry tracking
    QMap<QString, TokenExpiry> tokenExpiryMap;
    QTimer *expiryUpdateTimer = nullptr;
    bool autoRenewEnabled = true;  // Global setting

    void initUI();
    void updateExpiryDisplay();
    void refreshTokenForSession(const QString &sessionId);
    QString formatTimeRemaining(const QDateTime &expiry) const;
    QDateTime parseTokenExpiry(const QString &accessToken) const;

public slots:
    void onServerJson(const QJsonObject &obj);

    void launchAccessTokenWindow();
    void launchDeviceCodeWindow();
    void launchIllicitConsentWindow();
    void createNewSession();
    void addSessionRow(const QString &sessionId, const QString &username, const QString &tenantId, const QString &domain, const QString &resource, const QDateTime &expiry = QDateTime());

    void logEvent(const QString &msg);
    void updateSessionRow(const QString &sessionId, const QString &username, const QString &tenantId, const QString &defaultDomain, const QString &resource);
    void removeSessionById(const QString &sessionId);
    void setSessionTokenExpiry(const QString &sessionId, const QString &accessToken, const QString &refreshToken, const QString &resource, const QString &tenantId);
    void toggleAutoRenew(bool enabled);

    void onAzureLoginSuccess(const QString &token, const QString &resource, const QString &sessionId);

    void loadExistingSessions();
    //void getUsers();
    //void getGroups();
    //void getUserRoles();
    //void getContext();
    //void getAzContext();
    //void getCurrentUser();
    //void getTenantInfo();
    //void getTokenInfo();

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
    void openTokenLogWindow();
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

    // Persistence features
    void openEmailRulesWindow();
    void openConsentManipulationWindow();

    // Auto session persistence
    void autoRestoreSessions();
    void autoSaveSession(const QString &sessionId);

    // Session export/import
    void openExportSessionsWindow();
    void openImportSessionsWindow();

    //void logConnectionEvent(const QString &username, const QString &sessionId);
};

#endif // DASHBOARDWINDOW_H
