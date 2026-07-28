#ifndef WINDOWFACTORY_H
#define WINDOWFACTORY_H

#include <QWidget>

/**
 * Factory class for creating plugin windows.
 * This centralizes window creation and decouples DashboardWindow from
 * all plugin window headers, reducing compilation dependencies.
 *
 * Note: Windows that require DashboardWindow* as a constructor parameter
 * (DeviceCodeLoginWindow, CredentialLoginWindow, TokenLoginWindow,
 * IllicitConsentGrant) are not included here - they should be created
 * directly with the appropriate dashboard pointer.
 */
class WindowFactory {
public:
    // Token operations
    static QWidget* createRequestRefreshTokens(QWidget *parent = nullptr);
    static QWidget* createPRTTokenUI(QWidget *parent = nullptr);
    static QWidget* createSsoCookieTokenWindow(QWidget *parent = nullptr);
    static QWidget* createTokenLogWindow(QWidget *parent = nullptr);
    static QWidget* createTokenAnalysisWindow(QWidget *parent = nullptr);

    // Microsoft 365
    static QWidget* createGraphQueryWindow(QWidget *parent = nullptr);
    static QWidget* createSharePointBrowserWindow(QWidget *parent = nullptr);
    static QWidget* createOutlookEmailWindow(QWidget *parent = nullptr);
    static QWidget* createOutlookCalendarWindow(QWidget *parent = nullptr);
    static QWidget* createTeamsChatWindow(QWidget *parent = nullptr);

    // Discovery / Enumeration
    static QWidget* createAzureEnumWindow(QWidget *parent = nullptr);
    static QWidget* createConditionalAccessWindow(QWidget *parent = nullptr);
    static QWidget* createCrossTenantAccessWindow(QWidget *parent = nullptr);
    static QWidget* createMfaStatusCheckerWindow(QWidget *parent = nullptr);
    static QWidget* createPasswordWritebackCheckerWindow(QWidget *parent = nullptr);
    static QWidget* createOAuthConsentEnumeratorWindow(QWidget *parent = nullptr);
    static QWidget* createAzureStorageWindow(QWidget *parent = nullptr);
    static QWidget* createKeyVaultExplorerWindow(QWidget *parent = nullptr);
    static QWidget* createSqlDatabaseWindow(QWidget *parent = nullptr);
    static QWidget* createAzureVMManagerWindow(QWidget *parent = nullptr);
    static QWidget* createRunbookExplorerWindow(QWidget *parent = nullptr);
    static QWidget* createSPNEnumWindow(QWidget *parent = nullptr);
    static QWidget* createFunctionAppExplorerWindow(QWidget *parent = nullptr);
    static QWidget* createLogicAppsViewerWindow(QWidget *parent = nullptr);
    static QWidget* createWhoAmIWindow(QWidget *parent = nullptr);
    static QWidget* createTenantSearchWindow(QWidget *parent = nullptr);

    // Attack windows
    static QWidget* createMSOLSprayWindow(QWidget *parent = nullptr);
    static QWidget* createSPNSpraySerialWindow(QWidget *parent = nullptr);
    static QWidget* createAddAzADAppSecretWindow(QWidget *parent = nullptr);
    static QWidget* createWHfBAttackWindow(QWidget *parent = nullptr);

    // Post-exploitation / Persistence
    static QWidget* createPostExploitWindow(QWidget *parent = nullptr);
    static QWidget* createEmailRulesWindow(QWidget *parent = nullptr);
    static QWidget* createConsentManipulationWindow(QWidget *parent = nullptr);
    static QWidget* createAuthMethodPersistenceWindow(QWidget *parent = nullptr);
    static QWidget* createDeviceJoinWindow(QWidget *parent = nullptr);

    // Reporting / Timeline
    static QWidget* createSessionTimelineWindow(QWidget *parent = nullptr);
    // Note: ReportDialog, SessionExportWindow, SessionImportWindow require
    // special parameters (DashboardWindow*/ClientTransport*) and should be
    // created directly
};

#endif // WINDOWFACTORY_H
