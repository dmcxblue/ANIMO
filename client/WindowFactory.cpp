#include "WindowFactory.h"

// Token operations
#include "RequestRefreshTokens.h"
#include "PRTTokenUI.h"
#include "SsoCookieTokenWindow.h"
#include "TokenLogWindow.h"
#include "TokenAnalysisWindow.h"

// Microsoft 365
#include "GraphQueryWindow.h"
#include "SharePointBrowserWindow.h"
#include "OutlookEmailWindow.h"
#include "OutlookCalendarWindow.h"
#include "TeamsChatWindow.h"

// Discovery / Enumeration
#include "AzureEnumWindow.h"
#include "ConditionalAccessWindow.h"
#include "CrossTenantAccessWindow.h"
#include "MfaStatusCheckerWindow.h"
#include "PasswordWritebackCheckerWindow.h"
#include "OAuthConsentEnumeratorWindow.h"
#include "AzureStorageWindow.h"
#include "KeyVaultExplorerWindow.h"
#include "SqlDatabaseWindow.h"
#include "AzureVMManagerWindow.h"
#include "RunbookExplorerWindow.h"
#include "SPNEnumWindow.h"
#include "FunctionAppExplorerWindow.h"
#include "LogicAppsViewerWindow.h"
#include "WhoAmIWindow.h"
#include "TenantSearchWindow.h"

// Attack windows
#include "MSOLSprayWindow.h"
#include "SPNSpraySerialWindow.h"
#include "AddAzADAppSecret.h"
#include "WHfBAttackWindow.h"

// Post-exploitation / Persistence
#include "PostExploitWindow.h"
#include "EmailRulesWindow.h"
#include "ConsentManipulationWindow.h"

// Reporting / Timeline
#include "SessionTimelineWindow.h"

// ============================================================================
// Token Operations
// ============================================================================

QWidget* WindowFactory::createRequestRefreshTokens(QWidget *parent) {
    return new RequestRefreshTokens(parent);
}

QWidget* WindowFactory::createPRTTokenUI(QWidget *parent) {
    return new PRTTokenUI(parent);
}

QWidget* WindowFactory::createSsoCookieTokenWindow(QWidget *parent) {
    return new SsoCookieTokenWindow(parent);
}

QWidget* WindowFactory::createTokenLogWindow(QWidget *parent) {
    return new TokenLogWindow(parent);
}

QWidget* WindowFactory::createTokenAnalysisWindow(QWidget *parent) {
    return new TokenAnalysisWindow(parent);
}

// ============================================================================
// Microsoft 365
// ============================================================================

QWidget* WindowFactory::createGraphQueryWindow(QWidget *parent) {
    return new GraphQueryWindow(parent);
}

QWidget* WindowFactory::createSharePointBrowserWindow(QWidget *parent) {
    // Token is empty by default - user will provide it in the UI
    return new SharePointBrowserWindow(QString(), parent);
}

QWidget* WindowFactory::createOutlookEmailWindow(QWidget *parent) {
    return new OutlookEmailWindow(parent);
}

QWidget* WindowFactory::createOutlookCalendarWindow(QWidget *parent) {
    return new OutlookCalendarWindow(parent);
}

QWidget* WindowFactory::createTeamsChatWindow(QWidget *parent) {
    return new TeamsChatWindow(parent);
}

// ============================================================================
// Discovery / Enumeration
// ============================================================================

QWidget* WindowFactory::createAzureEnumWindow(QWidget *parent) {
    return new AzureEnumWindow(parent);
}

QWidget* WindowFactory::createConditionalAccessWindow(QWidget *parent) {
    return new ConditionalAccessWindow(parent);
}

QWidget* WindowFactory::createCrossTenantAccessWindow(QWidget *parent) {
    return new CrossTenantAccessWindow(parent);
}

QWidget* WindowFactory::createMfaStatusCheckerWindow(QWidget *parent) {
    return new MfaStatusCheckerWindow(parent);
}

QWidget* WindowFactory::createPasswordWritebackCheckerWindow(QWidget *parent) {
    return new PasswordWritebackCheckerWindow(parent);
}

QWidget* WindowFactory::createOAuthConsentEnumeratorWindow(QWidget *parent) {
    return new OAuthConsentEnumeratorWindow(parent);
}

QWidget* WindowFactory::createAzureStorageWindow(QWidget *parent) {
    return new AzureStorageWindow(parent);
}

QWidget* WindowFactory::createKeyVaultExplorerWindow(QWidget *parent) {
    return new KeyVaultExplorerWindow(parent);
}

QWidget* WindowFactory::createSqlDatabaseWindow(QWidget *parent) {
    return new SqlDatabaseWindow(parent);
}

QWidget* WindowFactory::createAzureVMManagerWindow(QWidget *parent) {
    return new AzureVMManagerWindow(parent);
}

QWidget* WindowFactory::createRunbookExplorerWindow(QWidget *parent) {
    return new RunbookExplorerWindow(parent);
}

QWidget* WindowFactory::createSPNEnumWindow(QWidget *parent) {
    return new SPNEnumWindow(parent);
}

QWidget* WindowFactory::createFunctionAppExplorerWindow(QWidget *parent) {
    return new FunctionAppExplorerWindow(parent);
}

QWidget* WindowFactory::createLogicAppsViewerWindow(QWidget *parent) {
    return new LogicAppsViewerWindow(parent);
}

QWidget* WindowFactory::createWhoAmIWindow(QWidget *parent) {
    return new WhoAmIWindow(parent);
}

QWidget* WindowFactory::createTenantSearchWindow(QWidget *parent) {
    return new TenantSearchWindow(parent);
}

// ============================================================================
// Attack Windows
// ============================================================================

QWidget* WindowFactory::createMSOLSprayWindow(QWidget *parent) {
    return new MSOLSprayWindow(parent);
}

QWidget* WindowFactory::createSPNSpraySerialWindow(QWidget *parent) {
    return new SPNSpraySerialWindow(parent);
}

QWidget* WindowFactory::createAddAzADAppSecretWindow(QWidget *parent) {
    return new AddAzADAppSecret(parent);
}

QWidget* WindowFactory::createWHfBAttackWindow(QWidget *parent) {
    return new WHfBAttackWindow(parent);
}

// ============================================================================
// Post-exploitation / Persistence
// ============================================================================

QWidget* WindowFactory::createPostExploitWindow(QWidget *parent) {
    return new PostExploitWindow(parent);
}

QWidget* WindowFactory::createEmailRulesWindow(QWidget *parent) {
    return new EmailRulesWindow(parent);
}

QWidget* WindowFactory::createConsentManipulationWindow(QWidget *parent) {
    return new ConsentManipulationWindow(parent);
}

// ============================================================================
// Reporting / Timeline
// ============================================================================

QWidget* WindowFactory::createSessionTimelineWindow(QWidget *parent) {
    return new SessionTimelineWindow(parent);
}
