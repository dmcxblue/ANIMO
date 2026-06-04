#ifndef CONSENTMANIPULATIONWINDOW_H
#define CONSENTMANIPULATIONWINDOW_H

#include <QWidget>
#include <atomic>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QTreeWidget>
#include <QComboBox>
#include <QTabWidget>
#include <QProgressBar>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QLabel>
#include <QListWidget>

class UserSelectorWidget;

/**
 * Consent Manipulation Window (Post-Exploitation)
 *
 * Once you have admin access, this window enables:
 * - Viewing and approving pending admin consent requests
 * - Adding new delegated permission grants (oauth2PermissionGrants)
 * - Viewing and adding app-only permissions (appRoleAssignments)
 * - Granting tenant-wide consent without user interaction
 *
 * Red Team Value:
 * - Silently grant permissions to attacker-controlled apps
 * - Escalate existing app permissions
 * - Bypass normal consent workflows
 * - Establish persistent access through consented apps
 */
class ConsentManipulationWindow : public QWidget {
    Q_OBJECT

public:
    explicit ConsentManipulationWindow(QWidget *parent = nullptr);
    ~ConsentManipulationWindow();

private slots:
    // Admin Consent Requests tab
    void fetchPendingConsentRequests();
    void approveConsentRequest();
    void denyConsentRequest();

    // Delegated Permissions tab
    void fetchDelegatedGrants();
    void addDelegatedGrant();
    void removeDelegatedGrant();
    void fetchServicePrincipals();

    // App-Only Permissions tab
    void fetchAppRoleAssignments();
    void addAppRoleAssignment();
    void removeAppRoleAssignment();
    void fetchAvailableAppRoles();

    // Common
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void copySelectedItem();
    void exportResults();
    void cancelRequests();

private:
    void setupUi();
    QWidget* createAdminConsentTab();
    QWidget* createDelegatedPermissionsTab();
    QWidget* createAppRolesTab();

    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);
    void updateTokenStatus();
    QString resolveServicePrincipalName(const QString &spId);
    QString translateScope(const QString &scope);

    // UI Components
    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;
    QLineEdit *tokenInput;
    QTabWidget *tabWidget;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QPushButton *copyBtn;
    QPushButton *exportBtn;

    // Admin Consent Requests tab
    QTreeWidget *consentRequestsTree;
    QPushButton *fetchRequestsBtn;
    QPushButton *approveRequestBtn;
    QPushButton *denyRequestBtn;

    // Delegated Permissions tab
    QTreeWidget *delegatedGrantsTree;
    QComboBox *targetSpCombo;
    QComboBox *resourceSpCombo;
    QLineEdit *scopeInput;
    QPushButton *fetchDelegatedBtn;
    QPushButton *addDelegatedBtn;
    QPushButton *removeDelegatedBtn;
    QPushButton *fetchSpBtn;
    QComboBox *consentTypeCombo;
    QLineEdit *principalIdInput;

    // App-Only Permissions tab
    QTreeWidget *appRolesTree;
    QComboBox *appRoleSpCombo;
    QComboBox *resourceAppCombo;
    QListWidget *availableRolesList;
    QPushButton *fetchAppRolesBtn;
    QPushButton *addAppRoleBtn;
    QPushButton *removeAppRoleBtn;
    QPushButton *fetchAvailableRolesBtn;

    QNetworkAccessManager *net;
    QString currentToken;

    // Cache for SP lookups
    QMap<QString, QString> spNameCache;
    QMap<QString, QString> spIdCache;  // displayName -> id
    QList<QPair<QString, QString>> availableAppRoles;  // id, displayName

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // CONSENTMANIPULATIONWINDOW_H
