#ifndef WHOAMIWINDOW_H
#define WHOAMIWINDOW_H

#include "EnumerationWindowBase.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include <QSet>
#include <QString>

class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;
class QTableWidget;
class QPlainTextEdit;
class QLabel;
class QPushButton;
class QLineEdit;
class QCheckBox;

// Discovery > WhoAmI (Entra/Azure)
//
// One-click detailed identity dump for the selected session. Panes:
//   Identity        - /me + tenant + parsed JWT claims + guest flag
//   Groups & Roles  - transitiveMemberOf split into Groups / Admin Units /
//                     Directory Roles; PIM eligible + active schedules;
//                     wids-derived roles; derived password-reset ability
//   Owned           - owned Applications (with requiredResourceAccess /
//                     appRoleAssignments), owned Service Principals, owned
//                     Groups (with role-assignable + member preview),
//                     owned devices + registered devices
//   Azure RBAC      - roleAssignments across every accessible subscription,
//                     roleDefinition names resolved
//   Access Surface  - my authentication methods, sign-in activity, licenses,
//                     consented OAuth grants (/me/oauth2PermissionGrants)
//   Token Perms     - delegated (scp) + application (roles) on the Graph token
//   Org             - manager + direct reports
//
// The RBAC + tenant listing panes need a Management token; other panes need
// Graph. Both are auto-fetched from the selected session via UserSelectorWidget
// (silent refresh-token exchange, stored back under the SAME sessionId so the
// terminal + other modules see the fresh tokens too).
class WhoAmIWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit WhoAmIWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void runWhoAmI();
    void exportReport();
    void copyReport();
    void onGroupsContextMenu(const QPoint &pos);
    void onOwnedContextMenu(const QPoint &pos);
    void onRolesContextMenu(const QPoint &pos);
    void onRbacContextMenu(const QPoint &pos);

private:
    void setupUi();

    void ensureTokensThen(std::function<void(const QString &graphToken, const QString &mgmtToken)> next);

    // Loaders
    void loadTenantOrg(const QString &graphToken);
    void loadIdentityAndClaims(const QString &graphToken);
    void loadMemberOf(const QString &graphToken);
    void loadOwnedObjects(const QString &graphToken);
    void loadOwnedDevices(const QString &graphToken);
    void loadRegisteredDevices(const QString &graphToken);
    void loadPimEligibility(const QString &graphToken);
    void loadPimActive(const QString &graphToken);
    void loadOAuthGrants(const QString &graphToken);
    void loadAuthMethods(const QString &graphToken);
    void loadLicenses(const QString &graphToken);
    void loadManagerAndReports(const QString &graphToken);
    void loadRbac(const QString &mgmtToken);

    // For each owned Application, fetch requiredResourceAccess + appRoleAssignments.
    void loadOwnedAppDetail(const QString &graphToken, const QString &appObjectId,
                            const QString &appDisplayName, QTreeWidgetItem *anchor);
    void loadOwnedGroupMembers(const QString &graphToken, const QString &groupId,
                               QTreeWidgetItem *anchor);
    void loadDirectoryRoleAssignments(const QString &graphToken);

    void resolveRoleDefinition(const QString &mgmtToken, const QString &roleDefId,
                               std::function<void(const QString &name, const QString &type)> cb);

    // Rendering
    void renderClaims(const QJsonObject &claims);
    void renderMemberOf(const QJsonArray &members);
    void renderOwnedObjects(const QJsonArray &owned, const QString &graphToken);
    void renderOwnedDevices(const QJsonArray &devices);
    void renderTokenPerms(const QJsonObject &claims);
    void renderOAuthGrant(const QJsonObject &grant);
    void renderAuthMethod(const QJsonObject &method);
    void renderLicense(const QJsonObject &license);
    void renderPimSchedule(const QJsonObject &sched, bool eligible);
    void addRbacRow(const QString &sub, const QString &scope, const QString &role,
                    const QString &roleType, const QString &principalType);
    void deriveResetCapability();  // pure client-side, no API call

    void checkComplete();
    void applyFilter(QTreeWidget *tree, QLineEdit *edit);
    void makeCopyContextMenu(QTreeWidget *tree);
    void makeTableCopyContextMenu(QTableWidget *table);

    // Custom controls
    QPushButton *runBtn = nullptr;
    QPushButton *exportBtn = nullptr;
    QPushButton *copyBtn = nullptr;

    QTabWidget *tabs = nullptr;

    // Identity tab
    QLabel *identityHeader = nullptr;
    QLabel *guestBanner = nullptr;
    QLabel *tenantHeader = nullptr;
    QPlainTextEdit *identityDetails = nullptr;
    QTreeWidget *claimsTree = nullptr;

    // Groups / Roles tab
    QLineEdit *groupsFilter = nullptr;
    QTreeWidget *groupsTree = nullptr;
    QTreeWidget *auTree = nullptr;
    QLineEdit *rolesFilter = nullptr;
    QTreeWidget *rolesTree = nullptr;      // active roles (from wids + memberOf + PIM active)
    QTreeWidget *rolesEligibleTree = nullptr;   // PIM eligible (can activate)
    QLabel *resetAbilityLabel = nullptr;    // derived password-reset ability summary

    // Owned tab
    QLineEdit *ownedFilter = nullptr;
    QTreeWidget *ownedTree = nullptr;      // apps + service principals + groups + devices
    QCheckBox *ownedHighValueOnly = nullptr;

    // RBAC tab
    QTableWidget *rbacTable = nullptr;
    QLabel *rbacSummary = nullptr;

    // Access surface tab
    QTreeWidget *authMethodsTree = nullptr;
    QTreeWidget *oauthGrantsTree = nullptr;
    QTreeWidget *licensesTree = nullptr;
    QLabel *signInLabel = nullptr;

    // Token perms tab
    QTreeWidget *scopesTree = nullptr;
    QTreeWidget *appRolesTree = nullptr;

    // Org tab
    QLabel *managerLabel = nullptr;
    QTreeWidget *reportsTree = nullptr;

    // Run state
    QString m_userOid;
    QString m_userTid;
    QString m_userUpn;
    QString m_graphToken;
    QString m_mgmtToken;
    bool m_isGuest = false;
    QSet<QString> m_activeRoleTemplateIds;  // for derived reset-capability
    int m_pending = 0;
    int m_rbacRoleLookups = 0;
    // roleDefinitionId -> {name, type ("BuiltInRole"|"CustomRole")}
    QMap<QString, QPair<QString, QString>> m_roleDefCache;
};

#endif // WHOAMIWINDOW_H
