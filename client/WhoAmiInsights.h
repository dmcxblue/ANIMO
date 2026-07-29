#ifndef WHOAMIINSIGHTS_H
#define WHOAMIINSIGHTS_H

#include <QDateTime>
#include <QList>
#include <QMap>
#include <QMutex>
#include <QObject>
#include <QSet>
#include <QString>

class QComboBox;
class QLineEdit;

// WhoAmiInsights — typed publish/subscribe bus for facts WhoAmIWindow
// discovers about the current identity. Post-Exploitation modules read from
// here to auto-populate their input fields (principal, tenant, scope, own
// appId, ...) so operators don't have to re-type what WhoAmI already knows.
//
// Pattern mirrors TokenStore (client/TokenStore.h): QObject singleton with a
// double-checked-locking `instance()`, thread-safe read/write via QMutex,
// and change signals that windows connect to in their ctor.
//
// Publish site: WhoAmIWindow::checkComplete() after renderCapabilities().
// Consumers: PostExploitWindow, AuthMethodPersistenceWindow, DeviceJoinWindow,
// RefreshTokenSprayWindow, SPNSpraySerialWindow, ConsentManipulationWindow,
// AddAzADAppSecret. Any future module can join by connecting to
// insightsUpdated and calling autofillLineEdit / autofillCombo.
class WhoAmiInsights : public QObject {
    Q_OBJECT
public:
    struct RbacScope {
        QString subscriptionId;   // "662a4fee-…" - GUID only
        QString scope;            // "/subscriptions/…/resourceGroups/…"
        QString roleName;         // "Owner", "Contributor", "Reader", ...
        QString roleType;         // "BuiltInRole" | "CustomRole"
    };

    struct OwnedApp {
        QString appId;            // application (client) id, GUID
        QString objectId;         // application object id
        QString displayName;
    };

    struct Snapshot {
        QString sessionId;                    // TokenStore key
        QString userOid;                      // Entra objectId
        QString userUpn;
        QString userTid;                      // tenant GUID
        QString tenantDefaultDomain;          // e.g. contoso.onmicrosoft.com
        bool    isGuest = false;
        QSet<QString>    activeRoleTemplateIds;
        QList<RbacScope> rbacScopes;
        QList<OwnedApp>  ownedApps;
        QSet<QString>    allControlActions;
        QSet<QString>    allDataActions;
        bool             hasMgmtToken = false;
        QDateTime        capturedAt;

        bool isValid() const { return !sessionId.isEmpty() || !userOid.isEmpty(); }
    };

    static WhoAmiInsights *instance();

    // Publish a fresh snapshot. Overwrites any previous snapshot for the same
    // sessionId. Emits insightsUpdated(sessionId).
    void publish(const Snapshot &s);

    // Look up the last snapshot for a given session. Returns a snapshot with
    // isValid() == false when nothing has been published for that session.
    Snapshot forSession(const QString &sessionId) const;

    // Most-recently-published snapshot, regardless of session. Convenience
    // for modules that don't know or care which session ran WhoAmI (e.g. the
    // spray windows that only want the tenant GUID).
    Snapshot latest() const;

    // Drop the snapshot for a session. Emits insightsCleared(sessionId).
    void clear(const QString &sessionId);

    // Static autofill helpers. Both fill only when force==true OR the widget
    // is empty (line edit) / has no current data (combo). This preserves
    // operator edits while letting a "🔗 Autofill from WhoAmI" button
    // unconditionally re-sync.
    static void autofillLineEdit(QLineEdit *w, const QString &value, bool force = false);
    static void autofillCombo(QComboBox   *w, const QString &value, bool force = false);

signals:
    void insightsUpdated(const QString &sessionId);
    void insightsCleared(const QString &sessionId);

private:
    explicit WhoAmiInsights(QObject *parent = nullptr);
    ~WhoAmiInsights() override = default;

    mutable QMutex           m_mutex;
    QMap<QString, Snapshot>  m_bySession;   // sessionId -> latest snapshot
    QString                  m_latestSessionId;

    static WhoAmiInsights *s_instance;
    static QMutex          s_instanceMutex;
};

#endif  // WHOAMIINSIGHTS_H
