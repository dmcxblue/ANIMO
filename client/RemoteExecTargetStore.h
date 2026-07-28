#ifndef REMOTEEXECTARGETSTORE_H
#define REMOTEEXECTARGETSTORE_H

#include <QDateTime>
#include <QList>
#include <QMap>
#include <QObject>
#include <QString>
#include <QVariantMap>

// RemoteExecTargetStore - persisted list of RemoteExecWindow target
// configurations.
//
// Each target carries a `kind` string ("azure_vm" | "http_webshell" |
// "http_ssti") and an opaque `params` map that the corresponding
// transport knows how to consume. The store round-trips through
// data/remote_exec_targets.dat via CryptoHelper (same envelope as
// SessionPersistence).
//
// The point of persisting: after the operator wires up a webshell URL /
// SSTI payload once, restarting ANIMO or switching sessions should not
// lose it. This is the concrete answer to "I had to hand-craft each
// ?cmd= call against cmd.php" - the target lives on disk between
// sessions.
class RemoteExecTargetStore : public QObject {
    Q_OBJECT
public:
    struct Target {
        QString      id;         // UUID
        QString      name;       // Display name
        QString      kind;       // See file-header note
        QVariantMap  params;     // Transport-specific config
        QDateTime    createdAt;
        QDateTime    lastUsedAt;
    };

    static RemoteExecTargetStore *instance();

    QList<Target> targets() const { return m_targets; }
    Target        find(const QString &id) const;

    // add / update: if `t.id` is empty, a fresh UUID is minted. Returns
    // the (possibly new) id.
    QString addOrUpdate(Target t);
    bool    remove(const QString &id);
    void    markUsed(const QString &id);   // touches lastUsedAt

signals:
    void targetAdded(const QString &id);
    void targetRemoved(const QString &id);
    void targetUpdated(const QString &id);

private:
    explicit RemoteExecTargetStore(QObject *parent = nullptr);
    ~RemoteExecTargetStore() override = default;

    void loadFromDisk();
    bool saveToDisk();

    QString       m_storagePath;
    QString       m_encryptionKey;
    QList<Target> m_targets;
};

#endif  // REMOTEEXECTARGETSTORE_H
