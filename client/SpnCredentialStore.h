#ifndef SPNCREDENTIALSTORE_H
#define SPNCREDENTIALSTORE_H

#include <QObject>
#include <QString>
#include <QMap>

// In-memory store of Service-Principal client_credentials, keyed by sessionId.
// SPN client_credentials tokens carry NO refresh token, so the normal
// refresh-token exchange path can't mint a token for a different resource.
// Modules that need Graph/Storage/etc. from an SPN session look up the SPN's
// {appId, secret, tenantId} here and run client_credentials themselves.
//
// The secret never touches disk. It is scrubbed when the session is removed
// (TokenStore::tokenRemoved) and when the process exits.
struct SpnCredentials {
    QString appId;
    QString secret;
    QString tenantId;
    bool isValid() const { return !appId.isEmpty() && !secret.isEmpty() && !tenantId.isEmpty(); }
};

class SpnCredentialStore : public QObject {
    Q_OBJECT
public:
    static SpnCredentialStore *instance();

    void store(const QString &sessionId, const SpnCredentials &creds);
    SpnCredentials get(const QString &sessionId) const;
    bool has(const QString &sessionId) const;
    void remove(const QString &sessionId);
    void clearAll();

private:
    explicit SpnCredentialStore(QObject *parent = nullptr);
    ~SpnCredentialStore() override;

    QMap<QString, SpnCredentials> m_creds;
    static SpnCredentialStore *s_instance;
};

#endif  // SPNCREDENTIALSTORE_H
