#ifndef SESSIONPERSISTENCE_H
#define SESSIONPERSISTENCE_H

#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>

/**
 * SessionPersistence - Save and Restore Session State
 *
 * Allows saving sessions with refresh tokens to disk so they survive
 * application restarts. Refresh tokens are encrypted before storage.
 *
 * Features:
 * - AES-256-GCM authenticated encryption via CryptoHelper
 * - PBKDF2-SHA256 key derivation (100,000 iterations)
 * - Session metadata preservation (user, tenant, resource, domain)
 * - Automatic session restoration on startup
 * - Token refresh using stored refresh tokens
 * - Backward compatible with legacy XOR-encrypted files
 *
 * Storage Location:
 * - data/saved_sessions.dat (AES-256-GCM encrypted)
 *
 * Attack Value:
 * - Persist access across application restarts
 * - Resume operations without re-authentication
 * - Maintain long-term access via refresh tokens
 */
class SessionPersistence {
public:
    static SessionPersistence& instance();

    struct SavedSession {
        QString sessionId;
        QString user;
        QString tenantId;
        QString defaultDomain;
        QString resource;
        QString refreshToken;      // Encrypted at rest
        QDateTime savedAt;
        QDateTime lastRefreshed;
        bool autoRestore = true;
    };

    // Save/Load operations
    bool saveSession(const SavedSession &session);
    bool removeSession(const QString &sessionId);
    QList<SavedSession> loadSavedSessions();
    bool clearAllSavedSessions();

    // Encryption key management
    void setEncryptionKey(const QString &key);
    bool hasEncryptionKey() const;

    // Export/Import for backup
    QJsonObject exportSessions(bool includeTokens = false);
    bool importSessions(const QJsonObject &data);

    // Session restoration
    struct RestorationResult {
        QString sessionId;
        bool success;
        QString error;
        QString newAccessToken;
    };

    // Check if saved sessions exist
    int getSavedSessionCount();
    bool hasSavedSessions();

private:
    SessionPersistence();
    ~SessionPersistence() = default;

    QString m_encryptionKey;
    QString m_storagePath;

    // Encryption helpers
    QString encrypt(const QString &plaintext) const;
    QString decrypt(const QString &ciphertext) const;

    // File operations
    bool saveToFile(const QJsonArray &sessions);
    QJsonArray loadFromFile();
};

#endif // SESSIONPERSISTENCE_H
