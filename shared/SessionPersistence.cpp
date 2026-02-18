#include "SessionPersistence.h"
#include "CryptoHelper.h"
#include "ErrorLogger.h"

#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QByteArray>
#include <QStandardPaths>
#include <QCoreApplication>

// Uses CryptoHelper for AES-256-GCM authenticated encryption

SessionPersistence& SessionPersistence::instance() {
    static SessionPersistence inst;
    return inst;
}

SessionPersistence::SessionPersistence() {
    // Default storage path
    QString dataDir = QCoreApplication::applicationDirPath() + "/data";
    QDir().mkpath(dataDir);
    m_storagePath = dataDir + "/saved_sessions.dat";

    // Generate default key from machine-specific info
    // In production, this should be derived from user password or secure enclave
    QString machineId = QSysInfo::machineUniqueId();
    if (machineId.isEmpty()) {
        machineId = QSysInfo::machineHostName() + QSysInfo::prettyProductName();
    }
    m_encryptionKey = QCryptographicHash::hash(machineId.toUtf8(), QCryptographicHash::Sha256).toHex();
}

void SessionPersistence::setEncryptionKey(const QString &key) {
    if (!key.isEmpty()) {
        m_encryptionKey = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex();
    }
}

bool SessionPersistence::hasEncryptionKey() const {
    return !m_encryptionKey.isEmpty();
}

QString SessionPersistence::encrypt(const QString &plaintext) const {
    if (plaintext.isEmpty() || m_encryptionKey.isEmpty()) {
        return plaintext;
    }

    // Use CryptoHelper AES-256-GCM encryption
    CryptoHelper::EncryptedData encrypted = CryptoHelper::encrypt(
        plaintext.toUtf8(), m_encryptionKey);

    if (!encrypted.success) {
        LOG_ERROR("SessionPersistence", QString("Encryption failed: %1").arg(encrypted.errorMessage));
        return QString();
    }

    // Serialize to JSON and Base64 encode for storage
    QJsonObject json = CryptoHelper::toJson(encrypted);
    QByteArray jsonData = QJsonDocument(json).toJson(QJsonDocument::Compact);
    return QString::fromLatin1(jsonData.toBase64());
}

QString SessionPersistence::decrypt(const QString &ciphertext) const {
    if (ciphertext.isEmpty() || m_encryptionKey.isEmpty()) {
        return ciphertext;
    }

    // Try new AES-256-GCM format first
    QByteArray jsonData = QByteArray::fromBase64(ciphertext.toLatin1());
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);

    if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
        QJsonObject json = doc.object();

        // Check if this is AES-256-GCM format (has salt, iv, tag, data)
        if (json.contains("salt") && json.contains("iv") && json.contains("tag")) {
            CryptoHelper::EncryptedData encrypted = CryptoHelper::fromJson(json);
            if (!encrypted.success) {
                LOG_WARNING("SessionPersistence", QString("Failed to parse encrypted data: %1").arg(encrypted.errorMessage));
                return QString();
            }

            CryptoHelper::DecryptedData decrypted = CryptoHelper::decrypt(
                encrypted.salt, encrypted.iv, encrypted.ciphertext, encrypted.tag, m_encryptionKey);

            if (!decrypted.success) {
                LOG_WARNING("SessionPersistence", QString("Decryption failed: %1").arg(decrypted.errorMessage));
                return QString();
            }

            return QString::fromUtf8(decrypted.plaintext);
        }
    }

    // Fallback: try legacy XOR decryption for old files
    QByteArray data = QByteArray::fromBase64(ciphertext.toUtf8());
    QByteArray key = m_encryptionKey.toUtf8();
    QByteArray result;
    result.reserve(data.size());

    for (int i = 0; i < data.size(); ++i) {
        result.append(data.at(i) ^ key.at(i % key.size()));
    }

    QString decrypted = QString::fromUtf8(result);

    // If legacy decryption worked, log a migration notice
    if (!decrypted.isEmpty()) {
        LOG_INFO("SessionPersistence", "Migrating from legacy XOR encryption to AES-256-GCM");
    }

    return decrypted;
}

bool SessionPersistence::saveSession(const SavedSession &session) {
    QJsonArray sessions = loadFromFile();

    // Check if session already exists and update it
    bool found = false;
    for (int i = 0; i < sessions.size(); ++i) {
        QJsonObject obj = sessions[i].toObject();
        if (obj.value("sessionId").toString() == session.sessionId) {
            // Update existing
            obj["user"] = session.user;
            obj["tenantId"] = session.tenantId;
            obj["defaultDomain"] = session.defaultDomain;
            obj["resource"] = session.resource;
            obj["refreshToken"] = encrypt(session.refreshToken);
            obj["savedAt"] = session.savedAt.toString(Qt::ISODate);
            obj["lastRefreshed"] = session.lastRefreshed.toString(Qt::ISODate);
            obj["autoRestore"] = session.autoRestore;
            sessions[i] = obj;
            found = true;
            break;
        }
    }

    if (!found) {
        // Add new session
        QJsonObject obj;
        obj["sessionId"] = session.sessionId;
        obj["user"] = session.user;
        obj["tenantId"] = session.tenantId;
        obj["defaultDomain"] = session.defaultDomain;
        obj["resource"] = session.resource;
        obj["refreshToken"] = encrypt(session.refreshToken);
        obj["savedAt"] = session.savedAt.toString(Qt::ISODate);
        obj["lastRefreshed"] = session.lastRefreshed.toString(Qt::ISODate);
        obj["autoRestore"] = session.autoRestore;
        sessions.append(obj);
    }

    bool result = saveToFile(sessions);
    if (result) {
        LOG_INFO("SessionPersistence", QString("Saved session: %1 (%2)")
                 .arg(session.sessionId.left(8), session.user));
    }
    return result;
}

bool SessionPersistence::removeSession(const QString &sessionId) {
    QJsonArray sessions = loadFromFile();
    QJsonArray filtered;

    for (const QJsonValue &val : sessions) {
        QJsonObject obj = val.toObject();
        if (obj.value("sessionId").toString() != sessionId) {
            filtered.append(obj);
        }
    }

    bool result = saveToFile(filtered);
    if (result) {
        LOG_INFO("SessionPersistence", QString("Removed saved session: %1").arg(sessionId.left(8)));
    }
    return result;
}

QList<SessionPersistence::SavedSession> SessionPersistence::loadSavedSessions() {
    QList<SavedSession> result;
    QJsonArray sessions = loadFromFile();

    for (const QJsonValue &val : sessions) {
        QJsonObject obj = val.toObject();
        SavedSession sess;
        sess.sessionId = obj.value("sessionId").toString();
        sess.user = obj.value("user").toString();
        sess.tenantId = obj.value("tenantId").toString();
        sess.defaultDomain = obj.value("defaultDomain").toString();
        sess.resource = obj.value("resource").toString();
        sess.refreshToken = decrypt(obj.value("refreshToken").toString());
        sess.savedAt = QDateTime::fromString(obj.value("savedAt").toString(), Qt::ISODate);
        sess.lastRefreshed = QDateTime::fromString(obj.value("lastRefreshed").toString(), Qt::ISODate);
        sess.autoRestore = obj.value("autoRestore").toBool(true);

        // Only include sessions with valid refresh tokens
        if (!sess.refreshToken.isEmpty()) {
            result.append(sess);
        }
    }

    LOG_INFO("SessionPersistence", QString("Loaded %1 saved session(s)").arg(result.size()));
    return result;
}

bool SessionPersistence::clearAllSavedSessions() {
    QFile file(m_storagePath);
    if (file.exists()) {
        bool result = file.remove();
        if (result) {
            LOG_INFO("SessionPersistence", "Cleared all saved sessions");
        }
        return result;
    }
    return true;
}

int SessionPersistence::getSavedSessionCount() {
    return loadFromFile().size();
}

bool SessionPersistence::hasSavedSessions() {
    return getSavedSessionCount() > 0;
}

QJsonObject SessionPersistence::exportSessions(bool includeTokens) {
    QJsonObject result;
    QJsonArray sessions = loadFromFile();

    if (!includeTokens) {
        // Strip tokens from export
        QJsonArray stripped;
        for (const QJsonValue &val : sessions) {
            QJsonObject obj = val.toObject();
            obj.remove("refreshToken");
            stripped.append(obj);
        }
        sessions = stripped;
    }

    result["sessions"] = sessions;
    result["exportedAt"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    result["count"] = sessions.size();

    return result;
}

bool SessionPersistence::importSessions(const QJsonObject &data) {
    if (!data.contains("sessions")) {
        return false;
    }

    QJsonArray imported = data.value("sessions").toArray();
    QJsonArray existing = loadFromFile();

    // Merge imported sessions (don't overwrite existing)
    QSet<QString> existingIds;
    for (const QJsonValue &val : existing) {
        existingIds.insert(val.toObject().value("sessionId").toString());
    }

    for (const QJsonValue &val : imported) {
        QJsonObject obj = val.toObject();
        QString sid = obj.value("sessionId").toString();
        if (!existingIds.contains(sid)) {
            existing.append(obj);
        }
    }

    return saveToFile(existing);
}

bool SessionPersistence::saveToFile(const QJsonArray &sessions) {
    QFile file(m_storagePath);
    if (!file.open(QIODevice::WriteOnly)) {
        LOG_ERROR("SessionPersistence", QString("Failed to open file for writing: %1").arg(m_storagePath));
        return false;
    }

    // Additional layer of obfuscation for the whole file
    QJsonDocument doc(sessions);
    QByteArray data = doc.toJson(QJsonDocument::Compact);
    QByteArray obfuscated = encrypt(QString::fromUtf8(data)).toUtf8();

    file.write(obfuscated);
    file.close();
    return true;
}

QJsonArray SessionPersistence::loadFromFile() {
    QFile file(m_storagePath);
    if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
        return QJsonArray();
    }

    QByteArray obfuscated = file.readAll();
    file.close();

    QString decrypted = decrypt(QString::fromUtf8(obfuscated));
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(decrypted.toUtf8(), &error);

    if (error.error != QJsonParseError::NoError) {
        LOG_WARNING("SessionPersistence", QString("Failed to parse saved sessions: %1").arg(error.errorString()));
        return QJsonArray();
    }

    return doc.array();
}
