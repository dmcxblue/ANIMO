#include "RemoteExecTargetStore.h"
#include "../shared/CryptoHelper.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSysInfo>
#include <QUuid>

namespace {

QJsonObject variantMapToJson(const QVariantMap &m) {
    return QJsonObject::fromVariantMap(m);
}
QVariantMap jsonToVariantMap(const QJsonObject &o) {
    return o.toVariantMap();
}

}  // namespace

RemoteExecTargetStore *RemoteExecTargetStore::instance() {
    static RemoteExecTargetStore inst;
    return &inst;
}

RemoteExecTargetStore::RemoteExecTargetStore(QObject *parent)
    : QObject(parent)
{
    const QString dataDir = QCoreApplication::applicationDirPath() + "/data";
    QDir().mkpath(dataDir);
    m_storagePath = dataDir + "/remote_exec_targets.dat";

    QString machineId = QSysInfo::machineUniqueId();
    if (machineId.isEmpty())
        machineId = QSysInfo::machineHostName() + QSysInfo::prettyProductName();
    m_encryptionKey = QCryptographicHash::hash(machineId.toUtf8(),
                                                QCryptographicHash::Sha256).toHex();

    loadFromDisk();
}

RemoteExecTargetStore::Target RemoteExecTargetStore::find(const QString &id) const {
    for (const auto &t : m_targets) if (t.id == id) return t;
    return {};
}

QString RemoteExecTargetStore::addOrUpdate(Target t) {
    if (t.id.isEmpty()) {
        t.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        if (!t.createdAt.isValid()) t.createdAt = QDateTime::currentDateTimeUtc();
        m_targets.append(t);
        saveToDisk();
        emit targetAdded(t.id);
        return t.id;
    }
    for (int i = 0; i < m_targets.size(); ++i) {
        if (m_targets[i].id == t.id) {
            if (!t.createdAt.isValid()) t.createdAt = m_targets[i].createdAt;
            m_targets[i] = t;
            saveToDisk();
            emit targetUpdated(t.id);
            return t.id;
        }
    }
    // Given id but no existing row - treat as add.
    if (!t.createdAt.isValid()) t.createdAt = QDateTime::currentDateTimeUtc();
    m_targets.append(t);
    saveToDisk();
    emit targetAdded(t.id);
    return t.id;
}

bool RemoteExecTargetStore::remove(const QString &id) {
    const int before = m_targets.size();
    m_targets.erase(std::remove_if(m_targets.begin(), m_targets.end(),
                                    [&](const Target &t){ return t.id == id; }),
                     m_targets.end());
    if (m_targets.size() == before) return false;
    saveToDisk();
    emit targetRemoved(id);
    return true;
}

void RemoteExecTargetStore::markUsed(const QString &id) {
    for (int i = 0; i < m_targets.size(); ++i) {
        if (m_targets[i].id == id) {
            m_targets[i].lastUsedAt = QDateTime::currentDateTimeUtc();
            saveToDisk();
            emit targetUpdated(id);
            return;
        }
    }
}

void RemoteExecTargetStore::loadFromDisk() {
    QFile f(m_storagePath);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return;
    const QByteArray ciphertextB64 = f.readAll();
    if (ciphertextB64.isEmpty()) return;

    const QByteArray jsonBytes = QByteArray::fromBase64(ciphertextB64);
    QJsonParseError pe;
    const QJsonDocument envelope = QJsonDocument::fromJson(jsonBytes, &pe);
    if (pe.error != QJsonParseError::NoError || !envelope.isObject()) return;

    CryptoHelper::EncryptedData ed = CryptoHelper::fromJson(envelope.object());
    if (!ed.success) return;
    CryptoHelper::DecryptedData dd = CryptoHelper::decrypt(
        ed.salt, ed.iv, ed.ciphertext, ed.tag, m_encryptionKey);
    if (!dd.success) return;

    const QJsonDocument doc = QJsonDocument::fromJson(dd.plaintext, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray()) return;

    m_targets.clear();
    for (const QJsonValue &v : doc.array()) {
        const QJsonObject o = v.toObject();
        Target t;
        t.id         = o.value("id").toString();
        t.name       = o.value("name").toString();
        t.kind       = o.value("kind").toString();
        t.params     = jsonToVariantMap(o.value("params").toObject());
        t.createdAt  = QDateTime::fromString(o.value("createdAt").toString(),  Qt::ISODateWithMs);
        t.lastUsedAt = QDateTime::fromString(o.value("lastUsedAt").toString(), Qt::ISODateWithMs);
        m_targets.append(t);
    }
}

bool RemoteExecTargetStore::saveToDisk() {
    QJsonArray arr;
    for (const auto &t : m_targets) {
        QJsonObject o;
        o.insert("id",         t.id);
        o.insert("name",       t.name);
        o.insert("kind",       t.kind);
        o.insert("params",     variantMapToJson(t.params));
        o.insert("createdAt",  t.createdAt.toString(Qt::ISODateWithMs));
        o.insert("lastUsedAt", t.lastUsedAt.toString(Qt::ISODateWithMs));
        arr.append(o);
    }
    const QByteArray plain = QJsonDocument(arr).toJson(QJsonDocument::Compact);
    CryptoHelper::EncryptedData ed = CryptoHelper::encrypt(plain, m_encryptionKey);
    if (!ed.success) return false;
    const QByteArray envelope = QJsonDocument(CryptoHelper::toJson(ed)).toJson(QJsonDocument::Compact);

    QFile f(m_storagePath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    f.write(envelope.toBase64());
    return true;
}
