#include "DeviceStore.h"
#include "CryptoHelper.h"
#include "ErrorLogger.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSysInfo>

DeviceStore& DeviceStore::instance() {
    static DeviceStore inst;
    return inst;
}

DeviceStore::DeviceStore() {
    const QString dataDir = QCoreApplication::applicationDirPath() + "/data";
    QDir().mkpath(dataDir);
    m_storagePath = dataDir + "/device_certs.dat";

    // Same default-key derivation as SessionPersistence, so a single
    // machine-scoped key covers both stores.
    QString machineId = QSysInfo::machineUniqueId();
    if (machineId.isEmpty())
        machineId = QSysInfo::machineHostName() + QSysInfo::prettyProductName();
    m_encryptionKey = QCryptographicHash::hash(machineId.toUtf8(),
                                               QCryptographicHash::Sha256).toHex();
}

void DeviceStore::setEncryptionKey(const QString &key) {
    if (!key.isEmpty())
        m_encryptionKey = QCryptographicHash::hash(key.toUtf8(),
                                                    QCryptographicHash::Sha256).toHex();
}

bool DeviceStore::hasEncryptionKey() const { return !m_encryptionKey.isEmpty(); }

QString DeviceStore::encrypt(const QByteArray &plaintext) const {
    if (plaintext.isEmpty() || m_encryptionKey.isEmpty()) return {};
    CryptoHelper::EncryptedData ed = CryptoHelper::encrypt(plaintext, m_encryptionKey);
    if (!ed.success) {
        LOG_ERROR("DeviceStore", QString("encrypt failed: %1").arg(ed.errorMessage));
        return {};
    }
    return QString::fromLatin1(
        QJsonDocument(CryptoHelper::toJson(ed)).toJson(QJsonDocument::Compact).toBase64());
}

QByteArray DeviceStore::decrypt(const QString &ciphertext) const {
    if (ciphertext.isEmpty() || m_encryptionKey.isEmpty()) return {};
    const QByteArray jsonBytes = QByteArray::fromBase64(ciphertext.toLatin1());
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(jsonBytes, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) return {};
    CryptoHelper::EncryptedData ed = CryptoHelper::fromJson(doc.object());
    if (!ed.success) return {};
    CryptoHelper::DecryptedData dd = CryptoHelper::decrypt(
        ed.salt, ed.iv, ed.ciphertext, ed.tag, m_encryptionKey);
    if (!dd.success) return {};
    return dd.plaintext;
}

bool DeviceStore::saveToFile(const QList<Device> &devices) {
    QJsonArray arr;
    for (const Device &d : devices) {
        QJsonObject o;
        o.insert("deviceId",       d.deviceId);
        o.insert("tenantId",       d.tenantId);
        o.insert("displayName",    d.displayName);
        o.insert("certThumbprint", d.certThumbprint);
        o.insert("joinedAt",       d.joinedAt.toString(Qt::ISODateWithMs));
        o.insert("privateKeyPem",   encrypt(d.privateKeyPem));
        o.insert("deviceCertPem",   encrypt(d.deviceCertPem));
        o.insert("transportKeyPem", encrypt(d.transportKeyPem));
        arr.append(o);
    }
    QFile f(m_storagePath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        LOG_ERROR("DeviceStore", QString("open %1 for write failed: %2")
                                      .arg(m_storagePath, f.errorString()));
        return false;
    }
    f.write(QJsonDocument(arr).toJson(QJsonDocument::Compact));
    return true;
}

QList<DeviceStore::Device> DeviceStore::loadFromFile() {
    QList<Device> out;
    QFile f(m_storagePath);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return out;
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray()) return out;
    for (const QJsonValue &v : doc.array()) {
        const QJsonObject o = v.toObject();
        Device d;
        d.deviceId        = o.value("deviceId").toString();
        d.tenantId        = o.value("tenantId").toString();
        d.displayName     = o.value("displayName").toString();
        d.certThumbprint  = o.value("certThumbprint").toString();
        d.joinedAt        = QDateTime::fromString(o.value("joinedAt").toString(),
                                                   Qt::ISODateWithMs);
        d.privateKeyPem   = decrypt(o.value("privateKeyPem").toString());
        d.deviceCertPem   = decrypt(o.value("deviceCertPem").toString());
        d.transportKeyPem = decrypt(o.value("transportKeyPem").toString());
        out.append(d);
    }
    return out;
}

bool DeviceStore::saveDevice(const Device &d) {
    QList<Device> devices = loadFromFile();
    for (int i = 0; i < devices.size(); ++i) {
        if (devices[i].deviceId == d.deviceId) { devices[i] = d; return saveToFile(devices); }
    }
    devices.append(d);
    return saveToFile(devices);
}

bool DeviceStore::removeDevice(const QString &deviceId) {
    QList<Device> devices = loadFromFile();
    const int before = devices.size();
    devices.erase(std::remove_if(devices.begin(), devices.end(),
                                  [&](const Device &x){ return x.deviceId == deviceId; }),
                   devices.end());
    if (devices.size() == before) return false;
    return saveToFile(devices);
}

QList<DeviceStore::Device> DeviceStore::loadDevices() { return loadFromFile(); }

DeviceStore::Device DeviceStore::findByDeviceId(const QString &deviceId) {
    for (const Device &d : loadFromFile()) if (d.deviceId == deviceId) return d;
    return {};
}

bool DeviceStore::clearAll() {
    if (!QFile::exists(m_storagePath)) return true;
    return QFile::remove(m_storagePath);
}
