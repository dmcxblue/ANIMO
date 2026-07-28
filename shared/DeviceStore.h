#ifndef DEVICESTORE_H
#define DEVICESTORE_H

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QString>

// DeviceStore - encrypted on-disk store for registered Entra devices.
//
// Sibling of SessionPersistence (**[4.2]**) that saves the material we
// obtained from a successful DRS join: the RSA private key that signed
// the CSR, the returned device X.509 cert, the deviceId + tenantId
// they're bound to, and metadata for later PRT-mint.
//
// All fields except the metadata are encrypted at rest via CryptoHelper
// (AES-256-GCM), keyed by the same machine-derived default password
// SessionPersistence uses (overridable via setEncryptionKey).
//
// Storage lives at `data/device_certs.dat` alongside `saved_sessions.dat`.
class DeviceStore {
public:
    struct Device {
        QString    deviceId;         // Entra deviceId (returned by DRS)
        QString    tenantId;         // TenantID the device is joined to
        QString    displayName;      // User-provided name shown in the portal
        QString    certThumbprint;   // SHA256 hex, UPPER (from DeviceCryptoHelper)
        QDateTime  joinedAt;         // When the join succeeded
        QByteArray privateKeyPem;    // Encrypted at rest; RSA that signed the CSR
        QByteArray deviceCertPem;    // Encrypted at rest; signed X.509 from DRS
        QByteArray transportKeyPem;  // Optional: private key of the transport pair
    };

    static DeviceStore& instance();

    // Persist / retrieve.
    bool           saveDevice(const Device &d);
    bool           removeDevice(const QString &deviceId);
    QList<Device>  loadDevices();
    Device         findByDeviceId(const QString &deviceId);
    bool           clearAll();

    // Same encryption-key contract as SessionPersistence.
    void setEncryptionKey(const QString &key);
    bool hasEncryptionKey() const;

private:
    DeviceStore();
    ~DeviceStore() = default;

    QString    m_encryptionKey;
    QString    m_storagePath;

    QString encrypt(const QByteArray &plaintext) const;   // base64(JSON envelope)
    QByteArray decrypt(const QString &ciphertext) const;  // empty on failure

    bool     saveToFile(const QList<Device> &devices);
    QList<Device> loadFromFile();
};

#endif  // DEVICESTORE_H
