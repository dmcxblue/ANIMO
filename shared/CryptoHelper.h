#ifndef CRYPTOHELPER_H
#define CRYPTOHELPER_H

#include <QString>
#include <QByteArray>
#include <QJsonObject>

/**
 * CryptoHelper - AES-256-GCM encryption for secure session export/import
 *
 * Uses OpenSSL for:
 * - PBKDF2-SHA256 key derivation (100,000 iterations)
 * - AES-256-GCM authenticated encryption
 * - Random salt and IV generation
 */
class CryptoHelper {
public:
    // Encryption result structure
    struct EncryptedData {
        QByteArray salt;        // 16 bytes, random per encryption
        QByteArray iv;          // 12 bytes for GCM
        QByteArray ciphertext;  // Encrypted data
        QByteArray tag;         // 16 bytes GCM authentication tag
        bool success = false;
        QString errorMessage;
    };

    // Decrypt result structure
    struct DecryptedData {
        QByteArray plaintext;
        bool success = false;
        QString errorMessage;
    };

    /**
     * Encrypt data using AES-256-GCM with password-derived key
     * @param plaintext Data to encrypt
     * @param password User-provided password
     * @return EncryptedData with salt, iv, ciphertext, tag
     */
    static EncryptedData encrypt(const QByteArray &plaintext, const QString &password);

    /**
     * Decrypt data using AES-256-GCM
     * @param salt Salt used for key derivation
     * @param iv Initialization vector
     * @param ciphertext Encrypted data
     * @param tag GCM authentication tag
     * @param password User-provided password
     * @return DecryptedData with plaintext or error
     */
    static DecryptedData decrypt(const QByteArray &salt,
                                  const QByteArray &iv,
                                  const QByteArray &ciphertext,
                                  const QByteArray &tag,
                                  const QString &password);

    /**
     * Serialize encrypted data to JSON for file storage
     * @param data EncryptedData from encrypt()
     * @return QJsonObject ready for file writing
     */
    static QJsonObject toJson(const EncryptedData &data);

    /**
     * Deserialize encrypted data from JSON
     * @param json JSON object from file
     * @return EncryptedData (check success field)
     */
    static EncryptedData fromJson(const QJsonObject &json);

    /**
     * Generate cryptographically secure random bytes
     * @param length Number of bytes to generate
     * @return Random bytes
     */
    static QByteArray randomBytes(int length);

private:
    static constexpr int SALT_LENGTH = 16;
    static constexpr int IV_LENGTH = 12;      // GCM recommended IV size
    static constexpr int TAG_LENGTH = 16;     // GCM tag size
    static constexpr int KEY_LENGTH = 32;     // AES-256
    static constexpr int PBKDF2_ITERATIONS = 100000;

    /**
     * Derive encryption key from password using PBKDF2-SHA256
     */
    static QByteArray deriveKey(const QString &password, const QByteArray &salt);
};

#endif // CRYPTOHELPER_H
