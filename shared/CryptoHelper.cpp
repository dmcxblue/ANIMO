#include "CryptoHelper.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <QJsonDocument>

QByteArray CryptoHelper::randomBytes(int length) {
    QByteArray result(length, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), length) != 1) {
        // Fallback - should not happen with proper OpenSSL
        return QByteArray();
    }
    return result;
}

QByteArray CryptoHelper::deriveKey(const QString &password, const QByteArray &salt) {
    QByteArray key(KEY_LENGTH, 0);
    QByteArray pwd = password.toUtf8();

    int result = PKCS5_PBKDF2_HMAC(
        pwd.constData(),
        pwd.size(),
        reinterpret_cast<const unsigned char*>(salt.constData()),
        salt.size(),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        KEY_LENGTH,
        reinterpret_cast<unsigned char*>(key.data())
    );

    if (result != 1) {
        return QByteArray();
    }

    return key;
}

CryptoHelper::EncryptedData CryptoHelper::encrypt(const QByteArray &plaintext, const QString &password) {
    EncryptedData result;

    if (plaintext.isEmpty() || password.isEmpty()) {
        result.errorMessage = "Plaintext and password cannot be empty";
        return result;
    }

    // Generate random salt and IV
    result.salt = randomBytes(SALT_LENGTH);
    result.iv = randomBytes(IV_LENGTH);

    if (result.salt.isEmpty() || result.iv.isEmpty()) {
        result.errorMessage = "Failed to generate random bytes";
        return result;
    }

    // Derive key from password
    QByteArray key = deriveKey(password, result.salt);
    if (key.isEmpty()) {
        result.errorMessage = "Failed to derive encryption key";
        return result;
    }

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.errorMessage = "Failed to create cipher context";
        return result;
    }

    // Set up AES-256-GCM encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to initialize encryption";
        return result;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to set IV length";
        return result;
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           reinterpret_cast<const unsigned char*>(result.iv.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to set key and IV";
        return result;
    }

    // Allocate output buffer (plaintext size + block size for padding)
    result.ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));

    int outLen = 0;
    int totalLen = 0;

    // Encrypt the data
    if (EVP_EncryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(result.ciphertext.data()),
                          &outLen,
                          reinterpret_cast<const unsigned char*>(plaintext.constData()),
                          plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Encryption failed";
        return result;
    }
    totalLen = outLen;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(result.ciphertext.data()) + totalLen,
                            &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Encryption finalization failed";
        return result;
    }
    totalLen += outLen;
    result.ciphertext.resize(totalLen);

    // Get authentication tag
    result.tag.resize(TAG_LENGTH);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH,
                            result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to get authentication tag";
        return result;
    }

    EVP_CIPHER_CTX_free(ctx);
    result.success = true;
    return result;
}

CryptoHelper::DecryptedData CryptoHelper::decrypt(const QByteArray &salt,
                                                   const QByteArray &iv,
                                                   const QByteArray &ciphertext,
                                                   const QByteArray &tag,
                                                   const QString &password) {
    DecryptedData result;

    if (salt.isEmpty() || iv.isEmpty() || ciphertext.isEmpty() || tag.isEmpty() || password.isEmpty()) {
        result.errorMessage = "Invalid parameters for decryption";
        return result;
    }

    // Derive key from password
    QByteArray key = deriveKey(password, salt);
    if (key.isEmpty()) {
        result.errorMessage = "Failed to derive decryption key";
        return result;
    }

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.errorMessage = "Failed to create cipher context";
        return result;
    }

    // Set up AES-256-GCM decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to initialize decryption";
        return result;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to set IV length";
        return result;
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           reinterpret_cast<const unsigned char*>(iv.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to set key and IV";
        return result;
    }

    // Allocate output buffer
    result.plaintext.resize(ciphertext.size());

    int outLen = 0;
    int totalLen = 0;

    // Decrypt the data
    if (EVP_DecryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(result.plaintext.data()),
                          &outLen,
                          reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                          ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Decryption failed";
        return result;
    }
    totalLen = outLen;

    // Set expected tag value (copy tag to mutable buffer for OpenSSL API)
    QByteArray tagCopy = tag;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH,
                            tagCopy.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        result.errorMessage = "Failed to set authentication tag";
        return result;
    }

    // Finalize decryption and verify tag
    int ret = EVP_DecryptFinal_ex(ctx,
                                   reinterpret_cast<unsigned char*>(result.plaintext.data()) + totalLen,
                                   &outLen);

    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        result.errorMessage = "Authentication failed - wrong password or corrupted data";
        result.plaintext.clear();
        return result;
    }

    totalLen += outLen;
    result.plaintext.resize(totalLen);
    result.success = true;
    return result;
}

QJsonObject CryptoHelper::toJson(const EncryptedData &data) {
    QJsonObject json;
    json["version"] = "1.0";
    json["algorithm"] = "AES-256-GCM";
    json["kdf"] = "PBKDF2-SHA256";
    json["iterations"] = PBKDF2_ITERATIONS;
    json["salt"] = QString::fromLatin1(data.salt.toBase64());
    json["iv"] = QString::fromLatin1(data.iv.toBase64());
    json["tag"] = QString::fromLatin1(data.tag.toBase64());
    json["data"] = QString::fromLatin1(data.ciphertext.toBase64());
    return json;
}

CryptoHelper::EncryptedData CryptoHelper::fromJson(const QJsonObject &json) {
    EncryptedData result;

    // Validate required fields
    if (!json.contains("salt") || !json.contains("iv") ||
        !json.contains("tag") || !json.contains("data")) {
        result.errorMessage = "Invalid encrypted file format";
        return result;
    }

    // Check version compatibility
    QString version = json.value("version").toString();
    if (!version.isEmpty() && version != "1.0") {
        result.errorMessage = QString("Unsupported file version: %1").arg(version);
        return result;
    }

    result.salt = QByteArray::fromBase64(json.value("salt").toString().toLatin1());
    result.iv = QByteArray::fromBase64(json.value("iv").toString().toLatin1());
    result.tag = QByteArray::fromBase64(json.value("tag").toString().toLatin1());
    result.ciphertext = QByteArray::fromBase64(json.value("data").toString().toLatin1());

    // Validate sizes
    if (result.salt.size() != SALT_LENGTH) {
        result.errorMessage = "Invalid salt size";
        return result;
    }
    if (result.iv.size() != IV_LENGTH) {
        result.errorMessage = "Invalid IV size";
        return result;
    }
    if (result.tag.size() != TAG_LENGTH) {
        result.errorMessage = "Invalid authentication tag size";
        return result;
    }

    result.success = true;
    return result;
}
