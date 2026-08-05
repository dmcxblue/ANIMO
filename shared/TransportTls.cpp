#include "TransportTls.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostInfo>
#include <QSslSocket>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

constexpr int RSA_KEY_BITS       = 2048;   // fast enough to generate on first start
constexpr int CERT_VALIDITY_DAYS = 3650;
constexpr int HANDSHAKE_TIMEOUT_MS = 10000;

// Write PEM bytes to disk, creating the parent directory. When `ownerOnly` is
// set the file is restricted to 0600 before any bytes are written, so the key
// is never briefly world-readable.
bool writePemFile(const QString &path, const QByteArray &pem, bool ownerOnly, QString *error) {
    const QFileInfo fi(path);
    if (!QDir().mkpath(fi.absolutePath())) {
        if (error) *error = QStringLiteral("cannot create directory %1").arg(fi.absolutePath());
        return false;
    }

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = QStringLiteral("cannot write %1: %2").arg(path, f.errorString());
        return false;
    }
    if (ownerOnly && !f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        f.close();
        f.remove();
        if (error) *error = QStringLiteral("cannot restrict permissions on %1").arg(path);
        return false;
    }
    if (f.write(pem) != pem.size()) {
        f.close();
        f.remove();
        if (error) *error = QStringLiteral("short write to %1").arg(path);
        return false;
    }
    f.close();
    return true;
}

// Pull the contents of a memory BIO out as a QByteArray.
QByteArray bioToByteArray(BIO *bio) {
    char *data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (!data || len <= 0) return QByteArray();
    return QByteArray(data, static_cast<int>(len));
}

bool addExtension(X509 *cert, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ext) return false;
    const int rc = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return rc == 1;
}

EVP_PKEY *generateRsaKey() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) != 1 ||
        EVP_PKEY_keygen(ctx, &pkey) != 1) {
        if (pkey) EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Serial numbers must be positive and unpredictable; a random 64-bit value is
// plenty for a self-signed leaf that is trusted by fingerprint anyway.
bool setRandomSerial(X509 *cert) {
    unsigned char buf[8];
    if (RAND_bytes(buf, sizeof(buf)) != 1) return false;
    buf[0] &= 0x7F; // keep it positive

    BIGNUM *bn = BN_bin2bn(buf, sizeof(buf), nullptr);
    if (!bn) return false;
    ASN1_INTEGER *serial = BN_to_ASN1_INTEGER(bn, nullptr);
    BN_free(bn);
    if (!serial) return false;

    const int rc = X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);
    return rc == 1;
}

} // namespace

namespace TransportTls {

int handshakeTimeoutMs() { return HANDSHAKE_TIMEOUT_MS; }

QString fingerprintSha256(const QSslCertificate &cert) {
    if (cert.isNull()) return QString();
    const QByteArray digest = QCryptographicHash::hash(cert.toDer(), QCryptographicHash::Sha256);
    return QString::fromLatin1(digest.toHex(':')).toUpper();
}

QString normalizeFingerprint(const QString &fingerprint) {
    QString out;
    out.reserve(fingerprint.size());
    for (const QChar c : fingerprint) {
        if (c.isLetterOrNumber()) out.append(c.toUpper());
    }
    return out;
}

bool fingerprintMatches(const QSslCertificate &cert, const QString &expected) {
    // An empty pin means "we do not know what to trust" - never a match.
    if (expected.trimmed().isEmpty() || cert.isNull()) return false;

    const QByteArray actual = normalizeFingerprint(fingerprintSha256(cert)).toLatin1();
    const QByteArray want   = normalizeFingerprint(expected).toLatin1();
    if (actual.isEmpty() || actual.size() != want.size()) return false;

    // Constant-time compare, mirroring Server::constantTimeCompare.
    unsigned char diff = 0;
    for (int i = 0; i < actual.size(); ++i)
        diff |= static_cast<unsigned char>(actual[i] ^ want[i]);
    return diff == 0;
}

bool isSelfSignedErrorSet(const QList<QSslError> &errors) {
    if (errors.isEmpty()) return true;
    for (const QSslError &e : errors) {
        switch (e.error()) {
        case QSslError::SelfSignedCertificate:
        case QSslError::SelfSignedCertificateInChain:
        case QSslError::CertificateUntrusted:
        case QSslError::UnableToGetLocalIssuerCertificate:
        case QSslError::UnableToVerifyFirstCertificate:
        case QSslError::HostNameMismatch:
            break; // expected for a pinned self-signed server certificate
        default:
            return false; // expired, revoked, bad signature, ... - fail closed
        }
    }
    return true;
}

QSslConfiguration serverConfiguration(const Material &material) {
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setProtocol(QSsl::TlsV1_2OrLater);
    cfg.setLocalCertificate(material.cert);
    cfg.setPrivateKey(material.key);
    // Phase 1 authenticates the server only; operator identity is still the
    // shared password. Client certificates arrive with mTLS in a later phase.
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    return cfg;
}

QSslConfiguration clientConfiguration() {
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setProtocol(QSsl::TlsV1_2OrLater);
    // VerifyPeer keeps the sslErrors handler in play; the pin check lives there.
    cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
    return cfg;
}

bool loadServerMaterial(const QString &certPath, const QString &keyPath,
                        Material *out, QString *error) {
    if (!out) return false;

    QFile certFile(certPath);
    if (!certFile.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("cannot read certificate %1: %2")
                                .arg(certPath, certFile.errorString());
        return false;
    }
    const QSslCertificate cert(&certFile, QSsl::Pem);
    certFile.close();
    if (cert.isNull()) {
        if (error) *error = QStringLiteral("%1 is not a valid PEM certificate").arg(certPath);
        return false;
    }

#ifndef Q_OS_WIN
    // A private key other local users can read is a finding, not a warning.
    const QFileDevice::Permissions perms = QFile(keyPath).permissions();
    if (perms & (QFileDevice::ReadGroup | QFileDevice::ReadOther |
                 QFileDevice::WriteGroup | QFileDevice::WriteOther)) {
        if (error) *error = QStringLiteral(
            "private key %1 is accessible to other users - run: chmod 600 %1").arg(keyPath);
        return false;
    }
#endif

    QFile keyFile(keyPath);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("cannot read private key %1: %2")
                                .arg(keyPath, keyFile.errorString());
        return false;
    }
    QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    if (key.isNull()) {
        keyFile.seek(0);
        key = QSslKey(&keyFile, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
    }
    keyFile.close();
    if (key.isNull()) {
        if (error) *error = QStringLiteral(
            "%1 is not a valid unencrypted PEM private key").arg(keyPath);
        return false;
    }

    out->cert = cert;
    out->key  = key;
    return true;
}

bool ensureServerMaterial(const QString &certPath, const QString &keyPath,
                          const QStringList &extraSans, QString *error) {
    const bool haveCert = QFileInfo::exists(certPath);
    const bool haveKey  = QFileInfo::exists(keyPath);
    if (haveCert && haveKey) return true;

    // Refuse to silently regenerate half a pair - that would rotate the
    // fingerprint out from under every operator who has already pinned it.
    if (haveCert != haveKey) {
        if (error) *error = QStringLiteral(
            "incomplete TLS material: %1 exists but %2 does not - remove the "
            "leftover file to regenerate, or supply both")
            .arg(haveCert ? certPath : keyPath, haveCert ? keyPath : certPath);
        return false;
    }

    EVP_PKEY *pkey = generateRsaKey();
    if (!pkey) {
        if (error) *error = QStringLiteral("RSA key generation failed");
        return false;
    }

    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        if (error) *error = QStringLiteral("certificate allocation failed");
        return false;
    }

    QByteArray certPem;
    QByteArray keyPem;
    bool ok = false;

    do {
        if (X509_set_version(cert, 2) != 1) break;           // v3
        if (!setRandomSerial(cert)) break;
        if (!X509_gmtime_adj(X509_get_notBefore(cert), 0)) break;
        if (!X509_gmtime_adj(X509_get_notAfter(cert),
                             60L * 60L * 24L * CERT_VALIDITY_DAYS)) break;
        if (X509_set_pubkey(cert, pkey) != 1) break;

        X509_NAME *name = X509_get_subject_name(cert);
        if (!name) break;
        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char *>("animo-server"), -1, -1, 0) != 1) break;
        if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                reinterpret_cast<const unsigned char *>("ANIMO"), -1, -1, 0) != 1) break;
        if (X509_set_issuer_name(cert, name) != 1) break;    // self-signed

        QStringList sans;
        sans << QStringLiteral("DNS:localhost")
             << QStringLiteral("IP:127.0.0.1")
             << QStringLiteral("IP:::1");
        const QString host = QHostInfo::localHostName();
        if (!host.isEmpty() && host != QLatin1String("localhost"))
            sans << QStringLiteral("DNS:%1").arg(host);
        for (const QString &s : extraSans) {
            if (!s.trimmed().isEmpty() && !sans.contains(s)) sans << s;
        }

        if (!addExtension(cert, NID_subject_alt_name, sans.join(',').toLatin1().constData())) break;
        if (!addExtension(cert, NID_basic_constraints, "critical,CA:FALSE")) break;
        if (!addExtension(cert, NID_key_usage, "critical,digitalSignature,keyEncipherment")) break;
        if (!addExtension(cert, NID_ext_key_usage, "serverAuth")) break;
        if (!addExtension(cert, NID_subject_key_identifier, "hash")) break;

        if (X509_sign(cert, pkey, EVP_sha256()) == 0) break;

        BIO *certBio = BIO_new(BIO_s_mem());
        if (certBio) {
            if (PEM_write_bio_X509(certBio, cert) == 1) certPem = bioToByteArray(certBio);
            BIO_free(certBio);
        }
        BIO *keyBio = BIO_new(BIO_s_mem());
        if (keyBio) {
            if (PEM_write_bio_PrivateKey(keyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1)
                keyPem = bioToByteArray(keyBio);
            BIO_free(keyBio);
        }
        ok = !certPem.isEmpty() && !keyPem.isEmpty();
    } while (false);

    X509_free(cert);
    EVP_PKEY_free(pkey);

    if (!ok) {
        if (error) *error = QStringLiteral("self-signed certificate generation failed");
        return false;
    }

    // Key first and owner-only, so a failure never leaves a usable cert next to
    // a world-readable key.
    if (!writePemFile(keyPath, keyPem, /*ownerOnly=*/true, error)) return false;
    if (!writePemFile(certPath, certPem, /*ownerOnly=*/false, error)) {
        QFile::remove(keyPath);
        return false;
    }
    return true;
}

} // namespace TransportTls
