#include "DeviceCryptoHelper.h"

#include <QJsonDocument>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

namespace {

// Small RAII holders so a mid-function early return can't leak.
struct BioHolder    { BIO      *b = nullptr; ~BioHolder()    { if (b)   BIO_free(b);           } };
struct EvpKeyHolder { EVP_PKEY *k = nullptr; ~EvpKeyHolder() { if (k)   EVP_PKEY_free(k);      } };
struct X509ReqHolder{ X509_REQ *r = nullptr; ~X509ReqHolder(){ if (r)   X509_REQ_free(r);      } };
struct MdCtxHolder  { EVP_MD_CTX *c = nullptr; ~MdCtxHolder(){ if (c)   EVP_MD_CTX_free(c);    } };

QString opensslError() {
    QByteArray out;
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256]{};
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.isEmpty()) out.append("; ");
        out.append(buf);
    }
    return QString::fromLatin1(out);
}

QByteArray pemFromBio(BIO *b) {
    BUF_MEM *mem = nullptr;
    BIO_get_mem_ptr(b, &mem);
    if (!mem || !mem->data) return {};
    return QByteArray(mem->data, int(mem->length));
}

EVP_PKEY *loadPrivateKey(const QByteArray &pem, QString *errOut) {
    BioHolder mem;
    mem.b = BIO_new_mem_buf(pem.constData(), int(pem.size()));
    if (!mem.b) { if (errOut) *errOut = "BIO_new_mem_buf failed"; return nullptr; }
    EVP_PKEY *k = PEM_read_bio_PrivateKey(mem.b, nullptr, nullptr, nullptr);
    if (!k && errOut) *errOut = QString("PEM_read_bio_PrivateKey: %1").arg(opensslError());
    return k;
}

// URL-safe base64 without padding, per JWT spec (RFC 7515).
QByteArray b64url(const QByteArray &in) {
    QByteArray out = in.toBase64();
    out.replace('+', '-').replace('/', '_');
    while (out.endsWith('=')) out.chop(1);
    return out;
}

}  // namespace

DeviceCryptoHelper::KeyPair DeviceCryptoHelper::generateRsa2048() {
    KeyPair kp;

    EvpKeyHolder pkey;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) { kp.errorMessage = "EVP_PKEY_CTX_new_id: " + opensslError(); return kp; }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        kp.errorMessage = "EVP_PKEY_keygen_init: " + opensslError();
        return kp;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        kp.errorMessage = "EVP_PKEY_CTX_set_rsa_keygen_bits: " + opensslError();
        return kp;
    }
    if (EVP_PKEY_keygen(ctx, &pkey.k) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        kp.errorMessage = "EVP_PKEY_keygen: " + opensslError();
        return kp;
    }
    EVP_PKEY_CTX_free(ctx);

    // Serialize private key (PKCS#8) and public key (SPKI) to PEM.
    BioHolder privBio; privBio.b = BIO_new(BIO_s_mem());
    BioHolder pubBio;  pubBio.b  = BIO_new(BIO_s_mem());
    if (!privBio.b || !pubBio.b) { kp.errorMessage = "BIO_new failed"; return kp; }

    if (!PEM_write_bio_PrivateKey(privBio.b, pkey.k, nullptr, nullptr, 0, nullptr, nullptr)) {
        kp.errorMessage = "PEM_write_bio_PrivateKey: " + opensslError();
        return kp;
    }
    if (!PEM_write_bio_PUBKEY(pubBio.b, pkey.k)) {
        kp.errorMessage = "PEM_write_bio_PUBKEY: " + opensslError();
        return kp;
    }

    kp.privateKeyPem = pemFromBio(privBio.b);
    kp.publicKeyPem  = pemFromBio(pubBio.b);
    kp.success = !kp.privateKeyPem.isEmpty() && !kp.publicKeyPem.isEmpty();
    if (!kp.success && kp.errorMessage.isEmpty()) kp.errorMessage = "empty PEM after write";
    return kp;
}

QByteArray DeviceCryptoHelper::buildCsr(const QByteArray &privateKeyPem,
                                        const QString    &commonName,
                                        QString          *errOut) {
    EvpKeyHolder key;
    key.k = loadPrivateKey(privateKeyPem, errOut);
    if (!key.k) return {};

    X509ReqHolder req;
    req.r = X509_REQ_new();
    if (!req.r) { if (errOut) *errOut = "X509_REQ_new: " + opensslError(); return {}; }

    X509_REQ_set_version(req.r, 0);
    X509_NAME *name = X509_REQ_get_subject_name(req.r);
    const QByteArray cnUtf8 = commonName.toUtf8();
    if (!X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_UTF8,
            reinterpret_cast<const unsigned char*>(cnUtf8.constData()),
            cnUtf8.size(), -1, 0)) {
        if (errOut) *errOut = "X509_NAME_add_entry_by_txt: " + opensslError();
        return {};
    }
    if (!X509_REQ_set_pubkey(req.r, key.k)) {
        if (errOut) *errOut = "X509_REQ_set_pubkey: " + opensslError();
        return {};
    }
    if (X509_REQ_sign(req.r, key.k, EVP_sha256()) <= 0) {
        if (errOut) *errOut = "X509_REQ_sign: " + opensslError();
        return {};
    }

    BioHolder out; out.b = BIO_new(BIO_s_mem());
    if (!out.b) { if (errOut) *errOut = "BIO_new failed"; return {}; }
    if (!PEM_write_bio_X509_REQ(out.b, req.r)) {
        if (errOut) *errOut = "PEM_write_bio_X509_REQ: " + opensslError();
        return {};
    }
    return pemFromBio(out.b);
}

QByteArray DeviceCryptoHelper::csrPemToDrsBase64(const QByteArray &csrPem) {
    // DRS wants the base64-encoded DER form of the CSR content. In
    // practice, stripping the PEM armor and joining the middle lines is
    // exactly what the endpoint accepts (the middle of a PEM is
    // base64-encoded DER already).
    QList<QByteArray> lines = csrPem.split('\n');
    QByteArray joined;
    for (const QByteArray &line : lines) {
        if (line.startsWith("-----")) continue;
        joined.append(line.trimmed());
    }
    return joined;
}

QString DeviceCryptoHelper::signJwtRS256(const QByteArray &privateKeyPem,
                                         const QJsonObject &header,
                                         const QJsonObject &payload,
                                         QString           *errOut) {
    EvpKeyHolder key;
    key.k = loadPrivateKey(privateKeyPem, errOut);
    if (!key.k) return {};

    const QByteArray hEnc = b64url(QJsonDocument(header).toJson(QJsonDocument::Compact));
    const QByteArray pEnc = b64url(QJsonDocument(payload).toJson(QJsonDocument::Compact));
    const QByteArray signingInput = hEnc + "." + pEnc;

    MdCtxHolder ctx; ctx.c = EVP_MD_CTX_new();
    if (!ctx.c) { if (errOut) *errOut = "EVP_MD_CTX_new failed"; return {}; }

    if (EVP_DigestSignInit(ctx.c, nullptr, EVP_sha256(), nullptr, key.k) <= 0) {
        if (errOut) *errOut = "EVP_DigestSignInit: " + opensslError();
        return {};
    }
    if (EVP_DigestSignUpdate(ctx.c, signingInput.constData(), signingInput.size()) <= 0) {
        if (errOut) *errOut = "EVP_DigestSignUpdate: " + opensslError();
        return {};
    }
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(ctx.c, nullptr, &sigLen) <= 0) {
        if (errOut) *errOut = "EVP_DigestSignFinal (size probe): " + opensslError();
        return {};
    }
    QByteArray sig(int(sigLen), 0);
    if (EVP_DigestSignFinal(ctx.c,
                            reinterpret_cast<unsigned char*>(sig.data()),
                            &sigLen) <= 0) {
        if (errOut) *errOut = "EVP_DigestSignFinal: " + opensslError();
        return {};
    }
    sig.resize(int(sigLen));

    return QString::fromLatin1(signingInput + "." + b64url(sig));
}

QString DeviceCryptoHelper::certSha256Thumbprint(const QByteArray &certPem) {
    BioHolder mem;
    mem.b = BIO_new_mem_buf(certPem.constData(), int(certPem.size()));
    if (!mem.b) return {};
    X509 *cert = PEM_read_bio_X509(mem.b, nullptr, nullptr, nullptr);
    if (!cert) return {};

    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int  digestLen = 0;
    if (!X509_digest(cert, EVP_sha256(), digest, &digestLen)) {
        X509_free(cert);
        return {};
    }
    X509_free(cert);
    QByteArray hex = QByteArray(reinterpret_cast<const char*>(digest), int(digestLen)).toHex();
    return QString::fromLatin1(hex).toUpper();
}
