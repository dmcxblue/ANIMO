#ifndef DEVICECRYPTOHELPER_H
#define DEVICECRYPTOHELPER_H

#include <QByteArray>
#include <QJsonObject>
#include <QString>

// DeviceCryptoHelper - pure-OpenSSL primitives for Entra device
// registration (DRS join) and cert-based PRT mint.
//
// Split from CryptoHelper (which only ships AES-256-GCM + PBKDF2) because
// device registration needs asymmetric RSA + X.509 CSR + JWT-RS256
// signing, none of which Qt exposes. All three sit on top of libssl /
// libcrypto directly (already linked PUBLIC into shared/, transitively
// available in client/).
//
// No global state; every call is self-contained. Errors surface via
// KeyPair::success + errorMessage or an empty QByteArray / QString.
class DeviceCryptoHelper {
public:
    struct KeyPair {
        QByteArray privateKeyPem;  // PKCS#8 PEM
        QByteArray publicKeyPem;   // SubjectPublicKeyInfo PEM
        bool       success = false;
        QString    errorMessage;
    };

    // Generate an RSA-2048 keypair.
    static KeyPair generateRsa2048();

    // Build a PKCS#10 CSR (PEM) signed with SHA256 using the given
    // private key. `commonName` is placed in CN=. DRS accepts a fixed
    // GUID CN in production; caller decides.
    static QByteArray buildCsr(const QByteArray &privateKeyPem,
                               const QString    &commonName,
                               QString          *errOut = nullptr);

    // Same CSR PEM but stripped of BEGIN/END lines and whitespace so it
    // can be dropped straight into the DRS enroll JSON body (which wants
    // the base64-encoded DER form of the CSR content).
    static QByteArray csrPemToDrsBase64(const QByteArray &csrPem);

    // Sign a JWT RS256 with the given RSA private key.
    // `header` should already carry {alg:"RS256", typ:"JWT", ...}.
    // Returns the compact serialization
    //   base64url(header) + "." + base64url(payload) + "." + base64url(sig)
    // Used for cert-based client_assertion when minting a PRT from a
    // registered device.
    static QString signJwtRS256(const QByteArray &privateKeyPem,
                                const QJsonObject &header,
                                const QJsonObject &payload,
                                QString           *errOut = nullptr);

    // Compute the SHA-256 thumbprint of a PEM cert (hex, uppercase, no
    // separators). Useful for `x5t#S256` claims and UI display.
    static QString certSha256Thumbprint(const QByteArray &certPem);
};

#endif  // DEVICECRYPTOHELPER_H
