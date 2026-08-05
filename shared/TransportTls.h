#ifndef TRANSPORTTLS_H
#define TRANSPORTTLS_H

#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>
#include <QString>
#include <QStringList>

/**
 * TransportTls - TLS policy for the operator client <-> ANIMO server channel.
 *
 * Deliberately separate from SslHelper: SslHelper encodes policy for Microsoft
 * endpoints (public CAs, optional pinning of MS roots). This channel is a
 * self-signed red-team server authenticated by SHA-256 certificate pin, which
 * is a different trust model and must not drift into the Microsoft one.
 *
 * Server side:
 *   TransportTls::ensureServerMaterial(cert, key, sans, &err);  // generates if absent
 *   TransportTls::loadServerMaterial(cert, key, &mat, &err);
 *   sslSocket->setSslConfiguration(TransportTls::serverConfiguration(mat));
 *
 * Client side:
 *   sslSocket->setSslConfiguration(TransportTls::clientConfiguration());
 *   // in the sslErrors handler, accept only when BOTH hold:
 *   TransportTls::isSelfSignedErrorSet(errors) && TransportTls::fingerprintMatches(cert, pin)
 */
namespace TransportTls {

/// Certificate + private key pair used to terminate TLS on the server.
struct Material {
    QSslCertificate cert;
    QSslKey key;
    bool isValid() const { return !cert.isNull() && !key.isNull(); }
};

/// SHA-256 over the DER encoding of the leaf certificate, formatted as
/// upper-case colon-separated hex ("AA:BB:CC:..."). Matches the fingerprint
/// browsers and `openssl x509 -fingerprint -sha256` display.
QString fingerprintSha256(const QSslCertificate &cert);

/// Strip formatting (colons, spaces, case) so pins can be pasted in any style.
QString normalizeFingerprint(const QString &fingerprint);

/// Constant-time comparison of a certificate against an expected pin.
/// Returns false for an empty pin - callers must never treat "no pin" as "any pin".
bool fingerprintMatches(const QSslCertificate &cert, const QString &expected);

/// True only if every error is one that a pinned self-signed certificate is
/// expected to raise. Any other error (expired, revoked, bad signature, ...)
/// makes this false, so the caller fails the handshake closed.
///
/// Use this with the LIST overload of QSslSocket::ignoreSslErrors(errors).
/// Never call the argument-less ignoreSslErrors() - it whitelists everything,
/// including errors raised after the pin check has already passed.
bool isSelfSignedErrorSet(const QList<QSslError> &errors);

/// TLS 1.2+ configuration for terminating connections on the server.
QSslConfiguration serverConfiguration(const Material &material);

/// TLS 1.2+ configuration for the client. Verification stays enabled so the
/// sslErrors handler is invoked and can enforce the pin; peer verification is
/// never silently disabled.
QSslConfiguration clientConfiguration();

/// Load PEM cert + key from disk. Fails if the key is readable by group/other.
bool loadServerMaterial(const QString &certPath, const QString &keyPath,
                        Material *out, QString *error);

/// Generate a self-signed cert + key at the given paths if either is missing.
/// No-op (returns true) when both already exist. The key is written 0600.
/// @param extraSans additional SAN entries, e.g. {"IP:10.0.0.5", "DNS:c2.lab"}
bool ensureServerMaterial(const QString &certPath, const QString &keyPath,
                          const QStringList &extraSans, QString *error);

/// Milliseconds a peer gets to finish the TLS handshake before being dropped.
/// Bounds the cost of a peer that connects and then goes silent.
int handshakeTimeoutMs();

} // namespace TransportTls

#endif // TRANSPORTTLS_H
