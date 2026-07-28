#ifndef TOKENORPSBRIDGE_H
#define TOKENORPSBRIDGE_H

#include <QObject>
#include <QString>
#include <QJsonValue>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkRequest>
#include <functional>

class QNetworkAccessManager;
class QNetworkReply;

// TokenOrPsBridge — one entry point for modules that need data about
// Entra / Azure / M365 but don't care whether it comes from an HTTP call or
// from `Get-Az*` / `Get-Mg*` in the session's pwsh.
//
// Decision order per fetch:
//   1) Existing valid access token in TokenStore for the required audience
//   2) Refresh-token exchange (works for user sessions with device-code /
//      credential / interactive tokens)
//   3) SPN client_credentials mint via SpnCredentialStore (works for SPN
//      sessions where we stashed the secret at login time)
//   4) Fall back to running the equivalent PowerShell in the session terminal
//      via PsSessionRunner (works when NONE of the above did - notably cert-
//      based SPNs, managed identity, or when the app permissions the token
//      would need aren't granted but the pwsh Connect-Az context has them)
//   5) Surface a single unified error describing what was tried
//
// Modules provide TWO recipes for the same data:
//   - httpUrl : Graph or ARM URL to GET (bearer-authenticated)
//   - psScript: the equivalent Get-Az* / Get-Mg* one-liner
// The bridge picks a path; both eventually produce a QJsonValue for the
// module to render.
class TokenOrPsBridge {
public:
    // Callback: ok, parsed JSON value, source ("http" or "ps" or "error"),
    // and a diagnostic error string when ok=false.
    using Callback = std::function<void(bool ok,
                                        const QJsonValue &result,
                                        const QString &source,
                                        const QString &error)>;

    struct Request {
        QString    sessionId;         // which session to run under
        QString    resource;          // e.g. https://graph.microsoft.com
        QString    httpUrl;           // e.g. https://graph.microsoft.com/v1.0/servicePrincipals
        QString    httpMethod = QStringLiteral("GET");  // "GET" or "POST" (default GET)
        QByteArray httpBody;          // JSON body when httpMethod == "POST"
        QString    psScript;          // e.g. Get-AzADServicePrincipal
        int        psDepth = 8;       // ConvertTo-Json -Depth
        bool       psWrap  = true;    // wrap script with @() | ConvertTo-Json
    };

    // Fire the fetch. `context` is a QObject that outlives the callback
    // (typically the module window `this`).
    static void fetch(QObject *context, const Request &req, Callback cb);
};

#endif  // TOKENORPSBRIDGE_H
