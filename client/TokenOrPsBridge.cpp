#include "TokenOrPsBridge.h"
#include "TokenStore.h"
#include "TokenHelper.h"
#include "PsSessionRunner.h"
#include "NetworkHelper.h"

#include <QCoreApplication>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <memory>

namespace {

// Small holder that owns the NAM per-fetch. Deleted after the callback fires
// so we don't leak between calls.
struct HttpCtx {
    QNetworkAccessManager *nam = nullptr;
    ~HttpCtx() { if (nam) nam->deleteLater(); }
};

// Issue the HTTP request with `token`. Uses req.httpMethod (default GET) and
// req.httpBody when POSTing. On success, parse JSON and hand off. On any HTTP
// or parse failure, invoke the PS fallback.
void doHttpRequest(QObject *context,
                   const QString &sessionId,
                   const QString &token,
                   const TokenOrPsBridge::Request &req,
                   TokenOrPsBridge::Callback cb) {
    auto ctx = std::make_shared<HttpCtx>();
    ctx->nam = new QNetworkAccessManager();
    ctx->nam->moveToThread(QCoreApplication::instance()->thread());

    QNetworkRequest netReq = NetworkHelper::createBearerRequest(req.httpUrl, token);
    QNetworkReply *reply = nullptr;
    if (req.httpMethod.compare(QStringLiteral("POST"), Qt::CaseInsensitive) == 0) {
        reply = ctx->nam->post(netReq, req.httpBody);
    } else {
        reply = ctx->nam->get(netReq);
    }
    if (!reply) {
        cb(false, QJsonValue(), QStringLiteral("error"),
           QStringLiteral("failed to issue HTTP request"));
        return;
    }
    QObject::connect(reply, &QNetworkReply::finished, context,
        [reply, ctx, context, sessionId, req, cb]() {
            reply->deleteLater();
            QString err;
            if (!NetworkHelper::isReplySuccess(reply, &err)) {
                // HTTP failed - try the PS path as fallback rather than surfacing
                // a token error to the user. Common causes here: insufficient
                // Graph permissions, throttling, temp network blip.
                if (!req.psScript.isEmpty()) {
                    PsSessionRunner::run(context, sessionId, req.psScript,
                        [cb, err](bool ok, const QJsonValue &json, const QString &raw) {
                            if (ok && !json.isNull()) {
                                cb(true, json, QStringLiteral("ps"), QString());
                            } else {
                                cb(false, QJsonValue(), QStringLiteral("error"),
                                   QString("HTTP failed (%1) and PS fallback failed: %2")
                                       .arg(err, raw.left(240)));
                            }
                        }, req.psWrap, req.psDepth);
                    return;
                }
                cb(false, QJsonValue(), QStringLiteral("error"), err);
                return;
            }
            const QByteArray body = reply->readAll();
            QJsonParseError pe;
            const QJsonDocument d = QJsonDocument::fromJson(body, &pe);
            if (pe.error != QJsonParseError::NoError) {
                cb(false, QJsonValue(), QStringLiteral("error"),
                   QString("JSON parse: %1").arg(pe.errorString()));
                return;
            }
            if (d.isObject()) cb(true, d.object(), QStringLiteral("http"), QString());
            else if (d.isArray()) cb(true, d.array(), QStringLiteral("http"), QString());
            else                  cb(true, QJsonValue(), QStringLiteral("http"), QString());
        });
}

// Run PS-only, no HTTP attempt. Used when no token can be minted.
void doPsOnly(QObject *context,
              const QString &sessionId,
              const TokenOrPsBridge::Request &req,
              TokenOrPsBridge::Callback cb) {
    if (req.psScript.isEmpty()) {
        cb(false, QJsonValue(), QStringLiteral("error"),
           QStringLiteral("no PS script provided and no token could be obtained"));
        return;
    }
    PsSessionRunner::run(context, sessionId, req.psScript,
        [cb](bool ok, const QJsonValue &json, const QString &raw) {
            if (ok && !json.isNull()) {
                cb(true, json, QStringLiteral("ps"), QString());
            } else {
                cb(false, QJsonValue(), QStringLiteral("error"),
                   QString("PS path failed: %1").arg(raw.left(240)));
            }
        }, req.psWrap, req.psDepth);
}

}  // namespace

void TokenOrPsBridge::fetch(QObject *context, const Request &req, Callback cb) {
    if (!cb) return;
    if (req.sessionId.isEmpty()) {
        cb(false, QJsonValue(), QStringLiteral("error"),
           QStringLiteral("no session selected"));
        return;
    }

    // Tier 1: existing valid token for this session + resource
    const QString existing = TokenHelper::instance()->getExistingTokenForSession(req.resource, req.sessionId);
    if (!existing.isEmpty() && !req.httpUrl.isEmpty()) {
        doHttpRequest(context, req.sessionId, existing, req, cb);
        return;
    }

    // Tier 2/3: TokenHelper::getTokenForResourceBySession internally handles
    // both refresh-token exchange (user sessions) and SPN client_credentials
    // mint (SPN sessions where SpnCredentialStore has the secret).
    if (!req.httpUrl.isEmpty()) {
        TokenHelper::instance()->getTokenForResourceBySession(
            req.resource,
            [context, req, cb](bool ok, const QString &token, const QString &err) {
                if (ok && !token.isEmpty()) {
                    doHttpRequest(context, req.sessionId, token, req, cb);
                } else {
                    // Tier 4: fall back to PS. This is the path that saves
                    // cert-based SPNs, managed identity, or any session where
                    // we can't mint a token but pwsh has an Az context.
                    if (!req.psScript.isEmpty()) {
                        doPsOnly(context, req.sessionId, req, cb);
                    } else {
                        cb(false, QJsonValue(), QStringLiteral("error"),
                           QString("no token (%1) and no PS fallback").arg(err));
                    }
                }
            },
            req.sessionId);
        return;
    }

    // No HTTP recipe at all - go straight to PS.
    doPsOnly(context, req.sessionId, req, cb);
}
