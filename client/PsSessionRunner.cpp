#include "PsSessionRunner.h"
#include "network/ClientTransport.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUuid>
#include <memory>

namespace {

QObject *locateTransportGlobal() {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

// Try to extract JSON from mixed stdout. Az cmdlets can emit warnings or
// progress lines before ConvertTo-Json output; find the first '{' or '['
// and parse from there. If parsing fails, returns Null and leaves it to the
// caller to interpret `raw`.
QJsonValue tryParseJson(const QString &raw) {
    const int braceIdx = raw.indexOf('{');
    const int brackIdx = raw.indexOf('[');
    int start = -1;
    if (braceIdx >= 0 && (brackIdx < 0 || braceIdx < brackIdx)) start = braceIdx;
    else if (brackIdx >= 0)                                     start = brackIdx;
    if (start < 0) return QJsonValue();

    const QByteArray bytes = raw.mid(start).toUtf8();
    QJsonParseError pe;
    const QJsonDocument d = QJsonDocument::fromJson(bytes, &pe);
    if (pe.error != QJsonParseError::NoError) return QJsonValue();
    if (d.isArray())  return d.array();
    if (d.isObject()) return d.object();
    return QJsonValue();
}

}  // namespace

bool PsSessionRunner::runRaw(QObject *context,
                             const QString &sessionId,
                             const QString &script,
                             Callback cb) {
    if (!cb) return false;
    if (sessionId.isEmpty()) {
        cb(false, QJsonValue(), QStringLiteral("no sessionId"));
        return false;
    }
    QObject *t = locateTransportGlobal();
    auto *typed = qobject_cast<ClientTransport*>(t);
    if (!typed) {
        cb(false, QJsonValue(),
           QStringLiteral("no ClientTransport - session terminal path unavailable"));
        return false;
    }

    const QString cmdId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    auto acc  = std::make_shared<QString>();
    auto conn = std::make_shared<QMetaObject::Connection>();
    *conn = QObject::connect(typed, &ClientTransport::messageReceived, context,
        [cmdId, acc, conn, cb](const QJsonObject &obj) {
            if (obj.value(QStringLiteral("cmdId")).toString() != cmdId) return;
            const QString act = obj.value(QStringLiteral("action")).toString();
            if (act == QLatin1String("output")) {
                acc->append(obj.value(QStringLiteral("data")).toString());
                acc->append('\n');
            } else if (act == QLatin1String("command_complete")) {
                QObject::disconnect(*conn);
                const bool ok = obj.value(QStringLiteral("ok")).toBool(true);
                // Prefer live-streamed output; if empty (server dropped it),
                // fall back to the DB-captured stdoutFallback field.
                QString raw = *acc;
                if (raw.trimmed().isEmpty()) {
                    raw = obj.value(QStringLiteral("stdoutFallback")).toString();
                }
                cb(ok, tryParseJson(raw), raw);
            }
        });

    QJsonObject req;
    req.insert(QStringLiteral("action"),    QStringLiteral("run_command"));
    req.insert(QStringLiteral("sessionId"), sessionId);
    req.insert(QStringLiteral("command"),   script);
    req.insert(QStringLiteral("cmdId"),     cmdId);
    typed->sendJson(req);
    return true;
}

bool PsSessionRunner::run(QObject *context,
                          const QString &sessionId,
                          const QString &script,
                          Callback cb,
                          bool wrap,
                          int depth) {
    if (!wrap) return runRaw(context, sessionId, script, std::move(cb));

    // @( ... ) forces array semantics so 0/1/many results all serialize as
    // an array. ConvertTo-Json -Depth N -Compress keeps the payload small and
    // deep enough for Az objects. -EnumsAsStrings and -EscapeHandling are
    // v7+ only, so skip them for compatibility with the pwsh we ship against.
    const QString wrapped = QString(
        "$__animo_result = @(%1) | ConvertTo-Json -Depth %2 -Compress -WarningAction SilentlyContinue;"
        "if($null -eq $__animo_result){'[]'}else{$__animo_result}").arg(script).arg(depth);
    return runRaw(context, sessionId, wrapped, std::move(cb));
}
