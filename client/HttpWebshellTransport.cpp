#include "HttpWebshellTransport.h"
#include "NetworkHelper.h"

#include <QRegularExpression>
#include <QUrlQuery>

HttpWebshellTransport::HttpWebshellTransport(const Config &cfg, QObject *parent)
    : RemoteExecTransport(parent),
      m_cfg(cfg),
      m_net(new QNetworkAccessManager(this))
{}

HttpWebshellTransport::~HttpWebshellTransport() { cancel(); }

bool HttpWebshellTransport::isReady(QString *why) const {
    if (m_cfg.baseUrl.isEmpty()) { if (why) *why = "no base URL";       return false; }
    if (m_cfg.cmdParam.isEmpty()){ if (why) *why = "no command param";  return false; }
    if (m_inFlight)              { if (why) *why = "already in flight"; return false; }
    return true;
}

QUrl HttpWebshellTransport::buildUrl(const QString &payload, QByteArray *bodyOut) const {
    QUrl url(m_cfg.baseUrl);
    QUrlQuery q;
    for (auto it = m_cfg.extraParams.constBegin(); it != m_cfg.extraParams.constEnd(); ++it)
        q.addQueryItem(it.key(), it.value());

    if (m_cfg.method.compare("POST", Qt::CaseInsensitive) == 0) {
        // POST: extra params + cmd go in body as form-urlencoded.
        q.addQueryItem(m_cfg.cmdParam, payload);
        if (bodyOut) *bodyOut = q.query(QUrl::FullyEncoded).toUtf8();
        // Keep any query already on the URL as-is.
    } else {
        // GET: cmd + extra params in query string.
        QUrlQuery existing(url);
        for (const auto &item : q.queryItems()) existing.addQueryItem(item.first, item.second);
        existing.addQueryItem(m_cfg.cmdParam, payload);
        url.setQuery(existing);
    }
    return url;
}

QString HttpWebshellTransport::applyExtractor(const QByteArray &body) const {
    const QString text = QString::fromUtf8(body);
    if (m_cfg.outputExtract.compare("regex", Qt::CaseInsensitive) == 0) {
        if (m_cfg.outputRegex.isEmpty()) return text;
        const QRegularExpression re(m_cfg.outputRegex,
                                    QRegularExpression::DotMatchesEverythingOption
                                    | QRegularExpression::MultilineOption);
        const auto m = re.match(text);
        if (m.hasMatch()) return m.captured(1);
        return QStringLiteral("[extractor: regex did not match]\n") + text.left(4096);
    }
    if (m_cfg.outputExtract.compare("between", Qt::CaseInsensitive) == 0) {
        const int a = text.indexOf(m_cfg.markerStart);
        if (a < 0) return QStringLiteral("[extractor: start marker not found]");
        const int b = text.indexOf(m_cfg.markerEnd, a + m_cfg.markerStart.size());
        if (b < 0) return QStringLiteral("[extractor: end marker not found]");
        return text.mid(a + m_cfg.markerStart.size(), b - a - m_cfg.markerStart.size());
    }
    return text;  // raw
}

void HttpWebshellTransport::execute(const QString &command, Callback cb) {
    if (!cb) return;
    if (m_inFlight) { cb({ false, "already in flight", {}, -1, 0 }); return; }
    m_cb = std::move(cb);
    m_inFlight = true;
    m_elapsed.start();

    const QString payload = transformCommand(command);
    QByteArray body;
    const QUrl url = buildUrl(payload, &body);

    QNetworkRequest req = NetworkHelper::genericRequest(
        url, m_cfg.headers,
        m_cfg.method.compare("POST", Qt::CaseInsensitive) == 0
            ? QByteArray("application/x-www-form-urlencoded") : QByteArray(),
        m_cfg.timeoutMs);

    m_reply = (m_cfg.method.compare("POST", Qt::CaseInsensitive) == 0)
                  ? m_net->post(req, body)
                  : m_net->get(req);

    if (!m_reply) {
        auto tmp = std::move(m_cb); m_cb = {}; m_inFlight = false;
        if (tmp) tmp({ false, "reply construction failed", {}, -1, int(m_elapsed.elapsed()) });
        return;
    }

    emit progress(QString("HTTP %1 %2 - awaiting response...")
                      .arg(m_cfg.method, url.toString(QUrl::RemovePassword)));

    QObject::connect(m_reply, &QNetworkReply::finished, this, [this]() {
        auto *reply = m_reply.data();
        if (!reply) return;
        reply->deleteLater();
        m_reply.clear();
        m_inFlight = false;
        auto cb = std::move(m_cb); m_cb = {};

        Result r;
        r.elapsedMs = int(m_elapsed.elapsed());
        r.exitCode  = -1;

        if (reply->error() != QNetworkReply::NoError) {
            const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            r.ok = false;
            r.stdoutText = status
                ? QString("HTTP %1: %2").arg(status).arg(reply->errorString())
                : QString("Network error: %1").arg(reply->errorString());
            if (cb) cb(r);
            return;
        }

        const QByteArray body = reply->readAll();
        r.ok = true;
        r.stdoutText = applyExtractor(body);
        if (cb) cb(r);
    });
}

void HttpWebshellTransport::cancel() {
    if (!m_inFlight) return;
    if (m_reply) {
        m_reply->disconnect(this);
        m_reply->abort();
    }
    m_inFlight = false;
    auto cb = std::move(m_cb); m_cb = {};
    if (cb) cb({ false, "cancelled", {}, -1, int(m_elapsed.elapsed()) });
}
