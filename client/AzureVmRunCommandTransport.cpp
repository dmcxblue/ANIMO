#include "AzureVmRunCommandTransport.h"
#include "NetworkHelper.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

namespace {

constexpr int kMaxPollAttempts   = 60;
constexpr int kPollIntervalMs    = 5000;
constexpr int kMaxRetries        = 3;
constexpr int kRetryDelayMs      = 10000;
constexpr int kPostTimeoutMs     = 30000;

}  // namespace

AzureVmRunCommandTransport::AzureVmRunCommandTransport(const Config &cfg, QObject *parent)
    : RemoteExecTransport(parent),
      m_cfg(cfg),
      m_net(new QNetworkAccessManager(this))
{}

AzureVmRunCommandTransport::~AzureVmRunCommandTransport() {
    cancel();
}

bool AzureVmRunCommandTransport::isReady(QString *why) const {
    if (m_cfg.token.isEmpty()) { if (why) *why = "no ARM token";  return false; }
    if (m_cfg.vmId.isEmpty())  { if (why) *why = "no VM resource id"; return false; }
    if (m_inFlight)            { if (why) *why = "command already in flight"; return false; }
    return true;
}

void AzureVmRunCommandTransport::execute(const QString &command, Callback cb) {
    if (!cb) return;
    if (m_inFlight) {
        cb({ false, {}, "another command is already in flight", -1, 0 });
        return;
    }
    m_cb = std::move(cb);
    m_inFlight = true;
    m_retries = 0;
    m_asyncUrl.clear();
    m_elapsed.start();
    postRunCommand(command);
}

void AzureVmRunCommandTransport::cancel() {
    if (!m_inFlight) return;
    if (m_reply) {
        m_reply->disconnect(this);
        m_reply->abort();
    }
    Result r;
    r.ok = false;
    r.stdoutText = QStringLiteral("cancelled");
    r.exitCode = -1;
    r.elapsedMs = m_elapsed.isValid() ? int(m_elapsed.elapsed()) : 0;
    deliver(r);
}

void AzureVmRunCommandTransport::retryPostAfter(int ms, const QString &command) {
    ++m_retries;
    emit progress(QString("VM busy (HTTP 409). Retry %1/%2 in %3s...")
                      .arg(m_retries).arg(kMaxRetries).arg(ms / 1000));
    QTimer::singleShot(ms, this, [this, command]() {
        if (!m_inFlight) return;
        postRunCommand(command);
    });
}

void AzureVmRunCommandTransport::postRunCommand(const QString &command) {
    m_pendingCmd = command;

    const QString commandId =
        m_cfg.osType.compare("linux", Qt::CaseInsensitive) == 0
            ? QStringLiteral("RunShellScript")
            : QStringLiteral("RunPowerShellScript");

    const QString url = QString("https://management.azure.com%1/runCommand?api-version=2023-07-01")
                            .arg(m_cfg.vmId);
    QJsonObject body{
        { "commandId", commandId },
        { "script",    QJsonArray{ command } },
    };

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, m_cfg.token, kPostTimeoutMs);
    m_reply = m_net->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (!m_reply) {
        deliver({ false, "network reply construction failed", {}, -1, int(m_elapsed.elapsed()) });
        return;
    }
    emit progress(QString("Sending runCommand to %1...").arg(m_cfg.displayName));

    QObject::connect(m_reply, &QNetworkReply::finished, this, [this, command]() {
        auto *reply = m_reply.data();
        if (!reply) return;
        reply->deleteLater();
        m_reply.clear();

        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            if (status == 409 && m_retries < kMaxRetries) {
                retryPostAfter(kRetryDelayMs, command);
                return;
            }
            const QString msg = (status == 409)
                ? QStringLiteral("VM still busy after retries (HTTP 409).")
                : NetworkHelper::parseApiError(reply);
            deliver({ false, msg, {}, -1, int(m_elapsed.elapsed()) });
            return;
        }

        // 202 async path (typical): poll the async-op URL until Succeeded/Failed.
        const QByteArray asyncHdr = reply->rawHeader("Azure-AsyncOperation");
        const QByteArray locHdr   = reply->rawHeader("Location");
        m_asyncUrl = QString::fromUtf8(!asyncHdr.isEmpty() ? asyncHdr : locHdr).trimmed();

        if (status == 202 && !m_asyncUrl.isEmpty()) {
            emit progress(QStringLiteral("Command accepted (202). Polling for completion..."));
            pollRunCommand(0);
            return;
        }

        // Rare synchronous fallback: 200 with inline body (some api-versions /
        // extension VMs).
        const QJsonObject result = QJsonDocument::fromJson(reply->readAll()).object();
        const QJsonArray outputs = result.value("value").toArray();
        QString outText;
        for (const QJsonValue &v : outputs) {
            const QJsonObject out = v.toObject();
            outText += QString("[%1]\n%2\n").arg(out.value("code").toString(),
                                                  out.value("message").toString());
        }
        deliver({ true, outText.isEmpty() ? "Command executed (no output)" : outText,
                  {}, 0, int(m_elapsed.elapsed()) });
    });
}

void AzureVmRunCommandTransport::pollRunCommand(int attempt) {
    if (!m_inFlight) return;

    if (attempt >= kMaxPollAttempts) {
        deliver({ false, "Timeout: script did not finish within 5 minutes.",
                  {}, -1, int(m_elapsed.elapsed()) });
        return;
    }

    QNetworkRequest req = NetworkHelper::createBearerRequest(m_asyncUrl, m_cfg.token, kPostTimeoutMs);
    m_reply = m_net->get(req);
    if (!m_reply) {
        deliver({ false, "poll request construction failed", {}, -1, int(m_elapsed.elapsed()) });
        return;
    }

    QObject::connect(m_reply, &QNetworkReply::finished, this, [this, attempt]() {
        auto *reply = m_reply.data();
        if (!reply) return;
        reply->deleteLater();
        m_reply.clear();

        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            deliver({ false, QString("Poll error: %1").arg(NetworkHelper::parseApiError(reply)),
                      {}, -1, int(m_elapsed.elapsed()) });
            return;
        }

        const QJsonObject body = QJsonDocument::fromJson(reply->readAll()).object();
        const QString status = body.value("status").toString();

        if (status.compare("InProgress", Qt::CaseInsensitive) == 0 || status.isEmpty()) {
            const int next = attempt + 1;
            if (next % 4 == 0) {
                emit progress(QString("Still running... (%1s)")
                                  .arg(next * kPollIntervalMs / 1000));
            }
            QTimer::singleShot(kPollIntervalMs, this, [this, next]() { pollRunCommand(next); });
            return;
        }

        if (status.compare("Succeeded", Qt::CaseInsensitive) == 0) {
            const QJsonArray outputs = body.value("properties").toObject()
                                            .value("output").toObject()
                                            .value("value").toArray();
            QString outText;
            for (const QJsonValue &v : outputs) {
                const QJsonObject out = v.toObject();
                outText += QString("[%1]\n%2\n").arg(out.value("code").toString(),
                                                      out.value("message").toString());
            }
            deliver({ true, outText.isEmpty() ? "Command executed (no output)." : outText,
                      {}, 0, int(m_elapsed.elapsed()) });
            return;
        }

        // Failed / Canceled / anything unexpected.
        const QJsonObject e = body.value("error").toObject();
        const QString code = e.value("code").toString();
        const QString msg  = e.value("message").toString();
        const QString rendered = (code.isEmpty() && msg.isEmpty())
            ? QString("runCommand ended with status: %1").arg(status)
            : QString("[%1] %2").arg(code, msg);
        deliver({ false, rendered, {}, -1, int(m_elapsed.elapsed()) });
    });
}

void AzureVmRunCommandTransport::deliver(const Result &r) {
    m_inFlight = false;
    m_asyncUrl.clear();
    m_pendingCmd.clear();
    m_retries = 0;
    auto cb = std::move(m_cb);
    m_cb = {};
    if (cb) cb(r);
}
