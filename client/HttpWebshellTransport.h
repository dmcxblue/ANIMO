#ifndef HTTPWEBSHELLTRANSPORT_H
#define HTTPWEBSHELLTRANSPORT_H

#include "RemoteExecTransport.h"

#include <QElapsedTimer>
#include <QMap>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>

// HttpWebshellTransport - for the classic "I uploaded cmd.php" case.
//
// The operator picked up an RCE via file upload / LFI / whatever and now
// has a URL that takes a `?cmd=...` (or POST body) and returns the
// command's output somewhere in the response body. This transport
// automates the "hand-craft each curl" pain: enter the URL + command
// param + output extractor once, then drive commands interactively.
//
// Output extractor is one of:
//   raw     - use the whole response body as stdout
//   regex   - apply outputRegex to the body, capture group 1 = stdout
//   between - substring between markerStart and markerEnd
class HttpWebshellTransport : public RemoteExecTransport {
    Q_OBJECT
public:
    struct Config {
        QString name;                          // Human display name (e.g. "prod-web-01")
        QString baseUrl;                       // e.g. http://target/cmd.php
        QString method = QStringLiteral("GET");// GET or POST
        QString cmdParam = QStringLiteral("cmd");
        QMap<QString, QString> extraParams;    // Static query/form pairs
        QMap<QString, QString> headers;        // Raw headers (User-Agent, Cookie, ...)
        QString outputExtract = QStringLiteral("raw");  // raw | regex | between
        QString outputRegex;                   // Used when outputExtract == "regex"
        QString markerStart;                   // Used when outputExtract == "between"
        QString markerEnd;                     // Used when outputExtract == "between"
        int     timeoutMs = 30000;
    };

    explicit HttpWebshellTransport(const Config &cfg, QObject *parent = nullptr);
    ~HttpWebshellTransport() override;

    QString kind() const override        { return QStringLiteral("http_webshell"); }
    QString displayName() const override { return m_cfg.name.isEmpty() ? m_cfg.baseUrl : m_cfg.name; }
    bool    isReady(QString *why = nullptr) const override;
    void    execute(const QString &command, Callback cb) override;
    void    cancel() override;

    const Config &config() const { return m_cfg; }

protected:
    // Hook so HttpSstiTransport can wrap `command` in a payload template
    // before it hits the wire. Default: passthrough.
    virtual QString transformCommand(const QString &command) const { return command; }

    Config                   m_cfg;

private:
    // Build the URL and body for the current transport `payload` (the
    // already-transformed command). `bodyOut` filled for POST; ignored for GET.
    QUrl        buildUrl(const QString &payload, QByteArray *bodyOut) const;
    QString     applyExtractor(const QByteArray &body) const;

    QNetworkAccessManager   *m_net;
    QPointer<QNetworkReply>  m_reply;
    Callback                 m_cb;
    bool                     m_inFlight = false;
    QElapsedTimer            m_elapsed;
};

#endif  // HTTPWEBSHELLTRANSPORT_H
