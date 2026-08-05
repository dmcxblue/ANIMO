#include <QCoreApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>
#include "Server.h"

namespace {
// Mirror every qDebug/qInfo/qWarning to /tmp/animo-srv-dbg.log so terminal
// scrollback loss can't hide the diagnostic lines we need for triage.
QFile *g_dbgLog = nullptr;
QMutex g_dbgLogMutex;
void animoServerMessageHandler(QtMsgType type, const QMessageLogContext &, const QString &msg) {
    const char *lvl = "?";
    switch (type) {
        case QtDebugMsg:    lvl = "D"; break;
        case QtInfoMsg:     lvl = "I"; break;
        case QtWarningMsg:  lvl = "W"; break;
        case QtCriticalMsg: lvl = "C"; break;
        case QtFatalMsg:    lvl = "F"; break;
    }
    const QString line = QString("[%1] [%2] %3\n")
        .arg(QDateTime::currentDateTime().toString(Qt::ISODateWithMs), lvl, msg);
    // Terminal
    fprintf(stderr, "%s", qUtf8Printable(line));
    fflush(stderr);
    // File
    QMutexLocker lk(&g_dbgLogMutex);
    if (g_dbgLog && g_dbgLog->isOpen()) {
        g_dbgLog->write(line.toUtf8());
        g_dbgLog->flush();
    }
}
} // namespace

int main(int argc, char *argv[]) {
    // Install log-to-file handler before anything else so we catch startup output.
    g_dbgLog = new QFile("/tmp/animo-srv-dbg.log");
    g_dbgLog->open(QIODevice::WriteOnly | QIODevice::Truncate);
    qInstallMessageHandler(animoServerMessageHandler);

    QCoreApplication app(argc, argv);
    app.setApplicationName("ANIMOServer");
    app.setApplicationVersion("1.0");

    // Setup command line parser
    QCommandLineParser parser;
    parser.setApplicationDescription("ANIMO Server");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption ipOption(QStringList() << "i" << "ip",
        "IP address to bind (default: 0.0.0.0)", "ip", "0.0.0.0");
    QCommandLineOption portOption(QStringList() << "p" << "port",
        "Port to bind (default: 7777)", "port", "7777");
    QCommandLineOption passwordOption(QStringList() << "P" << "password",
        "Password required for clients to connect (default: empty)", "password", "");

    // TLS is mandatory. A self-signed pair is generated on first start unless
    // custom material is supplied here.
    const QString defaultTlsDir = QCoreApplication::applicationDirPath() + "/data/tls";
    QCommandLineOption tlsCertOption(QStringList() << "tls-cert",
        "PEM certificate for the client channel (default: <appdir>/data/tls/server.crt, "
        "self-signed and generated on first start)",
        "path", defaultTlsDir + "/server.crt");
    QCommandLineOption tlsKeyOption(QStringList() << "tls-key",
        "PEM private key for the client channel (default: <appdir>/data/tls/server.key)",
        "path", defaultTlsDir + "/server.key");

    parser.addOption(ipOption);
    parser.addOption(portOption);
    parser.addOption(passwordOption);
    parser.addOption(tlsCertOption);
    parser.addOption(tlsKeyOption);

    parser.process(app);

    QString ip = parser.value(ipOption);
    quint16 port = parser.value(portOption).toUShort();
    QString password = parser.value(passwordOption);

    qDebug() << "Starting ANIMOServer on" << ip << ":" << port;
    if (!password.isEmpty())
        qDebug() << "Password required for clients.";

    // Only password matters, user can be anything
    Server server(ip, port, QString(), password);
    server.setTlsPaths(parser.value(tlsCertOption), parser.value(tlsKeyOption));

    // Server::log had no consumer, so status lines - including the TLS
    // fingerprint operators must verify - never reached the console.
    QObject::connect(&server, &Server::log, &app, [](const QString &line) {
        qInfo().noquote() << line;
    });

    if (!server.start()) {
        qCritical() << "Failed to start server.";
        return 1;
    }

    return app.exec();
}
