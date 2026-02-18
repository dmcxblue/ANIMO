#include <QCoreApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QDebug>
#include "Server.h"

int main(int argc, char *argv[]) {
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

    parser.addOption(ipOption);
    parser.addOption(portOption);
    parser.addOption(passwordOption);

    parser.process(app);

    QString ip = parser.value(ipOption);
    quint16 port = parser.value(portOption).toUShort();
    QString password = parser.value(passwordOption);

    qDebug() << "Starting ANIMOServer on" << ip << ":" << port;
    if (!password.isEmpty())
        qDebug() << "Password required for clients.";

    // Only password matters, user can be anything
    Server server(ip, port, QString(), password);

    if (!server.start()) {
        qCritical() << "Failed to start server.";
        return 1;
    }

    return app.exec();
}
