#include <QApplication>
#include <QIcon>
#include <QJsonArray>
#include <QJsonObject>
#include <QMessageBox>
#include <QPushButton>
#include <QScreen>
#include <QFile>
#include <QDateTime>
#include <QMutex>

#include "DashboardWindow.h"
#include "ThemeManager.h"
#include "ServerLoginWindow.h"
#include "TokenStore.h"
#include "WindowHelper.h"
#include "network/ClientTransport.h"
#include "../shared/Protocol.h"

namespace {
// Mirror every qDebug/qInfo/qWarning to /tmp/animo-cli-dbg.log so we don't
// depend on the terminal or a tee. Same handler pattern as the server side.
QFile *g_dbgLog = nullptr;
QMutex g_dbgLogMutex;
void animoClientMessageHandler(QtMsgType type, const QMessageLogContext &, const QString &msg) {
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
    fprintf(stderr, "%s", qUtf8Printable(line));
    fflush(stderr);
    QMutexLocker lk(&g_dbgLogMutex);
    if (g_dbgLog && g_dbgLog->isOpen()) {
        g_dbgLog->write(line.toUtf8());
        g_dbgLog->flush();
    }
}
} // namespace

namespace {
// Populate TokenStore from the server's Token Log so every plugin window's
// UserSelectorWidget can see users whose tokens were captured in previous
// sessions (webhook, PRT exchange, refresh-token exchange, imports, etc.).
// One-shot - disconnects after the first "tokens retrieved" response.
void bootstrapTokenStore(ClientTransport *transport, QObject *ownerScope) {
    auto conn = std::make_shared<QMetaObject::Connection>();
    *conn = QObject::connect(transport, &ClientTransport::messageReceived, ownerScope,
        [conn](const QJsonObject &obj) {
            if (obj.value("status").toString() != "ok" ||
                obj.value("message").toString() != "tokens retrieved") {
                return;
            }
            QObject::disconnect(*conn);

            const QJsonArray tokens = obj.value("tokens").toArray();
            int loaded = 0;
            for (const QJsonValue &v : tokens) {
                const QJsonObject t = v.toObject();
                TokenInfo info;
                info.accessToken  = t.value("access_token").toString();
                info.refreshToken = t.value("refresh_token").toString();
                info.idToken      = t.value("id_token").toString();
                info.resource     = t.value("resource").toString();
                info.tenantId     = t.value("tenant_id").toString();
                info.upn          = t.value("user").toString();
                if (info.accessToken.isEmpty()) continue;
                const QString sid = t.value("session_id").toString();
                if (sid.isEmpty()) continue;
                TokenStore::instance()->storeToken(sid, info);
                ++loaded;
            }
            qInfo() << "[Bootstrap] Loaded" << loaded
                    << "tokens from Token Log into TokenStore";
        });

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_GET_TOKENS);
    // sessionId omitted → server returns all tokens
    transport->sendJson(req);
}
} // namespace

int main(int argc, char *argv[])
{
    // Install log-to-file handler before Qt event loop so early qInfo lines land.
    g_dbgLog = new QFile("/tmp/animo-cli-dbg.log");
    g_dbgLog->open(QIODevice::WriteOnly | QIODevice::Truncate);
    qInstallMessageHandler(animoClientMessageHandler);

    QApplication app(argc, argv);

    // Set application-wide icon (Azure cloud theme)
    QIcon appIcon(":/icons/azure_cloud.svg");
    app.setWindowIcon(appIcon);

    // Start with Dark Theme
    ThemeManager::applyDark(app);

    // Create login window
    ServerLoginWindow loginWin;
    loginWin.setWindowFlags(Qt::Dialog | Qt::MSWindowsFixedSizeDialogHint);
    loginWin.setWindowTitle("ANIMO Login Server");
    loginWin.setWindowIcon(appIcon);

    // Center login window on primary screen
    WindowHelper::centerOnScreen(&loginWin);
    loginWin.show();

    // Transport lives for the app lifetime
    auto *transport = new ClientTransport(&app);           // parent to qApp
    transport->setObjectName(QStringLiteral("ClientTransport"));
    // Auto-reconnect if the server restarts under us. Without this the operator
    // has to close and reopen the client after every server restart. Reconnect
    // uses the same credentials cached in the transport after the first successful
    // login. Keep the retry cadence modest so a truly-dead server doesn't spin.
    transport->setMaxReconnectAttempts(10);
    transport->setReconnectDelay(3000);
    transport->enableAutoReconnect(true);

    DashboardWindow *dashboard = nullptr;

    // Trust-on-first-use prompt. Deliberately out of band: the handshake is
    // allowed to fail first, then the operator decides, then we retry. Putting
    // a modal dialog inside the sslErrors callback would nest it inside the
    // blocking event loop connectAndLogin already runs.
    auto confirmCertificate = [&](const QString &ip, quint16 port) -> bool {
        const bool mismatch =
            transport->lastTlsStatus() == ClientTransport::TlsStatus::PinMismatch;

        QMessageBox box(&loginWin);
        box.setIcon(mismatch ? QMessageBox::Critical : QMessageBox::Warning);
        box.setWindowTitle(mismatch ? "Server Certificate Changed"
                                    : "Unrecognised Server Certificate");
        box.setText(mismatch
            ? QString("The certificate presented by %1:%2 does not match the one "
                      "you trusted before.\n\nThis happens after a legitimate "
                      "certificate rotation - or when someone is intercepting "
                      "the channel.").arg(ip).arg(port)
            : QString("You have not connected to %1:%2 before.\n\nConfirm the "
                      "fingerprint against the one the server printed at startup.")
                      .arg(ip).arg(port));
        box.setInformativeText(
            QString("Fingerprint (SHA-256):\n%1\n\nSubject: %2\nValid: %3")
                .arg(transport->presentedFingerprint(),
                     transport->presentedSubject(),
                     transport->presentedValidity()));

        QPushButton *trustBtn = box.addButton(mismatch ? "Trust New Certificate"
                                                       : "Trust and Connect",
                                              QMessageBox::AcceptRole);
        QPushButton *cancelBtn = box.addButton("Cancel", QMessageBox::RejectRole);
        box.setDefaultButton(cancelBtn); // Enter must not trust a certificate
        box.exec();
        return box.clickedButton() == trustBtn;
    };

    QObject::connect(&loginWin, &ServerLoginWindow::connectToServer,
                     [&](const QString &ip, quint16 port, const QString &username, const QString &password) {
        // Connect + authenticate (uses your ClientTransport helper)
        bool ok = transport->connectAndLogin(ip, port, username, password, /*timeoutMs=*/5000);

        // Untrusted certificate: ask, pin, retry once.
        const ClientTransport::TlsStatus tls = transport->lastTlsStatus();
        if (!ok && (tls == ClientTransport::TlsStatus::PinUnknown ||
                    tls == ClientTransport::TlsStatus::PinMismatch)) {
            if (confirmCertificate(ip, port)) {
                transport->trustPresentedCertificate();
                ok = transport->connectAndLogin(ip, port, username, password, /*timeoutMs=*/5000);
            }
        }

        if (ok) {
            loginWin.close();

            // Create dashboard and inject transport BEFORE first use
            dashboard = new DashboardWindow();
            dashboard->setWindowFlags(Qt::Window);
            dashboard->setWindowTitle(QString("ANIMO - Azure Network Intel & Mission Ops  -  operator: %1").arg(username));
            dashboard->setWindowIcon(appIcon);
            dashboard->setMinimumSize(800, 500);
            dashboard->resize(1100, 700);

            // Try to restore previous geometry, or center on screen
            if (!WindowHelper::restoreGeometry(dashboard, "DashboardWindow")) {
                WindowHelper::centerOnScreen(dashboard);
            }

            dashboard->setTransport(transport);
            dashboard->setOperator(username);
            dashboard->show();

            // Prime TokenStore with everything already in the server's
            // Token Log so plugin-window UserSelectorWidgets aren't limited
            // to just currently-active PowerShell sessions.
            bootstrapTokenStore(transport, dashboard);
        } else if (transport->lastTlsStatus() != ClientTransport::TlsStatus::Ok) {
            // Never blame the password for a transport/trust failure.
            QMessageBox::critical(&loginWin, "Secure Connection Failed",
                                  transport->lastTlsError().isEmpty()
                                      ? QString("Could not establish a TLS connection to %1:%2.\n"
                                                "Check that the address and port are correct and "
                                                "that the ANIMO server is running.").arg(ip).arg(port)
                                      : transport->lastTlsError());
        } else {
            QMessageBox::critical(&loginWin, "Connection Failed",
                                  "Unable to authenticate with server.\nCheck IP, port, or password.");
        }
    });

    // Optional: if server disconnects, re-open login window
    QObject::connect(transport, &ClientTransport::disconnected, [&](){
        if (dashboard) {
            dashboard->close();
            dashboard->deleteLater();
            dashboard = nullptr;
        }
        loginWin.show();
    });

    return app.exec();
}
