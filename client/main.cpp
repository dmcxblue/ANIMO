#include <QApplication>
#include <QIcon>
#include <QJsonArray>
#include <QJsonObject>
#include <QMessageBox>
#include <QScreen>

#include "DashboardWindow.h"
#include "ThemeManager.h"
#include "ServerLoginWindow.h"
#include "TokenStore.h"
#include "WindowHelper.h"
#include "network/ClientTransport.h"
#include "../shared/Protocol.h"

namespace {
// Populate TokenStore from the server's Token Log so every plugin window's
// UserSelectorWidget can see users whose tokens were captured in previous
// sessions (webhook, PRT exchange, refresh-token exchange, imports, etc.).
// One-shot — disconnects after the first "tokens retrieved" response.
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

    DashboardWindow *dashboard = nullptr;

    QObject::connect(&loginWin, &ServerLoginWindow::connectToServer,
                     [&](const QString &ip, quint16 port, const QString &password) {
        // Connect + authenticate (uses your ClientTransport helper)
        const bool ok = transport->connectAndLogin(ip, port, password, /*timeoutMs=*/5000);
        if (ok) {
            loginWin.close();

            // Create dashboard and inject transport BEFORE first use
            dashboard = new DashboardWindow();
            dashboard->setWindowFlags(Qt::Window);
            dashboard->setWindowTitle("ANIMO - Azure Network Intel & Mission Ops");
            dashboard->setWindowIcon(appIcon);
            dashboard->setMinimumSize(800, 500);
            dashboard->resize(1100, 700);

            // Try to restore previous geometry, or center on screen
            if (!WindowHelper::restoreGeometry(dashboard, "DashboardWindow")) {
                WindowHelper::centerOnScreen(dashboard);
            }

            dashboard->setTransport(transport);
            dashboard->show();

            // Prime TokenStore with everything already in the server's
            // Token Log so plugin-window UserSelectorWidgets aren't limited
            // to just currently-active PowerShell sessions.
            bootstrapTokenStore(transport, dashboard);
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
