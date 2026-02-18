#include <QApplication>
#include <QIcon>
#include <QFile>
#include <QMessageBox>
#include <QScreen>
#include <QStyle>

#include "DashboardWindow.h"
#include "ThemeManager.h"
#include "ServerLoginWindow.h"
#include "WindowHelper.h"
#include "network/ClientTransport.h"
#include "../shared/Protocol.h"

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
