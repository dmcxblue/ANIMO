#ifndef DASHBOARDTAB_H
#define DASHBOARDTAB_H

#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QMap>
#include <QColor>
#include <QString>
#include <QByteArray>    // ⬅️ needed for slot param
#include <QJsonObject>   // ⬅️ needed for slot/helper
#include <QList>
#include <QPushButton>
#include "CommandLineEdit.h"

// Buffered command record to prevent output mixing
struct PendingCommand {
    QString cmdId;
    QString command;
    QStringList outputLines;  // Buffered output until command completes
    bool headerShown = false;
    bool completed = false;
    bool ok = true;           // false if the command reported failure
    int  exitCode = 0;        // native exit code, when applicable
};

class QTextCursor;
class DashboardWindow;

class DashboardTab : public QWidget {
    Q_OBJECT

public:
    DashboardTab(const QString &label,
                 const QString &token,
                 const QString &resource,
                 const QString &loginScript,
                 const QString &sessionId,
                 DashboardWindow *parentDashboard,
                 QWidget *parent = nullptr);

    QString getSessionId() const { return sessionId; }  // public accessor

    void addSessionRow(const QString &sessionId,
                       const QString &username,
                       const QString &tenantId,
                       const QString &resource);

public slots:
    void clearConsole();

signals:
    // Emitted with `true` when a command starts executing in this tab, and
    // `false` when the last in-flight command completes. DashboardWindow uses
    // this to decorate the tab title (e.g. "Session abc123 ⏳").
    void runningStateChanged(bool running);

private slots:
    void runCustomQuery();

    // ⬇️ NEW: slots to handle transport signals (any one that exists will be connected)
    void onTransportLineBytes(const QByteArray &line);
    void onTransportLineString(const QString &line);
    void onTransportJson(const QJsonObject &obj);

private:
    void ansiToQText(QTextCursor &cursor, const QString &text);
    // ⬇️ NEW: central handler for parsed server objects
    void handleServerObject(const QJsonObject &obj);
    // Normalize whitespace: collapse consecutive blank lines, trim edges
    static QString normalizeOutput(const QString &text);

    QString token;
    QString resource;
    QString label;
    QString loginScript;
    QString sessionId;
    DashboardWindow *parentDashboard = nullptr;
    QString lastSentCommand;
    QString currentCmdId;  // Currently executing command ID for output correlation
    QList<PendingCommand> pendingCommands;  // Queue of commands with buffered output
    QMap<QString, QStringList> orphanOutput;  // output that arrived before its command_started

    QTextEdit *output = nullptr;
    CommandLineEdit *queryInput = nullptr;
    QPushButton *clearBtn = nullptr;

    void loadCommandHistory();
    void saveCommandHistory();
    void setupPowerShellCompletion();
    void flushCompletedCommands();  // Display completed commands in order
};

#endif // DASHBOARDTAB_H
