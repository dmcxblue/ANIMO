#include "DashboardTab.h"
#include "DashboardWindow.h"

#include <QTextCharFormat>
#include <QDebug>
#include <QTextCursor>
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QRegularExpression>
#include <QSharedPointer>

#include <QTextEdit>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QShortcut>
#include <QKeySequence>
#include <QApplication>
#include <QTimer>

#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonObject>
#include <QMetaMethod>
#include <QByteArray>
#include <QUuid>

// ---- Try both header locations; set a single feature flag ----
#if __has_include("network/ClientTransport.h")
  #include "network/ClientTransport.h"
  #define HAVE_CLIENT_TRANSPORT 1
#elif __has_include("ClientTransport.h")
  #include "ClientTransport.h"
  #define HAVE_CLIENT_TRANSPORT 1
#else
  #define HAVE_CLIENT_TRANSPORT 0
#endif

#ifdef Q_OS_WIN
#include <windows.h>
#endif

// Extended ANSI → QColor map
static const QMap<QString, QColor> ANSI_COLOR_MAP = {
    {"\x1b[30m", QColor("black")},
    {"\x1b[31m", QColor("red")},
    {"\x1b[32m", QColor("green")},
    {"\x1b[33m", QColor("yellow")},
    {"\x1b[34m", QColor("blue")},
    {"\x1b[35m", QColor("magenta")},
    {"\x1b[36m", QColor("cyan")},
    {"\x1b[37m", QColor("lightGray")},
    {"\x1b[90m", QColor("darkGray")},
    {"\x1b[91m", QColor("lightCoral")},
    {"\x1b[92m", QColor("lightGreen")},
    {"\x1b[93m", QColor("lightYellow")},
    {"\x1b[94m", QColor("lightBlue")},
    {"\x1b[95m", QColor("plum")},
    {"\x1b[96m", QColor("lightCyan")},
    {"\x1b[97m", QColor("white")},
    {"\x1b[0m", QColor()},
    {"\x1b[39m", QColor()}
};

static void trySendJson(QObject *transport, const QJsonObject &obj) {
    if (!transport) return;
#if HAVE_CLIENT_TRANSPORT
    if (auto *t = qobject_cast<ClientTransport*>(transport)) {
        t->sendJson(obj);  // typed path if available
        return;
    }
#endif
    // Fallback: dynamic invoke if a slot "sendJson(QJsonObject)" exists
    QMetaObject::invokeMethod(transport, "sendJson", Q_ARG(QJsonObject, obj));
}

// Helper: connect by meta-methods (Qt 6 friendly, no SIGNAL/SLOT macros needed)
static bool connectBySignature(QObject* sender,
                               const char* signalSig,
                               QObject* receiver,
                               const char* slotSig,
                               Qt::ConnectionType type = Qt::AutoConnection)
{
    if (!sender || !receiver) return false;
    const QMetaObject* moS = sender->metaObject();
    const QMetaObject* moR = receiver->metaObject();
    int sIdx = moS->indexOfSignal(signalSig);
    if (sIdx < 0) return false;
    int rIdx = moR->indexOfSlot(slotSig);
    if (rIdx < 0) return false;
    QMetaMethod sM = moS->method(sIdx);
    QMetaMethod rM = moR->method(rIdx);
    bool ok = QObject::connect(sender, sM, receiver, rM, type);
    // Connection successful (debug removed for cleaner logs)
    return ok;
}

// Robust transport discovery: typed, by objectName, and class-name scan
static QObject* locateTransport(DashboardWindow* parentDashboard)
{
    QObject* found = nullptr;

#if HAVE_CLIENT_TRANSPORT
    if (!found) found = qApp->findChild<ClientTransport*>();
    if (!found && parentDashboard)
        found = parentDashboard->findChild<ClientTransport*>();
#endif

    if (!found && parentDashboard)
        found = parentDashboard->findChild<QObject*>("ClientTransport", Qt::FindChildrenRecursively);
    if (!found)
        found = qApp->findChild<QObject*>("ClientTransport", Qt::FindChildrenRecursively);

    if (!found) {
        // brute-force scan all objects for a type containing "ClientTransport"
        const auto objs = qApp->findChildren<QObject*>();
        for (QObject* o : objs) {
            const char* cn = o->metaObject() ? o->metaObject()->className() : nullptr;
            if (cn && QByteArray(cn).contains("ClientTransport")) {
                found = o;
                break;
            }
        }
    }

    if (!found) {
        qWarning() << "[DashboardTab] locateTransport: not found."
                   << "Ensure your ClientTransport is created, has a parent,"
                   << "and sets objectName(\"ClientTransport\").";
    }
    return found;
}

DashboardTab::DashboardTab(const QString &label,
                           const QString &token,
                           const QString &resource,
                           const QString &loginScript,
                           const QString &sessionId,
                           DashboardWindow *parentDashboard,
                           QWidget *parent)
    : QWidget(parent),
      token(token),
      resource(resource),
      label(label),
      loginScript(loginScript),
      sessionId(sessionId),
      parentDashboard(parentDashboard)
{
    output = new QTextEdit(this);
    output->setReadOnly(true);
    // Cap scrollback so unbounded output (Get-AzResource in huge tenants, tail
    // of a long-running script, etc.) doesn't blow up memory or slow repaints.
    // 50k lines is roughly 5-10 MB of text - plenty for interactive use.
    output->document()->setMaximumBlockCount(50000);
    // Cross-platform monospace font for proper column alignment
    QFont monoFont("Monospace", 10);
    monoFont.setStyleHint(QFont::Monospace);
    monoFont.setFamily("Consolas,Monaco,Courier New,Monospace");
    output->setFont(monoFont);

    queryInput = new CommandLineEdit(this);
    queryInput->setPlaceholderText("Run Custom Command (AzureAD, Az, MSGraph) - Use ↑/↓ for history, Ctrl+R to search");
    connect(queryInput, &QLineEdit::returnPressed, this, &DashboardTab::runCustomQuery);

    // Load command history and setup auto-completion
    loadCommandHistory();
    setupPowerShellCompletion();

    // Clear console button
    clearBtn = new QPushButton("Clear", this);
    clearBtn->setFixedWidth(60);
    clearBtn->setToolTip("Clear console output (Ctrl+L)");
    connect(clearBtn, &QPushButton::clicked, this, &DashboardTab::clearConsole);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->addWidget(output);

    // Bottom row: input + clear button
    QHBoxLayout *bottomRow = new QHBoxLayout();
    bottomRow->addWidget(queryInput);
    bottomRow->addWidget(clearBtn);
    layout->addLayout(bottomRow);
    setLayout(layout);

    // Ctrl+L shortcut to clear console
    QShortcut *clearShortcut = new QShortcut(QKeySequence("Ctrl+L"), this);
    connect(clearShortcut, &QShortcut::activated, this, &DashboardTab::clearConsole);

    // ====== SERVER-DRIVEN OUTPUT HOOKS ======
    QObject *transportObj = locateTransport(parentDashboard);

    if (transportObj) {
        // Tell server we want output for this session
        QTimer::singleShot(0, [transportObj, sid=sessionId]() {
            QJsonObject o;
            o.insert("action", "attach");
            o.insert("sessionId", sid);
            trySendJson(transportObj, o);
        });

        // Try to connect to several possible signals the transport may expose
        bool connected =
            connectBySignature(transportObj, "jsonReceived(QJsonObject)",    this, "onTransportJson(QJsonObject)")     ||
            connectBySignature(transportObj, "messageReceived(QJsonObject)", this, "onTransportJson(QJsonObject)")     ||
            connectBySignature(transportObj, "serverEvent(QJsonObject)",     this, "onTransportJson(QJsonObject)")     ||
            connectBySignature(transportObj, "lineReceived(QByteArray)",     this, "onTransportLineBytes(QByteArray)") ||
            connectBySignature(transportObj, "lineReceived(QString)",        this, "onTransportLineString(QString)");

        if (!connected) {
            qWarning() << "[DashboardTab] No compatible signal found on transport; output will not stream.";
        }
    }
    // ====== END SERVER HOOKS ======
}

void DashboardTab::runCustomQuery() {
    QString query = queryInput->text().trimmed();
    if (query.isEmpty()) return;

    // Add to command history and persist to file
    queryInput->addToHistory(query);
    saveCommandHistory();

    // NO client-side DB writes - server owns history.
    lastSentCommand = query; // keep this if you use it elsewhere

    // Send to server transport - server will send command_started which displays the command
    QObject *transportObj = locateTransport(parentDashboard);
    if (transportObj) {
        QJsonObject req;
        req.insert("action",    QStringLiteral("run_command"));
        req.insert("sessionId", sessionId);
        req.insert("command",   query);
        // Generate cmdId client-side for immediate tracking
        QString cmdId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        req.insert("cmdId", cmdId);
        trySendJson(transportObj, req);
    } else {
        QTextCursor cursor = output->textCursor();
        ansiToQText(cursor, "\x1b[31m[!] No transport found; cannot send command to server.\x1b[0m\n");
    }

    queryInput->clear();
}

void DashboardTab::ansiToQText(QTextCursor &cursor, const QString &text) {
    // Force insertion at the very end of the document. When the operator clicks
    // into the read-only output pane (e.g. to select/copy a previous line), the
    // widget's caret moves to the click position. `output->textCursor()` returns
    // *that* position - so without this move-to-end, new output inserts wherever
    // the operator last clicked, shifting subsequent blocks visually into the
    // wrong slots. Locking to End here is idempotent and cheap.
    cursor.movePosition(QTextCursor::End);

    QString remaining = text;
    QTextCharFormat format;

    static QRegularExpression ansiRegex("\x1B\\[[0-9;]*m");

    while (true) {
        QRegularExpressionMatch match = ansiRegex.match(remaining);
        if (!match.hasMatch()) {
            cursor.insertText(remaining, format);
            break;
        }

        int start = match.capturedStart();
        int end = match.capturedEnd();

        cursor.insertText(remaining.left(start), format);

        QString code = match.captured();
        remaining = remaining.mid(end);

        // normalize some color variants
        if (code.contains("32")) code = "\x1b[32m";
        else if (code.contains("31")) code = "\x1b[31m";
        else if (code.contains("33")) code = "\x1b[33m";

        if (ANSI_COLOR_MAP.contains(code)) {
            QColor c = ANSI_COLOR_MAP.value(code);
            if (c.isValid()) {
                format.setForeground(c);
            } else {
                format.clearForeground();
            }
        }
    }
}

// ===== transport slots & handler =====

void DashboardTab::onTransportLineBytes(const QByteArray &line) {
    QJsonParseError pe;
    QJsonDocument d = QJsonDocument::fromJson(line, &pe);
    if (pe.error == QJsonParseError::NoError && d.isObject())
        handleServerObject(d.object());
}

void DashboardTab::onTransportLineString(const QString &line) {
    QJsonParseError pe;
    QJsonDocument d = QJsonDocument::fromJson(line.toUtf8(), &pe);
    if (pe.error == QJsonParseError::NoError && d.isObject())
        handleServerObject(d.object());
}

void DashboardTab::onTransportJson(const QJsonObject &obj) {
    handleServerObject(obj);
}

// Normalize output: collapse consecutive blank lines, trim edges
QString DashboardTab::normalizeOutput(const QString &text) {
    if (text.isEmpty()) return text;

    // Normalize line endings
    QString tmp = text;
    tmp.replace("\r\n", "\n");
    tmp.replace('\r', '\n');

    // Split and process line by line
    QStringList lines = tmp.split('\n', Qt::KeepEmptyParts);
    QStringList result;
    int consecutiveBlank = 0;

    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        if (trimmed.isEmpty()) {
            // Allow at most 1 consecutive blank line
            if (consecutiveBlank < 1) {
                result << QString();
                consecutiveBlank++;
            }
        } else {
            consecutiveBlank = 0;
            result << line;
        }
    }

    // Join and trim leading/trailing whitespace
    QString normalized = result.join('\n').trimmed();
    return normalized;
}

void DashboardTab::handleServerObject(const QJsonObject &obj) {
    const QString act = obj.value("action").toString();
    const QString msgSessionId = obj.value("sessionId").toString();

    // Only process messages for this session
    if (msgSessionId != this->sessionId) return;

    if (act == QStringLiteral("command_started")) {
        // A new command has started executing - create a buffer entry
        const QString cmdId = obj.value("cmdId").toString();
        const QString command = obj.value("command").toString();
        currentCmdId = cmdId;

        // Create new pending command entry
        PendingCommand pc;
        pc.cmdId = cmdId;
        pc.command = command;
        pc.headerShown = false;
        pc.completed = false;
        // Attach any output that raced ahead of this command_started.
        if (orphanOutput.contains(cmdId)) pc.outputLines = orphanOutput.take(cmdId);
        pendingCommands.append(pc);

        // Signal "running" on the first in-flight command (rising edge).
        if (pendingCommands.size() == 1) emit runningStateChanged(true);

        // Show the header for the FRONT command immediately (just the echo). Output is
        // always buffered and rendered in order at completion, so nothing can interleave.
        if (pendingCommands.size() == 1) {
            pendingCommands[0].headerShown = true;
            QTextCursor cursor = output->textCursor();
            ansiToQText(cursor, QString("\n\x1b[36m─────────────────────────────────────────\x1b[0m\n"));
            ansiToQText(cursor, QString("\x1b[33m[>] %1\x1b[0m\n").arg(command));
            output->moveCursor(QTextCursor::End);
        }

    } else if (act == QStringLiteral("command_complete")) {
        // Command finished executing - mark as complete and flush
        const QString cmdId = obj.value("cmdId").toString();
        const bool ok = obj.value("ok").toBool(true);        // absent => assume success
        const int exitCode = obj.value("exitCode").toInt(0);
        // Server-side fallback: the DB-captured stdout shipped alongside the
        // completion frame. We use it only when our live outputLines buffer is
        // empty for the matched command, i.e. the live `output` message was
        // dropped somewhere between server and here.
        const QString fallbackStdout = obj.value("stdoutFallback").toString();

        if (cmdId == currentCmdId) {
            currentCmdId.clear();
        }

        // Find and mark the command as completed. If nothing streamed live,
        // use the DB-backed stdoutFallback so the operator always sees output.
        for (int i = 0; i < pendingCommands.size(); ++i) {
            if (pendingCommands[i].cmdId == cmdId) {
                pendingCommands[i].completed = true;
                pendingCommands[i].ok = ok;
                pendingCommands[i].exitCode = exitCode;
                if (pendingCommands[i].outputLines.isEmpty() && !fallbackStdout.isEmpty()) {
                    QString line = fallbackStdout;
                    if (!line.endsWith('\n')) line.append('\n');
                    pendingCommands[i].outputLines.append(line);
                }
                break;
            }
        }

        // Flush all completed commands from the front of the queue
        flushCompletedCommands();

    } else if (act == QStringLiteral("output")) {
        const QString stream = obj.value("stream").toString();
        const QString cmdId = obj.value("cmdId").toString();
        QString data = obj.value("data").toString();

        // Normalize the output to remove excessive blank lines
        data = normalizeOutput(data);
        if (data.isEmpty()) return;  // Skip empty output after normalization

        // Format the output line
        QString formattedLine;
        if (stream == QLatin1String("stderr")) {
            formattedLine = QString("\x1b[31m[ERR] %1\x1b[0m\n").arg(data);
        } else {
            formattedLine = data;
            if (!formattedLine.endsWith('\n')) formattedLine.append('\n');
        }

        // If the server sent output without a cmdId (pre-login raw broadcast, the
        // g_earlyOutput drain, or any code path that emits unframed output) render
        // it directly. Historically these bytes were silently dropped because the
        // pendingCommands lookup can't match an empty key and the orphan store
        // required a non-empty key too. That swallowed login diagnostics like
        // device-code URLs and the [Animo] SPN sub-list.
        if (cmdId.isEmpty()) {
            QTextCursor cursor = output->textCursor();
            ansiToQText(cursor, formattedLine);
            output->moveCursor(QTextCursor::End);
            return;
        }

        // ALWAYS buffer output against its command - never write to the cursor live.
        // Rendering happens only in flushCompletedCommands, strictly in FIFO order, so
        // one command's output can never appear under another's header.
        bool found = false;
        for (int i = 0; i < pendingCommands.size(); ++i) {
            if (pendingCommands[i].cmdId == cmdId) {
                pendingCommands[i].outputLines.append(formattedLine);
                found = true;
                break;
            }
        }

        // Output arrived before its command_started - hold it, keyed by cmdId, and
        // attach it when that command_started shows up (never dump it at the cursor).
        if (!found) {
            orphanOutput[cmdId].append(formattedLine);
        }

    } else if (act == QStringLiteral("session_exited")) {
        if (queryInput) {
            queryInput->setEnabled(false);
            QTextCursor cursor = output->textCursor();
            ansiToQText(cursor, "\n\x1b[31m[!] Session process ended. Input disabled.\x1b[0m\n");
        }
    }
}

void DashboardTab::flushCompletedCommands() {
    QTextCursor cursor = output->textCursor();

    // Process commands from the front while they are completed
    while (!pendingCommands.isEmpty() && pendingCommands.first().completed) {
        PendingCommand &pc = pendingCommands.first();

        // If header wasn't shown yet (was queued behind another command), show it now
        if (!pc.headerShown) {
            ansiToQText(cursor, QString("\n\x1b[36m─────────────────────────────────────────\x1b[0m\n"));
            ansiToQText(cursor, QString("\x1b[33m[>] %1\x1b[0m\n").arg(pc.command));
        }

        // Display all buffered output for this command
        for (const QString &line : pc.outputLines) {
            ansiToQText(cursor, line);
        }

        // Surface a failure so the user can tell a failed command from an empty one.
        if (!pc.ok) {
            const QString msg = pc.exitCode != 0
                ? QString("[!] Command failed (exit %1)\n").arg(pc.exitCode)
                : QStringLiteral("[!] Command failed\n");
            ansiToQText(cursor, QString("\x1b[31m%1\x1b[0m").arg(msg));
        }

        // Add closing separator
        ansiToQText(cursor, QString("\x1b[36m─────────────────────────────────────────\x1b[0m\n"));

        // Remove from queue
        pendingCommands.removeFirst();

        // If there's a next command waiting, show its header now
        if (!pendingCommands.isEmpty() && !pendingCommands.first().headerShown) {
            pendingCommands.first().headerShown = true;
            ansiToQText(cursor, QString("\n\x1b[36m─────────────────────────────────────────\x1b[0m\n"));
            ansiToQText(cursor, QString("\x1b[33m[>] %1\x1b[0m\n").arg(pendingCommands.first().command));
        }
    }

    output->moveCursor(QTextCursor::End);

    // Falling edge: no more in-flight commands - clear the "running" indicator.
    if (pendingCommands.isEmpty()) emit runningStateChanged(false);
}

void DashboardTab::loadCommandHistory() {
    // Load command history from local file per session
    QString historyFile = QString("data/history_%1.txt").arg(sessionId);
    QFile file(historyFile);

    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QStringList history;
        QTextStream in(&file);
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (!line.isEmpty()) {
                history.append(line);
            }
        }
        file.close();

        if (!history.isEmpty() && queryInput) {
            queryInput->loadHistory(history);
            // History loaded (debug removed for cleaner logs)
        }
    }
    // No history file (normal for new sessions - debug removed)
}

void DashboardTab::setupPowerShellCompletion() {
    if (!queryInput) return;

    // Comprehensive PowerShell cmdlet list for Azure, Az, Microsoft.Graph, and AzureAD modules
    QStringList completionList = {
        // AzureAD Module
        "Connect-AzureAD",
        "Disconnect-AzureAD",
        "Get-AzureADUser",
        "Get-AzureADGroup",
        "Get-AzureADApplication",
        "Get-AzureADServicePrincipal",
        "Get-AzureADDirectoryRole",
        "Get-AzureADDevice",
        "Get-AzureADTenantDetail",
        "Get-AzureADDomain",
        "New-AzureADUser",
        "New-AzureADGroup",
        "New-AzureADApplication",
        "Remove-AzureADUser",
        "Remove-AzureADGroup",
        "Set-AzureADUser",
        "Add-AzureADGroupMember",
        "Get-AzureADGroupMember",

        // Az Module - Core
        "Connect-AzAccount",
        "Disconnect-AzAccount",
        "Get-AzContext",
        "Set-AzContext",
        "Get-AzSubscription",
        "Select-AzSubscription",
        "Get-AzTenant",
        "Get-AzLocation",

        // Az Module - Resources
        "Get-AzResourceGroup",
        "New-AzResourceGroup",
        "Remove-AzResourceGroup",
        "Get-AzResource",
        "New-AzResource",
        "Remove-AzResource",
        "Set-AzResource",

        // Az Module - VMs
        "Get-AzVM",
        "New-AzVM",
        "Start-AzVM",
        "Stop-AzVM",
        "Restart-AzVM",
        "Remove-AzVM",
        "Get-AzVMSize",
        "Get-AzVMImage",

        // Az Module - Storage
        "Get-AzStorageAccount",
        "New-AzStorageAccount",
        "Remove-AzStorageAccount",
        "Get-AzStorageContainer",
        "New-AzStorageContainer",
        "Get-AzStorageBlob",

        // Az Module - Networking
        "Get-AzVirtualNetwork",
        "New-AzVirtualNetwork",
        "Get-AzNetworkSecurityGroup",
        "New-AzNetworkSecurityGroup",
        "Get-AzPublicIpAddress",
        "New-AzPublicIpAddress",

        // Az Module - Key Vault
        "Get-AzKeyVault",
        "New-AzKeyVault",
        "Get-AzKeyVaultSecret",
        "Set-AzKeyVaultSecret",
        "Get-AzKeyVaultKey",
        "Set-AzKeyVaultKey",

        // Microsoft.Graph Module - Users
        "Connect-MgGraph",
        "Disconnect-MgGraph",
        "Get-MgUser",
        "Get-MgUserManager",
        "Get-MgUserMemberOf",
        "Get-MgUserOwnedObject",
        "New-MgUser",
        "Update-MgUser",
        "Remove-MgUser",

        // Microsoft.Graph Module - Groups
        "Get-MgGroup",
        "Get-MgGroupMember",
        "Get-MgGroupOwner",
        "New-MgGroup",
        "Update-MgGroup",
        "Remove-MgGroup",
        "New-MgGroupMember",

        // Microsoft.Graph Module - Applications
        "Get-MgApplication",
        "Get-MgServicePrincipal",
        "New-MgApplication",
        "Update-MgApplication",
        "Remove-MgApplication",
        "New-MgServicePrincipal",

        // Microsoft.Graph Module - Mail
        "Get-MgUserMessage",
        "Send-MgUserMail",
        "New-MgUserMessage",
        "Remove-MgUserMessage",
        "Get-MgUserMailFolder",

        // Microsoft.Graph Module - Calendar
        "Get-MgUserEvent",
        "Get-MgUserCalendar",
        "New-MgUserEvent",
        "Update-MgUserEvent",
        "Remove-MgUserEvent",

        // Microsoft.Graph Module - Teams
        "Get-MgTeam",
        "Get-MgTeamChannel",
        "Get-MgTeamMember",
        "New-MgTeam",
        "Send-MgTeamChannelMessage",

        // Microsoft.Graph Module - SharePoint/OneDrive
        "Get-MgUserDrive",
        "Get-MgDriveItem",
        "New-MgDriveItem",
        "Copy-MgDriveItem",
        "Remove-MgDriveItem",
        "Get-MgSite",

        // Microsoft.Graph Module - Security
        "Get-MgDirectoryRole",
        "Get-MgDirectoryRoleMember",
        "Get-MgAuditLogSignIn",
        "Get-MgAuditLogDirectoryAudit",

        // Common PowerShell Core Cmdlets
        "Get-Command",
        "Get-Help",
        "Get-Member",
        "Get-Process",
        "Get-Service",
        "Get-Content",
        "Set-Content",
        "Out-File",
        "Export-Csv",
        "Import-Csv",
        "ConvertTo-Json",
        "ConvertFrom-Json",
        "Select-Object",
        "Where-Object",
        "ForEach-Object",
        "Sort-Object",
        "Measure-Object",
        "Format-Table",
        "Format-List",
        "Get-Date",
        "Write-Host",
        "Write-Output",
        "Clear-Host"
    };

    queryInput->setCompletionList(completionList);
    // PowerShell completion configured (debug removed for cleaner logs)
}

void DashboardTab::saveCommandHistory() {
    if (!queryInput) return;

    QString historyFile = QString("data/history_%1.txt").arg(sessionId);
    QFile file(historyFile);

    // Ensure data directory exists
    QDir dir("data");
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        QStringList history = queryInput->getHistory();
        for (const QString &cmd : history) {
            out << cmd << "\n";
        }
        file.close();
        // History saved (debug removed for cleaner logs)
    } else {
        qWarning() << "[DashboardTab] Failed to save command history to" << historyFile;
    }
}

void DashboardTab::clearConsole() {
    if (output) {
        output->clear();
        // Show a subtle message so user knows it worked
        QTextCursor cursor = output->textCursor();
        ansiToQText(cursor, "\x1b[90m[Console cleared]\x1b[0m\n");
        output->moveCursor(QTextCursor::End);
    }
    // Also clear pending command buffers since they were already displayed or are stale
    pendingCommands.clear();
    currentCmdId.clear();
}
