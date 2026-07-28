#include "Server.h"
#include "../shared/Protocol.h"
#include "../shared/OutputSanitizer.h"
#include "../shared/PowerShellManager.h"
#include "../shared/Config.h"
#include "SessionDBManager.h"


#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QHostAddress>
#include <QProcess>
#include <QHash>
#include <QSet>
#include <QPointer>
#include <QStandardPaths>
#include <QFileInfo>
#include <QTimer>
#include <QUuid>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QUrlQuery>
#include <QMutex>
#include <QMutexLocker>
#include <QCoreApplication>


// Network for tenant id resolution
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QRegularExpression>

// SQLite
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDateTime>

// ===== Thread-safe in-memory state =====
static QMutex g_stateMutex;  // Protects all global state below
static QHash<QString, QProcess*>         g_sessions;      // sessionId -> process
static QHash<QString, QSet<QTcpSocket*>> g_subscribers;   // sessionId -> sockets
static QHash<QString, QByteArray>        g_stdoutBuf;     // sessionId -> aggregated stdout (for marker scan)
static QHash<QString, QJsonObject>       g_sessionInfo;   // sessionId -> {user, tenantId, domain, resource}
static QHash<QString, QString>           g_loginRid;      // sessionId -> rid (to echo back on login)
static QHash<QString, QString>           g_pendingToken;  // sessionId -> access token (captured from PS before login OK)
static QHash<QString, QString>           g_lastCommand;   // sessionId -> last command (for history)

// Command execution state (one active command per session; the rest queued)
static QHash<QString, QString>           g_activeCmdId;   // sessionId -> currently executing cmdId
static QHash<QString, qint64>            g_cmdStartTime;  // sessionId -> when command started (ms since epoch)
static constexpr qint64 CMD_TIMEOUT_MS = 30000;           // 30 second timeout for stale command detection

struct QueuedCommand { QString cmdId; QString cmd; QString op; };
static QHash<QString, QList<QueuedCommand>> g_cmdQueue;   // sessionId -> commands waiting to run
static constexpr int MAX_CMD_QUEUE = 50;                  // bound the per-session queue

// Pending token reinject waiting for the current command to finish. If the
// client sends reinject_tokens while a command is running, we cannot write to
// stdin (it would interleave with the command's output stream). Instead the
// payload sits here and is flushed the moment the active command completes,
// so the terminal's Az context always ends up refreshed.
static QHash<QString, QByteArray> g_pendingReinject;      // sessionId -> full PS payload

// Buffered pre-login (inAuth) stdout so late-opened terminal tabs can still
// see login-time diagnostics (e.g. the SPN login script's subscription list).
// Drained the first time get_session subscribes a socket to the session.
static QHash<QString, QByteArray> g_earlyOutput;
static constexpr int MAX_EARLY_OUTPUT = 64 * 1024;         // bound the buffer

// Single-fire auth gating (prevents duplicate OK/FAIL handling)
enum class AuthState { Pending, Success, Failed };
static QHash<QString, AuthState> g_authState;

// ===== Helpers (define once) ===============================================
static inline QByteArray toBytes(const QJsonObject &o) { return Protocol::toBytes(o); }

// sessionId is used to build filesystem paths, so reject anything outside this
// charset/length (prevents path traversal like "../../foo").
static inline bool isValidSessionId(const QString &sid) {
    static const QRegularExpression sessionIdRe(
        QStringLiteral("^[a-zA-Z0-9_\\-]{1,64}$"));
    return sessionIdRe.match(sid).hasMatch();
}

// Load PowerShell script from Qt resources
static QByteArray loadScript(const QString &resourcePath) {
    QFile file(resourcePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "[Server] Failed to load script resource:" << resourcePath;
        return QByteArray();
    }
    return file.readAll();
}

// Returns true if bytes were actually written to a ConnectedState socket.
// Distinguishes "socket dead" from "socket buffer full" so callers can prune.
static inline bool sendTo(QTcpSocket *sock, const QJsonObject &obj) {
    if (!sock) return false;
    if (sock->state() != QAbstractSocket::ConnectedState) return false;
    const QByteArray bytes = toBytes(obj);
    const qint64 wrote = sock->write(bytes);
    if (wrote < 0) return false;
    // Force the OS to see it now, not on next event-loop turn. Broadcasts
    // are often followed by a mutex release + long computation, so buffered
    // writes would sit in Qt's send buffer instead of hitting the socket.
    sock->flush();
    return true;
}

// Broadcast + prune. If a socket isn't ConnectedState or write() fails, it's
// removed from the target session's subscriber set - otherwise a crashed
// client's dangling socket pointer would silently swallow every subsequent
// broadcast, making the caller think "N subscribers received it" when N-1 got
// nothing. Caller must hold g_stateMutex (all existing callers do).
static void broadcastToSession(const QString &sessionId, const QJsonObject &obj);

// Fallback for callers that don't have a sessionId (e.g. session_exit hook
// broadcasting to a saved local copy). No pruning possible here.
static inline void broadcastTo(const QSet<QTcpSocket*> &socks, const QJsonObject &obj) {
    for (QTcpSocket *s : socks) sendTo(s, obj);
}

static void broadcastToSession(const QString &sessionId, const QJsonObject &obj) {
    auto it = g_subscribers.find(sessionId);
    if (it == g_subscribers.end()) return;
    QSet<QTcpSocket*> &subs = it.value();
    QSet<QTcpSocket*> dead;
    // Iterate a snapshot so we can mutate `subs` (remove-during-iterate is UB).
    const QList<QTcpSocket*> snapshot(subs.begin(), subs.end());
    for (QTcpSocket *s : snapshot) {
        if (!sendTo(s, obj)) dead.insert(s);
    }
    if (!dead.isEmpty()) {
        for (QTcpSocket *s : dead) subs.remove(s);
        qInfo().noquote() << QString("[Server] pruned %1 dead subscriber(s) from sid=%2")
                                .arg(dead.size()).arg(sessionId.left(8));
    }
}

// Write a wrapped command to the session's shell, mark it active, persist it, and
// announce it to subscribers. Caller must hold g_stateMutex.
static void dispatchCommand(const QString &sid, const QString &cmdId, const QString &cmd,
                            const QString &op = QStringLiteral("unknown")) {
    QProcess *proc = g_sessions.value(sid);
    if (!proc) {
        qWarning().noquote() << QString("[Server] dispatchCommand: no process for session %1 (cmd=%2)")
                                    .arg(sid.left(8), cmd.left(60));
        return;
    }
    g_activeCmdId[sid]  = cmdId;
    g_cmdStartTime[sid] = QDateTime::currentMSecsSinceEpoch();

    const QString wrapped = OutputSanitizer::wrapPwshCommandWithId(cmd, cmdId);
    proc->write(wrapped.toUtf8());
    proc->write("\n");

    SessionDBManager::instance().insertCommandOutput(sid, cmd, QString(), cmdId, op);
    broadcastToSession(sid,
        QJsonObject{ {Protocol::F_ACTION, "command_started"},
                     {"sessionId", sid}, {Protocol::F_CMD_ID, cmdId}, {"command", cmd} });
}

static QString resolveTenantIdBlocking(const QString &domain) {
    if (domain.isEmpty()) return QStringLiteral("N/A");
    QNetworkAccessManager mgr;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);

    QNetworkReply *rep = mgr.get(QNetworkRequest(
        QUrl(QString("https://login.microsoftonline.com/%1/.well-known/openid-configuration").arg(domain))));

    QObject::connect(rep, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);

    timeout.start(5000);  // 5 second timeout to prevent server hang
    loop.exec();

    QString tenant = "N/A";
    if (timeout.isActive()) {
        // Network completed before timeout
        timeout.stop();
        if (rep->error() == QNetworkReply::NoError) {
            const auto doc  = QJsonDocument::fromJson(rep->readAll());
            const QString ae = doc.object().value("authorization_endpoint").toString();
            // Expected: https://login.microsoftonline.com/<tenantId>/oauth2/...
            const QStringList parts = ae.split('/', Qt::SkipEmptyParts);
            for (int i = 0; i < parts.size(); ++i) {
                if (parts[i].contains("login.microsoftonline.com", Qt::CaseInsensitive) && i + 1 < parts.size()) {
                    tenant = parts[i + 1];
                    break;
                }
            }
        }
    } else {
        // Timeout occurred - abort the request
        qWarning() << "[Server] Tenant resolution timed out for domain:" << domain;
        rep->abort();
    }
    rep->deleteLater();
    return tenant.isEmpty() ? QStringLiteral("N/A") : tenant;
}

// ---- Helpers ---------------------------------------
// Output sanitization moved to shared/OutputSanitizer.h
// PowerShell utilities moved to shared/PowerShellManager.h

// Escape strings for safe use in PowerShell single-quoted strings.
// In PS single-quoted strings, the ONLY special character is the single quote
// itself (doubled to escape). However, we also sanitize null bytes and
// carriage returns/newlines to prevent injection via string termination.
static QString escapePsString(const QString &s) {
    QString escaped;
    escaped.reserve(s.size() + 16);
    for (const QChar &ch : s) {
        if (ch == QLatin1Char('\'')) {
            escaped.append(QLatin1String("''"));
        } else if (ch == QLatin1Char('\0')) {
            // Strip null bytes - could terminate strings in edge cases
            continue;
        } else if (ch == QLatin1Char('\n') || ch == QLatin1Char('\r')) {
            // Strip newlines - could break out of single-line PS context
            continue;
        } else {
            escaped.append(ch);
        }
    }
    return escaped;
}

// ===========================================================================
// Database operations now handled by SessionDBManager
// See: SessionDBManager.h for all session and token database operations
// ===========================================================================

// ===========================================================================
// Ensure a PowerShell process exists for this session; start and wire output
// Now uses SessionDBManager for all DB I/O (main + per-session history)
// ===========================================================================
static QProcess* ensureProcess(QObject *parent, const QString &sessionId,
                               const QString &createdBy = QStringLiteral("unknown")) {
    QMutexLocker locker(&g_stateMutex);
    if (g_sessions.contains(sessionId)) return g_sessions.value(sessionId);

    const QString program = PowerShellManager::getPwshPath();

    auto *proc = new QProcess(parent);
    proc->setProcessChannelMode(QProcess::SeparateChannels);

    // Environment: use dumb terminal to disable escape sequences
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("TERM", "dumb");  // Force dumb terminal - no escape sequences
    env.insert("NO_COLOR", "1"); // Disable color output
    env.insert("POWERSHELL_TELEMETRY_OPTOUT", "1");

    // Per-session Az context isolation. Without this, every session shares
    // ~/.Azure/AzureRmContext.json and stale AccessToken contexts poison each
    // other's default context (breaks token minting non-deterministically).
    const QString azConfigDir = QString("%1/data/sessions/%2/.azure")
        .arg(QCoreApplication::applicationDirPath(), sessionId);
    QDir().mkpath(azConfigDir);
    env.insert("AZURE_CONFIG_DIR", azConfigDir);

    proc->setProcessEnvironment(env);

    // Common args
    QStringList args{ "-NoLogo", "-NoProfile", "-NonInteractive" };
#ifdef Q_OS_WIN
    // Only add ExecutionPolicy Bypass for legacy Windows PowerShell
    if (program.contains("powershell", Qt::CaseInsensitive)) {
        args << "-ExecutionPolicy" << "Bypass";
    }
#endif

    proc->start(program, args);
    if (!proc->waitForStarted(APP_CONFIG.processStartTimeoutMs())) {
        qWarning() << "[Server] Failed to start PowerShell:" << program << args;
        delete proc;
        return nullptr;
    }

    // Register session immediately, mark pending, ensure defaults
    g_sessions.insert(sessionId, proc);
    g_authState.insert(sessionId, AuthState::Pending);

    QJsonObject meta = g_sessionInfo.value(sessionId);
    if (!meta.contains("resource")) meta.insert("resource", "https://management.azure.com");
    if (!meta.contains("user"))     meta.insert("user",     "Unknown");
    if (!meta.contains("tenantId")) meta.insert("tenantId", "N/A");
    if (!meta.contains("domain"))   meta.insert("domain",   "N/A");
    g_sessionInfo.insert(sessionId, meta);

    // Persist/ensure DBs via SessionDBManager
    SessionDBManager::instance().initMainDB();
    SessionDBManager::instance().addSessionToMainDB(
        sessionId,
        meta.value("user").toString("Unknown"),
        meta.value("tenantId").toString("N/A"),
        meta.value("domain").toString("N/A"),
        meta.value("resource").toString("https://management.azure.com"),
        createdBy
    );
    SessionDBManager::instance().createSessionDB(sessionId);
    // Reflect live-process state so the sessions table isn't stuck on Alive=0.
    SessionDBManager::instance().setSessionAlive(sessionId, true);

    // Tell subscribers the shell is alive
    broadcastToSession(sessionId,
        QJsonObject{ {Protocol::F_ACTION, "session_open"},
                     {"sessionId", sessionId},
                     {"alive", true} });

    // Minimal init: suppress noise silently using $null assignment to prevent echo
    proc->write("$null=$ErrorActionPreference=$ProgressPreference=$WarningPreference='SilentlyContinue'\n");
    proc->write("$null=Remove-Module PSReadLine -Force -EA SilentlyContinue\n");
    proc->write("function global:prompt{''}\n");
    // Force TLS 1.2+ for Invoke-RestMethod/WebRequest so calls to Azure/M365 endpoints
    // don't fail TLS negotiation on hosts that still default to older protocols.
    proc->write("try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13}catch{try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12}catch{}}\n");

    // STDOUT hook: segment & sanitize AFTER login; raw during auth (so device code text shows)
    QObject::connect(proc, &QProcess::readyReadStandardOutput, parent, [proc, sessionId]() {
        const QByteArray chunk = proc->readAllStandardOutput();
		if (chunk.isEmpty()) return;

		QMutexLocker locker(&g_stateMutex);
		QByteArray &buf = g_stdoutBuf[sessionId];
		buf.append(chunk);

		// Limit buffer size to prevent unbounded memory growth (1MB max)
		static constexpr int MAX_BUFFER_SIZE = 1024 * 1024;
		if (buf.size() > MAX_BUFFER_SIZE) {
		    // Trim from beginning, keeping the most recent data
		    // Use swap for efficient memory management instead of remove()
		    QByteArray trimmed = buf.mid(buf.size() - MAX_BUFFER_SIZE);
		    buf.swap(trimmed);
		}

		bool emittedAny = false; // NEW: track if we emitted a cleaned segment this read

        // During login, pass-through raw so user sees device-code instructions etc.
        const bool inAuth = (g_authState.value(sessionId, AuthState::Pending) == AuthState::Pending);
        if (inAuth) {
            // Denylist-then-allowlist filter for pre-login pwsh output.
            //
            // Denylist fails because pwsh's stdin echo arrives split across TCP
            // chunks in arbitrary places ("nu" | "ll=$ErrorAction..."). A line
            // filter can't catch fragments.
            //
            // So instead: only forward chunks whose text CONTAINS something we
            // know an operator actually needs to see during login. Everything
            // else during inAuth is dropped. Post-login output isn't affected
            // (this whole block only runs while authState == Pending).
            //
            // Whitelist covers:
            //   - Device-code login (URL + code)
            //   - [Animo] diagnostic lines (SPN sub list, WARNING, etc.)
            //   - Login failure text
            //   - MFA prompts
            static const QList<QByteArray> keepSubstrings = {
                "microsoft.com/devicelogin",   // device code URL
                "https://microsoft.com/",      // any MSFT login URL
                "enter the code",              // device code instruction
                "[Animo]",                     // our SPN login-script diagnostics
                "__ANIMO_MFA_REQUIRED__",      // MFA marker (also parsed by scanner)
                "WARNING",                     // any Az/PS warning worth surfacing
                "ERROR",                       // any Az/PS error
                "authentication failed",       // MSAL fail
                "invalid_",                    // invalid_client, invalid_grant, etc.
            };
            auto looksInteresting = [&](const QByteArray &data) -> bool {
                for (const QByteArray &s : keepSubstrings) {
                    if (data.contains(s)) return true;
                }
                return false;
            };

            if (looksInteresting(chunk)) {
                broadcastToSession(sessionId,
                    QJsonObject{ {Protocol::F_ACTION, "output"},
                                 {"sessionId", sessionId},
                                 {"stream", "stdout"},
                                 {"data", QString::fromUtf8(chunk)} });
                QByteArray &early = g_earlyOutput[sessionId];
                if (early.size() < MAX_EARLY_OUTPUT) {
                    const int room = MAX_EARLY_OUTPUT - early.size();
                    early.append(chunk.left(room));
                }
            }
            emittedAny = true;  // Prevent duplicate broadcast later
        }

        // Extract complete segments:
        //   __QZ_BEGIN__:<id>  <output>  [__QZ_ERR__:<id> <err>]  __QZ_EXIT__:<id>:<fail>:<code>  __QZ_END__:<id>
        // Markers are matched ONLY at line boundaries and END is paired to its BEGIN by
        // cmdId, so output that merely contains marker-looking text cannot break framing,
        // and a command that never closed (no END) cannot merge into the next command.
        static const QByteArray B = "__QZ_BEGIN__";
        static const QByteArray E = "__QZ_END__";

        auto atLineStart = [&buf](int p) { return p == 0 || (p > 0 && buf.at(p - 1) == '\n'); };
        auto findMarkerLine = [&buf, &atLineStart](const QByteArray &m, int from) {
            int p = from;
            while ((p = buf.indexOf(m, p)) >= 0) {
                if (atLineStart(p)) return p;
                p += 1;
            }
            return -1;
        };

        while (true) {
            int b = findMarkerLine(B, 0);
            if (b < 0) break;

            int beginLineEnd = buf.indexOf('\n', b);
            if (beginLineEnd < 0) break;  // BEGIN line not fully arrived yet

            // cmdId from the BEGIN marker (format: __QZ_BEGIN__:<id>)
            QByteArray beginLine = buf.mid(b, beginLineEnd - b);
            QString beginCmdId;
            int colonPos = beginLine.indexOf(':');
            if (colonPos > 0) beginCmdId = QString::fromUtf8(beginLine.mid(colonPos + 1)).trimmed();

            // The matching END carries the same cmdId.
            const QByteArray endMarker = beginCmdId.isEmpty()
                ? E : (E + ":" + beginCmdId.toUtf8());
            int e = findMarkerLine(endMarker, beginLineEnd);
            if (e < 0) {
                // No matching END yet. If a newer BEGIN has already arrived, this segment
                // is orphaned (its command never closed) - drop it so it can't merge forward.
                int nextBegin = findMarkerLine(B, beginLineEnd);
                if (nextBegin >= 0) { buf.remove(0, nextBegin); continue; }
                break;  // otherwise wait for the rest of this command's output
            }

            QByteArray segment = buf.mid(beginLineEnd + 1, e - (beginLineEnd + 1));

            // Consume through the END line.
            int endLineEnd = buf.indexOf('\n', e);
            buf.remove(0, (endLineEnd >= 0) ? endLineEnd + 1 : buf.size());

            const QString cmdId = beginCmdId;

            // Pull exit status / failure flag from the segment (format __QZ_EXIT__:<id>:<fail>:<code>).
            bool failed = false;
            int exitCode = 0;
            int ei = segment.indexOf("__QZ_EXIT__:");
            if (ei >= 0) {
                int le = segment.indexOf('\n', ei);
                const QByteArray exitLine = (le >= 0 ? segment.mid(ei, le - ei) : segment.mid(ei)).trimmed();
                const QList<QByteArray> parts = exitLine.split(':');
                if (parts.size() >= 4) {
                    failed   = (parts.at(parts.size() - 2).trimmed() == "1");
                    exitCode = parts.at(parts.size() - 1).trimmed().toInt();
                }
            }
            if (segment.contains("__QZ_ERR__")) failed = true;

            // Sanitize and strip every QZ marker line from the visible output.
            QString cleaned = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(segment));
            static QRegularExpression markerRe(R"(__QZ_(BEGIN|END|EXIT|ERR)__(:[^\n]*)?)");
            cleaned.remove(markerRe);
            cleaned = cleaned.trimmed();

            // A non-empty cmdId means the segment came from wrapPwshCommandWithId
            // (i.e. a real operator command), which by construction only happens
            // AFTER the login script has finished. Don't let a lingering
            // inAuth==true gate silently drop that output - broadcast it either way.
            // Pre-login raw broadcasts (line 302) are the ONLY case that legitimately
            // should stay off the segment path, and those never have a cmdId.
            const bool haveCmdId = !cmdId.isEmpty();
            const bool shouldBroadcast = !cleaned.isEmpty() && (haveCmdId || !inAuth);

            if (shouldBroadcast) {
                QJsonObject outMsg{
                    {Protocol::F_ACTION, "output"},
                    {"sessionId", sessionId},
                    {"stream", "stdout"},
                    {"data", cleaned}
                };
                if (haveCmdId) outMsg.insert(Protocol::F_CMD_ID, cmdId);
                broadcastToSession(sessionId, outMsg);
            }

            SessionDBManager::instance().insertCommandOutput(sessionId, QString(), cleaned, cmdId);

            // Emit command_complete for THIS segment immediately, paired with its own
            // output and cmdId. Include the same cleaned output in a fallback field
            // so the client can render it even if the live output message got lost.
            // Same gate as broadcast: real commands (haveCmdId) always fire.
            if (haveCmdId || !inAuth) {
                const QString finalCmdId = cmdId.isEmpty() ? g_activeCmdId.value(sessionId) : cmdId;
                g_activeCmdId.remove(sessionId);
                g_cmdStartTime.remove(sessionId);

                QJsonObject completeMsg{
                    {Protocol::F_ACTION, "command_complete"},
                    {"sessionId", sessionId},
                    {Protocol::F_CMD_ID, finalCmdId},
                    {"ok", !failed},
                    {"exitCode", exitCode},
                    // Belt-and-suspenders: send the DB-captured stdout with the
                    // completion frame. Client uses it if its outputLines buffer
                    // is empty (i.e. the live output message got lost).
                    {"stdoutFallback", cleaned}
                };
                broadcastToSession(sessionId, completeMsg);

                // Flush any pending token reinject that arrived while this
                // command was running. Doing it here keeps the Az context
                // renewed even for sessions that are almost always busy.
                // NOTE: we're ALREADY inside g_stateMutex (locked at the top of
                // this lambda). QMutex is non-recursive, so a nested QMutexLocker
                // here would deadlock the whole main thread and every future
                // run_command would silently block. Access maps directly instead.
                {
                    QByteArray pending = g_pendingReinject.take(sessionId);
                    if (!pending.isEmpty()) {
                        if (QProcess *p = g_sessions.value(sessionId, nullptr))
                            p->write(pending);
                    }
                }

                // Dispatch the next queued command for this session, if any.
                if (!g_cmdQueue.value(sessionId).isEmpty()) {
                    const QueuedCommand next = g_cmdQueue[sessionId].takeFirst();
                    if (g_cmdQueue[sessionId].isEmpty()) g_cmdQueue.remove(sessionId);
                    dispatchCommand(sessionId, next.cmdId, next.cmd, next.op);
                }
            }
        }
		
		// ==== Only if we're still in auth AND we didn't emit a cleaned segment, pass raw ====
		if (inAuth && !emittedAny) {
			broadcastToSession(sessionId,
				QJsonObject{ {Protocol::F_ACTION, "output"},
							{"sessionId", sessionId},
							{"stream", "stdout"},
							{"data", QString::fromUtf8(chunk)} });
		}

        // ===== Login OK/FAIL/MFA marker scan (single-fire) =====
        if (g_authState.value(sessionId, AuthState::Pending) == AuthState::Pending) {
            static const QByteArray OK_MARKER   = "__ANIMO_LOGIN_OK__:";
            static const QByteArray FAIL_MARKER = "__ANIMO_LOGIN_FAIL__";
            static const QByteArray MFA_MARKER  = "__ANIMO_MFA_REQUIRED__:";

            // Strip ANSI escape sequences from buffer before marker detection
            // Matches: ESC[...X where X is a letter, and ESC[?...h/l sequences
            static const QRegularExpression escapeRe(R"(\x1b\[[0-9;?]*[A-Za-z]|\x1b\].*?\x07|\x1b[()][0-9A-Za-z])");
            QString bufStr = QString::fromUtf8(buf);
            bufStr.remove(escapeRe);
            buf = bufStr.toUtf8();

            // Capture access token emitted by SPN (or other) scripts before OK marker
            static const QByteArray TOKEN_MARKER = "__ANIMO_TOKEN__:";
            {
                int tIdx = buf.indexOf(TOKEN_MARKER);
                if (tIdx >= 0 && (tIdx == 0 || buf.at(tIdx - 1) == '\n')) {
                    const int tStart = tIdx + TOKEN_MARKER.size();
                    const int tNl = buf.indexOf('\n', tStart);
                    const QByteArray tokenBA = (tNl >= 0) ? buf.mid(tStart, tNl - tStart) : buf.mid(tStart);
                    QString token = QString::fromUtf8(tokenBA).trimmed();
                    if (!token.isEmpty()) {
                        g_pendingToken.insert(sessionId, token);
                    }
                    // consume the marker line
                    if (tNl >= 0) buf.remove(tIdx, tNl - tIdx + 1);
                    else buf.remove(tIdx, tokenBA.size() + TOKEN_MARKER.size());
                }
            }

            // Check for MFA required marker first
            const int mfaIdx = buf.indexOf(MFA_MARKER);
            if (mfaIdx >= 0) {
                const int nl = buf.indexOf('\n', mfaIdx);
                const int start = mfaIdx + MFA_MARKER.size();
                const QByteArray mfaData = (nl >= 0) ? buf.mid(start, nl - start) : buf.mid(start);

                // Parse MFA code and message (format: CODE:message)
                QString mfaStr = QString::fromUtf8(mfaData).trimmed();
                QString mfaCode = mfaStr.section(':', 0, 0);
                QString mfaMsg = mfaStr.section(':', 1);

                // Broadcast MFA required notification
                QJsonObject ev{
                    {Protocol::F_ACTION, Protocol::ACTION_MFA_REQUIRED},
                    {"sessionId", sessionId},
                    {"mfaCode", mfaCode},
                    {"mfaMessage", mfaMsg}
                };
                if (g_loginRid.contains(sessionId)) ev.insert("rid", g_loginRid.value(sessionId));
                broadcastToSession(sessionId, ev);

                // Consume the MFA marker line
                if (nl >= 0) buf.remove(mfaIdx, nl - mfaIdx + 1);
                else buf.remove(mfaIdx, mfaData.size() + MFA_MARKER.size());
            }

            // Find markers only at start of line (not embedded in echoed script code)
            auto findMarkerAtLineStart = [&buf](const QByteArray &marker) -> int {
                int pos = 0;
                while ((pos = buf.indexOf(marker, pos)) >= 0) {
                    // Check if marker is at start of buffer or after a newline
                    if (pos == 0 || buf.at(pos - 1) == '\n') {
                        return pos;
                    }
                    pos += marker.size();
                }
                return -1;
            };

            const int okIdx   = findMarkerAtLineStart(OK_MARKER);
            const int failIdx = findMarkerAtLineStart(FAIL_MARKER);
            const bool hasOk   = (okIdx  >= 0);
            const bool hasFail = (failIdx>= 0);

            // Prefer whichever marker appears first
            if (hasOk && (!hasFail || okIdx < failIdx)) {
                const int nl    = buf.indexOf('\n', okIdx);
                const int start = okIdx + OK_MARKER.size();
                const QByteArray upnBA = (nl >= 0) ? buf.mid(start, nl - start) : buf.mid(start);

                QString upn = QString::fromUtf8(upnBA).trimmed();
                if (upn.startsWith('"') && upn.endsWith('"') && upn.size() >= 2) {
                    upn = upn.mid(1, upn.size() - 2).trimmed();
                }

                const QString derivedDomain = upn.contains('@')
                                                  ? upn.section('@', 1, 1)
                                                  : QStringLiteral("N/A");

                // enrich + persist success. If the mode-specific branch already
                // stashed real tenant/domain metadata (e.g. SPN mode stores the
                // tenant GUID from the login request), keep it - the UPN-derived
                // fallback only fills in when we still have "N/A".
                QJsonObject meta = g_sessionInfo.value(sessionId);
                const QString existingTenant = meta.value("tenantId").toString();
                const QString existingDomain = meta.value("domain").toString();
                const auto isPlaceholder = [](const QString &v) {
                    return v.isEmpty() || v == QStringLiteral("N/A");
                };
                const QString tenant = isPlaceholder(existingTenant) ? derivedDomain : existingTenant;
                const QString domain = isPlaceholder(existingDomain) ? derivedDomain : existingDomain;

                meta.insert("user",     upn.isEmpty() ? QStringLiteral("Unknown") : upn);
                meta.insert("domain",   domain);
                meta.insert("tenantId", tenant);
                g_sessionInfo.insert(sessionId, meta);

                SessionDBManager::instance().updateSessionUser(sessionId, meta.value("user").toString("Unknown"));
                SessionDBManager::instance().updateSessionTenant(sessionId, tenant, domain);

                // notify (single-fire)
                QJsonObject ev{
                    {Protocol::F_ACTION, "session_created"},
                    {"sessionId", sessionId},
                    {"user",      meta.value("user").toString("Unknown")},
                    {"domain",    domain},
                    {"tenantId",  tenant},
                    {"resource",  meta.value("resource").toString("https://management.azure.com")}
                };
                if (g_loginRid.contains(sessionId)) ev.insert("rid", g_loginRid.take(sessionId));
                if (g_pendingToken.contains(sessionId)) ev.insert("accessToken", g_pendingToken.take(sessionId));
                // Forward storage token acquired via refresh exchange (MSAL sessions)
                const QString stToken = meta.value("storageToken").toString();
                if (!stToken.isEmpty()) ev.insert("storageToken", stToken);

                qInfo() << "[Server] ✓ Session created:" << sessionId << "| User:" << upn << "| Method: Credentials";
                broadcastToSession(sessionId, ev);

                // consume matched line and lock state
                if (nl >= 0) buf.remove(0, nl + 1);
                else buf.clear();
                g_authState[sessionId] = AuthState::Success;
                SessionDBManager::instance().setSessionStatus(sessionId, QStringLiteral("success"));
                // The early-output buffer is only useful for tabs opened during
                // the auth window. After we've transitioned to Success, the
                // buffer will never be replayed - drop it so it can't linger.
                g_earlyOutput.remove(sessionId);

            } else if (hasFail && (!hasOk || failIdx < okIdx)) {
                // failure - extract error message if present
                // Format: __ANIMO_LOGIN_FAIL__:error_message
                QString errorMsg = "Login failed";
                const int colonIdx = failIdx + FAIL_MARKER.size();
                if (colonIdx < buf.size() && buf.at(colonIdx) == ':') {
                    const int nlIdx = buf.indexOf('\n', colonIdx);
                    const int endIdx = (nlIdx >= 0) ? nlIdx : buf.size();
                    QString extracted = QString::fromUtf8(buf.mid(colonIdx + 1, endIdx - colonIdx - 1)).trimmed();
                    if (!extracted.isEmpty()) {
                        errorMsg = QString("Login failed: %1").arg(extracted);
                    }
                }
                qWarning() << "[Server] Login failed for session:" << sessionId << "-" << errorMsg;

                QJsonObject ev{ {Protocol::F_ACTION, "error"},
                                {"message", errorMsg} };
                if (g_loginRid.contains(sessionId)) ev.insert("rid", g_loginRid.take(sessionId));
                broadcastToSession(sessionId, ev);

                const int nl = buf.indexOf('\n', failIdx);
                if (nl >= 0) buf.remove(0, nl + 1); else buf.clear();
                g_authState[sessionId] = AuthState::Failed;
                SessionDBManager::instance().setSessionStatus(sessionId, QStringLiteral("failed"));
            }
        }
    });

    // STDERR hook (sanitize too)
    QObject::connect(proc, &QProcess::readyReadStandardError, parent, [proc, sessionId]() {
        const QByteArray chunk = proc->readAllStandardError();
        if (chunk.isEmpty()) return;

        QString cleaned = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(chunk));
        {
            QMutexLocker locker(&g_stateMutex);
            broadcastToSession(sessionId,
                QJsonObject{ {Protocol::F_ACTION, "output"},
                             {"sessionId", sessionId},
                             {"stream", "stderr"},
                             {"data", cleaned} });
        }

        SessionDBManager::instance().insertCommandOutput(sessionId, QString(), cleaned);
    });

    // Exit hook: notify subscribers and clean up session state
    QObject::connect(proc, QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
                     parent, [sessionId](int exitCode, QProcess::ExitStatus exitStatus){
        QMutexLocker locker(&g_stateMutex);

        // Guard: if session was already manually removed, skip cleanup
        if (!g_sessions.contains(sessionId) && !g_subscribers.contains(sessionId)) {
            return;
        }

        QJsonObject msg{ {Protocol::F_ACTION, "session_exited"},
                         {"sessionId", sessionId},
                         {"exitCode", exitCode},
                         {"crashed", exitStatus == QProcess::CrashExit} };
        broadcastToSession(sessionId, msg);

        // Reflect dead-process state in the DB so a table refresh doesn't lie.
        SessionDBManager::instance().setSessionAlive(sessionId, false);

        // Clean up subscribers - session is dead, no further messages will come
        g_subscribers.remove(sessionId);
        g_activeCmdId.remove(sessionId);
        g_cmdStartTime.remove(sessionId);
        g_stdoutBuf.remove(sessionId);
        g_cmdQueue.remove(sessionId);
        g_pendingReinject.remove(sessionId);
        g_earlyOutput.remove(sessionId);

        if (exitStatus == QProcess::CrashExit) {
            qWarning() << "[Server] PowerShell process crashed for session:" << sessionId;
        }
    });

    return proc;
}

// ================= Server =================

Server::Server(const QString &bindIp,
               quint16 port,
               const QString &user,
               const QString &pass,
               QObject *parent)
    : QObject(parent),
      bindIp_(bindIp),
      port_(port),
      allowedUser_(user),
      allowedPass_(pass) {}

bool Server::start() {
    if (!SessionDBManager::instance().initMainDB()) {
        emit log("[-] Sessions DB init failed (continuing with volatile memory only).");
    }
    connect(&tcp_, &QTcpServer::newConnection, this, &Server::onNewConnection);
    if (!tcp_.listen(QHostAddress(bindIp_), port_)) {
        emit log(QString("[-] Failed to listen on %1:%2").arg(bindIp_).arg(port_));
        return false;
    }
    emit log(QString("[+] Listening on %1:%2").arg(bindIp_).arg(port_));
    return true;
}

void Server::setLoginCredential(const QString &user, const QString &pass) {
    allowedUser_ = user;
    allowedPass_ = pass;
}

void Server::onNewConnection() {
    while (tcp_.hasPendingConnections()) {
        QTcpSocket *s = tcp_.nextPendingConnection();
        clients_.insert(s);
        emit log(QString("[*] Client connected: %1:%2")
                     .arg(s->peerAddress().toString())
                     .arg(s->peerPort()));
        connect(s, &QTcpSocket::readyRead,     this, &Server::onClientReady);
        connect(s, &QTcpSocket::disconnected,  this, &Server::onClientDisconnected);
    }
}

void Server::onClientReady() {
    QTcpSocket *s = qobject_cast<QTcpSocket *>(sender());
    if (!s) return;
    while (s->canReadLine()) {
        const QByteArray line = s->readLine().trimmed();
        if (!handleLine(s, line)) {
            s->write(Protocol::toBytes(Protocol::err("Malformed request")));
        }
    }
}

void Server::onClientDisconnected() {
    QTcpSocket *s = qobject_cast<QTcpSocket *>(sender());
    if (!s) return;
    {
        QMutexLocker locker(&g_stateMutex);
        for (auto it = g_subscribers.begin(); it != g_subscribers.end(); ++it)
            it.value().remove(s);
    }
    clients_.remove(s);
    authed_.remove(s);
    const QString op = operatorBySocket_.take(s);
    s->deleteLater();
    emit log(op.isEmpty() ? QStringLiteral("[*] Client disconnected")
                          : QString("[*] Operator '%1' disconnected").arg(op));
}

bool Server::handleLine(QTcpSocket *sock, const QByteArray &line) {
    QJsonParseError pe;
    QJsonDocument d = QJsonDocument::fromJson(line, &pe);
    if (pe.error != QJsonParseError::NoError || !d.isObject()) {
        qWarning() << "[Server] JSON parse error from"
                   << sock->peerAddress().toString() << ":"
                   << pe.errorString() << "at offset" << pe.offset;
        return false;
    }

    const QJsonObject obj = d.object();
    const QString action  = obj.value(Protocol::F_ACTION).toString();

    if (action == Protocol::ACTION_LOGIN) {
        return handleLogin(sock, obj);
    }

    if (!authed_.contains(sock)) {
        sendTo(sock, Protocol::err("Not authenticated"));
        return true;
    }

    // ── Create session (credentials or raw) ────────────────────────────────────
    if (action == Protocol::ACTION_NEW_SESSION) {
        const QString mode     = obj.value("mode").toString();
        const QString resource = obj.value("resource").toString(APP_CONFIG.defaultClientId().isEmpty()
            ? QStringLiteral("https://management.azure.com") : QStringLiteral("https://management.azure.com"));
        QString sid            = obj.value("sessionId").toString().trimmed();
        if (sid.isEmpty()) sid = QUuid::createUuid().toString(QUuid::WithoutBraces);
        const QString rid      = obj.value("rid").toString();

        // Validate session ID format (UUID or alphanumeric, max 64 chars)
        static const QRegularExpression sessionIdRe(
            QStringLiteral("^[a-zA-Z0-9_\\-]{1,64}$"));
        if (!sessionIdRe.match(sid).hasMatch()) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }

        SessionDBManager::instance().logAudit(
            operatorBySocket_.value(sock, QStringLiteral("unknown")), "new_session", sid, mode);

        // Enforce session count limit
        {
            QMutexLocker locker(&g_stateMutex);
            if (g_sessions.size() >= MAX_SESSIONS) {
                sendTo(sock, Protocol::err(
                    QString("session limit reached (%1 max)").arg(MAX_SESSIONS)));
                return true;
            }
        }

        // Ensure process and subscribe caller
        QProcess *proc = ensureProcess(this, sid, operatorBySocket_.value(sock, QStringLiteral("unknown")));
        if (!proc) {
            sendTo(sock, Protocol::err("failed to start session process"));
            return true;
        }

        QJsonObject meta;
        {
            QMutexLocker locker(&g_stateMutex);
            g_subscribers[sid].insert(sock);

            // In-memory meta + update resource if changed
            meta = g_sessionInfo.value(sid);
            meta.insert("resource", resource);
            g_sessionInfo.insert(sid, meta);
        }

        // Persist resource via SessionDBManager (best-effort)
        SessionDBManager::instance().initMainDB();
        if (auto db = SessionDBManager::instance().mainDb(); db.isOpen()) {
            QSqlQuery uq(db);
            uq.prepare("UPDATE sessions SET Resource=? WHERE SessionID=?");
            uq.addBindValue(resource);
            uq.addBindValue(sid);
            uq.exec();
        }

        // Per-session DB (idempotent)
        SessionDBManager::instance().createSessionDB(sid);

        // Immediately tell this subscriber the session process is alive
        sendTo(sock, QJsonObject{
            {Protocol::F_ACTION, "session_open"},
            {"sessionId", sid},
            {"alive", true}
        });

        // "credentials" flow
        if (mode == QStringLiteral("credentials")) {
            const QString user = obj.value("username").toString().trimmed();
            const QString pass = obj.value("password").toString();

            if (user.isEmpty() || pass.isEmpty()) {
                sendTo(sock, Protocol::err("username/password required"));
                return true;
            }

            // GRAPH - Connect-MgGraph (no module checks, emit markers)
            if (resource.contains("graph.microsoft.com", Qt::CaseInsensitive)) {
                // Load script from Qt resources
                QByteArray script = loadScript(":/scripts/login_graph.ps1");
                if (script.isEmpty()) {
                    sendTo(sock, Protocol::err("failed to load Graph login script"));
                    return true;
                }

                QString appDir = QCoreApplication::applicationDirPath();
                QDir().mkpath(QString("%1/data/sessions/%2").arg(appDir, sid));
                const QString ps1Path = QString("%1/data/sessions/%2/login.ps1").arg(appDir, sid);

                QFile f(ps1Path);
                if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                    sendTo(sock, Protocol::err("failed to create login script"));
                    return true;
                }
                f.write(script);
                f.close();

                if (!rid.isEmpty()) {
                    QMutexLocker locker(&g_stateMutex);
                    g_loginRid.insert(sid, rid);
                }

                // Use single quotes with proper escaping to prevent command injection
                QString execCmd = QString(". \"%1\" -Username '%2' -Password '%3'\n")
                    .arg(ps1Path, escapePsString(user), escapePsString(pass));
                proc->write(execCmd.toUtf8());

                QJsonObject ack = Protocol::ok("new_session ok");
                ack.insert("sessionId", sid);
                sendTo(sock, ack);
                return true;
            }

            // AZURE MANAGEMENT (Az) - Connect-AzAccount (no module checks)
            // Load script from Qt resources
            QByteArray script = loadScript(":/scripts/login_azure.ps1");
            if (script.isEmpty()) {
                sendTo(sock, Protocol::err("failed to load Azure login script"));
                return true;
            }

            QString appDir = QCoreApplication::applicationDirPath();
            QDir().mkpath(QString("%1/data/sessions/%2").arg(appDir, sid));
            const QString ps1Path = QString("%1/data/sessions/%2/login.ps1").arg(appDir, sid);

            QFile f(ps1Path);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                sendTo(sock, Protocol::err("failed to create login script"));
                return true;
            }
            f.write(script);
            f.close();

            if (!rid.isEmpty()) {
                QMutexLocker locker(&g_stateMutex);
                g_loginRid.insert(sid, rid);
            }

            // Use single quotes with proper escaping to prevent command injection
            QString execCmd = QString(". \"%1\" -Username '%2' -Password '%3'\n")
                .arg(ps1Path, escapePsString(user), escapePsString(pass));
            proc->write(execCmd.toUtf8());

            QJsonObject ack = Protocol::ok("new_session ok");
            ack.insert("sessionId", sid);
            sendTo(sock, ack);
            return true;
        }

        // --- FULL SESSION via DEVICE CODE (Connect-AzAccount -UseDeviceAuthentication) ---
        // Interactive device-code login run INSIDE Az, so the context keeps a real token
        // cache + refresh token. Data-plane cmdlets (Get-AzKeyVaultSecret, storage, etc.)
        // then work natively - unlike -AccessToken sessions. No username/password needed.
        if (mode == QStringLiteral("az_devicecode")) {
            QByteArray script = loadScript(":/scripts/login_azure_devicecode.ps1");
            if (script.isEmpty()) {
                sendTo(sock, Protocol::err("failed to load device-code login script"));
                return true;
            }

            QString appDir = QCoreApplication::applicationDirPath();
            QDir().mkpath(QString("%1/data/sessions/%2").arg(appDir, sid));
            const QString ps1Path = QString("%1/data/sessions/%2/login.ps1").arg(appDir, sid);

            QFile f(ps1Path);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                sendTo(sock, Protocol::err("failed to create login script"));
                return true;
            }
            f.write(script);
            f.close();

            if (!rid.isEmpty()) {
                QMutexLocker locker(&g_stateMutex);
                g_loginRid.insert(sid, rid);
            }

            // No credentials to pass - the device-code prompt streams to the Session Tab.
            QString execCmd = QString(". \"%1\"\n").arg(ps1Path);
            proc->write(execCmd.toUtf8());

            QJsonObject ack = Protocol::ok("new_session ok");
            ack.insert("sessionId", sid);
            sendTo(sock, ack);
            return true;
        }

        // --- SPN (Service Principal) FLOW ---
        if (mode == QStringLiteral("spn")) {
            const QString appId        = obj.value("appId").toString().trimmed();
            const QString clientSecret = obj.value("clientSecret").toString();
            const QString tenantId     = obj.value("tenantId").toString().trimmed();

            if (appId.isEmpty() || clientSecret.isEmpty() || tenantId.isEmpty()) {
                sendTo(sock, Protocol::err("appId, clientSecret, and tenantId required"));
                return true;
            }

            QByteArray script = loadScript(":/scripts/login_spn_azure.ps1");
            if (script.isEmpty()) {
                sendTo(sock, Protocol::err("failed to load SPN login script"));
                return true;
            }

            QString appDir = QCoreApplication::applicationDirPath();
            QDir().mkpath(QString("%1/data/sessions/%2").arg(appDir, sid));
            const QString ps1Path = QString("%1/data/sessions/%2/login.ps1").arg(appDir, sid);

            QFile f(ps1Path);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                sendTo(sock, Protocol::err("failed to create login script"));
                return true;
            }
            f.write(script);
            f.close();

            // Write credentials to a separate file to avoid exposing secret in process list
            const QString credPath = QString("%1/data/sessions/%2/spn_cred.json").arg(appDir, sid);
            QFile credFile(credPath);
            if (!credFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                sendTo(sock, Protocol::err("failed to create credentials file"));
                return true;
            }
            QJsonObject credObj;
            credObj.insert("appId", appId);
            credObj.insert("clientSecret", clientSecret);
            credObj.insert("tenantId", tenantId);
            credFile.write(QJsonDocument(credObj).toJson(QJsonDocument::Compact));
            credFile.close();

            if (!rid.isEmpty()) {
                QMutexLocker locker(&g_stateMutex);
                g_loginRid.insert(sid, rid);
            }

            // Stash SPN identity in g_sessionInfo BEFORE the login script runs.
            // The __ANIMO_LOGIN_OK__ handler is generic and would otherwise
            // derive tenant/domain from the UPN's @suffix - which for SPNs is
            // just the AppId with no '@' - giving "N/A". Preserving these here
            // means the sessions table shows the real tenant GUID.
            {
                QMutexLocker locker(&g_stateMutex);
                QJsonObject spnMeta = g_sessionInfo.value(sid);
                spnMeta.insert("user",     appId);
                spnMeta.insert("tenantId", tenantId);
                spnMeta.insert("domain",   QStringLiteral("ServicePrincipal"));
                spnMeta.insert("resource", QStringLiteral("https://management.azure.com"));
                g_sessionInfo.insert(sid, spnMeta);
            }
            SessionDBManager::instance().updateSessionUser(sid, appId);
            SessionDBManager::instance().updateSessionTenant(sid, tenantId, QStringLiteral("ServicePrincipal"));

            // Pass only the credential file path, not the secret itself
            QString execCmd = QString(". \"%1\" -CredentialFile \"%2\"\n")
                .arg(ps1Path, credPath);
            proc->write(execCmd.toUtf8());

            // The script deletes this after reading, but wipe it here too in case
            // pwsh never starts and the plaintext secret is left on disk.
            QTimer::singleShot(15000, this, [credPath]() {
                if (QFile::exists(credPath)) {
                    QFile::remove(credPath);
                }
            });

            QJsonObject ack = Protocol::ok("new_session ok");
            ack.insert("sessionId", sid);
            sendTo(sock, ack);
            return true;
        }

        // --- TOKENS FLOW ---
        if (mode == QStringLiteral("tokens")) {
            const QString access = obj.value("accessToken").toString();
            const QString refresh= obj.value("refreshToken").toString();
            QString user        = obj.value("user").toString().trimmed();
            QString tenantId    = obj.value("tenantId").toString().trimmed();
            QString domain      = obj.value("domain").toString().trimmed();

            if (access.isEmpty()) {
                qWarning() << "[Server] Token login failed: no access token";
                sendTo(sock, Protocol::err("accessToken required"));
                return true;
            }

            // Best-effort fill-ins if client didn't send them
            auto jwtField = [&](const QString &field)->QString {
                const QStringList parts = access.split('.');
                if (parts.size() < 2) return QString();
                QByteArray payload = parts.at(1).toUtf8();
                int pad = (4 - (payload.size() % 4)) % 4;
                payload.append(QByteArray(pad, '='));
                QByteArray decoded = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);
                if (decoded.isEmpty()) return QString();  // Base64 decode failed
                QJsonParseError parseError;
                QJsonDocument doc = QJsonDocument::fromJson(decoded, &parseError);
                if (parseError.error != QJsonParseError::NoError || !doc.isObject()) return QString();
                return doc.object().value(field).toString();
            };
            if (tenantId.isEmpty()) tenantId = jwtField("tid");
            if (user.isEmpty())     user     = jwtField("upn");
            if (domain.isEmpty())   domain   = (user.contains('@') ? user.section('@',1,1) : QStringLiteral("N/A"));

            // Persist canonical metadata early
            QJsonObject meta2;
            {
                QMutexLocker locker(&g_stateMutex);
                // CRITICAL: Register socket as subscriber so session_created reaches the client
                g_subscribers[sid].insert(sock);

                meta2 = g_sessionInfo.value(sid);
                meta2.insert("user",     user.isEmpty() ? QStringLiteral("Unknown") : user);
                meta2.insert("tenantId", tenantId.isEmpty() ? QStringLiteral("N/A") : tenantId);
                meta2.insert("domain",   domain.isEmpty() ? QStringLiteral("N/A") : domain);
                meta2.insert("resource", resource);
                g_sessionInfo.insert(sid, meta2);
                if (!rid.isEmpty()) g_loginRid.insert(sid, rid);
            }

            SessionDBManager::instance().initMainDB();
            SessionDBManager::instance().addSessionToMainDB(sid,
                meta2.value("user").toString("Unknown"),
                meta2.value("tenantId").toString("N/A"),
                meta2.value("domain").toString("N/A"),
                resource,
                operatorBySocket_.value(sock, QStringLiteral("unknown")));

            // Prepare a PS fragment that will emit markers understood by stdout hook
            auto emitOk = [&](const QString &upn)->QByteArray {
                return QString("Write-Output ('__ANIMO_LOGIN_OK__:%1')\n")
                    .arg(escapePsString(upn.isEmpty() ? QStringLiteral("Unknown") : upn)).toUtf8();
            };
            // emitFail now includes error message: __ANIMO_LOGIN_FAIL__:error_message
            auto emitFailWithMsg = [](const QString &errVar)->QByteArray {
                return QString("Write-Output \"__ANIMO_LOGIN_FAIL__:$%1\"\n").arg(errVar).toUtf8();
            };
            auto emitFail = []()->QByteArray {
                return QByteArray("Write-Output \"__ANIMO_LOGIN_FAIL__:Unknown error\"\n");
            };

            QByteArray ps;

            if (resource.contains("graph.microsoft.com", Qt::CaseInsensitive)) {
                // Graph: try SecureString (v2.x) then plain string (v1.x)
                ps.append("$t=@'\n"); ps.append(access.toUtf8()); ps.append("\n'@\n");
                ps.append("$e='Unknown'\n");
                ps.append("try{Connect-MgGraph -NoWelcome -AccessToken(ConvertTo-SecureString $t -AsPlainText -Force)|Out-Null;");
                ps.append(emitOk(user)); ps.append("return}catch{$e=$_.Exception.Message}\n");
                ps.append("try{Connect-MgGraph -NoWelcome -AccessToken $t|Out-Null;");
                ps.append(emitOk(user)); ps.append("return}catch{$e=$_.Exception.Message}\n");
                ps.append(emitFailWithMsg("e"));
            } else {
                // -- Az: need both Az access and a Graph token for Connect-AzAccount
                if (refresh.isEmpty()) {
                    // Access-token-only session (no refresh token, e.g. an SPN access
                    // token). We cannot mint other audiences - use the single token as-is.
                    if (resource.contains("management.azure.com", Qt::CaseInsensitive)) {
                        // Inert ARM context so Az cmdlets work with this token.
                        ps.append("$a=@\"\n"); ps.append(access.toUtf8()); ps.append("\n\"@\n");
                        ps.append("try{Connect-AzAccount -AccessToken $a ");
                        if (!user.isEmpty())     ps.append(QString("-AccountId '%1' ").arg(escapePsString(user)).toUtf8());
                        if (!tenantId.isEmpty()) ps.append(QString("-TenantId '%1' ").arg(escapePsString(tenantId)).toUtf8());
                        ps.append("-WA Ignore|Out-Null}catch{}\n");
                        ps.append("$ctx=Get-AzContext -EA SilentlyContinue\n");
                        ps.append("if($ctx-and$ctx.Account){"); ps.append(emitOk(user));
                        ps.append("}else{"); ps.append(emitFail()); ps.append("}\n");
                    } else {
                        // Key Vault / Storage / SQL are client-REST modules - no Az context
                        // needed, so just confirm the session (client stores the token).
                        ps.append(emitOk(user));
                    }
                } else {

                // Exchange refresh -> Graph token (server-side) to keep PS simple
                QNetworkAccessManager nam;
                QUrl turl(QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(
                            tenantId.isEmpty() ? QStringLiteral("organizations") : tenantId));
                QNetworkRequest treq(turl);
                treq.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
                QUrlQuery form;
                form.addQueryItem("client_id",  APP_CONFIG.defaultClientId());
                form.addQueryItem("grant_type", "refresh_token");
                form.addQueryItem("refresh_token", refresh);
                form.addQueryItem("scope", "https://graph.microsoft.com/.default");
                QEventLoop loop;
                QNetworkReply *rep = nam.post(treq, form.query(QUrl::FullyEncoded).toUtf8());
                QObject::connect(rep, &QNetworkReply::finished, &loop, &QEventLoop::quit);
                loop.exec();
                QString mgToken;
                if (rep->error() == QNetworkReply::NoError) {
                    mgToken = QJsonDocument::fromJson(rep->readAll()).object().value("access_token").toString();
                }
                rep->deleteLater();

                if (mgToken.isEmpty()) {
                    qWarning() << "[Server] Az login failed: could not obtain Graph token";
                    sendTo(sock, Protocol::err("failed to obtain Microsoft Graph token from refresh_token"));
                    return true;
                }

                // Also exchange refresh -> storage token so -UseConnectedAccount
                // isn't needed (access-token sessions have no token cache).
                QString storageToken;
                {
                    QUrl surl(QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(
                                tenantId.isEmpty() ? QStringLiteral("organizations") : tenantId));
                    QNetworkRequest sreq(surl);
                    sreq.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
                    QUrlQuery sform;
                    sform.addQueryItem("client_id",  APP_CONFIG.defaultClientId());
                    sform.addQueryItem("grant_type", "refresh_token");
                    sform.addQueryItem("refresh_token", refresh);
                    sform.addQueryItem("scope", "https://storage.azure.com/.default");
                    QEventLoop sloop;
                    QNetworkReply *srep = nam.post(sreq, sform.query(QUrl::FullyEncoded).toUtf8());
                    QObject::connect(srep, &QNetworkReply::finished, &sloop, &QEventLoop::quit);
                    sloop.exec();
                    if (srep->error() == QNetworkReply::NoError)
                        storageToken = QJsonDocument::fromJson(srep->readAll()).object().value("access_token").toString();
                    srep->deleteLater();
                }

                // Also exchange refresh -> KeyVault token and inject it as
                // -KeyVaultAccessToken so data-plane cmdlets (Get-AzKeyVaultSecret)
                // work in the terminal without a device-code login / token cache.
                QString keyVaultToken;
                {
                    QUrl kurl(QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(
                                tenantId.isEmpty() ? QStringLiteral("organizations") : tenantId));
                    QNetworkRequest kreq(kurl);
                    kreq.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
                    QUrlQuery kform;
                    kform.addQueryItem("client_id",  APP_CONFIG.defaultClientId());
                    kform.addQueryItem("grant_type", "refresh_token");
                    kform.addQueryItem("refresh_token", refresh);
                    kform.addQueryItem("scope", "https://vault.azure.net/.default");
                    QEventLoop kloop;
                    QNetworkReply *krep = nam.post(kreq, kform.query(QUrl::FullyEncoded).toUtf8());
                    QObject::connect(krep, &QNetworkReply::finished, &kloop, &QEventLoop::quit);
                    kloop.exec();
                    if (krep->error() == QNetworkReply::NoError)
                        keyVaultToken = QJsonDocument::fromJson(krep->readAll()).object().value("access_token").toString();
                    krep->deleteLater();
                }

                // Az: Connect with both access and graph tokens
                ps.append("$a=@\"\n"); ps.append(access.toUtf8()); ps.append("\n\"@\n");
                ps.append("$g=@\"\n"); ps.append(mgToken.toUtf8()); ps.append("\n\"@\n");
                if (!keyVaultToken.isEmpty()) {
                    ps.append("$kv=@\"\n"); ps.append(keyVaultToken.toUtf8()); ps.append("\n\"@\n");
                }
                ps.append("try{Connect-AzAccount -AccessToken $a -MicrosoftGraphAccessToken $g ");
                if (!keyVaultToken.isEmpty()) ps.append("-KeyVaultAccessToken $kv ");
                if (!user.isEmpty())     ps.append(QString("-AccountId '%1' ").arg(escapePsString(user)).toUtf8());
                if (!tenantId.isEmpty()) ps.append(QString("-TenantId '%1' ").arg(escapePsString(tenantId)).toUtf8());
                ps.append("-WA Ignore|Out-Null\n");
                // Also connect Microsoft.Graph with the same Graph token so Get-Mg*
                // cmdlets work in the terminal (Connect-AzAccount's -MicrosoftGraphAccessToken
                // only feeds Az's internal Graph calls, not the Mg module). Best-effort.
                ps.append("try{Connect-MgGraph -NoWelcome -AccessToken(ConvertTo-SecureString $g -AsPlainText -Force)|Out-Null}catch{try{Connect-MgGraph -NoWelcome -AccessToken $g|Out-Null}catch{}}\n");
                // Store storage token for the session_created event
                if (!storageToken.isEmpty()) {
                    QMutexLocker locker(&g_stateMutex);
                    g_sessionInfo[sid].insert("storageToken", storageToken);
                }
                // Tag this as an inert access-token Az session so token re-injection
                // (WS5 renewal) is allowed - full/live sessions must NOT be re-injected
                // (it would downgrade them to AccessToken and break silent minting).
                {
                    QMutexLocker locker(&g_stateMutex);
                    g_sessionInfo[sid].insert("azInjected", true);
                }

                // WS3: Storage data-plane cannot be injected into the Az context (no
                // -StorageAccessToken param), so expose REST helpers that use the
                // minted storage token directly: Get-AnimoStorageContainer/Blob/Content.
                if (!storageToken.isEmpty()) {
                    ps.append("$st=@\"\n"); ps.append(storageToken.toUtf8()); ps.append("\n\"@\n");
                    ps.append("$global:AnimoStorageToken=$st\n");
                    ps.append(
                        "function global:Get-AnimoStorageContainer{param([Parameter(Mandatory)][string]$Account)"
                        "$h=@{Authorization=\"Bearer $global:AnimoStorageToken\";'x-ms-version'='2021-08-06'};"
                        "(Invoke-RestMethod -Uri \"https://$Account.blob.core.windows.net/?comp=list\" -Headers $h)."
                        "EnumerationResults.Containers.Container|Select-Object Name}\n");
                    ps.append(
                        "function global:Get-AnimoStorageBlob{param([Parameter(Mandatory)][string]$Account,[Parameter(Mandatory)][string]$Container)"
                        "$h=@{Authorization=\"Bearer $global:AnimoStorageToken\";'x-ms-version'='2021-08-06'};"
                        "(Invoke-RestMethod -Uri \"https://$Account.blob.core.windows.net/$Container`?restype=container&comp=list\" -Headers $h)."
                        "EnumerationResults.Blobs.Blob|Select-Object Name,@{n='Size';e={$_.Properties.'Content-Length'}}}\n");
                    ps.append(
                        "function global:Get-AnimoBlobContent{param([Parameter(Mandatory)][string]$Account,[Parameter(Mandatory)][string]$Container,[Parameter(Mandatory)][string]$Blob)"
                        "$h=@{Authorization=\"Bearer $global:AnimoStorageToken\";'x-ms-version'='2021-08-06'};"
                        "Invoke-RestMethod -Uri \"https://$Account.blob.core.windows.net/$Container/$Blob\" -Headers $h}\n");
                }
                ps.append("$ctx=Get-AzContext -EA SilentlyContinue\n");
                ps.append("if($ctx-and$ctx.Account){Write-Output \"__ANIMO_LOGIN_OK__:$($ctx.Account)\"}");
                ps.append("else{"); ps.append(emitFail()); ps.append("}}catch{"); ps.append(emitFail()); ps.append("}\n");
                }   // end refresh-based Az path
            }

            // Write script directly to stdin (more reliable than sourcing file)
            proc->write(ps);
            proc->write("\n");

            qInfo() << "[Server] Token-based session requested:" << sid
                    << "| User:" << (user.isEmpty() ? "Unknown" : user)
                    << "| Tenant:" << (tenantId.isEmpty() ? "N/A" : tenantId)
                    << "| Resource:" << resource;

            // Immediate ack; final result comes via markers
            QJsonObject ack2 = Protocol::ok("new_session ok");
            ack2.insert("sessionId", sid);
            sendTo(sock, ack2);
            return true;
        }

        // Raw session creation / attach
        QJsonObject ack = Protocol::ok("new_session ok");
        ack.insert("sessionId", sid);
        sendTo(sock, ack);
        return true;
    }

    // ── Run command ────────────────────────────────────────────────────────────
    if (action == Protocol::ACTION_RUN_COMMAND) {
        const QString sid = obj.value("sessionId").toString().trimmed();
        const QString cmd = obj.value("command").toString();
        QString cmdId = obj.value(Protocol::F_CMD_ID).toString().trimmed();
        if (cmdId.isEmpty()) {
            cmdId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        }

        if (sid.isEmpty() || cmd.isEmpty()) {
            sendTo(sock, Protocol::err("missing sessionId or command"));
            return true;
        }
        if (!isValidSessionId(sid)) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }

        // Validate command length to prevent memory exhaustion
        if (cmd.size() > MAX_CMD_LENGTH) {
            sendTo(sock, Protocol::err(
                QString("command too long (%1 bytes, max %2)")
                    .arg(cmd.size()).arg(MAX_CMD_LENGTH)));
            return true;
        }
        QProcess *proc = ensureProcess(this, sid, operatorBySocket_.value(sock, QStringLiteral("unknown")));
        if (!proc) {
            sendTo(sock, Protocol::err("session not available"));
            return true;
        }

        {
            QMutexLocker locker(&g_stateMutex);
            g_subscribers[sid].insert(sock);

            if (g_authState.value(sid, AuthState::Pending) == AuthState::Pending) {
                g_authState[sid] = AuthState::Success;
            }

            // If a command is already running, queue this one. It is dispatched when the
            // active command completes (see the command_complete path in the stdout hook).
            if (g_activeCmdId.contains(sid)) {
                qint64 now = QDateTime::currentMSecsSinceEpoch();
                qint64 started = g_cmdStartTime.value(sid, 0);
                if (now - started < CMD_TIMEOUT_MS) {
                    if (g_cmdQueue.value(sid).size() >= MAX_CMD_QUEUE) {
                        sendTo(sock, Protocol::err("command queue full, please wait"));
                        return true;
                    }
                    g_cmdQueue[sid].append(QueuedCommand{cmdId, cmd,
                        operatorBySocket_.value(sock, QStringLiteral("unknown"))});
                    broadcastToSession(sid,
                        QJsonObject{ {Protocol::F_ACTION, "command_queued"},
                                     {"sessionId", sid}, {Protocol::F_CMD_ID, cmdId},
                                     {"command", cmd} });
                    QJsonObject qack = Protocol::ok("command queued");
                    qack.insert(Protocol::F_CMD_ID, cmdId);
                    sendTo(sock, qack);
                    return true;
                }
                // Timeout - clear stale command state AND discard any orphaned output
                // from the abandoned command so it can't contaminate this one.
                g_activeCmdId.remove(sid);
                g_cmdStartTime.remove(sid);
                g_stdoutBuf.remove(sid);
            }

            dispatchCommand(sid, cmdId, cmd, operatorBySocket_.value(sock, QStringLiteral("unknown")));
        }

        SessionDBManager::instance().logAudit(
            operatorBySocket_.value(sock, QStringLiteral("unknown")), "run_command", sid, cmd.left(200));

        QJsonObject ack = Protocol::ok("command accepted");
        ack.insert(Protocol::F_CMD_ID, cmdId);
        sendTo(sock, ack);
        return true;
    }

    // ── List sessions (main DB) ────────────────────────────────────────────────
    if (action == Protocol::ACTION_LIST) {
        SessionDBManager::instance().initMainDB();
        QSqlDatabase db = SessionDBManager::instance().mainDb();

        QJsonArray arr;
        if (db.isOpen()) {
            QSqlQuery q(db);
            q.prepare("SELECT SessionID, User, TenantID, DefaultDomain, Resource, CreatedBy "
                      "FROM sessions ORDER BY CreatedAt DESC");
            if (q.exec()) {
                while (q.next()) {
                    const QString sid = q.value(0).toString();

                    QJsonObject row;
                    row.insert("sessionId", sid);
                    row.insert("user",      q.value(1).toString());
                    row.insert("tenantId",  q.value(2).toString());
                    row.insert("domain",    q.value(3).toString());
                    row.insert("resource",  q.value(4).toString());
                    row.insert("createdBy", q.value(5).toString());

                    {
                        QMutexLocker locker(&g_stateMutex);
                        const bool alive = g_sessions.contains(sid) && g_sessions.value(sid) &&
                                           g_sessions.value(sid)->state() == QProcess::Running;
                        row.insert("alive", alive);

                        const AuthState st = g_authState.value(sid, AuthState::Pending);
                        const QString status = (st == AuthState::Success) ? "success" :
                                               (st == AuthState::Failed ) ? "failed"  : "pending";
                        row.insert("status", status);
                    }

                    arr.append(row);
                }
            }
        }

        QJsonObject resp = Protocol::ok("list ok");
        resp.insert("data", arr);
        resp.insert("count", arr.size());
        sendTo(sock, resp);
        return true;
    }

    // ── Re-inject fresh per-audience tokens into an inert Az session (WS5) ───────
    // Keeps the terminal's Az/Mg context alive past the ~1h token expiry. Silently
    // ignored for full/live sessions (would downgrade them to AccessToken).
    if (action == QStringLiteral("reinject_tokens")) {
        const QString sid = obj.value("sessionId").toString().trimmed();
        if (!isValidSessionId(sid)) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }
        bool injected = false;
        {
            QMutexLocker locker(&g_stateMutex);
            injected = g_sessionInfo.value(sid).value("azInjected").toBool();
        }
        QProcess *proc = g_sessions.value(sid, nullptr);
        if (!proc || !injected) {
            // Not an inert Az session (or gone) - no-op, ack so the client moves on.
            sendTo(sock, Protocol::ok("reinject skipped"));
            return true;
        }
        const QString access  = obj.value("accessToken").toString();
        const QString graph   = obj.value("graphToken").toString();
        const QString keyVault= obj.value("keyVaultToken").toString();
        const QString user    = obj.value("user").toString();
        const QString tenant  = obj.value("tenantId").toString();
        if (access.isEmpty()) {
            sendTo(sock, Protocol::err("reinject requires accessToken"));
            return true;
        }

        QByteArray ps;
        ps.append("$a=@\"\n"); ps.append(access.toUtf8()); ps.append("\n\"@\n");
        if (!graph.isEmpty())    { ps.append("$g=@\"\n");  ps.append(graph.toUtf8());    ps.append("\n\"@\n"); }
        if (!keyVault.isEmpty()) { ps.append("$kv=@\"\n"); ps.append(keyVault.toUtf8()); ps.append("\n\"@\n"); }
        ps.append("try{Connect-AzAccount -AccessToken $a ");
        if (!graph.isEmpty())    ps.append("-MicrosoftGraphAccessToken $g ");
        if (!keyVault.isEmpty()) ps.append("-KeyVaultAccessToken $kv ");
        if (!user.isEmpty())     ps.append(QString("-AccountId '%1' ").arg(escapePsString(user)).toUtf8());
        if (!tenant.isEmpty())   ps.append(QString("-TenantId '%1' ").arg(escapePsString(tenant)).toUtf8());
        ps.append("-WA Ignore|Out-Null}catch{}\n");
        if (!graph.isEmpty())
            ps.append("try{Connect-MgGraph -NoWelcome -AccessToken(ConvertTo-SecureString $g -AsPlainText -Force)|Out-Null}catch{}\n");

        // Never write into the terminal while a command is running - it would
        // interleave with that command's output stream. Queue the payload; the
        // command_complete path flushes it as soon as the command finishes so
        // the terminal's Az context is refreshed with no operator involvement.
        if (g_activeCmdId.contains(sid)) {
            {
                QMutexLocker locker(&g_stateMutex);
                g_pendingReinject.insert(sid, ps);  // overwrites older pending payload
            }
            sendTo(sock, Protocol::ok("reinject queued (busy - will apply on command complete)"));
            return true;
        }

        proc->write(ps);
        sendTo(sock, Protocol::ok("reinject ok"));
        return true;
    }

    // ── Get session info (+ ensure proc, subscribe) ────────────────────────────
    if (action == QStringLiteral("get_session")) {
        const QString sid = obj.value("sessionId").toString().trimmed();
        if (sid.isEmpty()) {
            sendTo(sock, Protocol::err("missing sessionId"));
            return true;
        }
        if (!isValidSessionId(sid)) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }

        // Ensure process exists/starts and subscribe caller
        QProcess *proc = ensureProcess(this, sid, operatorBySocket_.value(sock, QStringLiteral("unknown")));
        if (!proc) {
            sendTo(sock, Protocol::err("failed to ensure session process"));
            return true;
        }
        QByteArray earlyToReplay;
        {
            QMutexLocker locker(&g_stateMutex);
            g_subscribers[sid].insert(sock);
            // First subscriber to see this session -> replay any pre-login
            // stdout that arrived before the tab existed. This is where the
            // SPN login-script's [Animo] subscription list finally reaches
            // the user's terminal.
            earlyToReplay = g_earlyOutput.take(sid);
        }
        if (!earlyToReplay.isEmpty()) {
            sendTo(sock, QJsonObject{
                {Protocol::F_ACTION, "output"},
                {"sessionId", sid},
                {"stream", "stdout"},
                {"data", QString::fromUtf8(earlyToReplay)}
            });
        }

        // Pull canonical info from main DB
        SessionDBManager::instance().initMainDB();
        QSqlDatabase db = SessionDBManager::instance().mainDb();

        QJsonObject info;
        if (db.isOpen()) {
            QSqlQuery q(db);
            q.prepare("SELECT SessionID, User, TenantID, DefaultDomain, Resource "
                      "FROM sessions WHERE SessionID=? LIMIT 1");
            q.addBindValue(sid);
            if (q.exec() && q.next()) {
                info.insert("sessionId", q.value(0).toString());
                info.insert("user",      q.value(1).toString());
                info.insert("tenantId",  q.value(2).toString());
                info.insert("domain",    q.value(3).toString());
                info.insert("resource",  q.value(4).toString());
            } else {
                sendTo(sock, Protocol::err(QString("no such session: %1").arg(sid)));
                return true;
            }
        }

        // Merge live fields
        info.insert("alive", proc->state() == QProcess::Running);
        {
            QMutexLocker locker(&g_stateMutex);
            const AuthState st = g_authState.value(sid, AuthState::Pending);
            const QString status = (st == AuthState::Success) ? "success" :
                                   (st == AuthState::Failed ) ? "failed"  : "pending";
            info.insert("status", status);
        }

        // Reply
        QJsonObject resp = Protocol::ok("session_info");
        resp.insert("data", info);
        sendTo(sock, resp);
        return true;
    }

    // ── Remove session ─────────────────────────────────────────────────────
    if (action == Protocol::ACTION_REMOVE) {
        const QString sid = obj.value("sessionId").toString().trimmed();
        if (sid.isEmpty()) {
            sendTo(sock, Protocol::err("missing sessionId"));
            return true;
        }

        // Validate session ID format to prevent path traversal in removeRecursively()
        static const QRegularExpression sessionIdRe(
            QStringLiteral("^[a-zA-Z0-9_\\-]{1,64}$"));
        if (!sessionIdRe.match(sid).hasMatch()) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }

        SessionDBManager::instance().logAudit(
            operatorBySocket_.value(sock, QStringLiteral("unknown")), "remove_session", sid, QString());

        // Kill PS proc and clean global state
        QProcess *procToKill = nullptr;
        {
            QMutexLocker locker(&g_stateMutex);
            if (g_sessions.contains(sid)) {
                procToKill = g_sessions.take(sid);
                // Disconnect finished signal to prevent race with this cleanup
                if (procToKill) {
                    procToKill->disconnect();
                }
            }
            g_subscribers.remove(sid);
            g_sessionInfo.remove(sid);
            g_stdoutBuf.remove(sid);
            g_loginRid.remove(sid);
            g_authState.remove(sid);
            g_lastCommand.remove(sid);
            g_activeCmdId.remove(sid);
            g_cmdStartTime.remove(sid);
            g_pendingToken.remove(sid);
            g_pendingReinject.remove(sid);
            g_earlyOutput.remove(sid);
            g_cmdQueue.remove(sid);
        }
        if (procToKill) {
            procToKill->kill();
            procToKill->deleteLater();
        }

        // Remove from main DB
        SessionDBManager::instance().initMainDB();
        if (auto db = SessionDBManager::instance().mainDb(); db.isOpen()) {
            QSqlQuery q(db);
            q.prepare("DELETE FROM sessions WHERE SessionID=?");
            q.addBindValue(sid);
            q.exec();
        }

        // Delete per-session directory (optional)
        QString appDirDel = QCoreApplication::applicationDirPath();
        QDir perSess(QString("%1/data/sessions/%2").arg(appDirDel, sid));
        if (perSess.exists()) perSess.removeRecursively();

        sendTo(sock, Protocol::ok("remove ok"));
        return true;
    }

    // ── Update session metadata (heal DB rows created before real identity was persisted) ─
    // Client calls this after `list_sessions` if it sees a placeholder row but
    // has better data in its TokenStore (parsed from the JWT). We upsert-style
    // update the DB so the placeholder never comes back on the next list.
    if (action == QStringLiteral("update_session_meta")) {
        const QString sid    = obj.value("sessionId").toString().trimmed();
        const QString user   = obj.value("user").toString().trimmed();
        const QString ten    = obj.value("tenantId").toString().trimmed();
        const QString dom    = obj.value("domain").toString().trimmed();
        if (sid.isEmpty() || !isValidSessionId(sid)) {
            sendTo(sock, Protocol::err("update_session_meta: invalid sessionId"));
            return true;
        }
        auto isPlaceholder = [](const QString &v) {
            return v.isEmpty() || v == QStringLiteral("Unknown") || v == QStringLiteral("N/A");
        };
        if (!isPlaceholder(user)) SessionDBManager::instance().updateSessionUser(sid, user);
        if (!isPlaceholder(ten) || !isPlaceholder(dom)) {
            SessionDBManager::instance().updateSessionTenant(sid,
                isPlaceholder(ten) ? QStringLiteral("N/A") : ten,
                isPlaceholder(dom) ? QStringLiteral("N/A") : dom);
        }
        // Also keep the in-memory copy in sync so subsequent list responses are correct.
        {
            QMutexLocker locker(&g_stateMutex);
            QJsonObject m = g_sessionInfo.value(sid);
            if (!isPlaceholder(user)) m.insert("user", user);
            if (!isPlaceholder(ten))  m.insert("tenantId", ten);
            if (!isPlaceholder(dom))  m.insert("domain", dom);
            g_sessionInfo.insert(sid, m);
        }
        qInfo().noquote() << QString("[Server] healed session %1 metadata (user=%2)")
                                .arg(sid.left(8), user);
        sendTo(sock, Protocol::ok("session meta updated"));
        return true;
    }

    // ── Attach (subscribe) ─────────────────────────────────────────────────────
    if (action == QStringLiteral("attach")) {
        const QString sid = obj.value("sessionId").toString().trimmed();
        if (sid.isEmpty()) {
            sendTo(sock, Protocol::err("missing sessionId"));
            return true;
        }
        if (!isValidSessionId(sid)) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }
        // Ensure process exists and subscribe
        QProcess *proc = ensureProcess(this, sid, operatorBySocket_.value(sock, QStringLiteral("unknown")));
        if (!proc) {
            sendTo(sock, Protocol::err("session not available"));
            return true;
        }
        {
            QMutexLocker locker(&g_stateMutex);
            g_subscribers[sid].insert(sock);
        }

        // Echo back compact session_info (DB + live)
        SessionDBManager::instance().initMainDB();
        QSqlDatabase db = SessionDBManager::instance().mainDb();

        QJsonObject info;
        if (db.isOpen()) {
            QSqlQuery q(db);
            q.prepare("SELECT SessionID, User, TenantID, DefaultDomain, Resource "
                      "FROM sessions WHERE SessionID=? LIMIT 1");
            q.addBindValue(sid);
            if (q.exec() && q.next()) {
                info.insert("sessionId", q.value(0).toString());
                info.insert("user",      q.value(1).toString());
                info.insert("tenantId",  q.value(2).toString());
                info.insert("domain",    q.value(3).toString());
                info.insert("resource",  q.value(4).toString());
            }
        }

        info.insert("alive", proc->state() == QProcess::Running);
        {
            QMutexLocker locker(&g_stateMutex);
            const AuthState st = g_authState.value(sid, AuthState::Pending);
            const QString status = (st == AuthState::Success) ? "success" :
                                   (st == AuthState::Failed ) ? "failed"  : "pending";
            info.insert("status", status);
        }

        QJsonObject resp = Protocol::ok("attach ok");
        resp.insert("data", info);
        sendTo(sock, resp);
        return true;
    }

    // ── Log Token ──────────────────────────────────────────────────────────
    if (action == Protocol::ACTION_LOG_TOKEN) {
        const QString sessionId = obj.value("sessionId").toString();
        const QString source = obj.value("source").toString();
        const QString accessToken = obj.value("accessToken").toString();
        const QString refreshToken = obj.value("refreshToken").toString();
        const QString idToken = obj.value("idToken").toString();
        const QString user = obj.value("user").toString();
        const QString tenantId = obj.value("tenantId").toString();
        const QString resource = obj.value("resource").toString();
        const QString scope = obj.value("scope").toString();
        const int expiresIn = obj.value("expiresIn").toInt();

        if (sessionId.isEmpty() || source.isEmpty() || accessToken.isEmpty()) {
            sendTo(sock, Protocol::err("missing required fields for token logging"));
            return true;
        }
        if (!isValidSessionId(sessionId)) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }

        bool success = SessionDBManager::instance().logToken(
            sessionId, source, accessToken, refreshToken, idToken,
            user, tenantId, resource, scope, expiresIn,
            operatorBySocket_.value(sock, QStringLiteral("unknown"))
        );

        if (success) {
            SessionDBManager::instance().logAudit(
                operatorBySocket_.value(sock, QStringLiteral("unknown")), "capture_token", sessionId, source);
            sendTo(sock, Protocol::ok("token logged"));
            emit log(QString("[+] Token logged: session=%1, source=%2, user=%3")
                     .arg(sessionId, source, user.isEmpty() ? "N/A" : user));
        } else {
            sendTo(sock, Protocol::err("failed to log token"));
        }
        return true;
    }

    // ── Get Tokens ─────────────────────────────────────────────────────────
    if (action == Protocol::ACTION_GET_TOKENS) {
        const QString sessionId = obj.value("sessionId").toString();

        QJsonArray tokens;
        if (sessionId.isEmpty()) {
            // Get all tokens
            tokens = SessionDBManager::instance().getAllTokens();
        } else if (!isValidSessionId(sessionId)) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        } else {
            // Get tokens for specific session
            tokens = SessionDBManager::instance().getTokensBySession(sessionId);
        }

        QJsonObject resp = Protocol::ok("tokens retrieved");
        resp.insert("tokens", tokens);
        sendTo(sock, resp);
        return true;
    }

    // ── Delete Token ──────────────────────────────────────────────────────────
    if (action == Protocol::ACTION_DELETE_TOKEN) {
        const qint64 tokenId = obj.value("tokenId").toVariant().toLongLong();

        if (tokenId <= 0) {
            sendTo(sock, Protocol::err("missing or invalid tokenId"));
            return true;
        }

        bool success = SessionDBManager::instance().deleteToken(tokenId);

        if (success) {
            QJsonObject resp = Protocol::ok("token deleted");
            resp.insert("tokenId", tokenId);
            sendTo(sock, resp);
            emit log(QString("[+] Token deleted: id=%1").arg(tokenId));
        } else {
            sendTo(sock, Protocol::err("failed to delete token"));
        }
        return true;
    }

    // ── Get Report Data ───────────────────────────────────────────────────────
    if (action == Protocol::ACTION_GET_REPORT_DATA) {
        QJsonObject reportData = SessionDBManager::instance().getReportData();

        QJsonObject resp = Protocol::ok("report data retrieved");
        resp.insert("report", reportData);
        sendTo(sock, resp);
        emit log("[+] Report data requested");
        return true;
    }

    // ── Operator activity audit log ───────────────────────────────────────────
    if (action == QStringLiteral("get_audit")) {
        const int limit = obj.value("limit").toInt(500);
        QJsonObject resp = Protocol::ok("audit retrieved");
        resp.insert("audit", SessionDBManager::instance().getAuditLog(limit));
        sendTo(sock, resp);
        return true;
    }

    // ── Import Session (from encrypted backup) ────────────────────────────────
    if (action == Protocol::ACTION_IMPORT_SESSION) {
        QString sessionId = obj.value("sessionId").toString().trimmed();
        QString user = obj.value("user").toString();
        QString tenantId = obj.value("tenantId").toString();
        QString defaultDomain = obj.value("defaultDomain").toString();
        QString resource = obj.value("resource").toString();

        if (sessionId.isEmpty()) {
            sendTo(sock, Protocol::err("sessionId is required for import"));
            return true;
        }

        // Validate session ID format (same check as new_session)
        static const QRegularExpression sessionIdRe(
            QStringLiteral("^[a-zA-Z0-9_\\-]{1,64}$"));
        if (!sessionIdRe.match(sessionId).hasMatch()) {
            sendTo(sock, Protocol::err("invalid sessionId format"));
            return true;
        }

        bool success = SessionDBManager::instance().addSessionToMainDB(
            sessionId, user, tenantId, defaultDomain, resource,
            operatorBySocket_.value(sock, QStringLiteral("unknown"))
        );

        if (success) {
            SessionDBManager::instance().logAudit(
                operatorBySocket_.value(sock, QStringLiteral("unknown")), "import_session", sessionId, user);
            QJsonObject resp = Protocol::ok("session imported");
            resp.insert("sessionId", sessionId);
            sendTo(sock, resp);
            emit log(QString("[+] Session imported: %1 (%2)").arg(sessionId.left(8), user));
        } else {
            sendTo(sock, Protocol::err("failed to import session"));
        }
        return true;
    }

    sendTo(sock, Protocol::err("Unknown action"));
    return true;
}


bool Server::constantTimeCompare(const QString &a, const QString &b) {
    const QByteArray ab = a.toUtf8();
    const QByteArray bb = b.toUtf8();
    if (ab.size() != bb.size()) {
        // Still do a dummy loop to avoid leaking length info via timing
        volatile int dummy = 0;
        for (int i = 0; i < ab.size(); ++i) dummy |= ab[i];
        Q_UNUSED(dummy);
        return false;
    }
    volatile int result = 0;
    for (int i = 0; i < ab.size(); ++i) {
        result |= (ab[i] ^ bb[i]);
    }
    return result == 0;
}

bool Server::handleLogin(QTcpSocket *sock, const QJsonObject &obj) {
    const QString pass = obj.value(Protocol::F_PASSWORD).toString();
    const QString clientIp = sock->peerAddress().toString();

    // Rate limiting check
    LoginAttempt &attempt = loginAttempts_[clientIp];
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    if (attempt.lockoutUntilMs > now) {
        const qint64 remainSec = (attempt.lockoutUntilMs - now) / 1000;
        sock->write(Protocol::toBytes(Protocol::err(
            QString("Too many failed attempts. Locked out for %1s").arg(remainSec))));
        emit log(QString("[-] Auth blocked (rate limit): %1").arg(clientIp));
        return true;
    }

    // Operator identity used for activity attribution (claimed, not verified).
    QString op = obj.value(Protocol::F_USERNAME).toString().trimmed();
    op.remove(QRegularExpression(QStringLiteral("[\\x00-\\x1F\\x7F]")));  // strip control chars
    if (op.size() > 64) op = op.left(64);
    if (op.isEmpty()) {
        sock->write(Protocol::toBytes(Protocol::err("operator username required")));
        return true;
    }

    if (constantTimeCompare(pass, allowedPass_)) {
        authed_.insert(sock);
        operatorBySocket_.insert(sock, op);
        // Reset failures on success
        attempt.failCount = 0;
        attempt.lockoutUntilMs = 0;
        sock->write(Protocol::toBytes(Protocol::ok("login ok")));
        emit log(QString("[+] Auth success: operator '%1' from %2").arg(op, clientIp));
        SessionDBManager::instance().logAudit(op, "login", clientIp, QString());
    } else {
        attempt.failCount++;
        attempt.lastAttemptMs = now;

        if (attempt.failCount >= MAX_LOGIN_FAILURES) {
            attempt.lockoutUntilMs = now + LOGIN_LOCKOUT_MS;
            emit log(QString("[-] Auth lockout triggered for %1 (%2 failures)")
                     .arg(clientIp).arg(attempt.failCount));
        }

        sock->write(Protocol::toBytes(Protocol::err("invalid credentials")));
        emit log(QString("[-] Auth failed from %1 (attempt %2)")
                 .arg(clientIp).arg(attempt.failCount));
    }
    return true;
}
