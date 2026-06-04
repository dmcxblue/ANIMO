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

// Command execution state (simple queue with timeout)
static QHash<QString, QString>           g_activeCmdId;   // sessionId -> currently executing cmdId
static QHash<QString, qint64>            g_cmdStartTime;  // sessionId -> when command started (ms since epoch)
static constexpr qint64 CMD_TIMEOUT_MS = 30000;           // 30 second timeout for stale command detection

// Single-fire auth gating (prevents duplicate OK/FAIL handling)
enum class AuthState { Pending, Success, Failed };
static QHash<QString, AuthState> g_authState;

// ===== Helpers (define once) ===============================================
static inline QByteArray toBytes(const QJsonObject &o) { return Protocol::toBytes(o); }

// Load PowerShell script from Qt resources
static QByteArray loadScript(const QString &resourcePath) {
    QFile file(resourcePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "[Server] Failed to load script resource:" << resourcePath;
        return QByteArray();
    }
    return file.readAll();
}

static inline void sendTo(QTcpSocket *sock, const QJsonObject &obj) {
    if (sock && sock->state() == QAbstractSocket::ConnectedState)
        sock->write(toBytes(obj));
}

static inline void broadcastTo(const QSet<QTcpSocket*> &socks, const QJsonObject &obj) {
    for (QTcpSocket *s : socks) sendTo(s, obj);
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
            // Strip null bytes — could terminate strings in edge cases
            continue;
        } else if (ch == QLatin1Char('\n') || ch == QLatin1Char('\r')) {
            // Strip newlines — could break out of single-line PS context
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
static QProcess* ensureProcess(QObject *parent, const QString &sessionId) {
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
        meta.value("resource").toString("https://management.azure.com")
    );
    SessionDBManager::instance().createSessionDB(sessionId);

    // Tell subscribers the shell is alive
    broadcastTo(g_subscribers.value(sessionId),
        QJsonObject{ {Protocol::F_ACTION, "session_open"},
                     {"sessionId", sessionId},
                     {"alive", true} });

    // Minimal init: suppress noise silently using $null assignment to prevent echo
    proc->write("$null=$ErrorActionPreference=$ProgressPreference=$WarningPreference='SilentlyContinue'\n");
    proc->write("$null=Remove-Module PSReadLine -Force -EA SilentlyContinue\n");
    proc->write("function global:prompt{''}\n");

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
            broadcastTo(g_subscribers.value(sessionId),
                QJsonObject{ {Protocol::F_ACTION, "output"},
                             {"sessionId", sessionId},
                             {"stream", "stdout"},
                             {"data", QString::fromUtf8(chunk)} });
            emittedAny = true;  // Prevent duplicate broadcast later
        }

        // Extract zero or more complete __QZ_BEGIN__/__QZ_END__ segments (with optional :cmdId)
        // Also handle __QZ_ERROR_BEGIN__/__QZ_ERROR_END__ for error stream separation
        static const QByteArray B = "__QZ_BEGIN__";
        static const QByteArray E = "__QZ_END__";
        static const QByteArray EB = "__QZ_ERROR_BEGIN__";
        static const QByteArray EE = "__QZ_ERROR_END__";
        bool commandCompleted = false;
        QString completedCmdId;

        // First, extract and process any error segments
        while (true) {
            int eb = buf.indexOf(EB);
            if (eb < 0) break;

            // Find the end of the ERROR_BEGIN line to extract cmdId
            int errorBeginLineEnd = buf.indexOf('\n', eb);
            if (errorBeginLineEnd < 0) break;

            // Extract cmdId from ERROR_BEGIN marker
            QString errorCmdId;
            QByteArray errorBeginLine = buf.mid(eb, errorBeginLineEnd - eb);
            int colonPos = errorBeginLine.indexOf(':');
            if (colonPos > 0) {
                errorCmdId = QString::fromUtf8(errorBeginLine.mid(colonPos + 1)).trimmed();
            }

            int ee = buf.indexOf(EE, errorBeginLineEnd);
            if (ee < 0) break;

            // Extract error content
            int errorStart = errorBeginLineEnd + 1;
            int errorEnd = ee;
            QByteArray errorSegment = buf.mid(errorStart, errorEnd - errorStart);

            // Remove the error segment from buffer
            int eeLineEnd = buf.indexOf('\n', ee);
            int removeEnd = (eeLineEnd >= 0) ? eeLineEnd + 1 : ee + EE.size() + errorCmdId.size() + 1;
            buf.remove(0, removeEnd);

            // Sanitize error output
            QString errorCleaned = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(errorSegment));
            errorCleaned = errorCleaned.trimmed();

            if (!errorCleaned.isEmpty() && !inAuth) {
                QJsonObject errMsg{
                    {Protocol::F_ACTION, "output"},
                    {"sessionId", sessionId},
                    {"stream", "stderr"},
                    {"data", errorCleaned}
                };
                if (!errorCmdId.isEmpty()) {
                    errMsg.insert(Protocol::F_CMD_ID, errorCmdId);
                }
                broadcastTo(g_subscribers.value(sessionId), errMsg);
            }
        }

        // Now process normal output segments
        while (true) {
            int b = buf.indexOf(B);
            if (b < 0) break;

            // Find the end of the BEGIN line to extract cmdId
            int beginLineEnd = buf.indexOf('\n', b);
            if (beginLineEnd < 0) break;

            // Extract cmdId from BEGIN marker (format: __QZ_BEGIN__:cmdId or __QZ_BEGIN__)
            QString beginCmdId;
            QByteArray beginLine = buf.mid(b, beginLineEnd - b);
            int colonPos = beginLine.indexOf(':');
            if (colonPos > 0) {
                beginCmdId = QString::fromUtf8(beginLine.mid(colonPos + 1)).trimmed();
            }

            int e = buf.indexOf(E, beginLineEnd);
            if (e < 0) break;

            // Segment boundaries: content is between the BEGIN line's newline and the END marker
            int segStart = beginLineEnd + 1;
            int segEnd = e;

            // Extract cmdId from END marker for validation
            int endLineEnd = buf.indexOf('\n', e);
            QByteArray endLine = (endLineEnd >= 0) ? buf.mid(e, endLineEnd - e) : buf.mid(e);
            QString endCmdId;
            int endColonPos = endLine.indexOf(':');
            if (endColonPos > 0) {
                endCmdId = QString::fromUtf8(endLine.mid(endColonPos + 1)).trimmed();
            }

            // Use the cmdId from either marker (prefer END marker if present)
            QString cmdId = !endCmdId.isEmpty() ? endCmdId : beginCmdId;

            QByteArray segment = buf.mid(segStart, segEnd - segStart);

            // Remove everything up through the end marker line from the buffer
            int removeEnd = (endLineEnd >= 0) ? endLineEnd + 1 : e + E.size() + endCmdId.size() + 1;
            buf.remove(0, removeEnd);

            // Sanitize
            QString cleaned = OutputSanitizer::stripAnsiPrompt(QString::fromUtf8(segment));
            // Remove any embedded markers with or without cmdId (including error markers)
            static QRegularExpression markerRe(R"(__QZ_(BEGIN|END|ERROR_BEGIN|ERROR_END)__(:[^\s\n]*)?)");
            cleaned.remove(markerRe);
            cleaned = cleaned.trimmed();
            // We found a complete BEGIN/END segment - command output is done
            commandCompleted = true;
            if (!cmdId.isEmpty()) {
                completedCmdId = cmdId;
            }

            if (cleaned.isEmpty()) {
                continue;
            }

            // Emit cleaned only when not in auth phase
            if (!inAuth) {
                QJsonObject outMsg{
                    {Protocol::F_ACTION, "output"},
                    {"sessionId", sessionId},
                    {"stream", "stdout"},
                    {"data", cleaned}
                };
                if (!cmdId.isEmpty()) {
                    outMsg.insert(Protocol::F_CMD_ID, cmdId);
                }
                broadcastTo(g_subscribers.value(sessionId), outMsg);
            }

            // History
            SessionDBManager::instance().insertCommandOutput(sessionId, QString(), cleaned, cmdId);
        }

        // When any output segment completes (END marker found), clear active state
        if (commandCompleted) {
            // Get cmdId before clearing
            QString finalCmdId = completedCmdId.isEmpty() ? g_activeCmdId.value(sessionId) : completedCmdId;

            // Always clear - we execute sequentially so this must be our command
            g_activeCmdId.remove(sessionId);
            g_cmdStartTime.remove(sessionId);

            broadcastTo(g_subscribers.value(sessionId),
                QJsonObject{
                    {Protocol::F_ACTION, "command_complete"},
                    {"sessionId", sessionId},
                    {Protocol::F_CMD_ID, finalCmdId}
                });
        }
		
		// ==== Only if we're still in auth AND we didn't emit a cleaned segment, pass raw ====
		if (inAuth && !emittedAny) {
			broadcastTo(g_subscribers.value(sessionId),
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
                broadcastTo(g_subscribers.value(sessionId), ev);

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

                const QString domain  = upn.contains('@') ? upn.section('@', 1, 1) : QStringLiteral("N/A");
                // Skip blocking tenant resolution for now - use domain as tenant placeholder
                const QString tenant  = domain;

                // enrich + persist success
                QJsonObject meta = g_sessionInfo.value(sessionId);
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

                const auto subs = g_subscribers.value(sessionId);
                qInfo() << "[Server] ✓ Session created:" << sessionId << "| User:" << upn << "| Method: Credentials";
                broadcastTo(subs, ev);

                // consume matched line and lock state
                if (nl >= 0) buf.remove(0, nl + 1);
                else buf.clear();
                g_authState[sessionId] = AuthState::Success;

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
                broadcastTo(g_subscribers.value(sessionId), ev);

                const int nl = buf.indexOf('\n', failIdx);
                if (nl >= 0) buf.remove(0, nl + 1); else buf.clear();
                g_authState[sessionId] = AuthState::Failed;
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
            broadcastTo(g_subscribers.value(sessionId),
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
        broadcastTo(g_subscribers.value(sessionId), msg);

        // Clean up subscribers — session is dead, no further messages will come
        g_subscribers.remove(sessionId);
        g_activeCmdId.remove(sessionId);
        g_cmdStartTime.remove(sessionId);
        g_stdoutBuf.remove(sessionId);

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
    s->deleteLater();
    emit log("[*] Client disconnected");
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
        QProcess *proc = ensureProcess(this, sid);
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

            // GRAPH — Connect-MgGraph (no module checks, emit markers)
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

            // AZURE MANAGEMENT (Az) — Connect-AzAccount (no module checks)
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

        // ——— SPN (Service Principal) FLOW ———
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

            // Pass only the credential file path, not the secret itself
            QString execCmd = QString(". \"%1\" -CredentialFile \"%2\"\n")
                .arg(ps1Path, credPath);
            proc->write(execCmd.toUtf8());

            QJsonObject ack = Protocol::ok("new_session ok");
            ack.insert("sessionId", sid);
            sendTo(sock, ack);
            return true;
        }

        // ——— TOKENS FLOW ———
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
                resource);

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
                // —— Az: need both Az access and a Graph token for Connect-AzAccount
                if (refresh.isEmpty()) {
                    qWarning() << "[Server] Az login failed: no refresh token";
                    sendTo(sock, Protocol::err("refreshToken required for Az token login"));
                    return true;
                }

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

                // Az: Connect with both access and graph tokens
                ps.append("$a=@\"\n"); ps.append(access.toUtf8()); ps.append("\n\"@\n");
                ps.append("$g=@\"\n"); ps.append(mgToken.toUtf8()); ps.append("\n\"@\n");
                ps.append("try{Connect-AzAccount -AccessToken $a -MicrosoftGraphAccessToken $g ");
                if (!user.isEmpty())     ps.append(QString("-AccountId '%1' ").arg(escapePsString(user)).toUtf8());
                if (!tenantId.isEmpty()) ps.append(QString("-TenantId '%1' ").arg(escapePsString(tenantId)).toUtf8());
                ps.append("-WA Ignore|Out-Null\n");
                ps.append("$ctx=Get-AzContext -EA SilentlyContinue\n");
                ps.append("if($ctx-and$ctx.Account){Write-Output \"__ANIMO_LOGIN_OK__:$($ctx.Account)\"}");
                ps.append("else{"); ps.append(emitFail()); ps.append("}}catch{"); ps.append(emitFail()); ps.append("}\n");
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

        // Validate command length to prevent memory exhaustion
        if (cmd.size() > MAX_CMD_LENGTH) {
            sendTo(sock, Protocol::err(
                QString("command too long (%1 bytes, max %2)")
                    .arg(cmd.size()).arg(MAX_CMD_LENGTH)));
            return true;
        }
        QProcess *proc = ensureProcess(this, sid);
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

            // Check if previous command is still running (with timeout)
            if (g_activeCmdId.contains(sid)) {
                qint64 now = QDateTime::currentMSecsSinceEpoch();
                qint64 started = g_cmdStartTime.value(sid, 0);
                if (now - started < CMD_TIMEOUT_MS) {
                    // Previous command still active, queue this one
                    // For simplicity, just reject and tell client to retry
                    sendTo(sock, Protocol::err("previous command still running, please wait"));
                    return true;
                }
                // Timeout - clear stale command state
                g_activeCmdId.remove(sid);
                g_cmdStartTime.remove(sid);
            }

            // Mark this command as active
            g_activeCmdId[sid] = cmdId;
            g_cmdStartTime[sid] = QDateTime::currentMSecsSinceEpoch();
        }

        // Persist the command
        SessionDBManager::instance().createSessionDB(sid);
        SessionDBManager::instance().insertCommandOutput(sid, cmd, QString(), cmdId);

        // Execute with markers
        const QString wrapped = OutputSanitizer::wrapPwshCommandWithId(cmd, cmdId);
        proc->write(wrapped.toUtf8());
        proc->write("\n");

        // Notify client
        {
            QMutexLocker locker(&g_stateMutex);
            broadcastTo(g_subscribers.value(sid),
                QJsonObject{
                    {Protocol::F_ACTION, "command_started"},
                    {"sessionId", sid},
                    {Protocol::F_CMD_ID, cmdId},
                    {"command", cmd}
                });
        }

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
            q.prepare("SELECT SessionID, User, TenantID, DefaultDomain, Resource "
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

    // ── Get session info (+ ensure proc, subscribe) ────────────────────────────
    if (action == QStringLiteral("get_session")) {
        const QString sid = obj.value("sessionId").toString().trimmed();
        if (sid.isEmpty()) {
            sendTo(sock, Protocol::err("missing sessionId"));
            return true;
        }

        // Ensure process exists/starts and subscribe caller
        QProcess *proc = ensureProcess(this, sid);
        if (!proc) {
            sendTo(sock, Protocol::err("failed to ensure session process"));
            return true;
        }
        {
            QMutexLocker locker(&g_stateMutex);
            g_subscribers[sid].insert(sock);
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

    // ── Attach (subscribe) ─────────────────────────────────────────────────────
    if (action == QStringLiteral("attach")) {
        const QString sid = obj.value("sessionId").toString().trimmed();
        if (sid.isEmpty()) {
            sendTo(sock, Protocol::err("missing sessionId"));
            return true;
        }
        // Ensure process exists and subscribe
        QProcess *proc = ensureProcess(this, sid);
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

        bool success = SessionDBManager::instance().logToken(
            sessionId, source, accessToken, refreshToken, idToken,
            user, tenantId, resource, scope, expiresIn
        );

        if (success) {
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
            sessionId, user, tenantId, defaultDomain, resource
        );

        if (success) {
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

    if (constantTimeCompare(pass, allowedPass_)) {
        authed_.insert(sock);
        // Reset failures on success
        attempt.failCount = 0;
        attempt.lockoutUntilMs = 0;
        sock->write(Protocol::toBytes(Protocol::ok("login ok")));
        emit log(QString("[+] Auth success from %1").arg(clientIp));
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
