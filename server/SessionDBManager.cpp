#include "SessionDBManager.h"

#include <QDir>
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QDebug>
#include <QJsonArray>
#include <QJsonObject>
#include <QCoreApplication>
#include <QFileInfo>
#include <QMutexLocker>

static const char* kMainConn = "main_sessions";

SessionDBManager& SessionDBManager::instance() {
    static SessionDBManager s;
    return s;
}

SessionDBManager::SessionDBManager() {
    // nothing heavy here; DB opened in initMainDB()
}

SessionDBManager::~SessionDBManager() {
    // let Qt close connections on exit
}

bool SessionDBManager::initMainDB() {
    // Use absolute path relative to application directory for consistent database location
    QString appDir = QCoreApplication::applicationDirPath();
    QString dataDir = appDir + "/data";
    QString dbPath = dataDir + "/sessions.db";

    // Ensure data directory exists with proper permissions
    QDir dir;
    if (!dir.exists(dataDir)) {
        if (!dir.mkpath(dataDir)) {
            qWarning() << "[DB] Failed to create data directory:" << dataDir;
            return false;
        }
        qDebug() << "[DB] Created data directory:" << dataDir;
    }

    // Check directory is writable
    QFileInfo dirInfo(dataDir);
    if (!dirInfo.isWritable()) {
        qWarning() << "[DB] Data directory not writable:" << dataDir;
        return false;
    }

    if (!m_mainDb.isValid()) {
        m_mainDb = QSqlDatabase::addDatabase("QSQLITE", kMainConn);
        m_mainDb.setDatabaseName(dbPath);
        qDebug() << "[DB] Database path:" << dbPath;
    }

    if (!m_mainDb.isOpen() && !m_mainDb.open()) {
        qWarning() << "[DB] open main failed:" << m_mainDb.lastError().text();
        return false;
    }

    // Enable foreign key constraints (must be done per connection)
    QSqlQuery pragma(m_mainDb);
    pragma.exec("PRAGMA foreign_keys = ON");
    // Set WAL mode for better concurrent access
    pragma.exec("PRAGMA journal_mode = WAL");
    pragma.exec("PRAGMA busy_timeout = 5000");

    QSqlQuery q(m_mainDb);
    if (!q.exec(
        "CREATE TABLE IF NOT EXISTS sessions ("
        " SessionID TEXT PRIMARY KEY,"
        " User TEXT,"
        " TenantID TEXT,"
        " DefaultDomain TEXT,"
        " Resource TEXT,"
        " CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,"
        " UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,"
        " Alive INTEGER DEFAULT 0,"
        " LastSeen DATETIME,"
        " Status TEXT DEFAULT 'pending'"
        ")"
    )) {
        qWarning() << "[DB] create main table failed:" << q.lastError().text();
        return false;
    }

    // Schema migration: add columns if they don't exist (for existing databases)
    // SQLite returns error for duplicate columns, which is expected - only log unexpected errors
    auto execMigration = [&q](const QString &sql, const QString &desc) {
        if (!q.exec(sql)) {
            QString err = q.lastError().text();
            // Ignore "duplicate column" errors which are expected during migration
            if (!err.contains("duplicate column", Qt::CaseInsensitive)) {
                qWarning() << "[DB] Migration warning (" << desc << "):" << err;
            }
        }
    };
    execMigration("ALTER TABLE sessions ADD COLUMN Alive INTEGER DEFAULT 0", "add Alive");
    execMigration("ALTER TABLE sessions ADD COLUMN LastSeen DATETIME", "add LastSeen");
    execMigration("ALTER TABLE sessions ADD COLUMN Status TEXT DEFAULT 'pending'", "add Status");
    execMigration("ALTER TABLE sessions ADD COLUMN CreatedBy TEXT DEFAULT 'legacy'", "add CreatedBy");

    // UpdatedAt trigger (best-effort, log if creation fails)
    if (!q.exec(
        "CREATE TRIGGER IF NOT EXISTS sessions_updatedAt "
        "AFTER UPDATE ON sessions "
        "BEGIN "
        "  UPDATE sessions SET UpdatedAt = CURRENT_TIMESTAMP "
        "  WHERE SessionID = NEW.SessionID;"
        "END;"
    )) {
        qWarning() << "[DB] Failed to create UpdatedAt trigger:" << q.lastError().text();
    }

    // Create tokens table (no foreign key - tokens can exist without sessions)
    if (!q.exec(
        "CREATE TABLE IF NOT EXISTS tokens ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " session_id TEXT NOT NULL,"
        " timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        " source TEXT NOT NULL,"
        " user TEXT,"
        " tenant_id TEXT,"
        " resource TEXT,"
        " access_token TEXT NOT NULL,"
        " refresh_token TEXT,"
        " id_token TEXT,"
        " token_type TEXT DEFAULT 'Bearer',"
        " expires_in INTEGER,"
        " scope TEXT"
        ")"
    )) {
        qWarning() << "[DB] create tokens table failed:" << q.lastError().text();
        return false;
    }

    // Migration: Drop foreign key constraint from existing databases
    // SQLite doesn't support ALTER TABLE DROP CONSTRAINT, so we recreate the table
    // Check if the old schema has the foreign key by trying to insert a test and rollback
    q.exec("PRAGMA foreign_keys = OFF");
    q.exec("BEGIN TRANSACTION");
    bool needsMigration = false;

    // Try to detect if foreign key constraint exists by checking table info
    if (q.exec("SELECT sql FROM sqlite_master WHERE type='table' AND name='tokens'")) {
        if (q.next()) {
            QString createSql = q.value(0).toString();
            if (createSql.contains("FOREIGN KEY", Qt::CaseInsensitive)) {
                needsMigration = true;
            }
        }
    }

    if (needsMigration) {
        qDebug() << "[DB] Migrating tokens table to remove foreign key constraint...";
        bool migrationOk = true;
        migrationOk &= q.exec("ALTER TABLE tokens RENAME TO tokens_old");
        migrationOk &= q.exec(
            "CREATE TABLE tokens ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " session_id TEXT NOT NULL,"
            " timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
            " source TEXT NOT NULL,"
            " user TEXT,"
            " tenant_id TEXT,"
            " resource TEXT,"
            " access_token TEXT NOT NULL,"
            " refresh_token TEXT,"
            " id_token TEXT,"
            " token_type TEXT DEFAULT 'Bearer',"
            " expires_in INTEGER,"
            " scope TEXT"
            ")"
        );
        migrationOk &= q.exec("INSERT INTO tokens SELECT * FROM tokens_old");
        migrationOk &= q.exec("DROP TABLE tokens_old");
        if (migrationOk) {
            qDebug() << "[DB] Migration complete";
        } else {
            qWarning() << "[DB] Migration may have failed:" << q.lastError().text();
        }
    }

    if (!q.exec("COMMIT")) {
        qWarning() << "[DB] Failed to commit transaction:" << q.lastError().text();
    }
    q.exec("PRAGMA foreign_keys = ON");

    // Operator attribution: who captured each token (added after the FK migration
    // above so it applies to the finalized tokens table).
    execMigration("ALTER TABLE tokens ADD COLUMN captured_by TEXT DEFAULT 'legacy'", "add captured_by");

    // Create index on session_id for faster queries
    if (!q.exec("CREATE INDEX IF NOT EXISTS idx_tokens_session ON tokens(session_id)")) {
        qWarning() << "[DB] Failed to create session index:" << q.lastError().text();
    }

    // Create index on timestamp for chronological queries
    if (!q.exec("CREATE INDEX IF NOT EXISTS idx_tokens_timestamp ON tokens(timestamp DESC)")) {
        qWarning() << "[DB] Failed to create timestamp index:" << q.lastError().text();
    }

    // Operator activity audit log - append-only "who did what when".
    if (!q.exec(
        "CREATE TABLE IF NOT EXISTS audit_log ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        " operator TEXT NOT NULL,"
        " action TEXT NOT NULL,"
        " target TEXT,"
        " detail TEXT"
        ")"
    )) {
        qWarning() << "[DB] create audit_log failed:" << q.lastError().text();
    }

    return true;
}

bool SessionDBManager::logAudit(const QString &op, const QString &action,
                                const QString &target, const QString &detail)
{
    QMutexLocker locker(&m_mutex);
    if (!initMainDB()) return false;

    QSqlQuery q(m_mainDb);
    q.prepare("INSERT INTO audit_log (operator, action, target, detail) VALUES (?, ?, ?, ?)");
    q.addBindValue(op.isEmpty() ? QStringLiteral("unknown") : op);
    q.addBindValue(action);
    q.addBindValue(target);
    q.addBindValue(detail);
    if (!q.exec()) {
        qWarning() << "[DB] audit insert failed:" << q.lastError().text();
        return false;
    }
    return true;
}

QJsonArray SessionDBManager::getAuditLog(int limit)
{
    QMutexLocker locker(&m_mutex);
    QJsonArray arr;
    if (!initMainDB()) return arr;

    QSqlQuery q(m_mainDb);
    q.prepare("SELECT timestamp, operator, action, target, detail "
              "FROM audit_log ORDER BY id DESC LIMIT ?");
    q.addBindValue(limit > 0 ? limit : 500);
    if (q.exec()) {
        while (q.next()) {
            QJsonObject o;
            o.insert("timestamp", q.value(0).toString());
            o.insert("operator",  q.value(1).toString());
            o.insert("action",    q.value(2).toString());
            o.insert("target",    q.value(3).toString());
            o.insert("detail",    q.value(4).toString());
            arr.append(o);
        }
    }
    return arr;
}

QSqlDatabase SessionDBManager::mainDb() const {
    return m_mainDb;
}

bool SessionDBManager::addSessionToMainDB(const QString &sessionId,
                                          const QString &user,
                                          const QString &tenantId,
                                          const QString &defaultDomain,
                                          const QString &resource,
                                          const QString &createdBy)
{
    QMutexLocker locker(&m_mutex);
    if (!initMainDB()) return false;

    QSqlQuery q(m_mainDb);
    // Upsert. CreatedBy is set on first insert and deliberately NOT in the DO UPDATE
    // clause, so the original creator is preserved across later updates.
    q.prepare(
        "INSERT INTO sessions (SessionID,User,TenantID,DefaultDomain,Resource,CreatedBy) "
        "VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(SessionID) DO UPDATE SET "
        "  User=excluded.User, "
        "  TenantID=excluded.TenantID, "
        "  DefaultDomain=excluded.DefaultDomain, "
        "  Resource=excluded.Resource"
    );
    q.addBindValue(sessionId);
    q.addBindValue(user);
    q.addBindValue(tenantId);
    q.addBindValue(defaultDomain);
    q.addBindValue(resource);
    q.addBindValue(createdBy);

    if (!q.exec()) {
        qWarning() << "[DB] upsert session failed:" << q.lastError().text();
        return false;
    }
    return true;
}

bool SessionDBManager::updateSessionUser(const QString &sessionId, const QString &username) {
    QMutexLocker locker(&m_mutex);  // serialize with addSessionToMainDB and other DB writes
    if (!initMainDB()) return false;

    QSqlQuery q(m_mainDb);
    q.prepare("UPDATE sessions SET User=? WHERE SessionID=?");
    q.addBindValue(username);
    q.addBindValue(sessionId);

    if (!q.exec()) {
        qWarning() << "[DB] update user failed:" << q.lastError().text();
        return false;
    }
    return true;
}

void SessionDBManager::updateSessionTenant(const QString &sessionId,
                                           const QString &tenantId,
                                           const QString &defaultDomain)
{
    QMutexLocker locker(&m_mutex);  // serialize with addSessionToMainDB and other DB writes
    if (!initMainDB()) return;

    QSqlQuery q(m_mainDb);
    q.prepare("UPDATE sessions SET TenantID=?, DefaultDomain=? WHERE SessionID=?");
    q.addBindValue(tenantId);
    q.addBindValue(defaultDomain);
    q.addBindValue(sessionId);
    if (!q.exec()) {
        qWarning() << "[DB] update tenant/domain failed:" << q.lastError().text();
    }
}

bool SessionDBManager::createSessionDB(const QString &sessionId) {
    QString appDir = QCoreApplication::applicationDirPath();
    const QString dir = QString("%1/data/%2").arg(appDir, sessionId);

    QDir qdir;
    if (!qdir.exists(dir) && !qdir.mkpath(dir)) {
        qWarning() << "[DB] Failed to create session directory:" << dir;
        return false;
    }

    const QString connName = QString("sess-%1").arg(sessionId);
    QSqlDatabase db = QSqlDatabase::database(connName);
    if (!db.isValid()) {
        db = QSqlDatabase::addDatabase("QSQLITE", connName);
        db.setDatabaseName(QString("%1/sessions.db").arg(dir));
    }
    if (!db.isOpen() && !db.open()) {
        qWarning() << "[DB] open per-session failed:" << db.lastError().text();
        return false;
    }
    { QSqlQuery p(db); p.exec("PRAGMA journal_mode=WAL;"); p.exec("PRAGMA synchronous=NORMAL;"); p.exec("PRAGMA busy_timeout=10000;"); }
    QSqlQuery q(db);
    if (!q.exec(
        "CREATE TABLE IF NOT EXISTS history_v2 ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        " command     TEXT NOT NULL,"
        " cmd_id      TEXT DEFAULT NULL,"
        " status      TEXT NOT NULL DEFAULT 'ok',"
        " exit_code   INTEGER DEFAULT NULL,"
        " stdout_text TEXT NOT NULL DEFAULT '',"
        " stderr_text TEXT NOT NULL DEFAULT '',"
        " duration_ms INTEGER DEFAULT NULL"
        ")"
    )) { qWarning() << "[DB] create history_v2 failed:" << q.lastError().text(); return false; }

    // Migration: add cmd_id column if it doesn't exist
    QSqlQuery mig(db);
    if (!mig.exec("ALTER TABLE history_v2 ADD COLUMN cmd_id TEXT DEFAULT NULL")) {
        QString err = mig.lastError().text();
        if (!err.contains("duplicate column", Qt::CaseInsensitive)) {
            qWarning() << "[DB] Migration warning (add cmd_id):" << err;
        }
    }
    // Migration: add run_by column (operator who ran the command)
    if (!mig.exec("ALTER TABLE history_v2 ADD COLUMN run_by TEXT DEFAULT 'legacy'")) {
        QString err = mig.lastError().text();
        if (!err.contains("duplicate column", Qt::CaseInsensitive)) {
            qWarning() << "[DB] Migration warning (add run_by):" << err;
        }
    }
    q.exec(
        "CREATE TABLE IF NOT EXISTS history ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        " command TEXT,"
        " output TEXT)"
    );
    return true;
}

void SessionDBManager::insertCommandOutput(const QString &sessionId,
                                           const QString &command,
                                           const QString &output,
                                           const QString &cmdId,
                                           const QString &runBy)
{
    QMutexLocker locker(&m_mutex);

    // Skip if both are empty
    if (command.isEmpty() && output.isEmpty()) {
        return;
    }

    const QString connName = QString("sess-%1").arg(sessionId);
    if (!QSqlDatabase::contains(connName)) {
        if (!createSessionDB(sessionId)) return;
    }
    QSqlDatabase db = QSqlDatabase::database(connName);
    if (!db.isOpen() && !db.open()) {
        qWarning() << "[DB] history open failed:" << db.lastError().text();
        return;
    }

    // Case 1: New command entry (command provided, no output yet)
    if (!command.isEmpty() && output.isEmpty()) {
        db.transaction();
        QSqlQuery ins(db);
        ins.prepare("INSERT INTO history_v2 (command, cmd_id, status, stdout_text, run_by) VALUES (?, ?, 'pending', '', ?)");
        ins.addBindValue(command);
        ins.addBindValue(cmdId.isEmpty() ? QVariant() : cmdId);
        ins.addBindValue(runBy.isEmpty() ? QStringLiteral("unknown") : runBy);
        if (!ins.exec()) {
            qWarning() << "[DB] begin history_v2 failed:" << ins.lastError().text();
            db.rollback();
            return;
        }
        m_lastRowId[sessionId] = ins.lastInsertId().toLongLong();
        db.commit();
        return;
    }

    // Case 2: Append output to existing command entry
    if (!output.isEmpty() && command.isEmpty()) {
        qint64 id = m_lastRowId.value(sessionId, -1);

        // If cmdId is provided, find the row by cmdId for more precise matching
        if (!cmdId.isEmpty()) {
            QSqlQuery sel(db);
            sel.prepare("SELECT id FROM history_v2 WHERE cmd_id = ? ORDER BY id DESC LIMIT 1");
            sel.addBindValue(cmdId);
            if (sel.exec() && sel.next()) {
                id = sel.value(0).toLongLong();
            }
        }

        // Try to find the last row if we don't have a cached ID
        if (id < 0) {
            QSqlQuery sel(db);
            if (sel.exec("SELECT id FROM history_v2 ORDER BY id DESC LIMIT 1") && sel.next()) {
                id = sel.value(0).toLongLong();
                m_lastRowId[sessionId] = id;
            }
        }

        if (id >= 0) {
            QSqlQuery upd(db);
            const QString norm = normalizeText(output);
            // Handle both NULL and empty string cases properly
            upd.prepare("UPDATE history_v2 "
                        "SET stdout_text = CASE "
                        "  WHEN stdout_text IS NULL OR stdout_text = '' THEN ? "
                        "  ELSE stdout_text || char(10) || ? "
                        "END, "
                        "status = 'ok' "
                        "WHERE id = ?");
            upd.addBindValue(norm);
            upd.addBindValue(norm);
            upd.addBindValue(id);
            if (!upd.exec()) {
                qWarning() << "[DB] append stdout failed:" << upd.lastError().text();
                return;
            }
            return;
        }

        // No existing row to append to - create a synthetic entry
        db.transaction();
        QSqlQuery ins2(db);
        ins2.prepare("INSERT INTO history_v2 (command, status, stdout_text) VALUES ('<orphan output>', 'ok', ?)");
        ins2.addBindValue(normalizeText(output));
        if (!ins2.exec()) {
            qWarning() << "[DB] synth insert failed:" << ins2.lastError().text();
            db.rollback();
            return;
        }
        m_lastRowId[sessionId] = ins2.lastInsertId().toLongLong();
        db.commit();
        return;
    }

    // Case 3: Both command and output provided (single insert)
    db.transaction();
    QSqlQuery ins3(db);
    ins3.prepare("INSERT INTO history_v2 (command, status, stdout_text) VALUES (?, 'ok', ?)");
    ins3.addBindValue(command);
    ins3.addBindValue(normalizeText(output));
    if (!ins3.exec()) {
        qWarning() << "[DB] insert fallback failed:" << ins3.lastError().text();
        db.rollback();
        return;
    }
    m_lastRowId[sessionId] = ins3.lastInsertId().toLongLong();
    db.commit();
}



QString SessionDBManager::normalizeText(QString s) {
    s.replace("\r\n", "\n");
    s.remove(QChar('\0'));
    return s;
}


// Token logging implementation
bool SessionDBManager::logToken(const QString &sessionId,
                                 const QString &source,
                                 const QString &accessToken,
                                 const QString &refreshToken,
                                 const QString &idToken,
                                 const QString &user,
                                 const QString &tenantId,
                                 const QString &resource,
                                 const QString &scope,
                                 int expiresIn,
                                 const QString &capturedBy)
{
    QMutexLocker locker(&m_mutex);
    if (!initMainDB()) {
        qWarning() << "[DB] logToken: failed to init main DB";
        return false;
    }

    QSqlQuery q(m_mainDb);
    q.prepare(
        "INSERT INTO tokens (session_id, source, user, tenant_id, resource, "
        "access_token, refresh_token, id_token, scope, expires_in, captured_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    q.addBindValue(sessionId);
    q.addBindValue(source);
    q.addBindValue(user);
    q.addBindValue(tenantId);
    q.addBindValue(resource);
    q.addBindValue(accessToken);
    q.addBindValue(refreshToken);
    q.addBindValue(idToken);
    q.addBindValue(scope);
    q.addBindValue(expiresIn > 0 ? expiresIn : QVariant());
    q.addBindValue(capturedBy.isEmpty() ? QStringLiteral("unknown") : capturedBy);

    if (!q.exec()) {
        qWarning() << "[DB] logToken failed:" << q.lastError().text();
        return false;
    }

    qInfo() << "[DB] ✓ Token logged | Session:" << sessionId << "| Source:" << source << "| User:" << user;
    return true;
}

QJsonArray SessionDBManager::getTokensBySession(const QString &sessionId)
{
    QJsonArray result;
    if (!initMainDB()) {
        qWarning() << "[DB] getTokensBySession: failed to init main DB";
        return result;
    }

    QSqlQuery q(m_mainDb);
    q.prepare(
        "SELECT id, session_id, timestamp, source, user, tenant_id, resource, "
        "access_token, refresh_token, id_token, token_type, expires_in, scope, captured_by "
        "FROM tokens WHERE session_id = ? ORDER BY timestamp DESC"
    );
    q.addBindValue(sessionId);

    if (!q.exec()) {
        qWarning() << "[DB] getTokensBySession failed:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        QJsonObject obj;
        obj["id"] = q.value(0).toLongLong();
        obj["session_id"] = q.value(1).toString();
        obj["timestamp"] = q.value(2).toString();
        obj["source"] = q.value(3).toString();
        obj["user"] = q.value(4).toString();
        obj["tenant_id"] = q.value(5).toString();
        obj["resource"] = q.value(6).toString();
        obj["access_token"] = q.value(7).toString();
        obj["refresh_token"] = q.value(8).toString();
        obj["id_token"] = q.value(9).toString();
        obj["token_type"] = q.value(10).toString();
        obj["expires_in"] = q.value(11).toInt();
        obj["scope"] = q.value(12).toString();
        obj["captured_by"] = q.value(13).toString();
        result.append(obj);
    }

    return result;
}

QJsonArray SessionDBManager::getAllTokens()
{
    QJsonArray result;
    if (!initMainDB()) {
        qWarning() << "[DB] getAllTokens: failed to init main DB";
        return result;
    }

    QSqlQuery q(m_mainDb);
    if (!q.exec(
        "SELECT id, session_id, timestamp, source, user, tenant_id, resource, "
        "access_token, refresh_token, id_token, token_type, expires_in, scope, captured_by "
        "FROM tokens ORDER BY timestamp DESC"
    )) {
        qWarning() << "[DB] getAllTokens failed:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        QJsonObject obj;
        obj["id"] = q.value(0).toLongLong();
        obj["session_id"] = q.value(1).toString();
        obj["timestamp"] = q.value(2).toString();
        obj["source"] = q.value(3).toString();
        obj["user"] = q.value(4).toString();
        obj["tenant_id"] = q.value(5).toString();
        obj["resource"] = q.value(6).toString();
        obj["access_token"] = q.value(7).toString();
        obj["refresh_token"] = q.value(8).toString();
        obj["id_token"] = q.value(9).toString();
        obj["token_type"] = q.value(10).toString();
        obj["expires_in"] = q.value(11).toInt();
        obj["scope"] = q.value(12).toString();
        obj["captured_by"] = q.value(13).toString();
        result.append(obj);
    }

    return result;
}

bool SessionDBManager::deleteToken(qint64 tokenId)
{
    if (!initMainDB()) {
        qWarning() << "[DB] deleteToken: failed to init main DB";
        return false;
    }

    QSqlQuery q(m_mainDb);
    q.prepare("DELETE FROM tokens WHERE id = ?");
    q.addBindValue(tokenId);

    if (!q.exec()) {
        qWarning() << "[DB] deleteToken failed:" << q.lastError().text();
        return false;
    }

    return true;
}

// ============================================================================
// Session state management
// ============================================================================

bool SessionDBManager::setSessionAlive(const QString &sessionId, bool alive)
{
    QMutexLocker locker(&m_mutex);
    if (!initMainDB()) return false;

    QSqlQuery q(m_mainDb);
    q.prepare("UPDATE sessions SET Alive=?, LastSeen=CURRENT_TIMESTAMP WHERE SessionID=?");
    q.addBindValue(alive ? 1 : 0);
    q.addBindValue(sessionId);

    if (!q.exec()) {
        qWarning() << "[DB] setSessionAlive failed:" << q.lastError().text();
        return false;
    }
    return true;
}

bool SessionDBManager::setSessionStatus(const QString &sessionId, const QString &status)
{
    QMutexLocker locker(&m_mutex);
    if (!initMainDB()) return false;

    QSqlQuery q(m_mainDb);
    q.prepare("UPDATE sessions SET Status=?, LastSeen=CURRENT_TIMESTAMP WHERE SessionID=?");
    q.addBindValue(status);
    q.addBindValue(sessionId);

    if (!q.exec()) {
        qWarning() << "[DB] setSessionStatus failed:" << q.lastError().text();
        return false;
    }
    return true;
}

bool SessionDBManager::removeSession(const QString &sessionId)
{
    if (!initMainDB()) return false;

    QSqlQuery q(m_mainDb);
    q.prepare("DELETE FROM sessions WHERE SessionID=?");
    q.addBindValue(sessionId);

    if (!q.exec()) {
        qWarning() << "[DB] removeSession failed:" << q.lastError().text();
        return false;
    }
    return true;
}

QJsonArray SessionDBManager::listSessions()
{
    QJsonArray arr;
    if (!initMainDB()) return arr;

    QSqlQuery q(m_mainDb);
    if (!q.exec("SELECT SessionID, User, TenantID, DefaultDomain, Resource, Status, Alive, CreatedAt, LastSeen, CreatedBy "
                "FROM sessions ORDER BY LastSeen DESC NULLS LAST, CreatedAt DESC")) {
        qWarning() << "[DB] listSessions failed:" << q.lastError().text();
        return arr;
    }

    while (q.next()) {
        QJsonObject row;
        row.insert("sessionId", q.value(0).toString());
        row.insert("user",      q.value(1).toString());
        row.insert("tenantId",  q.value(2).toString());
        row.insert("domain",    q.value(3).toString());
        row.insert("resource",  q.value(4).toString());
        row.insert("status",    q.value(5).toString());
        row.insert("alive",     q.value(6).toInt() == 1);
        row.insert("createdAt", q.value(7).toString());
        row.insert("lastSeen",  q.value(8).toString());
        row.insert("createdBy", q.value(9).toString());
        arr.append(row);
    }
    return arr;
}

QJsonObject SessionDBManager::getSessionInfo(const QString &sessionId)
{
    QJsonObject out;
    if (!initMainDB()) return out;

    QSqlQuery q(m_mainDb);
    q.prepare("SELECT SessionID, User, TenantID, DefaultDomain, Resource, Status, Alive "
              "FROM sessions WHERE SessionID=? LIMIT 1");
    q.addBindValue(sessionId);

    if (!q.exec()) {
        qWarning() << "[DB] getSessionInfo failed:" << q.lastError().text();
        return out;
    }

    if (q.next()) {
        out.insert("sessionId", q.value(0).toString());
        out.insert("user",      q.value(1).toString());
        out.insert("tenantId",  q.value(2).toString());
        out.insert("domain",    q.value(3).toString());
        out.insert("resource",  q.value(4).toString());
        out.insert("status",    q.value(5).toString());
        out.insert("alive",     q.value(6).toInt() == 1);
    }
    return out;
}

// ============================================================================
// Report data methods
// ============================================================================

QJsonArray SessionDBManager::getCommandHistory(const QString &sessionId)
{
    QJsonArray commands;

    // If sessionId is provided, get commands for that session only
    // Otherwise, get session IDs from the main database
    QStringList sessionDirs;

    if (!sessionId.isEmpty()) {
        sessionDirs << sessionId;
    } else {
        // Get valid session IDs from the sessions table instead of scanning all directories
        if (!initMainDB()) return commands;

        QSqlQuery q(m_mainDb);
        if (q.exec("SELECT SessionID FROM sessions")) {
            while (q.next()) {
                sessionDirs << q.value(0).toString();
            }
        }
    }

    for (const QString &sid : sessionDirs) {
        QString dbPath = QString("data/%1/sessions.db").arg(sid);
        if (!QFile::exists(dbPath)) continue;

        QString connName = QString("report-sess-%1").arg(sid);
        {
            QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connName);
            db.setDatabaseName(dbPath);

            if (!db.open()) {
                qWarning() << "[DB] getCommandHistory: failed to open" << dbPath;
                continue;
            }

            QSqlQuery q(db);
            // Try history_v2 first (newer format) - exclude large stdout/stderr for performance
            // Only include first 500 chars of output for report summary
            if (q.exec("SELECT id, timestamp, command, status, exit_code, "
                       "SUBSTR(stdout_text, 1, 500), SUBSTR(stderr_text, 1, 500), duration_ms, run_by "
                       "FROM history_v2 ORDER BY timestamp ASC LIMIT 1000")) {
                while (q.next()) {
                    QJsonObject cmd;
                    cmd.insert("id", q.value(0).toLongLong());
                    cmd.insert("session_id", sid);
                    cmd.insert("timestamp", q.value(1).toString());
                    cmd.insert("command", q.value(2).toString());
                    cmd.insert("status", q.value(3).toString());
                    cmd.insert("exit_code", q.value(4).toInt());
                    QString stdout_text = q.value(5).toString();
                    QString stderr_text = q.value(6).toString();
                    if (stdout_text.length() >= 500) stdout_text += "...";
                    if (stderr_text.length() >= 500) stderr_text += "...";
                    cmd.insert("stdout", stdout_text);
                    cmd.insert("stderr", stderr_text);
                    cmd.insert("duration_ms", q.value(7).toLongLong());
                    cmd.insert("run_by", q.value(8).toString());
                    commands.append(cmd);
                }
            } else {
                // Fallback to old history table
                if (q.exec("SELECT id, timestamp, command, SUBSTR(output, 1, 500) "
                           "FROM history ORDER BY timestamp ASC LIMIT 1000")) {
                    while (q.next()) {
                        QJsonObject cmd;
                        cmd.insert("id", q.value(0).toLongLong());
                        cmd.insert("session_id", sid);
                        cmd.insert("timestamp", q.value(1).toString());
                        cmd.insert("command", q.value(2).toString());
                        QString output = q.value(3).toString();
                        if (output.length() >= 500) output += "...";
                        cmd.insert("stdout", output);
                        commands.append(cmd);
                    }
                }
            }

            db.close();
        }
        QSqlDatabase::removeDatabase(connName);
    }

    return commands;
}

QJsonObject SessionDBManager::getReportData(const QDateTime &startDate, const QDateTime &endDate)
{
    QJsonObject report;

    // Get all sessions
    QJsonArray sessions = listSessions();
    report.insert("sessions", sessions);

    // Get all tokens
    QJsonArray tokens = getAllTokens();
    report.insert("tokens", tokens);

    // Get all command history
    QJsonArray commands = getCommandHistory();
    report.insert("commands", commands);

    // Calculate unique users and tenants
    QSet<QString> uniqueUsers;
    QSet<QString> uniqueTenants;

    for (const QJsonValue &sessVal : sessions) {
        QJsonObject sess = sessVal.toObject();
        QString user = sess.value("user").toString();
        QString tenant = sess.value("tenantId").toString();
        if (!user.isEmpty() && user != "Unknown") uniqueUsers.insert(user);
        if (!tenant.isEmpty() && tenant != "N/A") uniqueTenants.insert(tenant);
    }

    for (const QJsonValue &tokVal : tokens) {
        QJsonObject tok = tokVal.toObject();
        QString user = tok.value("user").toString();
        QString tenant = tok.value("tenant_id").toString();
        if (!user.isEmpty()) uniqueUsers.insert(user);
        if (!tenant.isEmpty()) uniqueTenants.insert(tenant);
    }

    // Build unique users/tenants arrays
    QJsonArray usersArray;
    for (const QString &u : uniqueUsers) usersArray.append(u);
    report.insert("unique_users", usersArray);

    QJsonArray tenantsArray;
    for (const QString &t : uniqueTenants) tenantsArray.append(t);
    report.insert("unique_tenants", tenantsArray);

    // Operators who took part (from session creators, token capturers, command runners).
    QSet<QString> operators;
    auto noteOp = [&operators](const QString &op) {
        if (!op.isEmpty() && op != QLatin1String("legacy") && op != QLatin1String("unknown"))
            operators.insert(op);
    };
    for (const QJsonValue &v : sessions) noteOp(v.toObject().value("createdBy").toString());
    for (const QJsonValue &v : tokens)   noteOp(v.toObject().value("captured_by").toString());
    for (const QJsonValue &v : commands) noteOp(v.toObject().value("run_by").toString());
    QJsonArray opsArray;
    for (const QString &o : operators) opsArray.append(o);
    report.insert("operators", opsArray);

    // Categorize techniques based on token sources
    QJsonObject techniques;
    int phishingCount = 0;
    int credentialCount = 0;
    int tokenLoginCount = 0;
    int ssoCount = 0;

    for (const QJsonValue &tokVal : tokens) {
        QJsonObject tok = tokVal.toObject();
        QString source = tok.value("source").toString().toLower();

        if (source.contains("device_code") || source.contains("consent") || source.contains("phish")) {
            phishingCount++;
        } else if (source.contains("credential") || source.contains("password")) {
            credentialCount++;
        } else if (source.contains("sso") || source.contains("cookie")) {
            ssoCount++;
        } else if (source.contains("token")) {
            tokenLoginCount++;
        }
    }

    techniques.insert("phishing", phishingCount);
    techniques.insert("credential_access", credentialCount);
    techniques.insert("token_theft", tokenLoginCount);
    techniques.insert("sso_abuse", ssoCount);
    report.insert("techniques", techniques);

    // Build timeline from all events
    QJsonArray timeline;

    // Add session events
    for (const QJsonValue &sessVal : sessions) {
        QJsonObject sess = sessVal.toObject();
        QJsonObject event;
        event.insert("timestamp", sess.value("createdAt").toString());
        event.insert("type", "session_created");
        event.insert("title", "Session Created");
        event.insert("description", QString("Session established for %1").arg(sess.value("user").toString()));
        event.insert("session_id", sess.value("sessionId").toString());
        timeline.append(event);
    }

    // Add token events
    for (const QJsonValue &tokVal : tokens) {
        QJsonObject tok = tokVal.toObject();
        QJsonObject event;
        event.insert("timestamp", tok.value("timestamp").toString());
        event.insert("type", "token_captured");
        event.insert("title", "Token Captured");
        event.insert("description", QString("Token captured via %1 for %2")
                     .arg(tok.value("source").toString())
                     .arg(tok.value("user").toString()));
        event.insert("session_id", tok.value("session_id").toString());
        timeline.append(event);
    }

    // Add command events (significant ones only)
    for (const QJsonValue &cmdVal : commands) {
        QJsonObject cmd = cmdVal.toObject();
        QString command = cmd.value("command").toString();

        // Only include significant commands in timeline
        if (command.contains("Connect-", Qt::CaseInsensitive) ||
            command.contains("Get-AzureAD", Qt::CaseInsensitive) ||
            command.contains("New-", Qt::CaseInsensitive) ||
            command.contains("Add-", Qt::CaseInsensitive) ||
            command.contains("Remove-", Qt::CaseInsensitive) ||
            command.contains("Set-", Qt::CaseInsensitive)) {

            QJsonObject event;
            event.insert("timestamp", cmd.value("timestamp").toString());
            event.insert("type", "command");
            event.insert("title", "Command Executed");
            event.insert("description", command.left(100));
            event.insert("session_id", cmd.value("session_id").toString());
            timeline.append(event);
        }
    }

    report.insert("timeline", timeline);

    // Summary stats
    QJsonObject summary;
    summary.insert("total_sessions", sessions.size());
    summary.insert("total_tokens", tokens.size());
    summary.insert("total_commands", commands.size());
    summary.insert("unique_users", uniqueUsers.size());
    summary.insert("unique_tenants", uniqueTenants.size());
    report.insert("summary", summary);

    return report;
}

// ============================================================================
// Paginated Query Methods
// ============================================================================

QJsonArray SessionDBManager::getTokensPaginated(int limit, int offset) {
    QJsonArray result;
    if (!initMainDB()) return result;

    QSqlQuery q(m_mainDb);
    q.prepare(
        "SELECT id, session_id, timestamp, source, user, tenant_id, resource, "
        "access_token, refresh_token, id_token, token_type, expires_in, scope "
        "FROM tokens ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    );
    q.addBindValue(limit);
    q.addBindValue(offset);

    if (!q.exec()) {
        qWarning() << "[DB] getTokensPaginated failed:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        QJsonObject obj;
        obj["id"] = q.value(0).toLongLong();
        obj["session_id"] = q.value(1).toString();
        obj["timestamp"] = q.value(2).toString();
        obj["source"] = q.value(3).toString();
        obj["user"] = q.value(4).toString();
        obj["tenant_id"] = q.value(5).toString();
        obj["resource"] = q.value(6).toString();
        obj["access_token"] = q.value(7).toString();
        obj["refresh_token"] = q.value(8).toString();
        obj["id_token"] = q.value(9).toString();
        obj["token_type"] = q.value(10).toString();
        obj["expires_in"] = q.value(11).toInt();
        obj["scope"] = q.value(12).toString();
        result.append(obj);
    }

    return result;
}

QJsonArray SessionDBManager::getTokensBySessionPaginated(const QString &sessionId, int limit, int offset) {
    QJsonArray result;
    if (!initMainDB()) return result;

    QSqlQuery q(m_mainDb);
    q.prepare(
        "SELECT id, session_id, timestamp, source, user, tenant_id, resource, "
        "access_token, refresh_token, id_token, token_type, expires_in, scope "
        "FROM tokens WHERE session_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    );
    q.addBindValue(sessionId);
    q.addBindValue(limit);
    q.addBindValue(offset);

    if (!q.exec()) {
        qWarning() << "[DB] getTokensBySessionPaginated failed:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        QJsonObject obj;
        obj["id"] = q.value(0).toLongLong();
        obj["session_id"] = q.value(1).toString();
        obj["timestamp"] = q.value(2).toString();
        obj["source"] = q.value(3).toString();
        obj["user"] = q.value(4).toString();
        obj["tenant_id"] = q.value(5).toString();
        obj["resource"] = q.value(6).toString();
        obj["access_token"] = q.value(7).toString();
        obj["refresh_token"] = q.value(8).toString();
        obj["id_token"] = q.value(9).toString();
        obj["token_type"] = q.value(10).toString();
        obj["expires_in"] = q.value(11).toInt();
        obj["scope"] = q.value(12).toString();
        result.append(obj);
    }

    return result;
}

QJsonArray SessionDBManager::getCommandHistoryPaginated(const QString &sessionId, int limit, int offset) {
    QJsonArray commands;

    // For single session, use direct SQL pagination
    if (!sessionId.isEmpty()) {
        QString dbPath = QString("data/%1/sessions.db").arg(sessionId);
        if (!QFile::exists(dbPath)) return commands;

        QString connName = QString("paginated-sess-%1").arg(sessionId);
        {
            QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connName);
            db.setDatabaseName(dbPath);

            if (db.open()) {
                QSqlQuery q(db);
                q.prepare("SELECT id, timestamp, command, status, exit_code, stdout_text, stderr_text, duration_ms "
                          "FROM history_v2 ORDER BY timestamp DESC LIMIT ? OFFSET ?");
                q.addBindValue(limit);
                q.addBindValue(offset);

                if (q.exec()) {
                    while (q.next()) {
                        QJsonObject cmd;
                        cmd.insert("id", q.value(0).toLongLong());
                        cmd.insert("session_id", sessionId);
                        cmd.insert("timestamp", q.value(1).toString());
                        cmd.insert("command", q.value(2).toString());
                        cmd.insert("status", q.value(3).toString());
                        cmd.insert("exit_code", q.value(4).toInt());
                        cmd.insert("stdout", q.value(5).toString());
                        cmd.insert("stderr", q.value(6).toString());
                        cmd.insert("duration_ms", q.value(7).toLongLong());
                        commands.append(cmd);
                    }
                }
                db.close();
            }
        }
        QSqlDatabase::removeDatabase(connName);
        return commands;
    }

    // For all sessions, collect all entries then apply pagination
    // (necessary for proper cross-database ordering)
    QDir dataDir("data");
    QStringList sessionDirs = dataDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);

    QList<QPair<QDateTime, QJsonObject>> allEntries;

    for (const QString &sid : sessionDirs) {
        QString dbPath = QString("data/%1/sessions.db").arg(sid);
        if (!QFile::exists(dbPath)) continue;

        QString connName = QString("paginated-sess-%1").arg(sid);
        {
            QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connName);
            db.setDatabaseName(dbPath);

            if (db.open()) {
                QSqlQuery q(db);
                // Fetch a reasonable batch from each session (offset + limit to ensure coverage)
                q.prepare("SELECT id, timestamp, command, status, exit_code, stdout_text, stderr_text, duration_ms "
                          "FROM history_v2 ORDER BY timestamp DESC LIMIT ?");
                q.addBindValue(offset + limit);

                if (q.exec()) {
                    while (q.next()) {
                        QJsonObject cmd;
                        cmd.insert("id", q.value(0).toLongLong());
                        cmd.insert("session_id", sid);
                        cmd.insert("timestamp", q.value(1).toString());
                        cmd.insert("command", q.value(2).toString());
                        cmd.insert("status", q.value(3).toString());
                        cmd.insert("exit_code", q.value(4).toInt());
                        cmd.insert("stdout", q.value(5).toString());
                        cmd.insert("stderr", q.value(6).toString());
                        cmd.insert("duration_ms", q.value(7).toLongLong());

                        QDateTime ts = QDateTime::fromString(q.value(1).toString(), Qt::ISODate);
                        allEntries.append(qMakePair(ts, cmd));
                    }
                }
                db.close();
            }
        }
        QSqlDatabase::removeDatabase(connName);
    }

    // Sort all entries by timestamp descending
    std::sort(allEntries.begin(), allEntries.end(),
              [](const QPair<QDateTime, QJsonObject> &a, const QPair<QDateTime, QJsonObject> &b) {
                  return a.first > b.first;
              });

    // Apply pagination
    int start = qMin(offset, allEntries.size());
    int end = qMin(offset + limit, allEntries.size());
    for (int i = start; i < end; ++i) {
        commands.append(allEntries[i].second);
    }

    return commands;
}

int SessionDBManager::getTotalTokenCount() {
    if (!initMainDB()) return 0;

    QSqlQuery q(m_mainDb);
    if (q.exec("SELECT COUNT(*) FROM tokens") && q.next()) {
        return q.value(0).toInt();
    }
    return 0;
}

int SessionDBManager::getTokenCountBySession(const QString &sessionId) {
    if (!initMainDB()) return 0;

    QSqlQuery q(m_mainDb);
    q.prepare("SELECT COUNT(*) FROM tokens WHERE session_id = ?");
    q.addBindValue(sessionId);

    if (q.exec() && q.next()) {
        return q.value(0).toInt();
    }
    return 0;
}
