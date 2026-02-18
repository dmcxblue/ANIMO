#pragma once
#include <QSqlDatabase>
#include <QString>
#include <QHash>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>

class SessionDBManager {
public:
    static SessionDBManager& instance();

    bool initMainDB();  // idempotent
    QSqlDatabase mainDb() const;  // getter

    bool addSessionToMainDB(const QString &sessionId,
                            const QString &user,
                            const QString &tenantId,
                            const QString &defaultDomain,
                            const QString &resource);
    bool updateSessionUser(const QString &sessionId, const QString &username);
    bool createSessionDB(const QString &sessionId);
    void updateSessionTenant(const QString &sessionId,
                             const QString &tenantId,
                             const QString &defaultDomain);

    // Session state management
    bool setSessionAlive(const QString &sessionId, bool alive);
    bool setSessionStatus(const QString &sessionId, const QString &status);
    bool removeSession(const QString &sessionId);
    QJsonArray listSessions();
    QJsonObject getSessionInfo(const QString &sessionId);

    // Report data methods
    QJsonObject getReportData(const QDateTime &startDate = QDateTime(),
                              const QDateTime &endDate = QDateTime());
    QJsonArray getCommandHistory(const QString &sessionId = QString());

    void insertCommandOutput(const QString &sessionId,
                             const QString &command,
                             const QString &output);
							 
	bool open(const QString& dbPath); // replace existing open/init if present
    bool ensureSchemaV2();
    bool migrateHistoryToV2(); // optional, safe to skip if you don't care about old rows

    // Token logging methods
    bool logToken(const QString &sessionId,
                  const QString &source,
                  const QString &accessToken,
                  const QString &refreshToken = QString(),
                  const QString &idToken = QString(),
                  const QString &user = QString(),
                  const QString &tenantId = QString(),
                  const QString &resource = QString(),
                  const QString &scope = QString(),
                  int expiresIn = 0);

    QJsonArray getTokensBySession(const QString &sessionId);
    QJsonArray getAllTokens();
    bool deleteToken(qint64 tokenId);

    // Paginated queries for better performance
    QJsonArray getTokensPaginated(int limit = 100, int offset = 0);
    QJsonArray getTokensBySessionPaginated(const QString &sessionId, int limit = 100, int offset = 0);
    QJsonArray getCommandHistoryPaginated(const QString &sessionId = QString(), int limit = 100, int offset = 0);
    int getTotalTokenCount();
    int getTokenCountBySession(const QString &sessionId);

private:
    SessionDBManager();
    ~SessionDBManager();
	bool execPragmas();
    static QString normalizeText(QString s); // CRLF→LF, strip NUL

    QSqlDatabase m_mainDb;
    QHash<QString, qint64> m_lastRowId;
};
