#pragma once

#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>

/**
 * Report generator for ANIMO engagements
 * Generates HTML reports with session data, commands, tokens, and timeline
 */
class ReportGenerator {
public:
    ReportGenerator();

    // Report configuration
    void setTitle(const QString &title);
    void setEngagementName(const QString &name);
    void setOperatorName(const QString &name);
    void setClientName(const QString &name);
    void setDateRange(const QDateTime &start, const QDateTime &end);

    // Data input
    void addSessionData(const QJsonObject &session);
    void addSessions(const QJsonArray &sessions);
    void addCommandHistory(const QJsonArray &commands);
    void addTokens(const QJsonArray &tokens);
    void addTimeline(const QJsonArray &timeline);
    void addTechniques(const QJsonObject &techniques);
    void addUniqueUsers(const QJsonArray &users);
    void addUniqueTenants(const QJsonArray &tenants);

    // Report generation
    QString generateHTML() const;
    bool saveHTMLReport(const QString &filePath) const;

    // Data export
    static QString exportSessionsToJSON(const QJsonArray &sessions);
    static QString exportTokensToJSON(const QJsonArray &tokens);
    static QString exportCommandsToCSV(const QJsonArray &commands);
    static QString exportTokensToCSV(const QJsonArray &tokens);

private:
    // Report metadata
    QString m_title;
    QString m_engagementName;
    QString m_operatorName;
    QString m_clientName;
    QDateTime m_startDate;
    QDateTime m_endDate;

    // Report data
    QJsonArray m_sessions;
    QJsonArray m_commands;
    QJsonArray m_tokens;
    QJsonArray m_timeline;
    QJsonObject m_techniques;
    QJsonArray m_uniqueUsers;
    QJsonArray m_uniqueTenants;

    // HTML generation helpers
    QString generateHeader() const;
    QString generateSummarySection() const;
    QString generateTechniquesSection() const;
    QString generateUsersTenantsSection() const;
    QString generateSessionsSection() const;
    QString generateCommandsSection() const;
    QString generateTokensSection() const;
    QString generateTimelineSection() const;
    QString generateFooter() const;
    QString getCSS() const;
};
