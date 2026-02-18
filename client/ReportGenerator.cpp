#include "ReportGenerator.h"
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QDebug>

ReportGenerator::ReportGenerator()
    : m_title("ANIMO Engagement Report"),
      m_engagementName("Unnamed Engagement"),
      m_operatorName("Unknown"),
      m_clientName("Unknown"),
      m_startDate(QDateTime::currentDateTime()),
      m_endDate(QDateTime::currentDateTime())
{
}

void ReportGenerator::setTitle(const QString &title) {
    m_title = title;
}

void ReportGenerator::setEngagementName(const QString &name) {
    m_engagementName = name;
}

void ReportGenerator::setOperatorName(const QString &name) {
    m_operatorName = name;
}

void ReportGenerator::setClientName(const QString &name) {
    m_clientName = name;
}

void ReportGenerator::setDateRange(const QDateTime &start, const QDateTime &end) {
    m_startDate = start;
    m_endDate = end;
}

void ReportGenerator::addSessionData(const QJsonObject &session) {
    m_sessions.append(session);
}

void ReportGenerator::addSessions(const QJsonArray &sessions) {
    m_sessions = sessions;
}

void ReportGenerator::addCommandHistory(const QJsonArray &commands) {
    m_commands = commands;
}

void ReportGenerator::addTokens(const QJsonArray &tokens) {
    m_tokens = tokens;
}

void ReportGenerator::addTimeline(const QJsonArray &timeline) {
    m_timeline = timeline;
}

void ReportGenerator::addTechniques(const QJsonObject &techniques) {
    m_techniques = techniques;
}

void ReportGenerator::addUniqueUsers(const QJsonArray &users) {
    m_uniqueUsers = users;
}

void ReportGenerator::addUniqueTenants(const QJsonArray &tenants) {
    m_uniqueTenants = tenants;
}

QString ReportGenerator::generateHTML() const {
    QString html;
    html += "<!DOCTYPE html>\n<html>\n<head>\n";
    html += "<meta charset=\"UTF-8\">\n";
    html += "<title>" + m_title + "</title>\n";
    html += "<style>\n" + getCSS() + "\n</style>\n";
    html += "</head>\n<body>\n";

    html += generateHeader();
    html += generateSummarySection();
    html += generateTechniquesSection();
    html += generateUsersTenantsSection();
    html += generateSessionsSection();
    html += generateTokensSection();
    html += generateCommandsSection();
    html += generateTimelineSection();
    html += generateFooter();

    html += "</body>\n</html>";
    return html;
}

bool ReportGenerator::saveHTMLReport(const QString &filePath) const {
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Failed to open file for writing:" << filePath;
        return false;
    }

    QTextStream out(&file);
    out << generateHTML();
    file.close();

    qDebug() << "Report saved to:" << filePath;
    return true;
}

QString ReportGenerator::generateHeader() const {
    QString html;
    html += "<div class=\"header\">\n";
    html += "  <h1>" + m_title + "</h1>\n";
    html += "  <div class=\"subtitle\">" + m_engagementName + "</div>\n";
    html += "  <div class=\"meta\">\n";
    html += "    <p><strong>Operator:</strong> " + m_operatorName + "</p>\n";
    html += "    <p><strong>Client:</strong> " + m_clientName + "</p>\n";
    html += "    <p><strong>Period:</strong> " + m_startDate.toString("yyyy-MM-dd HH:mm")
            + " to " + m_endDate.toString("yyyy-MM-dd HH:mm") + "</p>\n";
    html += "    <p><strong>Generated:</strong> " + QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") + "</p>\n";
    html += "  </div>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateSummarySection() const {
    QString html;
    html += "<div class=\"section\">\n";
    html += "  <h2>Executive Summary</h2>\n";
    html += "  <div class=\"summary-grid\">\n";
    html += "    <div class=\"summary-card\">\n";
    html += "      <div class=\"card-value\">" + QString::number(m_sessions.size()) + "</div>\n";
    html += "      <div class=\"card-label\">Sessions Created</div>\n";
    html += "    </div>\n";
    html += "    <div class=\"summary-card\">\n";
    html += "      <div class=\"card-value\">" + QString::number(m_commands.size()) + "</div>\n";
    html += "      <div class=\"card-label\">Commands Executed</div>\n";
    html += "    </div>\n";
    html += "    <div class=\"summary-card\">\n";
    html += "      <div class=\"card-value\">" + QString::number(m_tokens.size()) + "</div>\n";
    html += "      <div class=\"card-label\">Tokens Captured</div>\n";
    html += "    </div>\n";
    html += "    <div class=\"summary-card\">\n";

    // Calculate phishing success rate
    int phishingTokens = 0;
    for (int i = 0; i < m_tokens.size(); ++i) {
        QJsonObject token = m_tokens[i].toObject();
        QString source = token.value("source").toString();
        if (source.contains("device_code") || source.contains("consent") || source.contains("sso_cookie")) {
            phishingTokens++;
        }
    }

    html += "      <div class=\"card-value\">" + QString::number(phishingTokens) + "</div>\n";
    html += "      <div class=\"card-label\">Phishing Successes</div>\n";
    html += "    </div>\n";
    html += "  </div>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateTechniquesSection() const {
    if (m_techniques.isEmpty()) {
        return "";
    }

    QString html;
    html += "<div class=\"section\">\n";
    html += "  <h2>Techniques Used</h2>\n";
    html += "  <div class=\"techniques-grid\">\n";

    // Phishing techniques
    int phishing = m_techniques.value("phishing").toInt();
    if (phishing > 0) {
        html += "    <div class=\"technique-card technique-phishing\">\n";
        html += "      <div class=\"technique-icon\">🎣</div>\n";
        html += "      <div class=\"technique-name\">Phishing</div>\n";
        html += "      <div class=\"technique-count\">" + QString::number(phishing) + " tokens</div>\n";
        html += "      <div class=\"technique-desc\">Device code phishing, consent grant attacks</div>\n";
        html += "    </div>\n";
    }

    // Credential access
    int credentials = m_techniques.value("credential_access").toInt();
    if (credentials > 0) {
        html += "    <div class=\"technique-card technique-credential\">\n";
        html += "      <div class=\"technique-icon\">🔑</div>\n";
        html += "      <div class=\"technique-name\">Credential Access</div>\n";
        html += "      <div class=\"technique-count\">" + QString::number(credentials) + " tokens</div>\n";
        html += "      <div class=\"technique-desc\">Password-based authentication</div>\n";
        html += "    </div>\n";
    }

    // Token theft
    int tokenTheft = m_techniques.value("token_theft").toInt();
    if (tokenTheft > 0) {
        html += "    <div class=\"technique-card technique-token\">\n";
        html += "      <div class=\"technique-icon\">🎫</div>\n";
        html += "      <div class=\"technique-name\">Token Theft</div>\n";
        html += "      <div class=\"technique-count\">" + QString::number(tokenTheft) + " tokens</div>\n";
        html += "      <div class=\"technique-desc\">Direct token capture and reuse</div>\n";
        html += "    </div>\n";
    }

    // SSO abuse
    int sso = m_techniques.value("sso_abuse").toInt();
    if (sso > 0) {
        html += "    <div class=\"technique-card technique-sso\">\n";
        html += "      <div class=\"technique-icon\">🍪</div>\n";
        html += "      <div class=\"technique-name\">SSO Abuse</div>\n";
        html += "      <div class=\"technique-count\">" + QString::number(sso) + " tokens</div>\n";
        html += "      <div class=\"technique-desc\">SSO cookie theft and reuse</div>\n";
        html += "    </div>\n";
    }

    html += "  </div>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateUsersTenantsSection() const {
    if (m_uniqueUsers.isEmpty() && m_uniqueTenants.isEmpty()) {
        return "";
    }

    QString html;
    html += "<div class=\"section\">\n";
    html += "  <h2>Compromised Identities</h2>\n";
    html += "  <div class=\"identity-grid\">\n";

    // Users section
    if (!m_uniqueUsers.isEmpty()) {
        html += "    <div class=\"identity-card\">\n";
        html += "      <h3>Users (" + QString::number(m_uniqueUsers.size()) + ")</h3>\n";
        html += "      <ul class=\"identity-list\">\n";
        for (int i = 0; i < m_uniqueUsers.size() && i < 20; ++i) {
            html += "        <li>" + m_uniqueUsers[i].toString() + "</li>\n";
        }
        if (m_uniqueUsers.size() > 20) {
            html += "        <li class=\"more\">... and " + QString::number(m_uniqueUsers.size() - 20) + " more</li>\n";
        }
        html += "      </ul>\n";
        html += "    </div>\n";
    }

    // Tenants section
    if (!m_uniqueTenants.isEmpty()) {
        html += "    <div class=\"identity-card\">\n";
        html += "      <h3>Tenants (" + QString::number(m_uniqueTenants.size()) + ")</h3>\n";
        html += "      <ul class=\"identity-list\">\n";
        for (int i = 0; i < m_uniqueTenants.size() && i < 10; ++i) {
            html += "        <li>" + m_uniqueTenants[i].toString() + "</li>\n";
        }
        if (m_uniqueTenants.size() > 10) {
            html += "        <li class=\"more\">... and " + QString::number(m_uniqueTenants.size() - 10) + " more</li>\n";
        }
        html += "      </ul>\n";
        html += "    </div>\n";
    }

    html += "  </div>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateSessionsSection() const {
    if (m_sessions.isEmpty()) {
        return "";
    }

    QString html;
    html += "<div class=\"section\">\n";
    html += "  <h2>Sessions</h2>\n";
    html += "  <table>\n";
    html += "    <thead>\n";
    html += "      <tr>\n";
    html += "        <th>Session ID</th>\n";
    html += "        <th>User</th>\n";
    html += "        <th>Tenant ID</th>\n";
    html += "        <th>Resource</th>\n";
    html += "        <th>Created</th>\n";
    html += "      </tr>\n";
    html += "    </thead>\n";
    html += "    <tbody>\n";

    for (int i = 0; i < m_sessions.size(); ++i) {
        QJsonObject session = m_sessions[i].toObject();
        html += "      <tr>\n";
        html += "        <td>" + session.value("sessionId").toString() + "</td>\n";
        html += "        <td>" + session.value("user").toString() + "</td>\n";
        html += "        <td>" + session.value("tenantId").toString() + "</td>\n";
        html += "        <td>" + session.value("resource").toString() + "</td>\n";
        html += "        <td>" + session.value("createdAt").toString() + "</td>\n";
        html += "      </tr>\n";
    }

    html += "    </tbody>\n";
    html += "  </table>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateTokensSection() const {
    if (m_tokens.isEmpty()) {
        return "";
    }

    QString html;
    html += "<div class=\"section\">\n";
    html += "  <h2>Captured Tokens</h2>\n";
    html += "  <table>\n";
    html += "    <thead>\n";
    html += "      <tr>\n";
    html += "        <th>Timestamp</th>\n";
    html += "        <th>Source</th>\n";
    html += "        <th>User</th>\n";
    html += "        <th>Tenant ID</th>\n";
    html += "        <th>Resource</th>\n";
    html += "        <th>Has Refresh</th>\n";
    html += "      </tr>\n";
    html += "    </thead>\n";
    html += "    <tbody>\n";

    for (int i = 0; i < m_tokens.size(); ++i) {
        QJsonObject token = m_tokens[i].toObject();
        QString hasRefresh = token.value("refresh_token").toString().isEmpty() ? "No" : "Yes";

        html += "      <tr>\n";
        html += "        <td>" + token.value("timestamp").toString() + "</td>\n";
        html += "        <td>" + token.value("source").toString() + "</td>\n";
        html += "        <td>" + token.value("user").toString() + "</td>\n";
        html += "        <td>" + token.value("tenant_id").toString() + "</td>\n";
        html += "        <td>" + token.value("resource").toString() + "</td>\n";
        html += "        <td>" + hasRefresh + "</td>\n";
        html += "      </tr>\n";
    }

    html += "    </tbody>\n";
    html += "  </table>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateCommandsSection() const {
    if (m_commands.isEmpty()) {
        return "";
    }

    QString html;
    html += "<div class=\"section\">\n";
    html += "  <h2>Command History</h2>\n";
    html += "  <div class=\"command-list\">\n";

    for (int i = 0; i < m_commands.size(); ++i) {
        QJsonObject cmd = m_commands[i].toObject();
        html += "    <div class=\"command-entry\">\n";
        html += "      <div class=\"command-header\">\n";
        html += "        <span class=\"command-time\">" + cmd.value("timestamp").toString() + "</span>\n";
        html += "        <span class=\"command-session\">Session: " + cmd.value("session_id").toString() + "</span>\n";
        html += "      </div>\n";
        html += "      <div class=\"command-text\">" + cmd.value("command").toString() + "</div>\n";
        html += "    </div>\n";
    }

    html += "  </div>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateTimelineSection() const {
    if (m_timeline.isEmpty()) {
        return "";
    }

    QString html;
    html += "<div class=\"section\">\n";
    html += "  <h2>Timeline</h2>\n";
    html += "  <div class=\"timeline\">\n";

    for (int i = 0; i < m_timeline.size(); ++i) {
        QJsonObject event = m_timeline[i].toObject();
        QString eventType = event.value("type").toString();
        QString className = "timeline-item";

        if (eventType == "token_captured") {
            className += " timeline-success";
        } else if (eventType == "command") {
            className += " timeline-info";
        } else if (eventType == "session_created") {
            className += " timeline-primary";
        }

        html += "    <div class=\"" + className + "\">\n";
        html += "      <div class=\"timeline-marker\"></div>\n";
        html += "      <div class=\"timeline-content\">\n";
        html += "        <div class=\"timeline-time\">" + event.value("timestamp").toString() + "</div>\n";
        html += "        <div class=\"timeline-title\">" + event.value("title").toString() + "</div>\n";
        html += "        <div class=\"timeline-description\">" + event.value("description").toString() + "</div>\n";
        html += "      </div>\n";
        html += "    </div>\n";
    }

    html += "  </div>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateFooter() const {
    QString html;
    html += "<div class=\"footer\">\n";
    html += "  <p>Generated by ANIMO - Azure Sessions Management Platform</p>\n";
    html += "  <p class=\"disclaimer\">This report contains sensitive information. Handle with care.</p>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::getCSS() const {
    return R"(
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 20px;
    color: #333;
}

.header {
    background: white;
    padding: 30px;
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.header h1 {
    color: #667eea;
    font-size: 32px;
    margin-bottom: 10px;
}

.subtitle {
    font-size: 20px;
    color: #666;
    margin-bottom: 20px;
}

.meta {
    border-top: 2px solid #eee;
    padding-top: 15px;
    margin-top: 15px;
}

.meta p {
    margin: 5px 0;
    color: #555;
}

.section {
    background: white;
    padding: 25px;
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.section h2 {
    color: #667eea;
    font-size: 24px;
    margin-bottom: 20px;
    border-bottom: 2px solid #667eea;
    padding-bottom: 10px;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.summary-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 25px;
    border-radius: 8px;
    text-align: center;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.card-value {
    font-size: 48px;
    font-weight: bold;
    margin-bottom: 10px;
}

.card-label {
    font-size: 14px;
    opacity: 0.9;
    text-transform: uppercase;
    letter-spacing: 1px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

thead {
    background: #667eea;
    color: white;
}

th {
    padding: 12px;
    text-align: left;
    font-weight: 600;
}

td {
    padding: 10px 12px;
    border-bottom: 1px solid #eee;
}

tbody tr:hover {
    background: #f5f5f5;
}

.command-list {
    margin-top: 15px;
}

.command-entry {
    background: #f9f9f9;
    border-left: 4px solid #667eea;
    padding: 15px;
    margin-bottom: 10px;
    border-radius: 4px;
}

.command-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
    font-size: 12px;
    color: #666;
}

.command-text {
    font-family: 'Consolas', 'Courier New', monospace;
    background: white;
    padding: 10px;
    border-radius: 4px;
    font-size: 13px;
}

.timeline {
    position: relative;
    padding-left: 40px;
    margin-top: 20px;
}

.timeline-item {
    position: relative;
    padding-bottom: 30px;
}

.timeline-marker {
    position: absolute;
    left: -32px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: #667eea;
    border: 3px solid white;
    box-shadow: 0 0 0 2px #667eea;
}

.timeline-item::before {
    content: '';
    position: absolute;
    left: -25px;
    top: 16px;
    bottom: -16px;
    width: 2px;
    background: #ddd;
}

.timeline-item:last-child::before {
    display: none;
}

.timeline-success .timeline-marker {
    background: #10b981;
    box-shadow: 0 0 0 2px #10b981;
}

.timeline-info .timeline-marker {
    background: #3b82f6;
    box-shadow: 0 0 0 2px #3b82f6;
}

.timeline-primary .timeline-marker {
    background: #8b5cf6;
    box-shadow: 0 0 0 2px #8b5cf6;
}

.timeline-content {
    background: #f9f9f9;
    padding: 15px;
    border-radius: 6px;
}

.timeline-time {
    font-size: 12px;
    color: #666;
    margin-bottom: 5px;
}

.timeline-title {
    font-weight: 600;
    margin-bottom: 5px;
    color: #333;
}

.timeline-description {
    font-size: 14px;
    color: #666;
}

.techniques-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.technique-card {
    background: white;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    border: 2px solid #eee;
    transition: transform 0.2s;
}

.technique-card:hover {
    transform: translateY(-2px);
}

.technique-icon {
    font-size: 48px;
    margin-bottom: 10px;
}

.technique-name {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 5px;
}

.technique-count {
    font-size: 24px;
    font-weight: bold;
    margin-bottom: 10px;
}

.technique-desc {
    font-size: 12px;
    color: #666;
}

.technique-phishing { border-color: #ef4444; }
.technique-phishing .technique-count { color: #ef4444; }

.technique-credential { border-color: #f59e0b; }
.technique-credential .technique-count { color: #f59e0b; }

.technique-token { border-color: #10b981; }
.technique-token .technique-count { color: #10b981; }

.technique-sso { border-color: #6366f1; }
.technique-sso .technique-count { color: #6366f1; }

.identity-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.identity-card {
    background: #f9f9f9;
    border-radius: 8px;
    padding: 20px;
}

.identity-card h3 {
    color: #667eea;
    margin-bottom: 15px;
    border-bottom: 2px solid #667eea;
    padding-bottom: 10px;
}

.identity-list {
    list-style: none;
    padding: 0;
}

.identity-list li {
    padding: 8px 12px;
    margin-bottom: 5px;
    background: white;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 13px;
}

.identity-list li.more {
    background: transparent;
    font-style: italic;
    color: #666;
}

.footer {
    background: white;
    padding: 20px;
    border-radius: 8px;
    text-align: center;
    color: #666;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.footer .disclaimer {
    margin-top: 10px;
    font-size: 12px;
    color: #999;
    font-style: italic;
}

@media print {
    body {
        background: white;
        padding: 0;
    }

    .section, .header, .footer {
        box-shadow: none;
        page-break-inside: avoid;
    }
}
)";
}

// ===== Static Export Methods =====

QString ReportGenerator::exportSessionsToJSON(const QJsonArray &sessions) {
    QJsonObject root;
    root.insert("export_type", "sessions");
    root.insert("export_date", QDateTime::currentDateTime().toString(Qt::ISODate));
    root.insert("count", sessions.size());
    root.insert("sessions", sessions);

    QJsonDocument doc(root);
    return doc.toJson(QJsonDocument::Indented);
}

QString ReportGenerator::exportTokensToJSON(const QJsonArray &tokens) {
    QJsonObject root;
    root.insert("export_type", "tokens");
    root.insert("export_date", QDateTime::currentDateTime().toString(Qt::ISODate));
    root.insert("count", tokens.size());
    root.insert("tokens", tokens);

    QJsonDocument doc(root);
    return doc.toJson(QJsonDocument::Indented);
}

QString ReportGenerator::exportCommandsToCSV(const QJsonArray &commands) {
    QString csv;
    csv += "Timestamp,Session ID,Command\n";

    for (int i = 0; i < commands.size(); ++i) {
        QJsonObject cmd = commands[i].toObject();
        QString timestamp = cmd.value("timestamp").toString();
        QString sessionId = cmd.value("session_id").toString();
        QString command = cmd.value("command").toString();

        // Escape quotes in command
        command.replace("\"", "\"\"");

        csv += QString("\"%1\",\"%2\",\"%3\"\n")
                   .arg(timestamp)
                   .arg(sessionId)
                   .arg(command);
    }

    return csv;
}

QString ReportGenerator::exportTokensToCSV(const QJsonArray &tokens) {
    QString csv;
    csv += "Timestamp,Source,User,Tenant ID,Resource,Has Refresh Token,Scope\n";

    for (int i = 0; i < tokens.size(); ++i) {
        QJsonObject token = tokens[i].toObject();
        QString timestamp = token.value("timestamp").toString();
        QString source = token.value("source").toString();
        QString user = token.value("user").toString();
        QString tenantId = token.value("tenant_id").toString();
        QString resource = token.value("resource").toString();
        QString hasRefresh = token.value("refresh_token").toString().isEmpty() ? "No" : "Yes";
        QString scope = token.value("scope").toString();

        csv += QString("\"%1\",\"%2\",\"%3\",\"%4\",\"%5\",\"%6\",\"%7\"\n")
                   .arg(timestamp)
                   .arg(source)
                   .arg(user)
                   .arg(tenantId)
                   .arg(resource)
                   .arg(hasRefresh)
                   .arg(scope);
    }

    return csv;
}
