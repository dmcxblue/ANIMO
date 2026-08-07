#pragma once
#include <QString>
#include <QJsonObject>
#include <QJsonDocument>

namespace Protocol {

// Actions
static const char* ACTION_LOGIN       = "login";
static const char* ACTION_NEW_SESSION = "new_session";
static const char* ACTION_RUN_COMMAND = "run_command";
static const char* ACTION_REMOVE      = "remove_session";
static const char* ACTION_LIST        = "list_sessions";
static const char* ACTION_LOG_TOKEN      = "log_token";
static const char* ACTION_GET_TOKENS     = "get_tokens";
static const char* ACTION_DELETE_TOKEN   = "delete_token";
static const char* ACTION_GET_REPORT_DATA = "get_report_data";
static const char* ACTION_MFA_REQUIRED   = "mfa_required";
static const char* ACTION_IMPORT_SESSION = "import_session";  // Import session metadata
static const char* ACTION_LIST_OPERATORS = "list_operators";  // Operator roster (audit_log 'login' rows + live sockets)

// Fields
static const char* F_ACTION   = "action";
static const char* F_STATUS   = "status";
static const char* F_MESSAGE  = "message";
static const char* F_USERNAME = "username";
static const char* F_PASSWORD = "password";
static const char* F_IP       = "ip";
static const char* F_PORT     = "port";
static const char* F_RESOURCE = "resource";
static const char* F_SESSION  = "sessionId";
static const char* F_COMMAND  = "command";
static const char* F_OUTPUT   = "output";
static const char* F_CMD_ID   = "cmdId";      // Command correlation ID

// Status
static const char* STATUS_OK  = "ok";
static const char* STATUS_ERR = "error";

inline QByteArray toBytes(const QJsonObject &o) {
    QJsonDocument d(o);
    QByteArray b = d.toJson(QJsonDocument::Compact);
    b.append('\n'); // line-delimited
    return b;
}

inline QJsonObject makeLogin(const QString &user, const QString &pass) {
    QJsonObject o;
    o[F_ACTION] = ACTION_LOGIN;
    o[F_USERNAME] = user;
    o[F_PASSWORD] = pass;
    return o;
}

inline QJsonObject ok(const QString &message = QString()) {
    QJsonObject o;
    o[F_STATUS] = STATUS_OK;
    if (!message.isEmpty()) o[F_MESSAGE] = message;
    return o;
}

inline QJsonObject err(const QString &message) {
    QJsonObject o;
    o[F_STATUS] = STATUS_ERR;
    o[F_MESSAGE] = message;
    return o;
}

} // namespace Protocol
