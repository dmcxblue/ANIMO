#include "Config.h"
#include <QCoreApplication>

Config& Config::instance() {
    static Config config;
    return config;
}

Config::Config() {
    // Check environment variables for overrides (with validation)
    if (qEnvironmentVariableIsSet("ANIMO_CLIENT_ID")) {
        QString id = qEnvironmentVariable("ANIMO_CLIENT_ID").trimmed();
        if (!id.isEmpty()) {
            m_defaultClientId = id;
        }
    }

    if (qEnvironmentVariableIsSet("ANIMO_SOCKET_TIMEOUT")) {
        bool ok = false;
        int val = qEnvironmentVariable("ANIMO_SOCKET_TIMEOUT").toInt(&ok);
        if (ok && val >= 1000 && val <= 120000) {
            m_socketConnectTimeoutMs = val;
        } else {
            qWarning() << "[Config] Invalid ANIMO_SOCKET_TIMEOUT (must be 1000-120000ms), using default";
        }
    }

    if (qEnvironmentVariableIsSet("ANIMO_LOGIN_TIMEOUT")) {
        bool ok = false;
        int val = qEnvironmentVariable("ANIMO_LOGIN_TIMEOUT").toInt(&ok);
        if (ok && val >= 1000 && val <= 120000) {
            m_loginTimeoutMs = val;
        } else {
            qWarning() << "[Config] Invalid ANIMO_LOGIN_TIMEOUT (must be 1000-120000ms), using default";
        }
    }
}

void Config::loadFromSettings() {
    QSettings settings("ANIMO", "Config");

    // Network timeouts
    m_socketConnectTimeoutMs = settings.value("network/socketConnectTimeoutMs", m_socketConnectTimeoutMs).toInt();
    m_loginTimeoutMs = settings.value("network/loginTimeoutMs", m_loginTimeoutMs).toInt();
    m_httpRequestTimeoutMs = settings.value("network/httpRequestTimeoutMs", m_httpRequestTimeoutMs).toInt();
    m_processStartTimeoutMs = settings.value("network/processStartTimeoutMs", m_processStartTimeoutMs).toInt();
    m_sprayRequestTimeoutMs = settings.value("network/sprayRequestTimeoutMs", m_sprayRequestTimeoutMs).toInt();

    // Database
    m_dbBusyTimeoutMs = settings.value("database/busyTimeoutMs", m_dbBusyTimeoutMs).toInt();
    m_dbQueryPageSize = settings.value("database/queryPageSize", m_dbQueryPageSize).toInt();

    // UI
    m_tokenExpiryWarningMinutes = settings.value("ui/tokenExpiryWarningMinutes", m_tokenExpiryWarningMinutes).toInt();
    m_sessionRefreshIntervalMs = settings.value("ui/sessionRefreshIntervalMs", m_sessionRefreshIntervalMs).toInt();
    m_maxEmailHtmlBytes = settings.value("ui/maxEmailHtmlBytes", m_maxEmailHtmlBytes).toInt();

    // Azure
    QString clientId = settings.value("azure/defaultClientId", m_defaultClientId).toString();
    if (!clientId.isEmpty()) {
        m_defaultClientId = clientId;
    }

    // Reconnection
    m_maxReconnectAttempts = settings.value("network/maxReconnectAttempts", m_maxReconnectAttempts).toInt();
    m_reconnectDelayMs = settings.value("network/reconnectDelayMs", m_reconnectDelayMs).toInt();

    // Buffers
    m_outputBufferMaxSize = settings.value("buffers/outputBufferMaxSize", m_outputBufferMaxSize).toInt();
}

void Config::saveToSettings() {
    QSettings settings("ANIMO", "Config");

    // Network timeouts
    settings.setValue("network/socketConnectTimeoutMs", m_socketConnectTimeoutMs);
    settings.setValue("network/loginTimeoutMs", m_loginTimeoutMs);
    settings.setValue("network/httpRequestTimeoutMs", m_httpRequestTimeoutMs);
    settings.setValue("network/processStartTimeoutMs", m_processStartTimeoutMs);
    settings.setValue("network/sprayRequestTimeoutMs", m_sprayRequestTimeoutMs);

    // Database
    settings.setValue("database/busyTimeoutMs", m_dbBusyTimeoutMs);
    settings.setValue("database/queryPageSize", m_dbQueryPageSize);

    // UI
    settings.setValue("ui/tokenExpiryWarningMinutes", m_tokenExpiryWarningMinutes);
    settings.setValue("ui/sessionRefreshIntervalMs", m_sessionRefreshIntervalMs);
    settings.setValue("ui/maxEmailHtmlBytes", m_maxEmailHtmlBytes);

    // Azure
    settings.setValue("azure/defaultClientId", m_defaultClientId);

    // Reconnection
    settings.setValue("network/maxReconnectAttempts", m_maxReconnectAttempts);
    settings.setValue("network/reconnectDelayMs", m_reconnectDelayMs);

    // Buffers
    settings.setValue("buffers/outputBufferMaxSize", m_outputBufferMaxSize);

    settings.sync();
}
