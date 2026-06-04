#ifndef CONFIG_H
#define CONFIG_H

#include <QString>
#include <QSettings>

/**
 * Centralized configuration for ANIMO
 * Provides type-safe access to timeouts, limits, and other configurable values
 * Values can be overridden via QSettings or environment variables
 */
class Config {
public:
    // Singleton access
    static Config& instance();

    // Network timeouts (milliseconds)
    int socketConnectTimeoutMs() const { return m_socketConnectTimeoutMs; }
    int loginTimeoutMs() const { return m_loginTimeoutMs; }
    int httpRequestTimeoutMs() const { return m_httpRequestTimeoutMs; }
    int processStartTimeoutMs() const { return m_processStartTimeoutMs; }
    int sprayRequestTimeoutMs() const { return m_sprayRequestTimeoutMs; }

    // Database settings
    int dbBusyTimeoutMs() const { return m_dbBusyTimeoutMs; }
    int dbQueryPageSize() const { return m_dbQueryPageSize; }

    // UI settings
    int tokenExpiryWarningMinutes() const { return m_tokenExpiryWarningMinutes; }
    int sessionRefreshIntervalMs() const { return m_sessionRefreshIntervalMs; }
    int maxEmailHtmlBytes() const { return m_maxEmailHtmlBytes; }

    // Azure/Microsoft settings
    QString defaultClientId() const { return m_defaultClientId; }

    // Reconnection settings
    int maxReconnectAttempts() const { return m_maxReconnectAttempts; }
    int reconnectDelayMs() const { return m_reconnectDelayMs; }

    // Buffer sizes
    int outputBufferMaxSize() const { return m_outputBufferMaxSize; }

    // Load settings from QSettings (call once at startup)
    void loadFromSettings();

    // Save current settings
    void saveToSettings();

    // Setters (for runtime configuration)
    void setSocketConnectTimeoutMs(int ms) { m_socketConnectTimeoutMs = qBound(1000, ms, 120000); }
    void setLoginTimeoutMs(int ms) { m_loginTimeoutMs = qBound(1000, ms, 120000); }
    void setDefaultClientId(const QString &id) { m_defaultClientId = id; }
    void setTokenExpiryWarningMinutes(int mins) { m_tokenExpiryWarningMinutes = qBound(1, mins, 1440); }
    void setDbQueryPageSize(int size) { m_dbQueryPageSize = qBound(10, size, 10000); }
    void setMaxEmailHtmlBytes(int bytes) { m_maxEmailHtmlBytes = qBound(1024, bytes, 10485760); }

private:
    Config();
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    // Network timeouts
    int m_socketConnectTimeoutMs = 3000;
    int m_loginTimeoutMs = 5000;
    int m_httpRequestTimeoutMs = 10000;
    int m_processStartTimeoutMs = 4000;
    int m_sprayRequestTimeoutMs = 8000;

    // Database
    int m_dbBusyTimeoutMs = 5000;
    int m_dbQueryPageSize = 100;

    // UI
    int m_tokenExpiryWarningMinutes = 15;
    int m_sessionRefreshIntervalMs = 30000;
    int m_maxEmailHtmlBytes = 1048576; // 1MB

    // Azure
    QString m_defaultClientId = "1950a258-227b-4e31-a9cf-717495945fc2";

    // Reconnection
    int m_maxReconnectAttempts = 5;
    int m_reconnectDelayMs = 5000;

    // Buffers
    int m_outputBufferMaxSize = 1048576; // 1MB
};

// Convenience macro for quick access
#define APP_CONFIG Config::instance()

#endif // CONFIG_H
