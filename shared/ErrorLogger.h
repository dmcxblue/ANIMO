#pragma once

#include <QString>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>
#include <QDebug>

/**
 * Centralized error logging service for ANIMO
 * Logs errors to file with timestamps and severity levels
 * Thread-safe singleton implementation
 */
class ErrorLogger {
public:
    enum Severity {
        Debug,
        Info,
        Warning,
        Error,
        Critical
    };

    // Singleton access
    static ErrorLogger& instance();

    // Logging methods
    void log(Severity severity, const QString &component, const QString &message);
    void logDebug(const QString &component, const QString &message);
    void logInfo(const QString &component, const QString &message);
    void logWarning(const QString &component, const QString &message);
    void logError(const QString &component, const QString &message);
    void logCritical(const QString &component, const QString &message);

    // Configuration
    void setLogFile(const QString &filePath);
    void setMinSeverity(Severity minSeverity);
    void enableConsoleOutput(bool enable);

private:
    ErrorLogger();
    ~ErrorLogger();
    ErrorLogger(const ErrorLogger&) = delete;
    ErrorLogger& operator=(const ErrorLogger&) = delete;

    QString severityToString(Severity severity) const;
    void writeToFile(const QString &logLine);
    void rotateLogIfNeeded();

    QString m_logFilePath;
    Severity m_minSeverity;
    bool m_consoleOutput;
    QMutex m_mutex;

    // Log rotation settings
    static constexpr qint64 MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
    static constexpr int MAX_LOG_FILES = 5;
};

// Convenience macros for logging
#define LOG_DEBUG(component, message) ErrorLogger::instance().logDebug(component, message)
#define LOG_INFO(component, message) ErrorLogger::instance().logInfo(component, message)
#define LOG_WARNING(component, message) ErrorLogger::instance().logWarning(component, message)
#define LOG_ERROR(component, message) ErrorLogger::instance().logError(component, message)
#define LOG_CRITICAL(component, message) ErrorLogger::instance().logCritical(component, message)
