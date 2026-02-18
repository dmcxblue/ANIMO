#include "ErrorLogger.h"
#include <QDir>
#include <QMutexLocker>

ErrorLogger& ErrorLogger::instance() {
    static ErrorLogger logger;
    return logger;
}

ErrorLogger::ErrorLogger()
    : m_logFilePath("data/error.log"),
      m_minSeverity(Info),  // Changed from Debug - only log Info and above by default
      m_consoleOutput(true)
{
    // Ensure data directory exists
    QDir dir("data");
    if (!dir.exists()) {
        dir.mkpath(".");
    }
}

ErrorLogger::~ErrorLogger() {
    // Nothing to clean up
}

void ErrorLogger::log(Severity severity, const QString &component, const QString &message) {
    if (severity < m_minSeverity) {
        return;
    }

    QMutexLocker locker(&m_mutex);

    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz");
    QString severityStr = severityToString(severity);
    QString logLine = QString("[%1] [%2] [%3] %4")
                          .arg(timestamp)
                          .arg(severityStr)
                          .arg(component)
                          .arg(message);

    // Write to console if enabled
    if (m_consoleOutput) {
        switch (severity) {
            case Debug:
                qDebug().noquote() << logLine;
                break;
            case Info:
                qInfo().noquote() << logLine;
                break;
            case Warning:
                qWarning().noquote() << logLine;
                break;
            case Error:
            case Critical:
                qCritical().noquote() << logLine;
                break;
        }
    }

    // Write to file
    writeToFile(logLine);
}

void ErrorLogger::logDebug(const QString &component, const QString &message) {
    log(Debug, component, message);
}

void ErrorLogger::logInfo(const QString &component, const QString &message) {
    log(Info, component, message);
}

void ErrorLogger::logWarning(const QString &component, const QString &message) {
    log(Warning, component, message);
}

void ErrorLogger::logError(const QString &component, const QString &message) {
    log(Error, component, message);
}

void ErrorLogger::logCritical(const QString &component, const QString &message) {
    log(Critical, component, message);
}

void ErrorLogger::setLogFile(const QString &filePath) {
    QMutexLocker locker(&m_mutex);
    m_logFilePath = filePath;
}

void ErrorLogger::setMinSeverity(Severity minSeverity) {
    QMutexLocker locker(&m_mutex);
    m_minSeverity = minSeverity;
}

void ErrorLogger::enableConsoleOutput(bool enable) {
    QMutexLocker locker(&m_mutex);
    m_consoleOutput = enable;
}

QString ErrorLogger::severityToString(Severity severity) const {
    switch (severity) {
        case Debug:    return "DEBUG";
        case Info:     return "INFO";
        case Warning:  return "WARN";
        case Error:    return "ERROR";
        case Critical: return "CRITICAL";
        default:       return "UNKNOWN";
    }
}

void ErrorLogger::rotateLogIfNeeded() {
    QFileInfo fi(m_logFilePath);
    if (!fi.exists() || fi.size() < MAX_LOG_SIZE) return;

    // Rotate: error.log.4 -> deleted, error.log.3 -> .4, ... error.log -> .1
    for (int i = MAX_LOG_FILES - 1; i >= 1; --i) {
        QString src = QString("%1.%2").arg(m_logFilePath).arg(i);
        QString dst = QString("%1.%2").arg(m_logFilePath).arg(i + 1);
        QFile::remove(dst);
        QFile::rename(src, dst);
    }
    QFile::rename(m_logFilePath, m_logFilePath + ".1");
}

void ErrorLogger::writeToFile(const QString &logLine) {
    rotateLogIfNeeded();
    QFile file(m_logFilePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&file);
        out << logLine << "\n";
        file.close();
    }
}
