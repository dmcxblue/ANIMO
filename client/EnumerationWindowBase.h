#ifndef ENUMERATIONWINDOWBASE_H
#define ENUMERATIONWINDOWBASE_H

#include <QWidget>
#include <atomic>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QProgressBar>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QElapsedTimer>
#include <QTimer>

class UserSelectorWidget;

/**
 * Base class for enumeration windows that provides common UI elements and functionality:
 * - User selector widget
 * - Token input with status indicator
 * - Auto-fetch token button
 * - Progress bar with elapsed time display
 * - Log output area
 * - Cancel button with request tracking
 *
 * Subclasses should:
 * 1. Call setupBaseUi() in their setupUi() method
 * 2. Add their custom controls to mainLayout
 * 3. Override onStartOperation() and onCancelOperation() as needed
 */
class EnumerationWindowBase : public QWidget {
    Q_OBJECT

public:
    explicit EnumerationWindowBase(QWidget *parent = nullptr);
    virtual ~EnumerationWindowBase();

protected:
    // UI Components available to subclasses
    QVBoxLayout *mainLayout;
    UserSelectorWidget *userSelector;
    QLineEdit *tokenInput;
    QLabel *tokenStatus;
    QPushButton *autoFetchBtn;
    QPushButton *cancelBtn;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QLabel *elapsedTimeLabel;
    QLabel *statsLabel;
    QNetworkAccessManager *net;

    // Request tracking
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
    bool operationInProgress;

    // Setup the base UI elements (call from subclass setupUi)
    void setupBaseUi(const QString &tokenGroupTitle = "Microsoft Graph Token",
                     const QString &tokenPlaceholder = "Paste access token for https://graph.microsoft.com",
                     const QString &permissionNote = QString());

    // Add the log output and progress bar at the bottom (call after adding custom controls)
    void setupBottomUi();

    // Create a standard bearer request with timeout
    QNetworkRequest createBearerRequest(const QString &url, const QString &token, int timeoutMs = 10000);

    // Logging helpers
    void appendLog(const QString &msg, const QString &color = "white");
    void logInfo(const QString &msg);
    void logSuccess(const QString &msg);
    void logWarning(const QString &msg);
    void logError(const QString &msg);

    // Loading state management
    void setLoading(bool loading);
    void updateProgress(int current, int total);
    void resetProgress();

    // Token validation (warns on audience mismatch but lets user proceed)
    bool validateToken(const QString &token, const QString &requiredAudience = QString());
    QString getToken() const;

    // Target resource for auto-fetch (subclasses can override)
    void setTargetResource(const QString &resource) { m_targetResource = resource; }

    // Request tracking
    void trackReply(QNetworkReply *reply);
    void untrackReply(QNetworkReply *reply);
    void abortAllRequests();

    // Override these in subclasses for custom behavior
    virtual void onStartOperation() {}
    virtual void onCancelOperation() {}
    virtual void onOperationComplete() {}
    virtual QList<QPushButton*> getOperationButtons() { return {}; }

protected slots:
    void onUserChanged(const QString &upn);
    void autoFetchTokens();
    void updateTokenStatus();
    void cancelRequests();

private slots:
    void updateElapsedTime();

private:
    QElapsedTimer elapsedTimer;
    QTimer *elapsedUpdateTimer;
    QString m_targetResource = QStringLiteral("https://graph.microsoft.com");
    QString formatElapsedTime(qint64 ms) const;
};

#endif // ENUMERATIONWINDOWBASE_H
