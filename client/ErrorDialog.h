#pragma once

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QString>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QStyle>

/**
 * User-friendly error dialog with suggested actions
 * Displays error messages with severity icons and actionable buttons
 */
class ErrorDialog : public QDialog {
    Q_OBJECT

public:
    enum ErrorType {
        NetworkError,
        AuthenticationError,
        TokenExpiredError,
        PowerShellError,
        DatabaseError,
        GenericError
    };

    explicit ErrorDialog(QWidget *parent = nullptr);

    // Static convenience methods
    static void showNetworkError(QWidget *parent, const QString &details);
    static void showAuthenticationError(QWidget *parent, const QString &details);
    static void showTokenExpiredError(QWidget *parent, const QString &details);
    static void showPowerShellError(QWidget *parent, const QString &details);
    static void showDatabaseError(QWidget *parent, const QString &details);
    static void showGenericError(QWidget *parent, const QString &title, const QString &details);

    // Instance methods
    void setErrorType(ErrorType type);
    void setErrorTitle(const QString &title);
    void setErrorDetails(const QString &details);
    void setSuggestedActions(const QStringList &actions);

signals:
    void retryRequested();
    void reconnectRequested();
    void refreshTokenRequested();

private slots:
    void onRetryClicked();
    void onReconnectClicked();
    void onRefreshTokenClicked();
    void onShowDetailsToggled();

private:
    void setupUI();
    QString getDefaultTitle(ErrorType type) const;
    QString getDefaultSuggestion(ErrorType type) const;
    QIcon getErrorIcon(ErrorType type) const;

    ErrorType m_errorType;
    QString m_errorTitle;
    QString m_errorDetails;

    // UI Components
    QLabel *m_iconLabel;
    QLabel *m_titleLabel;
    QLabel *m_suggestionLabel;
    QTextEdit *m_detailsText;
    QPushButton *m_detailsButton;
    QPushButton *m_retryButton;
    QPushButton *m_reconnectButton;
    QPushButton *m_refreshTokenButton;
    QPushButton *m_closeButton;
};
