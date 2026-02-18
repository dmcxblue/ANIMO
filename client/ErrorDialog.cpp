#include "ErrorDialog.h"
#include <QApplication>

ErrorDialog::ErrorDialog(QWidget *parent)
    : QDialog(parent),
      m_errorType(GenericError)
{
    setWindowTitle("Error");
    setMinimumWidth(500);
    setupUI();
}

void ErrorDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);

    // Top section: Icon + Title
    QHBoxLayout *headerLayout = new QHBoxLayout();
    m_iconLabel = new QLabel(this);
    m_iconLabel->setPixmap(style()->standardIcon(QStyle::SP_MessageBoxCritical).pixmap(48, 48));
    headerLayout->addWidget(m_iconLabel);

    m_titleLabel = new QLabel(this);
    QFont titleFont = m_titleLabel->font();
    titleFont.setPointSize(12);
    titleFont.setBold(true);
    m_titleLabel->setFont(titleFont);
    m_titleLabel->setWordWrap(true);
    headerLayout->addWidget(m_titleLabel, 1);
    mainLayout->addLayout(headerLayout);

    // Suggestion label
    m_suggestionLabel = new QLabel(this);
    m_suggestionLabel->setWordWrap(true);
    mainLayout->addWidget(m_suggestionLabel);

    // Details section (collapsible)
    m_detailsButton = new QPushButton("Show Details", this);
    m_detailsButton->setCheckable(true);
    connect(m_detailsButton, &QPushButton::toggled, this, &ErrorDialog::onShowDetailsToggled);
    mainLayout->addWidget(m_detailsButton);

    m_detailsText = new QTextEdit(this);
    m_detailsText->setReadOnly(true);
    m_detailsText->setFont(QFont("Consolas", 9));
    m_detailsText->setVisible(false);
    m_detailsText->setMaximumHeight(200);
    mainLayout->addWidget(m_detailsText);

    // Action buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    m_retryButton = new QPushButton("Retry", this);
    m_retryButton->setVisible(false);
    connect(m_retryButton, &QPushButton::clicked, this, &ErrorDialog::onRetryClicked);
    buttonLayout->addWidget(m_retryButton);

    m_reconnectButton = new QPushButton("Reconnect", this);
    m_reconnectButton->setVisible(false);
    connect(m_reconnectButton, &QPushButton::clicked, this, &ErrorDialog::onReconnectClicked);
    buttonLayout->addWidget(m_reconnectButton);

    m_refreshTokenButton = new QPushButton("Refresh Token", this);
    m_refreshTokenButton->setVisible(false);
    connect(m_refreshTokenButton, &QPushButton::clicked, this, &ErrorDialog::onRefreshTokenClicked);
    buttonLayout->addWidget(m_refreshTokenButton);

    m_closeButton = new QPushButton("Close", this);
    connect(m_closeButton, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(m_closeButton);

    mainLayout->addLayout(buttonLayout);
}

void ErrorDialog::setErrorType(ErrorType type) {
    m_errorType = type;
    m_iconLabel->setPixmap(getErrorIcon(type).pixmap(48, 48));

    // Show/hide action buttons based on error type
    m_retryButton->setVisible(type == NetworkError || type == GenericError);
    m_reconnectButton->setVisible(type == NetworkError);
    m_refreshTokenButton->setVisible(type == TokenExpiredError || type == AuthenticationError);

    if (m_errorTitle.isEmpty()) {
        m_titleLabel->setText(getDefaultTitle(type));
    }
    if (m_suggestionLabel->text().isEmpty()) {
        m_suggestionLabel->setText(getDefaultSuggestion(type));
    }
}

void ErrorDialog::setErrorTitle(const QString &title) {
    m_errorTitle = title;
    m_titleLabel->setText(title);
}

void ErrorDialog::setErrorDetails(const QString &details) {
    m_errorDetails = details;
    m_detailsText->setPlainText(details);
}

void ErrorDialog::setSuggestedActions(const QStringList &actions) {
    QString suggestion = "Suggested actions:\n";
    for (const QString &action : actions) {
        suggestion += "  • " + action + "\n";
    }
    m_suggestionLabel->setText(suggestion);
}

void ErrorDialog::onRetryClicked() {
    emit retryRequested();
    accept();
}

void ErrorDialog::onReconnectClicked() {
    emit reconnectRequested();
    accept();
}

void ErrorDialog::onRefreshTokenClicked() {
    emit refreshTokenRequested();
    accept();
}

void ErrorDialog::onShowDetailsToggled() {
    bool showDetails = m_detailsButton->isChecked();
    m_detailsText->setVisible(showDetails);
    m_detailsButton->setText(showDetails ? "Hide Details" : "Show Details");
    adjustSize();
}

QString ErrorDialog::getDefaultTitle(ErrorType type) const {
    switch (type) {
        case NetworkError:
            return "Network Connection Error";
        case AuthenticationError:
            return "Authentication Failed";
        case TokenExpiredError:
            return "Token Expired";
        case PowerShellError:
            return "PowerShell Command Error";
        case DatabaseError:
            return "Database Error";
        case GenericError:
        default:
            return "An Error Occurred";
    }
}

QString ErrorDialog::getDefaultSuggestion(ErrorType type) const {
    switch (type) {
        case NetworkError:
            return "The connection to the server was lost. Please check your network and try reconnecting.";
        case AuthenticationError:
            return "Authentication failed. Please verify your credentials and try again.";
        case TokenExpiredError:
            return "Your authentication token has expired. Please refresh your token or log in again.";
        case PowerShellError:
            return "The PowerShell command encountered an error. Check the details below for more information.";
        case DatabaseError:
            return "A database error occurred. Please check the error details and try again.";
        case GenericError:
        default:
            return "An unexpected error occurred. Please check the details below.";
    }
}

QIcon ErrorDialog::getErrorIcon(ErrorType type) const {
    switch (type) {
        case NetworkError:
            return style()->standardIcon(QStyle::SP_MessageBoxWarning);
        case AuthenticationError:
        case TokenExpiredError:
            return style()->standardIcon(QStyle::SP_MessageBoxQuestion);
        case PowerShellError:
        case DatabaseError:
        case GenericError:
        default:
            return style()->standardIcon(QStyle::SP_MessageBoxCritical);
    }
}

// Static convenience methods
void ErrorDialog::showNetworkError(QWidget *parent, const QString &details) {
    ErrorDialog dialog(parent);
    dialog.setErrorType(NetworkError);
    dialog.setErrorDetails(details);
    dialog.exec();
}

void ErrorDialog::showAuthenticationError(QWidget *parent, const QString &details) {
    ErrorDialog dialog(parent);
    dialog.setErrorType(AuthenticationError);
    dialog.setErrorDetails(details);
    dialog.exec();
}

void ErrorDialog::showTokenExpiredError(QWidget *parent, const QString &details) {
    ErrorDialog dialog(parent);
    dialog.setErrorType(TokenExpiredError);
    dialog.setErrorDetails(details);
    dialog.exec();
}

void ErrorDialog::showPowerShellError(QWidget *parent, const QString &details) {
    ErrorDialog dialog(parent);
    dialog.setErrorType(PowerShellError);
    dialog.setErrorDetails(details);
    dialog.exec();
}

void ErrorDialog::showDatabaseError(QWidget *parent, const QString &details) {
    ErrorDialog dialog(parent);
    dialog.setErrorType(DatabaseError);
    dialog.setErrorDetails(details);
    dialog.exec();
}

void ErrorDialog::showGenericError(QWidget *parent, const QString &title, const QString &details) {
    ErrorDialog dialog(parent);
    dialog.setErrorType(GenericError);
    dialog.setErrorTitle(title);
    dialog.setErrorDetails(details);
    dialog.exec();
}
