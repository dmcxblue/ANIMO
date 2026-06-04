#include "EnumerationWindowBase.h"
#include "UserSelectorWidget.h"
#include "StyleManager.h"
#include "NetworkHelper.h"
#include "ErrorDialog.h"

#include <QSplitter>
#include <QMessageBox>

EnumerationWindowBase::EnumerationWindowBase(QWidget *parent)
    : QWidget(parent),
      mainLayout(nullptr),
      userSelector(nullptr),
      tokenInput(nullptr),
      tokenStatus(nullptr),
      autoFetchBtn(nullptr),
      cancelBtn(nullptr),
      logOutput(nullptr),
      progressBar(nullptr),
      elapsedTimeLabel(nullptr),
      statsLabel(nullptr),
      net(new QNetworkAccessManager(this)),
      cancelRequested(false),
      operationInProgress(false),
      elapsedUpdateTimer(new QTimer(this))
{
    setAttribute(Qt::WA_DeleteOnClose);

    connect(elapsedUpdateTimer, &QTimer::timeout, this, &EnumerationWindowBase::updateElapsedTime);
}

EnumerationWindowBase::~EnumerationWindowBase() {
    // Disconnect ALL network replies to prevent callbacks during destruction
    if (net) {
        const auto replies = net->findChildren<QNetworkReply*>();
        for (auto *r : replies) {
            r->disconnect();
            r->abort();
        }
    }
    activeReplies.clear();
}

void EnumerationWindowBase::setupBaseUi(const QString &tokenGroupTitle,
                                          const QString &tokenPlaceholder,
                                          const QString &permissionNote)
{
    mainLayout = new QVBoxLayout(this);

    // Token input group
    auto *tokenGroup = new QGroupBox(tokenGroupTitle, this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    // User selector
    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &EnumerationWindowBase::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &EnumerationWindowBase::appendLog);

    // Auto-fetch button row
    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &EnumerationWindowBase::autoFetchTokens);

    // Token input row
    auto *tokenRow = new QHBoxLayout();
    tokenInput = new QLineEdit(this);
    tokenInput->setPlaceholderText(tokenPlaceholder);
    tokenInput->setEchoMode(QLineEdit::Password);
    tokenRow->addWidget(tokenInput);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    tokenRow->addWidget(tokenStatus);
    tokenLayout->addLayout(tokenRow);

    // Permission note (optional)
    if (!permissionNote.isEmpty()) {
        auto *permLabel = new QLabel(QString("<i>%1</i>").arg(permissionNote), this);
        permLabel->setStyleSheet(StyleManager::permissionNoteStyle());
        tokenLayout->addWidget(permLabel);
    }

    mainLayout->addWidget(tokenGroup);

    updateTokenStatus();
}

void EnumerationWindowBase::setupBottomUi()
{
    // Stats label
    statsLabel = new QLabel("Ready", this);
    statsLabel->setStyleSheet("font-weight: bold; padding: 5px;");
    mainLayout->addWidget(statsLabel);

    // Progress bar row with elapsed time
    auto *progressLayout = new QHBoxLayout();

    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressLayout->addWidget(progressBar);

    elapsedTimeLabel = new QLabel(this);
    elapsedTimeLabel->setFixedWidth(100);
    elapsedTimeLabel->setVisible(false);
    elapsedTimeLabel->setStyleSheet("color: #888; font-size: 11px;");
    progressLayout->addWidget(elapsedTimeLabel);

    // Cancel button
    cancelBtn = new QPushButton("Cancel", this);
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    cancelBtn->setVisible(false);
    cancelBtn->setFixedWidth(80);
    progressLayout->addWidget(cancelBtn);
    connect(cancelBtn, &QPushButton::clicked, this, &EnumerationWindowBase::cancelRequests);

    mainLayout->addLayout(progressLayout);

    // Log output
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    mainLayout->addWidget(logOutput);
}

QNetworkRequest EnumerationWindowBase::createBearerRequest(const QString &url, const QString &token, int timeoutMs)
{
    QNetworkRequest req = NetworkHelper::createBearerRequest(url, token, timeoutMs);
    req.setRawHeader("ConsistencyLevel", "eventual");
    return req;
}

// ============================================================================
// Logging Helpers
// ============================================================================

void EnumerationWindowBase::appendLog(const QString &msg, const QString &color)
{
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg));
}

void EnumerationWindowBase::logInfo(const QString &msg)
{
    appendLog(QString("[*] %1").arg(msg), StyleManager::logInfoStyle());
}

void EnumerationWindowBase::logSuccess(const QString &msg)
{
    appendLog(QString("[+] %1").arg(msg), StyleManager::logSuccessStyle());
}

void EnumerationWindowBase::logWarning(const QString &msg)
{
    appendLog(QString("[!] %1").arg(msg), StyleManager::logWarningStyle());
}

void EnumerationWindowBase::logError(const QString &msg)
{
    appendLog(QString("[-] %1").arg(msg), StyleManager::logErrorStyle());
}

// ============================================================================
// Loading State Management
// ============================================================================

void EnumerationWindowBase::setLoading(bool loading)
{
    operationInProgress = loading;
    progressBar->setVisible(loading);
    elapsedTimeLabel->setVisible(loading);
    cancelBtn->setVisible(loading);
    cancelBtn->setEnabled(loading);
    autoFetchBtn->setEnabled(!loading);
    tokenInput->setEnabled(!loading);

    // Enable/disable operation buttons in subclass
    for (QPushButton *btn : getOperationButtons()) {
        if (btn) btn->setEnabled(!loading);
    }

    if (loading) {
        cancelRequested = false;
        elapsedTimer.start();
        elapsedUpdateTimer->start(1000);  // Update every second
        elapsedTimeLabel->setText("0:00");
    } else {
        elapsedUpdateTimer->stop();
        cancelRequested = false;
    }
}

void EnumerationWindowBase::updateProgress(int current, int total)
{
    if (total > 0) {
        progressBar->setRange(0, total);
        progressBar->setValue(current);
    } else {
        // Indeterminate
        progressBar->setRange(0, 0);
    }
}

void EnumerationWindowBase::resetProgress()
{
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
}

void EnumerationWindowBase::updateElapsedTime()
{
    qint64 elapsed = elapsedTimer.elapsed();
    elapsedTimeLabel->setText(formatElapsedTime(elapsed));
}

QString EnumerationWindowBase::formatElapsedTime(qint64 ms) const
{
    qint64 seconds = ms / 1000;
    qint64 minutes = seconds / 60;
    seconds = seconds % 60;

    if (minutes > 0) {
        return QString("%1:%2").arg(minutes).arg(seconds, 2, 10, QChar('0'));
    } else {
        return QString("0:%1").arg(seconds, 2, 10, QChar('0'));
    }
}

// ============================================================================
// Token Handling
// ============================================================================

bool EnumerationWindowBase::validateToken(const QString &token, const QString &requiredAudience)
{
    if (token.isEmpty()) {
        ErrorDialog::showAuthenticationError(this, "Please enter an access token.");
        return false;
    }

    if (!requiredAudience.isEmpty()) {
        QString audience = NetworkHelper::extractTokenAudience(token);
        if (!audience.contains(requiredAudience, Qt::CaseInsensitive)) {
            QString msg = QString("Token audience mismatch: this operation expects '%1' "
                                  "but your token is for '%2'.\n\n"
                                  "The API call may fail with a 401 error.\n"
                                  "Proceed anyway?")
                          .arg(requiredAudience, audience.isEmpty() ? "unknown" : audience);
            auto result = QMessageBox::warning(this, "Token Audience Mismatch",
                                               msg, QMessageBox::Yes | QMessageBox::No);
            if (result != QMessageBox::Yes) {
                return false;
            }
            logWarning(QString("Proceeding with mismatched token (expected %1, got %2)")
                       .arg(requiredAudience, audience));
        }
    }

    return true;
}

QString EnumerationWindowBase::getToken() const
{
    return tokenInput ? tokenInput->text().trimmed() : QString();
}

void EnumerationWindowBase::updateTokenStatus()
{
    QString token = getToken();
    if (token.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet(StyleManager::tokenStatusEmptyStyle());
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet(StyleManager::tokenStatusReadyStyle());
    }
}

void EnumerationWindowBase::onUserChanged(const QString &upn)
{
    if (tokenInput) tokenInput->clear();
    updateTokenStatus();
    logInfo(QString("Switched to user: %1").arg(upn));
}

void EnumerationWindowBase::autoFetchTokens()
{
    if (!userSelector || !userSelector->hasSelection()) {
        logError("Please select a user first");
        return;
    }

    // Derive a short label from the resource URL for log messages
    QString label = m_targetResource;
    if (label.contains("graph.microsoft.com")) label = "Graph";
    else if (label.contains("management.azure.com")) label = "Management";
    else if (label.contains("vault.azure.net")) label = "Key Vault";

    logInfo(QString("Fetching %1 token for selected user...").arg(label));
    userSelector->fetchToken(m_targetResource, [this, label](bool success, const QString &token, const QString &error) {
        if (success) {
            if (tokenInput) tokenInput->setText(token);
            updateTokenStatus();
            logSuccess(QString("%1 token acquired").arg(label));
        } else {
            logError(QString("Failed to fetch %1 token: %2").arg(label, error));
            // If we failed and were looking for Graph, try Management as fallback (and vice versa)
            QString fallback;
            QString fallbackLabel;
            if (m_targetResource.contains("graph.microsoft.com")) {
                fallback = QStringLiteral("https://management.azure.com");
                fallbackLabel = "Management";
            } else if (m_targetResource.contains("management.azure.com")) {
                fallback = QStringLiteral("https://graph.microsoft.com");
                fallbackLabel = "Graph";
            }
            if (!fallback.isEmpty()) {
                logInfo(QString("Trying fallback: fetching %1 token...").arg(fallbackLabel));
                userSelector->fetchToken(fallback, [this, fallbackLabel](bool ok, const QString &tok, const QString &err) {
                    if (ok) {
                        if (tokenInput) tokenInput->setText(tok);
                        updateTokenStatus();
                        logWarning(QString("Using %1 token (audience may not match this operation)").arg(fallbackLabel));
                    } else {
                        logError(QString("Fallback also failed: %1").arg(err));
                    }
                });
            }
        }
    });
}

// ============================================================================
// Request Tracking
// ============================================================================

void EnumerationWindowBase::trackReply(QNetworkReply *reply)
{
    if (reply && !activeReplies.contains(reply)) {
        activeReplies.append(reply);
    }
}

void EnumerationWindowBase::untrackReply(QNetworkReply *reply)
{
    activeReplies.removeAll(reply);
}

void EnumerationWindowBase::abortAllRequests()
{
    for (QNetworkReply *reply : activeReplies) {
        if (reply && !reply->isFinished()) {
            reply->abort();
        }
    }
    activeReplies.clear();
}

void EnumerationWindowBase::cancelRequests()
{
    cancelRequested = true;
    logWarning("Cancelling requests...");
    abortAllRequests();
    setLoading(false);
    onCancelOperation();
    logInfo("Requests cancelled");
}
