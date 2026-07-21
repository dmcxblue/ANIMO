#include "GraphQueryWindow.h"
#include "StyleManager.h"
#include "GraphBodyDialog.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QTextEdit>
#include <QProgressBar>
#include <QGroupBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QSslConfiguration>
#include <QMessageBox>

GraphQueryWindow::GraphQueryWindow(QWidget* parent)
    : QWidget(parent)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Graph Queries (Graph Explorer-style)");
    resize(900, 700);

    auto* root = new QVBoxLayout(this);

    // User selector and token group
    auto *tokenGroup = new QGroupBox("Microsoft Graph Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    m_userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(m_userSelector);
    connect(m_userSelector, &UserSelectorWidget::userChanged, this, &GraphQueryWindow::onUserChanged);

    auto *autoFetchRow = new QHBoxLayout();
    m_autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(m_autoFetchBtn);
    autoFetchRow->addWidget(m_autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(m_autoFetchBtn, &QPushButton::clicked, this, &GraphQueryWindow::autoFetchTokens);

    auto *tokenRow = new QHBoxLayout();
    m_tokenEdit = new QLineEdit(this);
    m_tokenEdit->setEchoMode(QLineEdit::Normal);
    m_tokenEdit->setPlaceholderText("Paste Access Token for https://graph.microsoft.com");
    tokenRow->addWidget(m_tokenEdit);
    m_tokenStatus = new QLabel(this);
    m_tokenStatus->setFixedWidth(80);
    tokenRow->addWidget(m_tokenStatus);
    tokenLayout->addLayout(tokenRow);

    root->addWidget(tokenGroup);

    auto* form = new QFormLayout();

    m_urlEdit = new QLineEdit(this);
    m_urlEdit->setPlaceholderText("https://graph.microsoft.com/v1.0/teams/{team-id}/tags  OR  https://graph.microsoft.com/beta/teams/{team-id}/tags");
    form->addRow(new QLabel("Request URL:"), m_urlEdit);

    m_methodBox = new QComboBox(this);
    m_methodBox->addItems({"GET","POST","PUT","PATCH","DELETE"});
    form->addRow(new QLabel("Method:"), m_methodBox);

    auto* rowBtns = new QHBoxLayout();
    m_bodyBtn = new QPushButton("Body…", this);
    m_bodyBtn->setEnabled(false);
    m_sendBtn = new QPushButton("Send", this);
    rowBtns->addWidget(m_bodyBtn);
    rowBtns->addStretch();
    rowBtns->addWidget(m_sendBtn);

    m_status = new QLabel(this);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_status->setStyleSheet("color:#aaa;");

    // Progress bar for network operations
    m_progress = new QProgressBar(this);
    m_progress->setRange(0, 0);  // Indeterminate mode
    m_progress->setTextVisible(false);
    m_progress->setFixedHeight(4);
    m_progress->hide();  // Hidden by default

    m_output = new QTextEdit(this);
    m_output->setReadOnly(true);
    m_output->setPlaceholderText("Response will appear here…");

    root->addLayout(form);
    root->addLayout(rowBtns);
    root->addWidget(m_progress);
    root->addWidget(m_status);
    root->addWidget(m_output, 1);

    connect(m_methodBox, &QComboBox::currentIndexChanged, this, &GraphQueryWindow::onMethodChanged);
    connect(m_bodyBtn, &QPushButton::clicked, this, &GraphQueryWindow::onOpenBody);
    connect(m_sendBtn, &QPushButton::clicked, this, &GraphQueryWindow::onSend);
}

void GraphQueryWindow::onMethodChanged(int) {
    const QString m = m_methodBox->currentText();
    const bool needsBody = (m == "POST" || m == "PUT" || m == "PATCH");
    m_bodyBtn->setEnabled(needsBody);
}

void GraphQueryWindow::onOpenBody() {
    GraphBodyDialog dlg(this);
    if (!m_bodyText.isEmpty()) {
        // Preload previous text
        // (Not exposing a setter in dialog to keep it minimal; user can paste again.)
    }
    if (dlg.exec() == QDialog::Accepted) {
        m_bodyText = dlg.bodyText();
    }
}

static bool isGraphHostOk(const QUrl& url) {
    return url.isValid()
        && url.scheme() == "https"
        && url.host().compare("graph.microsoft.com", Qt::CaseInsensitive) == 0
        && (url.path().startsWith("/v1.0") || url.path().startsWith("/beta"));
}

bool GraphQueryWindow::validateInputs(QString& error) const {
    if (m_tokenEdit->text().trimmed().isEmpty()) {
        error = "Access Token is required.";
        return false;
    }
    const QUrl u(m_urlEdit->text().trimmed());
    if (!isGraphHostOk(u)) {
        error = "URL must be https://graph.microsoft.com/(v1.0|beta)/...";
        return false;
    }
    // Lightweight JWT 'aud' check for UX (no signature verification)
    QString aud, terr;
    if (!tokenAudIsGraph(m_tokenEdit->text().trimmed(), &aud, &terr)) {
        error = terr.isEmpty() ? "Access Token does not appear to be a valid Graph token." : terr;
        return false;
    }
    if (aud != "https://graph.microsoft.com") {
        error = QString("Access Token 'aud' is '%1', expected 'https://graph.microsoft.com'.").arg(aud);
        return false;
    }
    return true;
}

void GraphQueryWindow::onSend() {
    QString verr;
    if (!validateInputs(verr)) {
        QMessageBox::warning(this, "Validation", verr);
        return;
    }

    const QString token = m_tokenEdit->text().trimmed();
    const QString method = m_methodBox->currentText();
    const QUrl url(m_urlEdit->text().trimmed());

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "ANIMO/1.0");
    req.setRawHeader("Authorization", QByteArray("Bearer ").append(token.toUtf8()));

    // Default Accept JSON
    req.setRawHeader("Accept", "application/json");

    // Harden TLS a bit
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setProtocol(QSsl::TlsV1_2OrLater);
    req.setSslConfiguration(ssl);

    // Prepare body if needed
    QByteArray body;
    if (method == "POST" || method == "PUT" || method == "PATCH") {
        if (m_bodyText.trimmed().isEmpty()) {
            QMessageBox::warning(this, "Validation", "This method requires a JSON body.");
            return;
        }
        body = m_bodyText.toUtf8();
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    }

    // Fire the request
    QNetworkReply* reply = nullptr;
    if (method == "GET")       reply = m_nam.get(req);
    else if (method == "DELETE") reply = m_nam.sendCustomRequest(req, "DELETE");
    else if (method == "POST")   reply = m_nam.post(req, body);
    else if (method == "PUT")    reply = m_nam.put(req, body);
    else if (method == "PATCH")  reply = m_nam.sendCustomRequest(req, "PATCH", body);
    else {
        QMessageBox::warning(this, "Method", "Unsupported method.");
        return;
    }

    // Show progress indicator
    m_progress->show();
    m_sendBtn->setEnabled(false);
    m_status->setText("Sending…");
    m_output->clear();

    connect(reply, &QNetworkReply::finished, this, &GraphQueryWindow::onReplyFinished);
}

void GraphQueryWindow::onReplyFinished() {
    auto* reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) return;

    // Hide progress indicator and re-enable button
    m_progress->hide();
    m_sendBtn->setEnabled(true);

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray raw = reply->readAll();
    const QString pretty = prettyJson(raw);  // <<— QString, not QByteArray

    QString statusText = QString("HTTP %1").arg(status);
    if (status == 0 && reply->error() != QNetworkReply::NoError) {
        statusText += QString(" — Network error: %1").arg(reply->errorString());
    }
    m_status->setText(statusText);

    if (!pretty.isEmpty()) {
        m_output->setPlainText(pretty);
    } else {
        m_output->setPlainText(QString::fromUtf8(raw));
    }

    reply->deleteLater();
}


// -------- helpers

QString GraphQueryWindow::prettyJson(const QByteArray& in) {
    QJsonParseError e{};
    QJsonDocument doc = QJsonDocument::fromJson(in, &e);
    if (e.error != QJsonParseError::NoError || doc.isNull())
        return QString();
    return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
}

QByteArray GraphQueryWindow::base64UrlDecode(const QByteArray& in) {
    QByteArray tmp = in;
    tmp.replace('-', '+').replace('_', '/');
    while (tmp.size() % 4) tmp.append('=');
    return QByteArray::fromBase64(tmp);
}

bool GraphQueryWindow::tokenAudIsGraph(const QString& jwt, QString* audOut, QString* err) {
    // Expect JWT: header.payload.signature (base64url)
    const auto parts = jwt.split('.');
    if (parts.size() < 2) {
        if (err) *err = "Access Token is not a JWT (missing parts).";
        return false;
    }
    const QByteArray payload = base64UrlDecode(parts.at(1).toUtf8());
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(payload, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        if (err) *err = "Unable to parse token payload.";
        return false;
    }
    const QJsonObject o = doc.object();
    const QString aud = o.value("aud").toString();
    if (audOut) *audOut = aud;
    return !aud.isEmpty();
}

void GraphQueryWindow::onUserChanged(const QString &upn) {
    m_tokenEdit->clear();
    updateTokenStatus();
    m_status->setText(QString("Switched to user: %1").arg(upn));
}

void GraphQueryWindow::autoFetchTokens() {
    if (!m_userSelector->hasSelection()) {
        m_status->setText("Please select a user first");
        m_status->setStyleSheet("color: red;");
        return;
    }

    m_status->setText("Fetching Graph token...");
    m_status->setStyleSheet("color: cyan;");

    m_userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &token, const QString &error) {
        if (success) {
            m_tokenEdit->setText(token);
            updateTokenStatus();
            m_status->setText("Graph token acquired");
            m_status->setStyleSheet("color: lightgreen;");
        } else {
            m_status->setText(QString("Failed: %1").arg(error));
            m_status->setStyleSheet("color: red;");
        }
    });
}

void GraphQueryWindow::updateTokenStatus() {
    QString token = m_tokenEdit->text().trimmed();
    if (token.isEmpty()) {
        m_tokenStatus->setText("No Token");
        m_tokenStatus->setStyleSheet(StyleManager::tokenStatusEmptyStyle());
    } else {
        m_tokenStatus->setText("Ready");
        m_tokenStatus->setStyleSheet(StyleManager::tokenStatusReadyStyle());
    }
}
