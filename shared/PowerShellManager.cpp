#include "PowerShellManager.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QStringList>
#include <QTextStream>
#include <QDebug>

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#include <QStringConverter>
#endif

QString PowerShellManager::getPwshPath() {
    auto existsExec = [](const QString &p) -> QString {
        if (p.isEmpty()) return QString();
        // Prefer PATH resolution first
        const QString fromPath = QStandardPaths::findExecutable(p);
        if (!fromPath.isEmpty()) return fromPath;
        // Then literal file check
        QFileInfo fi(p);
        if (fi.exists() && fi.isExecutable()) return fi.absoluteFilePath();
        return QString();
    };

    const bool isWindows =
    #ifdef Q_OS_WIN
        true;
    #else
        false;
    #endif

    const bool isWSL = !isWindows && qEnvironmentVariableIsSet("WSL_DISTRO_NAME");

    // 1) Native Windows
    if (isWindows) {
        const QStringList candidates = {
            "pwsh.exe",
            "powershell.exe",
            "C:/Program Files/PowerShell/7/pwsh.exe",
            "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        };
        for (const QString &c : candidates) {
            const QString hit = existsExec(c);
            if (!hit.isEmpty()) return hit;
        }
        return "pwsh.exe";
    }

    // 2) WSL (Linux kernel, Windows binaries visible under /mnt/c)
    if (isWSL) {
        const QStringList candidates = {
            "/mnt/c/Program Files/PowerShell/7/pwsh.exe",
            "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "pwsh",       // in case pwsh is installed inside the WSL distro
            "pwsh.exe"    // rare, but try anyway
        };
        for (const QString &c : candidates) {
            const QString hit = existsExec(c);
            if (!hit.isEmpty()) return hit;
        }
        return "pwsh";
    }

    // 3) Regular Linux / macOS
    {
        const QStringList candidates = {
            "pwsh",
            "pwsh.exe",          // sometimes present via symlinks/mono
            "/usr/bin/pwsh",
            "/snap/bin/pwsh",
            "powershell"         // older packages
        };
        for (const QString &c : candidates) {
            const QString hit = existsExec(c);
            if (!hit.isEmpty()) return hit;
        }
        return "pwsh";
    }
}

QString PowerShellManager::sessionScriptsDir(const QString &sessionId) {
    const QString dir = QString("data/sessions/%1").arg(sessionId);
    QDir().mkpath(dir);
    return dir;
}

QString PowerShellManager::writePs1ForSession(const QString &sessionId,
                                               const QString &content,
                                               const QString &name) {
    const QString dir  = sessionScriptsDir(sessionId);
    const QString path = QFileInfo(dir, name).absoluteFilePath();

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        qWarning() << "[PowerShellManager] Cannot write PS1:" << path << f.errorString();
        return QString();
    }
    QTextStream ts(&f);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    ts.setEncoding(QStringConverter::Utf8);
#else
    ts.setCodec("UTF-8");
#endif
    ts << content;
    f.close();
    return QDir::toNativeSeparators(path);
}

QStringList PowerShellManager::getStartupArgs(bool includeExecutionPolicy) {
    QStringList args{ "-NoLogo", "-NoProfile", "-NonInteractive" };
#ifdef Q_OS_WIN
    if (includeExecutionPolicy) {
        args << "-ExecutionPolicy" << "Bypass";
    }
#else
    Q_UNUSED(includeExecutionPolicy);
#endif
    return args;
}
