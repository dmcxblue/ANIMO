#ifndef POWERSHELL_MANAGER_H
#define POWERSHELL_MANAGER_H

#include <QString>

/**
 * @brief Utility class for PowerShell-related operations
 *
 * Provides cross-platform PowerShell path resolution and
 * session script management.
 */
class PowerShellManager {
public:
    /**
     * @brief Find the PowerShell executable path
     *
     * Searches for PowerShell in the following order:
     * - Windows: pwsh.exe, powershell.exe, common install paths
     * - WSL: Windows PowerShell under /mnt/c, then native pwsh
     * - Linux/macOS: pwsh, /usr/bin/pwsh, /snap/bin/pwsh
     *
     * @return Full path to PowerShell executable, or fallback name
     */
    static QString getPwshPath();

    /**
     * @brief Get or create the scripts directory for a session
     *
     * Creates data/sessions/<sessionId> if it doesn't exist.
     *
     * @param sessionId The session UUID
     * @return Path to the session's scripts directory
     */
    static QString sessionScriptsDir(const QString &sessionId);

    /**
     * @brief Write a PowerShell script file for a session
     *
     * Writes UTF-8 encoded content to a .ps1 file in the session's
     * scripts directory.
     *
     * @param sessionId The session UUID
     * @param content The PowerShell script content
     * @param name The script filename (default: "login.ps1")
     * @return Native full path to the created file, or empty on error
     */
    static QString writePs1ForSession(const QString &sessionId,
                                       const QString &content,
                                       const QString &name = QStringLiteral("login.ps1"));

    /**
     * @brief Get common PowerShell startup arguments
     *
     * Returns arguments for non-interactive, clean PowerShell sessions:
     * -NoLogo -NoProfile -NonInteractive
     *
     * @param includeExecutionPolicy Whether to add -ExecutionPolicy Bypass (Windows only)
     * @return List of command-line arguments
     */
    static QStringList getStartupArgs(bool includeExecutionPolicy = false);
};

#endif // POWERSHELL_MANAGER_H
