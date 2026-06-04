#ifndef OUTPUT_SANITIZER_H
#define OUTPUT_SANITIZER_H

#include <QString>

/**
 * @brief Utility class for sanitizing PowerShell output
 *
 * Provides functions to clean ANSI escape sequences, filter noise,
 * and wrap commands for marker-based output extraction.
 */
class OutputSanitizer {
public:
    /**
     * @brief Strip ANSI escape codes and PowerShell noise from output
     *
     * Removes:
     * - ANSI/DEC control sequences (colors, cursor movement)
     * - Zero-width characters and BOM
     * - PowerShell prompts (PS>, PS C:\>)
     * - Internal setup commands ($ErrorActionPreference, etc.)
     * - Empty Write-Output statements
     * - Consecutive blank lines (keeps max 1)
     *
     * @param input Raw PowerShell output string
     * @return Cleaned output string
     */
    static QString stripAnsiPrompt(const QString &input);

    /**
     * @brief Wrap a PowerShell command with output markers
     *
     * Wraps the command between __QZ_BEGIN__ and __QZ_END__ markers
     * for reliable output extraction, capturing both stdout and stderr.
     *
     * @param cmd The PowerShell command to wrap
     * @return Wrapped command string ready for execution
     */
    static QString wrapPwshCommand(const QString &cmd);

    /**
     * @brief Wrap a PowerShell command with output markers including command ID
     *
     * Wraps the command between __QZ_BEGIN__:cmdId and __QZ_END__:cmdId markers
     * for reliable output extraction with command correlation.
     *
     * @param cmd The PowerShell command to wrap
     * @param cmdId Unique command ID for output correlation
     * @return Wrapped command string ready for execution
     */
    static QString wrapPwshCommandWithId(const QString &cmd, const QString &cmdId);

    // Marker constants for output extraction
    static constexpr const char* BEGIN_MARKER = "__QZ_BEGIN__";
    static constexpr const char* END_MARKER = "__QZ_END__";
};

#endif // OUTPUT_SANITIZER_H
