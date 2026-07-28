#include "OutputSanitizer.h"
#include <QStringList>
#include <cstring>

QString OutputSanitizer::stripAnsiPrompt(const QString &s) {
    // ---- 0) Remove ANSI/DEC control sequences via a tiny state machine (no regex) ----
    auto stripAnsiDec = [](const QString &in) -> QString {
        QString out;
        out.reserve(in.size());
        enum { Normal, InEsc, InCsi } st = Normal;
        for (int i = 0; i < in.size(); ++i) {
            const QChar ch = in.at(i);
            if (st == Normal) {
                if (ch == QChar(0x1B)) { // ESC
                    st = InEsc;
                    continue;
                }
                // Also catch orphaned CSI fragments like "[?1h" without ESC
                if (ch == '[' && i + 1 < in.size()) {
                    QChar next = in.at(i + 1);
                    if (next == '?' || next.isDigit()) {
                        st = InCsi;
                        continue;
                    }
                }
                out.append(ch);
            } else if (st == InEsc) {
                if (ch == '[') {
                    // CSI sequence: ESC [ ... final_byte
                    st = InCsi;
                } else if (ch.unicode() >= 0x40 && ch.unicode() <= 0x7E) {
                    // Simple ESC sequence ends here
                    st = Normal;
                }
                // Continue skipping
            } else { // InCsi: skip until final byte (0x40-0x7E, letters)
                if (ch.unicode() >= 0x40 && ch.unicode() <= 0x7E) {
                    st = Normal;
                }
                // (skip parameter bytes, intermediate bytes)
            }
        }
        return out;
    };

    // ---- 1) Pre-normalize ----
    QString tmp = stripAnsiDec(s);
    // Remove zero-width/BOM characters that break matches
    static const QChar ZWSU[] = { QChar(0x200B), QChar(0x200C), QChar(0x200D), QChar(0x2060), QChar(0xFEFF) };
    for (QChar zw : ZWSU) tmp.remove(zw);
    // Normalize newlines
    tmp.replace("\r\n", "\n");
    tmp.replace('\r',   '\n');

    // ---- 2) Line-by-line filtering (no regex) ----
    QStringList kept;
    kept.reserve(tmp.size() / 8);
    const QStringList lines = tmp.split('\n', Qt::KeepEmptyParts);
    int consecutiveBlankCount = 0;  // Track consecutive blank lines

    for (const QString &lineOrig : lines) {
        const QString lineTrim = lineOrig.trimmed();
        if (lineTrim.isEmpty()) {
            // Allow at most 1 consecutive blank line
            if (consecutiveBlankCount < 1) {
                kept << QString();  // Normalized empty line
                consecutiveBlankCount++;
            }
            continue;
        }
        consecutiveBlankCount = 0;  // Reset counter for non-blank lines

        // Strip a PS> prefix (hosts may echo without a space)
        QString noPS = lineTrim;
        if (noPS.startsWith(QStringLiteral("PS>"), Qt::CaseInsensitive)) {
            noPS = noPS.mid(3).trimmed();
            // If the whole line was a prompt-only line (e.g., "PS>" or "PS C:\>"), drop it now
            if (noPS.isEmpty() || noPS.endsWith(QLatin1Char('>'))) continue;
        }

        // 2.a Echoed wrapper pipeline line?
        // Normalize by removing spaces/tabs to make matching trivial.
        QString compact = noPS;
        compact.remove(' ');
        compact.remove('\t');
        const QString compactLower = compact.toCaseFolded();
        // Require starts with '&', has '{' and '}', and contains "|out-string"
        if (compactLower.startsWith('&')
            && compactLower.contains('{')
            && compactLower.contains('}')
            && compactLower.contains("|out-string")) {
            // Also accept both with/without explicit "2>&1"
            // (No further check needed: either form gets dropped.)
            continue;
        }

        // 2.b Empty Write-Output (with optional trailing ';' and any quotes)
        QString wo = noPS;
        QString woLower = wo.toCaseFolded();
        if (woLower.startsWith(QStringLiteral("write-output"))) {
            wo = wo.mid(int(strlen("Write-Output"))).trimmed();
            if (!wo.isEmpty() && wo.endsWith(QLatin1Char(';'))) {
                wo.chop(1);
                wo = wo.trimmed();
            }
            // Accept "", '', or truly empty
            if (wo.isEmpty() || wo == QStringLiteral("\"\"") || wo == QStringLiteral("''")) {
                continue;
            }
        }

        // 2.c Any remaining prompt-echo lines: drop any line that *begins* with PS>
        if (lineTrim.startsWith(QStringLiteral("PS>"), Qt::CaseInsensitive)) {
            continue;
        }

        // 2.d Filter out PowerShell initialization/setup commands
        // These are internal setup commands that shouldn't be shown to users
        static const QStringList initPatterns = {
            "$erroractionpreference",
            "$progresspreference",
            "$informationpreference",
            "$warningpreference",
            "remove-module psreadline",
            "function prompt",
            "$psstyle.outputrendering",
            "$formatenumerationlimit",
            "[console]::outputencoding",
            "::outputencoding",
            "preference='",
            "preference=\"",
            "}catch{};",
            "};try{",
            "-erroraction silentlycontinue",
        };
        bool isInitLine = false;
        QString lowerLine = lineTrim.toCaseFolded();
        for (const QString &pat : initPatterns) {
            if (lowerLine.contains(pat)) {
                isInitLine = true;
                break;
            }
        }
        if (isInitLine) continue;

        // 2.e Filter out lines that are just fragments of init commands (duplicates/splits)
        // Check for common init fragments
        if (lowerLine.startsWith("preference=") ||
            lowerLine.startsWith("h{};") ||
            lowerLine.startsWith("};try{") ||
            lowerLine.contains("::outputencoding=[system.text.encoding]::utf8")) {
            continue;
        }

        // Keep everything else (actual cmd output)
        kept << lineOrig;
    }

    return kept.join(QLatin1Char('\n')).trimmed();
}

QString OutputSanitizer::wrapPwshCommand(const QString &cmd) {
    // Markers on their own lines; capture BOTH streams as text.
    // No cmdId version for backward compatibility
    QString wrapped =
        "Write-Output \"__QZ_BEGIN__\"\n"
        "& { " + cmd + " } 2>&1 | Out-String -Width 9999\n"
        "Write-Output \"__QZ_END__\"\n";
    return wrapped;
}

QString OutputSanitizer::wrapPwshCommandWithId(const QString &cmd, const QString &cmdId) {
    // The command is Base64-encoded (UTF-8) so arbitrary content - multi-line
    // commands, quotes, semicolons, even text that looks like a marker - can never
    // break the single-line stdin framing. It is decoded and run inside PowerShell.
    const QString b64 = QString::fromLatin1(cmd.toUtf8().toBase64());

    // One logical stdin line. try/catch/finally guarantees the END marker is written
    // even when the command throws a terminating error, so the output segment ALWAYS
    // closes and can never merge into the next command. The EXIT marker carries a
    // failed flag (from $Error growth / a caught exception) plus $LASTEXITCODE so the
    // server can tell success from failure.
    QString w;
    w += QString("$__qzid='%1';").arg(cmdId);
    w += QString("$__qzcmd=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));").arg(b64);
    // Emit errors (SilentlyContinue during session init would otherwise hide them).
    w += "$ErrorActionPreference='Continue';";
    w += "$PSDefaultParameterValues['Out-String:Width']=512;";
    w += "$__qzeb=$Error.Count;$__qzcaught=$false;";
    w += "Write-Output \"__QZ_BEGIN__:$__qzid\";";
    w += "try{";
    // & (ScriptBlock) captures non-terminating errors via 2>&1 (Invoke-Expression drops them)
    // and still parses multi-line commands; a parse error throws into the catch below.
    w +=   "& ([ScriptBlock]::Create($__qzcmd)) 2>&1|Out-String -Stream -Width 512|ForEach-Object{if($null -ne $_){Write-Output $_}};";
    w += "}catch{";
    w +=   "$__qzcaught=$true;";
    w +=   "Write-Output \"__QZ_ERR__:$__qzid\";";
    w +=   "Write-Output ($_|Out-String -Width 512);";
    w += "}finally{";
    w +=   "$__qzfail=$__qzcaught -or ($Error.Count -gt $__qzeb);";
    // ${__qzid} must be brace-delimited: a bare $var followed by ':' is parsed as scope syntax.
    w +=   "Write-Output \"__QZ_EXIT__:${__qzid}:$(if($__qzfail){'1'}else{'0'}):$LASTEXITCODE\";";
    w +=   "Write-Output \"__QZ_END__:$__qzid\";";
    w += "}\n";
    return w;
}
