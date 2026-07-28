#ifndef PSSESSIONRUNNER_H
#define PSSESSIONRUNNER_H

#include <QObject>
#include <QString>
#include <QJsonValue>
#include <QMetaObject>
#include <functional>

class QJsonObject;

// Reusable helper: run a PowerShell snippet inside the selected session's
// terminal and get back parsed JSON. Encapsulates the run_command / cmdId /
// command_complete correlation the terminal already implements, so modules
// don't each hand-roll it.
//
// Typical use inside a module:
//   PsSessionRunner::run(this, sessionId, "Get-AzADServicePrincipal",
//       [](bool ok, const QJsonValue &json, const QString &raw) {
//           if (!ok) { showError(raw); return; }
//           for (const QJsonValue &v : json.toArray()) { ... }
//       });
//
// Notes:
// - The script is auto-wrapped with `@( ... ) | ConvertTo-Json -Depth 8 -Compress`
//   so 0/1/many results all come back as a JSON array (Az cmdlets otherwise
//   return a bare object for one row and $null for zero, which fails to parse).
// - Pass `wrap = false` to suppress that when your script already emits JSON.
// - Ownership: pass `context` = a QObject that outlives the callback (usually
//   the module window `this`). We disconnect on completion, so no leaks even
//   if the context dies mid-run.
class PsSessionRunner {
public:
    using Callback = std::function<void(bool ok, const QJsonValue &json, const QString &raw)>;

    // Fire-and-forget. Returns false if no transport / no session (callback
    // fires synchronously with ok=false in that case).
    static bool run(QObject *context,
                    const QString &sessionId,
                    const QString &script,
                    Callback callback,
                    bool wrap = true,
                    int depth = 8);

    // Same, but caller supplies its own wrapped script (still parses JSON).
    static bool runRaw(QObject *context,
                       const QString &sessionId,
                       const QString &script,
                       Callback callback);
};

#endif  // PSSESSIONRUNNER_H
