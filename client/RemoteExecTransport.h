#ifndef REMOTEEXECTRANSPORT_H
#define REMOTEEXECTRANSPORT_H

#include <QObject>
#include <QString>
#include <functional>

// RemoteExecTransport - abstract "send a command, get output back"
// primitive. Concrete implementations plug into the same interactive UI:
//
//   - AzureVmRunCommandTransport   ARM long-running runCommand + poll
//   - HttpWebshellTransport        uploaded cmd.php-style shells
//   - HttpSstiTransport            SSTI payload templating (Jinja2, Twig...)
//
// The framework's whole point is that the operator's mental model
// ("target -> command -> output") stays constant regardless of how
// the payload actually reaches the target.
//
// Ownership: transports are heap-allocated QObjects owned by the caller
// (typically a RemoteExecWindow session). Delete when the target is
// switched away or the window closes. `cancel()` must be safe to call
// during shutdown - it may fire the pending callback with ok=false.
class RemoteExecTransport : public QObject {
    Q_OBJECT
public:
    struct Result {
        bool    ok = false;
        QString stdoutText;    // Command stdout (post output-extraction if applicable)
        QString stderrText;    // Best-effort; may be empty for HTTP transports
        int     exitCode = -1; // -1 when unknown (async ARM ops, HTTP shells)
        int     elapsedMs = 0;
    };
    using Callback = std::function<void(const Result&)>;

    explicit RemoteExecTransport(QObject *parent = nullptr) : QObject(parent) {}
    ~RemoteExecTransport() override = default;

    // "azure_vm" | "http_webshell" | "http_ssti" - stable strings used
    // by RemoteExecTargetStore for serialization.
    virtual QString kind() const = 0;

    // Human-readable target name for the UI (e.g. "prod-web-01").
    virtual QString displayName() const = 0;

    // True when this transport can execute a command right now. If false,
    // populate `why` with a short reason for the UI.
    virtual bool isReady(QString *why = nullptr) const = 0;

    // Fire-and-forget. The callback runs once per execute() call. If the
    // operator hits cancel(), the callback fires with ok=false and
    // stdoutText = "cancelled". Concurrent execute() calls on the same
    // transport are undefined - each transport is single-shot.
    virtual void execute(const QString &command, Callback cb) = 0;

    // Abort any in-flight work. Safe to call when nothing is running.
    virtual void cancel() = 0;

signals:
    // Optional heartbeat / status line the UI can render as "still
    // running..." / "polling 20s..." etc. Never carries the final stdout.
    void progress(const QString &line);
};

#endif  // REMOTEEXECTRANSPORT_H
