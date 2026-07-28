#ifndef AZUREVMRUNCOMMANDTRANSPORT_H
#define AZUREVMRUNCOMMANDTRANSPORT_H

#include "RemoteExecTransport.h"

#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>

// AzureVmRunCommandTransport - ARM runCommand + async-op polling as a
// pluggable transport. Lift-and-shift of the flow originally inlined in
// AzureVMManagerWindow, factored so HttpWebshellTransport /
// HttpSstiTransport (Slice 5B) can live under the same RemoteExecWindow
// UI without knowing about ARM.
//
// Behaviour is byte-for-byte identical to the old inline path:
//   - POST /virtualMachines/{name}/runCommand?api-version=2023-07-01
//   - Retry 409 up to 3x, 10s delay each (VM busy = another runCommand
//     is still finishing)
//   - Detect 202 + Azure-AsyncOperation (or Location) header, then
//     poll every 5s up to 60 attempts (5 min ceiling)
//   - Emit progress() every 4 polls
//   - Terminal: status=Succeeded -> render
//     properties.output.value[].{code, message}; anything else -> render
//     body.error.{code, message}
class AzureVmRunCommandTransport : public RemoteExecTransport {
    Q_OBJECT
public:
    struct Config {
        QString token;        // Bearer for ARM (https://management.azure.com/)
        QString vmId;         // Full ARM resource id, e.g. /subscriptions/.../virtualMachines/foo
        QString osType;       // "windows" or "linux" (case-insensitive)
        QString displayName;  // For UI display (usually VM name)
    };

    explicit AzureVmRunCommandTransport(const Config &cfg, QObject *parent = nullptr);
    ~AzureVmRunCommandTransport() override;

    QString kind() const override        { return QStringLiteral("azure_vm"); }
    QString displayName() const override { return m_cfg.displayName; }
    bool    isReady(QString *why = nullptr) const override;
    void    execute(const QString &command, Callback cb) override;
    void    cancel() override;

private:
    void postRunCommand(const QString &command);
    void retryPostAfter(int ms, const QString &command);
    void pollRunCommand(int attempt);
    void deliver(const Result &r);   // Fires m_cb + resets state.

    Config                     m_cfg;
    QNetworkAccessManager     *m_net;
    QPointer<QNetworkReply>    m_reply;      // In-flight reply (post or poll).
    Callback                   m_cb;
    QString                    m_asyncUrl;
    QString                    m_pendingCmd; // For retry-on-409.
    int                        m_retries = 0;
    bool                       m_inFlight = false;
    QElapsedTimer              m_elapsed;
};

#endif  // AZUREVMRUNCOMMANDTRANSPORT_H
