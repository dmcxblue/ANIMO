#ifndef AZURESTORAGEWINDOW_H
#define AZURESTORAGEWINDOW_H

#include <QWidget>
#include <atomic>
#include <functional>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidget>
#include <QTextEdit>
#include <QComboBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonArray>
#include <QLabel>
#include <QProgressBar>

class UserSelectorWidget;

// Red-team storage looter. Operates on a storage account by NAME with any one of:
// an OAuth data-plane token, a SAS token, or an account key. The management token +
// subscription are OPTIONAL (only for ARM account discovery / key extraction).
// REST is the primary engine; PowerShell (Az.Storage, run in the selected session)
// is the fallback for the account-key path and when REST is denied.
class AzureStorageWindow : public QWidget {
    Q_OBJECT

public:
    explicit AzureStorageWindow(QWidget *parent = nullptr);
    ~AzureStorageWindow();

private slots:
    void listStorageAccounts();          // optional ARM discovery (needs mgmt token + sub)
    void onStorageAccountSelected(int index);
    void enumerateAll();                 // one-click: accounts -> containers -> blobs -> loot
    void listContainers();               // blob containers OR file shares (per service)
    void listKnownContainer();           // go straight to a named container's blobs (no listing)
    void listChildren();                 // blobs in a container / files in a share
    void onTreeItemClicked(QTreeWidgetItem *item, int column);
    void downloadSelected();             // REST client-side (OAuth/SAS) or PS (key)
    void bulkDownloadSelected();
    void checkPublicAccess();            // anonymous read probe
    void generateSas();                  // mint a SAS via PowerShell
    void copyUrl();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void onAuthModeChanged();
    void cancelRequests();

private:
    void setupUi();
    void updateTokenStatus();

    // REST helpers
    bool hasStorageToken() const;
    void acquireStorageToken(std::function<void(bool)> then = nullptr);
    // Auto-fetch a Management token from the selected session so the ARM (HTTP)
    // path can run instead of the much slower Az PowerShell one. Fires the
    // callback with the token, or empty on failure.
    void acquireManagementToken(std::function<void(const QString &)> then);
    // ARM (HTTP) implementations for the fast path. They fall back to the PS
    // variants only when a Management token can't be acquired.
    void listStorageAccountsArm(const QString &mgmtToken);
    void enumerateAllArm(const QString &mgmtToken);
    void enumerateAllPsLegacy();
    QString accountForItem(QTreeWidgetItem *item) const;
    QString accountHost() const;
    QString accountHostFor(const QString &acct) const;
    QNetworkRequest dataRequest(const QString &url, bool anonymous = false);
    QNetworkReply *track(QNetworkReply *reply);

    // PowerShell fallback (runs in the selected session)
    QObject *locateTransport() const;
    bool psAvailable() const;
    void runPs(const QString &script, std::function<void(bool ok, const QString &output)> cb);
    QString psContextSetup() const;                           // statements that set $ctx for current auth

    // Listing engines
    void listContainersRest();
    void listContainersPs();
    void listBlobsRest(QTreeWidgetItem *containerItem);
    void listBlobsPs(QTreeWidgetItem *containerItem);

    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);
    static bool isLootName(const QString &name);
    static QString humanSize(qint64 bytes);

    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;

    QComboBox *authModeCombo;      // OAuth Token | SAS Token | Account Key
    QComboBox *serviceCombo;       // Blob | File
    QLineEdit *accountInput;       // storage account NAME (direct entry)
    QLineEdit *containerInput;     // known container name (skip listing containers)
    QLineEdit *storageTokenInput;  // OAuth (storage.azure.com)
    QLineEdit *sasInput;           // SAS token
    QLineEdit *keyInput;           // account key
    QLineEdit *credUser;           // username for Connect-AzAccount -Credential
    QLineEdit *credPass;           // password
    QLineEdit *tenantInput;        // tenant for the credential login
    QLabel *storageTokenStatus;

    QLineEdit *mgmtTokenInput;     // optional: ARM discovery / key extraction
    QLineEdit *subscriptionInput;
    QLabel *mgmtTokenStatus;

    QProgressBar *progressBar;
    QComboBox *storageAccountCombo;
    QPushButton *enumerateBtn;
    QPushButton *listAccountsBtn;
    QPushButton *listContainersBtn;
    QPushButton *listBlobsBtn;
    QPushButton *checkPublicBtn;
    QPushButton *downloadBtn;
    QPushButton *bulkDownloadBtn;
    QPushButton *genSasBtn;
    QPushButton *copyUrlBtn;
    QPushButton *cancelBtn;
    QTreeWidget *storageTree;
    QTextEdit *logOutput;
    QNetworkAccessManager *net;

    QString currentStorageAccount;
    QJsonArray storageAccounts;

    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // AZURESTORAGEWINDOW_H
