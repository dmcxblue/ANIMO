#ifndef KEYVAULTEXPLORERWINDOW_H
#define KEYVAULTEXPLORERWINDOW_H

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
#include <QProgressBar>
#include <QLabel>

class UserSelectorWidget;

class KeyVaultExplorerWindow : public QWidget {
    Q_OBJECT

public:
    explicit KeyVaultExplorerWindow(QWidget *parent = nullptr);
    ~KeyVaultExplorerWindow();

private slots:
    void enumerateKeyVaults();
    void onVaultSelected(int index);
    void listSecrets();
    void listKeys();
    void listCertificates();
    void getSecretValue();
    void getKeyValue();
    void exportCertificate();
    void showTreeContextMenu(const QPoint &pos);
    void listAccessPolicies();
    void copySelectedItem();
    void exportResults();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void cancelRequests();

private:
    void setupUi();
    void updateTokenStatus();
    // Remove any existing top-level group with this label so re-listing refreshes
    // that category in place instead of appending a duplicate.
    void removeTreeGroup(const QString &label);
    // Seamlessly acquire a vault-audience token from the selected session's refresh token.
    void ensureVaultToken(std::function<void(bool)> then = nullptr);
    QNetworkRequest bearerRequest(const QString &url, const QString &token);
    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);

    UserSelectorWidget *userSelector;
    QLineEdit *mgmtTokenInput;
    QLineEdit *vaultTokenInput;
    QPushButton *autoFetchBtn;
    QLabel *mgmtTokenStatus;
    QLabel *vaultTokenStatus;
    QComboBox *subscriptionCombo;
    QComboBox *vaultCombo;
    QPushButton *enumVaultsBtn;
    QPushButton *listSecretsBtn;
    QPushButton *listKeysBtn;
    QPushButton *listCertsBtn;
    QPushButton *getSecretBtn;
    QPushButton *exportCertBtn;
    QPushButton *accessPoliciesBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *resultsTree;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;

    QJsonArray subscriptions;
    QJsonArray keyVaults;
    QString currentSubscriptionId;
    QString currentVaultUrl;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // KEYVAULTEXPLORERWINDOW_H
