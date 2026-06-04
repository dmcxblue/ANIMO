#ifndef MAGICAPPFINDERWINDOW_H
#define MAGICAPPFINDERWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTableWidget>
#include <QJsonArray>

class MagicAppFinderWindow : public EnumerationWindowBase
{
    Q_OBJECT

public:
    explicit MagicAppFinderWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;

private slots:
    void startScan();
    void exportResults();
    void copySelected();

private:
    void setupUi();
    void fetchOAuthGrants();
    void processGrants(const QJsonArray &grants);
    void checkServicePrincipal(const QString &clientId);
    void checkApplication(const QString &appId, const QString &spDisplayName);
    void addVulnerableApp(const QString &displayName, const QString &appId,
                          const QString &consentType, const QStringList &redirectUris,
                          const QString &scopeType);

    QPushButton *scanBtn;
    QPushButton *exportBtn;
    QPushButton *copyBtn;
    QTableWidget *resultsTable;

    QStringList allPrincipalsClients;
    int pendingChecks;
    int grantsProcessed;
    int totalGrants;
};

#endif // MAGICAPPFINDERWINDOW_H
