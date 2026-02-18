#ifndef SPNENUMWINDOW_H
#define SPNENUMWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTreeWidget>
#include <QJsonArray>

class SPNEnumWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit SPNEnumWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void enumerateServicePrincipals();
    void enumerateAppRegistrations();
    void getAppCredentials();
    void getPermissions();
    void onItemSelected();
    void copySelectedItem();
    void exportResults();

private:
    void setupUi();
    void fetchNextPage(const QString &nextLink);

    // Custom UI elements
    QPushButton *enumSPNBtn;
    QPushButton *enumAppsBtn;
    QPushButton *getCredsBtn;
    QPushButton *getPermsBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *resultsTree;
    QTextEdit *detailsArea;

    // State
    QJsonArray servicePrincipals;
    QJsonArray appRegistrations;
    QString currentObjectId;
    QString currentAppId;
    QString currentObjectType;
};

#endif // SPNENUMWINDOW_H
