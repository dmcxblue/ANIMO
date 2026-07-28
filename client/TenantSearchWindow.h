#ifndef TENANTSEARCHWINDOW_H
#define TENANTSEARCHWINDOW_H

#include "EnumerationWindowBase.h"
#include <QCheckBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QTreeWidget>
#include <QJsonArray>
#include <QMap>

// Tenant-wide search over M365 via POST /search/query. One Graph endpoint
// returns hits across driveItem / message / chatMessage / event / site /
// list / listItem / person, so a single query surfaces credential leaks
// across OneDrive, mail, Teams, calendar and SharePoint in one shot.
//
// Route goes through TokenOrPsBridge, so an SPN session without a Graph
// token falls back to Invoke-MgGraphRequest in the session's pwsh.
class TenantSearchWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit TenantSearchWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void startSearch();
    void exportCsv();
    void exportJson();
    void copySelectedRow();

private:
    void setupUi();
    void renderHit(const QString &entityType, const QJsonObject &hit);

    QLineEdit   *queryInput;
    QSpinBox    *sizeSpin;
    QMap<QString, QCheckBox*> entityChecks;
    QPushButton *searchBtn;
    QPushButton *exportCsvBtn;
    QPushButton *exportJsonBtn;
    QPushButton *copyBtn;
    QTreeWidget *resultsTree;

    QJsonArray   collectedHits;   // { entityType, hit } for exports
};

#endif  // TENANTSEARCHWINDOW_H
