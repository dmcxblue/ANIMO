#ifndef CROSSTENANTACCESSWINDOW_H
#define CROSSTENANTACCESSWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTreeWidget>
#include <QTabWidget>
#include <QJsonArray>
#include <QJsonObject>

class CrossTenantAccessWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit CrossTenantAccessWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void fetchPolicies();
    void onPartnerSelected(QTreeWidgetItem *item, int column);
    void copySelected();
    void exportPolicies();

private:
    void setupUi();
    void displayDefaultPolicy(const QJsonObject &policy);
    void displayPartnerDetails(const QJsonObject &partner);
    void parseB2BSettings(const QJsonObject &settings, const QString &direction, QString &html);

    // Custom UI elements
    QPushButton *fetchBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTabWidget *tabWidget;
    QTextEdit *defaultPolicyView;
    QTreeWidget *partnerTree;
    QTextEdit *partnerDetailsView;

    // State
    QJsonObject defaultPolicy;
    QJsonArray partners;
    int pendingRequests;
};

#endif // CROSSTENANTACCESSWINDOW_H
