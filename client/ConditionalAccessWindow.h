#ifndef CONDITIONALACCESSWINDOW_H
#define CONDITIONALACCESSWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTreeWidget>
#include <QTabWidget>
#include <QJsonArray>

/**
 * ConditionalAccessWindow - CA Policy Viewer with Security Analysis
 *
 * Features:
 * - Fetch and display CA policies from Microsoft Graph
 * - Parse policy details (conditions, users, apps, grant/session controls)
 * - Color-coded policy states (enabled/disabled/report-only)
 * - Export policies to JSON
 *
 * CA Bypass Detector - Red Team Security Analysis:
 * - Identifies policies in report-only mode (not enforced)
 * - Detects platform gaps (mobile-only policies leave desktop unprotected)
 * - Finds location exclusions (trusted networks = bypass vectors)
 * - Spots legacy auth gaps (policies not blocking legacy protocols)
 * - Identifies break-glass accounts (excluded users/groups)
 * - Detects missing MFA for sensitive apps (All Apps without MFA)
 * - Finds client app type gaps (browser-only leaves native apps open)
 */
class ConditionalAccessWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit ConditionalAccessWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void fetchPolicies();
    void onPolicySelected(QTreeWidgetItem *item, int column);
    void copySelectedPolicy();
    void exportPolicies();
    void analyzeSecurityGaps();

private:
    void setupUi();
    void displayPolicyDetails(const QJsonObject &policy);

    // Security analysis helpers
    struct SecurityFinding {
        QString severity;     // CRITICAL, HIGH, MEDIUM, LOW, INFO
        QString category;     // Report-Only, Platform Gap, etc.
        QString policyName;
        QString description;
        QString recommendation;
    };
    QList<SecurityFinding> analyzePolicies();
    void displaySecurityFindings(const QList<SecurityFinding> &findings);

    // Custom UI elements
    QPushButton *fetchBtn;
    QPushButton *analyzeBtn;
    QPushButton *copyBtn;
    QPushButton *exportBtn;
    QTreeWidget *policyTree;
    QTabWidget *detailsTabs;
    QTextEdit *detailsView;
    QTextEdit *securityView;

    // State
    QJsonArray policies;
};

#endif // CONDITIONALACCESSWINDOW_H
