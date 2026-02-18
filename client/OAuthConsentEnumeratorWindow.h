#ifndef OAUTHCONSENTENUMERATORWINDOW_H
#define OAUTHCONSENTENUMERATORWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTreeWidget>
#include <QCheckBox>

/**
 * OAuth Consent Enumeration Window
 *
 * Enumerates OAuth2 permission grants to identify:
 * - What permissions users have already consented to
 * - Applications with excessive permissions
 * - High-value targets for consent phishing
 *
 * Red Team Value:
 * - Users more likely to approve scopes they've approved before
 * - Identifies over-permissioned applications
 * - Maps application access across the tenant
 */
class OAuthConsentEnumeratorWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit OAuthConsentEnumeratorWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void enumerateMyConsents();
    void enumerateAllConsents();
    void enumerateAppConsents();
    void copySelectedItem();
    void exportResults();

private:
    void setupUi();
    void resolveServicePrincipal(const QString &spId, QTreeWidgetItem *item);

    // Custom UI elements
    QPushButton *enumMyConsentsBtn;
    QPushButton *enumAllConsentsBtn;
    QPushButton *enumAppConsentsBtn;
    QLineEdit *appIdInput;
    QCheckBox *resolveNamesCheckbox;
    QTreeWidget *resultsTree;
    QPushButton *copyBtn;
    QPushButton *exportBtn;

    // State
    QString currentToken;
    int pendingResolutions;
};

#endif // OAUTHCONSENTENUMERATORWINDOW_H
