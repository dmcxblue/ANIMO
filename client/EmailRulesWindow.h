#ifndef EMAILRULESWINDOW_H
#define EMAILRULESWINDOW_H

#include <QWidget>
#include <atomic>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTextEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QGroupBox>
#include <QProgressBar>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonArray>

class UserSelectorWidget;

/**
 * EmailRulesWindow - Inbox Rule Persistence for Red Team Operations
 *
 * Creates and manages Outlook inbox rules for:
 * - Email forwarding (copy to attacker inbox)
 * - Email redirection (move entirely, victim never sees)
 * - Keyword-based filtering (invoice, payment, wire, etc.)
 *
 * Attack Use Cases:
 * - BEC monitoring: Forward emails containing financial keywords
 * - Persistence: Rules survive password changes
 * - Stealth: Hidden rules with blank names
 */
class EmailRulesWindow : public QWidget {
    Q_OBJECT

public:
    explicit EmailRulesWindow(QWidget *parent = nullptr);
    ~EmailRulesWindow();

private slots:
    void listRules();
    void createRule();
    void deleteRule();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void onRuleSelected();
    void cancelRequests();

private:
    void setupUi();
    void updateTokenStatus();
    QNetworkRequest graphRequest(const QString &url, const QString &token);
    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);
    QString buildRuleJson();

    // Token section
    UserSelectorWidget *userSelector;
    QLineEdit *tokenInput;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;

    // Rules list
    QTableWidget *rulesTable;
    QPushButton *listRulesBtn;
    QPushButton *deleteRuleBtn;

    // Create rule section
    QGroupBox *createRuleGroup;
    QLineEdit *ruleNameInput;
    QComboBox *actionTypeCombo;      // Forward / Redirect / Move to folder
    QLineEdit *targetEmailInput;     // Forward/redirect target
    QCheckBox *stopProcessingCheck;  // Stop processing more rules

    // Conditions
    QLineEdit *subjectContainsInput;
    QLineEdit *fromContainsInput;
    QLineEdit *bodyContainsInput;
    QCheckBox *matchAllConditions;   // AND vs OR

    // Stealth options
    QCheckBox *hiddenRuleCheck;      // Use blank/space name
    QLineEdit *sequenceInput;        // Rule order (high = processed last)

    QPushButton *createRuleBtn;

    // Output
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QNetworkAccessManager *net;

    // State
    QString currentToken;
    QString selectedRuleId;
    QJsonArray existingRules;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};

#endif // EMAILRULESWINDOW_H
