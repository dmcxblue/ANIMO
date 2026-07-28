#ifndef AUTHMETHODPERSISTENCEWINDOW_H
#define AUTHMETHODPERSISTENCEWINDOW_H

#include "EnumerationWindowBase.h"
#include <QComboBox>
#include <QDateTimeEdit>
#include <QJsonArray>
#include <QLineEdit>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTableWidget>

// AuthMethodPersistenceWindow - write side of /users/{id}/authentication.
//
// Read-only enumeration lives in MfaStatusCheckerWindow (Discovery menu).
// This window is the offensive counterpart: mint a TAP, add a backdoor
// phone / alt email / software OATH method against a chosen target user,
// or delete an existing method for cleanup.
//
// FIDO2 and Microsoft Authenticator "push" registrations require a
// WebAuthn / Authenticator-app ceremony that can't be scripted from an
// HTTP call - those are read + delete only in this MVP.
class AuthMethodPersistenceWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit AuthMethodPersistenceWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void resolveTargetUser();
    void loadCurrentMethods();
    void addMethod();
    void deleteSelectedMethod();
    void generateOathSecret();
    void copyLastTapToClipboard();
    void onMethodTypeChanged(int index);

private:
    void setupUi();
    void setTargetUserId(const QString &id, const QString &upn);
    void appendMethodRow(const QJsonObject &method);

    // Target user
    QLineEdit *targetInput;              // accepts UPN or objectId
    QPushButton *resolveBtn;
    QLabel *resolvedLabel;
    QString resolvedUserId;              // objectId once resolved
    QString resolvedUserUpn;

    // Method-type write pane
    QComboBox *methodTypeCombo;
    QStackedWidget *methodStack;

    // TAP inputs
    QSpinBox *tapLifetimeSpin;           // minutes
    QComboBox *tapSingleUseCombo;        // usable-once yes/no
    QDateTimeEdit *tapStartTime;         // optional
    QLineEdit *lastTapCode;              // populated post-mint

    // Phone inputs
    QLineEdit *phoneNumberInput;
    QComboBox *phoneTypeCombo;

    // Email inputs
    QLineEdit *emailInput;

    // Software OATH inputs
    QLineEdit *oathSecretInput;
    QLineEdit *oathLabelInput;
    QPushButton *oathGenBtn;

    // Action buttons
    QPushButton *loadBtn;
    QPushButton *addBtn;
    QPushButton *deleteBtn;
    QPushButton *copyTapBtn;

    // Current methods table
    QTableWidget *methodsTable;
};

#endif  // AUTHMETHODPERSISTENCEWINDOW_H
