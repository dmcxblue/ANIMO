#ifndef DEVICEJOINWINDOW_H
#define DEVICEJOINWINDOW_H

#include "EnumerationWindowBase.h"
#include <QComboBox>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QTableWidget>

// DeviceJoinWindow - fresh Entra device registration via the DRS wire
// protocol (`https://enterpriseregistration.windows.net/EnrollmentServer/device/`).
//
// Flow:
//   1. Operator obtains a DRS-audience access token by device-code
//      login with client-id 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9
//      ("Device Registration Client", helpers/apps.json:121).
//   2. This window generates an RSA-2048 keypair via
//      DeviceCryptoHelper::generateRsa2048(), builds a PKCS#10 CSR, and
//      POSTs the enroll payload with a paired transport key.
//   3. On success, the returned deviceId + signed X.509 cert are
//      persisted to DeviceStore (encrypted at rest).
//
// Persistence value: the device cert survives password reset. A future
// commit will add cert-based PRT mint using
// DeviceCryptoHelper::signJwtRS256() and the JWT-bearer grant.
class DeviceJoinWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit DeviceJoinWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void performJoin();
    void refreshStoredList();
    void exportSelectedCert();
    void exportSelectedKey();
    void removeSelected();

private:
    void setupUi();

    // Inputs
    QLineEdit *displayNameInput;
    QLineEdit *osVersionInput;
    QLineEdit *tenantDomainInput;
    QComboBox *deviceTypeCombo;
    QComboBox *joinTypeCombo;

    // Action buttons
    QPushButton *joinBtn;
    QPushButton *refreshBtn;
    QPushButton *removeBtn;
    QPushButton *exportCertBtn;
    QPushButton *exportKeyBtn;

    // Post-join summary + stored devices
    QPlainTextEdit *joinSummary;
    QTableWidget   *storedTable;
};

#endif  // DEVICEJOINWINDOW_H
