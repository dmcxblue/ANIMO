#include "TenantSearchWindow.h"
#include "TokenOrPsBridge.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QTextStream>

namespace {

// Curated red-team default set: files, mail, and Teams chat are where
// creds usually live. Additional entity types kept opt-in via checkbox.
const QStringList kDefaultEntities = {
    QStringLiteral("driveItem"),
    QStringLiteral("message"),
    QStringLiteral("chatMessage"),
};

// Full set the Search API accepts. Order matters for the UI row.
const QList<QPair<QString, QString>> kEntityTypes = {
    { QStringLiteral("driveItem"),  QStringLiteral("OneDrive / SharePoint files") },
    { QStringLiteral("message"),    QStringLiteral("Mail") },
    { QStringLiteral("chatMessage"),QStringLiteral("Teams chat") },
    { QStringLiteral("event"),      QStringLiteral("Calendar events") },
    { QStringLiteral("site"),       QStringLiteral("SharePoint sites") },
    { QStringLiteral("list"),       QStringLiteral("SharePoint lists") },
    { QStringLiteral("listItem"),   QStringLiteral("List items") },
    { QStringLiteral("person"),     QStringLiteral("People") },
};

QString firstNonEmpty(std::initializer_list<QString> xs) {
    for (const QString &x : xs) if (!x.isEmpty()) return x;
    return QString();
}

}  // namespace

TenantSearchWindow::TenantSearchWindow(QWidget *parent)
    : EnumerationWindowBase(parent)
{
    setWindowTitle("Tenant Search (Microsoft Search API)");
    setupUi();
}

void TenantSearchWindow::setupUi() {
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required permissions (delegated): whatever the target entities need "
                "(Files.Read.All, Mail.Read, Chat.Read, etc.). App-only calls to "
                "/search/query aren't supported by Microsoft, so an SPN session will "
                "fall back to Invoke-MgGraphRequest in the session pwsh.");

    // Query row
    auto *queryGroup = new QGroupBox("Query", this);
    auto *queryOuter = new QVBoxLayout(queryGroup);

    auto *queryRow = new QHBoxLayout();
    queryInput = new QLineEdit(this);
    queryInput->setPlaceholderText("e.g. password | secret | vpn | onboarding");
    queryRow->addWidget(new QLabel("Search:", this));
    queryRow->addWidget(queryInput, 1);
    queryRow->addSpacing(12);
    queryRow->addWidget(new QLabel("Max per type:", this));
    sizeSpin = new QSpinBox(this);
    sizeSpin->setRange(1, 500);
    sizeSpin->setValue(50);
    queryRow->addWidget(sizeSpin);
    queryOuter->addLayout(queryRow);

    // Entity-type checkbox row
    auto *entityRow = new QHBoxLayout();
    entityRow->addWidget(new QLabel("Entities:", this));
    for (const auto &pair : kEntityTypes) {
        auto *cb = new QCheckBox(pair.second, this);
        cb->setChecked(kDefaultEntities.contains(pair.first));
        cb->setToolTip(QString("entityType = %1").arg(pair.first));
        entityChecks.insert(pair.first, cb);
        entityRow->addWidget(cb);
    }
    entityRow->addStretch();
    queryOuter->addLayout(entityRow);
    mainLayout->addWidget(queryGroup);

    // Actions row
    auto *actionsRow = new QHBoxLayout();
    searchBtn = new QPushButton("Search", this);
    StyleManager::applySuccessStyle(searchBtn);
    exportCsvBtn  = new QPushButton("Export CSV",  this);
    exportJsonBtn = new QPushButton("Export JSON", this);
    copyBtn       = new QPushButton("Copy Row",    this);
    actionsRow->addWidget(searchBtn);
    actionsRow->addStretch();
    actionsRow->addWidget(copyBtn);
    actionsRow->addWidget(exportCsvBtn);
    actionsRow->addWidget(exportJsonBtn);
    mainLayout->addLayout(actionsRow);

    // Results tree - grouped by entity type
    resultsTree = new QTreeWidget(this);
    resultsTree->setColumnCount(4);
    resultsTree->setHeaderLabels({ "Name / Sender", "Modified / Sent", "Type / Folder", "URL" });
    resultsTree->header()->setStretchLastSection(true);
    resultsTree->setAlternatingRowColors(true);
    resultsTree->setContextMenuPolicy(Qt::CustomContextMenu);
    mainLayout->addWidget(resultsTree, 1);

    setupBottomUi();

    connect(searchBtn,     &QPushButton::clicked, this, &TenantSearchWindow::startSearch);
    connect(exportCsvBtn,  &QPushButton::clicked, this, &TenantSearchWindow::exportCsv);
    connect(exportJsonBtn, &QPushButton::clicked, this, &TenantSearchWindow::exportJson);
    connect(copyBtn,       &QPushButton::clicked, this, &TenantSearchWindow::copySelectedRow);
    connect(queryInput,    &QLineEdit::returnPressed, this, &TenantSearchWindow::startSearch);
    connect(resultsTree,   &QWidget::customContextMenuRequested, this, [this](const QPoint &p){
        auto *item = resultsTree->itemAt(p);
        if (!item) return;
        QMenu m(this);
        m.addAction("Copy URL",   [item]() {
            QApplication::clipboard()->setText(item->text(3));
        });
        m.addAction("Copy Row",   this, &TenantSearchWindow::copySelectedRow);
        m.exec(resultsTree->viewport()->mapToGlobal(p));
    });

    resize(1100, 720);
}

QList<QPushButton*> TenantSearchWindow::getOperationButtons() {
    return { searchBtn, exportCsvBtn, exportJsonBtn, copyBtn };
}

void TenantSearchWindow::onCancelOperation() {
    // Bridge doesn't expose a per-call cancel handle; the base's
    // abortAllRequests handles any in-flight NAM reply on the HTTP path.
    // On the PS path the underlying run_command completes at its own pace.
}

void TenantSearchWindow::startSearch() {
    const QString query = queryInput->text().trimmed();
    if (query.isEmpty()) {
        QMessageBox::warning(this, "Missing Query", "Enter a search string first.");
        return;
    }

    QStringList selectedEntities;
    for (auto it = entityChecks.constBegin(); it != entityChecks.constEnd(); ++it) {
        if (it.value()->isChecked()) selectedEntities << it.key();
    }
    if (selectedEntities.isEmpty()) {
        QMessageBox::warning(this, "No Entity Types", "Tick at least one entity type.");
        return;
    }

    resultsTree->clear();
    collectedHits = QJsonArray();
    setLoading(true);
    logInfo(QString("Searching for '%1' across %2 entity type(s)...")
                .arg(query).arg(selectedEntities.size()));

    // Body per Search API: array of requests. We keep it to one request
    // covering all selected types - the Search service groups them into
    // separate hitsContainers in the response.
    QJsonObject queryObj{{ "queryString", query }};
    QJsonObject request{
        { "entityTypes", QJsonArray::fromStringList(selectedEntities) },
        { "query",       queryObj },
        { "from",        0 },
        { "size",        sizeSpin->value() },
    };
    QJsonObject body{{ "requests", QJsonArray{ request } }};

    // Same shape via PS - Invoke-MgGraphRequest emits its own JSON, so
    // suppress the auto-wrap.
    const QString psBody = QString::fromUtf8(QJsonDocument(body).toJson(QJsonDocument::Compact));
    const QString psScript = QString(
        "$body = @'\n%1\n'@; "
        "Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/search/query' "
        "-Body $body -ContentType 'application/json' -OutputType Json"
    ).arg(psBody);

    TokenOrPsBridge::Request req;
    req.sessionId  = userSelector->selectedSession();
    req.resource   = QStringLiteral("https://graph.microsoft.com");
    req.httpUrl    = QStringLiteral("https://graph.microsoft.com/v1.0/search/query");
    req.httpMethod = QStringLiteral("POST");
    req.httpBody   = QJsonDocument(body).toJson(QJsonDocument::Compact);
    req.psScript   = psScript;
    req.psWrap     = false;

    TokenOrPsBridge::fetch(this, req,
        [this](bool ok, const QJsonValue &result, const QString &source, const QString &err) {
            if (!ok) {
                logError(QString("Search failed: %1").arg(err));
                setLoading(false);
                return;
            }

            // /search/query -> { value: [ { hitsContainers: [ {total, hits: [...] } ] } ] }
            const QJsonArray responses = result.toObject().value("value").toArray();
            int totalHits = 0;
            for (const QJsonValue &respVal : responses) {
                const QJsonArray containers = respVal.toObject().value("hitsContainers").toArray();
                for (const QJsonValue &cVal : containers) {
                    const QJsonObject container = cVal.toObject();
                    const QJsonArray hits = container.value("hits").toArray();
                    for (const QJsonValue &hVal : hits) {
                        const QJsonObject hit = hVal.toObject();
                        const QString entityType =
                            hit.value("resource").toObject()
                               .value("@odata.type").toString();
                        renderHit(entityType, hit);
                        QJsonObject rec = hit;
                        rec.insert("_entityType", entityType);
                        collectedHits.append(rec);
                        ++totalHits;
                    }
                }
            }
            resultsTree->expandAll();
            logSuccess(QString("Returned %1 hit(s)  [source: %2]").arg(totalHits).arg(source));
            setLoading(false);
        });
}

void TenantSearchWindow::renderHit(const QString &entityType, const QJsonObject &hit) {
    // Group by @odata.type; strip Graph's #microsoft.graph. prefix for the label.
    QString typeLabel = entityType;
    if (typeLabel.startsWith(QStringLiteral("#microsoft.graph.")))
        typeLabel.remove(0, QString("#microsoft.graph.").size());

    QTreeWidgetItem *bucket = nullptr;
    for (int i = 0; i < resultsTree->topLevelItemCount(); ++i) {
        auto *b = resultsTree->topLevelItem(i);
        if (b->text(0) == typeLabel) { bucket = b; break; }
    }
    if (!bucket) {
        bucket = new QTreeWidgetItem(resultsTree);
        bucket->setText(0, typeLabel);
        bucket->setForeground(0, QColor(180, 200, 255));
    }

    const QJsonObject resource = hit.value("resource").toObject();
    const QString summary  = hit.value("summary").toString();
    const QString name     = firstNonEmpty({
        resource.value("name").toString(),
        resource.value("subject").toString(),
        resource.value("displayName").toString(),
        resource.value("title").toString(),
        summary.left(80),
    });
    const QString modified = firstNonEmpty({
        resource.value("lastModifiedDateTime").toString(),
        resource.value("sentDateTime").toString(),
        resource.value("createdDateTime").toString(),
    });
    const QString folder = firstNonEmpty({
        resource.value("parentReference").toObject().value("path").toString(),
        resource.value("from").toObject().value("emailAddress").toObject().value("address").toString(),
        resource.value("webUrl").toString(),
    });
    const QString url = firstNonEmpty({
        resource.value("webUrl").toString(),
        resource.value("id").toString(),
    });

    auto *node = new QTreeWidgetItem(bucket);
    node->setText(0, name);
    node->setText(1, modified);
    node->setText(2, folder);
    node->setText(3, url);
    node->setToolTip(0, summary);
    bucket->setText(1, QString("%1 hit(s)").arg(bucket->childCount()));
}

void TenantSearchWindow::copySelectedRow() {
    auto *item = resultsTree->currentItem();
    if (!item) return;
    QStringList cols;
    for (int c = 0; c < resultsTree->columnCount(); ++c) cols << item->text(c);
    QApplication::clipboard()->setText(cols.join("\t"));
    logInfo("Row copied to clipboard.");
}

void TenantSearchWindow::exportCsv() {
    if (collectedHits.isEmpty()) {
        QMessageBox::information(this, "No Results", "Nothing to export yet.");
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, "Export CSV", "tenant_search.csv", "CSV (*.csv)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export Failed", f.errorString());
        return;
    }
    QTextStream ts(&f);
    ts << "entityType,name,modified,folder_or_from,url,summary\n";
    for (const QJsonValue &v : collectedHits) {
        const QJsonObject hit = v.toObject();
        const QString et  = hit.value("_entityType").toString();
        const QJsonObject r = hit.value("resource").toObject();
        auto q = [](const QString &s){ QString e = s; e.replace('"', "\"\""); return QString("\"%1\"").arg(e); };
        ts << q(et) << ','
           << q(firstNonEmpty({ r.value("name").toString(), r.value("subject").toString(),
                                r.value("displayName").toString(), r.value("title").toString() })) << ','
           << q(firstNonEmpty({ r.value("lastModifiedDateTime").toString(),
                                r.value("sentDateTime").toString(),
                                r.value("createdDateTime").toString() })) << ','
           << q(firstNonEmpty({ r.value("parentReference").toObject().value("path").toString(),
                                r.value("from").toObject().value("emailAddress").toObject().value("address").toString() })) << ','
           << q(r.value("webUrl").toString()) << ','
           << q(hit.value("summary").toString()) << '\n';
    }
    logSuccess(QString("Wrote %1 rows to %2").arg(collectedHits.size()).arg(path));
}

void TenantSearchWindow::exportJson() {
    if (collectedHits.isEmpty()) {
        QMessageBox::information(this, "No Results", "Nothing to export yet.");
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, "Export JSON", "tenant_search.json", "JSON (*.json)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export Failed", f.errorString());
        return;
    }
    f.write(QJsonDocument(collectedHits).toJson(QJsonDocument::Indented));
    logSuccess(QString("Wrote %1 hits to %2").arg(collectedHits.size()).arg(path));
}
