#include "GatherAllWindow.h"
#include "UserSelectorWidget.h"
#include "StyleManager.h"
#include "NetworkHelper.h"

#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonArray>
#include <QFileDialog>
#include <QDir>
#include <QFile>
#include <QMessageBox>
#include <QDateTime>

GatherAllWindow::GatherAllWindow(QWidget *parent)
    : EnumerationWindowBase(parent), currentEndpointIndex(0)
{
    setWindowTitle("Gather All - Bulk Enumeration");
    setupUi();

    // Define all endpoints to gather
    endpoints = {
        {"organization", "https://graph.microsoft.com/v1.0/organization", false},
        {"users", "https://graph.microsoft.com/v1.0/users", false},
        {"groups", "https://graph.microsoft.com/v1.0/groups", false},
        {"applications", "https://graph.microsoft.com/v1.0/applications", false},
        {"servicePrincipals", "https://graph.microsoft.com/v1.0/servicePrincipals", false},
        {"directoryRoles", "https://graph.microsoft.com/v1.0/directoryRoles", false},
        {"oauth2PermissionGrants", "https://graph.microsoft.com/v1.0/oauth2PermissionGrants", false},
        {"authorizationPolicy", "https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy", true},
        {"conditionalAccessPolicies", "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", false},
        {"featureRolloutPolicies", "https://graph.microsoft.com/beta/policies/featureRolloutPolicies", true},
        {"domains", "https://graph.microsoft.com/v1.0/domains", false},
        {"subscribedSkus", "https://graph.microsoft.com/v1.0/subscribedSkus", false},
    };
}

void GatherAllWindow::setupUi()
{
    // Setup base UI first (creates mainLayout)
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required: Directory.Read.All (some endpoints need admin consent)");

    // Insert info banner at the top
    auto *infoLabel = new QLabel(
        "<b>Gather All</b> - Bulk enumerate all tenant data in one operation<br>"
        "<i>Collects:</i> Users, Groups, Apps, Service Principals, Roles, OAuth Grants, Policies, Domains<br>"
        "<i>Red Team Value:</i> Complete tenant snapshot for offline analysis and attack planning.", this);
    infoLabel->setStyleSheet("color: #ffc107; padding: 8px; background: #2a2a2a; border-radius: 3px;");
    infoLabel->setWordWrap(true);
    mainLayout->insertWidget(0, infoLabel);

    // Control buttons
    auto *controlGroup = new QGroupBox("Gather Controls", this);
    auto *controlLayout = new QHBoxLayout(controlGroup);

    gatherBtn = new QPushButton("Start Gather All", this);
    gatherBtn->setToolTip("Enumerate all tenant data");
    StyleManager::applyPrimaryStyle(gatherBtn);
    connect(gatherBtn, &QPushButton::clicked, this, &GatherAllWindow::startGather);

    exportBtn = new QPushButton("Export All to Folder", this);
    exportBtn->setEnabled(false);
    connect(exportBtn, &QPushButton::clicked, this, &GatherAllWindow::exportAll);

    exportFormatCombo = new QComboBox(this);
    exportFormatCombo->addItem("JSON", "json");
    exportFormatCombo->addItem("CSV (where applicable)", "csv");

    controlLayout->addWidget(gatherBtn);
    controlLayout->addWidget(cancelBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(new QLabel("Export format:", this));
    controlLayout->addWidget(exportFormatCombo);
    controlLayout->addWidget(exportBtn);

    mainLayout->addWidget(controlGroup);

    // Summary table
    auto *summaryGroup = new QGroupBox("Collection Summary", this);
    auto *summaryLayout = new QVBoxLayout(summaryGroup);

    summaryTable = new QTableWidget(0, 3, this);
    summaryTable->setHorizontalHeaderLabels({"Endpoint", "Status", "Items Collected"});
    summaryTable->horizontalHeader()->setStretchLastSection(true);
    summaryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    summaryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    summaryTable->setAlternatingRowColors(true);
    summaryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // Pre-populate with endpoints
    for (int i = 0; i < endpoints.size(); i++) {
        summaryTable->insertRow(i);
        summaryTable->setItem(i, 0, new QTableWidgetItem(endpoints[i].name));
        summaryTable->setItem(i, 1, new QTableWidgetItem("Pending"));
        summaryTable->setItem(i, 2, new QTableWidgetItem("-"));
    }

    summaryLayout->addWidget(summaryTable);
    mainLayout->addWidget(summaryGroup);

    setupBottomUi();

    resize(800, 700);
}

QList<QPushButton*> GatherAllWindow::getOperationButtons()
{
    return {gatherBtn};
}

void GatherAllWindow::startGather()
{
    QString token = getToken();
    if (token.isEmpty()) {
        logError("Please provide an access token");
        return;
    }

    if (!validateToken(token, "https://graph.microsoft.com")) {
        return;
    }

    // Reset state
    collectedData.clear();
    currentEndpointIndex = 0;
    exportBtn->setEnabled(false);

    // Reset table
    for (int i = 0; i < summaryTable->rowCount(); i++) {
        summaryTable->item(i, 1)->setText("Pending");
        summaryTable->item(i, 1)->setForeground(QColor("#888888"));
        summaryTable->item(i, 2)->setText("-");
    }

    setLoading(true);
    logInfo(QString("Starting bulk enumeration of %1 endpoints...").arg(endpoints.size()));
    updateProgress(0, endpoints.size());

    fetchNextEndpoint();
}

void GatherAllWindow::fetchNextEndpoint()
{
    if (cancelRequested || currentEndpointIndex >= endpoints.size()) {
        setLoading(false);
        exportBtn->setEnabled(!collectedData.isEmpty());

        int totalItems = 0;
        for (const auto &arr : collectedData) {
            totalItems += arr.size();
        }
        logSuccess(QString("Gather complete. Collected %1 total items across %2 endpoints")
            .arg(totalItems).arg(collectedData.size()));
        return;
    }

    const Endpoint &ep = endpoints[currentEndpointIndex];

    // Update table status
    summaryTable->item(currentEndpointIndex, 1)->setText("Fetching...");
    summaryTable->item(currentEndpointIndex, 1)->setForeground(QColor("#ffc107"));

    logInfo(QString("Fetching %1...").arg(ep.name));
    updateProgress(currentEndpointIndex, endpoints.size());

    QString token = getToken();
    QNetworkRequest req = createBearerRequest(ep.url, token);

    QNetworkReply *reply = net->get(req);
    trackReply(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, ep]() {
        untrackReply(reply);
        reply->deleteLater();

        if (cancelRequested) {
            setLoading(false);
            return;
        }

        int row = currentEndpointIndex;

        if (!NetworkHelper::isReplySuccess(reply)) {
            QString error = NetworkHelper::parseApiError(reply);
            summaryTable->item(row, 1)->setText("Failed");
            summaryTable->item(row, 1)->setForeground(QColor("#ff6666"));
            summaryTable->item(row, 2)->setText(error.left(50));
            logWarning(QString("%1: %2").arg(ep.name, error));
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();
            processResponse(ep.name, obj);
        }

        currentEndpointIndex++;
        fetchNextEndpoint();
    });
}

void GatherAllWindow::processResponse(const QString &name, const QJsonObject &response)
{
    int row = -1;
    for (int i = 0; i < endpoints.size(); i++) {
        if (endpoints[i].name == name) {
            row = i;
            break;
        }
    }

    if (row < 0) return;

    QJsonArray items;

    if (response.contains("value")) {
        items = response["value"].toArray();
    } else {
        // Single object response (like authorizationPolicy)
        items.append(response);
    }

    collectedData[name] = items;

    summaryTable->item(row, 1)->setText("Success");
    summaryTable->item(row, 1)->setForeground(QColor("#00ff00"));
    summaryTable->item(row, 2)->setText(QString::number(items.size()));

    logSuccess(QString("%1: %2 items").arg(name).arg(items.size()));

    // Handle pagination
    QString nextLink = response["@odata.nextLink"].toString();
    if (!nextLink.isEmpty() && !cancelRequested) {
        logInfo(QString("Fetching next page for %1...").arg(name));

        QString token = getToken();
        QNetworkRequest req = createBearerRequest(nextLink, token);

        QNetworkReply *reply = net->get(req);
        trackReply(reply);

        connect(reply, &QNetworkReply::finished, this, [this, reply, name]() {
            untrackReply(reply);
            reply->deleteLater();

            if (NetworkHelper::isReplySuccess(reply)) {
                QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
                QJsonObject obj = doc.object();
                QJsonArray moreItems = obj["value"].toArray();

                QJsonArray existing = collectedData[name];
                for (const QJsonValue &v : moreItems) {
                    existing.append(v);
                }
                collectedData[name] = existing;

                // Update count
                for (int i = 0; i < endpoints.size(); i++) {
                    if (endpoints[i].name == name) {
                        summaryTable->item(i, 2)->setText(QString::number(existing.size()));
                        break;
                    }
                }

                // Check for more pages
                QString nextNext = obj["@odata.nextLink"].toString();
                if (!nextNext.isEmpty()) {
                    processResponse(name, obj);
                }
            }
        });
    }
}

void GatherAllWindow::exportAll()
{
    if (collectedData.isEmpty()) {
        QMessageBox::information(this, "Export", "No data to export");
        return;
    }

    QString dir = QFileDialog::getExistingDirectory(this, "Select Export Directory");
    if (dir.isEmpty()) return;

    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString exportPath = QString("%1/gather_all_%2").arg(dir, timestamp);

    QDir().mkpath(exportPath);

    QString format = exportFormatCombo->currentData().toString();
    int exported = 0;

    for (const QString &name : collectedData.keys()) {
        const QJsonArray &data = collectedData[name];
        if (data.isEmpty()) continue;

        QString filename = QString("%1/%2.%3").arg(exportPath, name, format);
        QFile file(filename);

        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            if (format == "json") {
                QJsonDocument doc(data);
                file.write(doc.toJson(QJsonDocument::Indented));
            } else {
                // CSV export - basic implementation
                QTextStream out(&file);

                // Get all keys from first object
                if (!data.isEmpty() && data[0].isObject()) {
                    QJsonObject first = data[0].toObject();
                    QStringList keys = first.keys();
                    out << keys.join(",") << "\n";

                    for (const QJsonValue &v : data) {
                        QJsonObject obj = v.toObject();
                        QStringList values;
                        for (const QString &key : keys) {
                            QString val = obj[key].toVariant().toString();
                            val.replace("\"", "\"\"");
                            values.append(QString("\"%1\"").arg(val));
                        }
                        out << values.join(",") << "\n";
                    }
                }
            }
            file.close();
            exported++;
        }
    }

    logSuccess(QString("Exported %1 files to %2").arg(exported).arg(exportPath));
    QMessageBox::information(this, "Export Complete",
        QString("Exported %1 files to:\n%2").arg(exported).arg(exportPath));
}
