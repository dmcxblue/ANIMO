#include "CrossTenantAccessWindow.h"
#include "UserSelectorWidget.h"
#include "StyleManager.h"
#include "NetworkHelper.h"

#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QJsonDocument>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDateTime>

CrossTenantAccessWindow::CrossTenantAccessWindow(QWidget *parent)
    : EnumerationWindowBase(parent), pendingRequests(0)
{
    setWindowTitle("Cross-Tenant Access Policies");
    setupUi();
}

void CrossTenantAccessWindow::setupUi() {
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required: Policy.Read.All or CrossTenantInformation.ReadBasic.All");

    // Controls
    auto *controlLayout = new QHBoxLayout();
    fetchBtn = new QPushButton("Fetch Cross-Tenant Policies", this);
    copyBtn = new QPushButton("Copy Selected", this);
    exportBtn = new QPushButton("Export All", this);

    controlLayout->addWidget(fetchBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(copyBtn);
    controlLayout->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout);

    // Tab widget for Default Policy vs Partner Configurations
    tabWidget = new QTabWidget(this);

    // Tab 1: Default Policy
    auto *defaultTab = new QWidget();
    auto *defaultLayout = new QVBoxLayout(defaultTab);
    defaultPolicyView = new QTextEdit(this);
    defaultPolicyView->setReadOnly(true);
    defaultPolicyView->setPlaceholderText("Click 'Fetch Cross-Tenant Policies' to view the default policy...");
    defaultLayout->addWidget(defaultPolicyView);
    tabWidget->addTab(defaultTab, "Default Policy");

    // Tab 2: Partner Configurations (B2B Trust)
    auto *partnerTab = new QWidget();
    auto *partnerLayout = new QVBoxLayout(partnerTab);

    auto *partnerSplitter = new QSplitter(Qt::Horizontal, this);

    // Partner tree
    partnerTree = new QTreeWidget(this);
    partnerTree->setHeaderLabels({"Tenant ID", "Trust Type", "Inbound", "Outbound"});
    partnerTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    partnerTree->setAlternatingRowColors(true);
    partnerTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    partnerSplitter->addWidget(partnerTree);

    // Partner details view
    partnerDetailsView = new QTextEdit(this);
    partnerDetailsView->setReadOnly(true);
    partnerDetailsView->setPlaceholderText("Select a partner tenant to view details...");
    partnerSplitter->addWidget(partnerDetailsView);

    partnerSplitter->setSizes({400, 500});
    partnerLayout->addWidget(partnerSplitter);
    tabWidget->addTab(partnerTab, "Partner Tenants (B2B Trust)");

    mainLayout->addWidget(tabWidget, 1);

    setupBottomUi();

    // Connections
    connect(fetchBtn, &QPushButton::clicked, this, &CrossTenantAccessWindow::fetchPolicies);
    connect(partnerTree, &QTreeWidget::itemClicked, this, &CrossTenantAccessWindow::onPartnerSelected);
    connect(copyBtn, &QPushButton::clicked, this, &CrossTenantAccessWindow::copySelected);
    connect(exportBtn, &QPushButton::clicked, this, &CrossTenantAccessWindow::exportPolicies);

    resize(1100, 700);
}

QList<QPushButton*> CrossTenantAccessWindow::getOperationButtons() {
    return {fetchBtn, copyBtn, exportBtn};
}

void CrossTenantAccessWindow::onCancelOperation() {
    defaultPolicy = QJsonObject();
    partners = QJsonArray();
    pendingRequests = 0;
}

void CrossTenantAccessWindow::fetchPolicies() {
    QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) {
        return;
    }

    setLoading(true);
    logInfo("Fetching Cross-Tenant Access policies...");
    defaultPolicyView->clear();
    partnerTree->clear();
    partnerDetailsView->clear();
    defaultPolicy = QJsonObject();
    partners = QJsonArray();
    pendingRequests = 2;

    // Fetch default policy
    QString defaultUrl = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default";
    QNetworkReply *defaultReply = net->get(createBearerRequest(defaultUrl, token));

    if (!defaultReply) {
        logError("Failed to create request for default policy");
        pendingRequests--;
        if (pendingRequests == 0) setLoading(false);
        return;
    }

    trackReply(defaultReply);
    connect(defaultReply, &QNetworkReply::finished, this, [this, defaultReply]() {
        untrackReply(defaultReply);
        defaultReply->deleteLater();
        pendingRequests--;

        if (cancelRequested) {
            if (pendingRequests == 0) setLoading(false);
            return;
        }

        if (!NetworkHelper::isReplySuccess(defaultReply)) {
            logError(QString("Error fetching default policy: %1").arg(NetworkHelper::parseApiError(defaultReply)));
            int status = NetworkHelper::getHttpStatus(defaultReply);
            if (status == 403) {
                logWarning("Access denied. Token may lack Policy.Read.All permission.");
            }
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(defaultReply->readAll());
            defaultPolicy = doc.object();
            displayDefaultPolicy(defaultPolicy);
            logSuccess("Default cross-tenant policy retrieved");
        }

        if (pendingRequests == 0) setLoading(false);
    });

    // Fetch partner configurations
    QString partnersUrl = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners";
    QNetworkReply *partnersReply = net->get(createBearerRequest(partnersUrl, token));

    if (!partnersReply) {
        logError("Failed to create request for partner configurations");
        pendingRequests--;
        if (pendingRequests == 0) setLoading(false);
        return;
    }

    trackReply(partnersReply);
    connect(partnersReply, &QNetworkReply::finished, this, [this, partnersReply]() {
        untrackReply(partnersReply);
        partnersReply->deleteLater();
        pendingRequests--;

        if (cancelRequested) {
            if (pendingRequests == 0) setLoading(false);
            return;
        }

        if (!NetworkHelper::isReplySuccess(partnersReply)) {
            logError(QString("Error fetching partner configurations: %1").arg(NetworkHelper::parseApiError(partnersReply)));
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(partnersReply->readAll());
            partners = doc.object().value("value").toArray();

            if (partners.isEmpty()) {
                logWarning("No partner tenant configurations found (only default policy applies).");
            } else {
                logSuccess(QString("Found %1 partner tenant configuration(s)").arg(partners.size()));

                for (const QJsonValue &val : partners) {
                    QJsonObject partner = val.toObject();
                    QString tenantId = partner.value("tenantId").toString();

                    QString trustType = "Custom";
                    if (partner.value("isServiceProvider").toBool()) {
                        trustType = "Service Provider";
                    } else if (partner.value("isInMultiTenantOrganization").toBool()) {
                        trustType = "Multi-Tenant Org";
                    }

                    QString inboundSummary = "Default";
                    QString outboundSummary = "Default";

                    QJsonObject b2bInbound = partner.value("b2bCollaborationInbound").toObject();
                    QJsonObject b2bOutbound = partner.value("b2bCollaborationOutbound").toObject();

                    if (!b2bInbound.isEmpty()) {
                        QJsonObject usersApps = b2bInbound.value("usersAndGroups").toObject();
                        QString accessType = usersApps.value("accessType").toString();
                        if (accessType == "allowed") inboundSummary = "Allowed";
                        else if (accessType == "blocked") inboundSummary = "Blocked";
                    }

                    if (!b2bOutbound.isEmpty()) {
                        QJsonObject usersApps = b2bOutbound.value("usersAndGroups").toObject();
                        QString accessType = usersApps.value("accessType").toString();
                        if (accessType == "allowed") outboundSummary = "Allowed";
                        else if (accessType == "blocked") outboundSummary = "Blocked";
                    }

                    auto *item = new QTreeWidgetItem(partnerTree);
                    item->setText(0, tenantId);
                    item->setText(1, trustType);
                    item->setText(2, inboundSummary);
                    item->setText(3, outboundSummary);
                    item->setData(0, Qt::UserRole, QJsonDocument(partner).toJson());

                    if (inboundSummary == "Allowed") item->setForeground(2, QBrush(QColor("lightgreen")));
                    else if (inboundSummary == "Blocked") item->setForeground(2, QBrush(QColor("red")));
                    if (outboundSummary == "Allowed") item->setForeground(3, QBrush(QColor("lightgreen")));
                    else if (outboundSummary == "Blocked") item->setForeground(3, QBrush(QColor("red")));
                }
            }
        }

        if (pendingRequests == 0) setLoading(false);
    });
}

void CrossTenantAccessWindow::displayDefaultPolicy(const QJsonObject &policy) {
    QString html;
    html += "<h2>Default Cross-Tenant Access Policy</h2>";
    html += "<p>This policy applies to all external tenants unless overridden by a partner configuration.</p>";
    html += "<hr>";

    html += "<h3>B2B Collaboration Inbound</h3>";
    html += "<p><i>Controls how external users can access your organization.</i></p>";
    QJsonObject b2bInbound = policy.value("b2bCollaborationInbound").toObject();
    parseB2BSettings(b2bInbound, "Inbound", html);

    html += "<h3>B2B Collaboration Outbound</h3>";
    html += "<p><i>Controls how your users can access external organizations.</i></p>";
    QJsonObject b2bOutbound = policy.value("b2bCollaborationOutbound").toObject();
    parseB2BSettings(b2bOutbound, "Outbound", html);

    html += "<h3>Inbound Trust Settings</h3>";
    html += "<p><i>Whether to trust MFA and device claims from external organizations.</i></p>";
    QJsonObject inboundTrust = policy.value("inboundTrust").toObject();
    html += "<ul>";
    html += QString("<li><b>Trust MFA:</b> %1</li>")
        .arg(inboundTrust.value("isMfaAccepted").toBool() ? "Yes" : "No");
    html += QString("<li><b>Trust Compliant Devices:</b> %1</li>")
        .arg(inboundTrust.value("isCompliantDeviceAccepted").toBool() ? "Yes" : "No");
    html += QString("<li><b>Trust Hybrid Azure AD Joined:</b> %1</li>")
        .arg(inboundTrust.value("isHybridAzureADJoinedDeviceAccepted").toBool() ? "Yes" : "No");
    html += "</ul>";

    defaultPolicyView->setHtml(html);
}

void CrossTenantAccessWindow::parseB2BSettings(const QJsonObject &settings, const QString &direction, QString &html) {
    Q_UNUSED(direction);
    if (settings.isEmpty()) {
        html += "<p>Not configured (uses default behavior).</p>";
        return;
    }

    html += "<ul>";
    QJsonObject usersGroups = settings.value("usersAndGroups").toObject();
    if (!usersGroups.isEmpty()) {
        QString accessType = usersGroups.value("accessType").toString();
        html += QString("<li><b>Users/Groups Access:</b> %1</li>").arg(accessType);
    }

    QJsonObject applications = settings.value("applications").toObject();
    if (!applications.isEmpty()) {
        QString accessType = applications.value("accessType").toString();
        html += QString("<li><b>Applications Access:</b> %1</li>").arg(accessType);
    }
    html += "</ul>";
}

void CrossTenantAccessWindow::onPartnerSelected(QTreeWidgetItem *item, int column) {
    Q_UNUSED(column);
    if (!item) return;

    QByteArray jsonData = item->data(0, Qt::UserRole).toByteArray();
    QJsonDocument doc = QJsonDocument::fromJson(jsonData);
    QJsonObject partner = doc.object();

    displayPartnerDetails(partner);
}

void CrossTenantAccessWindow::displayPartnerDetails(const QJsonObject &partner) {
    QString html;
    QString tenantId = partner.value("tenantId").toString();

    html += QString("<h2>Partner Tenant: %1</h2>").arg(tenantId);

    html += "<h3>Configuration Details</h3>";
    html += "<ul>";
    html += QString("<li><b>Is Service Provider:</b> %1</li>")
        .arg(partner.value("isServiceProvider").toBool() ? "Yes" : "No");
    html += QString("<li><b>Is In Multi-Tenant Org:</b> %1</li>")
        .arg(partner.value("isInMultiTenantOrganization").toBool() ? "Yes" : "No");
    html += "</ul>";

    html += "<h3>B2B Collaboration Inbound</h3>";
    QJsonObject b2bInbound = partner.value("b2bCollaborationInbound").toObject();
    parseB2BSettings(b2bInbound, "Inbound", html);

    html += "<h3>B2B Collaboration Outbound</h3>";
    QJsonObject b2bOutbound = partner.value("b2bCollaborationOutbound").toObject();
    parseB2BSettings(b2bOutbound, "Outbound", html);

    html += "<h3>Inbound Trust Settings</h3>";
    QJsonObject inboundTrust = partner.value("inboundTrust").toObject();
    if (inboundTrust.isEmpty()) {
        html += "<p>Using default trust settings.</p>";
    } else {
        html += "<ul>";
        html += QString("<li><b>Trust MFA:</b> %1</li>")
            .arg(inboundTrust.value("isMfaAccepted").toBool() ? "Yes" : "No");
        html += QString("<li><b>Trust Compliant Devices:</b> %1</li>")
            .arg(inboundTrust.value("isCompliantDeviceAccepted").toBool() ? "Yes" : "No");
        html += "</ul>";
    }

    html += "<hr>";
    html += "<h3 style='color: #ff6b6b;'>Red Team Analysis</h3>";
    html += "<ul>";
    if (!b2bInbound.isEmpty()) {
        QJsonObject usersApps = b2bInbound.value("usersAndGroups").toObject();
        if (usersApps.value("accessType").toString() == "allowed") {
            html += "<li style='color: yellow;'>Inbound B2B is ALLOWED - external users from this tenant can access resources</li>";
        }
    }
    if (inboundTrust.value("isMfaAccepted").toBool()) {
        html += "<li style='color: yellow;'>MFA Trust Enabled - MFA from partner tenant is accepted (potential bypass vector)</li>";
    }
    html += "</ul>";

    partnerDetailsView->setHtml(html);
}

void CrossTenantAccessWindow::copySelected() {
    int currentTab = tabWidget->currentIndex();

    if (currentTab == 0) {
        if (defaultPolicy.isEmpty()) {
            QMessageBox::information(this, "No Data", "Please fetch policies first.");
            return;
        }
        QString prettyJson = QJsonDocument(defaultPolicy).toJson(QJsonDocument::Indented);
        QApplication::clipboard()->setText(prettyJson);
        logSuccess("Default policy JSON copied to clipboard");
    } else {
        auto *item = partnerTree->currentItem();
        if (!item) {
            QMessageBox::information(this, "No Selection", "Please select a partner tenant to copy.");
            return;
        }
        QByteArray jsonData = item->data(0, Qt::UserRole).toByteArray();
        QJsonDocument doc = QJsonDocument::fromJson(jsonData);
        QString prettyJson = doc.toJson(QJsonDocument::Indented);
        QApplication::clipboard()->setText(prettyJson);
        logSuccess("Partner configuration JSON copied to clipboard");
    }
}

void CrossTenantAccessWindow::exportPolicies() {
    if (defaultPolicy.isEmpty() && partners.isEmpty()) {
        QMessageBox::warning(this, "No Data", "Please fetch policies first.");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export Cross-Tenant Policies",
        "cross_tenant_access_policies.json", "JSON Files (*.json)");

    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }

    QJsonObject exportObj;
    exportObj.insert("defaultPolicy", defaultPolicy);
    exportObj.insert("partners", partners);
    exportObj.insert("exportDate", QDateTime::currentDateTime().toString(Qt::ISODate));
    exportObj.insert("partnerCount", partners.size());

    QJsonDocument doc(exportObj);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();

    logSuccess(QString("Exported cross-tenant policies to %1").arg(filename));
}
