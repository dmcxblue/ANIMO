#include "ConditionalAccessWindow.h"
#include "UserSelectorWidget.h"
#include "StyleManager.h"
#include "NetworkHelper.h"

#include <QSet>
#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDateTime>

ConditionalAccessWindow::ConditionalAccessWindow(QWidget *parent)
    : EnumerationWindowBase(parent)
{
    setWindowTitle("Conditional Access Policies");
    setupUi();
}

void ConditionalAccessWindow::setupUi() {
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Required: Policy.Read.All");

    // Controls
    auto *controlLayout = new QHBoxLayout();
    fetchBtn = new QPushButton("Fetch Policies", this);
    analyzeBtn = new QPushButton("Analyze Security Gaps", this);
    StyleManager::applyDangerStyle(analyzeBtn);
    analyzeBtn->setToolTip("Analyze policies for potential bypass vectors and security weaknesses");
    copyBtn = new QPushButton("Copy Selected", this);
    exportBtn = new QPushButton("Export All", this);

    controlLayout->addWidget(fetchBtn);
    controlLayout->addWidget(analyzeBtn);
    controlLayout->addStretch();
    controlLayout->addWidget(copyBtn);
    controlLayout->addWidget(exportBtn);
    mainLayout->addLayout(controlLayout);

    // Main splitter
    auto *mainSplitter = new QSplitter(Qt::Horizontal, this);

    // Policy tree
    policyTree = new QTreeWidget(this);
    policyTree->setHeaderLabels({"Policy Name", "State", "Created", "Modified"});
    policyTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    policyTree->setAlternatingRowColors(true);
    policyTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    mainSplitter->addWidget(policyTree);

    // Right side splitter (details + log)
    auto *rightSplitter = new QSplitter(Qt::Vertical, this);

    // Tabbed details area
    detailsTabs = new QTabWidget(this);

    // Details view tab
    detailsView = new QTextEdit(this);
    detailsView->setReadOnly(true);
    detailsView->setPlaceholderText("Select a policy to view details...");
    detailsTabs->addTab(detailsView, "Policy Details");

    // Security analysis tab
    securityView = new QTextEdit(this);
    securityView->setReadOnly(true);
    securityView->setPlaceholderText("Click 'Analyze Security Gaps' to identify potential bypass vectors...");
    detailsTabs->addTab(securityView, "Security Analysis");

    rightSplitter->addWidget(detailsTabs);

    mainSplitter->addWidget(rightSplitter);
    mainSplitter->setSizes({400, 500});

    mainLayout->addWidget(mainSplitter, 1);

    setupBottomUi();

    // Connections
    connect(fetchBtn, &QPushButton::clicked, this, &ConditionalAccessWindow::fetchPolicies);
    connect(analyzeBtn, &QPushButton::clicked, this, &ConditionalAccessWindow::analyzeSecurityGaps);
    connect(policyTree, &QTreeWidget::itemClicked, this, &ConditionalAccessWindow::onPolicySelected);
    connect(copyBtn, &QPushButton::clicked, this, &ConditionalAccessWindow::copySelectedPolicy);
    connect(exportBtn, &QPushButton::clicked, this, &ConditionalAccessWindow::exportPolicies);

    resize(1000, 600);
}

QList<QPushButton*> ConditionalAccessWindow::getOperationButtons() {
    return {fetchBtn, analyzeBtn, copyBtn, exportBtn};
}

void ConditionalAccessWindow::onCancelOperation() {
    policies = QJsonArray();
}

void ConditionalAccessWindow::fetchPolicies() {
    QString token = getToken();
    if (!validateToken(token, "graph.microsoft.com")) {
        return;
    }

    setLoading(true);
    logInfo("Fetching Conditional Access policies...");
    policyTree->clear();
    detailsView->clear();
    policies = QJsonArray();

    QString url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies";
    QNetworkReply *reply = net->get(createBearerRequest(url, token));

    if (!reply) {
        logError("Failed to create network request");
        setLoading(false);
        return;
    }

    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply);
        reply->deleteLater();
        setLoading(false);

        if (cancelRequested) return;

        QString errorMsg;
        if (!NetworkHelper::isReplySuccess(reply, &errorMsg)) {
            logError(QString("Error: %1").arg(errorMsg));

            int status = NetworkHelper::getHttpStatus(reply);
            if (status == 403) {
                logWarning("Access denied. Token may lack Policy.Read.All permission.");
            } else if (status == 401) {
                logWarning("Unauthorized. Token may be expired or invalid.");
            } else if (status == 429) {
                logWarning(QString("Rate limited. Retry after %1ms").arg(NetworkHelper::getRetryAfterMs(reply)));
            }
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray pols = doc.object().value("value").toArray();
        policies = pols;

        if (pols.isEmpty()) {
            logWarning("No Conditional Access policies found.");
            return;
        }

        logSuccess(QString("Found %1 policy(ies)").arg(pols.size()));

        for (const QJsonValue &val : pols) {
            QJsonObject pol = val.toObject();
            QString name = pol.value("displayName").toString();
            QString state = pol.value("state").toString();
            QString created = pol.value("createdDateTime").toString();
            QString modified = pol.value("modifiedDateTime").toString();

            auto *item = new QTreeWidgetItem(policyTree);
            item->setText(0, name);
            item->setText(1, state);
            item->setText(2, created.left(10));
            item->setText(3, modified.left(10));
            item->setData(0, Qt::UserRole, QJsonDocument(pol).toJson());

            if (state == "enabled") {
                item->setForeground(1, QBrush(QColor("lightgreen")));
            } else if (state == "disabled") {
                item->setForeground(1, QBrush(QColor("gray")));
            } else if (state == "enabledForReportingButNotEnforced") {
                item->setForeground(1, QBrush(QColor("yellow")));
            }
        }
    });
}

void ConditionalAccessWindow::onPolicySelected(QTreeWidgetItem *item, int column) {
    Q_UNUSED(column);
    if (!item) return;

    QByteArray jsonData = item->data(0, Qt::UserRole).toByteArray();
    QJsonDocument doc = QJsonDocument::fromJson(jsonData);
    QJsonObject policy = doc.object();

    displayPolicyDetails(policy);
}

void ConditionalAccessWindow::displayPolicyDetails(const QJsonObject &policy) {
    QString html;
    html += "<h3>" + policy.value("displayName").toString() + "</h3>";
    html += "<p><b>ID:</b> " + policy.value("id").toString() + "</p>";
    html += "<p><b>State:</b> " + policy.value("state").toString() + "</p>";

    QJsonObject conditions = policy.value("conditions").toObject();
    html += "<h4>Conditions:</h4><ul>";

    QJsonObject users = conditions.value("users").toObject();
    QJsonArray includeUsers = users.value("includeUsers").toArray();
    QJsonArray excludeUsers = users.value("excludeUsers").toArray();
    QJsonArray includeGroups = users.value("includeGroups").toArray();

    html += "<li><b>Include Users:</b> ";
    if (!includeUsers.isEmpty()) {
        QStringList userList;
        for (const auto &u : includeUsers) userList << u.toString();
        html += userList.join(", ");
    } else {
        html += "(none)";
    }
    html += "</li>";

    html += "<li><b>Exclude Users:</b> ";
    if (!excludeUsers.isEmpty()) {
        QStringList userList;
        for (const auto &u : excludeUsers) userList << u.toString();
        html += userList.join(", ");
    } else {
        html += "(none)";
    }
    html += "</li>";

    html += "<li><b>Include Groups:</b> ";
    if (!includeGroups.isEmpty()) {
        QStringList groupList;
        for (const auto &g : includeGroups) groupList << g.toString();
        html += groupList.join(", ");
    } else {
        html += "(none)";
    }
    html += "</li>";

    QJsonObject apps = conditions.value("applications").toObject();
    QJsonArray includeApps = apps.value("includeApplications").toArray();

    html += "<li><b>Include Apps:</b> ";
    if (!includeApps.isEmpty()) {
        QStringList appList;
        for (const auto &a : includeApps) appList << a.toString();
        html += appList.join(", ");
    } else {
        html += "(none)";
    }
    html += "</li>";

    QJsonObject platforms = conditions.value("platforms").toObject();
    QJsonArray includePlatforms = platforms.value("includePlatforms").toArray();
    if (!includePlatforms.isEmpty()) {
        QStringList platList;
        for (const auto &p : includePlatforms) platList << p.toString();
        html += "<li><b>Platforms:</b> " + platList.join(", ") + "</li>";
    }

    QJsonArray clientAppTypes = conditions.value("clientAppTypes").toArray();
    if (!clientAppTypes.isEmpty()) {
        QStringList appTypes;
        for (const auto &t : clientAppTypes) appTypes << t.toString();
        html += "<li><b>Client App Types:</b> " + appTypes.join(", ") + "</li>";
    }

    html += "</ul>";

    QJsonObject grantControls = policy.value("grantControls").toObject();
    html += "<h4>Grant Controls:</h4><ul>";

    QString grantOperator = grantControls.value("operator").toString();
    html += "<li><b>Operator:</b> " + grantOperator + "</li>";

    QJsonArray builtInControls = grantControls.value("builtInControls").toArray();
    if (!builtInControls.isEmpty()) {
        QStringList controls;
        for (const auto &c : builtInControls) controls << c.toString();
        html += "<li><b>Built-in Controls:</b> " + controls.join(", ") + "</li>";
    }

    html += "</ul>";

    detailsView->setHtml(html);
}

void ConditionalAccessWindow::copySelectedPolicy() {
    auto *item = policyTree->currentItem();
    if (!item) {
        QMessageBox::information(this, "No Selection", "Please select a policy to copy.");
        return;
    }

    QByteArray jsonData = item->data(0, Qt::UserRole).toByteArray();
    QJsonDocument doc = QJsonDocument::fromJson(jsonData);
    QString prettyJson = doc.toJson(QJsonDocument::Indented);

    QApplication::clipboard()->setText(prettyJson);
    logSuccess("Policy JSON copied to clipboard");
}

void ConditionalAccessWindow::exportPolicies() {
    if (policies.isEmpty()) {
        QMessageBox::warning(this, "No Data", "Please fetch policies first.");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export Policies",
        "conditional_access_policies.json", "JSON Files (*.json)");

    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }

    QJsonObject exportObj;
    exportObj.insert("policies", policies);
    exportObj.insert("exportDate", QDateTime::currentDateTime().toString(Qt::ISODate));
    exportObj.insert("count", policies.size());

    QJsonDocument doc(exportObj);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();

    logSuccess(QString("Exported %1 policies to %2").arg(policies.size()).arg(filename));
}

void ConditionalAccessWindow::analyzeSecurityGaps() {
    if (policies.isEmpty()) {
        QMessageBox::warning(this, "No Policies", "Please fetch policies first before analyzing.");
        return;
    }

    logInfo("Analyzing Conditional Access policies for security gaps...");

    QList<SecurityFinding> findings = analyzePolicies();

    displaySecurityFindings(findings);

    detailsTabs->setCurrentIndex(1);

    int critical = 0, high = 0, medium = 0, low = 0, info = 0;
    for (const auto &f : findings) {
        if (f.severity == "CRITICAL") critical++;
        else if (f.severity == "HIGH") high++;
        else if (f.severity == "MEDIUM") medium++;
        else if (f.severity == "LOW") low++;
        else info++;
    }

    logSuccess(QString("Analysis complete: %1 findings").arg(findings.size()));
    logWarning(QString("CRITICAL: %1 | HIGH: %2 | MEDIUM: %3 | LOW: %4 | INFO: %5")
              .arg(critical).arg(high).arg(medium).arg(low).arg(info));
}

QList<ConditionalAccessWindow::SecurityFinding> ConditionalAccessWindow::analyzePolicies() {
    QList<SecurityFinding> findings;

    bool hasAllUsersPolicy = false;
    bool hasLegacyAuthBlock = false;
    QSet<QString> excludedUsers;

    for (const QJsonValue &val : policies) {
        QJsonObject pol = val.toObject();
        QString name = pol.value("displayName").toString();
        QString state = pol.value("state").toString();

        QJsonObject conditions = pol.value("conditions").toObject();
        QJsonObject users = conditions.value("users").toObject();
        QJsonObject apps = conditions.value("applications").toObject();
        QJsonObject platforms = conditions.value("platforms").toObject();
        QJsonObject locations = conditions.value("locations").toObject();
        QJsonArray clientAppTypes = conditions.value("clientAppTypes").toArray();
        QJsonObject grantControls = pol.value("grantControls").toObject();
        QJsonArray builtInControls = grantControls.value("builtInControls").toArray();

        if (state == "enabledForReportingButNotEnforced") {
            findings.append({
                "HIGH", "Report-Only Mode", name,
                "Policy is in report-only mode and NOT enforced.",
                "If this policy is intended to protect resources, enable it fully."
            });
        }

        if (state == "disabled") {
            findings.append({
                "INFO", "Disabled Policy", name,
                "Policy is disabled and provides no protection.",
                "Review if this policy should be enabled."
            });
            continue;
        }

        QJsonArray exclUsers = users.value("excludeUsers").toArray();
        if (!exclUsers.isEmpty()) {
            QStringList userList;
            for (const auto &u : exclUsers) {
                QString userId = u.toString();
                userList << userId;
                excludedUsers.insert(userId);
            }
            findings.append({
                "MEDIUM", "User Exclusions", name,
                QString("Policy excludes %1 user(s). These accounts bypass this policy.").arg(exclUsers.size()),
                "Verify these are legitimate break-glass/emergency accounts."
            });
        }

        QJsonArray exclLocations = locations.value("excludeLocations").toArray();
        if (!exclLocations.isEmpty()) {
            findings.append({
                "HIGH", "Location Exclusions", name,
                "Policy excludes trusted locations. Access from these networks bypasses controls.",
                "Attackers with VPN/corporate network access can bypass this policy."
            });
        }

        QJsonArray inclPlatforms = platforms.value("includePlatforms").toArray();
        if (!inclPlatforms.isEmpty()) {
            QStringList platList;
            for (const auto &p : inclPlatforms) platList << p.toString();

            if (!platList.contains("all") && platList.size() < 4) {
                QStringList allPlatforms = {"windows", "macOS", "iOS", "android", "linux"};
                QStringList uncovered;
                for (const QString &p : allPlatforms) {
                    if (!platList.contains(p)) uncovered << p;
                }
                if (!uncovered.isEmpty()) {
                    findings.append({
                        "HIGH", "Platform Gap", name,
                        QString("Policy only covers: %1. NOT protected: %2").arg(platList.join(", ")).arg(uncovered.join(", ")),
                        "Attackers can use an unprotected platform to bypass this policy."
                    });
                }
            }
        }

        if (!clientAppTypes.isEmpty()) {
            QStringList appTypeList;
            for (const auto &t : clientAppTypes) appTypeList << t.toString();

            if (appTypeList.contains("exchangeActiveSync") || appTypeList.contains("other")) {
                hasLegacyAuthBlock = true;
            }
        }

        QJsonArray inclUsers = users.value("includeUsers").toArray();
        for (const auto &u : inclUsers) {
            if (u.toString() == "All") hasAllUsersPolicy = true;
        }
    }

    if (!hasLegacyAuthBlock && !policies.isEmpty()) {
        findings.append({
            "CRITICAL", "Legacy Auth Not Blocked", "(Global)",
            "No policy detected that blocks legacy authentication protocols.",
            "Create a policy to block legacy auth. Legacy protocols don't support MFA."
        });
    }

    if (!hasAllUsersPolicy && !policies.isEmpty()) {
        findings.append({
            "MEDIUM", "Incomplete User Coverage", "(Global)",
            "No policy targets 'All Users'. Some users may not be protected.",
            "Consider a baseline policy that applies to all users."
        });
    }

    if (excludedUsers.size() > 5) {
        findings.append({
            "HIGH", "Many Excluded Users", "(Global)",
            QString("%1 unique user accounts are excluded across policies.").arg(excludedUsers.size()),
            "Review all exclusions. High exclusion count increases attack surface."
        });
    }

    return findings;
}

void ConditionalAccessWindow::displaySecurityFindings(const QList<SecurityFinding> &findings) {
    QString html;
    html += "<h2>CA Bypass Analysis - Security Findings</h2>";
    html += QString("<p>Analyzed <b>%1</b> policies. Found <b>%2</b> potential issues.</p>")
            .arg(policies.size()).arg(findings.size());
    html += "<hr>";

    QMap<QString, QString> severityColors = {
        {"CRITICAL", "#dc3545"}, {"HIGH", "#fd7e14"},
        {"MEDIUM", "#ffc107"}, {"LOW", "#17a2b8"}, {"INFO", "#6c757d"}
    };

    QStringList severityOrder = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};

    for (const QString &sev : severityOrder) {
        QList<SecurityFinding> sevFindings;
        for (const auto &f : findings) {
            if (f.severity == sev) sevFindings.append(f);
        }

        if (sevFindings.isEmpty()) continue;

        QString color = severityColors.value(sev, "white");
        html += QString("<h3 style='color: %1;'>%2 (%3)</h3>").arg(color, sev).arg(sevFindings.size());

        for (const auto &f : sevFindings) {
            html += QString(
                "<div style='margin: 10px 0; padding: 10px; border-left: 4px solid %1; background: #2a2a2a;'>"
                "<b style='color: %1;'>[%2]</b> <b>%3</b><br>"
                "<span style='color: #aaa;'>Policy:</span> %4<br>"
                "<span style='color: #aaa;'>Issue:</span> %5<br>"
                "<span style='color: #5cb85c;'>Recommendation:</span> %6"
                "</div>"
            ).arg(color, f.severity, f.category, f.policyName, f.description, f.recommendation);
        }
    }

    if (findings.isEmpty()) {
        html += "<p style='color: #5cb85c;'>No obvious security gaps detected.</p>";
    }

    securityView->setHtml(html);
}
