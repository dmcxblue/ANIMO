#include "WhoAmIWindow.h"
#include "NetworkHelper.h"
#include "PsSessionRunner.h"
#include "StyleManager.h"
#include "TokenHelper.h"
#include "TokenStore.h"
#include "UserSelectorWidget.h"
#include "WhoAmiInsights.h"
#include "WindowFactory.h"
#include "WindowHelper.h"

#include <QSplitter>

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QMetaMethod>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSet>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextStream>
#include <QToolTip>
#include <QTreeWidget>
#include <QUrl>
#include <QUrlQuery>
#include <QVBoxLayout>

namespace {

// wids claim -> friendly Entra directory-role name. Kept short - the goal is a
// red-team readable label, not an exhaustive catalog. Templates come from the
// Microsoft docs "Azure AD built-in roles" list.
const QMap<QString, QString> &widToRole() {
    static const QMap<QString, QString> m = {
        {"62e90394-69f5-4237-9190-012177145e10", "Global Administrator"},
        {"e8611ab8-c189-46e8-94e1-60213ab1f814", "Privileged Role Administrator"},
        {"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "Application Administrator"},
        {"158c047a-c907-4556-b7ef-446551a6b5f7", "Cloud Application Administrator"},
        {"c4e39bd9-1100-46d3-8c65-fb160da0071f", "Authentication Administrator"},
        {"7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "Privileged Authentication Administrator"},
        {"29232cdf-9323-42fd-ade2-1d097af3e4de", "Exchange Administrator"},
        {"f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "SharePoint Administrator"},
        {"729827e3-9c14-49f7-bb1b-9608f156bbb8", "Helpdesk Administrator"},
        {"966707d0-3269-4727-9be2-8c3a10f19b9d", "Password Administrator"},
        {"b0f54661-2d74-4c50-afa3-1ec803f12efe", "Billing Administrator"},
        {"a9ea8996-122f-4c74-9520-8edcd192826c", "Skype for Business Administrator"},
        {"75941009-915a-4869-abe7-691bff18279e", "Teams Administrator"},
        {"3a2c62db-5318-420d-8d74-23affee5d9d5", "Intune Administrator"},
        {"194ae4cb-b126-40b2-bd5b-6091b380977d", "Security Administrator"},
        {"f2ef992c-3afb-46b9-b7cf-a126ee74c451", "Global Reader"},
        {"4a5d8f65-41da-4de4-8968-e035b65339cf", "Reports Reader"},
        {"5d6b6bb7-de71-4623-b4af-96380a352509", "Security Reader"},
        {"fdd7a751-b60b-444a-984c-02652fe8fa1c", "Groups Administrator"},
        {"fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator"},
        {"e6d1a23a-da11-4be4-9570-befc86d067a7", "Compliance Administrator"},
        {"88d8e3e3-8f55-4a1e-953a-9b9898b8876b", "Directory Readers"},
        {"9360feb5-f418-4baa-8175-e2a00bac4301", "Directory Writers"},
        {"c430b396-e693-46cc-96f3-db01bf8bb62a", "Attack Payload Author"},
        {"9c094953-4995-41c8-84c8-3ebb9b32c93f", "Attack Simulation Administrator"},
        {"14b83b21-be74-40e6-8c60-96017c67e8d0", "Application Developer"},
        {"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "Conditional Access Administrator"},
    };
    return m;
}

// Templates whose holders can reset passwords on regular users (per Microsoft
// docs). Auth Admin resets only limited users; Privileged Auth Admin resets any
// user including admins.
const QSet<QString> &passwordResetRoleTemplates() {
    static const QSet<QString> s = {
        "62e90394-69f5-4237-9190-012177145e10",  // Global Admin
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  // Privileged Role Admin
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  // Privileged Auth Admin
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",  // Auth Admin
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  // User Admin
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",  // Helpdesk Admin
        "966707d0-3269-4727-9be2-8c3a10f19b9d",  // Password Admin
    };
    return s;
}

QString jsonToDisplay(const QJsonValue &v) {
    switch (v.type()) {
        case QJsonValue::Null:   return QStringLiteral("null");
        case QJsonValue::Bool:   return v.toBool() ? QStringLiteral("true") : QStringLiteral("false");
        case QJsonValue::Double: return QString::number(v.toDouble(), 'f', 0);
        case QJsonValue::String: return v.toString();
        default: {
            QJsonDocument d;
            if (v.isArray()) d.setArray(v.toArray());
            else if (v.isObject()) d.setObject(v.toObject());
            return QString::fromUtf8(d.toJson(QJsonDocument::Compact));
        }
    }
}

QString classifyMember(const QJsonObject &o) {
    QString t = o.value("@odata.type").toString();
    if (t == "#microsoft.graph.group")              return "Group";
    if (t == "#microsoft.graph.directoryRole")      return "DirectoryRole";
    if (t == "#microsoft.graph.administrativeUnit") return "AdministrativeUnit";
    if (t == "#microsoft.graph.application")        return "Application";
    if (t == "#microsoft.graph.servicePrincipal")   return "ServicePrincipal";
    if (t == "#microsoft.graph.device")             return "Device";
    return t.isEmpty() ? QStringLiteral("Unknown") : t.mid(t.lastIndexOf('.') + 1);
}

QString friendlyAuthMethodType(const QString &odataType) {
    // "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" -> "microsoftAuthenticator"
    QString t = odataType.mid(odataType.lastIndexOf('.') + 1);
    if (t.endsWith("AuthenticationMethod")) t.chop(int(sizeof("AuthenticationMethod")) - 1);
    return t.isEmpty() ? odataType : t;
}

QColor authMethodColor(const QString &kind) {
    if (kind.contains("password", Qt::CaseInsensitive) ||
        kind.contains("email",    Qt::CaseInsensitive)) return QColor("#ff6b6b"); // weak
    if (kind.contains("temporaryAccessPass", Qt::CaseInsensitive)) return QColor("#f0b060");
    return QColor("#8fce8f"); // strong-ish default
}

}  // namespace

WhoAmIWindow::WhoAmIWindow(QWidget *parent)
    : EnumerationWindowBase(parent)
{
    setWindowTitle("WhoAmI - Entra / Azure Identity Overview");
    setupUi();
    setTargetResource(QStringLiteral("https://graph.microsoft.com"));
}

void WhoAmIWindow::setupUi() {
    setupBaseUi("Microsoft Graph Token",
                "Paste access token for https://graph.microsoft.com",
                "Uses Graph + Management tokens. Both are auto-fetched from the "
                "selected session's refresh token when missing and stored back "
                "under the same session id.");

    auto *controls = new QHBoxLayout();
    runBtn = new QPushButton("Run WhoAmI", this);
    StyleManager::applySuccessStyle(runBtn);
    copyBtn = new QPushButton("Copy Summary", this);
    exportBtn = new QPushButton("Export JSON", this);
    controls->addWidget(runBtn);
    controls->addStretch();
    controls->addWidget(copyBtn);
    controls->addWidget(exportBtn);
    mainLayout->addLayout(controls);

    tabs = new QTabWidget(this);

    // --- Identity tab ------------------------------------------------------
    auto *identityTab = new QWidget(this);
    auto *identityLayout = new QVBoxLayout(identityTab);

    guestBanner = new QLabel(identityTab);
    guestBanner->setTextFormat(Qt::RichText);
    guestBanner->setStyleSheet("background: #4a2020; color: #ffdada; padding: 6px; "
                               "border: 1px solid #7a3030; border-radius: 3px;");
    guestBanner->setVisible(false);
    identityLayout->addWidget(guestBanner);

    identityHeader = new QLabel("<i>Run WhoAmI to populate.</i>", identityTab);
    identityHeader->setTextFormat(Qt::RichText);
    identityHeader->setWordWrap(true);
    identityLayout->addWidget(identityHeader);

    tenantHeader = new QLabel(identityTab);
    tenantHeader->setTextFormat(Qt::RichText);
    tenantHeader->setWordWrap(true);
    tenantHeader->setStyleSheet("color: #b0b0b0; padding-top: 4px;");
    identityLayout->addWidget(tenantHeader);

    auto *identitySplit = new QSplitter(Qt::Vertical, identityTab);
    identityDetails = new QPlainTextEdit(identityTab);
    identityDetails->setReadOnly(true);
    identityDetails->setPlaceholderText("Graph /me response...");
    identitySplit->addWidget(identityDetails);

    claimsTree = new QTreeWidget(identityTab);
    claimsTree->setHeaderLabels({"Claim", "Value"});
    claimsTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    claimsTree->header()->setStretchLastSection(true);
    claimsTree->setAlternatingRowColors(true);
    makeCopyContextMenu(claimsTree);
    identitySplit->addWidget(claimsTree);
    identitySplit->setSizes({220, 320});
    identityLayout->addWidget(identitySplit, 1);
    tabs->addTab(identityTab, "Identity + Claims");

    // --- Capabilities tab --------------------------------------------------
    // Distils the raw facts collected on the other tabs into red-team-actionable
    // yes/no verdicts. Populated by renderCapabilities() from checkComplete().
    auto *capsTab = new QWidget(this);
    auto *capsLayout = new QVBoxLayout(capsTab);
    capsLayout->addWidget(new QLabel(
        "<b>Derived capability verdicts</b> - what this identity can actually do. "
        "Every row cites the evidence from the other tabs.", capsTab));

    auto *capsSplit = new QSplitter(Qt::Vertical, capsTab);

    capabilitiesTree = new QTreeWidget(capsTab);
    capabilitiesTree->setHeaderLabels({"Capability", "Verdict", "Because..."});
    capabilitiesTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    capabilitiesTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    capabilitiesTree->header()->setStretchLastSection(true);
    capabilitiesTree->setAlternatingRowColors(true);
    capabilitiesTree->setRootIsDecorated(false);
    makeCopyContextMenu(capabilitiesTree);
    capsSplit->addWidget(capabilitiesTree);

    // Fine-grained ARM actions - populated from `az role assignment list` +
    // `az role definition list` inside the session pwsh. Surfaces things like
    // Microsoft.Authorization/roleAssignments/write that a custom role could
    // expose without matching any built-in role name our derivation knows about.
    actionsTree = new QTreeWidget(capsTab);
    actionsTree->setHeaderLabels({"Scope / Role / Action", "Kind", "Notes"});
    actionsTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    actionsTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    actionsTree->header()->setStretchLastSection(true);
    actionsTree->setAlternatingRowColors(true);
    makeCopyContextMenu(actionsTree);
    capsSplit->addWidget(actionsTree);

    capsSplit->setStretchFactor(0, 3);
    capsSplit->setStretchFactor(1, 2);
    capsLayout->addWidget(capsSplit, 1);

    auto *capsBtnRow = new QHBoxLayout();
    copyCapabilitiesBtn = new QPushButton("Copy Summary", capsTab);
    connect(copyCapabilitiesBtn, &QPushButton::clicked, this, [this]() {
        QString out;
        for (int i = 0; i < capabilitiesTree->topLevelItemCount(); ++i) {
            auto *it = capabilitiesTree->topLevelItem(i);
            out += QString("%1  [%2]  %3\n").arg(it->text(0), it->text(1), it->text(2));
        }
        QApplication::clipboard()->setText(out);
        logInfo("Capabilities summary copied to clipboard.");
    });
    capsBtnRow->addStretch();
    capsBtnRow->addWidget(copyCapabilitiesBtn);
    capsLayout->addLayout(capsBtnRow);

    tabs->addTab(capsTab, "Capabilities");

    // --- Groups & Roles tab ------------------------------------------------
    auto *grTab = new QWidget(this);
    auto *grLayout = new QVBoxLayout(grTab);

    resetAbilityLabel = new QLabel(grTab);
    resetAbilityLabel->setTextFormat(Qt::RichText);
    resetAbilityLabel->setWordWrap(true);
    resetAbilityLabel->setStyleSheet("padding: 4px 6px;");
    grLayout->addWidget(resetAbilityLabel);

    auto *grBody = new QHBoxLayout();

    auto *groupsBox = new QVBoxLayout();
    groupsBox->addWidget(new QLabel("<b>Groups (transitive)</b>", grTab));
    groupsFilter = new QLineEdit(grTab);
    groupsFilter->setPlaceholderText("Filter groups...");
    groupsBox->addWidget(groupsFilter);
    groupsTree = new QTreeWidget(grTab);
    groupsTree->setHeaderLabels({"Display Name", "Type", "Id"});
    groupsTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    groupsTree->header()->setStretchLastSection(true);
    groupsTree->setAlternatingRowColors(true);
    groupsTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(groupsTree, &QTreeWidget::customContextMenuRequested,
            this, &WhoAmIWindow::onGroupsContextMenu);
    connect(groupsFilter, &QLineEdit::textChanged, this, [this](const QString&){
        applyFilter(groupsTree, groupsFilter);
    });
    groupsBox->addWidget(groupsTree, 1);
    grBody->addLayout(groupsBox, 1);

    auto *auBox = new QVBoxLayout();
    auBox->addWidget(new QLabel("<b>Administrative Units</b>", grTab));
    auTree = new QTreeWidget(grTab);
    auTree->setHeaderLabels({"Display Name", "Description", "Id"});
    auTree->header()->setStretchLastSection(true);
    auTree->setAlternatingRowColors(true);
    makeCopyContextMenu(auTree);
    auBox->addWidget(auTree, 1);
    grBody->addLayout(auBox, 1);

    auto *rolesCol = new QVBoxLayout();
    rolesCol->addWidget(new QLabel("<b>Active Directory Roles</b>", grTab));
    rolesFilter = new QLineEdit(grTab);
    rolesFilter->setPlaceholderText("Filter roles...");
    rolesCol->addWidget(rolesFilter);
    rolesTree = new QTreeWidget(grTab);
    rolesTree->setHeaderLabels({"Role", "Source / Scope", "Template Id"});
    rolesTree->header()->setStretchLastSection(true);
    rolesTree->setAlternatingRowColors(true);
    rolesTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(rolesTree, &QTreeWidget::customContextMenuRequested,
            this, &WhoAmIWindow::onRolesContextMenu);
    connect(rolesFilter, &QLineEdit::textChanged, this, [this](const QString&){
        applyFilter(rolesTree, rolesFilter);
    });
    rolesCol->addWidget(rolesTree, 1);

    rolesCol->addWidget(new QLabel("<b>PIM Eligible Roles (can activate)</b>", grTab));
    rolesEligibleTree = new QTreeWidget(grTab);
    rolesEligibleTree->setHeaderLabels({"Role", "Scope", "Ends"});
    rolesEligibleTree->header()->setStretchLastSection(true);
    rolesEligibleTree->setAlternatingRowColors(true);
    makeCopyContextMenu(rolesEligibleTree);
    rolesCol->addWidget(rolesEligibleTree, 1);
    grBody->addLayout(rolesCol, 1);

    grLayout->addLayout(grBody, 1);
    tabs->addTab(grTab, "Groups && Roles");

    // --- Owned tab ---------------------------------------------------------
    auto *ownedTab = new QWidget(this);
    auto *ownedLayout = new QVBoxLayout(ownedTab);
    auto *ownedIntro = new QLabel(
        "<b>Owned objects</b> - Applications / Service Principals / Groups / Devices "
        "this user directly owns. Owned applications are expanded to show their API "
        "permissions (delegated + application) - useful to know what a stolen app secret buys.",
        ownedTab);
    ownedIntro->setWordWrap(true);
    ownedLayout->addWidget(ownedIntro);

    auto *ownedControls = new QHBoxLayout();
    ownedFilter = new QLineEdit(ownedTab);
    ownedFilter->setPlaceholderText("Filter owned objects...");
    ownedControls->addWidget(ownedFilter, 1);
    ownedHighValueOnly = new QCheckBox("High-value only", ownedTab);
    ownedHighValueOnly->setToolTip("Show only Applications, Service Principals, and role-assignable Groups.");
    ownedControls->addWidget(ownedHighValueOnly);
    ownedLayout->addLayout(ownedControls);

    ownedTree = new QTreeWidget(ownedTab);
    ownedTree->setHeaderLabels({"Kind", "Display Name", "AppId / Identifier", "Id / Note"});
    ownedTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ownedTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ownedTree->header()->setStretchLastSection(true);
    ownedTree->setAlternatingRowColors(true);
    ownedTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ownedTree, &QTreeWidget::customContextMenuRequested,
            this, &WhoAmIWindow::onOwnedContextMenu);
    connect(ownedFilter, &QLineEdit::textChanged, this, [this](const QString&){
        applyFilter(ownedTree, ownedFilter);
    });
    connect(ownedHighValueOnly, &QCheckBox::toggled, this, [this](bool on){
        for (int i = 0; i < ownedTree->topLevelItemCount(); ++i) {
            auto *it = ownedTree->topLevelItem(i);
            const QString k = it->text(0);
            bool highValue = (k == "Application" || k == "ServicePrincipal" ||
                              (k == "Group" && it->text(3).contains("role-assignable")));
            it->setHidden(on && !highValue);
        }
    });
    ownedLayout->addWidget(ownedTree, 1);
    tabs->addTab(ownedTab, "Owned Apps / Groups / Devices");

    // --- RBAC tab ----------------------------------------------------------
    auto *rbacTab = new QWidget(this);
    auto *rbacLayout = new QVBoxLayout(rbacTab);
    rbacSummary = new QLabel("<i>Azure RBAC assignments across all accessible subscriptions.</i>",
                             rbacTab);
    rbacSummary->setWordWrap(true);
    rbacLayout->addWidget(rbacSummary);
    rbacTable = new QTableWidget(rbacTab);
    rbacTable->setColumnCount(5);
    rbacTable->setHorizontalHeaderLabels({"Subscription", "Scope", "Role", "Role Type", "Principal Type"});
    rbacTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    rbacTable->horizontalHeader()->setStretchLastSection(true);
    rbacTable->setAlternatingRowColors(true);
    rbacTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    rbacTable->setSortingEnabled(true);
    rbacTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(rbacTable, &QTableWidget::customContextMenuRequested,
            this, &WhoAmIWindow::onRbacContextMenu);
    rbacLayout->addWidget(rbacTable, 1);
    tabs->addTab(rbacTab, "Azure RBAC");

    // --- Access Surface tab (auth methods + sign-in + licenses + consents) --
    auto *asTab = new QWidget(this);
    auto *asLayout = new QVBoxLayout(asTab);

    signInLabel = new QLabel("<i>Sign-in activity not fetched yet (requires AuditLog.Read.All).</i>", asTab);
    signInLabel->setTextFormat(Qt::RichText);
    signInLabel->setStyleSheet("padding: 4px 6px;");
    asLayout->addWidget(signInLabel);

    auto *asBody = new QHBoxLayout();

    auto *amBox = new QVBoxLayout();
    amBox->addWidget(new QLabel("<b>Authentication methods</b>", asTab));
    authMethodsTree = new QTreeWidget(asTab);
    authMethodsTree->setHeaderLabels({"Method", "Detail", "Id"});
    authMethodsTree->header()->setStretchLastSection(true);
    authMethodsTree->setAlternatingRowColors(true);
    makeCopyContextMenu(authMethodsTree);
    amBox->addWidget(authMethodsTree, 1);
    asBody->addLayout(amBox, 1);

    auto *ogBox = new QVBoxLayout();
    ogBox->addWidget(new QLabel("<b>Consented OAuth grants (mine)</b>", asTab));
    oauthGrantsTree = new QTreeWidget(asTab);
    oauthGrantsTree->setHeaderLabels({"App (client)", "Resource", "Scopes"});
    oauthGrantsTree->header()->setStretchLastSection(true);
    oauthGrantsTree->setAlternatingRowColors(true);
    makeCopyContextMenu(oauthGrantsTree);
    ogBox->addWidget(oauthGrantsTree, 1);
    asBody->addLayout(ogBox, 1);

    auto *licBox = new QVBoxLayout();
    licBox->addWidget(new QLabel("<b>Licenses / SKUs</b>", asTab));
    licensesTree = new QTreeWidget(asTab);
    licensesTree->setHeaderLabels({"SKU Part Number", "SKU Id"});
    licensesTree->header()->setStretchLastSection(true);
    licensesTree->setAlternatingRowColors(true);
    makeCopyContextMenu(licensesTree);
    licBox->addWidget(licensesTree, 1);
    asBody->addLayout(licBox, 1);

    asLayout->addLayout(asBody, 1);
    tabs->addTab(asTab, "Access Surface");

    // --- Token perms tab ---------------------------------------------------
    auto *permTab = new QWidget(this);
    auto *permLayout = new QHBoxLayout(permTab);

    auto *scpBox = new QVBoxLayout();
    scpBox->addWidget(new QLabel("<b>Delegated scopes (scp)</b>", permTab));
    scopesTree = new QTreeWidget(permTab);
    scopesTree->setHeaderLabels({"Permission"});
    scopesTree->header()->setStretchLastSection(true);
    scopesTree->setAlternatingRowColors(true);
    makeCopyContextMenu(scopesTree);
    scpBox->addWidget(scopesTree, 1);
    permLayout->addLayout(scpBox, 1);

    auto *appRolesBox = new QVBoxLayout();
    appRolesBox->addWidget(new QLabel("<b>Application roles</b>", permTab));
    appRolesTree = new QTreeWidget(permTab);
    appRolesTree->setHeaderLabels({"Role"});
    appRolesTree->header()->setStretchLastSection(true);
    appRolesTree->setAlternatingRowColors(true);
    makeCopyContextMenu(appRolesTree);
    appRolesBox->addWidget(appRolesTree, 1);
    permLayout->addLayout(appRolesBox, 1);
    tabs->addTab(permTab, "Token Permissions");

    // --- Org tab -----------------------------------------------------------
    auto *orgTab = new QWidget(this);
    auto *orgLayout = new QVBoxLayout(orgTab);
    managerLabel = new QLabel("<i>Manager not fetched.</i>", orgTab);
    managerLabel->setTextFormat(Qt::RichText);
    orgLayout->addWidget(managerLabel);
    orgLayout->addWidget(new QLabel("<b>Direct Reports</b>", orgTab));
    reportsTree = new QTreeWidget(orgTab);
    reportsTree->setHeaderLabels({"Display Name", "UPN", "Job Title", "Id"});
    reportsTree->header()->setStretchLastSection(true);
    reportsTree->setAlternatingRowColors(true);
    makeCopyContextMenu(reportsTree);
    orgLayout->addWidget(reportsTree, 1);
    tabs->addTab(orgTab, "Org");

    mainLayout->addWidget(tabs, 1);
    setupBottomUi();

    connect(runBtn,    &QPushButton::clicked, this, &WhoAmIWindow::runWhoAmI);
    connect(exportBtn, &QPushButton::clicked, this, &WhoAmIWindow::exportReport);
    connect(copyBtn,   &QPushButton::clicked, this, &WhoAmIWindow::copyReport);

    // Every result view is read-only. Copy still works via the context menu.
    // Without this a stray double-click on any cell drops it into edit mode.
    for (QTreeWidget *tw : findChildren<QTreeWidget*>())
        tw->setEditTriggers(QAbstractItemView::NoEditTriggers);
    for (QTableWidget *tb : findChildren<QTableWidget*>())
        tb->setEditTriggers(QAbstractItemView::NoEditTriggers);

    resize(1350, 850);
}

QList<QPushButton*> WhoAmIWindow::getOperationButtons() {
    return {runBtn, exportBtn, copyBtn};
}

void WhoAmIWindow::onCancelOperation() {
    m_pending = 0;
    m_rbacRoleLookups = 0;
}

// ============================================================================
// Filter + copy context menu utilities
// ============================================================================

void WhoAmIWindow::applyFilter(QTreeWidget *tree, QLineEdit *edit) {
    if (!tree || !edit) return;
    const QString needle = edit->text().trimmed();
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        auto *it = tree->topLevelItem(i);
        bool match = needle.isEmpty();
        if (!match) {
            for (int c = 0; c < tree->columnCount(); ++c) {
                if (it->text(c).contains(needle, Qt::CaseInsensitive)) { match = true; break; }
            }
        }
        it->setHidden(!match);
    }
}

void WhoAmIWindow::makeCopyContextMenu(QTreeWidget *tree) {
    if (!tree) return;
    tree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tree, &QTreeWidget::customContextMenuRequested, this,
        [tree](const QPoint &pos) {
            auto *it = tree->itemAt(pos);
            QMenu menu;
            QAction *copyRow  = menu.addAction("Copy row");
            QAction *copyCell = menu.addAction("Copy cell");
            copyRow->setEnabled(it != nullptr);
            copyCell->setEnabled(it != nullptr);
            QAction *chosen = menu.exec(tree->viewport()->mapToGlobal(pos));
            if (!chosen || !it) return;
            if (chosen == copyRow) {
                QStringList cols;
                for (int c = 0; c < tree->columnCount(); ++c) cols << it->text(c);
                QApplication::clipboard()->setText(cols.join("\t"));
            } else if (chosen == copyCell) {
                const int col = tree->columnAt(pos.x());
                QApplication::clipboard()->setText(it->text(col < 0 ? 0 : col));
            }
        });
}

void WhoAmIWindow::makeTableCopyContextMenu(QTableWidget *table) {
    if (!table) return;
    table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(table, &QTableWidget::customContextMenuRequested, this,
        [table](const QPoint &pos) {
            const int row = table->rowAt(pos.y());
            const int col = table->columnAt(pos.x());
            if (row < 0) return;
            QMenu menu;
            QAction *copyRow  = menu.addAction("Copy row");
            QAction *copyCell = menu.addAction("Copy cell");
            QAction *chosen = menu.exec(table->viewport()->mapToGlobal(pos));
            if (!chosen) return;
            if (chosen == copyRow) {
                QStringList cols;
                for (int c = 0; c < table->columnCount(); ++c)
                    cols << (table->item(row, c) ? table->item(row, c)->text() : "");
                QApplication::clipboard()->setText(cols.join("\t"));
            } else if (chosen == copyCell) {
                if (col < 0) return;
                if (auto *it = table->item(row, col)) QApplication::clipboard()->setText(it->text());
            }
        });
}

// ============================================================================
// Right-click "Send To" menus (WhoAmI acts as a launcher)
// ============================================================================

void WhoAmIWindow::onOwnedContextMenu(const QPoint &pos) {
    auto *it = ownedTree->itemAt(pos);
    if (!it) return;
    QMenu menu;
    QAction *aCopyRow  = menu.addAction("Copy row");
    QAction *aCopyCell = menu.addAction("Copy cell");
    QAction *aOpenAddSecret = nullptr;
    QAction *aOpenGraph     = nullptr;
    const QString kind = it->text(0);
    const QString idText = it->text(2);
    const QString objectId = it->text(3).section(' ', 0, 0);
    if (kind == "Application" || kind == "ServicePrincipal") {
        menu.addSeparator();
        aOpenAddSecret = menu.addAction("Add secret to this app (opens Add App Secret)");
    }
    if (kind == "Group") {
        menu.addSeparator();
        aOpenGraph = menu.addAction("Query this group in Graph Query");
    }
    QAction *chosen = menu.exec(ownedTree->viewport()->mapToGlobal(pos));
    if (!chosen) return;

    if (chosen == aCopyRow) {
        QStringList cols;
        for (int c = 0; c < ownedTree->columnCount(); ++c) cols << it->text(c);
        QApplication::clipboard()->setText(cols.join("\t"));
    } else if (chosen == aCopyCell) {
        const int col = ownedTree->columnAt(pos.x());
        QApplication::clipboard()->setText(it->text(col < 0 ? 0 : col));
    } else if (chosen == aOpenAddSecret) {
        // Extract appId from "appId <guid>" or "appId <guid>  [type]".
        QString appId;
        const QRegularExpression rx(R"(appId\s+([0-9a-fA-F\-]{36}))");
        auto m = rx.match(idText);
        if (m.hasMatch()) appId = m.captured(1);
        QWidget *w = WindowFactory::createAddAzADAppSecretWindow(this);
        WindowHelper::setupWindow(w, this, 900, 600, 700, 400);
        if (!appId.isEmpty()) {
            // Try to prefill: any QLineEdit whose object name mentions "app" and
            // is empty is a candidate. Fallback: leave for the user to paste.
            const auto edits = w->findChildren<QLineEdit*>();
            for (QLineEdit *e : edits) {
                const QString name = e->objectName().toLower();
                if (name.contains("app") && e->text().isEmpty()) { e->setText(appId); break; }
            }
        }
        w->show();
        logInfo(QString("Opened Add App Secret prefilled with appId %1").arg(appId));
    } else if (chosen == aOpenGraph) {
        QWidget *w = WindowFactory::createGraphQueryWindow(this);
        WindowHelper::setupWindow(w, this, 1100, 700, 900, 500);
        // Best-effort prefill: first non-empty-QLineEdit that looks like the URL.
        const auto edits = w->findChildren<QLineEdit*>();
        for (QLineEdit *e : edits) {
            const QString ph = e->placeholderText().toLower();
            if (ph.contains("http") || ph.contains("graph") || e->objectName().contains("url", Qt::CaseInsensitive)) {
                e->setText(QString("https://graph.microsoft.com/v1.0/groups/%1?$expand=members").arg(objectId));
                break;
            }
        }
        w->show();
    }
}

void WhoAmIWindow::onGroupsContextMenu(const QPoint &pos) {
    auto *it = groupsTree->itemAt(pos);
    QMenu menu;
    QAction *aCopyRow = menu.addAction("Copy row");
    QAction *aCopyCell = menu.addAction("Copy cell");
    QAction *aOpenGraph = nullptr;
    if (it) {
        menu.addSeparator();
        aOpenGraph = menu.addAction("Query this group in Graph Query");
    }
    QAction *chosen = menu.exec(groupsTree->viewport()->mapToGlobal(pos));
    if (!chosen || !it) return;
    if (chosen == aCopyRow) {
        QStringList cols; for (int c = 0; c < groupsTree->columnCount(); ++c) cols << it->text(c);
        QApplication::clipboard()->setText(cols.join("\t"));
    } else if (chosen == aCopyCell) {
        const int col = groupsTree->columnAt(pos.x());
        QApplication::clipboard()->setText(it->text(col < 0 ? 0 : col));
    } else if (chosen == aOpenGraph) {
        QWidget *w = WindowFactory::createGraphQueryWindow(this);
        WindowHelper::setupWindow(w, this, 1100, 700, 900, 500);
        for (QLineEdit *e : w->findChildren<QLineEdit*>()) {
            const QString ph = e->placeholderText().toLower();
            if (ph.contains("http") || ph.contains("graph")) {
                e->setText(QString("https://graph.microsoft.com/v1.0/groups/%1?$expand=members").arg(it->text(2)));
                break;
            }
        }
        w->show();
    }
}

void WhoAmIWindow::onRolesContextMenu(const QPoint &pos) {
    auto *it = rolesTree->itemAt(pos);
    QMenu menu;
    QAction *aCopyRow  = menu.addAction("Copy row");
    QAction *aFindHolders = nullptr;
    if (it && !it->text(2).isEmpty()) {
        menu.addSeparator();
        aFindHolders = menu.addAction("Find other holders of this role in Graph Query");
    }
    QAction *chosen = menu.exec(rolesTree->viewport()->mapToGlobal(pos));
    if (!chosen || !it) return;
    if (chosen == aCopyRow) {
        QStringList cols; for (int c = 0; c < rolesTree->columnCount(); ++c) cols << it->text(c);
        QApplication::clipboard()->setText(cols.join("\t"));
    } else if (chosen == aFindHolders) {
        QWidget *w = WindowFactory::createGraphQueryWindow(this);
        WindowHelper::setupWindow(w, this, 1100, 700, 900, 500);
        for (QLineEdit *e : w->findChildren<QLineEdit*>()) {
            const QString ph = e->placeholderText().toLower();
            if (ph.contains("http") || ph.contains("graph")) {
                e->setText(QString(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/"
                    "roleAssignments?$filter=roleDefinitionId eq '%1'").arg(it->text(2)));
                break;
            }
        }
        w->show();
    }
}

void WhoAmIWindow::onRbacContextMenu(const QPoint &pos) {
    const int row = rbacTable->rowAt(pos.y());
    if (row < 0) return;
    QMenu menu;
    QAction *aCopyRow  = menu.addAction("Copy row");
    QAction *aCopyCell = menu.addAction("Copy cell");
    QAction *chosen = menu.exec(rbacTable->viewport()->mapToGlobal(pos));
    if (!chosen) return;
    if (chosen == aCopyRow) {
        QStringList cols;
        for (int c = 0; c < rbacTable->columnCount(); ++c)
            cols << (rbacTable->item(row, c) ? rbacTable->item(row, c)->text() : "");
        QApplication::clipboard()->setText(cols.join("\t"));
    } else if (chosen == aCopyCell) {
        const int col = rbacTable->columnAt(pos.x());
        if (col >= 0)
            if (auto *it = rbacTable->item(row, col)) QApplication::clipboard()->setText(it->text());
    }
}

// ============================================================================
// Main driver
// ============================================================================

void WhoAmIWindow::runWhoAmI() {
    if (!userSelector || !userSelector->hasSelection()) {
        logError("Select a session first.");
        return;
    }

    // Reset panes.
    guestBanner->setVisible(false);
    identityHeader->setText("<i>Fetching identity...</i>");
    tenantHeader->clear();
    identityDetails->clear();
    claimsTree->clear();
    groupsTree->clear();
    auTree->clear();
    rolesTree->clear();
    rolesEligibleTree->clear();
    resetAbilityLabel->clear();
    ownedTree->clear();
    rbacTable->setRowCount(0);
    rbacSummary->setText("<i>Fetching Azure RBAC assignments...</i>");
    scopesTree->clear();
    appRolesTree->clear();
    authMethodsTree->clear();
    oauthGrantsTree->clear();
    licensesTree->clear();
    signInLabel->setText("<i>Fetching sign-in activity...</i>");
    managerLabel->setText("<i>Fetching manager...</i>");
    reportsTree->clear();
    m_roleDefCache.clear();
    m_userOid.clear();
    m_userTid.clear();
    m_userUpn.clear();
    m_isGuest = false;
    m_activeRoleTemplateIds.clear();
    m_pending = 0;
    m_rbacRoleLookups = 0;

    setLoading(true);
    logInfo("Starting WhoAmI...");

    ensureTokensThen([this](const QString &graph, const QString &mgmt) {
        m_graphToken = graph;
        m_mgmtToken  = mgmt;

        const QJsonObject claims = TokenStore::parseJwtPayload(graph);
        m_userOid = claims.value("oid").toString();
        m_userTid = claims.value("tid").toString();
        m_userUpn = claims.value("upn").toString();
        if (m_userUpn.isEmpty()) m_userUpn = claims.value("preferred_username").toString();

        renderClaims(claims);
        renderTokenPerms(claims);

        if (m_userOid.isEmpty()) {
            logWarning("Graph token has no 'oid' claim - can't scope RBAC / PIM lookups. "
                       "Identity/Groups/Owned/AuthMethods will still work using /me.");
        } else {
            logSuccess(QString("Identity: %1  (oid: %2)").arg(m_userUpn, m_userOid.left(8)));
        }

        loadTenantOrg(graph);
        loadIdentityAndClaims(graph);
        loadMemberOf(graph);
        loadDirectoryRoleAssignments(graph);
        loadAuthorizationPolicy(graph);
        loadOwnedObjects(graph);
        loadOwnedDevices(graph);
        loadRegisteredDevices(graph);
        loadAuthMethods(graph);
        loadLicenses(graph);
        loadOAuthGrants(graph);
        loadManagerAndReports(graph);
        if (!m_userOid.isEmpty()) {
            loadPimEligibility(graph);
            loadPimActive(graph);
        }

        if (!mgmt.isEmpty() && !m_userOid.isEmpty()) {
            loadRbac(mgmt);
        } else if (mgmt.isEmpty()) {
            rbacSummary->setText("<i>No Management token available for this session - "
                                 "RBAC pane skipped.</i>");
            logWarning("Skipping RBAC lookup: no Management token could be obtained.");
        } else {
            rbacSummary->setText("<i>Graph token lacks 'oid' claim - RBAC lookup skipped.</i>");
        }

        // Fine-grained action enumeration runs in the session's own pwsh
        // (az cli first, Az PS fallback) and doesn't need any HTTP token
        // from us - the session context that Connect-AzAccount / `az login`
        // set up at login time already has what it needs.
        if (!m_userOid.isEmpty()) loadRbacActions();

        checkComplete();
    });
}

void WhoAmIWindow::ensureTokensThen(std::function<void(const QString&, const QString&)> next) {
    if (!userSelector || !userSelector->hasSelection()) return;

    const QString typed = getToken();

    auto haveGraph = [this, typed]() -> QString {
        if (!typed.isEmpty()) {
            const QString aud = NetworkHelper::extractTokenAudience(typed);
            if (aud.contains("graph.microsoft.com", Qt::CaseInsensitive)) return typed;
        }
        return userSelector->getExistingToken(QStringLiteral("https://graph.microsoft.com"));
    };

    auto haveMgmt = [this]() -> QString {
        return userSelector->getExistingToken(QStringLiteral("https://management.azure.com"));
    };

    QString g = haveGraph();
    QString m = haveMgmt();

    if (!g.isEmpty() && !m.isEmpty()) { next(g, m); return; }

    auto shared = std::make_shared<std::pair<QString, QString>>(g, m);
    auto pending = std::make_shared<int>(0);
    auto tryFinish = [this, shared, pending, next]() {
        if (*pending == 0) next(shared->first, shared->second);
    };

    if (g.isEmpty()) {
        (*pending)++;
        logInfo("Fetching Graph token for selected session...");
        userSelector->fetchToken(QStringLiteral("https://graph.microsoft.com"),
            [this, shared, pending, tryFinish](bool ok, const QString &tok, const QString &err) {
                (*pending)--;
                if (ok) {
                    shared->first = tok;
                    if (tokenInput) tokenInput->setText(tok);
                    updateTokenStatus();
                    logSuccess("Graph token acquired.");
                } else {
                    logError(QString("Graph token unavailable: %1").arg(err));
                }
                tryFinish();
            });
    }
    if (m.isEmpty()) {
        (*pending)++;
        logInfo("Fetching Management token for selected session (needed for Azure RBAC)...");
        userSelector->fetchToken(QStringLiteral("https://management.azure.com"),
            [this, shared, pending, tryFinish](bool ok, const QString &tok, const QString &err) {
                (*pending)--;
                if (ok) {
                    shared->second = tok;
                    logSuccess("Management token acquired.");
                } else {
                    logWarning(QString("Management token unavailable (RBAC pane will be skipped): %1").arg(err));
                }
                tryFinish();
            });
    }
    if (*pending == 0) next(shared->first, shared->second);
}

// ============================================================================
// Loaders
// ============================================================================

void WhoAmIWindow::loadTenantOrg(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;

    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/organization", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            tenantHeader->setText("<i>/organization failed (needs Organization.Read.All).</i>");
            checkComplete(); return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        if (arr.isEmpty()) { checkComplete(); return; }
        const QJsonObject o = arr.first().toObject();
        const QString name = o.value("displayName").toString();
        const bool synced  = o.value("onPremisesSyncEnabled").toBool();

        QStringList domains;
        for (const QJsonValue &v : o.value("verifiedDomains").toArray()) {
            const QJsonObject d = v.toObject();
            QString dom = d.value("name").toString();
            if (d.value("isDefault").toBool()) dom += " (default)";
            domains << dom;
        }
        tenantHeader->setText(QString("<span style='color:#888'>tenant:</span> <b>%1</b>&nbsp;&nbsp;"
                                      "<span style='color:#888'>hybrid:</span> %2&nbsp;&nbsp;"
                                      "<span style='color:#888'>domains:</span> %3")
                              .arg(name.toHtmlEscaped(),
                                   synced ? "yes (on-prem AD)" : "no (cloud-only)",
                                   domains.join(", ").toHtmlEscaped()));
        checkComplete();
    });
}

void WhoAmIWindow::loadIdentityAndClaims(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;

    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,displayName,mail,"
        "jobTitle,department,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName,"
        "userType,externalUserState,creationType,createdDateTime,mobilePhone,officeLocation,"
        "signInActivity",
        graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("/me failed: %1").arg(NetworkHelper::parseApiError(reply)));
            identityHeader->setText("<span style='color:#ff6b6b'>Identity fetch failed.</span>");
            checkComplete(); return;
        }
        const QJsonObject o = QJsonDocument::fromJson(reply->readAll()).object();
        const QString upn  = o.value("userPrincipalName").toString();
        const QString name = o.value("displayName").toString();
        const QString id   = o.value("id").toString();
        const bool enabled = o.value("accountEnabled").toBool();
        const bool synced  = o.value("onPremisesSyncEnabled").toBool();
        const QString userType = o.value("userType").toString();
        const QString externalState = o.value("externalUserState").toString();
        m_isGuest = (userType.compare("Guest", Qt::CaseInsensitive) == 0);

        if (m_isGuest) {
            guestBanner->setText(QString("<b>Guest / B2B account</b> - external state: %1. "
                                         "Guests have narrower access than members. Verify what this "
                                         "account can actually reach before planning next steps.")
                                 .arg(externalState.isEmpty() ? "unknown" : externalState.toHtmlEscaped()));
            guestBanner->setVisible(true);
        }

        identityHeader->setText(QString(
            "<b>%1</b> &nbsp; <span style='color:#888'>&lt;%2&gt;</span><br>"
            "<span style='color:#888'>oid:</span> %3 &nbsp;&nbsp; "
            "<span style='color:#888'>tid:</span> %4<br>"
            "<span style='color:#888'>account:</span> %5 &nbsp;&nbsp; "
            "<span style='color:#888'>hybrid sync:</span> %6 &nbsp;&nbsp; "
            "<span style='color:#888'>type:</span> %7")
            .arg(name.toHtmlEscaped(), upn.toHtmlEscaped(),
                 id.toHtmlEscaped(), m_userTid.toHtmlEscaped(),
                 enabled ? "<span style='color:#8fce8f'>enabled</span>"
                         : "<span style='color:#ff6b6b'>disabled</span>",
                 synced ? "<span style='color:#f0b060'>yes (on-prem AD)</span>"
                        : "<span style='color:#8fce8f'>no (cloud-only)</span>",
                 userType.isEmpty() ? QStringLiteral("Member") : userType.toHtmlEscaped()));

        // signInActivity requires AuditLog.Read.All AND a P1/P2 tenant. Handle gracefully.
        const QJsonObject sia = o.value("signInActivity").toObject();
        if (sia.isEmpty()) {
            signInLabel->setText("<i>signInActivity not available (needs AuditLog.Read.All + "
                                 "Azure AD Premium P1/P2).</i>");
        } else {
            signInLabel->setText(QString(
                "<b>Sign-in activity:</b> &nbsp;last interactive: <b>%1</b>&nbsp;&nbsp;"
                "last non-interactive: <b>%2</b>")
                .arg(sia.value("lastSignInDateTime").toString("unknown"),
                     sia.value("lastNonInteractiveSignInDateTime").toString("unknown")));
        }

        identityDetails->setPlainText(QString::fromUtf8(
            QJsonDocument(o).toJson(QJsonDocument::Indented)));
        logSuccess("Identity loaded.");
        checkComplete();
    });
}

void WhoAmIWindow::loadMemberOf(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$top=999", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("transitiveMemberOf failed: %1").arg(NetworkHelper::parseApiError(reply)));
            checkComplete(); return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        renderMemberOf(arr);
        logSuccess(QString("memberOf: %1 total").arg(arr.size()));
        deriveResetCapability();
        checkComplete();
    });
}

void WhoAmIWindow::loadDirectoryRoleAssignments(const QString &graphToken) {
    if (graphToken.isEmpty() || m_userOid.isEmpty()) return;
    m_pending++;
    // roleManagement API gives roleAssignments (permanent) + roleAssignmentScheduleInstances
    // (PIM active). Use the permanent list here; PIM active is loaded separately.
    const QString url = QString(
        "https://graph.microsoft.com/v1.0/roleManagement/directory/"
        "roleAssignments?$filter=principalId eq '%1'&$expand=roleDefinition").arg(m_userOid);
    QNetworkReply *reply = net->get(createBearerRequest(url, graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            // 403 is common if the token lacks RoleManagement.Read.Directory - skip quietly.
            checkComplete(); return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) {
            const QJsonObject a = v.toObject();
            const QJsonObject def = a.value("roleDefinition").toObject();
            auto *it = new QTreeWidgetItem(rolesTree);
            it->setText(0, def.value("displayName").toString());
            const QString scope = a.value("directoryScopeId").toString("/");
            it->setText(1, QString("roleAssignments  scope=%1").arg(scope));
            const QString tid = def.value("templateId").toString();
            it->setText(2, tid);
            it->setForeground(0, QBrush(QColor("#ff9060")));
            if (!tid.isEmpty()) m_activeRoleTemplateIds.insert(tid);
        }
        deriveResetCapability();
        checkComplete();
    });
}

void WhoAmIWindow::loadAuthorizationPolicy(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    // Tenant-wide "user role" permissions - what every non-admin user can do
    // by default (create apps, create security groups, invite guests, ...).
    // Cheap single GET; 403 is fine (older tenants restrict this).
    const QString url = QStringLiteral(
        "https://graph.microsoft.com/v1.0/policies/authorizationPolicy");
    QNetworkReply *reply = net->get(createBearerRequest(url, graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) { checkComplete(); return; }

        // v1.0 returns a single object; some tenants return {value:[{...}]}.
        QJsonObject root = QJsonDocument::fromJson(reply->readAll()).object();
        if (root.contains("value") && root.value("value").isArray()) {
            const QJsonArray arr = root.value("value").toArray();
            if (!arr.isEmpty()) root = arr.first().toObject();
        }
        const QJsonObject defaults =
            root.value("defaultUserRolePermissions").toObject();
        m_defaultAllowedToCreateApps =
            defaults.value("allowedToCreateApps").toBool(false);
        m_defaultAllowedToCreateSecurityGroups =
            defaults.value("allowedToCreateSecurityGroups").toBool(false);
        m_defaultAllowedToReadOtherUsers =
            defaults.value("allowedToReadOtherUsers").toBool(true);
        m_defaultAllowedToCreateTenants =
            defaults.value("allowedToCreateTenants").toBool(false);
        m_authPolicyLoaded = true;
        checkComplete();
    });
}

void WhoAmIWindow::loadRbacActions() {
    // Runs inside the session's pwsh (which is authenticated for both Az PS
    // and az cli after Slice 6/7). Tries az cli first because it enumerates
    // faster and often has broader read scope; falls back to
    // Get-AzRoleAssignment + Get-AzRoleDefinition.
    //
    // Returns: an array of {scope, roleName, actions[], notActions[],
    // dataActions[], notDataActions[], source}. If neither toolchain returns
    // anything the callback just runs with an empty array.
    if (!userSelector) return;
    const QString sid = userSelector->selectedSession();
    if (sid.isEmpty()) return;
    if (m_userOid.isEmpty()) return;

    // Escape the OID for embedding in single-quoted PS string.
    QString escOid = m_userOid;
    escOid.replace('\'', QStringLiteral("''"));

    // The wrapper (PsSessionRunner default) will apply `@(...)|ConvertTo-Json`,
    // so this script just needs to leave an array-of-objects at the pipeline
    // tail.
    const QString script = QString(
        "$oid='%1';"
        "$rows=@();"
        "try{"
          "$j=& az role assignment list --all --assignee $oid -o json 2>$null;"
          "if($LASTEXITCODE -eq 0 -and $j){"
            "$defs=@{};"
            "foreach($a in ($j|ConvertFrom-Json)){"
              "$rn=$a.roleDefinitionName;"
              "if(-not $defs.ContainsKey($rn)){"
                "$d=& az role definition list --name $rn -o json 2>$null;"
                "if($LASTEXITCODE -eq 0 -and $d){$defs[$rn]=($d|ConvertFrom-Json|Select-Object -First 1).permissions}"
              "}"
              "$perms=$defs[$rn];"
              "$rows+=[pscustomobject]@{"
                "scope=$a.scope;"
                "roleName=$rn;"
                "actions=@($perms|ForEach-Object{$_.actions}|Where-Object{$_}|Sort-Object -Unique);"
                "dataActions=@($perms|ForEach-Object{$_.dataActions}|Where-Object{$_}|Sort-Object -Unique);"
                "notActions=@($perms|ForEach-Object{$_.notActions}|Where-Object{$_}|Sort-Object -Unique);"
                "notDataActions=@($perms|ForEach-Object{$_.notDataActions}|Where-Object{$_}|Sort-Object -Unique);"
                "source='azcli'"
              "}"
            "}"
          "}"
        "}catch{}"
        "if($rows.Count -eq 0){"
          "try{"
            "$assignments=Get-AzRoleAssignment -ObjectId $oid -EA Stop;"
            "$defMap=@{};"
            "foreach($a in $assignments){"
              "if(-not $defMap.ContainsKey($a.RoleDefinitionId)){"
                "$defMap[$a.RoleDefinitionId]=Get-AzRoleDefinition -Id $a.RoleDefinitionId"
              "}"
              "$d=$defMap[$a.RoleDefinitionId];"
              "$rows+=[pscustomobject]@{"
                "scope=$a.Scope;"
                "roleName=$a.RoleDefinitionName;"
                "actions=@($d.Actions);"
                "dataActions=@($d.DataActions);"
                "notActions=@($d.NotActions);"
                "notDataActions=@($d.NotDataActions);"
                "source='azps'"
              "}"
            "}"
          "}catch{}"
        "}"
        "$rows"
    ).arg(escOid);

    m_pending++;
    PsSessionRunner::run(this, sid, script,
        [this](bool ok, const QJsonValue &json, const QString &raw) {
            m_pending--;
            m_actionsLoaded = true;
            if (!ok || !json.isArray()) {
                if (!ok) logWarning(QString("Fine-grained RBAC action lookup failed: %1")
                                        .arg(raw.left(200)));
                checkComplete();
                return;
            }
            const QJsonArray arr = json.toArray();
            for (const QJsonValue &v : arr) {
                if (!v.isObject()) continue;
                const QJsonObject o = v.toObject();
                m_rbacActionRows.append(o);
                if (m_actionsSource.isEmpty()) m_actionsSource = o.value("source").toString();
                for (const QJsonValue &a : o.value("actions").toArray())
                    m_allControlActions.insert(a.toString());
                for (const QJsonValue &a : o.value("dataActions").toArray())
                    m_allDataActions.insert(a.toString());
            }
            if (!arr.isEmpty()) {
                logSuccess(QString("Fine-grained RBAC actions: %1 role assignment(s), "
                                   "%2 unique control actions, %3 data actions  [%4]")
                                .arg(arr.size())
                                .arg(m_allControlActions.size())
                                .arg(m_allDataActions.size())
                                .arg(m_actionsSource));
            }
            checkComplete();
        }, /*wrap=*/true, /*depth=*/6);
}

void WhoAmIWindow::loadPimEligibility(const QString &graphToken) {
    m_pending++;
    const QString url = QString(
        "https://graph.microsoft.com/v1.0/roleManagement/directory/"
        "roleEligibilityScheduleInstances?$filter=principalId eq '%1'&$expand=roleDefinition")
        .arg(m_userOid);
    QNetworkReply *reply = net->get(createBearerRequest(url, graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            // PIM API needs P2 or the required permissions - fine if skipped.
            checkComplete(); return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) renderPimSchedule(v.toObject(), true);
        if (!arr.isEmpty()) logSuccess(QString("PIM eligible: %1 role(s)").arg(arr.size()));
        checkComplete();
    });
}

void WhoAmIWindow::loadPimActive(const QString &graphToken) {
    m_pending++;
    const QString url = QString(
        "https://graph.microsoft.com/v1.0/roleManagement/directory/"
        "roleAssignmentScheduleInstances?$filter=principalId eq '%1'&$expand=roleDefinition")
        .arg(m_userOid);
    QNetworkReply *reply = net->get(createBearerRequest(url, graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) { checkComplete(); return; }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) renderPimSchedule(v.toObject(), false);
        if (!arr.isEmpty()) logSuccess(QString("PIM active: %1 role(s)").arg(arr.size()));
        deriveResetCapability();
        checkComplete();
    });
}

void WhoAmIWindow::loadOwnedObjects(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/ownedObjects?$top=999", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, graphToken]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            logError(QString("ownedObjects failed: %1").arg(NetworkHelper::parseApiError(reply)));
            checkComplete(); return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        renderOwnedObjects(arr, graphToken);
        logSuccess(QString("ownedObjects: %1").arg(arr.size()));
        checkComplete();
    });
}

void WhoAmIWindow::loadOwnedDevices(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/ownedDevices?$top=999", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            logWarning(QString("ownedDevices skipped: %1").arg(NetworkHelper::parseApiError(reply)));
            checkComplete(); return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        renderOwnedDevices(arr);
        if (!arr.isEmpty()) logSuccess(QString("ownedDevices: %1").arg(arr.size()));
        checkComplete();
    });
}

void WhoAmIWindow::loadRegisteredDevices(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/registeredDevices?$top=999", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) { checkComplete(); return; }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) {
            const QJsonObject o = v.toObject();
            auto *it = new QTreeWidgetItem(ownedTree);
            it->setText(0, "Device (registered)");
            it->setText(1, o.value("displayName").toString());
            it->setText(2, QString("%1 %2").arg(o.value("operatingSystem").toString(),
                                                 o.value("operatingSystemVersion").toString()));
            it->setText(3, o.value("id").toString());
            it->setForeground(0, QBrush(QColor("#b0b0b0")));
        }
        if (!arr.isEmpty()) logSuccess(QString("registeredDevices: %1").arg(arr.size()));
        checkComplete();
    });
}

void WhoAmIWindow::loadOAuthGrants(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants?$top=999", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) { checkComplete(); return; }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) renderOAuthGrant(v.toObject());
        if (!arr.isEmpty()) logSuccess(QString("oauth2PermissionGrants: %1").arg(arr.size()));
        checkComplete();
    });
}

void WhoAmIWindow::loadAuthMethods(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/authentication/methods", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            // Common: UserAuthenticationMethod.Read scope missing.
            checkComplete(); return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) renderAuthMethod(v.toObject());
        if (!arr.isEmpty()) logSuccess(QString("authentication methods: %1").arg(arr.size()));
        checkComplete();
    });
}

void WhoAmIWindow::loadLicenses(const QString &graphToken) {
    if (graphToken.isEmpty()) return;
    m_pending++;
    QNetworkReply *reply = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/licenseDetails", graphToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) { checkComplete(); return; }
        const QJsonArray arr = QJsonDocument::fromJson(reply->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) renderLicense(v.toObject());
        checkComplete();
    });
}

void WhoAmIWindow::loadManagerAndReports(const QString &graphToken) {
    if (graphToken.isEmpty()) return;

    m_pending++;
    QNetworkReply *mr = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/manager", graphToken));
    trackReply(mr);
    connect(mr, &QNetworkReply::finished, this, [this, mr]() {
        untrackReply(mr); mr->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(mr)) {
            managerLabel->setText("<i>Manager: not set / not readable.</i>");
            checkComplete(); return;
        }
        const QJsonObject o = QJsonDocument::fromJson(mr->readAll()).object();
        managerLabel->setText(QString("<b>Manager:</b> %1 &lt;%2&gt;")
            .arg(o.value("displayName").toString("(none)").toHtmlEscaped(),
                 o.value("userPrincipalName").toString().toHtmlEscaped()));
        checkComplete();
    });

    m_pending++;
    QNetworkReply *dr = net->get(createBearerRequest(
        "https://graph.microsoft.com/v1.0/me/directReports?$top=999", graphToken));
    trackReply(dr);
    connect(dr, &QNetworkReply::finished, this, [this, dr]() {
        untrackReply(dr); dr->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(dr)) { checkComplete(); return; }
        const QJsonArray arr = QJsonDocument::fromJson(dr->readAll()).object().value("value").toArray();
        for (const QJsonValue &v : arr) {
            const QJsonObject o = v.toObject();
            auto *it = new QTreeWidgetItem(reportsTree);
            it->setText(0, o.value("displayName").toString());
            it->setText(1, o.value("userPrincipalName").toString());
            it->setText(2, o.value("jobTitle").toString());
            it->setText(3, o.value("id").toString());
        }
        checkComplete();
    });
}

void WhoAmIWindow::loadRbac(const QString &mgmtToken) {
    if (mgmtToken.isEmpty() || m_userOid.isEmpty()) return;
    m_pending++;

    QNetworkReply *reply = net->get(createBearerRequest(
        "https://management.azure.com/subscriptions?api-version=2020-01-01", mgmtToken));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, mgmtToken]() {
        untrackReply(reply); reply->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(reply)) {
            rbacSummary->setText(QString("<span style='color:#ff6b6b'>Subscriptions call failed: %1</span>")
                                 .arg(NetworkHelper::parseApiError(reply)));
            logError(QString("Subscriptions call failed: %1").arg(NetworkHelper::parseApiError(reply)));
            checkComplete(); return;
        }
        const QJsonArray subs = QJsonDocument::fromJson(reply->readAll())
                                    .object().value("value").toArray();
        if (subs.isEmpty()) {
            rbacSummary->setText("<i>User has access to 0 subscriptions.</i>");
            checkComplete(); return;
        }
        rbacSummary->setText(QString("Scanning %1 subscription(s) for role assignments...").arg(subs.size()));

        for (const QJsonValue &v : subs) {
            const QJsonObject sub = v.toObject();
            const QString subId   = sub.value("subscriptionId").toString();
            const QString subName = sub.value("displayName").toString();
            if (subId.isEmpty()) continue;

            m_pending++;
            const QString url = QString(
                "https://management.azure.com/subscriptions/%1/providers/"
                "Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
                "&$filter=principalId+eq+'%2'").arg(subId, m_userOid);

            QNetworkReply *r = net->get(createBearerRequest(url, mgmtToken));
            trackReply(r);
            connect(r, &QNetworkReply::finished, this, [this, r, mgmtToken, subId, subName]() {
                untrackReply(r); r->deleteLater(); m_pending--;
                if (!NetworkHelper::isReplySuccess(r)) {
                    logWarning(QString("roleAssignments %1: %2").arg(subName,
                                NetworkHelper::parseApiError(r)));
                    checkComplete(); return;
                }
                const QJsonArray asgn = QJsonDocument::fromJson(r->readAll())
                                            .object().value("value").toArray();
                for (const QJsonValue &av : asgn) {
                    const QJsonObject a  = av.toObject();
                    const QJsonObject p  = a.value("properties").toObject();
                    const QString roleId = p.value("roleDefinitionId").toString();
                    const QString scope  = p.value("scope").toString();
                    const QString ptype  = p.value("principalType").toString();

                    if (m_roleDefCache.contains(roleId)) {
                        const auto v = m_roleDefCache.value(roleId);
                        addRbacRow(subName, scope, v.first, v.second, ptype);
                    } else {
                        m_rbacRoleLookups++;
                        m_pending++;
                        resolveRoleDefinition(mgmtToken, roleId,
                            [this, subName, scope, ptype](const QString &name, const QString &type) {
                                addRbacRow(subName, scope, name, type, ptype);
                                m_pending--;
                                checkComplete();
                            });
                    }
                }
                checkComplete();
            });
        }
        checkComplete();
    });
}

void WhoAmIWindow::resolveRoleDefinition(const QString &mgmtToken,
                                          const QString &roleDefId,
                                          std::function<void(const QString&, const QString&)> cb) {
    const QString url = QString("https://management.azure.com%1?api-version=2022-04-01")
                            .arg(roleDefId);
    QNetworkReply *r = net->get(createBearerRequest(url, mgmtToken));
    trackReply(r);
    connect(r, &QNetworkReply::finished, this, [this, r, roleDefId, cb]() {
        untrackReply(r); r->deleteLater();
        QString name = roleDefId.section('/', -1);
        QString type = "Unknown";
        if (NetworkHelper::isReplySuccess(r)) {
            const QJsonObject o = QJsonDocument::fromJson(r->readAll()).object();
            const QJsonObject p = o.value("properties").toObject();
            const QString rn = p.value("roleName").toString();
            const QString rt = p.value("type").toString();
            if (!rn.isEmpty()) name = rn;
            if (!rt.isEmpty()) type = rt;
        }
        m_roleDefCache[roleDefId] = qMakePair(name, type);
        cb(name, type);
    });
}

// ============================================================================
// Owned-object detail loaders
// ============================================================================

void WhoAmIWindow::loadOwnedAppDetail(const QString &graphToken, const QString &appObjectId,
                                        const QString &appDisplayName, QTreeWidgetItem *anchor) {
    if (graphToken.isEmpty() || appObjectId.isEmpty() || !anchor) return;

    m_pending++;
    const QString url = QString("https://graph.microsoft.com/v1.0/applications/%1"
                                "?$select=requiredResourceAccess,appId").arg(appObjectId);
    QNetworkReply *r = net->get(createBearerRequest(url, graphToken));
    trackReply(r);
    connect(r, &QNetworkReply::finished, this, [this, r, anchor, appDisplayName]() {
        untrackReply(r); r->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(r)) { checkComplete(); return; }
        const QJsonObject o = QJsonDocument::fromJson(r->readAll()).object();
        const QJsonArray rra = o.value("requiredResourceAccess").toArray();
        auto *permHeader = new QTreeWidgetItem(anchor);
        permHeader->setText(0, "Permissions");
        permHeader->setText(1, QString("declared on '%1'").arg(appDisplayName));
        permHeader->setForeground(0, QBrush(QColor("#b0b0b0")));
        for (const QJsonValue &v : rra) {
            const QJsonObject app = v.toObject();
            const QString resAppId = app.value("resourceAppId").toString();
            auto *resNode = new QTreeWidgetItem(permHeader);
            resNode->setText(0, "resource");
            resNode->setText(1, resAppId);
            for (const QJsonValue &rv : app.value("resourceAccess").toArray()) {
                const QJsonObject ra = rv.toObject();
                auto *pn = new QTreeWidgetItem(resNode);
                pn->setText(0, ra.value("type").toString());
                pn->setText(1, ra.value("id").toString());
                pn->setText(2, "requiredResourceAccess");
                if (ra.value("type").toString() == "Role")
                    pn->setForeground(0, QBrush(QColor("#ff6b6b")));
                else
                    pn->setForeground(0, QBrush(QColor("#f0b060")));
            }
        }
        anchor->setExpanded(false);
        checkComplete();
    });
}

void WhoAmIWindow::loadOwnedGroupMembers(const QString &graphToken, const QString &groupId,
                                          QTreeWidgetItem *anchor) {
    if (graphToken.isEmpty() || groupId.isEmpty() || !anchor) return;

    m_pending++;
    const QString url = QString("https://graph.microsoft.com/v1.0/groups/%1/members?$top=25"
                                "&$select=id,displayName,userPrincipalName").arg(groupId);
    QNetworkReply *r = net->get(createBearerRequest(url, graphToken));
    trackReply(r);
    connect(r, &QNetworkReply::finished, this, [this, r, anchor]() {
        untrackReply(r); r->deleteLater(); m_pending--;
        if (!NetworkHelper::isReplySuccess(r)) { checkComplete(); return; }
        const QJsonArray arr = QJsonDocument::fromJson(r->readAll()).object().value("value").toArray();
        auto *memHdr = new QTreeWidgetItem(anchor);
        memHdr->setText(0, "Members");
        memHdr->setText(1, QString("first %1").arg(arr.size()));
        memHdr->setForeground(0, QBrush(QColor("#b0b0b0")));
        for (const QJsonValue &v : arr) {
            const QJsonObject o = v.toObject();
            auto *mn = new QTreeWidgetItem(memHdr);
            mn->setText(0, "member");
            mn->setText(1, o.value("displayName").toString());
            mn->setText(2, o.value("userPrincipalName").toString());
            mn->setText(3, o.value("id").toString());
        }
        checkComplete();
    });
}

// ============================================================================
// Rendering
// ============================================================================

void WhoAmIWindow::renderClaims(const QJsonObject &claims) {
    static const QStringList priority = {
        "upn", "preferred_username", "name", "oid", "tid", "aud", "iss",
        "appid", "azp", "app_displayname", "amr", "acr", "auth_time",
        "ipaddr", "onprem_sid", "roles", "wids", "groups", "scp",
        "family_name", "given_name", "unique_name", "xms_cae", "xms_pl", "xms_tpl"
    };
    QSet<QString> seen;
    auto add = [&](const QString &k) {
        if (!claims.contains(k) || seen.contains(k)) return;
        seen.insert(k);
        auto *item = new QTreeWidgetItem(claimsTree);
        item->setText(0, k);
        item->setText(1, jsonToDisplay(claims.value(k)));
        if (k == "wids" || k == "roles" || k == "scp")
            item->setForeground(0, QBrush(QColor("#f0b060")));
        if (k == "xms_cae")
            item->setToolTip(0, "Continuous Access Evaluation: this token can be revoked mid-flight.");
    };
    for (const QString &k : priority) add(k);
    for (auto it = claims.constBegin(); it != claims.constEnd(); ++it) add(it.key());

    // Expand wids into human-readable roles on the roles tab.
    const QJsonArray wids = claims.value("wids").toArray();
    for (const QJsonValue &v : wids) {
        const QString wid = v.toString();
        const QString name = widToRole().value(wid, "Unknown role template");
        auto *it = new QTreeWidgetItem(rolesTree);
        it->setText(0, name);
        it->setText(1, "wids (JWT)");
        it->setText(2, wid);
        it->setForeground(0, QBrush(QColor("#ff9060")));
        m_activeRoleTemplateIds.insert(wid);
    }
}

void WhoAmIWindow::renderMemberOf(const QJsonArray &members) {
    for (const QJsonValue &v : members) {
        const QJsonObject o = v.toObject();
        const QString kind = classifyMember(o);
        if (kind == "DirectoryRole") {
            auto *it = new QTreeWidgetItem(rolesTree);
            it->setText(0, o.value("displayName").toString());
            it->setText(1, "directoryRole (Graph)");
            it->setText(2, o.value("roleTemplateId").toString());
            it->setForeground(0, QBrush(QColor("#ff6b6b")));
            const QString tid = o.value("roleTemplateId").toString();
            if (!tid.isEmpty()) m_activeRoleTemplateIds.insert(tid);
        } else if (kind == "AdministrativeUnit") {
            auto *it = new QTreeWidgetItem(auTree);
            it->setText(0, o.value("displayName").toString());
            it->setText(1, o.value("description").toString());
            it->setText(2, o.value("id").toString());
        } else {
            auto *it = new QTreeWidgetItem(groupsTree);
            it->setText(0, o.value("displayName").toString());
            it->setText(1, kind);
            it->setText(2, o.value("id").toString());
            const bool roleAssignable = o.value("isAssignableToRole").toBool();
            if (roleAssignable) {
                it->setForeground(1, QBrush(QColor("#f0b060")));
                it->setText(1, kind + " *role-assignable");
                it->setToolTip(0, "Members of this group inherit directory-role assignments.");
            }
        }
    }
}

void WhoAmIWindow::renderOwnedObjects(const QJsonArray &owned, const QString &graphToken) {
    for (const QJsonValue &v : owned) {
        const QJsonObject o = v.toObject();
        const QString kind = classifyMember(o);
        auto *it = new QTreeWidgetItem(ownedTree);
        it->setText(0, kind);
        it->setText(1, o.value("displayName").toString());
        if (kind == "Application") {
            const QString appId = o.value("appId").toString();
            it->setText(2, "appId " + appId);
            it->setText(3, o.value("id").toString());
            it->setForeground(0, QBrush(QColor("#8fce8f")));
            loadOwnedAppDetail(graphToken, o.value("id").toString(),
                               o.value("displayName").toString(), it);
        } else if (kind == "ServicePrincipal") {
            const QString appId = o.value("appId").toString();
            const QString spType = o.value("servicePrincipalType").toString();
            it->setText(2, QString("appId %1  [%2]").arg(appId, spType));
            it->setText(3, o.value("id").toString());
            it->setForeground(0, QBrush(QColor("#8fce8f")));
        } else if (kind == "Group") {
            const bool roleAssignable = o.value("isAssignableToRole").toBool();
            it->setText(2, o.value("mailNickname").toString());
            it->setText(3, o.value("id").toString() + (roleAssignable ? "  (role-assignable)" : ""));
            if (roleAssignable) {
                it->setForeground(0, QBrush(QColor("#ff6b6b")));
                it->setToolTip(0, "You own a role-assignable group - self-add is a directory-role path.");
            }
            loadOwnedGroupMembers(graphToken, o.value("id").toString(), it);
        } else {
            it->setText(2, o.value("appId").toString());
            it->setText(3, o.value("id").toString());
        }
    }
}

void WhoAmIWindow::renderOwnedDevices(const QJsonArray &devices) {
    for (const QJsonValue &v : devices) {
        const QJsonObject o = v.toObject();
        auto *it = new QTreeWidgetItem(ownedTree);
        it->setText(0, "Device (owned)");
        it->setText(1, o.value("displayName").toString());
        it->setText(2, o.value("operatingSystem").toString() + " " +
                       o.value("operatingSystemVersion").toString());
        it->setText(3, o.value("id").toString());
    }
}

void WhoAmIWindow::renderTokenPerms(const QJsonObject &claims) {
    const QString scp = claims.value("scp").toString();
    if (!scp.isEmpty()) {
        for (const QString &s : scp.split(' ', Qt::SkipEmptyParts)) {
            auto *it = new QTreeWidgetItem(scopesTree);
            it->setText(0, s);
            if (s.contains("ReadWrite.All", Qt::CaseInsensitive) ||
                s.contains("Directory.ReadWrite", Qt::CaseInsensitive) ||
                s.contains("full_access", Qt::CaseInsensitive))
                it->setForeground(0, QBrush(QColor("#ff6b6b")));
            else if (s.endsWith(".All"))
                it->setForeground(0, QBrush(QColor("#f0b060")));
        }
    }
    const QJsonArray roles = claims.value("roles").toArray();
    for (const QJsonValue &v : roles) {
        auto *it = new QTreeWidgetItem(appRolesTree);
        it->setText(0, v.toString());
        it->setForeground(0, QBrush(QColor("#ff6b6b")));
    }
}

void WhoAmIWindow::renderOAuthGrant(const QJsonObject &grant) {
    auto *it = new QTreeWidgetItem(oauthGrantsTree);
    it->setText(0, grant.value("clientId").toString());
    it->setText(1, grant.value("resourceId").toString());
    it->setText(2, grant.value("scope").toString().trimmed());
}

void WhoAmIWindow::renderAuthMethod(const QJsonObject &method) {
    const QString type = method.value("@odata.type").toString();
    const QString kind = friendlyAuthMethodType(type);
    auto *it = new QTreeWidgetItem(authMethodsTree);
    it->setText(0, kind);
    QString detail;
    if (kind.contains("phone", Qt::CaseInsensitive)) {
        detail = QString("%1 (%2)").arg(method.value("phoneNumber").toString(),
                                         method.value("phoneType").toString());
    } else if (kind.contains("microsoftAuthenticator", Qt::CaseInsensitive) ||
               kind.contains("windowsHelloForBusiness", Qt::CaseInsensitive) ||
               kind.contains("fido2", Qt::CaseInsensitive) ||
               kind.contains("softwareOath", Qt::CaseInsensitive)) {
        detail = method.value("displayName").toString();
    } else if (kind.contains("email", Qt::CaseInsensitive)) {
        detail = method.value("emailAddress").toString();
    } else if (kind.contains("temporaryAccessPass", Qt::CaseInsensitive)) {
        detail = QString("TAP active: %1").arg(method.value("isUsable").toBool() ? "yes" : "no");
    }
    it->setText(1, detail);
    it->setText(2, method.value("id").toString());
    it->setForeground(0, QBrush(authMethodColor(kind)));
}

void WhoAmIWindow::renderLicense(const QJsonObject &license) {
    auto *it = new QTreeWidgetItem(licensesTree);
    it->setText(0, license.value("skuPartNumber").toString());
    it->setText(1, license.value("skuId").toString());
}

void WhoAmIWindow::renderPimSchedule(const QJsonObject &sched, bool eligible) {
    QTreeWidget *target = eligible ? rolesEligibleTree : rolesTree;
    const QJsonObject def = sched.value("roleDefinition").toObject();
    auto *it = new QTreeWidgetItem(target);
    it->setText(0, def.value("displayName").toString());
    it->setText(1, eligible ? sched.value("directoryScopeId").toString("/")
                            : QString("PIM active  scope=%1").arg(sched.value("directoryScopeId").toString("/")));
    const QString endsOrTemplate = eligible ? sched.value("endDateTime").toString("permanent")
                                            : def.value("templateId").toString();
    it->setText(2, endsOrTemplate);
    it->setForeground(0, QBrush(QColor(eligible ? "#f0b060" : "#ff6b6b")));
    if (!eligible) {
        const QString tid = def.value("templateId").toString();
        if (!tid.isEmpty()) m_activeRoleTemplateIds.insert(tid);
    }
}

void WhoAmIWindow::addRbacRow(const QString &sub, const QString &scope,
                                const QString &role, const QString &roleType,
                                const QString &principalType) {
    const int row = rbacTable->rowCount();
    rbacTable->insertRow(row);
    auto *sItem  = new QTableWidgetItem(sub);
    auto *scItem = new QTableWidgetItem(scope);
    auto *rItem  = new QTableWidgetItem(role);
    auto *tItem  = new QTableWidgetItem(roleType);
    auto *pItem  = new QTableWidgetItem(principalType);
    if (role == "Owner" || role == "User Access Administrator")
        rItem->setForeground(QBrush(QColor("#ff6b6b")));
    else if (role == "Contributor")
        rItem->setForeground(QBrush(QColor("#f0b060")));
    rbacTable->setItem(row, 0, sItem);
    rbacTable->setItem(row, 1, scItem);
    rbacTable->setItem(row, 2, rItem);
    rbacTable->setItem(row, 3, tItem);
    rbacTable->setItem(row, 4, pItem);
}

namespace {

// Well-known template IDs used only inside renderCapabilities/derive routines.
// Duplicating a few constants is fine - they're immutable Microsoft GUIDs -
// and keeps the mapping legible per-capability without a giant global table.
const QString kGlobalAdmin           = QStringLiteral("62e90394-69f5-4237-9190-012177145e10");
const QString kPrivRoleAdmin         = QStringLiteral("e8611ab8-c189-46e8-94e1-60213ab1f814");
const QString kApplicationAdmin      = QStringLiteral("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3");
const QString kCloudAppAdmin         = QStringLiteral("158c047a-c907-4556-b7ef-446551a6b5f7");
const QString kApplicationDeveloper  = QStringLiteral("14b83b21-be74-40e6-8c60-96017c67e8d0");
const QString kAuthAdmin             = QStringLiteral("c4e39bd9-1100-46d3-8c65-fb160da0071f");
const QString kPrivAuthAdmin         = QStringLiteral("7be44c8a-adaf-4e2a-84d6-ab2649e08a13");
const QString kUserAdmin             = QStringLiteral("fe930be7-5e62-47db-91af-98c3a49a38b1");
const QString kGroupsAdmin           = QStringLiteral("fdd7a751-b60b-444a-984c-02652fe8fa1c");
const QString kSecurityAdmin         = QStringLiteral("194ae4cb-b126-40b2-bd5b-6091b380977d");
const QString kConditionalAccessAdmin = QStringLiteral("b1be1c3e-b65d-4f19-8427-f6fa0d97feb9");

// Colouring convention for verdict cells.
const QColor kVerdictYes    = QColor("#8fce8f");   // green - full capability
const QColor kVerdictPartial= QColor("#f0b060");   // amber - scope-limited
const QColor kVerdictNo     = QColor("#a0a0a0");   // gray  - no capability

} // namespace

void WhoAmIWindow::deriveResetCapability() {
    QSet<QString> matches;
    for (const QString &tid : m_activeRoleTemplateIds) {
        if (passwordResetRoleTemplates().contains(tid)) matches.insert(tid);
    }
    if (matches.isEmpty()) {
        resetAbilityLabel->setText("<span style='color:#8fce8f'>Password reset ability: "
                                   "<b>none detected</b> from active directory roles.</span>");
        return;
    }
    QStringList names;
    for (const QString &tid : matches) {
        names << widToRole().value(tid, tid.left(8));
    }
    const bool everyone = matches.contains("62e90394-69f5-4237-9190-012177145e10") ||
                          matches.contains("7be44c8a-adaf-4e2a-84d6-ab2649e08a13") ||
                          matches.contains("e8611ab8-c189-46e8-94e1-60213ab1f814");
    resetAbilityLabel->setText(QString(
        "<span style='color:#ff6b6b'><b>Password reset ability:</b> via %1. "
        "%2</span>")
        .arg(names.join(", "),
             everyone ? "Can reset <b>any user including admins</b>."
                      : "Can reset limited-scope users (see Microsoft docs for the exact matrix)."));
}

// ============================================================================
// Derived Capabilities pane
// ============================================================================

void WhoAmIWindow::renderCapabilities() {
    capabilitiesTree->clear();

    // Small helper: does the current identity hold any of the given role tids?
    auto holdsAny = [this](std::initializer_list<QString> tids) -> QStringList {
        QStringList hit;
        for (const QString &t : tids) {
            if (m_activeRoleTemplateIds.contains(t))
                hit << widToRole().value(t, t.left(8));
        }
        return hit;
    };

    // Small helper: does rbacTable contain a row whose role-name column matches
    // any of `roleNames` (case-insensitive substring). Returns matching scopes.
    auto rbacScopesFor = [this](std::initializer_list<QString> roleNames) -> QStringList {
        QStringList scopes;
        for (int r = 0; r < rbacTable->rowCount(); ++r) {
            auto *roleItem  = rbacTable->item(r, 2);
            auto *scopeItem = rbacTable->item(r, 1);
            if (!roleItem || !scopeItem) continue;
            const QString role = roleItem->text();
            for (const QString &want : roleNames) {
                if (role.compare(want, Qt::CaseInsensitive) == 0 ||
                    role.contains(want, Qt::CaseInsensitive)) {
                    scopes << QString("%1 @ %2").arg(role, scopeItem->text());
                    break;
                }
            }
        }
        return scopes;
    };

    // Small helper: check if the Graph token has any of the delegated scopes.
    auto tokenHasScope = [this](std::initializer_list<QString> scopes) -> QStringList {
        QStringList hit;
        for (int i = 0; i < scopesTree->topLevelItemCount(); ++i) {
            const QString s = scopesTree->topLevelItem(i)->text(0);
            for (const QString &want : scopes) {
                if (s.compare(want, Qt::CaseInsensitive) == 0) hit << s;
            }
        }
        return hit;
    };

    // Count owned Applications for the "add secrets" derivation.
    int ownedApps = 0;
    for (int i = 0; i < ownedTree->topLevelItemCount(); ++i) {
        // ownedTree first column shows the display name; second column has the
        // type. This UI structure predates any label constants, so match the
        // exact word used in classifyMember(): "Application".
        for (int j = 0; j < ownedTree->columnCount(); ++j) {
            if (ownedTree->topLevelItem(i)->text(j) == QLatin1String("Application")) {
                ++ownedApps; break;
            }
        }
    }

    // PIM-eligible Global Admin?
    bool eligibleGA = false;
    for (int i = 0; i < rolesEligibleTree->topLevelItemCount(); ++i) {
        if (rolesEligibleTree->topLevelItem(i)->text(0).contains("Global Administrator",
                                                                  Qt::CaseInsensitive)) {
            eligibleGA = true; break;
        }
    }

    // Row-emit helper. Note: named `addRow` (not `emit`) because `emit` is a
    // Qt keyword and identifiers named `emit` don't parse when Qt keywords are
    // enabled (default).
    auto addRow = [this](const QString &cap, const QString &verdict,
                         const QColor &color, const QString &because) {
        auto *it = new QTreeWidgetItem(capabilitiesTree);
        it->setText(0, cap);
        it->setText(1, verdict);
        it->setText(2, because);
        it->setForeground(1, QBrush(color));
    };

    // --- Directory / Identity ------------------------------------------------

    // Register applications
    {
        const QStringList roles = holdsAny({kGlobalAdmin, kApplicationAdmin,
                                            kCloudAppAdmin, kApplicationDeveloper});
        if (!roles.isEmpty())
            addRow("Register applications", "YES", kVerdictYes,
                 QString("directory role: %1").arg(roles.join(", ")));
        else if (m_authPolicyLoaded && m_defaultAllowedToCreateApps)
            addRow("Register applications", "YES", kVerdictYes,
                 "tenant authorizationPolicy: defaultUserRolePermissions.allowedToCreateApps=true");
        else if (!m_authPolicyLoaded)
            addRow("Register applications", "unknown", kVerdictPartial,
                 "authorizationPolicy not readable with this token; needs role check "
                 "or Policy.Read.All to be sure");
        else
            addRow("Register applications", "no", kVerdictNo,
                 "no admin role AND tenant default disallows creating apps");
    }

    // Create security groups
    {
        const QStringList roles = holdsAny({kGlobalAdmin, kGroupsAdmin, kUserAdmin});
        if (!roles.isEmpty())
            addRow("Create security groups", "YES", kVerdictYes,
                 QString("directory role: %1").arg(roles.join(", ")));
        else if (m_authPolicyLoaded && m_defaultAllowedToCreateSecurityGroups)
            addRow("Create security groups", "YES", kVerdictYes,
                 "tenant authorizationPolicy: allowedToCreateSecurityGroups=true");
        else
            addRow("Create security groups", "no", kVerdictNo,
                 "no admin role AND tenant default disallows");
    }

    // Grant admin consent to apps
    {
        const QStringList roles = holdsAny({kGlobalAdmin, kPrivRoleAdmin,
                                            kApplicationAdmin, kCloudAppAdmin});
        const QStringList scopes = tokenHasScope({"Directory.AccessAsUser.All"});
        if (!roles.isEmpty() || !scopes.isEmpty()) {
            QStringList reasons;
            if (!roles.isEmpty())  reasons << QString("directory role: %1").arg(roles.join(", "));
            if (!scopes.isEmpty()) reasons << QString("token scope: %1").arg(scopes.join(", "));
            addRow("Grant admin consent to apps", "YES", kVerdictYes,
                 reasons.join("; "));
        } else {
            addRow("Grant admin consent to apps", "no", kVerdictNo,
                 "no matching directory role and no Directory.AccessAsUser.All in delegated scopes");
        }
    }

    // Reset other users' passwords (surfaces the deriveResetCapability finding
    // in the capabilities pane too, so operators don't have to switch tabs).
    {
        QStringList matched;
        for (const QString &tid : m_activeRoleTemplateIds)
            if (passwordResetRoleTemplates().contains(tid))
                matched << widToRole().value(tid, tid.left(8));
        if (!matched.isEmpty()) {
            const bool everyone = m_activeRoleTemplateIds.contains(kGlobalAdmin) ||
                                  m_activeRoleTemplateIds.contains(kPrivAuthAdmin) ||
                                  m_activeRoleTemplateIds.contains(kPrivRoleAdmin);
            addRow("Reset other users' passwords",
                 everyone ? "YES (any incl. admins)" : "YES (limited scope)",
                 everyone ? kVerdictYes : kVerdictPartial,
                 QString("directory role: %1").arg(matched.join(", ")));
        } else {
            addRow("Reset other users' passwords", "no", kVerdictNo,
                 "no Auth/User/Password/Helpdesk/Priv-Auth Admin role");
        }
    }

    // Add authentication methods to other users (TAP mint, backdoor phone, ...)
    {
        const QStringList roles = holdsAny({kGlobalAdmin, kAuthAdmin, kPrivAuthAdmin});
        const QStringList scopes = tokenHasScope({"UserAuthenticationMethod.ReadWrite.All"});
        if (!roles.isEmpty() || !scopes.isEmpty()) {
            QStringList reasons;
            if (!roles.isEmpty())  reasons << QString("directory role: %1").arg(roles.join(", "));
            if (!scopes.isEmpty()) reasons << QString("token scope: %1").arg(scopes.join(", "));
            addRow("Add auth methods to other users (TAP/phone/OATH)",
                 "YES", kVerdictYes, reasons.join("; "));
        } else {
            addRow("Add auth methods to other users (TAP/phone/OATH)", "no", kVerdictNo,
                 "no Auth/PrivAuth/Global Admin role and no UserAuthenticationMethod.ReadWrite.All scope");
        }
    }

    // Modify Conditional Access policies
    {
        const QStringList roles = holdsAny({kGlobalAdmin, kSecurityAdmin, kConditionalAccessAdmin});
        if (!roles.isEmpty())
            addRow("Modify Conditional Access policies", "YES", kVerdictYes,
                 QString("directory role: %1").arg(roles.join(", ")));
        else
            addRow("Modify Conditional Access policies", "no", kVerdictNo,
                 "no Global / Security / Conditional Access Admin role");
    }

    // Add secrets or certs to owned applications
    {
        if (ownedApps > 0)
            addRow("Add secrets/certs to owned apps", "YES", kVerdictYes,
                 QString("own %1 application(s) - see Owned tab").arg(ownedApps));
        else
            addRow("Add secrets/certs to owned apps", "no", kVerdictNo,
                 "no owned Application objects in this identity's ownership");
    }

    // Elevate to Global Admin (immediate vs PIM activation)
    {
        if (m_activeRoleTemplateIds.contains(kGlobalAdmin))
            addRow("Elevate to Global Admin", "YES (already)", kVerdictYes,
                 "active directory role assignment");
        else if (eligibleGA)
            addRow("Elevate to Global Admin", "YES via PIM", kVerdictPartial,
                 "PIM eligible - see Groups && Roles > PIM Eligible Roles");
        else
            addRow("Elevate to Global Admin", "no", kVerdictNo,
                 "not active, not PIM-eligible for Global Administrator");
    }

    // --- Azure resource ------------------------------------------------------

    // Run commands on VMs
    {
        const QStringList scopes = rbacScopesFor({"Owner", "Contributor",
                                                   "Virtual Machine Contributor"});
        if (!scopes.isEmpty())
            addRow("Run commands on VMs", "YES", kVerdictYes,
                 QString("%1 scope(s): %2")
                     .arg(scopes.size()).arg(scopes.join(" | ")));
        else
            addRow("Run commands on VMs", "no", kVerdictNo,
                 "no Owner / Contributor / VM Contributor at any accessible scope");
    }

    // Modify Azure RBAC (grant new role assignments)
    {
        const QStringList scopes = rbacScopesFor({"Owner", "User Access Administrator",
                                                   "Role Based Access Control Administrator"});
        if (!scopes.isEmpty())
            addRow("Modify Azure RBAC (grant roles)", "YES", kVerdictYes,
                 QString("%1 scope(s): %2")
                     .arg(scopes.size()).arg(scopes.join(" | ")));
        else
            addRow("Modify Azure RBAC (grant roles)", "no", kVerdictNo,
                 "no Owner / User Access Administrator / RBAC Administrator");
    }

    // Read Key Vault secrets (data plane, RBAC model)
    {
        const QStringList scopes = rbacScopesFor({
            "Key Vault Administrator", "Key Vault Secrets Officer",
            "Key Vault Secrets User", "Key Vault Reader" });
        if (!scopes.isEmpty())
            addRow("Read Key Vault secrets (RBAC model)", "YES", kVerdictYes,
                 QString("%1 scope(s): %2")
                     .arg(scopes.size()).arg(scopes.join(" | ")));
        else
            addRow("Read Key Vault secrets (RBAC model)", "unknown", kVerdictPartial,
                 "no matching Azure RBAC role; access-policy-model vaults are NOT "
                 "reflected here - check Key Vault Explorer to be sure");
    }

    // Read storage account data
    {
        const QStringList scopes = rbacScopesFor({
            "Storage Blob Data Owner", "Storage Blob Data Contributor",
            "Storage Blob Data Reader", "Storage Account Contributor",
            "Storage File Data" });
        if (!scopes.isEmpty())
            addRow("Read Storage account data", "YES", kVerdictYes,
                 QString("%1 scope(s): %2")
                     .arg(scopes.size()).arg(scopes.join(" | ")));
        else
            addRow("Read Storage account data", "no", kVerdictNo,
                 "no Storage-Blob-Data / Storage-Account-Contributor role");
    }

    // Managed Identity access from VMs - not derivable from Entra; pointer
    // note only.
    addRow("Steal Managed Identity token", "runtime check", kVerdictPartial,
         "not derivable from directory data - use VM Manager > Run Command "
         "or Remote Exec > Grab MI Token from IMDS on any accessible VM");

    // -------------------------------------------------------------------
    // Fine-grained action derivations. These read the actual actions[] /
    // dataActions[] from every assigned role definition, not just the role
    // NAME - which catches custom roles that grant e.g.
    // Microsoft.Authorization/roleAssignments/write without being named
    // Owner / User Access Administrator.
    // -------------------------------------------------------------------

    // Helper: does the identity have any action matching `patterns`? Patterns
    // may end with `*` for wildcard prefix match; a bare `*` matches
    // everything. Returns matching actions.
    auto matchActions = [](const QSet<QString> &pool,
                           std::initializer_list<QString> patterns) -> QStringList {
        QStringList hits;
        for (const QString &act : pool) {
            for (const QString &p : patterns) {
                if (p == QLatin1String("*")) { hits << act; break; }
                if (p.endsWith('*')) {
                    if (act.startsWith(p.left(p.size() - 1), Qt::CaseInsensitive)) {
                        hits << act; break;
                    }
                } else if (act.compare(p, Qt::CaseInsensitive) == 0) {
                    hits << act; break;
                }
            }
        }
        return hits;
    };

    if (!m_actionsLoaded) {
        addRow("Fine-grained RBAC actions", "loading...", kVerdictPartial,
               "az cli / Az PS enumeration still in flight (or session pwsh not ready)");
    } else if (m_rbacActionRows.isEmpty()) {
        addRow("Fine-grained RBAC actions", "none", kVerdictNo,
               "no ARM role assignments returned by `az role assignment list` OR "
               "Get-AzRoleAssignment for this OID (may indicate no ARM access at all "
               "or missing Microsoft.Authorization/*/read permission)");
    } else {
        addRow(QString("Fine-grained RBAC actions [%1]").arg(m_actionsSource),
               QString("%1 unique").arg(m_allControlActions.size()),
               kVerdictYes,
               QString("%1 role assignment(s) enumerated; see Actions tree below")
                   .arg(m_rbacActionRows.size()));

        // Grant new RBAC role assignments (catches custom roles that map
        // Microsoft.Authorization/roleAssignments/write - not just Owner/UAA).
        const QStringList hitsAssign = matchActions(m_allControlActions,
            { "Microsoft.Authorization/roleAssignments/write",
              "Microsoft.Authorization/*",
              "*" });
        if (!hitsAssign.isEmpty())
            addRow("Grant RBAC role assignments (from actions)", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsAssign.first()));

        // List storage keys / mint SAS.
        const QStringList hitsKeys = matchActions(m_allControlActions,
            { "Microsoft.Storage/storageAccounts/listKeys/action",
              "Microsoft.Storage/storageAccounts/listAccountSas/action",
              "Microsoft.Storage/storageAccounts/listServiceSas/action",
              "Microsoft.Storage/*", "*" });
        if (!hitsKeys.isEmpty())
            addRow("List Storage account keys / mint SAS", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsKeys.first()));

        // Key Vault secrets - RBAC model uses dataActions.
        const QStringList hitsKvSecrets = matchActions(m_allDataActions,
            { "Microsoft.KeyVault/vaults/secrets/getSecret/action",
              "Microsoft.KeyVault/vaults/secrets/*",
              "Microsoft.KeyVault/vaults/*", "*" });
        if (!hitsKvSecrets.isEmpty())
            addRow("Get Key Vault secrets (data plane)", "YES", kVerdictYes,
                   QString("dataAction: %1").arg(hitsKvSecrets.first()));

        // Deploy ARM templates - runs arbitrary resources.
        const QStringList hitsDeploy = matchActions(m_allControlActions,
            { "Microsoft.Resources/deployments/write",
              "Microsoft.Resources/*", "*" });
        if (!hitsDeploy.isEmpty())
            addRow("Deploy ARM templates", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsDeploy.first()));

        // Publish to App Service (RCE via WebDeploy / Kudu).
        const QStringList hitsWeb = matchActions(m_allControlActions,
            { "Microsoft.Web/sites/publish/action",
              "Microsoft.Web/sites/write",
              "Microsoft.Web/*", "*" });
        if (!hitsWeb.isEmpty())
            addRow("Publish to App Service (RCE via Kudu)", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsWeb.first()));

        // Function Apps master-key retrieval.
        const QStringList hitsFn = matchActions(m_allControlActions,
            { "Microsoft.Web/sites/host/listkeys/action",
              "Microsoft.Web/sites/functions/listkeys/action" });
        if (!hitsFn.isEmpty())
            addRow("Retrieve Function App master keys", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsFn.first()));

        // Automation Account run-as / hybrid worker code execution.
        const QStringList hitsAuto = matchActions(m_allControlActions,
            { "Microsoft.Automation/automationAccounts/runbooks/write",
              "Microsoft.Automation/automationAccounts/jobs/write",
              "Microsoft.Automation/*" });
        if (!hitsAuto.isEmpty())
            addRow("Automation Account job / runbook write (RCE)", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsAuto.first()));

        // Assign a Managed Identity to a resource (privilege elevation via MI).
        const QStringList hitsMi = matchActions(m_allControlActions,
            { "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
              "Microsoft.ManagedIdentity/*" });
        if (!hitsMi.isEmpty())
            addRow("Assign Managed Identity to resources", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsMi.first()));

        // Elevate to root management group.
        const QStringList hitsMg = matchActions(m_allControlActions,
            { "Microsoft.Management/managementGroups/write",
              "Microsoft.Management/*" });
        if (!hitsMg.isEmpty())
            addRow("Modify management-group hierarchy", "YES", kVerdictYes,
                   QString("action: %1").arg(hitsMg.first()));
    }

    // -------------------------------------------------------------------
    // Populate the fine-grained actions tree (scope -> role -> actions).
    // -------------------------------------------------------------------
    actionsTree->clear();

    // Interesting-action highlight: substrings that make an action red so
    // operators can spot high-value entries in a wall of read/list actions.
    static const QStringList kInterestingSubstrings = {
        "/write", "/delete", "/action",
        "roleAssignments", "listKeys", "listAccountSas", "listServiceSas",
        "getSecret", "getKey", "publish", "restart", "runCommand",
        "userAssignedIdentities/assign", "managementGroups", "deployments/write",
        "runbooks", "listkeys"
    };
    auto looksInteresting = [](const QString &action) -> bool {
        for (const QString &s : kInterestingSubstrings)
            if (action.contains(s, Qt::CaseInsensitive)) return true;
        return false;
    };

    for (const QJsonObject &row : m_rbacActionRows) {
        const QString scope    = row.value("scope").toString();
        const QString roleName = row.value("roleName").toString();
        auto *parent = new QTreeWidgetItem(actionsTree);
        parent->setText(0, QString("%1  @  %2").arg(roleName, scope));
        parent->setText(1, "role assignment");
        parent->setForeground(0, QBrush(QColor("#8fd48f")));

        auto addActionChild = [&](const QString &act, const QString &kind) {
            auto *c = new QTreeWidgetItem(parent);
            c->setText(0, act);
            c->setText(1, kind);
            if (looksInteresting(act)) {
                c->setForeground(0, QBrush(QColor("#ff9060")));
                c->setText(2, "high-value");
            }
        };
        for (const QJsonValue &a : row.value("actions").toArray())        addActionChild(a.toString(), "action");
        for (const QJsonValue &a : row.value("dataActions").toArray())    addActionChild(a.toString(), "dataAction");
        for (const QJsonValue &a : row.value("notActions").toArray())     addActionChild(a.toString(), "notAction (excluded)");
        for (const QJsonValue &a : row.value("notDataActions").toArray()) addActionChild(a.toString(), "notDataAction (excluded)");
    }
    actionsTree->collapseAll();
}

// ============================================================================
// Complete + export/copy
// ============================================================================

void WhoAmIWindow::checkComplete() {
    if (m_pending > 0 || cancelRequested) return;

    setLoading(false);
    const int rbacRows = rbacTable->rowCount();
    if (!m_userOid.isEmpty() && !m_mgmtToken.isEmpty()) {
        rbacSummary->setText(QString("<b>%1</b> role assignment(s) across the accessible subscriptions.")
                                 .arg(rbacRows));
    }
    // Distil the raw data collected across all panes into the derived
    // capability verdicts shown on the Capabilities tab.
    renderCapabilities();

    // Publish a typed snapshot so Post-Exploitation modules can autofill
    // their input fields from what WhoAmI just discovered. Subscribers
    // connect to WhoAmiInsights::insightsUpdated() in their ctor.
    {
        WhoAmiInsights::Snapshot snap;
        snap.sessionId = userSelector ? userSelector->selectedSession() : QString();
        snap.userOid              = m_userOid;
        snap.userUpn              = m_userUpn;
        snap.userTid              = m_userTid;
        snap.isGuest              = m_isGuest;
        snap.activeRoleTemplateIds= m_activeRoleTemplateIds;
        snap.allControlActions    = m_allControlActions;
        snap.allDataActions       = m_allDataActions;
        snap.hasMgmtToken         = !m_mgmtToken.isEmpty();
        snap.capturedAt           = QDateTime::currentDateTimeUtc();

        // Best-effort tenant default domain: prefer the UPN suffix
        // (@contoso.onmicrosoft.com), fall back to whatever the tenant
        // header text has after the last space. Falls back to userTid GUID
        // when neither works.
        if (m_userUpn.contains('@'))
            snap.tenantDefaultDomain = m_userUpn.section('@', -1);
        if (snap.tenantDefaultDomain.isEmpty() && tenantHeader) {
            const QString txt = tenantHeader->text();
            const int lastSpace = txt.lastIndexOf(' ');
            if (lastSpace >= 0) snap.tenantDefaultDomain = txt.mid(lastSpace + 1);
        }

        // RBAC scopes: walk rbacTable rows into typed RbacScope entries.
        // Column layout (per addRbacRow): 0=subscription, 1=scope, 2=role,
        // 3=roleType, 4=principalType.
        for (int r = 0; r < rbacTable->rowCount(); ++r) {
            WhoAmiInsights::RbacScope rs;
            if (auto *it = rbacTable->item(r, 0)) rs.subscriptionId = it->text();
            if (auto *it = rbacTable->item(r, 1)) rs.scope          = it->text();
            if (auto *it = rbacTable->item(r, 2)) rs.roleName       = it->text();
            if (auto *it = rbacTable->item(r, 3)) rs.roleType       = it->text();
            snap.rbacScopes.append(rs);
        }

        // Owned apps: walk ownedTree top-level items whose column 0 is
        // "Application". Per classifyMember() the label is exactly "Application".
        for (int i = 0; i < ownedTree->topLevelItemCount(); ++i) {
            auto *it = ownedTree->topLevelItem(i);
            if (!it) continue;
            if (it->text(0) != QLatin1String("Application")) continue;
            WhoAmiInsights::OwnedApp app;
            app.displayName = it->text(1);
            app.appId       = it->text(2);   // classifyMember stores appId here
            app.objectId    = it->text(3);
            snap.ownedApps.append(app);
        }

        WhoAmiInsights::instance()->publish(snap);
    }

    logSuccess("WhoAmI complete.");
}

void WhoAmIWindow::exportReport() {
    if (m_userOid.isEmpty()) {
        QMessageBox::information(this, "Nothing to export", "Run WhoAmI first.");
        return;
    }
    const QString fname = QFileDialog::getSaveFileName(this, "Export WhoAmI report",
        QString("whoami_%1_%2.json").arg(m_userUpn.isEmpty() ? m_userOid : m_userUpn,
                                          QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        "JSON (*.json)");
    if (fname.isEmpty()) return;

    QJsonObject report;
    report.insert("upn",   m_userUpn);
    report.insert("oid",   m_userOid);
    report.insert("tid",   m_userTid);
    report.insert("guest", m_isGuest);

    auto treeToArray = [](QTreeWidget *t, const QStringList &keys) {
        QJsonArray out;
        for (int i = 0; i < t->topLevelItemCount(); ++i) {
            auto *it = t->topLevelItem(i);
            QJsonObject o;
            for (int c = 0; c < t->columnCount() && c < keys.size(); ++c)
                o.insert(keys[c], it->text(c));
            out.append(o);
        }
        return out;
    };

    report.insert("groups",            treeToArray(groupsTree,       {"name", "type", "id"}));
    report.insert("administrativeUnits", treeToArray(auTree,         {"name", "description", "id"}));
    report.insert("directoryRolesActive", treeToArray(rolesTree,     {"role", "source", "templateId"}));
    report.insert("pimEligible",       treeToArray(rolesEligibleTree, {"role", "scope", "ends"}));
    report.insert("owned",             treeToArray(ownedTree,        {"kind", "displayName", "identifier", "id"}));
    report.insert("oauthGrants",       treeToArray(oauthGrantsTree,  {"clientId", "resourceId", "scopes"}));
    report.insert("authMethods",       treeToArray(authMethodsTree,  {"kind", "detail", "id"}));
    report.insert("licenses",          treeToArray(licensesTree,     {"skuPartNumber", "skuId"}));
    report.insert("directReports",     treeToArray(reportsTree,      {"displayName", "upn", "jobTitle", "id"}));

    QJsonArray rbac;
    for (int i = 0; i < rbacTable->rowCount(); ++i) {
        QJsonObject r;
        for (int j = 0; j < rbacTable->columnCount(); ++j) {
            const QString h = rbacTable->horizontalHeaderItem(j)->text();
            r.insert(h, rbacTable->item(i, j) ? rbacTable->item(i, j)->text() : "");
        }
        rbac.append(r);
    }
    report.insert("rbac", rbac);

    QFile f(fname);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export failed", "Could not open file for writing.");
        return;
    }
    f.write(QJsonDocument(report).toJson(QJsonDocument::Indented));
    f.close();
    logSuccess("Exported: " + fname);
}

void WhoAmIWindow::copyReport() {
    QString s;
    QTextStream t(&s);
    t << "== WhoAmI ==\n";
    t << "UPN : " << m_userUpn << "\n";
    t << "OID : " << m_userOid << "\n";
    t << "TID : " << m_userTid << "\n";
    if (m_isGuest) t << "*** GUEST ACCOUNT ***\n";
    t << "\n";

    t << "-- Active Directory Roles (" << rolesTree->topLevelItemCount() << ") --\n";
    for (int i = 0; i < rolesTree->topLevelItemCount(); ++i) {
        auto *it = rolesTree->topLevelItem(i);
        t << " * " << it->text(0) << "   [" << it->text(1) << "]\n";
    }

    t << "\n-- PIM Eligible (" << rolesEligibleTree->topLevelItemCount() << ") --\n";
    for (int i = 0; i < rolesEligibleTree->topLevelItemCount(); ++i) {
        auto *it = rolesEligibleTree->topLevelItem(i);
        t << " * " << it->text(0) << "  " << it->text(1) << "  ends=" << it->text(2) << "\n";
    }

    t << "\n-- Owned Objects (" << ownedTree->topLevelItemCount() << ") --\n";
    for (int i = 0; i < ownedTree->topLevelItemCount(); ++i) {
        auto *it = ownedTree->topLevelItem(i);
        t << " * " << it->text(0) << " : " << it->text(1) << "  " << it->text(2) << "\n";
    }

    t << "\n-- Azure RBAC (" << rbacTable->rowCount() << ") --\n";
    for (int i = 0; i < rbacTable->rowCount(); ++i) {
        t << " * " << rbacTable->item(i, 2)->text()
          << "  at  " << rbacTable->item(i, 1)->text()
          << "  (sub: " << rbacTable->item(i, 0)->text() << ")\n";
    }

    t << "\n-- Auth Methods (" << authMethodsTree->topLevelItemCount() << ") --\n";
    for (int i = 0; i < authMethodsTree->topLevelItemCount(); ++i) {
        auto *it = authMethodsTree->topLevelItem(i);
        t << " * " << it->text(0) << "  " << it->text(1) << "\n";
    }

    t << "\n-- OAuth Grants (" << oauthGrantsTree->topLevelItemCount() << ") --\n";
    for (int i = 0; i < oauthGrantsTree->topLevelItemCount(); ++i) {
        auto *it = oauthGrantsTree->topLevelItem(i);
        t << " * " << it->text(0) << " -> " << it->text(1) << "  scopes=" << it->text(2) << "\n";
    }

    QApplication::clipboard()->setText(s);
    logSuccess("Report copied to clipboard.");
}
