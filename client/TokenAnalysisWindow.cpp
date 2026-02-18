#include "TokenAnalysisWindow.h"
#include "TokenStore.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QHeaderView>
#include <QClipboard>
#include <QApplication>
#include <QJsonDocument>
#include <QJsonArray>
#include <QMessageBox>
#include <QSplitter>
#include <QTimeZone>

TokenAnalysisWindow::TokenAnalysisWindow(QWidget *parent)
    : QWidget(parent)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Token Lifetime Analysis");
    resize(900, 700);

    auto *mainLayout = new QVBoxLayout(this);

    // Token input section
    auto *inputGroup = new QGroupBox("JWT Token Input");
    auto *inputLayout = new QVBoxLayout(inputGroup);

    tokenInput = new QTextEdit();
    tokenInput->setPlaceholderText("Paste JWT access token here...");
    tokenInput->setMaximumHeight(100);
    inputLayout->addWidget(tokenInput);

    auto *btnRow = new QHBoxLayout();
    btnAnalyze = new QPushButton("Analyze Token");
    btnClear = new QPushButton("Clear");
    btnCopy = new QPushButton("Copy Report");
    btnRow->addWidget(btnAnalyze);
    btnRow->addWidget(btnClear);
    btnRow->addWidget(btnCopy);
    btnRow->addStretch();
    inputLayout->addLayout(btnRow);

    mainLayout->addWidget(inputGroup);

    // Results section with splitter
    auto *splitter = new QSplitter(Qt::Vertical);

    // Claims table
    auto *claimsGroup = new QGroupBox("Token Claims");
    auto *claimsLayout = new QVBoxLayout(claimsGroup);
    claimsTable = new QTableWidget();
    claimsTable->setColumnCount(3);
    claimsTable->setHorizontalHeaderLabels({"Claim", "Value", "Description"});
    claimsTable->horizontalHeader()->setStretchLastSection(true);
    claimsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    claimsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    claimsTable->setAlternatingRowColors(true);
    claimsLayout->addWidget(claimsTable);
    splitter->addWidget(claimsGroup);

    // Summary output
    auto *summaryGroup = new QGroupBox("Analysis Summary");
    auto *summaryLayout = new QVBoxLayout(summaryGroup);
    summaryOutput = new QTextEdit();
    summaryOutput->setReadOnly(true);
    summaryOutput->setStyleSheet("QTextEdit { font-family: 'Consolas', 'Monaco', monospace; }");
    summaryLayout->addWidget(summaryOutput);
    splitter->addWidget(summaryGroup);

    mainLayout->addWidget(splitter, 1);

    // Connections
    connect(btnAnalyze, &QPushButton::clicked, this, &TokenAnalysisWindow::analyzeToken);
    connect(btnClear, &QPushButton::clicked, this, &TokenAnalysisWindow::clearAnalysis);
    connect(btnCopy, &QPushButton::clicked, this, &TokenAnalysisWindow::copyReport);
}

void TokenAnalysisWindow::setToken(const QString &token)
{
    tokenInput->setPlainText(token);
    analyzeToken();
}

void TokenAnalysisWindow::analyzeToken()
{
    QString jwt = tokenInput->toPlainText().trimmed();
    if (jwt.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please paste a JWT token to analyze.");
        return;
    }

    if (!TokenStore::isValidJwtFormat(jwt)) {
        QMessageBox::warning(this, "Invalid Token", "The input does not appear to be a valid JWT token.");
        return;
    }

    parseAndDisplay(jwt);
}

void TokenAnalysisWindow::clearAnalysis()
{
    tokenInput->clear();
    claimsTable->setRowCount(0);
    summaryOutput->clear();
}

void TokenAnalysisWindow::copyReport()
{
    QString report = summaryOutput->toPlainText();
    if (report.isEmpty()) {
        QMessageBox::information(this, "No Report", "Analyze a token first to generate a report.");
        return;
    }

    QApplication::clipboard()->setText(report);
    QMessageBox::information(this, "Copied", "Report copied to clipboard.");
}

QJsonObject TokenAnalysisWindow::decodeJwtPayload(const QString &jwt)
{
    return TokenStore::parseJwtPayload(jwt);
}

void TokenAnalysisWindow::parseAndDisplay(const QString &jwt)
{
    QJsonObject payload = decodeJwtPayload(jwt);
    if (payload.isEmpty()) {
        summaryOutput->setPlainText("Failed to decode token payload.");
        return;
    }

    // Clear previous results
    claimsTable->setRowCount(0);

    // Claim descriptions
    QMap<QString, QString> claimDescriptions = {
        {"aud", "Audience - Intended recipient of the token"},
        {"iss", "Issuer - Token issuer (Azure AD tenant)"},
        {"iat", "Issued At - When the token was issued"},
        {"nbf", "Not Before - Token is not valid before this time"},
        {"exp", "Expiration - Token expiration time"},
        {"sub", "Subject - Unique identifier for the user"},
        {"oid", "Object ID - Azure AD object ID of the user"},
        {"upn", "User Principal Name - User's email/login"},
        {"name", "Display Name - User's display name"},
        {"preferred_username", "Preferred Username"},
        {"tid", "Tenant ID - Azure AD tenant identifier"},
        {"azp", "Authorized Party - Client ID that requested the token"},
        {"appid", "Application ID - Legacy claim for client ID"},
        {"scp", "Scope - Permissions granted to the token"},
        {"roles", "Roles - Application roles assigned"},
        {"wids", "Well-known IDs - Directory role template IDs"},
        {"groups", "Group Memberships - Azure AD group IDs"},
        {"amr", "Authentication Methods - How user authenticated"},
        {"acr", "Authentication Context Class Reference"},
        {"auth_time", "Authentication Time - When user last authenticated"},
        {"ipaddr", "IP Address - Client IP address"},
        {"platf", "Platform - Client platform"},
        {"ver", "Version - Token version (1.0 or 2.0)"},
        {"xms_tcdt", "Tenant Create Date"},
    };

    // Populate claims table
    for (auto it = payload.begin(); it != payload.end(); ++it) {
        int row = claimsTable->rowCount();
        claimsTable->insertRow(row);

        claimsTable->setItem(row, 0, new QTableWidgetItem(it.key()));
        claimsTable->setItem(row, 1, new QTableWidgetItem(formatClaim(it.key(), it.value())));
        claimsTable->setItem(row, 2, new QTableWidgetItem(claimDescriptions.value(it.key(), "")));
    }

    // Generate summary
    QString summary;
    QTextStream ts(&summary);

    ts << "╔══════════════════════════════════════════════════════════════╗\n";
    ts << "║              TOKEN LIFETIME ANALYSIS REPORT                  ║\n";
    ts << "╚══════════════════════════════════════════════════════════════╝\n\n";

    // Token version
    QString version = payload.value("ver").toString("1.0");
    ts << "Token Version: " << version << "\n\n";

    // Time analysis
    qint64 now = QDateTime::currentSecsSinceEpoch();
    qint64 iat = payload.value("iat").toVariant().toLongLong();
    qint64 nbf = payload.value("nbf").toVariant().toLongLong();
    qint64 exp = payload.value("exp").toVariant().toLongLong();

    ts << "─── TIME ANALYSIS ───────────────────────────────────────────\n";
    if (iat > 0) {
        ts << "Issued At:      " << formatDateTime(iat) << "\n";
    }
    if (nbf > 0) {
        ts << "Valid From:     " << formatDateTime(nbf) << "\n";
    }
    if (exp > 0) {
        ts << "Expires At:     " << formatDateTime(exp) << "\n";

        qint64 lifetime = exp - iat;
        ts << "Token Lifetime: " << formatDuration(lifetime) << "\n";

        qint64 remaining = exp - now;
        if (remaining > 0) {
            ts << "Time Remaining: " << formatDuration(remaining) << "\n";
            ts << "Status:         VALID\n";
        } else {
            ts << "Status:         EXPIRED (" << formatDuration(-remaining) << " ago)\n";
        }
    }

    // Identity
    ts << "\n─── IDENTITY ────────────────────────────────────────────────\n";
    if (payload.contains("upn")) {
        ts << "User:           " << payload.value("upn").toString() << "\n";
    }
    if (payload.contains("name")) {
        ts << "Display Name:   " << payload.value("name").toString() << "\n";
    }
    if (payload.contains("oid")) {
        ts << "Object ID:      " << payload.value("oid").toString() << "\n";
    }
    if (payload.contains("tid")) {
        ts << "Tenant ID:      " << payload.value("tid").toString() << "\n";
    }

    // Audience and Client
    ts << "\n─── AUDIENCE & CLIENT ───────────────────────────────────────\n";
    if (payload.contains("aud")) {
        ts << "Audience:       " << payload.value("aud").toString() << "\n";
    }
    if (payload.contains("azp")) {
        ts << "Client ID:      " << payload.value("azp").toString() << "\n";
    } else if (payload.contains("appid")) {
        ts << "Client ID:      " << payload.value("appid").toString() << "\n";
    }

    // Permissions
    ts << "\n─── PERMISSIONS ─────────────────────────────────────────────\n";
    if (payload.contains("scp")) {
        QString scopes = payload.value("scp").toString();
        QStringList scopeList = scopes.split(' ', Qt::SkipEmptyParts);
        ts << "Scopes (" << scopeList.size() << "):\n";
        for (const QString &scope : scopeList) {
            ts << "  • " << scope << "\n";
        }
    }
    if (payload.contains("roles")) {
        QJsonArray roles = payload.value("roles").toArray();
        ts << "App Roles (" << roles.size() << "):\n";
        for (const QJsonValue &role : roles) {
            ts << "  • " << role.toString() << "\n";
        }
    }

    // Authentication
    ts << "\n─── AUTHENTICATION ──────────────────────────────────────────\n";
    if (payload.contains("amr")) {
        QJsonArray amr = payload.value("amr").toArray();
        ts << "Methods: ";
        QStringList methods;
        for (const QJsonValue &m : amr) {
            methods << m.toString();
        }
        ts << methods.join(", ") << "\n";
    }
    if (payload.contains("ipaddr")) {
        ts << "IP Address:     " << payload.value("ipaddr").toString() << "\n";
    }

    ts << "\n═══════════════════════════════════════════════════════════════\n";

    summaryOutput->setPlainText(summary);
}

QString TokenAnalysisWindow::formatClaim(const QString &key, const QJsonValue &value)
{
    // Format timestamp claims
    if (key == "iat" || key == "nbf" || key == "exp" || key == "auth_time") {
        qint64 ts = value.toVariant().toLongLong();
        return formatDateTime(ts);
    }

    // Format arrays
    if (value.isArray()) {
        QJsonArray arr = value.toArray();
        QStringList items;
        for (const QJsonValue &v : arr) {
            items << v.toString();
        }
        return items.join(", ");
    }

    // Format objects
    if (value.isObject()) {
        return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
    }

    return value.toVariant().toString();
}

QString TokenAnalysisWindow::formatDateTime(qint64 timestamp)
{
    if (timestamp <= 0) return "N/A";
    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp, QTimeZone::utc());
    return dt.toString("yyyy-MM-dd hh:mm:ss UTC");
}

QString TokenAnalysisWindow::formatDuration(qint64 seconds)
{
    if (seconds < 0) seconds = -seconds;

    qint64 days = seconds / 86400;
    qint64 hours = (seconds % 86400) / 3600;
    qint64 mins = (seconds % 3600) / 60;
    qint64 secs = seconds % 60;

    if (days > 0) {
        return QString("%1d %2h %3m").arg(days).arg(hours).arg(mins);
    } else if (hours > 0) {
        return QString("%1h %2m %3s").arg(hours).arg(mins).arg(secs);
    } else if (mins > 0) {
        return QString("%1m %2s").arg(mins).arg(secs);
    } else {
        return QString("%1s").arg(secs);
    }
}
