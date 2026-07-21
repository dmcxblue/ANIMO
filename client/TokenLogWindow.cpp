#include "TokenLogWindow.h"
#include "TablePlaceholder.h"
#include "ClientTransport.h"
#include "../shared/Protocol.h"

#include <QHeaderView>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QJsonDocument>
#include <QFile>
#include <QFileDialog>
#include <QDateTime>
#include <QDebug>

TokenLogWindow::TokenLogWindow(QWidget *parent)
    : QWidget(parent)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Token Logs");
    resize(1200, 700);
    setupUI();
    loadTokens();
}

void TokenLogWindow::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Top bar with buttons
    QHBoxLayout *topBar = new QHBoxLayout();

    statusLabel = new QLabel("Token Logs", this);
    statusLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    topBar->addWidget(statusLabel);

    topBar->addStretch();

    refreshBtn = new QPushButton("Refresh", this);
    refreshBtn->setFixedWidth(100);
    topBar->addWidget(refreshBtn);

    mainLayout->addLayout(topBar);

    // Splitter for table and details
    QSplitter *splitter = new QSplitter(Qt::Vertical, this);

    // Token table
    tokenTable = new QTableWidget(this);
    new TablePlaceholder(tokenTable, "No tokens logged yet.");
    tokenTable->setColumnCount(6);
    tokenTable->setHorizontalHeaderLabels({"ID", "Timestamp", "Source", "User (UPN)", "Tenant ID", "Resource (Audience)"});
    tokenTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    tokenTable->setSelectionMode(QAbstractItemView::ExtendedSelection);  // Enable Shift+Click, Ctrl+Click
    tokenTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tokenTable->horizontalHeader()->setStretchLastSection(true);
    tokenTable->setAlternatingRowColors(true);

    // Set column widths
    tokenTable->setColumnWidth(0, 50);   // ID
    tokenTable->setColumnWidth(1, 160);  // Timestamp
    tokenTable->setColumnWidth(2, 200);  // Source
    tokenTable->setColumnWidth(3, 250);  // User (UPN)
    tokenTable->setColumnWidth(4, 300);  // Tenant ID

    splitter->addWidget(tokenTable);

    // Details view
    QWidget *detailsWidget = new QWidget(this);
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsWidget);

    QLabel *detailsLabel = new QLabel("Token Details (JWT Decoded):", this);
    detailsLabel->setStyleSheet("font-weight: bold;");
    detailsLayout->addWidget(detailsLabel);

    detailsView = new QTextEdit(this);
    detailsView->setReadOnly(true);
    detailsView->setPlaceholderText("Select a token to view details...");
    detailsView->setStyleSheet("font-family: 'Courier New', monospace; font-size: 10pt;");
    detailsLayout->addWidget(detailsView);

    // Action buttons for selected token
    QHBoxLayout *actionBar = new QHBoxLayout();

    copyAccessBtn = new QPushButton("Copy Access Token", this);
    copyRefreshBtn = new QPushButton("Copy Refresh Token", this);
    deleteBtn = new QPushButton("Delete", this);
    exportBtn = new QPushButton("Export All to JSON", this);

    copyAccessBtn->setEnabled(false);
    copyRefreshBtn->setEnabled(false);
    deleteBtn->setEnabled(false);

    copyAccessBtn->setToolTip("Select a token to copy the access token");
    copyRefreshBtn->setToolTip("Select a token to copy the refresh token");
    deleteBtn->setToolTip("Delete the selected token from the database");

    actionBar->addWidget(copyAccessBtn);
    actionBar->addWidget(copyRefreshBtn);
    actionBar->addStretch();
    actionBar->addWidget(deleteBtn);
    actionBar->addWidget(exportBtn);

    detailsLayout->addLayout(actionBar);
    splitter->addWidget(detailsWidget);

    // Set splitter sizes (60% table, 40% details)
    splitter->setSizes(QList<int>() << 400 << 300);

    mainLayout->addWidget(splitter);

    // Connect signals
    connect(refreshBtn, &QPushButton::clicked, this, &TokenLogWindow::refreshTokens);
    connect(tokenTable, &QTableWidget::itemSelectionChanged, this, &TokenLogWindow::onTokenSelected);
    connect(copyAccessBtn, &QPushButton::clicked, this, &TokenLogWindow::copyAccessToken);
    connect(copyRefreshBtn, &QPushButton::clicked, this, &TokenLogWindow::copyRefreshToken);
    connect(exportBtn, &QPushButton::clicked, this, &TokenLogWindow::exportTokens);
    connect(deleteBtn, &QPushButton::clicked, this, &TokenLogWindow::deleteSelectedToken);
}

QObject* TokenLogWindow::locateTransport() const
{
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void TokenLogWindow::loadTokens()
{
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        statusLabel->setText("Error: No server connection");
        QMessageBox::warning(this, "Connection Error", "Not connected to server");
        return;
    }

    // Send request to get all tokens
    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_GET_TOKENS);
    // Empty sessionId means get all tokens

    // Connect to receive response
    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        // Disconnect any previous connection
        disconnect(typed, &ClientTransport::messageReceived, this, nullptr);

        connect(typed, &ClientTransport::messageReceived, this,
                [this](const QJsonObject &obj) {
                    if (obj.value("status").toString() == "ok" &&
                        obj.value("message").toString() == "tokens retrieved") {
                        currentTokens = obj.value("tokens").toArray();

                        // Update table
                        tokenTable->setRowCount(0);
                        statusLabel->setText(QString("Loaded %1 tokens").arg(currentTokens.size()));

                        for (int i = 0; i < currentTokens.size(); ++i) {
                            QJsonObject token = currentTokens[i].toObject();

                            int row = tokenTable->rowCount();
                            tokenTable->insertRow(row);

                            // Extract values from JWT access token
                            QString accessToken = token.value("access_token").toString();
                            QString upn = extractJWTClaim(accessToken, "upn");
                            QString tid = extractJWTClaim(accessToken, "tid");
                            QString aud = extractJWTClaim(accessToken, "aud");

                            // Fallback to database values if JWT parsing fails
                            if (upn.isEmpty()) upn = token.value("user").toString();
                            if (tid.isEmpty()) tid = token.value("tenant_id").toString();
                            if (aud.isEmpty()) aud = token.value("resource").toString();

                            tokenTable->setItem(row, 0, new QTableWidgetItem(QString::number(token.value("id").toInt())));
                            tokenTable->setItem(row, 1, new QTableWidgetItem(token.value("timestamp").toString()));
                            tokenTable->setItem(row, 2, new QTableWidgetItem(token.value("source").toString()));
                            tokenTable->setItem(row, 3, new QTableWidgetItem(upn));
                            tokenTable->setItem(row, 4, new QTableWidgetItem(tid));
                            tokenTable->setItem(row, 5, new QTableWidgetItem(aud));
                        }
                    }
                });

        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }
}

void TokenLogWindow::refreshTokens()
{
    loadTokens();
}

void TokenLogWindow::onTokenSelected()
{
    QList<QTableWidgetItem*> selected = tokenTable->selectedItems();
    if (selected.isEmpty()) {
        copyAccessBtn->setEnabled(false);
        copyRefreshBtn->setEnabled(false);
        deleteBtn->setEnabled(false);
        detailsView->clear();
        selectedToken = QJsonObject();
        return;
    }

    int row = tokenTable->currentRow();
    if (row < 0 || row >= currentTokens.size()) return;

    selectedToken = currentTokens[row].toObject();
    displayTokenDetails(selectedToken);

    copyAccessBtn->setEnabled(true);
    copyRefreshBtn->setEnabled(!selectedToken.value("refresh_token").toString().isEmpty());
    deleteBtn->setEnabled(true);
}

void TokenLogWindow::displayTokenDetails(const QJsonObject &token)
{
    QString details;

    details += "═══════════════════════════════════════════════════════\n";
    details += "                    TOKEN METADATA\n";
    details += "═══════════════════════════════════════════════════════\n\n";

    details += QString("ID:           %1\n").arg(token.value("id").toInt());
    details += QString("Session ID:   %1\n").arg(token.value("session_id").toString());
    details += QString("Timestamp:    %1\n").arg(token.value("timestamp").toString());
    details += QString("Source:       %1\n").arg(token.value("source").toString());
    details += QString("User:         %1\n").arg(token.value("user").toString());
    details += QString("Tenant ID:    %1\n").arg(token.value("tenant_id").toString());
    details += QString("Resource:     %1\n").arg(token.value("resource").toString());
    details += QString("Scope:        %1\n").arg(token.value("scope").toString());
    details += QString("Token Type:   %1\n").arg(token.value("token_type").toString());

    int expiresIn = token.value("expires_in").toInt();
    if (expiresIn > 0) {
        details += QString("Expires In:   %1 seconds (%2 hours)\n").arg(expiresIn).arg(expiresIn / 3600.0, 0, 'f', 2);
    }

    details += "\n";
    details += "═══════════════════════════════════════════════════════\n";
    details += "                 ACCESS TOKEN (JWT)\n";
    details += "═══════════════════════════════════════════════════════\n\n";

    QString accessToken = token.value("access_token").toString();
    if (!accessToken.isEmpty()) {
        QString parsed = parseJWT(accessToken);
        details += parsed;
        details += "\n\nRaw Access Token:\n" + accessToken + "\n";
    } else {
        details += "[No access token]\n";
    }

    details += "\n";
    details += "═══════════════════════════════════════════════════════\n";
    details += "                REFRESH TOKEN (JWT)\n";
    details += "═══════════════════════════════════════════════════════\n\n";

    QString refreshToken = token.value("refresh_token").toString();
    if (!refreshToken.isEmpty()) {
        QString parsedRefresh = parseJWT(refreshToken);
        if (!parsedRefresh.isEmpty()) {
            details += parsedRefresh;
        }
        details += "\n\nRaw Refresh Token:\n" + refreshToken + "\n";
    } else {
        details += "[No refresh token]\n";
    }

    QString idToken = token.value("id_token").toString();
    if (!idToken.isEmpty()) {
        details += "\n";
        details += "═══════════════════════════════════════════════════════\n";
        details += "                   ID TOKEN (JWT)\n";
        details += "═══════════════════════════════════════════════════════\n\n";
        QString parsedId = parseJWT(idToken);
        details += parsedId;
        details += "\n\nRaw ID Token:\n" + idToken + "\n";
    }

    detailsView->setPlainText(details);
}

QString TokenLogWindow::parseJWT(const QString &token)
{
    if (token.isEmpty()) return QString();

    QStringList parts = token.split('.');
    if (parts.size() < 2) {
        return "Invalid JWT format\n";
    }

    QString result;

    // Decode header (part 0)
    QByteArray headerEncoded = parts[0].toUtf8();
    // Base64URL to Base64
    headerEncoded.replace('-', '+');
    headerEncoded.replace('_', '/');
    while (headerEncoded.size() % 4) headerEncoded.append('=');

    QByteArray headerDecoded = QByteArray::fromBase64(headerEncoded);
    QJsonDocument headerDoc = QJsonDocument::fromJson(headerDecoded);

    if (!headerDoc.isNull()) {
        result += "Header:\n";
        result += QString::fromUtf8(headerDoc.toJson(QJsonDocument::Indented));
        result += "\n";
    }

    // Decode payload (part 1)
    QByteArray payloadEncoded = parts[1].toUtf8();
    payloadEncoded.replace('-', '+');
    payloadEncoded.replace('_', '/');
    while (payloadEncoded.size() % 4) payloadEncoded.append('=');

    QByteArray payloadDecoded = QByteArray::fromBase64(payloadEncoded);
    QJsonDocument payloadDoc = QJsonDocument::fromJson(payloadDecoded);

    if (!payloadDoc.isNull()) {
        result += "Payload:\n";
        QJsonObject payload = payloadDoc.object();

        // Pretty print with timestamp conversion
        QString prettyPayload = QString::fromUtf8(payloadDoc.toJson(QJsonDocument::Indented));

        // Add human-readable timestamps
        if (payload.contains("exp")) {
            qint64 exp = payload.value("exp").toVariant().toLongLong();
            QDateTime expTime = QDateTime::fromSecsSinceEpoch(exp);
            result += QString("\n  exp (expires): %1 (%2)\n").arg(exp).arg(expTime.toString(Qt::ISODate));
        }
        if (payload.contains("iat")) {
            qint64 iat = payload.value("iat").toVariant().toLongLong();
            QDateTime iatTime = QDateTime::fromSecsSinceEpoch(iat);
            result += QString("  iat (issued):  %1 (%2)\n").arg(iat).arg(iatTime.toString(Qt::ISODate));
        }
        if (payload.contains("nbf")) {
            qint64 nbf = payload.value("nbf").toVariant().toLongLong();
            QDateTime nbfTime = QDateTime::fromSecsSinceEpoch(nbf);
            result += QString("  nbf (not before): %1 (%2)\n").arg(nbf).arg(nbfTime.toString(Qt::ISODate));
        }

        result += "\n" + prettyPayload;
    }

    return result;
}

QString TokenLogWindow::extractJWTClaim(const QString &token, const QString &claim)
{
    if (token.isEmpty() || claim.isEmpty()) return QString();

    QStringList parts = token.split('.');
    if (parts.size() < 2) return QString();

    // Decode payload (part 1)
    QByteArray payloadEncoded = parts[1].toUtf8();
    // Base64URL to Base64
    payloadEncoded.replace('-', '+');
    payloadEncoded.replace('_', '/');
    while (payloadEncoded.size() % 4) payloadEncoded.append('=');

    QByteArray payloadDecoded = QByteArray::fromBase64(payloadEncoded);
    QJsonDocument payloadDoc = QJsonDocument::fromJson(payloadDecoded);

    if (payloadDoc.isNull() || !payloadDoc.isObject()) return QString();

    QJsonObject payload = payloadDoc.object();
    return payload.value(claim).toString();
}

void TokenLogWindow::copyAccessToken()
{
    if (selectedToken.isEmpty()) return;

    QString accessToken = selectedToken.value("access_token").toString();
    if (!accessToken.isEmpty()) {
        QClipboard *clipboard = QApplication::clipboard();
        clipboard->setText(accessToken);
        statusLabel->setText("Access token copied to clipboard");
    }
}

void TokenLogWindow::copyRefreshToken()
{
    if (selectedToken.isEmpty()) return;

    QString refreshToken = selectedToken.value("refresh_token").toString();
    if (!refreshToken.isEmpty()) {
        QClipboard *clipboard = QApplication::clipboard();
        clipboard->setText(refreshToken);
        statusLabel->setText("Refresh token copied to clipboard");
    }
}

void TokenLogWindow::exportTokens()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        "Export Tokens",
        QString("tokens_%1.json").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        "JSON Files (*.json)");

    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing");
        return;
    }

    QJsonDocument doc(currentTokens);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();

    statusLabel->setText(QString("Exported %1 tokens to %2").arg(currentTokens.size()).arg(fileName));
    QMessageBox::information(this, "Export Success",
        QString("Successfully exported %1 tokens to:\n%2").arg(currentTokens.size()).arg(fileName));
}

void TokenLogWindow::deleteSelectedToken()
{
    if (selectedToken.isEmpty()) return;

    int tokenId = selectedToken.value("id").toInt();

    QMessageBox::StandardButton reply = QMessageBox::question(this,
        "Delete Token",
        QString("Are you sure you want to delete token ID %1?\nThis action cannot be undone.").arg(tokenId),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) return;

    // Get transport to send request to server
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        statusLabel->setText("Error: No server connection");
        QMessageBox::warning(this, "Connection Error", "Not connected to server");
        return;
    }

    // Build delete request
    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_DELETE_TOKEN);
    req.insert("tokenId", tokenId);

    // Send request and handle response
    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        // Disconnect any previous connection for delete responses
        disconnect(typed, &ClientTransport::messageReceived, this, nullptr);

        connect(typed, &ClientTransport::messageReceived, this,
                [this, tokenId](const QJsonObject &obj) {
                    QString status = obj.value("status").toString();
                    QString message = obj.value("message").toString();

                    if (status == "ok" && message == "token deleted") {
                        statusLabel->setText(QString("Token ID %1 deleted successfully").arg(tokenId));
                        // Refresh the token list
                        loadTokens();
                    } else if (status == "error") {
                        statusLabel->setText(QString("Delete failed: %1").arg(message));
                        QMessageBox::warning(this, "Delete Failed", message);
                    }
                });

        typed->sendJson(req);
        statusLabel->setText(QString("Deleting token ID %1...").arg(tokenId));
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
        statusLabel->setText(QString("Delete request sent for token ID %1").arg(tokenId));
    }
}
