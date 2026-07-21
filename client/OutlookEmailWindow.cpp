#include "OutlookEmailWindow.h"
#include "TablePlaceholder.h"
#include "StyleManager.h"
#include "HtmlReplyDialog.h"
#include "TokenStore.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "NetworkHelper.h"

#include <QDateTime>
#include <QUrlQuery>
#include <QTimer>
#include <QRegularExpression>
#include <QTextStream>
#include <QGroupBox>
#include <QPointer>
#include <memory>



OutlookEmailWindow::OutlookEmailWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this))
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Outlook Email");
    resize(1000, 750);

    auto *main = new QVBoxLayout(this);

    // User selector and token group
    auto *tokenGroup = new QGroupBox("Microsoft Graph Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &OutlookEmailWindow::onUserChanged);
    connect(userSelector, &UserSelectorWidget::logMessage, this, &OutlookEmailWindow::appendLog);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &OutlookEmailWindow::autoFetchTokens);

    // Auth row
    auto *authRow = new QHBoxLayout();
    btnAuth = new QPushButton("Paste Token", this);
    connect(btnAuth, &QPushButton::clicked, this, &OutlookEmailWindow::authenticate);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    sharedUpn = new QLineEdit(this);
    sharedUpn->setPlaceholderText("Shared mailbox UPN (optional)");
    authRow->addWidget(btnAuth);
    authRow->addWidget(tokenStatus);
    authRow->addWidget(sharedUpn);
    tokenLayout->addLayout(authRow);

    main->addWidget(tokenGroup);

    // Filters row
    auto *filterRow = new QHBoxLayout();
    cmbFolder = new QComboBox(this); cmbFolder->addItems({"Inbox","SentItems","Drafts"});
    editLimit = new QLineEdit("25", this);
    editSkip  = new QLineEdit("0", this);
    editSearch = new QLineEdit(this); editSearch->setPlaceholderText("Search query (KQL, optional)");
    btnReload = new QPushButton("Reload", this);
    filterRow->addWidget(new QLabel("Folder"));
    filterRow->addWidget(cmbFolder);
    filterRow->addWidget(new QLabel("Limit"));
    filterRow->addWidget(editLimit);
    filterRow->addWidget(new QLabel("Skip"));
    filterRow->addWidget(editSkip);
    filterRow->addWidget(btnReload);
    main->addLayout(filterRow);
    main->addWidget(editSearch);

    // Split view
    auto *splitRow = new QHBoxLayout();
    lstEmails = new QListWidget(this);
    new TablePlaceholder(lstEmails, "No emails loaded.");
    lstEmails->setFixedWidth(420);
    lstEmails->setSelectionMode(QAbstractItemView::ExtendedSelection);  // Enable multi-selection
    lstEmails->setStyleSheet(
        "QListWidget::item { padding: 8px; border-bottom: 1px solid #ccc; }"
        "QListWidget::item:selected { background-color: #0078D4; color: white; }");
    splitRow->addWidget(lstEmails);

    auto *previewCol = new QVBoxLayout();
    lblFrom = new QLabel(this); lblFrom->setStyleSheet("font-weight: bold"); lblFrom->setMaximumHeight(18);
    lblDate = new QLabel(this); lblDate->setMaximumHeight(18);
    lblTo   = new QLabel(this); lblTo->setMaximumHeight(18);
    lblCc   = new QLabel(this); lblCc->setMaximumHeight(18);
    txtBody = new QWebEngineView(this);

    previewCol->addWidget(lblFrom);
    previewCol->addWidget(lblDate);
    previewCol->addWidget(lblTo);
    previewCol->addWidget(lblCc);
    previewCol->addWidget(txtBody);
    splitRow->addLayout(previewCol);
    main->addLayout(splitRow);

    // Actions
    auto *actions = new QHBoxLayout();
	btnNew   = new QPushButton("New Email", this);
    btnReply = new QPushButton("Reply", this);
    btnMark  = new QPushButton("Mark Read/Unread", this);
    btnDelete= new QPushButton("Delete", this);
    btnPermDelete = new QPushButton("Permanent Delete", this);
	btnDownload = new QPushButton("Download Attachments", this);
	btnDownload->setEnabled(false);
	
	// 🔹 Scaled clip icon
	QPixmap pix;
	if (!QIcon::fromTheme("mail-attachment").isNull())
		pix = QIcon::fromTheme("mail-attachment").pixmap(14, 14);
	else
		pix = QPixmap(":/icons/shareicons/clip.png").scaled(
			14, 14, Qt::KeepAspectRatio, Qt::SmoothTransformation);
	
	btnDownload->setIcon(QIcon(pix));

	actions->addWidget(btnNew);
    actions->addWidget(btnReply);
    actions->addWidget(btnMark);
    actions->addWidget(btnDelete);
    actions->addWidget(btnPermDelete);
    actions->addWidget(btnDownload);
    main->addLayout(actions);

    // Selection buttons row
    auto *selectionRow = new QHBoxLayout();
    btnSelectAll = new QPushButton("Select All", this);
    btnSelectNone = new QPushButton("Select None", this);
    btnSelectAll->setToolTip("Select all emails in list (Ctrl+A)");
    btnSelectNone->setToolTip("Deselect all emails");
    selectionRow->addWidget(btnSelectAll);
    selectionRow->addWidget(btnSelectNone);
    selectionRow->addStretch();
    main->addLayout(selectionRow);

    // Bulk operations row
    auto *bulkActions = new QHBoxLayout();
    btnMarkAllRead = new QPushButton("Mark All Read", this);
    btnDeleteAll = new QPushButton("Delete All", this);
    btnExport = new QPushButton("Export to EML", this);
    btnAdvancedSearch = new QPushButton("Advanced Search", this);
    btnTemplates = new QPushButton("Email Templates", this);

    btnMarkAllRead->setToolTip("Mark all emails in current folder as read");
    btnDeleteAll->setToolTip("Delete all emails in current view");
    btnExport->setToolTip("Export current emails to EML format");
    btnAdvancedSearch->setToolTip("Advanced search with filters");
    btnTemplates->setToolTip("Load email templates for phishing scenarios");

    cancelBtn = new QPushButton("Cancel", this);
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);

    bulkActions->addWidget(cancelBtn);
    bulkActions->addWidget(btnMarkAllRead);
    bulkActions->addWidget(btnDeleteAll);
    bulkActions->addWidget(btnExport);
    bulkActions->addWidget(btnAdvancedSearch);
    bulkActions->addWidget(btnTemplates);
    bulkActions->addStretch();
    main->addLayout(bulkActions);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);  // Indeterminate mode
    main->addWidget(progressBar);

    setLayout(main);

    // Connections
	connect(btnNew, &QPushButton::clicked, this, &OutlookEmailWindow::composeNewEmail);
    connect(btnReload, &QPushButton::clicked, this, &OutlookEmailWindow::reloadMailbox);
    connect(cmbFolder, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &OutlookEmailWindow::reloadMailbox);
	// Load full message when the selection changes
	connect(lstEmails, &QListWidget::currentRowChanged, this, [this](int row) {
		if (row < 0) return;
		if (auto *item = lstEmails->item(row)) {
			QString id = item->data(Qt::UserRole).toString();
			if (id.isEmpty() && row >= 0 && row < emails.size())
				id = emails.at(row).toObject().value("id").toString();
			if (!id.isEmpty())
				loadFullMessage(id);
		}
	});
    connect(btnReply, &QPushButton::clicked, this, &OutlookEmailWindow::replyToEmail);
    connect(btnMark,  &QPushButton::clicked, this, &OutlookEmailWindow::toggleReadStatus);
    connect(btnDelete,&QPushButton::clicked, this, &OutlookEmailWindow::deleteEmail);
    connect(btnPermDelete,&QPushButton::clicked, this, &OutlookEmailWindow::permanentlyDeleteEmail);
    connect(btnDownload, &QPushButton::clicked, this, &OutlookEmailWindow::downloadAttachments);

    // Bulk operations connections
    connect(btnMarkAllRead, &QPushButton::clicked, this, &OutlookEmailWindow::markAllAsRead);
    connect(btnDeleteAll, &QPushButton::clicked, this, &OutlookEmailWindow::deleteAllEmails);
    connect(btnExport, &QPushButton::clicked, this, &OutlookEmailWindow::exportEmailsToEML);
    connect(btnAdvancedSearch, &QPushButton::clicked, this, &OutlookEmailWindow::showAdvancedSearch);
    connect(btnTemplates, &QPushButton::clicked, this, &OutlookEmailWindow::loadEmailTemplate);

    // Selection connections
    connect(btnSelectAll, &QPushButton::clicked, this, &OutlookEmailWindow::selectAllEmails);
    connect(btnSelectNone, &QPushButton::clicked, this, &OutlookEmailWindow::selectNoneEmails);
    connect(cancelBtn, &QPushButton::clicked, this, &OutlookEmailWindow::cancelRequests);
}

OutlookEmailWindow::OutlookEmailWindow(const QString &token, QWidget *parent)
    : OutlookEmailWindow(parent)
{
    setAccessToken(token);
}

OutlookEmailWindow::~OutlookEmailWindow() {
    // Stop WebEngineView before destruction to prevent crashes
    if (txtBody) {
        txtBody->stop();
        txtBody->setHtml(QString());
    }

    // Disconnect ALL network replies to prevent callbacks during destruction
    if (net) {
        const auto replies = net->findChildren<QNetworkReply*>();
        for (auto *r : replies) {
            r->disconnect();
            r->abort();
        }
    }
    activeReplies.clear();
}

void OutlookEmailWindow::setAccessToken(const QString &token)
{
    if (!token.trimmed().isEmpty()) {
        accessToken = token.trimmed();
        btnAuth->setText("Token Set ✓");
        btnAuth->setStyleSheet("color: green; font-weight: bold;");
        // Auto-reload if we have a token
        QTimer::singleShot(100, this, &OutlookEmailWindow::reloadMailbox);
    }
}

void OutlookEmailWindow::authenticate() {
    // First try to get token from TokenStore
    TokenInfo graphToken = TokenStore::instance()->getGraphToken();
    if (graphToken.isValid() && !graphToken.isExpired()) {
        int ret = QMessageBox::question(this, "Use Stored Token?",
            QString("Found a valid Graph token for: %1\n\nUse this token?").arg(graphToken.upn),
            QMessageBox::Yes | QMessageBox::No);
        if (ret == QMessageBox::Yes) {
            setAccessToken(graphToken.accessToken);
            return;
        }
    }

    // Fallback to manual paste
    bool ok = false;
    QString tok = QInputDialog::getMultiLineText(this, "Paste Access Token", "Access Token:", "", &ok);
    if (ok && !tok.trimmed().isEmpty()) {
        accessToken = tok.trimmed();
        reloadMailbox();
    }
}

QString OutlookEmailWindow::mailboxPath() const {
    const QString shared = sharedUpn->text().trimmed();
    return shared.isEmpty() ? "me" : QString("users/%1").arg(shared);
}

void OutlookEmailWindow::composeNewEmail() {
    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please authenticate first.");
        return;
    }

    HtmlReplyDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) return;

    const QString subject     = dlg.getSubject();
    const QString htmlBody    = dlg.getHtml();
    const QStringList toList  = dlg.getToRecipients();
    const QStringList ccList  = dlg.getCcRecipients();
    const QStringList bccList = dlg.getBccRecipients();
    const QStringList files   = dlg.getAttachments();

    // 🔹 Helper to build recipients
    auto buildRecipients = [](const QStringList &list) {
        QJsonArray arr;
        for (const QString &addr : list) {
            QString email = addr.trimmed();
            if (!email.isEmpty()) {
                arr.append(QJsonObject{
                    {"emailAddress", QJsonObject{{"address", email}}}
                });
            }
        }
        return arr;
    };

    // 🔹 Step 1: Create draft
    const QString createUrl = QString("https://graph.microsoft.com/v1.0/%1/messages")
                                  .arg(mailboxPath());
    auto req = NetworkHelper::outlookJsonRequest(createUrl, accessToken);
    NetworkHelper::setRequestTimeout(req);

    QJsonObject bodyObj{
        {"subject", subject.isEmpty() ? "New Message" : subject},
        {"body", QJsonObject{
            {"contentType", "HTML"},
            {"content", htmlBody}
        }},
        {"toRecipients", buildRecipients(toList)},
        {"ccRecipients", buildRecipients(ccList)},
        {"bccRecipients", buildRecipients(bccList)},
        {"isDraft", true}
    };

    QNetworkReply *rep = net->post(req, QJsonDocument(bodyObj).toJson());
    if (!rep) {
        QMessageBox::critical(this, "New Email Failed", "Network request failed");
        return;
    }
    activeReplies.append(rep);
    connect(rep, &QNetworkReply::finished, this, [this, rep, files]() {
        if (rep->error() != QNetworkReply::NoError) {
            QMessageBox::critical(this, "New Email Failed", NetworkHelper::parseApiError(rep));
            activeReplies.removeAll(rep);
            rep->deleteLater();
            return;
        }

        const QString draftId =
            QJsonDocument::fromJson(rep->readAll()).object().value("id").toString();
        activeReplies.removeAll(rep);
        rep->deleteLater();

        if (draftId.isEmpty()) {
            QMessageBox::critical(this, "New Email Failed", "No draft ID returned.");
            return;
        }

        // 🔹 Step 2: Upload attachments async, then send
        uploadAttachmentsAsync(draftId, files, [this, draftId](bool attachSuccess) {
            Q_UNUSED(attachSuccess);
            // 🔹 Step 3: Send the message async
            sendDraftAsync(draftId, [this](bool sendOk) {
                if (sendOk)
                    QMessageBox::information(this, "Success", "Email sent successfully.");
                else
                    QMessageBox::critical(this, "Send Failed", "Failed to send email.");
            });
        });
    });
}

void OutlookEmailWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    btnReload->setEnabled(!loading);
    btnAuth->setEnabled(!loading);
    autoFetchBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void OutlookEmailWindow::reloadMailbox() {
    if (accessToken.isEmpty()) return;

    setLoading(true);
    // Build URL + params
    const QString folder = cmbFolder->currentText().trimmed().isEmpty() ? "Inbox" : cmbFolder->currentText().trimmed();
    const QString baseUrl = QString("https://graph.microsoft.com/v1.0/%1/mailFolders/%2/messages")
                                .arg(mailboxPath(), folder);
    QUrl url{ baseUrl };
    QUrlQuery q;

    q.addQueryItem("$top",  QString::number(editLimit->text().toInt()));
    q.addQueryItem("$skip", QString::number(editSkip->text().toInt()));

    // ----- search handling (only once) -----
    QString search = editSearch->text().trimmed();
    const bool useSearch = !search.isEmpty();
    if (useSearch) {
        if (!(search.startsWith('"') && search.endsWith('"'))) search = "\"" + search + "\"";
        q.addQueryItem("$search", search);
    }

    url.setQuery(q);

    // Request with auth + proper headers
    QNetworkRequest req = NetworkHelper::outlookJsonRequest(url.toString(), accessToken);
    NetworkHelper::setRequestTimeout(req);

    // Graph requires this header when using $search
    if (useSearch) {
        req.setRawHeader("ConsistencyLevel", "eventual");
    }

    QNetworkReply *rep = net->get(req);
    activeReplies.append(rep);
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        setLoading(false);
        lstEmails->clear();

        if (!rep) {
            lstEmails->addItem("[!] Network request failed");
            return;
        }

        if (rep->error() != QNetworkReply::NoError) {
            lstEmails->addItem(QString("[!] HTTP error: %1").arg(NetworkHelper::parseApiError(rep)));
            activeReplies.removeAll(rep);
            rep->deleteLater();
            return;
        }

        const auto doc = QJsonDocument::fromJson(rep->readAll());
        emails = doc.object().value("value").toArray();

        if (emails.isEmpty()) {
            lstEmails->addItem("[!] No emails found");
            activeReplies.removeAll(rep);
            rep->deleteLater();
            return;
        }

        // Populate list and stash message IDs in UserRole
        for (const auto &val : emails) {
            const QJsonObject email = val.toObject();

            const QString id      = email.value("id").toString();
            const QString from    = email.value("from").toObject()
                                         .value("emailAddress").toObject()
                                         .value("name").toString("Unknown");
            const QString subject = email.value("subject").toString("(No Subject)");
            const QString date    = email.value("receivedDateTime").toString().replace("T", " ").split("+").first();
            const QString preview = email.value("bodyPreview").toString().left(80).replace("\n", " ");

            const QString text = QString("%1\n%2\n%3  [%4]").arg(from, subject, preview, date);

            auto *item = new QListWidgetItem(text);

            // Clip icon if attachments exist
			if (email.contains("hasAttachments") && email.value("hasAttachments").toBool()) {
				QIcon icon;
			
				// 1) Try system theme
				icon = QIcon::fromTheme("mail-attachment");
			
				// 2) Fallback to qrc
				if (icon.isNull()) {
					if (QFile::exists(":/icons/shareicons/clip.png")) {
						icon = QIcon(":/icons/shareicons/clip.png");
					} else {
						qWarning() << "Resource not found: :/icons/shareicons/clip.png";
					}
				}
			
				// 3) Fallback to on-disk (dev environments)
				if (icon.isNull() && QFile::exists("icons/shareicons/clip.png")) {
					icon = QIcon("icons/shareicons/clip.png");
				}
			
				if (!icon.isNull()) {
					item->setIcon(icon);
				} else {
					qWarning() << "Attachment icon could not be loaded from theme, qrc, or file.";
				}
			}
			

            // Mark unread
            if (!email.value("isRead").toBool(true)) {
                QFont f = item->font();
                f.setBold(true);
                item->setFont(f);
                item->setBackground(Qt::lightGray);
            }

            // 🔑 stash the message id for stable selection
            item->setData(Qt::UserRole, id);

            lstEmails->addItem(item);
        }

        // Auto-select first item to load its content immediately
        if (lstEmails->count() > 0) {
            lstEmails->setCurrentRow(0);  // triggers selection handler below
        }

        activeReplies.removeAll(rep);
        rep->deleteLater();
    });
}



void OutlookEmailWindow::populateList(const QJsonArray &items) {
    for (const auto &v : items) {
        const auto email = v.toObject();
        const QString fromName = email.value("from").toObject().value("emailAddress").toObject().value("name").toString("Unknown");
        const QString subject  = email.value("subject").toString("(No Subject)");
        QString date = email.value("receivedDateTime").toString();
        date.replace("T"," "); date = date.section('+',0,0);

        QString preview = email.value("bodyPreview").toString(); 
        if (preview.size() > 80) preview = preview.left(80);
        preview.replace('\n',' ');

        QListWidgetItem *it = new QListWidgetItem(QString("%1\n%2\n%3  [%4]").arg(fromName, subject, preview, date));
        if (email.value("hasAttachments").toBool(false)) {
            it->setIcon(QIcon(":/icons/shareicons/clip.png")); // add to your qrc
        }
        if (!email.value("isRead").toBool(true)) {
            auto f = it->font(); f.setBold(true); it->setFont(f);
            it->setBackground(Qt::lightGray);
        }
        lstEmails->addItem(it);
    }
}

/* void OutlookEmailWindow::onEmailSelect(QListWidgetItem *current, QListWidgetItem) {
    int idx = lstEmails->currentRow();
    if (idx < 0 || idx >= emails.size()) return;

    const auto mail = emails.at(idx).toObject();
    const QString msgId = mail.value("id").toString();
    if (msgId.isEmpty()) return;

    loadFullMessage(msgId);
}
*/
 
void OutlookEmailWindow::loadFullMessage(const QString &msgId) {
    const QString url = QString("https://graph.microsoft.com/v1.0/%1/messages/%2").arg(mailboxPath(), msgId);
    auto req = NetworkHelper::outlookJsonRequest(url, accessToken);
    NetworkHelper::setRequestTimeout(req);

    QNetworkReply *rep = net->get(req);
    activeReplies.append(rep);
    connect(rep, &QNetworkReply::finished, this, [this, rep, msgId]() {
        if (!rep) {
            txtBody->setHtml("<pre>[!] Network request failed</pre>");
            return;
        }
        if (rep->error() != QNetworkReply::NoError) {
            txtBody->setHtml(QString("<pre>[!] Failed to load message: %1</pre>").arg(NetworkHelper::parseApiError(rep)));
            activeReplies.removeAll(rep);
            rep->deleteLater();
            return;
        }
        const auto full = QJsonDocument::fromJson(rep->readAll()).object();

        lblFrom->setText("From: " + full.value("from").toObject().value("emailAddress").toObject().value("name").toString());
        lblDate->setText("Date: " + full.value("receivedDateTime").toString());
        QStringList tos, ccs;
        for (const auto &r : full.value("toRecipients").toArray())
            tos << r.toObject().value("emailAddress").toObject().value("address").toString();
        for (const auto &r : full.value("ccRecipients").toArray())
            ccs << r.toObject().value("emailAddress").toObject().value("address").toString();
        lblTo->setText("To: " + tos.join(", "));
        lblCc->setText("CC: " + ccs.join(", "));

        const auto body = full.value("body").toObject();
        QString html = body.value("content").toString();
        const bool isHtml = body.value("contentType").toString().compare("html", Qt::CaseInsensitive) == 0;

        // load attachments for CID mapping and download list
        const QString attUrl = QString("https://graph.microsoft.com/v1.0/%1/messages/%2/attachments")
                                   .arg(mailboxPath(), msgId);
        auto attReq = NetworkHelper::outlookJsonRequest(attUrl, accessToken);
        NetworkHelper::setRequestTimeout(attReq);
        QNetworkReply *attRep = net->get(attReq);
        activeReplies.append(attRep);
        connect(attRep, &QNetworkReply::finished, this, [this, attRep, isHtml, html]() mutable {
            if (!attRep) {
                txtBody->setHtml(isHtml ? html : ("<pre>" + html.toHtmlEscaped() + "</pre>"));
                return;
            }
            if (attRep->error() != QNetworkReply::NoError) {
                txtBody->setHtml(isHtml ? html : ("<pre>" + html.toHtmlEscaped() + "</pre>"));
                activeReplies.removeAll(attRep);
                attRep->deleteLater();
                return;
            }

            const auto arr = QJsonDocument::fromJson(attRep->readAll()).object().value("value").toArray();

            // 🔹 Reinforce clip icon if attachments exist
			if (!arr.isEmpty()) {
				if (auto *item = lstEmails->currentItem()) {
					QPixmap pix(":/icons/shareicons/clip.png");
			
					// Scale to 14x14 (or whatever you prefer), keeping aspect ratio
					QPixmap scaled = pix.scaled(14, 14, Qt::KeepAspectRatio, Qt::SmoothTransformation);
			
					item->setIcon(QIcon(scaled));
				}
			}
			

            setPreviewHtml(html, arr);
            activeReplies.removeAll(attRep);
            attRep->deleteLater();
        });

        activeReplies.removeAll(rep);
        rep->deleteLater();
    });
}


void OutlookEmailWindow::setPreviewHtml(QString html, const QJsonArray &attachments) {
    // build CID map + non-inline list
    currentAttachments = QJsonArray{};
    QMap<QString, QString> cidMap; // cid -> dataURI
    for (const auto &v : attachments) {
        const auto att = v.toObject();
        const bool isInline = att.value("isInline").toBool(false);
        const QString contentId = att.value("contentId").toString().trimmed();
        const QString contentB64 = att.value("contentBytes").toString();
        if (isInline && !contentId.isEmpty() && !contentB64.isEmpty()) {
            QString ctype = att.value("contentType").toString("image/png");
            cidMap[contentId.trimmed().remove('<').remove('>')] =
                QString("data:%1;base64,%2").arg(ctype, contentB64);
        } else if (!isInline) {
            currentAttachments.append(att);
        }
    }
    // replace cid:… with data URIs
    for (auto it = cidMap.begin(); it != cidMap.end(); ++it) {
        html.replace("cid:" + it.key(), it.value(), Qt::CaseInsensitive);
    }
    btnDownload->setEnabled(!currentAttachments.isEmpty());

    QString finalHtml = QString(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<style>body{font-family:'Segoe UI',sans-serif;padding:16px;margin:0}"
        "img{max-width:100%%;height:auto;display:block;margin:12px 0}</style>"
        "</head><body>%1</body></html>").arg(html);

    txtBody->setHtml(finalHtml);
}

void OutlookEmailWindow::downloadAttachments() {
    if (currentAttachments.isEmpty()) return;

    int idx = lstEmails->currentRow();
    if (idx < 0 || idx >= emails.size()) return;
    const QString msgId = emails.at(idx).toObject().value("id").toString();
    if (msgId.isEmpty()) return;

    // Store message ID for async downloads and start processing
    currentDownloadMsgId = msgId;
    downloadAttachmentAsync(0);
}

void OutlookEmailWindow::replyToEmail() {
    int idx = lstEmails->currentRow();
    if (idx < 0 || idx >= emails.size() || accessToken.isEmpty()) return;

    const QString msgId = emails.at(idx).toObject().value("id").toString();
    if (msgId.isEmpty()) return;

    const QString createUrl = QString("https://graph.microsoft.com/v1.0/%1/messages/%2/createReply")
                                  .arg(mailboxPath(), msgId);
    auto req = NetworkHelper::outlookJsonRequest(createUrl, accessToken);
    NetworkHelper::setRequestTimeout(req);
    QNetworkReply *rep = net->post(req, QByteArray()); // empty body per Graph docs
    activeReplies.append(rep);
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        if (!rep) {
            QMessageBox::warning(this, "Reply Error", "Network request failed");
            return;
        }
        if (rep->error() != QNetworkReply::NoError) {
            QMessageBox::warning(this, "Reply Error", NetworkHelper::parseApiError(rep));
            activeReplies.removeAll(rep);
            rep->deleteLater();
            return;
        }
        const auto replyMsg = QJsonDocument::fromJson(rep->readAll()).object();
        const QString replyId = replyMsg.value("id").toString();
        activeReplies.removeAll(rep);
        rep->deleteLater();
        if (replyId.isEmpty()) {
            QMessageBox::warning(this, "Reply Error", "Failed to create reply message.");
            return;
        }

        // Show composer
        HtmlReplyDialog dlg(this);
        if (dlg.exec() != QDialog::Accepted) return;
        const QString htmlBody = dlg.getHtml();
        const QStringList attachments = dlg.getAttachments();

        // PATCH update body (async)
        const QString updateUrl = QString("https://graph.microsoft.com/v1.0/%1/messages/%2")
                                      .arg(mailboxPath(), replyId);
        auto updReq = NetworkHelper::outlookJsonRequest(updateUrl, accessToken);
        NetworkHelper::setRequestTimeout(updReq);
        QJsonObject bodyObj{
            {"body", QJsonObject{
                {"contentType", "HTML"},
                {"content", htmlBody}
            }}
        };
        QNetworkReply *upd = net->sendCustomRequest(updReq, "PATCH",
                                                    QJsonDocument(bodyObj).toJson());
        activeReplies.append(upd);
        connect(upd, &QNetworkReply::finished, this, [this, upd, replyId, attachments]() {
            if (!upd) {
                QMessageBox::critical(this, "Reply Failed", "Network request failed");
                return;
            }
            if (upd->error() != QNetworkReply::NoError) {
                QMessageBox::critical(this, "Reply Failed", NetworkHelper::parseApiError(upd));
                activeReplies.removeAll(upd);
                upd->deleteLater();
                return;
            }
            activeReplies.removeAll(upd);
            upd->deleteLater();

            // Upload attachments async, then send
            uploadAttachmentsAsync(replyId, attachments, [this, replyId](bool attachSuccess) {
                Q_UNUSED(attachSuccess);
                // Send async
                sendDraftAsync(replyId, [this](bool sendOk) {
                    if (sendOk)
                        QMessageBox::information(this, "Success", "Reply sent successfully.");
                    else
                        QMessageBox::critical(this, "Reply Failed", "Failed to send reply.");
                });
            });
        });
    });
}

void OutlookEmailWindow::toggleReadStatus() {
    int idx = lstEmails->currentRow();
    if (idx < 0 || idx >= emails.size() || accessToken.isEmpty()) return;

    const auto mail = emails.at(idx).toObject();
    const QString msgId = mail.value("id").toString();
    const bool isRead = mail.value("isRead").toBool(true);

    const QString url = QString("https://graph.microsoft.com/v1.0/%1/messages/%2").arg(mailboxPath(), msgId);
    auto req = NetworkHelper::outlookJsonRequest(url, accessToken);
    NetworkHelper::setRequestTimeout(req);
    QJsonObject body{ {"isRead", !isRead} };

    QNetworkReply *r = net->sendCustomRequest(req, "PATCH", QJsonDocument(body).toJson());
    activeReplies.append(r);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        activeReplies.removeAll(r);
        if (r) r->deleteLater();
        reloadMailbox();
    });
}

void OutlookEmailWindow::deleteEmail() {
    int idx = lstEmails->currentRow();
    if (idx < 0 || idx >= emails.size() || accessToken.isEmpty()) return;

    const QString msgId = emails.at(idx).toObject().value("id").toString();
    const QString url = QString("https://graph.microsoft.com/v1.0/%1/messages/%2/move")
                            .arg(mailboxPath(), msgId);
    auto req = NetworkHelper::outlookJsonRequest(url, accessToken);
    NetworkHelper::setRequestTimeout(req);
    QJsonObject body{ {"destinationId", "deleteditems"} };

    QNetworkReply *r = net->post(req, QJsonDocument(body).toJson());
    activeReplies.append(r);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        activeReplies.removeAll(r);
        if (r) r->deleteLater();
        reloadMailbox();
    });
}

void OutlookEmailWindow::permanentlyDeleteEmail() {
    int idx = lstEmails->currentRow();
    if (idx < 0 || idx >= emails.size() || accessToken.isEmpty()) return;

    const QString msgId = emails.at(idx).toObject().value("id").toString();
    const QString url = QString("https://graph.microsoft.com/v1.0/%1/messages/%2")
                            .arg(mailboxPath(), msgId);
    auto req = NetworkHelper::outlookJsonRequest(url, accessToken);
    NetworkHelper::setRequestTimeout(req);
    QNetworkReply *r = net->deleteResource(req);
    activeReplies.append(r);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        activeReplies.removeAll(r);
        if (r) r->deleteLater();
        reloadMailbox();
    });
}

// ===== BULK OPERATIONS =====

void OutlookEmailWindow::markAllAsRead() {
    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please authenticate first.");
        return;
    }

    if (emails.isEmpty()) {
        QMessageBox::information(this, "No Emails", "No emails to mark as read.");
        return;
    }

    auto reply = QMessageBox::question(this, "Mark All Read",
        QString("Mark all %1 emails in the current view as read?").arg(emails.size()),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) return;

    for (int i = 0; i < emails.size(); ++i) {
        const QString msgId = emails.at(i).toObject().value("id").toString();
        if (msgId.isEmpty()) continue;

        const QString url = QString("https://graph.microsoft.com/v1.0/%1/messages/%2")
                                .arg(mailboxPath(), msgId);

        QJsonObject patch;
        patch.insert("isRead", true);

        auto req = NetworkHelper::outlookJsonRequest(url, accessToken);
        NetworkHelper::setRequestTimeout(req);
        QByteArray body = QJsonDocument(patch).toJson(QJsonDocument::Compact);

        QNetworkReply *r = net->sendCustomRequest(req, "PATCH", body);
        activeReplies.append(r);
        connect(r, &QNetworkReply::finished, this, [this, r]() { activeReplies.removeAll(r); if (r) r->deleteLater(); });
    }

    QMessageBox::information(this, "Bulk Operation",
        QString("Marking %1 emails as read...").arg(emails.size()));

    // Use QPointer guard to prevent callback on deleted object
    QPointer<OutlookEmailWindow> self = this;
    QTimer::singleShot(2000, [self]() {
        if (self) self->reloadMailbox();
    });
}

void OutlookEmailWindow::deleteAllEmails() {
    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Please authenticate first.");
        return;
    }

    if (emails.isEmpty()) {
        QMessageBox::information(this, "No Emails", "No emails to delete.");
        return;
    }

    auto reply = QMessageBox::warning(this, "Delete All",
        QString("⚠️ This will move all %1 emails to Deleted Items. Continue?").arg(emails.size()),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) return;

    for (int i = 0; i < emails.size(); ++i) {
        const QString msgId = emails.at(i).toObject().value("id").toString();
        if (msgId.isEmpty()) continue;

        const QString url = QString("https://graph.microsoft.com/v1.0/%1/messages/%2")
                                .arg(mailboxPath(), msgId);

        QJsonObject movePayload;
        movePayload.insert("destinationId", "deleteditems");

        auto req = NetworkHelper::outlookJsonRequest(url, accessToken);
        NetworkHelper::setRequestTimeout(req);
        QByteArray body = QJsonDocument(movePayload).toJson(QJsonDocument::Compact);

        QNetworkReply *r = net->post(req, body);
        activeReplies.append(r);
        connect(r, &QNetworkReply::finished, this, [this, r]() { activeReplies.removeAll(r); if (r) r->deleteLater(); });
    }

    QMessageBox::information(this, "Bulk Operation",
        QString("Deleting %1 emails...").arg(emails.size()));

    // Use QPointer guard to prevent callback on deleted object
    QPointer<OutlookEmailWindow> self = this;
    QTimer::singleShot(2000, [self]() {
        if (self) self->reloadMailbox();
    });
}

void OutlookEmailWindow::exportEmailsToEML() {
    if (emails.isEmpty()) {
        QMessageBox::information(this, "No Emails", "No emails to export.");
        return;
    }

    QString dirPath = QFileDialog::getExistingDirectory(this, "Select Export Directory");
    if (dirPath.isEmpty()) return;

    int exportedCount = 0;
    for (int i = 0; i < emails.size(); ++i) {
        const QJsonObject email = emails.at(i).toObject();
        const QString subject = email.value("subject").toString();
        const QString from = email.value("from").toObject()
                                 .value("emailAddress").toObject()
                                 .value("address").toString();
        const QString sentDateTime = email.value("sentDateTime").toString();
        const QString body = email.value("body").toObject().value("content").toString();

        // Create EML content
        QString emlContent;
        emlContent += QString("From: %1\n").arg(from);
        emlContent += QString("Subject: %1\n").arg(subject);
        emlContent += QString("Date: %1\n").arg(sentDateTime);
        emlContent += "Content-Type: text/html; charset=utf-8\n\n";
        emlContent += body;

        // Sanitize filename
        QString filename = subject;
        filename.replace(QRegularExpression("[<>:\"/\\\\|?*]"), "_");
        filename = filename.left(100); // Limit length

        QString filepath = QString("%1/%2_%3.eml").arg(dirPath).arg(i + 1).arg(filename);

        QFile file(filepath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << emlContent;
            file.close();
            exportedCount++;
        }
    }

    QMessageBox::information(this, "Export Complete",
        QString("Exported %1 emails to %2").arg(exportedCount).arg(dirPath));
}

void OutlookEmailWindow::showAdvancedSearch() {
    bool ok;
    QStringList items;
    items << "from:sender@domain.com"
          << "hasAttachments:true"
          << "importance:high"
          << "received>=2024-01-01"
          << "subject:invoice"
          << "body:password reset";

    QString filter = QInputDialog::getItem(this, "Advanced Search",
                                          "Select or enter KQL filter:",
                                          items, 0, true, &ok);

    if (ok && !filter.isEmpty()) {
        editSearch->setText(filter);
        reloadMailbox();
    }
}

void OutlookEmailWindow::loadEmailTemplate() {
    QStringList templates;
    templates << "Phishing - Password Reset"
              << "Phishing - IT Security Alert"
              << "Phishing - Document Share"
              << "Phishing - Payroll Update"
              << "Spearphishing - Executive Request"
              << "Custom Template...";

    bool ok;
    QString choice = QInputDialog::getItem(this, "Email Templates",
                                           "Select a template:",
                                           templates, 0, false, &ok);

    if (!ok || choice.isEmpty()) return;

    QString subject, body;

    if (choice == "Phishing - Password Reset") {
        subject = "Action Required: Password Expiring Soon";
        body = "<html><body>"
               "<p>Dear User,</p>"
               "<p>Your password will expire in 24 hours. Please reset it immediately to avoid account lockout.</p>"
               "<p><a href='https://phishing-link.com'>Reset Password Now</a></p>"
               "<p>IT Security Team</p>"
               "</body></html>";
    }
    else if (choice == "Phishing - IT Security Alert") {
        subject = "URGENT: Suspicious Activity Detected";
        body = "<html><body>"
               "<p>We have detected suspicious login attempts on your account from an unknown location.</p>"
               "<p><a href='https://phishing-link.com'>Verify Your Identity</a></p>"
               "<p>This link expires in 1 hour.</p>"
               "<p>Security Operations Center</p>"
               "</body></html>";
    }
    else if (choice == "Phishing - Document Share") {
        subject = "Document Shared: Q4_Financial_Report.xlsx";
        body = "<html><body>"
               "<p>A document has been shared with you:</p>"
               "<p><strong>Q4_Financial_Report.xlsx</strong></p>"
               "<p><a href='https://phishing-link.com'>View Document</a></p>"
               "<p>Shared via SharePoint</p>"
               "</body></html>";
    }
    else if (choice == "Phishing - Payroll Update") {
        subject = "Action Required: Update Direct Deposit Information";
        body = "<html><body>"
               "<p>Our payroll system is being upgraded. Please verify your direct deposit details:</p>"
               "<p><a href='https://phishing-link.com'>Update Banking Information</a></p>"
               "<p>Failure to update by Friday will result in delayed payment.</p>"
               "<p>Payroll Department</p>"
               "</body></html>";
    }
    else if (choice == "Spearphishing - Executive Request") {
        subject = "Urgent: Wire Transfer Needed";
        body = "<html><body>"
               "<p>I need you to process an urgent wire transfer for a confidential acquisition.</p>"
               "<p>Amount: $45,000 USD</p>"
               "<p>Please handle this discreetly and confirm once complete.</p>"
               "<p>Regards,<br>CEO Name</p>"
               "</body></html>";
    }
    else {
        // Custom template
        subject = QInputDialog::getText(this, "Custom Template", "Subject:");
        body = QInputDialog::getMultiLineText(this, "Custom Template", "HTML Body:");
    }

    if (!subject.isEmpty()) {
        // Open compose window with template pre-filled
        QMessageBox::information(this, "Template Loaded",
            QString("Template loaded:\n\nSubject: %1\n\nUse 'New Email' button to compose.")
                .arg(subject));

        // Store in a temporary variable or display in a preview
        // For now, just show the template
    }
}

void OutlookEmailWindow::selectAllEmails() {
    lstEmails->selectAll();
}

void OutlookEmailWindow::selectNoneEmails() {
    lstEmails->clearSelection();
}

void OutlookEmailWindow::onUserChanged(const QString &upn) {
    accessToken.clear();
    updateTokenStatus();
    appendLog(QString("[*] Switched to user: %1").arg(upn), "cyan");
}

void OutlookEmailWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        appendLog("[-] Please select a user first", "red");
        return;
    }

    appendLog("[*] Fetching Graph token for selected user...", "cyan");
    userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &token, const QString &error) {
        if (success) {
            accessToken = token;
            updateTokenStatus();
            appendLog("[+] Graph token acquired", "green");
            reloadMailbox();
        } else {
            appendLog(QString("[-] Failed to fetch token: %1").arg(error), "red");
        }
    });
}

void OutlookEmailWindow::updateTokenStatus() {
    if (accessToken.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet(StyleManager::tokenStatusEmptyStyle());
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet(StyleManager::tokenStatusReadyStyle());
    }
}

void OutlookEmailWindow::appendLog(const QString &msg, const QString &color) {
    Q_UNUSED(color);
    // OutlookEmailWindow doesn't have a logOutput, so we'll use qDebug
    qDebug() << msg;
}

// ===== ASYNC HELPERS =====

void OutlookEmailWindow::uploadAttachmentsAsync(const QString &draftId, const QStringList &files,
                                                 std::function<void(bool)> onComplete)
{
    if (files.isEmpty()) {
        onComplete(true);
        return;
    }

    // Use shared_ptr to track pending uploads
    auto pending = std::make_shared<int>(files.size());
    auto allSuccess = std::make_shared<bool>(true);

    for (const QString &path : files) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            (*pending)--;
            if (*pending == 0) onComplete(*allSuccess);
            continue;
        }

        QByteArray b64 = file.readAll().toBase64();
        file.close();

        const QString uploadUrl = QString("https://graph.microsoft.com/v1.0/%1/messages/%2/attachments")
                                      .arg(mailboxPath(), draftId);
        QNetworkRequest req = NetworkHelper::outlookJsonRequest(uploadUrl, accessToken);
        NetworkHelper::setRequestTimeout(req);

        QJsonObject att{
            {"@odata.type", "#microsoft.graph.fileAttachment"},
            {"name", QFileInfo(path).fileName()},
            {"contentBytes", QString::fromUtf8(b64)},
            {"contentType", "application/octet-stream"}
        };

        QNetworkReply *rep = net->post(req, QJsonDocument(att).toJson());
        activeReplies.append(rep);
        connect(rep, &QNetworkReply::finished, this, [rep, pending, allSuccess, onComplete, path, this]() {
            if (!rep || rep->error() != QNetworkReply::NoError) {
                *allSuccess = false;
                appendLog(QString("[-] Failed to upload: %1").arg(QFileInfo(path).fileName()), "red");
            }
            activeReplies.removeAll(rep);
            if (rep) rep->deleteLater();

            (*pending)--;
            if (*pending == 0) {
                onComplete(*allSuccess);
            }
        });
    }
}

void OutlookEmailWindow::sendDraftAsync(const QString &draftId, std::function<void(bool)> onComplete)
{
    const QString sendUrl = QString("https://graph.microsoft.com/v1.0/%1/messages/%2/send")
                                .arg(mailboxPath(), draftId);
    QNetworkRequest req = NetworkHelper::outlookJsonRequest(sendUrl, accessToken);
    NetworkHelper::setRequestTimeout(req);

    QNetworkReply *rep = net->post(req, QByteArray());
    activeReplies.append(rep);
    connect(rep, &QNetworkReply::finished, this, [this, rep, onComplete]() {
        bool ok = (rep && rep->error() == QNetworkReply::NoError);
        activeReplies.removeAll(rep);
        if (rep) rep->deleteLater();
        onComplete(ok);
    });
}

void OutlookEmailWindow::downloadAttachmentAsync(int index)
{
    if (index >= currentAttachments.size()) {
        // All done
        return;
    }

    const auto att = currentAttachments.at(index).toObject();
    const QString name = att.value("name").toString("unnamed");
    QString contentB64 = att.value("contentBytes").toString();

    auto processDownload = [this, name, index](const QString &b64) {
        if (!b64.isEmpty()) {
            const QString savePath = QFileDialog::getSaveFileName(this, "Save Attachment", name);
            if (!savePath.isEmpty()) {
                QFile f(savePath);
                if (f.open(QIODevice::WriteOnly)) {
                    f.write(QByteArray::fromBase64(b64.toUtf8()));
                    f.close();
                }
            }
        }
        // Process next attachment
        downloadAttachmentAsync(index + 1);
    };

    if (contentB64.isEmpty()) {
        // Need to fetch content first
        const QString url = QString("https://graph.microsoft.com/v1.0/%1/messages/%2/attachments/%3")
                                .arg(mailboxPath(), currentDownloadMsgId, att.value("id").toString());
        QNetworkRequest req = NetworkHelper::outlookJsonRequest(url, accessToken);
        NetworkHelper::setRequestTimeout(req);

        QNetworkReply *rep = net->get(req);
        activeReplies.append(rep);
        connect(rep, &QNetworkReply::finished, this, [this, rep, processDownload]() {
            QString b64;
            if (rep && rep->error() == QNetworkReply::NoError) {
                b64 = QJsonDocument::fromJson(rep->readAll()).object().value("contentBytes").toString();
            }
            activeReplies.removeAll(rep);
            if (rep) rep->deleteLater();
            processDownload(b64);
        });
    } else {
        processDownload(contentB64);
    }
}

void OutlookEmailWindow::cancelRequests() {
    cancelRequested = true;
    for (QNetworkReply *reply : activeReplies) {
        if (reply && !reply->isFinished()) {
            reply->abort();
        }
    }
    activeReplies.clear();
    setLoading(false);
}
