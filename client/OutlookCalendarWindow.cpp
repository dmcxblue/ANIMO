#include "OutlookCalendarWindow.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "NetworkHelper.h"
#include <QHBoxLayout>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QTextCharFormat>
#include <QColor>
#include <QFont>
#include <QJsonDocument>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QDateTime>
#include <QBuffer>
#include <QRegularExpression>
#include <QFileInfo>
#include <QUrl>
#include <QEventLoop>
#include <QTimeZone>
#include <QUrlQuery>
#include <QGroupBox>



// === Helper ===
// Overload that accepts QUrl and sets timezone preference for Graph
static QNetworkRequest bearerJson(const QUrl &url, const QString &token) {
    QNetworkRequest r = NetworkHelper::createBearerRequest(url.toString(), token);
    r.setRawHeader("Prefer", "outlook.timezone=\"UTC\"");
    return r;
}

// === Constructor ===
OutlookCalendarWindow::OutlookCalendarWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)) {

    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Outlook Calendar");
    resize(950, 750);
    setupUi();
}

OutlookCalendarWindow::OutlookCalendarWindow(const QString &token, QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)) {

    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Outlook Calendar");
    resize(950, 750);
    setupUi();
    setAccessToken(token);
}

OutlookCalendarWindow::~OutlookCalendarWindow() {
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

void OutlookCalendarWindow::setAccessToken(const QString &token) {
    if (!token.isEmpty()) {
        accessToken = token;
        loadMonthEvents();
    }
}

void OutlookCalendarWindow::setupUi() {

    auto *layout = new QVBoxLayout(this);

    // User selector and token group
    auto *tokenGroup = new QGroupBox("Microsoft Graph Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &OutlookCalendarWindow::onUserChanged);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &OutlookCalendarWindow::autoFetchTokens);

    // Top bar
    auto *topRow = new QHBoxLayout();
    btnToken = new QPushButton("Paste Token");
    connect(btnToken, &QPushButton::clicked, this, &OutlookCalendarWindow::pasteToken);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    upnInput = new QLineEdit();
    upnInput->setPlaceholderText("Shared UPN (optional)");
    topRow->addWidget(btnToken);
    topRow->addWidget(tokenStatus);
    topRow->addWidget(upnInput);
    tokenLayout->addLayout(topRow);

    layout->addWidget(tokenGroup);

    // Calendar
    calendar = new QCalendarWidget();
    calendar->setGridVisible(true);
    calendar->setVerticalHeaderFormat(QCalendarWidget::NoVerticalHeader);
    connect(calendar, &QCalendarWidget::selectionChanged, this, &OutlookCalendarWindow::loadEventsForSelectedDay);
    connect(calendar, &QCalendarWidget::currentPageChanged, this, &OutlookCalendarWindow::loadMonthEvents);
    layout->addWidget(calendar);

    // Action buttons
    auto *btnRow = new QHBoxLayout();
    btnAdd = new QPushButton("Add Event");
    btnDelete = new QPushButton("Delete Selected Event");
    btnRefresh = new QPushButton("Refresh");
    cancelBtn = new QPushButton("Cancel");
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    connect(btnAdd, &QPushButton::clicked, this, &OutlookCalendarWindow::createEvent);
    connect(btnDelete, &QPushButton::clicked, this, &OutlookCalendarWindow::deleteEvent);
    connect(btnRefresh, &QPushButton::clicked, this, &OutlookCalendarWindow::loadMonthEvents);
    connect(cancelBtn, &QPushButton::clicked, this, &OutlookCalendarWindow::cancelRequests);
    btnRow->addWidget(btnAdd);
    btnRow->addWidget(btnDelete);
    btnRow->addWidget(btnRefresh);
    btnRow->addWidget(cancelBtn);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    // Events list
    layout->addWidget(new QLabel("Events on selected day:"));
    eventsList = new QListWidget();
    eventsList->setFixedHeight(120);
    connect(eventsList, &QListWidget::currentRowChanged, this, &OutlookCalendarWindow::displayEventBody);
    layout->addWidget(eventsList);

    // HTML preview
    eventBody = new QWebEngineView();
    eventBody->setMinimumHeight(400);
    layout->addWidget(eventBody, 1);

    // Attachment container
    attachmentContainer = new QWidget();
    attachmentLayout = new QVBoxLayout();
    attachmentLayout->setContentsMargins(0, 0, 0, 0);
    attachmentLayout->setSpacing(4);
    attachmentContainer->setLayout(attachmentLayout);
    layout->addWidget(attachmentContainer);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);  // Indeterminate mode
    layout->addWidget(progressBar);
}

void OutlookCalendarWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    btnRefresh->setEnabled(!loading);
    btnToken->setEnabled(!loading);
    autoFetchBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

QString OutlookCalendarWindow::getUserPath() const {
    QString upn = upnInput->text().trimmed();
    return upn.isEmpty() ? "me" : QString("users/%1").arg(upn);
}

void OutlookCalendarWindow::pasteToken() {
    bool ok = false;
    QString tok = QInputDialog::getMultiLineText(this, "Access Token", "Paste your Access Token:", "", &ok);
    if (ok && !tok.trimmed().isEmpty()) {
        accessToken = tok.trimmed();
        loadMonthEvents();
    }
}

void OutlookCalendarWindow::loadMonthEvents() {
    if (accessToken.isEmpty()) return;

    setLoading(true);
    // Helper to force Zulu format (avoids '+' in "+00:00")
    auto toZulu = [](const QDate &d, const QTime &t) -> QString {
        const QDateTime utc(d, t, QTimeZone::utc());
        return utc.toUTC().toString("yyyy-MM-dd'T'HH:mm:ss'Z'");
    };

    const int year  = calendar->yearShown();
    const int month = calendar->monthShown();
    const QDate startDate(year, month, 1);
    const QDate endDate = startDate.addMonths(1).addDays(-1);

    const QString startIso = toZulu(startDate, QTime(0, 0, 0));        // e.g., 2025-09-01T00:00:00Z
    const QString endIso   = toZulu(endDate,   QTime(23, 59, 59));     // e.g., 2025-09-30T23:59:59Z

    // Build URL safely with QUrlQuery (prevents '+' → ' ' issues)
    QUrl url(QStringLiteral("https://graph.microsoft.com/v1.0/%1/calendarView").arg(getUserPath()));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("startDateTime"), startIso);
    q.addQueryItem(QStringLiteral("endDateTime"),   endIso);
    q.addQueryItem(QStringLiteral("$orderby"),      QStringLiteral("start/dateTime"));
    q.addQueryItem(QStringLiteral("$top"),          QStringLiteral("200"));
    q.addQueryItem(QStringLiteral("$select"),
                   QStringLiteral("id,subject,body,start,end,location,hasAttachments"));
    url.setQuery(q);

    QNetworkReply *rep = net->get(bearerJson(url, accessToken));
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        setLoading(false);
        eventsList->clear();

        if (rep->error() != QNetworkReply::NoError) {
            const int http = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QByteArray body = rep->readAll();
            QString msg = rep->errorString();
            if (!body.isEmpty()) {
                const QJsonObject root = QJsonDocument::fromJson(body).object();
                const QString gmsg = root.value("error").toObject().value("message").toString();
                if (!gmsg.isEmpty()) msg += QString(" (HTTP %1: %2)").arg(http).arg(gmsg);
                else if (http > 0)   msg += QString(" (HTTP %1)").arg(http);
            } else if (http > 0) {
                msg += QString(" (HTTP %1)").arg(http);
            }
            eventsList->addItem(QString("[!] Month fetch error: %1").arg(msg));
            rep->deleteLater();
            return;
        }

        const auto arr = QJsonDocument::fromJson(rep->readAll()).object().value("value").toArray();

        // Clear previous formatting
        for (auto it = monthEvents.begin(); it != monthEvents.end(); ++it) {
            calendar->setDateTextFormat(it.key(), QTextCharFormat{});
        }
        monthEvents.clear();

        QTextCharFormat highlightFmt;
        highlightFmt.setBackground(QColor("#404040"));
        highlightFmt.setForeground(QColor("#00ffaa"));
        highlightFmt.setFontWeight(QFont::Bold);
        highlightFmt.setFontItalic(true);

        for (const auto &v : arr) {
            const QJsonObject ev = v.toObject();
            const QString dtStr = ev.value("start").toObject().value("dateTime").toString();
            if (dtStr.isEmpty()) continue;

            // Robust ISO parse (handles Z or ±hh:mm). Fallback if needed.
            QDateTime dt = QDateTime::fromString(dtStr, Qt::ISODate);
            if (!dt.isValid())
                dt = QDateTime::fromString(dtStr.left(19), Qt::ISODate);

            const QDate qdate = dt.date();
            monthEvents[qdate].append(ev);
            calendar->setDateTextFormat(qdate, highlightFmt);
        }

        loadEventsForSelectedDay();
        rep->deleteLater();
    });
}

void OutlookCalendarWindow::loadEventsForSelectedDay() {
    QDate date = calendar->selectedDate();
    eventsList->clear();
    eventBody->setHtml("<html><body><i>(No content)</i></body></html>");
    clearAttachmentLayout();

    currentDayEvents.clear();

    if (!monthEvents.contains(date)) {
        eventsList->addItem("[!] No events for this day");
        return;
    }

    currentDayEvents = monthEvents.value(date);

    for (const QJsonObject &ev : currentDayEvents) {
        QString subject  = ev.value("subject").toString("(No Subject)");
        QString start    = ev.value("start").toObject().value("dateTime").toString();
        QString end      = ev.value("end").toObject().value("dateTime").toString();
        QString location = ev.value("location").toObject().value("displayName").toString();
        QString hasAtt   = ev.value("hasAttachments").toBool(false) ? "📎 " : "";

        QListWidgetItem *item = new QListWidgetItem(
            QString("%1%2\n%3 → %4\n%5")
                .arg(hasAtt, subject, start, end, location)
        );
        eventsList->addItem(item);
    }
}

void OutlookCalendarWindow::displayEventBody(int index) {
    if (index < 0 || index >= currentDayEvents.size()) {
        eventBody->setHtml("<html><body><i>(No content)</i></body></html>");
        clearAttachmentLayout();
        return;
    }

    clearAttachmentLayout();

    const QJsonObject ev  = currentDayEvents.at(index);
    const QString eventId = ev.value("id").toString();
    if (eventId.isEmpty()) {
        eventBody->setHtml("<html><body><i>(Missing event ID)</i></body></html>");
        return;
    }

    // Fetch full event to guarantee fresh body/attachments
    const QString eventUrl = QString("https://graph.microsoft.com/v1.0/%1/events/%2"
                                     "?$select=subject,body,hasAttachments")
                                 .arg(getUserPath(), eventId);

    QNetworkReply *evtRep = net->get(bearerJson(eventUrl, accessToken));
    connect(evtRep, &QNetworkReply::finished, this, [this, evtRep, eventId]() {
        if (evtRep->error() != QNetworkReply::NoError) {
            eventBody->setHtml("<html><body><i>(Failed to load event)</i></body></html>");
            evtRep->deleteLater();
            return;
        }

        const QJsonObject full = QJsonDocument::fromJson(evtRep->readAll()).object();
        evtRep->deleteLater();

        const QJsonObject body = full.value("body").toObject();
        QString content        = body.value("content").toString();
        QString type           = body.value("contentType").toString("HTML");
        bool hasAtt            = full.value("hasAttachments").toBool(false);

        // Render text immediately so something shows
        QString wrapped = QString(
            "<html><head><style>"
            "body{background:#2b2b2b;color:#e0e0e0;font-family:'Segoe UI',sans-serif;font-size:12pt;"
            "padding:16px;line-height:1.6em}"
            "a{color:#80d8ff;text-decoration:underline}"
            "img{max-width:100%%;height:auto;border-radius:6px;margin:8px 0}"
            "</style></head><body>%1</body></html>"
        ).arg(type.compare("text", Qt::CaseInsensitive) == 0
                  ? content.toHtmlEscaped()
                  : content);

        eventBody->setHtml(wrapped);

        if (!hasAtt) return;

        // ── Fetch attachments to resolve inline images ──
        const QString attUrl = QString("https://graph.microsoft.com/v1.0/%1/events/%2/attachments")
                                   .arg(getUserPath(), eventId);

        QNetworkReply *attRep = net->get(bearerJson(attUrl, accessToken));
        connect(attRep, &QNetworkReply::finished, this, [this, attRep, content, type, eventId]() mutable {
            if (attRep->error() != QNetworkReply::NoError) {
                attRep->deleteLater();
                return; // keep showing what we already rendered
            }

            const QJsonArray atts = QJsonDocument::fromJson(attRep->readAll()).object().value("value").toArray();
            attRep->deleteLater();

            QMap<QString, QString> cidMap;
            QList<QJsonObject> nonInline;

            auto fetchMediaToBase64 = [this](const QString &mediaUrl) -> QString {
                if (mediaUrl.isEmpty()) return {};
                QNetworkRequest req{ QUrl(mediaUrl) };
                req.setRawHeader("Authorization", QString("Bearer %1").arg(accessToken).toUtf8());
                NetworkHelper::setRequestTimeout(req);
                QNetworkReply *r = net->get(req);
                if (!r) return {};
                QEventLoop loop; QObject::connect(r, &QNetworkReply::finished, &loop, &QEventLoop::quit); loop.exec();
                QString out;
                if (r->error() == QNetworkReply::NoError) {
                    out = QString::fromLatin1(r->readAll().toBase64());
                }
                r->deleteLater();
                return out;
            };

            for (const auto &v : atts) {
                const QJsonObject a = v.toObject();
                const bool isInline = a.value("isInline").toBool(false);
                QString cid = a.value("contentId").toString().trimmed();
                cid.remove('<').remove('>');
                QString b64 = a.value("contentBytes").toString();
                if (b64.isEmpty()) {
                    const QString mediaUrl = a.value("@odata.mediaContentUrl").toString();
                    b64 = fetchMediaToBase64(mediaUrl);
                }
                QString ctype = a.value("contentType").toString("image/png");

                if (isInline && !cid.isEmpty() && !b64.isEmpty()) {
                    cidMap[cid.toLower()] = QString("data:%1;base64,%2").arg(ctype, b64);
                } else if (!isInline) {
                    nonInline.append(a);
                }
            }

            // Replace simple cid: refs
            QString htmlOut = content;
            for (auto it = cidMap.constBegin(); it != cidMap.constEnd(); ++it) {
                htmlOut.replace("cid:" + it.key(), it.value(), Qt::CaseInsensitive);
                htmlOut.replace("cid:<" + it.key() + ">", it.value(), Qt::CaseInsensitive);
            }

            QString wrappedFinal = QString(
                "<html><head><style>"
                "body{background:#2b2b2b;color:#e0e0e0;font-family:'Segoe UI',sans-serif;font-size:12pt;"
                "padding:16px;line-height:1.6em}"
                "a{color:#80d8ff;text-decoration:underline}"
                "img{max-width:100%%;height:auto;border-radius:6px;margin:8px 0}"
                "</style></head><body>%1</body></html>"
            ).arg(type.compare("text", Qt::CaseInsensitive) == 0
                      ? content.toHtmlEscaped()
                      : htmlOut);

            eventBody->setHtml(wrappedFinal);

            // Add download buttons for non-inline attachments
            for (const QJsonObject &att : nonInline) {
                const QString name = att.value("name").toString("attachment.bin");
                const QString mediaUrl = att.value("@odata.mediaContentUrl").toString();
                const QString attId = att.value("id").toString();

                QPushButton *btn = new QPushButton(QString("📎 Download %1").arg(name), attachmentContainer);
                if (!mediaUrl.isEmpty()) {
                    connect(btn, &QPushButton::clicked, this, [this, mediaUrl, name]() {
                        downloadAttachmentUrl(mediaUrl, name);
                    });
                } else if (!attId.isEmpty()) {
                    connect(btn, &QPushButton::clicked, this, [this, eventId, attId, name]() {
                        downloadAttachment(eventId, attId, name);
                    });
                } else {
                    btn->setEnabled(false);
                }
                attachmentLayout->addWidget(btn);
            }
        });
    });
}

void OutlookCalendarWindow::downloadAttachmentUrl(const QString &url, const QString &filename) {
    if (accessToken.isEmpty()) return;

    QNetworkRequest req{ QUrl(url) };
    req.setRawHeader("Authorization", QString("Bearer %1").arg(accessToken).toUtf8());
    NetworkHelper::setRequestTimeout(req);

    QNetworkReply *rep = net->get(req);
    if (!rep) {
        QMessageBox::critical(this, "Error", "Failed to create network request");
        return;
    }
    connect(rep, &QNetworkReply::finished, this, [this, rep, filename]() {
        if (rep->error() != QNetworkReply::NoError) {
            QMessageBox::critical(this, "Error", QString("Failed to download attachment:\n%1").arg(rep->errorString()));
            rep->deleteLater();
            return;
        }

        const QByteArray data = rep->readAll();
        rep->deleteLater();

        const QString path = QFileDialog::getSaveFileName(this, "Save Attachment", filename);
        if (path.isEmpty()) return;

        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(this, "Save Failed", "Could not open file for writing.");
            return;
        }
        f.write(data);
        f.close();

        QMessageBox::information(this, "Saved", "Attachment saved:\n" + path);
    });
}

void OutlookCalendarWindow::downloadAttachment(const QString &eventId, const QString &attachmentId, const QString &filename) {
    if (accessToken.isEmpty()) return;

    const QString url = QString("https://graph.microsoft.com/v1.0/%1/events/%2/attachments/%3")
                            .arg(getUserPath(), eventId, attachmentId);

    QNetworkReply *rep = net->get(bearerJson(url, accessToken));
    connect(rep, &QNetworkReply::finished, this, [this, rep, filename]() {
        if (rep->error() != QNetworkReply::NoError) {
            QMessageBox::critical(this, "Download Failed", rep->errorString());
            rep->deleteLater();
            return;
        }
        const QJsonObject obj = QJsonDocument::fromJson(rep->readAll()).object();
        rep->deleteLater();

        const QString contentB64 = obj.value("contentBytes").toString();
        if (contentB64.isEmpty()) {
            QMessageBox::warning(this, "Error", "Attachment has no downloadable content.");
            return;
        }

        const QByteArray raw = QByteArray::fromBase64(contentB64.toUtf8());
        const QString path = QFileDialog::getSaveFileName(this, "Save Attachment", filename);
        if (path.isEmpty()) return;

        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(this, "Save Failed", "Could not open file for writing.");
            return;
        }
        f.write(raw);
        f.close();

        QMessageBox::information(this, "Saved", "Attachment saved:\n" + path);
    });
}

void OutlookCalendarWindow::createEvent() {
    if (accessToken.isEmpty()) return;

    bool ok = false;
    const QString subject = QInputDialog::getText(this, "Create Event", "Subject:", QLineEdit::Normal, "", &ok).trimmed();
    if (!ok || subject.isEmpty()) return;

    const QString location = QInputDialog::getText(this, "Create Event", "Location (optional):").trimmed();
    const QString bodyHtml = QInputDialog::getMultiLineText(this, "Create Event", "HTML Body (optional):");

    // Default: selected day 10:00-11:00 UTC
    const QDate d = calendar->selectedDate();
    const QDateTime startUTC(d, QTime(10, 0), QTimeZone::utc());
	const QDateTime endUTC(d, QTime(11, 0), QTimeZone::utc());



    QJsonObject payload{
        {"subject", subject},
        {"start", QJsonObject{{"dateTime", startUTC.toString(Qt::ISODate)}, {"timeZone", "UTC"}}},
        {"end",   QJsonObject{{"dateTime", endUTC.toString(Qt::ISODate)},   {"timeZone", "UTC"}}},
        {"location", QJsonObject{{"displayName", location}}},
        {"body", QJsonObject{{"contentType", "HTML"}, {"content", bodyHtml}}}
    };

    const QString url = QString("https://graph.microsoft.com/v1.0/%1/events").arg(getUserPath());
    QNetworkReply *rep = net->post(bearerJson(url, accessToken), QJsonDocument(payload).toJson());
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        if (rep->error() != QNetworkReply::NoError) {
            QMessageBox::critical(this, "Error", "Failed to create event:\n" + rep->errorString());
        } else {
            QMessageBox::information(this, "Success", "Event created successfully.");
            loadMonthEvents();
        }
        rep->deleteLater();
    });
}

void OutlookCalendarWindow::deleteEvent() {
    if (accessToken.isEmpty() || currentDayEvents.isEmpty()) return;

    int idx = eventsList->currentRow();
    if (idx < 0 || idx >= currentDayEvents.size()) return;

    const QString eventId = currentDayEvents.at(idx).value("id").toString();
    if (eventId.isEmpty()) return;

    const QString url = QString("https://graph.microsoft.com/v1.0/%1/events/%2")
                            .arg(getUserPath(), eventId);

    QNetworkReply *rep = net->deleteResource(bearerJson(url, accessToken));
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        if (rep->error() == QNetworkReply::NoError || rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 204) {
            QMessageBox::information(this, "Deleted", "Event deleted.");
            loadMonthEvents();
        } else {
            QMessageBox::critical(this, "Error", "Failed to delete event:\n" + rep->errorString());
        }
        rep->deleteLater();
    });
}



void OutlookCalendarWindow::clearAttachmentLayout() {
    while (auto item = attachmentLayout->takeAt(0)) {
        if (auto w = item->widget()) w->deleteLater();
        delete item;
    }
}

void OutlookCalendarWindow::onUserChanged(const QString &upn) {
    accessToken.clear();
    updateTokenStatus();
    qDebug() << "[*] Switched to user:" << upn;
}

void OutlookCalendarWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        QMessageBox::warning(this, "No User", "Please select a user first");
        return;
    }

    userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &token, const QString &error) {
        if (success) {
            accessToken = token;
            updateTokenStatus();
            loadMonthEvents();
        } else {
            QMessageBox::warning(this, "Token Error", QString("Failed to fetch token: %1").arg(error));
        }
    });
}

void OutlookCalendarWindow::updateTokenStatus() {
    if (accessToken.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

void OutlookCalendarWindow::cancelRequests() {
    cancelRequested = true;
    for (QNetworkReply *reply : activeReplies) {
        if (reply && !reply->isFinished()) {
            reply->abort();
        }
    }
    activeReplies.clear();
    setLoading(false);
}
