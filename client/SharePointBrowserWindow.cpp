#include "SharePointBrowserWindow.h"
#include "TablePlaceholder.h"
#include "StyleManager.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "NetworkHelper.h"

#include <QHBoxLayout>
#include <QSet>
#include <QStringList>
#include <QUrl>
#include <QFile>
#include <QFileInfo>
#include <QIcon>
#include <QGroupBox>

// ------------------------------
// Constructor & basic wiring
// ------------------------------
SharePointBrowserWindow::SharePointBrowserWindow(const QString &tok, QWidget *parent)
    : QWidget(parent),
      token(tok),
      netManager(new QNetworkAccessManager(this))
{
    setWindowTitle("SharePoint Browser");
    resize(900, 700);

    auto *layout = new QVBoxLayout(this);

    // User selector and token group
    auto *tokenGroup = new QGroupBox("Microsoft Graph Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &SharePointBrowserWindow::onUserChanged);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    autoFetchRow->addWidget(tokenStatus);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &SharePointBrowserWindow::autoFetchTokens);

    // Token box
    tokenInput = new QTextEdit();
    tokenInput->setPlaceholderText("Paste a valid access token...");
    tokenInput->setFixedHeight(60);
    tokenInput->setText(token);
    tokenLayout->addWidget(tokenInput);

    layout->addWidget(tokenGroup);

    // Top row: Location dropdown + Load
    auto *topRow = new QHBoxLayout();
    topRow->addWidget(new QLabel("Location:"));

    locationBox = new QComboBox();
    locationBox->addItems({
        "My Files",
        "Shared with me",
        "Recent",
        "Places (Followed Sites)",
        "People",
        "Meetings",
        "Media"
    });
    connect(locationBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SharePointBrowserWindow::onLocationChanged);
    topRow->addWidget(locationBox, 1);

    loadButton = new QPushButton("Load");
    connect(loadButton, &QPushButton::clicked, this, &SharePointBrowserWindow::loadRoot);
    topRow->addSpacing(12);
    topRow->addWidget(loadButton);

    layout->addLayout(topRow);

    // Path label
    pathLabel = new QLabel("SharePoint");
    layout->addWidget(pathLabel);

    // Tree
    tree = new QTreeWidget();
    new TablePlaceholder(tree, "Nothing loaded yet.");
    tree->setHeaderLabels({"Name", "Type", "Last Modified"});
    tree->header()->setSectionResizeMode(QHeaderView::Stretch);
    tree->setSelectionMode(QAbstractItemView::ExtendedSelection);  // Enable Shift+Click, Ctrl+Click
    connect(tree, &QTreeWidget::itemDoubleClicked, this, &SharePointBrowserWindow::onItemDoubleClick);
    layout->addWidget(tree, 1);

    // Bottom buttons
    auto *btnRow = new QHBoxLayout();
    backButton = new QPushButton(QString::fromUtf8("⬅ Back"));
    backButton->setEnabled(false);
    connect(backButton, &QPushButton::clicked, this, &SharePointBrowserWindow::goBack);
    btnRow->addWidget(backButton);

    uploadButton = new QPushButton("Upload File");
    connect(uploadButton, &QPushButton::clicked, this, &SharePointBrowserWindow::uploadFile);
    btnRow->addWidget(uploadButton);

    cancelBtn = new QPushButton("Cancel");
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    connect(cancelBtn, &QPushButton::clicked, this, &SharePointBrowserWindow::cancelRequests);
    btnRow->addWidget(cancelBtn);
    btnRow->addStretch();

    layout->addLayout(btnRow);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);  // Indeterminate mode
    layout->addWidget(progressBar);

    setLayout(layout);
}

SharePointBrowserWindow::~SharePointBrowserWindow() {
    // Disconnect ALL network replies to prevent callbacks during destruction
    if (netManager) {
        const auto replies = netManager->findChildren<QNetworkReply*>();
        for (auto *r : replies) {
            r->disconnect();
            r->abort();
        }
    }
    activeReplies.clear();
}

void SharePointBrowserWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    loadButton->setEnabled(!loading);
    backButton->setEnabled(!loading && !pathStack.isEmpty());
    uploadButton->setEnabled(!loading);
    autoFetchBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

// ------------------------------
// UI events
// ------------------------------
void SharePointBrowserWindow::onLocationChanged(int index) {
    currentLocation = static_cast<Location>(index);
    pathStack.clear();
    pathLabel->setText("SharePoint");

    // Enable upload only for drive contexts
    bool driveContext =
        currentLocation == Location::MyFiles ||
        currentLocation == Location::Shared ||
        currentLocation == Location::Recent ||
        currentLocation == Location::Places ||
        currentLocation == Location::Media;
    uploadButton->setEnabled(driveContext);
}

void SharePointBrowserWindow::loadRoot() {
    token = tokenInput->toPlainText().trimmed();
    if (token.isEmpty()) {
        QMessageBox::warning(this, "Missing Token", "Access token is required.");
        return;
    }
    pathStack.clear();
    fetchLocationRoot();
}

void SharePointBrowserWindow::goBack() {
    if (!pathStack.isEmpty()) pathStack.pop_back();

    if (pathStack.isEmpty()) {
        fetchLocationRoot();
    } else {
        // still inside a drive/site-drive
        auto last = pathStack.last();
        const QString folderId = last.first;
        // Update path label
        QStringList names;
        for (const auto &p : pathStack) names << p.second;
        pathLabel->setText("Path: /" + names.join("/"));
        fetchDriveChildren(folderId);
    }
}

void SharePointBrowserWindow::onItemDoubleClick(QTreeWidgetItem *item, int) {
    const QJsonObject data = item->data(0, Qt::UserRole).toJsonObject();

    switch (currentLocation) {
        case Location::Places: {
            // Double-click a site to enter its default drive
            const QString siteId   = data.value("id").toString();
            const QString siteName = data.value("name").toString("Site");
            if (siteId.isEmpty()) {
                QMessageBox::warning(this, "No site id", "Unable to open this site (missing id).");
                return;
            }
            pathStack.clear();
            pathStack.append(qMakePair(QString("site:%1").arg(siteId), siteName));
            pathLabel->setText("Site: " + siteName);
            fetchSiteDriveRoot(siteId);
            break;
        }

        case Location::People: {
            const QString name = data.value("displayName").toString();
            const QString upn  = data.value("userPrincipalName").toString();
            QMessageBox::information(this, "Person",
                                     QString("Name: %1\nUPN: %2").arg(name, upn));
            break;
        }

        case Location::Meetings: {
            const QString subject = data.value("subject").toString("(No subject)");
            const QString bodyPrev = data.value("bodyPreview").toString();
            QMessageBox::information(this, "Event",
                                     QString("Subject: %1\n\n%2").arg(subject, bodyPrev));
            break;
        }

        default: {
            // Drive contexts: MyFiles / Shared / Recent / Media and site drives
            const bool isFolder = data.contains("folder");
            const QString name  = data.value("name").toString();

            if (isFolder) {
                const QString id = data.value("id").toString();
                pathStack.append(qMakePair(id, name));

                QStringList names;
                for (const auto &p : pathStack) names << p.second;
                pathLabel->setText("Path: /" + names.join("/"));
                fetchDriveChildren(id);
            } else {
                // File download - try multiple methods
                downloadFile(data, name);
            }
            break;
        }
    }
}

// ------------------------------
// Networking: entry points
// ------------------------------
void SharePointBrowserWindow::fetchLocationRoot() {
    setLoading(true);
    backButton->setEnabled(false);
    tree->clear();

    switch (currentLocation) {
        case Location::MyFiles:
            pathLabel->setText("My Files");
            fetchDriveChildren();  // me/drive/root
            break;

        case Location::Shared:
            pathLabel->setText("Shared with me");
            fetchSharedWithMe();
            break;

        case Location::Recent:
            pathLabel->setText("Recent");
            fetchRecent();
            break;

        case Location::Places:
            pathLabel->setText("Places (Followed Sites)");
            fetchFollowedSites();
            break;

        case Location::People:
            pathLabel->setText("People");
            fetchPeople();
            break;

        case Location::Meetings:
            pathLabel->setText("Meetings");
            fetchMeetings();
            break;

        case Location::Media:
            pathLabel->setText("Media");
            fetchMedia(); // routes to Recent and filters client-side
            break;
    }
}

// My files + site drives; if folderId empty => root children
void SharePointBrowserWindow::fetchDriveChildren(const QString &folderId) {
    QString url;

    // Are we inside a site drive? (pathStack[0] sentinel "site:{siteId}")
    if (!pathStack.isEmpty() && pathStack.first().first.startsWith("site:")) {
        const QString siteId = pathStack.first().first.mid(QString("site:").length());
        url = folderId.isEmpty()
              ? QString("https://graph.microsoft.com/v1.0/sites/%1/drive/root/children").arg(siteId)
              : QString("https://graph.microsoft.com/v1.0/sites/%1/drive/items/%2/children").arg(siteId, folderId);
    } else {
        url = folderId.isEmpty()
              ? "https://graph.microsoft.com/v1.0/me/drive/root/children"
              : QString("https://graph.microsoft.com/v1.0/me/drive/items/%1/children").arg(folderId);
    }

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply *reply = netManager->get(req);
    if (!reply) { setLoading(false); return; }
    activeReplies.append(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleNetworkReply(reply); });
}

void SharePointBrowserWindow::fetchSharedWithMe() {
    QNetworkRequest req = NetworkHelper::createBearerRequest("https://graph.microsoft.com/v1.0/me/drive/sharedWithMe", token);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply *reply = netManager->get(req);
    if (!reply) { setLoading(false); return; }
    activeReplies.append(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleNetworkReply(reply); });
}

void SharePointBrowserWindow::fetchRecent() {
    QNetworkRequest req = NetworkHelper::createBearerRequest("https://graph.microsoft.com/v1.0/me/drive/recent", token);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply *reply = netManager->get(req);
    if (!reply) { setLoading(false); return; }
    activeReplies.append(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleNetworkReply(reply); });
}

void SharePointBrowserWindow::fetchFollowedSites() {
    QNetworkRequest req = NetworkHelper::createBearerRequest("https://graph.microsoft.com/v1.0/me/followedSites", token);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply *reply = netManager->get(req);
    if (!reply) { setLoading(false); return; }
    activeReplies.append(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleNetworkReply(reply); });
}

/*
void SharePointBrowserWindow::fetchFollowedSites() {
    // Fetch both: followedSites and joinedSites, then union them in one list
    auto makeReq = [this](const QUrl &url) {
        QNetworkRequest req{ url };
        req.setRawHeader("Authorization", QString("Bearer %1").arg(token).toUtf8());
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        return netManager->get(req);
    };

    // Clear the tree early and set header for Places
    tree->clear();
    tree->setHeaderLabels({"Site Name", "Type", "Web URL"});

    // Track both replies
    QPointer<QNetworkReply> repFollow = makeReq(QUrl("https://graph.microsoft.com/v1.0/me/followedSites"));
    QPointer<QNetworkReply> repJoined = makeReq(QUrl("https://graph.microsoft.com/v1.0/me/joinedSites"));

    auto finishIfReady = [this, repFollow, repJoined]() {
        if (!repFollow || !repJoined) return;
        if (!repFollow->isFinished() || !repJoined->isFinished()) return;

        // Handle errors gently; show what we have
        auto parseArray = [](QNetworkReply *r) -> QJsonArray {
            if (!r || r->error() != QNetworkReply::NoError) return {};
            const QJsonDocument d = QJsonDocument::fromJson(r->readAll());
            return d.object().value("value").toArray();
        };

        QJsonArray followed = parseArray(repFollow);
        QJsonArray joined   = parseArray(repJoined);

        // Tag each for display
        auto addSites = [this](const QJsonArray &sites, const QString &tag) {
            for (const QJsonValue &v : sites) {
                QJsonObject s = v.toObject();
                s.insert("_placeTag", tag); // mark origin
                const QString name   = s.value("name").toString("Site");
                const QString webUrl = s.value("webUrl").toString();
                auto *it = new QTreeWidgetItem({name, tag, webUrl});
                it->setData(0, Qt::UserRole, s);
                it->setIcon(0, QIcon(":/icons/shareicons/folder.png"));
                tree->addTopLevelItem(it);
            }
        };

        addSites(followed, "Followed");
        addSites(joined,   "Joined");

        backButton->setEnabled(!pathStack.isEmpty());

        if (repFollow) repFollow->deleteLater();
        if (repJoined) repJoined->deleteLater();
    };

    connect(repFollow, &QNetworkReply::finished, this, finishIfReady);
    connect(repJoined, &QNetworkReply::finished, this, finishIfReady);
}


*/

void SharePointBrowserWindow::fetchSiteDriveRoot(const QString &siteId) {
    // Seed path with site sentinel if not set
    if (pathStack.isEmpty() || !pathStack.first().first.startsWith("site:")) {
        pathStack.clear();
        pathStack.append(qMakePair(QString("site:%1").arg(siteId), QString("Site")));
    }
    fetchDriveChildren(); // goes to sites/{id}/drive/root/children
}

void SharePointBrowserWindow::fetchPeople() {
    QNetworkRequest req = NetworkHelper::createBearerRequest("https://graph.microsoft.com/v1.0/me/people", token);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply *reply = netManager->get(req);
    if (!reply) { setLoading(false); return; }
    activeReplies.append(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleNetworkReply(reply); });
}

void SharePointBrowserWindow::fetchMeetings() {
    // Simple events list; could filter by time range later
    QNetworkRequest req = NetworkHelper::createBearerRequest("https://graph.microsoft.com/v1.0/me/events?$top=50&$orderby=start/dateTime", token);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply *reply = netManager->get(req);
    if (!reply) { setLoading(false); return; }
    activeReplies.append(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { handleNetworkReply(reply); });
}

void SharePointBrowserWindow::fetchMedia() {
    // Reuse Recent and filter media client-side
    fetchRecent();
}

// ------------------------------
// Network reply handler
// ------------------------------
void SharePointBrowserWindow::handleNetworkReply(QNetworkReply *reply) {
    setLoading(false);
    if (reply->error() != QNetworkReply::NoError) {
        QMessageBox::critical(this, "Network error", reply->errorString());
        reply->deleteLater();
        return;
    }

    const QByteArray payload = reply->readAll();
    const QJsonDocument doc = QJsonDocument::fromJson(payload);
    const QJsonArray items = doc.object().value("value").toArray();

    // Reset columns based on view
    switch (currentLocation) {
        case Location::MyFiles:
        case Location::Shared:
        case Location::Recent:
        case Location::Media:
            tree->clear();
            tree->setHeaderLabels({"Name", "Type", "Last Modified"});
            processDriveItems(items);
            break;

        case Location::Places:
            tree->clear();
            tree->setHeaderLabels({"Site Name", "Type", "Web URL"});
            processSites(items);
            break;

        case Location::People:
            tree->clear();
            tree->setHeaderLabels({"Name", "Type", "UPN"});
            processPeople(items);
            break;

        case Location::Meetings:
            tree->clear();
            tree->setHeaderLabels({"Subject", "Type", "Start"});
            processMeetings(items);
            break;
    }

    backButton->setEnabled(!pathStack.isEmpty());
    reply->deleteLater();
}

// ------------------------------
// Renderers
// ------------------------------
void SharePointBrowserWindow::processDriveItems(const QJsonArray &items) {
    auto isMedia = [](const QString &name) {
        const QString ext = name.section(".", -1).toLower();
        static const QSet<QString> img = {"jpg","jpeg","png","gif","bmp","tiff","webp","heic"};
        static const QSet<QString> vid = {"mp4","mov","mkv","avi","wmv","m4v","webm"};
        return img.contains(ext) || vid.contains(ext);
    };

    for (const QJsonValue &v : items) {
        const QJsonObject item = v.toObject();
        const QString name = item.value("name").toString("Unnamed");
        const bool isFolder = item.contains("folder");
        const QString modified = item.value("lastModifiedDateTime").toString("Unknown");

        if (currentLocation == Location::Media && !isFolder && !isMedia(name)) {
            continue; // filter out non-media
        }

        const QString type = isFolder ? "Folder" : (name.contains(".") ? (name.section(".", -1).toUpper() + " File") : "File");
        auto *treeItem = new QTreeWidgetItem({name, type, modified});
        treeItem->setData(0, Qt::UserRole, item);
        treeItem->setIcon(0, QIcon(isFolder ? ":/icons/shareicons/folder.png" : ":/icons/shareicons/other_file.png"));
        tree->addTopLevelItem(treeItem);
    }
}

void SharePointBrowserWindow::processSites(const QJsonArray &sites) {
    for (const QJsonValue &v : sites) {
        const QJsonObject s = v.toObject();
        const QString name  = s.value("name").toString("Site");
        const QString webUrl= s.value("webUrl").toString();
        auto *it = new QTreeWidgetItem({name, "Site", webUrl});
        it->setData(0, Qt::UserRole, s); // contains id
        it->setIcon(0, QIcon(":/icons/shareicons/folder.png"));
        tree->addTopLevelItem(it);
    }
}

void SharePointBrowserWindow::processPeople(const QJsonArray &people) {
    for (const QJsonValue &v : people) {
        const QJsonObject p = v.toObject();
        const QString display = p.value("displayName").toString();
        const QString upn = p.value("userPrincipalName").toString();
        auto *it = new QTreeWidgetItem({display, "Person", upn});
        it->setData(0, Qt::UserRole, p);
        it->setIcon(0, QIcon(":/icons/shareicons/other_file.png"));
        tree->addTopLevelItem(it);
    }
}

void SharePointBrowserWindow::processMeetings(const QJsonArray &events) {
    for (const QJsonValue &v : events) {
        const QJsonObject e = v.toObject();
        const QString subject = e.value("subject").toString("(No subject)");
        const QString start   = e.value("start").toObject().value("dateTime").toString();
        auto *it = new QTreeWidgetItem({subject, "Event", start});
        it->setData(0, Qt::UserRole, e);
        it->setIcon(0, QIcon(":/icons/shareicons/other_file.png"));
        tree->addTopLevelItem(it);
    }
}

// ------------------------------
// Upload (works in My Files and Site Drive contexts)
// ------------------------------
void SharePointBrowserWindow::uploadFile() {
    // Only allow in drive contexts
    if (!(currentLocation == Location::MyFiles ||
          currentLocation == Location::Shared ||
          currentLocation == Location::Recent ||
          currentLocation == Location::Places ||
          currentLocation == Location::Media)) {
        QMessageBox::information(this, "Not a drive", "Uploads are only supported in drive contexts.");
        return;
    }

    const QString filePath = QFileDialog::getOpenFileName(this, "Select file to upload");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Open error", "Could not open the selected file.");
        return;
    }
    const QByteArray content = file.readAll();
    const QString baseName = QFileInfo(filePath).fileName();

    // Build the upload URL depending on context and folder
    QString url;

    // Site drive?
    if (!pathStack.isEmpty() && pathStack.first().first.startsWith("site:")) {
        const QString siteId = pathStack.first().first.mid(QString("site:").length());
        if (pathStack.size() <= 1) {
            // at site drive root
            url = QString("https://graph.microsoft.com/v1.0/sites/%1/drive/root:/%2:/content").arg(siteId, QUrl::toPercentEncoding(baseName));
        } else {
            const QString parentId = pathStack.last().first;
            url = QString("https://graph.microsoft.com/v1.0/sites/%1/drive/items/%2:/%3:/content")
                      .arg(siteId, parentId, QUrl::toPercentEncoding(baseName));
        }
    } else {
        // Personal drive
        if (pathStack.isEmpty()) {
            // my root
            url = QString("https://graph.microsoft.com/v1.0/me/drive/root:/%1:/content").arg(QUrl::toPercentEncoding(baseName));
        } else {
            const QString parentId = pathStack.last().first;
            url = QString("https://graph.microsoft.com/v1.0/me/drive/items/%1:/%2:/content")
                      .arg(parentId, QUrl::toPercentEncoding(baseName));
        }
    }

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);
    // PUT raw bytes for simple upload (<=4MB recommended; larger needs upload session)
    QNetworkReply *reply = netManager->put(req, content);
    if (!reply) {
        QMessageBox::critical(this, "Upload error", "Failed to create upload request");
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QMessageBox::information(this, "Upload", "File uploaded successfully.");
            // Refresh current folder listing
            if (pathStack.isEmpty()) {
                fetchLocationRoot();
            } else {
                fetchDriveChildren(pathStack.last().first);
            }
        } else {
            QMessageBox::critical(this, "Upload error", reply->errorString());
        }
        reply->deleteLater();
    });
}

void SharePointBrowserWindow::onUserChanged(const QString &upn) {
    token.clear();
    tokenInput->clear();
    updateTokenStatus();
    qDebug() << "[*] Switched to user:" << upn;
}

// ------------------------------
// Robust file download handling
// ------------------------------
void SharePointBrowserWindow::downloadFile(const QJsonObject &itemData, const QString &fileName) {
    // Determine if this is a text file for preview
    bool isTextPreview = fileName.endsWith(".txt", Qt::CaseInsensitive) ||
                         fileName.endsWith(".json", Qt::CaseInsensitive) ||
                         fileName.endsWith(".xml", Qt::CaseInsensitive) ||
                         fileName.endsWith(".csv", Qt::CaseInsensitive) ||
                         fileName.endsWith(".log", Qt::CaseInsensitive) ||
                         fileName.endsWith(".md", Qt::CaseInsensitive) ||
                         fileName.endsWith(".ps1", Qt::CaseInsensitive) ||
                         fileName.endsWith(".py", Qt::CaseInsensitive) ||
                         fileName.endsWith(".sh", Qt::CaseInsensitive) ||
                         fileName.endsWith(".yml", Qt::CaseInsensitive) ||
                         fileName.endsWith(".yaml", Qt::CaseInsensitive);

    // Method 1: Try @microsoft.graph.downloadUrl (fastest if available)
    QString downloadUrl = itemData.value("@microsoft.graph.downloadUrl").toString();
    if (!downloadUrl.isEmpty()) {
        qDebug() << "[SharePoint] Using direct downloadUrl";
        downloadFromUrl(downloadUrl, fileName, isTextPreview);
        return;
    }

    // Method 2: Check for remoteItem (shared files from other drives)
    QJsonObject remoteItem = itemData.value("remoteItem").toObject();
    if (!remoteItem.isEmpty()) {
        QString remoteDriveId = remoteItem.value("parentReference").toObject().value("driveId").toString();
        QString remoteItemId = remoteItem.value("id").toString();

        // Try downloadUrl from remoteItem first
        downloadUrl = remoteItem.value("@microsoft.graph.downloadUrl").toString();
        if (!downloadUrl.isEmpty()) {
            qDebug() << "[SharePoint] Using remoteItem downloadUrl";
            downloadFromUrl(downloadUrl, fileName, isTextPreview);
            return;
        }

        // Fall back to /content endpoint for remote item
        if (!remoteDriveId.isEmpty() && !remoteItemId.isEmpty()) {
            qDebug() << "[SharePoint] Using remoteItem /content endpoint";
            downloadViaContentEndpoint(remoteDriveId, remoteItemId, fileName, isTextPreview);
            return;
        }
    }

    // Method 3: Use /content endpoint with item ID
    QString itemId = itemData.value("id").toString();
    if (!itemId.isEmpty()) {
        // Determine the drive context
        QString driveId;

        // Check parentReference for driveId
        QJsonObject parentRef = itemData.value("parentReference").toObject();
        driveId = parentRef.value("driveId").toString();

        if (driveId.isEmpty()) {
            // Check if we're in a site context
            if (!pathStack.isEmpty() && pathStack.first().first.startsWith("site:")) {
                // Site drive - we'll use sites/{siteId}/drive/items/{id}/content
                QString siteId = pathStack.first().first.mid(QString("site:").length());
                QString url = QString("https://graph.microsoft.com/v1.0/sites/%1/drive/items/%2/content")
                                  .arg(siteId, itemId);
                qDebug() << "[SharePoint] Using site drive /content endpoint:" << url;

                QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);
                req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
                QNetworkReply *reply = netManager->get(req);
                if (!reply) return;
                activeReplies.append(reply);
                connect(reply, &QNetworkReply::finished, this, [this, reply, fileName, isTextPreview]() {
                    handleDownloadResponse(reply, fileName, isTextPreview);
                });
                return;
            }

            // Default to user's personal drive
            QString url = QString("https://graph.microsoft.com/v1.0/me/drive/items/%1/content").arg(itemId);
            qDebug() << "[SharePoint] Using personal drive /content endpoint:" << url;

            QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);
            req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
            QNetworkReply *reply = netManager->get(req);
            if (!reply) return;
            activeReplies.append(reply);
            connect(reply, &QNetworkReply::finished, this, [this, reply, fileName, isTextPreview]() {
                handleDownloadResponse(reply, fileName, isTextPreview);
            });
            return;
        }

        // We have a driveId - use drives/{driveId}/items/{itemId}/content
        qDebug() << "[SharePoint] Using drives/{driveId}/items/{itemId}/content";
        downloadViaContentEndpoint(driveId, itemId, fileName, isTextPreview);
        return;
    }

    // No download method available
    QMessageBox::warning(this, "Download Error",
                         QString("Cannot download '%1'.\n\n"
                                 "The file metadata doesn't contain a download URL or item ID.\n"
                                 "This may happen with certain shared files or restricted content.")
                             .arg(fileName));
}

void SharePointBrowserWindow::downloadFromUrl(const QString &url, const QString &fileName, bool isTextPreview) {
    if (isTextPreview) {
        // Preview text files directly
        QNetworkRequest req{QUrl(url)};
        NetworkHelper::setRequestTimeout(req);
        QNetworkReply *reply = netManager->get(req);
        if (!reply) return;
        activeReplies.append(reply);
        connect(reply, &QNetworkReply::finished, this, [this, reply, fileName]() {
            if (reply->error() == QNetworkReply::NoError) {
                const QString content = QString::fromUtf8(reply->readAll());
                auto *viewer = new QTextEdit();
                viewer->setWindowTitle(fileName);
                viewer->setReadOnly(true);
                viewer->setFont(QFont("Monospace", 10));
                viewer->setText(content);
                viewer->resize(700, 500);
                viewer->setAttribute(Qt::WA_DeleteOnClose);
                viewer->show();
                textViewers.append(viewer);
                connect(viewer, &QObject::destroyed, this, [this, viewer]() {
                    textViewers.removeOne(viewer);
                });
            } else {
                QMessageBox::critical(this, "Preview Error", reply->errorString());
            }
            reply->deleteLater();
        });
    } else {
        // Prompt for save location
        const QString savePath = QFileDialog::getSaveFileName(this, "Save File As", fileName);
        if (savePath.isEmpty()) return;

        QNetworkRequest req{QUrl(url)};
        NetworkHelper::setRequestTimeout(req);
        QNetworkReply *reply = netManager->get(req);
        if (!reply) return;
        activeReplies.append(reply);
        connect(reply, &QNetworkReply::finished, this, [this, reply, savePath, fileName]() {
            if (reply->error() == QNetworkReply::NoError) {
                QFile f(savePath);
                if (f.open(QIODevice::WriteOnly)) {
                    f.write(reply->readAll());
                    f.close();
                    QMessageBox::information(this, "Download Complete",
                                             QString("'%1' downloaded successfully.").arg(fileName));
                } else {
                    QMessageBox::critical(this, "Save Error",
                                          QString("Could not write to: %1").arg(savePath));
                }
            } else {
                QMessageBox::critical(this, "Download Error", reply->errorString());
            }
            reply->deleteLater();
        });
    }
}

void SharePointBrowserWindow::downloadViaContentEndpoint(const QString &driveId, const QString &itemId,
                                                          const QString &fileName, bool isTextPreview) {
    QString url = QString("https://graph.microsoft.com/v1.0/drives/%1/items/%2/content")
                      .arg(driveId, itemId);

    QNetworkRequest req = NetworkHelper::createBearerRequest(url, token);
    // Handle redirects manually to get the actual download URL
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);

    QNetworkReply *reply = netManager->get(req);
    if (!reply) return;
    activeReplies.append(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, fileName, isTextPreview]() {
        handleDownloadResponse(reply, fileName, isTextPreview);
    });
}

void SharePointBrowserWindow::handleDownloadResponse(QNetworkReply *reply, const QString &fileName, bool isTextPreview) {
    // Check for redirect (302/307) - Graph API returns redirect to actual download URL
    int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

    if (statusCode == 302 || statusCode == 307 || statusCode == 301) {
        // Follow the redirect to get the actual file
        QUrl redirectUrl = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
        if (redirectUrl.isValid()) {
            qDebug() << "[SharePoint] Following redirect to:" << redirectUrl.toString().left(100);
            reply->deleteLater();
            downloadFromUrl(redirectUrl.toString(), fileName, isTextPreview);
            return;
        }
    }

    if (reply->error() != QNetworkReply::NoError) {
        // Parse error details from response body if available
        QByteArray errorBody = reply->readAll();
        QString errorMsg = reply->errorString();

        if (!errorBody.isEmpty()) {
            QJsonDocument doc = QJsonDocument::fromJson(errorBody);
            if (doc.isObject()) {
                QJsonObject error = doc.object().value("error").toObject();
                QString code = error.value("code").toString();
                QString message = error.value("message").toString();
                if (!message.isEmpty()) {
                    errorMsg = QString("%1: %2").arg(code, message);
                }
            }
        }

        QMessageBox::critical(this, "Download Error",
                              QString("Failed to download '%1':\n\n%2").arg(fileName, errorMsg));
        reply->deleteLater();
        return;
    }

    // Success - we got the file content directly (some endpoints don't redirect)
    QByteArray data = reply->readAll();

    if (isTextPreview) {
        auto *viewer = new QTextEdit();
        viewer->setWindowTitle(fileName);
        viewer->setReadOnly(true);
        viewer->setFont(QFont("Monospace", 10));
        viewer->setText(QString::fromUtf8(data));
        viewer->resize(700, 500);
        viewer->setAttribute(Qt::WA_DeleteOnClose);
        viewer->show();
        textViewers.append(viewer);
        connect(viewer, &QObject::destroyed, this, [this, viewer]() {
            textViewers.removeOne(viewer);
        });
    } else {
        const QString savePath = QFileDialog::getSaveFileName(this, "Save File As", fileName);
        if (!savePath.isEmpty()) {
            QFile f(savePath);
            if (f.open(QIODevice::WriteOnly)) {
                f.write(data);
                f.close();
                QMessageBox::information(this, "Download Complete",
                                         QString("'%1' downloaded successfully.").arg(fileName));
            } else {
                QMessageBox::critical(this, "Save Error",
                                      QString("Could not write to: %1").arg(savePath));
            }
        }
    }

    reply->deleteLater();
}

void SharePointBrowserWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        QMessageBox::warning(this, "No User", "Please select a user first");
        return;
    }

    userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &newToken, const QString &error) {
        if (success) {
            token = newToken;
            tokenInput->setPlainText(newToken);
            updateTokenStatus();
            loadRoot();
        } else {
            QMessageBox::warning(this, "Token Error",
                QString("Failed to fetch Graph token: %1").arg(error));
        }
    });
}

void SharePointBrowserWindow::updateTokenStatus() {
    if (token.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

void SharePointBrowserWindow::cancelRequests() {
    cancelRequested = true;
    for (QNetworkReply *reply : activeReplies) {
        if (reply && !reply->isFinished()) {
            reply->abort();
        }
    }
    activeReplies.clear();
    setLoading(false);
}
