#include "TeamsChatWindow.h"
#include "StyleManager.h"
#include "ExternalLinkPage.h"
#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "NetworkHelper.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QFileDialog>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QTimeZone>
#include <QByteArray>
#include <QStringList>
#include <QGroupBox>
#include <QInputDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QDateTimeEdit>
#include <QMenu>
#include <QFile>
#include <QTextStream>
#include <QDialog>

// Graph API base URL
static const QString GRAPH_BASE = "https://graph.microsoft.com/v1.0";
static const QString GRAPH_BETA = "https://graph.microsoft.com/beta";

// Skype/Teams undocumented API
static const QString TEAMS_AUTHZ_URL = "https://teams.microsoft.com/api/authsvc/v1.0/authz";
static const QString SKYPE_MSG_BASE = "https://amer.ng.msg.teams.microsoft.com/v1/users/ME";

// ---------- ctor / UI ----------
TeamsChatWindow::TeamsChatWindow(QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)) {

    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Teams Chat & Channels");
    resize(950, 700);
    setupUi();
}

TeamsChatWindow::TeamsChatWindow(const QString &accessTok, const QString &refreshTok, QWidget *parent)
    : QWidget(parent), net(new QNetworkAccessManager(this)) {

    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Teams Chat & Channels");
    resize(950, 700);
    setupUi();
    setTokens(accessTok, refreshTok);
}

TeamsChatWindow::~TeamsChatWindow() {
    // Stop poll timer first to prevent new requests during destruction
    if (pollTimer) {
        pollTimer->stop();
        pollTimer->disconnect();
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

void TeamsChatWindow::setTokens(const QString &accessTok, const QString &refreshTok) {
    if (!accessTok.isEmpty()) {
        accessToken = accessTok;
        tokenInput->setPlainText(accessTok);
    }
    if (!refreshTok.isEmpty()) {
        refreshToken = refreshTok;
        refreshInput->setPlainText(refreshTok);
    }
    updateTokenStatus();
}

void TeamsChatWindow::setupUi() {
    auto *layout = new QVBoxLayout(this);

    // User selector and token group
    auto *tokenGroup = new QGroupBox("Microsoft Graph Token", this);
    auto *tokenLayout = new QVBoxLayout(tokenGroup);

    userSelector = new UserSelectorWidget(this);
    tokenLayout->addWidget(userSelector);
    connect(userSelector, &UserSelectorWidget::userChanged, this, &TeamsChatWindow::onUserChanged);

    auto *autoFetchRow = new QHBoxLayout();
    autoFetchBtn = new QPushButton("Auto-Fetch Token for Selected User", this);
    StyleManager::applyPrimaryStyle(autoFetchBtn);
    autoFetchRow->addWidget(autoFetchBtn);
    tokenStatus = new QLabel(this);
    tokenStatus->setFixedWidth(80);
    autoFetchRow->addWidget(tokenStatus);
    autoFetchRow->addStretch();
    tokenLayout->addLayout(autoFetchRow);
    connect(autoFetchBtn, &QPushButton::clicked, this, &TeamsChatWindow::autoFetchTokens);

    layout->addWidget(tokenGroup);

    layout->addWidget(new QLabel("Access Token (graph.microsoft.com)"));
    tokenInput = new QTextEdit();
    tokenInput->setPlaceholderText("Paste a valid Graph API AccessToken...");
    tokenInput->setFixedHeight(50);
    layout->addWidget(tokenInput);

    layout->addWidget(new QLabel("Refresh Token (optional, for attachments)"));
    refreshInput = new QTextEdit();
    refreshInput->setPlaceholderText("Paste your RefreshToken here (needed for file attachments)...");
    refreshInput->setFixedHeight(50);
    layout->addWidget(refreshInput);

    // Mode selection row
    auto *modeRow = new QHBoxLayout();
    modeRow->addWidget(new QLabel("Mode:"));
    modeSelect = new QComboBox();
    modeSelect->addItem("Teams & Channels (Group.Read.All)", static_cast<int>(Mode::TeamsChannels));
    modeSelect->addItem("Direct Chats - Graph API (Chat.Read)", static_cast<int>(Mode::DirectChatsGraph));
    modeSelect->addItem("Direct Chats - Skype API (No special scope)", static_cast<int>(Mode::DirectChatsSkype));
    modeSelect->setFixedWidth(320);
    connect(modeSelect, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TeamsChatWindow::onModeChanged);
    modeRow->addWidget(modeSelect);

    loadBtn = new QPushButton("Load");
    loadBtn->setFixedWidth(80);
    connect(loadBtn, &QPushButton::clicked, this, [this]() {
        if (currentMode == Mode::TeamsChannels) {
            loadTeams();
        } else if (currentMode == Mode::DirectChatsGraph) {
            loadDirectChatsGraph();
        } else {
            loadDirectChatsSkype();
        }
    });
    modeRow->addWidget(loadBtn);
    modeRow->addStretch();
    layout->addLayout(modeRow);

    // Teams & Channels dropdowns
    auto *teamsRow = new QHBoxLayout();
    teamsRow->addWidget(new QLabel("Team:"));
    teamDropdown = new QComboBox();
    teamDropdown->setMinimumWidth(250);
    connect(teamDropdown, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TeamsChatWindow::onTeamSelected);
    teamsRow->addWidget(teamDropdown);

    teamsRow->addWidget(new QLabel("Channel:"));
    channelDropdown = new QComboBox();
    channelDropdown->setMinimumWidth(250);
    connect(channelDropdown, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TeamsChatWindow::onChannelSelected);
    teamsRow->addWidget(channelDropdown);
    teamsRow->addStretch();
    layout->addLayout(teamsRow);

    // Direct Chats dropdown with filter controls
    auto *chatRow = new QHBoxLayout();
    chatRow->addWidget(new QLabel("Chat:"));
    chatDropdown = new QComboBox();
    chatDropdown->setMinimumWidth(400);
    // Connect will be dynamic based on mode
    chatRow->addWidget(chatDropdown);

    // Filter by type
    chatFilterType = new QComboBox();
    chatFilterType->addItem("All Types", "all");
    chatFilterType->addItem("1:1 Chats", "oneOnOne");
    chatFilterType->addItem("Group Chats", "group");
    chatFilterType->addItem("Meetings", "meeting");
    chatFilterType->setFixedWidth(110);
    connect(chatFilterType, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TeamsChatWindow::onChatFilterChanged);
    chatRow->addWidget(chatFilterType);

    // Search box
    chatSearchBox = new QLineEdit();
    chatSearchBox->setPlaceholderText("Search chats...");
    chatSearchBox->setFixedWidth(150);
    chatSearchBox->setClearButtonEnabled(true);
    connect(chatSearchBox, &QLineEdit::textChanged, this, &TeamsChatWindow::filterChats);
    chatRow->addWidget(chatSearchBox);

    chatRow->addStretch();
    layout->addLayout(chatRow);

    // Initially show Teams mode, hide Direct Chats
    chatDropdown->setVisible(false);
    chatFilterType->setVisible(false);
    chatSearchBox->setVisible(false);

    htmlViewer = new QWebEngineView();
    htmlViewer->setPage(new ExternalLinkPage(htmlViewer));
    layout->addWidget(htmlViewer, 1);

    // Format bar
    auto *formatBar = new QHBoxLayout();

    fontSelect = new QFontComboBox();
    fontSelect->setFixedWidth(130);
    connect(fontSelect, &QFontComboBox::currentFontChanged, this, &TeamsChatWindow::updateFont);
    formatBar->addWidget(fontSelect);

    fontSizeBox = new QSpinBox();
    fontSizeBox->setRange(8, 72);
    fontSizeBox->setValue(12);
    fontSizeBox->setFixedWidth(60);
    connect(fontSizeBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &TeamsChatWindow::updateFontSize);
    formatBar->addWidget(fontSizeBox);

    formatSelect = new QComboBox();
    formatSelect->addItems({"HTML", "Plain Text"});
    formatSelect->setFixedWidth(100);
    formatBar->addWidget(formatSelect);

    attachBtn = new QPushButton("📎");
    attachBtn->setToolTip("Attach File (requires refresh token)");
    attachBtn->setFixedSize(32, 28);
    connect(attachBtn, &QPushButton::clicked, this, &TeamsChatWindow::sendAttachment);
    formatBar->addWidget(attachBtn);

    mentionBtn = new QPushButton("@");
    mentionBtn->setToolTip("Insert @mention");
    mentionBtn->setFixedSize(32, 28);
    connect(mentionBtn, &QPushButton::clicked, this, &TeamsChatWindow::showMentionPicker);
    formatBar->addWidget(mentionBtn);

    formatBar->addStretch();

    // Extra feature buttons
    presenceBtn = new QPushButton("👤 Presence");
    presenceBtn->setToolTip("View user presence status");
    presenceBtn->setFixedWidth(100);
    connect(presenceBtn, &QPushButton::clicked, this, &TeamsChatWindow::showPresencePanel);
    formatBar->addWidget(presenceBtn);

    meetingBtn = new QPushButton("📅 Meeting");
    meetingBtn->setToolTip("Schedule an online meeting");
    meetingBtn->setFixedWidth(100);
    connect(meetingBtn, &QPushButton::clicked, this, &TeamsChatWindow::showMeetingDialog);
    formatBar->addWidget(meetingBtn);

    exportBtn = new QPushButton("⬇ Export");
    exportBtn->setToolTip("Export chat to CSV/JSON");
    exportBtn->setFixedWidth(90);
    connect(exportBtn, &QPushButton::clicked, this, [this]() {
        QStringList options = {"Export to CSV", "Export to JSON"};
        bool ok;
        QString choice = QInputDialog::getItem(this, "Export Chat", "Select format:", options, 0, false, &ok);
        if (ok) {
            if (choice == "Export to CSV") exportToCSV();
            else exportToJSON();
        }
    });
    formatBar->addWidget(exportBtn);

    cancelBtn = new QPushButton("Cancel");
    StyleManager::applyDangerStyle(cancelBtn);
    cancelBtn->setEnabled(false);
    cancelBtn->setFixedWidth(80);
    connect(cancelBtn, &QPushButton::clicked, this, &TeamsChatWindow::cancelRequests);
    formatBar->addWidget(cancelBtn);

    layout->addLayout(formatBar);

    // Reply indicator
    auto *replyRow = new QHBoxLayout();
    replyLabel = new QLabel("");
    replyLabel->setStyleSheet("color: #bb86fc; font-style: italic; padding: 4px;");
    replyLabel->setVisible(false);
    replyRow->addWidget(replyLabel);
    cancelReplyBtn = new QPushButton("✕");
    cancelReplyBtn->setFixedSize(24, 24);
    cancelReplyBtn->setToolTip("Cancel reply");
    cancelReplyBtn->setVisible(false);
    connect(cancelReplyBtn, &QPushButton::clicked, this, &TeamsChatWindow::cancelReply);
    replyRow->addWidget(cancelReplyBtn);
    replyRow->addStretch();
    layout->addLayout(replyRow);

    msgBox = new QTextEdit();
    msgBox->setPlaceholderText("Write your message...");
    msgBox->setFixedHeight(80);
    layout->addWidget(msgBox);

    infoLabel = new QLabel("No file attached.");
    infoLabel->setStyleSheet("color: #bbbbbb; font-style: italic;");
    layout->addWidget(infoLabel);

    auto *btnRow = new QHBoxLayout();
    btnRow->addStretch();
    sendBtn = new QPushButton("Send");
    sendBtn->setFixedSize(80, 28);
    connect(sendBtn, &QPushButton::clicked, this, &TeamsChatWindow::sendMessage);
    btnRow->addWidget(sendBtn);
    layout->addLayout(btnRow);

    // Mention picker popup (hidden by default)
    mentionList = new QListWidget(this);
    mentionList->setWindowFlags(Qt::Popup);
    mentionList->setFixedSize(300, 200);
    mentionList->setStyleSheet("QListWidget { background: #2a2a2a; color: white; border: 1px solid #555; }");
    connect(mentionList, &QListWidget::itemClicked, this, &TeamsChatWindow::insertMention);

    // Progress bar
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    progressBar->setRange(0, 0);  // Indeterminate mode
    layout->addWidget(progressBar);

    setLayout(layout);

    // Poll timer for auto-refresh
    pollTimer = new QTimer(this);
    connect(pollTimer, &QTimer::timeout, this, [this]() {
        if (currentMode == Mode::TeamsChannels) {
            loadChannelMessages();
        } else if (currentMode == Mode::DirectChatsGraph) {
            loadChatMessagesGraph();
        } else {
            loadChatMessagesSkype();
        }
    });
}

void TeamsChatWindow::setLoading(bool loading) {
    progressBar->setVisible(loading);
    loadBtn->setEnabled(!loading);
    sendBtn->setEnabled(!loading);
    autoFetchBtn->setEnabled(!loading);
    cancelBtn->setEnabled(loading);
    if (!loading) {
        cancelRequested = false;
    }
}

void TeamsChatWindow::clearConversationUI() {
    teamDropdown->clear();
    channelDropdown->clear();
    chatDropdown->clear();
    activeTeamId.clear();
    activeChannelId.clear();
    activeChatId.clear();
    skypeToken.clear();  // Clear Skype token when switching
    pollTimer->stop();

    // Clear reply state
    replyToMessageId.clear();
    replyToSender.clear();
    replyLabel->setVisible(false);
    cancelReplyBtn->setVisible(false);

    // Clear cached data
    cachedMessages = QJsonArray();
    cachedIsSkypeFormat = false;
    cachedChats.clear();
    chatMembers.clear();
    pendingMentions.clear();

    // Reset filters
    if (chatFilterType) chatFilterType->setCurrentIndex(0);
    if (chatSearchBox) chatSearchBox->clear();

    htmlViewer->setHtml("<html><body style='background:#121212;color:#888;padding:20px;'>"
                        "<p>Select a team/channel or chat to view messages.</p></body></html>");
}

void TeamsChatWindow::onModeChanged(int index) {
    // Disconnect old signals
    chatDropdown->disconnect();

    currentMode = static_cast<Mode>(modeSelect->currentData().toInt());
    clearConversationUI();

    bool isTeamsMode = (currentMode == Mode::TeamsChannels);
    bool isDirectMode = (currentMode == Mode::DirectChatsGraph || currentMode == Mode::DirectChatsSkype);

    teamDropdown->setVisible(isTeamsMode);
    channelDropdown->setVisible(isTeamsMode);
    chatDropdown->setVisible(isDirectMode);
    chatFilterType->setVisible(isDirectMode);
    chatSearchBox->setVisible(isDirectMode);

    // Reconnect appropriate signal based on mode
    if (currentMode == Mode::DirectChatsGraph) {
        connect(chatDropdown, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &TeamsChatWindow::onChatSelectedGraph);
    } else if (currentMode == Mode::DirectChatsSkype) {
        connect(chatDropdown, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &TeamsChatWindow::onChatSelectedSkype);
    }
}

// ---------- UI slots ----------
void TeamsChatWindow::updateFont(const QFont &font) {
    msgBox->setCurrentFont(font);
}

void TeamsChatWindow::updateFontSize(int size) {
    QTextCharFormat fmt;
    fmt.setFontPointSize(size);
    QTextCursor cursor = msgBox->textCursor();
    cursor.mergeCharFormat(fmt);
    msgBox->mergeCurrentCharFormat(fmt);
}

// ---------- HTTP helpers ----------
QNetworkRequest TeamsChatWindow::bearerJson(const QString &url, const QString &token) const {
    QNetworkRequest r = NetworkHelper::createBearerRequest(url, token);
    return r;
}

QNetworkRequest TeamsChatWindow::bearerOctet(const QString &url, const QString &token) const {
    QNetworkRequest r{ QUrl(url) };
    r.setRawHeader("Authorization", QString("Bearer %1").arg(token).toUtf8());
    r.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");
    NetworkHelper::setRequestTimeout(r);
    return r;
}

QNetworkRequest TeamsChatWindow::skypeRequest(const QString &url) const {
    QNetworkRequest r{ QUrl(url) };
    r.setRawHeader("Authorization", QString("Bearer %1").arg(accessToken).toUtf8());
    r.setRawHeader("Authentication", QString("skypetoken=%1").arg(skypeToken).toUtf8());
    r.setRawHeader("User-Agent", "Mozilla/5.0");
    r.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    NetworkHelper::setRequestTimeout(r);
    return r;
}

// ---------- Scope warning helper ----------
void TeamsChatWindow::showScopeWarning(const QString &requiredScope, const QString &errorDetails) {
    QMessageBox::warning(this, "Missing Permissions",
        QString("This operation requires the <b>%1</b> scope.\n\n"
                "Your current token does not have this permission.\n\n"
                "Options:\n"
                "• Use a token with %1 scope\n"
                "• Register a custom app with this permission\n"
                "• Request admin consent for this scope\n\n"
                "Error details:\n%2")
            .arg(requiredScope, errorDetails));
}

// ---------- Helper to get chat display name from members ----------
QString TeamsChatWindow::getChatDisplayName(const QJsonObject &chat) const {
    QString topic = chat.value("topic").toString();
    if (!topic.isEmpty()) {
        return topic;
    }

    QJsonArray members = chat.value("members").toArray();
    QStringList names;
    QString currentUserId;

    // Try to get current user ID from the members array to filter it out
    for (const QJsonValue &m : members) {
        QJsonObject member = m.toObject();
        QString userId = member.value("userId").toString();
        QString displayName = member.value("displayName").toString();
        QString email = member.value("email").toString();

        // Check if this is the current user (identified by null/empty displayName in some cases)
        // or by matching roles
        QJsonArray roles = member.value("roles").toArray();
        bool isOwner = false;
        for (const QJsonValue &role : roles) {
            if (role.toString() == "owner") {
                isOwner = true;
                break;
            }
        }

        // Skip if this appears to be the current user
        // The current user often appears with displayName null or with only userId
        if (displayName.isEmpty() && email.isEmpty() && !userId.isEmpty()) {
            currentUserId = userId;
            continue;
        }

        // Build the name from available data
        QString name;
        if (!displayName.isEmpty()) {
            name = displayName;
        } else if (!email.isEmpty()) {
            name = email;
        } else if (!userId.isEmpty()) {
            // Last resort: use part of userId
            name = "User-" + userId.left(8);
        }

        if (!name.isEmpty() && userId != currentUserId) {
            names << name;
        }
    }

    if (names.isEmpty()) {
        QString chatType = chat.value("chatType").toString();
        if (chatType == "oneOnOne") return "1:1 Chat (No name available)";
        if (chatType == "group") return "Group Chat (No members loaded)";
        if (chatType == "meeting") return "Meeting Chat";
        return "Chat-" + chat.value("id").toString().left(20);
    }

    if (names.size() > 3) {
        return names.mid(0, 3).join(", ") + QString(" +%1 more").arg(names.size() - 3);
    }
    return names.join(", ");
}

// ==========================================================================
// SKYPE TOKEN EXCHANGE
// ==========================================================================

void TeamsChatWindow::ensureSkypeToken(std::function<void(bool)> done) {
    if (!skypeToken.isEmpty()) {
        done(true);
        return;
    }

    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Token Missing", "Enter a valid Graph API Access Token first.");
        done(false);
        return;
    }

    setLoading(true);

    // Exchange Graph token for SkypeToken via Teams authz endpoint
    QNetworkRequest req{ QUrl(TEAMS_AUTHZ_URL) };
    req.setRawHeader("Authorization", QString("Bearer %1").arg(accessToken).toUtf8());
    req.setRawHeader("User-Agent", "Mozilla/5.0");
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    NetworkHelper::setRequestTimeout(req);

    QNetworkReply *reply = net->post(req, QByteArray());
    if (!reply) {
        setLoading(false);
        QMessageBox::critical(this, "Network Error", "Failed to create Skype token request");
        done(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply, done]() {
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString errorMsg = reply->errorString();
            QByteArray body = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(body);
            if (doc.isObject()) {
                QString message = doc.object().value("message").toString();
                if (!message.isEmpty()) {
                    errorMsg = message;
                }
            }
            QMessageBox::critical(this, "SkypeToken Error",
                QString("Failed to obtain SkypeToken:\n\n%1\n\n"
                        "Make sure your Graph token is valid and has the appropriate audience.")
                    .arg(errorMsg));
            reply->deleteLater();
            done(false);
            return;
        }

        QByteArray body = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(body);
        QJsonObject tokens = doc.object().value("tokens").toObject();

        skypeToken = tokens.value("skypeToken").toString();
        if (skypeToken.isEmpty()) {
            skypeToken = tokens.value("SkypeToken").toString();
        }

        reply->deleteLater();

        if (skypeToken.isEmpty()) {
            QMessageBox::critical(this, "SkypeToken Error",
                "SkypeToken not found in response.\n\n"
                "The Teams authz endpoint did not return a valid SkypeToken.");
            done(false);
            return;
        }

        // SkypeToken obtained (debug removed for cleaner logs)
        done(true);
    });
}

// ==========================================================================
// TEAMS & CHANNELS MODE (Graph API)
// ==========================================================================

void TeamsChatWindow::loadTeams() {
    accessToken = tokenInput->toPlainText().trimmed();
    refreshToken = refreshInput->toPlainText().trimmed();

    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Token Missing", "Enter a valid Graph API Access Token.");
        return;
    }

    setLoading(true);
    teamDropdown->clear();
    channelDropdown->clear();

    const QString url = GRAPH_BASE + "/me/joinedTeams";

    QNetworkRequest req = bearerJson(url, accessToken);
    QNetworkReply *reply = net->get(req);
    if (!reply) {
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString errorMsg = reply->errorString();
            QByteArray body = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(body);
            if (doc.isObject()) {
                QJsonObject error = doc.object().value("error").toObject();
                QString code = error.value("code").toString();
                QString message = error.value("message").toString();
                if (!message.isEmpty()) {
                    errorMsg = QString("%1: %2").arg(code, message);
                }
            }

            showScopeWarning("Group.Read.All or Team.ReadBasic.All", errorMsg);
            reply->deleteLater();
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonArray teams = doc.object().value("value").toArray();

        if (teams.isEmpty()) {
            QMessageBox::information(this, "No Teams", "No Teams found for this user.");
            reply->deleteLater();
            return;
        }

        for (const QJsonValue &v : teams) {
            QJsonObject team = v.toObject();
            QString teamId = team.value("id").toString();
            QString displayName = team.value("displayName").toString();
            QString description = team.value("description").toString();

            QString label = displayName;
            if (!description.isEmpty() && description.length() < 50) {
                label += QString(" - %1").arg(description);
            }

            teamDropdown->addItem(label, teamId);
        }

        reply->deleteLater();
        QMessageBox::information(this, "Teams Loaded",
            QString("Found %1 team(s). Select one to view channels.").arg(teams.size()));
    });
}

void TeamsChatWindow::onTeamSelected(int idx) {
    if (idx < 0) {
        channelDropdown->clear();
        activeTeamId.clear();
        pollTimer->stop();
        return;
    }

    activeTeamId = teamDropdown->currentData().toString();
    channelDropdown->clear();
    activeChannelId.clear();

    if (activeTeamId.isEmpty()) return;

    setLoading(true);

    const QString url = QString("%1/teams/%2/channels").arg(GRAPH_BASE, activeTeamId);

    QNetworkRequest req = bearerJson(url, accessToken);
    QNetworkReply *reply = net->get(req);
    if (!reply) {
        setLoading(false);
        return;
    }
    activeReplies.append(reply);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        activeReplies.removeAll(reply);
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            qDebug() << "[Teams] Failed to load channels:" << reply->errorString();
            reply->deleteLater();
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonArray channels = doc.object().value("value").toArray();

        for (const QJsonValue &v : channels) {
            QJsonObject channel = v.toObject();
            QString channelId = channel.value("id").toString();
            QString displayName = channel.value("displayName").toString();
            QString membershipType = channel.value("membershipType").toString();

            QString label = displayName;
            if (membershipType == "private") {
                label = "🔒 " + label;
            } else if (membershipType == "shared") {
                label = "🔗 " + label;
            }

            channelDropdown->addItem(label, channelId);
        }

        reply->deleteLater();
    });
}

void TeamsChatWindow::onChannelSelected(int idx) {
    if (idx < 0 || activeTeamId.isEmpty()) {
        pollTimer->stop();
        activeChannelId.clear();
        return;
    }

    activeChannelId = channelDropdown->currentData().toString();
    if (activeChannelId.isEmpty()) {
        pollTimer->stop();
        return;
    }

    loadChannelMessages();
    pollTimer->start(15000);
}

void TeamsChatWindow::loadChannelMessages() {
    if (activeTeamId.isEmpty() || activeChannelId.isEmpty() || accessToken.isEmpty()) return;

    const QString url = QString("%1/teams/%2/channels/%3/messages?$top=50")
                            .arg(GRAPH_BETA, activeTeamId, activeChannelId);

    QNetworkRequest req = bearerJson(url, accessToken);
    QNetworkReply *reply = net->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            QString errorMsg = reply->errorString();
            QByteArray body = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(body);
            if (doc.isObject()) {
                QJsonObject error = doc.object().value("error").toObject();
                QString code = error.value("code").toString();
                QString message = error.value("message").toString();
                if (!message.isEmpty()) {
                    errorMsg = QString("%1: %2").arg(code, message);
                }
            }

            pollTimer->stop();
            showScopeWarning("ChannelMessage.Read.All", errorMsg);
            reply->deleteLater();
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonArray messages = doc.object().value("value").toArray();
        renderMessagesHtml(messages, true, false);
        reply->deleteLater();
    });
}

// ==========================================================================
// DIRECT CHATS MODE (Graph API)
// ==========================================================================

void TeamsChatWindow::loadDirectChatsGraph() {
    accessToken = tokenInput->toPlainText().trimmed();
    refreshToken = refreshInput->toPlainText().trimmed();

    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Token Missing", "Enter a valid Graph API Access Token.");
        return;
    }

    setLoading(true);
    chatDropdown->clear();

    const QString url = GRAPH_BASE + "/me/chats?$expand=members($select=id,displayName,userId,email)&$select=id,topic,chatType,members,lastMessagePreview&$top=50&$orderby=lastMessagePreview/createdDateTime%20desc";

    QNetworkRequest req = bearerJson(url, accessToken);
    QNetworkReply *reply = net->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        setLoading(false);

        if (reply->error() != QNetworkReply::NoError) {
            QString errorMsg = reply->errorString();
            QByteArray body = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(body);
            if (doc.isObject()) {
                QJsonObject error = doc.object().value("error").toObject();
                QString code = error.value("code").toString();
                QString message = error.value("message").toString();
                if (!message.isEmpty()) {
                    errorMsg = QString("%1: %2").arg(code, message);
                }
            }

            showScopeWarning("Chat.Read or Chat.ReadBasic", errorMsg);
            reply->deleteLater();
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonArray chats = doc.object().value("value").toArray();

        if (chats.isEmpty()) {
            QMessageBox::information(this, "No Chats", "No direct chats found for this user.");
            reply->deleteLater();
            return;
        }

        // Clear cached chats
        cachedChats.clear();

        for (const QJsonValue &v : chats) {
            QJsonObject chat = v.toObject();
            QString chatId = chat.value("id").toString();
            QString chatType = chat.value("chatType").toString();
            QString topic = getChatDisplayName(chat);

            // Get last message timestamp for sorting
            qint64 lastActivity = 0;
            QJsonObject lastMsg = chat.value("lastMessagePreview").toObject();
            QString lastMsgTime = lastMsg.value("createdDateTime").toString();
            if (!lastMsgTime.isEmpty()) {
                QDateTime dt = QDateTime::fromString(lastMsgTime, Qt::ISODate);
                if (dt.isValid()) lastActivity = dt.toMSecsSinceEpoch();
            }

            // For meetings, add date to distinguish recurring instances
            QString displayTopic = topic;
            bool isMeeting = (chatType == "meeting");
            if (isMeeting && lastActivity > 0) {
                QDateTime activityTime = QDateTime::fromMSecsSinceEpoch(lastActivity);
                QString dateStr = activityTime.toString("MMM d");
                displayTopic = QString("%1 (%2)").arg(topic, dateStr);
            }

            QString typeIcon;
            if (chatType == "oneOnOne") typeIcon = "[1:1] ";
            else if (chatType == "group") typeIcon = "[Group] ";
            else if (chatType == "meeting") typeIcon = "[Meeting] ";

            // Cache the chat info
            ChatInfo info;
            info.id = chatId;
            info.topic = topic;
            info.displayText = typeIcon + displayTopic;
            info.type = chatType;
            info.lastActivity = lastActivity;
            cachedChats.append(info);
        }

        // Sort by last activity (most recent first)
        std::sort(cachedChats.begin(), cachedChats.end(),
            [](const ChatInfo &a, const ChatInfo &b) {
                return a.lastActivity > b.lastActivity;
            });

        // Populate dropdown using filter
        filterChats();

        reply->deleteLater();
        QMessageBox::information(this, "Chats Loaded",
            QString("Found %1 chat(s). Select one to view messages.\n\n"
                    "Use the filter dropdown and search box to narrow results.")
                .arg(cachedChats.size()));
    });
}

void TeamsChatWindow::onChatSelectedGraph(int idx) {
    if (idx < 0) {
        pollTimer->stop();
        activeChatId.clear();
        return;
    }

    activeChatId = chatDropdown->currentData().toString();

    // Find the chat type from cached data
    activeChatType.clear();
    for (const ChatInfo &info : cachedChats) {
        if (info.id == activeChatId) {
            activeChatType = info.type;
            break;
        }
    }

    if (activeChatId.isEmpty()) {
        pollTimer->stop();
        return;
    }

    loadChatMessagesGraph();
    pollTimer->start(15000);
}

void TeamsChatWindow::loadChatMessagesGraph() {
    if (activeChatId.isEmpty() || accessToken.isEmpty()) return;

    const QString url = QString("%1/chats/%2/messages?$top=50&$orderby=createdDateTime%20desc")
                            .arg(GRAPH_BASE, activeChatId);

    QNetworkRequest req = bearerJson(url, accessToken);
    QNetworkReply *reply = net->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            QString errorMsg = reply->errorString();
            QByteArray body = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(body);
            if (doc.isObject()) {
                QJsonObject error = doc.object().value("error").toObject();
                QString code = error.value("code").toString();
                QString message = error.value("message").toString();
                if (!message.isEmpty()) {
                    errorMsg = QString("%1: %2").arg(code, message);
                }
            }

            pollTimer->stop();
            showScopeWarning("Chat.Read", errorMsg);
            reply->deleteLater();
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonArray messages = doc.object().value("value").toArray();
        renderMessagesHtml(messages, false, false);
        reply->deleteLater();
    });
}

// ==========================================================================
// DIRECT CHATS MODE (Skype/Undocumented API)
// ==========================================================================

void TeamsChatWindow::loadDirectChatsSkype() {
    accessToken = tokenInput->toPlainText().trimmed();
    refreshToken = refreshInput->toPlainText().trimmed();

    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Token Missing", "Enter a valid Graph API Access Token.");
        return;
    }

    // First ensure we have a SkypeToken
    ensureSkypeToken([this](bool ok) {
        if (!ok) return;

        setLoading(true);
        chatDropdown->clear();

        const QString url = SKYPE_MSG_BASE + "/conversations";

        QNetworkRequest req = skypeRequest(url);
        QNetworkReply *reply = net->get(req);

        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            setLoading(false);

            if (reply->error() != QNetworkReply::NoError) {
                QString errorMsg = reply->errorString();
                QByteArray body = reply->readAll();
                qDebug() << "[Skype] Error response:" << body;

                QMessageBox::critical(this, "Skype API Error",
                    QString("Failed to load conversations:\n\n%1\n\n"
                            "The Skype API may be unavailable or the token may have expired.")
                        .arg(errorMsg));
                reply->deleteLater();
                return;
            }

            QByteArray body = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(body);
            QJsonArray conversations = doc.object().value("conversations").toArray();

            if (conversations.isEmpty()) {
                QMessageBox::information(this, "No Chats", "No conversations found.");
                reply->deleteLater();
                return;
            }

            // Clear cached chats
            cachedChats.clear();

            for (const QJsonValue &v : conversations) {
                QJsonObject convo = v.toObject();
                QString convoId = convo.value("id").toString();
                if (convoId.isEmpty()) continue;

                QJsonObject props = convo.value("properties").toObject();
                QJsonObject threadProps = convo.value("threadProperties").toObject();

                // Get last activity timestamp for sorting
                qint64 lastActivity = 0;
                QString lastUpdated = props.value("lastUpdatedTime").toString();
                if (lastUpdated.isEmpty()) {
                    lastUpdated = convo.value("version").toString();
                }
                if (!lastUpdated.isEmpty()) {
                    // Parse ISO timestamp or numeric version
                    if (lastUpdated.contains("T")) {
                        QDateTime dt = QDateTime::fromString(lastUpdated.left(19), "yyyy-MM-ddTHH:mm:ss");
                        if (dt.isValid()) lastActivity = dt.toMSecsSinceEpoch();
                    } else {
                        lastActivity = lastUpdated.toLongLong();
                    }
                }

                // Get topic from multiple possible locations
                QString topic = props.value("topic").toString();
                if (topic.isEmpty()) {
                    topic = threadProps.value("topic").toString();
                }

                // Determine type from ID format
                bool isMeeting = convoId.contains(":meeting_");
                bool isGroup = convoId.contains(":19:");

                // For meetings, try to get the meeting subject from threadProperties
                if (topic.isEmpty() && isMeeting) {
                    topic = threadProps.value("meetingTitle").toString();
                    if (topic.isEmpty()) {
                        topic = threadProps.value("subject").toString();
                    }
                }

                // Try to build a name from members
                if (topic.isEmpty()) {
                    QJsonArray members = convo.value("members").toArray();
                    QStringList memberNames;

                    for (const QJsonValue &m : members) {
                        QJsonObject member = m.toObject();
                        QString role = member.value("role").toString();

                        // Skip the current user (usually has "User" role)
                        if (role == "User") continue;

                        // Try multiple fields for display name
                        QString displayName = member.value("friendlyName").toString();
                        if (displayName.isEmpty()) {
                            displayName = member.value("displayName").toString();
                        }
                        if (displayName.isEmpty()) {
                            displayName = member.value("userPrincipalName").toString();
                        }

                        // Also try parsing the member ID for display name
                        if (displayName.isEmpty()) {
                            QString memberId = member.value("id").toString();
                            if (memberId.contains("@")) {
                                displayName = memberId.section('@', 0, 0);
                            }
                        }

                        if (!displayName.isEmpty()) {
                            // Skip raw org IDs
                            if (displayName.startsWith("8:orgid:")) continue;
                            if (displayName.startsWith("28:")) continue;

                            // Clean up the display name
                            if (displayName.contains('@')) {
                                displayName = displayName.section('@', 0, 0);
                            }
                            memberNames << displayName;
                        }
                    }

                    // Build topic from member names
                    if (!memberNames.isEmpty()) {
                        if (memberNames.size() > 3) {
                            topic = memberNames.mid(0, 3).join(", ") + QString(" +%1 more").arg(memberNames.size() - 3);
                        } else {
                            topic = memberNames.join(", ");
                        }
                    }
                }

                // Try last message preview for context
                if (topic.isEmpty()) {
                    QJsonObject lastMsg = convo.value("lastMessage").toObject();
                    QString preview = lastMsg.value("content").toString();
                    QString senderName = lastMsg.value("imdisplayname").toString();
                    if (!preview.isEmpty()) {
                        preview.remove(QRegularExpression("<[^>]*>"));
                        if (preview.length() > 30) {
                            preview = preview.left(30) + "...";
                        }
                        if (!senderName.isEmpty()) {
                            topic = QString("%1: %2").arg(senderName, preview);
                        } else {
                            topic = preview;
                        }
                    }
                }

                // Last resort fallback with ID hint
                if (topic.isEmpty()) {
                    if (isMeeting) {
                        topic = "Meeting Chat";
                    } else if (isGroup) {
                        topic = "Group Chat";
                    } else {
                        QString shortId = convoId.mid(convoId.lastIndexOf(':') + 1).left(8);
                        topic = QString("Chat (%1)").arg(shortId);
                    }
                }

                // For meetings, add date to distinguish recurring instances
                QString displayTopic = topic;
                if (isMeeting && lastActivity > 0) {
                    QDateTime activityTime = QDateTime::fromMSecsSinceEpoch(lastActivity);
                    QString dateStr = activityTime.toString("MMM d");
                    displayTopic = QString("%1 (%2)").arg(topic, dateStr);
                }

                QString typeStr = isMeeting ? "meeting" : (isGroup ? "group" : "oneOnOne");
                QString typeIcon = isMeeting ? "[Meeting] " : (isGroup ? "[Group] " : "[1:1] ");

                // Cache the chat info
                ChatInfo info;
                info.id = convoId;
                info.topic = topic;
                info.displayText = typeIcon + displayTopic;
                info.type = typeStr;
                info.lastActivity = lastActivity;
                cachedChats.append(info);
            }

            // Sort by last activity (most recent first)
            std::sort(cachedChats.begin(), cachedChats.end(),
                [](const ChatInfo &a, const ChatInfo &b) {
                    return a.lastActivity > b.lastActivity;
                });

            // Populate dropdown
            filterChats();

            reply->deleteLater();

            if (!cachedChats.isEmpty()) {
                QMessageBox::information(this, "Chats Loaded (Skype API)",
                    QString("Found %1 conversation(s). Select one to view messages.\n\n"
                            "Use the filter dropdown and search box to narrow results.")
                        .arg(cachedChats.size()));
            } else {
                QMessageBox::information(this, "No Chats", "No valid conversations found.");
            }
        });
    });
}

void TeamsChatWindow::filterChats() {
    if (cachedChats.isEmpty()) return;

    QString filterType = chatFilterType->currentData().toString();
    QString searchText = chatSearchBox->text().toLower().trimmed();

    // Temporarily block signals to avoid triggering selection
    chatDropdown->blockSignals(true);
    chatDropdown->clear();

    int matchCount = 0;
    for (const ChatInfo &chat : cachedChats) {
        // Apply type filter
        if (filterType != "all" && chat.type != filterType) {
            continue;
        }

        // Apply search filter
        if (!searchText.isEmpty() && !chat.topic.toLower().contains(searchText)) {
            continue;
        }

        chatDropdown->addItem(chat.displayText, chat.id);
        matchCount++;
    }

    chatDropdown->blockSignals(false);

    // Update UI hint if filtered
    if (matchCount < cachedChats.size()) {
        chatDropdown->setToolTip(QString("Showing %1 of %2 chats").arg(matchCount).arg(cachedChats.size()));
    } else {
        chatDropdown->setToolTip("");
    }
}

void TeamsChatWindow::onChatFilterChanged() {
    filterChats();
}

void TeamsChatWindow::onChatSelectedSkype(int idx) {
    if (idx < 0) {
        pollTimer->stop();
        activeChatId.clear();
        return;
    }

    activeChatId = chatDropdown->currentData().toString();

    if (activeChatId.isEmpty()) {
        pollTimer->stop();
        return;
    }

    loadChatMessagesSkype();
    pollTimer->start(10000);  // Poll every 10 seconds for Skype API
}

void TeamsChatWindow::loadChatMessagesSkype() {
    if (activeChatId.isEmpty() || skypeToken.isEmpty()) return;

    const QString url = QString("%1/conversations/%2/messages?startTime=0&view=msnp24Equivalent")
                            .arg(SKYPE_MSG_BASE, activeChatId);

    QNetworkRequest req = skypeRequest(url);
    QNetworkReply *reply = net->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            qDebug() << "[Skype] Failed to load messages:" << reply->errorString();
            reply->deleteLater();
            return;
        }

        QByteArray body = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(body);
        QJsonArray messages = doc.object().value("messages").toArray();

        renderMessagesHtml(messages, false, true);  // isSkypeFormat = true
        reply->deleteLater();
    });
}

// ==========================================================================
// MESSAGE RENDERING
// ==========================================================================

void TeamsChatWindow::renderMessagesHtml(const QJsonArray &messages, bool isChannel, bool isSkypeFormat) {
    // Cache messages for export
    cachedMessages = messages;
    cachedIsSkypeFormat = isSkypeFormat;

    QString html = R"(
    <html><head>
    <meta charset='utf-8'/>
    <style>
    body { font-family: sans-serif; background:#121212; color:#fff; padding:10px; }
    .msg { background:#1e1e1e; padding:10px; border-radius:6px; margin-bottom:10px; box-shadow:0 1px 2px rgba(0,0,0,.3); position: relative; }
    .sender { font-weight:bold; color:#bb86fc; }
    .time { font-size:.8em; color:#aaa; float:right; }
    .content { margin-top:8px; color:#e0e0e0; }
    .system { background:#2a2a2a; font-style:italic; color:#888; }
    a { color:#62b0ff; }
    .reply-quote { border-left: 3px solid #555; padding-left: 10px; margin: 5px 0 8px 10px; color: #aaa; font-size: 0.9em; }
    .reply-btn { position: absolute; top: 8px; right: 8px; background: #333; color: #888; border: none; padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 0.8em; }
    .reply-btn:hover { background: #555; color: #fff; }
    .mention { background: #3d2c5e; padding: 2px 4px; border-radius: 3px; color: #bb86fc; }
    .reactions { margin-top: 6px; font-size: 0.85em; }
    .reaction { background: #333; padding: 2px 6px; border-radius: 10px; margin-right: 4px; }
    </style>
    </head><body>
    )";

    if (messages.isEmpty()) {
        html += "<p style='color:#888;'>No messages found.</p>";
    }

    // Messages come in reverse chronological order, reverse for display
    for (int i = messages.size() - 1; i >= 0; --i) {
        const QJsonObject msg = messages.at(i).toObject();

        QString sender;
        QString content;
        QString timeStr = "N/A";
        QString messageId;
        bool isSystem = false;
        QString replyToContent;

        if (isSkypeFormat) {
            // Skype API format
            sender = msg.value("imdisplayname").toString();
            if (sender.isEmpty()) {
                // Try alternate fields
                sender = msg.value("displayName").toString();
            }
            content = msg.value("content").toString();
            messageId = msg.value("id").toString();

            QString timeRaw = msg.value("composetime").toString();
            if (timeRaw.isEmpty()) {
                timeRaw = msg.value("originalarrivaltime").toString();
            }

            if (!timeRaw.isEmpty()) {
                // Parse ISO format
                if (timeRaw.contains("T")) {
                    QString cleanTime = timeRaw;
                    cleanTime.remove("Z");
                    if (cleanTime.contains(".")) {
                        cleanTime = cleanTime.left(cleanTime.indexOf("."));
                    }
                    QDateTime dt = QDateTime::fromString(cleanTime, "yyyy-MM-ddTHH:mm:ss");
                    dt.setTimeZone(QTimeZone::utc());
                    if (dt.isValid()) {
                        timeStr = dt.toLocalTime().toString("yyyy-MM-dd HH:mm:ss");
                    }
                }
            }

            // Check message type for system events
            QString msgType = msg.value("messagetype").toString();
            isSystem = msgType.contains("Event") || msgType.contains("ThreadActivity") ||
                       msgType.contains("RichText/Media_CallRecording") ||
                       msgType == "ControlClear" || sender.isEmpty();

            // Handle different system message types
            if (isSystem) {
                // Call events - parse and format nicely
                if (msgType.contains("Event/Call") || msgType == "Event/Call" ||
                    content.contains("callEnded") || content.contains("callLog")) {
                    // Extract meeting title if present
                    QRegularExpression meetingRx("([A-Za-z0-9 ]+(?:Huddle|Meeting|Standup|Sync|Call)[^0-9]*)");
                    QRegularExpressionMatch match = meetingRx.match(content);
                    if (match.hasMatch()) {
                        QString meetingName = match.captured(1).trimmed();
                        content = QString("Call ended: %1").arg(meetingName);
                    } else {
                        content = "Call ended";
                    }
                    sender = "System";
                }
                // Thread roster changes
                else if (msgType.contains("ThreadActivity/AddMember")) {
                    content = "A member was added to the conversation";
                    sender = "System";
                }
                else if (msgType.contains("ThreadActivity/DeleteMember")) {
                    content = "A member left the conversation";
                    sender = "System";
                }
                else if (msgType.contains("ThreadActivity/TopicUpdate")) {
                    content = "Conversation topic was updated";
                    sender = "System";
                }
                // Skip raw metadata dumps (long strings with IDs and timestamps concatenated)
                else if (content.length() > 200 && content.contains("orgid:") &&
                         content.count(':') > 10) {
                    continue; // Skip this message entirely
                }
                // Other system messages - show a cleaner version
                else if (sender.isEmpty()) {
                    sender = "System";
                    // Clean up content if it looks like raw data
                    if (content.contains("8:orgid:") || content.contains("28:")) {
                        content = "[System event]";
                    }
                }
            }

        } else {
            // Graph API format
            sender = "Unknown";
            messageId = msg.value("id").toString();
            QJsonObject from = msg.value("from").toObject();
            if (from.contains("user")) {
                sender = from.value("user").toObject().value("displayName").toString("Unknown User");
            } else if (from.contains("application")) {
                sender = from.value("application").toObject().value("displayName").toString("Bot");
            }

            QJsonObject body = msg.value("body").toObject();
            content = body.value("content").toString();
            QString contentType = body.value("contentType").toString();

            // Escape if plain text
            if (contentType == "text") {
                content = content.toHtmlEscaped().replace("\n", "<br>");
            }

            QString createdDateTime = msg.value("createdDateTime").toString();
            if (!createdDateTime.isEmpty()) {
                QDateTime dt = QDateTime::fromString(createdDateTime, Qt::ISODate);
                if (dt.isValid()) {
                    timeStr = dt.toLocalTime().toString("yyyy-MM-dd HH:mm:ss");
                }
            }

            QString messageType = msg.value("messageType").toString();
            isSystem = (messageType == "systemEventMessage" || sender == "Unknown");

            // Check for replies (Graph API has replyToId)
            QString replyToId = msg.value("replyToId").toString();
            if (!replyToId.isEmpty()) {
                // Find the original message
                for (int j = 0; j < messages.size(); ++j) {
                    QJsonObject origMsg = messages.at(j).toObject();
                    if (origMsg.value("id").toString() == replyToId) {
                        QString origSender = "Someone";
                        QJsonObject origFrom = origMsg.value("from").toObject();
                        if (origFrom.contains("user")) {
                            origSender = origFrom.value("user").toObject().value("displayName").toString("Someone");
                        }
                        QString origContent = origMsg.value("body").toObject().value("content").toString();
                        origContent.remove(QRegularExpression("<[^>]*>"));
                        if (origContent.length() > 60) {
                            origContent = origContent.left(60) + "...";
                        }
                        replyToContent = QString("<b>%1:</b> %2").arg(origSender.toHtmlEscaped(), origContent.toHtmlEscaped());
                        break;
                    }
                }
            }

            // Handle reactions (Graph API)
            QJsonArray reactions = msg.value("reactions").toArray();
            if (!reactions.isEmpty()) {
                QString reactionsHtml = "<div class='reactions'>";
                QMap<QString, int> reactionCounts;
                for (const QJsonValue &r : reactions) {
                    QString type = r.toObject().value("reactionType").toString();
                    reactionCounts[type]++;
                }
                for (auto it = reactionCounts.begin(); it != reactionCounts.end(); ++it) {
                    QString emoji;
                    if (it.key() == "like") emoji = "👍";
                    else if (it.key() == "heart") emoji = "❤️";
                    else if (it.key() == "laugh") emoji = "😂";
                    else if (it.key() == "surprised") emoji = "😮";
                    else if (it.key() == "sad") emoji = "😢";
                    else if (it.key() == "angry") emoji = "😠";
                    else emoji = it.key();
                    reactionsHtml += QString("<span class='reaction'>%1 %2</span>").arg(emoji).arg(it.value());
                }
                reactionsHtml += "</div>";
                content += reactionsHtml;
            }
        }

        // Skip empty messages
        if (content.trimmed().isEmpty()) continue;

        // Ensure sender is never empty
        if (sender.isEmpty()) {
            sender = "Unknown";
        }

        QString msgClass = isSystem ? "msg system" : "msg";

        // Build reply quote if present
        QString replyQuoteHtml;
        if (!replyToContent.isEmpty()) {
            replyQuoteHtml = QString("<div class='reply-quote'>%1</div>").arg(replyToContent);
        }

        // Only add reply button for non-system messages
        QString replyBtnHtml;
        if (!isSystem && !messageId.isEmpty()) {
            // Store data-msgid and data-sender for JavaScript handling
            replyBtnHtml = QString("<button class='reply-btn' onclick=\"window.location='reply://%1/%2'\">↩ Reply</button>")
                               .arg(messageId, QUrl::toPercentEncoding(sender));
        }

        html += QString(R"(
        <div class='%5'>
          %6
          <div><span class='sender'>%1</span><span class='time'>%2</span></div>
          %7
          <div class='content'>%3</div>
        </div>)").arg(sender.toHtmlEscaped(),
                      timeStr.toHtmlEscaped(),
                      content,
                      messageId,
                      msgClass,
                      replyBtnHtml,
                      replyQuoteHtml);
    }

    html += "</body></html>";
    htmlViewer->setHtml(html, QUrl("about:blank"));

    // Load chat members for mentions (if not already loaded)
    if (chatMembers.isEmpty() && !activeChatId.isEmpty()) {
        loadChatMembers();
    }
}

// ==========================================================================
// SEND MESSAGE
// ==========================================================================

void TeamsChatWindow::sendMessage() {
    const bool isHtml = (formatSelect->currentText() == "HTML");
    QString msg = msgBox->toPlainText().trimmed();

    if (msg.isEmpty()) {
        QMessageBox::warning(this, "Missing", "Enter a message to send.");
        return;
    }

    // Process @mentions - convert @Name to proper mention HTML for Graph API
    QString processedMsg = msg;
    if (!pendingMentions.isEmpty() && (currentMode == Mode::DirectChatsGraph || currentMode == Mode::TeamsChannels)) {
        // Replace @Name with proper mention tags
        for (const MentionInfo &mi : pendingMentions) {
            QString mentionText = QString("@%1").arg(mi.displayName);
            QString mentionHtml = QString("<at id=\"%1\">%2</at>").arg(mi.id).arg(mi.displayName);
            processedMsg.replace(mentionText, mentionHtml);
        }
    }

    // Append attachment link if present
    if (pendingAttachment.isValid()) {
        if (isHtml)
            processedMsg += QString("<br><a href=\"%1\">%2</a>").arg(pendingAttachment.url, pendingAttachment.filename);
        else
            processedMsg += QString("\n%1").arg(pendingAttachment.url);
        pendingAttachment.clear();
        infoLabel->setText("No file attached.");
    }

    if (isHtml) processedMsg.replace('\n', "<br>");

    // Build mentions array for Graph API
    QJsonArray mentionsArray;
    for (const MentionInfo &mi : pendingMentions) {
        QJsonObject mention;
        mention["id"] = mi.id;
        QJsonObject mentioned;
        QJsonObject user;
        user["id"] = mi.userId;
        user["displayName"] = mi.displayName;
        mentioned["user"] = user;
        mention["mentioned"] = mentioned;
        mention["mentionText"] = mi.displayName;
        mentionsArray.append(mention);
    }

    if (currentMode == Mode::TeamsChannels) {
        // Graph API - Channel message
        if (activeTeamId.isEmpty() || activeChannelId.isEmpty()) {
            QMessageBox::warning(this, "Missing", "Select a team and channel first.");
            return;
        }

        const QString url = QString("%1/teams/%2/channels/%3/messages")
                                .arg(GRAPH_BETA, activeTeamId, activeChannelId);

        setLoading(true);
        QNetworkRequest req = bearerJson(url, accessToken);

        QJsonObject body;
        QJsonObject bodyContent;
        bodyContent["contentType"] = pendingMentions.isEmpty() ? (isHtml ? "html" : "text") : "html";
        bodyContent["content"] = processedMsg;
        body["body"] = bodyContent;

        // Add mentions if present
        if (!mentionsArray.isEmpty()) {
            body["mentions"] = mentionsArray;
        }

        QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());

        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            setLoading(false);
            if (reply->error() != QNetworkReply::NoError) {
                showScopeWarning("ChannelMessage.Send", reply->errorString());
            } else {
                msgBox->clear();
                pendingMentions.clear();
                cancelReply();
                loadChannelMessages();
            }
            reply->deleteLater();
        });

    } else if (currentMode == Mode::DirectChatsGraph) {
        // Graph API - Chat message
        if (activeChatId.isEmpty()) {
            QMessageBox::warning(this, "Missing", "Select a chat first.");
            return;
        }

        const QString url = QString("%1/chats/%2/messages").arg(GRAPH_BASE, activeChatId);

        setLoading(true);
        QNetworkRequest req = bearerJson(url, accessToken);

        QJsonObject body;
        QJsonObject bodyContent;
        bodyContent["contentType"] = pendingMentions.isEmpty() ? (isHtml ? "html" : "text") : "html";
        bodyContent["content"] = processedMsg;
        body["body"] = bodyContent;

        // Add mentions if present
        if (!mentionsArray.isEmpty()) {
            body["mentions"] = mentionsArray;
        }

        QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());

        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            setLoading(false);
            if (reply->error() != QNetworkReply::NoError) {
                showScopeWarning("Chat.ReadWrite", reply->errorString());
            } else {
                msgBox->clear();
                pendingMentions.clear();
                cancelReply();
                loadChatMessagesGraph();
            }
            reply->deleteLater();
        });

    } else {
        // Skype API - Chat message
        if (activeChatId.isEmpty() || skypeToken.isEmpty()) {
            QMessageBox::warning(this, "Missing", "Select a chat first.");
            return;
        }

        const QString url = QString("%1/conversations/%2/messages").arg(SKYPE_MSG_BASE, activeChatId);

        setLoading(true);
        QNetworkRequest req = skypeRequest(url);

        QJsonObject body;
        body["content"] = processedMsg;
        body["messagetype"] = isHtml ? "RichText/Html" : "RichText";
        body["contenttype"] = "text";

        QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());

        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            setLoading(false);
            if (reply->error() != QNetworkReply::NoError) {
                QMessageBox::warning(this, "Send Failed",
                    QString("Failed to send message via Skype API:\n\n%1")
                        .arg(reply->errorString()));
            } else {
                msgBox->clear();
                pendingMentions.clear();
                cancelReply();
                loadChatMessagesSkype();
            }
            reply->deleteLater();
        });
    }
}

// ==========================================================================
// ATTACHMENTS (SharePoint upload)
// ==========================================================================

void TeamsChatWindow::sendAttachment() {
    if (currentMode == Mode::TeamsChannels) {
        if (activeTeamId.isEmpty() || activeChannelId.isEmpty()) {
            QMessageBox::warning(this, "Missing", "Select a team and channel first.");
            return;
        }
    } else {
        if (activeChatId.isEmpty()) {
            QMessageBox::warning(this, "Missing", "Select a chat first.");
            return;
        }
    }

    if (refreshToken.isEmpty()) {
        QMessageBox::warning(this, "Refresh Token Required",
            "File attachments require a refresh token to obtain SharePoint access.\n"
            "Please provide a refresh token.");
        return;
    }

    const QString path = QFileDialog::getOpenFileName(this, "Select Attachment");
    if (path.isEmpty()) return;

    setLoading(true);

    ensureSharepointToken([this, path](bool ok) {
        if (!ok) {
            setLoading(false);
            return;
        }

        uploadToChatFiles(path, [this](bool ok, QString sharedUrl, QString fileName) {
            setLoading(false);
            if (!ok) return;
            pendingAttachment.url = sharedUrl;
            pendingAttachment.filename = fileName;
            infoLabel->setText("Attached: " + fileName);
        });
    });
}

// Helper: Decode JWT and return claims JSON
static QJsonObject decodeJwt(const QString &jwt) {
    QStringList parts = jwt.split(".");
    if (parts.size() < 2) return {};

    QByteArray payload = QByteArray::fromBase64(parts[1].toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    QJsonDocument doc = QJsonDocument::fromJson(payload);
    return doc.object();
}

void TeamsChatWindow::ensureSharepointToken(std::function<void(bool)> done) {
    if (!sharepointToken.isEmpty() && !sharepointUrl.isEmpty() && !senderPath.isEmpty()) {
        done(true);
        return;
    }

    if (refreshToken.isEmpty() || accessToken.isEmpty()) {
        QMessageBox::critical(this, "SharePoint Token Error", "Refresh token required for file uploads.");
        done(false);
        return;
    }

    QJsonObject claims = decodeJwt(accessToken);
    QString tenant = claims.value("tid").toString();
    QString username = claims.value("upn").toString();
    if (username.isEmpty())
        username = claims.value("preferred_username").toString();

    if (tenant.isEmpty() || username.isEmpty()) {
        QMessageBox::critical(this, "SharePoint Token Error", "Failed to discover UPN from token claims.");
        done(false);
        return;
    }

    const QString domain = username.section('@', 1, 1).replace(".com", "");
    sharepointUrl = QString("https://%1-my.sharepoint.com").arg(domain);
    senderPath = username.toLower().replace('@', '_').replace('.', '_');

    const QString tokenUrl = QString("https://login.microsoftonline.com/%1/oauth2/token?api-version=1.0")
                                 .arg(tenant);
    QNetworkRequest req{ QUrl(tokenUrl) };
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    QUrlQuery form;
    form.addQueryItem("grant_type", "refresh_token");
    form.addQueryItem("refresh_token", refreshToken);
    form.addQueryItem("client_id", "d3590ed6-52b3-4102-aeff-aad2292ab01c");
    form.addQueryItem("resource", sharepointUrl);
    form.addQueryItem("scope", "openid");

    QNetworkReply *reply = net->post(req, form.query(QUrl::FullyEncoded).toUtf8());
    connect(reply, &QNetworkReply::finished, this, [this, reply, done]() {
        if (reply->error() != QNetworkReply::NoError) {
            QMessageBox::critical(this, "SharePoint Token Error", reply->errorString());
            reply->deleteLater();
            done(false);
            return;
        }
        const auto obj = QJsonDocument::fromJson(reply->readAll()).object();
        sharepointToken = obj.value("access_token").toString();
        reply->deleteLater();
        if (sharepointToken.isEmpty()) {
            QMessageBox::critical(this, "SharePoint Token Error", "access_token missing in response.");
            done(false);
            return;
        }
        done(true);
    });
}

void TeamsChatWindow::uploadToChatFiles(const QString &localPath,
                                        std::function<void(bool, QString, QString)> done) {
    QFileInfo fi(localPath);
    if (!fi.exists() || !fi.isFile()) {
        QMessageBox::critical(this, "Upload Failed", "Invalid file.");
        done(false, {}, {});
        return;
    }

    const QString fileName = fi.fileName();
    const QString url = QString("%1/personal/%2/_api/v2.0/drive/root:/Microsoft Teams Chat Files/%3:/content?@name.conflictBehavior=replace")
                            .arg(sharepointUrl, senderPath, fileName);

    QFile *file = new QFile(localPath, this);
    if (!file->open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Upload Failed", "Could not open file for reading.");
        done(false, {}, {});
        return;
    }

    auto req = bearerOctet(url, sharepointToken);
    QNetworkReply *reply = net->put(req, file);
    connect(reply, &QNetworkReply::finished, this, [this, reply, file, fileName, done]() {
        file->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            QMessageBox::critical(this, "Upload Failed", reply->errorString());
            reply->deleteLater();
            done(false, {}, {});
            return;
        }
        const auto obj = QJsonDocument::fromJson(reply->readAll()).object();
        const QString itemId = obj.value("id").toString();
        reply->deleteLater();
        if (itemId.isEmpty()) {
            QMessageBox::critical(this, "Upload Failed", "Uploaded file has no item ID.");
            done(false, {}, {});
            return;
        }
        createAnonViewLink(itemId, [this, fileName, done](bool ok, QString webUrl) {
            if (!ok || webUrl.isEmpty()) {
                done(false, {}, {});
                return;
            }
            done(true, webUrl, fileName);
        });
    });
}

void TeamsChatWindow::createAnonViewLink(const QString &itemId,
                                         std::function<void(bool, QString)> done) {
    const QString url = QString("%1/_api/v2.0/me/drive/items/%2/createLink").arg(sharepointUrl, itemId);
    auto req = bearerJson(url, sharepointToken);
    QJsonObject body{ {"type", "view"}, {"scope", "anonymous"} };
    QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [reply, done]() {
        if (reply->error() != QNetworkReply::NoError) {
            QMessageBox::critical(nullptr, "Share Link Failed", reply->errorString());
            reply->deleteLater();
            done(false, {});
            return;
        }
        const auto obj = QJsonDocument::fromJson(reply->readAll()).object();
        const QString webUrl = obj.value("link").toObject().value("webUrl").toString();
        reply->deleteLater();
        if (webUrl.isEmpty()) {
            done(false, {});
            return;
        }
        done(true, webUrl);
    });
}

// ==========================================================================
// USER SELECTOR INTEGRATION
// ==========================================================================

void TeamsChatWindow::onUserChanged(const QString &upn) {
    accessToken.clear();
    refreshToken.clear();
    skypeToken.clear();
    sharepointToken.clear();
    sharepointUrl.clear();
    senderPath.clear();
    tokenInput->clear();
    refreshInput->clear();
    clearConversationUI();
    updateTokenStatus();
    qDebug() << "[Teams] Switched to user:" << upn;
}

void TeamsChatWindow::autoFetchTokens() {
    if (!userSelector->hasSelection()) {
        QMessageBox::warning(this, "No User", "Please select a user first");
        return;
    }

    setLoading(true);

    userSelector->fetchToken("https://graph.microsoft.com", [this](bool success, const QString &token, const QString &error) {
        setLoading(false);

        if (success) {
            accessToken = token;
            tokenInput->setPlainText(token);
            skypeToken.clear();  // Clear old Skype token when getting new Graph token
            updateTokenStatus();

            QString modeHint;
            if (currentMode == Mode::TeamsChannels) {
                modeHint = "Click 'Load' to view your Teams and Channels.\n(Requires Group.Read.All scope)";
            } else if (currentMode == Mode::DirectChatsGraph) {
                modeHint = "Click 'Load' to view your Direct Chats via Graph API.\n(Requires Chat.Read scope)";
            } else {
                modeHint = "Click 'Load' to view your Direct Chats via Skype API.\n(Will exchange token for SkypeToken automatically)";
            }

            QMessageBox::information(this, "Token Acquired",
                QString("Graph token acquired successfully!\n\n%1").arg(modeHint));
        } else {
            QMessageBox::warning(this, "Token Error", QString("Failed to fetch token: %1").arg(error));
        }
    });
}

void TeamsChatWindow::updateTokenStatus() {
    if (accessToken.isEmpty()) {
        tokenStatus->setText("No Token");
        tokenStatus->setStyleSheet("color: gray;");
    } else {
        tokenStatus->setText("Ready");
        tokenStatus->setStyleSheet("color: #00ff00;");
    }
}

// ==========================================================================
// REPLY / THREADING
// ==========================================================================

void TeamsChatWindow::replyToMessage() {
    // This is called from URL handler when reply:// link is clicked
    // The htmlViewer's page navigation is intercepted by ExternalLinkPage
    // For now, we handle replies through the sendMessage function with replyToMessageId set
}

void TeamsChatWindow::cancelReply() {
    replyToMessageId.clear();
    replyToSender.clear();
    replyLabel->setVisible(false);
    cancelReplyBtn->setVisible(false);
    msgBox->setPlaceholderText("Write your message...");
}

// ==========================================================================
// @MENTIONS
// ==========================================================================

void TeamsChatWindow::loadChatMembers() {
    if (activeChatId.isEmpty() || accessToken.isEmpty()) return;

    QString url;
    if (currentMode == Mode::TeamsChannels && !activeTeamId.isEmpty() && !activeChannelId.isEmpty()) {
        // For channels, get channel members
        url = QString("%1/teams/%2/channels/%3/members").arg(GRAPH_BASE, activeTeamId, activeChannelId);
    } else if (currentMode == Mode::DirectChatsGraph) {
        // For chats, get chat members
        url = QString("%1/chats/%2/members").arg(GRAPH_BASE, activeChatId);
    } else {
        // Skype mode - try to get from Graph anyway
        url = QString("%1/chats/%2/members").arg(GRAPH_BASE, activeChatId);
    }

    QNetworkRequest req = bearerJson(url, accessToken);
    QNetworkReply *reply = net->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        chatMembers.clear();

        if (reply->error() == QNetworkReply::NoError) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonArray members = doc.object().value("value").toArray();

            for (const QJsonValue &m : members) {
                QJsonObject member = m.toObject();
                ChatMember cm;
                cm.displayName = member.value("displayName").toString();
                cm.email = member.value("email").toString();
                cm.id = member.value("userId").toString();
                if (cm.id.isEmpty()) {
                    cm.id = member.value("id").toString();
                }
                if (!cm.displayName.isEmpty()) {
                    chatMembers.append(cm);
                }
            }
            // Chat members loaded for mentions (debug removed for cleaner logs)
        }

        reply->deleteLater();
    });
}

void TeamsChatWindow::showMentionPicker() {
    if (chatMembers.isEmpty()) {
        QMessageBox::information(this, "No Members",
            "No chat members loaded for mentions.\n\n"
            "Members are loaded when you view a conversation.");
        return;
    }

    mentionList->clear();
    for (const ChatMember &cm : chatMembers) {
        QString label = cm.displayName;
        if (!cm.email.isEmpty()) {
            label += QString(" (%1)").arg(cm.email);
        }
        QListWidgetItem *item = new QListWidgetItem(label, mentionList);
        item->setData(Qt::UserRole, cm.id);
        item->setData(Qt::UserRole + 1, cm.displayName);
    }

    // Position near the mention button
    QPoint pos = mentionBtn->mapToGlobal(QPoint(0, mentionBtn->height()));
    mentionList->move(pos);
    mentionList->show();
}

void TeamsChatWindow::insertMention(QListWidgetItem *item) {
    mentionList->hide();

    QString userId = item->data(Qt::UserRole).toString();
    QString displayName = item->data(Qt::UserRole + 1).toString();

    // Add to pending mentions
    MentionInfo mi;
    mi.id = pendingMentions.size();
    mi.userId = userId;
    mi.displayName = displayName;
    pendingMentions.append(mi);

    // Insert @mention text into message box
    QTextCursor cursor = msgBox->textCursor();
    cursor.insertText(QString("@%1 ").arg(displayName));
    msgBox->setFocus();
}

// ==========================================================================
// PRESENCE
// ==========================================================================

void TeamsChatWindow::loadPresence() {
    // Load presence for all chat members
    if (chatMembers.isEmpty() || accessToken.isEmpty()) {
        qDebug() << "[Teams] No members to load presence for";
        return;
    }

    // Build list of user IDs
    QJsonArray userIds;
    for (const ChatMember &cm : chatMembers) {
        if (!cm.id.isEmpty()) {
            userIds.append(cm.id);
        }
    }

    if (userIds.isEmpty()) return;

    const QString url = GRAPH_BASE + "/communications/getPresencesByUserId";
    QNetworkRequest req = bearerJson(url, accessToken);

    QJsonObject body;
    body["ids"] = userIds;

    QNetworkReply *reply = net->post(req, QJsonDocument(body).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            qDebug() << "[Teams] Failed to load presence:" << reply->errorString();
            reply->deleteLater();
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray presences = doc.object().value("value").toArray();

        // Build presence map
        QMap<QString, QPair<QString, QString>> presenceMap; // userId -> (availability, activity)
        for (const QJsonValue &p : presences) {
            QJsonObject presence = p.toObject();
            QString userId = presence.value("id").toString();
            QString availability = presence.value("availability").toString();
            QString activity = presence.value("activity").toString();
            presenceMap[userId] = qMakePair(availability, activity);
        }

        // Show presence dialog
        QString html = "<html><head><style>"
                       "body { font-family: sans-serif; background: #1e1e1e; color: #fff; padding: 10px; }"
                       ".user { padding: 8px; margin: 4px 0; background: #2a2a2a; border-radius: 4px; }"
                       ".name { font-weight: bold; }"
                       ".status { font-size: 0.9em; }"
                       "</style></head><body>";

        for (const ChatMember &cm : chatMembers) {
            QString availability = presenceMap.value(cm.id).first;
            QString activity = presenceMap.value(cm.id).second;
            QString statusText = presenceToString(availability, activity);
            QString statusColor = presenceToColor(availability);

            html += QString("<div class='user'>"
                           "<span class='name'>%1</span><br>"
                           "<span class='status' style='color:%2;'>● %3</span>"
                           "</div>")
                        .arg(cm.displayName.toHtmlEscaped(), statusColor, statusText);
        }

        html += "</body></html>";

        // Show in a dialog
        QDialog *dialog = new QDialog(this);
        dialog->setWindowTitle("User Presence");
        dialog->resize(350, 400);

        QVBoxLayout *layout = new QVBoxLayout(dialog);
        QWebEngineView *view = new QWebEngineView(dialog);
        view->setHtml(html);
        layout->addWidget(view);

        QPushButton *closeBtn = new QPushButton("Close", dialog);
        connect(closeBtn, &QPushButton::clicked, dialog, &QDialog::accept);
        layout->addWidget(closeBtn);

        dialog->exec();
        dialog->deleteLater();

        reply->deleteLater();
    });
}

void TeamsChatWindow::showPresencePanel() {
    if (chatMembers.isEmpty()) {
        QMessageBox::information(this, "No Members",
            "No chat members loaded.\n\n"
            "Please select a conversation first.");
        return;
    }

    loadPresence();
}

QString TeamsChatWindow::presenceToString(const QString &availability, const QString &activity) const {
    if (availability == "Available") return "Available";
    if (availability == "Busy") {
        if (activity == "InACall") return "In a call";
        if (activity == "InAMeeting") return "In a meeting";
        if (activity == "Presenting") return "Presenting";
        return "Busy";
    }
    if (availability == "DoNotDisturb") return "Do not disturb";
    if (availability == "BeRightBack") return "Be right back";
    if (availability == "Away") return "Away";
    if (availability == "Offline") return "Offline";
    if (availability == "PresenceUnknown") return "Unknown";
    return availability.isEmpty() ? "Unknown" : availability;
}

QString TeamsChatWindow::presenceToColor(const QString &availability) const {
    if (availability == "Available") return "#00ff00";
    if (availability == "Busy" || availability == "DoNotDisturb") return "#ff0000";
    if (availability == "Away" || availability == "BeRightBack") return "#ffff00";
    return "#888888";
}

// ==========================================================================
// MEETINGS
// ==========================================================================

void TeamsChatWindow::showMeetingDialog() {
    if (accessToken.isEmpty()) {
        QMessageBox::warning(this, "Token Required", "Please provide an access token first.");
        return;
    }

    QDialog *dialog = new QDialog(this);
    dialog->setWindowTitle("Schedule Online Meeting");
    dialog->resize(400, 300);

    QFormLayout *form = new QFormLayout(dialog);

    QLineEdit *subjectEdit = new QLineEdit(dialog);
    subjectEdit->setPlaceholderText("Meeting subject");
    form->addRow("Subject:", subjectEdit);

    QDateTimeEdit *startEdit = new QDateTimeEdit(QDateTime::currentDateTime().addSecs(3600), dialog);
    startEdit->setDisplayFormat("yyyy-MM-dd HH:mm");
    form->addRow("Start:", startEdit);

    QDateTimeEdit *endEdit = new QDateTimeEdit(QDateTime::currentDateTime().addSecs(7200), dialog);
    endEdit->setDisplayFormat("yyyy-MM-dd HH:mm");
    form->addRow("End:", endEdit);

    QTextEdit *attendeesEdit = new QTextEdit(dialog);
    attendeesEdit->setPlaceholderText("Enter email addresses, one per line");
    attendeesEdit->setFixedHeight(80);
    form->addRow("Attendees:", attendeesEdit);

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog);
    connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    form->addRow(buttons);

    if (dialog->exec() == QDialog::Accepted) {
        QString subject = subjectEdit->text().trimmed();
        QDateTime startTime = startEdit->dateTime();
        QDateTime endTime = endEdit->dateTime();
        QStringList attendees = attendeesEdit->toPlainText().split('\n', Qt::SkipEmptyParts);

        if (subject.isEmpty()) {
            subject = "Teams Meeting";
        }

        // Create meeting object
        QJsonObject meeting;
        meeting["subject"] = subject;

        QJsonObject start;
        start["dateTime"] = startTime.toUTC().toString(Qt::ISODate);
        start["timeZone"] = "UTC";
        meeting["start"] = start;

        QJsonObject end;
        end["dateTime"] = endTime.toUTC().toString(Qt::ISODate);
        end["timeZone"] = "UTC";
        meeting["end"] = end;

        meeting["isOnlineMeeting"] = true;
        meeting["onlineMeetingProvider"] = "teamsForBusiness";

        if (!attendees.isEmpty()) {
            QJsonArray attendeesArray;
            for (const QString &email : attendees) {
                QString trimmed = email.trimmed();
                if (!trimmed.isEmpty()) {
                    QJsonObject attendee;
                    QJsonObject emailAddr;
                    emailAddr["address"] = trimmed;
                    attendee["emailAddress"] = emailAddr;
                    attendee["type"] = "required";
                    attendeesArray.append(attendee);
                }
            }
            meeting["attendees"] = attendeesArray;
        }

        createMeeting();  // Actually called below via the network request

        // Send request
        setLoading(true);
        const QString url = GRAPH_BASE + "/me/events";
        QNetworkRequest req = bearerJson(url, accessToken);

        QNetworkReply *reply = net->post(req, QJsonDocument(meeting).toJson());

        connect(reply, &QNetworkReply::finished, this, [this, reply, dialog]() {
            setLoading(false);

            if (reply->error() != QNetworkReply::NoError) {
                QString errorMsg = reply->errorString();
                QByteArray body = reply->readAll();
                QJsonDocument doc = QJsonDocument::fromJson(body);
                if (doc.isObject()) {
                    QString msg = doc.object().value("error").toObject().value("message").toString();
                    if (!msg.isEmpty()) errorMsg = msg;
                }
                QMessageBox::critical(this, "Meeting Failed",
                    QString("Failed to create meeting:\n\n%1").arg(errorMsg));
                reply->deleteLater();
                return;
            }

            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject event = doc.object();
            QString joinUrl = event.value("onlineMeeting").toObject().value("joinUrl").toString();
            QString webLink = event.value("webLink").toString();

            QString message = "Meeting created successfully!\n\n";
            if (!joinUrl.isEmpty()) {
                message += QString("Join URL:\n%1").arg(joinUrl);
            } else if (!webLink.isEmpty()) {
                message += QString("Event link:\n%1").arg(webLink);
            }

            QMessageBox::information(this, "Meeting Created", message);
            reply->deleteLater();
        });
    }

    dialog->deleteLater();
}

void TeamsChatWindow::createMeeting() {
    // Placeholder - actual meeting creation is done in showMeetingDialog
}

// ==========================================================================
// EXPORT
// ==========================================================================

void TeamsChatWindow::exportToCSV() {
    if (cachedMessages.isEmpty()) {
        QMessageBox::warning(this, "No Messages", "No messages to export. Load a conversation first.");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export to CSV", "teams_chat.csv", "CSV files (*.csv)");
    if (filename.isEmpty()) return;

    QString csv = messagesToCSV(cachedMessages, cachedIsSkypeFormat);

    QFile file(filename);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << csv;
        file.close();
        QMessageBox::information(this, "Export Complete",
            QString("Exported %1 messages to:\n%2").arg(cachedMessages.size()).arg(filename));
    } else {
        QMessageBox::critical(this, "Export Failed", "Could not write to file.");
    }
}

void TeamsChatWindow::exportToJSON() {
    if (cachedMessages.isEmpty()) {
        QMessageBox::warning(this, "No Messages", "No messages to export. Load a conversation first.");
        return;
    }

    QString filename = QFileDialog::getSaveFileName(this, "Export to JSON", "teams_chat.json", "JSON files (*.json)");
    if (filename.isEmpty()) return;

    QString json = messagesToJSON(cachedMessages);

    QFile file(filename);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << json;
        file.close();
        QMessageBox::information(this, "Export Complete",
            QString("Exported %1 messages to:\n%2").arg(cachedMessages.size()).arg(filename));
    } else {
        QMessageBox::critical(this, "Export Failed", "Could not write to file.");
    }
}

QString TeamsChatWindow::messagesToCSV(const QJsonArray &messages, bool isSkypeFormat) const {
    QString csv = "Date,Sender,Message\n";

    for (int i = messages.size() - 1; i >= 0; --i) {
        const QJsonObject msg = messages.at(i).toObject();

        QString sender;
        QString content;
        QString timeStr;

        if (isSkypeFormat) {
            sender = msg.value("imdisplayname").toString("Unknown");
            content = msg.value("content").toString();
            timeStr = msg.value("composetime").toString();
            if (timeStr.isEmpty()) {
                timeStr = msg.value("originalarrivaltime").toString();
            }
        } else {
            QJsonObject from = msg.value("from").toObject();
            if (from.contains("user")) {
                sender = from.value("user").toObject().value("displayName").toString("Unknown");
            } else if (from.contains("application")) {
                sender = from.value("application").toObject().value("displayName").toString("Bot");
            } else {
                sender = "Unknown";
            }
            content = msg.value("body").toObject().value("content").toString();
            timeStr = msg.value("createdDateTime").toString();
        }

        // Strip HTML tags
        content.remove(QRegularExpression("<[^>]*>"));
        // Escape quotes and newlines for CSV
        content.replace("\"", "\"\"");
        content.replace("\n", " ");
        sender.replace("\"", "\"\"");

        if (!content.trimmed().isEmpty()) {
            csv += QString("\"%1\",\"%2\",\"%3\"\n").arg(timeStr, sender, content);
        }
    }

    return csv;
}

QString TeamsChatWindow::messagesToJSON(const QJsonArray &messages) const {
    QJsonArray exportArray;

    for (int i = messages.size() - 1; i >= 0; --i) {
        const QJsonObject msg = messages.at(i).toObject();

        QJsonObject exportMsg;
        if (cachedIsSkypeFormat) {
            exportMsg["date"] = msg.value("composetime").toString();
            exportMsg["sender"] = msg.value("imdisplayname").toString("Unknown");
            exportMsg["message"] = msg.value("content").toString();
            exportMsg["messageType"] = msg.value("messagetype").toString();
        } else {
            exportMsg["date"] = msg.value("createdDateTime").toString();
            QJsonObject from = msg.value("from").toObject();
            if (from.contains("user")) {
                exportMsg["sender"] = from.value("user").toObject().value("displayName").toString("Unknown");
            } else {
                exportMsg["sender"] = from.value("application").toObject().value("displayName").toString("Unknown");
            }
            exportMsg["message"] = msg.value("body").toObject().value("content").toString();
            exportMsg["messageType"] = msg.value("messageType").toString();
        }

        QString content = exportMsg.value("message").toString();
        if (!content.trimmed().isEmpty()) {
            exportArray.append(exportMsg);
        }
    }

    QJsonObject root;
    root["messages"] = exportArray;
    root["exportDate"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    root["messageCount"] = exportArray.size();

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

void TeamsChatWindow::cancelRequests() {
    cancelRequested = true;
    for (QNetworkReply *reply : activeReplies) {
        if (reply && !reply->isFinished()) {
            reply->abort();
        }
    }
    activeReplies.clear();
    setLoading(false);
}
