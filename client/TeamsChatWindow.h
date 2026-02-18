#pragma once
#include <QWidget>
#include <QtWebEngineWidgets/QWebEngineView>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QFontComboBox>
#include <QSpinBox>
#include <QLabel>
#include <QTimer>
#include <QProgressBar>
#include <QNetworkAccessManager>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include <QTreeWidget>
#include <QListWidget>

class UserSelectorWidget;

/**
 * TeamsChatWindow - Microsoft Teams Chat/Channel viewer
 *
 * Supports three modes:
 *
 * 1. Teams & Channels (Graph API) - requires Group.Read.All
 *    - GET /me/joinedTeams
 *    - GET /teams/{teamId}/channels
 *    - GET /teams/{teamId}/channels/{channelId}/messages (requires ChannelMessage.Read.All)
 *
 * 2. Direct Chats (Graph API) - requires Chat.Read, Chat.ReadWrite
 *    - GET /me/chats
 *    - GET /chats/{chatId}/messages
 *    - POST /chats/{chatId}/messages
 *
 * 3. Direct Chats (Skype API) - undocumented, works with Graph token exchange
 *    - POST teams.microsoft.com/api/authsvc/v1.0/authz → SkypeToken
 *    - GET amer.ng.msg.teams.microsoft.com/v1/users/ME/conversations
 *    - GET/POST .../conversations/{id}/messages
 *
 * Additional Features:
 * - Message threading/replies (Graph API)
 * - @mentions in messages
 * - User presence status
 * - Online meeting scheduler
 * - Bulk export to CSV/JSON
 */
class TeamsChatWindow : public QWidget {
    Q_OBJECT
public:
    explicit TeamsChatWindow(QWidget *parent = nullptr);
    explicit TeamsChatWindow(const QString &accessToken, const QString &refreshToken, QWidget *parent = nullptr);
    ~TeamsChatWindow();

    void setTokens(const QString &accessToken, const QString &refreshToken);

private slots:
    // UI
    void updateFont(const QFont &font);
    void updateFontSize(int size);
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void onModeChanged(int index);
    void cancelRequests();

    // Teams & Channels mode (Graph)
    void loadTeams();
    void onTeamSelected(int idx);
    void onChannelSelected(int idx);
    void loadChannelMessages();

    // Direct Chats mode (Graph)
    void loadDirectChatsGraph();
    void onChatSelectedGraph(int idx);
    void loadChatMessagesGraph();

    // Direct Chats mode (Skype API)
    void loadDirectChatsSkype();
    void onChatSelectedSkype(int idx);
    void loadChatMessagesSkype();

    // Messaging
    void sendMessage();
    void sendAttachment();
    void replyToMessage();
    void cancelReply();

    // Presence
    void loadPresence();
    void showPresencePanel();

    // Meetings
    void createMeeting();
    void showMeetingDialog();

    // Export
    void exportToCSV();
    void exportToJSON();

    // Mentions
    void showMentionPicker();
    void insertMention(QListWidgetItem *item);

private:
    void setupUi();
    void clearConversationUI();

    // HTTP helpers
    QNetworkRequest bearerJson(const QString &url, const QString &token) const;
    QNetworkRequest bearerOctet(const QString &url, const QString &token) const;
    QNetworkRequest skypeRequest(const QString &url) const;

    // SkypeToken exchange (for Skype API mode)
    void ensureSkypeToken(std::function<void(bool)> done);

    // Token helper for SharePoint (needed for attachments)
    void ensureSharepointToken(std::function<void(bool)> done);

    // OneDrive/SharePoint helpers (async chains)
    void uploadToChatFiles(const QString &localPath,
                           std::function<void(bool, QString sharedUrl, QString fileName)> done);
    void createAnonViewLink(const QString &itemId,
                            std::function<void(bool, QString webUrl)> done);

    // Render
    void renderMessagesHtml(const QJsonArray &messages, bool isChannel, bool isSkypeFormat);
    void updateTokenStatus();
    void showScopeWarning(const QString &requiredScope, const QString &errorDetails);

    // Helper to extract chat display name from members
    QString getChatDisplayName(const QJsonObject &chat) const;

    // Presence helper
    QString presenceToString(const QString &availability, const QString &activity) const;
    QString presenceToColor(const QString &availability) const;

    // Export helpers
    QString messagesToCSV(const QJsonArray &messages, bool isSkypeFormat) const;
    QString messagesToJSON(const QJsonArray &messages) const;

    // Load chat/channel members for mentions
    void loadChatMembers();

    // UI - Top section
    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;
    QTextEdit *tokenInput;
    QTextEdit *refreshInput;

    // UI - Mode selection
    QComboBox *modeSelect;       // "Teams & Channels", "Direct Chats (Graph)", "Direct Chats (Skype)"
    QPushButton *loadBtn;

    // UI - Teams & Channels mode
    QComboBox *teamDropdown;
    QComboBox *channelDropdown;

    // UI - Direct Chats mode (shared between Graph and Skype)
    QComboBox *chatDropdown;

    // UI - Message display
    QWebEngineView *htmlViewer;
    QFontComboBox *fontSelect;
    QSpinBox *fontSizeBox;
    QComboBox *formatSelect;     // HTML / Plain Text
    QPushButton *attachBtn;
    QPushButton *mentionBtn;     // @ button for mentions
    QTextEdit *msgBox;
    QLabel *infoLabel;
    QLabel *replyLabel;          // Shows "Replying to: ..."
    QPushButton *cancelReplyBtn;
    QPushButton *sendBtn;
    QProgressBar *progressBar;

    // UI - Extra features
    QPushButton *presenceBtn;
    QPushButton *meetingBtn;
    QPushButton *exportBtn;

    // Mention picker popup
    QListWidget *mentionList;

    // State
    QString accessToken;
    QString refreshToken;

    // SkypeToken (for Skype API mode)
    QString skypeToken;

    // SharePoint tokens (for attachments only)
    QString sharepointToken;
    QString sharepointUrl;   // e.g. https://{tenant}-my.sharepoint.com
    QString senderPath;      // user@domain -> user_domain_com (for /personal/<senderPath>/)

    // Current selection state
    enum class Mode { TeamsChannels, DirectChatsGraph, DirectChatsSkype };
    Mode currentMode = Mode::TeamsChannels;

    QString activeTeamId;
    QString activeChannelId;
    QString activeChatId;
    QString activeChatType;  // "oneOnOne", "group", "meeting"

    // Reply state
    QString replyToMessageId;
    QString replyToSender;

    // Cached messages for export
    QJsonArray cachedMessages;
    bool cachedIsSkypeFormat = false;

    // Chat members for mentions
    struct ChatMember {
        QString id;
        QString displayName;
        QString email;
    };
    QList<ChatMember> chatMembers;

    struct PendingAttachment {
        QString url;
        QString filename;
        bool isValid() const { return !url.isEmpty() && !filename.isEmpty(); }
        void clear() { url.clear(); filename.clear(); }
    } pendingAttachment;

    // Pending mentions for the message
    struct MentionInfo {
        int id;
        QString userId;
        QString displayName;
    };
    QList<MentionInfo> pendingMentions;

    void setLoading(bool loading);

    QTimer *pollTimer = nullptr;
    QNetworkAccessManager *net;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    bool cancelRequested = false;
};
