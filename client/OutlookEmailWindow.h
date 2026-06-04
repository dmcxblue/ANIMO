#pragma once
#include <QWidget>
#include <atomic>
#include <QListWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QProgressBar>
#include <QtWebEngineWidgets/QWebEngineView>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <functional>

class UserSelectorWidget;

class OutlookEmailWindow : public QWidget {
    Q_OBJECT
public:
    explicit OutlookEmailWindow(QWidget *parent = nullptr);
    explicit OutlookEmailWindow(const QString &token, QWidget *parent = nullptr);
    ~OutlookEmailWindow();

    void setAccessToken(const QString &token);

private slots:
    void authenticate();
    void reloadMailbox();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    //void onEmailSelect(QListWidgetItem *current, QListWidgetItem *previous);
    void replyToEmail();
    void toggleReadStatus();
    void deleteEmail();
	void composeNewEmail();
	void newEmail() { composeNewEmail(); }
    void permanentlyDeleteEmail();
    void downloadAttachments();

    // Bulk operations
    void markAllAsRead();
    void deleteAllEmails();
    void exportEmailsToEML();
    void showAdvancedSearch();
    void loadEmailTemplate();

    // Selection operations
    void selectAllEmails();
    void selectNoneEmails();
    void cancelRequests();

private:
    // helpers
    QString mailboxPath() const;               // "me" or users/<shared>
    void populateList(const QJsonArray &items);
    void loadFullMessage(const QString &msgId);
    void setPreviewHtml(QString html, const QJsonArray &attachments);
    void updateTokenStatus();
    void appendLog(const QString &msg, const QString &color = "white");

    // UI
    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;
    QPushButton *btnAuth;
    QLineEdit   *sharedUpn;
    QComboBox   *cmbFolder;
    QLineEdit   *editLimit;
    QLineEdit   *editSkip;
    QLineEdit   *editSearch;
    QPushButton *btnReload;

    QListWidget *lstEmails;
    QLabel *lblFrom;
    QLabel *lblDate;
    QLabel *lblTo;
    QLabel *lblCc;
    QWebEngineView *txtBody;

    QPushButton *btnReply;
	QPushButton *btnNew;
    QPushButton *btnMark;
    QPushButton *btnDelete;
    QPushButton *btnPermDelete;
    QPushButton *btnDownload;

    // Bulk operation buttons
    QPushButton *btnMarkAllRead;
    QPushButton *btnDeleteAll;
    QPushButton *btnExport;
    QPushButton *btnAdvancedSearch;
    QPushButton *btnTemplates;

    // Selection buttons
    QPushButton *btnSelectAll;
    QPushButton *btnSelectNone;

    void setLoading(bool loading);

    // state
    QString accessToken;
    QJsonArray emails;                 // list page items
    QJsonArray currentAttachments;     // non-inline attachments for download

    // net
    QNetworkAccessManager *net;
    QProgressBar *progressBar;

    // Async operation helpers
    void uploadAttachmentsAsync(const QString &draftId, const QStringList &files,
                                std::function<void(bool)> onComplete);
    void sendDraftAsync(const QString &draftId, std::function<void(bool)> onComplete);
    void downloadAttachmentAsync(int index);

    // State for async download
    QString currentDownloadMsgId;
    int currentDownloadIndex = 0;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};
