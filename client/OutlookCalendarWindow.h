#pragma once
#include <QWidget>
#include <atomic>
#include <QCalendarWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>
#include <QWebEngineView>
#include <QVBoxLayout>
#include <QProgressBar>
#include <QMap>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QDate>
#include <QLabel>

class UserSelectorWidget;

class OutlookCalendarWindow : public QWidget {
    Q_OBJECT
public:
    explicit OutlookCalendarWindow(QWidget *parent = nullptr);
    explicit OutlookCalendarWindow(const QString &token, QWidget *parent = nullptr);
    ~OutlookCalendarWindow();

    void setAccessToken(const QString &token);

private slots:
    void pasteToken();
    void loadMonthEvents();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void loadEventsForSelectedDay();
    void displayEventBody(int index);
    void createEvent();
    void deleteEvent();
    void downloadAttachmentUrl(const QString &url, const QString &filename);
    void downloadAttachment(const QString &eventId, const QString &attachmentId, const QString &filename);
    void cancelRequests();

private:
    void setupUi();
    void updateTokenStatus();
    QString getUserPath() const;
    void clearAttachmentLayout();

    // UI
    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;
    QLineEdit *upnInput;
    QPushButton *btnToken;
    QCalendarWidget *calendar;
    QPushButton *btnAdd;
    QPushButton *btnDelete;
    QPushButton *btnRefresh;
    QListWidget *eventsList;
    QWebEngineView *eventBody;
    QWidget *attachmentContainer;
    QVBoxLayout *attachmentLayout;

    void setLoading(bool loading);

    // Data
    QString accessToken;
    QMap<QDate, QList<QJsonObject>> monthEvents;
    QList<QJsonObject> currentDayEvents;

    QNetworkAccessManager *net;
    QProgressBar *progressBar;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};
