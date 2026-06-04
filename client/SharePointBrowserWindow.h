#pragma once
#include <QWidget>
#include <atomic>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>
#include <QHeaderView>
#include <QMessageBox>
#include <QFileDialog>
#include <QProgressBar>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrlQuery>
#include <QComboBox>

class UserSelectorWidget;

class SharePointBrowserWindow : public QWidget {
    Q_OBJECT
public:
    explicit SharePointBrowserWindow(const QString &token, QWidget *parent = nullptr);
    ~SharePointBrowserWindow();

private slots:
    void loadRoot();
    void goBack();
    void onItemDoubleClick(QTreeWidgetItem *item, int column);
    void uploadFile();
    void handleNetworkReply(QNetworkReply *reply);
    void onLocationChanged(int index);
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void cancelRequests();

private:
    enum class Location { MyFiles, Shared, Recent, Places, People, Meetings, Media }; // ⬅ NEW

    // Fetchers
    void fetchLocationRoot();                          // ⬅ NEW (entry point for selected location)
    void fetchDriveChildren(const QString &driveItemId = QString()); // MyFiles + site drives
    void fetchSharedWithMe();                          // ⬅ NEW
    void fetchRecent();                                // ⬅ NEW
    void fetchFollowedSites();                         // ⬅ NEW ("Places")
    void fetchSiteDriveRoot(const QString &siteId);    // ⬅ NEW
    void fetchPeople();                                // ⬅ NEW
    void fetchMeetings();                              // ⬅ NEW
    void fetchMedia();                                 // ⬅ NEW (simple recent-media filter)

    // Renderers
    void processDriveItems(const QJsonArray &items);
    void processSites(const QJsonArray &sites);
    void processPeople(const QJsonArray &people);
    void processMeetings(const QJsonArray &events);
    void updateTokenStatus();

    // Download handling - robust multi-method approach
    void downloadFile(const QJsonObject &itemData, const QString &fileName);
    void downloadFromUrl(const QString &url, const QString &fileName, bool isTextPreview);
    void downloadViaContentEndpoint(const QString &driveId, const QString &itemId, const QString &fileName, bool isTextPreview);
    void handleDownloadResponse(QNetworkReply *reply, const QString &fileName, bool isTextPreview);

    void setLoading(bool loading);

    // UI
    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;
    QTextEdit *tokenInput;
    QPushButton *loadButton;
    QLabel *pathLabel;
    QTreeWidget *tree;
    QPushButton *backButton;
    QPushButton *uploadButton;
    QComboBox *locationBox;
    QProgressBar *progressBar;

    // State
    QString token;
    QVector<QPair<QString, QString>> pathStack; // (id, name) for drives and site-drives
    Location currentLocation = Location::MyFiles;

    QNetworkAccessManager *netManager;
    QList<QTextEdit*> textViewers;

    // Cancel support
    QPushButton *cancelBtn;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};
};
