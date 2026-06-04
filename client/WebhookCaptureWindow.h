#ifndef WEBHOOKCAPTUREWINDOW_H
#define WEBHOOKCAPTUREWINDOW_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QTableWidget>
#include <QTextEdit>
#include <QTcpServer>
#include <QTcpSocket>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDateTime>

class DashboardWindow;

class WebhookCaptureWindow : public QWidget
{
    Q_OBJECT

public:
    explicit WebhookCaptureWindow(DashboardWindow *dashboard, QWidget *parent = nullptr);
    ~WebhookCaptureWindow();

private slots:
    void toggleListener();
    void handleNewConnection();
    void clearCapturedTokens();

private:
    enum CaptureMode {
        CaptureAll = 0,
        CapturePRTOnly = 1,
        CaptureAccessRefreshOnly = 2
    };

    void startListener();
    void stopListener();
    void sendHttpResponse(QTcpSocket *socket, const QByteArray &response);
    void processRequest(QTcpSocket *socket, const QByteArray &data);
    void processToken(const QString &tokenData);
    void processJsonPayload(const QJsonObject &obj);
    void processAccessRefreshTokens(const QString &accessToken, const QString &refreshToken,
                                     const QString &resource, const QString &label);
    void processSingleToken(const QString &token);
    QString decodeJwtClaim(const QString &jwt, const char *field);
    bool isPRTToken(const QString &jwt);
    bool shouldCapture(bool isPRT);
    void logTokenToServer(const QString &accessToken, const QString &refreshToken,
                          const QString &source, const QString &resource);
    void createSessionFromToken(const QString &accessToken, const QString &refreshToken,
                                 const QString &resource);
    void addTokenToTable(const QString &token, const QString &tokenType,
                         const QString &user, const QString &tenant,
                         const QDateTime &expiry, const QString &audience);
    QObject* locateTransport() const;
    void wireTransport();

    DashboardWindow *parentDashboard;
    QTcpServer *tcpServer;

    QSpinBox *portSpinBox;
    QComboBox *captureModeCombo;
    QPushButton *toggleBtn;
    QPushButton *clearBtn;
    QCheckBox *createSessionCheckbox;
    QTableWidget *tokenTable;
    QTextEdit *logOutput;
    QLabel *statusLabel;

    bool hookConnected = false;
    bool sessionHandled = false;
    QString pendingRid;
    QString pendingAccessToken;
    QString pendingRefreshToken;
    QString pendingResource;
    int captureCount = 0;
};

#endif // WEBHOOKCAPTUREWINDOW_H
