#ifndef REFRESHTOKENSPRAYWINDOW_H
#define REFRESHTOKENSPRAYWINDOW_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QProgressBar>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonArray>
#include <QTimer>
#include <atomic>

class UserSelectorWidget;

class RefreshTokenSprayWindow : public QWidget
{
    Q_OBJECT

public:
    explicit RefreshTokenSprayWindow(QWidget *parent = nullptr);
    ~RefreshTokenSprayWindow();

private slots:
    void startSpray();
    void cancelSpray();
    void loadAppList();
    void exportResults();
    void copySuccessful();
    void processNextApp();

private:
    void setupUi();
    void appendLog(const QString &msg, const QString &color = "white");
    void logInfo(const QString &msg);
    void logSuccess(const QString &msg);
    void logError(const QString &msg);
    void sprayApp(const QString &appName, const QString &appId, const QString &version);
    void addResult(const QString &appName, const QString &appId, bool success,
                   const QString &scopes, const QString &error = QString());
    void setLoading(bool loading);

    QVBoxLayout *mainLayout;
    UserSelectorWidget *userSelector;
    QLineEdit *refreshTokenInput;
    QLineEdit *tenantInput;
    QComboBox *apiVersionCombo;
    QSpinBox *delaySpinBox;
    QCheckBox *checkPrivsCheckbox;

    QPushButton *startBtn;
    QPushButton *cancelBtn;
    QPushButton *loadAppsBtn;
    QPushButton *exportBtn;
    QPushButton *copyBtn;

    QTableWidget *resultsTable;
    QTextEdit *logOutput;
    QProgressBar *progressBar;
    QLabel *statsLabel;

    QNetworkAccessManager *net;
    QList<QNetworkReply*> activeReplies;
    std::atomic<bool> cancelRequested{false};

    QJsonArray appList;
    int currentAppIndex;
    int successCount;
    int failCount;
    QTimer *sprayTimer;
};

#endif // REFRESHTOKENSPRAYWINDOW_H
