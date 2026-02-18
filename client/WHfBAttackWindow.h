#ifndef WHFBATTACKWINDOW_H
#define WHFBATTACKWINDOW_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QProgressBar>
#include <QLabel>
#include <QProcess>
#include <QCheckBox>
#include <QComboBox>
#include <QGroupBox>

class UserSelectorWidget;

class WHfBAttackWindow : public QWidget {
    Q_OBJECT

public:
    explicit WHfBAttackWindow(QWidget *parent = nullptr);
    ~WHfBAttackWindow();

private slots:
    void startDeviceCodeFlow();
    void startWithExistingTokens();
    void stopAttack();
    void onProcessOutput();
    void onProcessError();
    void onProcessFinished(int exitCode, QProcess::ExitStatus status);
    void autoFetchTokens();
    void onUserChanged(const QString &upn);
    void copyOutput();
    void saveCredentials();

private:
    void setupUi();
    void updateTokenStatus();
    void appendLog(const QString &msg, const QString &color = "white");
    void setLoading(bool loading);
    QString findPythonScript();
    void launchPythonScript(const QString &accessToken = QString(), const QString &refreshToken = QString());

    UserSelectorWidget *userSelector;
    QPushButton *autoFetchBtn;
    QLabel *tokenStatus;

    QTextEdit *accessTokenInput;
    QTextEdit *refreshTokenInput;
    QLineEdit *deviceNameInput;

    QPushButton *startDeviceCodeBtn;
    QPushButton *startWithTokensBtn;
    QPushButton *stopBtn;
    QPushButton *copyBtn;
    QPushButton *saveBtn;

    QTextEdit *outputLog;
    QProgressBar *progressBar;
    QLabel *statusLabel;

    QProcess *pythonProcess;
    bool attackRunning;

    // Captured credentials
    QString capturedDeviceCert;
    QString capturedDeviceKey;
    QString capturedPRT;
};

#endif // WHFBATTACKWINDOW_H
