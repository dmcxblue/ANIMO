#pragma once
#include <QWidget>
#include <QNetworkAccessManager>
#include <QByteArray>

class QLineEdit;
class QComboBox;
class QPushButton;
class QTextEdit;
class QLabel;
class QProgressBar;
class UserSelectorWidget;

class GraphQueryWindow : public QWidget {
    Q_OBJECT
public:
    explicit GraphQueryWindow(QWidget* parent = nullptr);
    ~GraphQueryWindow() override = default;

private slots:
    void onMethodChanged(int idx);
    void onOpenBody();
    void onSend();
    void onReplyFinished();
    void autoFetchTokens();
    void onUserChanged(const QString &upn);

private:
    bool validateInputs(QString& error) const;
    void updateTokenStatus();
    static QString prettyJson(const QByteArray& in);
    static QByteArray base64UrlDecode(const QByteArray& in);
    static bool tokenAudIsGraph(const QString& jwt, QString* audOut = nullptr, QString* err = nullptr);

    // UI
    UserSelectorWidget* m_userSelector;
    QLineEdit*  m_tokenEdit;
    QPushButton* m_autoFetchBtn;
    QLabel*     m_tokenStatus;
    QLineEdit*  m_urlEdit;
    QComboBox*  m_methodBox;
    QPushButton* m_bodyBtn;
    QPushButton* m_sendBtn;
    QTextEdit*  m_output;
    QLabel*     m_status;
    QProgressBar* m_progress;

    // State
    QString     m_bodyText;
    QNetworkAccessManager m_nam;
};
