#ifndef MFAPROMPTDIALOG_H
#define MFAPROMPTDIALOG_H

#include <QDialog>
#include <QString>
#include <QLabel>
#include <QTextBrowser>
#include <QPushButton>

class MfaPromptDialog : public QDialog {
    Q_OBJECT

public:
    explicit MfaPromptDialog(const QString &mfaCode,
                             const QString &mfaMessage,
                             const QString &sessionId,
                             QWidget *parent = nullptr);

    QString mfaCode() const { return m_mfaCode; }
    QString sessionId() const { return m_sessionId; }

private:
    void setupUi();
    QString getMfaDescription(const QString &code);

    QString m_mfaCode;
    QString m_mfaMessage;
    QString m_sessionId;

    QLabel *m_iconLabel = nullptr;
    QLabel *m_titleLabel = nullptr;
    QTextBrowser *m_detailsBrowser = nullptr;
    QPushButton *m_okBtn = nullptr;
};

#endif // MFAPROMPTDIALOG_H
