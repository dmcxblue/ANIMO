#pragma once
#include <QDialog>
#include <QTextEdit>
#include <QToolBar>
#include <QFontComboBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QAction>
#include <QMessageBox>
#include <QFileDialog>
#include <QPixmap>
#include <QScreen>
#include <QBuffer>
#include <QLineEdit>
#include <QListWidget>
#include <QTemporaryFile>
#include <QFormLayout>
#include <QListWidget>

class HtmlReplyDialog : public QDialog {
    Q_OBJECT
public:
    explicit HtmlReplyDialog(QWidget *parent = nullptr);

    QString getHtml() const;
	QString getSubject() const;
    QStringList getAttachments() const;
	QStringList getToRecipients() const;
    QStringList getCcRecipients() const;
    QStringList getBccRecipients() const;


protected:
    // Enable delete key to remove attachments
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    void setFont(const QFont &font);
    void setSize(const QString &sizeStr);
    void addAttachment();
    void captureScreenshot();
    void toggleFormat(int attr, bool toggle);

private:
    QTextEdit *editor;
    QToolBar *toolbar;
    QFontComboBox *fontCombo;
    QComboBox *sizeCombo;
    QListWidget *attachmentList;   // preview list for attachments
    QStringList attachments;       // file paths
	QLineEdit *toInput;
    QLineEdit *ccInput;
    QLineEdit *bccInput;
	QLineEdit *subjectInput; 
};
