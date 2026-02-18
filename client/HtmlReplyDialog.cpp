// HtmlReplyDialog.cpp
#include "HtmlReplyDialog.h"
#include <QVBoxLayout>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QTemporaryFile>
#include <QDateTime>
#include <QGuiApplication>
#include <QScreen>
#include <QFileInfo>
#include <QKeyEvent>
#include <QFormLayout>
#include <QLineEdit>



HtmlReplyDialog::HtmlReplyDialog(QWidget *parent)
    : QDialog(parent) {
   // setWindowTitle("Reply");
   // setMinimumSize(600, 500);
	
	setWindowTitle("Compose Email");
    setMinimumSize(700, 600);

    auto *layout = new QVBoxLayout(this);
	auto *recipLayout = new QFormLayout();
    toInput  = new QLineEdit(this); toInput->setPlaceholderText("Enter recipient emails, comma-separated");
    ccInput  = new QLineEdit(this); ccInput->setPlaceholderText("CC (optional)");
    bccInput = new QLineEdit(this); bccInput->setPlaceholderText("BCC (optional)");
	subjectInput = new QLineEdit(this); subjectInput->setPlaceholderText("Subject");
    recipLayout->addRow("To:", toInput);
    recipLayout->addRow("Cc:", ccInput);
    recipLayout->addRow("Bcc:", bccInput);
	recipLayout->addRow("Subject:", subjectInput); 
    layout->addLayout(recipLayout);
	
    toolbar = new QToolBar(this);

    //  Font selector
    fontCombo = new QFontComboBox(this);
    connect(fontCombo, &QFontComboBox::currentFontChanged, this, &HtmlReplyDialog::setFont);
    toolbar->addWidget(fontCombo);

    //  Size selector
    sizeCombo = new QComboBox(this);
    for (int s = 8; s < 30; s += 2)
        sizeCombo->addItem(QString::number(s));
    connect(sizeCombo, &QComboBox::currentTextChanged, this, &HtmlReplyDialog::setSize);
    toolbar->addWidget(sizeCombo);

    toolbar->addSeparator();

    // Bold/Italic/Underline (toggleable)
	QAction *bold = toolbar->addAction("Bold");
	bold->setCheckable(true);
	connect(bold, &QAction::toggled, this, [this](bool checked) {
		QTextCharFormat fmt;
		fmt.setFontWeight(checked ? QFont::Bold : QFont::Normal);
		editor->mergeCurrentCharFormat(fmt);
	});
	
	QAction *italic = toolbar->addAction("Italic");
	italic->setCheckable(true);
	connect(italic, &QAction::toggled, this, [this](bool checked) {
		QTextCharFormat fmt;
		fmt.setFontItalic(checked);
		editor->mergeCurrentCharFormat(fmt);
	});
	
	QAction *underline = toolbar->addAction("Underline");
	underline->setCheckable(true);
	connect(underline, &QAction::toggled, this, [this](bool checked) {
		toggleFormat(9999, checked);
	});

    toolbar->addSeparator();

    //  Alignment
    QAction *alignLeft = toolbar->addAction(QIcon::fromTheme("format-justify-left"), "Left");
    connect(alignLeft, &QAction::triggered, [this]() { editor->setAlignment(Qt::AlignLeft); });

    QAction *alignCenter = toolbar->addAction(QIcon::fromTheme("format-justify-center"), "Center");
    connect(alignCenter, &QAction::triggered, [this]() { editor->setAlignment(Qt::AlignCenter); });

    QAction *alignRight = toolbar->addAction(QIcon::fromTheme("format-justify-right"), "Right");
    connect(alignRight, &QAction::triggered, [this]() { editor->setAlignment(Qt::AlignRight); });

    toolbar->addSeparator();

    //  Emoji palette
    for (const char *emoji : {"😊","😂","🔥","🎉","👍","❤️"}) {
        QAction *act = new QAction(QString::fromUtf8(emoji), this);
        connect(act, &QAction::triggered, this, [this, e = QString::fromUtf8(emoji)]() {
            editor->insertPlainText(e);
        });
        toolbar->addAction(act);
    }

    toolbar->addSeparator();

    //  Attachments
    QAction *attachAct = toolbar->addAction("📎 Attach");
    connect(attachAct, &QAction::triggered, this, &HtmlReplyDialog::addAttachment);

    //  Screenshot capture
    QAction *shotAct = toolbar->addAction("📷 Screenshot");
    connect(shotAct, &QAction::triggered, this, &HtmlReplyDialog::captureScreenshot);

    layout->addWidget(toolbar);

    //  Rich editor
    editor = new QTextEdit(this);
    editor->setAcceptRichText(true);
    editor->setHtml("<p><br></p>");
    layout->addWidget(editor, 1);

    //  Attachment preview list
    attachmentList = new QListWidget(this);
    attachmentList->setFixedHeight(80);
    attachmentList->setStyleSheet("QListWidget { background:#1e1e1e; color:#ddd; }");
    layout->addWidget(attachmentList);

    // Handle delete key → remove attachment
    attachmentList->installEventFilter(this);

    //  OK / Cancel
    auto *btns = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(btns, &QDialogButtonBox::accepted, this, &HtmlReplyDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, this, &HtmlReplyDialog::reject);
    layout->addWidget(btns);

    setLayout(layout);
}

// ---------- helpers ----------
bool HtmlReplyDialog::eventFilter(QObject *obj, QEvent *event) {
    if (obj == attachmentList && event->type() == QEvent::KeyPress) {
        auto *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Delete) {
            delete attachmentList->takeItem(attachmentList->currentRow());
            return true;
        }
    }
    return QDialog::eventFilter(obj, event);
}


void HtmlReplyDialog::toggleFormat(int attr, bool toggle) {
    QTextCharFormat fmt;

    if (attr == QFont::Bold) {
        fmt.setFontWeight(toggle ? QFont::Bold : QFont::Normal);
    } else if (attr == QFont::StyleItalic) {
        fmt.setFontItalic(toggle);
    } else if (attr == 9999) {  // custom marker for underline
        fmt.setFontUnderline(toggle);
    }

    editor->mergeCurrentCharFormat(fmt);
}

void HtmlReplyDialog::addAttachment() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Attach");
    if (!filePath.isEmpty()) {
        attachments.append(filePath);
        attachmentList->addItem(QFileInfo(filePath).fileName());
    }
}

void HtmlReplyDialog::captureScreenshot() {
    QScreen *screen = QGuiApplication::primaryScreen();
    if (!screen) return;

    QPixmap shot = screen->grabWindow((WId)parentWidget()->winId());
    if (shot.isNull()) {
        QMessageBox::critical(this, "Screenshot Error", "Failed to capture screenshot.");
        return;
    }

    QByteArray ba;
    QBuffer buffer(&ba);
    buffer.open(QIODevice::WriteOnly);
    shot.save(&buffer, "PNG");

    QString encoded = ba.toBase64();
    QString html = QString("<img src=\"data:image/png;base64,%1\" />").arg(encoded);
    editor->insertHtml(html);

    // Also add as temp-file attachment
    QTemporaryFile temp(QDir::tempPath() + "/reply_screenshotXXXXXX.png");
    temp.setAutoRemove(false);
    if (temp.open()) {
        shot.save(&temp, "PNG");
        attachments.append(temp.fileName());
        attachmentList->addItem(QFileInfo(temp.fileName()).fileName());
        temp.close();
    }
}

QString HtmlReplyDialog::getHtml() const {
    return editor->toHtml();
}

QStringList HtmlReplyDialog::getAttachments() const {
    return attachments;
}

void HtmlReplyDialog::setFont(const QFont &font) {
    editor->setCurrentFont(font);
}

QString HtmlReplyDialog::getSubject() const {
    return subjectInput->text().trimmed();
}

QStringList HtmlReplyDialog::getToRecipients() const {
    return toInput->text().split(",", Qt::SkipEmptyParts);
}
QStringList HtmlReplyDialog::getCcRecipients() const {
    return ccInput->text().split(",", Qt::SkipEmptyParts);
}
QStringList HtmlReplyDialog::getBccRecipients() const {
    return bccInput->text().split(",", Qt::SkipEmptyParts);
}


void HtmlReplyDialog::setSize(const QString &sizeStr) {
    bool ok;
    int size = sizeStr.toInt(&ok);
    if (!ok) return;

    QTextCursor cursor = editor->textCursor();
    if (!cursor.hasSelection())
        cursor.select(QTextCursor::WordUnderCursor);

    QTextCharFormat fmt;
    fmt.setFontPointSize(size);
    cursor.mergeCharFormat(fmt);
    editor->mergeCurrentCharFormat(fmt);
}