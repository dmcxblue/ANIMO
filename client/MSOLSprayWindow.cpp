#include "MSOLSprayWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFileDialog>
#include <QScrollBar>
#include <QFile>
#include <QTextStream>
#include <QGroupBox>

MSOLSprayWindow::MSOLSprayWindow(QWidget* parent)
    : QWidget(parent), worker(nullptr) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("MSOLSpray - Azure Password Spraying");
    resize(700, 600);

    QVBoxLayout* layout = new QVBoxLayout(this);

    // Warning banner
    auto *warningLabel = new QLabel(
        "<b>Warning:</b> Azure AD locks accounts after ~10 failed attempts in 5 minutes. "
        "Use rate limiting to avoid detection and lockouts.", this);
    warningLabel->setStyleSheet("color: #ffc107; padding: 8px; background: #2a2a2a; border-radius: 3px;");
    warningLabel->setWordWrap(true);
    layout->addWidget(warningLabel);

    // File selection
    layout->addWidget(new QLabel("Userlist File (user@domain.com):"));
    QHBoxLayout* fileRow = new QHBoxLayout();
    fileDisplay = new QLineEdit();
    fileDisplay->setReadOnly(true);
    QPushButton* btnBrowse = new QPushButton("Browse");
    connect(btnBrowse, &QPushButton::clicked, this, &MSOLSprayWindow::browseUserlist);
    fileRow->addWidget(fileDisplay);
    fileRow->addWidget(btnBrowse);
    layout->addLayout(fileRow);

    // Password input
    layout->addWidget(new QLabel("Single Password for Spray:"));
    pwdInput = new QLineEdit();
    pwdInput->setEchoMode(QLineEdit::Password);
    layout->addWidget(pwdInput);

    // Rate limiting controls
    auto *rateGroup = new QGroupBox("Rate Limiting", this);
    auto *rateLayout = new QHBoxLayout(rateGroup);

    rateLayout->addWidget(new QLabel("Delay between requests:"));

    delaySlider = new QSlider(Qt::Horizontal, this);
    delaySlider->setRange(0, 2000);
    delaySlider->setValue(500);
    delaySlider->setTickPosition(QSlider::TicksBelow);
    delaySlider->setTickInterval(250);
    rateLayout->addWidget(delaySlider);

    delaySpinBox = new QSpinBox(this);
    delaySpinBox->setRange(0, 2000);
    delaySpinBox->setValue(500);
    delaySpinBox->setSuffix(" ms");
    delaySpinBox->setMinimumWidth(80);
    rateLayout->addWidget(delaySpinBox);

    delayLabel = new QLabel("(500ms = ~2 req/sec)", this);
    delayLabel->setStyleSheet("color: gray;");
    rateLayout->addWidget(delayLabel);

    // Sync slider and spinbox
    connect(delaySlider, &QSlider::valueChanged, delaySpinBox, &QSpinBox::setValue);
    connect(delaySpinBox, QOverload<int>::of(&QSpinBox::valueChanged), delaySlider, &QSlider::setValue);
    connect(delaySlider, &QSlider::valueChanged, this, &MSOLSprayWindow::updateDelayLabel);

    layout->addWidget(rateGroup);

    // Buttons
    QHBoxLayout* btnRow = new QHBoxLayout();
    btnStart = new QPushButton("Start Spray");
    btnStart->setStyleSheet("QPushButton { background-color: #28a745; color: white; font-weight: bold; padding: 8px 16px; }");
    connect(btnStart, &QPushButton::clicked, this, &MSOLSprayWindow::runSpray);
    btnRow->addWidget(btnStart);

    btnStop = new QPushButton("Stop");
    btnStop->setStyleSheet("QPushButton { background-color: #dc3545; color: white; font-weight: bold; padding: 8px 16px; }");
    btnStop->setEnabled(false);
    connect(btnStop, &QPushButton::clicked, this, &MSOLSprayWindow::stopSpray);
    btnRow->addWidget(btnStop);

    btnRow->addStretch();
    layout->addLayout(btnRow);

    // Output
    output = new QTextEdit();
    output->setReadOnly(true);
    output->setFont(QFont("Courier", 10));
    layout->addWidget(output);

    setLayout(layout);
}

void MSOLSprayWindow::updateDelayLabel(int value) {
    if (value == 0) {
        delayLabel->setText("(No delay - FAST but risky)");
        delayLabel->setStyleSheet("color: #ff6b6b;");
    } else if (value < 200) {
        delayLabel->setText(QString("(%1ms = ~%2 req/sec - Risky)").arg(value).arg(1000 / qMax(value, 1)));
        delayLabel->setStyleSheet("color: orange;");
    } else if (value < 500) {
        delayLabel->setText(QString("(%1ms = ~%2 req/sec - Moderate)").arg(value).arg(1000 / value));
        delayLabel->setStyleSheet("color: yellow;");
    } else {
        delayLabel->setText(QString("(%1ms = ~%2 req/sec - Safe)").arg(value).arg(1000 / value));
        delayLabel->setStyleSheet("color: lightgreen;");
    }
}

void MSOLSprayWindow::browseUserlist() {
    QString path = QFileDialog::getOpenFileName(this, "Select Userlist File");
    if (!path.isEmpty()) {
        userlistPath = path;
        fileDisplay->setText(path);
    }
}

void MSOLSprayWindow::appendOutput(const QString& text, QColor color) {
    output->setTextColor(color);
    output->append(text);
    output->verticalScrollBar()->setValue(output->verticalScrollBar()->maximum());
}

void MSOLSprayWindow::runSpray() {
    output->clear();
    QString userFile = userlistPath.trimmed();
    QString password = pwdInput->text().trimmed();

    QFile file(userFile);
    if (!file.exists() || !file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        appendOutput("[!] Invalid user list path.", QColor("red"));
        return;
    }

    QStringList users;
    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (!line.isEmpty())
            users << line;
    }
    file.close();

    if (users.isEmpty()) {
        appendOutput("[!] User list is empty.", QColor("red"));
        return;
    }

    int delayMs = delaySpinBox->value();
    appendOutput(QString("[*] Spraying %1 users with password: %2").arg(users.size()).arg(password), QColor("yellow"));

    worker = new SprayWorker(users, password, delayMs, this);
    connect(worker, &SprayWorker::progress, this, &MSOLSprayWindow::appendOutput);
    connect(worker, &SprayWorker::finished, this, &MSOLSprayWindow::cleanupWorker);
    worker->start();

    btnStart->setEnabled(false);
    btnStop->setEnabled(true);
    delaySlider->setEnabled(false);
    delaySpinBox->setEnabled(false);
}

void MSOLSprayWindow::stopSpray() {
    if (worker) {
        worker->stop();
        appendOutput("[*] Stopping spray...", QColor("yellow"));
    }
}

void MSOLSprayWindow::cleanupWorker() {
    btnStart->setEnabled(true);
    btnStop->setEnabled(false);
    delaySlider->setEnabled(true);
    delaySpinBox->setEnabled(true);
    worker->deleteLater();
    worker = nullptr;
}
