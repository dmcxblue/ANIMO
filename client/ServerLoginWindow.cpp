#include "ServerLoginWindow.h"
#include <QIntValidator>
#include <QHostAddress>
#include <QMessageBox>
#include <QSettings>

ServerLoginWindow::ServerLoginWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("Connect to ANIMO Server");
    resize(300, 150);

    auto *layout = new QVBoxLayout(this);
    auto *formLayout = new QFormLayout();

    // Load saved connection settings or use defaults
    QSettings settings("ANIMO", "Client");
    QString savedIp = settings.value("server/ip", "127.0.0.1").toString();
    QString savedPort = settings.value("server/port", "7777").toString();
    QString savedUser = settings.value("operator/username").toString();

    ipEdit_ = new QLineEdit(this);
    ipEdit_->setText(savedIp);
    ipEdit_->setPlaceholderText("e.g. 192.168.1.100");

    portEdit_ = new QLineEdit(this);
    portEdit_->setValidator(new QIntValidator(1, 65535, this));
    portEdit_->setText(savedPort);

    usernameEdit_ = new QLineEdit(this);
    usernameEdit_->setText(savedUser);
    usernameEdit_->setMaxLength(64);

    passwordEdit_ = new QLineEdit(this);
    passwordEdit_->setEchoMode(QLineEdit::Password);

    formLayout->addRow("IP:", ipEdit_);
    formLayout->addRow("Port:", portEdit_);
    formLayout->addRow("Operator:", usernameEdit_);
    formLayout->addRow("Password:", passwordEdit_);

    layout->addLayout(formLayout);

    connectButton_ = new QPushButton("Connect", this);
    layout->addWidget(connectButton_);

    connect(connectButton_, &QPushButton::clicked, this, &ServerLoginWindow::onConnectClicked);
}

void ServerLoginWindow::onConnectClicked() {
    QString ip = ipEdit_->text().trimmed();
    QString username = usernameEdit_->text().trimmed();
    QString password = passwordEdit_->text();

    bool portOk = false;
    quint16 port = portEdit_->text().toUShort(&portOk);

    if (ip.isEmpty()) {
        QMessageBox::warning(this, "Invalid Input", "Please enter a valid IP address.");
        return;
    }

    if (!portOk || port == 0) {
        QMessageBox::warning(this, "Invalid Input", "Please enter a valid port (1-65535).");
        return;
    }

    if (username.isEmpty()) {
        QMessageBox::warning(this, "Invalid Input",
                             "Please enter an operator handle - it identifies your activity.");
        return;
    }

    // Save connection settings for next time
    QSettings settings("ANIMO", "Client");
    settings.setValue("server/ip", ip);
    settings.setValue("server/port", QString::number(port));
    settings.setValue("operator/username", username);

    emit connectToServer(ip, port, username, password);
}
