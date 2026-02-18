#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFormLayout>

class ServerLoginWindow : public QWidget {
    Q_OBJECT
public:
    explicit ServerLoginWindow(QWidget *parent = nullptr);

signals:
    void connectToServer(const QString &ip, quint16 port, const QString &password);

private slots:
    void onConnectClicked();

private:
    QLineEdit *ipEdit_;
    QLineEdit *portEdit_;
    QLineEdit *passwordEdit_;
    QPushButton *connectButton_;
};
