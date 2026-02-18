#pragma once

#include <QWidget>
#include <QNetworkAccessManager>

class QLineEdit;
class QTextEdit;
class QPushButton;
class QSpinBox;

class SPNSpraySerialWindow : public QWidget {
    Q_OBJECT
public:
    explicit SPNSpraySerialWindow(QWidget *parent = nullptr);

private slots:
    void startSpray();
    void cancelSpray();

private:
    bool trySPNLogin(const QString &clientId, const QString &clientSecret, const QString &tenant, QString &errOut);
    QStringList readLinesFromFile(const QString &path);
    void log(const QString &s);
    void setSprayRunning(bool running);

    QNetworkAccessManager *net;
    QLineEdit *tenantEdit;
    QLineEdit *clientFileEdit;
    QLineEdit *passwordFileEdit;
    QLineEdit *singleClientEdit;
    QLineEdit *singlePasswordEdit;
    QPushButton *startButton;
    QPushButton *cancelButton;
    QSpinBox *delaySpinBox;
    QTextEdit *output;
    bool cancelRequested = false;
    bool sprayRunning = false;
};
