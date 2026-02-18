#pragma once
#include <QThread>
#include <QStringList>
#include <QColor>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QMutex>

class SprayWorker : public QThread {
    Q_OBJECT

public:
    SprayWorker(const QStringList& users, const QString& password, int delayMs = 0, QObject* parent = nullptr);

    void stop();
    void setDelay(int delayMs);

signals:
    void progress(const QString& text, QColor color);
    void finished();

protected:
    void run() override;

private:
    QStringList users;
    QString password;
    int delayMs;
    bool stopFlag;
    QMutex stopMutex;
};
