#pragma once
#include <QObject>
#include <QString>
#include <QVariantMap>

class DeviceCodeWorker : public QObject {
    Q_OBJECT
public:
    DeviceCodeWorker(const QString &clientId,
                     const QString &resource,
                     const QString &userAgent,
                     const QString &labelId);

public slots:
    void run();

signals:
    void resultReceived(const QString &labelId, const QVariantMap &result);
    void errorOccurred(const QString &labelId, const QString &message);
    void finished();

private:
    QString clientId;
    QString resource;
    QString userAgent;
    QString labelId;

    QVariantMap postDeviceCodeFlow();
};
