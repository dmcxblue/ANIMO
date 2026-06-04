#ifndef GATHERALLWINDOW_H
#define GATHERALLWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTableWidget>
#include <QComboBox>
#include <QJsonObject>

class GatherAllWindow : public EnumerationWindowBase
{
    Q_OBJECT

public:
    explicit GatherAllWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;

private slots:
    void startGather();
    void exportAll();

private:
    struct Endpoint {
        QString name;
        QString url;
        bool useBeta;
    };

    void setupUi();
    void fetchNextEndpoint();
    void processResponse(const QString &name, const QJsonObject &response);
    void saveEndpointData(const QString &name, const QJsonArray &data);

    QPushButton *gatherBtn;
    QPushButton *exportBtn;
    QTableWidget *summaryTable;
    QComboBox *exportFormatCombo;

    QList<Endpoint> endpoints;
    int currentEndpointIndex;
    QMap<QString, QJsonArray> collectedData;
    QString exportDir;
};

#endif // GATHERALLWINDOW_H
