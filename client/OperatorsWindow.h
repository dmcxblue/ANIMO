#ifndef OPERATORSWINDOW_H
#define OPERATORSWINDOW_H

#include <QWidget>
#include <QJsonArray>

class QTableWidget;
class QLabel;

// Operator roster - one row per operator that has ever logged into this server,
// with an "online" flag for who's connected right now. Backed by the
// list_operators action (audit_log's login rows joined against the live socket
// table). Companion to the Activity Log; that one is a firehose, this one is
// a phone book.
class OperatorsWindow : public QWidget {
    Q_OBJECT
public:
    explicit OperatorsWindow(QWidget *parent = nullptr);

private slots:
    void refresh();

private:
    QObject *locateTransport() const;
    void populate(const QJsonArray &rows);

    QTableWidget *table_;
    QLabel *statusLabel_;
};

#endif // OPERATORSWINDOW_H
