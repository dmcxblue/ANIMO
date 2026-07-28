#ifndef ACTIVITYWINDOW_H
#define ACTIVITYWINDOW_H

#include <QWidget>
#include <QJsonArray>

class QTableWidget;
class QLineEdit;
class QLabel;

// Operator activity log - a unified "who did what, when" timeline backed by the
// server's audit_log table (fetched via the "get_audit" action).
class ActivityWindow : public QWidget {
    Q_OBJECT
public:
    explicit ActivityWindow(QWidget *parent = nullptr);

private slots:
    void refresh();

private:
    QObject *locateTransport() const;
    void applyFilter();
    void populate(const QJsonArray &rows);

    QTableWidget *table_;
    QLineEdit *filterEdit_;
    QLabel *statusLabel_;
    QJsonArray rows_;   // last fetched, unfiltered
};

#endif // ACTIVITYWINDOW_H
