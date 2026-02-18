#ifndef SESSIONTIMELINEWINDOW_H
#define SESSIONTIMELINEWINDOW_H

#include <QWidget>
#include <QTableWidget>
#include <QDateTime>
#include <QList>
#include <QPushButton>
#include <QComboBox>

/**
 * @brief Session Timeline Visualization
 *
 * Displays a timeline view of session activities including:
 * - Session creation times
 * - Token issuance and expiration
 * - Activity timestamps
 */
class SessionTimelineWindow : public QWidget {
    Q_OBJECT

public:
    explicit SessionTimelineWindow(QWidget *parent = nullptr);

    struct TimelineEvent {
        QDateTime timestamp;
        QString sessionId;
        QString eventType;  // "created", "token_issued", "token_expired", "activity"
        QString description;
        QString details;
    };

    void addEvent(const TimelineEvent &event);
    void loadSessionData();

private slots:
    void refreshTimeline();
    void filterEvents();
    void exportTimeline();

private:
    void populateTable();
    QString eventTypeIcon(const QString &type) const;

    QTableWidget *timelineTable;
    QComboBox *filterCombo;
    QPushButton *btnRefresh;
    QPushButton *btnExport;

    QList<TimelineEvent> events;
};

#endif // SESSIONTIMELINEWINDOW_H
