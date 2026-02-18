#include "SessionTimelineWindow.h"
#include "TokenStore.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QFileDialog>
#include <QTextStream>
#include <QMessageBox>

SessionTimelineWindow::SessionTimelineWindow(QWidget *parent)
    : QWidget(parent)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Session Timeline");
    resize(1000, 600);

    auto *mainLayout = new QVBoxLayout(this);

    // Controls row
    auto *controlsRow = new QHBoxLayout();

    controlsRow->addWidget(new QLabel("Filter:"));
    filterCombo = new QComboBox();
    filterCombo->addItems({"All Events", "Session Created", "Token Issued", "Token Expired", "Activity"});
    controlsRow->addWidget(filterCombo);

    controlsRow->addStretch();

    btnRefresh = new QPushButton("Refresh");
    btnExport = new QPushButton("Export CSV");
    controlsRow->addWidget(btnRefresh);
    controlsRow->addWidget(btnExport);

    mainLayout->addLayout(controlsRow);

    // Timeline table
    timelineTable = new QTableWidget();
    timelineTable->setColumnCount(5);
    timelineTable->setHorizontalHeaderLabels({"Time", "Session", "Event", "Description", "Details"});
    timelineTable->horizontalHeader()->setStretchLastSection(true);
    timelineTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    timelineTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    timelineTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    timelineTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    timelineTable->setAlternatingRowColors(true);
    timelineTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    timelineTable->setSortingEnabled(true);
    mainLayout->addWidget(timelineTable);

    // Connections
    connect(btnRefresh, &QPushButton::clicked, this, &SessionTimelineWindow::refreshTimeline);
    connect(btnExport, &QPushButton::clicked, this, &SessionTimelineWindow::exportTimeline);
    connect(filterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SessionTimelineWindow::filterEvents);

    // Initial load
    loadSessionData();
}

void SessionTimelineWindow::addEvent(const TimelineEvent &event)
{
    events.append(event);
}

void SessionTimelineWindow::loadSessionData()
{
    events.clear();

    // Load from TokenStore
    TokenStore *store = TokenStore::instance();
    QList<TokenInfo> tokens = store->getAllTokens();

    for (const TokenInfo &token : tokens) {
        // Token issued event
        if (token.issuedAt.isValid()) {
            TimelineEvent issued;
            issued.timestamp = token.issuedAt;
            issued.sessionId = token.sessionId.left(8) + "...";
            issued.eventType = "token_issued";
            issued.description = "Token issued for " + token.resource;
            issued.details = token.upn.isEmpty() ? "N/A" : token.upn;
            events.append(issued);
        }

        // Token expiry event
        if (token.expiresAt.isValid()) {
            TimelineEvent expiry;
            expiry.timestamp = token.expiresAt;
            expiry.sessionId = token.sessionId.left(8) + "...";
            expiry.eventType = token.isExpired() ? "token_expired" : "token_expiring";
            expiry.description = token.isExpired() ? "Token expired" : "Token will expire";
            expiry.details = token.resource;
            events.append(expiry);
        }
    }

    // Sort by timestamp
    std::sort(events.begin(), events.end(), [](const TimelineEvent &a, const TimelineEvent &b) {
        return a.timestamp < b.timestamp;
    });

    populateTable();
}

void SessionTimelineWindow::refreshTimeline()
{
    loadSessionData();
}

void SessionTimelineWindow::filterEvents()
{
    populateTable();
}

void SessionTimelineWindow::populateTable()
{
    timelineTable->setRowCount(0);
    timelineTable->setSortingEnabled(false);

    QString filter = filterCombo->currentText();

    for (const TimelineEvent &event : events) {
        // Apply filter
        if (filter != "All Events") {
            if (filter == "Session Created" && event.eventType != "session_created") continue;
            if (filter == "Token Issued" && event.eventType != "token_issued") continue;
            if (filter == "Token Expired" && !event.eventType.contains("expired")) continue;
            if (filter == "Activity" && event.eventType != "activity") continue;
        }

        int row = timelineTable->rowCount();
        timelineTable->insertRow(row);

        // Time column
        auto *timeItem = new QTableWidgetItem(event.timestamp.toString("yyyy-MM-dd hh:mm:ss"));
        timelineTable->setItem(row, 0, timeItem);

        // Session column
        auto *sessionItem = new QTableWidgetItem(event.sessionId);
        timelineTable->setItem(row, 1, sessionItem);

        // Event type column with icon
        QString eventDisplay = eventTypeIcon(event.eventType) + " " + event.eventType;
        auto *eventItem = new QTableWidgetItem(eventDisplay);

        // Color code by event type
        if (event.eventType == "token_expired") {
            eventItem->setForeground(QColor(220, 53, 69));  // Red
        } else if (event.eventType == "token_expiring") {
            eventItem->setForeground(QColor(255, 193, 7));  // Yellow
        } else if (event.eventType == "token_issued") {
            eventItem->setForeground(QColor(40, 167, 69));  // Green
        }
        timelineTable->setItem(row, 2, eventItem);

        // Description column
        auto *descItem = new QTableWidgetItem(event.description);
        timelineTable->setItem(row, 3, descItem);

        // Details column
        auto *detailsItem = new QTableWidgetItem(event.details);
        timelineTable->setItem(row, 4, detailsItem);
    }

    timelineTable->setSortingEnabled(true);
}

QString SessionTimelineWindow::eventTypeIcon(const QString &type) const
{
    if (type == "session_created") return "[+]";
    if (type == "token_issued") return "[T]";
    if (type == "token_expired") return "[X]";
    if (type == "token_expiring") return "[!]";
    if (type == "activity") return "[>]";
    return "[?]";
}

void SessionTimelineWindow::exportTimeline()
{
    QString filePath = QFileDialog::getSaveFileName(this, "Export Timeline",
        QDir::homePath() + "/timeline_export.csv", "CSV Files (*.csv)");

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "Timestamp,Session,Event Type,Description,Details\n";

    for (const TimelineEvent &event : events) {
        out << "\"" << event.timestamp.toString("yyyy-MM-dd hh:mm:ss") << "\","
            << "\"" << event.sessionId << "\","
            << "\"" << event.eventType << "\","
            << "\"" << event.description << "\","
            << "\"" << event.details << "\"\n";
    }

    file.close();
    QMessageBox::information(this, "Export Complete",
        QString("Exported %1 events to %2").arg(events.size()).arg(filePath));
}
