#include "OperatorsWindow.h"
#include "network/ClientTransport.h"
#include "StyleManager.h"
#include "TablePlaceholder.h"
#include "../shared/Protocol.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QApplication>
#include <QJsonObject>
#include <QFont>

OperatorsWindow::OperatorsWindow(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Operators");
    resize(760, 420);

    auto *layout = new QVBoxLayout(this);

    auto *top = new QHBoxLayout();
    top->addWidget(new QLabel("Operators seen on this server (online + historical)", this));
    top->addStretch();
    auto *refreshBtn = new QPushButton("Refresh", this);
    StyleManager::applyPrimaryStyle(refreshBtn);
    connect(refreshBtn, &QPushButton::clicked, this, &OperatorsWindow::refresh);
    top->addWidget(refreshBtn);
    layout->addLayout(top);

    table_ = new QTableWidget(0, 5, this);
    table_->setHorizontalHeaderLabels({"Operator", "Online", "First seen (UTC)", "Last seen (UTC)", "Logins"});
    table_->horizontalHeader()->setStretchLastSection(false);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->setSortingEnabled(true);
    new TablePlaceholder(table_, "No operators known yet - click Refresh.");
    layout->addWidget(table_);

    statusLabel_ = new QLabel(this);
    statusLabel_->setStyleSheet("color: #888;");
    layout->addWidget(statusLabel_);

    // Populate whenever a list_operators response arrives.
    if (auto *t = qobject_cast<ClientTransport*>(locateTransport())) {
        connect(t, &ClientTransport::messageReceived, this, [this](const QJsonObject &obj) {
            if (obj.contains("operators")) {
                populate(obj.value("operators").toArray());
            }
        });
    }

    refresh();
}

QObject *OperatorsWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void OperatorsWindow::refresh() {
    QObject *t = locateTransport();
    if (!t) { statusLabel_->setText("Not connected to server."); return; }

    QJsonObject req;
    req.insert(Protocol::F_ACTION, QString::fromLatin1(Protocol::ACTION_LIST_OPERATORS));
    if (auto *typed = qobject_cast<ClientTransport*>(t)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(t, "sendJson", Q_ARG(QJsonObject, req));
    }
}

void OperatorsWindow::populate(const QJsonArray &rows) {
    // Sorting must be off during bulk insertion or the row indices swap
    // underneath us and the wrong cells get their fonts/colors applied.
    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    int onlineCount = 0;
    for (const QJsonValue &v : rows) {
        const QJsonObject o = v.toObject();
        const QString op    = o.value("operator").toString();
        const bool online   = o.value("online").toBool();
        const int r = table_->rowCount();
        table_->insertRow(r);

        // Operator: stable per-operator color + bold, matching the Activity Log
        // and the top-right operator chip.
        auto *opItem = new QTableWidgetItem(op);
        opItem->setForeground(StyleManager::colorForOperator(op));
        QFont f = opItem->font(); f.setBold(true); opItem->setFont(f);
        opItem->setToolTip(o.value("lastIp").toString().isEmpty()
                               ? QString()
                               : QString("Last IP: %1").arg(o.value("lastIp").toString()));
        table_->setItem(r, 0, opItem);

        auto *onlineItem = new QTableWidgetItem(online ? QStringLiteral("● online")
                                                       : QStringLiteral("○ offline"));
        onlineItem->setForeground(online ? QColor("#4caf50") : QColor("#888"));
        table_->setItem(r, 1, onlineItem);

        table_->setItem(r, 2, new QTableWidgetItem(o.value("firstSeen").toString()));
        table_->setItem(r, 3, new QTableWidgetItem(o.value("lastSeen").toString()));

        auto *loginsItem = new QTableWidgetItem();
        // Numeric sort: setData with a real int, not a string.
        loginsItem->setData(Qt::DisplayRole, o.value("loginCount").toInt());
        table_->setItem(r, 4, loginsItem);

        if (online) ++onlineCount;
    }
    table_->resizeColumnsToContents();
    table_->setSortingEnabled(true);
    // Default sort: Last seen desc, so freshly-active operators bubble up.
    table_->sortByColumn(3, Qt::DescendingOrder);

    statusLabel_->setText(QString("%1 operator(s), %2 online").arg(rows.size()).arg(onlineCount));
}
