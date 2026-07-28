#include "ActivityWindow.h"
#include "ClientTransport.h"
#include "StyleManager.h"
#include "TablePlaceholder.h"
#include "../shared/Protocol.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QApplication>
#include <QJsonObject>
#include <QFont>

ActivityWindow::ActivityWindow(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Operator Activity Log");
    resize(950, 600);

    auto *layout = new QVBoxLayout(this);

    auto *top = new QHBoxLayout();
    top->addWidget(new QLabel("Filter by operator:", this));
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText("(all operators)");
    connect(filterEdit_, &QLineEdit::textChanged, this, &ActivityWindow::applyFilter);
    top->addWidget(filterEdit_);

    auto *refreshBtn = new QPushButton("Refresh", this);
    StyleManager::applyPrimaryStyle(refreshBtn);
    connect(refreshBtn, &QPushButton::clicked, this, &ActivityWindow::refresh);
    top->addWidget(refreshBtn);
    layout->addLayout(top);

    table_ = new QTableWidget(0, 5, this);
    table_->setHorizontalHeaderLabels({"Time (UTC)", "Operator", "Action", "Target", "Detail"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    new TablePlaceholder(table_, "No activity yet - click Refresh.");
    layout->addWidget(table_);

    statusLabel_ = new QLabel(this);
    statusLabel_->setStyleSheet("color: #888;");
    layout->addWidget(statusLabel_);

    // Populate whenever an audit response arrives.
    if (auto *t = qobject_cast<ClientTransport*>(locateTransport())) {
        connect(t, &ClientTransport::messageReceived, this, [this](const QJsonObject &obj) {
            if (obj.contains("audit")) {
                rows_ = obj.value("audit").toArray();
                applyFilter();
            }
        });
    }

    refresh();
}

QObject* ActivityWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void ActivityWindow::refresh() {
    QObject *t = locateTransport();
    if (!t) { statusLabel_->setText("Not connected to server."); return; }

    QJsonObject req;
    req.insert(Protocol::F_ACTION, QStringLiteral("get_audit"));
    req.insert("limit", 1000);
    if (auto *typed = qobject_cast<ClientTransport*>(t)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(t, "sendJson", Q_ARG(QJsonObject, req));
    }
}

void ActivityWindow::applyFilter() {
    const QString needle = filterEdit_->text().trimmed().toLower();
    QJsonArray filtered;
    for (const QJsonValue &v : rows_) {
        const QJsonObject o = v.toObject();
        if (needle.isEmpty() || o.value("operator").toString().toLower().contains(needle)) {
            filtered.append(o);
        }
    }
    populate(filtered);
}

void ActivityWindow::populate(const QJsonArray &rows) {
    table_->setRowCount(0);
    for (const QJsonValue &v : rows) {
        const QJsonObject o = v.toObject();
        const QString op     = o.value("operator").toString();
        const QString action = o.value("action").toString();
        const int r = table_->rowCount();
        table_->insertRow(r);

        table_->setItem(r, 0, new QTableWidgetItem(o.value("timestamp").toString()));

        // Operator: stable per-operator color, bold, so "who" is scannable.
        auto *opItem = new QTableWidgetItem(op);
        opItem->setForeground(StyleManager::colorForOperator(op));
        QFont f = opItem->font(); f.setBold(true); opItem->setFont(f);
        table_->setItem(r, 1, opItem);

        // Action: semantic color by category.
        auto *actItem = new QTableWidgetItem(action);
        actItem->setForeground(StyleManager::colorForAuditAction(action));
        table_->setItem(r, 2, actItem);

        table_->setItem(r, 3, new QTableWidgetItem(o.value("target").toString()));
        table_->setItem(r, 4, new QTableWidgetItem(o.value("detail").toString()));
    }
    table_->resizeColumnsToContents();
    statusLabel_->setText(QString("%1 event(s)").arg(rows.size()));
}
