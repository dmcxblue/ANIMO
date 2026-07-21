#include "TablePlaceholder.h"

#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QLabel>
#include <QEvent>

TablePlaceholder::TablePlaceholder(QAbstractItemView *view, const QString &text)
    : QObject(view), m_view(view), m_label(nullptr)
{
    if (!m_view || !m_view->viewport()) {
        return;
    }

    m_label = new QLabel(text, m_view->viewport());
    m_label->setAlignment(Qt::AlignCenter);
    m_label->setStyleSheet("color: #888; font-style: italic;");
    m_label->setAttribute(Qt::WA_TransparentForMouseEvents);
    m_label->setWordWrap(true);

    m_view->viewport()->installEventFilter(this);

    // Re-evaluate whenever the model's row set changes.
    if (auto *model = m_view->model()) {
        connect(model, &QAbstractItemModel::rowsInserted, this, [this]() { refresh(); });
        connect(model, &QAbstractItemModel::rowsRemoved, this, [this]() { refresh(); });
        connect(model, &QAbstractItemModel::modelReset, this, [this]() { refresh(); });
        connect(model, &QAbstractItemModel::layoutChanged, this, [this]() { refresh(); });
    }

    refresh();
}

void TablePlaceholder::setText(const QString &text)
{
    if (m_label) {
        m_label->setText(text);
    }
}

bool TablePlaceholder::eventFilter(QObject *obj, QEvent *event)
{
    if (m_label && obj == m_view->viewport() && event->type() == QEvent::Resize) {
        reposition();
    }
    return QObject::eventFilter(obj, event);
}

void TablePlaceholder::refresh()
{
    if (!m_label) {
        return;
    }
    auto *model = m_view->model();
    const bool empty = !model || model->rowCount() == 0;
    if (empty) {
        reposition();
    }
    m_label->setVisible(empty);
}

void TablePlaceholder::reposition()
{
    if (m_label && m_view->viewport()) {
        m_label->setGeometry(m_view->viewport()->rect());
    }
}
