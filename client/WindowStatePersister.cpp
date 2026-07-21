#include "WindowStatePersister.h"
#include "WindowHelper.h"

#include <QWidget>
#include <QEvent>

WindowStatePersister::WindowStatePersister(QWidget *window, const QString &key)
    : QObject(window), m_window(window), m_key(key)
{
    if (m_window) {
        m_window->installEventFilter(this);
    }
}

bool WindowStatePersister::eventFilter(QObject *obj, QEvent *event)
{
    // Geometry is still valid at Close time; the window deletes shortly after.
    if (obj == m_window && event->type() == QEvent::Close) {
        WindowHelper::saveGeometry(m_window, m_key);
    }
    return QObject::eventFilter(obj, event);
}
