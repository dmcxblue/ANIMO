#ifndef WINDOWSTATEPERSISTER_H
#define WINDOWSTATEPERSISTER_H

#include <QObject>
#include <QString>

class QWidget;
class QEvent;

// Saves a window's geometry when it closes, under a settings key. Parent it to
// the window (done automatically) so it is cleaned up with the window. Installed
// by WindowHelper::setupWindow(), so plugin windows reopen where they were left.
class WindowStatePersister : public QObject
{
    Q_OBJECT
public:
    WindowStatePersister(QWidget *window, const QString &key);

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    QWidget *m_window;
    QString m_key;
};

#endif // WINDOWSTATEPERSISTER_H
