#ifndef TABLEPLACEHOLDER_H
#define TABLEPLACEHOLDER_H

#include <QObject>
#include <QString>

class QAbstractItemView;
class QLabel;
class QEvent;

// Shows a centered placeholder message over an item view while it has no rows,
// so the user can tell "empty result" apart from "still loading". Attach one to a
// table after constructing it:
//     new TablePlaceholder(resultsTable, "No results.");
// It parents itself to the view and updates automatically as rows come and go.
class TablePlaceholder : public QObject
{
    Q_OBJECT
public:
    TablePlaceholder(QAbstractItemView *view, const QString &text);
    void setText(const QString &text);

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    void refresh();      // toggle visibility from the model's row count
    void reposition();   // keep the label filling the viewport

    QAbstractItemView *m_view;
    QLabel *m_label;
};

#endif // TABLEPLACEHOLDER_H
