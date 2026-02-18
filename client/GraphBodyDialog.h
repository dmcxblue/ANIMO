#pragma once
#include <QDialog>

class QTextEdit;
class QPushButton;

class GraphBodyDialog : public QDialog {
    Q_OBJECT
public:
    explicit GraphBodyDialog(QWidget* parent = nullptr);
    QString bodyText() const;

private:
    QTextEdit* m_edit;
    QPushButton* m_ok;
    QPushButton* m_cancel;
};
