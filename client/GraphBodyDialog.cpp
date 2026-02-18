#include "GraphBodyDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>

GraphBodyDialog::GraphBodyDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("Request Body (JSON)");
    resize(640, 420);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel("Enter JSON body (for POST/PUT/PATCH):", this));

    m_edit = new QTextEdit(this);
    m_edit->setPlaceholderText("{\n  \"sample\": \"value\"\n}");
    m_edit->setAcceptRichText(false);
    layout->addWidget(m_edit, 1);

    auto* btns = new QHBoxLayout();
    btns->addStretch();

    m_ok = new QPushButton("OK", this);
    m_cancel = new QPushButton("Cancel", this);
    btns->addWidget(m_ok);
    btns->addWidget(m_cancel);
    layout->addLayout(btns);

    connect(m_ok, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_cancel, &QPushButton::clicked, this, &QDialog::reject);
}

QString GraphBodyDialog::bodyText() const {
    return m_edit->toPlainText().trimmed();
}
