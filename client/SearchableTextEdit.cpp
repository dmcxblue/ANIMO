#include "SearchableTextEdit.h"
#include <QTextDocument>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QKeySequence>
#include <QApplication>
#include <QPalette>

SearchableTextEdit::SearchableTextEdit(QWidget *parent)
    : QWidget(parent)
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Create the text edit
    m_textEdit = new QTextEdit(this);
    mainLayout->addWidget(m_textEdit);

    // Create the search bar (initially hidden)
    m_searchBar = new QWidget(this);
    m_searchBar->setVisible(false);
    m_searchBar->setStyleSheet(
        "QWidget { background-color: #2d2d2d; border-top: 1px solid #555; padding: 4px; }"
        "QLineEdit { background-color: #3d3d3d; color: white; border: 1px solid #555; padding: 4px; border-radius: 3px; }"
        "QPushButton { background-color: #3d3d3d; color: white; border: 1px solid #555; padding: 4px 8px; border-radius: 3px; }"
        "QPushButton:hover { background-color: #4d4d4d; }"
        "QLabel { color: #aaa; }"
    );

    QHBoxLayout *searchLayout = new QHBoxLayout(m_searchBar);
    searchLayout->setContentsMargins(8, 4, 8, 4);
    searchLayout->setSpacing(8);

    // Search input
    m_searchInput = new QLineEdit(m_searchBar);
    m_searchInput->setPlaceholderText("Search...");
    m_searchInput->setMinimumWidth(200);
    searchLayout->addWidget(m_searchInput);

    // Previous button
    m_prevButton = new QPushButton("<", m_searchBar);
    m_prevButton->setToolTip("Find Previous (Shift+Enter)");
    m_prevButton->setFixedWidth(30);
    searchLayout->addWidget(m_prevButton);

    // Next button
    m_nextButton = new QPushButton(">", m_searchBar);
    m_nextButton->setToolTip("Find Next (Enter)");
    m_nextButton->setFixedWidth(30);
    searchLayout->addWidget(m_nextButton);

    // Match count label
    m_matchLabel = new QLabel("0/0", m_searchBar);
    m_matchLabel->setMinimumWidth(50);
    searchLayout->addWidget(m_matchLabel);

    searchLayout->addStretch();

    // Close button
    m_closeButton = new QPushButton("X", m_searchBar);
    m_closeButton->setToolTip("Close (Esc)");
    m_closeButton->setFixedWidth(30);
    searchLayout->addWidget(m_closeButton);

    mainLayout->addWidget(m_searchBar);

    // Setup shortcuts
    m_findShortcut = new QShortcut(QKeySequence::Find, this);
    connect(m_findShortcut, &QShortcut::activated, this, &SearchableTextEdit::showSearchBar);

    m_escShortcut = new QShortcut(QKeySequence(Qt::Key_Escape), m_searchBar);
    connect(m_escShortcut, &QShortcut::activated, this, &SearchableTextEdit::hideSearchBar);

    // Connect signals
    connect(m_searchInput, &QLineEdit::textChanged, this, &SearchableTextEdit::onSearchTextChanged);
    connect(m_searchInput, &QLineEdit::returnPressed, this, &SearchableTextEdit::findNext);
    connect(m_prevButton, &QPushButton::clicked, this, &SearchableTextEdit::findPrevious);
    connect(m_nextButton, &QPushButton::clicked, this, &SearchableTextEdit::findNext);
    connect(m_closeButton, &QPushButton::clicked, this, &SearchableTextEdit::hideSearchBar);

    // Shift+Enter for find previous
    QShortcut *shiftEnter = new QShortcut(QKeySequence(Qt::SHIFT | Qt::Key_Return), m_searchInput);
    connect(shiftEnter, &QShortcut::activated, this, &SearchableTextEdit::findPrevious);
}

void SearchableTextEdit::showSearchBar() {
    m_searchBar->setVisible(true);
    m_searchInput->setFocus();
    m_searchInput->selectAll();

    // If there's selected text, use it as search term
    QTextCursor cursor = m_textEdit->textCursor();
    if (cursor.hasSelection()) {
        m_searchInput->setText(cursor.selectedText());
    }
}

void SearchableTextEdit::hideSearchBar() {
    m_searchBar->setVisible(false);
    clearHighlights();
    m_textEdit->setFocus();
}

void SearchableTextEdit::toggleSearchBar() {
    if (m_searchBar->isVisible()) {
        hideSearchBar();
    } else {
        showSearchBar();
    }
}

void SearchableTextEdit::onSearchTextChanged(const QString &text) {
    highlightAllMatches(text);

    if (!text.isEmpty() && m_totalMatches > 0) {
        m_currentMatch = 1;
        findNext();
    }
}

void SearchableTextEdit::highlightAllMatches(const QString &searchText) {
    clearHighlights();
    m_totalMatches = 0;
    m_currentMatch = 0;

    if (searchText.isEmpty()) {
        m_matchLabel->setText("0/0");
        return;
    }

    QTextDocument *doc = m_textEdit->document();
    QTextCursor cursor(doc);

    // Highlight format
    QTextCharFormat highlightFormat;
    highlightFormat.setBackground(QColor(255, 255, 0, 100)); // Yellow highlight

    // Find all matches
    while (!cursor.isNull() && !cursor.atEnd()) {
        cursor = doc->find(searchText, cursor, QTextDocument::FindFlags());
        if (!cursor.isNull()) {
            m_totalMatches++;
        }
    }

    m_matchLabel->setText(QString("0/%1").arg(m_totalMatches));
}

void SearchableTextEdit::clearHighlights() {
    // Reset all formatting
    QTextCursor cursor(m_textEdit->document());
    cursor.select(QTextCursor::Document);

    QTextCharFormat format;
    format.setBackground(Qt::transparent);
    cursor.mergeCharFormat(format);
}

void SearchableTextEdit::findNext() {
    QString searchText = m_searchInput->text();
    if (searchText.isEmpty()) return;

    QTextDocument *doc = m_textEdit->document();
    QTextCursor current = m_textEdit->textCursor();

    // Start from current position or beginning
    QTextCursor found = doc->find(searchText, current);

    // Wrap around if not found
    if (found.isNull()) {
        found = doc->find(searchText, 0);
    }

    if (!found.isNull()) {
        // Update current match counter
        m_currentMatch++;
        if (m_currentMatch > m_totalMatches) m_currentMatch = 1;

        // Highlight the found text
        m_textEdit->setTextCursor(found);
        m_textEdit->ensureCursorVisible();

        // Update selection highlight
        QTextCharFormat format;
        format.setBackground(QColor(0, 120, 215)); // Blue selection
        format.setForeground(Qt::white);
        found.mergeCharFormat(format);

        m_matchLabel->setText(QString("%1/%2").arg(m_currentMatch).arg(m_totalMatches));
    }
}

void SearchableTextEdit::findPrevious() {
    QString searchText = m_searchInput->text();
    if (searchText.isEmpty()) return;

    QTextDocument *doc = m_textEdit->document();
    QTextCursor current = m_textEdit->textCursor();

    // Move cursor to start of selection to search backwards
    if (current.hasSelection()) {
        current.setPosition(current.selectionStart());
    }

    // Search backwards
    QTextCursor found = doc->find(searchText, current, QTextDocument::FindBackward);

    // Wrap around if not found
    if (found.isNull()) {
        QTextCursor endCursor(doc);
        endCursor.movePosition(QTextCursor::End);
        found = doc->find(searchText, endCursor, QTextDocument::FindBackward);
    }

    if (!found.isNull()) {
        // Update current match counter
        m_currentMatch--;
        if (m_currentMatch < 1) m_currentMatch = m_totalMatches;

        // Highlight the found text
        m_textEdit->setTextCursor(found);
        m_textEdit->ensureCursorVisible();

        // Update selection highlight
        QTextCharFormat format;
        format.setBackground(QColor(0, 120, 215)); // Blue selection
        format.setForeground(Qt::white);
        found.mergeCharFormat(format);

        m_matchLabel->setText(QString("%1/%2").arg(m_currentMatch).arg(m_totalMatches));
    }
}
