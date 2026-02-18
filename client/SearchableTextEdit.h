#ifndef SEARCHABLE_TEXT_EDIT_H
#define SEARCHABLE_TEXT_EDIT_H

#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QShortcut>
#include <QHBoxLayout>
#include <QVBoxLayout>

/**
 * QTextEdit with built-in Ctrl+F search functionality
 * Shows a search bar when Ctrl+F is pressed
 */
class SearchableTextEdit : public QWidget {
    Q_OBJECT

public:
    explicit SearchableTextEdit(QWidget *parent = nullptr);

    // Access the underlying text edit
    QTextEdit* textEdit() const { return m_textEdit; }

    // Convenience methods that forward to QTextEdit
    void setReadOnly(bool ro) { m_textEdit->setReadOnly(ro); }
    void setFont(const QFont &font) { m_textEdit->setFont(font); }
    void append(const QString &text) { m_textEdit->append(text); }
    void clear() { m_textEdit->clear(); }
    QString toPlainText() const { return m_textEdit->toPlainText(); }
    void setPlainText(const QString &text) { m_textEdit->setPlainText(text); }
    void setHtml(const QString &html) { m_textEdit->setHtml(html); }
    QTextDocument* document() const { return m_textEdit->document(); }
    void moveCursor(QTextCursor::MoveOperation op) { m_textEdit->moveCursor(op); }
    void ensureCursorVisible() { m_textEdit->ensureCursorVisible(); }

public slots:
    void showSearchBar();
    void hideSearchBar();
    void toggleSearchBar();

private slots:
    void findNext();
    void findPrevious();
    void onSearchTextChanged(const QString &text);

private:
    void highlightAllMatches(const QString &searchText);
    void clearHighlights();

    QTextEdit *m_textEdit;
    QWidget *m_searchBar;
    QLineEdit *m_searchInput;
    QPushButton *m_prevButton;
    QPushButton *m_nextButton;
    QPushButton *m_closeButton;
    QLabel *m_matchLabel;

    QShortcut *m_findShortcut;
    QShortcut *m_escShortcut;

    int m_currentMatch = 0;
    int m_totalMatches = 0;
};

#endif // SEARCHABLE_TEXT_EDIT_H
