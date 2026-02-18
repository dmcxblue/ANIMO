#include "CommandLineEdit.h"
#include <QStringListModel>
#include <QDebug>

CommandLineEdit::CommandLineEdit(QWidget *parent)
    : QLineEdit(parent),
      historyIndex(-1),
      reverseSearchMode(false),
      searchIndex(-1),
      completer(nullptr)
{
    // Set up auto-completion
    completer = new QCompleter(this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    completer->setCompletionMode(QCompleter::PopupCompletion);
    setCompleter(completer);
}

void CommandLineEdit::addToHistory(const QString &command)
{
    if (command.trimmed().isEmpty()) return;

    // Remove duplicate if exists
    commandHistory.removeAll(command);

    // Add to end (most recent)
    commandHistory.append(command);

    // Limit history size to 1000 commands
    if (commandHistory.size() > 1000) {
        commandHistory.removeFirst();
    }

    // Reset history navigation
    historyIndex = -1;
    currentCommand.clear();
}

void CommandLineEdit::loadHistory(const QStringList &history)
{
    commandHistory = history;
    historyIndex = -1;
}

void CommandLineEdit::clearHistory()
{
    commandHistory.clear();
    historyIndex = -1;
    currentCommand.clear();
}

void CommandLineEdit::setCompletionList(const QStringList &completions)
{
    if (completer) {
        completer->setModel(new QStringListModel(completions, completer));
    }
}

void CommandLineEdit::keyPressEvent(QKeyEvent *event)
{
    // Handle reverse search mode
    if (reverseSearchMode) {
        if (event->key() == Qt::Key_Escape) {
            exitReverseSearch();
            return;
        } else if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
            exitReverseSearch();
            QLineEdit::keyPressEvent(event);
            return;
        } else if (event->key() == Qt::Key_Backspace) {
            if (!searchPattern.isEmpty()) {
                searchPattern.chop(1);
                searchHistoryBackward();
            }
            return;
        } else if (event->key() == Qt::Key_R && (event->modifiers() & Qt::ControlModifier)) {
            // Continue searching backward
            searchIndex--;
            searchHistoryBackward();
            return;
        } else if (event->text().length() > 0 && event->text()[0].isPrint()) {
            searchPattern += event->text();
            searchHistoryBackward();
            return;
        }
    }

    // Ctrl+R: Reverse search
    if (event->key() == Qt::Key_R && (event->modifiers() & Qt::ControlModifier)) {
        reverseSearchMode = true;
        searchPattern.clear();
        searchIndex = commandHistory.size() - 1;
        setPlaceholderText("(reverse-i-search)`': ");
        return;
    }

    // Up arrow: Previous command
    if (event->key() == Qt::Key_Up) {
        navigateHistory(-1);
        return;
    }

    // Down arrow: Next command
    if (event->key() == Qt::Key_Down) {
        navigateHistory(1);
        return;
    }

    // Default behavior
    QLineEdit::keyPressEvent(event);
}

void CommandLineEdit::navigateHistory(int direction)
{
    if (commandHistory.isEmpty()) return;

    // Store current command if starting history navigation
    if (historyIndex == -1) {
        currentCommand = text();
    }

    // Calculate new index
    int newIndex = historyIndex + direction;

    // Going up (backward in history)
    if (direction < 0) {
        if (historyIndex == -1) {
            // Start from most recent
            newIndex = commandHistory.size() - 1;
        } else if (newIndex < 0) {
            // Already at oldest, stay there
            return;
        }
    }
    // Going down (forward in history)
    else {
        if (newIndex >= 0 && newIndex < commandHistory.size()) {
            // Valid history entry
        } else {
            // Restore current command
            setText(currentCommand);
            historyIndex = -1;
            return;
        }
    }

    // Update index and display command
    historyIndex = newIndex;
    if (historyIndex >= 0 && historyIndex < commandHistory.size()) {
        setText(commandHistory[historyIndex]);
    }
}

void CommandLineEdit::searchHistoryBackward()
{
    if (commandHistory.isEmpty()) return;

    // Search backward from current index
    for (int i = searchIndex; i >= 0; i--) {
        if (commandHistory[i].contains(searchPattern, Qt::CaseInsensitive)) {
            setText(commandHistory[i]);
            setPlaceholderText(QString("(reverse-i-search)`%1': %2").arg(searchPattern, commandHistory[i]));
            searchIndex = i;
            return;
        }
    }

    // No match found
    setPlaceholderText(QString("(failed reverse-i-search)`%1': ").arg(searchPattern));
}

void CommandLineEdit::exitReverseSearch()
{
    reverseSearchMode = false;
    searchPattern.clear();
    searchIndex = -1;
    setPlaceholderText("Run Custom Command (AzureAD, Az, MSGraph)");
}

void CommandLineEdit::onReverseSearch()
{
    // Slot for future menu integration
    reverseSearchMode = true;
    searchPattern.clear();
    searchIndex = commandHistory.size() - 1;
    setPlaceholderText("(reverse-i-search)`': ");
}
