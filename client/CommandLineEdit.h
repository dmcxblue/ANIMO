#pragma once

#include <QLineEdit>
#include <QStringList>
#include <QKeyEvent>
#include <QCompleter>

class CommandLineEdit : public QLineEdit {
    Q_OBJECT

public:
    explicit CommandLineEdit(QWidget *parent = nullptr);

    // History management
    void addToHistory(const QString &command);
    void loadHistory(const QStringList &history);
    QStringList getHistory() const { return commandHistory; }
    void clearHistory();

    // Auto-completion
    void setCompletionList(const QStringList &completions);

protected:
    void keyPressEvent(QKeyEvent *event) override;

private slots:
    void onReverseSearch();

private:
    QStringList commandHistory;
    int historyIndex;
    QString currentCommand;  // Store current input when navigating history

    // Reverse search (Ctrl+R)
    bool reverseSearchMode;
    QString searchPattern;
    int searchIndex;

    // Auto-completion
    QCompleter *completer;

    void navigateHistory(int direction);
    void searchHistoryBackward();
    void exitReverseSearch();
};
