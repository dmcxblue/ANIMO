#ifndef TOKENANALYSISWINDOW_H
#define TOKENANALYSISWINDOW_H

#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QJsonObject>
#include <QDateTime>

/**
 * @brief Token Lifetime Analysis Window
 *
 * Analyzes JWT tokens to display:
 * - Token expiration and lifetime
 * - Claims breakdown
 * - Scope/permissions analysis
 * - Issuer and audience information
 */
class TokenAnalysisWindow : public QWidget {
    Q_OBJECT

public:
    explicit TokenAnalysisWindow(QWidget *parent = nullptr);

    void setToken(const QString &token);

private slots:
    void analyzeToken();
    void clearAnalysis();
    void copyReport();

private:
    void parseAndDisplay(const QString &jwt);
    QJsonObject decodeJwtPayload(const QString &jwt);
    QString formatClaim(const QString &key, const QJsonValue &value);
    QString formatDateTime(qint64 timestamp);
    QString formatDuration(qint64 seconds);

    // UI
    QTextEdit *tokenInput;
    QPushButton *btnAnalyze;
    QPushButton *btnClear;
    QPushButton *btnCopy;
    QTableWidget *claimsTable;
    QTextEdit *summaryOutput;
};

#endif // TOKENANALYSISWINDOW_H
