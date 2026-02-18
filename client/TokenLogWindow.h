#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QLabel>
#include <QSplitter>
#include <QJsonArray>
#include <QJsonObject>

class TokenLogWindow : public QWidget {
    Q_OBJECT

public:
    explicit TokenLogWindow(QWidget *parent = nullptr);

private slots:
    void refreshTokens();
    void onTokenSelected();
    void copyAccessToken();
    void copyRefreshToken();
    void exportTokens();
    void deleteSelectedToken();

private:
    void setupUI();
    void loadTokens();
    void displayTokenDetails(const QJsonObject &token);
    QString parseJWT(const QString &token);
    QString extractJWTClaim(const QString &token, const QString &claim);
    QObject* locateTransport() const;

    // UI Components
    QTableWidget *tokenTable;
    QTextEdit *detailsView;
    QPushButton *refreshBtn;
    QPushButton *copyAccessBtn;
    QPushButton *copyRefreshBtn;
    QPushButton *exportBtn;
    QPushButton *deleteBtn;
    QLabel *statusLabel;

    // Data
    QJsonArray currentTokens;
    QJsonObject selectedToken;
};
