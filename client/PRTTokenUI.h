#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QJsonObject>
#include "PRTTokenExchanger.h"

class ClientIdSelector;

class PRTTokenUI : public QWidget {
    Q_OBJECT
public:
    PRTTokenUI(QWidget *parent = nullptr);

private slots:
    void performExchange();
    void handleResult(const QJsonObject &obj);
    void handleError(const QString &err);

private:
    void logTokenToServer(const QString &accessToken, const QString &refreshToken);
    QString b64UrlDecodeToJsonField(const QString &jwtToken, const QString &field);
    QObject* locateTransport();

    ClientIdSelector *clientId;
    QLineEdit *tenant;
    QLineEdit *resource;
    QTextEdit *prtToken;
    QTextEdit *output;
};
