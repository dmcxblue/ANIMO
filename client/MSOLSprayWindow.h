#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QSlider>
#include <QLabel>
#include <QSpinBox>
#include <QFont>
#include "SprayWorker.h"

class MSOLSprayWindow : public QWidget {
    Q_OBJECT

public:
    explicit MSOLSprayWindow(QWidget* parent = nullptr);

private slots:
    void browseUserlist();
    void appendOutput(const QString& text, QColor color);
    void runSpray();
    void stopSpray();
    void cleanupWorker();
    void updateDelayLabel(int value);

private:
    QString userlistPath;
    SprayWorker* worker;

    QLineEdit* fileDisplay;
    QLineEdit* pwdInput;
    QPushButton* btnStart;
    QPushButton* btnStop;
    QTextEdit* output;
    QSlider* delaySlider;
    QLabel* delayLabel;
    QSpinBox* delaySpinBox;
};
