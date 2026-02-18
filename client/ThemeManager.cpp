#include "ThemeManager.h"
#include <QPalette>
#include <QColor>
#include <QStyleFactory>

void ThemeManager::applyLight(QApplication &app) {
    app.setStyle(QStyleFactory::create("Fusion"));
    QPalette lightPalette;
    lightPalette.setColor(QPalette::Window, QColor(245, 245, 247));
    lightPalette.setColor(QPalette::WindowText, QColor(20, 20, 20));
    lightPalette.setColor(QPalette::Base, QColor(255, 255, 255));
    lightPalette.setColor(QPalette::AlternateBase, QColor(245, 245, 247));
    lightPalette.setColor(QPalette::ToolTipBase, QColor(255, 255, 255));
    lightPalette.setColor(QPalette::ToolTipText, QColor(20, 20, 20));
    lightPalette.setColor(QPalette::Text, QColor(20, 20, 20));
    lightPalette.setColor(QPalette::Button, QColor(240, 240, 240));
    lightPalette.setColor(QPalette::ButtonText, QColor(20, 20, 20));
    lightPalette.setColor(QPalette::Highlight, QColor(0, 122, 255));
    lightPalette.setColor(QPalette::HighlightedText, Qt::white);
    app.setPalette(lightPalette);
}

void ThemeManager::applyDark(QApplication &app) {
    app.setStyle(QStyleFactory::create("Fusion"));
    QPalette darkPalette;
    darkPalette.setColor(QPalette::Window, QColor(28, 28, 30));
    darkPalette.setColor(QPalette::WindowText, Qt::white);
    darkPalette.setColor(QPalette::Base, QColor(44, 44, 46));
    darkPalette.setColor(QPalette::AlternateBase, QColor(28, 28, 30));
    darkPalette.setColor(QPalette::ToolTipBase, QColor(44, 44, 46));
    darkPalette.setColor(QPalette::ToolTipText, Qt::white);
    darkPalette.setColor(QPalette::Text, Qt::white);
    darkPalette.setColor(QPalette::Button, QColor(58, 58, 60));
    darkPalette.setColor(QPalette::ButtonText, Qt::white);
    darkPalette.setColor(QPalette::Highlight, QColor(10, 132, 255));
    darkPalette.setColor(QPalette::HighlightedText, Qt::black);
    app.setPalette(darkPalette);
}
