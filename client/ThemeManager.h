#ifndef THEMEMANAGER_H
#define THEMEMANAGER_H

#include <QApplication>

class ThemeManager {
public:
    static void applyLight(QApplication &app);
    static void applyDark(QApplication &app);
};

#endif // THEMEMANAGER_H
