#ifndef WINDOWHELPER_H
#define WINDOWHELPER_H

#include <QWidget>
#include <QScreen>
#include <QApplication>
#include <QSettings>
#include <QStyle>
#include <QTimer>

#include "WindowStatePersister.h"

/**
 * @brief WindowHelper - Utility class for window positioning and geometry management
 *
 * Provides consistent window centering, geometry save/restore, and proper
 * window sizing across different screen resolutions and multi-monitor setups.
 */
class WindowHelper
{
public:
    /**
     * @brief Center a window on its parent widget or primary screen
     * @param window The window to center
     * @param parent Optional parent widget to center on (uses screen if null)
     */
    static void centerOnParent(QWidget *window, QWidget *parent = nullptr)
    {
        if (!window) return;

        QRect targetRect;

        if (parent && parent->isVisible()) {
            // Center on parent widget
            targetRect = parent->frameGeometry();
        } else {
            // Center on screen
            QScreen *screen = nullptr;
            if (parent) {
                screen = parent->screen();
            }
            if (!screen) {
                screen = QApplication::primaryScreen();
            }
            if (screen) {
                targetRect = screen->availableGeometry();
            }
        }

        if (targetRect.isValid()) {
            QRect aligned = QStyle::alignedRect(
                Qt::LeftToRight,
                Qt::AlignCenter,
                window->size(),
                targetRect
            );
            window->move(aligned.topLeft());
        }
    }

    /**
     * @brief Center window on screen with optional delayed positioning
     * @param window The window to center
     * @param delayMs Milliseconds to wait before centering (allows layout to finalize)
     */
    static void centerOnScreen(QWidget *window, int delayMs = 0)
    {
        if (!window) return;

        auto doCenter = [window]() {
            QScreen *screen = window->screen();
            if (!screen) {
                screen = QApplication::primaryScreen();
            }
            if (!screen) return;

            const QRect screenRect = screen->availableGeometry();
            const QRect aligned = QStyle::alignedRect(
                Qt::LeftToRight,
                Qt::AlignCenter,
                window->size(),
                screenRect
            );
            window->move(aligned.topLeft());
        };

        if (delayMs > 0) {
            QTimer::singleShot(delayMs, window, doCenter);
        } else {
            doCenter();
        }
    }

    /**
     * @brief Setup a window with standard configuration and centering
     * @param window The window to setup
     * @param parent Parent widget for centering reference
     * @param width Desired width (0 = keep current)
     * @param height Desired height (0 = keep current)
     * @param minWidth Minimum width (0 = no minimum)
     * @param minHeight Minimum height (0 = no minimum)
     * @param persistGeometry Remember size/position across sessions (keyed by class name)
     */
    static void setupWindow(QWidget *window, QWidget *parent = nullptr,
                            int width = 0, int height = 0,
                            int minWidth = 0, int minHeight = 0,
                            bool persistGeometry = true)
    {
        if (!window) return;

        // Set minimum size if specified
        if (minWidth > 0 && minHeight > 0) {
            window->setMinimumSize(minWidth, minHeight);
        }

        // Delete on close
        window->setAttribute(Qt::WA_DeleteOnClose);

        // Remember size/position per window type. If we have a saved geometry it wins
        // over the default resize+center below, so windows reopen where they were left.
        bool restored = false;
        if (persistGeometry) {
            const QString key = QString::fromLatin1(window->metaObject()->className());
            new WindowStatePersister(window, key);  // parented to window; saves on close
            restored = restoreGeometry(window, key);
        }

        if (!restored) {
            // Resize if dimensions specified
            if (width > 0 && height > 0) {
                window->resize(width, height);
            }

            // Center after layout finishes
            QTimer::singleShot(0, window, [window, parent]() {
                centerOnParent(window, parent);
            });
        }
    }

    /**
     * @brief Save window geometry to settings
     * @param window The window to save
     * @param windowName Unique name for settings key
     */
    static void saveGeometry(QWidget *window, const QString &windowName)
    {
        if (!window || windowName.isEmpty()) return;

        QSettings settings("ANIMO", "AnimoClient");
        settings.beginGroup("WindowGeometry");
        settings.setValue(windowName + "_geometry", window->saveGeometry());
        settings.setValue(windowName + "_pos", window->pos());
        settings.setValue(windowName + "_size", window->size());
        settings.endGroup();
    }

    /**
     * @brief Restore window geometry from settings
     * @param window The window to restore
     * @param windowName Unique name for settings key
     * @return true if geometry was restored, false if no saved geometry
     */
    static bool restoreGeometry(QWidget *window, const QString &windowName)
    {
        if (!window || windowName.isEmpty()) return false;

        QSettings settings("ANIMO", "AnimoClient");
        settings.beginGroup("WindowGeometry");

        QByteArray geometry = settings.value(windowName + "_geometry").toByteArray();
        if (!geometry.isEmpty()) {
            bool restored = window->restoreGeometry(geometry);
            settings.endGroup();

            if (restored) {
                // Un-maximize. `QWidget::saveGeometry` serialises the maximized
                // flag, and once a plugin window has been maximized (or opened
                // from a persisted state that came from a bigger screen) every
                // subsequent open of that class of window comes up eating the
                // whole screen. Operators want their normal-mode size back.
                if (window->isMaximized() || (window->windowState() & Qt::WindowMaximized)) {
                    window->setWindowState(window->windowState() & ~Qt::WindowMaximized);
                }
                // Clamp size to at most 90% of the current screen so a
                // multi-monitor state persisted on a 4K panel doesn't render
                // the window unusable on a 1080p laptop.
                QScreen *screen = window->screen();
                if (!screen) screen = QApplication::primaryScreen();
                if (screen) {
                    const QRect avail = screen->availableGeometry();
                    const int maxW = int(avail.width()  * 0.90);
                    const int maxH = int(avail.height() * 0.90);
                    const QSize s = window->size();
                    if (s.width() > maxW || s.height() > maxH) {
                        window->resize(qMin(s.width(), maxW), qMin(s.height(), maxH));
                    }
                }
                ensureOnScreen(window);
            }
            return restored;
        }

        settings.endGroup();
        return false;
    }

    /**
     * @brief Ensure window is visible on at least one screen
     * @param window The window to check
     */
    static void ensureOnScreen(QWidget *window)
    {
        if (!window) return;

        QRect windowRect = window->frameGeometry();
        bool onScreen = false;

        // Check if window intersects any available screen
        for (QScreen *screen : QApplication::screens()) {
            if (screen->availableGeometry().intersects(windowRect)) {
                onScreen = true;
                break;
            }
        }

        // If not on any screen, center on primary screen
        if (!onScreen) {
            centerOnScreen(window);
        }
    }

    /**
     * @brief Show a dialog centered on parent
     * @param dialog The dialog widget
     * @param parent Parent widget for centering
     */
    static void showCentered(QWidget *dialog, QWidget *parent = nullptr)
    {
        if (!dialog) return;

        dialog->setAttribute(Qt::WA_DeleteOnClose);

        // Use singleShot to ensure size is computed before centering
        QTimer::singleShot(0, dialog, [dialog, parent]() {
            centerOnParent(dialog, parent);
        });

        dialog->show();
    }
};

#endif // WINDOWHELPER_H
