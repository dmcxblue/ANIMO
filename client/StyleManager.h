#ifndef STYLEMANAGER_H
#define STYLEMANAGER_H

#include <QString>
#include <QPushButton>

/**
 * Centralized style definitions for consistent UI across all windows.
 * Use these methods instead of inline stylesheets to ensure consistency.
 */
class StyleManager {
public:
    // Button styles
    static QString primaryButtonStyle();      // Main action buttons (blue)
    static QString successButtonStyle();      // Positive actions (green)
    static QString dangerButtonStyle();       // Destructive/cancel actions (red)
    static QString warningButtonStyle();      // Warning actions (orange/yellow)
    static QString secondaryButtonStyle();    // Secondary actions (gray)

    // Convenience methods to apply styles directly
    static void applyPrimaryStyle(QPushButton *btn);
    static void applySuccessStyle(QPushButton *btn);
    static void applyDangerStyle(QPushButton *btn);
    static void applyWarningStyle(QPushButton *btn);
    static void applySecondaryStyle(QPushButton *btn);

    // Common UI element styles
    static QString tokenStatusReadyStyle();
    static QString tokenStatusEmptyStyle();
    static QString tokenStatusExpiredStyle();
    static QString logInfoStyle();
    static QString logSuccessStyle();
    static QString logWarningStyle();
    static QString logErrorStyle();
    static QString infoBannerStyle();
    static QString permissionNoteStyle();

    // Table row highlight colors
    static QString vulnerableRowBackground();
    static QString protectedRowBackground();
    static QString highlightRowBackground();
};

#endif // STYLEMANAGER_H
