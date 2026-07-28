#include "StyleManager.h"

// ============================================================================
// Button Styles
// ============================================================================

QString StyleManager::primaryButtonStyle() {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: #2d5aa0;"
        "  color: white;"
        "  font-weight: bold;"
        "  padding: 6px 12px;"
        "  border: none;"
        "  border-radius: 3px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #3a6ab8;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #244a88;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #555555;"
        "  color: #888888;"
        "}"
    );
}

QString StyleManager::successButtonStyle() {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: #28a745;"
        "  color: white;"
        "  font-weight: bold;"
        "  padding: 6px 12px;"
        "  border: none;"
        "  border-radius: 3px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #34c759;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #1e7e34;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #555555;"
        "  color: #888888;"
        "}"
    );
}

QString StyleManager::dangerButtonStyle() {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: #dc3545;"
        "  color: white;"
        "  font-weight: bold;"
        "  padding: 6px 12px;"
        "  border: none;"
        "  border-radius: 3px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #e04555;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #bd2130;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #555555;"
        "  color: #888888;"
        "}"
    );
}

QString StyleManager::warningButtonStyle() {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: #ffc107;"
        "  color: #212529;"
        "  font-weight: bold;"
        "  padding: 6px 12px;"
        "  border: none;"
        "  border-radius: 3px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #ffcd38;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #d9a406;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #555555;"
        "  color: #888888;"
        "}"
    );
}

QString StyleManager::secondaryButtonStyle() {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: #6c757d;"
        "  color: white;"
        "  font-weight: bold;"
        "  padding: 6px 12px;"
        "  border: none;"
        "  border-radius: 3px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #7c858d;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #5a6268;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #555555;"
        "  color: #888888;"
        "}"
    );
}

// ============================================================================
// Convenience Methods
// ============================================================================

void StyleManager::applyPrimaryStyle(QPushButton *btn) {
    if (btn) btn->setStyleSheet(primaryButtonStyle());
}

void StyleManager::applySuccessStyle(QPushButton *btn) {
    if (btn) btn->setStyleSheet(successButtonStyle());
}

void StyleManager::applyDangerStyle(QPushButton *btn) {
    if (btn) btn->setStyleSheet(dangerButtonStyle());
}

void StyleManager::applyWarningStyle(QPushButton *btn) {
    if (btn) btn->setStyleSheet(warningButtonStyle());
}

void StyleManager::applySecondaryStyle(QPushButton *btn) {
    if (btn) btn->setStyleSheet(secondaryButtonStyle());
}

// ============================================================================
// Token Status Styles
// ============================================================================

QString StyleManager::tokenStatusReadyStyle() {
    return QStringLiteral("color: #00ff00; font-weight: bold;");
}

QString StyleManager::tokenStatusEmptyStyle() {
    return QStringLiteral("color: gray;");
}

QString StyleManager::tokenStatusExpiredStyle() {
    return QStringLiteral("color: #ff6b6b; font-weight: bold;");
}

// ============================================================================
// Log Message Styles
// ============================================================================

QString StyleManager::logInfoStyle() {
    return QStringLiteral("cyan");
}

QString StyleManager::logSuccessStyle() {
    return QStringLiteral("green");
}

QString StyleManager::logWarningStyle() {
    return QStringLiteral("yellow");
}

QString StyleManager::logErrorStyle() {
    return QStringLiteral("red");
}

// ============================================================================
// UI Element Styles
// ============================================================================

QString StyleManager::infoBannerStyle() {
    return QStringLiteral(
        "color: #ffc107;"
        "padding: 8px;"
        "background: #2a2a2a;"
        "border-radius: 3px;"
    );
}

QString StyleManager::permissionNoteStyle() {
    return QStringLiteral("color: gray; font-size: 10px;");
}

// ============================================================================
// Table Row Colors
// ============================================================================

QString StyleManager::vulnerableRowBackground() {
    return QStringLiteral("#500000");  // Dark red
}

QString StyleManager::protectedRowBackground() {
    return QStringLiteral("#005000");  // Dark green
}

QString StyleManager::highlightRowBackground() {
    return QStringLiteral("#505000");  // Dark yellow
}

// ============================================================================
// Operator / activity coloring
// ============================================================================

QColor StyleManager::colorForOperator(const QString &op) {
    // Curated palette - all chosen to stay legible on the dark UI.
    static const QColor palette[] = {
        QColor("#4fc3f7"),  // light blue
        QColor("#81c784"),  // green
        QColor("#ffb74d"),  // orange
        QColor("#ba68c8"),  // purple
        QColor("#4db6ac"),  // teal
        QColor("#f06292"),  // pink
        QColor("#fff176"),  // yellow
        QColor("#7986cb"),  // indigo
        QColor("#ff8a65"),  // deep orange
        QColor("#a1887f"),  // taupe
    };
    static const int n = int(sizeof(palette) / sizeof(palette[0]));

    if (op.isEmpty() || op == QLatin1String("unknown") || op == QLatin1String("legacy")) {
        return QColor("#8a8a8a");  // muted gray for unattributed rows
    }

    // Stable hash of the handle so the color never shifts between sessions.
    quint32 h = 2166136261u;  // FNV-1a
    for (const QChar c : op) { h ^= c.unicode(); h *= 16777619u; }
    return palette[h % n];
}

QColor StyleManager::colorForAuditAction(const QString &action) {
    const QString a = action.toLower();
    if (a.contains("login"))                              return QColor("#4fc3f7");  // blue
    if (a.contains("remove") || a.contains("delete"))     return QColor("#ff6b6b");  // red
    if (a.contains("token"))                              return QColor("#ffd54f");  // gold
    if (a.contains("session"))                            return QColor("#81c784");  // green (new/import)
    if (a.contains("command"))                            return QColor("#cfd8dc");  // light gray
    return QColor("#b0bec5");                                                        // default slate
}

QColor StyleManager::colorForTokenSource(const QString &source) {
    const QString s = source.toLower();
    if (s.contains("phish"))       return QColor("#ff6b6b");  // phishing - red
    if (s.contains("consent"))     return QColor("#ffb74d");  // illicit consent - orange
    if (s.contains("credential"))  return QColor("#ba68c8");  // credential login - purple
    if (s.contains("webhook"))     return QColor("#4fc3f7");  // webhook capture - blue
    if (s.contains("exchange"))    return QColor("#4db6ac");  // refresh/PRT exchange - teal
    if (s.contains("import"))      return QColor("#8a8a8a");  // imported - muted
    if (s.contains("token_login")) return QColor("#81c784");  // pasted token - green
    return QColor("#cfd8dc");                                 // default slate
}
