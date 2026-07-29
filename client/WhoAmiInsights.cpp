#include "WhoAmiInsights.h"

#include <QComboBox>
#include <QLineEdit>
#include <QMutexLocker>

WhoAmiInsights *WhoAmiInsights::s_instance = nullptr;
QMutex          WhoAmiInsights::s_instanceMutex;

WhoAmiInsights *WhoAmiInsights::instance() {
    // Double-checked locking - same shape as TokenStore::instance().
    if (!s_instance) {
        QMutexLocker locker(&s_instanceMutex);
        if (!s_instance) s_instance = new WhoAmiInsights();
    }
    return s_instance;
}

WhoAmiInsights::WhoAmiInsights(QObject *parent) : QObject(parent) {}

void WhoAmiInsights::publish(const Snapshot &s) {
    QString sid;
    {
        QMutexLocker locker(&m_mutex);
        // Prefer sessionId as the key; fall back to userOid if the caller
        // didn't have a session context (shouldn't happen from WhoAmI, but
        // defends against future callers).
        sid = s.sessionId.isEmpty() ? s.userOid : s.sessionId;
        if (sid.isEmpty()) return;
        m_bySession.insert(sid, s);
        m_latestSessionId = sid;
    }
    emit insightsUpdated(sid);
}

WhoAmiInsights::Snapshot WhoAmiInsights::forSession(const QString &sessionId) const {
    QMutexLocker locker(&m_mutex);
    return m_bySession.value(sessionId);
}

WhoAmiInsights::Snapshot WhoAmiInsights::latest() const {
    QMutexLocker locker(&m_mutex);
    if (m_latestSessionId.isEmpty()) return {};
    return m_bySession.value(m_latestSessionId);
}

void WhoAmiInsights::clear(const QString &sessionId) {
    {
        QMutexLocker locker(&m_mutex);
        if (!m_bySession.remove(sessionId)) return;
        if (m_latestSessionId == sessionId) {
            m_latestSessionId = m_bySession.isEmpty()
                ? QString() : m_bySession.keys().last();
        }
    }
    emit insightsCleared(sessionId);
}

void WhoAmiInsights::autofillLineEdit(QLineEdit *w, const QString &value, bool force) {
    if (!w || value.isEmpty()) return;
    if (!force && !w->text().isEmpty()) return;
    w->setText(value);
}

void WhoAmiInsights::autofillCombo(QComboBox *w, const QString &value, bool force) {
    if (!w || value.isEmpty()) return;
    // Editable combos have a currentText; non-editable combos have to match
    // one of the entries.
    if (w->isEditable()) {
        if (!force && !w->currentText().isEmpty()) return;
        w->setEditText(value);
    } else {
        const int idx = w->findText(value, Qt::MatchFixedString);
        if (idx >= 0) {
            if (!force && w->currentIndex() > 0) return;
            w->setCurrentIndex(idx);
        }
    }
}
