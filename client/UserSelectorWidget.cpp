#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "TokenStore.h"
#include <QHash>

UserSelectorWidget::UserSelectorWidget(QWidget *parent)
    : QWidget(parent)
{
    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    layout->addWidget(new QLabel("Session:", this));

    m_userCombo = new QComboBox(this);
    m_userCombo->setMinimumWidth(340);
    m_userCombo->setPlaceholderText("Select a session...");
    layout->addWidget(m_userCombo);

    m_refreshBtn = new QPushButton("Refresh", this);
    m_refreshBtn->setFixedWidth(70);
    layout->addWidget(m_refreshBtn);

    layout->addStretch();

    connect(m_userCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &UserSelectorWidget::onUserSelected);
    connect(m_refreshBtn, &QPushButton::clicked,
            this, &UserSelectorWidget::onRefreshClicked);

    // Initial population
    refresh();
}

void UserSelectorWidget::refresh() {
    m_userCombo->blockSignals(true);
    const QString previousSession = m_selectedSessionId;
    m_userCombo->clear();

    const QList<SessionSummary> sessions = TokenStore::instance()->getSessionSummaries();

    if (sessions.isEmpty()) {
        m_userCombo->addItem("No authenticated sessions", "");
        m_selectedSessionId.clear();
        m_selectedUpn.clear();
        emit noUsersAvailable();
        emit logMessage("No authenticated sessions found. Please login first.", "orange");
        m_userCombo->blockSignals(false);
        return;
    }

    // Disambiguate only when the same UPN spans more than one session.
    QHash<QString, int> perUpn;
    for (const SessionSummary &s : sessions) perUpn[s.upn.toLower()]++;

    m_userCombo->addItem("Select a session...", "");
    for (const SessionSummary &s : sessions) {
        QString label = s.upn.isEmpty() ? QStringLiteral("(no user)") : s.upn;
        if (s.upn.isEmpty() || perUpn.value(s.upn.toLower()) > 1) {
            QStringList disc;
            if (!s.tenantId.isEmpty()) disc << "tid:" + s.tenantId.left(8);
            disc << "sid:" + s.sessionId.left(8);
            if (s.lastSeen.isValid()) disc << s.lastSeen.toString("hh:mm");
            label += "   [" + disc.join(", ") + "]";
        }
        const int idx = m_userCombo->count();
        m_userCombo->addItem(label, s.sessionId);
        m_userCombo->setItemData(idx, s.upn, Qt::UserRole + 1);  // stash UPN for back-compat
    }

    // Restore the previous session, else auto-select when there is exactly one.
    const int restoreIdx = previousSession.isEmpty() ? -1 : m_userCombo->findData(previousSession);
    if (restoreIdx >= 0) {
        m_userCombo->setCurrentIndex(restoreIdx);
        m_selectedSessionId = previousSession;
        m_selectedUpn = m_userCombo->itemData(restoreIdx, Qt::UserRole + 1).toString();
    } else if (sessions.size() == 1) {
        m_userCombo->setCurrentIndex(1);
        m_selectedSessionId = sessions.first().sessionId;
        m_selectedUpn = sessions.first().upn;
        emit logMessage(QString("Auto-selected session for %1").arg(m_selectedUpn), "cyan");
        emit userChanged(m_selectedUpn);
    } else {
        m_selectedSessionId.clear();
        m_selectedUpn.clear();
    }

    m_userCombo->blockSignals(false);
}

void UserSelectorWidget::onUserSelected(int index) {
    const QString newSession = m_userCombo->itemData(index).toString();
    if (newSession == m_selectedSessionId) return;

    m_selectedSessionId = newSession;
    m_selectedUpn = m_userCombo->itemData(index, Qt::UserRole + 1).toString();

    if (m_selectedSessionId.isEmpty()) {
        m_selectedUpn.clear();
        emit logMessage("No session selected", "gray");
    } else {
        emit logMessage(QString("Switched to session for %1 (sid:%2)")
                        .arg(m_selectedUpn.isEmpty() ? QStringLiteral("unknown") : m_selectedUpn,
                             m_selectedSessionId.left(8)), "cyan");
    }

    emit userChanged(m_selectedUpn);
}

void UserSelectorWidget::onRefreshClicked() {
    refresh();
}

void UserSelectorWidget::fetchToken(const QString &resource,
                                     std::function<void(bool, const QString&, const QString&)> callback,
                                     const QString &clientId) {
    if (m_selectedSessionId.isEmpty()) {
        callback(false, QString(), "No session selected. Please select a session first.");
        return;
    }

    TokenHelper::instance()->getTokenForResourceBySession(resource, callback, m_selectedSessionId, clientId);
}

void UserSelectorWidget::fetchTokens(const QStringList &resources,
                                      std::function<void(bool, const QMap<QString, QString>&, const QString&)> callback) {
    if (m_selectedSessionId.isEmpty()) {
        callback(false, QMap<QString, QString>(), "No session selected. Please select a session first.");
        return;
    }

    TokenHelper::instance()->getTokensForResourcesBySession(resources, callback, m_selectedSessionId);
}

QString UserSelectorWidget::getExistingToken(const QString &resource) const {
    if (m_selectedSessionId.isEmpty()) return QString();
    return TokenHelper::instance()->getExistingTokenForSession(resource, m_selectedSessionId);
}

bool UserSelectorWidget::hasValidToken(const QString &resource) const {
    if (m_selectedSessionId.isEmpty()) return false;
    return TokenHelper::instance()->hasValidTokenForSession(resource, m_selectedSessionId);
}
