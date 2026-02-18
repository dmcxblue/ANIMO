#include "UserSelectorWidget.h"
#include "TokenHelper.h"
#include "TokenStore.h"

UserSelectorWidget::UserSelectorWidget(QWidget *parent)
    : QWidget(parent)
{
    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    layout->addWidget(new QLabel("Active User:", this));

    m_userCombo = new QComboBox(this);
    m_userCombo->setMinimumWidth(280);
    m_userCombo->setPlaceholderText("Select user session...");
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
    QString previousSelection = m_selectedUpn;
    m_userCombo->clear();

    QStringList users = TokenHelper::instance()->getAvailableUsers();

    if (users.isEmpty()) {
        m_userCombo->addItem("No authenticated sessions", "");
        m_selectedUpn.clear();
        emit noUsersAvailable();
        emit logMessage("No authenticated sessions found. Please login first.", "orange");
    } else {
        m_userCombo->addItem("Select a user...", "");
        for (const QString &user : users) {
            m_userCombo->addItem(user, user);
        }

        // Restore previous selection if it still exists
        int idx = m_userCombo->findData(previousSelection);
        if (idx >= 0) {
            m_userCombo->setCurrentIndex(idx);
            m_selectedUpn = previousSelection;
        } else if (users.size() == 1) {
            // Auto-select if only one user
            m_userCombo->setCurrentIndex(1);
            m_selectedUpn = users.first();
            emit logMessage(QString("Auto-selected user: %1").arg(m_selectedUpn), "cyan");
            emit userChanged(m_selectedUpn);
        } else {
            m_selectedUpn.clear();
        }
    }

    m_userCombo->blockSignals(false);
}

void UserSelectorWidget::onUserSelected(int index) {
    QString newUpn = m_userCombo->itemData(index).toString();
    if (newUpn == m_selectedUpn) return;

    m_selectedUpn = newUpn;

    if (m_selectedUpn.isEmpty()) {
        emit logMessage("No user selected", "gray");
    } else {
        emit logMessage(QString("Switched to user: %1").arg(m_selectedUpn), "cyan");
    }

    emit userChanged(m_selectedUpn);
}

void UserSelectorWidget::onRefreshClicked() {
    refresh();
}

void UserSelectorWidget::fetchToken(const QString &resource,
                                     std::function<void(bool, const QString&, const QString&)> callback,
                                     const QString &clientId) {
    if (m_selectedUpn.isEmpty()) {
        callback(false, QString(), "No user selected. Please select a user first.");
        return;
    }

    TokenHelper::instance()->getTokenForResource(resource, callback, m_selectedUpn, clientId);
}

void UserSelectorWidget::fetchTokens(const QStringList &resources,
                                      std::function<void(bool, const QMap<QString, QString>&, const QString&)> callback) {
    if (m_selectedUpn.isEmpty()) {
        callback(false, QMap<QString, QString>(), "No user selected. Please select a user first.");
        return;
    }

    TokenHelper::instance()->getTokensForResources(resources, callback, m_selectedUpn);
}

QString UserSelectorWidget::getExistingToken(const QString &resource) const {
    if (m_selectedUpn.isEmpty()) return QString();
    return TokenHelper::instance()->getExistingToken(resource, m_selectedUpn);
}

bool UserSelectorWidget::hasValidToken(const QString &resource) const {
    if (m_selectedUpn.isEmpty()) return false;
    return TokenHelper::instance()->hasValidToken(resource, m_selectedUpn);
}
