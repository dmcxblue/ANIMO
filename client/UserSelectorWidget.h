#ifndef USERSELECTORWIDGET_H
#define USERSELECTORWIDGET_H

#include <QWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <functional>

class UserSelectorWidget : public QWidget {
    Q_OBJECT

public:
    explicit UserSelectorWidget(QWidget *parent = nullptr);

    // Get the currently selected user (UPN)
    QString selectedUser() const { return m_selectedUpn; }

    // Check if a user is selected
    bool hasSelection() const { return !m_selectedUpn.isEmpty(); }

    // Refresh the user list
    void refresh();

    // Get token for a resource for the selected user
    // Callback: (success, accessToken, error)
    // If clientId is provided, forces that client ID for the token exchange
    void fetchToken(const QString &resource,
                    std::function<void(bool, const QString&, const QString&)> callback,
                    const QString &clientId = QString());

    // Fetch multiple tokens for the selected user
    // Callback: (success, tokens map, error)
    void fetchTokens(const QStringList &resources,
                     std::function<void(bool, const QMap<QString, QString>&, const QString&)> callback);

    // Get existing token without fetching (returns empty if not available)
    QString getExistingToken(const QString &resource) const;

    // Check if we have a valid token for resource
    bool hasValidToken(const QString &resource) const;

signals:
    // Emitted when user selection changes
    void userChanged(const QString &upn);

    // Emitted when no users are available
    void noUsersAvailable();

    // Emitted for logging purposes
    void logMessage(const QString &message, const QString &color);

private slots:
    void onUserSelected(int index);
    void onRefreshClicked();

private:
    QComboBox *m_userCombo;
    QPushButton *m_refreshBtn;
    QString m_selectedUpn;
};

#endif // USERSELECTORWIDGET_H
