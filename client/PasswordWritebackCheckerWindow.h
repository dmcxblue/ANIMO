#ifndef PASSWORDWRITEBACKCHECKERWINDOW_H
#define PASSWORDWRITEBACKCHECKERWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTableWidget>
#include <QSpinBox>
#include <QCheckBox>
#include <QJsonArray>
#include <QSet>

class PasswordWritebackCheckerWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit PasswordWritebackCheckerWindow(QWidget *parent = nullptr);

protected:
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void startScan();
    void exportResults();
    void copySelectedRows();

private:
    void setupUi();
    void checkWritebackStatus();
    void fetchAdminRoles();
    void fetchAdminMembers(const QString &roleId, const QString &roleName);
    void fetchSyncedUsers(const QString &nextLink = QString());
    void processUserResults();
    void finishScan();

    // Custom UI elements
    QPushButton *startBtn;
    QPushButton *exportBtn;
    QPushButton *copyBtn;
    QSpinBox *maxUsersSpinBox;
    QCheckBox *targetsOnlyCheckbox;
    QLabel *writebackStatusLabel;
    QTableWidget *resultsTable;

    // State
    QString currentToken;
    QJsonArray allSyncedUsers;
    QSet<QString> adminUserIds;
    int usersProcessed;
    int usersTotal;
    int targetCount;
    int protectedCount;
    bool scanning;
    bool writebackEnabled;
    int pendingRequests;
};

#endif // PASSWORDWRITEBACKCHECKERWINDOW_H
