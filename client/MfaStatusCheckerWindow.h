#ifndef MFASTATUSCHECKERWINDOW_H
#define MFASTATUSCHECKERWINDOW_H

#include "EnumerationWindowBase.h"
#include <QTableWidget>
#include <QSpinBox>
#include <QCheckBox>
#include <QJsonArray>

class MfaStatusCheckerWindow : public EnumerationWindowBase {
    Q_OBJECT

public:
    explicit MfaStatusCheckerWindow(QWidget *parent = nullptr);

protected:
    // EnumerationWindowBase overrides
    QList<QPushButton*> getOperationButtons() override;
    void onCancelOperation() override;

private slots:
    void startScan();
    void exportResults();
    void copySelectedRows();

private:
    void setupUi();
    void fetchUsers(const QString &nextLink = QString());
    void checkUserMfa(const QString &userId, const QString &upn, const QString &displayName);
    void processAuthMethods(const QString &userId, const QString &upn, const QString &displayName, const QJsonArray &methods);
    void updateScanProgress();
    void finishScan();

    // Custom UI elements
    QPushButton *startBtn;
    QPushButton *exportBtn;
    QPushButton *copyBtn;
    QSpinBox *maxUsersSpinBox;
    QCheckBox *vulnerableOnlyCheckbox;
    QTableWidget *resultsTable;

    // Scan state
    QString currentToken;
    QJsonArray allUsers;
    int usersProcessed;
    int usersTotal;
    int vulnerableCount;
    int protectedCount;
    bool scanning;
    int pendingRequests;
};

#endif // MFASTATUSCHECKERWINDOW_H
