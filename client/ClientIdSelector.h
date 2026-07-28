#ifndef CLIENTIDSELECTOR_H
#define CLIENTIDSELECTOR_H

#include <QComboBox>
#include <QString>

// Editable combo box seeded with 10 confirmed FOCI-1 (Family Of Client IDs)
// Microsoft first-party apps. FOCI apps share a family_refresh_token - any
// FOCI client ID can redeem any other FOCI app's refresh token, which is what
// makes these useful for cross-resource token pivots.
//
// Source: https://github.com/secureworks/family-of-client-ids-research
// Cross-referenced with TokenTacticsV2.
//
// Users can still type or paste any custom client ID - the combo is
// editable. Read the effective value via currentClientId(), which extracts
// the GUID from the selected entry OR from free-text input.
class ClientIdSelector : public QComboBox {
    Q_OBJECT

public:
    explicit ClientIdSelector(QWidget *parent = nullptr,
                              const QString &defaultClientId = QString());

    // Extract the GUID from the current selection or free-text entry.
    // Returns an empty string if nothing recognisable is present.
    QString currentClientId() const;

    // Set the selection to a specific GUID; if the ID is one of the FOCI
    // entries, selects that entry; otherwise sets it as free text.
    void setClientId(const QString &clientId);

signals:
    void clientIdChanged(const QString &clientId);

private:
    void populateFociApps();
    void addEntry(const QString &displayName, const QString &clientId, const QString &category);
    static QString extractUuid(const QString &text);
};

#endif // CLIENTIDSELECTOR_H
