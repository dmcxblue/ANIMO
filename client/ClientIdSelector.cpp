#include "ClientIdSelector.h"

#include <QLineEdit>
#include <QRegularExpression>

namespace {

// Confirmed FOCI-1 members. Order = descending red-team utility so the top
// of the dropdown lists the highest-yield picks first (Teams for PRT,
// PowerShell / CLI for broad scopes, Office for M365).
//
// Source: https://github.com/secureworks/family-of-client-ids-research
struct FociApp {
    const char *name;
    const char *id;
    const char *category;
};

constexpr FociApp kFociApps[] = {
    {"Microsoft Teams",                     "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Desktop"},
    {"Microsoft Azure PowerShell",          "1950a258-227b-4e31-a9cf-717495945fc2", "PowerShell"},
    {"Microsoft Azure CLI",                 "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "CLI"},
    {"Microsoft Office",                    "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Desktop"},
    {"Azure Active Directory PowerShell",   "1b730954-1685-4b74-9bfd-dac224a7b894", "PowerShell"},
    {"Microsoft Authenticator App",         "4813382a-8fa7-425e-ab75-3b753aab3abb", "Mobile"},
    {"Outlook Mobile",                      "27922004-5251-4030-b22d-91ecd9a37ea4", "Mobile"},
    {"OneDrive SyncEngine",                 "ab9b8c07-8f02-4f72-87fa-80105867a763", "Desktop"},
    {"OneDrive iOS App",                    "af124e86-4e96-495a-b70a-90f90ab96707", "Mobile"},
    {"Microsoft Teams - Device Admin Agent","87749df4-7ccf-48f8-aa87-704bad0e0e16", "Broker"},
};

} // namespace

ClientIdSelector::ClientIdSelector(QWidget *parent, const QString &defaultClientId)
    : QComboBox(parent)
{
    setEditable(true);
    setInsertPolicy(QComboBox::NoInsert);
    setMinimumContentsLength(48);
    lineEdit()->setPlaceholderText(
        "FOCI-1 app or paste a custom GUID");
    setToolTip(
        "Family Of Client IDs (FOCI-1): these apps share a family "
        "refresh token that can be redeemed by any of them.\n"
        "Paste your own GUID for non-FOCI clients.");

    populateFociApps();

    if (!defaultClientId.isEmpty()) {
        setClientId(defaultClientId);
    }

    connect(this, &QComboBox::currentTextChanged, this, [this](const QString &) {
        emit clientIdChanged(currentClientId());
    });
}

QString ClientIdSelector::currentClientId() const {
    // 1) itemData holds the raw GUID for entries we populated ourselves.
    const QVariant data = currentData();
    if (data.isValid() && !data.toString().isEmpty()) {
        return data.toString();
    }
    // 2) Free-text entry - extract a UUID from whatever the user typed.
    return extractUuid(currentText());
}

void ClientIdSelector::setClientId(const QString &clientId) {
    for (int i = 0; i < count(); ++i) {
        if (itemData(i).toString().compare(clientId, Qt::CaseInsensitive) == 0) {
            setCurrentIndex(i);
            return;
        }
    }
    // Not in the FOCI list - put it in the edit line as free text.
    setEditText(clientId);
}

void ClientIdSelector::populateFociApps() {
    for (const auto &e : kFociApps) {
        addEntry(QString::fromLatin1(e.name),
                 QString::fromLatin1(e.id),
                 QString::fromLatin1(e.category));
    }
    setCurrentIndex(-1);
}

void ClientIdSelector::addEntry(const QString &displayName,
                                const QString &clientId,
                                const QString &category) {
    if (clientId.isEmpty()) return;
    const QString label = QString("%1  \xE2\x80\x94  %2  [%3]")
                              .arg(displayName, clientId, category);
    addItem(label, clientId);
}

QString ClientIdSelector::extractUuid(const QString &text) {
    static const QRegularExpression re(
        "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
    const auto m = re.match(text);
    if (m.hasMatch()) return m.captured(0).toLower();
    return text.trimmed().toLower();
}
