#include "SpnCredentialStore.h"
#include "TokenStore.h"

#include <QMutex>

SpnCredentialStore *SpnCredentialStore::s_instance = nullptr;
static QMutex s_spnInstanceMutex;

SpnCredentialStore *SpnCredentialStore::instance() {
    if (!s_instance) {
        QMutexLocker lk(&s_spnInstanceMutex);
        if (!s_instance) s_instance = new SpnCredentialStore();
    }
    return s_instance;
}

SpnCredentialStore::SpnCredentialStore(QObject *parent) : QObject(parent) {
    // Drop stored SPN creds whenever the paired session is gone.
    if (auto *store = TokenStore::instance()) {
        connect(store, &TokenStore::tokenRemoved, this,
                [this](const QString &sid) { remove(sid); });
        connect(store, &TokenStore::tokensCleared, this, [this]() { clearAll(); });
    }
}

SpnCredentialStore::~SpnCredentialStore() { clearAll(); }

void SpnCredentialStore::store(const QString &sessionId, const SpnCredentials &creds) {
    if (sessionId.isEmpty() || !creds.isValid()) return;
    m_creds.insert(sessionId, creds);
}

SpnCredentials SpnCredentialStore::get(const QString &sessionId) const {
    return m_creds.value(sessionId);
}

bool SpnCredentialStore::has(const QString &sessionId) const {
    return m_creds.value(sessionId).isValid();
}

void SpnCredentialStore::remove(const QString &sessionId) {
    auto it = m_creds.find(sessionId);
    if (it == m_creds.end()) return;
    // Wipe secret bytes before erasing so a memory scrape after removal misses it.
    it->secret.fill(QChar(0));
    it->secret.clear();
    m_creds.erase(it);
}

void SpnCredentialStore::clearAll() {
    for (auto it = m_creds.begin(); it != m_creds.end(); ++it) {
        it->secret.fill(QChar(0));
        it->secret.clear();
    }
    m_creds.clear();
}
