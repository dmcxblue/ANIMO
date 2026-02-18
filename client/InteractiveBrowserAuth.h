#ifndef INTERACTIVEBROWSERAUTH_H
#define INTERACTIVEBROWSERAUTH_H

#include <QWidget>
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QString>
#include <QUrl>

class InteractiveBrowserAuth;

// Custom page to intercept redirect navigation
class OAuthWebPage : public QWebEnginePage {
    Q_OBJECT
public:
    OAuthWebPage(const QString &redirectUri, QWebEngineProfile *profile, QObject *parent = nullptr);

signals:
    void redirectCaptured(const QUrl &url);

protected:
    bool acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame) override;

private:
    QString m_redirectUri;
};

class InteractiveBrowserAuth : public QWidget {
    Q_OBJECT

public:
    explicit InteractiveBrowserAuth(const QString &resource,
                                    const QString &clientId,
                                    const QString &tenant = "organizations",
                                    QWidget *parent = nullptr);
    ~InteractiveBrowserAuth();

    void startAuth();
    void clearBrowserData();

signals:
    void authSuccess(const QString &accessToken,
                     const QString &refreshToken,
                     const QString &idToken,
                     const QString &tenantId,
                     const QString &upn);
    void authFailed(const QString &error);

private slots:
    void onUrlChanged(const QUrl &url);
    void onLoadFinished(bool ok);
    void handleRedirect(const QUrl &url);

private:
    void setupUi();
    void exchangeCodeForTokens(const QString &code);
    QString extractCodeFromUrl(const QUrl &url);
    void parseTokenResponse(const QByteArray &data);
    QString decodeJwtClaim(const QString &jwt, const QString &claim);

    QString m_resource;
    QString m_clientId;
    QString m_tenant;
    QString m_redirectUri;
    QString m_state;
    QString m_codeVerifier;
    QString m_codeChallenge;

    QWebEngineView *m_webView = nullptr;
    QWebEngineProfile *m_profile = nullptr;
    QLabel *m_statusLabel = nullptr;
    QNetworkAccessManager *m_nam = nullptr;
};

#endif // INTERACTIVEBROWSERAUTH_H
