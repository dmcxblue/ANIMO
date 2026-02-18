#include "InteractiveBrowserAuth.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDebug>
#include <QWebEngineCookieStore>
#include <QUuid>

// Default Azure AD client ID (Azure PowerShell)
static const char* DEFAULT_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2";

// ============================================================================
// OAuthWebPage - Intercepts redirect navigation before browser tries to load it
// ============================================================================
OAuthWebPage::OAuthWebPage(const QString &redirectUri, QWebEngineProfile *profile, QObject *parent)
    : QWebEnginePage(profile, parent), m_redirectUri(redirectUri)
{
}

bool OAuthWebPage::acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame)
{
    Q_UNUSED(type)
    Q_UNUSED(isMainFrame)

    QString urlStr = url.toString();
    qDebug() << "[OAuthWebPage] Navigation request:" << urlStr;

    // Check if this is a redirect to our localhost URI
    if (urlStr.startsWith(m_redirectUri)) {
        qDebug() << "[OAuthWebPage] Intercepted redirect to localhost - capturing auth code";
        emit redirectCaptured(url);
        return false; // Don't actually navigate - we've captured the URL
    }

    return true; // Allow all other navigation
}

// ============================================================================
// InteractiveBrowserAuth
// ============================================================================

InteractiveBrowserAuth::InteractiveBrowserAuth(const QString &resource,
                                               const QString &clientId,
                                               const QString &tenant,
                                               QWidget *parent)
    : QWidget(parent),
      m_resource(resource),
      m_clientId(clientId.isEmpty() ? QString(DEFAULT_CLIENT_ID) : clientId),
      m_tenant(tenant.isEmpty() ? "organizations" : tenant),
      m_redirectUri("http://localhost")
{
    // Show the resource in window title for clarity
    QString resourceName = m_resource.contains("graph.microsoft.com") ? "Graph" : "Azure Management";
    setWindowTitle(QString("Azure Login - %1").arg(resourceName));
    setAttribute(Qt::WA_DeleteOnClose);
    m_nam = new QNetworkAccessManager(this);

    qDebug() << "[InteractiveBrowserAuth] Created with resource:" << m_resource;

    setupUi();
}

InteractiveBrowserAuth::~InteractiveBrowserAuth()
{
    // Clean up browser data on close
    clearBrowserData();
}

void InteractiveBrowserAuth::clearBrowserData()
{
    if (m_profile) {
        // Clear all cookies
        m_profile->cookieStore()->deleteAllCookies();
        // Clear HTTP cache
        m_profile->clearHttpCache();
        qDebug() << "[InteractiveBrowserAuth] Cleared cookies and cache";
    }
}

void InteractiveBrowserAuth::setupUi()
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    QString resourceName = m_resource.contains("graph.microsoft.com") ? "Graph" : "Azure Management";
    m_statusLabel = new QLabel(QString("Sign in with Azure credentials for %1...").arg(resourceName), this);
    m_statusLabel->setStyleSheet("padding: 8px; background-color: #0078d4; color: white;");
    layout->addWidget(m_statusLabel);

    // Create a unique off-the-record profile for each auth session
    // This ensures no cached credentials from previous sessions
    QString profileName = QStringLiteral("AzureAuth_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces).left(8));
    m_profile = new QWebEngineProfile(profileName, this);
    m_profile->setHttpCacheType(QWebEngineProfile::NoCache);
    m_profile->setPersistentCookiesPolicy(QWebEngineProfile::NoPersistentCookies);

    // Create custom page that intercepts redirect navigation
    auto *page = new OAuthWebPage(m_redirectUri, m_profile, this);
    connect(page, &OAuthWebPage::redirectCaptured, this, &InteractiveBrowserAuth::handleRedirect);

    m_webView = new QWebEngineView(this);
    m_webView->setPage(page);
    m_webView->setMinimumSize(500, 600);
    layout->addWidget(m_webView);

    // Bottom bar with cancel button
    auto *bottomBar = new QHBoxLayout();
    bottomBar->addStretch();
    auto *cancelBtn = new QPushButton("Cancel", this);
    connect(cancelBtn, &QPushButton::clicked, this, [this]() {
        clearBrowserData();
        emit authFailed("User cancelled");
        close();
    });
    bottomBar->addWidget(cancelBtn);
    layout->addLayout(bottomBar);

    connect(m_webView, &QWebEngineView::urlChanged, this, &InteractiveBrowserAuth::onUrlChanged);
    connect(m_webView, &QWebEngineView::loadFinished, this, &InteractiveBrowserAuth::onLoadFinished);

    resize(520, 700);
}

void InteractiveBrowserAuth::startAuth()
{
    // Clear any existing browser data first
    clearBrowserData();

    // Generate PKCE code verifier and challenge
    QByteArray randomBytes(32, 0);
    QRandomGenerator::global()->fillRange(reinterpret_cast<quint32*>(randomBytes.data()), 8);
    m_codeVerifier = randomBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    QByteArray hash = QCryptographicHash::hash(m_codeVerifier.toUtf8(), QCryptographicHash::Sha256);
    m_codeChallenge = hash.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    // Generate state
    QByteArray stateBytes(16, 0);
    QRandomGenerator::global()->fillRange(reinterpret_cast<quint32*>(stateBytes.data()), 4);
    m_state = stateBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    // Build authorization URL
    QString scope = QString("%1/.default offline_access openid profile").arg(m_resource);
    qDebug() << "[InteractiveBrowserAuth] Using scope:" << scope;

    QUrl authUrl(QString("https://login.microsoftonline.com/%1/oauth2/v2.0/authorize").arg(m_tenant));
    QUrlQuery query;
    query.addQueryItem("client_id", m_clientId);
    query.addQueryItem("response_type", "code");
    query.addQueryItem("redirect_uri", m_redirectUri);
    query.addQueryItem("response_mode", "query");
    query.addQueryItem("scope", scope);
    query.addQueryItem("state", m_state);
    query.addQueryItem("code_challenge", m_codeChallenge);
    query.addQueryItem("code_challenge_method", "S256");
    // Force fresh login - don't use cached SSO
    query.addQueryItem("prompt", "login");
    authUrl.setQuery(query);

    qDebug() << "[InteractiveBrowserAuth] Starting auth:" << authUrl.toString();

    // Ensure window shows on top
    setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
    m_webView->load(authUrl);
    show();
    raise();
    activateWindow();
}

void InteractiveBrowserAuth::onUrlChanged(const QUrl &url)
{
    qDebug() << "[InteractiveBrowserAuth] URL changed:" << url.toString();

    // Check if this is the redirect to localhost
    if (url.toString().startsWith(m_redirectUri)) {
        // IMPORTANT: Stop the page load immediately to prevent hanging
        m_webView->stop();

        QString code = extractCodeFromUrl(url);
        if (!code.isEmpty()) {
            qDebug() << "[InteractiveBrowserAuth] Got authorization code, exchanging for tokens...";
            m_statusLabel->setText("Authentication successful, exchanging tokens...");
            m_webView->setVisible(false);
            exchangeCodeForTokens(code);
        } else {
            // Check for error
            QUrlQuery query(url);
            QString error = query.queryItemValue("error");
            QString errorDesc = query.queryItemValue("error_description");
            qDebug() << "[InteractiveBrowserAuth] Redirect error:" << error << errorDesc;
            if (!error.isEmpty()) {
                emit authFailed(errorDesc.isEmpty() ? error : errorDesc);
                close();
            } else {
                // No code and no error - might be state mismatch
                qWarning() << "[InteractiveBrowserAuth] No code or error in redirect URL";
                emit authFailed("Authentication failed - no authorization code received");
                close();
            }
        }
    }
}

void InteractiveBrowserAuth::onLoadFinished(bool ok)
{
    if (!ok) {
        m_statusLabel->setText("Failed to load page. Check your connection.");
    }
}

void InteractiveBrowserAuth::handleRedirect(const QUrl &url)
{
    qDebug() << "[InteractiveBrowserAuth] handleRedirect called with:" << url.toString();

    QString code = extractCodeFromUrl(url);
    if (!code.isEmpty()) {
        qDebug() << "[InteractiveBrowserAuth] Got authorization code, exchanging for tokens...";
        m_statusLabel->setText("Authentication successful, exchanging tokens...");
        m_webView->setVisible(false);
        exchangeCodeForTokens(code);
    } else {
        // Check for error in URL
        QUrlQuery query(url);
        QString error = query.queryItemValue("error");
        QString errorDesc = query.queryItemValue("error_description");
        qDebug() << "[InteractiveBrowserAuth] Redirect error:" << error << errorDesc;

        if (!error.isEmpty()) {
            emit authFailed(errorDesc.isEmpty() ? error : errorDesc);
        } else {
            emit authFailed("Authentication failed - no authorization code received");
        }
        close();
    }
}

QString InteractiveBrowserAuth::extractCodeFromUrl(const QUrl &url)
{
    QUrlQuery query(url);

    // Verify state
    QString returnedState = query.queryItemValue("state");
    if (returnedState != m_state) {
        qWarning() << "[InteractiveBrowserAuth] State mismatch!";
        return QString();
    }

    return query.queryItemValue("code");
}

void InteractiveBrowserAuth::exchangeCodeForTokens(const QString &code)
{
    QUrl tokenUrl(QString("https://login.microsoftonline.com/%1/oauth2/v2.0/token").arg(m_tenant));

    QString scope = QString("%1/.default offline_access openid profile").arg(m_resource);
    qDebug() << "[InteractiveBrowserAuth] Token exchange - URL:" << tokenUrl.toString();
    qDebug() << "[InteractiveBrowserAuth] Token exchange - Scope:" << scope;
    qDebug() << "[InteractiveBrowserAuth] Token exchange - Client ID:" << m_clientId;

    QUrlQuery postData;
    postData.addQueryItem("client_id", m_clientId);
    postData.addQueryItem("scope", scope);
    postData.addQueryItem("code", code);
    postData.addQueryItem("redirect_uri", m_redirectUri);
    postData.addQueryItem("grant_type", "authorization_code");
    postData.addQueryItem("code_verifier", m_codeVerifier);

    QNetworkRequest request(tokenUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    QNetworkReply *reply = m_nam->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();

        QByteArray responseData = reply->readAll();
        int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        qDebug() << "[InteractiveBrowserAuth] Token response - HTTP status:" << httpStatus;

        if (reply->error() != QNetworkReply::NoError) {
            qDebug() << "[InteractiveBrowserAuth] Token exchange error:" << reply->errorString();
            qDebug() << "[InteractiveBrowserAuth] Response body:" << responseData;
            QString errorMsg = QString("Token exchange failed: %1").arg(reply->errorString());

            // Try to parse error from response body
            QJsonDocument doc = QJsonDocument::fromJson(responseData);
            if (doc.isObject()) {
                QJsonObject obj = doc.object();
                if (obj.contains("error_description")) {
                    errorMsg = obj.value("error_description").toString();
                }
            }

            emit authFailed(errorMsg);
            close();
            return;
        }

        parseTokenResponse(responseData);
    });
}

void InteractiveBrowserAuth::parseTokenResponse(const QByteArray &data)
{
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        emit authFailed("Invalid token response");
        close();
        return;
    }

    QJsonObject obj = doc.object();

    if (obj.contains("error")) {
        QString error = obj.value("error").toString();
        QString errorDesc = obj.value("error_description").toString();
        emit authFailed(errorDesc.isEmpty() ? error : errorDesc);
        close();
        return;
    }

    QString accessToken = obj.value("access_token").toString();
    QString refreshToken = obj.value("refresh_token").toString();
    QString idToken = obj.value("id_token").toString();

    if (accessToken.isEmpty()) {
        emit authFailed("No access token in response");
        close();
        return;
    }

    // Extract tenant and UPN from id_token
    QString tenantId = decodeJwtClaim(idToken, "tid");
    QString upn = decodeJwtClaim(idToken, "upn");
    if (upn.isEmpty()) {
        upn = decodeJwtClaim(idToken, "preferred_username");
    }

    qDebug() << "[InteractiveBrowserAuth] Auth success - UPN:" << upn << "Tenant:" << tenantId;

    // Clear browser data before closing to ensure fresh login next time
    clearBrowserData();

    emit authSuccess(accessToken, refreshToken, idToken, tenantId, upn);
    close();
}

QString InteractiveBrowserAuth::decodeJwtClaim(const QString &jwt, const QString &claim)
{
    QStringList parts = jwt.split('.');
    if (parts.size() < 2) return QString();

    QByteArray payload = parts.at(1).toUtf8();
    // Pad for base64url
    int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '='));
    payload = QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding);

    QJsonObject obj = QJsonDocument::fromJson(payload).object();
    return obj.value(claim).toString();
}
