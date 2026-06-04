#include "PRTTokenExchanger.h"
#include "NetworkHelper.h"
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QDebug>
#include <QUrlQuery>
#include <QRegularExpression>

// Constructor
PRTTokenExchanger::PRTTokenExchanger(const QString &clientId,
                                     const QString &tenant,
                                     const QString &resource,
                                     const QString &prtToken,
                                     QObject *parent)
    : QObject(parent),
      clientId(clientId),
      tenant(tenant.isEmpty() ? "common" : tenant),
      resource(resource),
      prtToken(prtToken),
      net(new QNetworkAccessManager(this)) {
    redirectUri = getRedirectUri();
}

QString PRTTokenExchanger::getRedirectUri() const {
    QString cid = clientId.toLower();
    QString res = resource.toLower();

    if (cid == "1fec8e78-bce4-4aaf-ab1b-5451cc387264")
        return "https://login.microsoftonline.com/common/oauth2/nativeclient";
    if (cid == "9bc3ab49-b65d-410a-85ad-de819febfddc")
        return "https://oauth.spops.microsoft.com/";
    if (cid == "c44b4083-3bb0-49c1-b47d-974e53cbdf3c")
        return "https://portal.azure.com/signin/index/?feature.prefetchtokens=true";
    if (cid == "0000000c-0000-0000-c000-000000000000")
        return "https://account.activedirectory.windowsazure.com/";
    if (cid == "19db86c3-b2b9-44cc-b339-36da233a3be2")
        return "https://mysignins.microsoft.com";
    if (cid == "29d9ed98-a469-4536-ade2-f981bc1d605e" &&
        res != "https://enrollment.manage.microsoft.com/")
        return "ms-aadj-redir://auth/drs";
    if (cid == "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa")
        return "https://azureapp";
    if (cid == "33be1cef-03fb-444b-8fd3-08ca1b4d803f")
        return "https://admin.onedrive.com/";
    if (cid == "ab9b8c07-8f02-4f72-87fa-80105867a763")
        return "https://login.windows.net/common/oauth2/nativeclient";
    if (cid == "3d5cffa9-04da-4657-8cab-c7f074657cad")
        return "http://localhost/m365/commerce";
    if (cid == "4990cffe-04e8-4e8b-808a-1175604b879f")
        return "https://partner.microsoft.com/aad/authPostGateway";
    if (cid == "3b511579-5e00-46e1-a89e-a6f0870e2f5a")
        return "https://windows365.microsoft.com/signin-oidc";
    if (cid == "08e18876-6177-487e-b8b5-cf950c1e598c")
        return "https://*-admin.sharepoint.com/_forms/spfxsinglesignon.aspx";
    if (cid == "dd762716-544d-4aeb-a526-687b73838a22")
        return "ms-appx-web://microsoft.aad.brokerplugin/dd762716-544d-4aeb-a526-687b73838a22";
    if (cid == "4765445b-32c6-49b0-83e6-1d93765276ca")
        return "https://www.office.com/landingv2";

    // Default
    return "https://login.microsoftonline.com/common/oauth2/nativeclient";
}

QString PRTTokenExchanger::buildAuthorizationUrl() const {
    QString requestId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    return QString("https://login.microsoftonline.com/%1/oauth2/authorize?"
                   "resource=%2&client_id=%3&response_type=code&redirect_uri=%4"
                   "&client-request-id=%5&mscrid=%5")
        .arg(tenant, resource, clientId, redirectUri, requestId);
}

void PRTTokenExchanger::getAccessToken() {
    QString url = buildAuthorizationUrl();

    qDebug() << "[PRTTokenExchanger] Authorization URL:" << url;
    qDebug() << "[PRTTokenExchanger] Client ID:" << clientId;
    qDebug() << "[PRTTokenExchanger] Tenant:" << tenant;
    qDebug() << "[PRTTokenExchanger] Resource:" << resource;
    qDebug() << "[PRTTokenExchanger] Redirect URI:" << redirectUri;
    qDebug() << "[PRTTokenExchanger] PRT Token length:" << prtToken.length();

    QNetworkRequest req{ QUrl(url) };
    // Use Windows native client User-Agent for SSO compatibility
    req.setRawHeader("User-Agent", QByteArray(
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; "
        ".NET4.0C; .NET4.0E; Tablet PC 2.0)"));
    req.setRawHeader("x-ms-RefreshTokenCredential", prtToken.toUtf8());
    req.setRawHeader("Accept", QByteArray("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));

    // Disable automatic redirect following so we can capture the Location header
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);

    NetworkHelper::setRequestTimeout(req);

    qDebug() << "[PRTTokenExchanger] Sending request...";

    QNetworkReply *rep = net->get(req);
    if (!rep) {
        emit errorOccurred("Failed to create network request");
        return;
    }
    connect(rep, &QNetworkReply::finished, this, &PRTTokenExchanger::handleAuthReply);
}

void PRTTokenExchanger::handleAuthReply() {
    QNetworkReply *rep = qobject_cast<QNetworkReply *>(sender());
    if (!rep) return;

    // Read response body first (before any early returns)
    QByteArray responseBody = rep->readAll();

    // Get HTTP status code
    int httpStatus = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    qDebug() << "[PRTTokenExchanger] HTTP Status:" << httpStatus;

    // Debug: log all response headers
    qDebug() << "[PRTTokenExchanger] Response headers:";
    for (const auto &headerPair : rep->rawHeaderPairs()) {
        qDebug() << "  " << headerPair.first << ":" << headerPair.second;
    }

    // Debug: log response body length only (avoid logging sensitive token data)
    qDebug() << "[PRTTokenExchanger] Response body length:" << responseBody.length();

    QString location = rep->header(QNetworkRequest::LocationHeader).toString();

    // Handle network errors
    if (rep->error() != QNetworkReply::NoError && rep->error() != QNetworkReply::ProtocolInvalidOperationError) {
        QString errorMsg = QString("Network error: %1\nHTTP Status: %2\n\nResponse body:\n%3")
            .arg(rep->errorString())
            .arg(httpStatus)
            .arg(QString::fromUtf8(responseBody.left(500)));
        emit errorOccurred(errorMsg);
        rep->deleteLater();
        return;
    }

    rep->deleteLater();

    // Check for Location header (redirect)
    if (location.isEmpty()) {
        QString bodyText = QString::fromUtf8(responseBody);

        // Try to extract error details from HTML response
        QString errorDetail;
        if (bodyText.contains("AADSTS", Qt::CaseInsensitive)) {
            QRegularExpression aadRe("(AADSTS\\d+[^<\"'\\n]{0,200})");
            QRegularExpressionMatch m = aadRe.match(bodyText);
            if (m.hasMatch()) {
                errorDetail = QString("\n\nAAD Error: %1").arg(m.captured(1));
            }
        }

        QString errorMsg = QString("PRT SSO failed - Microsoft returned login page instead of redirect.\n\n"
                                   "HTTP Status: %1%2\n\n"
                                   "Possible causes:\n"
                                   "• PRT token is expired or invalid\n"
                                   "• PRT must be the full signed assertion from BrowserCore\n"
                                   "• Tenant mismatch (PRT is for different tenant)\n"
                                   "• Device is not AAD-joined or Hybrid-joined\n"
                                   "• Conditional Access policy blocking SSO\n\n"
                                   "Tip: Ensure you're using the x-ms-RefreshTokenCredential value\n"
                                   "from BrowserCore, not a raw refresh token.")
            .arg(httpStatus)
            .arg(errorDetail);
        emit errorOccurred(errorMsg);
        return;
    }

    qDebug() << "[PRTTokenExchanger] Location header:" << location;

    // Check if location contains error
    if (location.contains("error=")) {
        QRegularExpression errorRe("error=([^&]+)");
        QRegularExpression errorDescRe("error_description=([^&]+)");
        QRegularExpressionMatch errorMatch = errorRe.match(location);
        QRegularExpressionMatch descMatch = errorDescRe.match(location);

        QString error = errorMatch.hasMatch() ? QUrl::fromPercentEncoding(errorMatch.captured(1).toUtf8()) : "unknown";
        QString errorDesc = descMatch.hasMatch() ? QUrl::fromPercentEncoding(descMatch.captured(1).toUtf8()) : "No description";

        QString errorMsg = QString("Microsoft OAuth Error:\n\nError: %1\nDescription: %2\n\nLocation: %3")
            .arg(error, errorDesc, location);
        emit errorOccurred(errorMsg);
        return;
    }

    QRegularExpression re("[?&]code=([^&]+)");
    QRegularExpressionMatch m = re.match(location);
    if (!m.hasMatch()) {
        QString errorMsg = QString("Authorization Code not received.\n\nLocation header:\n%1\n\n"
                                   "The redirect doesn't contain a 'code' parameter.\n"
                                   "Check the Location header above for error details.")
            .arg(location);
        emit errorOccurred(errorMsg);
        return;
    }

    QString code = m.captured(1);
    qDebug() << "[PRTTokenExchanger] Authorization code extracted (length:" << code.length() << ")";

    // Exchange for token
    QString tokenUrl = QString("https://login.microsoftonline.com/%1/oauth2/token").arg(tenant);
    QUrlQuery q;
    q.addQueryItem("grant_type", "authorization_code");
    q.addQueryItem("client_id", clientId);
    q.addQueryItem("code", code);
    q.addQueryItem("redirect_uri", redirectUri);
    q.addQueryItem("resource", resource);

    QNetworkRequest req{ QUrl(tokenUrl) };
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    NetworkHelper::setRequestTimeout(req);

    QNetworkReply *tokRep = net->post(req, q.toString(QUrl::FullyEncoded).toUtf8());
    if (!tokRep) {
        emit errorOccurred("Failed to create token exchange request");
        return;
    }
    connect(tokRep, &QNetworkReply::finished, this, &PRTTokenExchanger::handleTokenReply);
}

void PRTTokenExchanger::handleTokenReply() {
    QNetworkReply *rep = qobject_cast<QNetworkReply *>(sender());
    if (!rep) return;

    if (rep->error() != QNetworkReply::NoError) {
        emit errorOccurred(rep->errorString());
        rep->deleteLater();
        return;
    }

    const QJsonObject obj = QJsonDocument::fromJson(rep->readAll()).object();
    rep->deleteLater();
    emit exchangeFinished(obj);
}
