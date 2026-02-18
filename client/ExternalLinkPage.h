#pragma once
#include <QWebEnginePage>
#include <QDesktopServices>

class ExternalLinkPage : public QWebEnginePage {
    Q_OBJECT
public:
    using QWebEnginePage::QWebEnginePage;

protected:
    bool acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame) override {
        if (type == QWebEnginePage::NavigationTypeLinkClicked) {
            QDesktopServices::openUrl(url);
            return false;
        }
        return QWebEnginePage::acceptNavigationRequest(url, type, isMainFrame);
    }
};
