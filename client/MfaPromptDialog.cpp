#include "MfaPromptDialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QStyle>
#include <QApplication>

MfaPromptDialog::MfaPromptDialog(const QString &mfaCode,
                                 const QString &mfaMessage,
                                 const QString &sessionId,
                                 QWidget *parent)
    : QDialog(parent),
      m_mfaCode(mfaCode),
      m_mfaMessage(mfaMessage),
      m_sessionId(sessionId)
{
    setWindowTitle("MFA Required");
    setModal(true);
    setMinimumSize(480, 320);
    setupUi();
}

void MfaPromptDialog::setupUi()
{
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Header with icon and title
    auto *headerLayout = new QHBoxLayout();

    m_iconLabel = new QLabel(this);
    m_iconLabel->setPixmap(style()->standardIcon(QStyle::SP_MessageBoxWarning).pixmap(48, 48));
    headerLayout->addWidget(m_iconLabel);

    m_titleLabel = new QLabel("<h2>Multi-Factor Authentication Required</h2>", this);
    m_titleLabel->setWordWrap(true);
    headerLayout->addWidget(m_titleLabel, 1);

    mainLayout->addLayout(headerLayout);

    // MFA code badge
    QString codeStyle = "background-color: #f0ad4e; color: #000; padding: 4px 8px; "
                        "border-radius: 4px; font-weight: bold; font-family: monospace;";
    QLabel *codeLabel = new QLabel(QString("<span style='%1'>%2</span>").arg(codeStyle, m_mfaCode), this);
    mainLayout->addWidget(codeLabel);

    // Description
    QString description = getMfaDescription(m_mfaCode);
    QLabel *descLabel = new QLabel(description, this);
    descLabel->setWordWrap(true);
    descLabel->setStyleSheet("font-size: 12px;");
    mainLayout->addWidget(descLabel);

    // Details browser for the full error message
    m_detailsBrowser = new QTextBrowser(this);
    m_detailsBrowser->setReadOnly(true);
    m_detailsBrowser->setMaximumHeight(80);
    m_detailsBrowser->setPlainText(m_mfaMessage);
    m_detailsBrowser->setStyleSheet("font-family: monospace; font-size: 10px; "
                                    "background-color: #2d2d2d; color: #f0f0f0;");
    mainLayout->addWidget(m_detailsBrowser);

    // Info label
    QLabel *infoLabel = new QLabel(
        "<p>Credential-based login is not supported for accounts with MFA enabled.</p>"
        "<p>Please use <b>Device Code</b> or <b>Token-based</b> login instead.</p>",
        this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("font-size: 11px;");
    mainLayout->addWidget(infoLabel);

    mainLayout->addStretch();

    // OK button
    auto *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    m_okBtn = new QPushButton("OK", this);
    m_okBtn->setMinimumWidth(100);
    m_okBtn->setDefault(true);
    connect(m_okBtn, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(m_okBtn);

    mainLayout->addLayout(buttonLayout);
}

QString MfaPromptDialog::getMfaDescription(const QString &code)
{
    if (code == "AADSTS50076") {
        return "This account requires Multi-Factor Authentication. "
               "The user has not completed MFA setup or the MFA claim is missing.";
    }
    if (code == "AADSTS50079") {
        return "The user needs to enroll in Multi-Factor Authentication. "
               "MFA registration is required before accessing this resource.";
    }
    if (code == "AADSTS50158") {
        return "An external security challenge was not satisfied. "
               "This usually means Conditional Access policies require additional verification.";
    }
    if (code == "AADSTS53003") {
        return "Access has been blocked by Conditional Access policies. "
               "The access policy does not allow token issuance for this request.";
    }
    if (code == "AADSTS50074") {
        return "Strong authentication (MFA) is required. "
               "The user must pass a secondary authentication challenge.";
    }
    if (code == "AADSTS500121") {
        return "Authentication failed during strong authentication request. "
               "The MFA verification was not completed or timed out.";
    }
    return "Multi-Factor Authentication or Conditional Access is required for this account.";
}
