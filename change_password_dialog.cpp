#include <QShowEvent>
#include <QPushButton>

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/message_box_util.h"

#include "change_password_dialog.h"
#include "ui_change_password_dialog.h"

ChangePasswordDialog::ChangePasswordDialog(QWidget *parent, const QString& windowTitle)
	: QDialog(parent), m_ui(new Ui::ChangePasswordDialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

	if (m_ui->buttonBox->button(QDialogButtonBox::Ok)) {
#ifdef STRONG_SECURITY_RESTRICTION
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
#else
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
#endif
	}

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	QObject::connect(m_ui->txtOldPassword, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtNewPassword, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtConfirmPassword, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
}

ChangePasswordDialog::~ChangePasswordDialog()
{
	delete m_ui;
}

void ChangePasswordDialog::changeEvent(QEvent *e)
{
	switch (e->type()) {
	case QEvent::LanguageChange:
		m_ui->retranslateUi(this);
#ifdef FIX_OK_CANCEL_TR
		if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
			m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
		if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
			m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
		break;
	default:
		break;
	}

	QDialog::changeEvent(e);
}

void ChangePasswordDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void ChangePasswordDialog::onTextChanged(const QString& text)
{
	Q_UNUSED(text);

#ifdef STRONG_SECURITY_RESTRICTION
	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (okButton) {
		okButton->setEnabled(!m_ui->txtOldPassword->text().isEmpty()
			&& !m_ui->txtNewPassword->text().isEmpty() && !m_ui->txtConfirmPassword->text().isEmpty());
	}
#endif
}

void ChangePasswordDialog::done(int r)
{
	if (QDialog::Accepted == r) {
		if (m_ui->txtNewPassword->text() != m_ui->txtConfirmPassword->text()) {
			m_ui->txtNewPassword->setFocus(Qt::OtherFocusReason);
			MessageBoxUtil::error(this, tr("Change password"), tr("Password mismatching"));
			return;
		} else if (m_ui->txtNewPassword->text() == m_ui->txtOldPassword->text()) {
			m_ui->txtNewPassword->setFocus(Qt::OtherFocusReason);
			MessageBoxUtil::error(this, tr("Change password"), tr("New password equal old password"));
			return;
		}
	}

	QDialog::done(r);
}

QString ChangePasswordDialog::getOldPassword() const
{
	return m_ui->txtOldPassword->text();
}

QString ChangePasswordDialog::getNewPassword() const
{
	return m_ui->txtNewPassword->text();
}
