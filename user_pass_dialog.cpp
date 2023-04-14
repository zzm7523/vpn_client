#include <QShowEvent>
#include <QDir>
#include <QFile>
#include <QPushButton>

#include "common/common.h"
#include "common/dialog_util.h"

#include "user_pass_dialog.h"
#include "ui_user_pass_dialog.h"

UserPassDialog::UserPassDialog(QWidget *parent, const QString& windowTitle, const QString& description,
		const QString& userName)
	: QDialog(parent),  m_ui(new Ui::UserPassDialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

	if (!description.isEmpty())
		m_ui->lblDescription->setText(description);

	if (userName.isEmpty())
		m_ui->txtUserName->setFocus(Qt::ActiveWindowFocusReason);
	else {
		m_ui->txtUserName->setText(userName);
		m_ui->txtPassword->setFocus(Qt::ActiveWindowFocusReason);
	}

	// 输入用户名密码前, 无效OK按钮
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok)) {
#ifdef STRONG_SECURITY_RESTRICTION
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
#else
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(!m_ui->txtUserName->text().isEmpty());
#endif
	}

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	QObject::connect(m_ui->txtUserName, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtPassword, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
}

UserPassDialog::~UserPassDialog()
{
	delete m_ui;
}

QString UserPassDialog::getUserName() const
{
	return m_ui->txtUserName->text();
}

QString UserPassDialog::getPassword() const
{
	return m_ui->txtPassword->text();
}

void UserPassDialog::changeEvent(QEvent *e)
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

void UserPassDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void UserPassDialog::onTextChanged(const QString& text)
{
	Q_UNUSED(text);

	// 用户名、密码都不为空时, 有效OK按钮
	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (okButton) {
		okButton->setEnabled(!m_ui->txtUserName->text().isEmpty()
#ifdef STRONG_SECURITY_RESTRICTION
			&& !m_ui->txtPassword->text().isEmpty()
#endif
			);
	}
}
