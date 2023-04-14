#include <QShowEvent>
#include <QPushButton>

#include "common/common.h"
#include "common/dialog_util.h"

#include "passphrase_dialog.h"
#include "ui_passphrase_dialog.h"

PassphraseDialog::PassphraseDialog(QWidget *parent, const QString& windowTitle, const QString& description,
		const QString& pathName)
	: QDialog(parent), m_ui(new Ui::PassphraseDialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

	if (!description.isEmpty())
		m_ui->lblDescription->setText(description);

	m_ui->lblPathName->setText(pathName);
	m_ui->txtPassword->setFocus(Qt::ActiveWindowFocusReason);

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
}

PassphraseDialog::~PassphraseDialog()
{
	delete m_ui;
}

void PassphraseDialog::setDescription(const QString& description)
{
	m_ui->lblDescription->setText(description);
}

void PassphraseDialog::clearPassphrase()
{
	m_ui->txtPassword->clear();
}

QString PassphraseDialog::getPassphrase() const
{
	return m_ui->txtPassword->text();
}

void PassphraseDialog::changeEvent(QEvent *e)
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

void PassphraseDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void PassphraseDialog::on_txtPassword_textChanged(const QString& text)
{
	Q_UNUSED(text);

#ifdef STRONG_SECURITY_RESTRICTION
	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (okButton) {
		okButton->setEnabled(!m_ui->txtPassword->text().isEmpty());
	}
#endif
}
