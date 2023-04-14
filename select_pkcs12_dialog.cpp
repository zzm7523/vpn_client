#include <QShowEvent>
#include <QDir>
#include <QFile>
#include <QFileDialog>

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/pkcs12_util.h"
#include "common/message_box_util.h"
#include "settings.h"

#include "select_pkcs12_dialog.h"
#include "ui_select_pkcs12_dialog.h"

SelectPkcs12Dialog::SelectPkcs12Dialog(QWidget *parent, const QString& windowTitle)
	: QDialog(parent), m_ui(new Ui::SelectPkcs12Dialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	// 保护密码可以为空
	QObject::connect(m_ui->txtPkcs12, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
}

SelectPkcs12Dialog::~SelectPkcs12Dialog()
{
	delete m_ui;
}

QString SelectPkcs12Dialog::getPkcs12File() const
{
	return m_ui->txtPkcs12->text();
}

QString SelectPkcs12Dialog::getProtectPassword() const
{
	return m_ui->txtPassword->text();
}

void SelectPkcs12Dialog::changeEvent(QEvent *e)
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

void SelectPkcs12Dialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void SelectPkcs12Dialog::onTextChanged(const QString& text)
{
	Q_UNUSED(text);

	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (okButton) {
		okButton->setEnabled(!m_ui->txtPkcs12->text().isEmpty());
	}
}

void SelectPkcs12Dialog::on_cmdPkcs12_clicked()
{
	const QString p12FileName = QFileDialog::getOpenFileName(this, tr("Select PKCS12 file"),
		Settings::instance()->getLastAccessPath(), tr("Personal Information Exchange (*.p12 *.pfx);;All Files (*.*)"));

    if (!p12FileName.isEmpty()) {
		m_ui->txtPkcs12->setText(QDir::toNativeSeparators(p12FileName));
		Settings::instance()->setLastAccessPath(QFileInfo(p12FileName).absolutePath());
    }
}

void SelectPkcs12Dialog::done(int r)
{
	if (QDialog::Accepted == r) {
		EVP_PKEY *prvkey = NULL;
		X509 *cert = NULL;

		if (!Pkcs12Util::readPkcs12(getPkcs12File(), getProtectPassword().toLocal8Bit(), &prvkey, &cert, NULL)) {
			MessageBoxUtil::error(this, tr("Certificate import"), tr("The password you entered is incorrect"));
			return;
		} else {
			if (prvkey)
				EVP_PKEY_free(prvkey);
			if (cert)
				X509_free(cert);
		}
	}

	QDialog::done(r);
}
