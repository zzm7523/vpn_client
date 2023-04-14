#include <QShowEvent>
#include <QPushButton>

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/x509_certificate_util.h"

#include "trust_certificate.h"
#include "ui_trust_certificate.h"
#include "certificate_detail.h"

TrustCertificate::TrustCertificate(QWidget *_parent, const QString& _windowTitle, const QList<X509*>& _x509List)
	: QDialog(_parent), x509List(_x509List), m_ui(new Ui::TrustCertificate)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(_windowTitle);

	m_ui->chkPersist->setChecked(false);
	Q_ASSERT(x509List.size() > 1);

	X509 *x509_cert = x509List.at(0);
	QString cn = X509CertificateUtil::get_friendly_name(x509_cert);
	m_ui->txtCN->setText(cn);
	QString issuer_cn = tr("(Not trusted)") + X509CertificateUtil::get_issuer_friendly_name(x509_cert);
	m_ui->txtIssuerCN->setText(issuer_cn);

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
}

TrustCertificate::~TrustCertificate()
{
	X509CertificateUtil::free_all_cert(x509List);

	delete m_ui;
}

void TrustCertificate::changeEvent(QEvent *e)
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

void TrustCertificate::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

bool TrustCertificate::isPersist() const
{
	return m_ui->chkPersist->isChecked();
}

void TrustCertificate::on_btnMoreInfo_clicked()
{
	CertificateDetail certDetail(this, CertificateDetail::tr("X509 certificate"));
	certDetail.setCertChain(x509List);
	certDetail.exec();
}
