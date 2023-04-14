#include <QShowEvent>
#include <QPushButton>

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/x509v3_ext.h"
#include "common/x509_name.h"
#include "common/x509_certificate_util.h"

#include "widgets/distname.h"
#include "ui_certificate_detail.h"
#include "certificate_detail.h"

CertificateDetail::CertificateDetail(QWidget *parent, const QString& windowTitle)
	: QDialog(parent), m_ui(new Ui::CertificateDetail)
{
	m_ui->setupUi(this);
	m_ui->tabwidget->setCurrentIndex(0);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
}

CertificateDetail::~CertificateDetail()
{
	delete m_ui;
}

void CertificateDetail::setCertChain(const QList<X509*>& certChain)
{
	X509 *cert = certChain.at(0);
	
	m_ui->txtVersion->setText(QString::number(X509_get_version(cert) + 1));

	// details of the subject
	X509_NAME *xn = X509_get_subject_name(cert);
	m_ui->subject->setX509name(x509_name(xn));

	// V3 extensions
	x509v3_ext_list el;
	
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	el.setStack(cert->cert_info->extensions);
#else
	el.setStack(X509_get0_extensions(cert));
#endif
	if (el.count() == 0) {
		m_ui->tabwidget->removeTab(4);
	} else {
		exts = el.getHtml(QLatin1String("<br>"));
		m_ui->v3extensions->document()->setHtml(exts);
	}

	EVP_PKEY *pkey = X509_get_pubkey(cert);
	if (pkey) {
		int type = EVP_PKEY_id(pkey);
		QString pubKeyDescn;

		if (EVP_PKEY_type(type) == EVP_PKEY_RSA) {
			pubKeyDescn.append(tr("RSA")).append(" ");
		} else if (EVP_PKEY_type(type) == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			EC_KEY* ec = pkey->pkey.ec;
#else
			EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
#endif
			int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));

			pubKeyDescn.append(tr("EC")).append(" ");
			pubKeyDescn.append(OBJ_nid2sn(nid)).append(" ");
		} else if (EVP_PKEY_type(type) == EVP_PKEY_DSA) {
			pubKeyDescn.append(tr("DSA")).append(" ");
		} else {
			pubKeyDescn.append(tr("Unknown")).append(" ");
		}

		pubKeyDescn.append(QString::number(EVP_PKEY_bits(pkey))).append(" ").append(tr("bits"));
		m_ui->txtPubKey->setText(pubKeyDescn);
	}

	// Algorithm
	m_ui->txtSigAlgo->setText(X509CertificateUtil::get_sig_alg_name(cert));

	// the serial
	m_ui->txtSerial->setText(X509CertificateUtil::get_serial_number(cert));

	// details of the issuer
	xn = X509_get_issuer_name(cert);
	m_ui->issuer->setX509name(x509_name(xn));

	// The dates
	m_ui->txtNotBefore->setText(X509CertificateUtil::get_not_before(cert).toString(QLatin1String("yyyy-MM-dd hh:mm:ss")));
	m_ui->txtNotAfter->setText(X509CertificateUtil::get_not_after(cert).toString(QLatin1String("yyyy-MM-dd hh:mm:ss")));

	// the fingerprints
#ifdef ENABLE_GUOMI
	if (X509CertificateUtil::get_sig_alg_nid(cert) == NID_sm3WithSM2Encryption) {
		m_ui->lblFP1->setText(tr("SHA1"));
		m_ui->txtFP1->setText(X509CertificateUtil::get_sha1_fingerprint(cert, true));
		m_ui->lblFP2->setText(tr("SM3"));
		m_ui->txtFP2->setText(X509CertificateUtil::get_sm3_fingerprint(cert, true));
	} else
#endif	
	{
		m_ui->lblFP1->setText(tr("MD5"));
		m_ui->txtFP1->setText(X509CertificateUtil::get_md5_fingerprint(cert, true));
		m_ui->lblFP2->setText(tr("SHA1"));
		m_ui->txtFP2->setText(X509CertificateUtil::get_sha1_fingerprint(cert, true));
	}
}

void CertificateDetail::changeEvent(QEvent *e)
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

void CertificateDetail::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}
