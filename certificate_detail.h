#ifndef __CERTIFICATE_DETAIL_H__
#define __CERTIFICATE_DETAIL_H__

#include "config/config.h"

#include <QDialog>
#include <QString>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace Ui {
	class CertificateDetail;
}

class CertificateDetail: public QDialog
{
	Q_OBJECT
public:
	CertificateDetail(QWidget *parent, const QString& windowTitle);
	~CertificateDetail();

	void setCertChain(const QList<X509*>& certChain);

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private:
	QString exts;
	Ui::CertificateDetail *m_ui;

};

#endif
