#ifndef __TRUST_CERTIFICATE_H__
#define __TRUST_CERTIFICATE_H__

#include "config/config.h"

#include <QDialog>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace Ui {
	class TrustCertificate;
}

class TrustCertificate : public QDialog
{
	Q_OBJECT
public:
	TrustCertificate(QWidget *parent, const QString& windowTitle, const QList<X509*>& x509List);
	~TrustCertificate();

	bool isPersist() const;

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void on_btnMoreInfo_clicked();

private:
	QList<X509*> x509List;
	Ui::TrustCertificate *m_ui;

};

#endif
