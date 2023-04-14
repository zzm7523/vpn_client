#ifndef __SELECT_CERTIFICATE_H__
#define __SELECT_CERTIFICATE_H__

#include "config/config.h"

#include <QDialog>
#include <QWidget>
#include <QPixmap>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidgetItem>
#include <QList>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace Ui {
	class SelectCertificate;
}

class X509CertificateInfo;

class X509CertificateInfoWidget : public QWidget
{
	Q_OBJECT
public:
	X509CertificateInfoWidget(QWidget *parent, QListWidgetItem *item, X509CertificateInfo *cert_info);
	~X509CertificateInfoWidget();

	QListWidgetItem* getItem() const;
	X509CertificateInfo* getCertificateInfo() const;

public slots:
	void click(QListWidgetItem *item);
	void showCertificateDetail();

private:
	QListWidgetItem *item;
	QToolButton *button;
	X509CertificateInfo *cert_info;

};

class SelectCertificate : public QDialog
{
	Q_OBJECT
public:
	SelectCertificate(QWidget *parent, const QString& windowTitle, const QString& x509UserNameField,
		const QString& tlsVersion, const QStringList& keyTypes, const QStringList& issuers);
	~SelectCertificate();

	X509CertificateInfo* getCertificateInfo() const;
	bool hasCertificateInfo(X509CertificateInfo *cert_info);

public slots:
#ifdef ENABLE_GUOMI
#ifdef _WIN32
	void timerSacnMyStore();
#endif
	void loadCandidateCertificates(const QString& providerName, bool plug = true);
#else
	void loadCandidateCertificates();
#endif

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void done(int r);
	void on_ckAllCert_stateChanged(int state);
	void on_cmdRefresh_clicked();

private:
	bool isCandidateCertificate(X509 *x509_cert);
	void updateUI();
	void freeX509CertificateInfos(const QList<X509CertificateInfo*>& cert_infos);

	Ui::SelectCertificate *m_ui;

	QString x509UserNameField;
	QString tlsVersion;
	QStringList keyTypes;
	QStringList issuers;
	int scanMyStoreNum;

	X509CertificateInfo *selected_cert_info;

	QList<X509CertificateInfo*> all_device_certs;
	QList<X509CertificateInfo*> all_p12_certs;
	QList<X509CertificateInfo*> all_mystore_certs;

};

#endif
