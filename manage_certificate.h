#ifndef __MANAGE_CERTIFICATE_H__
#define __MANAGE_CERTIFICATE_H__

#include "config/config.h"

#include <QDialog>
#include <QTreeWidgetItem>
#include <QString>
#include <QMap>
#include <QMapIterator>
#include <QList>
#include <QListIterator>
#include <QDateTime>
#include <QByteArray>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace Ui {
	class ManageCertificate;
}

class ManageCertificate : public QDialog
{
	Q_OBJECT
public:
	ManageCertificate(QWidget *parent, const QString& windowTitle);
	~ManageCertificate();

public slots:
#ifdef ENABLE_GUOMI
#ifdef _WIN32
	void timerSacnMyStore();
#endif
	void loadClientCertificates(const QString& providerName, bool plug = true);
#else
	void loadClientCertificates();
#endif

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void on_cmdImport_clicked();
	void on_cmdRemove_clicked();
	void on_cmdRefresh_clicked();
	void on_cmdClose_clicked();
	void on_tabWidget_currentChanged(int index);
	void on_trvClientCerts_itemDoubleClicked(QTreeWidgetItem *item, int column);
	void on_trvIssuerCerts_itemDoubleClicked(QTreeWidgetItem *item, int column);
	void on_trvClientCerts_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
	void on_trvIssuerCerts_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);

private:
	void loadClientCertificate(X509 *cert, const QString& source, const QString& identity, int index);
	void loadCaCertificates();
	void updateTabClientCertsUI();
	bool importPkcs12(const QString& pkcs12File, const QString& protectPassword);
	bool importCaCertificate(const QString& caFile);
	X509* getClientCertificateByIndex(int index) const;
	QString generateUniqueFileName(const QString& dirname, const QString& suffix);

	QMap<X509*, int> allDeviceClientCertMap_i;
	QMap<X509*, QString> allDeviceClientCertMap_s;

	QMap<X509*, int> allP12ClientCertMap_i;
	QMap<X509*, QString> allP12ClientCertMap_s;

	QMap<X509*, int> allMyStoreClientCertMap_i;
	QMap<X509*, QString> allMyStoreClientCertMap_s;

	QMap<int, X509*> allCaCertMap;

	int scanMyStoreNum;
	int cert_index;
	Ui::ManageCertificate *m_ui;

};

#endif
