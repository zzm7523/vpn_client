#ifndef __X509_CERTIFICATE_INFO_H__
#define __X509_CERTIFICATE_INFO_H__

#include "../config/config.h"

#include <QString>
#include <QByteArray>
#include <QDataStream>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define ENCRYPT_DEVICE_SOURCE	"__encrypt_device_source__"
#define PKCS12_FILE_SOURCE		"__pkcs12_file_source__"
#define MS_CRYPTAPI_SOURCE		"__ms_cryptapi_source__"

class X509CertificateInfo
{
public:
	X509CertificateInfo(X509 *x509_cert, const QString& source, const QString& identity);
	X509CertificateInfo(const X509CertificateInfo& certInfo);
	X509CertificateInfo();
	~X509CertificateInfo();

	bool isEmpty() const;
	void clear();

	X509* getCertificate() const;
	void setCertificate(X509 *cert);

	const QString& getSource() const;
	void setSource(const QString& source);

	const QString& getIdentity() const;
	void setIdentity(const QString& identity);

	bool operator == (const X509CertificateInfo& other);
	bool operator != (const X509CertificateInfo& other);
	X509CertificateInfo& operator = (const X509CertificateInfo& other);

private:
	friend QDataStream& operator<<(QDataStream& stream, const X509CertificateInfo& certInfo);
	friend QDataStream& operator>>(QDataStream& stream, X509CertificateInfo& certInfo);

	X509 *x509_cert;
	QString source;
	QString identity;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(X509CertificateInfo)

#endif
