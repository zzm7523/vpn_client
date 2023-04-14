#ifndef __CREDENTIALS_H__
#define __CREDENTIALS_H__

#include "../config/config.h"

#include <QString>
#include <QByteArray>
#include <QDataStream>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "x509_certificate_info.h"

class Credentials
{
public:
	enum TypeOptionFlag
	{
		CertificateInfo = 0x0001,
		KeyPassword     = 0x0002,
		UserName        = 0x0004,
		Password        = 0x0010,
		Otp             = 0x0020,
		ProxyUserName   = 0x0040,
		ProxyPassword   = 0x0100
	};
	Q_DECLARE_FLAGS(TypeOptions, TypeOptionFlag)

	Credentials(const X509CertificateInfo& certInfo, const QByteArray& keyPassword, const QString& userName,
		const QString& password, const QString& otp, const QString& proxyUserName, const QString& proxyPassword);
	Credentials();
	~Credentials();

	const X509CertificateInfo& getCertificateInfo() const;
	void setCertificateInfo(const X509CertificateInfo& certInfo);

	const QByteArray& getKeyPassword() const;
	void setKeyPassword(const QByteArray& keyPassword);

	const QString& getUserName() const;
	void setUserName(const QString& userName);

	const QString& getPassword() const;
	void setPassword(const QString& password);

	const QString& getOtp() const;
	void setOtp(const QString& otp);

	const QString& getProxyUserName() const;
	void setProxyUserName(const QString& proxyUserName);

	const QString& getProxyPassword() const;
	void setProxyPassword(const QString& proxyPassword);

	bool isEmpty() const;

	bool hasAnyCrediantials() const;
	bool hasCrediantials(Credentials::TypeOptions types) const;

	void clear();
	void removeCredentials(Credentials::TypeOptions types);

private:
	friend QDataStream& operator<<(QDataStream& stream, const Credentials& credentials);
	friend QDataStream& operator>>(QDataStream& stream, Credentials& credentials);

	X509CertificateInfo certInfo;
	QByteArray keyPassword;

	QString userName;
	QString password;
	QString otp;	// 一次性密码

	QString proxyUserName;
	QString proxyPassword;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(Credentials)
Q_DECLARE_OPERATORS_FOR_FLAGS(Credentials::TypeOptions)

#endif
