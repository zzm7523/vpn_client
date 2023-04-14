#include "common.h"
#include "credentials.h"
#include "x509_certificate_util.h"

const unsigned int Credentials::serial_uid = 0x057;

Credentials::Credentials(const X509CertificateInfo& _certInfo, const QByteArray& _keyPassword,
		const QString& _userName, const QString& _password, const QString& _otp,
		const QString& _proxyUserName, const QString& _proxyPassword)
	: certInfo(_certInfo), keyPassword(_keyPassword), userName(_userName), password(_password),
	otp(_otp), proxyUserName(_proxyUserName), proxyPassword(_proxyPassword)
{
}

Credentials::Credentials()
{
}

Credentials::~Credentials()
{
}

const X509CertificateInfo& Credentials::getCertificateInfo() const
{
	return certInfo;
}

void Credentials::setCertificateInfo(const X509CertificateInfo& certInfo)
{
	this->certInfo = certInfo;
}

const QByteArray& Credentials::getKeyPassword() const
{
	return keyPassword;
}

void Credentials::setKeyPassword(const QByteArray& keyPassword)
{
	this->keyPassword = keyPassword;
}

const QString& Credentials::getUserName() const
{
	return userName;
}

void Credentials::setUserName(const QString& userName)
{
	this->userName = userName;
}

const QString& Credentials::getPassword() const
{
	return password;
}

void Credentials::setPassword(const QString& password)
{
	this->password = password;
}

const QString& Credentials::getOtp() const
{
	return otp;
}

void Credentials::setOtp(const QString& otp)
{
	this->otp = otp;
}

const QString& Credentials::getProxyUserName() const
{
	return proxyUserName;
}

void Credentials::setProxyUserName(const QString& proxyUserName)
{
	this->proxyUserName = proxyUserName;
}

const QString& Credentials::getProxyPassword() const
{
	return proxyPassword;
}

void Credentials::setProxyPassword(const QString& proxyPassword)
{
	this->proxyPassword = proxyPassword;
}

bool Credentials::isEmpty() const
{
	return certInfo.isEmpty() && keyPassword.isEmpty() && userName.isEmpty() && password.isEmpty()
		&& otp.isEmpty() && proxyUserName.isEmpty() && proxyPassword.isEmpty();
}

bool Credentials::hasAnyCrediantials() const
{
	return !certInfo.isEmpty() || !keyPassword.isEmpty() || !userName.isEmpty() || !password.isEmpty()
		|| !otp.isEmpty() || !proxyUserName.isEmpty() || !proxyPassword.isEmpty();
}

bool Credentials::hasCrediantials(Credentials::TypeOptions types) const
{
	if ((types & Credentials::CertificateInfo) && certInfo.isEmpty())
		return false;
	if ((types & Credentials::KeyPassword) && keyPassword.isEmpty())
		return false;
	if ((types & Credentials::UserName) && userName.isEmpty())
		return false;
	if ((types & Credentials::Password) && password.isEmpty())
		return false;
	if ((types & Credentials::Otp) && otp.isEmpty())
		return false;
	if ((types & Credentials::ProxyUserName) && proxyUserName.isEmpty())
		return false;
	if ((types & Credentials::ProxyPassword) && proxyPassword.isEmpty())
		return false;

	return true;
}

void Credentials::clear()
{
	certInfo.clear();
	keyPassword.clear();
	userName.clear();
	password.clear();
	otp.clear();
	proxyUserName.clear();
	proxyPassword.clear();
}

void Credentials::removeCredentials(Credentials::TypeOptions types)
{
	if (types & Credentials::CertificateInfo)
		certInfo.clear();
	if (types & Credentials::KeyPassword)
		keyPassword.clear();
	if (types & Credentials::UserName)
		userName.clear();
	if (types & Credentials::Password)
		password.clear();
	if (types & Credentials::Otp)
		otp.clear();
	if (types & Credentials::ProxyUserName)
		proxyUserName.clear();
	if (types & Credentials::ProxyPassword)
		proxyPassword.clear();
}

QDataStream& operator << (QDataStream& stream, const Credentials& credentials)
{
	stream << Credentials::serial_uid << credentials.certInfo << credentials.keyPassword << credentials.userName
		<< credentials.password << credentials.otp
		<< credentials.proxyUserName << credentials.proxyPassword;
	return stream;
}

QDataStream& operator >> (QDataStream& stream, Credentials& credentials)
{
	unsigned int local_serial_uid;

	stream >> local_serial_uid >> credentials.certInfo >> credentials.keyPassword >> credentials.userName
		>> credentials.password >> credentials.otp
		>> credentials.proxyUserName >> credentials.proxyPassword;

	Q_ASSERT(Credentials::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}
