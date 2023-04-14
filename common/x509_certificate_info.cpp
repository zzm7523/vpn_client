#include "x509_certificate_util.h"
#include "x509_certificate_info.h"

const unsigned int X509CertificateInfo::serial_uid = 0x361;

X509CertificateInfo::X509CertificateInfo(X509 *_x509_cert, const QString& _source, const QString& _identity)
	: x509_cert(NULL), source(_source), identity(_identity)
{
	if (_x509_cert)
		this->x509_cert = X509_dup(_x509_cert);
}

X509CertificateInfo::X509CertificateInfo(const X509CertificateInfo& certInfo)
	: x509_cert(NULL), source(certInfo.source), identity(certInfo.identity)
{
	if (certInfo.x509_cert)
		this->x509_cert = X509_dup(certInfo.x509_cert);
}

X509CertificateInfo::X509CertificateInfo()
	: x509_cert(NULL)
{
}

X509CertificateInfo::~X509CertificateInfo()
{
	if (this->x509_cert)
		X509_free(this->x509_cert);
}

bool X509CertificateInfo::isEmpty() const
{
	return x509_cert == NULL;
}

void X509CertificateInfo::clear()
{
	if (x509_cert)
		X509_free(x509_cert);
	x509_cert = NULL;
	source.clear();
	identity.clear();
}

X509* X509CertificateInfo::getCertificate() const
{
	return x509_cert;
}

void X509CertificateInfo::setCertificate(X509 *x509_cert)
{
	if (this->x509_cert)
		X509_free(this->x509_cert);

	if (x509_cert)
		this->x509_cert = X509_dup(x509_cert);
	else
		this->x509_cert = NULL;
}

const QString& X509CertificateInfo::getSource() const
{
	return source;
}

void X509CertificateInfo::setSource(const QString& source)
{
	this->source = source;
}

const QString& X509CertificateInfo::getIdentity() const
{
	return identity;
}

void X509CertificateInfo::setIdentity(const QString& identity)
{
	this->identity = identity;
}

bool X509CertificateInfo::operator == (const X509CertificateInfo& other)
{
	if ((this->x509_cert && !other.x509_cert) || (!this->x509_cert && other.x509_cert))
		return false;
	if (X509_cmp(this->x509_cert, other.x509_cert) != 0)
		return false;

	return this->source == other.source && this->identity == other.identity;
}

bool X509CertificateInfo::operator != (const X509CertificateInfo& other)
{
	return !(*this == other);
}

X509CertificateInfo& X509CertificateInfo::operator = (const X509CertificateInfo& other)
{
	// 可能是自我赋值， 保留当前证书指针
	X509 *curr_x509 = this->x509_cert;

	if (other.x509_cert)
		this->x509_cert = X509_dup(other.x509_cert);
	else
		this->x509_cert = NULL;

	if (curr_x509)
		X509_free(curr_x509);

	this->source = other.source;
	this->identity = other.identity;

	return *this;
}

QDataStream& operator<<(QDataStream& stream, const X509CertificateInfo& certInfo)
{
	stream << X509CertificateInfo::serial_uid << X509CertificateUtil::encode_to_base64(certInfo.x509_cert)
		<< certInfo.source << certInfo.identity;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, X509CertificateInfo& certInfo)
{
	unsigned int local_serial_uid;
	QString base64_cert;

	stream >> local_serial_uid >> base64_cert >> certInfo.source >> certInfo.identity;
	if (certInfo.x509_cert)
		X509_free(certInfo.x509_cert);
	certInfo.x509_cert = X509CertificateUtil::decode_from_base64(base64_cert);

	Q_ASSERT (X509CertificateInfo::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}

