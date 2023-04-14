#include "common.h"
#include "tls_auth.h"

const unsigned int TLSAuth::serial_uid = 0x111;

TLSAuth::TLSAuth(const QString& _fileName, const QString& _auth, int _direction)
	: fileName(_fileName), auth(_auth), direction(_direction)
{
	Q_ASSERT(direction == KEY_DIRECTION_BIDIRECTIONAL || direction == KEY_DIRECTION_NORMAL
		|| direction == KEY_DIRECTION_INVERSE);
}

TLSAuth::TLSAuth()
	: direction(KEY_DIRECTION_BIDIRECTIONAL)
{
}

bool TLSAuth::isEmpty() const
{
	return this->auth.isEmpty() || this->fileName.isEmpty();
}

void TLSAuth::clear()
{
	this->fileName.clear();
	this->auth = QLatin1String("SHA1");
	this->direction = KEY_DIRECTION_BIDIRECTIONAL;
}

const QString& TLSAuth::getFileName() const
{
	return this->fileName;
}

void TLSAuth::setFileName(const QString& fileName)
{
	this->fileName = fileName;
}

const QString& TLSAuth::getAuth() const
{
	return this->auth;
}

void TLSAuth::setAuth(const QString& auth)
{
	this->auth = auth;
}

int TLSAuth::getDirection() const
{
	return this->direction;
}

void TLSAuth::setDirection(int direction)
{
	if (direction == KEY_DIRECTION_BIDIRECTIONAL || direction == KEY_DIRECTION_NORMAL
			|| direction == KEY_DIRECTION_INVERSE)
		this->direction = direction;
}

bool TLSAuth::operator == (const TLSAuth& other) const
{
	return this->fileName.compare(other.fileName, Qt::CaseInsensitive) == 0
		&& this->auth.compare(other.auth, Qt::CaseInsensitive) == 0
		&& this->direction == other.direction;
}

bool TLSAuth::operator != (const TLSAuth& other) const
{
	return this->fileName.compare(other.fileName, Qt::CaseInsensitive) != 0
		|| this->auth.compare(other.auth, Qt::CaseInsensitive) != 0
		|| this->direction != other.direction;
}

QDataStream& operator<<(QDataStream& stream, const TLSAuth& tlsAuth)
{
	stream << TLSAuth::serial_uid << tlsAuth.fileName << tlsAuth.auth << tlsAuth.direction;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, TLSAuth& tlsAuth)
{
	unsigned int local_serial_uid;

	stream >> local_serial_uid >> tlsAuth.fileName >> tlsAuth.auth >> tlsAuth.direction;

	Q_ASSERT(TLSAuth::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}
