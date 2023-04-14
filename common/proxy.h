#ifndef __PROXY_H__
#define __PROXY_H__

#include "../config/config.h"

#include <QString>
#include <QObject>

#ifdef _WIN32
#pragma warning(disable:4100)
#endif

#include "common.h"
#include "connection.h"

class Proxy : public QObject
{
	Q_OBJECT
public:
	Proxy(const QString& _uniqueIdentify, TcpConnection *_connection)
		: uniqueIdentify(_uniqueIdentify), connection(_connection) {
		if (connection) {
			QObject::connect(connection, SIGNAL(disconnected()), this, SIGNAL(disconnected()));
			connection->incRefCount();
		}
	}
	virtual ~Proxy() {
		if (connection) {
			QObject::disconnect(connection, 0, this, 0);
			connection->decRefCount();
			connection = NULL;
		}
	}

	bool isValid() const {
		Q_ASSERT (connection->getRefCount() != 0);
		return connection && connection->state() == QAbstractSocket::ConnectedState;
	}

	const QString& getUniqueIdentify() const {
		return uniqueIdentify;
	}

	TcpConnection* getConnection() const {
		return connection;
	}

	bool operator==(const Proxy& other) {
		return this->uniqueIdentify == other.uniqueIdentify && this->connection == other.connection;
	}

signals:
	void disconnected();

protected:
	QString uniqueIdentify;
	TcpConnection *connection;

};

class Skeleton
{
public:
	explicit Skeleton(const QString& _uniqueIdentify)
		: uniqueIdentify(_uniqueIdentify) {
	}
	virtual ~Skeleton() {
	}

	const QString& getUniqueIdentify() const {
		return uniqueIdentify;
	}

	bool operator==(const Skeleton& other) {
		return this->uniqueIdentify == other.uniqueIdentify;
	}

	virtual void processRequest(Request *request) = 0;

protected:
	QString uniqueIdentify;

};

class SkeletonFactory
{
public:
	virtual Skeleton* newInstance(const QString& uniqueIdentify) = 0;

};

template<typename T>
class GeneralSkeletonFactory : public SkeletonFactory
{
public:
	Skeleton* newInstance(const QString& uniqueIdentify) {
		return new T(uniqueIdentify);
	}

};

template<typename T> QString encodeToQString(const T& t)
{
	QByteArray bytes;
	QDataStream out(&bytes, QIODevice::WriteOnly);
	out.setVersion(QDataStream::Qt_5_2);
	Q_ASSERT (out.status() == QDataStream::Ok);

	out << t;
	Q_ASSERT (out.status() == QDataStream::Ok);

	return QString::fromUtf8(bytes.toBase64());
}

template<typename T> T decodeFromQString(const QString& string)
{
	QByteArray bytes;
    bytes.append(string.toUtf8());

	QDataStream in(QByteArray::fromBase64(bytes));
	in.setVersion(QDataStream::Qt_5_2);
//	Q_ASSERT (in.status() == QDataStream::Ok);

	T t;

	in >> t;
//	Q_ASSERT (in.status() == QDataStream::Ok);

	return in.status() == QDataStream::Ok ? t : T();
}

#endif
