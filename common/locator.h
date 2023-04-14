#ifndef __LOCATOR_H__
#define __LOCATOR_H__

#include "../config/config.h"

#include <QString>
#include <QList>
#include <QMutex>
#include <QHostAddress>

#include "connection.h"

class Locator
{
public:
	template<typename T>
	static T* locate(const QHostAddress& hostAddress, quint16 port, const QString& uniqueIdentify) {
		QMutableListIterator<TcpConnection*> i(globalConnections);
		TcpConnection* connection = NULL;

		globalConnectionsMutex.lock();

		while (i.hasNext()) {
			connection = i.next();
			Q_ASSERT (connection && connection->getRefCount() != 0);
			if (connection && connection->state() == QAbstractSocket::ConnectedState &&
					hostAddress == connection->peerAddress() && port == connection->peerPort())
				break;
			connection = NULL;
		}

		globalConnectionsMutex.unlock();

		if (!connection) {
			connection = new TcpConnection();
			connection->connectToHost(hostAddress, port);
			if (connection->waitForConnected(5000))	// 5秒超时应该足够了
				registerConnection(connection);
			else {
				connection->deleteLater();
				throw SocketException(__FILE__, __LINE__, "Connect to the service failed");
			}
		}

		return new T(uniqueIdentify, connection);
	}

	static void registerConnection(TcpConnection *connection);
	static void unregisterConnection(TcpConnection *connection);
	static void unregisterAllConnections();

private:
	static QMutex globalConnectionsMutex;
	static QList<TcpConnection*> globalConnections;

};

#endif
