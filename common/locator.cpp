#include "locator.h"

QMutex Locator::globalConnectionsMutex;
QList<TcpConnection*> Locator::globalConnections;

void Locator::registerConnection(TcpConnection *connection)
{
	QMutexLocker locker(&globalConnectionsMutex);

	if (connection && connection->state() == QAbstractSocket::ConnectedState && !globalConnections.contains(connection)) {
		globalConnections.prepend(connection);
		connection->incRefCount();
	}
}

void Locator::unregisterConnection(TcpConnection *connection)
{
	QMutexLocker locker(&globalConnectionsMutex);

	QMutableListIterator<TcpConnection*> i(globalConnections);

	while (i.hasNext()) {
		if (connection == i.next()) {
			connection->decRefCount();
			i.remove();
		}
	}
}

void Locator::unregisterAllConnections()
{
	QMutexLocker locker(&globalConnectionsMutex);

	QMutableListIterator<TcpConnection*> i(globalConnections);

	while (i.hasNext()) {
		TcpConnection *connection = i.next();
		connection->decRefCount();
		i.remove();
	}
}
