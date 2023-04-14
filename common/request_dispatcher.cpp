#include "request_dispatcher.h"

QMutex RequestDispatcher::globalServantsMutex(QMutex::Recursive);
QMap<QString, Skeleton*> RequestDispatcher::globalServants;
QMap<QString, SkeletonFactory*> RequestDispatcher::globalServantFactorys;

void RequestDispatcher::registerFactory(const QString& objectType, SkeletonFactory *factory)
{
	QMutexLocker locker(&globalServantsMutex);
	globalServantFactorys.insert(objectType, factory);
}

void RequestDispatcher::unregisterFactory(const QString& objectType)
{
	QMutexLocker locker(&globalServantsMutex);
	globalServantFactorys.remove(objectType);
}

void RequestDispatcher::registerServant(const QString& objectType, Skeleton *skeleton)
{
	QString globalUniqueIdentify = QString(QLatin1String("%1:%2")).arg(objectType).arg(skeleton->getUniqueIdentify()); 

	QMutexLocker locker(&globalServantsMutex);

	Q_ASSERT(!globalServants.contains(globalUniqueIdentify));

	Skeleton *dangling = globalServants.value(globalUniqueIdentify);
	if (dangling) {
//		delete dangling;	// ?? 安全起见, 不删除; 会造成内存泄漏
		globalServants.remove(globalUniqueIdentify);
	}

#ifdef _DEBUG
	QMutableMapIterator<QString, Skeleton*> i(globalServants);
	while (i.hasNext()) {
		i.next();
		Q_ASSERT(i.value() != skeleton);
	}
#endif

	globalServants.insert(globalUniqueIdentify, skeleton);
}

void RequestDispatcher::unregisterServant(Skeleton *skeleton)
{
	if (skeleton) {
		QMutexLocker locker(&globalServantsMutex);

		QMutableMapIterator<QString, Skeleton*> i(globalServants);
		while (i.hasNext()) {
			if (i.next().value() == skeleton) {
				i.remove();
				break;
			}
		}
	}
}

void RequestDispatcher::dispatch()
{
	Skeleton *skeleton = NULL;
	Request *request = NULL;

	while (!TcpConnection::globalRequestQueue.isEmpty()) {
		if ((request = TcpConnection::globalRequestQueue.dequeue())) {
			globalServantsMutex.lock();
			skeleton = findServant(request->getType(), request->getObject());
			globalServantsMutex.unlock();

			try {
				if (skeleton)
					skeleton->processRequest(request);
				else {
					TcpConnection *connection = request->getConnection();
					Q_ASSERT(connection);

					if (!request->isOneway()) {
						QString reasonPhrase = QString(QLatin1String("locate servant %1:%2 fail"))
							.arg(request->getType()).arg(request->getObject());
						Response response(request->getRequestId(), Response::LOCATE_SERVANT_FAIL, reasonPhrase);
						connection->sendResponse(&response);
					}
				}
			} catch (const SocketException& ex) {
				// 忽略SocketException异常, 客户端可能异常终止
				qDebug() << "RequestDispatcher::dispatch(...), " << ex.getMessage();
			}
			delete request;
		}
	}
}

Skeleton* RequestDispatcher::findServant(const QString& objectType, const QString& uniqueIdentify)
{
	QString globalUniqueIdentify = QString(QLatin1String("%1:%2")).arg(objectType).arg(uniqueIdentify); 
	Skeleton *skeleton = globalServants.value(globalUniqueIdentify);

	if (!skeleton) {
		SkeletonFactory *factory = globalServantFactorys.value(objectType);
		if (factory) {
			skeleton = factory->newInstance(uniqueIdentify);
			globalServants.insert(globalUniqueIdentify, skeleton);
		}
	}

	return skeleton;
}
