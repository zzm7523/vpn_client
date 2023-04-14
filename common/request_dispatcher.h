#ifndef __REQUEST_DISPATCHER_H__
#define __REQUEST_DISPATCHER_H__

#include "../config/config.h"

#include <QString>
#include <QList>
#include <QMap>
#include <QMutex>

#include "proxy.h"
#include "connection.h"

class RequestDispatcher
{
public:
	static void registerFactory(const QString& objectType, SkeletonFactory *factory);
	static void unregisterFactory(const QString& objectType);

	static void registerServant(const QString& objectType, Skeleton *skeleton);
	static void unregisterServant(Skeleton *skeleton);

	static void dispatch();

private:
	static Skeleton* findServant(const QString& objectType, const QString& uniqueIdentify);

	static QMutex globalServantsMutex;
	static QMap<QString, Skeleton*> globalServants;
	static QMap<QString, SkeletonFactory*> globalServantFactorys;

};

#endif
