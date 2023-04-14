#ifndef __SERVICE_H__
#define __SERVICE_H__

#include "../config/config.h"
#include "../common/connection.h"
#include "qtservice.h"

#include <QCoreApplication>
#include <QTcpServer>

class Service : private QTcpServer, public QtService<QCoreApplication>
{
	Q_OBJECT
public:
	Service(int argc, char **argv);
	~Service();

protected:
	void incomingConnection(qintptr socket);
	void start();
	void stop();

private:
	void registerMetaTypes();

};

#endif
