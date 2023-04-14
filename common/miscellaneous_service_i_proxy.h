#ifndef __MISCELLANEOUS_SERVICE_PROXY_H__
#define __MISCELLANEOUS_SERVICE_PROXY_H__

#include "../config/config.h"
#include "proxy.h"
#include "miscellaneous_service_i.h"

class MiscellaneousServiceProxy : public Proxy, public MiscellaneousServiceI
{
	Q_OBJECT
public:
	MiscellaneousServiceProxy(const QString& uniqueIdentify, TcpConnection *connection);

	virtual bool changeLanguage(const QString& language, const Context& ctx = Context::getDefaultContext());

	virtual QString generateFingerprint(const Context& ctx = Context::getDefaultContext());

	virtual QString getFingerprint(const QString& fileName, const Context& ctx = Context::getDefaultContext());
	virtual void saveFingerprint(const QString& fileName, const QString& fingerprint,
		const Context& ctx = Context::getDefaultContext());

	virtual ExecuteResult execute(const QString& program, const QStringList& arguments,
		const QString& workingDirectory, const Context& ctx = Context::getDefaultContext());

};

#endif
