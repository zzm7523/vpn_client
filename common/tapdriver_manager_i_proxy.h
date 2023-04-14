#ifndef __TAPDRIVER_MANAGER_I_PROXY_H__
#define __TAPDRIVER_MANAGER_I_PROXY_H__

#include "../config/config.h"

#include <QString>

#include "proxy.h"
#include "tapdriver_manager_i.h"

class TapDriverManagerProxy : public Proxy, public TapDriverManagerI
{
	Q_OBJECT
public:
	TapDriverManagerProxy(const QString& uniqueIdentify, TcpConnection *connection);
	virtual ~TapDriverManagerProxy();

	virtual bool initialize(const QString& driverDir, const Context& ctx = Context::getDefaultContext());
	virtual void clear(const Context& ctx = Context::getDefaultContext());

	virtual bool isTapDriverInstalled(const Context& ctx = Context::getDefaultContext());
	virtual int getTapDeviceCount(const Context& ctx = Context::getDefaultContext());

	virtual bool installTapDriver(const Context& ctx = Context::getDefaultContext());
	virtual bool removeTapDriver(const Context& ctx = Context::getDefaultContext());

};

#endif
