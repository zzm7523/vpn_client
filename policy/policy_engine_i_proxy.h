#ifndef __POLICY_ENGINE_I_PROXY_H__
#define __POLICY_ENGINE_I_PROXY_H__

#include "../config/config.h"
#include "../common/proxy.h"
#include "policy_engine_i.h"

class PolicyEngineProxy : public Proxy, public PolicyEngineI
{
	Q_OBJECT
public:
	PolicyEngineProxy(const QString& uniqueIdentify, TcpConnection *connection);

	virtual bool initialize(const Context& ctx = Context::getDefaultContext());

	virtual void clear(const Context& ctx = Context::getDefaultContext());

	virtual bool addPolicy(const QString& policy, const Context& ctx = Context::getDefaultContext());

	virtual bool hasPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx = Context::getDefaultContext());

	virtual ApplyResult applyPolicy(const QString& policy, const Context& ctx = Context::getDefaultContext());

	virtual ApplyResult applyPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx = Context::getDefaultContext());

};

#endif
