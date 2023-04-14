#ifndef __POLICY_ENGINE_SERVANT_H__
#define __POLICY_ENGINE_SERVANT_H__

#include "../config/config.h"

#include <QString>
#include <QList>
#include <QObject>

#include "../common/vpn_i_proxy.h"
#include "../policy/policy.h"
#include "../policy/policy_engine_i_proxy.h"
#include "../policy/policy_engine_i_skeleton.h"

class PolicyEngineServant: public QObject, public PolicyEngineSkeleton
{
	Q_OBJECT
public:
	PolicyEngineServant(const QString& uniqueIdentify, bool front, VPNAgentI *agentI,
		PolicyEngineProxy *remoteEngineProxy);
	virtual ~PolicyEngineServant();

	PolicyEngineProxy* getRemotePolicyEngine();
	void setRemotePolicyEngine(PolicyEngineProxy *remoteEngineProxy);

	virtual bool initialize(const Context& ctx);

	virtual void clear(const Context& ctx);

	virtual bool addPolicy(const QString& policy, const Context& ctx);

	virtual bool hasPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx);

	virtual ApplyResult applyPolicy(const QString& policy, const Context& ctx);

	virtual ApplyResult applyPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx);

private:
	bool front;
	VPNAgentI *agentI;
	PolicyEngineProxy *remoteEngineProxy;
	QList<Policy*> policys;

};

#endif
