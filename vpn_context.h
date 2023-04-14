#ifndef __VPN_CONTEXT_H__
#define __VPN_CONTEXT_H__

#include "config/config.h"

#include "common/vpn_config.h"
#include "common/vpn_i_proxy.h"
#include "common/server_endpoint_selector.h"

#include "policy/policy.h"
#include "policy/policy_engine_i_proxy.h"

class VPNContext
{
public:
	VPNContext(VPNAgentProxy *agentProxy, VPNInputAgentI *inputAgentI, PolicyEngineI *frontPolicyEngineI,
		PolicyEngineProxy *backPolicyEngineProxy);
	~VPNContext();

	ServerEndpointSelector* getServerEndpointSelector() const;

	VPNAgentProxy* getVPNAgentI() const;

	VPNInputAgentI* getVPNInputAgentI() const;

	PolicyEngineI* getFrontPolicyEngineI() const;

	PolicyEngineI* getBackPolicyEngineI() const;

	VPNObserverI* getVPNObserverI() const;

	void setVPNObserverI(VPNObserverI *observerI);

private:
	VPNContext(const VPNContext& context);

	ServerEndpointSelector *selector;
	VPNObserverI *observerI;
	VPNAgentProxy *agentProxy;
	VPNInputAgentI *inputAgentI;
	PolicyEngineI *frontPolicyEngineI;
	PolicyEngineProxy *backPolicyEngineProxy;

};

#endif
