#include "common/common.h"
#include "common/locator.h"
#include "common/request_dispatcher.h"
#include "common/vpn_i_skeleton.h"
#include "policy/policy_engine_i_skeleton.h"

#include "vpn_context.h"

VPNContext::VPNContext(VPNAgentProxy *_agentProxy, VPNInputAgentI *_inputAgentI, PolicyEngineI *_frontPolicyEngineI,
		PolicyEngineProxy *_backPolicyEngineProxy)
	: selector(new ServerEndpointSelector()), observerI(NULL), agentProxy(_agentProxy),
	inputAgentI(_inputAgentI), frontPolicyEngineI(_frontPolicyEngineI), backPolicyEngineProxy(_backPolicyEngineProxy)
{
}

VPNContext::~VPNContext()
{
	if (this->selector)
		delete this->selector;

	if (this->frontPolicyEngineI) {
		RequestDispatcher::unregisterServant(dynamic_cast<PolicyEngineSkeleton*>(this->frontPolicyEngineI));
		QObject *object = dynamic_cast<QObject*>(this->frontPolicyEngineI);
		if (object)
			object->deleteLater();
		else
			delete this->frontPolicyEngineI;
	}

	if (this->backPolicyEngineProxy)
		this->backPolicyEngineProxy->deleteLater();

	if (this->agentProxy)
		this->agentProxy->deleteLater();

	if (this->inputAgentI) {
		RequestDispatcher::unregisterServant(dynamic_cast<VPNInputAgentSkeleton*>(this->inputAgentI));
		QObject *object = dynamic_cast<QObject*>(this->inputAgentI);
		if (object)
			object->deleteLater();
		else
			delete this->inputAgentI;
	}

	if (this->observerI) {
		RequestDispatcher::unregisterServant(dynamic_cast<VPNObserverSkeleton*>(this->observerI));
		QObject *object = dynamic_cast<QObject*>(this->observerI);
		if (object)
			object->deleteLater();
		else
			delete this->observerI;
	}	
}

ServerEndpointSelector* VPNContext::getServerEndpointSelector() const
{
	return this->selector;
}

VPNAgentProxy* VPNContext::getVPNAgentI() const
{
	return this->agentProxy;
}

VPNInputAgentI* VPNContext::getVPNInputAgentI() const
{
	return this->inputAgentI;
}

PolicyEngineI* VPNContext::getFrontPolicyEngineI() const
{
	return this->frontPolicyEngineI;
}

PolicyEngineI* VPNContext::getBackPolicyEngineI() const
{
	return this->backPolicyEngineProxy;
}

VPNObserverI* VPNContext::getVPNObserverI() const
{
	return this->observerI;
}

void VPNContext::setVPNObserverI(VPNObserverI *observerI)
{
	this->observerI = observerI;
}
