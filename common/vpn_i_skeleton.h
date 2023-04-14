#ifndef __VPN_I_SKELETON_H__
#define __VPN_I_SKELETON_H__

#include "../config/config.h"

#include "proxy.h"
#include "vpn_i.h"

class VPNAgentSkeleton : public Skeleton, public VPNAgentI
{
public:
	explicit VPNAgentSkeleton(const QString& uniqueIdentify)
		: Skeleton(uniqueIdentify) {
	}

	virtual void processRequest(Request *request);

};

class VPNInputAgentSkeleton : public Skeleton, public VPNInputAgentI
{
public:
	explicit VPNInputAgentSkeleton(const QString& uniqueIdentify)
		: Skeleton(uniqueIdentify) {
	}

	virtual void processRequest(Request *request);

};

class VPNObserverSkeleton : public Skeleton, public VPNObserverI
{
public:
	explicit VPNObserverSkeleton(const QString& uniqueIdentify)
		: Skeleton(uniqueIdentify) {
	}

	virtual void processRequest(Request *request);

};

#endif
