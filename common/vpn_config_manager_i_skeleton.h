#ifndef __VPN_CONFIG_MANAGER_I_SKELETON_H__
#define __VPN_CONFIG_MANAGER_I_SKELETON_H__

#include "../config/config.h"
#include "proxy.h"
#include "vpn_config_manager_i.h"

class VPNConfigManagerSkeleton : public Skeleton, public VPNConfigManagerI
{
public:
	explicit VPNConfigManagerSkeleton(const QString& uniqueIdentify)
		: Skeleton(uniqueIdentify) {
	}

	virtual void processRequest(Request *request);

};

#endif
