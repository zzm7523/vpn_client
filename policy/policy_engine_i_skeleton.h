#ifndef __POLICY_ENGINE_I_SKELETON_H__
#define __POLICY_ENGINE_I_SKELETON_H__

#include "../config/config.h"
#include "../common/proxy.h"
#include "policy_engine_i.h"

class PolicyEngineSkeleton : public Skeleton, public PolicyEngineI
{
public:
	explicit PolicyEngineSkeleton(const QString& uniqueIdentify)
		: Skeleton(uniqueIdentify) {
	}

	virtual void processRequest(Request *request);

};

#endif
