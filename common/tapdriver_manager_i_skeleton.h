#ifndef __TAPDRIVER_MANAGER_I_SKELETON_H__
#define __TAPDRIVER_MANAGER_I_SKELETON_H__

#include "../config/config.h"

#include <QString>

#include "proxy.h"
#include "tapdriver_manager_i.h"

class TapDriverManagerSkeleton : public Skeleton, public TapDriverManagerI
{
public:
	TapDriverManagerSkeleton(const QString& uniqueIdentify)
		: Skeleton(uniqueIdentify) {
	}

	virtual ~TapDriverManagerSkeleton() {
	}

	virtual void processRequest(Request *request);

};

#endif
