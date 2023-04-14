#ifndef __MISCELLANEOUS_SERVICE_SKELETON_H__
#define __MISCELLANEOUS_SERVICE_SKELETON_H__

#include "../config/config.h"
#include "proxy.h"
#include "miscellaneous_service_i.h"

class MiscellaneousServiceSkeleton : public Skeleton, public MiscellaneousServiceI
{
public:
	explicit MiscellaneousServiceSkeleton(const QString& uniqueIdentify)
		: Skeleton(uniqueIdentify) {
	}

	virtual void processRequest(Request *request);

};
#endif
