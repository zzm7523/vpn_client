#if defined(_WIN32) || defined(WIN32)
#include "../common/common.h"
#include "../common/translate.h"
#include "../common/tapdriver_manager.h"

#include "tapdriver_manager_servant.h"

TapDriverManagerServant::TapDriverManagerServant(const QString& uniqueIdentify)
	: TapDriverManagerSkeleton(uniqueIdentify)
{
}

bool TapDriverManagerServant::initialize(const QString& driverDir, const Context& ctx)
{
	return tapDrvMgr.initialize(driverDir);
}

void TapDriverManagerServant::clear(const Context& ctx)
{
	tapDrvMgr.clear();
}

bool TapDriverManagerServant::isTapDriverInstalled(const Context& ctx)
{
	return tapDrvMgr.isTapDriverInstalled();
}

int TapDriverManagerServant::getTapDeviceCount(const Context& ctx)
{
	return tapDrvMgr.getTapDeviceCount();
}

bool TapDriverManagerServant::installTapDriver(const Context& ctx)
{
	return tapDrvMgr.installTapDriver();
}

bool TapDriverManagerServant::removeTapDriver(const Context& ctx)
{
	return tapDrvMgr.removeTapDriver();
}

#endif
