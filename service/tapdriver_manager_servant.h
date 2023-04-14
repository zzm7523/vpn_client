#ifndef __TAPDRIVER_MANAGER_SERVANT_H__
#define __TAPDRIVER_MANAGER_SERVANT_H__

// _WIN32����vc�������ڲ������; moc tapdriver_manager_servant.hʱ, ��û�ж��������
#if defined(_WIN32) || defined(WIN32)
#include "../config/config.h"

#include <QString>

#include "../common/tapdriver_manager.h"
#include "../common/tapdriver_manager_i_skeleton.h"

class TapDriverManagerServant : public TapDriverManagerSkeleton
{
public:
	TapDriverManagerServant(const QString& uniqueIdentify);

	virtual bool initialize(const QString& driverDir, const Context& ctx);
	virtual void clear(const Context& ctx);

	virtual bool isTapDriverInstalled(const Context& ctx);
	virtual int getTapDeviceCount(const Context& ctx);

	virtual bool installTapDriver(const Context& ctx);
	virtual bool removeTapDriver(const Context& ctx);

private:
	TapDriverManager tapDrvMgr;

};

#endif
#endif
