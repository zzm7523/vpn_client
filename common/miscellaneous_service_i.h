#ifndef __MISCELLANEOUS_SERVICE_I_H__
#define __MISCELLANEOUS_SERVICE_I_H__

#include "../config/config.h"

#include <QString>
#include <QStringList>

#include "common.h"
#include "context.h"
#include "process_util.h"

class MiscellaneousServiceI
{
public:
	virtual ~MiscellaneousServiceI() {}

	virtual bool changeLanguage(const QString& language, const Context& ctx) = 0;

	// !! 通过WMI获取硬件信息可能会很慢, 在XP虚拟机看见过几十秒 !!, 所以放在后台, 机器启动时计算一次
	virtual QString generateFingerprint(const Context& ctx) = 0;

	virtual QString getFingerprint(const QString& fileName, const Context& ctx) = 0;
	virtual void saveFingerprint(const QString& fileName, const QString& fingerprint, const Context& ctx) = 0;

	virtual ExecuteResult execute(const QString& program, const QStringList& arguments,
		const QString& workingDirectory, const Context& ctx) = 0;

};

#endif
