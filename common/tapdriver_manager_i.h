#ifndef __TAP_DRIVER_MANAGER_I_H__
#define __TAP_DRIVER_MANAGER_I_H__

#include "../config/config.h"

#include <QString>

#include "common.h"
#include "context.h"

class TapDriverManagerI
{
public:
	virtual ~TapDriverManagerI() {}

	virtual bool initialize(const QString& workingDirectory, const Context& ctx) = 0;
	virtual void clear(const Context& ctx) = 0;

	virtual bool isTapDriverInstalled(const Context& ctx) = 0;
	virtual int getTapDeviceCount(const Context& ctx) = 0;

	virtual bool installTapDriver(const Context& ctx) = 0;
	virtual bool removeTapDriver(const Context& ctx) = 0;

};

#endif
