#ifndef __SYSTEM_INFO_H__
#define __SYSTEM_INFO_H__

#include "../config/config.h"
#include "common.h"

#include <QString>
#include <QStringList>

class SystemInfo
{
public:    
	static QString getMainboardId();
	static QString getBiosId();
	static QStringList getMacs();

	static QString getCurrentUser();

private:
	SystemInfo();

};

#endif
