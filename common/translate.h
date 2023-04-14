#ifndef __PROCESS_ERROR_H__
#define __PROCESS_ERROR_H__

#include "../config/config.h"

#include <QString>
#include <QProcess>

#include "vpn_i.h"

class Translate
{
public:
	static QString translateProcessError(QProcess::ProcessError processError);
	static QString translateVPNState(VPNAgentI::State state);

};

#endif
