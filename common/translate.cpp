#include "translate.h"

#include <QApplication>

QString Translate::translateProcessError(QProcess::ProcessError processError)
{
	switch (processError) {
	case QProcess::FailedToStart:
		return QApplication::translate("Process", "The process failed to start. Either the invoked program is missing,"
			" or you may have insufficient permissions to invoke the program.");
	case QProcess::Crashed:
		return QApplication::translate("Process", "The process crashed some time after starting successfully.");
	case QProcess::Timedout:
		return QApplication::translate("Process", "The last waitFor...() function timed out."
			" The state of QProcess is unchanged, and you can try calling waitFor...() again.");
	case QProcess::WriteError:
		return QApplication::translate("Process", "An error occurred when attempting to write to the process."
			" For example, the process may not be running, or it may have closed its input channel.");
	case QProcess::ReadError:
		return QApplication::translate("Process", "An error occurred when attempting to read from the process."
			" For example, the process may not be running.");
	case QProcess::UnknownError:
		return QApplication::translate("Process", "An unknown error occurred. This is the default return value of error().");
	default:
		return QApplication::translate("Process", "No valid error code!");
	}
}

QString Translate::translateVPNState(VPNAgentI::State state)
{
	if (VPNAgentI::Disconnected == state || VPNAgentI::ReadyToConnect == state)
		return QApplication::translate("VPNAgentI", "Ready to connect");
	else if (VPNAgentI::Connected == state)
		return QApplication::translate("VPNAgentI", "Connection established");
	else if (VPNAgentI::Reconnecting == state)
		return QApplication::translate("VPNAgentI", "Reconnecting ...");
	else if (VPNAgentI::Connecting == state)
		return QApplication::translate("VPNAgentI", "Connecting ...");
	else if (VPNAgentI::Disconnecting == state)
		return QApplication::translate("VPNAgentI", "Disconnecting ...");
	else
		return QApplication::translate("VPNAgentI", "State unknown");
}

