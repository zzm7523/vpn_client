#ifndef __TAPDRIVER_MANAGER_H__
#define __TAPDRIVER_MANAGER_H__

// _WIN32宏是vc编译器内部定义的; moc tapdriver_manager.h时, 并没有定义这个宏
#if defined(_WIN32) || defined(WIN32)
#include "../config/config.h"

#include <QProcess>
#include <QString>

class TapDriverManagerPrivate : public QObject
{
	Q_OBJECT
public:
	TapDriverManagerPrivate(const QString& driverDir);

	bool isTapDriverInstalled();
	int getTapDeviceCount();

	bool installTapDriver();
	bool removeTapDriver();

	bool enableTapDriver();
	bool disableTapDriver();

private:
	bool probeTapDriverInf();

	bool drvAvailable;
	bool drvInstalledSuccess;
	bool drvRemovedSuccess;
	bool drvEnableSuccess;
	bool drvDisableSuccess;
	int drvCount;

	QString devConApp;
	QString tapInf;
	QString tapHwid;

	QString driverDir;
	QProcess drvProc;

private slots:
	void readTapDriverData();
	void onProcessError(QProcess::ProcessError error);

};

class TapDriverManager : public QObject
{
public:
	bool initialize(const QString& driverDir);
	void clear();

	bool isTapDriverInstalled();
	int getTapDeviceCount();

	bool installTapDriver();
	bool removeTapDriver();

	bool enableTapDriver();
	bool disableTapDriver();

private:
	QString driverDir;

};

#endif
#endif
