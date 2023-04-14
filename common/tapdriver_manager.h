#ifndef __TAPDRIVER_MANAGER_H__
#define __TAPDRIVER_MANAGER_H__

// _WIN32����vc�������ڲ������; moc tapdriver_manager.hʱ, ��û�ж��������
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
