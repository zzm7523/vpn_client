#ifndef __SINGLE_APPLICATION_H__
#define __SINGLE_APPLICATION_H__

#include "config/config.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QTranslator>
#include <QSharedMemory>
#include <QByteArray>
#include <QStringList>
#include <QAbstractNativeEventFilter>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include "common/common.h"
#include "common/ticket.h"
#include "common/tapdriver_manager_i_proxy.h"
#include "common/vpn_config.h"
#include "common/vpn_config_manager_i_proxy.h"

#define ENUM_ENCRYPT_DEVICE_EVENT	quint16(QEvent::User) + 304

class Preferences;

#if defined(ENABLE_GUOMI) && defined(_WIN32)
class DeviceInterfaceEventFilter : public QAbstractNativeEventFilter
{
public:
	DeviceInterfaceEventFilter(HWND hwnd);
	~DeviceInterfaceEventFilter();

	bool nativeEventFilter(const QByteArray& eventType, void *message, long *result);

private:
	HDEVNOTIFY hDeviceNotify;

};
#endif

class SingleApplication : public QApplication
{
	Q_OBJECT
public:
	SingleApplication(int& argc, char *argv[]);
	~SingleApplication();

	void setPreferences(Preferences *preferences);

	// 启动设置了自动启动选项的VPN隧道
	void startTunnel();

	// 启动指定的VPN隧道
	void startTunnel(const QString& host, int port, const QString& protocol, const QString& ticket);

	void stopTunnel(const QString& host, int port, const QString& protocol, bool silent);

	bool isRunning() const;
	bool sendMessage(const QString& message);

	void changeLanguage(const QString& language);

	int exec();

public slots:
	void checkForMessage();
	void receiveMessage(const QString& message);

signals:
	void messageAvailable(const QString& message);

protected:
#ifdef ENABLE_GUOMI
	bool event(QEvent *e);
#endif

private:
	void processArguments(const QStringList& args, bool autoStart);
	void registerMetaTypes();

	QTranslator appTranslator;
	QTranslator qtTranslator;

	bool running;
	Preferences *preferences;
	QSharedMemory *sharedMemory;

};

#endif
