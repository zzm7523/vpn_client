#ifndef __ENCRYPT_DEVICE_MANAGER_H__
#define __ENCRYPT_DEVICE_MANAGER_H__

#include "../config/config.h"

#ifdef ENABLE_GUOMI

#include <QProcess>
#include <QString>
#include <QStringList>

#define DBT_DEVICE_ARRIVAL	 0x0001
#define DBT_DEVICE_REMOVE	 0x0002

class EncryptDeviceManagerPrivate : public QObject
{
	Q_OBJECT
public:
	EncryptDeviceManagerPrivate(const QString& toolAppExe, const QString& libPath, const QString& workDir);

	void enumDevice(const QString& providerName, qlonglong& funcFlags, QStringList &deviceList);

private slots:
	void readDeviceData();
	void onProcessError(QProcess::ProcessError error);

private:
	QString toolAppExe;
	QString libPath;
	QString workDir;

	qlonglong funcFlags;
	QStringList deviceList;

	QProcess devProcess;

};

class EncryptDeviceManager : public QObject
{
	Q_OBJECT
public:
	static EncryptDeviceManager* instance();

	void initialize(const QString& libPath, const QString& workDir, const QString& lastProviderName);
	void clear();

	void enumDevice(unsigned int hint = 0);

	QString getProviderName() const;
	QStringList getDeviceList() const;

	bool supportsEnrollToMY(const QString& providerName) const;
	bool supportsChangeDevicePIN(const QString& providerName) const;

	bool verifyDevicePIN(const QString& providerName, const QString& pathName, const QString& pin,
		int *retryCount);
	bool changeDevicePIN(const QString& providerName, const QString& pathName, const QString& oldPIN,
		const QString& newPIN, int *retryCount);

	QByteArray sign(const QString& providerName, const QString& pathName, const QString& pin, const QByteArray& digest);

signals:
	// 枚举, 检测设备可能需要较长时间, 导致信号发送时间和插拔发生时间差异较大, timestamp表示实际插拔发生时间
	void deviceListArrival(const QString& providerName, const QStringList& deviceList, qint64 timestamp);
	void deviceListRemove(const QString& providerName, const QStringList& deviceList, qint64 timestamp);
	void deviceListChange(const QString& providerName, const QStringList& deviceList, qint64 timestamp);
	void deviceCurrentList(const QString& providerName, const QStringList& deviceList, qint64 timestamp);

	void unknownDeviceArrival(const QString& providerName, qint64 timestamp);
	void unknownDeviceRemove(const QString& providerName, qint64 timestamp);

private:
	bool isEqualDeviceList(const QStringList& savedList, const QStringList& currentList);
	QStringList getArrivedDeviceList(const QStringList& savedList, const QStringList& currentList);
	QStringList getRemovedDeviceList(const QStringList& savedList, const QStringList& currentList);

	QString toolAppExe;
	QString libPath;
	QString workDir;

	QStringList providerNameList;
	QString lastProviderName;	// 最近插入的设备提供者, 一般来讲用户总是使用同一把Key

	qint64 enumSequence;
	QString providerName;
	qlonglong funcFlags;
	QStringList deviceList;

};

#endif

#endif
