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
	// ö��, ����豸������Ҫ�ϳ�ʱ��, �����źŷ���ʱ��Ͳ�η���ʱ�����ϴ�, timestamp��ʾʵ�ʲ�η���ʱ��
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
	QString lastProviderName;	// ���������豸�ṩ��, һ�������û�����ʹ��ͬһ��Key

	qint64 enumSequence;
	QString providerName;
	qlonglong funcFlags;
	QStringList deviceList;

};

#endif

#endif
