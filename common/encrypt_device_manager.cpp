#include <QApplication>
#include <QTimer>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QDebug>
#include <QEventLoop>

#include "encrypt_device_manager.h"
#ifdef ENABLE_GUOMI
#include "common.h"
#include "translate.h"
#include "process_util.h"

#include <openssl/encrypt_device.h>

#ifdef _WIN32
#pragma warning(disable:4100)
#endif

static ENCRYPT_DEVICE_LOCKING_CALLBACK static_device_locking_cb = { NULL, NULL, NULL, NULL, NULL };

static int static_GM_X509_usage_index = -1;
static int static_GM_RSA_usage_index  = -1;
static int static_GM_Encrypt_device_index = -1;

static void edl_lock_lock_impl() {}
static void edl_lock_unlock_impl() {}
static void edl_cond_wait_impl() {}
static void edl_cond_signal_impl() {}
static void edl_cond_broadcast_impl() {}

static void init_encrypt_device_locking_callback()
{
	static_device_locking_cb.edl_lock_lock = edl_lock_lock_impl;
	static_device_locking_cb.edl_lock_unlock = edl_lock_unlock_impl;
	static_device_locking_cb.edl_cond_wait = edl_cond_wait_impl;
	static_device_locking_cb.edl_cond_signal = edl_cond_signal_impl;
	static_device_locking_cb.edl_cond_broadcast = edl_cond_broadcast_impl;

	OPENSSL_set_encrypt_device_locking_callback (&static_device_locking_cb);
}

static void OPENSSL_STRING_free(OPENSSL_STRING str)
{
	if (str)
		OPENSSL_free(str);
}

static int OPENSSL_STRING_cmp(const char* const *a, const char* const *b )
{
	// 倒序, 保证huashen在huada前面
	return !strcmp(*a, *b);
}

EncryptDeviceManagerPrivate::EncryptDeviceManagerPrivate(const QString& _toolAppExe, const QString& _libPath, const QString& _workDir)
	: toolAppExe(_toolAppExe), libPath(_libPath), workDir(_workDir), funcFlags(0L)
{
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	/*
	 * 华申应用库有很多版本, 库和设备混用会造成应用程序崩溃(弹出对话框要求调试).
	 * 例如用华堂版本的库打开上海CA的Key, 或者用上海CA版本的库打开华堂的Key.
	 * 采用minidump功能屏蔽这个BUG(minidump时exitCode == -1073741819, exitCode != 0表示失败)
	 */
	// set ENCRYPT_DEVICE_TOOL=d:\\encrypt_device_tool.dmp
	env.insert("ENCRYPT_DEVICE_TOOL", QDir(workDir).absoluteFilePath("encrypt_device_tool.dmp"));
	this->devProcess.setProcessEnvironment(env);
	this->devProcess.setWorkingDirectory(workDir);
}

void EncryptDeviceManagerPrivate::enumDevice(const QString& providerName, qlonglong& funcFlags, QStringList &deviceList)
{
	if (!QFile(toolAppExe).exists()) {	// probeApp不存在时, 不调用, 否则QT内存崩溃(? BUG)
		qDebug() << toolAppExe << " don't exist";
		return;
	}

	// 枚举加密设备	encrypt_device_tool enum lib_path provider_name
	QStringList params;
	params << QLatin1String("enum") << libPath << providerName;

	QObject::connect(&this->devProcess, SIGNAL(readyReadStandardOutput()), this, SLOT(readDeviceData()));
	QObject::connect(&this->devProcess, SIGNAL(readyReadStandardError()), this, SLOT(readDeviceData()));
	QObject::connect(&this->devProcess, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	QEventLoop eventLoop;
	QObject::connect(&this->devProcess, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->devProcess, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(5000, &eventLoop, SLOT(quit()));	// 5秒

	this->devProcess.start(toolAppExe, params);
	// Calling waitForStarted(...) from the main (GUI) thread might cause your user interface to freeze.
	if (/*this->devProcess.waitForStarted(3000) &&*/ this->devProcess.state() != QProcess::NotRunning) {
		eventLoop.exec();

		if (this->devProcess.state() != QProcess::NotRunning) {	// 可能是华申设备死锁, 检测进程不能完成
			// 优先选用ProcessUtil::killProcess(...)
			qint64 pid = this->devProcess.processId();
			if (pid)
				ProcessUtil::killProcess(pid);
			else
				this->devProcess.kill();
		}

		this->readDeviceData();	// QEventLoop退出, 可能在readyReadStandard...()被回调前
	}

	funcFlags = this->funcFlags;
	deviceList = this->deviceList;
	qDebug() << "EncryptDeviceManagerPrivate::enumDevice(...), funcFlags=" << funcFlags << ", deviceList=" << deviceList;
}

void EncryptDeviceManagerPrivate::readDeviceData() {
	QByteArray output = devProcess.readAllStandardOutput();
	if (output.isEmpty()) {
		output = devProcess.readAllStandardError();
	}

	if (!output.isEmpty()) {
		const QString text = QString::fromLocal8Bit(output);
		qDebug() << "EncryptDeviceManagerPrivate::readDeviceData()\n" << text;

		QListIterator<QString> it(text.split(QLatin1Char('\n'), QString::SkipEmptyParts));
		while (it.hasNext()) {
			int index;
			QString line = it.next().trimmed();

			index = line.indexOf(QLatin1String("func_flags:"));
			if (index != -1) {
				this->funcFlags = line.mid(index + QLatin1String("func_flags:").size()).trimmed().toULongLong();
			} else {
				index = line.indexOf(QLatin1String("device_name:"));
				if (index != -1) {
					this->deviceList << line.mid(index + QLatin1String("device_name:").size()).trimmed();
				}
			}
		}
	}
}

void EncryptDeviceManagerPrivate::onProcessError(QProcess::ProcessError processError)
{
	qDebug() << Translate::translateProcessError(processError);
}

static EncryptDeviceManager* globalEncDevMgr = NULL;

EncryptDeviceManager* EncryptDeviceManager::instance()
{
	if (!globalEncDevMgr)
		globalEncDevMgr = new EncryptDeviceManager();
	return globalEncDevMgr;
}

void EncryptDeviceManager::initialize(const QString& libPath, const QString& workDir, const QString& lastProviderName)
{
	Q_ASSERT(!libPath.isEmpty() && !workDir.isEmpty());
	this->toolAppExe = QDir(QApplication::applicationDirPath()).absoluteFilePath(QLatin1String(ENCRYPT_DEVICE_TOOL));
	this->workDir = workDir;
	this->lastProviderName = lastProviderName;

	// 重新扫描支持的加密设备提供者, 并且重新探测加密设备
	this->libPath = libPath;
	this->providerNameList.clear();
	this->enumSequence = 0;
	this->providerName.clear();
	this->funcFlags = 0L;
	this->deviceList.clear();

	init_encrypt_device_locking_callback();

	STACK_OF(OPENSSL_STRING) *name_stack = sk_OPENSSL_STRING_new(OPENSSL_STRING_cmp);

	if (ENCRYPT_DEVICE_PROVIDER_enum(qPrintable(libPath), name_stack)) {
		sk_OPENSSL_STRING_sort(name_stack);
		for (int i = 0; i < sk_OPENSSL_STRING_num(name_stack); ++i)
			this->providerNameList.append(QLatin1String(sk_OPENSSL_STRING_value(name_stack, i)));
	}

	if (!this->providerNameList.contains(this->lastProviderName))
		this->lastProviderName.clear();

	sk_OPENSSL_STRING_pop_free(name_stack, OPENSSL_STRING_free);
}

void EncryptDeviceManager::clear()
{
	this->deviceList.clear();
}

void EncryptDeviceManager::enumDevice(unsigned int hint)
{
	// 枚举, 检测设备可能需要较长时间, 导致信号发送时间和插拔发生时间差异较大, timestamp表示实际插拔发生时间
	const qint64 timestamp = QDateTime::currentMSecsSinceEpoch();

	// 当前设备提供者为空, 当前设备列表为空
	QString currentProviderName;
	qlonglong currentFuncFlags = 0L;
	QStringList currentDeviceList;

	QStringList z_providerNameList;
	// 必须用预定的顺序扫描(例如: huashen_shca必须在huashen前面, huashen试图打开huashen_shca应用会崩溃)
	z_providerNameList = this->providerNameList;
/*
	if (hint == DBT_DEVICE_REMOVE) {
		// 设备拔除, 先扫描当前设备提供者
		if (!this->providerName.isEmpty()) {
			z_providerNameList.push_front(this->providerName);
		}
	} else {
		// 设备插入或未知, 扫描所有设备提供者, 先检查this->lastProviderName指定的设备提供者
		z_providerNameList = this->providerNameList;
		if (!this->lastProviderName.isEmpty()) {
			z_providerNameList.removeAll(this->lastProviderName);
			z_providerNameList.push_front(this->lastProviderName);
		}
	}
*/

	for (int i = 0; i < z_providerNameList.size(); ++i) {
		EncryptDeviceManagerPrivate privateImpl(toolAppExe, libPath, workDir);
		privateImpl.enumDevice(z_providerNameList.at(i), currentFuncFlags, currentDeviceList);
		if (!currentDeviceList.isEmpty()) {
			currentProviderName = z_providerNameList.at(i);
			break;
		}
	}

	// EncryptDeviceManagerPrivate::enumDevice可能导致EncryptDeviceManager::enumDevice递归, 后续代码必须串行
	// !!采用QMetaObject::invokeMethod(...)发送信号, 使代码串行

	const QString previousProviderName = this->providerName;	// 记住先前的设备提供者
	const QStringList previousDeviceList = this->deviceList;	// 记住先前的设备列表

	QStringList removedDeviceList = getRemovedDeviceList(previousDeviceList, currentDeviceList);
	if (removedDeviceList.isEmpty()) {
		if (hint == DBT_DEVICE_REMOVE) {
			bool result = QMetaObject::invokeMethod(this, "unknownDeviceRemove", Qt::QueuedConnection,
				Q_ARG(QString, QString()), Q_ARG(qint64, timestamp));
			Q_ASSERT_X(result, "unknownDeviceRemove", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
		}
	} else {
		bool result = QMetaObject::invokeMethod(this, "deviceListRemove", Qt::QueuedConnection,
			Q_ARG(QString, previousProviderName), Q_ARG(QStringList, removedDeviceList), Q_ARG(qint64, timestamp));
		Q_ASSERT_X(result, "deviceListRemove", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
	}

	QStringList arrivedDeviceList = getArrivedDeviceList(previousDeviceList, currentDeviceList);
	if (arrivedDeviceList.isEmpty()) {
		if (hint == DBT_DEVICE_ARRIVAL) {
			bool result = QMetaObject::invokeMethod(this, "unknownDeviceArrival", Qt::QueuedConnection,
				Q_ARG(QString, QString()), Q_ARG(qint64, timestamp));
			Q_ASSERT_X(result, "unknownDeviceArrival", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
		}
	} else {
		bool result = QMetaObject::invokeMethod(this, "deviceListArrival", Qt::QueuedConnection,
			Q_ARG(QString, currentProviderName), Q_ARG(QStringList, arrivedDeviceList), Q_ARG(qint64, timestamp));
		Q_ASSERT_X(result, "deviceListArrival", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
	}

	if (!isEqualDeviceList(previousDeviceList, currentDeviceList)) {
		bool result = QMetaObject::invokeMethod(this, "deviceListChange", Qt::QueuedConnection,
			Q_ARG(QString, currentProviderName), Q_ARG(QStringList, this->deviceList), Q_ARG(qint64, timestamp));
		Q_ASSERT_X(result, "deviceListChange", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
	}

	// 总是发送当前的设备列表信号
	bool result = QMetaObject::invokeMethod(this, "deviceCurrentList", Qt::QueuedConnection,
		Q_ARG(QString, currentProviderName), Q_ARG(QStringList, currentDeviceList), Q_ARG(qint64, timestamp));
	Q_ASSERT_X(result, "deviceCurrentList", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);

	// 记住最后扫描结果
	if (timestamp > this->enumSequence) {
		this->enumSequence = timestamp;
		this->lastProviderName = this->providerName = currentProviderName;	// 记住当前设备提供者
		this->funcFlags = currentFuncFlags;
		this->deviceList = currentDeviceList;	// 记住当前设备列表
	}
}

QString EncryptDeviceManager::getProviderName() const
{
	return this->providerName;
}

QStringList EncryptDeviceManager::getDeviceList() const
{
	return this->deviceList;
}

bool EncryptDeviceManager::supportsEnrollToMY(const QString& providerName) const
{
	if (providerName.isEmpty() || providerName.compare(this->providerName, Qt::CaseInsensitive) != 0)
		return false;

	return this->funcFlags & ENCRYPT_DEVICE_PROVIDER_ENROLL_MY;
}

bool EncryptDeviceManager::supportsChangeDevicePIN(const QString& providerName) const
{
	if (providerName.isEmpty() || providerName.compare(this->providerName, Qt::CaseInsensitive) != 0)
		return false;

	return this->funcFlags & ENCRYPT_DEVICE_PROVIDER_PIN;
}

bool EncryptDeviceManager::verifyDevicePIN(const QString& providerName, const QString& pathName, const QString& pin,
		int *retryCount)
{
	if (this->libPath.isEmpty() || this->providerName.isEmpty())
		return false;

	ENCRYPT_DEVICE_PROVIDER *provider = ENCRYPT_DEVICE_PROVIDER_load(qPrintable(libPath), qPrintable(providerName));
	if (!provider)
		return false;

	char *deviceName = NULL;
	if (!ENCRYPT_DEVICE_PROVIDER_parse_path(provider, qPrintable(pathName), &deviceName, NULL, NULL)) {
		ENCRYPT_DEVICE_PROVIDER_unload(provider);
		return false;
	}

	int ret = 0;
	ENCRYPT_DEVICE *device = ENCRYPT_DEVICE_open(provider, deviceName, 0);
	if (device) {
		ENCRYPT_DEVICE_CONTAINER *container = ENCRYPT_DEVICE_CONTAINER_open(device, qPrintable(pathName));
		if (container) {
			ret = ENCRYPT_DEVICE_CONTAINER_verify_pin(container, 0, qPrintable(pin), retryCount);
			ENCRYPT_DEVICE_CONTAINER_close(container);
		}
		ENCRYPT_DEVICE_close(device);
	}

	OPENSSL_free(deviceName);
	ENCRYPT_DEVICE_PROVIDER_unload(provider);
	return ret ? true : false;
}

bool EncryptDeviceManager::changeDevicePIN(const QString& providerName, const QString& pathName, const QString& oldPIN,
		const QString& newPIN, int *retryCount)
{
	if (this->libPath.isEmpty() || this->providerName.isEmpty())
		return false;

	ENCRYPT_DEVICE_PROVIDER *provider = ENCRYPT_DEVICE_PROVIDER_load(qPrintable(libPath), qPrintable(providerName));
	if (!provider)
		return false;

	char *deviceName = NULL;
	if (!ENCRYPT_DEVICE_PROVIDER_parse_path(provider, qPrintable(pathName), &deviceName, NULL, NULL)) {
		ENCRYPT_DEVICE_PROVIDER_unload(provider);
		return false;
	}

	int ret = 0;
	ENCRYPT_DEVICE *device = ENCRYPT_DEVICE_open(provider, deviceName, 0);
	if (device) {
		ENCRYPT_DEVICE_CONTAINER *container = ENCRYPT_DEVICE_CONTAINER_open(device, qPrintable(pathName));
		if (container) {
			ret = ENCRYPT_DEVICE_CONTAINER_change_pin(container, 0, qPrintable(oldPIN), qPrintable(newPIN), retryCount);
			ENCRYPT_DEVICE_CONTAINER_close(container);
		}
		ENCRYPT_DEVICE_close(device);
	}

	OPENSSL_free(deviceName);
	ENCRYPT_DEVICE_PROVIDER_unload(provider);
	return ret ? true : false;
}

QByteArray EncryptDeviceManager::sign(const QString& providerName, const QString& pathName, const QString& pin, const QByteArray& digest)
{
	// /63311362/HT-SSLVPN/X509
	const char *pos = NULL;
	char path_name[1024], device_name[256];
	unsigned long open_flags = 0;
	int retry_count;
	unsigned char data_buf[1024], sign[1024];
	int data_buf_len = 1024, sign_len = 1024;

	EVP_PKEY *sign_prv = NULL;
	X509 *sign_cert = NULL;
	STACK_OF(OPENSSL_STRING) *dev_stack = NULL;
	ENCRYPT_DEVICE_PROVIDER *provider = NULL;
	ENCRYPT_DEVICE *device = NULL;
	ENCRYPT_DEVICE_CONTAINER *container = NULL;

	QByteArray sig;

	strncpy(path_name, qPrintable(pathName), sizeof(path_name));
	path_name[sizeof(path_name) - 1] = 0x0;

	if (!(pos = strchr(path_name + 1, '/')))
	{
		qDebug() << "invalid pathname " << path_name;
		goto finish;
	}

	dev_stack = sk_OPENSSL_STRING_new_null();
	provider = ENCRYPT_DEVICE_PROVIDER_load(qPrintable(libPath), qPrintable(providerName));
	if (!provider)
	{
		qDebug() << "load encrypt device provider " << providerName  << " fail";
		goto finish;
	}

	strncpy(device_name, path_name + 1, pos - path_name - 1);
	device_name[pos - path_name - 1] = 0x0;

	device = ENCRYPT_DEVICE_open(provider, device_name, open_flags);
	if (!device)
	{
		qDebug() << "open encrypt device " << device_name <<  " fail";
		goto finish;
	}

	container = ENCRYPT_DEVICE_CONTAINER_open(device, path_name);
	if (!container)
	{
		qDebug() << "open container " << path_name << " fail";
		goto finish;
	}

	if (!ENCRYPT_DEVICE_CONTAINER_verify_pin(container, 0, qPrintable(pin), &retry_count))
	{
		qDebug() << "verify encrypt device pin fail";
		goto finish;
	}

	if (!ENCRYPT_DEVICE_CONTAINER_read_certs(container, &sign_cert, &sign_prv, NULL, NULL))
	{
		qDebug() << "read sign cert fail";
		goto finish;
	}

	ENCRYPT_DEVICE_release(device);

	memcpy (data_buf, digest.data(), digest.size());
	data_buf_len = digest.size();
	sign_len = 1024;

	if (sign_prv->type == EVP_PKEY_EC)
	{
		EC_KEY *ec_prv = EVP_PKEY_get1_EC_KEY(sign_prv);
		if (ECDSA_sign(NID_sm3, data_buf, data_buf_len, sign, (unsigned int*) &sign_len, ec_prv))
			sig.append((char *) sign, sign_len);
		EC_KEY_free(ec_prv);
    }
	else
	{
		RSA *rsa_prv = EVP_PKEY_get1_RSA(sign_prv);
		sign_len = RSA_private_encrypt(data_buf_len, data_buf, sign, rsa_prv, RSA_PKCS1_PADDING);
		if (sign_len > 0)
			sig.append((char *) sign, sign_len);
		RSA_free(rsa_prv);
	}

finish:
	// 容器使用完后需要关闭, !!持有加密设备才能关闭容器
	if (container)
	{
		ENCRYPT_DEVICE_acquire(ENCRYPT_DEVICE_PROVIDER_get(), NULL, device);
		ENCRYPT_DEVICE_CONTAINER_close(container);
		ENCRYPT_DEVICE_release(device);
	}
	if (provider)
	{
		ENCRYPT_DEVICE_close_all(provider);
		ENCRYPT_DEVICE_PROVIDER_unload(provider);
	}
	if (dev_stack)
		sk_OPENSSL_STRING_pop_free(dev_stack, OPENSSL_STRING_free);

	return sig;
}

bool EncryptDeviceManager::isEqualDeviceList(const QStringList& savedList, const QStringList& currentList)
{
	if (savedList.size() != currentList.size())
		return false;

	for (int i = 0; i < savedList.size(); ++i) {
		if (!currentList.contains(savedList.at(i)))
			return false;
	}

	for (int i = 0; i < currentList.size(); ++i) {
		if (!savedList.contains(currentList.at(i)))
			return false;
	}

	return true;
}

QStringList EncryptDeviceManager::getArrivedDeviceList(const QStringList& savedList, const QStringList& currentList)
{
	QStringList arrivedDeviceList;
	for (int i = 0; i < currentList.size(); ++i) {
		if (!savedList.contains(currentList.at(i)))
			arrivedDeviceList.append(currentList.at(i));
	}
	return arrivedDeviceList;
}

QStringList EncryptDeviceManager::getRemovedDeviceList(const QStringList& savedList, const QStringList& currentList)
{
	QStringList removedDeviceList;
	for (int i = 0; i < savedList.size(); ++i) {
		if (!currentList.contains(savedList.at(i)))
			removedDeviceList.append(savedList.at(i));
	}
	return removedDeviceList;
}

#endif
