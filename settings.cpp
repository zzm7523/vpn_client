#include <QApplication>
#include <QRegularExpression>
#include <QLocale>
#include <QSettings>
#include <QDir>
#include <QStandardPaths>

#include "settings.h"
#include "common/cipher.h"
#include "common/file_util.h"
#include "common/system_info.h"

static Settings *globalSettings = NULL;

Settings* Settings::instance()
{
	if (!globalSettings)
		globalSettings = new Settings();
	return globalSettings;
}

Settings::Settings()
	: checkUpdate(true), showToolbar(true), showStatusBar(true), showBallonMessage(true), autoReconnect(true),
	autoMinimum(false), saveCredential(true), popupAccessibleResource(false)
{
}

void Settings::load(const QString &appDirPath, const QString &appSavePath)
{
	this->appDirPath = QDir(appDirPath).canonicalPath();
	// 删除结尾的/或\字符
	this->appDirPath.replace(QRegularExpression(QLatin1String("[/|\\\\]$")), QLatin1String(""));

	this->appSavePath = QDir(appSavePath).canonicalPath();
	// 删除结尾的/或\字符
	this->appSavePath.replace(QRegularExpression(QLatin1String("[/|\\\\]$")), QLatin1String(""));

	// 必须保留结尾的/或\字符; 不能正确处理QDir("D:").canonicalPath()
	QStringList locations = QStandardPaths::standardLocations(QStandardPaths::DocumentsLocation);
	if (!locations.isEmpty())
		this->lastAccessPath = locations.first();

	this->caFileName = QDir(this->appSavePath).absoluteFilePath(QLatin1String(VPN_CA_FILE));
	QFile caFile(caFileName);
	if (!caFile.exists()) {
		caFile.open(QIODevice::Text | QIODevice::WriteOnly);
		caFile.close();
	}

	this->iniPath = QDir(this->appSavePath).absoluteFilePath(QLatin1String(VPN_CLIENT_SETTINGS_FILE));
	QSettings sett(this->iniPath, QSettings::IniFormat);

	this->language = sett.value(QLatin1String("language"), QLatin1String("")).toString();
	if (this->language.isEmpty()) {
		const QLocale system = QLocale::system();
		switch (system.language()) {
		case QLocale::Chinese:
			if (system.country() == QLocale::Taiwan)
				this->language = QLatin1String("zh_TW");
			else
				this->language = QLatin1String("zh_CN");
			break;
		default:
			this->language = QLatin1String("en_US");
		}
	}

	this->lastProviderName = sett.value(QLatin1String("last_provider_name"), QLatin1String("")).toString();

#ifdef ENABLE_UPDATER
	this->lastCheckUpdate = sett.value(QLatin1String("last_check_update"), QDateTime()).toDateTime();
	if (!this->lastCheckUpdate.isValid())
		this->lastCheckUpdate = QDateTime::fromTime_t(0);
	// 缺省自动更新软件
	this->checkUpdate = sett.value(QLatin1String("check_update"), QLatin1String("true")).toString()
		== QLatin1String("true") ? true : false;
#else
	// 未启用自动更新软件
	this->lastCheckUpdate = QDateTime::fromTime_t(0);
	this->checkUpdate = false;
#endif

	// 缺省自动保存Credential
	this->saveCredential = sett.value(QLatin1String("save_credential"), QLatin1String("true")).toString()
		== QLatin1String("true") ? true : false;

	// 缺省自动重连
	this->autoReconnect = sett.value(QLatin1String("auto_reconnect"), QLatin1String("true")).toString()
		== QLatin1String("true") ? true : false;

	this->autoMinimum = sett.value(QLatin1String("auto_minimum"), QLatin1String("false")).toString()
		== QLatin1String("false") ? false : true;

	this->showToolbar = sett.value(QLatin1String("show_toolbar"), QLatin1String("true")).toString()
		== QLatin1String("true") ? true : false;

	this->showStatusBar = sett.value(QLatin1String("show_statusbar"), QLatin1String("true")).toString()
		== QLatin1String("true") ? true : false;

	// 缺省显示消息气球
	this->showBallonMessage = sett.value(QLatin1String("show_ballon"), QLatin1String("true")).toString()
		== QLatin1String("true") ? true : false;

#ifdef ENABLE_INTEGRATION
	this->popupAccessibleResource = sett.value(QLatin1String("popup_accessible_resource"), QLatin1String("false")).toString()
		== QLatin1String("false") ? false : true;
#else
	this->popupAccessibleResource = false;
#endif
}

const QString& Settings::getAppDirPath() const
{
	return this->appDirPath;
}

const QString& Settings::getAppSavePath() const
{
	return this->appSavePath;
}

const QString& Settings::getCAFileName() const
{
	return this->caFileName;
}

const QString& Settings::getLanguage() const
{
	return this->language;
}

void Settings::setLanguage(const QString& language)
{
	if (this->language.compare(language, Qt::CaseInsensitive) != 0) {
		this->language = language;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("language"), language);
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

const QString& Settings::getLastAccessPath() const
{
	return this->lastAccessPath;
}

void Settings::setLastAccessPath(const QString &path)
{
	// 必须保留结尾的/或\字符; 不能正确处理QDir("D:").canonicalPath()
	if (!path.isEmpty()) {
		this->lastAccessPath = QDir(path).canonicalPath();
	}
}

const QString& Settings::getLastProviderName() const
{
	return this->lastProviderName;
}

void Settings::setLastProviderName(const QString& lastProviderName)
{
	if (this->lastProviderName.compare(lastProviderName, Qt::CaseInsensitive) != 0) {
		this->lastProviderName = lastProviderName;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("last_provider_name"), lastProviderName);
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

const QDateTime& Settings::getLastCheckUpdate() const
{
	return this->lastCheckUpdate;
}

void Settings::setLastCheckUpdate(const QDateTime& lastCheckUpdate)
{
	if (this->lastCheckUpdate != lastCheckUpdate) {
		this->lastCheckUpdate = lastCheckUpdate;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("last_check_update"), lastCheckUpdate);
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isCheckUpdate() const
{
	return this->checkUpdate;
}

void Settings::setCheckUpdate(bool flag)
{
	if (this->checkUpdate != flag) {
		this->checkUpdate = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("check_update"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isShowToolbar() const
{
	return this->showToolbar;
}

void Settings::setShowToolbar(bool flag)
{
	if (this->showToolbar != flag) {
		this->showToolbar = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("show_toolbar"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isShowStatusBar() const
{
	return this->showStatusBar;
}

void Settings::setShowStatusBar(bool flag)
{
	if (this->showStatusBar != flag) {
		this->showStatusBar = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("show_statusbar"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isShowBallonMessage() const
{
	return this->showBallonMessage;
}

void Settings::setShowBallonMessage(bool flag)
{
	if (this->showBallonMessage != flag) {
		this->showBallonMessage = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("show_ballon"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isAutoReconnect() const
{
	return this->autoReconnect;
}

void Settings::setAutoReconnect(bool flag)
{
	if (this->autoReconnect != flag) {
		this->autoReconnect = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("auto_reconnect"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isAutoMinimum() const
{
	return this->autoMinimum;
}

void Settings::setAutoMinimum(bool flag)
{
	if (this->autoMinimum != flag) {
		this->autoMinimum = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett (iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("auto_minimum"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isAutoStartOnWindowsStartup() const
{
#ifdef _WIN32
	QSettings regRun(QLatin1String("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
		QSettings::NativeFormat);
	// 必须和NSIS安装脚本中定义的PRODUCT_NAME变量值一致
	QString regVal = regRun.value(QLatin1String("Big SSL VPN"), QLatin1String("")).toString();
	return !regVal.isEmpty();
#else
	// TODO
	return false;
#endif
}

void Settings::setAutoStartOnWindowsStartup(bool flag)
{
#ifdef _WIN32
	QSettings regRun(QLatin1String("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), QSettings::NativeFormat);
	if (flag) {
		if (!this->isAutoStartOnWindowsStartup()) {
			const QString path = QDir::toNativeSeparators(
				QDir(QApplication::applicationDirPath()).absoluteFilePath(QLatin1String(VPN_CLIENT)));
			// 必须和NSIS安装脚本中定义的PRODUCT_NAME变量值一致
			regRun.setValue(QLatin1String("Big SSL VPN"), QLatin1Char('\"') + path + QLatin1Char('\"'));
		}
	} else {
		if (this->isAutoStartOnWindowsStartup())
			regRun.remove(QLatin1String("Big SSL VPN"));
	}
#else
	Q_UNUSED(flag)
	// TODO
#endif
}

bool Settings::isSaveCredential() const
{
	return this->saveCredential;
}

void Settings::setSaveCredential(bool flag)
{
	if (this->saveCredential != flag) {
		this->saveCredential = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("save_credential"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}

bool Settings::isPopupAccessibleResource() const
{
	return this->popupAccessibleResource;
}

void Settings::setPopupAccessibleResource(bool flag)
{
	if (this->popupAccessibleResource != flag) {
		this->popupAccessibleResource = flag;
#ifdef _WIN32
		FileUtil::setReadonlyAttribute(iniPath, false);
#endif
		QSettings sett(iniPath, QSettings::IniFormat);
		sett.setValue(QLatin1String("popup_accessible_resource"), flag ? QLatin1String("true") : QLatin1String("false"));
#ifndef _WIN32
		FileUtil::addPermissions(iniPath, FileUtil::ANY_BODY_READ);
#endif
	}
}
