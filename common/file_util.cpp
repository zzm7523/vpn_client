#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QRegularExpression>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include "file_util.h"

#ifndef _WIN32
const QFileDevice::Permissions FileUtil::ANY_BODY_READ = QFileDevice::ReadOwner|QFileDevice::ReadUser|QFileDevice::ReadGroup|QFileDevice::ReadOther;
const QFileDevice::Permissions FileUtil::ANY_BODY_WRITE = QFileDevice::WriteOwner|QFileDevice::WriteUser|QFileDevice::WriteGroup|QFileDevice::WriteOther;
const QFileDevice::Permissions FileUtil::ANY_BODY_EXE = QFileDevice::ExeOwner|QFileDevice::ExeUser|QFileDevice::ExeGroup|QFileDevice::ExeOther;
#endif

#ifdef _WIN32
bool FileUtil::setReadonlyAttribute(const QString& fileName, bool readonly)
{
	DWORD currAttrs = GetFileAttributesA(qPrintable(fileName));
	DWORD newAttrs = currAttrs;
	bool result = true;

	if (readonly)
		newAttrs = currAttrs | FILE_ATTRIBUTE_READONLY;
	else
		newAttrs = currAttrs & ~FILE_ATTRIBUTE_READONLY;

	if (newAttrs != currAttrs)
		result = TRUE == SetFileAttributesA(qPrintable(fileName), newAttrs);
	return result;
}

bool FileUtil::setHideAttribute(const QString& fileName, bool hide)
{
	DWORD currAttrs = GetFileAttributesA(qPrintable(fileName));
	DWORD newAttrs = currAttrs;
	bool result = true;

	if (hide)
		newAttrs = currAttrs | FILE_ATTRIBUTE_HIDDEN;
	else
		newAttrs = currAttrs & ~FILE_ATTRIBUTE_HIDDEN;

	if (newAttrs != currAttrs)
		result = TRUE == SetFileAttributesA(qPrintable(fileName), newAttrs);
	return result;
}
#else
bool FileUtil::addPermissions(const QString& fileName, QFileDevice::Permissions permissions)
{
	QFileDevice::Permissions currPermissions = QFile::permissions(fileName);
	QFileDevice::Permissions newPermissions = currPermissions | permissions;
	bool result = true;

	if (newPermissions != currPermissions)
		result = QFile::setPermissions(fileName, newPermissions);
	return result;
}

bool FileUtil::removePermissions(const QString& fileName, QFileDevice::Permissions permissions)
{
	QFileDevice::Permissions currPermissions = QFile::permissions(fileName);
	QFileDevice::Permissions newPermissions = currPermissions & ~permissions;
	bool result = true;

	if (newPermissions != currPermissions)
		result = QFile::setPermissions(fileName, newPermissions);
	return result;
}
#endif

QString FileUtil::getAppSavePath(const QString& appName, bool create)
{
	Q_ASSERT(!appName.isEmpty());

#ifdef _WIN32
	QString appDataLoc = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
	int index = appDataLoc.lastIndexOf(QRegularExpression("[/|\\\\]"));
	if (index > 0)
		appDataLoc = appDataLoc.mid(0, index);

	QDir appDataDir(appDataLoc);
	if (!appDataDir.exists())
		appDataDir.mkpath(appDataLoc);

	if (create && !appDataDir.exists(appName)) // 不存在, 自动创建
		appDataDir.mkdir(appName);
	return QDir(appDataDir.absoluteFilePath(appName)).canonicalPath();
#else
	const QString homeLoc = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
	QDir homeDir(homeLoc);
	if (!homeDir.exists())
		homeDir.mkpath(homeLoc);
	
	const QString hAppName = QLatin1String(".") + appName;
	if (create && !homeDir.exists(hAppName)) // 不存在, 自动创建
		homeDir.mkdir(hAppName);
	const QString appSavePath = QDir(homeDir.absoluteFilePath(hAppName)).canonicalPath();
	FileUtil::addPermissions(appSavePath, FileUtil::ANY_BODY_READ|FileUtil::ANY_BODY_EXE);
	return appSavePath;
#endif
}
