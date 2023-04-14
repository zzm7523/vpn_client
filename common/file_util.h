#include <QString>
#include <QFileDevice>

class FileUtil
{
public:
#ifndef _WIN32
	const static QFileDevice::Permissions ANY_BODY_READ;
	const static QFileDevice::Permissions ANY_BODY_WRITE;
	const static QFileDevice::Permissions ANY_BODY_EXE;
#endif

#ifdef _WIN32
	static bool setReadonlyAttribute(const QString& fileName, bool readonly);
	static bool setHideAttribute(const QString& fileName, bool hide);
#else
	static bool addPermissions(const QString& fileName, QFileDevice::Permissions permissions);
	static bool removePermissions(const QString& fileName, QFileDevice::Permissions permissions);
#endif

	static QString getAppSavePath(const QString& appName, bool create=true);

private:
	FileUtil();

};
