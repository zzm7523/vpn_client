#ifndef __ZIP_UTIL_H__
#define __ZIP_UTIL_H__

#include "../config/config.h"

#include <QString>
#include <QStringList>
#include <QDir>
#include <QFile>

class ZipUtil
{
public:
	static bool extract(const QString& filePath, const QString& extDirPath, const QString& singleFileName = QLatin1String(""));
	static bool archive(const QString& filePath, const QDir& dir, const QString& comment = QLatin1String(""));
	static bool archiveFile(const QString& fileArchPath, const QString& fileSourcePath, const bool addMode = true,
		const QString& comment = QLatin1String(""));

private:
	static bool recurseAddDir(const QDir& dir, QStringList& sl);
	ZipUtil();

};

#endif
