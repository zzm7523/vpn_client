#ifndef __ACCESSIBLE_RESOURCE_H__
#define __ACCESSIBLE_RESOURCE_H__

#include "../config/config.h"

#include <QString>
#include <QDataStream>

#define ANY_PLATFORM		"any"
#define WINDOWS_PLATFORM	"windows"
#define LINUX_PLATFORM		"linux"
#define MACX_PLATFORM		"macx"
#define IOS_PLATFORM		"ios"
#define ANDROID_PLATFORM	"android"

class AccessibleResource
{
public:
	AccessibleResource(const QString& name, const QString& uri, const QString& platform, const QString& program);
	AccessibleResource(const QString& name, const QString& uri);
	AccessibleResource();

	bool isEmpty() const;

	const QString& getName() const;
	void setName(const QString& name);

	const QString& getUri() const;
	void setUri(const QString& uri);
	
	const QString& getPlatform() const;
	void setPlatform(const QString& platform);

	const QString& getProgram() const;
	void setProgram(const QString& program);

	QString toExternalForm() const;

	bool operator!=(const AccessibleResource& other);
	bool operator==(const AccessibleResource& other);

private:
	friend QDataStream& operator<<(QDataStream& stream, const AccessibleResource& accessibleResource);
	friend QDataStream& operator>>(QDataStream& stream, AccessibleResource& accessibleResource);

	QString name;
	QString uri;
	QString platform;
	QString program;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(AccessibleResource)

#endif
