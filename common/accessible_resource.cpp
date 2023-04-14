#include "common.h"
#include "accessible_resource.h"

const unsigned int AccessibleResource::serial_uid = 0x025;

AccessibleResource::AccessibleResource(const QString& _name, const QString& _uri, const QString& _platform,
		const QString& _program)
	: name(_name), uri(_uri), platform(_platform), program(_program)
{
}

AccessibleResource::AccessibleResource(const QString& _name, const QString& _uri)
	: name(_name), uri(_uri), platform(QLatin1String(ANY_PLATFORM))
{
}

AccessibleResource::AccessibleResource()
	: platform(QLatin1String(ANY_PLATFORM))
{
}

bool AccessibleResource::isEmpty() const
{
	return this->name.isEmpty() || this->uri.isEmpty();
}

const QString& AccessibleResource::getName() const
{
	return this->name;
}

void AccessibleResource::setName(const QString& name)
{
	this->name = name;
}

const QString& AccessibleResource::getUri() const
{
	return this->uri;
}

void AccessibleResource::setUri(const QString& _uri)
{
	this->uri = _uri;
}

const QString& AccessibleResource::getPlatform() const
{
	return this->platform;
}

void AccessibleResource::setPlatform(const QString& platform)
{
	this->platform = platform;
}

const QString& AccessibleResource::getProgram() const
{
	return this->program;
}

void AccessibleResource::setProgram(const QString& program)
{
	this->program = program;
}

QString AccessibleResource::toExternalForm() const
{
	QString externalForm;
	if (!this->isEmpty()) {
		externalForm.append(this->name).append(QLatin1Char(' ')).append(this->uri);
		if (!this->platform.isEmpty())
			externalForm.append(QLatin1Char(' ')).append(this->platform);
		if (!this->program.isEmpty())	
			externalForm.append(QLatin1Char(' ')).append(this->program);
	}
	return externalForm;
}

bool AccessibleResource::operator!=(const AccessibleResource& other)
{
	return 0 != this->name.compare(other.name, Qt::CaseInsensitive)
		|| 0 != this->uri.compare(other.uri, Qt::CaseInsensitive)
		|| 0 != this->platform.compare(other.platform, Qt::CaseInsensitive)
#ifdef _WIN32
		|| 0 != this->program.compare(other.program, Qt::CaseInsensitive)
#else
		|| 0 != this->program.compare(other.program, Qt::CaseSensitive)
#endif
		;
}

bool AccessibleResource::operator==(const AccessibleResource& other)
{
	return 0 == this->name.compare(other.name, Qt::CaseInsensitive)
		&& 0 == this->uri.compare(other.uri, Qt::CaseInsensitive)
		&& 0 == this->platform.compare(other.platform, Qt::CaseInsensitive)
#ifdef _WIN32
		&& 0 == this->program.compare(other.program, Qt::CaseInsensitive);
#else
		&& 0 == this->program.compare(other.program, Qt::CaseSensitive);
#endif
}

QDataStream& operator<<(QDataStream& stream, const AccessibleResource& accessibleResource)
{
	stream << AccessibleResource::serial_uid << accessibleResource.name << accessibleResource.uri
		<< accessibleResource.platform << accessibleResource.program;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, AccessibleResource& accessibleResource)
{
	static unsigned int local_serial_uid;

	stream >> local_serial_uid >> accessibleResource.name >> accessibleResource.uri
		>> accessibleResource.platform >> accessibleResource.program;

	Q_ASSERT(AccessibleResource::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}
