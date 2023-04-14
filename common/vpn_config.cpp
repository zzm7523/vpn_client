#include <QRegularExpression>

#include "common.h"
#include "vpn_config.h"

const unsigned int VPNConfig::serial_uid = 0x139;

VPNConfig::VPNConfig(qint32 id, const QString& _path) 
	: id(id), path(_path), x509UserNameField(QLatin1String("CN")), temporary(false), autoReconnect(true),
	autoStart(false), authOptions(VPNConfig::EnablePassword), enableProxy(false), proxyType(VPNConfig::NoneProxy)
{
	// É¾³ý½áÎ²µÄ/»ò\×Ö·û
	this->path.replace(QRegularExpression(QLatin1String("[/|\\\\]$")), QLatin1String(""));
}

VPNConfig::VPNConfig()
{
	this->clear();
}

void VPNConfig::clear()
{
	this->id = -1;
	this->name.clear();
	this->path.clear();

	this->x509UserNameField = QLatin1String("CN");
	this->temporary = false;
	this->autoReconnect = true;
	this->autoStart = false;
	this->authOptions = VPNConfig::AutoProbe;
	this->remotes.clear();
	this->cipher.clear();
	this->auth.clear();
	this->tlsAuth.clear();
	this->enableProxy = false;
	this->proxyType = VPNConfig::NoneProxy;
	this->proxyHost.clear();
	this->proxyPort = 0;
	this->credentials.clear();
}

bool VPNConfig::isEmpty() const
{
	return this->name.isEmpty() || this->remotes.isEmpty();
}

qint32 VPNConfig::getId() const
{
	return this->id;
}

void VPNConfig::setId(qint32 id)
{
	this->id = id;
}

const QString& VPNConfig::getName() const
{
	return this->name;
}

void VPNConfig::setName(const QString& name)
{
	this->name = name;
}

const QString& VPNConfig::getPath() const
{
	return this->path;
}

void VPNConfig::setPath(const QString& path)
{
	this->path = path;
	// É¾³ý½áÎ²µÄ/»ò\×Ö·û
	this->path.replace(QRegularExpression(QLatin1String("[/|\\\\]$")), QLatin1String(""));
}

const QString& VPNConfig::getX509UserNameField() const
{
	return this->x509UserNameField;
}

void VPNConfig::setX509UserNameField(const QString& x509UserNameField)
{
	this->x509UserNameField = x509UserNameField;
}

bool VPNConfig::isTemporary() const
{
	return this->temporary;
}

void VPNConfig::setTemporary(bool temporary)
{
	this->temporary = temporary;
}

bool VPNConfig::isAutoReconnect() {
	return autoReconnect;
}

void VPNConfig::setAutoReconnect(bool autoReconnect) {
	this->autoReconnect = autoReconnect;
}

bool VPNConfig::isAutoStart() const
{
	return this->autoStart;
}

void VPNConfig::setAutoStart(bool autoStart)
{
	this->autoStart = autoStart;
}

VPNConfig::AuthOptions VPNConfig::getAuthOptions() const
{
	Q_ASSERT(!(this->authOptions & VPNConfig::EnablePassword && this->authOptions & VPNConfig::DisablePassword));
	return this->authOptions;
}

void VPNConfig::setAuthOptions(VPNConfig::AuthOptions authOptions)
{
	Q_ASSERT(!(authOptions & VPNConfig::EnablePassword && authOptions & VPNConfig::DisablePassword));
	this->authOptions = authOptions;
}

const QList<ServerEndpoint>& VPNConfig::getServerEndpoints() const
{
	return this->remotes;
}

void VPNConfig::setServerEndpoints(const QList<ServerEndpoint>& remotes)
{
	this->remotes = remotes;
}

const QString& VPNConfig::getTlsVersion() const
{
	return this->tlsVersion;
}

void VPNConfig::setTlsVersion(const QString& tlsVersion)
{
	this->tlsVersion = tlsVersion;
}

const QString& VPNConfig::getCipher() const
{
	return this->cipher;
}

void VPNConfig::setCipher(const QString& cipher)
{
	this->cipher = cipher;
}

const QString& VPNConfig::getAuth() const
{
	return this->auth;
}

void VPNConfig::setAuth(const QString& auth)
{
	this->auth = auth;
}

TLSAuth& VPNConfig::getTLSAuth()
{
	return tlsAuth;
}

void VPNConfig::setTLSAuth(const TLSAuth& tlsAuth)
{
	this->tlsAuth = tlsAuth;
}

bool VPNConfig::isEnableProxy() const
{
	return this->enableProxy;
}

void VPNConfig::setEnableProxy(bool enableProxy)
{
	this->enableProxy = enableProxy;
}

VPNConfig::ProxyType VPNConfig::getProxyType() const
{
	return this->proxyType;
}

void VPNConfig::setProxyType(VPNConfig::ProxyType proxyType)
{
	this->proxyType = proxyType;
	this->enableProxy = this->proxyType != VPNConfig::NoneProxy;
}

const QString& VPNConfig::getProxyHost() const
{
	return this->proxyHost;
}

void VPNConfig::setProxyHost(const QString& proxyHost)
{
	this->proxyHost = proxyHost;
}

quint16 VPNConfig::getProxyPort() const
{
	return this->proxyPort;
}

void VPNConfig::setProxyPort(quint16 proxyPort)
{
	this->proxyPort = proxyPort;
}

const QString& VPNConfig::getCompatibleOption()
{
	return this->compatibleOption;
}

void VPNConfig::setCompatibleOption(const QString& compatibleOption)
{
	this->compatibleOption = compatibleOption;
}

Credentials& VPNConfig::getCredentials()
{
	return this->credentials;
}

bool VPNConfig::operator == (const VPNConfig& other) const
{
	return this->id == other.id;
}

bool VPNConfig::operator < (const VPNConfig& other) const
{
	return this->id < other.id;
}

QDataStream& operator<<(QDataStream& stream, const VPNConfig& config)
{
	stream << VPNConfig::serial_uid << config.id << config.name << config.path << config.x509UserNameField
		<< config.temporary << config.autoReconnect << config.autoStart << static_cast<quint32>(config.authOptions)
		<< config.remotes << config.tlsVersion << config.cipher << config.auth << config.tlsAuth
		<< config.enableProxy << static_cast<quint32>(config.proxyType) << config.proxyHost << config.proxyPort
		<< config.compatibleOption << config.credentials;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, VPNConfig& config)
{
	quint32 local_serial_id, authOptions, proxyType;

	stream >> local_serial_id >> config.id >> config.name >> config.path >> config.x509UserNameField
		>> config.temporary >> config.autoReconnect >> config.autoStart >> authOptions
		>> config.remotes >> config.tlsVersion >> config.cipher >> config.auth >> config.tlsAuth
		>> config.enableProxy >> proxyType >> config.proxyHost >> config.proxyPort >> config.compatibleOption
		>> config.credentials; 

	config.authOptions = static_cast<VPNConfig::AuthOptions>(authOptions);
	config.proxyType = static_cast<VPNConfig::ProxyType>(proxyType);
	Q_ASSERT(VPNConfig::serial_uid == local_serial_id);

	return stream;
}
