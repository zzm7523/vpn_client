#include <QApplication>

#include "accessible_resource.h"
#include "vpn_config.h"
#include "tls_auth.h"
#include "credentials.h"
#include "x509_certificate_info.h"
#include "server_endpoint.h"
#include "vpn_i.h"

const unsigned int VPNTunnel::serial_uid = 0x637;

VPNTunnel::VPNTunnel()
	: fragment(-1), compression(VPNTunnel::NO), tunDeviceType(VPNTunnel::TUN), tunDeviceIndex(0xFFFFFFFF),
	keepAlive(-1, -1)
{
}

bool VPNTunnel::isEmpty() const
{
	return (this->virtualIPv4Addr.isEmpty() && this->virtualIPv6Addr.isEmpty()) ||
		this->tlsVersion.isEmpty();
}

void VPNTunnel::clear()
{
	this->establishedTime = QDateTime();
	this->deviceList.clear();
	this->tlsVersion.clear();
	this->tlsCipher.clear();

	this->cipher.clear();
	this->auth.clear();
	this->fragment = -1;
	this->compression = VPNTunnel::NO;

	this->tunDeviceType = VPNTunnel::TUN;
	this->tunDeviceName.clear();
	this->tunDeviceIndex = 0xFFFFFFFF;

	this->virtualIPv4Gateway.clear();
	this->virtualIPv6Gateway.clear();
	this->virtualIPv4Addr.clear();
	this->virtualIPv6Addr.clear();
	this->keepAlive = QPair<int, int>(-1, -1);
	this->serverEndpoint.clear();
}

QString VPNTunnel::format(const QString& prefix, const QString& separator) const
{
	QString text(prefix);

	text.append(QApplication::translate("VPNTunnel", "Cipher:")).append(" ").append(this->getCipher());
	text.append(separator);
	text.append(QApplication::translate("VPNTunnel", "Auth:")).append(" ").append(this->getAuth());

	// 只显示一种虚拟IP地址, IPv4优先
	if (!this->getVirtualIPv4Addr().isEmpty()) {
		text.append(separator);
		text.append(QApplication::translate("VPNTunnel", "Virtual IP:")).append(" ").append(this->getVirtualIPv4Addr());
	} else if (!this->getVirtualIPv6Addr().isEmpty()) {
		text.append(separator);
		text.append(QApplication::translate("VPNTunnel", "Virtual IP:")).append(" ").append(this->getVirtualIPv6Addr());
	}

	return text;
}

const QDateTime& VPNTunnel::getEstablishedTime() const
{
	return this->establishedTime;
}

void VPNTunnel::setEstablishedTime(const QDateTime& establishedTime)
{
	this->establishedTime = establishedTime;
}

const QStringList& VPNTunnel::getOpenedEncryptDevices() const
{
	return this->deviceList;
}

void VPNTunnel::setOpenedEncryptDevices(const QStringList& deviceList)
{
	this->deviceList = deviceList;
}

const QString& VPNTunnel::getTLSVersion() const
{
	return this->tlsVersion;
}

void VPNTunnel::setTLSVersion(const QString& tlsVersion)
{
	this->tlsVersion = tlsVersion;
}

const QString& VPNTunnel::getTLSCipher() const
{
	return this->tlsCipher;
}

void VPNTunnel::setTLSCipher(const QString& tlsCipher)
{
	this->tlsCipher = tlsCipher;
}

const QString& VPNTunnel::getCipher() const
{
	return this->cipher;
}

void VPNTunnel::setCipher(const QString& cipher)
{
	this->cipher = cipher;
}

const QString& VPNTunnel::getAuth() const
{
	return this->auth;
}

void VPNTunnel::setAuth(const QString& auth)
{
	this->auth = auth;
}

int VPNTunnel::getFragment() const
{
	return this->fragment;
}

void VPNTunnel::setFragment(int fragment)
{
	this->fragment = fragment;
}

VPNTunnel::CompressionOption VPNTunnel::getCompressionOption() const
{
	return this->compression;
}

void VPNTunnel::setCompressionOption(VPNTunnel::CompressionOption compression)
{
	this->compression = compression;
}

VPNTunnel::TunDeviceType VPNTunnel::getTunDeviceType() const
{
	return this->tunDeviceType;
}

void VPNTunnel::setTunDeviceType(VPNTunnel::TunDeviceType tunDeviceType)
{
	this->tunDeviceType = tunDeviceType;
}

const QString& VPNTunnel::getTunDeviceName() const
{
	return this->tunDeviceName;
}

void VPNTunnel::setTunDeviceName(const QString& tunDeviceName)
{
	this->tunDeviceName = tunDeviceName;
}

#ifdef _WIN32
unsigned long VPNTunnel::getTunDeviceIndex() const
{
	return this->tunDeviceIndex;
}

void VPNTunnel::setTunDeviceIndex(unsigned long tunDeviceIndex)
{
	this->tunDeviceIndex = tunDeviceIndex;
}
#endif

const QString& VPNTunnel::getVirtualIPv4Gateway() const
{
	return this->virtualIPv4Gateway;
}

void VPNTunnel::setVirtualIPv4Gateway(const QString& virtualIPv4Gateway)
{
	this->virtualIPv4Gateway = virtualIPv4Gateway;
}

const QString& VPNTunnel::getVirtualIPv6Gateway() const
{
	return this->virtualIPv6Gateway;
}

void VPNTunnel::setVirtualIPv6Gateway(const QString& virtualIPv6Gateway)
{
	this->virtualIPv6Gateway = virtualIPv6Gateway;
}

const QString& VPNTunnel::getVirtualIPv4Addr() const
{
	return this->virtualIPv4Addr;
}

void VPNTunnel::setVirtualIPv4Addr(const QString& virtualIPv4Addr)
{
	this->virtualIPv4Addr = virtualIPv4Addr;
}

const QString& VPNTunnel::getVirtualIPv6Addr() const
{
	return this->virtualIPv6Addr;
}

void VPNTunnel::setVirtualIPv6Addr(const QString& virtualIPv6Addr)
{
	this->virtualIPv6Addr = virtualIPv6Addr;
}

const QPair<int, int>& VPNTunnel::getKeepAlive() const
{
	return this->keepAlive;
}

void VPNTunnel::setKeepAlive(const QPair<int, int>& keepAlive)
{
	this->keepAlive = keepAlive;
}

const ServerEndpoint& VPNTunnel::getServerEndpoint() const
{
	return this->serverEndpoint;
}

void VPNTunnel::setServerEndpoint(const ServerEndpoint& serverEndpoint)
{
	this->serverEndpoint = serverEndpoint;
}

QDataStream& operator<<(QDataStream& stream, const VPNTunnel& tunnel)
{
	stream << VPNTunnel::serial_uid << tunnel.establishedTime << tunnel.deviceList << tunnel.tlsVersion
		<< tunnel.tlsCipher << tunnel.cipher << tunnel.auth << tunnel.fragment
		<< static_cast<unsigned int>(tunnel.compression) << static_cast<unsigned int>(tunnel.tunDeviceType)
		<< tunnel.tunDeviceName << static_cast<unsigned long long>(tunnel.tunDeviceIndex)
		<< tunnel.virtualIPv4Gateway << tunnel.virtualIPv6Gateway << tunnel.virtualIPv4Addr
		<< tunnel.virtualIPv6Addr << tunnel.keepAlive << tunnel.serverEndpoint;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, VPNTunnel& tunnel)
{
	unsigned int local_serial_uid, x_compression, x_tun_device_type;
	unsigned long long x_tun_device_index;

	stream >> local_serial_uid >> tunnel.establishedTime >> tunnel.deviceList >> tunnel.tlsVersion
		>> tunnel.tlsCipher >> tunnel.cipher >> tunnel.auth >> tunnel.fragment >> x_compression
		>> x_tun_device_type >> tunnel.tunDeviceName >> x_tun_device_index
		>> tunnel.virtualIPv4Gateway >> tunnel.virtualIPv6Gateway >> tunnel.virtualIPv4Addr
		>> tunnel.virtualIPv6Addr >> tunnel.keepAlive >> tunnel.serverEndpoint;
	tunnel.compression = static_cast<VPNTunnel::CompressionOption>(x_compression);
	tunnel.tunDeviceType = static_cast<VPNTunnel::TunDeviceType>(x_tun_device_type);
	tunnel.tunDeviceIndex = static_cast<unsigned long>(x_tun_device_index);

	Q_ASSERT(VPNTunnel::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}

VPNAgentI::VPNAgentI()
{
}

VPNAgentI::~VPNAgentI()
{
}
