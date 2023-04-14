#include "../common/common.h"
#include "vpn_edge.h"

const unsigned int VPNEdge::serial_uid = 0x141;

VPNEdge::VPNEdge()
	: weakPassword(false), clusterAlgorithm(ServerEndpointSelector::Random)
{
}

VPNEdge::~VPNEdge()
{
}

const QString& VPNEdge::getUpdateService() const
{
	return this->updateService;
}

void VPNEdge::setUpdateService(const QString& updateService)
{
	this->updateService = updateService;
}

const QString& VPNEdge::getPasswordService() const
{
	return this->passwordService;
}

void VPNEdge::setPasswordService(const QString& passwordService)
{
	this->passwordService = passwordService;
}	
	
bool VPNEdge::isWeakPassword() const
{
	return this->weakPassword;
}

void VPNEdge::setWeakPassword(bool weakPassword)
{
	this->weakPassword = weakPassword;
}

ServerEndpointSelector::Algorithm VPNEdge::getClusterAlgorithm() const
{
	return this->clusterAlgorithm;
}

void VPNEdge::setClusterAlgorithm(ServerEndpointSelector::Algorithm clusterAlgorithm)
{
	this->clusterAlgorithm = clusterAlgorithm;
}	
	
const QList<ServerEndpoint>& VPNEdge::getClusterEndpoints() const
{
	return this->clusterEndpoints;
}

bool VPNEdge::addClusterEndpoint(const ServerEndpoint& clusterEndpoint)
{
	if (!this->clusterEndpoints.contains(clusterEndpoint)) {
		this->clusterEndpoints.append(clusterEndpoint);
		return true;
	}
	return false;
}

bool VPNEdge::removeClusterEndpoint(const ServerEndpoint& clusterEndpoint)
{
	return this->clusterEndpoints.removeOne(clusterEndpoint);
}

QDataStream& operator<<(QDataStream& stream, const VPNEdge& edge)
{
	stream << VPNEdge::serial_uid << edge.updateService << edge.passwordService << edge.weakPassword
		<< static_cast<quint32>(edge.clusterAlgorithm) << edge.clusterEndpoints;
	return stream;
}

QDataStream& operator >> (QDataStream& stream, VPNEdge& edge)
{
	quint32 local_serial_id, clusterAlgorithm;

	stream >> local_serial_id >> edge.updateService >> edge.passwordService >> edge.weakPassword
		>> clusterAlgorithm >> edge.clusterEndpoints;
	edge.clusterAlgorithm = static_cast<ServerEndpointSelector::Algorithm>(clusterAlgorithm);
	Q_ASSERT(VPNEdge::serial_uid == local_serial_id);

	return stream;
}
