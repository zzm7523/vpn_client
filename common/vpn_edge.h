#ifndef __VPN_EDGE_H__
#define __VPN_EDGE_H__

#include "../config/config.h"

#include <QString>
#include <QList>

#include "server_endpoint.h"
#include "server_endpoint_selector.h"

/**
 * �洢OpenVPN��������Ϣ 
 */
class VPNEdge
{
public:
	VPNEdge();
	~VPNEdge();
	// ȱʡ�������캯���Ϳ�����

	const QString& getUpdateService() const;
	void setUpdateService(const QString& updateService);

	const QString& getPasswordService() const;
	void setPasswordService(const QString& passwordService);
	
	bool isWeakPassword() const;
	void setWeakPassword(bool weakPassword);

	ServerEndpointSelector::Algorithm getClusterAlgorithm() const;
	void setClusterAlgorithm(ServerEndpointSelector::Algorithm clusterAlgorithm);
	
	const QList<ServerEndpoint>& getClusterEndpoints() const;
	bool addClusterEndpoint(const ServerEndpoint& clusterEndpoint);
	bool removeClusterEndpoint(const ServerEndpoint& clusterEndpoint);

private:
	friend QDataStream& operator<<(QDataStream& stream, const VPNEdge& edge);
	friend QDataStream& operator >> (QDataStream& stream, VPNEdge& edge);

	QString updateService;
	QString passwordService;
	bool weakPassword;
	ServerEndpointSelector::Algorithm clusterAlgorithm;
	QList<ServerEndpoint> clusterEndpoints;

	// ÿ�����serial_uid����ͬ
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(VPNEdge)

#endif
