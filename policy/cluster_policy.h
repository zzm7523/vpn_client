#ifndef __OS_UPDATE_POLICY_H__
#define __OS_UPDATE_POLICY_H__

#include "../config/config.h"

#include <QList>

#include "../common/server_endpoint.h"
#include "../common/server_endpoint_selector.h"
#include "policy.h"

/*
 * АэИз:
 * cluster random 192.168.31.29:2791:udp 192.168.31.29:2791:tcp
 */

class ClusterPolicy : public Policy
{
public:
	static const QString& type_name();

	explicit ClusterPolicy(const QStringList& items);

	virtual const QString toExternalForm() const;

	virtual ApplyResult apply(const Context& ctx);

private:
	ClusterPolicy(const ClusterPolicy& policy);
	ServerEndpoint parseServerEndpoint(const QString& text, bool *ok);

	ServerEndpointSelector::Algorithm algorithm;
	QList<ServerEndpoint> endpoints;

};

#endif
