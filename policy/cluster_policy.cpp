#include <QDebug>

#include "cluster_policy.h"

const QString& ClusterPolicy::type_name()
{
	static const QString type_name(QLatin1String("cluster"));
	return type_name;
}

ClusterPolicy::ClusterPolicy(const QStringList& items)
	: Policy(PolicyEngineI::ConnectedAfter, Policy::NoneOption), algorithm(ServerEndpointSelector::Random)
{
	QStringList localItems = items;	// 复制临时变量

	setOptionStringList(localItems);

	if (localItems.size() > 0) {
		if (localItems.at(0) == QLatin1String("random"))
			this->algorithm = ServerEndpointSelector::Random;
		else if (localItems.at(0) == QLatin1String("sequence"))
			this->algorithm = ServerEndpointSelector::Sequence;
		else if (localItems.at(0) == QLatin1String("balance"))
			this->algorithm = ServerEndpointSelector::Balance;
		else
			this->valid = false;
	}

	if (localItems.size() > 1) {
		bool ok;
		ServerEndpoint endpoint;

		for (int i = 1; i < localItems.size(); ++i) {
			endpoint = parseServerEndpoint(localItems.at(i), &ok);
			if (ok)
				this->endpoints.append(endpoint);
			else {
				this->valid = false;
				break;
			}
		}
	}

	if (!this->valid) {
		this->valid = !endpoints.isEmpty();
	}
}

const QString ClusterPolicy::toExternalForm() const
{
	QString externalForm;
	externalForm.append(ClusterPolicy::type_name()).append(QLatin1Char(' '));

	const QStringList options = getOptionStringList();
	if (!options.isEmpty())
		externalForm.append(options.join(QLatin1Char(' '))).append(QLatin1Char(' '));

	if (this->algorithm == ServerEndpointSelector::Random)
		externalForm.append("random");
	else if (this->algorithm == ServerEndpointSelector::Sequence)
		externalForm.append("sequence");
	else if (this->algorithm == ServerEndpointSelector::Balance)
		externalForm.append("balance");

	QListIterator<ServerEndpoint> it(this->endpoints);
	while (it.hasNext()) {
		const ServerEndpoint& endpoint = it.next();
		externalForm.append(' ').append(endpoint.getHost())
			.append(':').append(endpoint.getPort()).append(':').append(endpoint.getProtocol());
	}

	return externalForm;
}

ApplyResult ClusterPolicy::apply(const Context& ctx)
{
	Q_UNUSED(ctx)

	ApplyResult result(ApplyResult::Success);
	result.setAttribute(ApplyResult::TYPE_NAME, ClusterPolicy::type_name());
	result.setAttribute(ApplyResult::CLUSTER_ALGORITHM, QVariant::fromValue(static_cast<int>(algorithm)));
	result.setAttribute(ApplyResult::SERVER_ENDPOINT_LIST, QVariant::fromValue(endpoints));
	return result;
}

ServerEndpoint ClusterPolicy::parseServerEndpoint(const QString& text, bool *ok)
{
	// 192.168.31.29:2791:udp
	ServerEndpoint endpoint;
	QStringList items = text.split(QLatin1Char(':'), QString::SkipEmptyParts);
	if (items.size() == 3) {
		*ok = true;
		endpoint.setHost(items.at(0));
		endpoint.setPort(items.at(1).toInt(ok));
		endpoint.setProtocol(ServerEndpoint::string2Protocol(items.at(2)));
	} else {
		*ok = false;
		qDebug() << QLatin1String("parse ServerEndpoint fail, ") << text;
	}
	return endpoint;
}
