#ifndef __RESOURCE_POLICY_H__
#define __RESOURCE_POLICY_H__

#include "../config/config.h"

#include <QUrl>

#include "../common/accessible_resource.h"
#include "policy.h"

/*
 * АэИз:
 * policy resource http://www.oschina.net/ http://www.oschina.net/ all
 */

class ResourcePolicy : public Policy
{
public:
	static const QString& type_name();

	explicit ResourcePolicy(const QStringList& items);

	virtual const QString toExternalForm() const;

	virtual ApplyResult apply(const Context& ctx);

private:
	ResourcePolicy(const ResourcePolicy& policy);

	AccessibleResource resource;

};

#endif
