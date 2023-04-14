#ifndef __UPDATE_POLICY_H__
#define __UPDATE_POLICY_H__

#include "../config/config.h"
#include "policy.h"

/*
 * АэИз:
 * policy update https://192.168.31.29/download
 */

class UpdatePolicy : public Policy
{
public:
	static const QString& type_name();

	explicit UpdatePolicy(const QStringList& items);

	virtual const QString toExternalForm() const;

	virtual ApplyResult apply(const Context& ctx);

private:
	UpdatePolicy(const UpdatePolicy& policy);

	QString serviceUrl;

};

#endif
