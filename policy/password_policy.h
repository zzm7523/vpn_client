#ifndef __OS_PASSWORD_POLICY_H__
#define __OS_PASSWORD_POLICY_H__

#include "../config/config.h"
#include "policy.h"

/*
 * АэИз:
 * policy password https://192.168.31.29/chg_passwd.do weak_password
 */

class PasswordPolicy : public Policy
{
public:
	static const QString& type_name();

	explicit PasswordPolicy(const QStringList& items);

	virtual const QString toExternalForm() const;

	virtual ApplyResult apply(const Context& ctx);

private:
	PasswordPolicy(const PasswordPolicy& policy);

	QString serviceUrl;
	bool weakPassword;
	
};

#endif
