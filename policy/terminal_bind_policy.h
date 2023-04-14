#ifndef __TERMINAL_BIND_POLICY_H__
#define __TERMINAL_BIND_POLICY_H__

#include "../config/config.h"
#include "policy.h"

class TerminalBindPolicy : public Policy
{
public:
	static const QString& type_name();

	// 终端绑定必须再认证前执行, 而策略推送是在连接成功后, 所以绑定策略不能由服务端推送. 
	TerminalBindPolicy();

	virtual const QString toExternalForm() const;

	virtual ApplyResult apply(const Context& ctx);

private:
	TerminalBindPolicy(const TerminalBindPolicy& policy);

};


#endif
