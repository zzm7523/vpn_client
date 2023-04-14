#ifndef __TERMINAL_BIND_POLICY_H__
#define __TERMINAL_BIND_POLICY_H__

#include "../config/config.h"
#include "policy.h"

class TerminalBindPolicy : public Policy
{
public:
	static const QString& type_name();

	// �ն˰󶨱�������֤ǰִ��, �����������������ӳɹ���, ���԰󶨲��Բ����ɷ��������. 
	TerminalBindPolicy();

	virtual const QString toExternalForm() const;

	virtual ApplyResult apply(const Context& ctx);

private:
	TerminalBindPolicy(const TerminalBindPolicy& policy);

};


#endif
