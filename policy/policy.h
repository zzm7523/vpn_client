#ifndef __POLICY_H__
#define __POLICY_H__

#include "../config/config.h"

#include <QVariant>
#include <QString>
#include <QStringList>

#include "../common/context.h"
#include "policy_engine_i.h"

#ifdef _WIN32
#pragma warning(disable:4100)
#endif

class Policy
{
public:
	// 策略执行选项
	enum OptionFlag
	{
		NoneOption = 0x0,
		AsInvoker  = 0x0001,
		RequireAdministrator = 0x0002,
		Interactive   = 0x0004,
		NoInteractive = 0x0010
	};
	Q_DECLARE_FLAGS(Options, OptionFlag)

	virtual ~Policy() {
	}

	PolicyEngineI::ApplyPoint getApplyPoint() const {
		return this->point;
	}

	void setApplyPoint(PolicyEngineI::ApplyPoint applyPoint) {
		Q_UNUSED(applyPoint)
		this->point = applyPoint;
	}

	Policy::Options getOptions() const {
		return this->options;
	}

	void setOptions(Policy::Options options) {
		this->options = options;
	}

	virtual const QString toExternalForm() const = 0;

	virtual bool prepare(const Context& ctx) {
		Q_UNUSED(ctx)
		return valid;
	}

	virtual ApplyResult apply(const Context& ctx) = 0;

protected:
    Policy(PolicyEngineI::ApplyPoint _point, Options _options)
		: point(_point), options(_options), valid(true) {
	}
	// 策略不允许复制, 拷贝
	Policy(const Policy& policy);

	QStringList getOptionStringList() const;
	void setOptionStringList(QStringList& items);

    PolicyEngineI::ApplyPoint point;
	Policy::Options options;
	bool valid;

};
Q_DECLARE_OPERATORS_FOR_FLAGS(Policy::Options)

#endif
