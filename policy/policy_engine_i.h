#ifndef __POLICY_ENGINE_I_H__
#define __POLICY_ENGINE_I_H__

#include "../config/config.h"

#include <QString>
#include <QMap>
#include <QMutex>

#include "../common/common.h"
#include "../common/context.h"

#define MAX_POLICY_ENGINE_COUNTER	2

// 策略执行结果
class ApplyResult
{
public:
	// 常用属性名称定义
	static const QString TYPE_NAME;
	static const QString SERVICE_URL;
	static const QString WEAK_PASSWORD;
	static const QString CLUSTER_ALGORITHM;
	static const QString SERVER_ENDPOINT_LIST;
	static const QString ACCESSIBLE_RESOURCE;

	enum Result
	{
		Success = 0,	// 不影响隧道
		Fail,			// 要求断开隧道
		Warning			// 不影响隧道
	};

	explicit ApplyResult(ApplyResult::Result _result, const QString& _reason = QLatin1String(""))
		: result(_result), reason(_reason) {
	}
	ApplyResult() : result(ApplyResult::Fail) {
	}

	ApplyResult::Result getResult() const {
		return this->result;
	}

	void setResult(ApplyResult::Result result) {
		this->result = result;
	}

	const QString& getReason() const {
		return this->reason;
	}

	void setReason(const QString& reason) {
		this->reason = reason;
	}

	bool hasAttribute(const QString& name) const {
		return this->attributes.contains(name);
	}

	QVariant getAttribute(const QString& name) const {
		return this->attributes.value(name);
	}

	void setAttribute(const QString& name, const QVariant& value) {
		this->attributes.insert(name, value);
	}

private:
	friend QDataStream& operator<<(QDataStream& stream, const ApplyResult& applyResult);
	friend QDataStream& operator>>(QDataStream& stream, ApplyResult& applyResult);

	ApplyResult::Result result;
	QString reason;
	QMap<QString, QVariant> attributes;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};

class Policy;

class PolicyFactory
{
public:
	virtual Policy* newInstance(const QStringList& items) = 0;

};

template<typename T>
class GeneralPolicyFactory : public PolicyFactory
{
public:
	Policy* newInstance(const QStringList& items) {
		return new T(items);
	}

};

class PolicyEngineI
{
public:
	// 应用策略的时间点
	enum ApplyPoint
	{
		ConnectedBefore = 0,
		ConnectedAfter,
		DisconnectBefore,
		DisconnectAfter,
		DeviceRemoved
	};

	static void registerFactory(const QString& objectType, PolicyFactory *factory);
	static void unregisterFactory(const QString& objectType);

	static Policy* newInstance(const QString& externalForm);

	PolicyEngineI();
	virtual ~PolicyEngineI() {}

	virtual bool initialize(const Context& ctx) = 0;

	virtual void clear(const Context& ctx) = 0;

	virtual bool addPolicy(const QString& policy, const Context& ctx) = 0;

	virtual bool hasPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx) = 0;

	virtual ApplyResult applyPolicy(const QString& policy, const Context& ctx) = 0;

	virtual ApplyResult applyPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx) = 0;

private:
	static QMutex globalPolicysMutex;
	static QMap<QString, PolicyFactory*> globalPolicyFactorys;

};

#endif
