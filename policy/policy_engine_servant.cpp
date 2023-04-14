#include <QCoreApplication>

#include "policy_engine_i_proxy.h"
#include "policy.h"
#include "policy_engine_servant.h"

PolicyEngineServant::PolicyEngineServant(const QString& uniqueIdentify, bool _front, VPNAgentI *_agentI,
		PolicyEngineProxy *_remoteEngineProxy)
	: PolicyEngineSkeleton(uniqueIdentify), front(_front), agentI(_agentI), remoteEngineProxy(_remoteEngineProxy)
{
}

PolicyEngineServant::~PolicyEngineServant()
{
}

PolicyEngineProxy* PolicyEngineServant::getRemotePolicyEngine()
{
	return this->remoteEngineProxy;
}

void PolicyEngineServant::setRemotePolicyEngine(PolicyEngineProxy *remoteEngineProxy)
{
	this->remoteEngineProxy = remoteEngineProxy;
}

bool PolicyEngineServant::initialize(const Context& ctx)
{
	Q_UNUSED(ctx)

	return true;
}

void PolicyEngineServant::clear(const Context& ctx)
{
	Q_UNUSED(ctx)

	for (QList<Policy*>::iterator it = policys.begin(); it != policys.end(); ++it) {
		delete *it;
	}
	policys.clear();
}

bool PolicyEngineServant::addPolicy(const QString& policy, const Context& ctx)
{
	Q_UNUSED(ctx)

	Policy *policyPtr = PolicyEngineI::newInstance(policy);

	if (policyPtr) {
		policys.append(policyPtr);
	}

	return policyPtr ? true : false;
}

bool PolicyEngineServant::hasPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx)
{
	Q_UNUSED(ctx)

	QListIterator<Policy*> it(policys);
	while (it.hasNext()) {
		if (it.next()->getApplyPoint() == point)
			return true;
	}
	return false;
}

ApplyResult PolicyEngineServant::applyPolicy(const QString& policy, const Context& ctx)
{
	int counter = ctx.getAttribute(Context::POLICY_ENGINE_COUNTER).toInt();
	if (counter > MAX_POLICY_ENGINE_COUNTER)
		return ApplyResult(ApplyResult::Fail, QCoreApplication::translate("PolicyEngineI", "beyond counter limit"));

	Policy *policyPtr = PolicyEngineI::newInstance(policy);
	if (!policyPtr)
		return ApplyResult(ApplyResult::Warning, QCoreApplication::translate("PolicyEngineI", "invalid policy"));

	ApplyResult result(ApplyResult::Fail);
	bool remote = false;	// 由远端引擎执行
	const Policy::Options options = policyPtr->getOptions();

	if ((options & Policy::AsInvoker) || (options & Policy::Interactive)) {	// 必须由前端策略引擎执行
		if (!front)
			remote = true;
	} else if (options & Policy::RequireAdministrator) {	// 必须由后端策略引擎执行
		if (front)
			remote = true;
	}

	if (remote) {
		if (remoteEngineProxy) {
			result = remoteEngineProxy->applyPolicy(policyPtr->toExternalForm(), ctx);
		} else {
			result.setResult(ApplyResult::Fail);
			result.setReason(QCoreApplication::translate("PolicyEngineI", "remote policy engine undefine"));
		}
	} else {
		Context localCtx(ctx);

		localCtx.setAttribute(Context::POLICY_ENGINE_COUNTER, QVariant::fromValue(++counter));

		if (policyPtr->prepare(localCtx))
			result = policyPtr->apply(localCtx);
	}

	delete policyPtr;
	return result;
}

ApplyResult PolicyEngineServant::applyPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx)
{
	int counter = ctx.getAttribute(Context::POLICY_ENGINE_COUNTER).toInt();
	if (counter > MAX_POLICY_ENGINE_COUNTER)
		return ApplyResult(ApplyResult::Fail, QCoreApplication::translate("PolicyEngineI", "beyond counter limit"));

	QListIterator<Policy*> it(policys);
	Policy *policyPtr = NULL;

	// 查找满足条件的第一条策略
	while (it.hasNext()) {
		policyPtr = it.next();
		if (policyPtr->getApplyPoint() == point)
			break;
	}

	if (!policyPtr || policyPtr->getApplyPoint() != point)
		return ApplyResult(ApplyResult::Success);	// 不影响隧道

	// 执行满足条件的第一条策略
	policys.removeAll(policyPtr);

	ApplyResult result(ApplyResult::Fail);
	bool remote = false;	// 由远端引擎执行
	const Policy::Options options = policyPtr->getOptions();

	if ((options & Policy::AsInvoker) || (options & Policy::Interactive)) {	// 必须由前端策略引擎执行
		if (!front)
			remote = true;
	} else if (options & Policy::RequireAdministrator) {	// 必须由后端策略引擎执行
		if (front)
			remote = true;
	}

	if (remote) {
		if (remoteEngineProxy) {
			result = remoteEngineProxy->applyPolicy(policyPtr->toExternalForm(), ctx);
		} else {
			result.setResult(ApplyResult::Fail);
			result.setReason(QCoreApplication::translate("PolicyEngineI", "remote policy engine undefine"));
		}
	} else {
		Context localCtx(ctx);

		localCtx.setAttribute(Context::POLICY_ENGINE_COUNTER, QVariant::fromValue(++counter));

		if (policyPtr->prepare(localCtx))
			result = policyPtr->apply(localCtx);
	}

	delete policyPtr;
	return result;
}
