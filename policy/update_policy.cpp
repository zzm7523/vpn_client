#include <QUrl>

#include "update_policy.h"

const QString& UpdatePolicy::type_name()
{
	static const QString type_name(QLatin1String("update"));
	return type_name;
}

UpdatePolicy::UpdatePolicy(const QStringList& items)
	: Policy(PolicyEngineI::ConnectedAfter, Policy::NoneOption)
{
	QStringList localItems = items;	// 复制临时变量

	setOptionStringList(localItems);

	if (localItems.size() > 0) {
		this->serviceUrl = localItems.at(0);
		this->valid = QUrl(this->serviceUrl).isValid();
	} else {
		this->valid = false;
	}
}

const QString UpdatePolicy::toExternalForm() const
{
	QString externalForm;
	externalForm.append(UpdatePolicy::type_name()).append(QLatin1Char(' '));

	const QStringList options = getOptionStringList();
	if (!options.isEmpty())
		externalForm.append(options.join(QLatin1Char(' '))).append(QLatin1Char(' '));

	externalForm.append(this->serviceUrl);
	
	return externalForm;
}

ApplyResult UpdatePolicy::apply(const Context& ctx)
{
	Q_UNUSED(ctx)

	ApplyResult result(ApplyResult::Success);
	result.setAttribute(ApplyResult::TYPE_NAME, UpdatePolicy::type_name());
	result.setAttribute(ApplyResult::SERVICE_URL, QVariant::fromValue(serviceUrl));
	return result;	
}
