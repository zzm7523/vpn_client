#include "resource_policy.h"

const QString& ResourcePolicy::type_name()
{
	static const QString type_name(QLatin1String("resource"));
	return type_name;
}

ResourcePolicy::ResourcePolicy(const QStringList& items)
	: Policy(PolicyEngineI::ConnectedAfter, Policy::NoneOption)
{
	QStringList localItems = items;	// 复制临时变量

	setOptionStringList(localItems);

	QString name, uri, platform = QLatin1String(ANY_PLATFORM), program;

	if (localItems.size() < 2)
		this->valid = false;
	else {
		name = localItems.at(0);
		uri = localItems.at(1);
	}
	if (localItems.size() > 2)
		platform = localItems.at(2);
	if (localItems.size() > 3)
		program = localItems.at(3);

	resource = AccessibleResource(name, uri, platform, program);
}

const QString ResourcePolicy::toExternalForm() const
{
	QString externalForm;
	externalForm.append(ResourcePolicy::type_name()).append(QLatin1Char(' '));

	const QStringList options = getOptionStringList();
	if (!options.isEmpty())
		externalForm.append(options.join(QLatin1Char(' '))).append(QLatin1Char(' '));

	externalForm.append(this->resource.toExternalForm());
	
	return externalForm;
}

ApplyResult ResourcePolicy::apply(const Context& ctx)
{
	Q_UNUSED(ctx)

	ApplyResult result(ApplyResult::Success);
	result.setAttribute(ApplyResult::TYPE_NAME, ResourcePolicy::type_name());
	result.setAttribute(ApplyResult::ACCESSIBLE_RESOURCE, QVariant::fromValue(resource));
	return result;	
}
