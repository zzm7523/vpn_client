#include <QUrl>

#include "password_policy.h"

const QString& PasswordPolicy::type_name()
{
	static const QString type_name(QLatin1String("password"));
	return type_name;
}

PasswordPolicy::PasswordPolicy(const QStringList& items)
	: Policy(PolicyEngineI::ConnectedAfter, 0), weakPassword(false)
{
	QStringList localItems = items;	// 复制临时变量

	setOptionStringList(localItems);
	
	if (localItems.size() > 0) {
		this->serviceUrl = localItems.at(0);
		this->valid = QUrl(this->serviceUrl).isValid();
	} else {
		this->valid = false;
	}
	
	if (localItems.size() > 1) {
		if (ApplyResult::WEAK_PASSWORD.compare(localItems.at(1), Qt::CaseSensitive))
			this->weakPassword = true;
	}	
}

const QString PasswordPolicy::toExternalForm() const
{
	QString externalForm;
	externalForm.append(PasswordPolicy::type_name()).append(QLatin1Char(' '));

	const QStringList options = getOptionStringList();
	if (!options.isEmpty())
		externalForm.append(options.join(QLatin1Char(' '))).append(QLatin1Char(' '));

	externalForm.append(this->serviceUrl);
	if (this->weakPassword)
		externalForm.append(QLatin1Char(' ')).append(ApplyResult::WEAK_PASSWORD);
	
	return externalForm;
}

ApplyResult PasswordPolicy::apply(const Context& ctx)
{
	Q_UNUSED(ctx)

	ApplyResult result(ApplyResult::Success);
	result.setAttribute(ApplyResult::TYPE_NAME, PasswordPolicy::type_name());
	result.setAttribute(ApplyResult::SERVICE_URL, QVariant::fromValue(serviceUrl));
	result.setAttribute(ApplyResult::WEAK_PASSWORD, QVariant::fromValue(weakPassword));
	return result;
}
