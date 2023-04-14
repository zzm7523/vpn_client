#include "policy.h"

QStringList Policy::getOptionStringList() const
{
	QStringList optionList;

	if (this->options & Policy::AsInvoker)
		optionList.append(QLatin1String("--asInvoker"));
	if (this->options & Policy::RequireAdministrator)
		optionList.append(QLatin1String("--requireAdministrator"));

	if (this->options & Policy::Interactive)
		optionList.append(QLatin1String("--interactive"));
	if (this->options & Policy::NoInteractive)
		optionList.append(QLatin1String("--noInteractive"));

	return optionList;
}

void Policy::setOptionStringList(QStringList& items)
{
	const Qt::CaseSensitivity cs = Qt::CaseSensitive;
	QStringList::iterator it = items.begin();

	while (it != items.end()) {
		if ((*it).startsWith(QLatin1String("--"))) {
			if ((*it).compare(QLatin1String("--asInvoker"), cs) == 0) {
				this->options &= ~Policy::RequireAdministrator;
				this->options |= Policy::AsInvoker;
			} else if ((*it).compare(QLatin1String("--requireAdministrator"), cs) == 0) {
				this->options &= ~Policy::AsInvoker;
				this->options |= Policy::RequireAdministrator;

			} else if ((*it).compare(QLatin1String("--interactive"), cs) == 0) {
				this->options &= ~Policy::NoInteractive;
				this->options |= Policy::Interactive;
			} else if ((*it).compare(QLatin1String("--noInteractive"), cs) == 0) {
				this->options &= ~Policy::Interactive;
				this->options |= Policy::NoInteractive;

			} else {
				;	// Ignore
			}

			it = items.erase(it); // 删除以--开始的项
		} else
			++it;
	}
}
