#include <QApplication>

#include "../common/message_box_util.h"
#include "terminal_bind_policy.h"

const QString& TerminalBindPolicy::type_name()
{
	static const QString type_name(QLatin1String("terminal-bind"));
	return type_name;
}

TerminalBindPolicy::TerminalBindPolicy()
	: Policy(PolicyEngineI::ConnectedBefore, Policy::AsInvoker | Policy::Interactive)
{
}

const QString TerminalBindPolicy::toExternalForm() const
{
	QString externalForm;
	externalForm.append(TerminalBindPolicy::type_name()).append(QLatin1Char(' '));
	
	const QStringList options = getOptionStringList();
	if (!options.isEmpty())
		externalForm.append(options.join(QLatin1Char(' '))).append(QLatin1Char(' '));

	return externalForm;
}

ApplyResult TerminalBindPolicy::apply(const Context& ctx)
{
	Q_UNUSED(ctx)

	QWidget *parent = QApplication::activeWindow();
	QString message = QApplication::translate("Policy", "Terminal bind ok?");

	if (MessageBoxUtil::confirm(parent, QApplication::translate("Policy", "Terminal bind"), message)) {
		return ApplyResult(ApplyResult::Success);
	} else { 
		return ApplyResult(ApplyResult::Fail, QApplication::translate("Policy", "User reject bind!"));
	}
}
