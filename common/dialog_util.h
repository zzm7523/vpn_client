#ifndef __DIALOG_UTIL_H__
#define __DIALOG_UTIL_H__

#include <QWidget>
#include <QAction>
#include <QAbstractButton>

class DialogUtil
{
public:
	static void centerDialog(QWidget *aWidget, QWidget *aRelative);

private:
	DialogUtil();

};

class ActionGuard
{
public:
	ActionGuard(QAction *_action, bool _enabled)
		: action(_action), enabled(_enabled) {
		Q_ASSERT(action);
		action->setEnabled(enabled);
	}

	~ActionGuard() {
		action->setEnabled(!enabled);
	}

private:
	QAction *action;
	bool enabled;

};

class ButtonGuard
{
public:
	ButtonGuard(QAbstractButton *_button, bool _enabled)
		: button(_button), enabled(_enabled) {
		Q_ASSERT(button);
		button->setEnabled(enabled);
	}

	~ButtonGuard() {
		button->setEnabled(!enabled);
	}

private:
	QAbstractButton *button;
	bool enabled;

};

#endif
