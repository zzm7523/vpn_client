#ifndef __MESSAGE_BOX_UTIL_H__
#define __MESSAGE_BOX_UTIL_H__

#include "../config/config.h"

#include <QString>
#include <QWidget>

class MessageBoxUtil
{
public:
	static bool confirm(QWidget *parent, const QString &title, const QString &message);
	static void error(QWidget *parent, const QString &title, const QString &message);
	static void warning(QWidget *parent, const QString &title, const QString &message);
	static void information(QWidget *parent, const QString &title, const QString &message);
	static void tooltip(QWidget *parent, const QString &message, int duration);

private:
	MessageBoxUtil();

};

#endif
