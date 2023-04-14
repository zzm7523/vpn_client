#ifndef __APPINFO_H__
#define __APPINFO_H__

#include "config/config.h"

#include <QDialog>
#include <QString>

namespace Ui {
	class AppInfo;
}

class AppInfo : public QDialog
{
	Q_OBJECT
public:
	AppInfo(QWidget *parent, const QString& windowTitle);
	~AppInfo();

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private:
	Ui::AppInfo *m_ui;

};

#endif
