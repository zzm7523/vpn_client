#include <QApplication>
#include <QDesktopWidget>

#include "dialog_util.h"

void DialogUtil::centerDialog(QWidget *aWidget, QWidget *aRelative)
{
	int left = -1, top = -1;

	if (aRelative && aRelative->isVisible()) {
		left = aRelative->geometry().x() + (aRelative->geometry().width() - aWidget->width()) / 2;
		top  = aRelative->geometry().y() + (aRelative->geometry().height() - aWidget->height()) / 2;
	} 
	
	if (left < 0 || top < 0) {
		left = qApp->desktop()->width();
		if (left > 2000 && qApp->desktop()->isVirtualDesktop())
			left /= 4;
		else
			left = (left - aWidget->width()) / 2;
		top = qApp->desktop()->height();
		if (top > 2000 && qApp->desktop()->isVirtualDesktop())
			top /= 4;
		else
			top = (top - aWidget->height()) / 2;
	}

	aWidget->setGeometry(left, top, aWidget->width(), aWidget->height());
	aWidget->setWindowState(Qt::WindowActive);
}