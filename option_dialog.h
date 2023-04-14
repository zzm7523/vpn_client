#ifndef __OPTION_DIALOG_H__
#define __OPTION_DIALOG_H__

#include "config/config.h"

#include <QDialog>

namespace Ui {
	class OptionDialog;
}

class OptionDialog : public QDialog
{
	Q_OBJECT
public:
	OptionDialog(QWidget * parent, const QString& windowTitle);
	~OptionDialog();

	void loadOption();
	void saveOption();

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private:
	Ui::OptionDialog *m_ui;

};

#endif
