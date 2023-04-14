#ifndef __PROGRESS_DIALOG_H__
#define __PROGRESS_DIALOG_H__

#include <QDialog>

namespace Ui{
	class ProgressDialog;
}

class ProgressDialog : public QDialog
{
	Q_OBJECT
public:
	ProgressDialog(QWidget *parent, const QString& windowTitle, const QString& labelText);
	~ProgressDialog();

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private:
	Ui::ProgressDialog *m_ui;

};

#endif
