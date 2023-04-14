#ifndef __DIST_NAME_H__
#define __DIST_NAME_H__

#include "../config/config.h"

#include <QWidget>
#include <QGridLayout>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>

class x509_name;

class DistName : public QWidget
{
	Q_OBJECT
public:
	explicit DistName(QWidget *parent);
	void setX509name(const x509_name& xn);

protected:
	QString translate(const QString& name);

	QGridLayout *nameLayout;
	QLineEdit *rfc2253;
	QLineEdit *nameHash;

};

#endif
