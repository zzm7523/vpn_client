#include "distname.h"
#include "common/x509_name.h"

DistName::DistName(QWidget *parent)
	: QWidget(parent)
{
	nameLayout = new QGridLayout();
	nameLayout->setAlignment(Qt::AlignTop);
	nameLayout->setSpacing(5);
	nameLayout->setMargin(6);

	QGridLayout *g = new QGridLayout();
	g->setAlignment(Qt::AlignTop);
	g->setSpacing(5);
	g->setMargin(6);

	QVBoxLayout *v = new QVBoxLayout(this);
	v->setSpacing(5);
	v->setMargin(6);
	v->addLayout(nameLayout);
	v->addStretch();
	v->addLayout(g);

	rfc2253 = new QLineEdit(this);
	rfc2253->setReadOnly(true);
	rfc2253->setMinimumSize(QSize(260, 0));
	g->addWidget(new QLabel(tr("RFC 2253"), this), 0, 0);
	g->addWidget(rfc2253, 0, 1);

	nameHash = new QLineEdit(this);
	nameHash->setReadOnly(true);
	g->addWidget(new QLabel(tr("Hash"), this), 1, 0);
	g->addWidget(nameHash, 1, 1);
}

void DistName::setX509name(const x509_name& xn)
{
	QLabel *l1;
	QLineEdit *e1;
	QStringList sl;

	for (int i = 0; i < xn.entryCount(); ++i) {
		l1 = new QLabel(this);
		e1 = new QLineEdit(this);

		sl = xn.entryList(i);
		l1->setTextFormat(Qt::PlainText);
		l1->setText(translate(sl[1]));
		if (l1->text().isEmpty())
			l1->setText(translate(sl[0]));

		e1->setReadOnly(true);
		e1->setMinimumWidth(260);
		e1->setText(sl[2]);

		nameLayout->addWidget( l1, i, 0 );
		nameLayout->addWidget( e1, i, 1 );
	}

	rfc2253->setText(xn.oneLine(XN_FLAG_RFC2253));
	rfc2253->setCursorPosition(0);
	nameHash->setText(xn.hash());

	updateGeometry();
}

QString DistName::translate(const QString& name)
{
	if (name == QLatin1String("countryName"))
		return tr("countryName");
	else if (name == QLatin1String("stateOrProvinceName"))
		return tr("stateOrProvinceName");
	else if (name == QLatin1String("localityName"))
		return tr("localityName");
	else if (name == QLatin1String("organizationName"))
		return tr("organizationName");
	else if (name == QLatin1String("organizationalUnitName"))
		return tr("organizationalUnitName");
	else if (name == QLatin1String("commonName"))
		return tr("commonName");
	else if (name == QLatin1String("emailAddress"))
		return tr("emailAddress");
	else
		return name;
}
