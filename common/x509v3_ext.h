#ifndef __X509V3_EXT_H__
#define __X509V3_EXT_H__

#include "../config/config.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <QList>
#include <QString>
#include <QStringList>

class x509v3_ext
{
public:
	x509v3_ext();
	explicit x509v3_ext(const X509_EXTENSION *n);
	explicit x509v3_ext(const x509v3_ext &n);
	~x509v3_ext();

	x509v3_ext& set(const X509_EXTENSION *n);
	x509v3_ext& create(int nid, const QString &et, X509V3_CTX *ctx = NULL);
	x509v3_ext& operator = (const x509v3_ext &x);
	QString getObject() const;
	int getCritical() const;
	QString getValue(bool html=false) const;
	QString getHtml() const;
	X509_EXTENSION* get() const;
	bool isValid() const;
	int nid() const;
	void* d2i() const;
	bool genConf(QString *single, QString *adv) const;
	bool parse_generic(QString *single, QString *adv) const;

protected:
	QString parse_critical() const;
	bool parse_certpol(QString *single, QString *adv) const;
	bool parse_ainfo(QString *single, QString *adv) const;
	bool parse_Crldp(QString *single, QString *adv) const;
	bool parse_eku(QString *single, QString *adv) const;
	bool parse_generalName(QString *single, QString *adv) const;
	bool parse_ia5(QString *single, QString *adv) const;
	bool parse_bc(QString *single, QString *adv) const;
	bool parse_bitstring(QString *single, QString *adv) const;
	bool parse_sKeyId(QString *single, QString *adv) const;
	bool parse_aKeyId(QString *single, QString *adv) const;

private:
	X509_EXTENSION *ext;

};

class x509v3_ext_list : public QList<x509v3_ext>
{
public:
	void setStack(const STACK_OF(X509_EXTENSION) *st, int start = 0);
	STACK_OF(X509_EXTENSION) *getStack();
	QString getHtml(const QString &sep);
	bool delByNid(int nid);
	int delInvalid();
	int idxByNid(int nid);
	bool genConf(int nid, QString *single, QString *adv = NULL);
	void genGenericConf(QString *adv);

};

#endif
