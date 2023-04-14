#ifndef __X509_NAME_H__
#define __X509_NAME_H__

#include "../config/config.h"

#include <QString>
#include <QStringList>

#include <openssl/x509.h>

#define I2D_VOID(a) ((int (*)(const void *, unsigned char **))(a))
#define D2I_VOID(a) ((void *(*)(void *, unsigned char **, long))(a))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

const char* OBJ_obj2sn(ASN1_OBJECT *a);
QString OBJ_obj2QString(ASN1_OBJECT *a, int no_name = 0);
QString asn1ToQString(const ASN1_STRING *str, bool quote = false);

class x509_name
{
public:
	x509_name();
	explicit x509_name(const X509_NAME *n);
	explicit x509_name(const x509_name &n);
	x509_name(STACK_OF(X509_NAME_ENTRY) *entries);
	~x509_name();

	x509_name& set(const X509_NAME *n);
	QString oneLine(unsigned long flags = XN_FLAG_ONELINE) const;
	int nid(int i) const;
	QString getOid(int i) const;
	QByteArray i2d();
	void d2i(QByteArray &ba);
	QStringList entryList(int i) const;
	QString getEntryByNid(int nid ) const;
	QString getEntry(int i) const;
	QString getEntryTag(int i) const;
	int entryCount() const;
	x509_name& operator = (const x509_name &x);
	bool operator == (const x509_name &x) const;
	static int getNidByName(const QString &nid_name);
	void addEntryByNid(int nid, const QString entry);
	QString checkLength() const;
	QString popEntryByNid(int nid);
	X509_NAME* get() const;
	QString getMostPopular() const;
	QString taggedValues() const;
	QString hash() const;

private:
	X509_NAME *xn;

};

#endif
