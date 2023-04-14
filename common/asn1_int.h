#ifndef __ASN1_INTEGER_H__
#define __ASN1_INTEGER_H__

#include "../config/config.h"

#include <QString>

#include <openssl/asn1.h>

class asn1_int
{
public:
	asn1_int();
	explicit asn1_int(const ASN1_INTEGER *i);
	asn1_int(const asn1_int &a);
	explicit asn1_int(long l);
	~asn1_int();

	asn1_int& set(const ASN1_INTEGER *i);
	asn1_int& set(long l);
	QString toHex() const;
	QString toDec() const;
	asn1_int& setHex(const QString &s);
	asn1_int& setDec(const QString &s);
	asn1_int& setRaw(const unsigned char *data, unsigned len);
	long getLong() const;
	ASN1_INTEGER* get() const;
	unsigned char* i2d(unsigned char *p);
	int derSize() const;

	asn1_int& operator ++ (void);
	asn1_int operator ++ (int);
	asn1_int& operator = (const asn1_int &a);
	asn1_int& operator = (long i);
	bool operator > (const asn1_int &a) const;
	bool operator < (const asn1_int &a) const;
	bool operator == (const asn1_int &a) const;
	bool operator != (const asn1_int &a) const;

private:
	ASN1_INTEGER *in;
	ASN1_INTEGER *dup(const ASN1_INTEGER *a) const;

};

#endif
