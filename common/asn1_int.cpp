#include "asn1_int.h"

#include <openssl/err.h>
#include <openssl/bn.h>

ASN1_INTEGER* asn1_int::dup(const ASN1_INTEGER *a) const
{
	// this wrapper casts the const to work around the nonconst declared ASN1_STRING_dup (actually it is const
	return ASN1_INTEGER_dup((ASN1_INTEGER *) a);
}

asn1_int::asn1_int()
{
	in = ASN1_INTEGER_new();
	ASN1_INTEGER_set(in, 0);
}

asn1_int::asn1_int(const ASN1_INTEGER *i)
{
	in = dup(i);
	if (!in)
		in = ASN1_INTEGER_new();
}

asn1_int::asn1_int(const asn1_int &a)
{
	in = dup(a.in);
	if (!in)
		in = ASN1_INTEGER_new();
}


asn1_int::asn1_int(long l)
{
	in = ASN1_INTEGER_new();
	set(l);
}

asn1_int::~asn1_int()
{
	ASN1_INTEGER_free(in);
}

asn1_int& asn1_int::set(const ASN1_INTEGER *i)
{
	ASN1_INTEGER_free(in);
	in = dup(i);
	return *this;
}

asn1_int& asn1_int::set(long l)
{
	ASN1_INTEGER_set(in, l);
	return *this;
}

QString asn1_int::toHex() const
{
	QString r;
	if (in->length == 0) {
		return r;
	}
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	char *res = BN_bn2hex(bn);
	r = QLatin1String(res);
	OPENSSL_free(res);
	BN_free(bn);
	return r;
}

QString asn1_int::toDec() const
{
	QString r;
	if (in->length == 0) {
		return r;
	}
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	char *res = BN_bn2dec(bn);
	r = QLatin1String(res);
	BN_free(bn);
	OPENSSL_free(res);
	return r;
}

asn1_int& asn1_int::setHex(const QString &s)
{
	BIGNUM *bn=0;
	if (s.isEmpty()) {
		return *this;
	}
	if (!BN_hex2bn(&bn, s.toLatin1()))
		ERR_clear_error();
	BN_to_ASN1_INTEGER(bn, in);
	BN_free(bn);
	return *this;
}

asn1_int& asn1_int::setDec(const QString &s)
{
	BIGNUM *bn=0;
	if (!BN_dec2bn(&bn, s.toLatin1()))
		ERR_clear_error();
	BN_to_ASN1_INTEGER(bn, in);
	BN_free(bn);
	return *this;
}

asn1_int& asn1_int::setRaw(const unsigned char *data, unsigned len)
{
	BIGNUM *bn = BN_bin2bn(data, len, NULL);
	if (!bn)
		ERR_clear_error();
	BN_to_ASN1_INTEGER(bn, in);
	BN_free(bn);
	return *this;
}

ASN1_INTEGER* asn1_int::get() const
{
	return dup(in);
}

long asn1_int::getLong() const
{
	return ASN1_INTEGER_get(in);
}

asn1_int& asn1_int::operator ++ (void)
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	BN_add(bn, bn, BN_value_one());
	BN_to_ASN1_INTEGER(bn, in);
	BN_free(bn);
	return *this;
}

asn1_int asn1_int::operator ++ (int)
{
	asn1_int tmp = *this;
	operator ++ ();
	return tmp;
}

asn1_int& asn1_int::operator = (const asn1_int &a)
{
	set(a.in);
	return *this;
}

asn1_int& asn1_int::operator = (long i)
{
	ASN1_INTEGER_set(in, i);
	return *this;
}

bool asn1_int::operator > (const asn1_int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) > 0);
}

bool asn1_int::operator < (const asn1_int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) < 0);
}

bool asn1_int::operator == (const asn1_int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) == 0);
}

bool asn1_int::operator != (const asn1_int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) != 0);
}

unsigned char* asn1_int::i2d(unsigned char *p)
{
	unsigned char *mp = p;
	i2d_ASN1_INTEGER(in, &mp);
	return mp;
}

int asn1_int::derSize() const
{
	return i2d_ASN1_INTEGER(in, NULL);
}

