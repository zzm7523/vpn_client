#include <QApplication>
#include <QObject>
#include <QByteArray>

#ifdef _WIN32
#include <winsock2.h>
#include <shlobj.h>
#else
#include <netinet/in.h>
#endif

#include <openssl/asn1.h>
#include <openssl/err.h>

#include "x509_name.h"

const char* OBJ_obj2sn(ASN1_OBJECT *a)
{
	OBJ_obj2nid(a);
	ERR_clear_error();
	return OBJ_nid2sn(OBJ_obj2nid(a));
}

QString asn1ToQString(const ASN1_STRING *str, bool quote)
{
	QString qs;
	unsigned short *bmp;
	int i;

	if (!str)
		return qs;

	switch (str->type) {
	case V_ASN1_BMPSTRING:
		bmp = (unsigned short*) str->data;
		for (i = 0; i < str->length/2; i++) {
			unsigned short s = ntohs(bmp[i]);
			qs += QString::fromUtf16(&s, 1);
		}
		break;
	case V_ASN1_UTF8STRING:
		qs = QString::fromUtf8((const char*) str->data, str->length);
		break;
	case V_ASN1_T61STRING:
		qs = QString::fromLocal8Bit((const char*) str->data, str->length);
		break;
	default:
		qs = QString::fromLatin1((const char*) str->data, str->length);
	}
#if 0
	printf("Convert %s (%d %d) string to '%s' len %d:", ASN1_tag2str(str->type), str->type, V_ASN1_UTF8STRING, CCHAR(qs), str->length);
	for (int i = 0; i < str->length; i++)
		printf(" %02x", str->data[i]);
	printf("\n");
#endif
	if (quote)
		qs.replace(QLatin1Char('\n'), QLatin1String("\\n\\"));
	return qs;
}

QString OBJ_obj2QString(ASN1_OBJECT *a, int no_name)
{
	char buf[512];
	int len;

	len = OBJ_obj2txt(buf, 256, a, no_name);
	ERR_clear_error();
	return QString::fromLatin1(buf, len);
}

QByteArray i2d_bytearray(int(*i2d)(const void *, unsigned char **), const void *data)
{
	QByteArray ba;

	ba.resize(i2d(data, NULL));
	unsigned char *p = (unsigned char*) ba.data();
	i2d(data, &p);
	ERR_clear_error();
	return ba;
}

void* d2i_bytearray(void *(*d2i)(void *, unsigned char **, long), QByteArray &ba)
{
	unsigned char *p, *p1;
	void *ret;
	p = p1 = (unsigned char*) ba.constData();
	ret = d2i(NULL, &p1, ba.count());
	ba = ba.mid(p1-p);
	ERR_clear_error();
	return ret;
}

/* returns an encoded ASN1 string from QString for a special nid*/
ASN1_STRING* QStringToAsn1(const QString s, int nid)
{
	QByteArray ba = s.toUtf8();
	const unsigned char *utf8 = (const unsigned char*) ba.constData();
	unsigned long global_mask = ASN1_STRING_get_default_mask();
	unsigned long mask = DIRSTRING_TYPE & global_mask;
	ASN1_STRING *out = NULL;
	ASN1_STRING_TABLE *tbl;

	tbl = ASN1_STRING_TABLE_get(nid);
	if (tbl) {
		mask = tbl->mask;
		if (!(tbl->flags & STABLE_NO_MASK))
			mask &= global_mask;
	}
	ASN1_mbstring_copy(&out, utf8, -1, MBSTRING_UTF8, mask);
	ERR_clear_error();
	return out;
}

x509_name::x509_name()
{
	xn = X509_NAME_new();
}

x509_name::x509_name(const X509_NAME *n)
{
	xn = X509_NAME_dup((X509_NAME *)n);
}

x509_name::x509_name(STACK_OF(X509_NAME_ENTRY) *entries)
{
	xn = X509_NAME_new();
	if (xn && entries) {
		int count = sk_X509_NAME_ENTRY_num(entries);
		for (int i = 0; i < count; i++) {
			X509_NAME_ENTRY* entry = sk_X509_NAME_ENTRY_value(entries, i);
			X509_NAME_add_entry(xn, entry, -1, 0);
		}
	}
}

x509_name::x509_name(const x509_name &n)
{
	xn = NULL;
	set(n.xn);
}

x509_name::~x509_name()
{
	X509_NAME_free(xn);
}

x509_name& x509_name::set(const X509_NAME *n)
{
	if (xn != NULL)
		X509_NAME_free(xn);
	xn = X509_NAME_dup((X509_NAME *)n);
	return *this;
}

QString x509_name::oneLine(unsigned long flags) const
{
	QString ret;
	long l;
	const char *p;
	BIO *mem = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(mem, xn, 0, flags);
	l = BIO_get_mem_data(mem, &p);
	ret = ret.fromUtf8(p,l);
	BIO_free(mem);
	return ret;
}

QString x509_name::getEntryByNid(int nid) const
{
	int i = X509_NAME_get_index_by_NID(xn, nid, -1);
	if (i < 0)
        return QString();
	return getEntry(i);
}

QString x509_name::getMostPopular() const
{
	static const int nids[] = { NID_commonName, NID_pkcs9_emailAddress, NID_organizationalUnitName, NID_organizationName };
	int pos = -1;

	for (unsigned i = 0; i < ARRAY_SIZE(nids) && pos < 0; i++) {
		pos = X509_NAME_get_index_by_NID(xn, nids[i], -1);
	}
	if (pos < 0)
		pos = 0;
	return getEntry(pos);
}

QString x509_name::getEntry(int i) const
{
	QString ret;
	ASN1_STRING *d;

	if ( i<0 || i>entryCount() )
		return ret;

	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn,i));

	return asn1ToQString(d);
}

QString x509_name::getEntryTag(int i) const
{
	QString s = QLatin1String("Invalid");
	ASN1_STRING *d;

	if (i<0 || i>=entryCount())
		i = entryCount() - 1;
	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn,i));

	if (!d)
		return s;

	s = QLatin1String(ASN1_tag2str(d->type));
	return s;
}

QString x509_name::popEntryByNid(int nid)
{
	int i = X509_NAME_get_index_by_NID(xn, nid, -1);
	if (i < 0)
        return QString();
	QString n = getEntry(i);
	X509_NAME_delete_entry(xn, i);
	return n;
}

QString x509_name::hash() const
{
	return QString(QLatin1String("%1")).arg(X509_NAME_hash(xn), 8, 16, QLatin1Char('0'));
}

QStringList x509_name::entryList(int i) const
{
	QStringList sl;
	int n = nid(i);
	if (n == NID_undef) {
		QString oid = getOid(i);
		sl << oid << oid;
	} else {
		sl << QLatin1String(OBJ_nid2sn(n)) << QLatin1String(OBJ_nid2ln(n));
	}
	sl << getEntry(i) << getEntryTag(i);
	return sl;
}

int x509_name::nid(int i) const
{
	X509_NAME_ENTRY *ne;

	ne = X509_NAME_get_entry(xn, i);
	if (ne == NULL)
		return NID_undef;
	return OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne));
}

QString x509_name::getOid(int i) const
{
	X509_NAME_ENTRY *ne;

	ne = X509_NAME_get_entry(xn, i);
	if (ne == NULL)
		return QString();
	return OBJ_obj2QString(X509_NAME_ENTRY_get_object(ne), 1);
}

void x509_name::d2i(QByteArray &ba)
{
	X509_NAME *n = (X509_NAME*) d2i_bytearray(D2I_VOID(d2i_X509_NAME), ba);
	if (n) {
		X509_NAME_free(xn);
		xn = n;
	}
}

QByteArray x509_name::i2d()
{
	 return i2d_bytearray(I2D_VOID(i2d_X509_NAME), xn);
}

bool x509_name::operator == (const x509_name &x) const
{
	return (X509_NAME_cmp(xn, x.xn) == 0);
}

x509_name& x509_name::operator = (const x509_name &x)
{
	set(x.xn);
	return *this;
}

int x509_name::entryCount() const
{
	return  X509_NAME_entry_count(xn);
}

int x509_name::getNidByName(const QString &nid_name)
{
	return OBJ_txt2nid(nid_name.toLatin1());
}

QString x509_name::checkLength() const
{
	ASN1_STRING_TABLE *tab;
	int i, max = entryCount();
	QString warn;

	for (i = 0; i < max; i++) {
		int n = nid(i);
		QString entry;

		tab = ASN1_STRING_TABLE_get(n);
		if (!tab)
			continue;
		entry = getEntry(i);
		if (tab->minsize > entry.size()) {
			warn += QApplication::translate("X509Certificate", "%1 is shorter than %2 bytes: '%3'")
				.arg(QLatin1String(OBJ_nid2ln(n))).arg(tab->maxsize).arg(entry);
			warn += QLatin1String("\n");
		}
		if ((tab->maxsize != -1) && (tab->maxsize < entry.size())) {
			warn += QApplication::translate("X509Certificate", "%1 is longer than %2 bytes: '%3'")
				.arg(QLatin1String(OBJ_nid2ln(n))).arg(tab->maxsize).arg(entry);
			warn += QLatin1String("\n");
		}
	}
	return warn;
}

QString x509_name::taggedValues() const
{
	int i, max = entryCount();
	QString ret;

	for (i = 0; i < max; i++) {
		int n = nid(i);
		ret += QString(QLatin1String("%1.%2=%3\n")).arg(i).arg(QLatin1String(OBJ_nid2sn(n))).arg(getEntry(i));
	}
	return ret;
}

void x509_name::addEntryByNid(int nid, const QString entry)
{
	if (entry.isEmpty())
		return;
	ASN1_STRING *a = QStringToAsn1(entry, nid);
	X509_NAME_add_entry_by_NID(xn, nid, a->type, a->data, a->length, -1, 0);
	ASN1_STRING_free(a);
	ERR_clear_error();
}

X509_NAME* x509_name::get() const
{
	return X509_NAME_dup(xn);
}
