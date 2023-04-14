#include <QRegularExpression>

#include <openssl/stack.h>
#include <openssl/err.h>

#include "x509v3_ext.h"
#include "x509_name.h"
#include "asn1_int.h"

#define CCHAR(x) qPrintable(x)

x509v3_ext::x509v3_ext()
{
	ext = X509_EXTENSION_new();
}

x509v3_ext::x509v3_ext(const X509_EXTENSION *n)
{
	ext = X509_EXTENSION_dup((X509_EXTENSION*) n);
}

x509v3_ext::x509v3_ext(const x509v3_ext &n)
{
	ext = NULL;
	set(n.ext);
}

x509v3_ext::~x509v3_ext()
{
	X509_EXTENSION_free(ext);
}

x509v3_ext& x509v3_ext::set(const X509_EXTENSION *n)
{
	if (ext != NULL)
		X509_EXTENSION_free(ext);
	ext = X509_EXTENSION_dup((X509_EXTENSION *)n);
	return *this;
}

x509v3_ext& x509v3_ext::create(int nid, const QString &et, X509V3_CTX *ctx)
{
	if (ext) {
		X509_EXTENSION_free(ext);
		ext = NULL;
	}
	if (!et.isEmpty()) {
		ext = X509V3_EXT_conf_nid(NULL, ctx, nid, (char*)CCHAR(et));
	}
	if (!ext)
		ext = X509_EXTENSION_new();
	else {
		if (ctx && ctx->subject_cert) {
			X509_add_ext(ctx->subject_cert, ext, -1);
		}
	}
	return *this;
}

int x509v3_ext::nid() const
{
	ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
	return OBJ_obj2nid(obj);
}

void* x509v3_ext::d2i() const
{
	return X509V3_EXT_d2i(ext);
}

x509v3_ext& x509v3_ext::operator = (const x509v3_ext &x)
{
	set(x.ext);
	return *this;
}

QString x509v3_ext::getObject() const
{
	return OBJ_obj2QString(X509_EXTENSION_get_object(ext));
}

int x509v3_ext::getCritical() const
{
	return X509_EXTENSION_get_critical(ext);
}

QString x509v3_ext::getValue(bool html) const
{
	QString text = QLatin1String("");
	char *p = NULL;
	BIO *bio = BIO_new(BIO_s_mem());

	int ret = X509V3_EXT_print(bio, ext, X509V3_EXT_DEFAULT, 0);
	if (!ret)
		ret = ASN1_STRING_print(bio, (ASN1_STRING *) X509_EXTENSION_get_data(ext));
	if (ret) {
		long len = BIO_get_mem_data(bio, &p);
		text = QString::fromLocal8Bit(p, len);
	}
	BIO_free(bio);
	if (html) {
		text.replace(QRegularExpression(QLatin1String("&")), QLatin1String("&amp;"));
		text.replace(QRegularExpression(QLatin1String("<")), QLatin1String("&lt;"));
		text.replace(QRegularExpression(QLatin1String(">")), QLatin1String("&gt;"));
		text.replace(QRegularExpression(QLatin1String("\n")), QLatin1String("<br>\n"));
	}
	return text.trimmed();
}

static QString vlist2Section(QStringList vlist, QString tag, QString *sect)
{
	/* Check for commas in the text */
	if (!vlist.join(QLatin1String("")).contains(QLatin1String(",")))
		return vlist.join(QLatin1String(", "));

	*sect += QString(QLatin1String("\n[%1_sect]\n")).arg(tag);

	for (int i = 0; i < vlist.count(); i++) {
		QString s = vlist[i];
		int eq = s.indexOf(QLatin1String(":"));
		*sect += QString(QLatin1String("%1.%2=%3\n")).arg(s.left(eq)).arg(i).arg(s.mid(eq+1));
	}
	return QString(QLatin1String("@%1_sect\n")).arg(tag);
}

bool x509v3_ext::parse_ia5(QString *single, QString *adv) const
{
	ASN1_STRING *str = (ASN1_STRING *)d2i();
	QString ret;

	if (!str)
		return false;
	ret = QString(asn1ToQString(str));
	if (single)
		*single = ret;
	else if (adv)
		*adv = QString(QLatin1String("%1=%2\n")).arg(QLatin1String(OBJ_nid2sn(nid()))).arg(ret) + *adv;

	ASN1_STRING_free(str);
	return true;
}


static const char *asn1Type2Name(int type)
{
#define ASN1_GEN_STR(x,y) { x,y }
	struct {
		const char *strnam;
		int tag;
	} tags[] = {
		ASN1_GEN_STR("BOOL", V_ASN1_BOOLEAN),
		ASN1_GEN_STR("NULL", V_ASN1_NULL),
		ASN1_GEN_STR("INT", V_ASN1_INTEGER),
		ASN1_GEN_STR("ENUM", V_ASN1_ENUMERATED),
		ASN1_GEN_STR("OID", V_ASN1_OBJECT),
		ASN1_GEN_STR("UTC", V_ASN1_UTCTIME),
		ASN1_GEN_STR("GENTIME", V_ASN1_GENERALIZEDTIME),
		ASN1_GEN_STR("OCT", V_ASN1_OCTET_STRING),
		ASN1_GEN_STR("BITSTR", V_ASN1_BIT_STRING),
		ASN1_GEN_STR("UNIV", V_ASN1_UNIVERSALSTRING),
		ASN1_GEN_STR("IA5", V_ASN1_IA5STRING),
		ASN1_GEN_STR("UTF8", V_ASN1_UTF8STRING),
		ASN1_GEN_STR("BMP", V_ASN1_BMPSTRING),
		ASN1_GEN_STR("VISIBLE", V_ASN1_VISIBLESTRING),
		ASN1_GEN_STR("PRINTABLE", V_ASN1_PRINTABLESTRING),
		ASN1_GEN_STR("T61", V_ASN1_T61STRING),
		ASN1_GEN_STR("GENSTR", V_ASN1_GENERALSTRING),
		ASN1_GEN_STR("NUMERIC", V_ASN1_NUMERICSTRING),
	};
	for (unsigned i=0; i< ARRAY_SIZE(tags); i++) {
		if (tags[i].tag == type)
			return tags[i].strnam;
	}
	return NULL;
}

static bool asn1TypePrintable(int type)
{
	switch (type) {
	case V_ASN1_IA5STRING:
	case V_ASN1_UTF8STRING:
	case V_ASN1_BMPSTRING:
	case V_ASN1_VISIBLESTRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_T61STRING:
	case V_ASN1_GENERALSTRING:
		return true;
	}
	return false;
}

static QString ipv6_from_binary(const unsigned char *p)
{
	QString ip;
	int i, skip =0, skiplen = 0, skippos =0;

	/* find largest gap */
	for (i = 0; i < 17; i += 2) {
		if (i==16 || (p[i] | p[i +1])) {
			if (skiplen < skip) {
				skiplen = skip;
				skippos = i - skip;
			}
			skip = 0;
		} else {
			skip += 2;
		}
	}
	for (i = 0, skip = 0; i < 16; i += 2) {
		int x = p[i] << 8 | p[i+1];
		skip += skippos == i;
		switch (!x*4 + skip) {
		case 5: // skip first 0
			skip = 2;
			ip += QLatin1String(":");
		case 6: // skip next 0
			break;
		default: // no reduction
			skip = 0;
			ip += QString(QLatin1String("%1%2")).arg(i? QLatin1String(":") : QLatin1String("")).arg(x,0,16);
		}
	}
	if (skip == 2)
		ip += QLatin1String(":");
	return ip;
}

static bool
genName2conf(GENERAL_NAME *gen, QString tag, QString *single, QString *sect)
{
	unsigned char *p;
	QString ret;

	switch (gen->type) {
	case GEN_EMAIL: ret = QLatin1String("email:%1"); break;
	case GEN_DNS:   ret = QLatin1String("DNS:%1"); break;
	case GEN_URI:   ret = QLatin1String("URI:%1"); break;

	case GEN_DIRNAME: {
		tag += QLatin1String("_dirname");
		x509_name xn(gen->d.dirn);
		*sect += QString(QLatin1String("\n[%1]\n")).arg(tag);
		*sect += xn.taggedValues();
		*single = QString(QLatin1String("dirName:")) + tag;
		return true;
	}
	case GEN_IPADD:
		p = gen->d.ip->data;
		if (gen->d.ip->length == 4) {
			*single = QString(QLatin1String("IP:%1.%2.%3.%4")).arg(p[0]).arg(p[1]).arg(p[2]).arg(p[3]);
			return true;
		} else if (gen->d.ip->length == 16) {
			*single = QLatin1String("IP:") + ipv6_from_binary(gen->d.ip->data);
			return true;
		}
		return false;

	case GEN_RID:
		*single = QString(QLatin1String("RID:%1")).arg(OBJ_obj2QString(gen->d.rid));
		return true;
	case GEN_OTHERNAME: {
		int type = gen->d.otherName->value->type;
		ASN1_STRING *a;
		a = gen->d.otherName->value->value.asn1_string;
		if (asn1TypePrintable(type)) {
			*single = QString(QLatin1String("otherName:%1;%2:%3")).arg(OBJ_obj2QString(gen->d.otherName->type_id))
				.arg(QLatin1String(asn1Type2Name(type))).arg(asn1ToQString(a, true));
		} else {
			*single = QString(QLatin1String("otherName:%1;FORMAT:HEX,%2")).arg(OBJ_obj2QString(gen->d.otherName->type_id))
				.arg(QLatin1String(asn1Type2Name(type)));
			for (int i = 0; i < a->length; i++) {
				*single += QString(QLatin1String(":%1")).arg((int)(a->data[i]), 2, 16, QLatin1Char('0'));
			}
		}
		return true;
	}
	default:
		return false;
	}
	if (!ret.isEmpty())
		*single = ret.arg(asn1ToQString(gen->d.ia5, true));
	return true;
}

static bool genNameStack2conf(STACK_OF(GENERAL_NAME) *gens, QString tag, QString *single, QString *sect)
{
	int i;
	QStringList sl;
	for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		QString one;
		if (!genName2conf(sk_GENERAL_NAME_value(gens, i), QString(QLatin1String("%1_%2")).arg(tag).arg(i), &one, sect))
			return false;
		sl << one;
	}
	*single = vlist2Section(sl, tag, sect);
	return true;
}

QString x509v3_ext::parse_critical() const
{
	return QString(getCritical() ? QLatin1String("critical,") : QLatin1String(""));
}

bool x509v3_ext::parse_generalName(QString *single, QString *adv) const
{
	bool retval = true;
	QString sect, ret;
	QString tag = QLatin1String(OBJ_nid2sn(nid()));
	STACK_OF(GENERAL_NAME) *gens = (STACK_OF(GENERAL_NAME) *)d2i();

	if (!genNameStack2conf(gens, tag, &ret, &sect))
		retval = false;
	else if (sect.isEmpty() && single)
		*single = parse_critical() + ret;
	else if (adv)
		*adv = QString(QLatin1String("%1=%2\n")).arg(tag).arg(parse_critical() +ret) + *adv + sect;

	sk_GENERAL_NAME_free(gens);
	return retval;
}

bool x509v3_ext::parse_eku(QString *single, QString *adv) const
{
	EXTENDED_KEY_USAGE *eku = (EXTENDED_KEY_USAGE *)d2i();
	QStringList sl;
	int i;

	for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++)
		sl << QString(QLatin1String(OBJ_obj2sn(sk_ASN1_OBJECT_value(eku, i))));

	QString r = parse_critical() + sl.join(QLatin1String(", "));
	if (single)
		*single = r;
	else if (adv)
		*adv = QString(QLatin1String("%1=%2\n")).arg(QLatin1String(OBJ_nid2sn(nid()))).arg(r) + *adv;

	EXTENDED_KEY_USAGE_free(eku);
	return true;
}

bool x509v3_ext::parse_ainfo(QString *single, QString *adv) const
{
	bool retval = true;
	QString sect, ret;
	QString tag = QLatin1String(OBJ_nid2sn(nid()));
	QStringList sl;
	int i;

	AUTHORITY_INFO_ACCESS *ainfo = (AUTHORITY_INFO_ACCESS *)d2i();

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ainfo); i++) {
		QString one;
		ACCESS_DESCRIPTION *desc = sk_ACCESS_DESCRIPTION_value(ainfo, i);
		if (!genName2conf(desc->location, QString(QLatin1String("%1_%2")).arg(tag).arg(i), &one, &sect)) {
			retval = false;
			break;
		}
		sl << QString(QLatin1String("%1;%2")).arg(QLatin1String(OBJ_obj2sn(desc->method))).arg(one);
	}
	if (retval) {
		ret = vlist2Section(sl, tag, &sect);
		if (sect.isEmpty() && sk_ACCESS_DESCRIPTION_num(ainfo) == 1 && single)
			*single = parse_critical() + ret;
		else if (adv)
			*adv = QString(QLatin1String("%1=%2\n")).arg(tag).arg(parse_critical() + ret) + *adv + sect;
	}
	AUTHORITY_INFO_ACCESS_free(ainfo);
	return retval;
}

static const BIT_STRING_BITNAME reason_flags[] = {
	{0, "", "unused"},
	{1, "", "keyCompromise"},
	{2, "", "CACompromise"},
	{3, "", "affiliationChanged"},
	{4, "", "superseded"},
	{5, "", "cessationOfOperation"},
	{6, "", "certificateHold"},
	{7, "", "privilegeWithdrawn"},
	{8, "", "AACompromise"},
	{-1, NULL, NULL}
};

static QString parse_bits(const BIT_STRING_BITNAME *flags, ASN1_BIT_STRING *str)
{
	const BIT_STRING_BITNAME *pbn;
	QStringList r;
	for (pbn = flags; pbn->sname; pbn++) {
		if (ASN1_BIT_STRING_get_bit(str, pbn->bitnum))
			r << QString(QLatin1String(pbn->sname));
	}
	return r.join(QLatin1String(", "));
}

bool x509v3_ext::parse_Crldp(QString *single, QString *adv) const
{
	QString othersect;
	QStringList crldps;
	const char *sn = OBJ_nid2sn(nid());

	STACK_OF(DIST_POINT) *crld = (STACK_OF(DIST_POINT)*)d2i();
	if (sk_DIST_POINT_num(crld) == 1 && single) {
		DIST_POINT *point = sk_DIST_POINT_value(crld, 0);
		if (point->distpoint && !point->reasons && !point->CRLissuer && !point->distpoint->type) {
			QString sect, ret;
			if (!genNameStack2conf(point->distpoint->name.fullname, QLatin1String(""), &ret, &sect))
				goto could_not_parse;

			if (sect.isEmpty()) {
				if (single)
					*single = parse_critical() +ret;
				else if (adv)
					*adv = QString(QLatin1String("%1=%2\n")).arg(QLatin1String(sn)).arg(parse_critical() + ret) + *adv;
				return true;
			}
		}
	}
	for(int i = 0; i < sk_DIST_POINT_num(crld); i++) {
		DIST_POINT *point = sk_DIST_POINT_value(crld, i);
		QString tag = QString(QLatin1String("crlDistributionPoint%1_sect")).arg(i);
		QString crldpsect = QString(QLatin1String("\n[%1]\n")).arg(tag);
		if (point->distpoint) {
			if (!point->distpoint->type) {
				QString ret;
				if (!genNameStack2conf(point->distpoint->name.fullname, tag + QLatin1String("_fullname"), &ret, &othersect))
					goto could_not_parse;

				crldpsect += QLatin1String("fullname=") + ret + QLatin1String("\n");
			} else {
				QString mysect = tag + QLatin1String("_relativename");
				x509_name xn(point->distpoint->name.relativename);
				crldpsect += QLatin1String("relativename=") + mysect + QLatin1String("\n");
				othersect += QString(QLatin1String("\n[%1]\n")).arg(mysect) + xn.taggedValues();
			}
		}
		if (point->reasons) {
			crldpsect += QString(QLatin1String("reasons=%1\n")).arg(parse_bits(reason_flags, point->reasons));
		}
		if (point->CRLissuer) {
			QString ret;
			if (genNameStack2conf(point->CRLissuer, tag + QLatin1String("_crlissuer"), &ret, &othersect))
				goto could_not_parse;
			crldpsect += QLatin1String("CRLissuer=") + ret + QLatin1String("\n");
		}
		crldps << tag;
		othersect = crldpsect + othersect;
	}
	sk_DIST_POINT_free(crld);
	if (crldps.size() == 0)
		return true;
	if (adv) {
		*adv = QString(QLatin1String("%1=%2\n")).arg(QLatin1String(sn)).arg(parse_critical() + crldps.join(QLatin1String(", "))) + *adv + othersect;

#if OPENSSL_VERSION_NUMBER < 0x10000000L
		*adv = QString(QLatin1String("\n"
			"# This syntax only works for openssl >= 1.0.0\n"
			"# But this is %1\n"
			"# ")).arg(OPENSSL_VERSION_TEXT) + *adv;
#endif
	}
	return true;

could_not_parse:
	sk_DIST_POINT_free(crld);
	return false;
}

static void gen_cpol_notice(QString tag, USERNOTICE *notice, QString *adv)
{
	*adv += QString(QLatin1String("\n[%1]\n")).arg(tag);
	if (notice->exptext) {
		*adv += QString(QLatin1String("explicitText=%1\n")).arg(asn1ToQString(notice->exptext, true));
	}
	if (notice->noticeref) {
		NOTICEREF *ref = notice->noticeref;
		QStringList sl;
		int i;
		*adv += QString(QLatin1String("organization=%1\n")).arg(asn1ToQString(ref->organization, true));
		for (i = 0; i < sk_ASN1_INTEGER_num(ref->noticenos); i++) {
			asn1_int num(sk_ASN1_INTEGER_value(ref->noticenos, i));
			sl << num.toDec();
		}
		if (sl.size())
			*adv += QString(QLatin1String("noticeNumbers=%1\n")).arg(sl.join(QLatin1String(", ")));
	}
}

static bool gen_cpol_qual_sect(QString tag, POLICYINFO *pinfo, QString *adv)
{
	QString polsect = QString(QLatin1String("\n[%1]\n")).arg(tag);
	QString noticetag, _adv;
	STACK_OF(POLICYQUALINFO) *quals = pinfo->qualifiers;
	int i;

	if (!adv)
		adv = &_adv;

	polsect += QString(QLatin1String("policyIdentifier=%1\n")).arg(OBJ_obj2QString(pinfo->policyid));

	for (i = 0; i < sk_POLICYQUALINFO_num(quals); i++) {
		POLICYQUALINFO *qualinfo = sk_POLICYQUALINFO_value(quals, i);
		switch (OBJ_obj2nid(qualinfo->pqualid)) {
		case NID_id_qt_cps:
			polsect += QString(QLatin1String("CPS.%1=%2\n")).arg(i).arg(asn1ToQString(qualinfo->d.cpsuri, true));
			break;
		case NID_id_qt_unotice:
			noticetag = QString(QLatin1String("%1_notice%2_sect")).arg(tag).arg(i);
			polsect += QString(QLatin1String("userNotice.%1=@%2\n")).arg(i).arg(noticetag);
			gen_cpol_notice(noticetag, qualinfo->d.usernotice, adv);
			break;
		default:
			return false;
		}
	}
	*adv = polsect + *adv;
	return true;
}

bool x509v3_ext::parse_certpol(QString *, QString *adv) const
{
	bool retval = true;
	QStringList pols;
	QString myadv;
	STACK_OF(POLICYINFO) *pol = (STACK_OF(POLICYINFO) *)d2i();
	int i;
	for (i = 0; i < sk_POLICYINFO_num(pol); i++) {
		POLICYINFO *pinfo = sk_POLICYINFO_value(pol, i);
		if (!pinfo->qualifiers) {
			pols << OBJ_obj2QString(pinfo->policyid);
			continue;
		}
		QString tag = QString(QLatin1String("certpol%1_sect")).arg(i);
		pols << QString(QLatin1String("@")) + tag;
		if (!gen_cpol_qual_sect(tag, pinfo, &myadv)) {
			retval = false;
			break;
		}
	}
	if (retval && adv)
		*adv = QString(QLatin1String("certificatePolicies=ia5org,%1\n")).arg(pols.join(QLatin1String(", "))) + *adv + myadv;
	sk_POLICYINFO_free(pol);
	return retval;
}

bool x509v3_ext::parse_bc(QString *single, QString *adv) const
{
	BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS *)d2i();
	QString ret = asn1_int(bc->pathlen).toDec();
	if (!ret.isEmpty())
		ret = QLatin1String(",pathlen:") + ret;
	ret = parse_critical() + (bc->ca ? QLatin1String("CA:TRUE") : QLatin1String("CA:FALSE")) + ret;
	if (single)
		*single = ret;
	else if (adv)
		*adv = QString(QLatin1String("%1=%2\n")).arg(QLatin1String(OBJ_nid2sn(nid()))).arg(ret) + *adv;
	BASIC_CONSTRAINTS_free(bc);
	return true;
}

static const BIT_STRING_BITNAME key_usage_type_table[] = {
	{0, "Digital Signature", "digitalSignature"},
	{1, "Non Repudiation", "nonRepudiation"},
	{2, "Key Encipherment", "keyEncipherment"},
	{3, "Data Encipherment", "dataEncipherment"},
	{4, "Key Agreement", "keyAgreement"},
	{5, "Certificate Sign", "keyCertSign"},
	{6, "CRL Sign", "cRLSign"},
	{7, "Encipher Only", "encipherOnly"},
	{8, "Decipher Only", "decipherOnly"},
	{-1, NULL, NULL}
};

static const BIT_STRING_BITNAME ns_cert_type_table[] = {
	{0, "SSL Client", "client"},
	{1, "SSL Server", "server"},
	{2, "S/MIME", "email"},
	{3, "Object Signing", "objsign"},
	{4, "Unused", "reserved"},
	{5, "SSL CA", "sslCA"},
	{6, "S/MIME CA", "emailCA"},
	{7, "Object Signing CA", "objCA"},
	{-1, NULL, NULL}
};

bool x509v3_ext::parse_bitstring(QString *single, QString *adv) const
{
	ASN1_BIT_STRING *bs;
	const BIT_STRING_BITNAME *bnames;
	int n = nid();

	switch (n) {
	case NID_key_usage: bnames = key_usage_type_table; break;
	case NID_netscape_cert_type: bnames = ns_cert_type_table; break;
	default: return false;
	}
	bs = (ASN1_BIT_STRING *)d2i();
	QString ret = parse_critical() + parse_bits(bnames, bs);
	if (single)
		*single = ret;
	else if (adv)
		*adv = QString(QLatin1String("%1=%2\n")).arg(QLatin1String(OBJ_nid2sn(nid()))).arg(ret) + *adv;
	ASN1_BIT_STRING_free(bs);
	return true;
}

bool x509v3_ext::parse_sKeyId(QString *, QString *adv) const
{
	if (adv)
		*adv = QString(QLatin1String("%1=hash\n")).arg(QLatin1String(OBJ_nid2sn(nid()))) + *adv;
	return true;
}

bool x509v3_ext::parse_aKeyId(QString *, QString *adv) const
{
	QStringList ret;
	AUTHORITY_KEYID *akeyid = (AUTHORITY_KEYID *)d2i();

	if (akeyid->keyid)
		ret << QLatin1String("keyid");
	if (akeyid->issuer)
		ret << QLatin1String("issuer");
	if (adv)
		*adv = QString(QLatin1String("%1=%2\n")).arg(QLatin1String(OBJ_nid2sn(nid()))).arg(ret.join(QLatin1String(", "))) + *adv;
	AUTHORITY_KEYID_free(akeyid);
	return true;
}

bool x509v3_ext::parse_generic(QString *, QString *adv) const
{
	QString der, obj;
	int n = nid();

	if (n == NID_undef)
		obj = OBJ_obj2QString(X509_EXTENSION_get_object(ext));
	else
		obj = QLatin1String(OBJ_nid2sn(n));

	ASN1_OCTET_STRING *v = X509_EXTENSION_get_data(ext);
	for (int i = 0; i < v->length; i++)
		der += QString(QLatin1String(":%1")).arg((int)(v->data[i]), 2, 16, QLatin1Char('0'));

	if (adv)
		*adv = QString(QLatin1String("%1=%2DER%3\n")).arg(obj).arg(parse_critical()).arg(der) + *adv;
	return true;
}

bool x509v3_ext::genConf(QString *single, QString *adv) const
{
	int n = nid();
	switch (n) {
	case NID_crl_distribution_points:
		return parse_Crldp(single, adv);
	case NID_subject_alt_name:
	case NID_issuer_alt_name:
		return parse_generalName(single, adv);
	case NID_info_access:
		return parse_ainfo(single, adv);
	case NID_ext_key_usage:
		return parse_eku(single, adv);
	case NID_certificate_policies:
		return parse_certpol(single, adv);
	case NID_netscape_comment:
	case NID_netscape_base_url:
	case NID_netscape_revocation_url:
	case NID_netscape_ca_revocation_url:
	case NID_netscape_renewal_url:
	case NID_netscape_ca_policy_url:
	case NID_netscape_ssl_server_name:
		return parse_ia5(single, adv);
	case NID_basic_constraints:
		return parse_bc(single, adv);
	case NID_key_usage:
	case NID_netscape_cert_type:
		return parse_bitstring(single, adv);
	case NID_subject_key_identifier:
		return parse_sKeyId(single, adv);
	case NID_authority_key_identifier:
		return parse_aKeyId(single, adv);
	default:
		return parse_generic(single, adv);
	}
	return false;
}

QString x509v3_ext::getHtml() const
{
	QString html;
	html = QLatin1String("<b><u>") + getObject();
	if (getCritical() != 0)
		html += QLatin1String(" <font color=\"red\">critical</font>");
	html += QLatin1String(":</u></b><br><tt>") + getValue(true) + QLatin1String("</tt>");
	return html;
}

X509_EXTENSION *x509v3_ext::get() const
{
	return X509_EXTENSION_dup(ext);
}

bool x509v3_ext::isValid() const
{
	ASN1_OCTET_STRING *v = X509_EXTENSION_get_data(ext);
	ASN1_OBJECT *o = X509_EXTENSION_get_object(ext);
	return v && o && v->length > 0 && OBJ_obj2nid(o) != NID_undef;
}

/*************************************************************/

bool x509v3_ext_list::genConf(int nid, QString *single, QString *adv)
{
	int i = idxByNid(nid);
	if (i != -1) {
		if (at(i).genConf(single, adv))
			removeAt(i);
		ERR_clear_error();
		return true;
	}
	return false;
}

void x509v3_ext_list::genGenericConf(QString *adv)
{
	for (int i = 0; i < size();) {
		if (at(i).genConf(NULL, adv) || at(i).parse_generic(NULL, adv))
			removeAt(i);
		else
			i++;
		ERR_clear_error();
	}
}

void x509v3_ext_list::setStack(const STACK_OF(X509_EXTENSION) *st, int start)
{
	clear();
	int cnt = sk_X509_EXTENSION_num(st);
	x509v3_ext e;
	for (int i = start; i < cnt; i++) {
		e.set(sk_X509_EXTENSION_value(st,i));
		append(e);
	}
}

STACK_OF(X509_EXTENSION) *x509v3_ext_list::getStack()
{
	STACK_OF(X509_EXTENSION) *sk;
	sk = sk_X509_EXTENSION_new_null();
	for (int i = 0; i < count(); i++) {
		sk_X509_EXTENSION_push(sk, operator[](i).get());
	}
	return sk;
}

QString x509v3_ext_list::getHtml(const QString &sep)
{
	x509v3_ext e;
	QStringList s;
	for (int i = 0; i < size(); i++)
		s << at(i).getHtml();
	QString a = s.join(sep);
	return a;
}

bool x509v3_ext_list::delByNid(int nid)
{
	for(int i = 0; i < size(); i++) {
		if (at(i).nid() == nid) {
			removeAt(i);
			return true;
		}
	}
	return false;
}

int x509v3_ext_list::idxByNid(int nid)
{
	for(int i = 0; i < size(); i++) {
		if (at(i).nid() == nid) {
			return i;
		}
	}
	return -1;
}

int x509v3_ext_list::delInvalid(void)
{
	int removed=0;
	for(int i = 0; i < size(); i++) {
		if (!at(i).isValid()) {
			removeAt(i);
			removed=1;
			i--;
		}
	}
	return removed;
}
