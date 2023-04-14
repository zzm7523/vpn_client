#ifndef __MISCELLANEOUS_SERVICE_SERVANT_H__
#define __MISCELLANEOUS_SERVICE_SERVANT_H__

#include "../config/config.h"

#include <QStringList>
#include <QTranslator>

#include "../common/miscellaneous_service_i_skeleton.h"

class MiscellaneousServiceServant : public MiscellaneousServiceSkeleton
{
public:
	MiscellaneousServiceServant(const QString& uniqueIdentify);

	virtual bool changeLanguage(const QString& language, const Context& ctx);

	virtual QString generateFingerprint(const Context& ctx);

	virtual QString getFingerprint(const QString& fileName, const Context& ctx);
	virtual void saveFingerprint(const QString& fileName, const QString& fingerprint, const Context& ctx);

	virtual ExecuteResult execute(const QString& program, const QStringList& arguments,
		const QString& workingDirectory, const Context& ctx);

private:
	QString currentFingerprint;
	QTranslator appTranslator;
	QTranslator qtTranslator;

};

#endif
