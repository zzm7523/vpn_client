#ifndef __MISCELLANEOUS_SERVICE_I_H__
#define __MISCELLANEOUS_SERVICE_I_H__

#include "../config/config.h"

#include <QString>
#include <QStringList>

#include "common.h"
#include "context.h"
#include "process_util.h"

class MiscellaneousServiceI
{
public:
	virtual ~MiscellaneousServiceI() {}

	virtual bool changeLanguage(const QString& language, const Context& ctx) = 0;

	// !! ͨ��WMI��ȡӲ����Ϣ���ܻ����, ��XP�������������ʮ�� !!, ���Է��ں�̨, ��������ʱ����һ��
	virtual QString generateFingerprint(const Context& ctx) = 0;

	virtual QString getFingerprint(const QString& fileName, const Context& ctx) = 0;
	virtual void saveFingerprint(const QString& fileName, const QString& fingerprint, const Context& ctx) = 0;

	virtual ExecuteResult execute(const QString& program, const QStringList& arguments,
		const QString& workingDirectory, const Context& ctx) = 0;

};

#endif
