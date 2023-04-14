#include <QCoreApplication>
#include <QFile>
#include <QDir>
#include <QTextStream>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "../common/file_util.h"
#include "../common/process_util.h"
#include "../common/system_info.h"

#include "miscellaneous_service_servant.h"

MiscellaneousServiceServant::MiscellaneousServiceServant(const QString& uniqueIdentify)
	: MiscellaneousServiceSkeleton(uniqueIdentify)
{
}

bool MiscellaneousServiceServant::changeLanguage(const QString& language, const Context& ctx)
{
    Q_UNUSED(ctx)

	if (language.compare(QLatin1String("zh_CN"), Qt::CaseInsensitive) == 0) {
		appTranslator.load(QLatin1String(":/service_zh_CN.qm"), QCoreApplication::applicationDirPath());
		qtTranslator.load(QLatin1String(":/qt_zh_CN.qm"), QCoreApplication::applicationDirPath());
		QCoreApplication::instance()->installTranslator(&appTranslator);
		QCoreApplication::instance()->installTranslator(&qtTranslator);
	} else {
		QCoreApplication::instance()->removeTranslator(&appTranslator);
		QCoreApplication::instance()->removeTranslator(&qtTranslator);
	}
	return true;
}

QString MiscellaneousServiceServant::generateFingerprint(const Context& ctx)
{
    Q_UNUSED(ctx)

	// !!不要修改实现!!, 不兼容会造成TAP驱动不必要的卸载然后重新安装

	// 通过WMI获取硬件信息可能会很慢, 在XP虚拟机看见过几十秒

	if (currentFingerprint.isEmpty()) {
		unsigned char md[EVP_MAX_MD_SIZE];
		QByteArray source;

		source.append("rtwt_^&vtghskkd;;$fg%k@!~`y&vg0ghfgh[+563kl;:q?<##");

		// 不要使用CPU信息, 用户升级CPU的可能性比较大
		// 不要使用硬盘信息, 用户更换硬盘的可能性比较大

		// 微软官方和很多授权方法都推崇使用主板序号来生成指纹(!!不是所有厂商都提供主板序号!!)
        source.append(SystemInfo::getMainboardId().toUtf8());

		// 使用静态MAC地址, 网卡一般都集成到主板, 用户更换主板的可能性比较小
		QStringList macList = SystemInfo::getMacs();
		for (int i = 0; i < macList.size(); ++i)
            source.append(macList.at(i).toUtf8());

		SHA1((unsigned char*) source.data(), source.size(), md);
		currentFingerprint = QString::fromUtf8(QByteArray((const char*) md, SHA_DIGEST_LENGTH).toBase64());
	}

	return currentFingerprint;
}

QString MiscellaneousServiceServant::getFingerprint(const QString& fileName, const Context& ctx)
{
    Q_UNUSED(ctx)

	QFile fingerprintFile(fileName);
	QString savedFingerprint;

	if (fingerprintFile.open(QIODevice::ReadOnly)) {
		savedFingerprint = QString::fromLocal8Bit(fingerprintFile.readAll());
		fingerprintFile.close();
	}

	return savedFingerprint;
}

void MiscellaneousServiceServant::saveFingerprint(const QString& fileName, const QString& fingerprint, const Context& ctx)
{
    Q_UNUSED(ctx)

#ifdef _WIN32
	FileUtil::setReadonlyAttribute(fileName, false);
#endif
	QFile fingerprintFile(fileName);

	if (fingerprintFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		fingerprintFile.write(fingerprint.toLocal8Bit());
		fingerprintFile.flush();
		fingerprintFile.close();
	}

#ifdef _WIN32
	FileUtil::setHideAttribute(fileName, true);	// 隐藏文件
#else
	FileUtil::addPermissions(fileName, FileUtil::ANY_BODY_READ);
#endif
}

ExecuteResult MiscellaneousServiceServant::execute(const QString& program, const QStringList& arguments,
		const QString& workingDirectory, const Context& ctx)
{
    Q_UNUSED(ctx)

	return ProcessUtil::execute(program, arguments, workingDirectory);
}

