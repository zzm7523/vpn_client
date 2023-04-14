#include <QDebug>
#include <QRegularExpression>
#include <QDateTime>
#include <QFile>
#include <QTextStream>

#include <algorithm>

#include "../common/common.h"
#include "../common/cipher.h"
#include "../common/file_util.h"
#include "../common/zip_util.h"
#include "../common/server_endpoint.h"
#include "vpn_config_manager_servant.h"

#define CREDENTIALS_CIPHER_NAME		"AES-128-CBC"
#define CREDENTIALS_MAGIC			"V!#7Fx}&%Zd?qR"
#define CREDENTIALS_KEY_ROTATE		157
#define CREDENTIALS_IV_ROTATE		51

VPNConfigManagerServant::VPNConfigManagerServant(const QString& _uniqueIdentify)
	: VPNConfigManagerSkeleton(_uniqueIdentify), nextConfigId(0), loaded(false)
{
}

bool VPNConfigManagerServant::load(const QString& baseSavePath, const QByteArray& passphrase, bool loadCreds,
		const Context& ctx)
{
	Q_UNUSED(ctx)
	Q_ASSERT(!loadCreds || (loadCreds && !passphrase.isEmpty()));

	QDir baseSaveDir(baseSavePath);
	if (!baseSaveDir.exists())
		return false;

	if (this->loaded && baseSaveDir == QDir(this->baseSavePath))		// 已经加载
		return true;

	unload(Context::getDefaultContext());	// 必须先卸载

	this->baseSavePath = baseSaveDir.canonicalPath();	// 保存当前加载目录 
	this->loaded = true;		// 记住已经加载

	QListIterator<QString> i(baseSaveDir.entryList(QDir::AllDirs, QDir::Name));
	while (i.hasNext()) {
		const QString& entryName = i.next();
		if (entryName != QLatin1String(".") && entryName != QLatin1String("..")) {
			QDir configDir(QDir(this->baseSavePath).absoluteFilePath(entryName));
			QFile configFile(configDir.absoluteFilePath(QLatin1String(VPN_CONFIG_FILE)));

			bool ok = false;
			qint32 id = entryName.toInt(&ok, 10);
			if (nextConfigId < id)
				nextConfigId = id;	// 记住已分配的最大ID
			if (ok) {
				if (configFile.exists()) {
					VPNConfig config(id, configDir.canonicalPath());
					if (loadVPNConfig(configDir.canonicalPath(), passphrase, loadCreds, config))
						this->configList.append(config);
				} else	// 无效的配置目录, 删除它 ??
					configDir.removeRecursively();
			}
		}
	}

	if (!this->configList.isEmpty())
		std::sort(this->configList.begin(), this->configList.end());		// 排序VPNConfig

	qDebug() << "load VPN config from" << this->baseSavePath << ", size=" << this->configList.size();

	return true;
}

void VPNConfigManagerServant::unload(const Context& ctx)
{
	Q_UNUSED(ctx)

	this->baseSavePath.clear();
	this->configList.clear();
	this->loaded = false;
}

bool VPNConfigManagerServant::backup(qint32 id, const QString& filename, VPNConfigManagerI::OptionFlag flag, const Context& ctx)
{
	Q_UNUSED(flag)

	VPNConfig config = this->get(id, ctx);
	if (config.isEmpty()) {
		return false;
	}

	const QString configFile = QDir(config.getPath()).absoluteFilePath(QLatin1String(VPN_CONFIG_FILE));
	if (!ZipUtil::archiveFile(filename, configFile))
		return false;

	const QString keyFile = QDir(config.getPath()).absoluteFilePath(QLatin1String(VPN_KEY_FILE));
	if (QFile::exists(keyFile) && !ZipUtil::archiveFile(filename, keyFile))
		return false;

	const QString advConfigFile = QDir(config.getPath()).absoluteFilePath(QLatin1String(VPN_ADV_CONFIG_FILE));
	if (QFile::exists(advConfigFile) && !ZipUtil::archiveFile(filename, advConfigFile))
		return false;

	// 不允许用户备份和导入安全信息
/*
	if (VPNConfigManagerI::O_All == flag || VPNConfigManagerI::O_Credentials == flag) {
		const QString credFile = QDir(config.getPath()).absoluteFilePath(QLatin1String(CREDIANTIALS_FILE));
		if (QFile::exists(credFile) && !ZipUtil::archiveFile(filename, credFile))
			return false;
	}
*/

	return true;
}

GenericResult VPNConfigManagerServant::restore(const QString& filename, bool forceCover, const Context& ctx)
{
	Q_UNUSED(ctx)

	VPNConfig tempConfig, config;

	// 解压到临时目录
	QDir tempDir = QDir::temp();
	if (!ZipUtil::extract(filename, tempDir.canonicalPath(), QLatin1String(VPN_CONFIG_FILE)))
		return GenericResult(1);

	QDir baseSaveDir(this->baseSavePath);
	QDir configDir;
	qint32 id = -1, existIndex = -1;

	// 查找要覆盖的配置
	if (!readVPNConfig(tempDir.absoluteFilePath(QLatin1String(VPN_CONFIG_FILE)), tempConfig))
		return GenericResult(1);

	for (int i = 0; i < configList.size(); ++i) {
		config = configList.at(i);
		if (tempConfig.getName().compare(config.getName(), Qt::CaseInsensitive) == 0) {
			existIndex = i;
			id = config.getId();
			configDir.setPath(baseSaveDir.absoluteFilePath(QString::number(id)));
			break;
		}
	}

	if (existIndex >= 0 && !forceCover) {
		GenericResult result(2);
		result.setAttribute(GenericResult::VPN_CONFIG_ID, id);
		return result;
	}

	if (existIndex < 0) {	// 创建新配置
		id = generateVPNConfigId();
		configDir.setPath(baseSaveDir.absoluteFilePath(QString::number(id)));
		if (!baseSaveDir.mkdir(QString::number(id)))	// 创建配置目录
			return GenericResult(1);
	}

	if (!ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(VPN_CONFIG_FILE)))
		goto error;

	ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(VPN_KEY_FILE));
	ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(VPN_ADV_CONFIG_FILE));
	// 不允许用户备份和导入安全信息
//	ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(CREDIANTIALS_FILE));

	// 重新读取导入的配置
	config.clear();
	config.setId(id);
	config.setPath(configDir.canonicalPath());
	if (!readVPNConfig(configDir.absoluteFilePath(QLatin1String(VPN_CONFIG_FILE)), config))
		return GenericResult(1);

	if (existIndex >= 0) // 存在, 删除, 重新增加
		configList.removeAt(existIndex);
	configList.append(config);

	std::sort(this->configList.begin(), this->configList.end());		// 重新排序VPNConfig

	return GenericResult(id);

error:
	configDir.removeRecursively();
	return GenericResult(1);
}

qint32 VPNConfigManagerServant::save(const VPNConfig& config, const QByteArray& passphrase,
		VPNConfigManagerI::OptionFlag flag, const Context& ctx)
{
	Q_UNUSED(ctx)
	Q_ASSERT(flag == VPNConfigManagerI::O_Config || (flag != VPNConfigManagerI::O_Config && !passphrase.isEmpty()));

	if (config.isTemporary() || config.isEmpty())
		return -1;

	VPNConfig tmpConfig = config;

	int existIndex = -1;
	for (int i = 0; i < configList.size(); ++i) {
		if (configList.at(i).getId() == tmpConfig.getId()) {
			existIndex = i;
			break;
		}
	}

	QDir baseSaveDir(this->baseSavePath);
	if (existIndex == -1) // 配置不存在
		tmpConfig.setId(generateVPNConfigId());	// 分配配置ID

	QDir configDir(baseSaveDir.absoluteFilePath(QString::number(tmpConfig.getId())));
	if (!configDir.exists()) {		
		if (!baseSaveDir.mkdir(QString::number(tmpConfig.getId())))	// 创建配置目录
			return -1;
		else {
			createAdvConfigFile(configDir); // 生成空的高级配置文件
			createLogFile(configDir); // 生成日志文件
			tmpConfig.setPath(configDir.canonicalPath());
#ifndef _WIN32
			FileUtil::addPermissions(configDir.canonicalPath(), FileUtil::ANY_BODY_READ|FileUtil::ANY_BODY_EXE);
#endif
		}
	}

	if (VPNConfigManagerI::O_Config == flag || VPNConfigManagerI::O_All == flag) {
		if (existIndex != -1 && !serverEndpointsEqual(configList.at(existIndex).getServerEndpoints(),
				tmpConfig.getServerEndpoints()))
			truncEdgeFile(configDir); // 清理Edge文件

		if (!tmpConfig.getTLSAuth().isEmpty() && !saveTLSAuthFile(tmpConfig)) {
			// 新建失败, 删除配置
			if (existIndex == -1)
				configDir.removeRecursively();
			return -1;
		}

		const QString configFile = QDir(configDir.canonicalPath()).absoluteFilePath(QLatin1String(VPN_CONFIG_FILE));
		if (!saveVPNConfig(configFile, tmpConfig)) {
			// 新建失败, 删除配置
			if (existIndex == -1)
				configDir.removeRecursively();
			return -1;
		}
	}

	if (VPNConfigManagerI::O_Credentials == flag || VPNConfigManagerI::O_All == flag) {
		const QString credFile = QDir(configDir.canonicalPath()).absoluteFilePath(QLatin1String(CREDIANTIALS_FILE));
		saveCrediantials(credFile, passphrase, tmpConfig);	// 忽略错误
	}

	if (existIndex != -1) // 存在, 删除, 重新增加
		configList.removeAt(existIndex);
	configList.append(tmpConfig);

	std::sort(this->configList.begin(), this->configList.end());		// 重新排序VPNConfig

	return tmpConfig.getId();
}

bool VPNConfigManagerServant::remove(qint32 id, const Context& ctx)
{
	Q_UNUSED(ctx)

	bool success = false;
	QMutableListIterator<VPNConfig> i(this->configList);
	while (i.hasNext()) {
		VPNConfig config = i.next();
		if (config.getId() == id) {
			if (!config.isTemporary()) {
				Q_ASSERT(!config.getPath().isEmpty());
				success = QDir(config.getPath()).removeRecursively();
			}
			i.remove();
			success = true;
		}
	}
	return success;
}

bool VPNConfigManagerServant::clearCredentials(qint32 id, const Context& ctx)
{
	const VPNConfig config = get(id, ctx);
	QFile credFile(QDir(config.getPath()).absoluteFilePath(CREDIANTIALS_FILE));

	if (!credFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
		return false;
	else {
		credFile.close();
		return true;
	}
}

VPNConfig VPNConfigManagerServant::get(qint32 id, const Context& ctx)
{
	Q_UNUSED(ctx)

	if (id >= 0) {
		QListIterator<VPNConfig> i(this->configList);
		while (i.hasNext()) {
			VPNConfig config = i.next();
			if (config.getId() == id)
				return config;
		}
	}
	return VPNConfig();
}

VPNConfig VPNConfigManagerServant::get(const QString& name, const Context& ctx)
{
	Q_UNUSED(ctx)

	if (!name.isEmpty()) {
		QListIterator<VPNConfig> i(this->configList);
		while (i.hasNext()) {
			VPNConfig config = i.next();
			if (config.getName().compare(name, Qt::CaseInsensitive) == 0)
				return config;
		}
	}
	return VPNConfig();
}

VPNConfig VPNConfigManagerServant::get(const QString& host, quint16 port, const QString& protocol, const Context& ctx)
{
	Q_UNUSED(ctx)

	QListIterator<VPNConfig> i(this->configList);
	while (i.hasNext()) {
		VPNConfig config = i.next();
		if (config.getServerEndpoints().contains(ServerEndpoint(host, port, ServerEndpoint::string2Protocol(protocol))))
			return config;
	}
	return VPNConfig();
}

QList<VPNConfig> VPNConfigManagerServant::list(const Context& ctx) const
{
	Q_UNUSED(ctx)
	return configList;
}

qint32 VPNConfigManagerServant::generateVPNConfigId()
{
	QDir baseSaveDir(this->baseSavePath);
	if (nextConfigId < 0)
		nextConfigId = 0;

	while (true) {
		QDir configDir(baseSaveDir.absoluteFilePath(QString::number(nextConfigId)));
		if (configDir.exists())
			++nextConfigId;
		else {
			return nextConfigId;
		}
	}
}

bool VPNConfigManagerServant::createAdvConfigFile(const QDir& configDir) const
{
	const QString fileName = QDir(configDir).absoluteFilePath(QLatin1String(VPN_ADV_CONFIG_FILE));
	if (!configDir.exists(fileName)) { // 生成空的高级配置文件
		QFile advConfigFile(fileName);
		advConfigFile.open(QIODevice::Text | QIODevice::WriteOnly);
		advConfigFile.close();
	}
	return true;
}

bool VPNConfigManagerServant::createLogFile(const QDir& configDir) const
{
	const QString fileName = QDir(configDir).absoluteFilePath(QLatin1String(VPN_LOG_FILE));
	if (!configDir.exists(fileName)) { // 生成空的日志文件
		QFile logFile(fileName);
		logFile.open(QIODevice::Text | QIODevice::WriteOnly);
		logFile.close();
	}
	return true;
}

bool VPNConfigManagerServant::truncEdgeFile(const QDir& configDir) const
{
	const QString fileName = QDir(configDir).absoluteFilePath(QLatin1String(VPN_EDGE_FILE));
	if (configDir.exists(fileName)) { // 清理Edge文件
		QFile edgeFile(fileName);
		edgeFile.open(QIODevice::WriteOnly | QIODevice::Truncate);
		edgeFile.close();
	}
	return true;
}

bool VPNConfigManagerServant::loadVPNConfig(const QString& configPath, const QByteArray& passphrase,
		bool loadCreds, VPNConfig& config)
{
	QDir configDir(configPath);
	const QString configFile = configDir.absoluteFilePath(QLatin1String(VPN_CONFIG_FILE));
	const QString credFile = configDir.absoluteFilePath(QLatin1String(CREDIANTIALS_FILE));

	if (readVPNConfig(configFile, config)) {
		if (loadCreds)
			readCrediantials(credFile, passphrase, config);	// 忽略错误
		return true;
	} else {
		qDebug() << "load vpn config fail! path=" << configPath << ", name=" << config.getName();
		return false;
	}
}

bool VPNConfigManagerServant::saveTLSAuthFile(VPNConfig& config)
{
	const QString stdKeyFileName = QDir(config.getPath()).absoluteFilePath(QLatin1String(VPN_KEY_FILE));
	QString currFileName = config.getTLSAuth().getFileName();
	int idx = config.getTLSAuth().getFileName().indexOf(QLatin1Char('/'));
	if (idx == -1)
		idx = config.getTLSAuth().getFileName().indexOf(QLatin1Char('\\'));
	if (idx == -1)
		currFileName = QDir(config.getPath()).absoluteFilePath(config.getTLSAuth().getFileName());

	if (currFileName.compare(stdKeyFileName, Qt::CaseInsensitive) != 0) {
		QFile stdKeyFile(stdKeyFileName);
		if (stdKeyFile.exists())
			stdKeyFile.remove();
		if (!QFile::copy(currFileName, stdKeyFileName))
			return false;
	}
	config.getTLSAuth().setFileName(QLatin1String(VPN_KEY_FILE));
	return true;
}

bool VPNConfigManagerServant::saveVPNConfig(const QString& fileName, VPNConfig& config)
{
#ifdef _WIN32
	FileUtil::setReadonlyAttribute(fileName, false);
#endif
	QFile configFile(fileName);
	if (!configFile.open(QIODevice::Text | QIODevice::WriteOnly))
		return false;

#ifndef _WIN32
	FileUtil::addPermissions(fileName, FileUtil::ANY_BODY_READ);
#endif

	QTextStream out(&configFile);
	out.setCodec("UTF-8"); // 配置文件采用UTF-8编码

	const QDateTime now = QDateTime::currentDateTime();
	out << "#\n";
	out << "# Configuration file generated by Big SSL VPN " << now.toString(Qt::RFC2822Date) << "\n\n";
	out << "# *DO NOT* modify this file directly. If there is a value that you would like to override,\n";
	out << "# please add it to vpn_adv.conf file.\n";
	out << "#\n";

	out << "setenv FORWARD_COMPATIBLE 1\n";
	out << "verb 3\n";
	out << "mute 20\n";
	out << "client\n";

	if (!config.getName().isEmpty())
		out << "#? name " << config.getName() << "\n";

	if (!config.getCompatibleOption().isEmpty())
		out << "#? compatible-option " << config.getCompatibleOption() << "\n";

	const QList<ServerEndpoint>& remotes = config.getServerEndpoints();
	for (int i = 0; i < remotes.size(); ++i) {	
		out << "#? remote " << remotes.at(i).getHost() << " " << QString::number(remotes.at(i).getPort())
			<< " " << ServerEndpoint::protocol2String(remotes.at(i).getProtocol()).toLower() << "\n";
		// 采用UDP协议时在命令行添加
//		out << "explicit-exit-notify " << QString::number(2) << "\n";
	}

	if (config.isAutoStart())
		out << "#? auto-start\n";

#ifdef _WIN32
	out << "ip-win32 adaptive\n";	// 如果通过DHCP设置IP失败, 那么用netsh再尝试一下
#endif
	out << "remap-usr1 SIGTERM\n";
	out << "resolv-retry 0\n";
	// 采用TCP协议时在命令行添加
//	out << "connect-retry-max 1\n";
	// 需要时, 由服务端推送, 或在vpn_adv.conf文件中单独指定
//	out << "register-dns\n";	// This is known to kick Windows into recognizing pushed DNS servers.
	out << "nobind\n";	// 客户端最好启用这个参数
	out << "float\n";
	out << "mssfix\n";	
	out << "script-security 2\n";
	out << "#? auth-options " << static_cast<quint32>(config.getAuthOptions()) << "\n";
	out << "tls-exit\n";

	const TLSAuth &tlsAuth = config.getTLSAuth();
	if (!tlsAuth.isEmpty()) {
		out << "tls-auth " << tlsAuth.getFileName();
		if (tlsAuth.getDirection() == KEY_DIRECTION_NORMAL)
			out << " 0";
		else if (tlsAuth.getDirection() == KEY_DIRECTION_INVERSE)
			out << " 1";
		if (!tlsAuth.getAuth().isEmpty())
			out << " " << tlsAuth.getAuth() << "\n";
	}

	if (config.isEnableProxy() && config.getProxyType() != VPNConfig::NoneProxy) {
		if (config.getProxyType() == VPNConfig::System)
			out << "#? system-proxy\n";
		else if (config.getProxyType() == VPNConfig::Http)
			out << "http-proxy " << config.getProxyHost() << " " << config.getProxyPort() << " auto\n";
		else if (config.getProxyType() == VPNConfig::Socks)
			out << "socks-proxy " << config.getProxyHost() << " " << config.getProxyPort() << " stdin\n";
	}

	if (config.getTlsVersion().isEmpty())
		out << "tls-version " << TLS_VERSION_LIST << "\n";
	else
		out << "tls-version " << config.getTlsVersion() << "\n";

	if (config.getCipher().isEmpty()) {
		QStringList cipherList = QString(QLatin1String(CHANNEL_SOFTWARE_CIPHER_LIST)).split(QLatin1Char(':'));
		for (int i = 0; i < cipherList.size(); ++i)
			out << "cipher " << cipherList.at(i) << "\n";
	}
	else
		out << "cipher " << config.getCipher() << "\n";

	if (config.getAuth().isEmpty()) {
		QStringList authList = QString(QLatin1String(CHANNEL_AUTH_LIST)).split(QLatin1Char(':'));
		for (int i = 0; i < authList.size(); ++i)
			out << "auth " << authList.at(i) << "\n";
	} else
		out << "auth " << config.getAuth() << "\n";

	out.flush();
	configFile.close();
	return true;
}

bool VPNConfigManagerServant::saveCrediantials(const QString& fileName, const QByteArray& passphrase, VPNConfig& config)
{
#ifdef _WIN32
	FileUtil::setReadonlyAttribute(fileName, false);
#endif
	QFile credFile(fileName);
	if (!credFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
		return false;

#ifndef _WIN32
	FileUtil::addPermissions(fileName, FileUtil::ANY_BODY_READ);
#endif

	QByteArray plaintext;
	QDataStream out(&plaintext, QIODevice::WriteOnly);
	out.setVersion(QDataStream::Qt_5_2);

	Credentials &cred = config.getCredentials();
	cred.setKeyPassword(QByteArray());	// 私钥保护密码不保存, 每次插拔必须重新输入
	cred.setOtp(QLatin1String(""));		// 一次性密码不需要保存
	out << QString(QLatin1String(CREDENTIALS_MAGIC)) << cred;

	bool success = false;
	const QByteArray key = Cipher::generateKey(EVP_MAX_KEY_LENGTH, CREDENTIALS_KEY_ROTATE, passphrase, success);
	const QByteArray iv = Cipher::generateIV(EVP_MAX_KEY_LENGTH, CREDENTIALS_IV_ROTATE, passphrase, success);

	Cipher cipher(QLatin1String(CREDENTIALS_CIPHER_NAME), key, iv);
	QByteArray ciphertext = cipher.encrypt(plaintext, success);
	if (!success)
		ciphertext.clear();

	credFile.write(ciphertext);
	credFile.flush();
	credFile.close();
	return success;
}

bool VPNConfigManagerServant::parseOptionLine(const QString& line, QStringList& params)
{
	params = line.split(QRegularExpression(QLatin1String("\\s+")), QString::SkipEmptyParts);
	if (params.isEmpty())
		return false;
	else {
		const QString name = params.at(0);
		if (name.startsWith(QLatin1Char(';')))
			// ; 开始的内容是注解
			return false;
		else if (name.startsWith(QLatin1Char('#')) && !name.startsWith(QLatin1String("#?"))) {
			// #? 有特殊意义, 不是注解
			return false;
		}
		return true;
	}
}

bool VPNConfigManagerServant::readVPNConfig(const QString& fileName, VPNConfig& config)
{
	QFile configFile(fileName);
	if (!configFile.open(QIODevice::Text | QIODevice::ReadOnly))
		return false;

	QList<ServerEndpoint> remotes = config.getServerEndpoints();
	QStringList tlsVersionList, cipherList, authList;
	bool noError = true;

	QTextStream in(&configFile);
	in.setCodec("UTF-8"); // 配置文件采用UTF-8编码

	config.setAutoStart(false);
	config.setEnableProxy(false);

	while (noError && !in.atEnd()) {
		const QString line = in.readLine();
		QStringList params;

		if (line.isEmpty() || !parseOptionLine(line, params))
			continue;

		if (params.at(0) == QLatin1String("#?") && (noError = (params.length() >= 2))) {
			if (params.at(1) == "name" && (noError = (params.length() == 3))) {
				config.setName(params.at(2));
			} else if (params.at(1) == "compatible-option" && (noError = (params.length() == 3))) {
				config.setCompatibleOption(params.at(2));
			} else if (params.at(1) == "remote" && (noError = (params.length() == 5))) {
				remotes.append(ServerEndpoint(params.at(2), params.at(3).toInt(),
					ServerEndpoint::string2Protocol(params.at(4))));
			} else if (params.at(1) == "system-proxy" && (noError = (params.length() == 2))) {
				config.setEnableProxy(true);
				config.setProxyType(VPNConfig::System);
			} else if (params.at(1) == "auth-options" && (noError = (params.length() == 3))) {
				config.setAuthOptions(static_cast<VPNConfig::AuthOptions>(params.at(2).toUInt()));
			} else if (params.at(1) == "auto-start" && (noError = (params.length() == 2))) {
				config.setAutoStart(true);
			} else {				
				// noError = false;	// 忽略其它选项
			}

		} else if (params.at(0) == "tls-auth" && (noError = (params.length() >= 2 && params.length() <= 4))) {
			// tls-auth ta.key 1 SHA256
			config.getTLSAuth().setFileName(params.at(1));
			if (params.length() > 2) {
				if (params.at(2) == QLatin1String("0"))
					config.getTLSAuth().setDirection(KEY_DIRECTION_NORMAL);
				else if (params.at(2) == QLatin1String("1"))
					config.getTLSAuth().setDirection(KEY_DIRECTION_INVERSE);
				else
					config.getTLSAuth().setAuth(params.at(2));
			}
			if (params.length() > 3)
				config.getTLSAuth().setAuth(params.at(3));

		} else if (params.at(0) == "tls-version" && (noError = (params.length() == 2))) {
			tlsVersionList = params.at(1).split(":", QString::KeepEmptyParts);
		} else if (params.at(0) == "cipher" && (noError = (params.length() == 2))) {
			cipherList.append(params.at(1));
		} else if (params.at(0) == "auth" && (noError = (params.length() == 2))) {
			authList.append(params.at(1));

		} else if (params.at(0) == "http-proxy" && (noError = (params.length() == 4))) {
			// http-proxy 10.7.78.9 1080 auto
			config.setEnableProxy(true);
			config.setProxyType(VPNConfig::Http);
			config.setProxyHost(params.at(1));
			config.setProxyPort(params.at(2).toInt());
		} else if (params.at(0) == "socks-proxy" && (noError = (params.length() == 4))) {
			// socks-proxy 10.7.78.9 1080 stdin
			config.setEnableProxy(true);
			config.setProxyType(VPNConfig::Socks);
			config.setProxyHost(params.at(1));
			config.setProxyPort(params.at(2).toInt());

		} else {			
			// noError = false;	// 忽略其它选项
		}

		if (!noError)
			qDebug() << "parse option line fail\n" << line;
	}

	configFile.close();

	config.setServerEndpoints(remotes);
	
	// 存在多个tls版本时表示自动协商tls版本
	config.setTlsVersion(tlsVersionList.size() == 1 ? tlsVersionList.at(0) : QLatin1String(""));
	// 存在多个cipher时表示自动协商cipher
	config.setCipher(cipherList.size() == 1 ? cipherList.at(0) : QLatin1String(""));
	// 存在多个auth时表示自动协商auth
	config.setAuth(authList.size() == 1 ? authList.at(0) : QLatin1String(""));

	return !config.isEmpty();
}

bool VPNConfigManagerServant::readCrediantials(const QString& fileName, const QByteArray& passphrase, VPNConfig& config)
{
	QFile credFile(fileName);
	if (!credFile.open(QIODevice::ReadOnly))
		return false;

	const QByteArray ciphertext = credFile.readAll();
	credFile.close();

	bool success = false;
	const QByteArray key = Cipher::generateKey(EVP_MAX_KEY_LENGTH, CREDENTIALS_KEY_ROTATE, passphrase, success);
	const QByteArray iv = Cipher::generateIV(EVP_MAX_KEY_LENGTH, CREDENTIALS_IV_ROTATE, passphrase, success);
	Cipher cipher(QLatin1String(CREDENTIALS_CIPHER_NAME), key, iv);

	const QByteArray plaintext = cipher.decrypt(ciphertext, success);
	Credentials &credentials = config.getCredentials();
	QString magic;
	QDataStream in(plaintext);
	in.setVersion(QDataStream::Qt_5_2);
	in >> magic;
	success = false;

	if (magic == QLatin1String(CREDENTIALS_MAGIC)) {
		success = true;
		in >> credentials;
	}

	return success;
}
