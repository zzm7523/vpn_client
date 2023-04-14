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

	if (this->loaded && baseSaveDir == QDir(this->baseSavePath))		// �Ѿ�����
		return true;

	unload(Context::getDefaultContext());	// ������ж��

	this->baseSavePath = baseSaveDir.canonicalPath();	// ���浱ǰ����Ŀ¼ 
	this->loaded = true;		// ��ס�Ѿ�����

	QListIterator<QString> i(baseSaveDir.entryList(QDir::AllDirs, QDir::Name));
	while (i.hasNext()) {
		const QString& entryName = i.next();
		if (entryName != QLatin1String(".") && entryName != QLatin1String("..")) {
			QDir configDir(QDir(this->baseSavePath).absoluteFilePath(entryName));
			QFile configFile(configDir.absoluteFilePath(QLatin1String(VPN_CONFIG_FILE)));

			bool ok = false;
			qint32 id = entryName.toInt(&ok, 10);
			if (nextConfigId < id)
				nextConfigId = id;	// ��ס�ѷ�������ID
			if (ok) {
				if (configFile.exists()) {
					VPNConfig config(id, configDir.canonicalPath());
					if (loadVPNConfig(configDir.canonicalPath(), passphrase, loadCreds, config))
						this->configList.append(config);
				} else	// ��Ч������Ŀ¼, ɾ���� ??
					configDir.removeRecursively();
			}
		}
	}

	if (!this->configList.isEmpty())
		std::sort(this->configList.begin(), this->configList.end());		// ����VPNConfig

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

	// �������û����ݺ͵��밲ȫ��Ϣ
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

	// ��ѹ����ʱĿ¼
	QDir tempDir = QDir::temp();
	if (!ZipUtil::extract(filename, tempDir.canonicalPath(), QLatin1String(VPN_CONFIG_FILE)))
		return GenericResult(1);

	QDir baseSaveDir(this->baseSavePath);
	QDir configDir;
	qint32 id = -1, existIndex = -1;

	// ����Ҫ���ǵ�����
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

	if (existIndex < 0) {	// ����������
		id = generateVPNConfigId();
		configDir.setPath(baseSaveDir.absoluteFilePath(QString::number(id)));
		if (!baseSaveDir.mkdir(QString::number(id)))	// ��������Ŀ¼
			return GenericResult(1);
	}

	if (!ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(VPN_CONFIG_FILE)))
		goto error;

	ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(VPN_KEY_FILE));
	ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(VPN_ADV_CONFIG_FILE));
	// �������û����ݺ͵��밲ȫ��Ϣ
//	ZipUtil::extract(filename, configDir.canonicalPath(), QLatin1String(CREDIANTIALS_FILE));

	// ���¶�ȡ���������
	config.clear();
	config.setId(id);
	config.setPath(configDir.canonicalPath());
	if (!readVPNConfig(configDir.absoluteFilePath(QLatin1String(VPN_CONFIG_FILE)), config))
		return GenericResult(1);

	if (existIndex >= 0) // ����, ɾ��, ��������
		configList.removeAt(existIndex);
	configList.append(config);

	std::sort(this->configList.begin(), this->configList.end());		// ��������VPNConfig

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
	if (existIndex == -1) // ���ò�����
		tmpConfig.setId(generateVPNConfigId());	// ��������ID

	QDir configDir(baseSaveDir.absoluteFilePath(QString::number(tmpConfig.getId())));
	if (!configDir.exists()) {		
		if (!baseSaveDir.mkdir(QString::number(tmpConfig.getId())))	// ��������Ŀ¼
			return -1;
		else {
			createAdvConfigFile(configDir); // ���ɿյĸ߼������ļ�
			createLogFile(configDir); // ������־�ļ�
			tmpConfig.setPath(configDir.canonicalPath());
#ifndef _WIN32
			FileUtil::addPermissions(configDir.canonicalPath(), FileUtil::ANY_BODY_READ|FileUtil::ANY_BODY_EXE);
#endif
		}
	}

	if (VPNConfigManagerI::O_Config == flag || VPNConfigManagerI::O_All == flag) {
		if (existIndex != -1 && !serverEndpointsEqual(configList.at(existIndex).getServerEndpoints(),
				tmpConfig.getServerEndpoints()))
			truncEdgeFile(configDir); // ����Edge�ļ�

		if (!tmpConfig.getTLSAuth().isEmpty() && !saveTLSAuthFile(tmpConfig)) {
			// �½�ʧ��, ɾ������
			if (existIndex == -1)
				configDir.removeRecursively();
			return -1;
		}

		const QString configFile = QDir(configDir.canonicalPath()).absoluteFilePath(QLatin1String(VPN_CONFIG_FILE));
		if (!saveVPNConfig(configFile, tmpConfig)) {
			// �½�ʧ��, ɾ������
			if (existIndex == -1)
				configDir.removeRecursively();
			return -1;
		}
	}

	if (VPNConfigManagerI::O_Credentials == flag || VPNConfigManagerI::O_All == flag) {
		const QString credFile = QDir(configDir.canonicalPath()).absoluteFilePath(QLatin1String(CREDIANTIALS_FILE));
		saveCrediantials(credFile, passphrase, tmpConfig);	// ���Դ���
	}

	if (existIndex != -1) // ����, ɾ��, ��������
		configList.removeAt(existIndex);
	configList.append(tmpConfig);

	std::sort(this->configList.begin(), this->configList.end());		// ��������VPNConfig

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
	if (!configDir.exists(fileName)) { // ���ɿյĸ߼������ļ�
		QFile advConfigFile(fileName);
		advConfigFile.open(QIODevice::Text | QIODevice::WriteOnly);
		advConfigFile.close();
	}
	return true;
}

bool VPNConfigManagerServant::createLogFile(const QDir& configDir) const
{
	const QString fileName = QDir(configDir).absoluteFilePath(QLatin1String(VPN_LOG_FILE));
	if (!configDir.exists(fileName)) { // ���ɿյ���־�ļ�
		QFile logFile(fileName);
		logFile.open(QIODevice::Text | QIODevice::WriteOnly);
		logFile.close();
	}
	return true;
}

bool VPNConfigManagerServant::truncEdgeFile(const QDir& configDir) const
{
	const QString fileName = QDir(configDir).absoluteFilePath(QLatin1String(VPN_EDGE_FILE));
	if (configDir.exists(fileName)) { // ����Edge�ļ�
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
			readCrediantials(credFile, passphrase, config);	// ���Դ���
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
	out.setCodec("UTF-8"); // �����ļ�����UTF-8����

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
		// ����UDPЭ��ʱ�����������
//		out << "explicit-exit-notify " << QString::number(2) << "\n";
	}

	if (config.isAutoStart())
		out << "#? auto-start\n";

#ifdef _WIN32
	out << "ip-win32 adaptive\n";	// ���ͨ��DHCP����IPʧ��, ��ô��netsh�ٳ���һ��
#endif
	out << "remap-usr1 SIGTERM\n";
	out << "resolv-retry 0\n";
	// ����TCPЭ��ʱ�����������
//	out << "connect-retry-max 1\n";
	// ��Ҫʱ, �ɷ��������, ����vpn_adv.conf�ļ��е���ָ��
//	out << "register-dns\n";	// This is known to kick Windows into recognizing pushed DNS servers.
	out << "nobind\n";	// �ͻ�����������������
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
	cred.setKeyPassword(QByteArray());	// ˽Կ�������벻����, ÿ�β�α�����������
	cred.setOtp(QLatin1String(""));		// һ�������벻��Ҫ����
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
			// ; ��ʼ��������ע��
			return false;
		else if (name.startsWith(QLatin1Char('#')) && !name.startsWith(QLatin1String("#?"))) {
			// #? ����������, ����ע��
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
	in.setCodec("UTF-8"); // �����ļ�����UTF-8����

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
				// noError = false;	// ��������ѡ��
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
			// noError = false;	// ��������ѡ��
		}

		if (!noError)
			qDebug() << "parse option line fail\n" << line;
	}

	configFile.close();

	config.setServerEndpoints(remotes);
	
	// ���ڶ��tls�汾ʱ��ʾ�Զ�Э��tls�汾
	config.setTlsVersion(tlsVersionList.size() == 1 ? tlsVersionList.at(0) : QLatin1String(""));
	// ���ڶ��cipherʱ��ʾ�Զ�Э��cipher
	config.setCipher(cipherList.size() == 1 ? cipherList.at(0) : QLatin1String(""));
	// ���ڶ��authʱ��ʾ�Զ�Э��auth
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
