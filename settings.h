#ifndef __SETTINGS_H__
#define __SETTINGS_H__

#include "config/config.h"

#include <QString>
#include <QDateTime>

#include "common/common.h"

class Settings
{
public:
	static Settings* instance();

	void load(const QString& appDirPath, const QString& appSavePath);

	const QString& getAppDirPath() const;
	const QString& getAppSavePath() const;
	const QString& getCAFileName() const;

	const QString& getLanguage() const;
	void setLanguage(const QString& language);

	const QString& getLastAccessPath() const;
	void setLastAccessPath(const QString& path);

	const QString& getLastProviderName() const;
	void setLastProviderName(const QString& lastProviderName);

	const QDateTime& getLastCheckUpdate() const;
	void setLastCheckUpdate(const QDateTime& lastCheckUpdate);

	bool isCheckUpdate() const;
	void setCheckUpdate(bool flag);

	bool isAutoReconnect() const;
	void setAutoReconnect(bool flag);

	bool isAutoMinimum() const;
	void setAutoMinimum(bool flag);

	bool isShowBallonMessage() const;
	void setShowBallonMessage(bool flag);

	bool isShowToolbar() const;
	void setShowToolbar(bool flag);

	bool isShowStatusBar() const;
	void setShowStatusBar(bool flag);

	bool isAutoStartOnWindowsStartup() const;
	void setAutoStartOnWindowsStartup(bool flag);

	bool isSaveCredential() const;
	void setSaveCredential(bool flag);

	bool isPopupAccessibleResource() const;
	void setPopupAccessibleResource(bool flag);

private:
	Settings();

	QString appDirPath;
	QString appSavePath;

	QString iniPath;
	QString caFileName;
	QString language;
	QString lastAccessPath;
	// 最近插入的设备提供者, 一般来讲用户总是使用同一把Key
	QString lastProviderName;

	QDateTime lastCheckUpdate;
	bool checkUpdate;

	bool showToolbar;
	bool showStatusBar;
	bool showBallonMessage;
	bool autoReconnect;
	bool autoMinimum;
	bool saveCredential;
	bool popupAccessibleResource;

};

#endif
