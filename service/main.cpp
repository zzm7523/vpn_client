#include "../config/config.h"

#include <QApplication>
#include <QString>
#include <QDir>
#include <QDebug>
#include <iostream>

/*
#ifdef _DEBUG
#include <vld.h>
#endif
*/

#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef ENABLE_GUOMI
#include <openssl/encrypt_device.h>
#endif

#include "../common/common.h"
#include "../common/process_util.h"
#include "../common/system_info.h"
#include "miscellaneous_service_servant.h"
#include "service.h"

static void processArgs(int argc, char **argv)
{
	bool exitApplication = false;
	QString localAppData;	

	for (int i = 0; i < argc; ++i) {
		if (strcmp("-vv", argv[i]) == 0) {
			std::cout << VPN_SERVICE_VER_PRODUCTNAME_STR << std::endl;
			std::cout << VPN_SERVICE_VER_FILEVERSION_STR << std::endl;
			exitApplication = true;
			break;
		} else if (strcmp("-gt", argv[i]) == 0 || strcmp("-generate", argv[i]) == 0) {
			if (i + 1 < argc)
				localAppData = QLatin1String(argv[i + 1]);
			exitApplication = true;
			break;
		}
	}

	if (!localAppData.isEmpty()) {
		Context ctx = Context::getDefaultContext();
		MiscellaneousServiceServant miscSrvServant(QLatin1String("MiscellaneousServiceI:single"));
		const QString fingerprint = miscSrvServant.generateFingerprint(ctx);
		if (!fingerprint.isEmpty()) {
			const QString appSaveDir = QDir(localAppData).absoluteFilePath(VPN_CONFIG_DIR_NAME);
			miscSrvServant.saveFingerprint(QDir(appSaveDir).absoluteFilePath(FINGERPRINT_FILE), fingerprint, ctx);
		}
	}	

	if (exitApplication) {
		::exit(0);
	}
}

int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();
#ifdef ENABLE_GUOMI
	ECDSA_set_default_method(ECDSA_sm2());
#endif

	processArgs(argc, argv);
	
	Service vpnservice(argc, argv);
	int ret = vpnservice.exec();

	ERR_free_strings();
	EVP_cleanup();

	return ret;
}
