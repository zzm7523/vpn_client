TARGET = vpn_service
TEMPLATE = app
CONFIG += c++11 console qt
QT = core widgets network

DEFINES += QUAZIP_STATIC _UNICODE __STDC_FORMAT_MACROS

QMAKE_CXXFLAGS_DEBUG += -D_DEBUG

win32::QMAKE_LFLAGS_DEBUG += /NODEFAULTLIB:"msvcrt.lib"

SOURCES = main.cpp \
    service.cpp \
    vpn_log_parser.cpp \
    vpn_agent_servant.cpp \
    vpn_config_manager_servant.cpp \
    tapdriver_manager_servant.cpp \
    miscellaneous_service_servant.cpp \	
    ../policy/policy_engine_i.cpp \
    ../policy/policy_engine_i_proxy.cpp \
    ../policy/policy_engine_i_skeleton.cpp \
    ../policy/policy.cpp \
    ../policy/cluster_policy.cpp \
    ../policy/password_policy.cpp \
    ../policy/resource_policy.cpp \
    ../policy/update_policy.cpp \
    ../policy/terminal_bind_policy.cpp \
    ../policy/encrypt_device_remove_policy.cpp \
    ../policy/policy_engine_servant.cpp \
    ../common/common.cpp \
    ../common/dialog_util.cpp \
    ../common/message_box_util.cpp \
    ../common/translate.cpp \	
    ../common/credentials.cpp \
    ../common/passphrase_generator.cpp \
    ../common/process_util.cpp \
    ../common/generic_result.cpp \
    ../common/server_endpoint.cpp \
    ../common/server_endpoint_selector.cpp \
    ../common/x509_certificate_info.cpp \
    ../common/file_util.cpp \
    ../common/zip_util.cpp \
    ../common/cipher.cpp \
    ../common/x509_name.cpp \
    ../common/x509v3_ext.cpp \
    ../common/asn1_int.cpp \
    ../common/pkcs12_util.cpp \	
    ../common/x509_certificate_util.cpp \
    ../common/system_info.cpp \
    ../common/accessible_resource.cpp \
    ../common/locator.cpp \	
    ../common/connection.cpp \
    ../common/request_dispatcher.cpp \
    ../common/vpn_config.cpp \
    ../common/vpn_edge.cpp \
    ../common/vpn_statistics.cpp \
    ../common/vpn_config_manager_i_proxy.cpp \
    ../common/vpn_config_manager_i_skeleton.cpp \
    ../common/vpn_i.cpp \
    ../common/vpn_i_proxy.cpp \
    ../common/vpn_i_skeleton.cpp \
    ../common/tapdriver_manager.cpp \
    ../common/tapdriver_manager_i_proxy.cpp \
    ../common/tapdriver_manager_i_skeleton.cpp \
    ../common/encrypt_device_manager.cpp \
    ../common/miscellaneous_service_i_proxy.cpp \
    ../common/miscellaneous_service_i_skeleton.cpp \
    ../common/tls_auth.cpp \
    ../common/ticket.cpp \
    ../common/context.cpp

include(src/qtservice.pri)

HEADERS += service.h \
    vpn_log_parser.h \
    vpn_agent_servant.h \
    vpn_config_manager_servant.h \
    tapdriver_manager_servant.h \
    miscellaneous_service_servant.h \
    ../policy/policy_engine_i.h \
    ../policy/policy_engine_i_proxy.h \
    ../policy/policy_engine_i_skeleton.h \
    ../policy/policy.h \
    ../policy/cluster_policy.h \
    ../policy/password_policy.h \
    ../policy/resource_policy.h \
    ../policy/update_policy.h \
    ../policy/terminal_bind_policy.h \
    ../policy/encrypt_device_remove_policy.h \
    ../policy/policy_engine_servant.h \
    ../config/config.h \
    ../config/version.h \
    ../common/common.h \
    ../common/dialog_util.h \
    ../common/message_box_util.h \
    ../common/translate.h \	
    ../common/credentials.h \
    ../common/passphrase_generator.h \
    ../common/process_util.h \
    ../common/generic_result.h \
    ../common/server_endpoint.h \
    ../common/server_endpoint_selector.h \
    ../common/x509_certificate_info.h \
    ../common/file_util.h \
    ../common/zip_util.h \
    ../common/cipher.h \
    ../common/x509_name.h \
    ../common/x509v3_ext.h \
    ../common/asn1_int.h \
    ../common/pkcs12_util.h \
    ../common/x509_certificate_util.h \
    ../common/system_info.h \
    ../common/accessible_resource.h \
    ../common/proxy.h \
    ../common/locator.h \
    ../common/connection.h \
    ../common/request_dispatcher.h \
    ../common/vpn_config.h \
    ../common/vpn_edge.h \
    ../common/vpn_statistics.h \
    ../common/vpn_config_manager_i.h \
    ../common/vpn_config_manager_i_proxy.h \
    ../common/vpn_config_manager_i_skeleton.h \
    ../common/vpn_i.h \
    ../common/tapdriver_manager.h \
    ../common/tapdriver_manager_i.h \
    ../common/vpn_i_proxy.h \
    ../common/vpn_i_skeleton.h \
    ../common/tapdriver_manager_i_proxy.h \
    ../common/tapdriver_manager_i_skeleton.h \
    ../common/encrypt_device_manager.h \
    ../common/miscellaneous_service_i.h \
    ../common/miscellaneous_service_i_proxy.h \
    ../common/miscellaneous_service_i_skeleton.h \
    ../common/tls_auth.h \
    ../common/ticket.h \
    ../common/context.h

win32::DESPICABLE_ME = D:/private_my_work/despicable_me

win32::INCLUDEPATH += $${DESPICABLE_ME}/gm-openssl-1.0.1/inc64
win32::INCLUDEPATH += $${DESPICABLE_ME}/zlib-1.2.8
win32::INCLUDEPATH += $${DESPICABLE_ME}/quazip-0.7.1
win32::INCLUDEPATH += $${DESPICABLE_ME}/email-tools/sendemailapi

win32::LIBPATH += $${DESPICABLE_ME}/gm-openssl-1.0.1/out64_debug
win32::LIBPATH += $${DESPICABLE_ME}/zlib-1.2.8
win32::LIBPATH += $${DESPICABLE_ME}/quazip-0.7.1/x64/Debug
win32::LIBPATH += $${DESPICABLE_ME}/email-tools/release

win32::LIBS += gdi32.lib Advapi32.lib crypt32.lib ws2_32.lib shell32.lib Iphlpapi.lib psapi.lib Version.lib libeay32.lib ssleay32.lib zlib.lib quazip.lib

unix::DESPICABLE_ME = /home/zzy/despicable_me/trunk

unix::INCLUDEPATH += $${DESPICABLE_ME}/gm-openssl-1.0.1/include
unix::INCLUDEPATH += $${DESPICABLE_ME}/zlib-1.2.11
unix::INCLUDEPATH += $${DESPICABLE_ME}/quazip-1.1

unix::LIBPATH += $${DESPICABLE_ME}/gm-openssl-1.0.1/${BUILD_DEBUG_TARGET}
unix::LIBPATH += $${DESPICABLE_ME}/zlib-1.2.11/${BUILD_RELEASE_TARGET}
unix::LIBPATH += $${DESPICABLE_ME}/quazip-1.1/${BUILD_RELEASE_TARGET}

unix:LIBS += -ldl -lquazip1-qt5 -lz $${DESPICABLE_ME}/gm-openssl-1.0.1/${BUILD_DEBUG_TARGET}/libcrypto.a

FORMS += 

RC_FILE = service.rc

RESOURCES = service.qrc

TRANSLATIONS  = service_zh_CN.ts

