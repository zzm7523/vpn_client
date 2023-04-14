TARGET = vpn_client
TEMPLATE = app
CONFIG += c++11 qt
QT += core widgets network

DEFINES += QUAZIP_STATIC _UNICODE __STDC_FORMAT_MACROS

QMAKE_CXXFLAGS_DEBUG += -D_DEBUG

win32::QMAKE_LFLAGS += /NODEFAULTLIB:"msvcrt.lib"

HEADERS = preferences.h \
    appinfo.h \
    accessible_resource_dialog.h \
    user_pass_dialog.h \
    passphrase_dialog.h \	
    single_application.h \
    vpn_item.h \
    vpn_log_dialog.h \
    settings.h \
    vpn_config_dialog.h \
    vpn_context.h \
    vpn_tunnel_detail.h \	
    change_password_dialog.h \
    change_pin_dialog.h \
    option_dialog.h \	
    select_certificate.h \
    trust_certificate.h \
    certificate_detail.h \
    select_pkcs12_dialog.h \
    manage_certificate.h \
    vpn_input_agent_servant.h \	
    vpn_observer_servant.h \
    command_line_parser.h \
    widgets/distname.h \
    widgets/waiting_spinner_widget.h \
    policy/policy_engine_i.h \
    policy/policy_engine_i_proxy.h \
    policy/policy_engine_i_skeleton.h \
    policy/policy.h \
    policy/cluster_policy.h \
    policy/password_policy.h \
    policy/resource_policy.h \
    policy/update_policy.h \
    policy/terminal_bind_policy.h \	
    policy/encrypt_device_remove_policy.h \
    policy/policy_engine_servant.h \
    config/config.h \
    config/version.h \
    common/common.h \
    common/progress_dialog.h \
    common/dialog_util.h \
    common/message_box_util.h \	
    common/translate.h \	
    common/credentials.h \
    common/passphrase_generator.h \
    common/process_util.h \
    common/generic_result.h \
    common/server_endpoint.h \
    common/server_endpoint_selector.h \
    common/x509_certificate_info.h \
    common/zip_util.h \	
    common/file_util.h \
    common/cipher.h \
    common/x509_name.h \
    common/x509v3_ext.h \
    common/asn1_int.h \	
    common/pkcs12_util.h \		
    common/x509_certificate_util.h \
    common/system_info.h \
    common/accessible_resource.h \
    common/proxy.h \
    common/locator.h \		
    common/connection.h \
    common/request_dispatcher.h \
    common/vpn_config.h \
    common/vpn_edge.h \
    common/vpn_statistics.h \	
    common/vpn_config_manager_i.h \
    common/vpn_config_manager_i_proxy.h \
    common/vpn_config_manager_i_skeleton.h \		
    common/vpn_i.h \
    common/tapdriver_manager_i.h \
    common/vpn_i_proxy.h \
    common/vpn_i_skeleton.h \
    common/encrypt_device_manager.h \
    common/tapdriver_manager.h \	
    common/tapdriver_manager_i_proxy.h \	
    common/tapdriver_manager_i_skeleton.h \
    common/miscellaneous_service_i.h \	
    common/miscellaneous_service_i_proxy.h \	
    common/miscellaneous_service_i_skeleton.h \	
    common/tls_auth.h \
    common/ticket.h \
    common/context.h

SOURCES = main.cpp \
    command_line_parser.cpp \
    preferences.cpp \
    appinfo.cpp \
    accessible_resource_dialog.cpp \
    user_pass_dialog.cpp \
    passphrase_dialog.cpp \	
    single_application.cpp \
    vpn_item.cpp \
    vpn_log_dialog.cpp \
    settings.cpp \
    vpn_config_dialog.cpp \
    vpn_context.cpp \
    vpn_tunnel_detail.cpp \	
    change_password_dialog.cpp \
    change_pin_dialog.cpp \
    option_dialog.cpp \
    select_certificate.cpp \
    trust_certificate.cpp \	
    certificate_detail.cpp \
    select_pkcs12_dialog.cpp \
    manage_certificate.cpp \	
    vpn_input_agent_servant.cpp \
    vpn_observer_servant.cpp \
    widgets/distname.cpp \
    widgets/waiting_spinner_widget.cpp \
    policy/policy_engine_i.cpp \
    policy/policy_engine_i_proxy.cpp \
    policy/policy_engine_i_skeleton.cpp \
    policy/policy.cpp \
    policy/cluster_policy.cpp \
    policy/password_policy.cpp \
    policy/resource_policy.cpp \
    policy/update_policy.cpp \
    policy/terminal_bind_policy.cpp \		
    policy/encrypt_device_remove_policy.cpp \
    policy/policy_engine_servant.cpp \		
    common/common.cpp \
    common/progress_dialog.cpp \
    common/dialog_util.cpp \	
    common/message_box_util.cpp \	
    common/translate.cpp \	
    common/credentials.cpp \
    common/passphrase_generator.cpp \
    common/process_util.cpp \
    common/generic_result.cpp \
    common/server_endpoint.cpp \
    common/server_endpoint_selector.cpp \
    common/x509_certificate_info.cpp \
    common/zip_util.cpp \	
    common/file_util.cpp \
    common/cipher.cpp \
    common/x509_name.cpp \
    common/x509v3_ext.cpp \
    common/asn1_int.cpp \	
    common/pkcs12_util.cpp \		
    common/x509_certificate_util.cpp \
    common/system_info.cpp \
    common/accessible_resource.cpp \
    common/locator.cpp \	
    common/connection.cpp \
    common/request_dispatcher.cpp \
    common/vpn_config.cpp \	
    common/vpn_edge.cpp \
    common/vpn_statistics.cpp \		
    common/vpn_config_manager_i_proxy.cpp \
    common/vpn_config_manager_i_skeleton.cpp \			
    common/vpn_i.cpp \
    common/vpn_i_proxy.cpp \
    common/vpn_i_skeleton.cpp \
    common/encrypt_device_manager.cpp \
    common/tapdriver_manager.cpp \		
    common/tapdriver_manager_i_proxy.cpp \
    common/tapdriver_manager_i_skeleton.cpp \
    common/miscellaneous_service_i_proxy.cpp \	
    common/miscellaneous_service_i_skeleton.cpp \	
    common/tls_auth.cpp \
    common/ticket.cpp \
    common/context.cpp
	
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

#unix:LIBS += -ldl -lcrypto -lquazip1-qt5 -lz
unix:LIBS += -ldl -lquazip1-qt5 -lz $${DESPICABLE_ME}/gm-openssl-1.0.1/${BUILD_DEBUG_TARGET}/libcrypto.a

RESOURCES = vpn_client.qrc

FORMS += preferences.ui \
    common/progress_dialog.ui \
    appinfo.ui \
    accessible_resource_dialog.ui \
    user_pass_dialog.ui \
    passphrase_dialog.ui \
    vpn_config_dialog.ui \
    vpn_tunnel_detail.ui \	
    vpn_log_dialog.ui \
    change_password_dialog.ui \
    change_pin_dialog.ui \
    option_dialog.ui \
    select_certificate.ui \
    trust_certificate.ui \
    certificate_detail.ui \
    select_pkcs12_dialog.ui \
    manage_certificate.ui
	
RC_FILE = vpn_client.rc

TRANSLATIONS  = vpn_client_zh_CN.ts
