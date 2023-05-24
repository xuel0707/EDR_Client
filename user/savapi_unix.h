#ifndef SAVAPI_UNIX_H_
#define SAVAPI_UNIX_H_

/**
 * This header is a wrapper over savapi.h and should be included instead of savapi.h on UNIX
 * platforms when using char* instead of SAVAPI_TCHAR* in SAVAPI structures and functions
 * \note: When using this header, there will be no need for string conversions (CharToSTCHAR or STCHARToChar)
 */

#define _SAVAPI_UTF8

/*
 * _SAVAPI_DIVERT_STRING_API is for internal use only, please do not define it
 */
#ifndef _SAVAPI_DIVERT_STRING_API
    #define SAVAPI_set_log_callback         SAVAPI_set_log_callback_unix
    #define SAVAPI_initialize               SAVAPI_initialize_unix
    #define SAVAPI_set_quickload_init       SAVAPI_set_quickload_init_unix
    #define SAVAPI_uninitialize             SAVAPI_uninitialize_unix
    #define SAVAPI_APC_initialize           SAVAPI_APC_initialize_unix
    #define SAVAPI_APC_uninitialize         SAVAPI_APC_uninitialize_unix
    #define SAVAPI_get_version              SAVAPI_get_version_unix
    #define SAVAPI_engine_versions_get      SAVAPI_engine_versions_get_unix
    #define SAVAPI_APC_get_version          SAVAPI_APC_get_version_unix
    #define SAVAPI_create_instance          SAVAPI_create_instance_unix
    #define SAVAPI_release_instance         SAVAPI_release_instance_unix
    #define SAVAPI_set_user_data            SAVAPI_set_user_data_unix
    #define SAVAPI_get_user_data            SAVAPI_get_user_data_unix
    #define SAVAPI_is_running_ex            SAVAPI_is_running_ex_unix
    #define SAVAPI_register_callback        SAVAPI_register_callback_unix
    #define SAVAPI_unregister_callback      SAVAPI_unregister_callback_unix
    #define SAVAPI_scan                     SAVAPI_scan_unix
    #define SAVAPI_set                      SAVAPI_set_unix
    #define SAVAPI_get                      SAVAPI_get_unix
    #define SAVAPI_send_signal              SAVAPI_send_signal_unix
    #define SAVAPI_set_fops                 SAVAPI_set_fops_unix
    #define SAVAPI_get_fops                 SAVAPI_get_fops_unix
    #define SAVAPI_free                     SAVAPI_free_unix
    #define SAVAPI_reload_engine_ex         SAVAPI_reload_engine_ex_unix
    #define SAVAPI_extract_malware_names    SAVAPI_extract_malware_names_unix
    #define SAVAPI_engine_modules_get       SAVAPI_engine_modules_get_unix
    #define SAVAPI_global_set               SAVAPI_global_set_unix
    #define SAVAPI_get_dynamic_detect       SAVAPI_get_dynamic_detect_unix
    #define SAVAPI_simple_scan              SAVAPI_simple_scan_unix
    #define SAVAPI_FPC_disable_preinit      SAVAPI_FPC_disable_preinit_unix
#endif

#include "savapi.h"

#endif /* SAVAPI_UNIX_H_ */
