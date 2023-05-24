#ifndef _PLUGINS_SAVAPI_PLG_H__
#define _PLUGINS_SAVAPI_PLG_H__
/**
 * @mainpage SAVAPI-Plugins' Interface
 *
 * @section intro Introduction
 *
 *    In order to coupe with a continously increasing customization demand Savapi allows to extend its functionality through
 *  external modules called "plugins".
 *
 *    The Savapi plugins interface is described in the sections below
 *
 * @section plg_desc Plugin Description
 *
 *  A plugin:
 *  - will be loaded and initialized by Savapi
 *  - can export multiple interfaces, identified by unique ids
 *  - must be reentrant and be able to build an arbitrary number of instances
 *
 * @section how_to HowTo SAVAPI plugin
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup plg_defines Plugin defines
 * @{
 */
#ifdef _WINDOWS
/** On WINDOWS we need to export the symbols */
#    define SAVAPI_PLG_EXP __declspec(dllexport)
#    ifndef CC
#       define CC _cdecl
#    endif /* CC */
#else  /* UNIXes */
#    define SAVAPI_PLG_EXP
#    ifndef CC
#       define CC /* calling convention may not be defined on unix */
#    endif /* CC */
#endif /* _WINDOWS */

#ifdef _WINDOWS
    #include <tchar.h>
    #define SAVAPI_PLG_tchar_t TCHAR
#else  /* UNIXes - using Utf8 encoding */
    #define SAVAPI_PLG_tchar_t char
    #define _T(x) x
#endif /* _WINDOWS */

/**
 * @brief Defines the maximum size for the plugin's information fields
 */
#define SAVAPI_PLG_MAX_STR       1024
#define SAVAPI_PLG_MAX_VER_STR     64

#define SAVAPI_PLG_VER_MAJ          0   /** Savapi's plugins interface major version */
#define SAVAPI_PLG_VER_MIN          1   /** Savapi's plugins interface minor version */

/**
 * @}
 * @defgroup plg_status Plugin return statuses
 *
 * @brief This statuses are returned by the plugin routines
 * @{
 */
#define SAVAPI_EPLG_SUCCESS         0   /** Operation ended with success             */
#define SAVAPI_EPLG_UKNW_INTERFACE  1   /** The requested interface is not supported */
#define SAVAPI_EPLG_INVAL           2   /** An invalid parameter has been provided   */
#define SAVAPI_EPLG_INIT            3   /** Plugin or instance already initialized   */
#define SAVAPI_EPLG_NO_MEM          4   /** Memory allocation error                  */
#define SAVAPI_EPLG_INTERNAL        5   /** An internal error occurred               */

/**
 * @}
 * @defgroup plg_spec_typedefs Plugin's specific typedefs
 *
 * @remark Specific definition of this types are found in the specific header of each plugin.
 * @{
 */
typedef void SAVAPI_PLG_options_t;       /** plugin's global init data   */
typedef void SAVAPI_PLG_inst_options_t;  /** plugin's instance init data */
typedef void SAVAPI_PLG_instance_t;      /** plugin's instance           */

/**
 * @}
 * @defgroup plg_typedefs Plugin's general typedefs
 * @{
 */

/**
 * @brief Plugin's return codes type
 */
typedef int SAVAPI_PLG_status_t;
/**
 * @brief Prototype for a plugin's initialize function
 */
typedef SAVAPI_PLG_status_t (CC *SAVAPI_PLG_init_t) (const SAVAPI_PLG_options_t *options);
/**
 * @brief Prototype for a plugin's uninitialize function
 */
typedef void (CC *SAVAPI_PLG_uninit_t) ();
/**
 * @brief Prototype for a plugin's instance create function
 */
typedef SAVAPI_PLG_status_t (CC *SAVAPI_PLG_instance_create_t) (SAVAPI_PLG_instance_t **instance, const SAVAPI_PLG_tchar_t *interface_id, const SAVAPI_PLG_inst_options_t *options);
/**
 * @brief Prototype for a plugin's instance destroy function
 */
typedef void (CC *SAVAPI_PLG_instance_release_t) (SAVAPI_PLG_instance_t **instance);

/**
 * @}
 * @defgroup plg_structs Plugin's structures definitions
 * @{
 */

/**
 * @brief Structure containing the plugin's information (name, version etc.)
 */
typedef struct _SAVAPI_PLG_info_t
{
    /** Global related routines */
    SAVAPI_PLG_init_t   init;                                /** global init                                                       */
    SAVAPI_PLG_uninit_t uninit;                              /** global uninit                                                     */
    /** Instance related routines */
    SAVAPI_PLG_instance_create_t  instance_create;           /** instance create                                                   */
    SAVAPI_PLG_instance_release_t instance_release;          /** instance release                                                  */
    /** Version related fields */
    int interface_ver_maj;                                   /** interface major version. Should be set to \ref SAVAPI_PLG_VER_MAJ */
    int interface_ver_min;                                   /** interface minor version. Should be set to \ref SAVAPI_PLG_VER_MIN */
    SAVAPI_PLG_tchar_t name[SAVAPI_PLG_MAX_STR];             /** friendly name                                                     */
    SAVAPI_PLG_tchar_t version[SAVAPI_PLG_MAX_VER_STR];      /** plugin's version                                                  */
    void *res;                                               /** reserved for future use                                           */
} SAVAPI_PLG_info_t;

/**
 * @brief Main function that must be exported by the plugin
 */
typedef SAVAPI_PLG_status_t (CC *SAVAPI_PLG_main_t)(const SAVAPI_PLG_info_t **savapi_plg_info);

#define SAVAPI_PLG_MAIN_FUNC       savapi_plg_main
SAVAPI_PLG_EXP SAVAPI_PLG_status_t CC SAVAPI_PLG_MAIN_FUNC(const SAVAPI_PLG_info_t **plg_info);

/**
 *
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _PLUGINS_SAVAPI_PLG_H__ */
