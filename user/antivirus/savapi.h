#ifndef SAVAPI_H__
#define SAVAPI_H__

#include "savapi_errors.h"
#include "stchar.h"

/**
 * \mainpage SAVAPI
 *
 * SAVAPI stands for Secure AntiVirus Application Programming Interface.
 * Its main purpose is to offer a very simple scanning interface for clients who want
 * to programmatically integrate scanning services into their applications.
 *
 * This document explains how to use the SAVAPI interface shared libraries written and provided
 * by Avira Operations GmbH & Co. KG.
 * The provided LICENSE file explains the terms and conditions
 * for using the SAVAPI interface shared libraries.
 *
 * By utilizing the implemented SAVAPI interface, it becomes
 * very simple to quickly integrate SAVAPI into your applications.
 * There is no need to be concerned about protocol details,
 * since they have all been implemented by Avira Operations GmbH & Co. KG.
 *
 * See: \ref defs "SAVAPI options", \ref defs "SAVAPI constants", \ref defs "SAVAPI defines",
 * \ref structs "SAVAPI structures", \ref funcs "SAVAPI functions"
 *
 */

/**
 * \defgroup defs SAVAPI constants
 * \{
 *
 * \defgroup api_version API version
 * \note The API version must be passed to the \ref SAVAPI_GLOBAL_INIT structure and is used to
 *       ensure compatibility between the API used by the library and the API used by the application
 *       which integrates the library.
 *
 *       Examples of API compatibility:
 *
 *       Version used by application | Version used by library | Status
 *       --------------------------- | ----------------------- | ------
 *       4.0                         | 4.0                     | OK
 *       4.0                         | 4.1                     | OK
 *       4.1                         | 4.0                     | Error
 *       3.6                         | 4.0                     | Error
 *       4.0                         | 3.6                     | Error
 *
 * \{
 */

/**
 * \brief Major API version
 * \note This version must match exactly the version used by the library, otherwise SAVAPI library will not initialize
 */
#define SAVAPI_API_MAJOR_VERSION    5
/**
 * \brief Minor API version
 * \note This version indicates which subset of features the API provides.
 * \note The version used by the library must be at least as high as this version.
 */
#define SAVAPI_API_MINOR_VERSION    5

/**
 * \}
 * \brief Macro to be used when loading a SAVAPI symbol while using dynamic linking
 * \note When using dynamic linking, it is strongly recommended to use the SAVAPI_SYMBOL
 *       macro for loading a symbol, instead of the plain function name
 *       Check the lib_loadlibrary_example for implementation details
 */
#define SAVAPI_SYMBOL(s) STR(s)
#define STR(s) #s

/**
 * \}
 * \ingroup defs
 * \defgroup error_cat Error or information categories
 * \note Used by the error callbacks to categorize the errors or the information they return
 * \{
 */
/** i/o error category */
#define SAVAPI_ECAT_ERROR_IO                           0
/** scan error category */
#define SAVAPI_ECAT_ERROR_SCAN                         1
/** unpack error category */
#define SAVAPI_ECAT_ERROR_UNPACK                       2
/** uncategorized error category */
#define SAVAPI_ECAT_ERROR_GENERIC                      3
/** APC report ttl category */
#define SAVAPI_ECAT_APC_REPORT_TTL                     4

/**
 * \}
 * \ingroup defs
 * \defgroup error_level Error levels
 * \note Used by the error callbacks to categorize the returned errors
 * \{
 */
/** error level */
#define SAVAPI_ELEVEL_ERROR                            0
/** warning level */
#define SAVAPI_ELEVEL_WARNING                          1
/** info level */
#define SAVAPI_ELEVEL_INFO                             2

/**
 * \}
 * \ingroup defs
 * \defgroup init_flags Initialization flags
 * \note Initialization flags will be extended on the fly when needed!
 *       The SAVAPI_FLAG_USE_TCP and SAVAPI_FLAG_USE_LOCAL_SOCKET must not be set
 *       simultaneously
 * \{
 */
/** TCP sockets will be used for communication (SAVAPI client-mode only) */
#define SAVAPI_FLAG_USE_TCP                    1
/** local sockets will be used for communication (SAVAPI client-mode only) */
#define SAVAPI_FLAG_USE_LOCAL_SOCKET           2

/**
 * \}
 * \ingroup defs
 * \defgroup scan_warnings Scan warnings
 * \note Warnings that can be received during the scanning process
 * \{
 */
/** File has potentially been damaged by virus */
#define SAVAPI_W_DAMAGED                       1
/** OLE-File is potentially damaged */
#define SAVAPI_W_OLE_DAMAGED                   2
/** File is suspicious */
#define SAVAPI_W_SUSPICIOUS                    4
/** An abort was triggered by the progress callback */
#define SAVAPI_W_PROGRESS_ABORT                8
/** A malformed archive header was detected */
#define SAVAPI_W_HEADER_MALFORMED              16
/**
 * This file could be an archive bomb, ratio
 * might be exceeded or something else might
 * have happened to trigger that detection
 */
#define SAVAPI_W_POTENTIAL_ARCH_BOMB           32
/** The ratio set by the application regarding unpacking size in archives has been exceeded */
#define SAVAPI_W_RATIO_EXCEEDED                64
/** Unpacking has reached the maximum limit of extracted data */
#define SAVAPI_W_MAX_EXTRACTED                 128

/**
 * \}
 * \ingroup defs
 * \defgroup iframes_info Iframes informations
 * \note Informations that can be received during the scanning process
 * \note These options are deprecated
 * \{
 */
/** The object is invisible to the user surfing the site */
#define SAVAPI_HTML_CONTENT_ATTRIB_INVISIBLE  1
/** The object is very small and as such almost invisible to the user surfing the site */
#define SAVAPI_HTML_CONTENT_ATTRIB_EXTRASMALL 2
/** The object is inserted at a very uncommon position in the HTML code */
#define SAVAPI_HTML_CONTENT_ATTRIB_ODDPOS     4
/** The object is likely of a malicious nature */
#define SAVAPI_HTML_CONTENT_ATTRIB_MALICIOUS  8

/**
 * \}
 * \ingroup defs
 * \defgroup scan_info Scan information
 * \note Information that can be received during the scanning process
 * \{
*/
/** OLE: file is a compound doc (OLE2) */
#define SAVAPI_I_OLEFILE                       1
/** OLE: contains a word template */
#define SAVAPI_I_TEMPLATE                      2
/** OLE: contains macros */
#define SAVAPI_I_MACROS_PRESENT                4
/** OLE: all macros were deleted - this flag is deprecated */
#define SAVAPI_I_ALL_MACROS_DELETED            8
/** OLE: encrypted marker, only for DOCs */
#define SAVAPI_I_OLE_ENCRYPTED                 16
/** SCRIPT: html contains active content (JS/VBS, etc.) - this flag is deprecated */
#define SAVAPI_I_ACTIVE_CONTENT_PRESENT        32
/** ARCHIVE: Mailbox detected */
#define SAVAPI_I_MAILBOX                       64
/** OLE: contains macros with autostart enabled */
#define SAVAPI_I_MACRO_AUTOSTART               128
/** APC: report an estimation time (in seconds) until a response will be available from the APC
 *  \note The estimation for an APC scan may be updated by several calls with this information
 */
#define SAVAPI_I_APC_SCAN_DURATION             256
/** APC: report the time (in seconds) after which an APC detection result expires */
#define SAVAPI_I_APC_RESULT_EXPIRY             512

/**
 * \}
 * \defgroup options SAVAPI options
 * \{
 *
 * \remark
 * Almost each option used to configure the SAVAPI instance (the paths to the temporary
 * folders, the scanning options) has a default value that is written in its description
 * as a note (i.e. Default value: \<value\>).
 * \remark
 * In client-mode, the default values are dependent to the configuration used to start
 * the SAVAPI service, so the provided defaults only applies in library-mode!!!
 * \remark
 * The options that has no default (i.e. unsupported options, obsolete, ignored) will be marked
 * with the "Default value: None" string.
 */

typedef enum SAVAPI_option
{
    /*
     * GET/SET options (read/write)
     * "SET" requests are available to configure SAVAPI. For the following requests,
     * a "GET" counterpart is also available and these are therefore labeled as
     * "read/write". Only the "SET" version is listed here although a "GET" version
     * also exists. The "GET" response will return the same data that is provided
     * with the "SET" request (although the representation of the data may be
     * different. For example, a "SET" request with "10K" could lead to a "GET"
     * response with "10240".)
     */

    /**
     * \brief Specifies current working directory for SAVAPI.
     * \note This eliminates the need to specify full paths in filenames.
     * \note Available only in client-mode.
     * \note Default value: None
     */
    SAVAPI_OPTION_CWD = 1,
    /**
     * \brief Specifies the configuration file that is used.
     * \note The configuration file will be (re-)read as part of this request.
     * \note Available only in client-mode.
     * \note Default value: None
     */
    SAVAPI_OPTION_CONF,
    /**
     * \brief Activates archive detection and scanning.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_ARCHIVE_SCAN,

    /**
     * \brief Set the maximum allowed size (in bytes) for any file within an archive.
     * \note A value of "0" means the maximum allowed value (INT64_MAX bytes).
     * \note This setting has no meaning if ARCHIVE_SCAN is deactivated.
     * \note Default value: 1073741824 (1G)
     */
    SAVAPI_OPTION_ARCHIVE_MAX_SIZE,
    /**
     * \brief Set the maximum allowed recursion within an archive.
     * \note A value of "0" means the maximum allowed value (1000 recursion levels).
     * \note This setting has no meaning if ARCHIVE_SCAN is deactivated.
     * \note Default value: 200
     */
    SAVAPI_OPTION_ARCHIVE_MAX_REC,
    /**
     * \brief Set the maximum allowed decompressing-ratio within an archive.
     * \note A value of "0" means the maximum allowed value (INT32_MAX).
     * \note This setting has no meaning if ARCHIVE_SCAN is deactivated.
     * \note Default value: 150
     */
    SAVAPI_OPTION_ARCHIVE_MAX_RATIO,
    /**
     * \brief Set the maximum allowed number of files within an archive.
     * \note A value of "0" means the maximum allowed value (INT64_MAX).
     * \note This setting has no meaning if ARCHIVE_SCAN is deactivated.
     * \note Default value: 0
     */
    SAVAPI_OPTION_ARCHIVE_MAX_COUNT,
    /**
     * \brief Activates detection and scanning of mailboxes.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_MAILBOX_SCAN,
    /**
     * \brief Activates heuristic macro detection
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_HEUR_MACRO,
    /**
     * \brief Set the heuristic level for the engine. The available levels are:
     * - 0 - Disable heuristic detection.
     * - 1 - Lazy heuristic detection. This is the lowest possible mode, detection
     *     is not very good, but the false positives number will be low.
     * - 2 - Normal heuristic detection.
     * - 3 - High heuristic detection. This is the highest possible mode, but the false
     *     positives number will be high.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_HEUR_LEVEL,
    /**
     * \brief Set the temporary directory used for scanning files.
     * \note SAVAPI may use other temporary directories for files that are not being scanned. These
     *       other directories can be specified with command-line arguments or in a configuration file.
     * \note Default value: The system temporary folder
     */
    SAVAPI_OPTION_SCAN_TEMP,
    /**
     * \brief Set the maximum number of seconds allowed to scan a file before aborting
     * \note Available values: 0 - 86400 (1 second - 24 hours)
     * \note Default value: 0 (no timeout)
     */
    SAVAPI_OPTION_SCAN_TIMEOUT,
    /**
     * \brief Activates the repairing of infected files
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_REPAIR,
    /**
     * \brief Activates the notification of reparable infected files
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_NOTIFY_REPAIR,
    /**
     * \brief Activates the detection of Microsoft Office OLE documents
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_NOTIFY_OFFICE,
    /**
     * \brief Activates the detection of macros within Microsoft Office OLE documents
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_NOTIFY_OFFICE_MACRO,
    /**
     * \brief Activates the notification of virus description url
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_NOTIFY_ALERTURL,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_DETECT_ADSPY,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_DETECT_APPL,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_DETECT_BDC,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_DETECT_DIAL,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_DETECT_GAME,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_DETECT_HIDDENEXT,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_DETECT_JOKE,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 0 (disabled)
     * \note This option is deprecated.
     */
    SAVAPI_OPTION_DETECT_PCK,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_DETECT_PHISH,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_DETECT_SPR,
    /**
     * \brief Activate IFRAME detection
     * \note Default value: 0 (disabled)
     * \note This option is deprecated.
     */
    SAVAPI_OPTION_IFRAMES_URL,
    /**
     * \brief Activate reporting of encrypted mails
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_REPORT_ENCRYPTED_MIME,
    /**
     * \brief Set the scanning method. Available options are:
     * - SMART   - Smart Extensions scan mode. The files scanned for malware are chosen by SAVAPI
     *             The choice is made based on the files content. This is the recommended setting.
     * - ALL     - All scan mode. Files are scanned for malware, no matter their content or extension.
     * - EXTLIST - Extensions List scan mode. Only files with specific extensions are scanned for
     *             malware content.
     * \note Default value: SMART
     */
    SAVAPI_OPTION_SCAN_MODE,
    /**
     * \brief Activate detection and scanning of mails
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_MIME_SCAN,
    /**
     * \brief Activate scanning and reporting of PGP encrypted files
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_PGP_SCAN,
    /**
     * \brief Activate regular interval messages during scanning to confirm that the
     * SAVAPI service is still alive
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_SCAN_PROGRESS,
    /**
     * \brief Activate detection for the ADWARE type.
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_DETECT_ADWARE,
    /**
     * \brief Activate detection for the PFS (possible fraudulent software) type.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_DETECT_PFS,
    /**
     * \brief This option is reserved and must not be used
     */
    SAVAPI_OPTION_RESERVED1,
    /**
     * \brief This option is reserved and must not be used
     */
    SAVAPI_OPTION_RESERVED2,
    /**
     * \brief Set the maximum number of seconds before an APC connection establish attempt times out
     * \note Available values: 0 - 86400 (1 second - 24 hours)
     * \note If 0, SAVAPI will wait indefinitely for a connection to establish.
     * \note Default value: 20
     */
    SAVAPI_OPTION_APC_CONNECTION_TIMEOUT,
    /**
     * \brief Set the maximum number of seconds before an APC file scan times out
     * \note Available values: 0 - 86400 (1 second - 24 hours)
     * \note If 0, SAVAPI will wait indefinitely for data transfer to/from APC.
     * \note Default value: 30
     */
    SAVAPI_OPTION_APC_SCAN_TIMEOUT,
    /**
     * \brief Set the APC_CHECK_RISK_RATING_LEVEL threshold.
     * \note A hash request will be sent to APC only if the malware probability is greater than or equal to this threshold.
     * \note Available values: 0 - 7 (Very Low Risk - Very High Risk)
     * \note Default value: 4
     */
    SAVAPI_OPTION_APC_CHECK_RISK_RATING_LEVEL,
    /**
     * \brief Set the APC_UPLOAD_RISK_RATING_LEVEL threshold.
     * \note An unknown file will be uploaded to APC only if the malware probability is greater than or equal to this threshold.
     * \note If APC_CHECK_RISK_RATING_LEVEL is greater than APC_UPLOAD_RISK_RATING_LEVEL, then the
     *       file will be uploaded only if the malware probability is greater than or equal to APC_CHECK_RISK_RATING_LEVEL.
     * \note Available values: 0 - 7 (Very Low Risk - Very High Risk)
     * \note Default value: 4
     */
    SAVAPI_OPTION_APC_UPLOAD_RISK_RATING_LEVEL,
    /**
     * \brief Activates the detection of macros with autostart enabled within Microsoft Office OLE documents
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_NOTIFY_OFFICE_MACRO_AUTOSTART,
    /**
     * \brief Activate detection for the specified type.
     * \note Default value: 1 (enabled)
     */
    SAVAPI_OPTION_DETECT_PUA,
    /**
     * \brief Activate reporting of APC TTLs. If enabled, more \ref SAVAPI_CALLBACK_REPORT_ERROR triggers will be made,
     *        having the following information:
     *        - error_data.level          = SAVAPI_ELEVEL_INFO
     *        - error_data.category       = SAVAPI_ECAT_APC_REPORT_TTL
     *        - error_data.code           = SAVAPI_I_APC_RESULT_EXPIRY or SAVAPI_I_APC_SCAN_DURATION
     *        - error_data.options->type  = the actual TTL (in seconds)
     *        - error_data.file_info.name = the file name or the hash of the file, in case of hash scanning
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_APC_REPORT_SCAN_TTL,
    /**
     * \brief Activate the FPC detection check.(1 = enabled, 0 = disabled)
     * \note Default value: 0
     */
    SAVAPI_OPTION_FPC,
    /**
     * \brief Set the maximum number of seconds before a FPC check times out
     * \note Available values: 0 - 86400 (1 second - 24 hours)
     * \note If 0, SAVAPI will wait indefinitely for a FPC check.
     * \note Default value: 20
     */
    SAVAPI_OPTION_FPC_TIMEOUT,
    /**
     * \brief Specifies the APC scanning mode for PE files.
     * \note Available values:
     *       - DISABLED   - no PE file will be scanned with APC
     *       - CHECK-ONLY - only file hashes of PE files will be sent to APC, no uploads
     *       - FULL       - PE files will be completely scanned with APC (hash checks and uploads)
     * \note Default value: FULL
     * \note This option depends on the value of apc_mode from the \ref SAVAPI_APC_GLOBAL_INIT structure
     */
    SAVAPI_OPTION_APC_PE_MODE,
    /**
     * \brief Specifies the policy of the files that will be scanned with APC
     * \note Available values: AUTO (all files extensions supported by SAVAPI internal list will be scanned with APC)
     *                         CUSTOM (user-defined list of extensions to be scanned with APC)
     * \note The extensions defined by "CUSTOM" option must exist also in SAVAPI internal list, otherwise will not be scanned with APC
     * \note When changing to a different policy, all the extensions filters (\ref SAVAPI_OPTION_APC_FILE_EXTENSIONS_DISABLED,
     *       \ref SAVAPI_OPTION_APC_FILE_EXTENSIONS_CHECK_ONLY, \ref SAVAPI_OPTION_APC_FILE_EXTENSIONS_FULL) will be reset
     * \note Default value: CUSTOM
     */
    SAVAPI_OPTION_APC_FILE_EXTENSIONS_POLICY,
    /**
     * \brief Specifies a list of extensions of the files that will not be scanned with APC
     * \note Available values: a string containing semicolon separated extensions (including the dot).
     * \note Maximum extension length is 255 characters (including the dot). The maximum number of extensions is 128.
     * \note This option has a higher priority and will refine SAVAPI_OPTION_APC_FILE_EXTENSIONS_POLICY option
     * \note Default value: none
     * Example: .xls;.bin;.doc
     */
    SAVAPI_OPTION_APC_FILE_EXTENSIONS_DISABLED,
    /**
     * \brief Specifies a list of extensions of the files that will be hashed-scanned with APC
     * \note Available values: a string containing semicolon separated extensions (including the dot).
     * \note Maximum extension length is 255 characters (including the dot). The maximum number of extensions is 128.
     * \note This option has a higher priority and will refine SAVAPI_OPTION_APC_FILE_EXTENSIONS_POLICY option
     * \note This option depends on the value of apc_mode from the \ref SAVAPI_APC_GLOBAL_INIT structure
     * \note Default value: none
     * Example: .xls;.bin;.doc
     */
    SAVAPI_OPTION_APC_FILE_EXTENSIONS_CHECK_ONLY,
    /**
     * \brief Specifies a list of extension for the files that will be hashed-checked or uploaded to APC
     * \note Available values: a string containing semicolon separated extensions (including the dot).
     * \note Maximum extension length is 255 characters (including the dot). The maximum number of extensions is 128.
     * \note This option has a higher priority and will refine SAVAPI_OPTION_APC_FILE_EXTENSIONS_POLICY option
     * \note This option depends on the value of apc_mode from the \ref SAVAPI_APC_GLOBAL_INIT structure
     * \note Default value: none
     * Example: .xls;.bin;.doc
     */
    SAVAPI_OPTION_APC_FILE_EXTENSIONS_FULL,
    /**
     * \brief Specifies the APC scanning mode for ELF files.
     * \note Available values:
     *       - DISABLED   - no ELF file will be scanned with APC
     *       - CHECK-ONLY - only file hashes of ELF files will be sent to APC, no uploads
     *       - FULL       - ELF files will be completely scanned with APC (hash checks and uploads)
     * \note Default value: DISABLED
     * \note This option depends on the value of apc_mode from the \ref SAVAPI_APC_GLOBAL_INIT structure
     */
    SAVAPI_OPTION_APC_ELF_MODE,
    /**
     * \brief Specifies the APC scanning mode for Mach-O and Apple Universal Binary files.
     * \note Available values:
     *       - DISABLED   - no Mach-O file will be scanned with APC
     *       - CHECK-ONLY - only file hashes of Mach-O files will be sent to APC, no uploads
     *       - FULL       - Mach-O files will be completely scanned with APC (hash checks and uploads)
     * \note Default value: DISABLED
     * \note This option depends on the value of apc_mode from the \ref SAVAPI_APC_GLOBAL_INIT structure
     */
    SAVAPI_OPTION_APC_MACH_O_MODE,

    /*
     * SET options (write only)
     * "SET" requests are available to configure SAVAPI. Usually a "SET" request also
     * has a "GET" request counterpart to retrieve current settings. However, the
     * following commands do not have a "GET" counterpart and are therefore labeled
     * as "write only".
     */

    /**
     * \brief Set the key-id that is required by the application.
     * \note SAVAPI will check if the key-id is within the license and that it is not
     * expired. If it is available and is valid, the application is free to use SAVAPI.
     * If not, most requests will result in an error response.
     */
    SAVAPI_OPTION_PRODUCT = 1000,
    /** Activate detection for all types. */
    SAVAPI_OPTION_DETECT_ALLTYPES,
    /**
     * \brief Set all three timeouts (APC Connection Timeout, APC Scan Timeout, Scan Timeout) using a single command
     * \note The timeouts must be set in the following order, separated by space.
     * (APC Connection Timeout, APC Scan Timeout, Scan Timeout). Ex: "20 30 40"
     */
    SAVAPI_OPTION_SCAN_TIMEOUTS,

    /*
     * GET options (read only)
     * "GET" requests are available to retrieve current SAVAPI settings.
     * Usually a "GET" request also has a "SET" request counterpart to configure
     * SAVAPI. However, the following commands do not have a "SET" counterpart
     * and are therefore labeled as "read only".
     */

    /**
     * \brief Retrieves SAVAPI Service version for client-mode, or,
     * for library-mode, it retrieves the SAVAPI library version
     */
    SAVAPI_OPTION_SAVAPI = 2000,
    /** Retrieve engine version number */
    SAVAPI_OPTION_AVE_VERSION,
    /** Retrieve vdf(-set) version number */
    SAVAPI_OPTION_VDF_VERSION,
    /**
     * \brief Retrieve the process-id for the SAVAPI process that is currently handling the TCP/IP connection.
     * \note Available only in client-mode.
     */
    SAVAPI_OPTION_PID,
    /** Retrieve the expiration date of the SAVAPI license (YYYYMMDD) */
    SAVAPI_OPTION_EXPIRE,
    /** Retrieve the number of signatures in the vdf(-set) */
    SAVAPI_OPTION_VDFSIGCOUNT,
    /**
     * \brief Retrieve the various types that can be detected (and dynamically turned on/off).
     * \note The types are returned as a comma separated list. The current value
     *       would be: ADWARE,ADSPY,APPL,BDC,DIAL,GAME,HIDDENEXT,JOKE,PCK,PFS,PHISH,PUA,SPR
     */
    SAVAPI_OPTION_SELECTABLE_DETECT,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_ADSPY,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_APPL,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_BDC,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_DIAL,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_GAME,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_HIDDENEXT,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_JOKE,
    /** Retrieve the English description for the given type.*/
    /** This option is deprecated.*/
    SAVAPI_OPTION_DESCR_PCK,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_PHISH,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_SPR,
    /** Retrieve the creation date of the vdf(-set). Date is the form of YYYYMMDD. */
    SAVAPI_OPTION_VDF_DATE,
    /**
     * \brief Retrieve the path to the file containing the dump of the malware names
     * \note This option's value should only be checked after a successfully call to the
     *       \ref SAVAPI_extract_malware_names function, otherwise it will contain
     *       an empty string.
     * \note Default value: None
     */
    SAVAPI_OPTION_MALWARE_NAMES_FILE,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_ADWARE,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_PFS,
    /** Retrieve the English description for the given type.*/
    SAVAPI_OPTION_DESCR_PUA,
} SAVAPI_OPTION;


/**
 * \}
 * \defgroup global_options SAVAPI global options
 * \{
 *
 * \remark
 * Almost each option used to configure the SAVAPI global
 * has a default value that is written in its description
 * as a note (i.e. Default value: \<value\>).
 * \remark
 * The options that have no default (i.e. unsupported options, obsolete, ignored) will be marked
 * with the "Default value: None" string.
 */

typedef enum SAVAPI_global_option
{
    /**
     * Global OnAccess options
     * "Global SET" requests are available to configure the SAVAPI OnAccess scanner.
     */

    /**
    * \brief Set OnAccess scanner file extensions list
    * If set to empty string, all files are scanned.
    * Maximum extension length is 12 characters. The maximum extension number is 150 extensions.
    * \note The extensions specified here are only considered for files not being mapped for
    * execution. Any file mapped for execution, no matter its extension, will be scanned. It is
    * therefore possible that files having extensions others than those defined here will be
    * scanned.
    * The separator is the semicolon. White spaces, if present, are considered as being part of
    * the extension.
    * Example: .doc;.xls;.txt;.avi
    */
    SAVAPI_OPTION_G_OA_EXTENSIONS_LIST = 3000,
    /**
    * \brief Set OnAccess scanner excepted file objects list
    * If set to empty string, then no objects will be excluded from on-access scanning.
    * Maximum length of the string is 6000 characters, string terminator included. Wildcards are
    * accepted, only if present after the last path separator (backslash).
    * Any files and folders specified here will be ignored, even if they will be mapped for
    * execution. For each drive, you can specify a maximum of 20 exceptions by entering the
    * complete path. The maximum number of exceptions without a complete path is 64.
    * \note If a directory is excluded, all its sub-directories are automatically also excluded.
    * \note Keeping this list short is HIGHLY RECOMMENDED, since every file accessed by the
    * operating system will be cross-checked against this list.
    * \note This option is case sensitive.
    * The separator is the semicolon. White spaces, if present, are considered as being part of
    * the path.
    * Examples:\code
    *          C:\Folder\file.exe
    *          C:\Folder\Subfolder\*.doc?
    *          C:\Exclude\All\From\Here\
    *          \Device\HarddiskDmVolumes\PhysicalDmVolumes\BlockVolume1\
    *          *.mdb;*.md?
    *          F:
    *          \endcode
    * Statements like: \code
    *                  C:\Folder*\file.exe
    *                  C:\Folde?\fi*.exe
    *                  \\.\c:\file.exe
    *                  \??\c:\file.exe
    *                  \endcode
    * are considered invalid.
    * When excluding an entire drive, not using the backslash after the drive quotation mark is
    * faster. 'F:' performs faster than 'F:\'.
    * Statements exclusively comprising the following characters are invalid: * (asterisk),
    * ? (question mark), / (forward slash), \ (backslash), . (dot), : (colon).
    */
    SAVAPI_OPTION_G_OA_EXCEPTED_FILES,
    /**
    * \brief Set OnAccess scanner excepted processes list
    * If set to empty string, then no processes will be excluded from on-access scanning.
    * All file actions performed by processes defined here will be excluded from the on-access
    * scan operation. Maximum number of excepted processes is 128.
    * Maximum length is 6000 characters, string terminator included. Wildcards are accepted only
    * if present after the last path separator(backslash).
    * Excluding a process without full path details only applies to processes where the executable
    * files are located on hard disk drives. Full network path is required for processes whose
    * executable is located on remote drives. Do not specify any exceptions for processes where
    * the executable files are located on dynamic drives(e.g.: USB keys).
    * \note The Windows Explorer and the operating system itself cannot be excluded.
    * \note The specified path and file name of each process must contain a maximum of 255
    * characters.
    * \note This option is case sensitive.
    * The separator is the semicolon. White spaces, if present, are considered as being part of
    * the path.
    * Examples:\code
    *          C:\Folder1\Subfolder\application.exe
    *          C:\Folder2\Subfolder\applicatio?.exe
    *          C:\Folder3\Subfolder\app*.exe
    *          C:\Folder4\Subfolder\*.exe
    *          Application.exe
    *          App*.exe
    *          \endcode
    * Statements like: \code
    *                  C:\Folder*\file.exe
    *                  C:\Folde?\fi*.exe
    *                  \\*
    *                  \\.\c:\file.exe
    *                  \??\c:\file.exe
    *                  \endcode
    * are considered invalid.
    * Statements exclusively comprising the following characters are invalid: * (asterisk),
    * ? (question mark), / (forward slash), \ (backslash), . (dot), : (colon).
    */
    SAVAPI_OPTION_G_OA_EXCEPTED_PROCESSES,
    /**
     * \brief Set OnAccess scanner at file changes
     * \note All the files that were previously accessed and scanned will be scanned again,
     * whenever possible, when modifications are detected.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_G_OA_SCAN_AT_FILE_CHANGES,
    /**
     * \brief Set OnAccess to scan network files
     * \note All the files accessed on a network location will be scanned as well.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_G_OA_SCAN_NETWORK_DRIVES,
    /**
     * \brief Set OnAccess to cache scan results for network files.
     * \note The results are cached based on file modify time.
     * \note Default value: 0 (disabled)
     */
    SAVAPI_OPTION_G_OA_CACHE_SCAN_NETWORK_DRIVES,
    /**
     * \brief Set the maximum number of seconds allowed to scan an OnAccess file before aborting
     * \note Available values: 0 - 60 (1 second - 60 seconds)
     * \note If 0, SAVAPI will wait maximum (60 seconds) for OnAccess file to be scanned.
     * \note Default value: 25
     */
    SAVAPI_OPTION_G_OA_SCAN_TIMEOUT,
    /**
     * \brief Set the interval in which a file detected as malware will not be scanned again when it is accessed
     * \note If a file was detected as malware and a second access for it comes before the end of the interval
     *       0 - SAVAPI_OPTION_G_OA_MALWARE_RESPONSE_TTL, the file will not be scanned again and the result
     *       for the second access will be the same as for the first access. If the callback
     *       SAVAPI_CALLBACK_OA_FILE_RESULT is defined, it is up to the callback implementation to grant or deny
     *       the access.
     * \note Available values: 0 - 300 (0 seconds - 300 seconds)
     * \note If 0, SAVAPI will scan the file at each access
     * \note Default value: 5
     */
    SAVAPI_OPTION_G_OA_MALWARE_RESPONSE_TTL,
    /**
     * \brief Specifies the number of seconds after which SAVAPI will try to establish another connection to FPC.
     * \note Available values: 1 - 86400 (0 seconds - 86400 seconds)
     * \note Default value: 300
     */
    SAVAPI_OPTION_G_FPC_BLACKOUT_TIMEOUT = 4000,
    /**
     * \brief Specifies the maximum number of consecutive timeouts allowed before declaring FPC unreachable.
     * \note Available values: 0 - INT16_MAX
     * \note Default value: 5
     * \note If set to 0, FPC will always try to check the files
     */
    SAVAPI_OPTION_G_FPC_BLACKOUT_RETRIES,
    /**
     * \brief Explicitly set a proxy server to be used by all SAVAPI modules (APC, FPC)
     * \note The parameter holds the host name or IP address.
     *       To specify a port number in this string, append :[port] to the end of the host name.
     *       If not specified, SAVAPI will use as default the port 1080.
     * \note The proxy string may be prefixed with [scheme]:// to specify the kind of proxy to be used.
     *       Supported schemes are: http://, https://, socks4://, socks4a:// and socks5://.
     * \note If no protocol is specified, the proxy will be treated as a HTTP proxy server.
     * \note Only ASCII characters are supported.
     * \note This option must be applied after \ref SAVAPI_initialize(), but before \ref SAVAPI_create_instance()
     *       in order to have any effect. All SAVAPI (and APC) instances created before calling this function will
     *       still use the proxy server that was defined at the time they were created.
     */
    SAVAPI_OPTION_G_PROXY,
} SAVAPI_GLOBAL_OPTION;

/**
 * \}
 * \defgroup oa_result SAVAPI OnAccess result
 * \{
 */
typedef enum
{
    /**
     * \brief Allow access to the file
     */
    SAVAPI_OA_RESULT_ALLOW = 0,

    /**
     * \brief Deny access to the file
     */
    SAVAPI_OA_RESULT_DENY,

    /**
     * \brief Deny access and delete the file
     */
    SAVAPI_OA_RESULT_DELETE,

    /**
     * \brief Deny access and rename the file if it is executable
     */
    SAVAPI_OA_RESULT_RENAME,

    /**
     * \brief Deny access and wipe the file
     */
    SAVAPI_OA_RESULT_WIPE
} SAVAPI_OA_SCAN_RESULT;

/**
 * \}
 * \defgroup apc_scan_result SAVAPI APC scan callback return values
 * \{
 */
typedef enum
{
    /** Continue with the next stage of the scan */
    SAVAPI_APC_SCAN_CONTINUE,
    /** Stop scanning the current file */
    SAVAPI_APC_SCAN_STOP,
    /** Stop scanning the current file and report the information given in \ref APC_set_report_info_t */
    SAVAPI_APC_SCAN_REPORT,
} SAVAPI_APC_SCAN_RESULT;

/**
 * \}
 * \ingroup defs
 * \defgroup callbacks_id Callbacks' ids
 * \{
 */

/**
 * \brief Triggered after a file is scanned. The callback data contains the status of the last scanned file.
 */
#define SAVAPI_CALLBACK_REPORT_FILE_STATUS             0

/**
 * \brief Triggered to report an error or a warning.
 * \note Can be triggered at any time.
 */
#define SAVAPI_CALLBACK_REPORT_ERROR                   3

/**
 * \brief Triggered before the scanning begins. Can be used to create filters.  For example, if we want to scan only .exe files, we install
 * a PRE_SCAN callback. Before each file is scanned, the PRE_SCAN callback will be called. Inside our implementation of the callback,
 * we implement the filter. If the returned code is success, the file will be scanned, otherwise it will be skipped.
 * \note Currently, this callback is not triggered in client-mode.
 */
#define SAVAPI_CALLBACK_PRE_SCAN                       4

/**
 * \brief Triggered before opening an archive. If the returned code is success, the archive will be opened, otherwise
 * it will be skipped from opening.
 * \note Currently, this callback is not triggered in client-mode.
 */
#define SAVAPI_CALLBACK_ARCHIVE_OPEN                   5

/**
 * \brief Triggered when messages related to scan progress are available.
 */
#define SAVAPI_CALLBACK_PROGRESS_REPORT                6

/**
 * \brief Triggered when messages related to scan (progress, warnings or infos that are not error_callback related)
 * are available. IFRAME detection (\ref SAVAPI_OPTION_IFRAMES_URL) will be reported through this callback.
 * \note This callback is deprecated.
 */
#define SAVAPI_CALLBACK_CONTENT_REPORT                 7

/**
 * \brief Triggered when messages related to scan process details are available.
 * The virus description url (\ref SAVAPI_OPTION_NOTIFY_ALERTURL)
 */
#define SAVAPI_CALLBACK_SCAN_DETAILS_REPORT            8

/**
 * \brief Triggered after a file was scanned with OnAccess, in order to decide what action to take
 * The action is taken depending on the return code of the callback (see \ref SAVAPI_OA_SCAN_RESULT)
 */
#define SAVAPI_CALLBACK_OA_FILE_RESULT                 9

/**
 * Triggered at various stages of scanning a file with APC:
 * - before any action is performed on the file (see \ref SAVAPI_APC_STAGE_PRE_FILTER);
 * - after the file passed the APC filter, but before the APC hash check (see \ref SAVAPI_APC_STAGE_PRE_HASH_CHECK);
 * - after the APC hash check, but before the APC upload (see \ref SAVAPI_APC_STAGE_PRE_UPLOAD);
 * - after the entire APC scan was finished (see \ref SAVAPI_APC_STAGE_POST_SCAN).
 *
 * An action is taken depending on the return code of the callback:
 * - \ref SAVAPI_APC_SCAN_CONTINUE - the scan will continue and a new callback will be triggered at the next available stage;
 * - \ref SAVAPI_APC_SCAN_STOP - stop the APC scan for the current file;
 * - \ref SAVAPI_APC_SCAN_REPORT - stop the APC scan for the current file and use the information given in
 *   the \ref APC_set_report_info_t function. This information will be reported on the \ref SAVAPI_CALLBACK_REPORT_FILE_STATUS callback.
 *
 * \note If the current stage is \ref SAVAPI_APC_STAGE_POST_SCAN, the return codes \ref SAVAPI_APC_SCAN_CONTINUE
 *       and SAVAPI_APC_SCAN_STOP have the same effect.
 *
 * \note Currently, this callback is not triggered in client-mode.
 */
#define SAVAPI_CALLBACK_APC_SCAN                       10

/**
 * \}
 * \ingroup defs
 * \defgroup report_detail_types SAVAPI report scan details types
 * \{
 */

/** Malware URL description */
#define SAVAPI_REPORT_ALERTURL                 1
/** Malware found in the object can be repaired */
#define SAVAPI_REPORT_REPAIRABLE               2

/**
 * \}
 * \ingroup defs
 * \defgroup report_content_types SAVAPI report content types
 * \{
 */

/** IFRAME URL report */
/** This option is deprecated.*/
#define SAVAPI_REPORT_CONTENT_IFRAME                   0

/**
 * \}
 * \ingroup defs
 * \defgroup signal_ids SAVAPI signals
 * \{
 */

/**
 * \brief Will cause the SAVAPI instance to abort scanning process as soon as possible
 * \note The signal have no associated specific data. When calling \ref SAVAPI_send_signal function, "data"
 *       argument may be NULL.
 * \todo Add new signals as needed.
 */
#define SAVAPI_SIGNAL_SCAN_ABORT                       1

/**
 * \}
 * \ingroup defs
 * \defgroup scan_statuses SAVAPI scan statuses
 * \{
 */
/** Processed object is clean.
 * \note This scan status is obsolete.
 */
#define SAVAPI_SCAN_STATUS_CLEAN               0
/** Viral code found during object processing. */
#define SAVAPI_SCAN_STATUS_INFECTED            1
/** Suspicious code found during object processing. */
#define SAVAPI_SCAN_STATUS_SUSPICIOUS          2
/** An error occurred during object processing */
#define SAVAPI_SCAN_STATUS_ERROR               3
/** Object processing finished. */
#define SAVAPI_SCAN_STATUS_FINISHED            4

/**
 * \}
 * \ingroup defs
 * \defgroup file_type File types
 * \note Used by the callbacks to report the type of the scanned file
 * \{
 */
/** Regular file (all files are regular) */
#define SAVAPI_FTYPE_REGULAR                           4
/** Known archive type */
#define SAVAPI_FTYPE_ARCHIVE                           1
/** File is in an archive */
#define SAVAPI_FTYPE_IN_ARCHIVE                        2

/**
 * \}
 * \ingroup defs
 * \defgroup filename_flags Filename flags
 * \note Used by the callbacks to report the state of the last reported filename
 * \{
 */
/**
 * \brief The last filename is not the one reported by the engine, but a default one set by the lib
 * \note This flag is passed to the callback data structures: \ref SAVAPI_PRESCAN_DATA,
 *       \ref SAVAPI_ARCHIVE_OPEN_DATA, \ref SAVAPI_FILE_STATUS_DATA in the 'flags' field.
 */
#define SAVAPI_FLAG_LAST_FILENAME_DEFAULT 1 << 0

/**
 * \}
 * \defgroup structs SAVAPI structures
 * \{
 */

/**
 * \brief The structure used at SAVAPI initialization
 */
typedef struct SAVAPI_global_init
{
    /** The expected API major version (\ref SAVAPI_API_MAJOR_VERSION) */
    unsigned int    api_major_version;

    /** The expected API minor version (\ref SAVAPI_API_MINOR_VERSION) */
    unsigned int    api_minor_version;

    /** The unique program number which identifies the 3rd party application
     * for the license checking function.
     * This has to be requested from Avira.
     */
    unsigned int    program_type;

    /**
     * Path to a directory containing engine modules (optional)
     * \note If this variable is set to NULL or empty string,
     *       the current working directory will be used instead
     */
    SAVAPI_TCHAR    *engine_dirpath;

    /** Path to a directory containing the signature files (optional)
     * \note If this variable is set to NULL or empty string,
     *       the same directory as \ref engine_dirpath will be used
     */
    SAVAPI_TCHAR    *vdfs_dirpath;

    /** IGNORED OPTION - Path to a directory containing avll license library */
    SAVAPI_TCHAR    *avll_dirpath;

    /** The path to the license file (optional)
     * \note If this field is set to NULL or empty string,
     *       the default values of current_dir/HBEDV.KEY or current_dir/hbedv.key
     *       will be used instead, if any of them exists
     * \note If the path is not absolute, it will be considered relative to the current working directory
     */
    SAVAPI_TCHAR    *key_file_name;
} SAVAPI_GLOBAL_INIT;

/**
 * \brief Defines the APC scan mode
 */
typedef enum SAVAPI_APC_scan_mode
{
    /**
     * APC checks only hashes
     */
    SAVAPI_APC_SCAN_MODE_CHECK_ONLY = 1,

    /**
     * Full APC functionality (hash checking and file uploads)
     */
    SAVAPI_APC_SCAN_MODE_FULL
} SAVAPI_APC_SCAN_MODE;

/**
 * \brief The structure used for initializing APC
 */
typedef struct SAVAPI_APC_global_init
{
    /**
     * Path to the APC certificate directory (optional)
     * \note If this variable is set to NULL or empty string,
     *       the current working directory will be used instead
     */
    SAVAPI_TCHAR *cert_dir;

    /**
     * Path to the temporary directory to be used by APC (optional)
     * \note If this variable is set to NULL or empty string,
     *       the default system temporary directory will be used instead
     */
    SAVAPI_TCHAR *temp_dir;

    /**
     * Path to the directory containing the APC library (optional)
     * \note If this variable is set to NULL or empty string,
     *       the current working directory will be used instead
     */
    SAVAPI_TCHAR *lib_dir;

    /**
     * APC scan mode
     */
    SAVAPI_APC_SCAN_MODE apc_mode;

    /**
     * APC cache size
     * \note If 0, the cache will be disabled
     * \note The size of the cache will greatly affect the time needed by the APC
     *       to finish processing the requests. The more size available, the more
     *       data can be stored and used later, in order to save bandwidth.
     *       For high-intensive applications, a bigger value is recommended.
     * \note Recommended size is 5242880 (5MB)
     */
    SAVAPI_SIZE_T cache_size;

    /**
     * Enable/disable cache file dump (1 = enabled, 0 = disabled)
     */
    unsigned int dump_cache_file;

    /**
     * Path for cache file dump (optional)
     * \note It must be unique for each library implementation, otherwise conflicts may appear
     * \note If dump_cache_file is set to disabled, this parameter is ignored
     * \note If this variable is set to NULL or empty string, cache file (savapi_apc_cache.dat)
     *       will be saved in default temporary directory
     */
    SAVAPI_TCHAR* cache_file_path;

    /**
     * The maximum number of timeouts allowed before declaring APC unreachable.
     * \note If 0, then SAVAPI will always try to reach APC.
     */
    unsigned int blackout_retries;

    /**
     * Number of seconds after which SAVAPI will try another connection to APC.
     * \note Accepted range is 1 - INT16_MAX
     */
    unsigned int blackout_timeout;

    /**
     * APC connection proxy server
     * \note The parameter holds the host name or IP address.
     *       To specify a port number in this string, append :[port] to the end of the host name.
     *       If not specified, SAVAPI will use as default the port 1080.
     * \note The proxy string may be prefixed with [scheme]:// to specify the kind of proxy to be used.
     *       Supported schemes are: http://, https://, socks4://, socks4a:// and socks5://.
     * \note If no protocol is specified, the proxy will be treated as a HTTP proxy server.
     * \note Only ASCII characters are supported.
     * \note If the proxy requires authentication, the credentials can be specified by adding
     *       username:password before the host name, as shown in one of the examples below.
     * \note If no proxy is provided, SAVAPI will try to read it from other sources:
     *       environment variables in the following order: https_proxy, HTTPS_PROXY, http_proxy, HTTP_PROXY, all_proxy, ALL_PROXY.
     * \note Examples:
     *       Proxy=10.0.0.1:3128
     *       Proxy=http://proxy-server:3128
     *       Proxy=socks4://socks-proxy-server
     *       Proxy=http://username:password@proxy-server:3128
     */
    char *proxy;
} SAVAPI_APC_GLOBAL_INIT;

/**
 * \brief The structure used at SAVAPI instance creation
 */
typedef struct SAVAPI_instance_init
{
    /** Initialization flags, right now only the flag deciding the connection type is defined.
    * See \ref init_flags
    */
    unsigned int flags;
    /** Specified the connection timeout in milliseconds.
    * \note Available only in client-mode.
    */
    unsigned int connection_timeout;
    /** Specifies the machine on which the SAVAPI daemon is located.
    * \note Used only in client-mode.
    */
    SAVAPI_TCHAR *host_name;
    /** Specifies the port on which to connect to the daemon.
    * \note Used in the same conditions as \ref host_name.
    */
    unsigned int port;
    /** This field is deprecated.
    * \note Any data contained by this field will be ignored.
    */
    unsigned int scan_timeout;
    /** Specifies the timeout (in milliseconds) of the get options operation.
    * \note Used only in client-mode.
    */
    unsigned int get_timeout;
    /** Specifies the timeout (in milliseconds) of the set options operation.
    * \note Used only in client-mode.
    */
    unsigned int set_timeout;
    /** This field is deprecated.
    * \note Any data contained by this field will be ignored.
    */
    SAVAPI_TCHAR *username;
    /** This field is deprecated.
    * \note Any data contained by this field will be ignored.
    */
    SAVAPI_TCHAR *password;
} SAVAPI_INSTANCE_INIT;


/**
 * \brief Contains data about the scanned file
 */
typedef struct SAVAPI_file_info
{
    /** file name */
    SAVAPI_TCHAR    *name;
    /** The file type. See \ref file_type.
    * \note Can be one or more types (ex: file is an archive and is found in an archive).
    */
    unsigned int    type;
    /** The file recursion level (0 for regular files, +1 for each level in an archive) */
    unsigned int    level;
} SAVAPI_FILE_INFO;

/**
 * \brief Contains data about the found malware in an infected/suspicious file
 */
typedef struct SAVAPI_malware_info
{
    /** The malware name or null if file is clean */
    SAVAPI_TCHAR    *name;
    /** The malware type. Can have the following values:
     *  adware, backdoor, constructor, dialer, dropper, exploit, game, heuristic, joke,
     *  macro, packer, phishing, program, riskware, script, trash, trojan, virus, worm
     *  Additionally, there is a dynamic list of types from APC, which start with "APC/" prefix
     */
    SAVAPI_TCHAR    *type;
    /** Additional information about found malware */
    SAVAPI_TCHAR    *message;
    /** malware flags */
    SAVAPI_TCHAR    *app_flags;
    /** 1 if malware removable/ 0 otherwise */
    unsigned int    removable;
    /** Malware signature found at correct offset */
    unsigned short  strict;
} SAVAPI_MALWARE_INFO;


/**
 * \brief Contains the data sent to a prescan callback
 */
typedef struct SAVAPI_pre_scan_data
{
    /** General purpose flags field. \note Currently defined flags: see \ref filename_flags group */
    unsigned int            flags;
    /** Information (name, type, level) about the scanned file */
    SAVAPI_FILE_INFO       file_info;
} SAVAPI_PRESCAN_DATA;

/**
 * \brief Contains the data sent to a archive_open callback
 */
typedef struct SAVAPI_archive_open_data
{
    /** General purpose flags field. \note Currently defined flags: see \ref filename_flags group. */
    unsigned int            flags;
    /** Information (name, type, level) about the archive to be opened */
    SAVAPI_FILE_INFO       file_info;
} SAVAPI_ARCHIVE_OPEN_DATA;

/**
 * \brief Generic container
 *
 * This kind of container is very useful in case of need to store many options. It offers a very elegant
 * encapsulation and a very high flexibility (the user will not know how data will be stored).\n
 * The elements from container are accessed using a key (SAVAPI_key_value#id member). The element is accessed through
 * SAVAPI_key_value#value member and its type through SAVAPI_key_value#type member
 */
typedef struct SAVAPI_key_value
{
    /** The element associated id */
    unsigned int id;
    /** The element type */
    unsigned int type;
    /** The element value */
    char *value;
} SAVAPI_KEY_VALUE;

/**
 * \brief Contains the data sent to a report file status callback
 * \note See \ref SAVAPI_CALLBACK_REPORT_FILE_STATUS
 */
typedef struct SAVAPI_file_status_data
{
    /** General purpose flags field. \note Currently defined flags: check \ref filename_flags group */
    unsigned int flags;
    /** File scan answer. See \ref scan_statuses for available values */
    unsigned int scan_answer;
    /** File information (name, type, level). See \ref SAVAPI_file_info for more details */
    SAVAPI_FILE_INFO file_info;
    /**
    * \brief Malware information (name, type, etc).
    * See \ref SAVAPI_malware_info for more details.
    * \note Contains data only if the object processed is not clean.
    */
    SAVAPI_MALWARE_INFO malware_info;
    /** warning value to report
    * See \ref scan_warnings
    */
    unsigned int warning;
    /** additional info to report
    * See \ref scan_info
    */
    unsigned int info;
} SAVAPI_FILE_STATUS_DATA;

/**
 * \brief Contains the data sent to an OnAccess file status callback
 * \note See \ref SAVAPI_CALLBACK_OA_FILE_RESULT
 */
typedef struct SAVAPI_OA_file_result_data
{
    /** name of the file for which the allow/block decision needs to be made */
    SAVAPI_TCHAR *filename;
    /** process ID of the process which opened the file */
    unsigned int pid;
    /** security ID of the user who opened the file */
    unsigned char *sid;
    /** the length of the buffer containing the security ID */
    unsigned long sid_len;
} SAVAPI_OA_FILE_RESULT_DATA;

/**
 * \brief The structure associated with report error callback
 *
 * The callback is triggered each time an error occurred on scanning process
 * (an I/O error for instance). Also the callback can be called if warnings or infos
 * reports during scanning are activated.
 *
 * \note See \ref SAVAPI_CALLBACK_REPORT_ERROR
 */
typedef struct SAVAPI_error_data
{
    /** Information (name, type, level) about the file where the error occurred */
    SAVAPI_FILE_INFO file_info;
    /** error category see \ref error_cat */
    unsigned int category;
    /** error level see \ref error_level */
    unsigned int level;
    /** error code. See \ref rets
    * \note If error level is not SAVAPI_ELEVEL_ERROR this field contains flags.
    * See \ref scan_warnings and \ref scan_info
    */
    int code;
    /** The container contain currently only the error code string.
    * \note The \ref code is the id within container
    */
    SAVAPI_KEY_VALUE *options;
} SAVAPI_ERROR_DATA;

/**
 * \brief The stage in APC scanning in which the \ref SAVAPI_CALLBACK_APC_SCAN callback was called
 */
typedef enum
{
    /** The file was not yet checked with APC */
    SAVAPI_APC_STAGE_PRE_FILTER,
    /** The file has passed the APC filter, but has not yet been checked */
    SAVAPI_APC_STAGE_PRE_HASH_CHECK,
    /** The hash of the file was checked with APC, but the file was not uploaded */
    SAVAPI_APC_STAGE_PRE_UPLOAD,
    /** APC scan has finished for this file */
    SAVAPI_APC_STAGE_POST_SCAN,
} SAVAPI_APC_SCAN_STAGE;

/**
 * \brief Scan answers that can be provided by the user for a reported file.
 */
typedef enum
{
    /** The file is clean */
    SAVAPI_APC_ANSWER_CLEAN = 1,
    /** The file is infected */
    SAVAPI_APC_ANSWER_INFECTED,
} SAVAPI_APC_SCAN_ANSWER;

/**
 * \brief Information to report when calling a \ref APC_set_report_info_t function.
 */
typedef struct
{
    /** File scan answer */
    SAVAPI_APC_SCAN_ANSWER scan_answer;
    /** Information about the reported malware
     *  \note This structure is read only if \ref scan_answer is \ref SAVAPI_APC_ANSWER_INFECTED
     */
    SAVAPI_MALWARE_INFO    malware_info;
    /** Store the result in cache or not (1 = enabled, 0 = disabled)
     *  \note The result cannot be stored in cache if the hash received on
     *        the \ref SAVAPI_APC_SCAN_DATA structure is unavailable
     */
    unsigned int           store_cache;
    /** For how many seconds should this detection remain valid
     * \note This field is read only if \ref store_cache is enabled
     * \note If 0, a default value of 600 (10 minutes) will be applied.
     */
    SAVAPI_SIZE_T          ttl;
} SAVAPI_APC_REPORT_DATA;

/**
 * \}
 * \defgroup typedefs SAVAPI typedefs
 * \{
 */

/**
 * \brief SAVAPI instance handle.
 */
typedef void * SAVAPI_FD;

/**
 * \brief Type of function that is called by the user to report findings regarding a scanned file.
 * \param savapi_fd [IN]: Handle to the savapi instance.
 * \param data      [IN]: Pointer to the structure containing the report data.
 * \retval SAVAPI_S_OK if successful
 * \retval SAVAPI_E_INVALID_PARAMETER if any of the parameters are invalid
 * \retval SAVAPI_E_NO_MEMORY if no memory is left for allocations
 */
typedef SAVAPI_STATUS(CC *APC_set_report_info_t)(SAVAPI_FD savapi_fd, SAVAPI_APC_REPORT_DATA *data);

/**
 * \}
 * \addtogroup structs SAVAPI structures
 * \{
 */

/**
 * \brief The structure associated with the \ref SAVAPI_CALLBACK_APC_SCAN callback
 */
typedef struct SAVAPI_apc_scan_data
{
    /** Information (name, type, level) about the scanned file */
    SAVAPI_FILE_INFO         file_info;
    /** The stage of the APC scan in which the callback was called */
    SAVAPI_APC_SCAN_STAGE    stage;
    /** The hash of the scanned file
     *  \note This field is unavailable if stage is \ref SAVAPI_APC_STAGE_PRE_FILTER
     *        or if stage is \ref SAVAPI_APC_STAGE_POST_SCAN and the file was filtered
     */
    char                     *hash;
    /** A value between 0 and 7 which states the risk of the current file containing malware:
     *  - 0  -> file has very low risk;
     *  - 7  -> file has very high risk.
     * \note A value of -1 means that no rating level is provided for this file.
     */
    int                      risk_rating_level;
    /** FOPS handle for the current file (of type \ref FOPS_HANDLE) */
    void                     *fops_handle;
    /** FOPS context for the current file */
    void                     *fops_context;
    /** General purpose flags field */
    unsigned int             flags;
    /** Handle to the SAVAPI instance, needed for \ref set_report_info */
    SAVAPI_FD                savapi_fd;
    /** Function to be called when new information is found about the current scanned file
     *  \note The information given by calling this function will be used only if \ref SAVAPI_APC_SCAN_REPORT
     *        is returned in the \ref SAVAPI_CALLBACK_APC_SCAN callback
     */
    APC_set_report_info_t    set_report_info;
} SAVAPI_APC_SCAN_DATA;

/**
 * \brief The structure associated with report progress callback
 */
typedef struct SAVAPI_report_progress_data
{
    /** Reserved */
    unsigned int    flags;
    /** the progress message */
    SAVAPI_TCHAR    *message;
} SAVAPI_REPORT_PROGRESS_DATA;

/**
 * \brief Structure associated with the iframe report
 * \note This structure is deprecated.
 */
typedef struct SAVAPI_iframe_url_data
{
    /** iframe attribute. See \ref iframes_info */
    unsigned int    attribute;
    /** iframe url. */
    SAVAPI_TCHAR    *url;
} SAVAPI_IFRAME_URL_DATA;

/**
 * \brief The structure associated with report content callback
 * \note This structure is deprecated.
 */
typedef struct SAVAPI_report_content_data
{
    /** Reserved */
    unsigned int            flags;
    /** report type (\ref report_content_types) */
    unsigned int            type;
    /** Information (name, type, level) about the scanned file */
    SAVAPI_FILE_INFO       file_info;
    /** Union used to switch the content data depending on the received 'type' */
    union _content_data
    {
        /** Information about the iframe report (url, attribute) */
        SAVAPI_IFRAME_URL_DATA *iframeurl_data;
    } content_data;

} SAVAPI_REPORT_CONTENT_DATA;

/**
 * \brief Structure associated with the ALERTURL report
 */
typedef struct SAVAPI_alert_url_data
{
    /** Pointer to the string containing the alert URL */
    SAVAPI_TCHAR            *alert_url;
    /** Information (name, type, level) about the scanned file */
    SAVAPI_FILE_INFO       file_info;
} SAVAPI_ALERT_URL_DATA;

/**
 * \brief Structure associated with the REPAIRABLE report
 */
typedef struct SAVAPI_repairable_data
{
    /** Information (name, type, level) about the scanned file */
    SAVAPI_FILE_INFO       file_info;
    /** Malware information (name, type, etc). */
    SAVAPI_MALWARE_INFO    malware_info;
} SAVAPI_REPAIRABLE_DATA;

/**
 * \brief The structure associated with report scan details callback
 */
typedef struct SAVAPI_report_scan_details_data
{
    /** Reserved */
    unsigned int                    flags;
    /** report type(see \ref report_detail_types) */
    unsigned int                    type;
    /** Union used to switch the scan details data depending on the received 'type' */
    union _scan_details_data
    {
        /** Contains the alert URL report */
        SAVAPI_ALERT_URL_DATA  *alert_url_data;
        /** Contains the details about the reparable data */
        SAVAPI_REPAIRABLE_DATA *repairable_data;
    } scan_details_data;
} SAVAPI_REPORT_SCAN_DETAILS_DATA;

/**
 *      \brief Structure passed by SAVAPI to a user defined callback, containing all the necessary data.
 */
typedef struct SAVAPI_callback_data
{
    /** The callback id. See \ref callbacks_id */
    unsigned int type;
    /** The callback version */
    unsigned int version;
    /** Reserved */
    unsigned int flags;
    /**
     * \brief User custom data
     * \note SAVAPI will not make any assumption regarding this field. It will just be passed back to callback
     *       function
     */
    void          *user_data;
    /**
     * \brief  Callbacks specific data
     */
    union specific_data
    {
        /** specific data for pre scan callback \n See \ref SAVAPI_pre_scan_data */
        SAVAPI_PRESCAN_DATA                    *pre_scan_data;
        /** specific data for archive open callback \n See \ref SAVAPI_archive_open_data */
        SAVAPI_ARCHIVE_OPEN_DATA               *archive_open_data;
        /** specific data for file status callback \n See \ref SAVAPI_file_status_data */
        SAVAPI_FILE_STATUS_DATA                *file_status_data;
        /** specific data for error report callback \n See \ref SAVAPI_error_data */
        SAVAPI_ERROR_DATA                      *error_data;
        /** specific data for report progress callback \n See \ref SAVAPI_report_progress_data */
        SAVAPI_REPORT_PROGRESS_DATA            *report_progress_data;
        /** specific data for report content callback. See \ref SAVAPI_report_content_data */
        SAVAPI_REPORT_CONTENT_DATA             *report_content_data;
        /** specific data for report scan details callback. See \ref SAVAPI_report_scan_details_data */
        SAVAPI_REPORT_SCAN_DETAILS_DATA        *report_scan_details_data;
        /** specific data for OnAccess file result callback. See \ref SAVAPI_OA_file_result_data */
        SAVAPI_OA_FILE_RESULT_DATA             *oa_file_result_data;
        /** specific data for the APC scan callback. See \ref SAVAPI_apc_scan_data */
        SAVAPI_APC_SCAN_DATA                   *apc_scan_data;
        /** private data. Reserved for internal use */
        void                                   *private_data;
    } callback_data;
} SAVAPI_CALLBACK_DATA;

/**
 * \brief The structure contains information about each infected, suspicious, or erroneous
 *        file scanned by \ref SAVAPI_simple_scan
 */
typedef struct SAVAPI_simple_scan_file_data
{
    /** file name */
    SAVAPI_TCHAR *name;
    /** File scan answer. See \ref scan_statuses for available values */
    unsigned int scan_answer;
    /** error level see \ref error_level
     * \note when \ref scan_answer is SAVAPI_SCAN_STATUS_ERROR this should be checked
     * together with the error code
     */
    unsigned int error_level;
    /** error code. See \ref rets
    * \note If error level is not SAVAPI_ELEVEL_ERROR this field contains flags.
    * See \ref scan_warnings and \ref scan_info
    */
    unsigned int error_code;
    /** The malware name or null if file is clean */
    SAVAPI_TCHAR *malware_name;
    /** The malware type. Can have the following values:
     *  adware, backdoor, constructor, dialer, dropper, exploit, game, heuristic, joke,
     *  macro, packer, phishing, program, riskware, script, trash, trojan, virus, worm
     *  Additionally, there is a dynamic list of types from APC, which start with "APC/" prefix
     */
    SAVAPI_TCHAR *malware_type;
} SAVAPI_SIMPLE_SCAN_FILE_DATA;

/**
 * \brief The structure contains statistics for the simple scan
 */
typedef struct SAVAPI_simple_scan_statistics
{
    /** Total number of files that were scanned
     * \note For client mode this statistic parameter is not available and will always be 0
     */
    unsigned int total_files;
    /** number of infections detected (can be more than one per file) */
    unsigned int infections;
    /** number of suspicions detected (can be more than one per file) */
    unsigned int suspicions;
    /** number of errors, warnings, or additional information (can be more than one per file) */
    unsigned int errors;
} SAVAPI_SIMPLE_SCAN_STATISTICS;

/**
 * \brief The structure containing the output for \ref SAVAPI_simple_scan.
 * \note Memory management is done by SAVAPI so there is no need to allocate or free the structure.
 */
typedef struct SAVAPI_simple_scan_output
{
    /** array of files that were found to be infected, suspicious, erroneous
     *  or for which there is additional information (example: office macros)
     */
    SAVAPI_SIMPLE_SCAN_FILE_DATA *files;
    /** number of items in the array containing files that are infected, suspicious or encountered errors */
    unsigned int count;
    /** simple scan statistics */
    SAVAPI_SIMPLE_SCAN_STATISTICS stats;
} SAVAPI_SIMPLE_SCAN_OUTPUT;

/**
 * \brief  The structure to be passed when sending a signal
 */
typedef struct SAVAPI_signal_data
{
    /** signal id. See \ref signal_ids */
    unsigned int signal_id;

    /**
     * \brief Signal specific data
     * \note Currently SAVAPI has defined only \ref SAVAPI_SIGNAL_SCAN_ABORT signal which doesn't require any
     *       data. Thus, "specific_data" field is currently empty.
     * \todo Add specific date as soon as new signals, which require data will be defined.
    */
    void *signal_data;
} SAVAPI_SIGNAL_DATA;

/**
 * \brief  The structure to be passed when sending a command
 */
typedef struct SAVAPI_command_data
{
    /** signal id. See \ref signal_ids */
    unsigned int signal_id;

    /**
     * \brief Signal specific data
     * \note Currently SAVAPI has defined only \ref SAVAPI_SIGNAL_SCAN_ABORT signal which doesn't require any
     *       data. Thus, "specific_data" field is currently empty.
     * \todo Add specific date as soon as new signals, which require data will be defined.
    */
    /*      union signal_specific_data
    {
    } signal_data;
    */
    void *command_data;
} SAVAPI_COMMAND_DATA;

/**
 * \brief The structure used to retrieve SAVAPI version
 */
typedef struct SAVAPI_version
{
    /** Major version of the product */
    unsigned int major;
    /** Minor version of the product */
    unsigned int minor;
    /** Major version of the build */
    unsigned int build_major;
    /** Minor version of the build */
    unsigned int build_minor;
} SAVAPI_VERSION;

/**
 * \brief The enumeration used to specify the SAVAPI's logging levels
 */
typedef enum _SAVAPI_log_level
{
    /** Low level (debug, trace) messages.
     * This the service MESSAGE level equivalent
     */
    SAVAPI_LOG_DEBUG = 0,
    /** informative messages */
    SAVAPI_LOG_INFO,
    /** warning messages */
    SAVAPI_LOG_WARNING,
    /** alert messages (i.e. malware found or any other alert) */
    SAVAPI_LOG_ALERT,
    /** error messages */
    SAVAPI_LOG_ERROR
} SAVAPI_LOG_LEVEL;

/**
 * \brief Defines the type of an engine module
 */
typedef enum SAVAPI_engine_module_type
{
    /* AVE module type */
    SAVAPI_ENGINE_MODULE_AVE = 0,

    /* VDF module type */
    SAVAPI_ENGINE_MODULE_VDF
} SAVAPI_ENGINE_MODULE_TYPE;

/**
 * \brief The structure used for initializing OnAccess
 * \note Only supported on Windows.
 */
typedef struct SAVAPI_OA_global_init
{
    /**
     * \brief Number of threads to be used by OnAccess scanner
     * \note Available values: 3 - 16
     * \note If this value is set to 0, the default value will be used
     * \note Default value: 16
     */
    unsigned int    threads_number;

    /**
     * \brief SCM pending time
     * \note In case of a service, the estimated time required, in milliseconds,
     *       for a pending start, stop, pause, or continue operation. Set it to 0 if
     *       the library will not run inside a service.
     * \note Available values: 0 or any value bigger than or equal to 5000
     * \note Default value: 0
     */
    unsigned int    scm_pending_time;
} SAVAPI_OA_GLOBAL_INIT;

/**
 * \}
 * \addtogroup typedefs SAVAPI typedefs
 * \{
 */

/**
 * \brief SAVAPI callback function pointer definition.
 * \param data [IN]: Pointer to the structure containing the callback data.
 */
typedef int(CC *SAVAPI_CALLBACK)(SAVAPI_CALLBACK_DATA *data);

/**
 * \brief SAVAPI callback for logging
 * \param log_level [IN]: The log level for the given message
 * \param message   [IN]: The message to be logged
 * \param user_data [IN]: The user context
 * \return Nothing
 */
typedef void(CC *SAVAPI_LOG_CALLBACK)(SAVAPI_LOG_LEVEL log_level, const SAVAPI_TCHAR *message, void *user_data);

/**
 * \brief Callback function used to return one engine single module
 * \param name      : The name of the module
 * \param type      : The type of the returned module
 * \param user_data : Pointer to the user-specific data
 */
typedef int(CC *SAVAPI_ENGINE_MODULE_CALLBACK)(const SAVAPI_TCHAR *name, SAVAPI_ENGINE_MODULE_TYPE type, void *user_data);

/**
 * \brief Callback function used to configure the instances created by OnAccess
 * \param savapi_fd : Handle to savapi instance
 */
typedef int(CC *SAVAPI_OA_INSTANCE_CALLBACK)(SAVAPI_FD savapi_fd);

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * \}
 * \defgroup handle_funcs SAVAPI function pointers
 * \brief Handle types for exported SAVAPI functions
 * \{
 */

/**
 * \}
 * \ingroup handle_funcs
 * \defgroup handle_funcs_main SAVAPI main function pointers
 * \brief Handle types for exported SAVAPI main functions
 * \{
 */
typedef SAVAPI_STATUS (CC *SAVAPI_set_log_callback_t)(SAVAPI_LOG_CALLBACK log_fct, SAVAPI_LOG_LEVEL min_level, void *user_data);
typedef SAVAPI_STATUS (CC *SAVAPI_initialize_t)(SAVAPI_GLOBAL_INIT *savapi_init);
typedef void(CC *SAVAPI_set_quickload_init_t)(void);
typedef SAVAPI_STATUS (CC *SAVAPI_uninitialize_t)(void);
typedef SAVAPI_STATUS (CC *SAVAPI_get_version_t)(SAVAPI_VERSION *version);
typedef SAVAPI_STATUS (CC *SAVAPI_engine_versions_get_t)(SAVAPI_VERSION *ave_version, SAVAPI_VERSION *avpack_version, SAVAPI_VERSION *vdf_version);
typedef SAVAPI_STATUS (CC *SAVAPI_APC_get_version_t)(SAVAPI_VERSION *apc_version);
typedef SAVAPI_STATUS (CC *SAVAPI_create_instance_t)(SAVAPI_INSTANCE_INIT *init, SAVAPI_FD *savapi_fd);
typedef SAVAPI_STATUS (CC *SAVAPI_release_instance_t)(SAVAPI_FD *savapi_fd);
typedef SAVAPI_STATUS (CC *SAVAPI_set_user_data_t)(SAVAPI_FD savapi_fd, void *user_data);
typedef SAVAPI_STATUS (CC *SAVAPI_get_user_data_t)(SAVAPI_FD savapi_fd, void **user_data);
typedef SAVAPI_STATUS (CC *SAVAPI_is_running_ex_t)(const SAVAPI_TCHAR *hostname, unsigned int port);
typedef SAVAPI_STATUS (CC *SAVAPI_register_callback_t)(SAVAPI_FD savapi_fd, unsigned int callback_id, SAVAPI_CALLBACK callback);
typedef SAVAPI_STATUS (CC *SAVAPI_unregister_callback_t)(SAVAPI_FD savapi_fd, unsigned int callback_id, SAVAPI_CALLBACK callback);
typedef SAVAPI_STATUS (CC *SAVAPI_scan_t)(SAVAPI_FD savapi_fd, SAVAPI_TCHAR *file_name);
typedef SAVAPI_STATUS (CC *SAVAPI_simple_scan_t)(SAVAPI_FD savapi_fd, SAVAPI_TCHAR *file_name, SAVAPI_SIMPLE_SCAN_OUTPUT *output);
typedef SAVAPI_STATUS (CC *SAVAPI_set_t)(SAVAPI_FD savapi_fd, SAVAPI_OPTION option_id, SAVAPI_TCHAR *buffer);
typedef SAVAPI_STATUS (CC *SAVAPI_get_t)(SAVAPI_FD savapi_fd, SAVAPI_OPTION option_id, SAVAPI_TCHAR *buffer, SAVAPI_SIZE_T *buffer_size);
typedef SAVAPI_STATUS (CC *SAVAPI_send_signal_t)(SAVAPI_FD savapi_fd, unsigned int signal_id, SAVAPI_SIGNAL_DATA* data);
typedef SAVAPI_STATUS (CC *SAVAPI_set_fops_t)(SAVAPI_FD savapi_fd, void *fops_pointer, void *fops_context);
typedef SAVAPI_STATUS (CC *SAVAPI_get_fops_t)(SAVAPI_FD savapi_fd, void **fops_pointer, void **fops_context);
typedef void (CC *SAVAPI_free_t)(void **ptr);
typedef SAVAPI_STATUS (CC *SAVAPI_reload_engine_ex_t)(const SAVAPI_GLOBAL_INIT *global_init);
typedef SAVAPI_STATUS (CC *SAVAPI_extract_malware_names_t)(const SAVAPI_TCHAR *dir_path);
typedef SAVAPI_STATUS (CC *SAVAPI_engine_modules_get_t)(const SAVAPI_GLOBAL_INIT *init, SAVAPI_ENGINE_MODULE_CALLBACK module_func, void *user_data);
typedef SAVAPI_STATUS (CC *SAVAPI_global_set_t)(SAVAPI_GLOBAL_OPTION option_id, SAVAPI_TCHAR *buffer);

typedef SAVAPI_STATUS (CC *SAVAPI_APC_initialize_t)(SAVAPI_APC_GLOBAL_INIT *savapi_apc_init);
typedef SAVAPI_STATUS (CC *SAVAPI_APC_uninitialize_t)(void);

typedef SAVAPI_STATUS (CC *SAVAPI_OA_initialize_t)(SAVAPI_OA_GLOBAL_INIT *savapi_oa_init);
typedef SAVAPI_STATUS (CC *SAVAPI_OA_uninitialize_t)(void);
typedef SAVAPI_STATUS (CC *SAVAPI_OA_create_instances_t)(SAVAPI_OA_INSTANCE_CALLBACK init_func, SAVAPI_OA_INSTANCE_CALLBACK uninit_func);
typedef SAVAPI_STATUS (CC *SAVAPI_OA_start_scan_t)(void);
typedef SAVAPI_STATUS (CC *SAVAPI_OA_stop_scan_t)(void);

/**
 * \}
 * \defgroup funcs SAVAPI functions
 * \{
 */
/**
 * \brief Sets the SAVAPI logging function
 * \param log_fct   [IN]: The function used for logging. If given  function is NULL all data set with a previous
 *                        SAVAPI_set_log_callback call will be cleared so logging will not be performed anymore.
 * \param min_level [IN]: Sets the desired minimum log level. This can be used to filter unwanted log-levels, so that if a
 *                        message have a lower level, it will be automatically "thrown" by the SAVAPI
 * \param user_data [IN]: The user context
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note This function can be called before or/and after global initialization (calling before it's recommended, so that
 *       any error messages in the SAVAPI_initialize() can be logged)
 * \note This can be called several times in the same process, so that SAVAPI's user can change the log-level on-the-fly
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_set_log_callback(SAVAPI_LOG_CALLBACK log_fct, SAVAPI_LOG_LEVEL min_level, void *user_data);

/**
 * \brief SAVAPI initialization function
 * Initializes the SAVAPI library, according to the parameters specified in the initialization structure.
 * It should be called once per process, but it may be called several times per process only
 * if \ref SAVAPI_uninitialize() has been called in between. The latter case is useful when initializing
 * SAVAPI in 'quick load' mode (\ref SAVAPI_set_quickload_init()), and then uninitializing and reinitializing
 * SAVAPI in 'normal mode' for scanning purposes.
 * \param savapi_init [IN]: A pointer to the initialization structure, which must be filled with the proper values for initialization
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note The initialization function must be called before calling any other
 *       SAVAPI function (except the \ref SAVAPI_set_log_callback() and \ref SAVAPI_set_quickload_init() functions).
 * \note The \ref SAVAPI_GLOBAL_INIT structure is copied internally and it is not longer needed by SAVAPI after calling this function.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_initialize(SAVAPI_GLOBAL_INIT *savapi_init);

/**
 * \brief Sets the SAVAPI initialization mode to 'quick load'
 * Recommended if only component versions are needed.
 * \return nothing
 * \note Must be called before any initialization function (\ref SAVAPI_initialize())
 * \note Scanning is prohibited in this mode
 * \note Calling \ref SAVAPI_uninitialize() resets the mode to 'normal load'

 * \note Function doesn't perform anything in client-mode
 */
void SAVAPI_EXP CC SAVAPI_set_quickload_init(void);

/**
 * \brief SAVAPI uninitialization function
 * Uninitializes the SAVAPI library, cleaning up all used resources. Once called, all subsequent SAVAPI calls will fail
 * with SAVAPI_E_NOT_INITIALIZED error code.
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note All SAVAPI instances must be released before calling this function, otherwise the \ref SAVAPI_E_BUSY will be returned.
 * \note If \ref SAVAPI_set_quickload_init() has been called before, then calling this function will also reset the mode to 'normal load'
 * \note If calling this function without prior SAVAPI initialization, an error will be returned
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_uninitialize(void);

/**
 * \brief SAVAPI initialization function for APC component
 * Initializes the APC library, according to the parameters specified in the initialization structure.
 * \param savapi_apc_init [IN]: A pointer to the initialization structure, which must be filled with the proper values for initialization
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note APC is an optional component of SAVAPI which allows scanning in the cloud. By calling this function you enable the APC functionality
 * \note This function must be called a single time per process
 * \note This function must be called after \ref SAVAPI_initialize(), before creating any instance
 * \note The \ref SAVAPI_APC_GLOBAL_INIT structure is copied internally and it is not longer needed by SAVAPI after calling this function.
 * \note This function returns \ref SAVAPI_E_NOT_SUPPORTED in client mode.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_APC_initialize(SAVAPI_APC_GLOBAL_INIT *savapi_apc_init);

/**
 * \brief SAVAPI uninitialization function for APC component
 * Unitializes the APC library, cleaning up all used resources.
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note APC is an optional component of SAVAPI which allows scanning in the cloud. By calling this function you disable the APC functionality
 * \note This function must be called a single time per process
 * \note This function must be called after all SAVAPI instances are released and before \ref SAVAPI_uninitialize()
 * \note This function returns \ref SAVAPI_E_NOT_SUPPORTED in client mode.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_APC_uninitialize(void);

/**
 * \brief Returns the APC version
 *
 * \param version [OUT]: Pointer to the structure where to store the result
 * \return SAVAPI_S_OK for success or an error code otherwise
 *
 * \note Function returns \ref SAVAPI_E_NOT_SUPPORTED in client-mode
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_APC_get_version(SAVAPI_VERSION *version);

/**
 * \brief Returns SAVAPI library version
 *
 * \param version [OUT]: Pointer to the structure where to store the result
 * \return SAVAPI_S_OK on success or an error otherwise
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_get_version(SAVAPI_VERSION *version);

/**
 * \brief SAVAPI factory function
 * The function opens a connection to the SAVAPI daemon for client-mode, or,
 * for library mode, it creates a new SAVAPI instance.
 *
 * \param init       [IN]: Pointer to a structure containing all the initialization data needed to create a
 *                         SAVAPI instance.
 * \param savapi_fd [OUT]: Handle to the SAVAPI instance. To be used in all the subsequent SAVAPI calls
 * \return SAVAPI_S_OK on success or an error otherwise
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_create_instance(SAVAPI_INSTANCE_INIT *init, SAVAPI_FD *savapi_fd);

/**
 * \brief Destroys a SAVAPI handler, previously created with \ref SAVAPI_create_instance.
 * The function closes the connection to the SAVAPI daemon for client-mode, or,
 * for library mode, it releases the SAVAPI instance.
 *
 * \param savapi_fd [IN/OUT]: SAVAPI instance to be released. As a precaution, the  pointer will be
 *                            nulled in order to become very clear that pointer will be unusable for now on
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note \li For each handler created with \ref SAVAPI_create_instance function, the
 *       correspondent \c \b SAVAPI_release_instance must be called!
 *       \li After calling the function the \c \b savapi_fd pointer will be invalid and must not be used anymore
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_release_instance(SAVAPI_FD *savapi_fd);

/**
 * \brief Sets user specific data.
 * This functions sets user data that will be returned untouched as <i> user_data </i>
 * member of \ref SAVAPI_CALLBACK_DATA structure.
 *
 * \param savapi_fd     [IN]: Handle to the SAVAPI instance.
 * \param user_data     [IN]: User specific data
 * \return SAVAPI_S_OK in case of success or an error code otherwise
 *
 * \note The user is responsible with the memory management. This function will only set the value given in the
 *       \ref SAVAPI_CALLBACK_DATA structure. It will not reserve or free memory for the data.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_set_user_data(SAVAPI_FD savapi_fd, void *user_data);

/**
 * \brief Gets user specific data.
 * This functions gets the user data set by \ref SAVAPI_set_user_data
 *
 * \param savapi_fd     [IN]: Handle to the SAVAPI instance.
 * \param user_data    [OUT]: User specific data
 * \return SAVAPI_S_OK in case of success or an error code otherwise
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_get_user_data(SAVAPI_FD savapi_fd, void **user_data);

/**
 * \brief Determines if the SAVAPI daemon is running
 * The library must be initialized with the proper daemon connection parameters
 * for this function to run correctly.
 *
 * \return
 * - 0 If the daemon is stopped
 * - 1 If the daemon is running
 * - SAVAPI_E_NOT_INITIALIZED If the SAVAPI library was not properly initialized.
 *
 * \note This function is deprecated, use \ref SAVAPI_is_running_ex() instead.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_is_running(void);

/**
 * \brief Determines if the SAVAPI daemon is running on the specified interface (hostname and port)
 * \param hostname [IN]: Specifies the host on which the SAVAPI daemon is located.
 * \param port     [IN]: Specifies the port on which to connect to the daemon.
 * \return SAVAPI_S_OK if the SAVAPI daemon is running on the given interface or an error code otherwise.
 *
 * \note For local sockets (see \ref SAVAPI_FLAG_USE_LOCAL_SOCKET) the \param hostname must be a
 *       path to a file and the \param port must be 0.
 * \note This function returns \ref SAVAPI_E_NOT_SUPPORTED in library mode.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_is_running_ex(const SAVAPI_TCHAR *hostname, unsigned int port);

/**
 * \brief Registers a client defined callback.
 * \param savapi_fd   [IN]: Handle to the SAVAPI instance on which the callback will be available.
 * \param callback_id [IN]: The callback type (e.g. SAVAPI_CALLBACK_REPORT_FILE_STATUS, SAVAPI_CALLBACK_ARCHIVE_OPEN etc.)
 * \param callback    [IN]: Pointer to a callback function
 * \return SAVAPI_S_OK if everything went OK or an error code otherwise\n\n
 *
 * \note Callback registering is not allowed during scanning operations, otherwise the \ref SAVAPI_E_BUSY will be returned.
 * \note Only one callback function is allowed to be registered per callback type/id. If for the given type/id
 *       a callback function was already registered then this function will return \ref SAVAPI_E_INVALID_PARAMETER
 *      \sa callbacks_id
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_register_callback(SAVAPI_FD savapi_fd, unsigned int callback_id, SAVAPI_CALLBACK callback);

/**
 * \brief Unregisters a previously registered client defined callback
 * \param savapi_fd   [IN]: Handle to the SAVAPI instance.
 * \param callback_id [IN]: The callback type (e.g. SAVAPI_CALLBACK_REPORT_FILE_STATUS, SAVAPI_CALLBACK_ARCHIVE_OPEN etc.)
 * \param callback    [IN]: Pointer to a callback function
 * \return SAVAPI_S_OK in case of success or an error code otherwise
 *
 * \note Callback unregistering is not allowed during scanning operations, otherwise the \ref SAVAPI_E_BUSY will be returned.
 * \note The callback type/id is searched by SAVAPI in its internal callback list and if found then the callback function
 *       will be removed, otherwise this function will return \ref SAVAPI_E_INVALID_PARAMETER
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_unregister_callback(SAVAPI_FD savapi_fd, unsigned int callback_id, SAVAPI_CALLBACK callback);

/**
 * \brief Starts a scanning process. During the scan operation the registered callbacks may be triggered.
 * \param savapi_fd [IN]: The handle of the SAVAPI instance that will do the scanning
 * \param file_name [IN]: The name of the file to be scanned.
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note The execution will not leave \ref SAVAPI_scan function until scan process is finished.
 * \note SAVAPI supports various scan types depending on the file_name format:
 *       - 'path/to/the/file/on/disk' for normal file scanning.
 *       - 'mem://0xAddress,size,name' for scan in memory.
 *         The '0xAddress' is the memory area where the buffer with size 'size' is loaded.
 *         The 'name' is the display name used when callbacks are triggered.
 *         SAVAPI expects that the file from disk is mapped into memory and it will scan that memory address.
 *         SAVAPI does not scan processes in memory.
 *       - 'hex_enc://hex_encoded_filename' for scanning files with filename given using hex encoding.
 *         This is useful for special encodings (ex. Chinese) in order to avoid conversions.
 *         This is not available on Windows platforms: SAVAPI_E_NOT_SUPPORTED will be returned.
 *         All filenames returned via callbacks will also be hex-encoded.
 *       - 'apchash://file_hash1,file_hash2' for directly scanning the files' fingerprints (also referred to as hashes) with APC.
 *         Users can compute the hashes by using the apchash library and multiple hashes can be verified in a single scan.
 *         NOTE: All engine-related scanning options and some APC-related options have no effect in this scanning mode.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_scan(SAVAPI_FD savapi_fd, SAVAPI_TCHAR *file_name);

/**
 * \brief Starts a scanning process during which no callbacks will be triggered.
 * \param savapi_fd [IN]: The handle of the SAVAPI instance that will do the scanning
 * \param file_name [IN]: The name of the file to be scanned
 * \param output   [OUT]: The output of the scan, containing a list of the files that were found to be infected, suspicious,
 *                        erroneous or for which there is additional information (example: office macros)
 * \return SAVAPI_S_OK if no infected or suspicious file was scanned, and if there was no error while scanning any file
 *         SAVAPI_S_INFECTED if at least one infected file was found
 *         SAVAPI_S_SUSPICIOUS if at least one suspicious file was found, but no infected file
 *         SAVAPI_E_SCAN_ERROR if an error was encountered while scanning any of the files, but no infected or suspicious file
 *         specific error code if a non scanning error was encountered during the scan process
 *
 * \note The output data structure requires no memory management.
 *       Memory allocation and deallocation is handled internally by SAVAPI.
 * \note More information about the error can be obtained by checking the error code of
 *       each file in the list (if it contains any such files).
 * \note SAVAPI supports various scan types depending on the file_name format:
 *       - 'path/to/the/file/on/disk' for normal file scanning.
 *       - 'mem://0xAddress,size,name' for scan in memory.
 *         The '0xAddress' is the memory area where the buffer with size 'size' is loaded.
 *         SAVAPI expects that the file from disk is mapped into memory and it will scan that memory address.
 *         SAVAPI does not scan processes in memory.
 *       - 'hex_enc://hex_encoded_filename' for scanning files with filename given using hex encoding.
 *         This is useful for special encodings (ex. Chinese) in order to avoid conversions.
 *         This is not available on Windows platforms: SAVAPI_E_NOT_SUPPORTED will be returned.
 *       - 'apchash://file_hash1,file_hash2' for directly scanning the files' fingerprints (also referred to as hashes) with APC.
 *         Users can compute the hashes by using the apchash library and multiple hashes can be verified in a single scan.
 *         NOTE: All engine-related scanning options and some APC-related options have no effect in this scanning mode.
 * \note No callbacks and user data set before calling this function will be used. They can still be used with a regular
 *       \ref SAVAPI_scan call
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_simple_scan(SAVAPI_FD savapi_fd, SAVAPI_TCHAR *file_name, SAVAPI_SIMPLE_SCAN_OUTPUT *output);

/**
 * \brief Sets SAVAPI individual settings.
 * \param savapi_fd [IN]: Handle of the SAVAPI instance
 * \param option_id [IN]: The id of the option to be set
 * \param buffer    [IN]: NULL-terminated string containing the value of the option to be set
 *
 * \return SAVAPI_S_OK If everything went ok an error code otherwise.
 * \note Calling this function during a scanning operation performed by this instance will fail.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_set(SAVAPI_FD savapi_fd, SAVAPI_OPTION option_id, SAVAPI_TCHAR *buffer);

/**
 * \brief Reads SAVAPI settings.
 * \param savapi_fd       [IN]: Handle of the SAVAPI instance
 * \param option_id       [IN]: The id of the option to be retrieved
 * \param buffer         [OUT]: Buffer allocated by caller which will store the result of a successful get as a NULL terminated string.
 *                              If the buffer is NULL and the other parameters are valid, the function will set the needed buffer-size and return SAVAPI_S_OK
 * \param buffer_size [IN/OUT]: Specifies the size, given in SAVAPI_TCHAR characters, of the buffer argument.
 *                              If the buffer is not large enough, upon return it will contain the needed size (including the terminator).
 *                              If it's equal or larger than the needed size, it will remain unchanged.
 *
 * \return SAVAPI_S_OK on success or an error otherwise
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_get(SAVAPI_FD savapi_fd, SAVAPI_OPTION option_id, SAVAPI_TCHAR *buffer, SAVAPI_SIZE_T *buffer_size);

/**
 * \brief Retrieve the various types that can be detected (and dynamically turned on/off).
 * \param type [IN]: The type that should be detected (current values: ADWARE,ADSPY,APPL,BDC,DIAL,GAME,HIDDENEXT,JOKE,PCK,PFS,PHISH,PUA,SPR)
 * \param id  [OUT]: Stores the type id
 * \return SAVAPI_S_OK on success or an error otherwise
 * \warning Not implemented yet.
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_get_dynamic_detect(SAVAPI_TCHAR *type, int *id);

/**
 * \brief Sends a signal to a specific SAVAPI instance
 * The \ref SAVAPI_scan may take a long amount of time to finish scanning its target and in some
 * situations a forced abort would be desirable. In these kind of situations, SAVAPI_send_signal may help
 * by sending signals to a running SAVAPI instance (\ref SAVAPI_SIGNAL_SCAN_ABORT for instance).
 *
 * \param savapi_fd [IN]: Handle of the SAVAPI instance
 * \param signal_id [IN]: Identifies the signal to be sent. See \ref signal_ids "Signal IDs section"
 * \param data      [IN]: Specific data to be sent when sending the signal. See \ref SAVAPI_SIGNAL_DATA
 * \return SAVAPI_S_OK for success or an error code otherwise.
 *
 * \note The SAVAPI signals were designed to be sent asynchronously, when an event arrives (Ctrl+C was issued
 *       for instance) and if program execution is within \ref SAVAPI_scan. It makes no sense to
 *       send a signal to a SAVAPI instance when we have execution flow control.
 *       \sa Current supported \ref signal_ids
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_send_signal(SAVAPI_FD savapi_fd, unsigned int signal_id, SAVAPI_SIGNAL_DATA* data);

/**
 * \brief Specify the new fops who will be used by the engine
 * \param savapi_fd    [IN]: Handle of the SAVAPI instance
 * \param fops_pointer [IN]: Pointer to the fops to use in the current savapi session
 * \param fops_context [IN]: This context will be passed back to the application by each call to the fops used
 * \return SAVAPI_S_OK for success or an error code otherwise.
 *
 * \note This function will return \ref SAVAPI_E_NOT_SUPPORTED in client-mode
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_set_fops(SAVAPI_FD savapi_fd, void *fops_pointer, void *fops_context);

/**
 * \brief Get the fops which is currently used by the engine
 * \param savapi_fd     [IN]: Handle of the SAVAPI instance
 * \param fops_pointer [OUT]: The fops used in the current savapi session
 * \param fops_context [OUT]: The fops context used in the current savapi session
 * \return SAVAPI_S_OK for success or an error code otherwise.
 *
 * \note This function will return \ref SAVAPI_E_NOT_SUPPORTED in client-mode
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_get_fops(SAVAPI_FD savapi_fd, void **fops_pointer, void **fops_context);

/**
 * \brief Frees the memory space pointed to by ptr
 * \param ptr [IN/OUT]: Pointer who will become free and null
 * \return Nothing
 */
void SAVAPI_EXP CC SAVAPI_free(void **ptr);

/**
 * \brief Reloads the engine from the location given at global initialization
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note This function will simply call the \ref SAVAPI_uninitialize routine
 *       followed by the \ref SAVAPI_initialize having as parameter the same
 *       data provided at global initialization (aka the call to \ref
 *       SAVAPI_initialize) in order to (re)load the engine files from the
 *       initial location(s).
 * \note All constraints that apply to the \ref SAVAPI_uninitialize and
 *       \ref SAVAPI_initialize are also available for this function. Therefore,
 *       in order to call the function, all instances must be released otherwise
 *       the \ref SAVAPI_E_BUSY will be returned.
 * \note This function is deprecated, use \ref SAVAPI_reload_engine_ex instead, which allows loading a new
 *       engine without interrupt of service.
 * \note This function will return \ref SAVAPI_E_NOT_SUPPORTED in client-mode
 * \warning If something wrong goes when the new engine is loaded (e.g. engine is
 *       corrupted, some engine files are missing, etc), the library will not be
 *       usable anymore (i.e. all functions will return \ref SAVAPI_E_NOT_INITIALIZED)
 *       so the user should only call \ref SAVAPI_uninitialize and abort the execution.
 * \warning This function might fail if called after a \ref SAVAPI_reload_engine_ex call.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_reload_engine(void);

/**
 * \brief Retrieves the engine vesions: ave, avpack and vdf
 *
 * \param ave_version This structure will contain the AVE version numbers
 * \param avpack_version This structure will contain the AV-PACK version numbers
 * \param vdf_version This structure will contain the VDF version numbers
 * \return SAVAPI_S_OK or an error code otherwise
 *
 * \note Function returns \ref SAVAPI_E_NOT_SUPPORTED in client-mode
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_engine_versions_get(SAVAPI_VERSION *ave_version, SAVAPI_VERSION *avpack_version, SAVAPI_VERSION *vdf_version);

/**
 * \brief Reloads the engine from the specified location
 * \param global_init [IN]: A pointer to the initialization structure containing the paths
 *                          to the new engine and vdf files
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note When this function is called, the engine will be (re)loaded from
 *       the specified path. The old engine's instances will be kept until
 *       their reference counter will reach 0. Calling this function, affects
 *       only the new SAVAPI instances (obtained by calling SAVAPI_create_instance()).
 *       They will use the new loaded engine. The SAVAPI instances that are
 *       already started won't be affected by this function, they will continue
 *       to use the engine that they were started with.
 * \note This function will return \ref SAVAPI_E_NOT_SUPPORTED in client-mode
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_reload_engine_ex(const SAVAPI_GLOBAL_INIT *global_init);

/**
 * \brief Extracts the malware names from memory to disk.
 *        The purpose of the function is to reduce the amount of memory (RAM) used
 *        by the SAVAPI Library. The basic idea is to unload the malware names
 *        (which are only needed in case of alerts) from memory and dump them to disk.
 * \param dir_path [IN]: The directory where the file containing the malware names
 *                       information will be created. If set to NULL, the function
 *                       will use the system temporary folder.
 *
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note The function will create, in the chosen folder (the \a dir_path or the system
 *       temporary folder), a file with the following naming scheme:
 *       'AV-malware-names-<process-PID>-<6 random chars>'. In order to
 *       retrieve the path to the file, the \ref SAVAPI_get function along with
 *       the \ref SAVAPI_OPTION_MALWARE_NAMES_FILE option should be used.
 *       The file will be kept opened by the SAVAPI Library as long as the current engine
 *       is in use and will be closed and removed afterwards (i.e. after a successfully
 *       call to one of \ref SAVAPI_reload_engine, \ref SAVAPI_reload_engine_ex and
 *       \ref SAVAPI_uninitialize functions). Thus after a call to the \ref SAVAPI_reload_engine
 *       or \ref SAVAPI_reload_engine_ex, this function should be called again in
 *       order to extract the new engine's malware names.
 * \note It has to be ensured that the Library has the appropriate permissions to create
 *       the file and that there is enough free disk space - around 100 Mb.
 * \note This function will return \ref SAVAPI_E_NOT_SUPPORTED in client-mode.
 * \warning Calling this function more than once for a single engine is forbidden
 *          and the \ref SAVAPI_E_BUSY error will be returned instead!
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_extract_malware_names(const SAVAPI_TCHAR *dir_path);

/**
 * \brief Retrieves the engine components through the provided callback
 * \param init        [IN]: A pointer to the initialization structure
 * \param module_func [IN]: Pointer to the function to be called for every engine module
 * \param user_data   [IN]: Pointer to the user-defined data
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note This function will return \ref SAVAPI_E_NOT_SUPPORTED in client-mode.
 */
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_engine_modules_get(const SAVAPI_GLOBAL_INIT *init, SAVAPI_ENGINE_MODULE_CALLBACK module_func, void *user_data);

/**
* \brief Sets SAVAPI global settings
* \param optionId [IN]: The id of the option to be set
* \param buffer   [IN]: Pointer to the value to be set
*
* \return SAVAPI_S_OK on success or an error otherwise
* \note All options related to SAVAPI OnAccess must be set after \ref SAVAPI_OA_create_instances() has been called.
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_global_set(SAVAPI_GLOBAL_OPTION optionId, SAVAPI_TCHAR *buffer);

/**
 * \brief SAVAPI initialization function for OnAccess component
 * Initializes the OnAccess library, according to the parameters specified in the initialization structure.
 * \param oa_global_init [IN]: A pointer to the initialization structure, which must be filled
 *                             with the proper values for initialization
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note OnAccess is an optional component of SAVAPI which allows real-time on-access scanning.
 *       By calling this function you enable the OA functionality
 * \note This function must be called a single time per process
 * \note This function must be called after \ref SAVAPI_initialize()
 * \note The \ref SAVAPI_OA_GLOBAL_INIT structure is copied internally and it is not longer needed
 *       by SAVAPI after calling this function.
 * \note Only supported on Windows.
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_OA_initialize(SAVAPI_OA_GLOBAL_INIT *oa_global_init);

/**
 * \brief SAVAPI uninitialization function for OnAccess component
 * Unitializes the OnAccess library, cleaning up all used resources.
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note OnAccess is an optional component of SAVAPI which allows real-time on-access scanning.
 *       By calling this function you disable the OnAccess functionality
 * \note This function must be called a single time per process
 * \note This function must be called before \ref SAVAPI_uninitialize()
 * \note Only supported on Windows.
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_OA_uninitialize(void);

/**
 * \brief Creates automatically the number of SAVAPI instances specified in SAVAPI_OA_initialize.
          For each instance created, the callback_func function will be called with the instance to be configured
 * \param init_func    [IN]: Callback function to be called after each OnAccess instance is created
 * \param uninit_func  [IN]: Callback function to be called before each OnAccess instance is destroyed
 * \return SAVAPI_S_OK on success or an error otherwise
 *
 * \note This function must be called after \ref SAVAPI_OA_initialize()
 * \note If init_func and uninit_func are NULL, OnAccess will have the default behavior, meaning that
 *       the infected files will be blocked and the clean files will be allowed
 * \note If one of the parameters is NULL, the other must be NULL, also. Otherwise, an error will be returned
 * \note The instances creation is asynchronous, they might be created after the function returns
 * \note Only supported on Windows.
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_OA_create_instances(SAVAPI_OA_INSTANCE_CALLBACK init_func, SAVAPI_OA_INSTANCE_CALLBACK uninit_func);

/**
 * \brief Starts the real-time on-access scanning process. During the scan operation the instance
 *        registered callbacks may be triggered.
 * \return SAVAPI_S_OK on success or an error otherwise
 * \note Only supported on Windows.
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_OA_start_scan(void);

/**
 * \brief Stops the real-time on-access scanning process
 * \return SAVAPI_S_OK on success or an error otherwise
 * \note Only supported on Windows.
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_OA_stop_scan(void);

/**
 * \brief Disables the pre-initialization of FPC inside the \ref SAVAPI_initialize() function
 * \return SAVAPI_S_OK on success or an error otherwise
 * \note This function must be called before \ref SAVAPI_initialize()
 * \note If this function is called, FPC cannot be enabled afterwards using \ref SAVAPI_OPTION_FPC option
 * \note This function returns \ref SAVAPI_E_NOT_SUPPORTED in client mode
*/
SAVAPI_EXP SAVAPI_STATUS CC SAVAPI_FPC_disable_preinit(void);

/** \}*/
#ifdef __cplusplus
}
#endif
#endif /* SAVAPI_H__ */
