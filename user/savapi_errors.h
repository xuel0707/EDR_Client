#ifndef SAVAPI_ERRORS_H__
#define SAVAPI_ERRORS_H__

/**
 * \defgroup rets SAVAPI return codes
 * @{
 */
typedef enum SAVAPI_status
{
    /**
     * \brief Operation ended with success
     */
    SAVAPI_S_OK = 0,
    /**
     * \brief One of supplied parameters is invalid
     * \note At least one of the function's parameters is invalid (invalid pointers,
     * empty strings, out of range values, etc.).
     */
    SAVAPI_E_INVALID_PARAMETER = 1,
    /**
     * \brief SAVAPI was already initialized
     * \note Trying to initialize an already initialized SAVAPI library (\ref SAVAPI_initialize was
     * already called successfully).
     */
    SAVAPI_E_ALREADY_INITIALIZED = 2,
    /**
     * \brief SAVAPI is not initialized
     * \note The used functionality requires the SAVAPI library to be initialized first
     * (a successful call of \ref SAVAPI_initialize is needed before).
     */
    SAVAPI_E_NOT_INITIALIZED = 3,
    /**
     * \brief Supplied buffer is too small
     * \note An interface function that requires a buffer size as parameter was called
     * with a value smaller than the needed size.
     */
    SAVAPI_E_BUFFER_TOO_SMALL = 4,
    /**
     * \brief Connection mode flag is not set
     * \note The \ref SAVAPI_INSTANCE_INIT::flags in the instance creation structure
     * is not set to a known connection mode.
     * \note This error can only be triggered by the SAVAPI Client Library.
     */
    SAVAPI_E_CONNECTION_MODE_NOT_SET = 5,
    /**
     * \brief Host name is not set
     * \note The \ref SAVAPI_INSTANCE_INIT::host_name field in the instance creation
     * structure was not set.
     * \note This error can only be triggered by the SAVAPI Client Library.
     */
    SAVAPI_E_HOSTNAME_NOT_SET = 6,
    /**
     * \brief Memory allocation failed
     * \note There is not enough memory available for allocation.
     */
    SAVAPI_E_NO_MEMORY = 7,
    /**
     * \brief VDF file(s) not found
     * \note Path to the VDF files is not correct, files are missing, or there are
     * no access rights to open the files.
     */
    SAVAPI_E_VDF_NOT_FOUND = 8,
    /**
     * \brief VDF file(s) read failed
     * \note VDF files are damaged or truncated.
     */
    SAVAPI_E_VDF_READ = 9,
    /**
     * \brief VDF file(s) crc check failed
     * \note One ore more VDF files failed checksum check because they were damaged,
     * manipulated or truncated.
     */
    SAVAPI_E_VDF_CRC = 10,
    /**
     * \brief Inconsistent versions in VDF files set
     * \note There are incompatible VDF files within the VDF set. Not all relevant VDF
     * files were downloaded or the engine is too old for the present VDF set.
     */
    SAVAPI_E_VDF_VERSION = 11,
    /**
     * \brief Engine initialization failed
     * \note Engine is too old for this version of SAVAPI. SAVAPI used a wrong character
     * set when initializing the engine.
     */
    SAVAPI_E_WRONG_ENGINE = 12,
    /**
     * \brief Engine file(s) not found
     * \note One or more engine files are not present in the engine's directory.
     */
    SAVAPI_E_ENGINE_NOT_FOUND = 13,
    /**
     * \brief Inconsistent versions in engine files set
     * \note There are incompatible engine files within the engine set which do not match the
     * expected version. The engine file set was not updated or is too old for the present engine set.
     */
    SAVAPI_E_SELFCHK_PATCHED = 14,
    /**
     * \brief Engine file(s) read failed
     * \note One or more engine files are damaged or truncated.
     */
    SAVAPI_E_SELFCHK_FILE_ERR = 15,
    /**
     * \brief Engine file(s) crc check failed
     * \note One or more engine files failed checksum check because they were manipulated,
     * damaged or truncated.
     */
    SAVAPI_E_SELFCHK_FILE_CRC = 16,
    /**
     * \brief Generic key file error
     */
    SAVAPI_E_KEYFILE = 17,
    /**
     * \brief SAVAPI internal error
     * \note An unexpected internal event prevented the normal execution of the library
     * (incorrect pointers, incorrect return values, etc.). Normally this error should
     * never occur. If this error occurs there is a major problem which must be fixed.
     */
    SAVAPI_E_INTERNAL = 18,
    /**
     * \brief Unsupported feature
     * \note The requested functionality (feature, command, option) may be known but it is
     * not supported by this version of SAVAPI or engine. For instance a called function
     * is not available in the current library mode (\ref SAVAPI_is_running_ex() is not
     * available in SAVAPI Library, or \ref SAVAPI_reload_engine_ex() is not available
     * in SAVAPI Client Library); or the used signal id is unknown (the only known signal
     * for \ref SAVAPI_send_signal is \ref SAVAPI_SIGNAL_SCAN_ABORT); or a new functionality
     * was added but is not yet implemented or not supported yet by the current library version
     * or within the current engine version.
     */
    SAVAPI_E_NOT_SUPPORTED = 19,
    /**
     * \brief Could not extract file
     * \note A file to extract during an archive scanning could not be found.
     */
    SAVAPI_E_RESULT_FILE_NOT_FOUND = 20,
    /**
     * \brief Option is not supported
     * \note Trying to set or retrieve a value for an option with an unknown or
     *  obsolete id (for instance, option SAVAPI_OPTION_UPDATE_SERVERS is obsolete).
     */
    SAVAPI_E_OPTION_NOT_SUPPORTED = 21,
    /**
     * \brief Archive maximum recursion limit reached
     * \note The limit on the maximum number of archive recursions was exceeded when extracting
     * a file because the file was packed too many times or it contained other deeply nested files.
     * The decompression will be aborted as soon as the limit is exceeded.
     */
    SAVAPI_E_HIT_MAX_REC = 22,
    /**
     * \brief Archive maximum extraction size reached
     * \note Size of an uncompressed file has exceeded the maximum extraction size. The decompression
     * will be aborted as soon as the limit is exceeded.
     */
    SAVAPI_E_HIT_MAX_SIZE = 23,
    /**
     * \brief Archive maximum extraction ratio reached
     * \note Size of an uncompressed file has exceeded the maximum extraction ratio.
     * The decompression will be aborted as soon as the limit is exceeded.
     */
    SAVAPI_E_HIT_MAX_RATIO = 24,
    /**
     * \brief Encrypted contents found
     * \note One or more files inside the archive are encrypted, but there are also
     * files which are not encrypted and can be extracted; or all files inside the
     * archive are encrypted and it's not possible to extract them.
     */
    SAVAPI_E_ENCRYPTED = 25,
    /**
     * \brief Unsupported archive type/format
     * \note The archive type is not supported. The version of a known archive type is
     * not supported. The archive format is unknown.
     */
    SAVAPI_E_UNSUPPORTED = 26,
    /**
     * \brief Archive generic processing error
     * \note Any other archive scan processing error which is not covered by
     * SAVAPI_E_PROC_<name> error codes.
     */
    SAVAPI_E_PROC_ERROR = 27,
    /**
     * \brief File was not completely scanned
     * \note Scanning was aborted by user or as result of a terminal warning or error.
     */
    SAVAPI_E_INCOMPLETE = 28,
    /**
     * \brief Cannot extract multi-volume archive
     * \note In case of an archive which is part of a multi-volume archive set, a file
     * could not be fully extracted because is split over several archive parts.
     * Processing the next file may be successful if all information is stored in that part.
     */
    SAVAPI_E_PARTIAL = 29,
    /**
     * \brief Maximum number of files in archive reached
     * \note Maximum files count limit was reached while scanning an archive.
     * The scanning will be aborted as soon as the limit is exceeded.
     */
    SAVAPI_E_HIT_MAX_COUNT = 30,
    /**
     * \brief Scan was aborted by signal
     * \note A scan in progress was aborted by user with \ref SAVAPI_SIGNAL_SCAN_ABORT signal.
     */
    SAVAPI_E_ABORTED = 31,
    /**
     * \brief Scan timed out
     * \note A scan in progress exceeded the maximum user set scan time-out.
     */
    SAVAPI_E_TIMEOUT = 32,
    /**
     * \brief Could not open file
     * \note File is missing or there are no access rights to open it.
     */
    SAVAPI_E_FILE_OPEN = 33,
    /** File read error */
    /**
     * \brief Could not read file
     * \note There are no access rights to read file, or the file has been removed, or
     * data from file end is missing, or file is truncated.
     */
    SAVAPI_E_FILE_READ = 34,
    /**
     * \brief Could not write file
     * \note There are no access rights to write file, or the file has been removed.
     * Disk quota exceeded or disk is damaged.
     */
    SAVAPI_E_FILE_WRITE = 35,
    /**
     * \brief Invalid value in configuration or command
     * \note Failure in SAVAPI Client Library communication with SAVAPI Service resulting
     * in commands with invalid values which cannot be accepted by Service (for instance
     * SET or GET commands with invalid values). The engine path given to the
     * \ref SAVAPI_reload_engine_ex() function collides with previous engine path.
     */
    SAVAPI_E_INVALID_VALUE = 36,
    /**
     * \brief Could not change directory
     * \note Failure in SAVAPI Client Library communication with SAVAPI Service resulting
     * in an unsuccessful SET CWD command.
     * \note This error can only be triggered by the SAVAPI Client Library.
     */
    SAVAPI_E_CHDIR_FAILED = 37,
    /**
     * \brief Path is not absolute
     * \note Path to a given or required directory is not absolute (for example the path of
     * the temporary scanning directory is not absolute).
     */
    SAVAPI_E_NOT_ABSOLUTE_PATH = 38,
    /**
     * \brief Directory path does not exist
     * \note Path to a given directory does not exist (for example the path of the temporary
     * scanning directory does not exist).
     * \note This error can only be triggered by the SAVAPI Client Library.
     */
    SAVAPI_E_DIR_NOT_EXISTS = 39,
    /**
     * \brief File was filtered from scanning
     * \note File matched a black list rule and was not scanned.
     */
    SAVAPI_E_MATCHED = 40,
    /**
     * \brief Converting failed
     * \note A string could not be converted from one encoding to another (for instance
     * a string could not be converted from SAVAPI_TCHAR to char, or in case of
     * SAVAPI Client Library  a string could not be converted from SAVAPI_TCHAR to
     * the SAVAPI Service's text mode encoding).
     */
    SAVAPI_E_CONVERSION_FAILED = 41,
    /**
     * \brief Connection with the SAVAPI Service failed
     * \note The SAVAPI service is not running on the specified interface.
     * \note This error can only be triggered by the SAVAPI Client Library.
     */
    SAVAPI_E_CONNECTION_FAILED = 42,
    /**
     * \brief Failed to receive data from the SAVAPI Service
     * \note The SAVAPI service is not running anymore.
     * \note This error can only be triggered by the SAVAPI Client Library.
     */
    SAVAPI_E_RECEIVE_FAILED = 43,
    /**
     * \brief Failed to send data to the SAVAPI Service
     * \note The SAVAPI service is not running anymore.
     * \note This error can only be triggered by the SAVAPI Client Library.
     */
    SAVAPI_E_SEND_FAILED = 44,
    /**
     * \brief Invalid option value
     * \note A configuration command received a value buffer which is not acceptable as
     * a value for the associated option id (for instance it is empty).
     */
    SAVAPI_E_OPTION_VALUE_INVALID = 45,
    /**
     * \brief Repair an infected file failed
     */
    SAVAPI_E_REPAIR_FAILED = 46,
    /**
     * \brief Failed to create file
     * \note Failed to create a temporary file in the temporary scanning directory
     * because there are no access rights, or the file already exists, etc.
     */
    SAVAPI_E_FILE_CREATE = 47,
    /**
     * \brief Failed to delete file
     * \note Failed to delete a temporary file in the temporary scanning directory
     * because there are no access rights, file is locked, file does not exist anymore, etc.
     */
    SAVAPI_E_FILE_DELETE = 48,
    /**
     * \brief Failed to close file
     * \note Failed to close a temporary file in the temporary scanning directory because
     * there are no access rights, file was accidentally deleted, etc.
     */
    SAVAPI_E_FILE_CLOSE = 49,
    /**
     * \brief Unknown engine error
     * \note Engine returns an unknown error code.
     */
    SAVAPI_E_UNKNOWN = 50,
    /**
     * \brief Failed to set a detect type option
     * \note SAVAPI failed to set a detect type option (for instance
     * \ref SAVAPI_OPTION_DETECT_ADSPY, \ref SAVAPI_OPTION_DETECT_APPL, others)
     */
    SAVAPI_E_PREFIX_SET = 51,
    /**
     * \brief Failed to retrieve a detect type option
     * \note SAVAPI failed to retrieve a detect type option (for instance
     * \ref SAVAPI_OPTION_DETECT_ADSPY, \ref SAVAPI_OPTION_DETECT_APPL, others).
     */
    SAVAPI_E_PREFIX_GET = 52,
    /**
     * \brief Invalid query for SAVAPI Service
     * \note  Failure in SAVAPI Client Library communication with SAVAPI Service
     *  resulting in an unacceptable command (invalid command, syntax error).
     * \note This error can only be triggered by the SAVAPI Client Library
     */
    SAVAPI_E_INVALID_QUERY = 53,
    /**
     * \brief Keyfile has not been found
     */
    SAVAPI_E_KEY_NO_KEYFILE = 54,
    /**
     * \brief Access to key file has been denied
     */
    SAVAPI_E_KEY_ACCESS_DENIED = 55,
    /**
     * \brief An invalid header has been found
     */
    SAVAPI_E_KEY_INVALID_HEADER = 56,
    /**
     * \brief Invalid keyfile version number
     */
    SAVAPI_E_KEY_KEYFILE_VERSION = 57,
    /**
     * \brief No valid license found
     */
    SAVAPI_E_KEY_NO_LICENSE = 58,
    /**
     * \brief Key file is invalid (invalid CRC)
     */
    SAVAPI_E_KEY_FILE_INVALID = 59,
    /**
     * \brief Invalid license record detected
     */
    SAVAPI_E_KEY_RECORD_INVALID = 60,
    /**
     * \brief Application is evaluation version
     */
    SAVAPI_E_KEY_EVAL_VERSION = 61,
    /**
     * \brief Application is demo version
     */
    SAVAPI_E_KEY_DEMO_VERSION = 62,
    /**
     * \brief Illegal (cracked) license in keyfile
     */
    SAVAPI_E_KEY_ILLEGAL_LICENSE = 63,
    /**
     * \brief This key has expired
     */
    SAVAPI_E_KEY_EXPIRED = 64,
    /**
     * \brief Error reading from key file
     */
    SAVAPI_E_KEY_READ = 65,
    /**
     * \brief Operation not allowed (license restriction)
     * \note Scan command was issued without setting a valid product id.
     */
    SAVAPI_E_LICENSE_RESTRICTION = 66,
    /**
     * \brief Error loading engine modules
     * \note SAVAPI could not load engine modules because they are not available or
     * there are no access rights.
     */
    SAVAPI_E_LOADING_ENGINE_MODULES = 67,
    /**
     * \brief SAVAPI is busy
     * \note A configuration request was given during scanning a file (for instance
     * SET/GET command or callback register/unregister command).
     * \ref SAVAPI_uninitialize was called without releasing all SAVAPI instances before.
     */
    SAVAPI_E_BUSY = 68,
    /**
     * \brief Encrypted mail found
     * \note While scanning an archive an encrypted mail was found.
     */
    SAVAPI_E_ENCRYPTED_MIME = 69,
    /**
     * \brief Non addressable memory location
     * \note A scan request was issued for an address that is not in the available address
     * space for the current platform. For example, on a 64 bit machine the available
     * address space is [0..MAX_INT_64].
     */
    SAVAPI_E_NON_ADDRESSABLE = 70,
    /**
     * \brief Internal memory limit reached
     * \note An engine-internal safety limit regarding memory usage of a subroutine
     * has been reached (this can i.e. be caused by excessively large dictionaries in archives).
     */
    SAVAPI_E_MEMORY_LIMIT = 71,
    /**
     * \brief Incomplete archive block read
     * \note An archive block is damaged and could not be read.
     */
    SAVAPI_E_PROC_INCOMPLETE_BLOCK_READ = 72,
    /**
     * \brief Bad archive header
     * \note The archive header is invalid.
     */
    SAVAPI_E_PROC_BAD_HEADER = 73,
    /**
     * \brief Bad compressed data
     * \note The compressed data from the archive is invalid. Some files could not be
     * extracted and scanned.
     */
    SAVAPI_E_PROC_INVALID_COMPRESSED_DATA = 74,
    /**
     * \brief Obsolete archive information
     * \note Archive is packed with a very old or a developer version of a packer
     * application and contains obsolete information and unsupported entries.
     */
    SAVAPI_E_PROC_OBSOLETE = 75,
    /**
     * \brief Bad header format
     * \note The archive header has been changed with a newer (unsupported) version of
     * a packer application. The archive header is damaged.
     */
    SAVAPI_E_PROC_BAD_FORMAT = 76,
    /**
     * \brief Bad header crc
     * \note An archive header failed checksum check.
     */
    SAVAPI_E_PROC_HEADER_CRC = 77,
    /**
     * \brief Bad data crc.
     * \note Checksum of compressed data does not match.
     */
    SAVAPI_E_PROC_DATA_CRC = 78,
    /**
     * \brief Bad crc for extracted file
     * \note Checksum of a decompressed file does not match.
     */
    SAVAPI_E_PROC_FILE_CRC = 79,
    /**
     * \brief Invalid decompression table
     * \note Archive contains an invalid decompression table.
     */
    SAVAPI_E_PROC_BAD_TABLE = 80,
    /**
     * \brief Unexpected end of file
     * \note Decompression aborted because of unexpected end of file in archive.
     */
    SAVAPI_E_PROC_UNEXPECTED_EOF = 81,
    /**
     * \brief Archive internal handle error
     * \note An internal handle related to archive processing is invalid or not initialized.
     */
    SAVAPI_E_PROC_ARCHIVE_HANDLE = 82,
    /**
     * \brief No files could be extracted
     * \note Archive is invalid, corrupt or damaged.
     */
    SAVAPI_E_PROC_NO_FILES_TO_EXTRACT = 83,
    /**
     * \brief Archive internal callback error
     * \note Decompression aborted because an internal archive callback is invalid or caused an error.
     */
    SAVAPI_E_PROC_CALLBACK = 84,
    /**
     * \brief File extraction failed.
     * \note Not all archive contents could be extracted.
     */
    SAVAPI_E_PROC_TOTAL_LOSS = 85,
    /**
     * \brief Generic APC-related error.
     */
    SAVAPI_E_APC_ERROR = 86,
    /**
     * \brief APC connection error
     * \note An error occurred while communicating with the cloud server.
     */
    SAVAPI_E_APC_CONNECTION = 87,
    /**
     * \brief APC protocol is not supported
     * \note The APC protocol is no longer supported and must be updated.
     */
    SAVAPI_E_APC_NOT_SUPPORTED = 88,
    /**
     * \brief APC operation timed out.
     * \note Either the APC connection timeout, APC scan timeout or global scan timeout
     *       was reached while an APC operation was taking place.
     */
    SAVAPI_E_APC_TIMEOUT = 89,
    /**
     * \brief APC is currently disabled due to too many failed APC scans.
     */
    SAVAPI_E_APC_TEMPORARILY_DISABLED = 90,
    /**
     * \brief File could not be scanned with APC.
     * \note APC scanning was aborted by user or as result of an error.
     */
    SAVAPI_E_APC_INCOMPLETE = 91,
    /**
     * \brief No valid APC license found in the key file.
     */
    SAVAPI_E_APC_NO_LICENSE = 92,
    /**
     * \brief APC authentication failed.
     */
    SAVAPI_E_APC_AUTHENTICATION = 93,
    /**
     * \brief APC authentication failed, but it should be retried later
     */
    SAVAPI_E_APC_AUTH_RETRY_LATER = 94,
    /**
     * \brief Initially, APC random will be read from "apc_random_id" file. If for some reason the operation fails or the ID is invalid,
     * the ID is computed. If this also fails, the SAVAPI_E_APC_RANDOM_ID will be returned.
     * \note  A valid APC random id is a "40 printable characters" string.
     */
    SAVAPI_E_APC_RANDOM_ID = 95,
    /**
     * \brief APC has not been initialized.
     * \note The used functionality requires the APC library to be initialized first
     * (a successful call of \ref SAVAPI_APC_initialize is needed before).
     */
    SAVAPI_E_APC_NOT_INITIALIZED = 96,
    /**
     * \brief APC was already initialized
     * \note Trying to initialize an already initialized APC library (\ref SAVAPI_APC_initialize was
     * already called successfully).
     */
    SAVAPI_E_APC_ALREADY_INITIALIZED = 97,
    /**
     * \brief APC permanently disabled
     * \note This error is given when APC is disabled
     */
    SAVAPI_E_APC_DISABLED = 98,
    /**
     * \brief APC timeout restrictions not met
     * \note This error is given when APC was enabled and the user tries to set new APC timeouts
     * that do not comply with the following restriction: APCConnectionTimeout < APCScanTimeout < ScanTimeout.
     */
    SAVAPI_E_APC_TIMEOUT_RESTRICTION = 99,
    /**
     * \brief A category could not be determined for the object which was scanned by APC
     * \note This is generally caused by either:
     * - apc_mode being set to \ref SAVAPI_APC_SCAN_MODE_CHECK_ONLY;
     * or
     * - scanning a hash (no file being involved, there is nothing to upload).
     */
    SAVAPI_E_APC_UNKNOWN_CATEGORY = 100,
    /**
     * \brief APC quota limit reached
     * \note This error is given when APC quota limit has been reached. Please contact Avira support
     */
    SAVAPI_E_APC_QUOTA = 101,

    /**
    * \brief Unsupported compression method
    * \note The compression method of the archive is not supported.
    */
    SAVAPI_E_UNSUPPORTED_COMPRESSION = 1000,

    /**
    * \brief OnAccess has not been initialized
    * \note The used functionality requires the OnAccess library to be initialized first
    * (a successful call of \ref SAVAPI_OA_initialize is needed before).
    */
    SAVAPI_E_OA_NOT_INITIALIZED = 2000,
    /**
    * \brief OnAccess was already initialized
    * \note Trying to initialize an already initialized OnAccess library (\ref SAVAPI_OA_initialize was
    * already called successfully).
    */
    SAVAPI_E_OA_INITIALIZED = 2001,
    /**
    * \brief OnAccess instances have not been created yet
    * \note Trying to do an action (for e.g. calling \ref SAVAPI_OA_start_scan) which requires OA instances to be created
    */
    SAVAPI_E_OA_NO_INSTANCES_CREATED = 2002,
    /**
    * \brief OnAccess instances have already been created
    * \note Trying to create OnAccess instances when they are already created
    *       (\ref SAVAPI_OA_create_instances was already called successfully).
    */
    SAVAPI_E_OA_INSTANCES_CREATED = 2003,
    /**
    * \brief No OnAccess scanning in progress
    * \note Trying to stop an OnAccess scan which is not in progress (\ref SAVAPI_OA_stop_scan was
    * already called successfully or no \ref SAVAPI_OA_start_scan was called).
    */
    SAVAPI_E_OA_NO_SCAN_IN_PROGRESS = 2004,
    /**
    * \brief OnAccess scanning is already in progress
    * \note Trying to start an OnAccess scan which is already in progress (\ref SAVAPI_OA_start_scan was
    * already called successfully).
    */
    SAVAPI_E_OA_SCAN_IN_PROGRESS = 2005,
    /**
     * \brief No valid OA license found in the key file
     */
    SAVAPI_E_OA_NO_LICENSE = 2006,
    /**
     * \brief Generic OnAccess-related error
     */
    SAVAPI_E_OA_ERROR = 2007,
    /**
     * \brief Not enough previleges when trying to initialize OnAccess module
     * \note Administrator privileges are needed.
     */
    SAVAPI_E_OA_NO_PRIVILEGES = 2008,
    /**
     * \brief OnAccess drivers are not installed or not running
     */
    SAVAPI_E_OA_DRIVERS = 2009,

    /**
     * \brief FPC timeout restrictions not met
     * \note This error is given when FPC was enabled and the user tries to set new FPC timeout
     * that do not comply with the following restriction: FPCTimeout < ScanTimeout.
     */
    SAVAPI_E_FPC_TIMEOUT_RESTRICTION = 3000,

    /*
     * \brief The SAVAPI Simple Scan has detected at least one infected file.
     * \note This code is only returned by the \ref SAVAPI_simple_scan function.
     */
    SAVAPI_S_INFECTED = 4000,

    /*
     * \brief The SAVAPI Simple Scan has detected at least one suspicious file, but no infected ones.
     * \note This code is only returned by the \ref SAVAPI_simple_scan function.
     */
    SAVAPI_S_SUSPICIOUS = 4001,

    /*
     * \brief The SAVAPI Simple Scan has returned an error for at least one file,
     * but no infected or suspicious ones
     * \note This code is only returned by the \ref SAVAPI_simple_scan function.
     */
    SAVAPI_E_SCAN_ERROR = 4002,
} SAVAPI_STATUS;

/** @} */

#endif /* SAVAPI_ERRORS_H__ */
