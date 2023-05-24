#ifndef XVDF_MERGE_LIB_H_
#define XVDF_MERGE_LIB_H_

#ifdef _WINDOWS
#   include <tchar.h>
#   ifdef XVDF_MERGE_LIB_DLL
#       define XVDF_MERGE_EXPORT __declspec(dllexport)
#   else /* when using the DLL */
#       define XVDF_MERGE_EXPORT __declspec(dllimport)
#   endif /* XVDF_MERGE_LIB_DLL */
#   ifndef CC
#       define CC _cdecl
#   endif /* CC */
#else /* on UNIX */
#   define XVDF_MERGE_EXPORT
#   define TCHAR char
#   ifndef CC
#       define CC /* calling convention may not be defined on unix */
#   endif /* CC */
#endif /* _WINDOWS */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * XVDF_files_merge return codes
 */
typedef enum
{
    XVDF_MERGE_S_OK                     = 0,   /**< Operation ended with success */
    XVDF_MERGE_E_NO_MEMORY              = 1,   /**< Memory allocation failed */
    XVDF_MERGE_E_INVALID_PARAMETER      = 2,   /**< One of supplied parameters is invalid */
    XVDF_MERGE_E_FILE_NOT_SIGNED        = 3,   /**< One of the files is not signed */
    XVDF_MERGE_E_PATH_NOT_EXIST         = 4,   /**< One of supplied paths does not exist */
    XVDF_MERGE_E_PATH_NO_READ_ACCESS    = 5,   /**< One of supplied paths does have read access */
    XVDF_MERGE_E_LOAD_LIBRARY           = 6,   /**< Loading library failed */
    XVDF_MERGE_E_ENGINE_VDF             = 101, /**< Error while loading VDF files */
    XVDF_MERGE_E_ENGINE_CHECK           = 102, /**< Engine check failed */
    XVDF_MERGE_E_ENGINE_ACCESS          = 103, /**< Error while accessing engine files */
    XVDF_MERGE_E_ENGINE_NOT_SUPPORTED   = 104, /**< Wrong API version or feature not supported */
    XVDF_MERGE_E_ENGINE_LOAD_MODULES    = 105, /**< Error while loading modules */
    XVDF_MERGE_E_ENGINE_MEMORY          = 106, /**< Engine memory allocation failed */
    XVDF_MERGE_E_ENGINE_INTERNAL        = 107  /**< Engine internal error */
} XVDF_MERGE_STATUS;


/**
 * \brief Function that merges the xVDF files
 * \param engine_dir  [IN]: Path to the engine files directory
 * \param xvdfs_dir   [IN]: Path to the xVDF files directory
 * \return 0 on success and an error otherwise
 * \note Before calling this function, the engine must not be initialized by any other application (SAVAPI, ICAP, Avira Antivirus, etc.)
 * \note The merged file will be written in the xvdfs_dir directory, therefore the application calling this function must have
 *       write permissions in that folder
 * \note TCHAR type is:
 *       - wchar_t on Windows
 *       - char on Unix
 */
XVDF_MERGE_EXPORT XVDF_MERGE_STATUS CC XVDF_files_merge(const TCHAR* engine_dir, const TCHAR* xvdfs_dir);

#ifdef __cplusplus
}
#endif

#endif /*XVDF_MERGE_LIB_H_ */
