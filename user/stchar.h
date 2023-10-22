#if !defined(_SAVAPI_TCHAR_CONVERSION_H__)
#define _SAVAPI_TCHAR_CONVERSION_H__
/**
 * \file stchar.h
 * \brief Conversion between SAVAPI_TCHAR and char/TCHAR
 *
 * UNICODE (WIN) SAVAPI_TCHAR = wchar_t(UCS2) |  char(UTF-8)
 * UNICODE (UNIX) SAVAPI_TCHAR = wchar_t(UCS2) | char(locale)
 * ANSI (WIN + UNIX) SAVAPI_TCHAR = char(locale)  | char(locale)
 */

#include "savapi_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

#if 0
/* Checks for the platform defines: _WINDOWS or _UNIX */
#if !defined(_WINDOWS) && !defined(_UNIX)
#   error    "Please define a supported platform!"
#endif /* !defined(_WINDOWS) && !defined(_UNIX) */

/* Checks for the build encoding defines: _UNICODE or _ANSI */
#if !defined(_UNICODE) && !defined(_ANSI)
#   error    "Please define a supported encoding!"
#endif /* !defined(_UNICODE) && !defined(_ANSI) */
#endif

#ifdef _WINDOWS
#   ifdef MAKINGDLL_SAVAPI
#       define SAVAPI_EXP __declspec(dllexport)
#   else /* when using the DLL */
#       define SAVAPI_EXP __declspec(dllimport)
#   endif /* MAKINGDLL_SAVAPI */
#   ifndef CC
#       define CC _cdecl
#   endif /* CC */
#else /* on UNIX */
#   define SAVAPI_EXP
#   ifndef CC
#       define CC /* calling convention may not be defined on unix */
#   endif /* CC */
#endif /* _WINDOWS */

#if defined(_WINDOWS)
#   include <tchar.h>
#   define SAVAPI_TCHAR TCHAR
#   define SAVAPI_SIZE_T size_t
#else /* _UNIX */
#   if defined(_UNICODE) /* UNIX, UNICODE */
#       if defined(_SAVAPI_UTF8)
#           include <stddef.h>
#           define SAVAPI_TCHAR char
#       else /* wchar_t */
#           include <wchar.h>
#           define SAVAPI_TCHAR wchar_t
#       endif /* _SAVAPI_UTF8 */
#   define SAVAPI_SIZE_T size_t
#   else /* UNIX, ANSI */
#       define SAVAPI_TCHAR char
#       define SAVAPI_SIZE_T unsigned int
#   endif /* defined(_UNICODE) */
#endif /* _WINDOWS */

/**
 * \ingroup handle_funcs
 * \defgroup handle_funcs_stchar SAVAPI STCHAR function pointers
 * \brief Handle types for exported SAVAPI STCHAR functions
 * @{
 */

typedef SAVAPI_STATUS (CC *STCHARToChar_t)(char **pDest, const SAVAPI_TCHAR *pSrc);
typedef SAVAPI_STATUS (CC *CharToSTCHAR_t)(SAVAPI_TCHAR **pDest, const char *pSrc);
#ifdef _WINDOWS
    typedef SAVAPI_STATUS (CC *STCHARToTCHAR_t)(TCHAR **pDest, const SAVAPI_TCHAR *pSrc);
    typedef SAVAPI_STATUS (CC *TCHARToSTCHAR_t)(SAVAPI_TCHAR **pDest, const TCHAR *pSrc);
#endif /* _WINDOWS */

/**
 * @}
 * \brief Convert from char//TCHAR to a SAVAPI_TCHAR
 *
 * \param pDest [OUT]: Pointer to a SAVAPI_TCHAR that will hold the converted buffer
 * \param pSrc   [IN]: The buffer to convert.
 * \return SAVAPI_S_OK for success or an error code
 *
 * \note The pDest parameter will be internally allocated.
 *       The caller is responsible to release the memory by calling SAVAPI_free() on pDest.
 */

SAVAPI_EXP SAVAPI_STATUS CC CharToSTCHAR(SAVAPI_TCHAR **pDest, const char *pSrc);
#ifdef _WINDOWS
SAVAPI_EXP SAVAPI_STATUS CC TCHARToSTCHAR(SAVAPI_TCHAR **pDest, const TCHAR *pSrc);
#endif /* _WINDOWS */


/**
 * \brief Convert from a SAVAPI_TCHAR buffer to a char//TCHAR
 * \param pDest [OUT]: Pointer to a char that will hold the converted buffer
 * \param pSrc   [IN]: Pointer to the SAVAPI_TCHAR to convert
 * \return SAVAPI_S_OK for success or an error code
 *
 * \note The pDest parameter will be internally allocated.
 *       The caller is responsible to release the memory by calling SAVAPI_free() on pDest.
 */
SAVAPI_EXP SAVAPI_STATUS CC STCHARToChar(char **pDest, const SAVAPI_TCHAR *pSrc);
#ifdef _WINDOWS
SAVAPI_EXP SAVAPI_STATUS CC STCHARToTCHAR(TCHAR **pDest, const SAVAPI_TCHAR *pSrc);
#endif /* _WINDOWS */

#ifdef __cplusplus
}
#endif

#endif /* _SAVAPI_TCHAR_CONVERSION_H__ */
