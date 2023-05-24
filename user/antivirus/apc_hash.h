#ifndef _APC_HASHLIB_H_
#define _APC_HASHLIB_H_

#ifdef _WINDOWS
#   include <tchar.h>
#   ifdef APC_HASHLIB_DLL
#       define APC_HASH_EXPORT __declspec(dllexport)
#   else /* when using the DLL */
#       define APC_HASH_EXPORT __declspec(dllimport)
#   endif /* APC_HASHLIB_DLL */
#   ifndef CC
#       define CC _cdecl
#   endif /* CC */
#else /* on UNIX */
#   define APC_HASH_EXPORT
#   define TCHAR char
#   ifndef CC
#       define CC /* calling convention may not be defined on unix */
#   endif /* CC */
#endif /* _WINDOWS */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief This function computes the APC hash for a file
 * \param filepath       [IN]: The path of the file whose hash will be calculated
 * \param apc_hash      [OUT]: Pointer to a char that will hold the converted buffer
 *                             The parameter \ref apc_hash will be internally allocated
 *                             The caller is responsible to release the memory by calling APC_hash_free() on \ref apc_hash
 * \return The function will return 0 on success, an error code otherwise
 */
APC_HASH_EXPORT int CC APC_hash_file_compute(TCHAR* file_path, char **apc_hash);

/**
 * \brief Frees the memory space pointed to by ptr
 * \param ptr [IN/OUT]: Pointer who will become free and null
 * \return Nothing
 */
APC_HASH_EXPORT void CC APC_hash_free(void **ptr);

#ifdef __cplusplus
}
#endif
#endif /*_APC_HASHLIB_H_ */
