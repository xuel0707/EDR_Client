/**
 * @file fops.h
 * @brief This file defines the interface to allow the engine to scan any type of object
 *
 * @warning Please take care to respect the following constrains when implementing the following functions:
 *
 * <B>open</B> @see _AVE_STRUCT_FILE_OPERATIONS::fops_open <BR>
 * The implementation needs to set the passed handle to invalid FOPS_INVALID_HANDLE in case of an error.
 *
 * <B>read</B> @see _AVE_STRUCT_FILE_OPERATIONS::fops_read <BR>
 * set *nread on error as well
 * reading 0 bytes is not an error case.
 *
 * <B>write</B> @see _AVE_STRUCT_FILE_OPERATIONS::fops_write <BR>
 * Set *nwritten in all error cases
 *
 * <B>tell</B> @see _AVE_STRUCT_FILE_OPERATIONS::fops_tell <BR>
 * *curpos must be -1 in all error cases
 *
 * <B>getfattr</B> @see _AVE_STRUCT_FILE_OPERATIONS::fops_getfattr <BR>
 * *attr must be set NULL in all error cases
 *
 * <B>getfsize</B> @see _AVE_STRUCT_FILE_OPERATIONS::fops_getfsize <BR>
 * *fsize must be 0 in all error cases
 */

/***
 * Usage of the 'fops_context' and 'file_context' parameters
 *
 * In general, the application can either use the standard FOPS provided by the
 * SAVAPI Library _OR_ it can implement its own FOPS functions in order to prevent
 * the SAVAPI Library from using the standard memory and file I/O functions, and
 * to use the application-defined functions instead.
 *
 * If an application decides to provide its own FOPS functions, it has to
 * implement _ALL_ memory and file I/O functions that are part of the
 * AVE_FOPS structure (defined in this header file).
 *
 * The 'fops_context' parameter is an opaque data set by the applications through
 * @ref SAVAPI_set_fops.
 * It is reserved for the application in order to pass user-defined data associated
 * with the FOPS instance to each FOPS function. SAVAPI Library passes it to all
 * FOPS functions without modifying its value.
 *
 * The 'file_context' parameter is internally used by the SAVAPI Library and it
 * should not be touched by the applications!
 **/


/*
 Doxygen has a problem parsing the function definitions below
 when the calling convention is used. This is why I have defined CC as _cdecl.
 If you want to generate the docs, just remove the string CC.
*/

#ifndef __FOPS_H
#define __FOPS_H


#include <stdio.h>
#include <sys/stat.h>

/* all functions are extern "C" */
#ifdef __cplusplus
extern "C"
{
#endif

#ifndef AVCORE
  #include "fopstypes.h"
#else
  #include "system.h"
#endif

/**

 @name  Some defines used along the code

 @name File Open modes
 @{
*/

/** Open Read Only */
#define OPEN_RO 0

/** Open Read/Write */
#define OPEN_RW 1

/** Create file*/
#define OPEN_CR 2

/**
@}
*/

/** Invalid handle. Set this when the file can not be created/accessed */
#define FOPS_INVALID_HANDLE NULL

/** Return this in the functions which return an error */
#define FOPS_ERROR 1

/** A generic definition of the FOPS_HANDLE.
 *  You may have anything you want here.
 */
typedef void *FOPS_HANDLE;

/** @name SEEK defines
 @{
*/
#ifndef SEEK_SET
/** Start from the beginning */
#  define SEEK_SET 0
/** Start from the current position */
#  define SEEK_CUR 1
/** Start from the end of the file */
#  define SEEK_END 2
#endif
/**
@}
*/

/** Special data type for our FOPS*/
typedef long _fpos_t;

/** Special attribute type for our FOPS */
typedef int  _fattr_t; /* S_IREAD, S_IWRITE */

/**
@}
*/

#ifndef CC
#   define CC _cdecl
#endif

/** @struct _AVE_STRUCT_FILE_OPERATIONS
 *  @brief The File OPerationS (FOPS) structure.
 *  Here are defined all the function prototypes which must be implemented in order to allow the scanning engine
 *  to process a special type of object.
 */
typedef struct _AVE_STRUCT_FILE_OPERATIONS
{
/** @brief Opens / creates a file
 *
 *  @param fh Will be set to the handle of the file just opened
 *  @param filename The name of the file to be opened
 *  @param mode The file open mode.It can be one of
 *               <BR>OPEN_RO - open for read access
 *               <BR>OPEN_RW - open for read and write access (default implementation locks file)
 *               <BR>OPEN_CR - create or truncate the file (with read + write access, default implementation locks file)
 *  @param file_context File-specific context, it's internally used by the SAVAPI Library and should not be modified by the apps.
 *  @param fops_context The context of the scan. It can be anything.
 *  @return Zero if successfully opened / created or non-zero if failed
 */
int (CC *fops_open)(FOPS_HANDLE *fh, void *filename, int mode, void *file_context, void *fops_context);

/** @brief Closes a file handle
 *
 *  @param fh The file handle to be closed
 *  @param fops_context The context of the scan. It can be anything.
 *  @return Zero if successful closed or non-zero if it failed.
 */
int (CC *fops_close)(FOPS_HANDLE *fh, void *fops_context);

/** @brief Reads 'count' bytes from file 'fh' into 'buffer'
 *
 *  @param fh The file handle to read from
 *  @param buffer The buffer to write the bytes read from the handle
 *  @param count The amount of bytes to be read
 *  @param nread The number of bytes actually read, even in error case
 *  @param fops_context The context of the scan. It can be anything.
 *  @return Zero if successful or non-zero on error
 *
 *  @warning *nread may be less than count on EOF condition
 *
 */
int (CC *fops_read)(FOPS_HANDLE fh, void *buffer, UINT64 count, UINT64 *nread, void *fops_context);

/** @brief Writes 'count' bytes from 'buffer' into file 'fh'
 *
 *  @param fh The file handle to write to
 *  @param buffer The buffer which will be written into the handle
 *  @param count The amount of bytes to write
 *  @param nwritten The number of bytes actually written, even in error case
 *  @param fops_context The context of the scan. It can be anything.
 *
 *  @warning *nwritten may be less than count if the disk is full
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_write)(FOPS_HANDLE fh, void *buffer, UINT64 count, UINT64 *nwritten, void *fops_context);

/** @brief Gets the current position in the file
 *
 *  @param fh The file handle
 *  @param curpos The current file position; it is set to -1 on error
 *  @param fops_context The context of the scan. It can be anything.
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_tell)(FOPS_HANDLE fh, INT64 *curpos, void *fops_context);

/** @brief Sets the current file position to 'offset' (relative to 'wherefrom')
 *
 *
 *  @param fh The file handle
 *  @param offset The position in the file  (relative to 'wherefrom')
 *  @param wherefrom The position in the file. It may be one of
 *       <BR>SEEK_SET - set absolute file position
 *       <BR>SEEK_CUR - add offset to current position
 *       <BR>SEEK_END - seek offset bytes from end of file
 *  @param fops_context The context of the scan. It can be anything.
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_seek)(FOPS_HANDLE fh, INT64 offset, int wherefrom, void *fops_context);

/** @brief Gets the file's attributes
 *
 *  @param filename The name of the file
 *  @param attr The actual file attributes, *attr must be NULL on error
 *  @param file_context File-specific context, it's internally used by the SAVAPI Library and should not be modified by the apps.
 *  @param fops_context The context of the scan. It can be anything.
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_getfattr)(void *filename, _fattr_t *attr, void *file_context, void *fops_context);

/** @brief Sets the file's attributes
 *
 *  @param filename The name of the file
 *  @param attr The attribute to be set. It may be
 *              <BR>S_IREAD
 *              <BR>S_IWRITE
 *              <BR>S_IREAD
 *              <BR>S_IWRITE
 *  @param file_context File-specific context, it's internally used by the SAVAPI Library and should not be modified by the apps.
 *  @param fops_context The context of the scan. It can be anything.
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_setfattr)(void *filename, _fattr_t attr, void *file_context, void *fops_context);

/** @brief Gets the file's size
 *
 *  @param fh The file handle
 *  @param fsize The file size returned
 *  @param file_context The file context, usually a handler(HANDLE, int, FILE*, etc.)
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_getfsize)(FOPS_HANDLE fh, INT64 *fsize, void *fops_context);

/** @brief Deletes a file
 *
 *  @param file_name The file name to be deleted
 *  @param file_context File-specific context, it's internally used by the SAVAPI Library and should not be modified by the apps.
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_unlink)(void *filename, void *file_context, void *fops_context);

/** @brief Renames a file
 *
 *  @param oldname The old file name to be renamed
 *  @param newname The new file name to be set
 *  @param file_context File-specific context, it's internally used by the SAVAPI Library and should not be modified by the apps.
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return Zero if successful or non-zero on error
 */
int (CC *fops_rename)(void *oldname, void *newname, void *file_context, void *fops_context);

/** @brief tries to access a file with a specific access
 *
 *  @param amode The mode to access the file. It can be one of
 *                              <BR>0 Existence only
 *                              <BR>2 Write-only
 *                              <BR>4 Read-only
 *                              <BR>6 Read and write
 *  @param file_context File-specific context, it's internally used by the SAVAPI Library and should not be modified by the apps.
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return Returns 0 if the file is accessible with the given mode, 1 if it is not accessible
 */
int (CC *fops_access)(void *filename, int amode, void *file_context, void *fops_context);

/** @brief allocates memory
 *
 *  @param size amount of bytes to be allocated
 *  @param file_context the file context, usually a handler(HANDLE, int, FILE*, etc.)
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return Zero (NULL) if there is not enough memory is available or a pointer to the allocated memory if the memory was allocated
 */
void *(CC *fops_malloc)(UINT64 size, void *fops_context);

/** @brief frees the memory allocated by fops_malloc @see fops_malloc
 *
 *  @param ptr the pointer to be released
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return Nothing
 */
void (CC *fops_free)(void *ptr, void *fops_context);

/** @brief Read a complete string from an opened file.
 *
 * @note The string will end either when a 0 termination character or a carriage return is found.<BR>
 *       See also fgets ANSI function. Note that there is no text mode behavior, only binary.
 *
 *  @param fh The file handle to read from
 *  @param str The buffer where to store the chars
 *  @param num The maximum length to read
 *  @param fops_context The context of the scan. It can be anything.
 *  @return The string (same as in str) or NULL if an error occurs
 */
char *(CC *fops_gets)(FOPS_HANDLE fh, char *str, int num, void *fops_context);

/** @brief Write a complete string to an opened file.
 *
 *  @note The string will end when a 0 termination character is found. <BR>
 *        See also fputs ANSI function. Note that there is no text mode behavior, only binary.
 *
 *  @param fh The file handle to write to
 *  @param str The buffer which contains the chars
 *  @param fops_context The context of the scan. It can be anything.
 *
 *  @return Returns on success, a non-negative value. On error, the function returns -1.
 */
int (CC *fops_puts)(FOPS_HANDLE fh, char *str, void *fops_context);

/** @brief Gets a character from an opened file
 *
 *  @param fh The file handle to write to
 *      Returns the character   currently pointed by the internal file position indicator of the specified stream.<BR>
 *      The internal file position indicator is then advanced by one character to point to the next character.<BR>
 *      fgetc and getc are equivalent, except that the latter one may be implemented as a macro.
 *
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return The character read is returned as an int value. If the End-of-File is reached or a reading error occurs,
 *      the function returns -1
 */
int (CC *fops_getc)(FOPS_HANDLE fh, void *fops_context);

/** @brief Writes a character to a stream
 *
 *  @note Writes a single byte to the file at the current offset and advances the position indicator.
 *  @param fh The file handle to write
 *  @param character The character to be written.
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return If there are no errors, the same character that has been written is returned.If an error occurs, -1 is returned.
 */
int (CC *fops_putc)(FOPS_HANDLE fh, int character, void *fops_context);

/** @brief      Ungets a character from the stream
 *
 *  @note A character is virtually put back into an input stream at the same position the last character
 *      was read and the internal file position indicator is decreased back to that previous position,
 *      so that this character is returned by the next call to a reading operation on that stream.
 *      This character MUST be the same character as the one last read from the stream in a previous operation.
 *      If it differs the resulting behaviour is UNDEFINED.The default fops as implemented by the engine
 *      supports submitting a different character just like the ansi ungetc, however this
 *      should not be relied upon in all circumstances since this provides a
 *      big obstacle to implementations that don't have access to equivalents of the ansi
 *      streaming file functions.
 *      If the End-Of-File internal indicator was set, it is cleared after a call to this function.
 *      If the argument passed for the character parameter is EOF, the operation fails.
 *
 *  @param fh The file handle to write to
 *  @param character The character to be put back. The character is passed as its int promotion.
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return If successful, the character that was pushed back is returned. On failure, -1 is returned and the stream remains unchanged.
 */
int (CC *fops_ungetc)(FOPS_HANDLE fh, int character, void *fops_context);

/** @brief      Flushes pending file operations.
 *
 *  @note Flushes potentially pending operations, so parallel calls to fops_open/fops_read will result in
 *  up-to-date data to be read
 *
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return Returns 0 on success.On failure, -1 is returned and the stream remains unchanged.
 */
int (CC *fops_flush)(FOPS_HANDLE fh, void *fops_context);

/** @brief Gets the last known error from the fops
 *
 *  @param fops_context The context of the scan. It It can be anything..
 *  @return The error code as defined by this fops (platform/fops-specific) 0 is no error
 */
int (CC *fops_get_last_error)(void *fops_context);

} AVE_FOPS;

extern int f_check_mem;
void check_free_mem(void);
int  e_tempname(void *dir);

extern AVE_FOPS _user_fops;

#ifdef __cplusplus
}
#endif

#endif /* __FILEIO_H */


