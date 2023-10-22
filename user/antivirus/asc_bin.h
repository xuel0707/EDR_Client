#ifndef ASC_BIN_H_
#define ASC_BIN_H_

#include "savapi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \ingroup handle_funcs
 * \defgroup handle_funcs_hex2bin SAVAPI hex2bin function pointers
 * \brief Handle types for exported SAVAPI hex2bin functions
 * @{
 */

typedef int (CC *bin2hex_t)(const char *binblock, SAVAPI_SIZE_T binblock_size, char *hexblock, SAVAPI_SIZE_T *hexblock_size);
typedef int (CC *hex2bin_t)(const char *hexblock, SAVAPI_SIZE_T hexblock_size, char *binblock, SAVAPI_SIZE_T *binblock_size);

/**
 * @}
 * \brief Convert the file name to ASCII hex representation 
 * \param binblock  [IN]: The file name to convert
 * \param ascblock [OUT]: The ASCII hex file name representation
 * \return SAVAPI_S_OK for success or an error code
 *
 * \note The ascblock parameter will be internally allocated.
 *       The caller is responsible to release the memory (ie: calling SAVAPI_free() on ascblock).
 *       
 * \note This function is obsolete. Instead, please use the new, bin2hex() function.
 */
SAVAPI_EXP int CC bin2asc(const char *binblock, char **ascblock);

/**
 * \brief Convert ASCII hex representation to file name 
 * \param ascblock      [IN]: The ASCII hex block
 * \param ascblock_size [IN]: The ASCII hex block size
 * \param binblock     [OUT]: The converted file name
 * \return SAVAPI_S_OK for success or an error code
 *
 * \note The binblock parameter will be internally allocated.
 *       The caller is responsible to release the memory (ie: calling SAVAPI_free() on binblock).
 *       
 * \note This function is obsolete. Instead, please use the new, hex2bin() function.
 */
SAVAPI_EXP int CC asc2bin(const char *ascblock, SAVAPI_SIZE_T ascblock_size, char **binblock);

/**
 * \brief Transform the string given in binblock in the equivalent encoded string in hexblock.
 * 
 * \param binblock          [IN]: Buffer containing the string to be transformed.
 * \param binblock_size     [IN]: Number of characters to encode from the binblock
 * \param hexblock         [OUT]: Will contain the transformed buffer. Must be allocated by caller
 * \param hexblock_size [IN/OUT]: On input it contains the available size of the hexblock, on output will contain needed size for the resulted hexblock
 *                               It must be at least two times the binblock_size (each character will be displayed as 2 hexadecimal digits)
 * \return - SAVAPI_S_OK for success,
 *         - SAVAPI_E_INVALID_PARAMETER if one of the input parameters is NULL, or the binblock length
 * exceeds the maximum allowed buffer size
 *         - SAVAPI_E_BUFFER_TOO_SMALL if the given size is too small,
 *         - SAVAPI_E_CONVERSION_FAILED if the conversion could not be performed
 *         
 * \note If the hexblock buffer is not big enough it will return an error and will put the needed size 
 * in the hexblock_size parameter on output.
 * 
 * \note Unlike the bin2asc function, this functions does not internally allocate anything.
 *       It will use buffers allocated by the caller according to the given size.
 */
SAVAPI_EXP int CC bin2hex(const char *binblock, SAVAPI_SIZE_T binblock_size, char *hexblock, SAVAPI_SIZE_T *hexblock_size);

/**
 * \brief Converts a series of hex-encoded characters to normal binary encoding
 * \param hexblock          [IN]: Buffer containing an already encoded sequence of characters
 * \param hexblock_size     [IN]: Number of characters to decode from the hexblock
 * \param binblock         [OUT]: Contains the original string. Must be allocated by caller
 * \param binblock_size [IN/OUT]: On input contains the available size of the binblock, on output will contain needed size for the resulted binblock
 *                               It must be at least half the binblock_size (each character is displayed as 2 hexadecimal digits)
 * \return - SAVAPI_S_OK for success,
 *         - SAVAPI_E_INVALID_PARAMETER if one of the input parameters is NULL, or the binblock length
 * exceeds the maximum allowed buffer size
 *         - SAVAPI_E_BUFFER_TOO_SMALL if the given size is too small,
 *         - SAVAPI_E_CONVERSION_FAILED if the conversion could not be performed
 *         
 * \note Unlike the asc2bin function, this functions does not internally allocate anything.
 *       It will use buffers allocated by the caller according to the given size.
 */
SAVAPI_EXP int CC hex2bin(const char *hexblock, SAVAPI_SIZE_T hexblock_size, char *binblock, SAVAPI_SIZE_T *binblock_size);

#ifdef __cplusplus
}
#endif
#endif /*ASC_BIN_H_*/
