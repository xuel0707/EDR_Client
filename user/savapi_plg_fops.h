#ifndef SAVAPI_PLG_FOPS_H
#define SAVAPI_PLG_FOPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "fops.h"

/**
 * @defgroup Specific types for a SAVAPI FOPS plugin
 * @{
 */
#define SAVAPI_PLG_AVE_FOPS      _T("SAVAPI_AVE_FOPS")

typedef const char** SAVAPI_PLG_fops_options_t;     /** plugin's global init options   */
typedef void SAVAPI_PLG_fops_inst_options_t;        /** plugin's instance init options */

typedef struct _SAVAPI_PLG_fops_instance_t
{
    AVE_FOPS fops;                                  /** the fops structure             */
} SAVAPI_PLG_fops_instance_t;

/**
 *
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif    /* SAVAPI_PLG_FOPS_H */
