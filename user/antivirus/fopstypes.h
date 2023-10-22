#ifndef __FOPSTYPES_H
#define __FOPSTYPES_H

#ifndef DISABLE_AVETYPES

#if defined(__WIN32__) || defined(_WIN32) || defined(WIN32)
  #include <BaseTsd.h> 
#else
  #include <sys/types.h>
  #ifndef  _cdecl 
    #define _cdecl
  #endif
  #if defined(__sun__)
    typedef uint64_t        UINT64;
    typedef int64_t         INT64;
    typedef uint32_t        UINT32;
    typedef int32_t         INT32;
    typedef uint16_t        UINT16;
    typedef int16_t         INT16;
    typedef uint8_t         UINT8;
    typedef int8_t          INT8;
  #else
    typedef u_int64_t       UINT64;
    typedef int64_t         INT64;
    typedef u_int32_t       UINT32;
    typedef int32_t         INT32;
    typedef u_int16_t       UINT16;
    typedef int16_t         INT16;
    typedef u_int8_t        UINT8;
    typedef int8_t          INT8;
  #endif
#endif

#endif

#endif // __AVETYPES_H

