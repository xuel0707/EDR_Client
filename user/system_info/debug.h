/*************************************************************************
    > File Name: sys_db_op.h
    > Author: Qushb
    > Created Time: Thu 17 Dec 2020 17:39:33 PM CST
 ************************************************************************/


#ifndef __DEBUG_H__
#define __DEBUG_H__

#define DEBUG 0

#ifdef DEBUG
#define dlog(fmt, ...) do { fprintf(stderr, ("[DBG][%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);} while(0)
#define elog(fmt, ...) fprintf(stderr, ("[ERR][%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);
#else
#define dlog(fmt, ...) do { ; } while(0)
#define vlog(fmt, ...) do { ; } while(0)
#endif

extern int sniper_debug;
#define slog(fmt, ...) if (sniper_debug) { fprintf(stderr, ("[DBG][%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);}

#endif
