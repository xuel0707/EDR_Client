/*************************************************************************
    > File Name: sys_db_op.h
    > Author: Qushb
    > Created Time: Thu 17 Dec 2020 15:08:18 PM CST
 ************************************************************************/

#ifndef __SYS_DB_OP_H__
#define __SYS_DB_OP_H__

#include "../sqlite3.h"

sqlite3 *init_sys_db(const char *db_name, const char *key, unsigned int flag);

void close_db(sqlite3 *db);

int exec_sql(sqlite3 *db, const char *sql);

#endif
