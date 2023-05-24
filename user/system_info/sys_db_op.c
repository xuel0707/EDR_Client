/*************************************************************************
    > File Name: sys_db_op.c
    > Author: Qushb
    > Created Time: Thu 17 Dec 2020 14:25:38 PM CST
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sys_db_op.h"
#include "debug.h"


/*
 * desc   :  Create database
 * args   :
 *    db_name :  Database name
 *    key     :  If empty, no encryption
 *    flag    :  Database flag
 * return :  Return a non-null pointer on success, return a null pointer on failure
 */
sqlite3 *init_sys_db(const char *db_name, const char *key, unsigned int flag)
{
    sqlite3 *db = NULL;
    int ret = 0;

    if (db_name == NULL) return NULL;

    if (flag == 0) {
        flag = SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_SHAREDCACHE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE;
    }

    ret = sqlite3_open_v2(db_name, &db, flag, NULL);
    if (ret != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }

#ifdef SQLCIPHER
    if (key != NULL) {
        char pwd[64];
        memset(pwd, 0x00, sizeof(pwd));
        snprintf(pwd, sizeof(pwd)-1, "%s", key);
        if (sqlite3_key(db , pwd , strlen(pwd)) != SQLITE_OK) {
            sqlite3_close(db);
            elog("encrypt failed\n");
            return NULL;
        }
    }
    dlog("Encrypt DB success\n");
#endif

    dlog("init DB success\n");

    return db;
}

void close_db(sqlite3 *db)
{
    if (db == NULL) return;

    sqlite3_close(db);

    return;
}


int exec_sql(sqlite3 *db, const char *sql)
{
    int ret = 0;
    char *err_msg = NULL;

    if (db == NULL || sql == NULL) return -1;

    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        elog("exec sql:%s failed, %s\n", sql, err_msg);
        sqlite3_free(err_msg);
        ret = -1;
    }

    return ret;
}
