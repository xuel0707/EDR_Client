#include "header.h"
#include <sqlite3.h>

#define SQLITE_OPEN_MODE SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_SHAREDCACHE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE

#define DFT_BUSY_TIMEOUT 100*1000
int db_busy_callback(void *data, int count)
{
        if (count >= 10) {
                return 0;
	}
        usleep(DFT_BUSY_TIMEOUT);
        return SQLITE_ERROR;
}

sqlite3* connectDb(char *dbname, const char *crt_tbl_sql, char *pwd, int *first_time)
{
	int rc = 0, dbexist = 0;
	sqlite3 *db = NULL;
	struct stat st = {0};

	if (stat(dbname, &st) == 0) {
		if (st.st_size == 0) {
			unlink(dbname); //删除长度为0的无效的数据库文件
		} else {
			dbexist = 1;
		}
	}
	if (dbexist) {
		rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
		if (rc == SQLITE_OK) {
#ifdef DB_CRYPT
			if (pwd) {
				sqlite3_key(db, pwd, strlen(pwd));
			}
#endif
			rc = sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);
			if (rc == SQLITE_OK) {
				*first_time = 0;
				INFO("open db %s ok\n", dbname);
				return db;
			}
		}
		if (db) {
			sqlite3_close_v2(db);
		}
		MON_ERROR("open db %s fail: %s. rebuild it\n", dbname, sqlite3_errstr(rc));
		unlink(dbname);
	}

	/* 第一次创建新数据库，或打开老数据库失败，重建数据库 */
	rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
	if (rc == SQLITE_OK) {
		rc = sqlite3_exec(db, crt_tbl_sql, NULL, NULL, NULL);
		if (rc == SQLITE_OK) {
			*first_time = 1;
			INFO("create db %s success\n", dbname);
			return db;
		}
		MON_ERROR("create table in db %s fail: %s.   %s\n", dbname, sqlite3_errstr(rc), strerror(errno));
	}

	MON_ERROR("create db %s fail: %s.   %s\n", dbname, sqlite3_errstr(rc), strerror(errno));
	if (db) {
		sqlite3_close_v2(db);
	}
	return NULL;
}

sqlite3* connect_to_Db(char *dbname, const char *crt_tbl_sql, const char *crt_tbl_sql2, char *pwd, int *first_time)
{
	int rc = 0, dbexist = 0;
	sqlite3 *db = NULL;
	struct stat st = {0};

	if (stat(dbname, &st) == 0) {
		if (st.st_size == 0) {
			unlink(dbname); //删除长度为0的无效的数据库文件
		} else {
			dbexist = 1;
		}
	}
	if (dbexist) {
		rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
		if (rc == SQLITE_OK) {
#ifdef DB_CRYPT
			if (pwd) {
				sqlite3_key(db, pwd, strlen(pwd));
			}
#endif
			rc = sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);
			if (rc == SQLITE_OK) {
				*first_time = 0;
				INFO("open db %s ok\n", dbname);
				return db;
			}
		}
		if (db) {
			sqlite3_close_v2(db);
		}
		MON_ERROR("open db %s fail: %s. rebuild it\n", dbname, sqlite3_errstr(rc));
		unlink(dbname);
	}

	/* 第一次创建新数据库，或打开老数据库失败，重建数据库 */
	rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
	if (rc == SQLITE_OK) {
		rc = sqlite3_exec(db, crt_tbl_sql, NULL, NULL, NULL);
		sqlite3_exec(db, crt_tbl_sql2, NULL, NULL, NULL);
		if (rc == SQLITE_OK) {
			*first_time = 1;
			INFO("create db %s success\n", dbname);
			return db;
		}
		MON_ERROR("create table in db %s fail: %s.  %s\n", dbname, sqlite3_errstr(rc), strerror(errno));
	}

	MON_ERROR("create db %s fail: %s.  %s\n", dbname, sqlite3_errstr(rc), strerror(errno));
	if (db) {
		sqlite3_close_v2(db);
	}
	return NULL;
}

sqlite3* connect_five_tbl(char *dbname, const char *crt_tbl_sql, const char *crt_tbl_sql1, const char *crt_tbl_sql2, const char *crt_tbl_sql3, const char *crt_tbl_sql4, char *pwd, int *first_time)
{
	int rc = 0, dbexist = 0;
	sqlite3 *db = NULL;
	struct stat st = {0};

	if (stat(dbname, &st) == 0) {
		if (st.st_size == 0) {
			unlink(dbname); //删除长度为0的无效的数据库文件
		} else {
			dbexist = 1;
		}
	}
	if (dbexist) {
		rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
		if (rc == SQLITE_OK) {
#ifdef DB_CRYPT
			if (pwd) {
				sqlite3_key(db, pwd, strlen(pwd));
			}
#endif
			rc = sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);
			if (rc == SQLITE_OK) {
				*first_time = 0;
				INFO("open db %s ok\n", dbname);
				return db;
			}
		}
		if (db) {
			sqlite3_close_v2(db);
		}

		MON_ERROR("open db %s fail: %s. rebuild it\n", dbname, sqlite3_errstr(rc));
		unlink(dbname);
	}

	/* 第一次创建新数据库，或打开老数据库失败，重建数据库 */
	rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
	if (rc == SQLITE_OK) {
		rc = sqlite3_exec(db, crt_tbl_sql, NULL, NULL, NULL);
		sqlite3_exec(db, crt_tbl_sql1, NULL, NULL, NULL);
		sqlite3_exec(db, crt_tbl_sql2, NULL, NULL, NULL);
		sqlite3_exec(db, crt_tbl_sql3, NULL, NULL, NULL);
		sqlite3_exec(db, crt_tbl_sql4, NULL, NULL, NULL);
		if (rc == SQLITE_OK) {
			*first_time = 1;
			INFO("create db %s success\n", dbname);
			return db;
		}
		MON_ERROR("create table in db %s fail: %s.  %s\n", dbname, sqlite3_errstr(rc), strerror(errno));
	}

	MON_ERROR("create db %s fail: %s.  %s\n", dbname, sqlite3_errstr(rc), strerror(errno));
	if (db) {
		sqlite3_close_v2(db);
	}
	return NULL;
}

