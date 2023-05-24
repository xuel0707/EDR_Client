#include "header.h"

sqlite3* trust_db = NULL;
int first_trust_check = 0;

const char crt_trust_tbl_sql[1024] =
{
    "CREATE TABLE IF NOT EXISTS trust( "
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "mtime int,"                               //备份时间
    "path  varchar(4096),"                     //信任区路径
    "uid int);"                                //操作用户uid
};

const char* trust_new_sql = "INSERT INTO trust VALUES(NULL,?,?,?);";
const char* trust_delete_sql = "DELETE FROM trust WHERE path=? and uid=?;";
const char* trust_select_sql = "SELECT mtime, uid, path FROM trust;";
const char* trust_select_uid_sql = "SELECT uid FROM trust WHERE path=?;";
const char* trust_clean_sql = "DELETE FROM trust WHERE uid=?;";

sqlite3_stmt* trust_new_stmt = NULL;
sqlite3_stmt* trust_delete_stmt = NULL;
sqlite3_stmt* trust_select_stmt = NULL;
sqlite3_stmt* trust_select_uid_stmt = NULL;
sqlite3_stmt* trust_clean_stmt = NULL;


int init_trust_db(void)
{
	char dbname[140] = {0};

	snprintf(dbname, 140, "%s/%s/trust.db", WORKDIR, VIRUSDB);
	trust_db = connectDb(dbname, crt_trust_tbl_sql, NULL, &first_trust_check);
	if (trust_db == NULL) {
//		printf("Error: Failed to open database\n");
		return -1;
	}
	chmod(dbname, 0666);

	sqlite3_busy_handler(trust_db, db_busy_callback, NULL );
	sqlite3_prepare_v2(trust_db, trust_new_sql, -1, &trust_new_stmt, NULL);
	sqlite3_prepare_v2(trust_db, trust_delete_sql, -1, &trust_delete_stmt, NULL);
	sqlite3_prepare_v2(trust_db, trust_select_sql, -1, &trust_select_stmt, NULL);
	sqlite3_prepare_v2(trust_db, trust_select_uid_sql, -1, &trust_select_uid_stmt, NULL);
	sqlite3_prepare_v2(trust_db, trust_clean_sql, -1, &trust_clean_stmt, NULL);

	return 0;
}

void fini_trust_db(void)
{
	if (trust_db == NULL) {
		return;
	}

	sqlite3_finalize(trust_new_stmt);
	sqlite3_finalize(trust_delete_stmt);
	sqlite3_finalize(trust_select_stmt);
	sqlite3_finalize(trust_select_uid_stmt);
	sqlite3_finalize(trust_clean_stmt);
	sqlite3_close_v2(trust_db);
}

/* 由于设计缺陷，4.0.9以前的数据库没有uid这一列，此函数检测修复所有数据库，对没有uid成员的trust表添加uid列 */
void repair_trust_db(void)
{
	char buf[1024] = {0};
	int rc = 0, nrow = 0, ncolumn = 0;
	char **azResult = NULL;

	snprintf(buf, sizeof(buf), "select count(*) from sqlite_master  where name='trust' and sql like '%%uid%%';");
	rc = sqlite3_get_table(trust_db, buf, &azResult, &nrow, &ncolumn, NULL);
	if (rc != SQLITE_OK) {
		MON_DBG("Detect uid column in trust database failed:%s(%d)\n", sqlite3_errstr(rc), rc);
		return;
	}

	if (nrow == 0) {
		return;
	}

	/*
	 * 执行结果放在azResult数组中, azResult[0]是列名，azResult[1]才是需要的值
	 * azResult[0]值为1的时候表示有uid这一列，为0的时候表示没有uid这一列
	 */
	/*
 	 * 新添加uid列后，数据库中每条记录里uid值不会自动赋值，显示为空，调用接口获取uid数值结果为0
	 * 对于以前没有记录uid的都当做超级用户操作的来处理，因此查询的时候获取到uid结果为0则不用做特殊处理
	 */
	if (atoi(azResult[1]) == 0) {
		sqlite3_free_table(azResult);
		snprintf(buf, sizeof(buf), "alter table trust add column uid int;");
		rc = sqlite3_get_table(trust_db, buf, &azResult, &nrow, &ncolumn, NULL);
		if (rc != SQLITE_OK) {
			MON_DBG("alter table trust add column uid failed:%s(%d)\n", sqlite3_errstr(rc), rc);
			return;
		}

		/* 需要重新加载影响的sql操作 */
		sqlite3_finalize(trust_select_stmt);
		sqlite3_prepare_v2(trust_db, trust_select_sql, -1, &trust_select_stmt, NULL);
	}

	sqlite3_free_table(azResult);
	return; 
}

static int path_type_check(char *path)
{
	struct stat st = {0};

	if (lstat(path, &st) < 0) {
		MON_DBG("get path:%s stat error: %s\n", path, strerror(errno));
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		return PATH_TYPE_DIR;
	}

	if (S_ISREG(st.st_mode)) {
		return PATH_TYPE_FILE;
	}

	MON_DBG("Path:%s is not regular file or dir\n");
	return PATH_TYPE_OTHER;
}

int check_file_accessible(char *path)
{
	DIR *dp = NULL;
	FILE *fp = NULL;
	int ret = 0;

	ret = path_type_check(path);
	if (ret == PATH_TYPE_FILE) {
		fp = fopen(path, "r");
		if (!fp) {
			MON_DBG("open %s failed!:%s\n", path, strerror(errno));
			return -1;
		}
		fclose(fp);
	} else if (ret == PATH_TYPE_DIR) {
		dp = opendir(path);
		if (!dp) {
			MON_DBG("open %s failed!:%s\n", path, strerror(errno));
			return -1;
		}
		closedir(dp);
	} else {
		return -1;
	}

	return 0;
}

int query_trust_path(int argc)
{
	int mtime = 0, uid = 0;
	char time_str[TIME_LEN] = {0};
	struct passwd *uid_info;

	if (argc != 3) {
		printf("Error: Wrong parameters\n");
		show_usage();
		return -1;
	}

	printf("Time\t\t\tUser\t\tTrust path\n");
	sqlite3_reset(trust_select_stmt);
	while (sqlite3_step(trust_select_stmt) == SQLITE_ROW) {
		mtime = sqlite3_column_int(trust_select_stmt,0);
		uid = sqlite3_column_int(trust_select_stmt,1);
		const char *path = (const char *)sqlite3_column_text(trust_select_stmt,2);
		get_time_string(mtime, time_str, sizeof(time_str));

		/* root用户自己设置的信任区，普通用户显示自己和root用户设置的信任区 */
		if (uid == 0 || exec_uid == uid) {

			uid_info = getpwuid(uid);
			if (!uid_info || !uid_info->pw_name) {
				continue;
			}

			if (strlen(uid_info->pw_name) < 8) {
				printf("%s\t%s\t\t%s\n", time_str, uid_info->pw_name, path);
			} else {
				printf("%s\t%s\t%s\n", time_str, uid_info->pw_name, path);
			}
		}

	}

	return 0;
}

int  clean_trust_path(int argc)
{
	int rc = 0;

	if (argc != 3) {
		printf("Error: Wrong parameters\n");
		show_usage();
		return -1;
	}

	sqlite3_reset(trust_clean_stmt);
	sqlite3_bind_int(trust_clean_stmt, 1, exec_uid);
	rc = sqlite3_step(trust_clean_stmt);
	if (rc != SQLITE_DONE) {
		MON_DBG("Sql clean trust path fail: %s(%d)\n", sqlite3_errstr(rc), rc);
		return -1;
	}

	return 0;
}

static int add_path_to_trust_db(char *path)
{

	char buf[1024] = {0};
	int rc = 0, nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	int ret = 1;
	struct timeval tv = {0};

	if (check_file_accessible(path) < 0) {
		return -1;
	}

	gettimeofday(&tv, NULL);

	snprintf(buf, sizeof(buf), "SELECT * FROM trust WHERE path='%s' and uid=%d;", path, exec_uid);
	rc = sqlite3_get_table(trust_db, buf, &azResult, &nrow, &ncolumn, NULL);
	if (rc != SQLITE_OK) {
		MON_DBG("Get path:%s record error:%s(%d)\n",path, sqlite3_errstr(rc), rc);
		return -1;
	}

	if (nrow == 0) {
		sqlite3_reset(trust_new_stmt);
		sqlite3_bind_int(trust_new_stmt, 1, tv.tv_sec);
		sqlite3_bind_text(trust_new_stmt, 2, path, -1, SQLITE_STATIC);
		sqlite3_bind_int(trust_new_stmt, 3, exec_uid);
		rc = sqlite3_step(trust_new_stmt);
		if (rc != SQLITE_DONE) {
			MON_DBG("Sql inserted new trust:%s failed: %s(%d)\n", path, sqlite3_errstr(rc), rc);
			ret = -1;
		}
	} else {
		MON_DBG("Path:%s is already in the trusted path\n", path);
		ret = 0;
	}
	sqlite3_free_table(azResult);

	return ret;
}

int add_trust_path(int argc, char **argv)
{
	int num = 0, i = 0;
	char *path = NULL;
	int ret = 0;
	int count = 0;

	if (argc < 4) {
		printf("Error: Missing parameters\n");
		show_usage();
		return -1;
	}

	num = argc - 3;
	for (i = 0; i < num; i++) {
		path = argv[i+3];
		if (path[0] != '/') {
			MON_DBG("Path:%s is not a correct path format\n", path);
			continue;
		}
		ret = add_path_to_trust_db(path);
		if (ret < 0) {
			MON_DBG("Error: Add path:%s failed\n", path);
		}
		if (ret > 0) {
			count++;
		}
	}

	return count;
}

static int delete_path_from_trust_db(char *path)
{
	int uid = 0;
	int root_match = 0;
	int self_match = 0;
	int ret = -1, rc = 0;

	sqlite3_reset(trust_select_uid_stmt);
	sqlite3_bind_text(trust_select_uid_stmt, 1, path, -1, SQLITE_STATIC);
	while (sqlite3_step(trust_select_uid_stmt) == SQLITE_ROW) {
		uid = sqlite3_column_int(trust_select_uid_stmt,0);
		if (uid == exec_uid) {
			self_match = 1;
			sqlite3_reset(trust_delete_stmt);
			sqlite3_bind_text(trust_delete_stmt, 1, path, -1, SQLITE_STATIC);
			sqlite3_bind_int(trust_delete_stmt, 2, exec_uid);
			rc = sqlite3_step(trust_delete_stmt);
			if (rc != SQLITE_DONE) {
				MON_DBG("Sql deleted trust path:%s failed: %s(%d)\n", path, sqlite3_errstr(rc), rc);
				ret = -1;
			} else {
				ret = 1;
			}
			break;
		}
		
		if (uid == 0 && uid != exec_uid) {
			root_match = 1;
		}

	}

	/*
	 * 删除的路径如果只有普通用户设置过，直接删除
	 * 如果只有超级用户设置过，提示权限报错，
	 * 如果普通用户和超级用户都有设置，只删除普通用户设置的路径，不提示权限问题
	 */
	if (self_match != 1 && root_match == 1) {
		printf("Error: Permission denied. %s is set by root\n", path);
	}

	return ret;
}

int delete_trust_path(int argc, char **argv)
{
	int num = 0, i = 0;
	char *path = NULL;
	int ret = 0;
	int count = 0;

	if (argc < 4) {
		printf("Error: Missing parameters\n");
		show_usage();
		return -1;
	}

	num = argc - 3;
	for (i = 0; i < num; i++) {
		path = argv[i+3];
		if (path[0] != '/') {
			MON_DBG("path:%s is not a correct path format\n", path);
			continue;
		}
		ret = delete_path_from_trust_db(path);
		if (ret < 0) {
			MON_DBG("delete path:%s failed\n", path);
		}
		if (ret > 0) {
			count++;
		}
	}

	return count;
}

int trust_path_operate(int argc, char **argv)
{
	int ret = 0;

	if (argc < 3) {
		printf("Error: Missing parameters\n");
		show_usage();
		return -1;
	}

	if (init_trust_db() < 0) {
		printf("Error: Failed to operate database\n");
		return -1;
	}

	/* 4.0.9之前的数据库没有uid这一列, 新版本检查并添加这一列 */
	repair_trust_db();

	if (strcmp(argv[2], "query") == 0) {
		ret = query_trust_path(argc);
		if (ret < 0) {
			printf("Query trust zone failed\n");
		}
        } else if (strcmp(argv[2], "clean") == 0) {
		ret = clean_trust_path(argc);
		if (ret < 0) {
			printf("Clean trust zone failed\n");
		}
        } else if (strcmp(argv[2], "add") == 0) {
                ret = add_trust_path(argc, argv);
                if (ret > 1) {
                        printf("Total of %d paths were added\n", ret);
		} else if (ret == 1) {
			printf("Total of %d paths was added\n", ret);
		} else if (ret == 0) {
			printf("No path need to add\n");
                } else {
			printf("Add trust path failed\n");
		}
        } else if (strcmp(argv[2], "delete") == 0)  {
                ret = delete_trust_path(argc, argv);
		if (ret > 1) {
			printf("Total of %d paths were deleted\n", ret);
		} else if (ret == 1) {
			printf("Total of %d path was deleted\n", ret);
		} else if (ret == 0) {
			printf("No path need to deleted\n");
		} else {
			printf("Delete trust path failed\n");
		}
        } else {
		show_usage();
                ret = -1;
        }

	print_tips();
	fini_trust_db();

	return ret;
}

