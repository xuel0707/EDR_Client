#include "header.h"
#include <sqlite3.h>

int first_group_check = 0;
struct timeval grpchktv = {0};
sqlite3* group_db = NULL;

const char crt_group_tbl_sql[1024] =
{
    "CREATE TABLE IF NOT EXISTS groupinfo( "
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "name varchar(64) UNIQUE,"         //组名
    "gid int,"                         //组ID
    "userlist varchar(1024),"          //组用户
    "lastchk int);"                    //上次检查时间
};

const char* group_new_sql = "INSERT INTO groupinfo VALUES(NULL,?,?,?,?);";
const char* group_chg_sql = "UPDATE groupinfo SET lastchk=?,gid=?,userlist=?,name=? WHERE id=?;";
const char* group_unchg_sql = "UPDATE groupinfo SET lastchk=? WHERE id=?;";
const char* group_sdel_sql = "SELECT id,name FROM groupinfo WHERE lastchk!=?;";
const char* group_del_sql = "DELETE FROM groupinfo WHERE id=?;";

const char* group_passwd_sql = "SELECT name FROM groupinfo WHERE name=?;";

sqlite3_stmt* group_new_stmt = NULL;
sqlite3_stmt* group_chg_stmt = NULL;
sqlite3_stmt* group_unchg_stmt = NULL;
sqlite3_stmt* group_sdel_stmt = NULL;
sqlite3_stmt* group_del_stmt = NULL;
sqlite3_stmt* group_passwd_stmt = NULL;

static void group_db_init(void)
{
	char dbfile[128] = {0};

	snprintf(dbfile, sizeof(dbfile), "%s/%s", WORKDIR, DBDIR);
	if (access(dbfile, F_OK) != 0) {
		mkdir(dbfile, 0700);
	}

	snprintf(dbfile, sizeof(dbfile), "%s/%s/group.db", WORKDIR, DBDIR);
	group_db = connectDb(dbfile, crt_group_tbl_sql, NULL, &first_group_check);
	if (group_db == NULL) {
		return;
	}

	sqlite3_busy_handler(group_db, db_busy_callback, NULL );
	sqlite3_prepare_v2(group_db, group_new_sql   ,-1, &group_new_stmt   , NULL);
	sqlite3_prepare_v2(group_db, group_chg_sql   ,-1, &group_chg_stmt   , NULL);
	sqlite3_prepare_v2(group_db, group_unchg_sql ,-1, &group_unchg_stmt , NULL);
	sqlite3_prepare_v2(group_db, group_sdel_sql  ,-1, &group_sdel_stmt  , NULL);
	sqlite3_prepare_v2(group_db, group_del_sql   ,-1, &group_del_stmt   , NULL);
	sqlite3_prepare_v2(group_db, group_passwd_sql   ,-1, &group_passwd_stmt   , NULL);
}

void group_db_release(void)
{
	if (group_db == NULL) {
		return;
	}

	sqlite3_finalize(group_new_stmt);
	sqlite3_finalize(group_chg_stmt);
	sqlite3_finalize(group_unchg_stmt);
	sqlite3_finalize(group_sdel_stmt);
	sqlite3_finalize(group_del_stmt);
	sqlite3_finalize(group_passwd_stmt);
	sqlite3_close_v2(group_db);
}

int select_from_group(char *passwd_name)
{
	const char *name = NULL;

	sqlite3_reset(group_passwd_stmt);
	sqlite3_bind_text(group_passwd_stmt, 1, passwd_name, -1, SQLITE_STATIC);

	while (sqlite3_step(group_passwd_stmt) == SQLITE_ROW) {
		name = (const char *)sqlite3_column_text(group_passwd_stmt,0);
		if (name) {
			return 1;
		}
	}

	return 1;
}

static void send_group_msg(const char *user_name, const char *new_group, 
			   const char *old_group, const char* userlist,
			   const char *operation)
{
	char reply[REPLY_MAX] = {0};
	char uuid[S_UUIDLEN] = {0};
	struct timeval tv = {0};
	unsigned long event_time = 0;
	char *post = NULL;
	char *log_name = "UserGroupChange";
	cJSON *object = NULL;
	cJSON *arguments = NULL;

	if (operation == NULL) {
		return;
	}

	/* 用户组变更开关 */
	if (protect_policy_global.account.user_change.enable != MY_TURNON ||
			protect_policy_global.account.user_change.group.enable != MY_TURNON) {
		return;
	}

	/* 第一次创建数据库时，不发变化日志 */
	if (first_group_check) {
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) { //没取到uuid
		return;
	}
	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + tv.tv_usec / 1000;

	object = cJSON_CreateObject();
	arguments = cJSON_CreateObject();

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Account");
	cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddNumberToObject(object, "level", 1);    /* 关键 */
	cJSON_AddNumberToObject(object, "behavior", 0); /* 无 */
	cJSON_AddNumberToObject(object, "result", 0);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddStringToObject(object, "operating", operation);
	cJSON_AddNumberToObject(object, "terminate", 0); /* 策略配置的阻断开关 */

	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "ipv6_address", If_info.ipv6);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);		
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur); /* 策略ID */
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	/* 执行操作的用户
	 * 执行操作的用户拿不到，如果是空，Json中会缺少这一项，改为root用户
	 */
	cJSON_AddStringToObject(arguments, "subject_user", "root");
	if (strncmp(operation, "Rename", 6) == 0) { /* 用户重命名 */
		cJSON_AddStringToObject(arguments, "object_user_group", old_group);
		cJSON_AddStringToObject(arguments, "object_user_new_group", new_group);
	} else if (strncmp(operation, "Created", 7) == 0) {
		cJSON_AddStringToObject(arguments, "object_user_group", old_group);
		cJSON_AddStringToObject(arguments, "object_user_new_group", new_group);
	} else if (strncmp(operation, "Deleted", 7) == 0) {
		cJSON_AddStringToObject(arguments, "object_user_group", old_group);
		cJSON_AddStringToObject(arguments, "object_user_new_group", new_group);
	} else if (strncmp(operation, "Changed", 7) == 0) {
		cJSON_AddStringToObject(arguments, "object_user_group", old_group);
		cJSON_AddStringToObject(arguments, "object_user_new_group", new_group);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_USER, "--group change--%s\n", post);
	// INFO("--group change--%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "inotify");

	cJSON_Delete(object);
	free(post);
}

static void handle_group(char *name, gid_t gid, char *userlist)
{
	int rc = 0, nrow = 0, ncolumn = 0, id = 0, old_gid = 0;
	char **azResult = NULL;
	char *old_userlist = NULL;
	char buf[1024] = {0};

	if (name == NULL) {
		return ;
	}

        snprintf(buf, sizeof(buf), "SELECT id,gid,userlist FROM groupinfo WHERE name='%s';", name);
        rc = sqlite3_get_table(group_db, buf, &azResult, &nrow, &ncolumn, NULL);
	DBG2(DBGFLAG_GROUP, "SELECT group %s, rc %d(%d), nrow %d\n", name, rc, SQLITE_OK, nrow);
	if (rc != SQLITE_OK) {
		sqlite3_free_table(azResult);
		return;
	}

	if (nrow == 0) { //新组
		/* 重命名groudmod -n newName oldName, gid相同,名字不同 */
		memset (buf, 0x00, sizeof(buf));
		snprintf(buf, sizeof(buf), "SELECT id,name,userlist FROM groupinfo WHERE gid='%u';", gid);
		if (sqlite3_get_table(group_db, buf, &azResult, &nrow, &ncolumn, NULL) == SQLITE_OK) {
			if (nrow) { /* gid已存在 */
				id = atoi(azResult[ncolumn]);
				char *tmp_name = azResult[ncolumn+1];
				send_group_msg(NULL, name, tmp_name, NULL, "Rename");
				
				sqlite3_reset(group_chg_stmt);
				sqlite3_bind_int(group_chg_stmt,1,grpchktv.tv_sec);
				sqlite3_bind_int(group_chg_stmt,2,gid);
				sqlite3_bind_text(group_chg_stmt,3,userlist,-1,SQLITE_STATIC);
				sqlite3_bind_text(group_chg_stmt,4,name,-1,SQLITE_STATIC);
				sqlite3_bind_int(group_chg_stmt,5,id);
				if ((rc = sqlite3_step(group_chg_stmt)) != SQLITE_DONE) {
					MON_ERROR("sql update rename group fail: %s(%d)\n", sqlite3_errstr(rc), rc);
				}

				sqlite3_free_table(azResult);
				return;
			}
		}
		send_group_msg(NULL, NULL, name, NULL, "Created");

		sqlite3_reset(group_new_stmt);
		sqlite3_bind_text(group_new_stmt,1,name,-1,SQLITE_STATIC);
		sqlite3_bind_int(group_new_stmt,2,gid);
		sqlite3_bind_text(group_new_stmt,3,userlist,-1,SQLITE_STATIC);
		sqlite3_bind_int(group_new_stmt,4,grpchktv.tv_sec);
		if ((rc = sqlite3_step(group_new_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql insert new group %s:%d:%s fail: %s(%d)\n",
				name, gid, userlist, sqlite3_errstr(rc), rc);
		}

		sqlite3_free_table(azResult);
		return;
	}

	id = atoi(azResult[ncolumn]);
	old_gid = atoi(azResult[ncolumn+1]);
	old_userlist = azResult[ncolumn+2];

	if (gid != old_gid) { //gid不同，说明是删了老的组，又建了新的同名组
		send_group_msg(NULL, NULL, name, NULL, "Deleted");
		send_group_msg(NULL, NULL, name, NULL, "Created");

		sqlite3_reset(group_chg_stmt);
		sqlite3_bind_int(group_chg_stmt,1,grpchktv.tv_sec);
		sqlite3_bind_int(group_chg_stmt,2,gid);
		sqlite3_bind_text(group_chg_stmt,3,userlist,-1,SQLITE_STATIC);
		sqlite3_bind_text(group_chg_stmt,4,name,-1,SQLITE_STATIC);
		sqlite3_bind_int(group_chg_stmt,5,id);
		if ((rc = sqlite3_step(group_chg_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql update chg group fail: %s(%d)\n", sqlite3_errstr(rc), rc);
		}

	} else if (strcmp(userlist, old_userlist) != 0) { //组用户有变化
		send_group_msg(name, userlist, old_userlist, userlist, "Rename");

		sqlite3_reset(group_chg_stmt);
		sqlite3_bind_int(group_chg_stmt,1,grpchktv.tv_sec);
		sqlite3_bind_int(group_chg_stmt,2,gid);
		sqlite3_bind_text(group_chg_stmt,3,userlist,-1,SQLITE_STATIC);
		sqlite3_bind_text(group_chg_stmt,4,name,-1,SQLITE_STATIC);
		sqlite3_bind_int(group_chg_stmt,5,id);
		if ((rc = sqlite3_step(group_chg_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql update chg group fail: %s(%d)\n", sqlite3_errstr(rc), rc);
		}

	} else { //组信息无变化
		sqlite3_reset(group_unchg_stmt);
		sqlite3_bind_int(group_unchg_stmt,1,grpchktv.tv_sec);
		sqlite3_bind_int(group_unchg_stmt,2,id);
		if ((rc = sqlite3_step(group_unchg_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql update unchg group fail: %s(%d)\n", sqlite3_errstr(rc), rc);
		}
	}

	sqlite3_free_table(azResult);
	return;
}

void check_group(void)
{
	int rc = 0;
        FILE *fp = NULL;
        char line[1024] = {0};

	DBG2(DBGFLAG_GROUP, "check group\n");

	if (!group_db) {
		group_db_init();
	}
	if (!group_db) {
		return;
	}

        fp = sniper_fopen("/etc/group", "r", FILE_GET);
        if (!fp) {
                MON_ERROR("check_group open /etc/group fail: %s\n", strerror(errno));
                return;
        }

	gettimeofday(&grpchktv, NULL);

	DBG2(DBGFLAG_GROUP, "check current group\n");
	sqlite3_exec(group_db,"BEGIN;",0,0,0);

        while (fgets(line, sizeof(line), fp)) {
        	gid_t gid = 0;
		char name[64] = {0};
		char userlist[1024] = {0};

                rc = sscanf(line, "%63[^:]:%*[^:]:%d:%1023s[^\n]", name, &gid, userlist);
		DBG2(DBGFLAG_GROUP, "rc %d, group: %s:%d:%s.\n", rc, name, gid, userlist);
		if (rc < 2) {
			continue;
		}

		handle_group(name, gid, userlist);
        }

        sniper_fclose(fp, FILE_GET);

	sqlite3_exec(group_db,"COMMIT;",0,0,0);

	DBG2(DBGFLAG_GROUP, "check deleted group\n");

	sqlite3_reset(group_sdel_stmt);
	sqlite3_bind_int(group_sdel_stmt,1,grpchktv.tv_sec);
	while (sqlite3_step(group_sdel_stmt) == SQLITE_ROW) {
		int id = sqlite3_column_int(group_sdel_stmt,0);
		const char *name = (const char *)sqlite3_column_text(group_sdel_stmt,1);

		send_group_msg(NULL, NULL, name, NULL, "Deleted");

		DBG2(DBGFLAG_GROUP, "delete id:%d, group %s\n", id, name);
		sqlite3_reset(group_del_stmt);
		sqlite3_bind_int(group_del_stmt,1,id);
		if ((rc = sqlite3_step(group_del_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql del group %s fail: %s(%d)\n", name, sqlite3_errstr(rc), rc);
		}
	}

	DBG2(DBGFLAG_GROUP, "check group end\n");
}

//TODO 增加查数据库版
void get_user_grplist(char *user, gid_t gid, char *group, int group_len, char *grplist, int grplist_len)
{
	char userstr[128] = {0};
        char line[1024] = {0};
	FILE *fp = fopen("/etc/group", "r");

        if (!fp) {
                printf("get_user_grplist open /etc/group fail: %s\n", strerror(errno));
                return;
        }

	snprintf(userstr, sizeof(userstr), ",%s,", user);

        while (fgets(line, sizeof(line), fp)) {
		int rc = 0, len = 0;
        	gid_t id = 0;
		char name[64] = {0};
		char userlist[1024] = {0};
		char userliststr[1032] = {0};

                rc = sscanf(line, "%63[^:]:%*[^:]:%d:%1023s[^\n]", name, &id, userlist);
		if (rc < 2) {
			continue;
		}
		if (gid == id) {
			snprintf(group, group_len, "%s", name);
			if (grplist[0] == 0) {
				snprintf(grplist, grplist_len, "%s", name);
				continue;
			}
			len = strlen(grplist);
			if (grplist_len > len) {
				snprintf(grplist+len, grplist_len-len, ",%s", name);
			}
			continue;
		}

		if (rc < 3) {
			continue;
		}

		snprintf(userliststr, sizeof(userliststr), ",%s,", userlist);
		if (strstr(userliststr, userstr)) {
			if (grplist[0] == 0) {
				snprintf(grplist, grplist_len, "%s", name);
				continue;
			}
			len = strlen(grplist);
			if (grplist_len > len) {
				snprintf(grplist+len, grplist_len-len, ",%s", name);
			}
		}
	}
	fclose(fp);
}

gid_t get_cdrom_gid(void)
{
        char line[S_LINELEN] = {0};
	FILE *fp = NULL;
	int rc = 0;
        gid_t gid = 0;
	char name[64] = {0};

	fp = fopen("/etc/group", "r");
        if (!fp) {
                INFO("open /etc/group fail: %s\n", strerror(errno));
                return 0;
        }

        while (fgets(line, sizeof(line), fp)) {
                rc = sscanf(line, "%63[^:]:%*[^:]:%d:", name, &gid);
		if (rc != 2) {
			continue;
		}
		if (strcmp(name, "cdrom") == 0) {
			INFO("cdrom gid %d\n", gid);
			break;
		}
	}
	fclose(fp);
	return gid;
}
