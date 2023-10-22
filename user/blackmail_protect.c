#include <sys/vfs.h>
#include <sys/types.h>

#include "header.h"

#define TIME_DIFF       57600
#define DAY_SECOND      86400

int backup_space_full;
int day_global;

int first_encrypt_check = 0;
sqlite3* encrypt_db = NULL;

const char *files_ext[] = {
	".bak",
	".sql",
	".mdf",
	".ldf",
	".myd",
	".myi",
	".dmp",
	".xls",
	".xlsx",
	".docx",
	".pptx",
	".eps",
	".csv",
	".rtf",
	".pdf",
	".db",
	".vdi",
	".vmdk",
	".vmx",
	".pem",
	".pfx",
	".cer",
	".psd",
	".txt",
	".zip",
	".gz",
	NULL
};

const char crt_encrypt_tbl_sql[1024] =
{
    "CREATE TABLE IF NOT EXISTS encryptbackup( "
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "mtime int,"                               //上次备份时间
    "md5   varchar(4096),"                      //备份新文件名
    "path  varchar(4096));"                      //备份原文件名
};

const char* encrypt_new_sql = "INSERT INTO encryptbackup VALUES(NULL,?,?,?);";
const char* encrypt_update_sql = "UPDATE encryptbackup SET mtime=?,md5=? WHERE path=?;";

sqlite3_stmt* encrypt_new_stmt = NULL;
sqlite3_stmt* encrypt_update_stmt = NULL;

/* 计算备份文件目录已有的文件总大小 */
off_t calculate_backup_file_size(void)
{
	DIR *dp = NULL;
	struct dirent *dirp;
	off_t size = 0;
	struct stat st = {0};
	char name[PATH_MAX] = {0};

	dp = opendir(BACKUP_DIR);
	if(dp == NULL) {
		MON_ERROR("open %s failed!\n", BACKUP_DIR);
		return 0;
	}

	while ((dirp = readdir(dp))) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0) {
			continue;
		}

		snprintf(name, PATH_MAX, "%s/%s", BACKUP_DIR, dirp->d_name);
		if(stat(name, &st) < 0) {
			continue;
		}

		size += st.st_size;
	}

	closedir(dp);
	return size;
}

void check_backup_free_size(void)
{
	unsigned long free = 0;
	struct statfs stat;
	struct timeval tv = {0};
	int day = 0;
	unsigned long size = 0;

	/* 备份开关关闭或者备份*/
	if (protect_policy_global.behaviour.ransomware.encrypt.backup.enable == TURN_MY_OFF ||
		protect_policy_global.behaviour.ransomware.encrypt.backup.backup_size <= 0) {
		return;
	}

	memset(&stat, 0, sizeof(struct statfs));
	statfs(BACKUP_DIR, &stat);
	free = stat.f_bsize * stat.f_bfree/1024;

	/* 因为算出来的free单位是K，所以size这边只要乘以MB的大小 */
	size = protect_policy_global.behaviour.ransomware.encrypt.backup.backup_size*(MB_SIZE);
	DBG2(DBGFLAG_INOTIFY, "backup dir free size:%lu(K), policy backup_size:%d(G), size:%lu(K)\n", free, protect_policy_global.behaviour.ransomware.encrypt.backup.backup_size, size);
	if (free < size) {
		backup_space_full = TURN_MY_ON;
		gettimeofday(&tv, NULL);
		/* 算出的秒数有个16个小时的时差，第一次启动或者一天只报一次 */
		day = (tv.tv_sec - TIME_DIFF)/DAY_SECOND;
		if (client_registered == 1 &&(day_global == 0 || day > day_global)) {
			report_dependency_msg("BackupFileSpaceIsFull");
			day_global = day;
		}
	} else {
		backup_space_full = TURN_MY_OFF;
	}

	return;
}

void create_file(char *path)
{
	FILE *fp;
	char buf[S_LINELEN] = "Do not change it,testtesttesttesttest!";
	struct stat st = {0};

	if (stat(path, &st) == 0 && st.st_size == strlen(buf) + 1) {
		return;
	}

	fp = sniper_fopen(path,"w+", FILE_GET);
	if (fp == NULL) {
		DBG2(DBGFLAG_FILEDEBUG, "create file fopen %s fail: %s\n",
			path, strerror(errno));
		return;
	} 

	fprintf(fp, "%s\n", buf);

	sniper_fclose(fp, FILE_GET);
	chmod(path, 0666);
	return;
}

void check_dir_trap_files(char *path, int hide, int type)
{
	DIR *dp = NULL;
	int i = 0;
	char *name = NULL;
	char dir[PATH_MAX] = {0};
	struct stat st = {0};

	/* type为OP_DELETE时,全部删除,不需要考虑hide的值 */
	if (hide == HIDE_TURNOFF) {
		name = TRAP_FILE_NOHIDE;
	} else {
		name = TRAP_FILE_HIDE;
	}

	if (stat(path, &st) < 0 ||
		S_ISDIR(st.st_mode) == 0) {
		return;
	}

	dp = opendir(path);
	if (dp == NULL) {
		DBG2(DBGFLAG_FILEDEBUG, "open dir %s fail: %s\n",
			path, strerror(errno));
		return;
	}
	closedir(dp);

	/* 勒索会按文件格式来筛选加密，文件类型通过files_ext来增减 */
	i = 0;
	while (files_ext[i] != NULL) {
		if(i >= WHILE_MAX) {
			break;
		}

		if (type == OP_CREATE) {
			snprintf(dir, PATH_MAX, "%s/%s%s", path, name, files_ext[i]);
			create_file(dir);
		} else {
			snprintf(dir, PATH_MAX, "%s/%s%s", path, TRAP_FILE_HIDE, files_ext[i]);
			unlink(dir);
			snprintf(dir, PATH_MAX, "%s/%s%s", path, TRAP_FILE_NOHIDE, files_ext[i]);
			unlink(dir);
		}

		i++;
	}

	return;
}

void operate_encrypt_trap_files(int hide, int type) 
{
	char dir[PATH_MAX] = {0};
	char child_dir[PATH_MAX] = {0};
	struct dirent *dirp;
	struct dirent *child_dirp;
	DIR *dp = NULL;
	DIR *child_dp = NULL;
	struct stat st = {0};

	/* 创建前都清理下旧的诱捕文件 */
	if (type == OP_CREATE) {
		operate_encrypt_trap_files(hide, OP_DELETE);
	}

	/* 根目录下操作诱捕文件 */
	check_dir_trap_files("/", hide, type);

	/* 一级目录下操作诱捕文件 */
	dp = opendir("/");
	if(dp == NULL) {
		MON_ERROR("encrypt trap files open / failed!,type:%d\n", type);
		return;
	}

	while ((dirp = readdir(dp))) {
		if (strcmp(dirp->d_name, ".") == 0 ||
		    strcmp(dirp->d_name, "..") == 0 ||
		    strcmp(dirp->d_name, "tmp") == 0 ||
		    strcmp(dirp->d_name, "net") == 0 ||
		    strcmp(dirp->d_name, "misc") == 0 ||
		    strcmp(dirp->d_name, "selinux") == 0 ||
		    strcmp(dirp->d_name, "proc") == 0 ||
		    strcmp(dirp->d_name, "sys") == 0) {
			continue;
		}

		snprintf(dir, PATH_MAX, "/%s", dirp->d_name);
		if (stat(dir, &st) < 0 ||
			S_ISDIR(st.st_mode) == 0) {
			continue;
		}

		/* home下各个目录操作诱捕文件*/
		if (strcmp(dirp->d_name, "home") == 0) {
			child_dp = opendir(dir);
			if (child_dp == NULL) {
				DBG2(DBGFLAG_FILE, "open dir %s fail: %s,type:%d\n",
					dir, strerror(errno), type);
				continue;
			}

			while ((child_dirp = readdir(child_dp))) {
				if (strcmp(child_dirp->d_name, ".") == 0 ||
				    strcmp(child_dirp->d_name, "..") == 0) {
					continue;
				}

				snprintf(child_dir, PATH_MAX, "/%s/%s", dirp->d_name, child_dirp->d_name);
				check_dir_trap_files(child_dir, hide, type);
			}

			closedir(child_dp);
		}

		check_dir_trap_files(dir, hide, type);
	}

	closedir(dp);
	return;
}

void init_encrypt_db(void)
{
	char dbname[140] = {0};

	operate_encrypt_trap_files(HIDE_TURNON, OP_CREATE);

	snprintf(dbname, 140, "%s/%s/encrypt.db", WORKDIR, FILEDB);
	encrypt_db = connectDb(dbname, crt_encrypt_tbl_sql, NULL, &first_encrypt_check);
        if (encrypt_db == NULL) {
		MON_ERROR("connect encrypt db failed\n");
                return;
        }

        sqlite3_busy_handler(encrypt_db, db_busy_callback, NULL );
	sqlite3_prepare_v2(encrypt_db, encrypt_new_sql, -1, &encrypt_new_stmt, NULL);
	sqlite3_prepare_v2(encrypt_db, encrypt_update_sql, -1, &encrypt_update_stmt, NULL);

}

void fini_encrypt_db(void)
{
	operate_encrypt_trap_files(HIDE_TURNON, OP_DELETE);

	if (encrypt_db == NULL) {
		return;
	}

	sqlite3_finalize(encrypt_new_stmt);
	sqlite3_finalize(encrypt_update_stmt);
	sqlite3_close_v2(encrypt_db);
}
#if 0
void add_record_to_encrypt_db(filereq_t *rep, struct file_msg_args *msg)
#else
void add_record_to_encrypt_db(struct ebpf_filereq_t *rep, struct file_msg_args *msg)
#endif
{
	char buf[1024] = {0};
	int rc = 0, nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	int ret = 0;
	char log_name[LOG_NAME_MAX] = {0};
	bool event = false;
	int terminate = 0;
	int behavior = 0, level = 0, result = MY_RESULT_OK;
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	char *extension = NULL;
	char md5[S_MD5LEN] = {0};
	char *path = NULL;
	struct stat st;
	char event_category[EVENT_NAME_MAX] = {0};
	char operating[OP_LEN_MAX] = {0};

	snprintf(buf, sizeof(buf), "SELECT id FROM encryptbackup WHERE path='%s';", thestring(msg->pathname));
	rc = sqlite3_get_table(encrypt_db, buf, &azResult, &nrow, &ncolumn, NULL);
	if (rc != SQLITE_OK) {
		MON_ERROR("get sqlite3 encrypt table error:%s(%d)\n", sqlite3_errstr(rc), rc);
		result = MY_RESULT_FAIL;
		return;
	}

	if (nrow == 0) {
		sqlite3_reset(encrypt_new_stmt);
		sqlite3_bind_int(encrypt_new_stmt, 1, msg->start_tv.tv_sec);
		sqlite3_bind_text(encrypt_new_stmt, 2, msg->pathname_new, -1, SQLITE_STATIC);
		sqlite3_bind_text(encrypt_new_stmt, 3, msg->pathname, -1, SQLITE_STATIC);
		rc = sqlite3_step(encrypt_new_stmt);
		if (rc != SQLITE_DONE) {
			MON_ERROR("sql insert new encrypt fail: %s(%d)\n", sqlite3_errstr(rc), rc);
			result = MY_RESULT_FAIL;
		}
	} else {

		sqlite3_reset(encrypt_update_stmt);
		sqlite3_bind_int(encrypt_update_stmt, 1, msg->start_tv.tv_sec);
		sqlite3_bind_text(encrypt_update_stmt, 2, msg->pathname_new, -1, SQLITE_STATIC);
		sqlite3_bind_text(encrypt_update_stmt, 3, msg->pathname, -1, SQLITE_STATIC);
		rc = sqlite3_step(encrypt_update_stmt);
		if (rc != SQLITE_DONE) {
			MON_ERROR("sql update old encrypt fail: %s(%d)\n", sqlite3_errstr(rc), rc);
			result = MY_RESULT_FAIL;
		}
	}
	sqlite3_free_table(azResult);

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	path = msg->pathname_new;

	if (md5_filter_large_file(path, md5) < 0) {
		if (md5_filter_large_file(msg->pathname, md5) < 0) {
			memset(md5, 0, S_MD5LEN);
		}
	}

	if (check_filter_after(msg->pathname, md5, msg->cmd) == 0) {
		return;
	}

	memset(&st, 0, sizeof(struct stat));

	ret = stat(path, &st);
	if (ret < 0) {
		if (stat(msg->pathname, &st) < 0) {
			msg->file_size = rep->file_size;
		} else {
			msg->file_size = st.st_size;
		}
	} else {
		msg->file_size = st.st_size;
	}

	level = MY_LOG_KEY;
	behavior = MY_BEHAVIOR_NO;
	event = false;
	terminate = MY_HANDLE_NO;
	strncpy(log_name, "FileBackup", LOG_NAME_MAX);
	strncpy(event_category, "", EVENT_NAME_MAX);
	log_name[LOG_NAME_MAX - 1] = '\0';
	event_category[EVENT_NAME_MAX - 1] = '\0';
	get_file_event_operating(rep->op_type, operating);

	extension = get_path_types(msg->pathname);
	event_time = (msg->start_tv.tv_sec + serv_timeoff) * 1000 + (int)msg->start_tv.tv_usec / 1000;

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "File");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->username);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "process_uuid", msg->taskuuid);
	cJSON_AddStringToObject(arguments, "process_name", msg->cmdname);
	cJSON_AddNumberToObject(arguments, "process_id", msg->pid);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
	cJSON_AddStringToObject(arguments, "process_path", msg->cmd);
	cJSON_AddStringToObject(arguments, "process_commandline", msg->args);
	cJSON_AddStringToObject(arguments, "md5", md5);
	cJSON_AddStringToObject(arguments, "user", msg->username);
	cJSON_AddStringToObject(arguments, "filename", safebasename(msg->pathname));
	cJSON_AddStringToObject(arguments, "filepath", msg->pathname);
	cJSON_AddNumberToObject(arguments, "size", msg->file_size);
	cJSON_AddStringToObject(arguments, "extension", extension);
	cJSON_AddStringToObject(arguments, "new_filepath", "");
	cJSON_AddStringToObject(arguments, "backup_filepath", msg->pathname_new);
	cJSON_AddStringToObject(arguments, "session_uuid", msg->session_uuid);

        cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_FILE, "backup file post:%s\n", post);
//	printf("backup file post:%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "file");

	cJSON_Delete(object);
	free(post);
}
#if 0
void report_encrypt_msg(filereq_t *rep, struct file_msg_args *msg)
#else
void report_encrypt_msg(struct ebpf_filereq_t *rep, struct file_msg_args *msg)
#endif
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	int behavior = 0, level = 0, result = MY_RESULT_OK;
	int defence_result = MY_RESULT_OK;
	char *extension = NULL;
	char operating[OP_LEN_MAX] = {0};
	char md5[S_MD5LEN] = {0};
	char *path = NULL;
	int ret = 0;
	struct stat st = {0};
	struct stat sniper_st = {0};
	struct stat process_st = {0};
	bool event = false;
	char log_name[LOG_NAME_MAX] = {0};
	char event_category[EVENT_NAME_MAX] = {0};
	int terminate = 0;
	struct defence_msg defmsg = {0};
	
	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	/* vsftpd,mounted,smbd为ftp,nfs,samba的守护进程,以及wine,遇到这几个进程操作先全部报日志，待优化 */
	if (strncmp(msg->cmdname, "vsftpd", 6) != 0 &&
	    strncmp(msg->cmdname, "mounted", 7) != 0 &&
	    strncmp(msg->cmdname, "smbd", 4) != 0 &&
	    strncmp(msg->cmdname, "wine", 4) != 0) {
		/* 如果勒索进程的修改时间是在sniper安装之前, 默认不是勒索进程 */
		if (stat(msg->cmd, &process_st) == 0 &&
		    stat("/usr/sbin/sniper", &sniper_st) == 0 &&
		    process_st.st_ctime < sniper_st.st_ctime) {
			cJSON_Delete(object);
			DBG2(DBGFLAG_FILE, "进程(%s)不是勒索进程, 过滤\n", msg->cmd);
			return;
		}
	}

	/* 阻断成功的时候算旧的文件md5值 */
	if (md5_filter_large_file(msg->cmd, md5) < 0) {
		memset(md5, 0, S_MD5LEN);
	}

	/* 检查是否是过滤名单进程，如果是则不报日志 */
	if (check_process_filter_pro(msg->cmd, md5)) {
		cJSON_Delete(object);
		return;
	}

	if (rep->op_type == OP_RENAME) {
		path = msg->pathname_new;
	} else {
		path = msg->pathname;
	}

	memset(&st, 0, sizeof(struct stat));
	/* 阻断成功的时候算旧的文件大小 */
	ret = stat(path, &st);
	if (ret < 0) {
		if (rep->op_type == OP_RENAME &&
		    stat(msg->pathname, &st) < 0) {
			msg->file_size = rep->file_size;
		} else {
			msg->file_size = st.st_size;
		}
	} else {
		msg->file_size = st.st_size;
	}
	if (rep->op_type == OP_UNLINK) {
		msg->file_size = rep->file_size;
	}

	/* 可信名单下不报事件，日志级别为普通，不阻断 */
	/* 运维和学习模式下在内核修改了rep->terminate为0 */
#if 0
	if (rep->is_trust == 1) {
		event = false;
		level = MY_LOG_NORMAL;
		rep->terminate = 0;
	} else {
		event = true;
		level = MY_LOG_HIGH_RISK;
	}
#endif

	behavior = MY_BEHAVIOR_ABNORMAL;
	if (rep->terminate == 1) {
		if (mykillpg(msg->pid, SIGKILL) < 0) {
			result = MY_RESULT_OK;
			terminate = MY_HANDLE_BLOCK_FAIL;
		} else {
			result = MY_RESULT_FAIL;
			terminate = MY_HANDLE_BLOCK_OK;
		}
	} else {
		terminate = MY_HANDLE_WARNING;
	}
	strncpy(log_name, "Ransomeware", LOG_NAME_MAX);
	log_name[LOG_NAME_MAX - 1] = '\0';
	strncpy(event_category, "Malicious", EVENT_NAME_MAX);
	event_category[EVENT_NAME_MAX - 1] = '\0';


	extension = get_path_types(msg->pathname);
	event_time = (msg->start_tv.tv_sec + serv_timeoff) * 1000 + (int)msg->start_tv.tv_usec / 1000;
	get_file_event_operating(rep->op_type, operating);

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "File");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->username);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

        cJSON_AddStringToObject(arguments, "process_uuid", msg->taskuuid);
        cJSON_AddStringToObject(arguments, "process_name", msg->cmdname);
	cJSON_AddNumberToObject(arguments, "process_id", msg->pid);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
        cJSON_AddStringToObject(arguments, "process_path", msg->cmd);
        cJSON_AddStringToObject(arguments, "process_commandline", msg->args);
        cJSON_AddStringToObject(arguments, "work_directory", "");
        cJSON_AddStringToObject(arguments, "user", msg->username);
        cJSON_AddStringToObject(arguments, "md5", md5);
        cJSON_AddStringToObject(arguments, "filename", safebasename(msg->pathname));
        cJSON_AddStringToObject(arguments, "filepath", msg->pathname);
	cJSON_AddNumberToObject(arguments, "size", msg->file_size);
        cJSON_AddStringToObject(arguments, "extension", extension);
        cJSON_AddStringToObject(arguments, "new_filepath", msg->pathname_new);
	cJSON_AddStringToObject(arguments, "ransomeware_detection_type", "DocumentTrap");
	cJSON_AddStringToObject(arguments, "session_uuid", msg->session_uuid);

        cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
//	printf("encrypt post:%s\n", post);
	DBG2(DBGFLAG_FILE, "encrypt post:%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "file");

	cJSON_Delete(object);
	free(post);

	/* 上传进程样本 */
	upload_file_sample(msg, log_name, uuid, rep->op_type, md5);

	if (rep->terminate != 1) {
		return;
	}

	defmsg.event_tv.tv_sec = msg->start_tv.tv_sec;
	defmsg.event_tv.tv_usec = msg->start_tv.tv_usec;
	defmsg.operation = termstr;
	defmsg.result = defence_result;

	defmsg.user = msg->username;
	defmsg.log_name = log_name;
	defmsg.log_id = uuid;
	defmsg.object = msg->cmd;
	
	send_defence_msg(&defmsg, "file");
}
