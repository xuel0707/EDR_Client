#include "header.h"
#include "savapi_unix.h"

#define ISOLATE_OFF     0
#define ISOLATE_ON      1

const char *quick_path[] = {
 "/bin",
 "/usr/bin",
 "/sbin",
 "/usr/sbin",
 "/tmp",
 "/var",
 "/dev/shm",
 "/usr/libexec",
 NULL
};

static unsigned long files_count = 0;
static unsigned long virus_count = 0;

static SAVAPI_GLOBAL_INIT global_init = {0};
static SAVAPI_FD instance_handle = NULL;
static SAVAPI_INSTANCE_INIT instance_init = {0};
static int savapi_inited = -1;
static int instance_created = -1;
static int callbacks_registered = -1;

/* 隔离区数据库执行语句 */
static const char *virus_new_sql = "INSERT INTO virus VALUES(NULL,?,?,?,?,?,?);";
static const char *virus_update_sql = "UPDATE virus SET mtime=?,uid=?,gid=?,mode=? WHERE path=?;";
static const char *virus_delete_md5_sql = "DELETE from virus WHERE md5=?;";
static const char *virus_select_md5_sql = "SELECT md5 from virus order by mtime;";

/* 信任区数据库执行语句 */
static const char* trust_select_path_sql = "SELECT uid, path FROM trust;";

static sqlite3_stmt *virus_new_stmt = NULL;
static sqlite3_stmt *virus_update_stmt = NULL;
static sqlite3_stmt *virus_delete_md5_stmt = NULL;
static sqlite3_stmt *virus_select_md5_stmt = NULL;

static sqlite3_stmt* trust_select_path_stmt = NULL;

struct passwd *my_info;

static char *qurstr = "Qurantine";
static char archive_file[PATH_MAX] = {0};
static int stop_scan = 0;

/* 获取执行一共消耗的时间 */
static void get_total_duration(time_t start_sec, time_t end_sec, char *timestr, int timestr_len)
{
	time_t all = 0, tmp = 0;
	int hour = 0, min = 0, sec = 0;

	all = end_sec - start_sec;
	hour = all / HOUR_SEC;
	tmp = all % HOUR_SEC;
	min = tmp / MIN_SEC;
	sec = tmp % MIN_SEC;

	/* 最高单位只显示到小时 */
	if (hour !=0) {
		if (min !=0) {
			snprintf(timestr, timestr_len, "%dh%dm%ds", hour, min, sec);
		} else {
			/* 分钟为空的情况*/
			snprintf(timestr, timestr_len, "%dh%ds", hour, sec);
		}
	} else {
		/* 不到1个小时的情况 */
		if (min != 0) {
			snprintf(timestr, timestr_len, "%dm%ds", min, sec);
		} else {
			/* 不到1分钟的情况*/
			snprintf(timestr, timestr_len, "%ds", sec);
		}
	}

}

/* 初始化数据库 */
static int init_virus_db(void)
{
	char dbname[140] = {0};
	int rc = 0;

	snprintf(dbname, sizeof(dbname), "%s/%s/virus.db", WORKDIR, VIRUSDB);
	rc = sqlite3_open_v2(dbname, &virus_db, SQLITE_OPEN_MODE, NULL);
	if (rc != SQLITE_OK) {
//		MON_ERROR("open virus db failed\n");
		return -1;
	}

	sqlite3_busy_handler(virus_db, db_busy_callback, NULL );

	/* 与fini_virus_db一一对应 */
	sqlite3_prepare_v2(virus_db, virus_new_sql, -1, &virus_new_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_update_sql, -1, &virus_update_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_delete_md5_sql, -1, &virus_delete_md5_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_select_md5_sql, -1, &virus_select_md5_stmt, NULL);

	return 0;
}

/* 回收数据库开销 */
static void fini_virus_db(void)
{
	if (virus_db == NULL) {
		return;
	}

	/* 与init_virus_db一一对应 */
	sqlite3_finalize(virus_new_stmt);
	sqlite3_finalize(virus_update_stmt);
	sqlite3_finalize(virus_delete_md5_stmt);
	sqlite3_finalize(virus_select_md5_stmt);

	sqlite3_close_v2(virus_db);
}

/* 执行小红伞的错误代码转换成错误信息 */
static char* scan_error_to_string(int error_code)
{
	switch(error_code) {
		case SAVAPI_E_INVALID_PARAMETER:
			return "Invalid parameter";
		case SAVAPI_E_NO_MEMORY:
			return "Out of memory";
		case SAVAPI_E_INTERNAL:
			return "Internal error";
		case SAVAPI_E_HIT_MAX_REC:
			return "Maximum archive recursion reached!";
		case SAVAPI_E_HIT_MAX_SIZE:
			return "Maximum archive size reached!";
		case SAVAPI_E_HIT_MAX_RATIO:
			return "Maximum archive ratio reached!";
		case SAVAPI_E_HIT_MAX_COUNT:
			return "Maximum archive number of files in archive reached!";
		case SAVAPI_E_ENCRYPTED_MIME:
			return "Encrypted content found!";
		case SAVAPI_E_ENCRYPTED:
			return "Encrypted content found!";
		case SAVAPI_E_UNSUPPORTED:
			return "Archive type unsupported!";
		case SAVAPI_E_UNSUPPORTED_COMPRESSION:
			return "Compression method unsupported!";
		case SAVAPI_E_PROC_INCOMPLETE_BLOCK_READ:
			return "Read block unexpected end!";
		case SAVAPI_E_PROC_BAD_HEADER:
			return "Invalid archive header!";
		case SAVAPI_E_PROC_INVALID_COMPRESSED_DATA:
			return "Invalid compressed data!";
		case SAVAPI_E_PROC_OBSOLETE:
			return "Obsolete information!";
		case SAVAPI_E_PROC_BAD_FORMAT:
			return "Invalid specified format!";
		case SAVAPI_E_PROC_HEADER_CRC:
			return "Invalid header signature!";
		case SAVAPI_E_PROC_DATA_CRC:
			return "Invalid data signature!";
		case SAVAPI_E_PROC_FILE_CRC:
			return "Invalid file signature!";
		case SAVAPI_E_PROC_BAD_TABLE:
			return "Invalid decompression table!";
		case SAVAPI_E_PROC_UNEXPECTED_EOF:
			return "Unexpected end of file reached!";
		case SAVAPI_E_PROC_ARCHIVE_HANDLE:
			return "Archive handle not initialized!";
		case SAVAPI_E_PROC_NO_FILES_TO_EXTRACT:
			return "Archive invalid or corrupted!";
		case SAVAPI_E_PROC_CALLBACK:
			return "Callback invalid or causes an error!";
		case SAVAPI_E_PROC_TOTAL_LOSS:
			return "Archive contents cannot be extracted!";
		case SAVAPI_E_PROC_ERROR:
			return "Error while processing file!";
		case SAVAPI_E_INCOMPLETE:
			return "Not all file contents could be scanned!";
		case SAVAPI_E_PARTIAL:
			return "File is part of a multi-volume archive!";
		case SAVAPI_E_ABORTED:
			return "Scan aborted (requested by user)!";
		case SAVAPI_E_TIMEOUT:
			return "Scan aborted (timeout reached)!";
		case SAVAPI_E_MATCHED:
			return "matched!";
		case SAVAPI_E_LICENSE_RESTRICTION:
			return "Operation not allowed (license restriction)!";
		case SAVAPI_E_REPAIR_FAILED:
			return "Failed to repair file!";
		case SAVAPI_E_CONVERSION_FAILED:
			return "Conversion failed";
		case SAVAPI_E_UNKNOWN:
			return "Unknown engine error occurred";
		case SAVAPI_E_NON_ADDRESSABLE:
			return "Memory area not addressable";
		case SAVAPI_E_MEMORY_LIMIT:
			return "Internal memory limit reached";
		case SAVAPI_E_BUFFER_TOO_SMALL:
			return "Buffer too small";
		case SAVAPI_E_VDF_NOT_FOUND:
			return "One or more VDF files not found";
		case SAVAPI_E_VDF_READ:
			return "Failed to read VDF file";
		case SAVAPI_E_VDF_CRC:
			return "Failed to check VDF file signature";
		case SAVAPI_E_ENGINE_NOT_FOUND:
			return "One or more engine files not found";
		case SAVAPI_E_KEYFILE:
			return "Invalid key file (CRC error)";
		case SAVAPI_E_NOT_SUPPORTED:
			return "Unsupported feature";
		case SAVAPI_E_OPTION_NOT_SUPPORTED:
			return "Unsupported option";
		case SAVAPI_E_FILE_OPEN:
			return "File open error";
		case SAVAPI_E_FILE_READ:
			return "File read error";
		case SAVAPI_E_FILE_WRITE:
			return "File write error";
		case SAVAPI_E_NOT_ABSOLUTE_PATH:
			return "Not an absolute path";
		case SAVAPI_E_FILE_CREATE:
			return "Failed to create file";
		case SAVAPI_E_FILE_DELETE:
			return "Failed to delete file";
		case SAVAPI_E_FILE_CLOSE:
			return "Failed to close file";
		case SAVAPI_E_PREFIX_SET:
			return "Failed to set a detect type option";
		case SAVAPI_E_PREFIX_GET:
			return "Failed to retrieve a detect type option";
		case SAVAPI_E_INVALID_QUERY:
			return "Invalid query for SAVAPI Service";
		case SAVAPI_E_KEY_NO_KEYFILE:
			return "Keyfile has not been found";
		case SAVAPI_E_KEY_ACCESS_DENIED:
			return "Access to key file has been denied";
		case SAVAPI_E_KEY_INVALID_HEADER:
			return "Invalid header has been found";
		case SAVAPI_E_KEY_KEYFILE_VERSION:
			return "Invalid keyfile version number";
		case SAVAPI_E_KEY_NO_LICENSE:
			return "No valid license found";
		case SAVAPI_E_KEY_FILE_INVALID:
			return "Key file is invalid (invalid CRC)";
		case SAVAPI_E_KEY_RECORD_INVALID:
			return "Invalid license record detected";
		case SAVAPI_E_KEY_EVAL_VERSION:
			return "Application is evaluation version";
		case SAVAPI_E_KEY_DEMO_VERSION:
			return "Application is demo version";
		case SAVAPI_E_KEY_ILLEGAL_LICENSE:
			return "Illegal (cracked) license in keyfile";
		case SAVAPI_E_KEY_EXPIRED:
			return "This key has expired";
		case SAVAPI_E_KEY_READ:
			return "Failed to reading from key file";
		case SAVAPI_E_BUSY:
			return "Operation could not be performed (resource is busy)";
		case SAVAPI_E_APC_CONNECTION:
			return "Communication with cloud server failed";
		case SAVAPI_E_APC_NOT_SUPPORTED:
			return "APC protocol is not supported";
		case SAVAPI_E_APC_ERROR:
			return "APC error occurred";
		case SAVAPI_E_APC_TIMEOUT:
			return "APC timeout occurred";
		case SAVAPI_E_APC_TEMPORARILY_DISABLED:
			return "APC declared unreachable (too many failed scans with APC)";
		case SAVAPI_E_APC_INCOMPLETE:
			return "Not all objects could be scanned with APC";
		case SAVAPI_E_APC_NO_LICENSE:
			return "No valid APC license found";
		case SAVAPI_E_APC_AUTHENTICATION:
			return "APC authentication failed";
		case SAVAPI_E_APC_AUTH_RETRY_LATER:
			return "APC authentication was not successful. Retry later";
		case SAVAPI_E_APC_RANDOM_ID:
			return "APC random id is invalid, not accesible or not computable";
		case SAVAPI_E_APC_DISABLED:
			return "APC is permanently disabled";
		case SAVAPI_E_APC_TIMEOUT_RESTRICTION:
			return "APC timeout restrictions not met: APCConnectionTimeout < APCScanTimeout < ScanTimeout";
		case SAVAPI_E_APC_UNKNOWN_CATEGORY:
			return "Could not determine category for object scanned with APC";
		case SAVAPI_E_APC_QUOTA:
			return "APC quota limit reached";
		default:
			return "Unknown error code!";
	}
}

/* 获取文件权限,属主, 属组 */
static int get_file_stat(char *path, file_stat_t *f_st)
{
	struct stat st = {0};

	if (stat(path, &st) < 0) {
		return -1;
	}

	f_st->mode = st.st_mode;
	f_st->uid = st.st_uid;
	f_st->gid = st.st_gid;

	return 0;
}

/*
 * 查询数据库中有没有这条路径的记录
 * 返回-1，执行错误;返回0，没有该条记录;返回1，有这条路径记录
 */
int query_db_path_record(char *path)
{
	char buf[1024] = {0};
	int rc = 0, nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	int ret = 0;

	snprintf(buf, sizeof(buf), "SELECT id FROM virus WHERE path='%s';", path);
	rc = sqlite3_get_table(virus_db, buf, &azResult, &nrow, &ncolumn, NULL);
	if (rc != SQLITE_OK) {
		MON_ERROR("get sqlite3 virus table error:%s(%d)\n", sqlite3_errstr(rc), rc);
		return -1;
	}
	sqlite3_free_table(azResult);

	if (nrow == 0) {
		ret = 0;
	} else {
		ret = 1;
	}

	return ret;
}

/* 添加隔离病毒的记录到数据库 返回-1表示添加失败 */
static int add_record_to_virus_db(file_stat_t *f_st, char *record_path, char *md5_path)
{
	int rc = 0;

	sqlite3_reset(virus_new_stmt);
	sqlite3_bind_int(virus_new_stmt, 1, f_st->mtime);
	sqlite3_bind_text(virus_new_stmt, 2, md5_path, -1, SQLITE_STATIC);
	sqlite3_bind_text(virus_new_stmt, 3, record_path, -1, SQLITE_STATIC);
	sqlite3_bind_int(virus_new_stmt, 4, f_st->uid);
	sqlite3_bind_int(virus_new_stmt, 5, f_st->gid);
	sqlite3_bind_int(virus_new_stmt, 6, f_st->mode);
	rc = sqlite3_step(virus_new_stmt);
	if (rc != SQLITE_DONE) {
		MON_DBG("Sql insert new virus:%s failed: %s(%d)\n", f_st->path, sqlite3_errstr(rc), rc);
		return -1;
	}

	return 0;
}

/* 拷贝文件，循环从旧的文件读一部分内容写到新文件中 */
int copy_file(char *old_file, char *new_file)
{
	FILE *oldfp = NULL;
	FILE *newfp = NULL;
	struct stat st = {0};
	off_t old_len = 0, new_len = 0;
	char buf[512] = {0};
	int size = 0, len = 0;
	int ret = 0;

	if (stat(old_file, &st) < 0) {
		MON_DBG("Stat file:%s error:%s\n", old_file, strerror(errno));
		return -1;
	}

	old_len = st.st_size;

	oldfp = sniper_fopen(old_file, "r", SCAN_GET);
	if (!oldfp) {
		MON_DBG("Copy file open oldfile %s failed:%s\n", old_file, strerror(errno));
		return -1;
	}

	newfp = sniper_fopen(new_file, "w+", SCAN_GET);
	if (!newfp) {
		MON_DBG("Copy file open newfile %s failed:%s\n", new_file, strerror(errno));
		sniper_fclose(oldfp, SCAN_GET);
		return -1;
	}

	/* 边读边写到新文件中 */
	while ((len = fread(buf, 1, sizeof(buf), oldfp)) > 0) {
		size = fwrite(buf, 1, len, newfp);
		if (size != len) {
			ret = -1;
			MON_DBG("Write file len less then read\n");
			break;
		}
		new_len += size;
	}

	/* 长度不一致也认为失败 */
	if (ret == 0 && new_len != old_len) {
		ret = -1;
		MON_DBG("New file size less then old file\n");
	}

	/* 失败清理新写的文件 */
	if (ret < 0) {
		unlink(new_file);
	}

	sniper_fclose(oldfp, SCAN_GET);
	sniper_fclose(newfp, SCAN_GET);
	return ret;
}

/* 隔离文件 */
static int quarantine_file(char *path, char *record_path, char *newpath, file_stat_t *f_st)
{
	int ret = 0;
	int rename_ok = 0;

	/* 同一个文件系统可以用rename,失败再尝试复制文件更改属性 */
	ret = rename(path, newpath);
	if (ret < 0) {
		ret = copy_file(path, newpath);
	} else {
		rename_ok = 1;
	}

	if (ret < 0) {
		return -1;
	}

	/* rename成功的隔离文件属性信息不用修改, 修改失败的适合当隔离失败处理 */
	if (rename_ok != 1) {

		/* 修改属性 */
		ret = chmod(newpath, f_st->mode);
		if (ret < 0) {
			MON_DBG("quarantine file:%s chmod %s error:%s\n", path, newpath, strerror(errno));
			unlink(newpath);
			return -1;
		}

		/* 修改属主 */
		ret = chown(newpath, f_st->uid, f_st->gid);
		if (ret < 0) {
			MON_DBG("quarantine file:%s chown %s error:%s\n", path, newpath, strerror(errno));
			unlink(newpath);
			return -1;
		}
	}

	/* 记录到数据库, 修改失败的适合当隔离失败处理 */
	ret = add_record_to_virus_db(f_st, record_path, newpath);
	if (ret < 0) {
		unlink(newpath);
		return -1;
	}

	/* 隔离成功删除原文件,rename成功这边unlink就会失败,需要先判断path存不存在 */
	if (access(path, F_OK) == 0) {
		ret = unlink(path);

		/* 如果删除原文件失败, 删除隔离文件和隔离记录 */
		if (ret < 0) {
			unlink(newpath);
			sqlite3_reset(virus_delete_md5_stmt);
			sqlite3_bind_text(virus_delete_md5_stmt, 1, newpath, -1, SQLITE_STATIC);
			sqlite3_step(virus_delete_md5_stmt);
			MON_DBG("unlink file:%s error:%s\n", path, strerror(errno));
		}

	}
	return ret;
}

/* 删除旧的隔离文件，直到空间足够存放新病毒文件，失败返回0，成功返回1 */
static int delete_old_quarantine_file(unsigned long dir_size, unsigned long path_size)
{
	unsigned long size = 0;
	struct stat st;
	int ret = 0;
	int rc = 0;
	char dir[PATH_MAX] = {0};

	/* 目录的名字是以扫描执行的用户名命名 */
	if (exec_uid != 0) {
		snprintf(dir, sizeof(dir), "%s/%s/", QUARANTINE_DIR, my_info->pw_name);
	}

	sqlite3_reset(virus_select_md5_stmt);
	while (sqlite3_step(virus_select_md5_stmt) == SQLITE_ROW) {
		const char *md5 = (const char *)sqlite3_column_text(virus_select_md5_stmt, 0);

		/* 普通用户只删自己隔离目录里面的文件 */
		if (exec_uid != 0 &&
		    strncmp(md5, dir, strlen(dir)) != 0) {
			continue;
		}

		if (stat(md5, &st) < 0) {
			continue;
		}
		size += st.st_size;

		/* 删除隔离区的文件和数据库记录 */
		if (unlink(md5) < 0) {
			ret = 0;
			break;
		}
		sqlite3_reset(virus_delete_md5_stmt);
		sqlite3_bind_text(virus_delete_md5_stmt, 1, md5, -1, SQLITE_STATIC);
		rc = sqlite3_step(virus_delete_md5_stmt);
		if (rc != SQLITE_DONE) {
			DBG2(DBGFLAG_ANTIVIRUS_SCAN, "sql delete path %s fail: %s(%d)\n", md5, sqlite3_errstr(rc), rc);
			ret = 0;
			break;
		}

		/* 删除的空间大小超过病毒文件就不用再删了 */
		if (size >= path_size) {
			ret = 1;
			break;
		}
	}

	/* 全部删除了仍然比病毒文件的大小还小, 依然认为成功了 */
	if (size == dir_size) {
		ret = 1;
	}

	return ret;
}

/* 交互询问是否删除文件，确认返回1. 否返回0 */
static int ask_whether_delete_file(char *file)
{
	char output[PATH_MAX] = {0};
	char input[INPUT_LEN] = {0};

	snprintf(output, sizeof(output),
		"Insufficient space in the quarantine area, whether to delete the virus file %s directly [Y/N]:", file);
	printf("%s", output);
	get_input_result(output, input, INPUT_LEN);

	/* y,Y和回车表示确认 */
	if (input[0] == 10 || ((input[0] == 'y' || input[0] == 'Y') && input[1] == 10)) {
		return 1;
	} else {
		return 0;
	}
}

/* 根据隔离区设置剩余空间大小和隔离区情况, 是否隔离病毒文件*/
static int check_quarantine_file(char *path, char *record_path, char *newpath, struct _file_stat *f_st)
{
	struct stat st = {0};
	unsigned long path_size = 0;
	unsigned long dir_size = 0;
	unsigned long disk_size = 0;
	unsigned long policy_size = 0;
	int ret = 0;
	char dir[PATH_MAX] = {0};

	if (!path || !record_path || !newpath || !f_st) {
		return -1;
	}

	if (stat(path, &st) < 0) {
		return -1;
	}

	/* 策略大小以GB作为单位 */
	path_size = st.st_size;
	policy_size = (unsigned long)antivirus_policy_global.reserved_space * (unsigned long)GB_SIZE;

	/* 超级用户获取总的隔离区目录内的大小, 普通用户获取自己隔离目录内的大小*/
	if (exec_uid == 0) {
		snprintf(dir, sizeof(dir), "%s/", QUARANTINE_DIR);
	} else {
		snprintf(dir, sizeof(dir), "%s/%s/", QUARANTINE_DIR, my_info->pw_name);
	}

	/* 获取磁盘剩余空间 */
	disk_size = get_path_disk_size(dir);

	/* 实时检测是root用户,获取总的隔离区目录内的大小 */
	dir_size = get_dir_size(dir);

	/*
	 * 之前没有隔离过文件时，比较分区剩余空间和策略设置的大小+path大小的总和
	 * 分区空间>= 策略设置大小+病毒大小，隔离病毒。
	 * 否则直接忽略, 同时返回-1做隔离失败处理
	 */
	MON_DBG2(DBGFLAG_ANTIVIRUS, "disk_size:%lu, dir_size:%lu, policy_size:%lu, path_size:%lu\n",
			disk_size, dir_size, policy_size, path_size);
	if (dir_size == 0) {
		if (disk_size < policy_size + path_size) {
			/* 隔离空间不够时，询问用户是否直接删除原文件 */
			ret = ask_whether_delete_file(path);
			if (ret == 1) {
				ret = unlink(path);
			} else {
				ret = -1;
			}
			return ret;
		}

		ret = quarantine_file(path, record_path, newpath, f_st);
		return ret;
	}

	/* 有隔离区且其中有隔离文件的情况下 */

	/*
	 * 如果分区空间 >= 策略设置大小+病毒大小
	 * 直接隔离
	 */
	if (disk_size >= policy_size + path_size) {
		ret = quarantine_file(path, record_path, newpath, f_st);
		return ret;
	}

	/*
	 * 其他情况下
	 * 2种情况会去删除旧隔离文件，隔离新病毒文件
	 * 1.分区空间-隔离空间+新病毒文件大小 大于 策略设置的大小
	 * 2.隔离区的大小比新病毒文件大
	 * 否则直接忽略, 返回-1，当作隔离失败
	 */
	if ((disk_size + path_size - dir_size <  policy_size) &&
	    (dir_size <  path_size)) {
		/* 隔离空间不够时，询问用户是否直接删除原文件 */
		ret = ask_whether_delete_file(path);
		if (ret == 1) {
			ret = unlink(path);
		} else {
			ret = -1;
		}
		return ret;
	}

	/* 删除旧的隔离文件过程中失败，不再继续隔离 */
	if (delete_old_quarantine_file(dir_size, path_size) == 0) {
		return -1;
	}

	ret = quarantine_file(path, record_path, newpath, f_st);
	return ret;
}

/* 隔离病毒文件 */
static int quarantine_virus_file(char *path, char *dir)
{
	file_stat_t st = {0};
	int ret = 0;
	char md5[S_MD5LEN] = {0};
	char newpath[PATH_MAX] = {0};
	char record_path[PATH_MAX] = {0};
	time_t time_sec = 0;
	int i = 0;

	snprintf(st.path, sizeof(st.path), "%s", path);

	/* 获取文件权限,属主, 属组*/
	ret = get_file_stat(path, &st);
	if (ret < 0) {
		MON_DBG("quarantine file:%s get stat error:%s\n", path, strerror(errno));
		return -1;
	}

	/*
	 * 如果数据库中已经备份了该路径的文件(例如/tmp/1.txt),
	 * 文件名后面拼接"(数字).sniper"到原文件后的后面(例如/tmp/1.txt(1).sniper)
	 * 拼接后的路径如果在数据库中也存在了，括号中的数字递增+1
	 * 同一路径的文件最多可以存放10000条
	 * 有.sniper表示这条路径是副本拼接的路径，没有则说明是原路径
	 * 显示的时候只显示/tmp/1.txt(1)
	 */

	ret = query_db_path_record(path);
	if (ret < 0) {
		return -1;
	}

	if (ret == 0) {
		/* 旧版本记录的路径，或没有副本的路径 */
		snprintf(record_path, sizeof(record_path), "%s", thestring(path));
	} else {
		/* 有副本的路径, 最高查询到10000个副本 */
		for (i = 1; i < MAX_WHILE; i++) {
			snprintf(record_path, sizeof(record_path), "%s(%d).sniper", path, i);
			ret = query_db_path_record(record_path);
			if (ret < 0) {
				return -1;
			} else if (ret == 0){
				break;
			}
		}
	}

	/* 用文件路径计算唯一值用来存放在隔离区 */
	md5_string(record_path, md5);
	if (md5[0] == 0) {
		MON_DBG("quarantine file:%s get md5 error\n", path);
		return -1;
	}
	snprintf(st.md5, sizeof(st.md5), "%s", md5);
	snprintf(newpath, sizeof(newpath), "%s/%s", dir, md5);

	time_sec = time(NULL);
	st.mtime = time_sec;

	/* 检查文件是隔离还是忽略 */
	ret = check_quarantine_file(path, record_path, newpath, &st);
	return ret;
}

/* 设置实例的选项 */
static SAVAPI_STATUS set_instance_options(SAVAPI_FD instance_handle)
{
	SAVAPI_STATUS ret = SAVAPI_S_OK;

	/* Enable false positive control */
	if (ret == SAVAPI_S_OK) {
		ret = SAVAPI_set(instance_handle, SAVAPI_OPTION_FPC, "1");
	}

	/* Enable archive scanning */
	if (ret == SAVAPI_S_OK) {
		ret = SAVAPI_set(instance_handle, SAVAPI_OPTION_ARCHIVE_SCAN, "1");
	}

	/* Set maximum allowed size (in bytes) for any file within an archive */
	if (ret == SAVAPI_S_OK) {
		ret = SAVAPI_set(instance_handle, SAVAPI_OPTION_ARCHIVE_MAX_SIZE, "0");
	}

	/* set archive max recursion to maximum (2) recursion levels */
	/*
	 * zip压缩的文件相当于一层
	 * tar.gz压缩的文件相当于两层
	 * 所以这边设置的是扫描两层
	 */
	if (ret == SAVAPI_S_OK) {
		ret = SAVAPI_set(instance_handle, SAVAPI_OPTION_ARCHIVE_MAX_REC, "2");
	}

	/* Enable detection for all categories */
	if (ret == SAVAPI_S_OK) {
		ret = SAVAPI_set(instance_handle, SAVAPI_OPTION_DETECT_ALLTYPES, "1");
	}

	return ret;
}

/* 在扫描开始之前触发 */
static int prescan_callback(SAVAPI_CALLBACK_DATA *data)
{
	SAVAPI_PRESCAN_DATA *pre_scan_data = data->callback_data.pre_scan_data;

	/* 压缩包内已经有识别到一个病毒文件，不再继续扫描其他文件 */
	if (stop_scan == 1 &&
	    pre_scan_data->file_info.type == SAVAPI_FTYPE_IN_ARCHIVE) {
		return -1;
	}

	return 0;
}

/* 在打开压缩文件之前触发 */
static int archive_open_callback(SAVAPI_CALLBACK_DATA *data)
{
	SAVAPI_ARCHIVE_OPEN_DATA *archive_open_data = data->callback_data.archive_open_data;

	/* 获取压缩文件的全路径，用于识别到压缩包内的文件为病毒时，只报压缩包的路径 */
	if (archive_open_data->file_info.level == 0) {
		snprintf(archive_file, sizeof(archive_file), "%s", archive_open_data->file_info.name);
	}

	return 0;
}

/* 扫描的callback中获取文件的信息 */
static int file_status_callback(SAVAPI_CALLBACK_DATA *data)
{
	SAVAPI_FILE_STATUS_DATA *file_status_data = data->callback_data.file_status_data;
	virus_info_t info = {{0}};
	char path[PATH_MAX] = {0};

	if (file_status_data->scan_answer == SAVAPI_SCAN_STATUS_INFECTED) {

		/*
		 * 如果是压缩包内的文件，此处结构体内的名字不是全路径
		 * 此类情况下用读取压缩包第0层的名字
		 * 同时通过stop_scan控制不再继续扫描压缩包内的其他文件
		 */
		if (archive_file[0] != 0) {
			snprintf(path, sizeof(path), "%s", archive_file);
			stop_scan = 1;
		} else {
			snprintf(path, sizeof(path), "%s", file_status_data->file_info.name);
		}

		/* 输出病毒信息的同时输出到安全日志中 */
		virus_count++;
		printf("File:%s is infected!name:%s, type:%s, info:%s\n",
			path,
			file_status_data->malware_info.name,
			file_status_data->malware_info.type,
			file_status_data->malware_info.message);
		INFO("File:%s is infected!name:%s, type:%s, info:%s\n",
			path,
			file_status_data->malware_info.name,
			file_status_data->malware_info.type,
			file_status_data->malware_info.message);
		snprintf(info.pathname, sizeof(info.pathname), "%s", path);
		snprintf(info.virus_name, sizeof(info.virus_name), "%s", file_status_data->malware_info.name);
		snprintf(info.virus_type, sizeof(info.virus_type), "%s", file_status_data->malware_info.type);

		/* 队列满则丢弃所有新消息 */
		if (virus_msg_queue_full()) {
			return 0;
		}

		virus_msg_queue_push(&info);
	}

	return 0;
}

/* 注册callback函数 */
static SAVAPI_STATUS register_instance_callbacks(SAVAPI_FD instance_handle)
{
	SAVAPI_STATUS ret = SAVAPI_S_OK;

	ret = SAVAPI_register_callback(instance_handle, SAVAPI_CALLBACK_PRE_SCAN, prescan_callback);
	ret = SAVAPI_register_callback(instance_handle, SAVAPI_CALLBACK_ARCHIVE_OPEN, archive_open_callback);
	ret = SAVAPI_register_callback(instance_handle, SAVAPI_CALLBACK_REPORT_FILE_STATUS, file_status_callback);

	return ret;
}

/* 注销callback函数 */
static SAVAPI_STATUS unregister_instance_callbacks(SAVAPI_FD instance_handle)
{
	SAVAPI_STATUS ret = SAVAPI_S_OK;

	ret = SAVAPI_unregister_callback(instance_handle, SAVAPI_CALLBACK_PRE_SCAN, prescan_callback);
	ret = SAVAPI_unregister_callback(instance_handle, SAVAPI_CALLBACK_ARCHIVE_OPEN, archive_open_callback);
	ret = SAVAPI_unregister_callback(instance_handle, SAVAPI_CALLBACK_REPORT_FILE_STATUS, file_status_callback);

	return ret;
}

/* 扫描前的准备工作，包括初始化，创建实例，注册callback */
static void prepare_savapi(void)
{
	/* 定义引擎依赖文件的路径 */
	global_init.api_major_version = SAVAPI_API_MAJOR_VERSION;
	global_init.api_minor_version = SAVAPI_API_MINOR_VERSION;
	global_init.program_type = ANTIVIRUS_PROGRAM_TYPE;
	global_init.engine_dirpath = ANTIVIRUS_ENGINE_DIRPATH;
	global_init.vdfs_dirpath = ANTIVIRUS_VDFS_DIRPATH;
	global_init.avll_dirpath = ANTIVIRUS_AVLL_DIRPATH;
	global_init.key_file_name = ANTIVIRUS_KEY_FILENAME;

	/* 初始化小红伞引擎 */
	printf("Virus database loading......\n");
	if (savapi_inited != SAVAPI_S_OK) {
		savapi_inited = SAVAPI_initialize(&global_init);
	}
	if (savapi_inited == SAVAPI_S_OK) {
		if (instance_created != SAVAPI_S_OK) {
			instance_created = SAVAPI_create_instance(&instance_init, &instance_handle);
			set_instance_options(instance_handle);
		}
		if (instance_created == SAVAPI_S_OK) {
			if (callbacks_registered != SAVAPI_S_OK) {
				callbacks_registered = register_instance_callbacks(instance_handle);
			}
			if (callbacks_registered != SAVAPI_S_OK) {
				printf("antivirus register instance callback error(%d): %s\n",
						callbacks_registered, scan_error_to_string(callbacks_registered));
			}
		} else {
			printf("antivirus create instance error(%d): %s\n",
					instance_created, scan_error_to_string(instance_created));
		}
	} else {
		printf("antivirus initialize error(%d): %s\n",
				savapi_inited, scan_error_to_string(savapi_inited));
	}
}

/* 回收savapi的资源，和prepare_savapi成对使用 */
static void finish_savapi(void)
{
	SAVAPI_STATUS ret = -1;
	if (callbacks_registered == SAVAPI_S_OK) {
		ret = unregister_instance_callbacks(instance_handle);
		if (ret != SAVAPI_S_OK) {
			printf("antivirus unregistering callbacks failed with error code(%d): %s\n",
					ret, scan_error_to_string(ret));
		} else {
			callbacks_registered = -1;
		}
	}

	if (instance_handle != NULL) {
		ret = SAVAPI_release_instance(&instance_handle);
		if (ret != SAVAPI_S_OK) {
			printf("antivirus release instance failed with error code(%d): %s\n",
					ret, scan_error_to_string(ret));
		} else {
			instance_handle = NULL;
			instance_created = -1;
		}
	}

	if (savapi_inited == SAVAPI_S_OK) {
		ret = SAVAPI_uninitialize();
		if (ret != SAVAPI_S_OK) {
			printf("antivirus uninitialize failed with error code(%d): %s\n",
					ret, scan_error_to_string(ret));
		} else {
			savapi_inited = -1;
		}
	}
}

/* 匹配过滤扫描的路径，匹配上返回1，不匹配返回0 */
static int skip_path(const char *path)
{
	int match = 0;

	/*/proc/和/sys/为伪文件系统，隔离和样本目录，及程序本身无需扫描 */
	if (strncmp(path, "/proc/", strlen("/proc/")) == 0 ||
	    strncmp(path, "/sys/", strlen("/sys/")) == 0 ||
	    strncmp(path, "/opt/snipercli/.quarantine/", strlen("/opt/snipercli/.quarantine/")) == 0 ||
	    strncmp(path, "/opt/snipercli/sample/", strlen("/opt/snipercli/sample/")) == 0 ||
	    strcmp(path, "/sbin/sniper") == 0 ||
	    strcmp(path, "/usr/sbin/sniper") == 0 ||
	    strcmp(path, "/bin/sniper_antivirus") == 0 ||
	    strcmp(path, "/usr/bin/sniper_antivirus") == 0) {
		match = 1;
	}

	return match;
}

/* 检测文件的类型(文件，目录，其他) */
static int path_type_check(char *path)
{
	struct stat st = {0};

	/* 过滤目录不扫描, 返回其他文件 */
	if (skip_path(path)) {
		return PATH_TYPE_OTHER;
	}

	if (lstat(path, &st) < 0) {
//		printf("check %s type fail, stat error: %s\n", path, strerror(errno));
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		return PATH_TYPE_DIR;
	}

	if (S_ISREG(st.st_mode)) {
		return PATH_TYPE_FILE;
	}

	/* 其余文件一律不做扫描 */
	return PATH_TYPE_OTHER;
}

/* 检测文件是否需要过滤, 需要过滤返回1 */
static int check_filter_files(const char *path)
{
	struct stat st = {0};
	struct stat snapshot_st = {0};
	int num = 0, ret = 0;
	char file[PATH_MAX] = {0}; // PATH_MAX长度为4096
	off_t max_size = 0;

	if (lstat(path, &st) < 0) {
//		printf("check %s lstat fail, stat error: %s\n", path, strerror(errno));
		return -1;
	}

	/* 小于16字节的文件不扫描 */
	if (st.st_size < 16) {
		return 1;
	}

	/* 大于策略设置的忽略文件大小不扫描 */
	max_size = antivirus_policy_global.neglect_size * MB_SIZE;
	if (max_size != 0 && st.st_size > max_size) {
		MON_DBG("sizo of file %s is lager than the policy setting\n", path);
		return 1;
	}

	/* 快照文件如果inode号和设备号和实际文件一致，则不扫描 */
	/* 4095是(PATH_MAX -1)的长度 */
	ret = sscanf(path, "/.snapshots/%d/snapshot%4095s", &num, file);
	if (ret != 2) {
		return -1;
	}

	if (lstat(file, &snapshot_st) < 0) {
		return -1;
	}

	if (snapshot_st.st_ino == st.st_ino &&
		snapshot_st.st_dev == st.st_dev) {
		return 1;
	}

	return 0;
}

/* 检测是否匹配手动添加的信任路径, 匹配返回1 */
static int check_custom_trust_path(const char *path, int type)
{
	char dbname[140] = {0};
	int rc = 0;
	int len = 0;
	int match = 0;
	char list[PATH_MAX] = {0};
	struct stat st;
	int uid;

	snprintf(dbname, sizeof(dbname), "%s/%s/trust.db", WORKDIR, VIRUSDB);
	rc = sqlite3_open_v2(dbname, &trust_db, SQLITE_OPEN_MODE, NULL);
	if (rc != SQLITE_OK) {
//		printf("check open trust db error\n");
		return -1;
	}

	if (stat(dbname, &st) < 0) {
//		printf("check no trust path\n");
		sqlite3_close_v2(trust_db);
		return -1;
	}

	if (st.st_size == 0) {
//		printf("check trust db is NULL\n");
		sqlite3_close_v2(trust_db);
		return -1;
	}

	sqlite3_busy_handler(trust_db, db_busy_callback, NULL );
	sqlite3_prepare_v2(trust_db, trust_select_path_sql, -1, &trust_select_path_stmt, NULL);

	sqlite3_reset(trust_select_path_stmt);
	while (sqlite3_step(trust_select_path_stmt) == SQLITE_ROW) {

		uid =  sqlite3_column_int(trust_select_path_stmt, 0);
		/* 检测是否是本用户或者超级用户设置的信任区*/
		if (uid != 0 && uid != exec_uid) {
			continue;
		}

		/* 数据库获得的字符串都是const char *，用list_tmp转一下 */
		const char *list_tmp = (const char *)sqlite3_column_text(trust_select_path_stmt, 1);
		if (!list_tmp) {
			break;
		}

		/* 路径可能为空 */
		if (list_tmp[0] == 0) {
			continue;
		}


		snprintf(list, sizeof(list), "%s", list_tmp);
		len = strlen(list);
		/*检查文件时，跟信任区的文件做绝对匹配, 跟信任区的目录只匹配信任目录的长度 */
		if (type == PATH_TYPE_FILE) {
			if (list[len-1] != '/') {
				if (strcmp(list, path) == 0) {
					match = 1;
					break;
				}
			} else {
				if (strncmp(list, path, len) == 0) {
					match = 1;
					break;
				}
			}
		}

		/*检查目录时，跟信任区的文件不做匹配, 跟信任区的目录只匹配信任目录的长度 */
		if (type == PATH_TYPE_DIR) {
			if (list[len-1] != '/') {
				continue;
			}

			if (strncmp(list, path, len) == 0) {
				match = 1;
				break;
			}
		}
	}

	sqlite3_finalize(trust_select_path_stmt);
	sqlite3_close_v2(trust_db);
	return match;
}

/* 检测是否匹配管控下发的信任路径，是返回1 */
static int check_policy_trust_path(const char *path, int type)
{
	int len = 0, match = 0, i = 0;
	char *list = NULL;

	if (!path) {
		return -1;
	}

	if (type != PATH_TYPE_FILE && type != PATH_TYPE_DIR) {
		return -1;
	}

	pthread_rwlock_rdlock(&antivirus_policy_global.lock);
	for (i = 0; i < antivirus_policy_global.list_num; i++) {
		list = antivirus_policy_global.trust_list[i].list;
		len = strlen(list);

		/*检查文件时，跟信任区的文件做绝对匹配, 跟信任区的目录只匹配信任目录的长度 */
		if (type == PATH_TYPE_FILE) {
			if (list[len-1] != '/') {
				if (strcmp(list, path) == 0) {
					match = 1;
					break;
				}
			} else {
				if (strncmp(list, path, len) == 0) {
					match = 1;
					break;
				}
			}
		}

		/*检查目录时，跟信任区的文件不做匹配, 跟信任区的目录只匹配信任目录的长度 */
		if (type == PATH_TYPE_DIR) {
			if (list[len-1] != '/') {
				continue;
			}

			if (strncmp(list, path, len) == 0) {
				match = 1;
				break;
			}
		}

	}
	pthread_rwlock_unlock(&antivirus_policy_global.lock);

	return match;
}

/* 扫描目录, 会递归调用 */
static int scan_dir(const char *path)
{
	DIR *dir = NULL;
	struct dirent *dent = NULL;
	char buffer[PATH_MAX] = {0};
	int len = 0, ret = -1;
	int path_type = PATH_TYPE_OTHER;

	if (!path) {
		return -1;
	}

	/* 过滤目录不扫描 */
	if (skip_path(path)) {
		return 0;
	}

	/* 过滤策略信任区 */
	if (check_policy_trust_path(path, PATH_TYPE_DIR) == 1) {
		return 0;
	}

	/* 过滤手动添加的信任区 */
	if (check_custom_trust_path(path, PATH_TYPE_DIR) == 1) {
		return 0;
	}

	dir = opendir(path);
	if (dir == NULL) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "scan path fail, opendir %s error: %s\n", path, strerror(errno));
		return -1;
	}

	/* 将path拷贝到buffer里，如果path不是/结尾的，buffer尾部添加一个/ */
	len = strlen(path);

//	INFO("Scan dir:%s\n", path);

	while ((dent = readdir(dir)) != NULL) {
		/* 过滤自己和父目录 */
		if ((strcmp(dent->d_name, ".") == 0) ||
		    (strcmp(dent->d_name, "..") == 0)) {
			continue;
		}

		/* 路径可能没有加/,此处检查并补全 */
		if (path[len-1] == '/') {
			snprintf(buffer, sizeof(buffer), "%s%s", path, dent->d_name);
		} else {
			snprintf(buffer, sizeof(buffer), "%s/%s", path, dent->d_name);
		}

		/* 目录类型则递归调用本函数 */
		path_type = path_type_check(buffer);
		if (path_type == PATH_TYPE_DIR) {
			scan_dir(buffer);
			continue;
		}

		if (path_type == PATH_TYPE_FILE) {
//			INFO("Scan file:%s\n", buffer);

			/* 优化扫描，过滤部分文件 */
			if (check_filter_files(buffer) == 1) {
				continue;
			}

			/* 过滤策略信任区 */
			if (check_policy_trust_path(buffer, PATH_TYPE_FILE) == 1) {
				continue;
			}

			/* 过滤手动添加信任区 */
			if (check_custom_trust_path(buffer, PATH_TYPE_FILE) == 1) {
				continue;
			}

			/* 初始化扫描信息，扫描普通文件 */
			memset(archive_file, 0, sizeof(archive_file));
			stop_scan = 0;
			ret = SAVAPI_scan(instance_handle, buffer);
			if (ret == SAVAPI_S_OK) {
				files_count++;
				MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "Scan file:%s succeeded\n", buffer);
			} else {
				MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "Scan file:%s failed with error code: %d\n", buffer, ret);
			}
			continue;
		}

		/* 其他文件暂不处理 */
	}
	closedir(dir);

	return 0;
}

/* 全盘扫描模式 */
static int scan_fulldisk(void)
{
	int ret = 0;;

	/* 全盘为根目录 */
	ret = scan_dir("/");

	return ret;
}

/* 快速扫描模式 */
static int scan_quickly(void)
{
	int i = 0;

	/*
	 * 内置的需要检查的目录
	 * 采用了简单的错误处理策略, 遇到错误即报错退出
	 * 如果实际使用中有改进需求，如要求遇到错误继续扫描，再修改
	 */
	while(quick_path[i] != NULL) {
		if (scan_dir(quick_path[i]) < 0) {
			return -1;
		}

		i++;
	}

	return 0;
}

/* 自定义扫描 */
static int scan_mode_custom(int num, char **argv)
{
	int i = 0, ret = 0;
	int path_type = PATH_TYPE_OTHER;
	char *file = NULL;
	char path[PATH_MAX] = {0};
	char real_path[PATH_MAX] = {0};
	char dir[PATH_MAX] = {0};

	if (num <= 0) {
		printf("Error: Missing parameters\n");
		return -1;
	}

	getcwd(dir, PATH_MAX);

	for (i = 0; i < num; i++) {
		file = argv[i+3];
		/* 先只支持全路径的参数 */
		if (file[0] != '/' && strncmp(file, "~/", 2) != 0) {
			snprintf(path, sizeof(path), "%s/%s", thestring(dir), file);
		} else {
			snprintf(path, sizeof(path), "%s", file);
		}

		if (realpath(path, real_path) == NULL) {
			printf("Error: %s is not a correct path\n", file);
			continue;
		}

		path_type = path_type_check(real_path);
		if (path_type == PATH_TYPE_DIR) {
			ret = scan_dir(real_path);
		} else if (path_type == PATH_TYPE_FILE) {
//			INFO("Scan file:%s\n", real_path);

			/* 优化扫描，过滤部分文件 */
			if (check_filter_files(real_path) == 1) {
				continue;
			}

			/* 过滤策略信任区 */
			if (check_policy_trust_path(real_path, PATH_TYPE_FILE) == 1) {
				continue;
			}

			/* 过滤手动添加的信任区 */
			if (check_custom_trust_path(real_path, PATH_TYPE_FILE) == 1) {
				continue;
			}

			/* 初始化扫描信息，扫描普通文件 */
			memset(archive_file, 0, sizeof(archive_file));
			stop_scan = 0;
			ret = SAVAPI_scan(instance_handle, real_path);
			if (ret == SAVAPI_S_OK) {
				files_count++;
				MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "Scan file:%s succeeded\n", real_path);
			} else {
				MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "Scan file:%s failed with error code: %d\n", real_path, ret);
			}
		} else {
			/* 其他文件暂不处理 */
			printf("Error: %s is not a regular file or directory\n", real_path);
		}

	}

	return ret;
}

/* 发送上传样本的消息 */
static void send_virus_upload_sample_log(virus_info_t *msg, char *pathname, char *log_name, char *log_id, int result, char*md5)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN+1] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	char size_str[64] = {0};
	unsigned long event_time = 0;
	struct stat st = {0};

	get_random_uuid(uuid, sizeof(uuid));
	if (uuid[0] == 0) {
		return;
	}

	/* 拼接json字符串*/
	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}

	/* 1级子json字符串挂在object下 */
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	event_time = (msg->tv.tv_sec + serv_timeoff) * 1000 + msg->tv.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientSimpleUpload");
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddStringToObject(object, "log_category", "Client");
	cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddNumberToObject(object, "level", 1);
	cJSON_AddNumberToObject(object, "behavior", 0);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "Upload");
	cJSON_AddNumberToObject(object, "terminate", 0);
	cJSON_AddNumberToObject(object, "timestamp", event_time);

	cJSON_AddStringToObject(object, "host_name", hostname);
	cJSON_AddStringToObject(object, "ip_address", host_ip);
	cJSON_AddStringToObject(object, "mac", host_mac);
	cJSON_AddStringToObject(object, "uuid", host_sku);
	cJSON_AddStringToObject(object, "user", msg->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", os_dist);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);

	cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
	cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
	cJSON_AddStringToObject(arguments, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(arguments, "policy_name", policy_name_cur);
	cJSON_AddStringToObject(arguments, "policy_time", policy_time_cur);
	cJSON_AddStringToObject(arguments, "md5", md5);
	cJSON_AddStringToObject(arguments, "file_path", pathname);
	cJSON_AddStringToObject(arguments, "file_name", safebasename(pathname));
	cJSON_AddStringToObject(arguments, "process_uuid", "");
	cJSON_AddStringToObject(arguments, "log_name", log_name);
	cJSON_AddStringToObject(arguments, "log_id", log_id);

	if (stat(pathname, &st) < 0) {
		cJSON_AddBoolToObject(arguments, "file_exists", false);
		cJSON_AddStringToObject(arguments, "size", "0");
	} else {
		cJSON_AddBoolToObject(arguments, "file_exists", true);
		snprintf(size_str, sizeof(size_str), "%ld", st.st_size);
		cJSON_AddStringToObject(arguments, "size", size_str);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);

	/* 单条发送 */
	http_post(SINGLE_LOG_URL, post, reply);
//	printf("file send upload sample:%s, reply:%s\n", post, reply);
	MON_DBG2(DBGFLAG_ANTIVIRUS, "file send upload sample:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
}

/* return 0，不上传；1，上传成功；-1，上传失败 */
static int upload_virus_sample(virus_info_t *msg)
{
	int ret = 0, result = MY_RESULT_OK;
	char *pathname = NULL;

	if (conf_global.allow_upload_sample != 1) {
		return 0;
	}


	if (!msg) {
		return 0;
	}

	pathname = msg->pathname;

	ret = http_upload_sample(pathname, msg->tv.tv_sec, "AntivirusProtection", msg->uuid, msg->user, msg->md5);
	if (ret < 0) {
		result = MY_RESULT_FAIL;
	}

	/* 发送样本上传日志 */
	send_virus_upload_sample_log(msg, pathname, "AntivirusProtection", msg->uuid, result, msg->md5);

	return ret;
}

/* 发送病毒日志 */
static int send_antivirus_msg(virus_info_t *msg)
{
	cJSON *object = NULL, *arguments = NULL;
	char reply[REPLY_MAX] = {0}, *post = NULL;
	bool event = false;
	char log_name[LOG_NAME_MAX] = {0};
	char event_category[EVENT_NAME_MAX] = {0};
	int behavior = 0, level = 0, result = MY_RESULT_ZERO;
	char operating[OP_LEN_MAX] = {0};
	int terminate = 0;
	unsigned long event_time = 0;
//	char process[64] = {0};
//	char process_md5[S_MD5LEN] = {0};
	char *path = NULL;
	int check_way = 0;
	struct timeval tv = {0};

	get_random_uuid(msg->uuid, sizeof(msg->uuid));
	if (msg->uuid[0] == 0) {
		return -1;
	}

	gettimeofday(&tv, NULL);
	memcpy(&msg->tv, &tv, sizeof(struct timeval));
	path = msg->pathname;

	snprintf(log_name, sizeof(log_name), "%s", "AntivirusProtection");
	snprintf(event_category, sizeof(event_category), "%s", "AntivirusProtection");
	event = true;
	behavior = MY_BEHAVIOR_ABNORMAL;
	level = MY_LOG_HIGH_RISK;
	result = MY_RESULT_ZERO;
	terminate = MY_HANDLE_WARNING;
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;
//	snprintf(process, sizeof(process), "%s", "/bin/sniper_antivirus");

	if (md5_filter_large_file(path, msg->md5) < 0) {
		memset(msg->md5, 0, S_MD5LEN);
	}

#if 0
	/* 计算进程的md5, 用于匹配进程过滤规则 */
	md5_filter_large_file(process, process_md5);

	/* 匹配过滤规则 */
	if (check_filter_after(path, msg->md5) == 0 || check_process_filter_pro(process, process_md5)) {
		return 0;
	}
#endif

	/* 拼接json字符串*/
	object = cJSON_CreateObject();
	if (object == NULL) {
		return -1;
	}

	/* 1级子json字符串挂在object下 */
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return -1;
	}

	check_way = 1;

	cJSON_AddStringToObject(object, "id", msg->uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "AntivirusProtection");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", hostname);
	cJSON_AddStringToObject(object, "ip_address", host_ip);
	cJSON_AddStringToObject(object, "mac", host_mac);
	cJSON_AddStringToObject(object, "uuid", host_sku);
	cJSON_AddStringToObject(object, "user", msg->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "virus_name", msg->virus_name);
	cJSON_AddStringToObject(arguments, "virus_type", msg->virus_type);
	cJSON_AddStringToObject(arguments, "filename", safebasename(path));
	cJSON_AddStringToObject(arguments, "filepath", path);
	cJSON_AddStringToObject(arguments, "file_md5", msg->md5);
	cJSON_AddNumberToObject(arguments, "scan_type", 1);
	cJSON_AddNumberToObject(arguments, "automate", antivirus_policy_global.automate);
	cJSON_AddNumberToObject(arguments, "check_way", check_way);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	http_post(SINGLE_LOG_URL, post, reply);
//	printf("antivirus post:%s, reply:%s\n", post, reply);
	MON_DBG2(DBGFLAG_ANTIVIRUS, "antivirus post:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
	return 0;
}

/* 发送防御日志 */
static void send_defence_msg(struct defence_msg *msg)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN+1] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;

	if (!msg) {
		return;
	}

	/* 病毒防护时virus_name和virus_type不能为空 */
	if (!msg->virus_name || !msg->virus_type) {
		return;
	}

	/* 没有传入事件时间，则用当前时间 */
	if (msg->event_tv.tv_sec == 0) {
		gettimeofday(&msg->event_tv, NULL);
	}
	event_time = (msg->event_tv.tv_sec + serv_timeoff) * 1000 + msg->event_tv.tv_usec / 1000;

	get_random_uuid(uuid, sizeof(uuid));
	if (uuid[0] == 0) {
		return;
	}

	/* 拼接json字符串*/
	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}

	/* 1级子json字符串挂在object下 */
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientProtection");
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddStringToObject(object, "log_category", "Client");
	  cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddNumberToObject(object, "level", MY_LOG_KEY);
	cJSON_AddNumberToObject(object, "behavior", 0);
	cJSON_AddNumberToObject(object, "result", msg->result);
	cJSON_AddStringToObject(object, "operating", msg->operation);
	cJSON_AddNumberToObject(object, "terminate", 0);
	cJSON_AddNumberToObject(object, "timestamp", event_time);

	cJSON_AddStringToObject(object, "host_name", hostname);
	cJSON_AddStringToObject(object, "ip_address", host_ip);
	cJSON_AddStringToObject(object, "mac", host_mac);
	cJSON_AddStringToObject(object, "uuid", host_sku);
	cJSON_AddStringToObject(object, "user", msg->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", os_dist);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);

	cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
	cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
	cJSON_AddStringToObject(arguments, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(arguments, "policy_name", policy_name_cur);
	cJSON_AddStringToObject(arguments, "policy_time", policy_time_cur);
	cJSON_AddStringToObject(arguments, "log_name", msg->log_name);
	cJSON_AddStringToObject(arguments, "log_id", msg->log_id);
	cJSON_AddStringToObject(arguments, "object", msg->object);
	cJSON_AddStringToObject(arguments, "virus_name", msg->virus_name);
	cJSON_AddStringToObject(arguments, "virus_type", msg->virus_type);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);

	http_post(SINGLE_LOG_URL, post, reply);
//	printf("post:%s, reply:%s\n", post, reply);
	MON_DBG2(DBGFLAG_ANTIVIRUS, "defence post:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
}

/* 发送扫描查杀的防御日志 */
static int send_antivirus_defence_msg(virus_info_t *msg)
{
	struct defence_msg defmsg = {0};
	defmsg.event_tv.tv_sec = msg->tv.tv_sec;
	defmsg.event_tv.tv_usec = msg->tv.tv_usec;
	defmsg.operation = qurstr;
	defmsg.result = msg->result;

	defmsg.virus_name = msg->virus_name;
	defmsg.virus_type = msg->virus_type;
	defmsg.user = msg->user;
	defmsg.log_name = "AntivirusProtection";
	defmsg.log_id = msg->uuid;
	defmsg.object = msg->pathname;

	send_defence_msg(&defmsg);
	return 0;
}

/* 发送所有病毒的消息和上传样本 */
static int report_virus_files(void)
{
	virus_msg_t *virus_msg = NULL;
	virus_info_t *info = NULL;

	if (virus_msg_count <= 0) {
		return -1;
	}

	/* 从队里里取出每一条单独处理 */
	while(virus_msg_count) {
		if (virus_msg) {
			sniper_free(virus_msg->data, virus_msg->datalen, SCAN_GET);
			sniper_free(virus_msg, sizeof(struct virus_msg), SCAN_GET);
		}

		virus_msg = (virus_msg_t *)get_virus_msg();
		if (!virus_msg) {
			continue;
		}

		info = (virus_info_t *)virus_msg->data;
		if (!info) {
			continue;
		}
		snprintf(info->user, sizeof(info->user), "%s", my_info->pw_name);

		/* 发送病毒防护日志 */
		send_antivirus_msg(info);

		/*上传病毒样本 */
		upload_virus_sample(info);

		/* 队列满则丢弃所有新消息 */
		if (handle_msg_queue_full()) {
			return 0;
		}

		/* 存放到需要处理防御的日志队列里 */
		handle_msg_queue_push(info);

		sniper_free(virus_msg->data, virus_msg->datalen, SCAN_GET);
		sniper_free(virus_msg, sizeof(struct virus_msg), SCAN_GET);
	}

	return 0;
}

/* 隔离病毒文件，mode为1时表示需要隔离，mode为0时表示不隔离 */
static void quarantine_viruses(int mode)
{
	handle_msg_t *handle_msg = NULL;
	virus_info_t *info = NULL;
	int i = 0;
	char dirname[PATH_MAX] = {0};
	int match = 0;
	int quarantine_ok = 0;
	int quarantine_failed = 0;
	int virus_count = 0;

	if (handle_msg_count <= 0) {
		return;
	}

	/*
	 * 需要隔离时检查隔离目录，队列取出数据后隔离，并且输出隔离结果
	 * 不需要隔离时队列里取出数据后释放资源
	 */

	if (mode == ISOLATE_ON) {
		/* 检测隔离目录是否存在，sniper进程inotify线程创建目录的速度可能比这边慢, 最多等待10秒 */
		snprintf(dirname, sizeof(dirname), "%s/%s",
				QUARANTINE_DIR, my_info->pw_name);
		if (access(dirname, F_OK) < 0) {
			for(i = 0; i < 10; i++) {
				if(access(dirname, F_OK) == 0) {
					match = 1;
					break;
				}
				sleep(1);
			}

			if (!match) {
				printf("Error: Quarantine directory does not exist, cannot be quarantined\n");
				return;
			}
		}

		printf("Start quarantining......\n");
	}

	/* 从队列里取出每一条单独处理 */
	virus_count = handle_msg_count;
	while(handle_msg_count) {
		if (handle_msg) {
			sniper_free(handle_msg->data, handle_msg->datalen, SCAN_GET);
			sniper_free(handle_msg, sizeof(struct handle_msg), SCAN_GET);
		}

		handle_msg = (handle_msg_t *)get_handle_msg();
		if (!handle_msg) {
			continue;
		}

		info = (virus_info_t *)handle_msg->data;
		if (!info) {
			continue;
		}

		if (mode == ISOLATE_ON) {
			if(quarantine_virus_file(info->pathname, dirname) < 0) {
				quarantine_failed++;
				info->result = MY_RESULT_FAIL;
				MON_DBG2(DBGFLAG_ANTIVIRUS, "Failed Quarantine virus file:%s,\
						virus name:%s, virus type:%s\n",
						info->pathname, info->virus_name, info->virus_type);
			} else {
				quarantine_ok++;
				info->result = MY_RESULT_OK;
				MON_DBG2(DBGFLAG_ANTIVIRUS, "Success Quarantine virus file:%s,\
						virus name:%s, virus type:%s\n",
						info->pathname, info->virus_name, info->virus_type);
			}

			send_antivirus_defence_msg(info);
		} else {
			MON_DBG2(DBGFLAG_ANTIVIRUS, "Ignore handle virus file:%s,\
					virus name:%s, virus type:%s\n",
					info->pathname, info->virus_name, info->virus_type);

		}

		sniper_free(handle_msg->data, handle_msg->datalen, SCAN_GET);
		sniper_free(handle_msg, sizeof(struct handle_msg), SCAN_GET);
	}

	if (mode == ISOLATE_ON) {
	/* 输出隔离的结果信息 */
		if (quarantine_failed == 0) {
			printf("A total of %d virus %s quarantined this time, %d %s successful\n",
				virus_count, virus_count > 1?"were":"was",
				quarantine_ok, quarantine_ok > 1?"were":"was");
			INFO("A total of %d virus %s quarantined this time, %d %s successful\n",
				virus_count, virus_count > 1?"were":"was",
				quarantine_ok, quarantine_ok > 1?"were":"was");
		} else if (quarantine_ok == 0){
			printf("A total of %d virus %s quarantined this time, %d %s failed\n",
				virus_count, virus_count > 1?"were":"was",
				quarantine_failed, quarantine_failed > 1?"were":"was");
			INFO("A total of %d virus %s quarantined this time, %d %s failed\n",
				virus_count, virus_count > 1?"were":"was",
				quarantine_failed, quarantine_failed > 1?"were":"was");
		} else {
			printf("A total of %d virus %s quarantined this time, %d %s successful and %d %s failed\n",
				virus_count, virus_count > 1?"were":"was",
				quarantine_ok, quarantine_ok > 1?"were":"was",
				quarantine_failed, quarantine_failed > 1?"were":"was");
			INFO("A total of %d virus %s quarantined this time, %d %s successful and %d %s failed\n",
				virus_count, virus_count > 1?"were":"was",
				quarantine_ok, quarantine_ok > 1?"were":"was",
				quarantine_failed, quarantine_failed > 1?"were":"was");
		}
	}
}

/* 通过创建uid的文件, 使主程序知道创建对应的隔离目录 */
static int inotify_quarantine_dir(uid_t uid)
{
	FILE *fp = NULL;
	char filename[PATH_MAX] = {0};

	/* 以uid命名文件来通知sniper创建防病毒隔离目录 */
	snprintf(filename, sizeof(filename), "%s%u", INOTIFY_QUARANTINE_DIR, uid);
	if (access(filename, F_OK) == 0) {
		return 0;
	}

	fp = sniper_fopen(filename, "w", SCAN_GET);
	if (!fp) {
//		MON_ERROR("Create %s uid:%d inotify failed:%s\n", filename, uid, strerror(errno));
		return -1;
	}
	sniper_fclose(fp, SCAN_GET);

	return 0;
}

/* 检查是否需要隔离病毒文件, 是返回1，否返回0 */
static int get_quarantine_mode(void)
{
	char *output = "Please select whether to quarantine all viruses [Y/N]:";
	char input[INPUT_LEN] = {0};

	/* 自动处理和交互同意会隔离病毒文件，其余情况不隔离 */
	if (antivirus_policy_global.automate == AUTO_PROCESS) {
		return ISOLATE_ON;
	} else {
		/* 获取输入的结果存放到input字符串中 */
		printf("%s", output);
		get_input_result(output, input, INPUT_LEN);
		if (input[0] == 10 || ((input[0] == 'y' || input[0] == 'Y') && input[1] == 10)) {
			return ISOLATE_ON;;
		}
	}

	return ISOLATE_OFF;
}

/* 扫描的模式 */
int scan_mode(int argc, char **argv)
{
	int result = 0;
	int num = 0;
	char filename[PATH_MAX] = {0};
	char time_str[TIME_LEN] = {0};
	time_t start_sec = {0};
	time_t end_sec = {0};
	int mode = 0;

	start_sec = time(NULL);

	if (argc < 3) {
		printf("Error: Missing parameters\n");
		show_usage();
		return -1;
	}

/* sniper停止运行的时候依然允许手动扫描运行 */
#if 0
	if (access(PIDFILE, F_OK) < 0) {
		printf("Please run the sniper program first\n");
		return -1;
	}
#endif

	snprintf(filename, sizeof(filename), "%s%u", INOTIFY_QUARANTINE_DIR, exec_uid);

	/* 一个用户只能同时启动一次 */
	if (is_this_running(exec_uid) == 1) {
		printf("A user can only start once at the same time\n");
		return -1;
	}

	/* 加载策略 */
	load_local_policy();
	load_local_conf();
	if (antivirus_policy_global.scanning_kill.enable == TURN_MY_OFF) {
		printf("Scanning policy is off\n");
		return -1;
	}

	/* 通知创建隔离目录失败则返回 */
	if (inotify_quarantine_dir(exec_uid) < 0) {
		printf("Error: Inotify sniper failed\n");
		return -1;
	}

	/* 获取主机和管控的基本信息 */
	if (get_os_release(os_dist, sizeof(os_dist)) < 0 ||
	    gethostname(hostname, S_NAMELEN) < 0 ||
	    get_sku(host_sku) < 0 ||
	    get_current_ethinfo() < 0 ||
	    get_serverconf() < 0 ) {
		printf("Get Sysinfo error\n");
		return -1;
	}

	sniper_adjust_time();
	/* 初始化病毒隔离的数据库 */
	if (init_virus_db() < 0) {
		printf("Error: Failed to operate database\n");
	}

	/* 加载小红伞引擎 */
	prepare_savapi();
	if (callbacks_registered != SAVAPI_S_OK) {
		finish_savapi();
		return -1;
	}

	/* 根据参数执行不同的扫描模式 */
	if (strcmp(argv[2], "all") == 0) {
		printf("Start scanning......\n");
		INFO("Full mode scanning start\n");
		result = scan_fulldisk();
	} else if (strcmp(argv[2], "quick") == 0) {
		printf("Start scanning......\n");
		INFO("Quick mode scanning start\n");
		result = scan_quickly();
	} else if (strcmp(argv[2], "custom") == 0)  {
		printf("Start scanning......\n");
		INFO("Custom mode scanning start\n");
		num = argc - 3;
		result = scan_mode_custom(num, argv);
	} else {
		printf("Error: Wrong parameter.such as \"all\", \"quick\", \"custom\"\n");
		result = -1;
		goto out;
	}

	end_sec = time(NULL);

	/* 输出扫描的统计信息 */
	get_total_duration(start_sec, end_sec, time_str, sizeof(time_str));
	if (virus_msg_count > 0) {
		printf("Scan all finished.\n");
		printf("This scan took a total of %s, a total of %lu files %s scanned, and %lu viruses %s identified.\n",
			time_str, files_count, files_count > 1?"were":"was", virus_count, virus_count > 1?"were":"was");
		INFO("This scan took a total of %s, a total of %lu files %s scanned, and %lu viruses %s identified.\n",
			time_str, files_count, files_count > 1?"were":"was", virus_count, virus_count > 1?"were":"was");
		printf("Log uploading, please wait......\n");
		if (report_virus_files() < 0) {
			printf("The scan results are stored in the security log:%s\n", ANTIVIRUS_LOGFILE);
			goto out;
		}
	} else {
		printf("Scan all finished\n");
		printf("This scan took a total of %s, a total of %lu files %s scanned, and %lu viruses %s identified.\n",
			time_str, files_count, files_count > 1?"were":"was", virus_count, virus_count > 1?"were":"was");
		INFO("This scan took a total of %s, a total of %lu files %s scanned, and %lu viruses %s identified.\n",
			time_str, files_count, files_count > 1?"were":"was", virus_count, virus_count > 1?"were":"was");
		printf("The scan results are stored in the security log:%s\n", ANTIVIRUS_LOGFILE);
		goto out;
	}

	/* 获取是否需要隔离*/
	mode = get_quarantine_mode();

	quarantine_viruses(mode);

	printf("The scan results are stored in the security log:%s\n", ANTIVIRUS_LOGFILE);

out:
	/* 检测报错信息 */
	print_tips();
	/* 结束后删除uid通知文件, 否则下次不会触发检查 */
	unlink(filename);

	finish_savapi();

	fini_virus_db();

	return result;
}
