#include "header.h"

const char* virus_query_sql = "SELECT mtime, path, md5, uid FROM virus;";
const char* virus_query_path_sql = "SELECT md5, uid, gid, mode FROM virus WHERE path=?;";
const char* virus_delete_sql = "DELETE FROM virus WHERE path=?;";

sqlite3_stmt* virus_query_stmt = NULL;
sqlite3_stmt* virus_query_path_stmt = NULL;
sqlite3_stmt* virus_delete_stmt = NULL;

int init_virus_operate_db(void)
{
	char dbname[140] = {0};
	int rc = 0;

	snprintf(dbname, 140, "%s/%s/virus.db", WORKDIR, VIRUSDB);
	rc = sqlite3_open_v2(dbname, &virus_db, SQLITE_OPEN_MODE, NULL);
        if (rc != SQLITE_OK) {
//                printf("open db error\n");
                return -1;
        }

        sqlite3_busy_handler(virus_db, db_busy_callback, NULL );
	sqlite3_prepare_v2(virus_db, virus_query_sql, -1, &virus_query_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_query_path_sql, -1, &virus_query_path_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_delete_sql, -1, &virus_delete_stmt, NULL);

	return 0;
}

void fini_virus_operate_db(void)
{
	if (virus_db == NULL) {
		return;
	}

	sqlite3_finalize(virus_query_stmt);
	sqlite3_finalize(virus_query_path_stmt);
	sqlite3_finalize(virus_delete_stmt);
	sqlite3_close_v2(virus_db);
}

int check_dir_exist(char *dir)
{
	struct stat st;

	if (!dir) {
		return -1;
	}

	if (lstat(dir, &st) < 0) {
		return -1;	
	}

	if ((st.st_mode & S_IFDIR) != 0) {
		return 0;
	}

	return -1;
}

/* 
 * 通过数据库中记录的路径获取原来的路径
 * 例如/tmp/1.txt(1).sniper获取到原来的路径为/tmp/1.txt
 * record_path为数据库记录的路径，ori_path为原来的实际路径
 */
void record_path_to_original_path(char *record_path, char *ori_path)
{
	char *ptr = NULL;
	int len = 0, pathlen = 0, ptrlen = 0;

	if (!record_path || !ori_path) {
		return;
	}

	if (strstr(record_path, ").sniper") == NULL) {
		snprintf(ori_path, PATH_MAX, "%s", record_path);
		return;
	}

	ptr = strrchr(record_path, '(');
	if (!ptr) {
		snprintf(ori_path, PATH_MAX, "%s", record_path);
		return;
	}

	ptrlen = strlen(ptr);
	pathlen = strlen(record_path);
	len = pathlen - ptrlen;
	snprintf(ori_path, len+1, "%s", record_path);
	return;
}

/* 
 * 通过数据库中记录的路径获取展示的路径
 * 例如/tmp/1.txt(1).sniper展示的路径为/tmp/1.txt(1)
 * record_path为数据库记录的路径，show_path为展示的路径
 */
void record_path_to_show_path(char *record_path, char *show_path)
{
	char *ptr = NULL;
	int len = 0, pathlen = 0, ptrlen = 0;

	if (!record_path || !show_path) {
		return;
	}

	if (strstr(record_path, ").sniper") == NULL) {
		snprintf(show_path, PATH_MAX, "%s", record_path);
		return;
	}

	ptr = strrchr(record_path, '.');
	if (!ptr) {
		snprintf(show_path, PATH_MAX, "%s", record_path);
		return;
	}

	ptrlen = strlen(ptr);
	pathlen = strlen(record_path);
	len = pathlen - ptrlen;
	snprintf(show_path, len+1, "%s", record_path);
	return;
}

/* 
 * 通过展示的路径获取数据库中记录的路径
 * 例如/tmp/1.txt(1)记录的路径为/tmp/1.txt(1).sniper
 * show_path为展示的路径 record_path为数据库记录的路径
 */
void show_path_to_record_path(char *show_path, char *record_path)
{
	char *ptr = NULL;
	int pathlen = 0, ptrlen = 0;
	int i = 0;
	int ret = 0;

	if (!show_path || !record_path) {
		return;
	}

	/* 如果是副本文件，最后一个字符是')', 且'('和')'之间的字符应该都是数字 */
	pathlen = strlen(show_path);
	if (show_path[pathlen-1] != ')') {
		snprintf(record_path, PATH_MAX, "%s", show_path);
		return;
	}

	ptr = strrchr(show_path, '(');
	if (!ptr) {
		snprintf(record_path, PATH_MAX, "%s", show_path);
		return;
	}
	
	ptrlen = strlen(ptr);
	/* 减去'('和')'两个长度 */
	if (ptrlen <= 2) {
		snprintf(record_path, PATH_MAX, "%s", show_path);
		return;
	}
	ptr++;
	for (i = 0; i < ptrlen-2; i++) {	
		if(ptr[0] > '9' || ptr[0] < '0') {
			snprintf(record_path, PATH_MAX, "%s", show_path);
			return;
		}
		ptr++;
	}

	ret = query_db_path_record(show_path);
	if (ret <= 0) {
		snprintf(record_path, PATH_MAX, "%s.sniper", show_path);
	} else {
		snprintf(record_path, PATH_MAX, "%s", show_path);
	}

	return;
}

/* 
 * 通过展示的路径获取原来的路径
 * 例如/tmp/1.txt(1)记录的路径为/tmp/1.txt
 * show_path为展示的路径 ori_path为原来的实际路径
 */
void show_path_to_ori_path(char *show_path, char *ori_path)
{
	char *ptr = NULL;
	int len = 0, pathlen = 0, ptrlen = 0;
	int i = 0;
	int ret = 0;

	if (!show_path || !ori_path) {
		return;
	}

	/* 如果是副本文件，最后一个字符是')', 且'('和')'之间的字符应该都是数字 */
	pathlen = strlen(show_path);
	if (show_path[pathlen-1] != ')') {
		snprintf(ori_path, PATH_MAX, "%s", show_path);
		return;
	}

	ptr = strrchr(show_path, '(');
	if (!ptr) {
		snprintf(ori_path, PATH_MAX, "%s", show_path);
		return;
	}
	
	ptrlen = strlen(ptr);
	/* 减去'('和')'两个长度 */
	if (ptrlen <= 2) {
		snprintf(ori_path, PATH_MAX, "%s", show_path);
		return;
	}
	ptr++;
	for (i = 0; i < ptrlen-2; i++) {	
		if(ptr[0] > '9' || ptr[0] < '0') {
			snprintf(ori_path, PATH_MAX, "%s", show_path);
			return;
		}
		ptr++;
	}

	len = pathlen - ptrlen; 
	ret = query_db_path_record(show_path);
	if (ret <= 0) {
		snprintf(ori_path, len+1, "%s", show_path);
	} else {
		snprintf(ori_path, PATH_MAX, "%s", show_path);
	}

	return;
}

int extract_files(char *quarantine_path, char *extract_path)
{
	int ret = 0; 
	mode_t mode;
        uid_t uid;
        gid_t gid;
	const char *md5 = NULL;
	char md5_path[PATH_MAX] = {0};
	char output[PATH_MAX] = {0};
	char input[INPUT_LEN] = {0};

	sqlite3_reset(virus_query_path_stmt);
	sqlite3_bind_text(virus_query_path_stmt, 1, quarantine_path, -1, SQLITE_STATIC);

	sqlite3_reset(virus_query_path_stmt);
	while (sqlite3_step(virus_query_path_stmt) == SQLITE_ROW) {
                md5 = (const char *)sqlite3_column_text(virus_query_path_stmt,0);
                uid = sqlite3_column_int(virus_query_path_stmt,1);
                gid = sqlite3_column_int(virus_query_path_stmt,2);
                mode = sqlite3_column_int(virus_query_path_stmt,3);
		break;
        }	

	if (md5 == NULL) {
		MON_DBG("File:%s is not in quarantine\n", quarantine_path);
		return -1;
	}

	snprintf(md5_path, sizeof(md5_path), "%s", md5);
	/* path如果已存在，需要交互询问是否替换*/
	if (access(extract_path, F_OK) == 0) {
		if (force_flag == 0) {
			snprintf(output, sizeof(output), "%s already exists, whether to overwrite [Y/N]:", thestring(extract_path));
			printf("%s", output);
			get_input_result(output, input, INPUT_LEN);
		}

		if (force_flag != 1 && 
		    input[0] != 10 &&
		    ((input[0] != 'y' &&
		    input[0] != 'Y') ||
		    input[1] != 10)) {
			return -1;
		}
	}
	ret = copy_file(md5_path, extract_path);
	if (ret < 0) {
		return -1;
	}

	ret = chmod(extract_path, mode);
	if (ret < 0) {
		MON_DBG("chmod %s error:%s\n", extract_path, strerror(errno));
		return -1;
	}
                
	ret = chown(extract_path, uid, gid);
	if (ret < 0) {
		MON_DBG("chown %s error:%s\n", extract_path, strerror(errno));
		return -1;
	}

	return ret;
}

int recover_files(char *path)
{
	int ret = 0; 
	mode_t mode;
        uid_t uid;
        gid_t gid;
	const char *md5 = NULL;
	char md5_path[PATH_MAX] = {0};
	char ori_path[PATH_MAX] = {0};
	int rc = 0;
	char output[PATH_MAX] = {0};
	char input[INPUT_LEN] = {0};

	record_path_to_original_path(path, ori_path);

	sqlite3_reset(virus_query_path_stmt);
	sqlite3_bind_text(virus_query_path_stmt, 1, path, -1, SQLITE_STATIC);

	sqlite3_reset(virus_query_path_stmt);
	while(sqlite3_step(virus_query_path_stmt) == SQLITE_ROW) {
		md5 = (const char *)sqlite3_column_text(virus_query_path_stmt,0);
		uid = sqlite3_column_int(virus_query_path_stmt,1);
		gid = sqlite3_column_int(virus_query_path_stmt,2);
		mode = sqlite3_column_int(virus_query_path_stmt,3);
		break;
	}

	if (md5 == NULL) {
		MON_DBG("File:%s is not in quarantine\n", path);
		return -1;
	}

	snprintf(md5_path, sizeof(md5_path), "%s", md5);

	/* 如果文件存在要交互询问是否覆盖 */
	if (access(ori_path, F_OK) == 0) {
		if (force_flag == 0) {
			snprintf(output, sizeof(output), "%s already exists, whether to overwrite [Y/N]:", thestring(ori_path));
			printf("%s", output);
			get_input_result(output, input, INPUT_LEN);
		}

		if (force_flag != 1 && 
		    input[0] != 10 &&
		    ((input[0] != 'y' &&
		    input[0] != 'Y') ||
		    input[1] != 10)) {
			return -1;
		}
	}

	ret = copy_file(md5_path, ori_path);
	if (ret < 0) {
		return -1;
	}

	ret = chmod(ori_path, mode);
	if (ret < 0) {
		MON_DBG("chmod %s error:%s\n", ori_path, strerror(errno));
		return -1;
	}
                
	ret = chown(ori_path, uid, gid);
	if (ret < 0) {
		MON_DBG("chown %s error:%s\n", ori_path, strerror(errno));
		return -1;
	}

	sqlite3_reset(virus_delete_stmt);
	sqlite3_bind_text(virus_delete_stmt, 1, path, -1, SQLITE_STATIC);
	rc = sqlite3_step(virus_delete_stmt);
	if (rc != SQLITE_DONE) {
		MON_DBG("Failed to delete record:%s(%d)\n", sqlite3_errstr(rc), rc);
		ret = -1;
	} else {
		unlink(md5_path);
	}

	return ret;
}

int delete_files(char *path)
{
	int ret = 0; 
	const char *md5 = NULL;
	char md5_path[PATH_MAX] = {0};
	int rc = 0;
	char output[PATH_MAX] = {0};
	char input[INPUT_LEN] = {0};
	char record_path[PATH_MAX] = {0};

	show_path_to_record_path(path, record_path);

	sqlite3_reset(virus_query_path_stmt);
	sqlite3_bind_text(virus_query_path_stmt, 1, record_path, -1, SQLITE_STATIC);

	sqlite3_reset(virus_query_path_stmt);
	while (sqlite3_step(virus_query_path_stmt) == SQLITE_ROW) {
                md5 = (const char *)sqlite3_column_text(virus_query_path_stmt,0);
		break;
        }	

	if (md5 == NULL) {
		MON_DBG("File:%s is not in quarantine\n", path);
		return -1;
	}

	snprintf(md5_path, sizeof(md5_path), "%s", md5);
	if (force_flag == 0) {
		snprintf(output, sizeof(output), "whether to delete the file '%s' [Y/N]:", path);
		printf("%s", output);
		get_input_result(output, input, INPUT_LEN);
	}

	if (force_flag == 1 || input[0] == 10 ||
		((input[0] == 'y' || input[0] == 'Y') && input[1] == 10)) {
		ret = unlink(md5_path);
		if (ret < 0) {
			MON_DBG("delete file:%s failed:%s\n", md5_path, strerror(errno));
			return 0;
		}

		sqlite3_reset(virus_delete_stmt);
		sqlite3_bind_text(virus_delete_stmt, 1, record_path, -1, SQLITE_STATIC);
		rc = sqlite3_step(virus_delete_stmt);
		if (rc != SQLITE_DONE) {
			MON_DBG("Failed to delete record:%s\n", sqlite3_errstr(rc), rc);
			ret = -1;
		}
	} else {
		ret = -1;
	}

	return ret;
}

int extract_quarantine_files(int argc, char **argv)
{
	int ret = 0;
	char dirname[PATH_MAX] = {0};
	char *ori_file = NULL;
	char *extr_path = NULL;
	char *filename = NULL;
	char path_tmp[PATH_MAX] = {0};
	char path[PATH_MAX] = {0};
	char record_path[PATH_MAX] = {0};
	char dir[PATH_MAX] = {0};
	int len = 0;
	int minimum_argc = 5;
	int ori_offset = 0;
	int ori_number = 0;
	int extr_offset = 0;
	int extr_number = 0;

	/* 
 	 * 无强制参数时，提取操作命令共五个参数, 被提取的文件是第四个参数argv[3], 提取的路径是第五个参数argv[4]
	 * 有强制参数时，强制参数在被提取文件之前，被提取文件偏移序号加+1, 提取路径偏移序号+1
	 * 强制参数在被提取文件和提取路径之间，提取路径偏移序号+1
	 * 除了-qf，有强制标志时，比正常情况多一个参数
	 */
	if (force_flag && force_number) {
		minimum_argc = 6;
		if (force_number == 4) {
			extr_offset = 1;
		} else if (force_number > 0 && force_number <= 3) {
			ori_offset = 1;
			extr_offset = 1;
		}
	}

	/* 检查参数个数, 提取操作只能一次提取单个文件 */
	if (argc < minimum_argc) {
		return -1;
	}

	/* ori_file为被提取文件, extr_path为提取路径 */
	ori_number = 3 + ori_offset;
	extr_number = 4 + extr_offset;
	ori_file = argv[ori_number];
	extr_path = argv[extr_number];

	show_path_to_record_path(ori_file, record_path);

	filename = safebasename(ori_file);
	if (!filename) {
		MON_DBG("Error: Wrong parameters\n");
		return -1;
	}

	getcwd(dir, PATH_MAX);
	/* 参数为相对路径时，先拼接路径 */
	if (extr_path[0] != '/' && strncmp(extr_path, "~/", 2) != 0) {
		snprintf(path_tmp, sizeof(path_tmp), "%s/%s", thestring(dir), extr_path);
	} else {
		snprintf(path_tmp, sizeof(path_tmp), "%s", extr_path);
	}

	/* 拼接路径为目录则拼接完整文件名，拼接路径为文件则判断目录是否存在 */
	if (check_dir_exist(path_tmp) == 0) {
		len = strlen(path_tmp);
		if (path_tmp[len-1] == '/') {
			snprintf(path, sizeof(path), "%s%s", thestring(path_tmp), filename);
		} else {
			snprintf(path, sizeof(path), "%s/%s", thestring(path_tmp), filename);
		}
	} else {
		safedirname(path_tmp, dirname, sizeof(dirname));
		snprintf(path, sizeof(path), "%s", path_tmp);

		/* 判断提取路径的目录存不存在*/
		if (check_dir_exist(dirname) < 0) {
			MON_DBG("Dir: %s not exist\n", dirname);
			return -1;
		}

	}

	ret = extract_files(record_path, path);
	if (ret < 0) {
		MON_DBG("Extract %s to %s failed\n", argv[3], path);
	}

	return ret; 
}

int query_quarantine_files(int argc, char **argv)
{
        char dbname[140] = {0};
        struct stat st = {0};
        int rc = 0;
        int mtime = 0, uid = 0;
	char time_str[TIME_LEN] = {0};
	char md5_tmp[PATH_MAX] = {0};
	char show_path[PATH_MAX] = {0};
	char tmp_path[PATH_MAX] = {0};

        if (argc != 3) {
		printf("Error: Wrong parameters\n");
		show_usage();
                return -1;
        }

        snprintf(dbname, 140, "%s/%s/virus.db", WORKDIR, VIRUSDB);

        if (lstat(dbname, &st) < 0) {
		MON_DBG("Get db failed:%s\n", strerror(errno));
                return -1;
        }

        if (st.st_size == 0) {
		MON_DBG("Db size is 0\n");
                return -1;
        }

        rc = sqlite3_open_v2(dbname, &virus_db, SQLITE_OPEN_MODE, NULL);
        if (rc != SQLITE_OK) {
		MON_DBG("Open db failed\n");
                return -1;
        }

        printf("Time\t\t\t Quarantine file\t\t\t Original file:\n");
	sqlite3_reset(virus_query_stmt);
	while (sqlite3_step(virus_query_stmt) == SQLITE_ROW) {
		mtime = sqlite3_column_int(virus_query_stmt ,0);
		const char *path = (const char *)sqlite3_column_text(virus_query_stmt ,1);
		snprintf(tmp_path, sizeof(tmp_path), "%s", path);
		record_path_to_show_path(tmp_path, show_path);
		const char *md5 = (const char *)sqlite3_column_text(virus_query_stmt ,2);
		uid = sqlite3_column_int(virus_query_stmt ,3);

		/* root用户可以查看所有用户隔离的文件，普通用户只能查看自己隔离的文件 */
		if (exec_uid == 0 || exec_uid == uid) {
			get_time_string(mtime, time_str, sizeof(time_str));
			snprintf(md5_tmp, sizeof(md5_tmp), "%s", md5);
			printf("%s\t%s\t%s\n", time_str, safebasename(md5_tmp), show_path);
		}
	}

        return 0;
}

int recover_quarantine_files(int argc, char **argv)
{
	int ret = 0;
	int num = 0, i = 0, count = 0;
	char *file = NULL;
	char path[PATH_MAX] = {0};
	char record_path[PATH_MAX] = {0};
	char dir[PATH_MAX] = {0};
	int minimum_argc = 4;

	/* 除了-qf，有强制标志时，比正常情况多一个参数 */
	if (force_flag && force_number) {
		minimum_argc = 5;
	}

	/* 检查参数个数 */
	if (argc < minimum_argc) {
		printf("Error: Missing parameters\n");
		show_usage();
		return -1;
	}

	getcwd(dir, PATH_MAX);

	num = argc - 3;
	for(i = 0; i < num; i++) {
		file = argv[i+3];

		if (strcmp(file, "-f") == 0 ||
		    strcmp(file, "--force") == 0 ||
		    strcmp(file, "recover") == 0) {
			continue;
		}

		if (file[0] != '/') {
			snprintf(path, sizeof(path), "%s/%s", thestring(dir), file);
		} else {
			snprintf(path, sizeof(path), "%s", file);
		}

		show_path_to_record_path(path, record_path);

		ret = recover_files(record_path);
		if (ret < 0) {
			MON_DBG("Recover file:%s failed\n", path);
			continue;
		}
		count++;
	}

	return count; 
}

int delete_quarantine_files(int argc, char **argv)
{
	int ret = 0;
	int num = 0, i = 0, count = 0;
	char *file = NULL;
	int minimum_argc = 4;

	/* 除了-qf，有强制标志时，比正常情况多一个参数 */
	if (force_flag) {
		minimum_argc = 5;
	}

	/* 检查参数个数 */
	if (argc < minimum_argc) {
		printf("Error: Missing parameters\n");
		show_usage();
		return -1;
	}

	num = argc - 3;
	for(i = 0; i < num; i++) {
		file = argv[i+3];

		if (strcmp(file, "-f") == 0 ||
		    strcmp(file, "--force") == 0 ||
		    strcmp(file, "delete") == 0) {
			continue;
		}

		if (file[0] != '/') {
			MON_DBG("File:%s is not a correct file format\n", file);
			continue;
		}

		ret = delete_files(file);
		if (ret < 0) {
			MON_DBG("Delete file:%s failed\n", file);
			continue;
		}
		count++;
	}

	return count; 
}

int quarantine_files_operate(int argc, char **argv)
{
	int ret = 0;
	int minimum_argc = 3;
	int action_number = 2;

	/*
	 * 有-f参数时, 参数个数最少为4个，否则为三个
	 * -f参数时在具体动作之前的(例如./sniper_antivirus -q -f recover /tmp/1.txt), 检查的动作recover为第4个参数argv[3]
	 * 否则检查的为第3个参数argv[2](例如./sniper_antivirus -q recover /tmp/1.txt)
	 * 除了-qf，有强制标志时，比正常情况多一个参数
	 */
	if (force_flag && force_number) {
		minimum_argc = 4;
		if (force_number > 0 && force_number <= 2) {
			action_number = 3;
		}
	}

	if (argc < minimum_argc ) {
		printf("Error: Missing parameters\n");
		show_usage();
		return -1;
	}

	/* 一个用户只能同时启动一次 */
	if (is_this_running(exec_uid) == 1) {
		printf("A user can only start once at the same time\n");
		return -1;
	}

	if (init_virus_operate_db() < 0) {
		printf("Error: Failed to operate virus database\n");
		return -1;
	}

	if (strcmp(argv[action_number], "query") == 0) {
		ret = query_quarantine_files(argc, argv);
		if (ret < 0) {
			printf("Query failed\n");
		}
	} else if (strcmp(argv[action_number], "recover") == 0) {
		ret = recover_quarantine_files(argc, argv);
		if (ret > 1) {
			printf("Total of %d files were recovered\n", ret);
		} else if(ret == 1) {
			printf("Total of %d file was recovered\n", ret);
		} else if(ret == 0) {
			printf("No file need to recover\n");
		} else {
			printf("Recover failed\n");
		}
	} else if (strcmp(argv[action_number], "delete") == 0) {
		ret = delete_quarantine_files(argc, argv);
		if (ret > 1) {
			printf("Total of %d files were deleted\n", ret);
		} else if (ret == 1) {
			printf("Total of %d file was deleted\n", ret);
		} else if (ret == 0) {
			printf("No file need to delete\n");
		} else {
			printf("Delete failed\n");
		} 
	} else if (strcmp(argv[action_number], "extract") == 0)  {
		ret = extract_quarantine_files(argc, argv);
		if (ret < 0) {
			printf("Extract failed\n");
		} else {
			printf("Extract successed\n");
		}
	} else {
		show_usage();
		ret = -1;
	}

	print_tips();
	fini_virus_operate_db();
	return ret;
}
