#include "header.h"

char def_printer_name[64] = {0};

unsigned long printer_filesize = 0;
unsigned long printer_fileinode = 0;

struct _print_job print_job_old[JOB_MAX] = {{0}};
int job_count_old = 0;

void printer_terminate_post_data(taskstat_t *taskstat)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	bool event = true;
	int terminate = 0;
	unsigned long event_time = 0;
	struct timeval tv = {0};
	struct defence_msg defmsg = {0};
	char *path = NULL, tmp_path[PATH_MAX] = {0}, real_path[PATH_MAX] = {0};
	char *ext = NULL, *filename = NULL;
	struct stat st = {0};
	char *cmdname = safebasename(taskstat->cmd);
	int result = 0;
	int defence_result = MY_RESULT_OK;

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

	/* 取命令行最后一个参数作为要打印的文件 */
	path = strrchr(taskstat->args, ' ');
	if (path) {
		path++;
		if (*path != '/') {
			snprintf(tmp_path, PATH_MAX, "%s/%s", taskstat->cwd, path);
			realpath(tmp_path, real_path);
			path = real_path;
		}
		if (stat(path, &st) < 0) {
			path = NULL;
		} else {
			filename = safebasename(path);
			ext = strrchr(filename, '.');
			if (!ext) {
				ext = "";
			} else {
				ext++;
			}
		}
	}

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;
	get_session_uuid(taskstat->tty, taskstat->session_uuid);

	if (client_mode_global == OPERATION_MODE) {
		terminate = MY_HANDLE_WARNING;
		event = false;
		result = MY_RESULT_OK;
		defence_result = MY_RESULT_FAIL;
        } else {
		terminate = MY_HANDLE_BLOCK_OK;
		event = true;
		result = MY_RESULT_FAIL;
		defence_result = MY_RESULT_OK;
        }

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "IllegalPrint");
	cJSON_AddStringToObject(object, "log_category", "Print");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", "Fasten");
	cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_VIOLATION);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "Print");
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", taskstat->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);
	cJSON_AddStringToObject(arguments, "process_name", cmdname);
	cJSON_AddNumberToObject(arguments, "process_id", taskstat->pid);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
	cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
	cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);
	cJSON_AddStringToObject(arguments, "md5", taskstat->md5);
	cJSON_AddStringToObject(arguments, "printer_name", "");
	cJSON_AddStringToObject(arguments, "printer_type", "");
	cJSON_AddNumberToObject(arguments, "print_num", 0);
	cJSON_AddStringToObject(arguments, "print_queue_id", "");
	cJSON_AddNumberToObject(arguments, "print_page", 0);
	if (path) {
		cJSON_AddStringToObject(arguments, "file_name", filename);
		cJSON_AddStringToObject(arguments, "file_path", path);
		cJSON_AddStringToObject(arguments, "extension", ext);
		cJSON_AddNumberToObject(arguments, "file_size", st.st_size);
	} else {
		cJSON_AddStringToObject(arguments, "file_name", "");
		cJSON_AddStringToObject(arguments, "file_path", "");
		cJSON_AddStringToObject(arguments, "extension", "");
		cJSON_AddNumberToObject(arguments, "file_size", 0);
	}
	cJSON_AddStringToObject(arguments, "session_uuid", taskstat->session_uuid);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_PRINT, "IllegalPrint: %s\n", post);

	/*
	 * 禁止刻录由process线程处理，如果日志存到其他类别日志里，如打印刻录作为一类(cdrom)，
	 * 则可能存在这样的风险，process线程正在将禁止刻录的日志存到cdrom类别日志中，
	 * 同时cdrom线程正在发送cdrom类日志，此时，发送的可能是不完整的日志
	 */
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "process");

	cJSON_Delete(object);
	free(post);

	if (client_mode_global == OPERATION_MODE) {
		return;
	}

	defmsg.event_tv.tv_sec = tv.tv_sec + serv_timeoff;
	defmsg.event_tv.tv_usec = tv.tv_usec;
	defmsg.operation = termstr;
	defmsg.result = defence_result;

	defmsg.user = taskstat->user;
	defmsg.log_name = "IllegalPrint";
	defmsg.log_id = uuid;
	defmsg.object = cmdname;
	
	send_defence_msg(&defmsg, "process"); //禁止刻录由process线程处理
}

static void operation_print_post_data(struct _print_msg *msg, struct  _print_job *info)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	int behavior = 0, level = 0, result = 0;
	char operating[OP_LEN_MAX] = {0};
	bool event = false;
	int terminate = 0;
	unsigned long event_time = 0;
	struct timeval tv;
	char user[S_NAMELEN];
	char *extension = NULL;

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

	level = MY_LOG_KEY;
	behavior = MY_BEHAVIOR_NO;
	result = MY_RESULT_OK;
	terminate = MY_HANDLE_NO;

	strncpy(operating, "Print", OP_LEN_MAX);
	operating[OP_LEN_MAX - 1] = '\0';

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

	if (info->user == NULL) {
		strcpy(user, "N/A");
	} else {
		strncpy(user, info->user, S_NAMELEN);
		user[S_NAMELEN-1] = 0;
	}

	extension = get_path_types(info->file);

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "Print");
	cJSON_AddStringToObject(object, "log_category", "Print");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "process_uuid", "");
	cJSON_AddStringToObject(arguments, "process_name", "cpusd");
	cJSON_AddNumberToObject(arguments, "process_id", 0);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
	cJSON_AddStringToObject(arguments, "process_path", "");
	cJSON_AddStringToObject(arguments, "process_commandline", "");
	cJSON_AddStringToObject(arguments, "md5", "");
	cJSON_AddStringToObject(arguments, "printer_name", msg->device_name);
	cJSON_AddStringToObject(arguments, "printer_type", msg->device_name);
	cJSON_AddNumberToObject(arguments, "print_num", 0);
	cJSON_AddNumberToObject(arguments, "print_queue_id", info->job);
	cJSON_AddNumberToObject(arguments, "print_page", 0);
	cJSON_AddStringToObject(arguments, "file_name", safebasename(info->file));
	cJSON_AddStringToObject(arguments, "file_path", info->file);
	cJSON_AddStringToObject(arguments, "extension", extension);
	cJSON_AddNumberToObject(arguments, "file_size", info->size);
	cJSON_AddStringToObject(arguments, "session_uuid", "");

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_PRINT, "printer post:%s\n", post);

	client_send_msg(post, reply, sizeof(reply), LOG_URL, "inotify"); //打印日志由inotify线程处理

	cJSON_Delete(object);
	free(post);
}	

int get_job_list(struct _print_job *print_job, int *job_count)
{
        FILE *fp = NULL;
        int ret = 0;
        char user[S_NAMELEN] = {0};
        int job = 0;
        char file[S_PATHLEN] = {0};
        int size = 0;
        int i = 0;
        int count = 0;
        char result_buf[MAXLINE], command[MAXLINE];

        snprintf(command, sizeof(command), "lpq -a");

        fp = popen(command, "r");
        if (NULL == fp) {
                MON_ERROR("popen执行失败！");
                return 0;
        }

        while (fgets(result_buf, sizeof(result_buf), fp) != NULL) {
		DBG("result_buf:%s\n", result_buf);
                if (strstr(result_buf, "result:Rank") != NULL 
			|| strstr(result_buf, "无条目") != NULL
			|| strstr(result_buf, "no entries") != NULL) {
                        continue;
                }

                if (strstr(result_buf, "Test Page") != NULL) {
                        ret = sscanf(result_buf, "%*s %s %d %*s %*s %d", user, &job, &size);
                        if (ret != 3) {
                                continue;
                        }
                        strcpy(file, "Test Page");
                        count ++;
                        
                } else {
                        ret = sscanf(result_buf, "%*s %s %d %s %d", user, &job, file, &size);
                        if (ret != 4) {
                                continue;
                        }
                        count ++;
                }

                print_job[i].job = job;
                print_job[i].size = size;
                strncpy(print_job[i].user, user, S_NAMELEN);
                print_job[i].user[S_NAMELEN-1] = 0;
                strncpy(print_job[i].file, file, S_PATHLEN);
                print_job[i].file[S_PATHLEN-1] = 0;
                i++;
                *job_count = count;
        }
#if 0
	//后面会有脏数据，要清零
        memset(print_job+count, 0, sizeof(struct _print_job)* (JOB_MAX - count));
#endif
        pclose(fp);

        return 0;
}

static void cancel_all_job(void)
{
	struct _print_job print_job_new[JOB_MAX];
	int job_count_new = 0;
	int i = 0;
	char command[MAXLINE] = {0};

	memset(&print_job_new, 0, sizeof(struct _print_job));

        get_job_list(print_job_new, &job_count_new);
	for (i = 0; i < job_count_new; i++) {
		snprintf(command, sizeof(command), "lprm %d", print_job_new[i].job);
		system(command);		
	}
}

static void get_print_job(struct _print_msg *msg)
{
	struct _print_job print_job_new[JOB_MAX];
        int job_count_new = 0;
        int i = 0, j = 0;
        char *extension = NULL;
        int flag = 0;
	int count = 0;
	int unknown_flag = 0;

        if (job_count_old >= JOB_MAX) {
                INFO("job list is larger then max\n");
                return;
        }
        memset(&print_job_new, 0, sizeof(struct _print_job));

        get_job_list(print_job_new, &job_count_new);
	DBG("job_count_new:%d\n", job_count_new);

	for (i = 0; i < job_count_new; i++) {
//		printf("job_count_old:%d, print_job_new[%d].job:%d, print_job_old[%d].job:%d\n", job_count_old, i, print_job_new[i].job, job_count_old-1, print_job_old[job_count_old-1].job);
		unknown_flag = 0;
		if (job_count_old == 0 || print_job_new[i].job > print_job_old[job_count_old-1].job) {
			if (strcmp(print_job_new[i].file, "unknown") == 0) {
				unknown_flag = 1;
			}
			extension = get_path_types(print_job_new[i].file);
//			printf("file:%s, extension:%s\n",print_job_new[i].file, extension);
                        flag = 0;
			pthread_rwlock_rdlock(&fasten_policy_global.lock);
			count = fasten_policy_global.device.printer.ext_num;
                        for (j = 0; j < count; j++) {
                                if (strcmp(fasten_policy_global.device.printer.ext[j].list, "*") == 0 ||
				    strcmp(fasten_policy_global.device.printer.ext[j].list, extension) == 0 ||
				    unknown_flag == 1) {
                                        flag = 1;
                                        break;
                                }
                        }
			pthread_rwlock_unlock(&fasten_policy_global.lock);

                        memcpy(&print_job_old[job_count_old], &print_job_new[i], sizeof(struct _print_job));
                        job_count_old++;

			/* 监控类型为空则全报 */
			if (count == 0) {
				flag = 1;
			}
                        if (flag == 1) {
                                operation_print_post_data(msg, &print_job_new[i]);
                                break;
                        }
                }
        }

        return;
}

static void get_cancel_job(struct _print_msg *msg)
{
        struct _print_job print_job_new[JOB_MAX];
        int job_count_new = 0;
        int i = 0, j = 0, tmpcount=0;
        int max = 0;
	char *extension = NULL;
	int flag = 0;

        struct _print_job *print_job_tmp = NULL;
        max = job_count_old < JOB_MAX-1?job_count_old:JOB_MAX-1;

        memset(&print_job_new, 0, sizeof(struct _print_job));

        get_job_list(print_job_new, &job_count_new);

        for (i = 0; i < max; i++) {
                if (print_job_old[i].job != print_job_new[i].job) {
			extension = get_path_types(print_job_old[i].file);
                        flag = 0;

			pthread_rwlock_rdlock(&fasten_policy_global.lock);
                        for (j = 0; j < fasten_policy_global.device.printer.ext_num; j++) {
                                if (strcmp(fasten_policy_global.device.printer.ext[j].list, "*") == 0
                                        || strcmp(fasten_policy_global.device.printer.ext[j].list, extension) == 0) {
                                        flag = 1;
                                        break;
                                }
                        }
                        pthread_rwlock_unlock(&fasten_policy_global.lock);

			if (flag == 0) {
				continue;
			}

                        operation_print_post_data(msg, &print_job_old[i]);
                        tmpcount = job_count_old - i + 1;
                        print_job_tmp = sniper_malloc(sizeof(struct _print_job)* tmpcount, FILE_GET);
                        if (print_job_tmp == NULL) {
                                MON_ERROR("malloc print_job_tmp failed\n");
                                return;
                        }
                        memcpy(print_job_tmp, &print_job_old[i+1], sizeof(struct _print_job)* tmpcount);
                        memset(&print_job_old[i], 0, sizeof(struct _print_job)* tmpcount+1);
                        memcpy(&print_job_old[i], print_job_tmp, sizeof(struct _print_job)* tmpcount);
                        job_count_old--;
                        break;
                }
        }

        if (print_job_tmp) {
                sniper_free(print_job_tmp, tmpcount, FILE_GET);
        }
}

void check_printer_files(void)
{
        int ret = 0;
        FILE *fp = NULL;
        char buff[S_LINELEN] = {0};
	struct stat pbuf = {0};
	struct _print_msg printer_msg = {0};

        if (fasten_policy_global.device.printer.enable == 0) {
                return;
        }

	if (stat(LP_PATH, &pbuf) < 0) {	
		return;
	}

	if (pbuf.st_ino != printer_fileinode) {
		printer_filesize = 0;
		printer_fileinode = pbuf.st_ino;
	}

        fp = fopen(LP_PATH, "r");
        if (fp == NULL) {
                MON_ERROR("print open %s fail : %s", LP_PATH, strerror(errno));
                return;
        }

        fseek(fp, printer_filesize, SEEK_SET);

        while (fgets(buff, S_LINELEN, fp)) {
		DBG("buff:%s\n", buff);
                printer_filesize = ftell(fp);
                if (strstr(buff, "Print-Job successful-ok") ||
                    strstr(buff, "Send-Document successful-ok")) {
			if (fasten_policy_global.device.printer.terminate == 1) {
				cancel_all_job();
				job_count_old = 0;
				memset(&print_job_old, 0, sizeof(struct _print_job)*JOB_MAX);
				continue;
			}

                        ret = sscanf(buff, "%*s%*s%*s%*s%*s%*s /printers/%63s", printer_msg.device_name);
                        if (ret != 1) {
                                continue;
                        }

                        if (strlen(def_printer_name) == 0) {
                                strncpy(def_printer_name, printer_msg.device_name, 63);
                        }
                        get_print_job(&printer_msg);
			continue;
		}

                if (strstr(buff, "Cancel-Job successful-ok")) {
			if (fasten_policy_global.device.printer.terminate == 1) {
				cancel_all_job();
				job_count_old = 0;
				memset(&print_job_old, 0, sizeof(struct _print_job)*JOB_MAX);	
				continue;
			}

                        if (strlen(def_printer_name) == 0) {
                                strcpy(printer_msg.device_name, "default printer");
                        } else {
                                strncpy(printer_msg.device_name, def_printer_name, 63);
                        }

                        get_cancel_job(&printer_msg);
			continue;
		}

                if (strstr(buff, "Create-Job successful-ok")) {
                        continue;
                }
	}

        fclose(fp);
}
