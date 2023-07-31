/*
 * 发送日志相关的函数，和logsend线程
 */

#include "header.h"

time_t last_local_time = 0;

/* 将日志消息存入本地日志文件 */
static void store_local_log(char *post, char *logtype)
{
	FILE *fp = NULL;
	struct timeval tv = {0};
	struct stat st = {0};
	unsigned long event_time = 0;
	long maxsize = 0;
	char logpath[512] = {0};
	int log_maxsize = 0;                 //日志保留空间大小(默认MB)

	/* 默认设为1个G，小于1个G, 按1个G 处理*/
	log_maxsize = conf_global.offline_space_size;
	if (log_maxsize < 1024) {
		log_maxsize = 1024;
	}

	maxsize = log_maxsize * MB_SIZE;

	gettimeofday(&tv, NULL);
	event_time = tv.tv_sec * 1000000 + tv.tv_usec;

	snprintf(logpath, sizeof(logpath), "%s/%s/%s.log", LOCALLOG_DIR, logtype, logtype);

	/* 检查日志目录的大小 */
	if (check_dir_maxsize(LOCALLOG_DIR, maxsize) < 0) {
		/* 如果日志目录空间大于设置的大小消息就丢弃 */
		/* 一个小时只报一次离线日志目录满 */
		if (last_local_time != 0)  {
			if(tv.tv_sec - last_local_time < ONEHOUR) {
				return;
			}
		}
		last_local_time = tv.tv_sec;

		report_dependency_msg("LogStorageSpaceIsFull");
		INFO("offline log full, dir %s larger than %dMB\n",
		     LOCALLOG_DIR, log_maxsize);
		return;
	}

	/* 若离线日志小于1MB，追加在尾部，否则转储老的到日志转发目录，由日志线程统一发送，重新记一个新的 */
	if (stat(logpath, &st) < 0) {
		fp = fopen(logpath, "w+");
	} else if (st.st_size < MB_SIZE) {
		fp = fopen(logpath, "a+");
	} else {
		char path[512] = {0};

		snprintf(path, sizeof(path), "%s/%s-%lu.log", LOG_SEND_DIR, logtype, event_time);
		rename(logpath, path);
		fp = fopen(logpath, "w+");
	}

	if (fp == NULL) {
		MON_ERROR("store_offlinelog: open %s fail: %s\n", logpath, strerror(errno));
		return;
	}

	fprintf(fp, "%s\n", post);
	fflush(fp);
	fclose(fp);
}

/* 将之前的日志消息转存入本地待发送目录 */
void check_log_to_send(char *logtype)
{
	struct timeval tv = {0};
	struct stat st = {0};
	unsigned long event_time = 0;
	char logpath[512] = {0};
	char path[512] = {0};
	int log_collect_interval = 0;          //缓存日志批量发送时间(默认s)

	debug_vmrss(logtype); //显示进程内存使用情况，用于调试线程是否有内存泄漏

	gettimeofday(&tv, NULL);
	event_time = tv.tv_sec * 1000000 + tv.tv_usec;

	snprintf(logpath, sizeof(logpath), "%s/%s", LOCALLOG_DIR, logtype);

	/* 检查日志创建时间是否超过了批量发送时间 */
	if (stat(logpath, &st) < 0) {
		return;
	}

	/* 小于30秒按30秒处理 */
	log_collect_interval = conf_global.log_collect_interval;
	if (log_collect_interval < 30) {
		log_collect_interval = 30;
	}

	/* 大于时间间隔才会转存 */
	if (tv.tv_sec - st.st_ctime >= log_collect_interval) {
		/* 日志文件不存在时不用转存 */
		snprintf(logpath, sizeof(logpath), "%s/%s/%s.log", LOCALLOG_DIR, logtype, logtype);
		if (access(logpath, F_OK) < 0) {
			return;
		}

		snprintf(path, sizeof(path), "%s/%s-%lu.log", LOG_SEND_DIR, logtype, event_time);
		rename(logpath, path);
	}
}

/* return 0, success; -1 fail */
/* http_post里已经DBG了post和reply，这里不重复DBG */
/* logtype为了区分日志分类，存放到对应的目录下 */
int client_send_msg(char *post, char *reply, int reply_len, char *url, char *logtype)
{
	/*
	 * reply的长度都是统一的REPLY_MAX，临时定义一个变量方便提交
	 * client_send_msg函数涉及到多个文件，等这些文件全部通过commit脚本检查后，
	 * 再把client_send_msg定义和实现的地方加上reply_len参数
	 */

	printf("post %s msg : %s\n", logtype, post);
	if (!post || !reply || !url || !logtype) {
		MON_ERROR("client_send_msg: null argument: "
			  "post %p, reply %p, url %p, logtype %p\n", post, reply, url, logtype);
		return -1;
	}

	/* 单条模式下，不发批量日志，发单条日志 */
	if (conf_global.log_collect_mode == SINGLE_LOG_MODE && strcmp(url, LOG_URL) == 0) {
		url = SINGLE_LOG_URL;
	}

	/* 批量发送存入本地 */
	if (strcmp(url, LOG_URL) == 0) {
		store_local_log(post, logtype);
		return 0;
	}

	/* 剩下的都是需要即使通信的, 失败再存入本地 */
	if (http_post(url, post, reply, reply_len) <= 0) {
		printf("send msg to %s fail\n", url);
		if (client_registered && !Heartbeat_fail) { //已知与管控通信异常时不打印
			MON_ERROR("send msg to %s fail\n", url);
		}
		store_local_log(post, logtype);
		return -1;
	}
	printf("post URL is %s55555555555555555555555\n", url);

	return 0;
}

/* 发送防御日志, 不同类别的日志需要区分存放对应类别的名字日志中 */
void send_defence_msg(struct defence_msg *msg, char *logtype)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;

	if (!msg) {
		return;
	}

	/* 病毒防护时virus_name和virus_type不能为空 */
	if (strcmp(msg->log_name, "AntivirusProtection") == 0) {
		if (!msg->virus_name || !msg->virus_type) {
			return;
		}
	}

	/* 没有传入事件时间，则用当前时间 */
	if (msg->event_tv.tv_sec == 0) {
		gettimeofday(&msg->event_tv, NULL);
	}
	event_time = (msg->event_tv.tv_sec + serv_timeoff) * 1000 + msg->event_tv.tv_usec / 1000;

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

	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
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
	if (strcmp(msg->log_name, "AntivirusProtection") == 0) {
		cJSON_AddStringToObject(arguments, "virus_name", msg->virus_name);
		cJSON_AddStringToObject(arguments, "virus_type", msg->virus_type);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);

	client_send_msg(post, reply, sizeof(reply), LOG_URL, logtype);

	cJSON_Delete(object);
	free(post);
}

/* 发送解锁ip消息 */
void send_unlockip_msg(char *ip, int result)
{
	char ippath[S_SHORTPATHLEN] = {0};
	FILE *fp = NULL;
	char buf1[S_LINELEN] = "", *log_name = buf1;
	char buf2[S_LINELEN] = "", *log_id = buf2;
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	int behavior = 0, level = 1, terminate = 0;
	struct timeval tv;

	if (!ip) {
		return;
	}
	snprintf(ippath, sizeof(ippath), "%s/%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR, ip);

	fp = fopen(ippath, "r");
	if (fp) {
		fgets(buf1, sizeof(buf1), fp);
		log_name = skip_headspace(buf1);
		delete_tailspace(log_name);

		fgets(buf2, sizeof(buf2), fp);
		log_id = skip_headspace(buf2);
		delete_tailspace(log_id);

		fclose(fp);
	}

	if (result == OPERATE_OK) {
		INFO("unlock %s\n", ip);
		unlink(ippath);
	}

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

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec+serv_timeoff) *1000 + (int)tv.tv_usec/1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientUnlockIP");
	cJSON_AddStringToObject(object, "log_category", "Client");
	cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "Unlock");
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
	cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
	cJSON_AddStringToObject(arguments, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(arguments, "policy_name", policy_name_cur);
	cJSON_AddStringToObject(arguments, "policy_time", policy_time_cur);
	cJSON_AddStringToObject(arguments, "log_name", log_name);
	cJSON_AddStringToObject(arguments, "log_id", log_id);
	cJSON_AddStringToObject(arguments, "object", ip);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_POST, "unlock_ip: %s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "network");

	cJSON_Delete(object);
	free(post);
}

/* 发送客户端依赖日志 */
void report_dependency_msg(char *string)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	int behavior = 0, level = 0, result = MY_RESULT_OK;
	bool event = false;
	char log_name[LOG_NAME_MAX] = {0};
	char event_category[EVENT_NAME_MAX] = {0};
	int terminate = 0;
	unsigned long event_time = 0;
	struct timeval tv = {0};

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
	event = false;
	snprintf(log_name, sizeof(log_name), "%s", "ClientDependency");
	snprintf(event_category, sizeof(event_category), "%s", "");

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Client");
	  cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "Query");
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
	cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
	cJSON_AddStringToObject(arguments, "client_dependency", string);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "file");
	DBG2(DBGFLAG_FILE, "report dependency msg:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
}

/* 上传日志的公共头信息 */
void cJSON_AddCommonHeader(cJSON *object)
{
	if (object) {
		cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
		cJSON_AddStringToObject(object, "ip_address", If_info.ip);
		cJSON_AddStringToObject(object, "mac", If_info.mac);
		cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
		cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
		cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
		cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
		cJSON_AddStringToObject(object, "source", "Agent");
		cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	}
}

/* logsend thread */
void *log_send(void *ptr)
{
	DIR *dirp = NULL;
	struct dirent *dent = NULL;
	struct stat st = {0};
	char logfile[PATH_MAX] = {0};

	prctl(PR_SET_NAME, "logsend");
	save_thread_pid("logsend", SNIPER_THREAD_LOGSEND);

	/*
	 * 轮训检测目录下是否有需要发送给管控的日志文件
	 * 文件是由各个线程将需要发送的日志转存到此处
	 */
	while (Online) {
		sleep(1); //每次批量发送日志间隔一秒，避免狂占cpu

		/* 如果过期了/停止客户端工作，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			sleep(STOP_WAIT_TIME);
			continue;
		}

		/* 工具模式或者离线了不再尝试 */
		if (tool_mode == 1 || Heartbeat_fail == 1 || client_registered == 0) {
			continue;
		}

		dirp = opendir(LOG_SEND_DIR);
		if (dirp == NULL) {
			DBG2(DBGFLAG_LOGSEND, "open logdir %s fail: %s\n", LOG_SEND_DIR, strerror(errno));
			continue;
		}

		/* 目录下的文件都是转存过来的，即使不是日志文件,发送给管控也不影响 */
		while ((dent = readdir(dirp))) {
			if (dent->d_name[0] == '.') {
				continue; //忽略.和..
			}

			snprintf(logfile, sizeof(logfile), "%s/%s", LOG_SEND_DIR, dent->d_name);

			if (stat(logfile, &st) < 0) {
				DBG2(DBGFLAG_LOGSEND, "not send bad logfile %s: %s\n", logfile, strerror(errno));
				continue;
			}

			if (upload_file(logfile, LOG_URL) < 0) {
				DBG2(DBGFLAG_LOGSEND, "send logfile %s fail\n", logfile);
				break;
			}
			DBG2(DBGFLAG_LOGSENDOk, "send logfile %s ok\n", logfile);
		}
		closedir(dirp);
	}

	INFO("log_send thread exit\n");

	return NULL;
}
