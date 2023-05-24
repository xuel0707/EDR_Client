/*
 * 客户端升级
 * Author: zhengxiang
 */

#include "header.h"

#define UPDATE_TASKINFO "/opt/snipercli/.update_task_information"

/* write download data into file */
static size_t write_file(void *ptr, size_t size, size_t nmemb, void *userp)
{
	FILE *fp = (FILE *)userp;
	size_t write_size = fwrite(ptr, size, nmemb, fp);

	return write_size;
}

/* 下载url指向的数据。成功返回0，失败返回-1 */
int download_file(char *url, FILE *fp)
{
	CURL *curl = NULL;
	CURLcode res = 0;

	if (!url || !fp) {
		return -1;
	}
	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("init download curl failed!\n");
		return -1;
	}

	DBG2(DBGFLAG_POST, "download %s\n", url);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 500L); //遇到过30s超时不够，延长到5分钟
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  //不处理信号

	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT"); //客户端统一使用ANTIAPT作为消息标志头

	curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L); //禁止后续连接重新使用

	/* 设置保存数据的回调函数 */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L); //不需要显示下载进度

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); //不验证SSL证书
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); //不验证SSL证书中的主机名

	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		MON_ERROR("download fail: %s\n", curl_easy_strerror(res));
		return -1;
	}

	return 0;
}

/* 客户端启动Startd/停止Stoped/升级Upgrade/删除Uninstalled时，报告状态变化是否成功 */
void send_client_change_resp(char *old_version, char *new_version, int result, char *operating)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	struct timeval tv = {0};
	char *url = NULL;

	/* 客户端变更日志均用单条发送，防止漏报。单条发送失败，会转为task类批量日志 */
	url = SINGLE_LOG_URL;

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
	event_time = (tv.tv_sec+serv_timeoff) *1000 + (int)tv.tv_usec/1000; //serv_timeoff是客户端与管控端的时间偏差

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientStateChange");
	cJSON_AddStringToObject(object, "log_category", "Client");
	  cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", MY_LOG_KEY);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "timestamp", event_time);

	cJSON_AddCommonHeader(object);

	cJSON_AddStringToObject(arguments, "client_version", new_version);
	cJSON_AddStringToObject(arguments, "client_old_version", old_version);
	cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
	cJSON_AddStringToObject(arguments, "client_process_name", SNIPER_NAME);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	if (post) {
		DBG2(DBGFLAG_POST, "client change post:%s\n", post);
		client_send_msg(post, reply, sizeof(reply), url, "task");
		free(post);
	}

	cJSON_Delete(object);
}

/* 获取升级包下载链接和md5校验值。成功返回0，失败返回-1 */
static int get_update_package_url_md5(char *version, char *url, int url_len, char *md5, int md5_len)
{
	char reply[REPLY_MAX] = {0};
	char query_str[S_LINELEN] = {0};
	char query_url[URL_MAX] = {0};
	cJSON *json, *data, *code, *jmd5, *jurl;

	if (!version || !url || !md5) {
		return -1;
	}

	snprintf(query_url, sizeof(query_url), "api/client/version/%s", version);
	snprintf(query_str, sizeof(query_str), "uuid=%s&os_type=%d", Sys_info.sku, OS_LINUX);

	if (http_get(query_url, query_str, reply, sizeof(reply)) < 0) {
		MON_ERROR("http_get %s fail\n", query_url);
		return -1;
	}

	/* 解析应答包 */
	json = cJSON_Parse(reply);
	if (!json) {
		MON_ERROR("parse newpkg reply %s fail\n", reply);
		return -1;
	}
	code = cJSON_GetObjectItem(json, "code");
	if (!code || code->valueint != 0) {
		MON_ERROR("get code from newpkg reply %s fail\n", reply);
		cJSON_Delete(json);
		return -1;
	}
	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("get data from newpkg reply %s fail\n", reply);
		cJSON_Delete(json);
		return -1;
	}
	jurl = cJSON_GetObjectItem(data, "url");
	if (!jurl) {
		MON_ERROR("get url from newpkg reply %s fail\n", reply);
		cJSON_Delete(json);
		return -1;
	}
	jmd5 = cJSON_GetObjectItem(data, "md5");
	if (!jmd5) {
		MON_ERROR("get md5 from newpkg reply %s fail\n", reply);
		cJSON_Delete(json);
		return -1;
	}

	snprintf(url, url_len, "%s", jurl->valuestring);
	snprintf(md5, md5_len, "%s", jmd5->valuestring);

	cJSON_Delete(json);
	return 0;
}

/* 下载升级包。成功返回0，失败返回-1 */
static int download_update_package(char *version)
{
	int ret = 0;
	FILE *fp = NULL;
	char file_md5[S_MD5LEN] = {0};
	char pkg_md5[S_MD5LEN] = {0};
	char pkg_url[1024] = {0};
	char path[256] = {0};

	/* 获取安装包的下载链接和md5校验值 */
	if (get_update_package_url_md5(version, pkg_url, sizeof(pkg_url), pkg_md5, sizeof(pkg_md5)) < 0) {
		MON_ERROR("get update package download url and md5 fail\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/sniper-linux-%s.bin", WORKDIR, version);
	fp = fopen(path, "w");
	if (!fp) {
		MON_ERROR("create %s fail: %s\n", path, strerror(errno));
		return -1;
	}

	INFO("---download update package: %s---\n", pkg_url);
	ret = download_file(pkg_url, fp);
	fclose(fp);

	if (ret < 0) {
		MON_ERROR("download package %s fail\n", pkg_url);
		return -1;
	}

	if (md5_file(path, file_md5) < 0) { //计算下载的安装包的md5校验值
		MON_ERROR("count %s md5 fail\n", path);
		return -1;
	}

	if (strcmp(pkg_md5, file_md5) != 0) { //校验值不同
		MON_ERROR("package md5 is %s, not %s\n", file_md5, pkg_md5);
		return -1;
	}

	INFO("---package downloaded: %s---\n", path);
	return 0;
}

/*
 * 记录升级的相关信息，用于升级后客户端重启时检查和报告是否升级成功
 * cmd_id和cmd_type为升级任务的id和类型
 */
static void save_update_task_information(char *cmd_id, int cmd_type, char *old_version, char *new_version)
{
	char buf[S_LINELEN] = {0};
	FILE *fp = NULL;

	fp = fopen(UPDATE_TASKINFO, "w");
	if (!fp) {
		MON_ERROR("save_update_task_information fail: %s\n", strerror(errno));
		return;
	}

	snprintf(buf, sizeof(buf), "cmd_id %s cmd_type %d old_version %s new_version %s",
		cmd_id, cmd_type, old_version, new_version);

	if (fwrite(buf, strlen(buf), 1, fp) != 1) {
		MON_ERROR("save_update_task_information fail: %s\n", strerror(errno));
		fclose(fp);
		return;
	}

	INFO("save %s\n", UPDATE_TASKINFO);
	fflush(fp);
	fclose(fp);
}

/* 读取升级前记录的信息。成功返回0，失败返回-1 */
static int get_update_task_information(int *cmd_type, char *id, int id_len,
		char *oldver, int oldver_len, char *newver, int newver_len)
{
	int ret = 0;
	FILE *fp = NULL;
	char cmd_id[64] = {0}, old_version[64] = {0}, new_version[64] = {0};

	if (!cmd_type || !id || !oldver || !newver) {
		return -1;
	}

	fp = fopen(UPDATE_TASKINFO, "r");
	if (!fp) {
		MON_ERROR("open update task information file %s fail: %s\n", UPDATE_TASKINFO, strerror(errno));
		return -1;
	}

	ret = fscanf(fp, "cmd_id %63s cmd_type %d old_version %63s new_version %63s",
			cmd_id, cmd_type, old_version, new_version);
	fclose(fp);

	snprintf(id, id_len, "%s", cmd_id);
	snprintf(oldver, oldver_len, "%s", old_version);
	snprintf(newver, newver_len, "%s", new_version);

	if (ret != 4) {
		MON_ERROR("get update task information from %s fail\n", UPDATE_TASKINFO);
		return -1;
	}

	return 0;
}

/*
 * 创建升级进程来升级。父进程（即老的客户端程序）退出。子进程作为独立进程，进行升级
 * 失败返回-1
 */
static int do_update(char *cmd)
{
	int i = 0;
	pid_t pid = 0;
	char buf[S_LINELEN] = {0};
	FILE *fp = NULL;
	char *ptr = NULL, *pkg = NULL;

	if (!cmd || strncmp(cmd, "sh ", 3) != 0) {
		return -1;
	}
	pkg = cmd + 3;

	pid = fork();
	if (pid < 0) {
		save_sniper_status("sniper update fail\n");
		INFO("Update fail, fork error: %s\n", strerror(errno));
		return -1;
	}

	/* 父进程退出 */
	if (pid > 0) {
		myexit();
	}

	/* 子进程升级 */

	setsid(); //与父进程脱钩

#ifdef USE_AVIRA
	/*
	 * 回收病毒防护功能中加载小红伞引擎的资源
	 * 观察是否对升级时aecore.so引起的core起作用
	 */
	finish_savapi();
#endif

	/* 关闭所有继承自父进程的文件描述符 */
	for (i = 0; i < 1024; i++) {
		close(i);
	}

	sleep(10); //给10秒让父进程工作线程尽量结束，等父进程主动退出

	moni_log_init(&g_moni_log, LOGFILE); //因为关闭了所有文件描述符，需要重新打开antiapt.log

	save_sniper_status("sniper update\n");
	INFO("Sniper Online Updating...\n");
	INFO("To do %s\n", cmd);

	fp = popen(cmd, "r");
	if (fp == NULL) { //升级命令没做起来
		INFO("update fail, do %s fail: %s/n", cmd, strerror(errno));
		exit(errno);
	}

	/* 在antiapt.log里记录升级过程日志 */
	while (fgets(buf, sizeof(buf), fp)) {
		INFO("Update Info: %s", buf);
	}
	pclose(fp);

	/* 从字符串"/opt/snipercli/sniper-linux-W.X.Y.Z.bin update"获取安装包路径*/
	ptr = strchr(pkg, ' ');
	if (ptr) {
		*ptr = 0;
	}
	/* 升级后删除升级包 */
	unlink(pkg);

	exit(0);
}

/*
 * 报告升级结果，要报告2条消息：升级任务应答消息，和客户端状态变化日志
 * 报告后删除级标志文件，避免重复报告
 */
static void report_update_result(char *old_version, char *new_version, task_recv_t *msg, int result)
{
	if (RESULT_OK == result) {
		INFO("Update %s to %s success\n", old_version, new_version);
		send_client_change_resp(old_version, new_version, OPERATE_OK, "Upgrade");
		send_update_client_task_resp(msg, RESULT_OK, old_version, new_version);
	} else {
		MON_ERROR("Update %s to %s fail\n", old_version, new_version);
		send_client_change_resp(old_version, new_version, OPERATE_FAIL, "Upgrade");
		send_update_client_task_resp(msg, RESULT_FAIL, old_version, new_version);
	}
	INFO("unlink %s\n", UPDATE_TASKINFO);
	unlink(UPDATE_TASKINFO);
}

/* task线程收到升级任务时，调用此函数 */
unsigned char update_flag = 0; //多个升级任务共用此全局变量，避免重复升级
void update_client(task_recv_t *msg)
{
	char update_cmd[256] = {0};

	if (msg->new_version == NULL) { //升级任务参数错误
		MON_ERROR("update_client fail, unknown new version\n");
		send_update_client_task_resp(msg, RESULT_FAIL, Sys_info.version, "unknown");
		return;
	}

	if (conf_global.licence_expire || client_disable == TURN_MY_ON) { //如果许可过期了，什么也不做
		INFO("skip update_client, licence expired or client work stoped\n");
		send_update_client_task_resp(msg, RESULT_FAIL, Sys_info.version, msg->new_version);
		return;
	}

	if (strcmp(msg->new_version, Sys_info.version) == 0) { //相同版本不重复升
		INFO("same version %s, skip update_client\n", Sys_info.version);
		send_update_client_task_resp(msg, RESULT_OK, Sys_info.version, msg->new_version);
		return;
	}

	if (update_flag) { //正在升级，不重复升
		INFO("updating, skip new update_client\n");
		send_update_client_task_resp(msg, RESULT_FAIL, Sys_info.version, msg->new_version);
		return;
	}

	/* 设置正在升级的标志，退出前记得要将升级标志重新改为0 */
	update_flag = 1;

	INFO("update from %s to %s\n", Sys_info.version, msg->new_version);

	if (download_update_package(msg->new_version) < 0) { //下载升级包失败
		MON_ERROR("Download update package fail\n");
		send_client_change_resp(Sys_info.version, msg->new_version, OPERATE_FAIL, "Upgrade");
		send_update_client_task_resp(msg, RESULT_FAIL, Sys_info.version, msg->new_version);
		update_flag = 0; //升级失败，清升级标志，使得可以再次接收管控的升级任务
		return;
	}

	INFO("Download update package ok, Start updating...\n");

	/* 记录升级任务信息 */
	save_update_task_information(msg->cmd_id, msg->cmd_type, Sys_info.version, msg->new_version);

	/* 升级 */
	snprintf(update_cmd, sizeof(update_cmd), "sh %s/sniper-linux-%s.bin update", WORKDIR, msg->new_version);
	if (do_update(update_cmd) < 0) {
		report_update_result(Sys_info.version, msg->new_version, msg, RESULT_FAIL);
		update_flag = 0; //升级失败，清升级标志，使得可以再次接收升级任务
	}
}

/* 由新的客户端进程启动后，检查并报告升级结果 */
void check_update_result(int value)
{
	int cmd_type = 0;
	char cmd_id[64] = {0};
	char old_version[64] = {0}, new_version[64] = {0}, version[64] = {0};
	task_recv_t msg;
	FILE *fp = NULL;
	struct stat st = {0};
	time_t now = time(NULL);

	/* 没有升级标志文件，忽略。这通常是客户端未升级，或已经报告过升级状态了 */
	if (access(UPDATE_TASKINFO, F_OK) < 0) {
		return;
	}

	/* 取升级信息失败，无法报告升级状态，只能让管控端超时结束升级任务了 */
	if (get_update_task_information(&cmd_type, cmd_id, sizeof(cmd_id),
					old_version, sizeof(old_version),
					new_version, sizeof(new_version)) < 0) {
		return;
	}
	msg.cmd_type = cmd_type;
	snprintf(msg.cmd_id, sizeof(msg.cmd_id), "%s", cmd_id);

	/* 升级后客户端程序运行起来了 */
	if (value == SNIPER_RUNNING) {
		/* 当前客户端运行的是新版本，报告升级成功 */
		if (strcmp(SNIPER_VERSION, new_version) == 0) {
			report_update_result(old_version, new_version, &msg, RESULT_OK);
			return;
		}

		/* 当前客户端运行的是老版本，报告升级失败 */
		report_update_result(old_version, new_version, &msg, RESULT_FAIL);
		return;
	}

	/* 升级后客户端程序运行失败，报告升级失败 */
	if (value == SNIPER_FAILURE) {
		report_update_result(old_version, new_version, &msg, RESULT_FAIL);
		return;
	}

	/* 老的客户端程序仍在运行，报告升级失败 */

	/* 为避免误报，升级操作3分钟后再确认老的程序是否仍在运行 */
	if (stat(UPDATE_TASKINFO, &st) < 0 || now - st.st_mtime < 180) {
		return;
	}

	fp = fopen(VERSION_FILE, "r");
	if (fp) {
		fscanf(fp, "%*s %63s", version);
		fclose(fp);

		/* 当前客户端运行的是老版本，老的程序仍在运行 */
		if (strcmp(version, old_version) == 0) {
			INFO("Old version %s still running\n", old_version);
			report_update_result(old_version, new_version, &msg, RESULT_FAIL);
			return;
		}
	}

	/* 其他出错的情况（几乎不可能发生），只能让管控端等升级任务超时 */
}
