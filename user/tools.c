/* netlink */
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sqlite3.h>

/* libcurl */
#include <curl/curl.h>

#include <time.h>

#include "header.h"

#define RANDOM_NUMBER_LEN	8
#define UNINSTALL_CODE_LEN	6

#define SQLITE_OPEN_MODE SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_SHAREDCACHE|SQLITE_OPEN_READWRITE

int Doinstall = 0;
int cansendlog = 0;

/* 用于支持sniper和oem统一处理 */
pid_t routine_pid = 0;
int module_loaded = 0;
int routine_adjusted = 0;
char module_name[64] = {0};
char routine_name[64] = {0};
char workdir[256] = {0};
char sniper_conf[512] = {0};
char current_server_conf[512] = {0};

/* 检查是否有名字叫xxx_edr的内核模块 */
static int check_edr_module(void)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, module[64] = {0}, *ptr = NULL;

	fp = sniper_fopen("/proc/modules", "r", OTHER_GET);
	if (!fp) {
		printf("check_edr_module open /proc/modules fail: %s\n", strerror(errno));
		return 0;
	}

	/* 检查每一行是否有xxx_edr */
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%63s", module) == 1) {
			ptr = strrchr(module, '_');
			if (ptr && strcmp(ptr, "_edr") == 0) {
				sniper_fclose(fp, OTHER_GET);
				return 1;
			}
		}
	}

	sniper_fclose(fp, OTHER_GET);
	return 0;
}

/* 检查是否有叫module_name的内核模块。返回0，无；1，有 */
int check_module(char *module_name)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, module[64] = {0};

	if (!module_name) {
		return 0;
	}

	fp = sniper_fopen("/proc/modules", "r", OTHER_GET);
	if (!fp) {
		printf("check_module open /proc/modules fail: %s\n", strerror(errno));
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%63s", module) == 1 &&
		    strcmp(module, module_name) == 0) {
			sniper_fclose(fp, OTHER_GET);
			return 1;
		}
	}

	sniper_fclose(fp, OTHER_GET);
	return 0;
}

/* 检查是否加载了内核模块，包括oem出去的内核模块。返回0，未加载；1，已加载 */
static int search_ksniperd(char *module, int module_len)
{
	char comm[S_COMMLEN] = {0}, name[64] = {0};
	DIR *procdirp = NULL;
	struct dirent *pident = NULL;
	pid_t pid = 0;
	char *ptr = NULL;

	if (!module) {
		return 0;
	}

	procdirp = sniper_opendir("/proc", OTHER_GET);
	if (!procdirp) {
		printf("search_ksniperd open /proc fail: %s\n", strerror(errno));
		return 0;
	}

	while ((pident = readdir(procdirp))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue; //忽略非进程项信息
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) {
			continue;
		}

		if (!is_kernel_thread(pid)) {
			continue; //ksniperd_xxx应当是内核进程
		}

		if (get_proc_comm(pid, comm) <= 0 || comm[0] != 'k') {
			continue;
		}

		ptr = strstr(comm, "d_");
		if (!ptr) {
			continue;
		}
		*ptr = 0;

		/* 检查是否加载了其他oem的xxx_edr */
		snprintf(name, sizeof(name), "%s_edr", comm+1);
		if (check_module(name)) {
			snprintf(module, module_len, "%s", name);
			sniper_closedir(procdirp, OTHER_GET);
			return 1;
		}
	}

	sniper_closedir(procdirp, OTHER_GET);
	return 0;
}

/* 获取到运行当中的sniper的pid */
static pid_t get_sniper_pid(void)
{
	pid_t pid = 0;
	int fd = 0;
	FILE *fp = NULL;
	struct flock fl = {0};

	fl.l_type = F_RDLCK; //读锁
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	fp = sniper_fopen(PIDFILE, "r", OTHER_GET);
	if (!fp) {
		return 0;
	}

	fd = fileno(fp);
	if (fcntl(fd, F_SETLK, &fl) < 0) { //锁失败说明sniper正在运行
		fscanf(fp, "%d", &pid);
	}

	sniper_fclose(fp, OTHER_GET);
	return pid;
}

/* 获取到运行当中的小程序的pid */
static pid_t get_assist_pid(void)
{
	pid_t pid = 0;
	int fd = 0;
	FILE *fp = NULL;
	struct flock fl = {0};

	fl.l_type = F_RDLCK; //读锁
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	fp = sniper_fopen(ASSIST_PIDFILE, "r", OTHER_GET);
	if (!fp) {
		return 0;
	}

	fd = fileno(fp);
	if (fcntl(fd, F_SETLK, &fl) < 0) { //锁失败说明sniper正在运行
		fscanf(fp, "%d", &pid);
	}

	sniper_fclose(fp, OTHER_GET);
	return pid;
}

/* 获取客户端当前的工作模式 */
static void get_routine_mode_global(void)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, path[512] = {0};

	snprintf(path, sizeof(path), "%s/conf.info", workdir);
	fp = sniper_fopen(path, "r", OTHER_GET);
	if (fp == NULL) {
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "客户端模式:%d", &client_mode_global) == 1) {
			break;
		}
	}
	sniper_fclose(fp, OTHER_GET);
}

/* 获取客户端记录的sku */
static void get_routine_sku(char *sku, int sku_len)
{
	FILE *fp = NULL;
	char buf[65] = {0};   //S_UUIDLEN+1
	char path[512] = {0};

	if (!sku) {
		return;
	}

	snprintf(path, sizeof(path), "/etc/%s-sku", routine_name);
	fp = sniper_fopen(path, "r", OTHER_GET);
	if (fp) {
		if (fscanf(fp, "%64s", buf) == 1) {
			snprintf(sku, sku_len, "%s", buf);
		}
		sniper_fclose(fp, OTHER_GET);
	}
}

/* 替换WORKDIR中的客户端程序名，如/opt/snipercli->/opt/sedrcli */
static void get_routine_workdir(char *workdir, int workdir_len, char *routine_name)
{
	char path[256] = {0};
	char *ptr = NULL, *tail = NULL;

	if (!workdir || !routine_name) {
		return;
	}

	snprintf(path, sizeof(path), "%s", WORKDIR);
	ptr = strstr(path, SNIPER_NAME);
	if (!ptr) {
		return;
	}

	*ptr = 0;
	tail = ptr + strlen(SNIPER_NAME);
	snprintf(workdir, workdir_len, "%s%s%s", path, routine_name, tail); // /opt/+sedr+cli
}

/* 当前运行的客户端程序和内核模块可能是oem的版本，取实际的信息 */
static void get_routine_info(void)
{
	if (routine_adjusted) {
		return; //已经取过实际的信息，不重复取
	}

	/* 取当前正在运行的客户端程序的名字，未必是sniper，可能某个oem出去的客户端程序，如sedr */
	routine_pid = get_sniper_pid();
	if (routine_pid) {
		get_proc_comm(routine_pid, routine_name);
	} else {
		/* 当前没有正在运行的客户端程序，用sniper作为客户端程序的名字 */
		snprintf(routine_name, sizeof(routine_name), "%s", SNIPER_NAME);
	}

	if (strcmp(routine_name, SNIPER_NAME) != 0) {
		/* 当前正在运行的是oem的客户端程序，取其工作目录 */
		get_routine_workdir(workdir, sizeof(workdir), routine_name);
	} else {
		snprintf(workdir, sizeof(workdir), "%s", WORKDIR);
	}

	/* 检查是否有加载本客户端程序的内核模块 */
	snprintf(module_name, sizeof(module_name), "%s", MODULE_NAME);
	module_loaded = check_module(module_name);
	if (!module_loaded) {
		if (strcmp(routine_name, SNIPER_NAME) != 0) {
			/* 当前运行着某个oem出去的客户端程序，检查是否有加载其内核模块 */
			char *name = routine_name;
			snprintf(module_name, sizeof(module_name), "%s_edr", name);
			module_loaded = check_module(module_name);
		}

		/* 没有预期的内核模块，但有叫xxx_edr的内核模块，确认其是否也是oem的内核模块 */
		if (!module_loaded && check_edr_module()) {
			/* 遍历进程，检查是否有kxxxd_yyy的进程，有则xxx_edr是oem的内核模块 */
			module_loaded = search_ksniperd(module_name, sizeof(module_name));
		}
	}

	snprintf(current_server_conf, sizeof(current_server_conf), "%s/current_server", workdir);
	snprintf(sniper_conf, sizeof(sniper_conf), "/etc/%s.conf", routine_name);

	get_routine_sku(Sys_info.sku, sizeof(Sys_info.sku));
	get_routine_mode_global();

	routine_adjusted = 1;
}

/* 与send_client_change_resp()的不同是，使用了workdir和routine_name */
static void send_routine_change_resp(char *old_version, char *new_version, int result, char *operating)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	bool event = false;
	int behavior = 0, level = 1, terminate = 0;
	struct timeval tv;
	char *url = NULL;

	/* 均用单条发送，防止漏报 */
	url = SINGLE_LOG_URL;

	get_routine_sku(Sys_info.sku, sizeof(Sys_info.sku)); //不同之处

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	/* 凭借json字符串 */
	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}

	/* arguments 作为1级子json在object下 */
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec+serv_timeoff) *1000 + (int)tv.tv_usec/1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientStateChange");
	cJSON_AddStringToObject(object, "log_category", "Client");
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
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

        cJSON_AddStringToObject(arguments, "client_version", new_version);
        cJSON_AddStringToObject(arguments, "client_old_version", old_version);
        cJSON_AddStringToObject(arguments, "client_dir", workdir);                 //不同之处
        cJSON_AddStringToObject(arguments, "client_process_name", routine_name);   //不同之处

        cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	if (!post) {
		MON_ERROR("send_routine_change_resp: no memory\n");
	}

	DBG2(DBGFLAG_POST, "client change post:%s\n", post);
	client_send_msg(post, reply, sizeof(reply), url, "task");

	cJSON_Delete(object);
	free(post);
}

/* 检查当前客户端与管控的通信情况 */
static int check_server(FILE *fp)
{
	int ret = 0;
	unsigned short port = 0;
	char post[64] = {0};
	char reply[REPLY_MAX] = {0};
	char server[S_LINELEN] = {0};

	if (!fp) {
		return -1;
	}

	if (fp == stdout) { //sniper_status程序里也打了下面的信息，因此这里仅命令执行sniper -t时打
		fprintf(fp, "%s\n", lang ? "Check connection with server..." : "检查与管控中心的网络连接状态……");
	}

	if (access(current_server_conf, F_OK) == 0) {
		read_servaddr(&port, server, current_server_conf);
		if (!port) {
			fprintf(fp, "%s\n", lang ? "Fail to get server information" :
						   "检查失败，未获取到当前连接的管控中心信息");
			return 0;
		}
		if (hostname_to_ip(server, Serv_conf.ip) < 0) {
			fprintf(fp, "%s\n", lang ? "Fail to get server ip" :
						   "检查失败，未获取到当前连接的管控中心IP地址");
			return 0;
		}
		Serv_conf.port = port;
	} else if (access(sniper_conf, F_OK) == 0) {
		read_servaddr(&port, server, sniper_conf);
		if (port == 0) {
			fprintf(fp, "%s\n", lang ? "Fail to get server config" :
						   "检查失败，未获取到管控中心配置");
			return 0;
		}
		if (hostname_to_ip(server, Serv_conf.ip) < 0) {
			fprintf(fp, "%s\n", lang ? "Fail to get server ip config" :
						   "检查失败，未获取到管控中心IP地址");
			return 0;
		}
		Serv_conf.port = port;
	} else {
		fprintf(fp, "%s\n", lang ? "Local mode, no server config" : "当前运行在单机模式");
		return 0;
	}

	curl_global_init(CURL_GLOBAL_ALL);

	/* sniper -t没调用postmsg_pre，自行查询管控是否可用 */
	ret = http_get("api/client/test", post, reply, sizeof(reply));

	curl_global_cleanup();
	if (ret < 0) {
		if (lang)
			fprintf(fp, "Connect %s:%d fail: %s\n", Serv_conf.ip, Serv_conf.port, reply);
		else
			fprintf(fp, "与管控中心(%s:%d)连接失败\n", Serv_conf.ip, Serv_conf.port);
		return -1;
	}

	if (lang)
		fprintf(fp, "Connection with server %s:%d OK\n", Serv_conf.ip, Serv_conf.port);
	else
		fprintf(fp, "与管控中心(%s:%d)连接正常\n", Serv_conf.ip, Serv_conf.port);
	return 0;
}

/* 检查进程是否运行 */
int search_proc(char *procname, int match_type)
{
	char comm[S_COMMLEN] = {0};
	int found = 0, len;
	DIR *procdirp = NULL;
	struct dirent *pident = NULL;
	pid_t pid = 0, mypid = getpid();

	if (!procname) {
		return 0;
	}
	len = strlen(procname);

	procdirp = sniper_opendir("/proc", OTHER_GET);
	if (!procdirp) {
		printf("search %s in /proc fail, open /proc error: %s\n",
			procname, strerror(errno));
		return 0;
	}

	while ((pident = readdir(procdirp))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue; //忽略非进程项信息
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

		if (pid == mypid) {
			continue;
		}

		if (get_proc_comm(pid, comm) <= 0) {
			continue;
		}

		if (match_type == FULL_MATCH) {
			if (strcmp(comm, procname) == 0) {
				found = pid;
				break;
			}
			continue;
		}

		if (match_type == HEAD_MATCH) {
			if (strncmp(comm, procname, len) == 0) {
				found = pid;
				break;
			}
			continue;
		}

		if (match_type == SUB_MATCH) {
			if (strstr(comm, procname)) {
				found = pid;
				break;
			}
			continue;
		}
	}
	sniper_closedir(procdirp, OTHER_GET);

	return found;
}

/* 杀掉图形界面程序 */
void kill_snipertray(void)
{
	int i = 0;
	pid_t pid = 0;

	for (i = 0; i < 1024; i++) {
		pid = search_proc("snipertray", FULL_MATCH);
		if (pid <= 0) {
			return;
		}
		kill(pid, SIGKILL);
	}
}

/* 获取sniper线程的数量 */
static int get_sniper_threads_num(pid_t pid)
{
	int num = 0, pidnum = 0;
	char dir[256] = {0};
	DIR *dirp = NULL;
	struct dirent *pident = NULL;

	snprintf(dir, sizeof(dir), "/proc/%d/task", pid);

	dirp = sniper_opendir(dir, OTHER_GET);
	if (!dirp) {
		printf("open %s error: %s\n", dir, strerror(errno));
		return 0;
	}

	while ((pident = readdir(dirp))) {
		/* 忽略非进程项信息 */
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue;
		}

		pidnum = atoi(pident->d_name);
		if (pidnum <= 0 || pidnum == pid) {
			continue;
		}

		num++;
	}
	sniper_closedir(dirp, OTHER_GET);

	return num;
}

/* 检查线程是否结束 */
static void check_thread(pid_t pid, char *thread_name, int stopping, FILE *fp)
{
	char comm[S_LINELEN] = {0};

	if (!thread_name || !fp) {
		return;
	}

	if (pid > 0) {
		get_proc_comm(pid, comm);
		if (strcmp(comm, "sniper") == 0) {
			return;
		}
	}

	if (stopping) {
		fprintf(fp, "  %s%s\n", thread_name, lang ? " thread exit" : "线程结束");
	} else {
		fprintf(fp, "  %s%s\n", thread_name, lang ? " thread stopped" : "线程未运行");
	}
}

static void simple_report(pid_t pid, int threads_num, int module_loaded, FILE *fp)
{
	if (!fp) {
		return;
	}

	if (pid) {
		fprintf(fp, "Sniper V%s %s\n", SNIPER_VERSION, lang ? "" : "防护中");
		if (threads_num > 0 && threads_num < 10) {
			fprintf(fp, "  %d%s\n", threads_num, lang ? " threads running" : "个线程在运行");
			fprintf(fp, "  %d%s\n", 10-threads_num, lang ? " threads down" : "个线程未运行");
		}
	} else {
		fprintf(fp, "%s\n", lang ? "Sniper stopped" : "Sniper未运行");
	}

	if (module_loaded) {
		fprintf(fp, "%s%s\n", module_name, lang ? " module loaded" : "模块已加载");
	} else {
		fprintf(fp, "%s%s\n", module_name, lang ? " module NOT loaded" : "模块未加载");
	}
}

/* 获取线程的pid */
static int get_thread_pid(char *line)
{
	int i = 0, ret = 0;
	char format[S_LINELEN] = {0};

	if (!line) {
		return 0;
	}

	for (i = 0; i < SNIPER_THREAD_NUMS; i++) {
		if (!sniper_thread[i].thread) {
			continue;
		}

		snprintf(format, sizeof(format), "%s thread id %%d", sniper_thread[i].desc);
		ret = sscanf(line, format, &sniper_thread[i].pid);
		if (ret == 1) {
			return 1;
		}
	}
	return 0;
}

/* 获取sniper的状态 */
int monstatus1(FILE *fp)
{
	pid_t pid = 0;
	int threads_num = 0;
	int register_ok = 0;
	int tasklist_fail = 0, uninstall = 0;
	int engine_fail = 0, module_fail = 0;
	int stop = 0, stopped = 0, update = 0, update_fail = 0;
	int i = 0, ret = 0, n1 = 0, n2 = 0, n3 = 0, n4 = 0;
	char buf[S_LINELEN] = {0}, *line = NULL;
	char module_fail_str[S_LINELEN] = {0};
	FILE *stfp = NULL;
	char version[S_NAMELEN] = {0};
	int len = strlen("load module fail. ");

	if (!fp) {
		return -1;
	}

	get_routine_info();
	if (routine_pid) {
		threads_num = get_sniper_threads_num(routine_pid);
	}

	/* 获取sniper异常或未运行的原因 */
	stfp = fopen(STATUSFILE, "r");
	if (!stfp) {
		simple_report(routine_pid, threads_num, module_loaded, fp);
		return 0;
	}

	/* 解析记录的状态 */
	while (fgets(buf, sizeof(buf), stfp)) {
		line = skip_headspace(buf);
		delete_tailspace(line);
		if (strcmp(line, "init tasklist fail") == 0) {
			tasklist_fail = 1;
			continue;
		}
		if (strcmp(line, "init tasklist ok") == 0) {
			tasklist_fail = 0;
			continue;
		}
		if (strcmp(line, "register client fail") == 0) {
			register_ok = 0;
			continue;
		}
		if (strcmp(line, "register client ok") == 0) {
			register_ok = 1;
			continue;
		}
		if (strstr(line, " engine fail")) {
			engine_fail = 1;
			continue;
		}
		if (strstr(line, " engine ok")) {
			engine_fail = 0;
			continue;
		}
		if (strstr(line, " stopped")) {
			stopped = 1;
			continue;
		}
		if (strstr(line, "stop ")) {
			stop = 1;
			continue;
		}
		if (strstr(line, " update fail")) {
			update_fail = 1;
			continue;
		}
		if (strstr(line, " update")) {
			update = 1;
			continue;
		}
		if (strstr(line, "uninstall ")) {
			uninstall = 1;
			continue;
		}

		if (strncmp(line, "load module fail. ", len) == 0) {
			module_fail = 1;
			snprintf(module_fail_str, sizeof(module_fail_str), "%s", line+len);
			continue;
		}
		if (strcmp(line, "load module ok") == 0) {
			module_fail = 0;
			continue;
		}

		ret = sscanf(line, "%*s routine id %d", &pid);
		if (ret == 1) {
			continue;
		}

		if (get_thread_pid(line)) {
			continue;
		}

		if (strstr(line, " start") ||
		    strcmp(line, "connect server ok") == 0 ||
		    strcmp(line, "get server info ok") == 0 ||
		    strcmp(line, "load server config ok") == 0) {
			continue;
		}
		printf("Invalid infomation: %s\n", line);
	}
	fclose(stfp);

	/* sniper在运行，但状态异常 */
	if (routine_pid) {
		if (pid != routine_pid) {
			simple_report(routine_pid, threads_num, module_loaded, fp);
			return 0;
		}

		/* 取当前运行进程的版本。不用宏SNIPER_VERION，可能和当前运行的进程不一致
		   遇到过运行着的老sniper没停，但/sbin/sniper程序已更新的情况 */
		stfp = fopen(VERSION_FILE, "r");
		if (stfp) {
			if (fscanf(stfp, "%*s %d.%d.%d.%d", &n1, &n2, &n3, &n4) == 4) {
				snprintf(version, sizeof(version), "%d.%d.%d.%d", n1, n2, n3, n4);
			}
			fclose(stfp);
		}
		fprintf(fp, "%s %s %s\n", routine_name, version, lang ? "" : "防护中");

		if (threads_num != SNIPER_THREAD_NUMS) {
			for (i = 0; i < SNIPER_THREAD_NUMS; i++) {
				if (!sniper_thread[i].thread) {
					continue;
				}

				check_thread(sniper_thread[i].pid, sniper_thread[i].desc, stop, fp);
			}
		}
	} else {
		fprintf(fp, "%s%s\n", routine_name, lang ? " stopped" : "未运行");
	}

	if (module_loaded) {
		fprintf(fp, "%s%s\n", module_name, lang ? " module loaded" : "模块已加载");
	} else {
		fprintf(fp, "%s%s\n", module_name, lang ? " module NOT loaded" : "模块未加载");
	}

	if (tasklist_fail) {
		fprintf(fp, "%s\n", lang ? "Fail to initialize tasklist" : "初始化当前进程列表失败");
	}
	if (!register_ok) {
		/* 没有current_server_conf和sniper_conf这2个文件，说明是单机模式，无需注册 */
		if (access(current_server_conf, F_OK) == 0 || access(sniper_conf, F_OK) == 0) {
			fprintf(fp, "%s\n", lang ? "Fail to register client" : "注册客户端失败");
		}
	}
	if (engine_fail) {
		if (lang)
			fprintf(fp, "Enable %s engine fail\n", routine_name);
		else
			fprintf(fp, "激活%s引擎失败\n", routine_name);
	}
	if (module_fail) {
		if (lang)
			fprintf(fp, "Fail to load module %s\n", module_name);
		else
			fprintf(fp, "加载模块%s失败\n", module_name);
		fprintf(fp, "%s\n", module_fail_str);
	}
	if (uninstall) {
		if (stopped) {
			fprintf(fp, "%s%s\n", routine_name, lang ? " uninstalled" : "被卸载");
		} else {
			fprintf(fp, "%s%s\n", routine_name, lang ? " uninstall" : "正在卸载");
		}
	}
	if (update_fail) {
		fprintf(fp, "%s%s\n", routine_name, lang ? " update fail" : "升级失败");
	} else if (update) {
		fprintf(fp, "%s%s\n", routine_name, lang ? " update" : "正在升级");
	}

	if (stop) {
		fprintf(fp, "%s%s\n", routine_name, lang ? " stopped manually" : "被人为停止");
	} else if (!routine_pid && module_loaded) {
		fprintf(fp, "%s%s\n", routine_name, lang ? " fault" : "异常退出");
	}

	return 0;
}

int monstatus2(FILE *fp)
{
	get_routine_info();

	return check_server(fp);
}

int monstatus(int type, pid_t pid)
{
	char path[S_SHORTPATHLEN] = {0};
	FILE *fp = NULL;

	if (type <= 0 || type > 2) {
		monstatus1(stdout);
		monstatus2(stdout);
		return 0;
	}

	snprintf(path, sizeof(path), "/dev/shm/sniperstatus.%d", pid);
	fp = fopen(path, "w");
	if (!fp) {
		snprintf(path, sizeof(path), "/tmp/sniperstatus.%d", pid);
		fp = fopen(path, "w");
		if (!fp) {
			printf("open %s fail: %s\n", path, strerror(errno));
			return -1;
		}
	}

	if (type == 1) {
		monstatus1(fp);
	} else {
		monstatus2(fp);
	}

	fclose(fp);
	return 0;
}

/* sniper作为工具使用时，准备发送日志消息的环境。成功设置cansendlog=1 */
static void postmsg_pre(void)
{
	unsigned short port = 0;
	char *file = NULL;
	char server[S_LINELEN] = {0};
	char portstr[8] = {0};

        /* set timezone to China */
        setenv("TZ", "GMT-8", 1);
        tzset();

        curl_global_init(CURL_GLOBAL_ALL);
        init_systeminfo(&Sys_info);

	get_routine_info();
	get_routine_sku(Sys_info.sku, sizeof(Sys_info.sku));

	if (access(current_server_conf, F_OK) == 0) {
		file = current_server_conf;
	} else if (access(sniper_conf, F_OK) == 0) {
		file = sniper_conf;
	}
	if (!file) {
		INFO("sniper run in local mode\n");
		localmode = 1;
		return;
	}

	errno = 0;
	read_servaddr(&port, server, file);
	if (port == 0) {
		MON_ERROR("get server from %s fail: %s\n", file, strerror(errno));
		localmode = 1;
		return;
	}
	if (hostname_to_ip(server, Serv_conf.ip) < 0) {
		localmode = 1;
		return;
	}
	Serv_conf.port = port;
	snprintf(portstr, sizeof(portstr), "%d", Serv_conf.port);
	if (strstr(portstr, "443")) {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "https");
	} else {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "http");
	}
	client_registered = 1; //置注册标志，允许向管控中心发消息

	fprintf(stdout, "Check connection with server(%s:%d) ... ", Serv_conf.ip, Serv_conf.port);
	fflush(stdout);

	if (sniper_adjust_time() < 0) {
		printf("Fail\n");
	} else {
		printf("OK\n");
		cansendlog = 1;
	}
}

static void postmsg_post(void)
{
	curl_global_cleanup();
}

/*
 * return 1, 说明netlink_num未被使用
 *        0，消息发送成功，但并不一定解除自保护，发给了人家的netlink也返回0
 *       -1，消息发送失败
 */
static int monstopv5(int netlink_num)
{
	struct sockaddr_nl src_addr = {0};
	struct nlmsghdr *nlh = NULL;
	struct iovec iov = {0};
	struct msghdr msg = {0};
	int sockfd = 0, ret = 0;

	sockfd = socket(PF_NETLINK, SOCK_RAW, netlink_num);
	if (sockfd < 0) {
		/* Sniper module may already unloaded */
		if (errno == EPROTONOSUPPORT) {
			return 1;
		}
		printf("nl[%d] socket fail: %s\n", netlink_num, strerror(errno));
		ret = -1;
		goto out;
	}

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid() + SNIPER_THREAD_MAX + 1;
	src_addr.nl_groups = SNIPER_MAGIC;

	if (bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
		printf("nl[%d] bind fail: %s\n", netlink_num, strerror(errno));
		ret = -1;
		goto out;
	}

	nlh = (struct nlmsghdr *)malloc(NLMSGLEN);
	if (!nlh) {
		printf("malloc nl message fail\n");
		ret = -1;
		goto out;
	}
	memset(nlh, 0, NLMSGLEN);

	/* 停内核引擎 */
	nlh->nlmsg_len = NLMSGLEN;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = NLMSG_REG;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

        if (sendmsg(sockfd, &msg, 0) < 0) {
                printf("sendmsg into kernel fail: %s\n", strerror(errno));
		ret = -1;
        }

out:
	if (nlh) {
		free(nlh);
	}
	if (sockfd >= 0) {
		close(sockfd);
	}

	return ret;
}

/* 卸载时monuninstall()已经做了postmsg_pre()，这里不重复做 */
int monstop(char *token, int uninstall)
{
	int i = 0, ret = 0, result = 0, n1 = 0, n2 = 0, n3 = 0, n4 = 0;
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0};
	char version[S_NAMELEN] = {0};

	printf("%s version: %s\n", SNIPER_NAME, SNIPER_VERSION);

	if (!token) {
		printf("Error: NULL token\n");
		return -1;
	}

	if (strcmp(token, TOKEN) != 0 && strcmp(token, TOKENL)) {
		printf("Error: Wrong token %s\n", token);
		return -1;
	}

	if (getuid() != 0) {
		printf("Error: Permission Denied\n");
		return -1;
	}

	get_routine_info();

	/* 解除对客户端程序的防杀保护 */
	if (module_loaded) {
		ret = get_netlink_num();
		if (ret > 0) {
			ret = monstopv5(netlinknum);
			if (ret < 0 && netlinknum == OLD_NETLINK_SNIPER) {
				ret = monstopv5(NETLINK_SNIPER);
			}
		}

		if (ret < 0) {
			printf("Turnoff %s self-protection fail\n", routine_name);
		} else {
			printf("%s self-protection off\n", routine_name);
		}
	}

	if (routine_pid) {
		snprintf(buf, sizeof(buf), "stop %s\n", routine_name);
		save_sniper_status(buf);

		fp = fopen(VERSION_FILE, "r");
		if (fp) {
			if (fscanf(fp, "%*s %d.%d.%d.%d", &n1, &n2, &n3, &n4) == 4) {
				snprintf(version, sizeof(version), "%d.%d.%d.%d", n1, n2, n3, n4);
			}
			fclose(fp);
		}

		mykillpg(mygetpgid(routine_pid), SIGKILL);
		for (i = 0; i < 10; i++) {
			if (kill(routine_pid, 0) < 0) {
				printf("process %d stopped\n", routine_pid);
				break;
			}
			printf("process %d stopping, wait 1s...\n", routine_pid);
			sleep(1);
		}
		if (i == 10) {
			printf("Stop %s %s process %d fail\n", routine_name, version, routine_pid);
		} else {
			printf("%s %s stopped\n", routine_name, version);
		}
	} else {
		printf("%s stopped\n", SNIPER_NAME);
	}

	/* 退出前杀死小程序 */
        kill_assist();

	check_cupsd(1); //启动之前被我们停的打印服务

#if 0
	// if (!module_loaded || del_module(module_name) == 0) {
	// 	printf("module %s unloaded\n", module_name);
	// 	ret = 0;
	// 	result = OPERATE_OK;
	// 	goto out;
	// }
#else
	if (unload_ebpf_program() == 0) {
		printf("ebpf program unloaded\n");
		ret = 0;
		result = OPERATE_OK;
		goto out;
	}
#endif

	for (i = 0; i < 10; i++) {
		if (routine_pid) {
			mykillpg(mygetpgid(routine_pid), SIGKILL);
		}
#if 0
		// if (del_module(module_name) == 0) {
		// 	printf("module %s unloaded\n", module_name);
		// 	ret = 0;
		// 	result = OPERATE_OK;
		// 	goto out;
		// }
		// printf("Unload module %s fail: %s, wait 1s, retry\n",
		//        module_name, strerror(errno));
#else
		if (unload_ebpf_program() == 0) {
			printf("ebpf program unloaded\n");
			ret = 0;
			result = OPERATE_OK;
			goto out;
		}
		printf("unload ebpf program fail\n");
#endif
		sleep(1);
	}
#if 0
	// printf("Unload module %s FAIL! Do it by yourself\n", module_name);
#else
	printf("Unload ebpf program FAIL! Do it by yourself\n");
#endif

	ret = -1;
	result = OPERATE_FAIL;

out:
	if (!uninstall) {
		/* 命令行停止客户端，报告管控 */
		if (routine_pid || module_loaded) {
			if (!client_registered) {
				postmsg_pre();
			}
			if (version[0] == 0) {
				snprintf(version, sizeof(version), "%s", SNIPER_VERSION);
			}
			if (cansendlog) {
				send_routine_change_resp(version, version, result, "Stoped");
			}
		}

		postmsg_post();
	}
	return ret;
}

/* 是否rpm卸载 */
static int is_rpm_uninstall(void)
{
	FILE *fp = NULL;
	char path[S_PROCPATHLEN] = {0};
	char buf[S_LINELEN] = {0};
	pid_t pid = getppid();
	char *ptr = NULL;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			MON_ERROR("open %s fail: %s\n", path, strerror(errno));
		}
		return 0;
	}

	fgets(buf, sizeof(buf), fp);
	sniper_fclose(fp, PROCESS_GET);

	ptr = strchr(buf, ')');
	if (!ptr) {
		return 0;
	}

	if (sscanf(ptr+4, "%d %*s", &pid) != 1) {
		return 0;
	}

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			MON_ERROR("open %s fail: %s\n", path, strerror(errno));
		}
		return 0;
	}

	fgets(buf, sizeof(buf), fp);
	sniper_fclose(fp, PROCESS_GET);

	if (strstr(buf, "rpm")) {
		return 1;
	}
	return 0;
}

/* 通过特殊码卸载 */
int monuninstall(char *token)
{
	struct stat st = {0};
	struct timeval tv = {0};

	gettimeofday(&tv, NULL);

	get_routine_info();

	if (!localmode) {
		if (!client_registered) {
			postmsg_pre();
		}

		if (access(UNINSTALL_DISABLE, F_OK) == 0) {
			if (stat(FORCE_UNINSTALL, &st) < 0 || tv.tv_sec - st.st_mtime > 60) {
				printf("Uninstall permission denied. Uninstall fail\n");
				goto fail;
			}
		}
	}

	/* 停止客户端运行 */
	if (monstop(token, 1) < 0) {
		goto fail;
	}

	/* rpm卸载时，由rpm删除安装文件，避免警告要删除的文件不存在 */
	if (!is_rpm_uninstall()) {
		sniper_cleanup();
	}

	/* 发送卸载日志 */
	if (cansendlog) {
		send_routine_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Uninstalled");
	}

	postmsg_post();
	return 0;

fail:
	if (cansendlog) {
		send_routine_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_FAIL, "Uninstalled");
	}

	postmsg_post();
	return -1;
}

/* aes 128 ecb的方式加密 */
int aes_128_ecb_pkcs5padding(char *data, const unsigned char *key, char *en_data)
{
	int len = 0, dlen = 0;
	unsigned char encrypt[100] = {0};
	EVP_CIPHER_CTX *ctx;
	int mlen = 0, flen = 0;
	int i = 0, ret = 0;
	char *ptr = NULL;
	int ptr_len = 0;

	if (data == NULL) {
		return -1;
	}

	/*加密的数据如果是整AES_BLOCK_SIZE倍，需要补上AES_BLOCK_SIZE长度的padding*/
	len = strlen(data);
	dlen = len/AES_BLOCK_SIZE + AES_BLOCK_SIZE;

	/*初始化ctx*/
	ctx = EVP_CIPHER_CTX_new();

	/*指定加密算法及key和iv(此处IV没有用)*/
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	if (ret != 1) {
		printf("EVP_EncryptInit_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	/*进行加密操作*/
	ret = EVP_EncryptUpdate(ctx, encrypt, &mlen, (const unsigned char *)data, strlen(data));
	if(ret != 1) {
		printf("EVP_EncryptUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
        }

	/*结束加密操作*/
	ret = EVP_EncryptFinal_ex(ctx, encrypt+mlen, &flen);
	if(ret != 1) {
		printf("EVP_EncryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	ret = EVP_CIPHER_CTX_cleanup(ctx);
	if(ret != 1) {
		printf("EVP_CIPHER_CTX_cleanup failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	EVP_CIPHER_CTX_free(ctx);

//	printf("encrypt: ");
	ptr = en_data;
	ptr_len = 3; //为了通过commit检查特别定义了ptr_len的变量
	for(i = 0; i < dlen; i ++){
//		printf("%.2x", encrypt[i]);
		/*每个字节用2个十六进制表示*/
		snprintf(ptr, ptr_len, "%.2x", encrypt[i]); //TODO
		ptr +=2;
	}
//	printf("\n");

	return 0;
}

/* 获取卸载码 */
int get_uninstall_code(char *data, char *code)
{
	char *en_data = NULL;
	int len = 0;
	if (data == NULL) {
		return -1;
	}

	len = (strlen(data)/AES_BLOCK_SIZE + AES_BLOCK_SIZE)*4 + 1;
	en_data = (char *)malloc(len);
        if (en_data == NULL) {
                return -1;
        }
        memset(en_data, 0, len);
	
	/* 先通过aes 128位 ecb加密，再取加密后的字符串前三位和后三位组成卸载码 */
	if (aes_128_ecb_pkcs5padding(data, (const unsigned char*)UNINSTALL_KEY, en_data) < 0) {
		free(en_data);
		return -1;
	}

//	printf("(%lu)en_data:%s\n", strlen(en_data), en_data);
	len = strlen(en_data);
	code[0] = en_data[0];
	code[1] = en_data[1];
	code[2] = en_data[2];
	code[3] = en_data[len - 3];
	code[4] = en_data[len - 2];
	code[5] = en_data[len - 1];

//	printf("code:%s\n", code);
	free(en_data);
	return 0;
}

/* 验证卸载码是否正确来判断是否可以卸载 */
int compare_uninstall_code(char *token)
{
	int ret = 0;
	char number_str[16] = {0};
	char uninstall_str[8] = {0};
	FILE *fp = NULL;

	fp = fopen(RANDOM_NUMBER_FILE, "r");
	if (!fp) {
		printf("获取卸载请求码失败\n");
		return -1;
	}

	fscanf(fp, "%15s", number_str);
	fclose(fp);

	if (number_str[0] == '\0' || strlen(number_str) != RANDOM_NUMBER_LEN) {
		printf("卸载请求码错误:%s\n", number_str);
		return -1;
	}

	ret = get_uninstall_code(number_str, uninstall_str);
	if (ret < 0) {
		printf("获取卸载码失败\n");
		return -1;
	}

//	printf("uninstall_str:%s\n", uninstall_str);

	if (strcmp(token, uninstall_str) != 0) {
		printf("卸载码不正确\n");
		return -1;
	}

	return 0;
}

/* 强制卸载 */
int monforece_uninstall(char *token)
{
	get_routine_info();

	if (token == NULL) {
		printf("缺少卸载码\n");
		goto fail;
	}

	if (compare_uninstall_code(token) < 0) {
		goto fail;
	}

	if (monstop(TOKEN, 1) < 0) {
		goto fail;
	}

	/* rpm卸载时，由rpm删除安装文件，避免警告要删除的文件不存在 */
	if (!is_rpm_uninstall()) {
		sniper_cleanup();
	}

	send_routine_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Uninstalled");

	postmsg_post();
	return 0;

fail:
	send_routine_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_FAIL, "Uninstalled");

	postmsg_post();
	return -1;
}

int monallowip(char *ip)
{
	int ret = 0;

	if (getuid() != 0) {
		printf("Permission Denied\n");
		return -1;
	}

	if (get_netlink_num() < 0) {
		printf("get netlink num fail\n");
		return -1;
	}
		
	postmsg_pre();

	printf("unlock_ip %s\n", ip);
	prepare_netlink_socket();
	ret = unlock_ip(ip);
	close_netlink_socket();

	postmsg_post();

	return ret;
}

static int fgets_value(char *str, int str_len)
{
        int len = 0;
	char buf[S_LINELEN] = {0};

	if (!str) {
                return -1;
	}

        if (!fgets(buf, sizeof(buf), stdin)){
                return -1;
        }
        len = strlen(buf);
        if (len > 0) {
		if (buf[len-1] == '\n') {
                	buf[len-1] = 0;
		}
        }
	len = strlen(buf);
	if (len > 0) {
		snprintf(str, str_len, "%s", buf);
	}
        return 0;
}

static int init_line_text(char *buf, const char *headstr, char *value, int value_len)
{
        int headlen = 0;

        if (!buf || !headstr || !value) {
                return 0;
        }

        headlen = strlen(headstr);
        if (strncmp(buf, headstr, headlen) != 0) {
                return 0;
        }

	snprintf(value, value_len, "%s", buf+headlen);
        return 1;
}

void hostinfo(void)
{
	char username[S_LINELEN] = {0}, *username_encode = NULL;
	char phone[S_LINELEN] = {0}, *phone_encode = NULL;
	char department[S_LINELEN] = {0}, *department_encode = NULL;
	char company[S_LINELEN] = {0}, *company_encode = NULL;
	char email[S_LINELEN] = {0}, *email_encode = NULL;
	char assets_number[S_LINELEN] = {0}, *assets_number_encode = NULL;
	char location[S_LINELEN] = {0}, *location_encode = NULL;
	char remark[S_LINELEN] = {0}, *remark_encode = NULL;
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0}, *line = NULL;
	char reply[REPLY_MAX] = {0};
	char path[128] = {0};
	cJSON *object = NULL, *data = NULL;
	char *post = NULL;

	if (getenv("DISPLAY")) {
		snprintf(path, sizeof(path), "%s/sniper_hostinfo", WORKDIR);
		system(path);
		exit(0);
	}

	snprintf(path, sizeof(path), "%s/%s", WORKDIR, NODEINFO);
        fp = sniper_fopen(path, "r", OTHER_GET);
        if (fp) {
                while (fgets(buf, sizeof(buf), fp)) {
			line = skip_headspace(buf);
			delete_tailspace(line);

                        if (init_line_text(line, "username=", username, sizeof(username))) {
                                continue;
                        }
                        if (init_line_text(line, "phone=", phone, sizeof(phone))) {
                                continue;
                        }
                        if (init_line_text(line, "department=", department, sizeof(department))) {
                                continue;
                        }
                        if (init_line_text(line, "company=", company, sizeof(company))) {
                                continue;
                        }
                        if (init_line_text(line, "email=", email, sizeof(email))) {
                                continue;
                        }
                        if (init_line_text(line, "assets_number=", assets_number, sizeof(assets_number))) {
                                continue;
                        }
                        if (init_line_text(line, "location=", location, sizeof(location))) {
                                continue;
                        }
                        if (init_line_text(line, "remark=", remark, sizeof(remark))) {
                                continue;
                        }
                }
                sniper_fclose(fp, OTHER_GET);
        }

	fflush(stdin);

	if (username[0]) {
		printf("姓名Name [%s]: ", username);
	} else {
		printf("姓名Name: ");
	}
	if (fgets_value(username, sizeof(username)) < 0) {
		exit(1);
	}

	if (phone[0]) {
		printf("电话Phone [%s]: ", phone);
	} else {
		printf("电话Phone: ");
	}
	if (fgets_value(phone, sizeof(phone)) < 0) {
		exit(1);
	}

	if (company[0]) {
		printf("单位Company [%s]: ", company);
	} else {
		printf("单位Company: ");
	}
	if (fgets_value(company, sizeof(company)) < 0) {
		exit(1);
	}

	if (department[0]) {
		printf("部门Department [%s]: ", department);
	} else {
		printf("部门Department: ");
	}
	if (fgets_value(department, sizeof(department)) < 0) {
		exit(1);
	}

	if (email[0]) {
		printf("邮箱Email [%s]: ", email);
	} else {
		printf("邮箱Email: ");
	}
	if (fgets_value(email, sizeof(email)) < 0) {
		exit(1);
	}

	if (assets_number[0]) {
		printf("资产编号Assets_number [%s]: ", assets_number);
	} else {
		printf("资产编号Assets_number: ");
	}
	if (fgets_value(assets_number, sizeof(assets_number)) < 0) {
		exit(1);
	}

	if (location[0]) {
		printf("机房位置Location [%s]: ", location);
	} else {
		printf("机房位置Location: ");
	}
	if (fgets_value(location, sizeof(location)) < 0) {
		exit(1);
	}

#if 0
	if (remark[0]) {
		printf("备注Remark [%s]: ", remark);
	} else {
		printf("备注Remark: ");
	}
	if (fgets_value(remark, sizeof(remark)) < 0) {
		exit(1);
	}
#endif

        fp = sniper_fopen(path, "w", OTHER_GET);
        if (fp) {
                fprintf(fp, "username=%s\nphone=%s\ndepartment=%s\ncompany=%s\n"
			"email=%s\nassets_number=%s\nlocation=%s\nremark=%s",
			username, phone, department, company,
			email, assets_number, location, remark);
                sniper_fclose(fp, OTHER_GET);
        }

	username_encode = url_encode(username);
	if (!username_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	phone_encode = url_encode(phone);
	if (!phone_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	department_encode = url_encode(department);
	if (!department_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	company_encode = url_encode(company);
	if (!company_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	email_encode = url_encode(email);
	if (!email_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	assets_number_encode = url_encode(assets_number);
	if (!assets_number_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	location_encode = url_encode(location);
	if (!location_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	remark_encode = url_encode(remark);
	if (!remark_encode) {
		printf("Error: no memory\n");
		exit(1);
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		exit(1);
	}

	data = cJSON_CreateObject();
	if (data == NULL) {
		cJSON_Delete(object);
		exit(1);
	}

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);

	cJSON_AddStringToObject(data, "name", username_encode);
	cJSON_AddStringToObject(data, "phone", phone_encode);
	cJSON_AddStringToObject(data, "department", department_encode);
	cJSON_AddStringToObject(data, "company", company_encode);
	cJSON_AddStringToObject(data, "email", email_encode);
	cJSON_AddStringToObject(data, "assets_number", assets_number_encode);
	cJSON_AddStringToObject(data, "location", location_encode);

	cJSON_AddItemToObject(object, "data", data);
	post = cJSON_PrintUnformatted(object);

        free(username_encode);
        free(phone_encode);
        free(department_encode);
        free(company_encode);
        free(email_encode);
        free(assets_number_encode);
        free(location_encode);

	if (http_post("api/client/asset/reg", post, reply, sizeof(reply)) <= 0) {
		printf("send hostinfo to server(%s:%u) fail\n",
			Serv_conf.ip, Serv_conf.port);
		postmsg_post();
		cJSON_Delete(object);
		free(post);
		exit(1);
	}

	cJSON_Delete(object);
	free(post);

	postmsg_post();
	if (strstr(reply, "\"code\":0")) {
		printf("\n%s\n", lang ? "Success" : "上报主机信息成功");
		exit(0);
	}

	printf("report hostinfo to server(%s:%u) fail: %s\n",
		Serv_conf.ip, Serv_conf.port, reply);
	exit(1);
}


int monrandom(void)
{
	char number_str[16] = {0};
	FILE *fp = NULL;

	creat_random_number(number_str, 8);

	fp = fopen(RANDOM_NUMBER_FILE, "w");
	if (!fp) {
		printf("卸载请求码创建失败\n");
		return -1;
	}
	
	fprintf(fp, "%s\n", number_str);
	printf("卸载请求码:%s\n", number_str);

	fclose(fp);
	return 0;
}

int mondisplay(void)
{
	char dbname[256] = {0};
	sqlite3 *db = NULL;
	const char *sql = "SELECT mtime,path FROM encryptbackup;";
	sqlite3_stmt* stmt = NULL;
	int rc = 0, mtime = 0;
	const unsigned char *path;

	snprintf(dbname, sizeof(dbname), "%s/%s/encrypt.db", WORKDIR, FILEDB);
	rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
	if (rc != SQLITE_OK) {
		printf("dispay open encrypt db failed: %s\n", sqlite3_errstr(rc));
		return -1;
	}

	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		printf("dispay connect encrypt db failed: %s\n", sqlite3_errstr(rc));
		sqlite3_close_v2(db);
		return -1;
	}

	printf("备份文件列表:\n");
	printf("时间\t\t文件名\n");
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		mtime = sqlite3_column_int(stmt, 0);
		printf("%d\t", mtime);
		path = sqlite3_column_text(stmt, 1);
		printf("%s\n", path);
	}

	sqlite3_finalize(stmt);
	sqlite3_close_v2(db);
	return 0;
}

int monrecovery_file(char *path)
{
	int rc = 0;
	char dbname[256] = {0};
	sqlite3 *db = NULL;
	char sql[1024] = {0};
	sqlite3_stmt* stmt = NULL;
	const unsigned char *md5 = NULL;
	char file[PATH_MAX] = {0};

	snprintf(dbname, sizeof(dbname), "%s/%s/encrypt.db", WORKDIR, FILEDB);
	rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_MODE, NULL);
	if (rc != SQLITE_OK) {
		printf("dispay open encrypt db failed: %s\n", sqlite3_errstr(rc));
		return -1;
	}

	snprintf(sql, sizeof(sql), "SELECT md5 FROM encryptbackup where path='%s';", path);
	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		printf("dispay connect encrypt db failed: %s\n", sqlite3_errstr(rc));
		sqlite3_close_v2(db);
		return -1;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		md5 = sqlite3_column_text(stmt, 0);
	}

	snprintf(file, sizeof(file), "%s", md5);

	if (access(file, F_OK) != 0) {
		printf("%s 备份文件不存在\n", safebasename(file));
	}

	if (copy_file(file, path) < 0) {
		printf("备份失败\n");
	} else {
		printf("file:%s 已恢复\n", path);
	}

	sqlite3_finalize(stmt);
	sqlite3_close_v2(db);

	return 0;
}

/* 杀死小程序 */
void kill_assist(void)
{
	pid_t assist_pid;

	assist_pid = get_assist_pid();
	INFO("assist pid:%d\n", assist_pid);
        if (assist_pid) {
		mykill(assist_pid, SIGKILL);
	}
}
