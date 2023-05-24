#include "header.h"

char *nullstr = "";
// sniper内存使用计数 ------>
/* 计算大小，不足16个字节的，补足16个字节 */
int round_size(int size)
{
	int left = size % 16;

	if (left == 0) {
		return size;
	}

	return (size + 16 - left);
}

unsigned long snipermem[GETTYPE_MAX] = {0};

/* sniper malloc调用封装 */
void *sniper_malloc(int size, int gettype)
{
	/* 大小取16的整数倍 */
	int real_size = round_size(size);
	char *buf = NULL;

	buf = malloc(real_size);
	if (!buf) {
		return NULL;
	}
	memset(buf, 0, real_size);

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		snipermem[gettype] += real_size;
	} else {
		snipermem[GETTYPE_MIN] += real_size;
	}

	return buf;
}

/* sniper free调用封装 */
void do_sniper_free(void *buf, int size, int gettype)
{

	/* 大小取16的整数倍 */
	int real_size = round_size(size);

	if (!buf) {
		return;
	}

	/* 不安全，不要画蛇添足，如果size给错了，就会写越界 */
	//memset(buf, 0, real_size);

	free(buf);

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		snipermem[gettype] -= real_size;
	} else {
		snipermem[GETTYPE_MIN] -= real_size;
	}
}
// <------ sniper内存使用计数

// sniper打开文件计数 ------>
static unsigned long sniperfd[GETTYPE_MAX] = {0};

/* sniper open调用封装 */
int sniper_open(char *path, int flags, int gettype)
{
	int fd = 0;

	if (!path) {
		return -1;
	}

	fd = open(path, flags);
	if (fd < 0) {
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fd;
}

/* sniper close调用封装 */
int sniper_close(int fd, int gettype)
{
	int ret = 0;

	if (fd < 0) {
		return -1;
	}

	ret = close(fd);
	if (ret != 0) {
		MON_ERROR("close fd(%d) fail: %s\n", fd, strerror(errno));
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] --;
	} else {
		sniperfd[GETTYPE_MIN] --;
	}

	return 0;
}

/* sniper fopen调用封装 */
FILE *sniper_fopen(char *path, char *mode, int gettype)
{
	FILE *fp = NULL;

	if (!path || !mode) {
		return NULL;
	}

	fp = fopen(path, mode);
	if (!fp) {
		return NULL;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fp;
}

/* sniper fclose调用封装 */
int sniper_fclose(FILE *fp, int gettype)
{
	int ret = 0;

	if (!fp) {
		return -1;
	}

	ret = fclose(fp);
	if (ret != 0) {
		MON_ERROR("fclose fp(%#x) fail: %s\n", fp, strerror(errno));
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] --;
	} else {
		sniperfd[GETTYPE_MIN] --;
	}

	return 0;
}

/* 打印 fd计数情况 */
void dump_sniperfd(void)
{
	int i = 0, fdsum = 0;

	for (i = GETTYPE_MIN; i < GETTYPE_MAX; i++) {
		fdsum += sniperfd[i];
	}

	if (fdsum < 100) {
		return;
	}

	INFO("open files: scan:%d, info:%d, policy:%d, other:%d\n",
	     sniperfd[SCAN_GET], sniperfd[INFO_GET], sniperfd[POLICY_GET],
	     sniperfd[GETTYPE_MIN]);
}

/* sniper opendir调用封装 */
DIR *sniper_opendir(char *path, int gettype)
{
	DIR *dirp = NULL;

	if (!path) {
		return NULL;
	}

	dirp = opendir(path);
	if (!dirp) {
		return NULL;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return dirp;
}

/* sniper closedir调用封装 */
int sniper_closedir(DIR *dirp, int gettype)
{
	int ret = 0;

	if (!dirp) {
		return -1;
	}

	ret = closedir(dirp);
	if (ret != 0) {
		MON_ERROR("close dirp(%#x) fail: %s\n", dirp, strerror(errno));
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] --;
	} else {
		sniperfd[GETTYPE_MIN] --;
	}

	return 0;
}
// <------ sniper打开文件计数

/*
 *用于消除编译警告
 *把path拼入post消息时，由于path和post的最大长度都是4096，故警告path加上其他字符
 *可能会超过post的最大长度，把path最后拼入post，并用thestring(path)忽略此警告
 */
char *thestring(char *str)
{
	return str;
}

/* 获取随机的uuid字符串 */
void get_random_uuid(char *uuid, int uuid_len)
{
	FILE *fp = NULL;

	if (uuid == NULL) {
		return;
	}

	/* 通过系统文件获取随机字符串 */
	fp = sniper_fopen("/proc/sys/kernel/random/uuid", "r", INFO_GET);
	if (!fp) {
		return;
	}

	fgets(uuid, uuid_len, fp);
	/* 清除头部空格 */
	delete_tailspace(uuid);
	sniper_fclose(fp, INFO_GET);
}

/* 获取文件名 */
char *safebasename(char *path)
{
	char *baseptr = NULL;

	if (path == NULL) {
		return nullstr;
	}

	/* 不是以/或.开头的，basename即path，如events/0核心线程 */
	if (path[0] != '/' && path[0] != '.') {
		return path;
	}

	baseptr = strrchr(path, '/');
	if (baseptr) {
		return baseptr+1;
	}

	return path;
}

/* 获取目录名 */
void safedirname(char *path, char *dir, int dir_len)
{
	char *baseptr;
	int pathlen = 0;
	int baselen = 0;
	int len = 0;

	if (path == NULL) {
		 return;
	}

	pathlen = strlen(path);
	snprintf(dir, dir_len, "%s", path);

	baseptr = strrchr(path, '/');
	if (baseptr) {
		baselen = strlen(baseptr);
		len = pathlen-baselen+1;
		dir[len] = '\0';
		return;
	}

	return;
}

/* 消除头部的空格符 */
char *skip_headspace(char *str)
{
	char *ptr = str;

	while (isspace(*ptr)) {
		ptr++;
	}
	return ptr;
}

/* 消除尾部的空格符、回车和换行符 */
void delete_tailspace(char *str)
{
	int i = 0, len = strlen(str);

	for (i = len-1; i >= 0; i--) {
		if (!isspace(str[i])) {
			return;
		}
		str[i] = 0;
	}
}

/* 判断扫描查杀程序是否运行 */
int is_this_running(uid_t uid)
{
	char pidfile[1024] = {0};
	char buf[32] = {0};
	int pid_fd = 0;
	int len = 0;
	struct flock fl;
	FILE *fp = NULL;
	pid_t pid = getpid();

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	snprintf(pidfile, sizeof(pidfile), "%s/%s.%u", ANTIVIRUS_PIDDIR, ANTIVIRUS_PIDFILE, uid);
	pid_fd = open(pidfile, O_RDWR|O_CREAT, 0644);
	if (pid_fd < 0) {
		/* error */
		fprintf(stderr, "Open %s fail: %s\n", pidfile, strerror(errno));
		fp = fopen("/tmp/sniper_antivirus.error", "a");
		chmod("/tmp/sniper_antivirus.error", 0777);
		if (fp) {
			fprintf(fp, "process %d Open %s fail: %s\n",
				pid, pidfile, strerror(errno));
			fclose(fp);
		}
		return -1;
	}

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		/* lock file failed means another is running */
		fprintf(stderr, "sniper_antivirus already running\n");
		close(pid_fd);
		return 1;
	}

	len = snprintf(buf, sizeof(buf), "%d", pid);

	if (write(pid_fd, buf, len+1) < 0) {
		fp = fopen("/tmp/sniper_antivirus.error", "a");
		chmod("/tmp/sniper_antivirus.error", 0777);
		fprintf(stderr, "Write %s fail: %s\n", pidfile, strerror(errno));
		if (fp) {
			fprintf(fp, "process %d Write %s fail: %s\n",
				pid, pidfile, strerror(errno));
			fclose(fp);
		}
		return -1;
	}

	return 0;
}

/* 按照规定格式获取时间的输出 */
void get_time_string(int mtime, char *timestr, int timestr_len)
{
	struct tm now = {0};
	time_t t;

	t = (time_t)mtime;
	localtime_r(&t, &now);

	/* 例如 2022.08.03 17:22 */
	snprintf(timestr, timestr_len, "%04d.%02d.%02d %02d:%02d",
			now.tm_year+1900, now.tm_mon+1, now.tm_mday,
			now.tm_hour, now.tm_min);
	return;
}

/* 获取日志的名称 */
void get_log_name(char *name, int name_len)
{
	struct timeval tv = {0};

	gettimeofday(&tv, NULL);

	snprintf(name, name_len, "/tmp/antivirus-%lu.log",
			tv.tv_sec);
	return;
}

/* 获取输入的结果存放在input中,input为len长度的字符数组, len必须大于等于3, output为提示的信息输出 */
void get_input_result(char *output, char *input, int len)
{
	int i = 0;

	if (!output || !input || len < 3) {
		return;
	}

	while(1) {

		/* 只用到input前两个字符，防止代码错误原因导致越界 */
		if (i >= 2) {
			break;
		}

		scanf("%c", &input[i]);

		/*
		 * 输入收到回车时判断三种情况
		 * 1.第一个字符收到回车,按同意处理
		 * 2.第一个字符为y/Y,第二个字符为回车,按同意处理;第一个字符为n/N,第二个字符为回车,按不同意处理
		 * 3.收到预期以外的字符，遇到第一个回车，清空字符串，重新接受输入
		 */
		if (input[i] == 10) {
			if (i == 0 || ((i == 1) && (input[0] == 'y' || input[0] == 'Y' || input[0] == 'n' || input[0] == 'N'))) {
				break;
			} else {
				printf("unrecognized input, please try again\n");
				memset(input, 0, len);
				i = 0;
				printf("%s", output);
				continue;
			}
		}

		/* 第二个字符如果不符合预期，重置第一个字符为a，再次获取的字符还是放在第二个字符内，直到遇到回车 */
		if (i == 0) {
			i++;
		} else if (input[i] != 'y' && input[i] != 'Y' && input[i] != 'n' && input[i] != 'N') {
			input[0] = 'a';
		}
	}
}

/* 比较管控时间后获取时间差 */
int check_server_time(int time_sec)
{
	long int offset = 0;
	time_t now = 0;

	now = time(NULL);

	if (time_sec <= 0) {
		return -1;
	}

	offset = time_sec - now;

	/* 一分钟内的时间偏差不调整 */
	if (offset > MIN_SERV_TIMEOFF ||
	    offset < -MIN_SERV_TIMEOFF) {
		serv_timeoff = offset;
	} else {
		serv_timeoff = 0;
	}
	MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "serv_timeoff: %ld\n", serv_timeoff);

	return 0;
}

/* 获取管控的时间,并修正客户端的时间差 */
int adjust_client_time(char* string)
{
	cJSON *json, *data, *server_time;
	int time_sec = 0;

	json = cJSON_Parse(string);
	if (!json) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "parse heartbeat reply fail: %s\n", cJSON_GetErrorPtr());
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "heartbeat reply get data error: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(json);
		return -1;
	}

	server_time = cJSON_GetObjectItem(data, "server_time");
	if (!server_time) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "heartbeat reply get server_time error: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(json);
		return -1;
	}

	time_sec = server_time->valueint;
	check_server_time(time_sec);

	cJSON_Delete(json);
	return 0;
}

/* 客户端修正时间 */
int sniper_adjust_time(void)
{
	int ret = 0;
	char *post = NULL;
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL;

	/* 拼接json字符串，只有uuid一个成员 */
	object = cJSON_CreateObject();
	if (!object) {
		return -1;
	}

	cJSON_AddStringToObject(object, "uuid", host_sku);
	post = cJSON_PrintUnformatted(object);
	if (!post) {
		cJSON_Delete(object);
		return -1;
	}

	/* 心跳的返回数据中包含管控时间 */
	if (http_post("api/client/heartbeat", post, reply) <= 0) {
		cJSON_Delete(object);
		free(post);
		return -1;
	}

	ret = adjust_client_time(reply);

	cJSON_Delete(object);
	free(post);

	return ret;
}

/* 计算目录空间的大小,单位是字节 */
unsigned long get_dir_size(char *dir)
{
	DIR *dirp = NULL;
	struct dirent *fdent = NULL;
	struct stat st = {0};
	char path[PATH_MAX] = {0};
	unsigned long child_dirsize = 0;
	unsigned long dirsize = 0;

	if (!dir) {
		return 0;
	}

	dirp = sniper_opendir(dir, SCAN_GET);
	if (dirp == NULL) {
		DBG2(DBGFLAG_ANTIVIRUS_SCAN, "open path %s failed!:%s\n", path, strerror(errno));
		return 0;
	}

	while ((fdent = readdir(dirp)) != NULL) {
		/* 排除 .和..两种情况 */
		if (strcmp(fdent->d_name, ".") == 0 ||
		    strcmp(fdent->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir, fdent->d_name);
		if (lstat(path, &st) < 0) {
			DBG2(DBGFLAG_ANTIVIRUS_SCAN, "lstat path %s failed!:%s\n", path, strerror(errno));
			continue;
		}

		/* 如果子文件是目录，继续递归计算 */
		if (S_ISDIR(st.st_mode)) {
			child_dirsize = get_dir_size(path);
			if(child_dirsize == 0) {
				continue;
			}
			dirsize += child_dirsize;
		} else {
			dirsize += st.st_size;
		}

	}
	sniper_closedir(dirp, SCAN_GET);

	return dirsize;
}

/* 计算路径所在分区的剩余空间大小,单位是字节 */
unsigned long get_path_disk_size(char *path)
{
	unsigned long free = 0;
	struct statfs stat;

	memset(&stat, 0, sizeof(struct statfs));
	if (statfs(path, &stat) < 0) {
		return 0;
	}

	free = (unsigned long)stat.f_bsize * (unsigned long)stat.f_bfree;
	return free;
}
