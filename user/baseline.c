#include <pcre.h>
#include <regex.h>
#include <strings.h>

#include "header.h"

#define OVECCOUNT 30

#define MaxLength 1024
#define MaxParaLength 256

#define CMD_SIZE_MAX 256

#define SNIPER_EQUAL 1
#define SNIPER_LARGE 2
#define SNIPER_LITTLE 3
#define SNIPER_LARGE_EQUAL 4
#define SNIPER_LITTLE_EQUAL 5

int base_stop = 0;
int some_resault[64] = {0};
pid_t nginx_pid = 0, apache_pid = 0, tomcat_pid = 0, mysql_pid = 0, solr_pid = 0;
char tomcat_path[S_LINELEN] = {0}, nginx_path[S_LINELEN] = {0};
int tomcat_version_five = 0, tomcat_version_other = 0;

static app_module baseline_app_info[] = {
    {&tomcat_pid, "java", "tomcat"},
    {&nginx_pid, "nginx", "nginx"},
    {&apache_pid, "httpd", "httpd"},
    {&apache_pid, "apache2", "apache2"},
    {0, NULL, NULL}};

/* 取nginx配置文件 */
void nginx_conf_path(pid_t pid)
{
	char *set = NULL, *ptr = NULL;
	char cmdline[4096] = {0};

	if (pid <= 0) {
		return;
	}

	if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	/* 解析命令行中的配置文件 */
	set = strstr(cmdline, " -c ");
	if (set) {
		ptr = skip_headspace(set + 4);
		snprintf(nginx_path, sizeof(nginx_path), "%s", ptr);
		ptr = strchr(nginx_path, ' ');
		if (ptr) {
			*ptr = 0;  // 去掉命令行中配置文件之后的内容
		}

		if (access(nginx_path, F_OK) == 0) {
			INFO("nginx conf file %s\n", nginx_path);
			return;
		}
		INFO("nginx conf file %s from cmdline %s not exist, try default value\n", nginx_path, cmdline);
	}

	/* 如果命令行未指定配置文件，用默认值 */
	if (access("/etc/nginx/nginx.conf", F_OK) == 0) {
		snprintf(nginx_path, sizeof(nginx_path), "/etc/nginx/nginx.conf");
	} else if (access("/usr/local/nginx/conf/nginx.conf", F_OK) == 0) {
		snprintf(nginx_path, sizeof(nginx_path), "/usr/local/nginx/conf/nginx.conf");
	} else if (access("/opt/nginx/conf/nginx.conf", F_OK) == 0) {
		snprintf(nginx_path, sizeof(nginx_path), "/opt/nginx/conf/nginx.conf");
	}

	if (nginx_path[0] == 0) {
		INFO("NO nginx conf file\n");
		return;
	}
	INFO("nginx conf file: %s\n", nginx_path);
}

/* 取tomcat配置目录 */
void tomcat_conf_path(pid_t pid)
{
	char *set = NULL, *ptr = NULL;
	char cmdline[4096] = {0};

	if (pid <= 0) {
		return;
	}

	if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	// TODO 从命令行参数logging.config.file中取，不可靠
	set = strstr(cmdline, "logging.config.file=");
	if (!set) {
		INFO("NO tomcat conf file\n");
		return;
	}

	set += strlen("logging.config.file=");

	ptr = strstr(set, "/log");
	if (!ptr) {
		INFO("NO tomcat conf file\n");
		return;
	}

	*(ptr + 1) = 0;
	snprintf(tomcat_path, sizeof(tomcat_path), "%s", set);
	INFO("tomcat conf dir: %s\n", tomcat_path);
}

static int check_type_classify(cJSON *string_to_json);

/*
 * 匹配正则表达式
 * 编译正则表达式 regcomp()
 * 匹配正则表达式 regexec()
 * 释放正则表达式 regfree()
 */
int regular_match(char *bematch, char *pattern)
{
	pcre *re;
	const char *error;
	int erroffset;
	int ovector[OVECCOUNT];
	int rc;

	re = pcre_compile(pattern, PCRE_CASELESS | PCRE_MULTILINE, &error, &erroffset, NULL);
	if (re == NULL) {
		MON_ERROR("compile failed at offset %d: %s\n", erroffset, error);
		return -1;
	}

	rc = pcre_exec(re, NULL, bematch, strlen(bematch), 0, 0, ovector, OVECCOUNT);
	if (rc < 0) {
		free(re);
		return SNIPER_RISK;
	} else {
		return SNIPER_NORISK;
	}
}

/* 判断文件中某个参数是否存在 */
/* 存在且规则中给的present为true返回SNIPER_NORISK */
/* 不存在且规则中给的present为false返回SNIPER_RISK */
/* 反之同理 */
static int linux_file_string_presence(cJSON *params)
{
	FILE *fp = NULL;
	char p[MaxLength] = {0};
	char *path = NULL, *parameterName = NULL;
	int res = 1, present = 0;

	path = cJSON_GetObjectItem(params, "file")->valuestring;
	parameterName = cJSON_GetObjectItem(params, "patterns")->valuestring;
	present = cJSON_GetObjectItem(params, "present")->valueint;

	fp = fopen(path, "rb");
	if (fp == NULL) {
		DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, path, strerror(errno));
		return SNIPER_RISK;
	}
	// printf("%s\n", parameterName);
	while ((fgets(p, sizeof(p), fp)) != NULL) {
		res = regular_match(p, parameterName);

		if (res && present)  // 匹配到了并且present为true
		{
			fclose(fp);
			return SNIPER_NORISK;
		}
		if (res && !present)  // 匹配到了并且present为false
		{
			fclose(fp);
			return SNIPER_RISK;
		}
	}

	if (!res && (present == 0))  // 没有匹配到并且present为false
	{
		fclose(fp);
		return SNIPER_NORISK;
	}
	fclose(fp);
	return SNIPER_RISK;
}

/* 检查是否有某个参数，且参数的数值满足条件 */
/* 匹配返回SNIPER_NORISK，不匹配返回SNIPER_RISK */
static int configuration_file_setting(cJSON *params)
{
	char *path = NULL, *comment = NULL, *condition = NULL, *check_key = NULL;
	char line[S_LINELEN] = {0}, *ptr = NULL, *str = NULL, *key = NULL;
	int value = 0, check_value = 0, ret = 0, operator= 0;
	FILE *fp = NULL;
	char *trans = NULL;
	int len = 0;
	char string_value[S_LINELEN] = {0};

	path = cJSON_GetObjectItem(params, "config_file_path")->valuestring;
	comment = cJSON_GetObjectItem(params, "comment_character")->valuestring;
	condition = cJSON_GetObjectItem(params, "desired_value")->valuestring;
	check_key = cJSON_GetObjectItem(params, "config_item")->valuestring;

	if (!path || !comment || !condition || !check_key) {
		str = cJSON_PrintUnformatted(params);
		DBG2(DBGFLAG_BASELINE, "%s: missing condition: %s\n", __FUNCTION__, str);
		free(str);
		return SNIPER_RISK;
	}

	if (strchr(condition, '>')) {
		if (strchr(condition, '=')) {
			operator= SNIPER_LARGE_EQUAL;
		} else {
			operator= SNIPER_LARGE;
		}
	} else if (strchr(condition, '<')) {
		if (strchr(condition, '=')) {
			operator= SNIPER_LITTLE_EQUAL;
		} else {
			operator= SNIPER_LITTLE;
		}
	}

	if (!operator) {
		fp = fopen(path, "rb");
		if (fp == NULL) {
			DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, path, strerror(errno));
			return SNIPER_RISK;
		}

		while (fgets(line, sizeof(line), fp)) {
			ptr = skip_headspace(line);

			/* 忽略注释行 */
			if (*ptr == *comment || *ptr == '#') {
				continue;
			}

			if (!strstr(ptr, check_key)) {
				continue;
			}

			len = strlen(ptr);
			trans = strchr(ptr, '=');
			if (trans) {
				ptr[len - 1] = '\0';

				/*这种情况表现形式为SELINUXTYPE=targeted，=之后紧接着字符串*/
				if (strcasecmp(trans + 1, condition) == 0) {  // 忽略大小写比较
					fclose(fp);
					return SNIPER_NORISK;
				}

				/*这种情况表现形式为max_log_file_action = keep_logs，=与字符串之间存在空格*/
				sscanf(trans, "%*s%511s", string_value);
				if (strcasecmp(string_value, condition) == 0) {
					fclose(fp);
					return SNIPER_NORISK;
				}
			} else if (strstr(ptr, condition)) {
				fclose(fp);
				return SNIPER_NORISK;
			}
		}
		fclose(fp);
		return SNIPER_RISK;
	}

	ret = sscanf(condition, "%*[^0-9]%d", &check_value);

	if (ret != 1) {
		str = cJSON_PrintUnformatted(params);
		DBG2(DBGFLAG_BASELINE, "%s: bad condition: %s\n", __FUNCTION__, str);
		free(str);
		return SNIPER_RISK;
	}

	fp = fopen(path, "rb");
	if (fp == NULL) {
		DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, path, strerror(errno));
		return SNIPER_RISK;
	}

	key = (char *)malloc(S_LINELEN);
	memset(key, 0, S_LINELEN);
	if (NULL == key) {
		fclose(fp);
		return SNIPER_RISK;
	}

	while (fgets(line, sizeof(line), fp)) {
		ptr = skip_headspace(line);

		/* 忽略注释行 */
		if (*ptr == *comment || *ptr == '#') {
			continue;
		}

		/* 取参数名和参数值 */
		ret = sscanf(ptr, "%511s", key);

		ptr += strlen(key);  // 跳过key开始，避免会出现minlen-14 = 14类似的情况

		if (strcmp(key, check_key) != 0) {
			continue;
		}

		// printf("!!!!!!!%s, %s\n", key, ptr);

		if (strchr(ptr, '-')) {	 // 两种情况，一种是minlen = 14，另一种是minlen 14，干脆正数的话从数字开始取，负数的话从-号开始取
			sscanf(ptr, "%*[^-]%d", &value);
		} else {
			sscanf(ptr, "%*[^0-9]%d", &value);
		}

		/* 找到了参数所在的行，不需要再查找，关闭文件 */
		fclose(fp);
		free(key);

		switch (operator) {
			case SNIPER_EQUAL:
				if (check_value == value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LARGE:
				if (value > check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LITTLE:
				if (value < check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LARGE_EQUAL:
				if (value >= check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LITTLE_EQUAL:
				if (value <= check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			default:
				return SNIPER_RISK;
		}
	}

	fclose(fp);
	free(key);
	return SNIPER_RISK;
}

/* 检查是否不存在无约束的守护程序即进程current与1号进程current相同为无约束 */
static int linux_unconfined_daemon_chk(void)
{
	FILE *parent_process = NULL, *other_process = NULL;
	char parent_current[1024] = {0}, current_buf[1024] = {0}, other_current[1024] = {0};
	DIR *dirp = NULL;
	int pid = 0;
	struct dirent *pident = NULL;

	parent_process = fopen("/proc/1/attr/current", "rb");
	if (parent_process == NULL) {
		DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, "/proc/1/attr/current", strerror(errno));
		return SNIPER_NORISK;
	}

	fgets(parent_current, sizeof(parent_current), parent_process);
	fclose(parent_process);

	dirp = opendir("/proc");
	if (dirp == NULL) {
		DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, "/proc", strerror(errno));
		return SNIPER_NORISK;
	}

	while ((pident = readdir(dirp))) {
		/*忽略非进程*/
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue;
		}
		pid = atoi(pident->d_name);

		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue;  // 忽略内核线程
		}

		snprintf(current_buf, sizeof(current_buf), "/proc/%d/attr/current", pid);
		other_process = fopen(current_buf, "r");
		if (other_process == NULL) {
			DBG2(DBGFLAG_BASELINE, "%s: open %d current fail: %s\n", __FUNCTION__, pid, strerror(errno));
			continue;
		}

		fgets(other_current, sizeof(other_current), other_process);
		fclose(other_process);
		if (strcmp(parent_current, other_current) == 0) {
			closedir(dirp);
			return SNIPER_RISK;
		}
	}
	closedir(dirp);
	return SNIPER_NORISK;
}

/*
	检查某个服务是否启用是否开机自启动
	检查目录:/etc/systemd/system/multi-user.target.wants/
*/
static int linux_systemd_service_chk(cJSON *params)
{
	DIR *dirp = NULL;
	struct dirent *ent = 0;
	char *service_name = NULL;
	int boot = 0;
	char tmp[1024] = {0};

	service_name = cJSON_GetObjectItem(params, "service")->valuestring;
	boot = cJSON_GetObjectItem(params, "boot")->valueint;

	snprintf(tmp, sizeof(tmp), "%s.service", service_name);

	dirp = opendir("/etc/systemd/system/multi-user.target.wants/");
	if (!dirp) {
		DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, "/etc/init.d", strerror(errno));
		return SNIPER_RISK;
	}

	while ((ent = readdir(dirp)) != NULL) {
		if (strcmp(ent->d_name, tmp) == 0 && boot) {
			closedir(dirp);
			return SNIPER_NORISK;
		} else if (strcmp(ent->d_name, tmp) == 0 && !boot) {
			closedir(dirp);
			return SNIPER_RISK;
		}
	}

	if (!boot) {
		closedir(dirp);
		return SNIPER_NORISK;
	}
	closedir(dirp);
	return SNIPER_RISK;
}

/*
   检查密码过期警告时间是否大于等于给定参数
   检查文件 /etc/login.defs
   检查字段 PASS_WARN_AGE

   检查密码过期时间
   检查文件 /etc/login.defs
   检查字段 PASS_MAX_DAYS
*/
static int linux_passwd_expire_days_chk(char *title, cJSON *params)
{
	char line[S_LINELEN] = {0};
	char *ptr = NULL, *value = NULL;
	FILE *fp = NULL;
	int num = 0, operator= 0, check_value = 0, ret = 0;

	value = cJSON_GetObjectItem(params, "days")->valuestring;

	ret = sscanf(value, "%*[^0-9]%d", &check_value);
	if (ret != 1) {
		return SNIPER_RISK;
	}

	if (strchr(value, '>')) {
		if (strchr(value, '=')) {
			operator= SNIPER_LARGE_EQUAL;
		} else {
			operator= SNIPER_LARGE;
		}
	} else if (strchr(value, '<')) {
		if (strchr(value, '=')) {
			operator= SNIPER_LITTLE_EQUAL;
		} else {
			operator= SNIPER_LITTLE;
		}
	} else {
		operator= SNIPER_EQUAL;
	}

	fp = fopen("/etc/login.defs", "rb");
	if (fp == NULL) {
		DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, "/etc/login.defs", strerror(errno));
		return SNIPER_RISK;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strcmp(title, "passwd_expire_warning_chk") == 0) {
			ptr = strstr(line, "PASS_WARN_AGE");
		} else {
			ptr = strstr(line, "PASS_MAX_DAYS");
		}

		if (!ptr) {
			continue;
		}
		fclose(fp);
		sscanf(line, "%*s%d", &num);
		switch (operator) {
			case SNIPER_EQUAL:
				if (check_value == num) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LARGE:
				if (num > check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LITTLE:
				if (num < check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LARGE_EQUAL:
				if (num >= check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LITTLE_EQUAL:
				if (num <= check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			default:
				return SNIPER_RISK;
		}
	}
	fclose(fp);
	return SNIPER_RISK;
}

/* 检查某package是否安装 */
static int linux_pkg_install_chk(cJSON *params)
{
	char *packages = NULL, *present = NULL, *str = NULL;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char package_cmd[CMD_SIZE_MAX] = {0};
#ifdef SNIPER_FOR_DEBIAN
	char cmd_line[64] = "dpkg -l | grep ";
#else
	char cmd_line[64] = "rpm -qa | grep ";
#endif

	packages = cJSON_GetObjectItem(params, "package")->valuestring;
	present = cJSON_GetObjectItem(params, "present")->valuestring;

	if (!packages || !present) {
		str = cJSON_PrintUnformatted(params);
		DBG2(DBGFLAG_BASELINE, "%s: missing condition: %s\n", __FUNCTION__, str);
		free(str);
		return SNIPER_RISK;
	}

	snprintf(package_cmd, sizeof(package_cmd), "%s%s > /tmp/package", cmd_line, packages);
	my_system(package_cmd, 0);

	fp = fopen("/tmp/package", "r");

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, packages) && strcmp(present, "true") == 0) {
			fclose(fp);
			unlink("/tmp/package");
			return SNIPER_NORISK;
		} else if (strstr(line, packages) && strcmp(present, "true") != 0) {
			fclose(fp);
			unlink("/tmp/package");
			return SNIPER_RISK;
		}
	}

	fclose(fp);
	unlink("/tmp/package");

	if (strcmp(present, "false") == 0) {
		return SNIPER_NORISK;
	} else {
		return SNIPER_RISK;
	}
}

/* 检查su命令的访问是否受限制 */
static int linux_su_cmd_chk(void)
{
	FILE *fp = NULL;
	char buf[1024] = {0};
	int res = 0;
	char *expression = "^\\s*auth\\s+required\\s+pam_wheel\\.so";

	fp = fopen("/etc/pam.d/su", "r");
	if (!fp) {
		DBG2(DBGFLAG_BASELINE, "open dir /etc/pam.d/su fail\n");
		return SNIPER_RISK;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (buf[0] == '#') {
			continue;
		}
		res = regular_match(buf, expression);

		if (res) {
			fclose(fp);
			return SNIPER_NORISK;
		}
	}
	fclose(fp);
	return SNIPER_RISK;
}

/* 读取passwd中用户名和用户id存入数据库，并查询两者是否有重复 */
static int get_user_name(char *title)
{
	const char *sSQL1 = "create table users(username varchar(64), uid int);";
	int result = 0;
	// 连接数据库
	sqlite3 *db = 0;
	int nrow = 0;
	int ncolumn = 0;
	char **azResult = NULL;	 // 二维数组存放结果

	int ret = sqlite3_open("/opt/snipercli/.mondb/user.db", &db);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "无法打开数据库: %s", sqlite3_errmsg(db));
		return -1;
	}
	// printf("数据库连接成功!\n");

	ret = sqlite3_exec(db, sSQL1, 0, 0, 0);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL %s error: %s\n", sSQL1, sqlite3_errmsg(db));
	}

	char line[1024] = {0};
	FILE *fp = fopen("/etc/passwd", "r");

	if (!fp) {
		DBG2(DBGFLAG_BASELINE, "get_password open /etc/passwd fail: %s\n", strerror(errno));
		sqlite3_close(db);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char name[64] = {0}, buf[128] = {0};
		int uid = 0;

		sscanf(line, "%63[^:]:%*[^:]:%d[^:]:", name, &uid);
		// printf("%s, %d\n", name, uid);
		snprintf(buf, sizeof(buf), "insert into users values('%s', %d);", name, uid);
		result = sqlite3_exec(db, buf, 0, 0, 0);
		if (result == SQLITE_OK) {
			// printf("插入数据成功\n");
		}
	}

	fclose(fp);
	if (strcmp(title, "user_dup_chk") == 0) {
		sqlite3_get_table(db, "select * from users group by username having count(*)>1;", &azResult, &nrow, &ncolumn, 0);  // 检查用户名是否唯一
	} else {
		sqlite3_get_table(db, "select * from users group by uid having count(*)>1;", &azResult, &nrow, &ncolumn, 0);  // 检查用户id是否唯一
	}

	sqlite3_free_table(azResult);
	sqlite3_close(db);
	if (nrow != 0) {
		return SNIPER_RISK;
	} else {
		return SNIPER_NORISK;
	}
}

/* 读取group中组名和组id存入数据库，并查询两者是否有重复 */
static int get_group_name(char *title)
{
	const char *sSQL1 = "create table groups(groupname varchar(64), gid int);";
	int result = 0;
	// 连接数据库
	sqlite3 *db = 0;
	int nrow = 0;
	int ncolumn = 0;
	char **azResult = NULL;	 // 二维数组存放结果

	int ret = sqlite3_open("/opt/snipercli/.mondb/group.db", &db);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "无法打开数据库: %s", sqlite3_errmsg(db));
		return -1;
	}
	// printf("数据库连接成功!\n");

	sqlite3_exec(db, sSQL1, 0, 0, 0);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL %s error: %s\n", sSQL1, sqlite3_errmsg(db));
	}

	char line[1024] = {0};
	FILE *fp = fopen("/etc/group", "r");

	if (!fp) {
		DBG2(DBGFLAG_BASELINE, "get_group_name open /etc/group fail: %s\n", strerror(errno));
		sqlite3_close(db);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char name[64] = {0}, buf[128] = {0};
		int uid = 0;

		sscanf(line, "%63[^:]:%*[^:]:%d[^:]:", name, &uid);
		// printf("%s, %d\n", name, uid);
		snprintf(buf, sizeof(buf), "insert into groups values('%s', %d);", name, uid);
		result = sqlite3_exec(db, buf, 0, 0, 0);
		if (result == SQLITE_OK) {
			// printf("插入数据成功\n");
		}
	}

	fclose(fp);
	if (strcmp(title, "gid_unique") == 0) {
		sqlite3_get_table(db, "select * from groups group by gid having count(*)>1;", &azResult, &nrow, &ncolumn, 0);  // 查询gid是否唯一
	} else {
		sqlite3_get_table(db, "select * from groups group by groupname having count(*)>1;", &azResult, &nrow, &ncolumn, 0);  // 查询groupname是否唯一
	}

	sqlite3_free_table(azResult);
	sqlite3_close(db);
	if (nrow != 0) {
		return SNIPER_RISK;
	} else {
		return SNIPER_NORISK;
	}
}

/*
	检查用户名、用户uid、用户组名、用户组gid是否唯一，唯一返回SNIPER_NORISK， 不唯一返回SNIPER_RISK
	drop table语句表示每一次检查完清空表，下次存入新的
*/
static int user_group_content_unique(char *title)
{
	int ret = 0;
	sqlite3 *db = NULL;

	if ((strcmp(title, "user_dup_chk") == 0) || (strcmp(title, "uid_unique") == 0)) {
		sqlite3_open("/opt/snipercli/.mondb/user.db", &db);

		sqlite3_exec(db, "drop table users;", 0, 0, 0);

		ret = get_user_name(title);
		DBG2(DBGFLAG_BASELINE, "%s, %d\n", title, ret);

		// sqlite3_open("/opt/snipercli/.mondb/user.db", &db);

		sqlite3_exec(db, "drop table users;", 0, 0, 0);
	} else {
		sqlite3_open("/opt/snipercli/.mondb/group.db", &db);

		sqlite3_exec(db, "drop table groups;", 0, 0, 0);

		ret = get_group_name(title);
		DBG2(DBGFLAG_BASELINE, "%s, %d\n", title, ret);

		// sqlite3_open("/opt/snipercli/.mondb/group.db", &db);

		sqlite3_exec(db, "drop table groups;", 0, 0, 0);
	}

	sqlite3_close(db);

	if (ret == 0) {
		return SNIPER_RISK;
	} else {
		return SNIPER_NORISK;
	}
}

static int linux_user_haspasswd(cJSON *params)
{
	FILE *fp = NULL;
	char line[MaxLength] = {0};
	char *user = cJSON_GetObjectItem(params, "user")->valuestring;

	fp = fopen("/etc/shadow", "rb");
	if (fp == NULL) {
		return SNIPER_RISK;
	}

	while ((fgets(line, sizeof(line), fp)) != NULL) {
		char value[S_LINELEN] = {0};

		if (strcmp(user, "ALL") == 0)  // 给的规则中要检查的是所有用户
		{
			if (line[0] == '#') {
				continue;
			}

			sscanf(line, "%*[^:]:%511[^:]", value);

			if (value[0] == 0) {
				fclose(fp);
				return SNIPER_RISK;
			}
		} else	// 给的规则中要检查的是指定用户
		{
			if (line[0] == '#') {
				continue;
			}
			if (!strstr(line, user)) {
				continue;
			}
			fclose(fp);
			sscanf(line, "%*[^:]:%511[^:]", value);

			if (value[0] == 0) {
				return SNIPER_RISK;
			}
		}
	}
	fclose(fp);
	return SNIPER_NORISK;
}

static int linux_self_start_chk(cJSON *params)
{
	char *service = NULL, *boot = NULL, *str = NULL;
	int run_level = 0;
	DIR *rc_d = NULL;
	struct dirent *pident = NULL;

	service = cJSON_GetObjectItem(params, "service")->valuestring;
	boot = cJSON_GetObjectItem(params, "boot")->valuestring;
	run_level = cJSON_GetObjectItem(params, "run_level")->valueint;

	if (!service || !boot) {
		str = cJSON_PrintUnformatted(params);
		DBG2(DBGFLAG_BASELINE, "%s: missing condition: %s\n", __FUNCTION__, str);
		free(str);
		return SNIPER_RISK;
	}

	switch (run_level)  // 查看规则给的运行级别的相对应的文件中是否有service
	{
		case 2:
			rc_d = opendir("/etc/rc2.d");
			break;

		case 3:
			rc_d = opendir("/etc/rc3.d");
			break;

		case 4:
			rc_d = opendir("/etc/rc4.d");
			break;

		case 5:
			rc_d = opendir("/etc/rc5.d");
			break;
		default:
			return SNIPER_RISK;
	}

	while ((pident = readdir(rc_d))) {
		if (strstr(pident->d_name, service)) {
			if (strcmp(boot, "true") == 0) {
				closedir(rc_d);
				return SNIPER_NORISK;
			} else {
				closedir(rc_d);
				return SNIPER_RISK;
			}
		}
	}
	closedir(rc_d);
	if (strcmp(boot, "false") == 0) {
		return SNIPER_NORISK;
	} else {
		return SNIPER_RISK;
	}
}

static int linux_grp_consistency_chk(void)
{
	sqlite3 *db_user = NULL;
	// sqlite3 *db_group = NULL;
	char *attach_group = NULL;
	char *union_query = NULL;
	int nrow = 0;
	int ncolumn = 0;
	char **azResult = NULL;	 // 二维数组存放结果

	sqlite3_open("/opt/snipercli/.mondb/user.db", &db_user);
	// sqlite3_open("/opt/snipercli/.mondb/group.db", &db_group);

	// 先命group数据库为b，方便下面查询语句使用
	attach_group = "ATTACH DATABASE \"/opt/snipercli/.mondb/group.db\" AS \"B\" ;";
	sqlite3_exec(db_user, attach_group, 0, 0, 0);

	// 查询user表所有gid在group表中是否存在
	union_query = "select * from userinfo where gid not in (select gid from B.groupinfo) ;";
	sqlite3_get_table(db_user, union_query, &azResult, &nrow, &ncolumn, 0);

	// 释放内存空间
	sqlite3_free_table(azResult);
	sqlite3_close(db_user);
	// sqlite3_close(db_group);

	// 如果nrow不为0，说明union_query查询出来存在两表不统一的情况，故不通过
	if (nrow != 0) {
		return SNIPER_RISK;
	}
	return SNIPER_NORISK;
}

static int linux_user_uid_range(cJSON *params, char *title)
{
	int range = 0;
	char *user = NULL;
	sqlite3 *db = NULL;
	char select[512] = {0};
	int nrow = 0;
	int ncolumn = 0;
	char **azResult = NULL;	 // 二维数组存放结果
	int i = 0;

	range = cJSON_GetObjectItem(params, "range")->valueint;
	user = cJSON_GetObjectItem(params, "user")->valuestring;

	sqlite3_open("/opt/snipercli/.mondb/user.db", &db);

	if (strcmp(title, "user_uid_range") == 0) {
		snprintf(select, sizeof(select), "select uid from userinfo where name = '%s'", user);  // 检查用户uid
	} else {
		snprintf(select, sizeof(select), "select gid from userinfo where name = '%s'", user);  // 检查用户gid
	}

	sqlite3_get_table(db, select, &azResult, &nrow, &ncolumn, 0);

	for (i = 1; i <= nrow; i++) {
		if (atoi(azResult[i]) == range) {
			sqlite3_free_table(azResult);
			sqlite3_close(db);
			return SNIPER_NORISK;
		}
	}

	sqlite3_free_table(azResult);
	sqlite3_close(db);
	return SNIPER_RISK;
}

/*
	检查不活跃的密码锁定
	检查文件：/etc/shadow
	检查字段：例：telnetd:*:18921:5:99999:8:::	8：之后的一个字段
*/
static int linux_inactive_pwd_lock_chk(cJSON *params)
{
	FILE *fp = NULL;
	char buf[1024] = {0};
	char *days = NULL;
	int operator= 0, check_value = 0;

	days = cJSON_GetObjectItem(params, "days")->valuestring;
	sscanf(days, "%*[^0-9]%d", &check_value);

	if (strchr(days, '>')) {
		if (strchr(days, '=')) {
			operator= SNIPER_LARGE_EQUAL;
		} else {
			operator= SNIPER_LARGE;
		}
	} else if (strchr(days, '<')) {
		if (strchr(days, '=')) {
			operator= SNIPER_LITTLE_EQUAL;
		} else {
			operator= SNIPER_LITTLE;
		}
	} else {
		operator= SNIPER_EQUAL;
	}

	fp = fopen("/etc/shadow", "r");

	while (fgets(buf, sizeof(buf), fp)) {
		int value = 0;
		sscanf(buf, "%*[^:]:%*[^:]:%*[^:]:%*[^:]:%*[^:]:%*[^:]:%d", &value);

		switch (operator) {
			case SNIPER_EQUAL:
				if (check_value != value) {
					return SNIPER_RISK;
				}

			case SNIPER_LARGE:
				if (value <= check_value) {
					return SNIPER_RISK;
				}

			case SNIPER_LITTLE:
				if (value >= check_value) {
					return SNIPER_RISK;
				}

			case SNIPER_LARGE_EQUAL:
				if (value < check_value) {
					return SNIPER_RISK;
				}

			case SNIPER_LITTLE_EQUAL:
				if (value > check_value) {
					return SNIPER_RISK;
				}
		}
	}
	fclose(fp);
	return SNIPER_NORISK;
}

static int app_chk_run_user(cJSON *params)
{
	char line[S_LINELEN] = {0};
	FILE *fp = NULL;
	char value[S_NAMELEN] = {0}, key[S_NAMELEN] = {0};
	char *kb_name = NULL;
	int user = 0, group = 0;

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	if (strcmp(kb_name, "httpd") == 0) {
		fp = fopen("/etc/httpd/conf/httpd.conf", "r");
		if (!fp) {
			fp = fopen("/etc/apache2/apache2.conf", "r");
		}
		if (!fp) {
			DBG2(DBGFLAG_BASELINE, "httpd_conf open fail: %s\n", strerror(errno));
			return 0;
		}
	} else {
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == '#') {
			continue;
		}
		sscanf(line, "%63s %63s", key, value);
		if (strcmp(key, "User") == 0) {
			user = 1;
			if (strcmp(value, "apache") != 0 && strcmp(value, "${APACHE_RUN_USER}") != 0) {
				fclose(fp);
				return SNIPER_RISK;
			}
		}
		if (strcmp(key, "Group") == 0) {
			group = 1;
			if (strcmp(value, "apache") != 0 && strcmp(value, "${APACHE_RUN_GROUP}") != 0) {
				fclose(fp);
				return SNIPER_RISK;
			}
		}
	}
	fclose(fp);

	if (!user || !group) {
		return SNIPER_RISK;
	}
	return SNIPER_NORISK;
}

int read_file_context(char *file_name, char *patterns, int present)
{
	char *ptr = NULL;
	char line[S_LINELEN] = {0};
	int res = 0;
	FILE *fp;

	fp = fopen(file_name, "r");
	if (!fp) {
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		ptr = skip_headspace(line);
		if (*ptr == '#') {
			continue;
		}
		res = regular_match(ptr, patterns);

		if (res && present)  // 匹配到了并且present为true
		{
			fclose(fp);
			return 0;
		}
		if (res && !present)  // 匹配到了并且present为false
		{
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);

	if (!res && (present == 0))  // 没有匹配到并且present为false
	{
		return 0;
	}
	return 1;
}

int type_listen_item(char *value, char *patterns, int present)
{
	int ret = 0;
	char *set = NULL;
	char home_path[S_LINELEN] = {0};
	DIR *dirp = NULL;
	struct dirent *dir_ptr;
	char file_path[S_PATHLEN] = {0};

	set = strstr(value, "*.conf");
	if (set) {
		*set = 0;
		if (access("/etc/httpd/conf/httpd.conf", F_OK) == 0) {
			snprintf(home_path, sizeof(home_path), "/etc/httpd/%s", value);
		} else {
			snprintf(home_path, sizeof(home_path), "/etc/apache2/%s", value);
		}
		dirp = opendir(home_path);
		if (!dirp) {
			return 0;
		}
		while ((dir_ptr = readdir(dirp)) != NULL) {
			if (!strstr(dir_ptr->d_name, ".conf")) {
				continue;
			}
			snprintf(file_path, sizeof(file_path), "%s%s", home_path, dir_ptr->d_name);

			ret = read_file_context(file_path, patterns, present);
			if (ret) {
				closedir(dirp);
				return 1;
			}
		}
		closedir(dirp);
		return 0;
	} else {
		if (access("/etc/httpd/conf/httpd.conf", F_OK) == 0) {
			snprintf(home_path, sizeof(home_path), "/etc/httpd/conf/%s", value);
		} else {
			snprintf(home_path, sizeof(home_path), "/etc/apache2/%s", value);
		}
		ret = read_file_context(home_path, patterns, present);
		if (ret) {
			return 1;
		}
	}
	return 0;
}

static int app_chk_file_string_presence(cJSON *params)
{
	char *kb_name = NULL, *patterns = NULL;
	int present = 0, res = 0;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *ptr = NULL;
	char key[S_NAMELEN] = {0}, value[S_NAMELEN] = {0};
	int ret = 0;

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	if (strcmp(kb_name, "nginx") == 0) {
		fp = fopen(nginx_path, "r");
	} else if (strcmp(kb_name, "httpd") == 0) {
		fp = fopen("/etc/httpd/conf/httpd.conf", "r");
		if (!fp) {
			fp = fopen("/etc/apache2/apache2.conf", "r");
		}
	}
	if (!fp) {
		return SNIPER_NORISK;
	}

	patterns = cJSON_GetObjectItem(params, "patterns")->valuestring;
	present = cJSON_GetObjectItem(params, "present")->valueint;

	while (fgets(line, sizeof(line), fp)) {
		ptr = skip_headspace(line);
		if (*ptr == '#') {
			continue;
		}

		sscanf(ptr, "%63s%*s", key);
		if (strstr(patterns, "Listen") && strcmp(key, "Include") == 0) {
			sscanf(ptr, "%*s%63s", value);
			break;
		}
		res = regular_match(ptr, patterns);

		if (res && present)  // 匹配到了并且present为true
		{
			fclose(fp);
			return SNIPER_NORISK;
		}
		if (res && !present)  // 匹配到了并且present为false
		{
			fclose(fp);
			return SNIPER_RISK;
		}
	}
	fclose(fp);

	if (!res && strstr(patterns, "Listen")) {
		if (value[0] == 0) {
			return SNIPER_NORISK;  // 说明既没有配置“Listen 80”，也没有配置“Include ports.conf”
		}
		ret = type_listen_item(value, patterns, present);
		if (!ret) {
			return SNIPER_NORISK;
		}
		return SNIPER_RISK;
	}

	if (!res && (present == 0)) {  // 没有匹配到并且present为false
		return SNIPER_NORISK;
	}
	return SNIPER_RISK;
}

static int app_chk_file_acl(cJSON *params)
{
	char *kb_name = NULL, *path_name = NULL;
	struct stat st = {0};
	char *acls = NULL;
	char value[64] = {0};

#ifdef SNIPER_FOR_DEBIAN
	path_name = "/etc/apache2/apache2.conf";
#else
	path_name = "/etc/httpd/conf/httpd.conf";
#endif
	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	acls = cJSON_GetObjectItem(params, "acls")->valuestring;

	if (strcmp(kb_name, "httpd") == 0) {
		if (stat(path_name, &st) < 0) {
			return SNIPER_RISK;
		}
		snprintf(value, sizeof(value), "%o", st.st_mode & 0777);
		if (strstr(acls, value)) {
			return SNIPER_NORISK;
		} else {
			return SNIPER_RISK;
		}
	}
	return SNIPER_NORISK;
}

static int app_chk_process_presence(cJSON *params)
{
	char *kb_name = NULL;
	int present = 0;

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	present = cJSON_GetObjectItem(params, "present")->valueint;

	if (strcmp(kb_name, "httpd") == 0 && apache_pid > 0 && present == true) {
		return SNIPER_NORISK;
	} else {
		return SNIPER_RISK;
	}

	if (strcmp(kb_name, "tomcat") == 0 && tomcat_pid > 0 && present == true) {
		return SNIPER_NORISK;
	} else {
		return SNIPER_RISK;
	}

	if (strcmp(kb_name, "nginx") == 0 && nginx_pid > 0 && present == true) {
		return SNIPER_NORISK;
	} else {
		return SNIPER_RISK;
	}
}

static int app_chk_file_user_ownership(cJSON *params)
{
	char *kb_name = NULL, *owned_by = NULL;
	char *cmd = NULL;
	struct stat st = {0};
	char line[1024] = {0};
	int uid = 0;
	FILE *fp = fopen("/etc/passwd", "r");

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	owned_by = cJSON_GetObjectItem(params, "owned_by")->valuestring;

	if (!fp) {
		DBG2(DBGFLAG_BASELINE, "get_password open /etc/passwd fail: %s\n", strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char name[64] = {0};

		sscanf(line, "%63[^:]:%*[^:]:%d[^:]:", name, &uid);
		if (strcmp(name, owned_by) == 0) {
			break;
		}
	}
	fclose(fp);

	if (strcmp(kb_name, "nginx") == 0) {
		if (nginx_pid <= 0) {
			return SNIPER_NORISK;
		}
		if (get_proc_exe(nginx_pid, cmd) > 0) {
			if (stat(cmd, &st) < 0) {
				return SNIPER_RISK;
			}
			if (st.st_uid == uid) {
				return SNIPER_NORISK;
			} else {
				return SNIPER_RISK;
			}
		}
	}
	return SNIPER_RISK;
}

static int app_chk_configuration_file_setting(cJSON *params)
{
	char *path = NULL, *comment = NULL, *condition = NULL, *check_key = NULL, *kb_name = NULL;
	char line[S_LINELEN] = {0}, *ptr = NULL, *str = NULL, *key = NULL;
	int value = 0, check_value = 0, ret = 0, operator= 0;
	FILE *fp = NULL;
	char *trans = NULL;
	int len = 0;
	char string_value[S_LINELEN] = {0};

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	if (strcmp(kb_name, "nginx") == 0) {
		path = nginx_path;
	} else if (strcmp(kb_name, "httpd") == 0) {
#ifdef SNIPER_FOR_DEBIAN
		path = "/etc/apache2/apache2.conf";
#else
		path = "/etc/httpd/conf/httpd.conf";
#endif
	}
	comment = cJSON_GetObjectItem(params, "comment_character")->valuestring;
	condition = cJSON_GetObjectItem(params, "desired_value")->valuestring;
	check_key = cJSON_GetObjectItem(params, "config_item")->valuestring;

	if (!path || !comment || !condition || !check_key) {
		str = cJSON_PrintUnformatted(params);
		DBG2(DBGFLAG_BASELINE, "%s: missing condition: %s\n", __FUNCTION__, str);
		free(str);
		return SNIPER_RISK;
	}

	if (strstr(condition, "EXISTS")) {
		return SNIPER_NORISK;
	}

	if (strcmp(check_key, "TimeOut") == 0) {
		check_key = "Timeout";
	}

	if (strchr(condition, '>')) {
		if (strchr(condition, '=')) {
			operator= SNIPER_LARGE_EQUAL;
		} else {
			operator= SNIPER_LARGE;
		}
	} else if (strchr(condition, '<')) {
		if (strchr(condition, '=')) {
			operator= SNIPER_LITTLE_EQUAL;
		} else {
			operator= SNIPER_LITTLE;
		}
	}

	if (!operator) {
		fp = fopen(path, "rb");
		if (fp == NULL) {
			DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, path, strerror(errno));
			return SNIPER_RISK;
		}

		while (fgets(line, sizeof(line), fp)) {
			ptr = skip_headspace(line);

			/* 忽略注释行 */
			if (*ptr == *comment || *ptr == '#') {
				continue;
			}

			if (!strstr(ptr, check_key)) {
				continue;
			}

			len = strlen(ptr);
			trans = strchr(ptr, '=');
			if (trans) {
				ptr[len - 1] = '\0';

				/*这种情况表现形式为SELINUXTYPE=targeted，=之后紧接着字符串*/
				if (strcasecmp(trans + 1, condition) == 0) {  // 忽略大小写比较
					fclose(fp);
					return SNIPER_NORISK;
				}

				/*这种情况表现形式为max_log_file_action = keep_logs，=与字符串之间存在空格*/
				sscanf(trans, "%*s%511s", string_value);
				if (strcasecmp(string_value, condition) == 0) {
					fclose(fp);
					return SNIPER_NORISK;
				}
			} else if (strstr(ptr, condition)) {
				if (strcmp(check_key, "Deny") == 0 || strcmp(check_key, "Require") == 0 || strcmp(check_key, "Order") == 0) {
					fclose(fp);
					return SNIPER_RISK;
				}
				fclose(fp);
				return SNIPER_NORISK;
			}

			if (strcmp(check_key, "Deny") == 0 || strcmp(check_key, "Require") == 0 || strcmp(check_key, "Order") == 0) {
				fclose(fp);
				return SNIPER_NORISK;
			}
		}
		fclose(fp);
		return SNIPER_RISK;
	}

	ret = sscanf(condition, "%*[^0-9]%d", &check_value);

	if (ret != 1) {
		str = cJSON_PrintUnformatted(params);
		DBG2(DBGFLAG_BASELINE, "%s: bad condition: %s\n", __FUNCTION__, str);
		free(str);
		return SNIPER_RISK;
	}

	fp = fopen(path, "rb");
	if (fp == NULL) {
		DBG2(DBGFLAG_BASELINE, "%s: open %s fail: %s\n", __FUNCTION__, path, strerror(errno));
		return SNIPER_RISK;
	}

	key = (char *)malloc(S_LINELEN);
	memset(key, 0, S_LINELEN);
	if (NULL == key) {
		fclose(fp);
		return SNIPER_RISK;
	}

	while (fgets(line, sizeof(line), fp)) {
		ptr = skip_headspace(line);

		/* 忽略注释行 */
		if (*ptr == *comment || *ptr == '#') {
			continue;
		}

		/* 取参数名和参数值 */
		ret = sscanf(ptr, "%511s", key);

		ptr += strlen(key);  // 跳过key开始，避免会出现minlen-14 = 14类似的情况

		if (strcmp(key, check_key) != 0) {
			continue;
		}

		if (strchr(ptr, '-')) {	 // 两种情况，一种是minlen = 14，另一种是minlen 14，干脆正数的话从数字开始取，负数的话从-号开始取
			sscanf(ptr, "%*[^-]%d", &value);
		} else {
			sscanf(ptr, "%*[^0-9]%d", &value);
		}

		/* 找到了参数所在的行，不需要再查找，关闭文件 */
		fclose(fp);
		free(key);

		switch (operator) {
			case SNIPER_EQUAL:
				if (check_value == value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LARGE:
				if (value > check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LITTLE:
				if (value < check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LARGE_EQUAL:
				if (value >= check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			case SNIPER_LITTLE_EQUAL:
				if (value <= check_value) {
					return SNIPER_NORISK;
				}
				return SNIPER_RISK;

			default:
				return SNIPER_RISK;
		}
	}

	fclose(fp);
	free(key);
	return SNIPER_RISK;
}

static int app_chk_file_presence(cJSON *params)
{
	char *kb_name = NULL, *conf_name = NULL;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, key[S_NAMELEN] = {0}, value[S_NAMELEN] = {0};
	int err_flag = 0, access_flag = 0;
	char *file = NULL, *ptr = NULL;
	int present = 0;
	char path[S_PATHLEN] = {0};
	char path1[S_LINELEN] = {0};
	char *gtr = NULL;

	if (tomcat_path[0] != 0) {
		snprintf(path1, sizeof(path1), "%s", tomcat_path);
		gtr = strstr(path1, "/conf");
		if (gtr) {
			*(gtr + 1) = 0;
		}
	}

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	if (strcmp(kb_name, "nginx") == 0) {
		conf_name = nginx_path;
	}

	/*
	 *tomcat5 manager目录为/usr/share/tomcat/server/webapps/manager
	 *tomcat678 manager目录为目录为/usr/share/tomcat/webapps/manager
	 */
	if (strcmp(kb_name, "tomcat") == 0) {
		file = cJSON_GetObjectItem(params, "file")->valuestring;
		present = cJSON_GetObjectItem(params, "present")->valueint;
		ptr = strstr(file, "${prefix}$");
		if (!tomcat_version_five) {
			if (strstr(ptr, "server")) {
				snprintf(path, sizeof(path), "%s%s", path1, ptr + 18);
			} else {
				snprintf(path, sizeof(path), "%s%s", path1, ptr + 11);
			}
		} else {
			if (strstr(ptr, "server")) {
				snprintf(path, sizeof(path), "%s%s", path1, ptr + 11);
			} else {
				snprintf(path, sizeof(path), "%sserver/%s", path1, ptr + 11);
			}
		}

		DBG2(DBGFLAG_BASELINE, "manager file: %s\n", path);
		if (access(path, F_OK) == 0 && present == 1) {
			return SNIPER_NORISK;
		} else if (access(path, F_OK) == 0 && present == 0) {
			return SNIPER_RISK;
		} else if (access(path, F_OK) != 0 && present == 0) {
			return SNIPER_NORISK;
		} else {
			return SNIPER_RISK;
		}
	}

	fp = fopen(conf_name, "r");
	if (!fp) {
		DBG2(DBGFLAG_BASELINE, "open app_conf fail: %s\n", strerror(errno));
		return SNIPER_NORISK;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == '#') {
			continue;
		}
		sscanf(line, "%63s %63s", key, value);
		sscanf(value, "%63[^;]", value);
		if (strcmp(key, "error_log") == 0 && access(value, F_OK) == 0) {
			err_flag = 1;
		}
		if (strcmp(key, "access_log") == 0 && access(value, F_OK) == 0) {
			access_flag = 1;
		}
		if (err_flag && access_flag) {
			fclose(fp);
			return SNIPER_NORISK;
		}
	}
	fclose(fp);
	return SNIPER_RISK;
}

static int app_chk_shell_string_presence(cJSON *params)
{
	char bin_path[CMD_SIZE_MAX] = {0};
	char *kb_name = NULL, *param = NULL, *patterns = NULL;
	int present = 0;
	char shell[S_PROCPATHLEN] = {0};
	FILE *pcmd = NULL;
	char pline[S_LINELEN] = {0}, pkey[S_NAMELEN] = {0};

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	param = cJSON_GetObjectItem(params, "param")->valuestring;
	patterns = cJSON_GetObjectItem(params, "patterns")->valuestring;
	present = cJSON_GetObjectItem(params, "present")->valueint;

	if (strcmp(kb_name, "nginx") == 0 && nginx_pid > 0) {
		if (get_proc_exe(nginx_pid, bin_path) <= 0) {
			return SNIPER_NORISK;
		}
	} else if (strcmp(kb_name, "httpd") == 0 && apache_pid > 0) {
		if (get_proc_exe(apache_pid, bin_path) <= 0) {
			return SNIPER_NORISK;
		}
	}

	if (bin_path[0] == 0) {
		snprintf(shell, sizeof(shell), "%s %s", "httpd", param);
	} else {
		snprintf(shell, sizeof(shell), "%s %s", bin_path, param);
	}

	pcmd = popen(shell, "r");
	while (fgets(pline, sizeof(pline), pcmd)) {
		sscanf(pline, "%63s", pkey);
		if (strcmp(pkey, patterns) == 0 && present == 1) {
			pclose(pcmd);
			return SNIPER_NORISK;
		}
	}
	pclose(pcmd);
	return SNIPER_RISK;
}

static int get_passwd_uid(char *desired_name)
{
	char line[1024] = {0};
	FILE *fp = fopen("/etc/passwd", "r");
	int uid = 0;

	if (!fp) {
		DBG2(DBGFLAG_BASELINE, "get_password open /etc/passwd fail: %s\n", strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char name[64] = {0};

		sscanf(line, "%63[^:]:%*[^:]:%d[^:]:", name, &uid);
		// printf("%s, %d\n", name, uid);
		if (strcmp(name, desired_name) == 0) {
			fclose(fp);
			return uid;
		}
	}
	fclose(fp);
	return -1;
}

static int app_chk_value_compare(cJSON *params)
{
	FILE *fp = NULL;
	char line[1024] = {0}, path[S_NAMELEN] = {0};
	char *kb_name = NULL, *desired = NULL;
	char field[S_NAMELEN] = {0}, desired_name[S_LINELEN] = {0};
	int id = 0, Uid = 0, passwd_uid = 0;

	kb_name = cJSON_GetObjectItem(params, "kb_name")->valuestring;
	desired = cJSON_GetObjectItem(params, "desired")->valuestring;

	if (strcmp(kb_name, "tomcat") == 0 && tomcat_pid > 0) {
		snprintf(path, sizeof(path), "/proc/%d/status", tomcat_pid);
	} else if (strcmp(kb_name, "httpd") == 0 && apache_pid > 0) {
		snprintf(path, sizeof(path), "/proc/%d/status", apache_pid);
	} else if (strcmp(kb_name, "nginx") == 0 && nginx_pid > 0) {
		snprintf(path, sizeof(path), "/proc/%d/status", nginx_pid);
	}

	fp = fopen(path, "r");
	if (!fp) {
		DBG2(DBGFLAG_BASELINE, "get_status open /proc/status fail: %s\n", strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		sscanf(line, "%63s %d", field, &id);
		if (strcmp(field, "Uid:") == 0) {
			Uid = id;
			break;
		}
	}
	fclose(fp);
	if (strstr(desired, "NOT:")) {
		sscanf(desired, "NOT:%511s", desired_name);
		passwd_uid = get_passwd_uid(desired_name);

		if (passwd_uid == -1) {
			return SNIPER_RISK;
		}
		if (Uid != passwd_uid) {
			return SNIPER_NORISK;
		} else {
			return SNIPER_RISK;
		}
	} else {
		passwd_uid = get_passwd_uid(desired);
		if (passwd_uid == -1) {
			return SNIPER_RISK;
		}
		if (Uid != passwd_uid) {
			return SNIPER_RISK;
		} else {
			return SNIPER_NORISK;
		}
	}
}

/* 判断密码强弱 */
static int get_passwd_strength(char *password, int passwd_length)
{
	if (password == NULL) {
		return SNIPER_RISK;
	}
	int iSymbol = 0, iNumber = 0, iLetter = 0, Iletter = 0;
	int passwd_len = 0;
	char *pChar = password;
	passwd_len = strlen(password);
	if (passwd_len < passwd_length) { /*密码字符数小于要求不满足规则，无效密码*/
		DBG2(DBGFLAG_BASELINE, "passwd %s Less than %d\n", password, passwd_length);
		return SNIPER_RISK;
	}

	for (; *pChar != '\0'; pChar++) {
		if (*pChar >= '0' && *pChar <= '9')
			iNumber++;
		else if (*pChar >= 'A' && *pChar <= 'Z')
			Iletter++;
		else if (*pChar >= 'a' && *pChar <= 'z')
			iLetter++;
		else
			iSymbol++;
	}
	if ((iLetter == 0 && Iletter == 0 && iSymbol == 0) || (iNumber == 0 && iSymbol == 0 && Iletter == 0) || (iNumber == 0 && iSymbol == 0 && iLetter == 0) || (iLetter == 0 && iNumber == 0 && Iletter == 0)) {
		return SNIPER_RISK; /*密码只含有数字 或 只含有小写字母 或 只含大写字母 或 只含有特殊字符*/
	}
	if ((iNumber > 0 && Iletter > 0) || (iNumber > 0 && iLetter > 0) || (iNumber > 0 && iSymbol > 0) || (Iletter > 0 && iLetter > 0) || (Iletter > 0 && iSymbol > 0) || (iLetter > 0 && iSymbol > 0)) {
		DBG2(DBGFLAG_BASELINE, "passwd %s len Greater than %d and more complex than 2\n", password, passwd_length);
		return SNIPER_NORISK; /*两种组合*/
	}
	DBG2(DBGFLAG_BASELINE, "passwd %s more complex than 3 and len Greater than %d\n", password, passwd_length);
	return SNIPER_NORISK; /*三种组合，密码长度大于要求*/
}

/* 检查是否设置口令长度和复杂度
 * 按规则要求只检查指定的username，而不是针对所有用户，检查一个通用的弱密码规则
 */
static int app_chk_weak_passwd(cJSON *params)
{
	char *key_path = NULL, *ptr = NULL, *str = NULL;
	char user_name[S_LINELEN] = {0}, path_name[S_PATHLEN] = {0};
	char *file_path = NULL;
	FILE *fp = NULL;
	char *password = NULL;
	char value[S_NAMELEN] = {0}, line[S_LINELEN] = {0};
	char user[S_NAMELEN] = {0};
	int ret = 0;
	char *passwd_length = NULL;
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	key_path = cJSON_GetObjectItem(params, "key_path")->valuestring;
	file_path = cJSON_GetObjectItem(params, "file_path")->valuestring;
	passwd_length = cJSON_GetObjectItem(params, "passwd_length")->valuestring;
	str = strstr(file_path, "${conf_dir}$");
	if (str) {
		snprintf(path_name, sizeof(path_name), "%s%s", tomcat_path, str + 12);
	} else {
		snprintf(path_name, sizeof(path_name), "%s%s", tomcat_path, file_path);
	}

	ptr = strstr(key_path, "username");
	if (!ptr) {
		return SNIPER_RISK;
	}

	sscanf(ptr, "%*[^\']\'%63[^\']", user);
	snprintf(user_name, sizeof(user_name), "username=\"%s\"", user);

	fp = fopen(path_name, "r");
	if (!fp) {
		return SNIPER_RISK;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "<?")) { /* XML文件声明行 */
			continue;
		}
		if (line[0] == '\n') {
			continue;
		}
		delete_tailspace(line);
		tmp = skip_headspace(line);

		if (start) { /* 已在多行注释中 */
			if (strstr(tmp, "-->")) {
				/* 跨行注释结束 */
				start = 0;
				continue;
			} else {
				continue;
			}
		}

		if (*tmp == '<' && *(++tmp) == '!' && *(++tmp) == '-' && *(++tmp) == '-') { /* 注释开始 <!-- */
			start = 1;

			len = strlen(tmp);
			tmp += len;
			if (*(--tmp) == '\n') {
				*(tmp) = '\0';
				--tmp;
			}
			while (*tmp == ' ') {
				--tmp;
			}
			if (*tmp == '>' && *(--tmp) == '-' && *(--tmp) == '-') { /* 单行的注释结束 */
				start = 0;
				continue;
			}
		}

		if (start) {
			continue;
		}
		if (!strstr(line, user_name)) {
			continue;
		}
		password = strstr(line, "password=");
		if (!password) {
			fclose(fp);
			return SNIPER_RISK;
		}
		sscanf(password, "%*[^\"]\"%63[^\"]", value);

		ret = get_passwd_strength(value, atoi(passwd_length));
		if (ret) {
			fclose(fp);
			return SNIPER_NORISK;
		} else {
			fclose(fp);
			return SNIPER_RISK;
		}
	}
	fclose(fp);
	return SNIPER_RISK;
}

/* 检查是否启用日志功能 */
static int app_chk_xml_node_exist(cJSON *params)
{
	FILE *fp = NULL;
	char conf_path[S_PATHLEN] = {0};
	char line[S_LINELEN] = {0};
	char *node_path = NULL;
	int present = 0;
	char *ptr = NULL;
	char value[S_LINELEN] = {0};
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	node_path = cJSON_GetObjectItem(params, "node_path")->valuestring;
	present = cJSON_GetObjectItem(params, "present")->valueint;

	ptr = strstr(node_path, "='");
	if (!ptr) {
		return SNIPER_RISK;
	}
	sscanf(ptr + 2, "%511[^']", value);

	snprintf(conf_path, sizeof(conf_path), "%sserver.xml", tomcat_path);

	fp = fopen(conf_path, "r");
	if (!fp) {
		return SNIPER_RISK;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "<?")) { /* XML文件声明行 */
			continue;
		}
		if (line[0] == '\n') {
			continue;
		}
		delete_tailspace(line);
		tmp = skip_headspace(line);

		if (start) { /* 已在多行注释中 */
			if (strstr(tmp, "-->")) {
				/* 跨行注释结束 */
				start = 0;
				continue;
			} else {
				continue;
			}
		}

		if (*tmp == '<' && *(++tmp) == '!' && *(++tmp) == '-' && *(++tmp) == '-') { /* 注释开始 <!-- */
			start = 1;

			len = strlen(tmp);
			tmp += len;
			if (*(--tmp) == '\n') {
				*(tmp) = '\0';
				--tmp;
			}
			while (*tmp == ' ') {
				--tmp;
			}
			if (*tmp == '>' && *(--tmp) == '-' && *(--tmp) == '-') { /* 单行的注释结束 */
				start = 0;
				continue;
			}
		}

		if (start) {
			continue;
		}

		if (strstr(line, value) && present == 1) {
			fclose(fp);
			return SNIPER_NORISK;
		}
	}
	fclose(fp);
	return SNIPER_RISK;
}

static int xml_first_treatment(char *path_name, char *node_name, char *node_path, char *desired_value)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *ptr = NULL, *str = NULL, *gtr = NULL, *ttr = NULL;
	int value = 0;
	char node[S_NAMELEN] = {0}, node1[S_NAMELEN] = {0};
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	str = strstr(node_path, "[@");
	if (str) {
		sscanf(str + 2, "%63[0-9a-zA-Z]", node);
	}
	gtr = strstr(node_path, "/@");
	if (gtr) {
		sscanf(gtr + 2, "%63[0-9a-zA-Z]", node1);
	}

	fp = fopen(path_name, "r");
	if (!fp) {
		return SNIPER_RISK;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "<?")) { /* XML文件声明行 */
			continue;
		}
		if (line[0] == '\n') {
			continue;
		}
		delete_tailspace(line);
		tmp = skip_headspace(line);

		if (start) { /* 已在多行注释中 */
			if (strstr(tmp, "-->")) {
				/* 跨行注释结束 */
				start = 0;
				continue;
			} else {
				continue;
			}
		}

		if (*tmp == '<' && *(++tmp) == '!' && *(++tmp) == '-' && *(++tmp) == '-') { /* 注释开始 <!-- */
			start = 1;

			len = strlen(tmp);
			tmp += len;
			if (*(--tmp) == '\n') {
				*(tmp) = '\0';
				--tmp;
			}
			while (*tmp == ' ') {
				--tmp;
			}
			if (*tmp == '>' && *(--tmp) == '-' && *(--tmp) == '-') { /* 单行的注释结束 */
				start = 0;
				continue;
			}
		}

		if (start) {
			continue;
		}

		if (!strstr(line, node_name)) {
			continue;
		}

		if (strstr(node_path, "protocol") && strstr(node_path, "port")) {
			if (!strstr(line, "HTTP/1.1")) {
				continue;
			}
		}

		fclose(fp);

		if (strstr(node_path, "protocol") && strstr(node_path, "port")) {
			ttr = strstr(line, "port=");
			sscanf(ttr, "%*[^\"]\"%d[^\"]", &value);
			if (value == 8080) {
				return SNIPER_RISK;
			}
			return SNIPER_NORISK;
		}

		ptr = strstr(desired_value, "ISIN:");
		if (ptr) {
			if (strstr(line, ptr + 5)) {
				return SNIPER_NORISK;
			} else {
				return SNIPER_RISK;
			}
		}
		ttr = strstr(line, node_name);
		DBG2(DBGFLAG_BASELINE, "xml_first_treatment match line : %s\n", line);
		sscanf(ttr, "%*[^\"]\"%d[^\"]", &value);
		if (strncmp(desired_value, "NOT:", 4) == 0) {
			desired_value += 4;
			if (desired_value == NULL) {
				return SNIPER_NORISK;
			}
		}

		if (strstr(desired_value, "<=:")) {
			desired_value += 3;
			if (value <= atoi(desired_value)) {
				return SNIPER_NORISK;
			} else {
				return SNIPER_RISK;
			}
		}

		if (strstr(desired_value, "<:")) {
			desired_value += 3;
			if (value < atoi(desired_value)) {
				return SNIPER_NORISK;
			} else {
				return SNIPER_RISK;
			}
		}

		if (strstr(desired_value, ">=:")) {
			desired_value += 3;
			if (value >= atoi(desired_value)) {
				return SNIPER_NORISK;
			} else {
				return SNIPER_RISK;
			}
		}

		if (strstr(desired_value, ">:")) {
			desired_value += 3;
			if (value > atoi(desired_value)) {
				return SNIPER_NORISK;
			} else {
				return SNIPER_RISK;
			}
		}

		if (atoi(desired_value) == value) {
			return SNIPER_NORISK;
		} else {
			return SNIPER_RISK;
		}
	}
	fclose(fp);
	return SNIPER_RISK;
}

int split_string_isin_file(char *key, char *path_name)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	fp = fopen(path_name, "r");
	if (!fp) {
		return SNIPER_RISK;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "<?")) { /* XML文件声明行 */
			continue;
		}
		if (line[0] == '\n') {
			continue;
		}
		delete_tailspace(line);
		tmp = skip_headspace(line);

		if (start) { /* 已在多行注释中 */
			if (strstr(tmp, "-->")) {
				/* 跨行注释结束 */
				start = 0;
				continue;
			} else {
				continue;
			}
		}

		if (*tmp == '<' && *(++tmp) == '!' && *(++tmp) == '-' && *(++tmp) == '-') { /* 注释开始 <!-- */
			start = 1;

			len = strlen(tmp);
			tmp += len;
			if (*(--tmp) == '\n') {
				*(tmp) = '\0';
				--tmp;
			}
			while (*tmp == ' ') {
				--tmp;
			}
			if (*tmp == '>' && *(--tmp) == '-' && *(--tmp) == '-') { /* 单行的注释结束 */
				start = 0;
				continue;
			}
		}

		if (start) {
			continue;
		}

		if (strstr(line, key)) {
			if (strcmp(key, "listings") == 0 || strcmp(key, "readonly") == 0) {
				break;
			}
			fclose(fp);
			return SNIPER_NORISK;
		}
	}
	fgets(line, sizeof(line), fp);
	if (line[0] != 0 && line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;

	fclose(fp);
	if (strcmp(key, "listings") == 0 && strstr(line, "false")) {
		return SNIPER_NORISK;
	}
	if (strcmp(key, "readonly") == 0 && strstr(line, "true")) {
		return SNIPER_NORISK;
	}
	return SNIPER_RISK;
}

/*
 *将字符串中所有两个单引号之间的字符串取出
 *传入path_name文件中查找是否存在
 *存在返回match，不存在返回notmatch
 */

int sscanf_split_string(char *ptr, char *path_name, char *desired_value)
{
	char key[S_NAMELEN] = {0};
	char value[S_LINELEN] = {0};
	int ret = 1;

	if (sscanf(ptr, "%*[^\']\'%63[^\']%511s", key, value) == 2) {
		ret = split_string_isin_file(key, path_name);
		if (!ret) {
			return SNIPER_RISK;
		}
		return sscanf_split_string(value + 1, path_name, desired_value);
	}

	return SNIPER_NORISK;
}

int handle_roles_situation(char *path, char *key, char *value)
{
	FILE *fp = NULL;
	char handel_value[S_NAMELEN] = {0};
	char line[S_LINELEN] = {0};
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;
	char *ptr = NULL;

	if (strstr(value, ":")) {
		if (sscanf(value, "%*[^:]:%63s", handel_value) != 1) {
			return SNIPER_RISK;
		}
	}

	// printf("%s, %s, %s\n", path, key, handel_value);
	fp = fopen(path, "r");
	if (!fp) {
		return SNIPER_RISK;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "<?")) { /* XML文件声明行 */
			continue;
		}
		if (line[0] == '\n') {
			continue;
		}
		delete_tailspace(line);
		tmp = skip_headspace(line);

		if (start) { /* 已在多行注释中 */
			if (strstr(tmp, "-->")) {
				/* 跨行注释结束 */
				start = 0;
				continue;
			} else {
				continue;
			}
		}

		if (*tmp == '<' && *(++tmp) == '!' && *(++tmp) == '-' && *(++tmp) == '-') { /* 注释开始 <!-- */
			start = 1;

			len = strlen(tmp);
			tmp += len;
			if (*(--tmp) == '\n') {
				*(tmp) = '\0';
				--tmp;
			}
			while (*tmp == ' ') {
				--tmp;
			}
			if (*tmp == '>' && *(--tmp) == '-' && *(--tmp) == '-') { /* 单行的注释结束 */
				start = 0;
				continue;
			}
		}

		if (start) {
			continue;
		}

		if (strstr(line, "username") && strstr(line, key)) {
			// printf("%s, %s\n", line, handel_value);
			ptr = strstr(line, "roles");
			if (ptr) {
				if (strstr(ptr, handel_value)) {
					fclose(fp);
					return SNIPER_NORISK;
				}
			}
		}
	}
	fclose(fp);
	return SNIPER_RISK;
}

char *strrstr(const char *string, const char *str)
{
	char *index = NULL;
	char *ret = NULL;
	int i = 0;
	do {
		index = strstr(string + i++, str);
		if (index != NULL)
			ret = index;
	} while (index != NULL);
	return ret;
}

static int app_chk_xml_value(cJSON *params)
{
	char *file_path = NULL, *node_path = NULL, *desired_value = NULL;
	char *ptr = NULL, *str = NULL, *gtr = NULL;
	char path_name[S_PATHLEN] = {0};
	int ret = 0;
	char node_name[S_NAMELEN] = {0}, roles_value[S_NAMELEN] = {0};

	file_path = cJSON_GetObjectItem(params, "file_path")->valuestring;
	node_path = cJSON_GetObjectItem(params, "node_path")->valuestring;
	desired_value = cJSON_GetObjectItem(params, "desired_value")->valuestring;

	ptr = strstr(file_path, "}$");
	if (ptr) {
		if (*(ptr + 3) == '\0') {
			snprintf(path_name, sizeof(path_name), "%sserver.xml", tomcat_path);
		} else {
			if (strchr(ptr, '/')) {
				snprintf(path_name, sizeof(path_name), "%s%s", tomcat_path, ptr + 3);
			} else {
				snprintf(path_name, sizeof(path_name), "%s%s", tomcat_path, ptr + 2);
			}
		}
	}

	/*
	    取最后一个@出现的位置,一个@和多个@都适用
	    除了"检查tomcat用户是否具有管理权限"这条检查项，有两个@，但要看第一个@
	*/
	str = strrstr(node_path, "@");
	if (str) {
		if (strstr(node_path, "roles")) {
			gtr = strstr(node_path, "username");
			if (gtr) {
				sscanf(gtr, "%*[^\']\'%63[^\']", roles_value);
			}
			// printf("!!!%s, %s, %s\n", path_name, roles_value, desired_value);
			ret = handle_roles_situation(path_name, roles_value, desired_value);
			if (!ret) {
				return SNIPER_RISK;
			} else {
				return SNIPER_NORISK;
			}
		}

		if (strstr(node_path, "port")) {
			str = strstr(node_path, "[@");
			sscanf(str + 2, "%63[0-9a-zA-Z]", node_name);
		} else {
			sscanf(str + 1, "%63[0-9a-zA-Z]", node_name);
		}

		DBG2(DBGFLAG_SYSDANGER, "node_name %s\n", node_name);

		ret = xml_first_treatment(path_name, node_name, node_path, desired_value);
		if (ret) {
			return SNIPER_NORISK;
		} else {
			return SNIPER_RISK;
		}
	}

	/*
		json2: node_path: [name()='web-app'][name()='error-page'][name()='error-code']
	*/
	ret = sscanf_split_string(node_path, path_name, desired_value);

	if (ret) {
		return SNIPER_NORISK;
	}
	return SNIPER_RISK;
}

/* 处理有and和or的嵌套规则 */
static int handle_combine(cJSON *string_to_json)
{
	int arr_num = 0, i = 0, res = 0, flag = 0;
	cJSON *arr;
	cJSON *combine = cJSON_GetObjectItem(string_to_json, "$and");
	if (!combine) {
		combine = cJSON_GetObjectItem(string_to_json, "$or");
		flag = 1;
	}

	arr_num = cJSON_GetArraySize(combine);	// 获取规则中数组的个数
	for (i = 0; i < arr_num; i++) {
		arr = cJSON_GetArrayItem(combine, i);  // 通过数组个数获取到每个小规则
		DBG2(DBGFLAG_BASELINE, "%s\n", cJSON_Print(arr));
		res = check_type_classify(arr);	 // 使用check_type_classify函数处理每个小规则，返回1说明该小规则通过，返回0表示规则不通过
		DBG2(DBGFLAG_BASELINE, "result:%d\n", res);

		if (res && flag) {  // 如果combine是or，并有一个规则结果已经满足了，便直接返回SNIPER_NORISK
			return SNIPER_NORISK;
		}

		if (!res && !flag)  // 如果combine是and，并有一个规则不结果不满足，便直接返回SNIPER_RISK
		{
			return SNIPER_RISK;
		}
	}
	if (!flag)  // 每个规则都通过，且combine是and
	{
		return SNIPER_NORISK;
	} else {
		return SNIPER_RISK;
	}
}

/* 处理每种check_type */
static int check_type_classify(cJSON *string_to_json)
{
	char *check_type = NULL;
	int res = 0;

	if (!string_to_json) {
		return SNIPER_RISK;
	}

	cJSON *type = cJSON_GetObjectItem(string_to_json, "check_type");

	check_type = cJSON_Print(type);

	cJSON *params = cJSON_GetObjectItem(string_to_json, "params");

	if (!params) {
		res = handle_combine(string_to_json);
	}

	if (!check_type) {
		goto end;
	}

	if (strcmp(check_type, "\"combine\"") == 0 || strcmp(check_type, "\"combine_app_chk\"") == 0) {
		res = handle_combine(params);
	} else if (strcmp(check_type, "\"configuration_file_setting\"") == 0) {
		res = configuration_file_setting(params);
	} else if (strcmp(check_type, "\"file_string_presence\"") == 0) {
		res = linux_file_string_presence(params);
	} else if (strcmp(check_type, "\"unconfined_daemon_chk\"") == 0) {
		res = linux_unconfined_daemon_chk();
	} else if (strcmp(check_type, "\"passwd_expire_warning_chk\"") == 0) {
		res = linux_passwd_expire_days_chk("passwd_expire_warning_chk", params);
	} else if (strcmp(check_type, "\"passwd_expire_days_chk\"") == 0) {
		res = linux_passwd_expire_days_chk("passwd_expire_days_chk", params);
	} else if (strcmp(check_type, "\"inactive_pwd_lock_chk\"") == 0) {
		res = linux_inactive_pwd_lock_chk(params);
	} else if (strcmp(check_type, "\"user_uid_range\"") == 0) {
		res = linux_user_uid_range(params, "user_uid_range");
	} else if (strcmp(check_type, "\"pkg_install_chk\"") == 0) {
		res = linux_pkg_install_chk(params);
	} else if (strcmp(check_type, "\"user_default_gid_range\"") == 0) {
		res = linux_user_uid_range(params, "user_default_gid_range");
	} else if (strcmp(check_type, "\"passwd_change_chk\"") == 0) {
		res = linux_passwd_expire_days_chk("passwd_change_chk", params);
	} else if (strcmp(check_type, "\"user_has_password\"") == 0) {
		res = linux_user_haspasswd(params);
	} else if (strcmp(check_type, "\"grp_consistency_chk\"") == 0) {
		res = linux_grp_consistency_chk();
	} else if (strcmp(check_type, "\"su_cmd_chk\"") == 0) {
		res = linux_su_cmd_chk();
	} else if (strcmp(check_type, "\"self_start_chk\"") == 0) {
		res = linux_self_start_chk(params);
	} else if (strcmp(check_type, "\"systemd_service_chk\"") == 0) {
		res = linux_systemd_service_chk(params);
	}

	else if (strcmp(check_type, "\"gid_unique\"") == 0) {
		res = user_group_content_unique("gid_unique");
	} else if (strcmp(check_type, "\"grp_dup_chk\"") == 0) {
		res = user_group_content_unique("grp_dup_chk");
	} else if (strcmp(check_type, "\"user_dup_chk\"") == 0) {
		res = user_group_content_unique("user_dup_chk");
	} else if (strcmp(check_type, "\"uid_unique\"") == 0) {
		res = user_group_content_unique("uid_unique");
	} else if (strcmp(check_type, "\"file_presence\"") == 0) {
		res = 1;
	}
	/*****application baseline*****/
	else if (strcmp(check_type, "\"app_chk_run_user\"") == 0) {
		res = app_chk_run_user(params);
	} else if (strcmp(check_type, "\"app_chk_file_string_presence\"") == 0) {
		res = app_chk_file_string_presence(params);
	} else if (strcmp(check_type, "\"app_chk_file_acl\"") == 0) {
		res = app_chk_file_acl(params);
	} else if (strcmp(check_type, "\"app_chk_process_presence\"") == 0) {
		res = app_chk_process_presence(params);
	} else if (strcmp(check_type, "\"app_chk_file_user_ownership\"") == 0) {
		res = app_chk_file_user_ownership(params);
	} else if (strcmp(check_type, "\"app_chk_configuration_file_setting\"") == 0) {
		res = app_chk_configuration_file_setting(params);
	} else if (strcmp(check_type, "\"app_chk_file_presence\"") == 0) {
		res = app_chk_file_presence(params);
	} else if (strcmp(check_type, "\"app_chk_shell_string_presence\"") == 0) {
		res = app_chk_shell_string_presence(params);
	} else if (strcmp(check_type, "\"app_chk_value_compare\"") == 0) {
		res = app_chk_value_compare(params);
	}
	/* tomcat */
	else if (strcmp(check_type, "\"app_chk_xml_value\"") == 0) {
		res = app_chk_xml_value(params);
	} else if (strcmp(check_type, "\"app_chk_xml_node_exist\"") == 0) {
		res = app_chk_xml_node_exist(params);
	} else if (strcmp(check_type, "\"app_chk_weak_passwd\"") == 0) {
		res = app_chk_weak_passwd(params);
	} else {
		res = 0;
	}

end:
	free(check_type);
	return res;
}

/*
 *如果管控下发了某个应用 的应用基线，但是客户端发现没有该应用，则需要返回status为2
 *如果是安装了应用没起动，照理应该也能检查配置文件
 *TODO 现在进程不启动的情况下，无法获取到该应用的准确的主目录，从而无法判断该应用是否安装
 *     所以暂时只能判断该应用起没起，以后再优化依据应用的安装与否来返回status。
 * 	   暂时先看启动情况返回status。
 */
static void check_baseline(cJSON *array, int item, int rule_id)
{
	cJSON *items = cJSON_CreateObject();
	int res = -1;

	// 打开保存JSON数据的文件
	int fd = open("/opt/snipercli/baseline.json", O_RDWR);
	if (fd < 0) {
		DBG2(DBGFLAG_BASELINE, "open fail /opt/snipercli/baseline.json\n");
		cJSON_Delete(items);
		return;
	}

	// 读取文件中的数据
	char buf[4096] = {0};
	int ret = read(fd, buf, sizeof(buf));
	if (ret == -1) {
		cJSON_Delete(items);
		return;
	}

	// 关闭文件
	close(fd);

	// 把该字符串数据转换成JSON数据  (对象)
	cJSON *string_to_json = cJSON_Parse(buf);
	if (string_to_json == NULL) {
		cJSON_Delete(items);
		return;
	}

	// 根据key值去获取对应的value
	res = check_type_classify(string_to_json);

	cJSON_AddNumberToObject(items, "item", item);

	if (rule_id == 31 && tomcat_version_five != 1) {
		cJSON_AddNumberToObject(items, "status", 2);
	} else if (rule_id == 32 && tomcat_version_other != 1) {
		cJSON_AddNumberToObject(items, "status", 2);
	} else if (rule_id == 30 && nginx_pid <= 0) {
		cJSON_AddNumberToObject(items, "status", 2);
	} else {
		cJSON_AddNumberToObject(items, "status", res);
	}
	cJSON_AddItemToArray(array, items);

	cJSON_Delete(string_to_json);
}

void get_tomcat_version(char *path_tomcat)
{
	char path[S_PATHLEN] = {0};
	int tomcat_version = 0;
	FILE *fp = NULL;
	char *ptr = NULL;
	char line[S_LINELEN] = {0};

	snprintf(path, sizeof(path), "%scatalina.policy", tomcat_path);
	fp = fopen(path, "r");
	if (!fp) {
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		ptr = strstr(line, "Permissions for Tomcat");
		if (!ptr) {
			continue;
		}
		fclose(fp);
		sscanf(ptr, "%*s%*s%*s%d", &tomcat_version);
		if (tomcat_version == 5) {
			tomcat_version_five = 1;
		} else {
			tomcat_version_other = 1;
		}
		return;
	}
	fclose(fp);
	return;
}

int parse_baseline_database(task_recv_t *msg, int rule_id, int *whitelist_id, int white_size)
{
	sqlite3 *db = NULL;
	cJSON *object = NULL, *arguments = NULL;
	int nrow = 0, ncolumn = 0, nrow2 = 0, ncolumn2 = 0, ncolumn3 = 0, nrow3 = 0;
	char **azResult_category_id = NULL, **azResult_item_id = NULL, **azResult_rule = NULL;	// 二维数组存放结果
	char buf[1024] = {0};
	int rc = 0, search = 0;
	FILE *fp = NULL;
	char *post = NULL, *str_post = NULL;
	char reply[REPLY_MAX] = {0};
	int ret = 0;
	int j = 0, k = 0, iCen = 0;

	int i = 0;
	get_app_pid(baseline_app_info);

	while (baseline_app_info[i].name_app) {
		DBG2(DBGFLAG_BASELINE, "%s %d\n", baseline_app_info[i].sub_name, *baseline_app_info[i].pid);
		i++;
	}

	nginx_conf_path(nginx_pid);
	tomcat_conf_path(tomcat_pid);

	get_tomcat_version(tomcat_path);

	const char *select_category_id = "SELECT category_id FROM baseline_rule GROUP BY category_id;";

	if (msg == NULL || sniper_other_loadoff == 1) {
		return -1;
	}

	rc = sqlite3_open("/opt/snipercli/.download/baseline.dat", &db);

	if (rc != SQLITE_OK) {
		MON_ERROR("Can't open database: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return -1;
	}

	cJSON *final = cJSON_CreateObject();
	if (final == NULL) {
		cJSON_Delete(object);
		cJSON_Delete(arguments);
		return -1;
	}

	cJSON *array = cJSON_CreateArray();
	if (array == NULL) {
		cJSON_Delete(object);
		cJSON_Delete(arguments);
		cJSON_Delete(final);
		return -1;
	}

	sqlite3_get_table(db, select_category_id, &azResult_category_id, &nrow, &ncolumn, 0);

	snprintf(buf, sizeof(buf), "SELECT item_id FROM baseline_rule WHERE category_id = %d", rule_id);  // 通过category_id获取对应的所有的item_id
	sqlite3_get_table(db, buf, &azResult_item_id, &nrow2, &ncolumn2, 0);

	for (j = 1; j <= nrow2; j++) {
		snprintf(buf, sizeof(buf), "SELECT match_rule FROM baseline_rule WHERE item_id = %s", azResult_item_id[j]);  // 通过item_id获取对应的match_rule
		sqlite3_get_table(db, buf, &azResult_rule, &nrow3, &ncolumn3, 0);

		for (k = 1; k <= nrow3; k++) {
			/*如果是白名单检查项，则跳过*/
			search = 0;
			for (iCen = 0; iCen < white_size; iCen++) {
				if (whitelist_id[iCen] != 0) {
					if (atoi(azResult_item_id[j]) == whitelist_id[iCen]) {
						search = 1;
						break;
					}
				}
			}
			if (search) {
				continue;
			}

			fp = fopen("/opt/snipercli/baseline.json", "w");  // 将规则从大的数据表中取出，依次存入/opt/snipercli/baseline.json，方便检查
			fputs(azResult_rule[k], fp);
			fclose(fp);

			check_baseline(array, atoi(azResult_item_id[j]), rule_id);
		}
	}
	sqlite3_free_table(azResult_category_id);
	sqlite3_free_table(azResult_item_id);
	sqlite3_free_table(azResult_rule);

	sqlite3_close(db);  // 关闭数据库

	cJSON_AddStringToObject(final, "uuid", Sys_info.sku);

	cJSON_AddStringToObject(object, "cmd_id", msg->cmd_id);
	cJSON_AddNumberToObject(object, "cmd_type", msg->cmd_type);
	cJSON_AddNumberToObject(object, "result", 1);
	cJSON_AddNumberToObject(arguments, "category_id", rule_id);

	cJSON_AddItemToObject(arguments, "items", array);
	cJSON_AddItemToObject(object, "data", arguments);

	str_post = cJSON_PrintUnformatted(object);
	cJSON_Delete(object);

	cJSON_AddItemToObject(final, "data", cJSON_CreateString(str_post));

	post = cJSON_PrintUnformatted(final);
	ret = client_send_msg(post, reply, sizeof(reply), NOTIFY_URL, "task");

	DBG2(DBGFLAG_BASELINE, "基线检测---%s\n", post);

	cJSON_Delete(final);
	free(post);
	free(str_post);

	if (base_stop) {
		base_stop = 0;
		return -1;
	}

	return ret;
}

int baseline_stop(task_recv_t *msg)
{
	base_stop = 1;
	return 0;
}
