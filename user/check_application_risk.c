#include <pcre.h>
#include <regex.h>
#include <strings.h>

#include "header.h"

#define OVECCOUNT 30

#define key_auth_users 1
#define key_read_only 2

pid_t jenkins_pid = 0, es_pid = 0, mongod_pid = 0, squid_pid = 0, openvpn_pid = 0;
pid_t redis_pid = 0, weblogic_pid = 0, rsync_pid = 0, proftpd_pid = 0, jboss_pid = 0, jdwp_pid = 0;

static app_module risk_app_info[] = {
    {&tomcat_pid, "java", "tomcat"},
    {&solr_pid, "java", "solr"},
    {&nginx_pid, "nginx", "nginx"},
    {&mysql_pid, "mysqld", "mysqld"},
    {&apache_pid, "httpd", "httpd"},
    {&apache_pid, "apache2", "apache2"},
    {&jenkins_pid, "java", "jenkins"},
    {&es_pid, "java", "elasticsearch"},
    {&mongod_pid, "mongod", "mongod"},
    {&squid_pid, "squid", "squid"},
    {&redis_pid, "redis-server", "redis-server"},
    {&weblogic_pid, "java", "weblogic"},
    {&rsync_pid, "rsync", "rsync"},
    {&proftpd_pid, "proftpd", "proftpd"},
    {&jboss_pid, "java", "jboss"},
    {&openvpn_pid, "python3", "openvpn"},
    {&jdwp_pid, "java", "jdwp"},
    {0, NULL, NULL}};

sqlite3 *db = NULL;
char solr_path[S_LINELEN] = {0}, plugin_path[S_LINELEN] = {0};
char jenkins_path[S_LINELEN] = {0}, jboss_path[S_LINELEN] = {0};
char weblogic_path[S_LINELEN] = {0};

/* 父进程和当前进程name相同，则继续找父进程 */
static pid_t compare_parent_name(pid_t pid, pid_t ppid, char *task_name)
{
	FILE *fp = NULL;
	char path[S_PATHLEN] = {0};
	char buf[S_LINELEN] = {0};
	char name[S_NAMELEN] = {0};
	pid_t pppid = 0;

	if (!task_name) {
		return 0;
	}
	if (ppid == 1) {
		return pid;
	}

	snprintf(path, S_PATHLEN, "/proc/%d/status", ppid);
	fp = fopen(path, "r");
	if (!fp) {
		return 0;
	}

	fgets(buf, S_LINELEN, fp);
	sscanf(buf, "Name: %63s", name);

	while (fgets(buf, S_LINELEN, fp)) {
		if (sscanf(buf, "PPid: %d", &pppid) == 1) {
			break;
		}
	}
	if (strcmp(name, task_name) == 0) {  // 父进程名与本进程相同，继续往上查
		fclose(fp);
		return compare_parent_name(ppid, pppid, name);
	}
	fclose(fp);
	return pid;
}

/*
 * 遍历/proc目录，查找应用进程
 * 对于java应用，app_name和cmd_name不同，如tomcat/solr的进程名是java
 * 对于非java应用，app_name和cmd_name通常相同，如mysqld的进程名就是mysqld
 *
 * TODO 对于cmd_name和app_name相同的情况，是否要考虑下面这种情况
 * 假设有个脚本名叫mysqld，然后这个脚本起了mysqld的服务进程
 *
 */
void get_app_pid(app_module *app_info)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	int i = 0;

	dirp = opendir("/proc");
	if (NULL == dirp) {
		return;
	}

	i = 0;
	while (app_info[i].name_app) {
		*app_info[i].pid = 0;
		i++;
	}

	while ((ent = readdir(dirp)) != NULL) {
		FILE *fp = NULL;
		char buf[S_LINELEN] = {0};
		char filepath[S_LINELEN] = {0};
		char cmdline[4096] = {0};
		char task_name[64] = {0};
		pid_t pid = 0, ppid = 0;

		if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
			continue;  // 忽略非进程项信息
		}

		pid = atoi(ent->d_name);
		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue;  // 忽略内核线程
		}

		snprintf(filepath, S_LINELEN, "/proc/%s/status", ent->d_name);
		fp = fopen(filepath, "r");
		if (!fp) {
			continue;
		}

		fgets(buf, S_LINELEN, fp);
		sscanf(buf, "Name: %63s", task_name);

		if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
			fclose(fp);
			continue;
		}

		while (fgets(buf, S_LINELEN, fp)) {
			if (sscanf(buf, "PPid: %d", &ppid) == 1) {
				break;
			}
		}
		fclose(fp);

		i = 0;
		while (app_info[i].name_app) {
			if (strcmp(task_name, app_info[i].name_app) == 0 &&
			    strstr(cmdline, app_info[i].sub_name)) {
				*app_info[i].pid = compare_parent_name(pid, ppid, task_name);
				break;
			}
			i++;
		}
	}
	closedir(dirp);
}

void mysql_plugin_path(pid_t pid)
{
	char *set = NULL;
	char cmdline[4096] = {0};

	if (pid <= 0) {
		return;
	}

	if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	set = strstr(cmdline, "--plugin-dir=");
	if (!set) {
		INFO("NO plugin dir\n");
		return;
	}

	set += strlen("--plugin-dir=");

	sscanf(set, "%s", plugin_path);
	if (plugin_path[0] == 0) {
		INFO("NO plugin dir\n");
		return;
	}

	INFO("plugin dir: %s\n", plugin_path);
}

void weblogic_conf_path(pid_t pid)
{
	char *set = NULL, *ptr = NULL;
	char cmdline[4096] = {0};

	if (pid <= 0) {
		return;
	}

	if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	set = strstr(cmdline, "-Dweblogic.home=");
	if (!set) {
		INFO("NO weblogic path\n");
		return;
	}

	set += strlen("-Dweblogic.home=");

	ptr = strstr(set, "/wlserver");
	if (!ptr) {
		INFO("NO weblogic path\n");
		return;
	}

	*(ptr + 1) = 0;
	snprintf(weblogic_path, sizeof(weblogic_path), "%s", set);
	INFO("weblogic conf path: %s\n", weblogic_path);
}

void jenkins_conf_path(pid_t pid)
{
	char *set = NULL;
	char cmdline[4096] = {0};

	if (pid <= 0) {
		return;
	}

	if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	set = strstr(cmdline, "-DJENKINS_HOME=");
	if (!set) {
		INFO("NO jenkins conf file\n");
		return;
	}

	set += strlen("-DJENKINS_HOME=");

	sscanf(set, "%s", jenkins_path);
	if (jenkins_path[0] == 0) {
		INFO("NO jenkins conf file\n");
		return;
	}

	INFO("jenkins conf dir: %s\n", jenkins_path);
}

/*
 *-Djava.net.preferIPv4Stack=true -Djava.endorsed.dirs=/home/zzh/jboss-5.1.0.GA/lib/endorsed -classpath /home/zzh/jboss-5.1.0.GA/bin/run.jar org.jboss.Main
 *TODO 上面为命令行中带有配置目录的情况，还要考虑是否还有其他情况
 */
void jboss_conf_path(pid_t pid)
{
	char *set = NULL, *ptr = NULL;
	char cmdline[4096] = {0};

	if (pid <= 0) {
		return;
	}

	if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	set = strstr(cmdline, "-Djava.endorsed.dirs=");
	if (!set) {
		INFO("NO jboss home dir\n");
		return;
	}

	set += strlen("-Djava.endorsed.dirs=");	 // 例：-Djava.endorsed.dirs=/home/zzh/jboss-5.1.0.GA/lib/endorsed取/lib之前的路径为主目录
	ptr = strstr(set, "/lib");
	if (ptr) {
		*ptr = 0;
	}

	sscanf(set, "%s", jboss_path);

	if (jboss_path[0] == 0) {
		INFO("NO jboss home dir\n");
		return;
	}

	INFO("jboss conf dir: %s\n", jboss_path);
}

#if 0
//从命令行中取openvpn的logfile——path
void vpn_log_path(pid_t pid)
{
    char *set = NULL;
    char cmdline[4096] = {0};

    if (get_proc_cmdline(pid, cmdline, sizeof(cmdline)) < 0) {
        return;
    }

    set = strstr(cmdline, "--logfile=");
    if (!set) {
        INFO("NO openvpn log file\n");
        return;
    }

    set += strlen("--logfile="); //例：-Djava.endorsed.dirs=/home/zzh/jboss-5.1.0.GA/lib/endorsed取/lib之前的路径为主目录

    sscanf(set, "%s", vpn_logpath);

    if (vpn_logpath[0] == 0) {
        INFO("NO openvpn log file\n");
        return;
    }

    INFO("openvpn log file: %s\n", vpn_logpath);
}
#endif

static int ignore_risk_key(char *key)
{
	char *item = NULL;
	int i, j, sys_num, list_num;

	sys_num = rule_white_global.risk.sys_num;
	for (i = 0; i < sys_num; i++) {
		list_num = rule_white_global.risk.sys[i].rule.list_num;
		for (j = 0; j < list_num; j++) {
			item = rule_white_global.risk.sys[i].rule.list[j].list;
			if (strcmp(item, key) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

int sregular_match(char *bematch, char *pattern)
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

/* 取tomcat配置目录 */
void solr_conf_path(pid_t pid)
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
	set = strstr(cmdline, "-Xloggc:");
	if (!set) {
		INFO("NO solr conf file\n");
		return;
	}

	set += strlen("-Xloggc:");

	ptr = strstr(set, "/log");
	if (!ptr) {
		INFO("NO tomcat conf file\n");
		return;
	}

	*(ptr + 1) = 0;
	snprintf(solr_path, S_LINELEN, "%s", set);
	INFO("solr conf dir: %s\n", solr_path);
}

int check_app_uid_gid(pid_t *pid)
{
	FILE *fp = NULL;
	char path[S_NAMELEN] = {0};
	char line[S_LINELEN] = {0};
	char field[S_NAMELEN] = {0};
	int id = 0, Uid = 0, Gid = 0;

	snprintf(path, S_NAMELEN, "/proc/%d/status", *pid);
	fp = fopen(path, "r");
	if (!fp) {
		DBG2(DBGFLAG_SYSDANGER, "get_status open /proc/status fail: %s\n", strerror(errno));
		return 1;
	}

	while (fgets(line, S_LINELEN, fp)) {
		sscanf(line, "%s %d", field, &id);
		if (strcmp(field, "Uid:") == 0) {
			Uid = id;
		}
		if (strcmp(field, "Gid:") == 0) {
			Gid = id;
		}
	}

	fclose(fp);

	if (Uid == 0 || Gid == 0) {
		return 0;
	}
	return 1;
}

static int check_line_value(char *path, char *key, char *value, cJSON *log_value)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	fp = fopen(path, "r");
	if (!fp) {
		return -1;
	}
	cJSON_AddItemToArray(log_value, cJSON_CreateString("check_line_value"));

	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, key)) {
			continue;
		}
		fclose(fp);
		if (strcmp(key, "allow-query") == 0) {
			if (strstr(line, value)) {
				return 0;
			} else {
				return 1;
			}
		}
		if (strcmp(key, "allow-recursion") == 0) {
			if (strstr(line, value) || strstr(line, "no")) {
				return 1;
			} else {
				return 0;
			}
		}
		if (strcmp(key, "OPTIONS") == 0) {
			if (strstr(line, value)) {
				return 1;
			} else {
				return 0;
			}
		}
		MON_ERROR("%s in check_line_value is invalid\n", key);
		break;
	}
	fclose(fp);
	return 0;
}

/*
 *默认配置是将该行注释掉了，所以按照该检查项描述，符合未被修改的情况，故该项也应为不通过。
 *现检查过程中会跳过判断有没有配置rename-command。
 *如果配置了该字段，再看有没有在双引号中配置内容。
 */
void app_check_redis_config_not_update(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0, ret = 0;

	if (ignore_risk_key("app_check_redis_config_not_update")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_redis_config_not_update");
	fp = fopen("/etc/redis.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "rename-command")) {
			continue;
		}

		ret = 1;
		if (strstr(line, "\"\"")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

/* NFS服务允许未授权访问 */
void app_check_nfs_noauth_visit(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_nfs_noauth_visit")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fp = fopen("/etc/exports", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nfs_noauth_visit");

	while (fgets(line, S_LINELEN, fp)) {
		if (strstr(line, "*")) {
			ret = 1;
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			break;
		}
	}

	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_ntp_enlarge_dos_attack(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_ntp_enlarge_dos_attack")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_ntp_enlarge_dos_attack");
	fp = fopen("/etc/ntp.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}

		if (strstr(line, "disable monitor")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

/* Memcache服务存在UDP端口ping-pong攻击/DDOS反射放大漏洞 -- 检查memcached是否侦听UDP端口，且外网可访问 */
void app_check_memcache_udp_listening(cJSON *array)
{
	int ret = 0;
	if (ignore_risk_key("app_check_memcache_udp_listening")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_memcache_udp_listening");

	ret = check_line_value("/etc/sysconfig/memcached", "OPTIONS", "-U 0", value);
	if (ret == -1 || ret == 1) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_vsftpd_chroot_local_user(cJSON *array)
{
	int fd = 0, len = 0;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;
	char *ptr = NULL;
	char buf[S_PATHLEN] = {0};

	if (ignore_risk_key("app_check_vsftpd_chroot_local_user")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_vsftpd_chroot_local_user");
	fp = fopen("/etc/vsftpd/vsftpd.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "chroot_local_user")) {
			if (strstr(line, "NO")) {
				ca = 1;
				break;
			}
		}

		ptr = strstr(line, "chroot_list_file=");
		if (ptr) {
			ptr += strlen("chroot_list_file=");
			sscanf(ptr, "%s", buf);
		}
	}

	fclose(fp);

	if (ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		fd = open(buf, O_RDONLY);
		if (fd < 0) {
			cJSON_Delete(value);
			cJSON_Delete(arguments);
			return;
		}

		len = read(fd, line, sizeof(line));
		close(fd);
		if (len > 0) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		} else {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
		}
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

/* SSH服务AuthorizedKeysFile配置名称被修改--
   检测sshd_config文件，并分析认证授权文件“AuthorizedKeysFile”是否位于文件最后一行，且该配置项是否被修改 */
void app_check_ssh_authorized_keys_file(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int rc = 0, ret = 0;
	char key[S_NAMELEN] = {0};

	if (ignore_risk_key("app_check_ssh_authorized_keys_file")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fp = fopen("/etc/ssh/sshd_config", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		DBG2(DBGFLAG_SYSDANGER, "NO FILE /etc/ssh/sshd_config\n");
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_ssh_authorized_keys_file");

	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "AuthorizedKeysFile")) {
			ret = 1;
			sscanf(line, "%*s %s", key);
			if (strcmp(key, ".ssh/authorized_keys") == 0) {
				rc = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (!rc && ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
	return;
}

char suspicious_ext[][8] = {"pem", "key", ""};
static int check_suspicious_file_inpath(char *path, cJSON *value)
{
	int i = 0;
	DIR *Dir = NULL;
	struct dirent *ent = NULL;
	char *ext = NULL, subpath[PATH_MAX] = {0}, filepath[PATH_MAX] = {0};

	if (!path) {
		return 0;
	}

	Dir = opendir(path);
	if (!Dir) {
		return 0;
	}

	while ((ent = readdir(Dir)) != NULL) {
		if (DT_DIR == ent->d_type) {  // 查子目录
			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
				continue;
			}

			snprintf(subpath, PATH_MAX, "%s/%s", path, ent->d_name);
			if (check_suspicious_file_inpath(subpath, value)) {
				/* 找到可疑文件，结束检查 */
				closedir(Dir);
				return 1;
			}
			continue;
		}

		/* 查文件 */
		if (ent->d_name[0] == '.') {  //.开头的文件忽略开头的.
			ext = strrchr(ent->d_name + 1, '.');
		} else {
			ext = strrchr(ent->d_name, '.');
		}
		if (ext == NULL) {
			continue;
		}
		ext++;

		/* 检查文件是否命中某种文件类型 */
		i = 0;
		while (suspicious_ext[i][0]) {
			if (strcmp(ext, suspicious_ext[i]) == 0) {
				/* 记录找到的可疑文件 */
				snprintf(filepath, PATH_MAX, "%s/%s", path, ent->d_name);
				cJSON_AddItemToArray(value, cJSON_CreateString(filepath));

				/* 找到一个可疑文件，结束检查 */
				closedir(Dir);
				return 1;
			}
			i++;
		}
	}
	closedir(Dir);

	return 0;
}

void app_check_ssh_homefile_have_key(cJSON *array)
{
	int ret = 0;

	if (ignore_risk_key("app_check_ssh_homefile_have_key")) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		cJSON_Delete(arguments);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_ssh_homefile_have_key");

	ret = check_suspicious_file_inpath("/home", value);
	if (ret == 0) {						  // 没有可疑密钥
		cJSON_AddNumberToObject(arguments, "status", 1);  // 没有风险
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);  // 有风险
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_rsync_root_running(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_rsync_root_running")) {
		return;
	}

	if (rsync_pid <= 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_rsync_root_running");

	if (check_app_uid_gid(&rsync_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(array, arguments);
		return;
	}

	fp = fopen("/etc/rsyncd.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "uid") || !strstr(line, "gid")) {
			continue;
		}
		if (!strstr(line, "rsync")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			ca = 1;
			break;
		}
	}
	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void get_vpnconf_file(pid_t *pid, char *path)
{
	int fd = 0;
	char conf_path[S_PATHLEN] = {0};
	char line[S_LINELEN] = {0};
	char *ptr = NULL, *set = NULL;
	int len = 0;
	char *end = NULL, *tmp = NULL;

	if (!pid) {
		return;
	}

	snprintf(conf_path, S_PATHLEN, "/proc/%d/environ", *pid);

	fd = open(conf_path, O_RDONLY);
	len = read(fd, line, sizeof(line));

	end = line + len;
	for (tmp = line; tmp < end; tmp++) {
		if (*tmp == 0) {
			*tmp = ' ';
		}
	}
	close(fd);

	ptr = strstr(line, "OPENVPN_AS_CONFIG=");
	if (ptr) {
		ptr += strlen("OPENVPN_AS_CONFIG=");
		set = strstr(ptr, "PYTHONUNBUFFERED");
		if (set) {
			*set = 0;
		}
		strcpy(path, ptr);
		close(fd);
		return;
	}

	close(fd);
}

void app_check_openvpn_unuse_key(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0, cert = 0, key = 0;
	char path[S_PATHLEN] = {0};
	char title[S_NAMELEN] = {0};

	if (ignore_risk_key("app_check_openvpn_unuse_key")) {
		return;
	}

	if (openvpn_pid <= 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (access("/etc/openvpn/server.conf", F_OK) == 0) {
		snprintf(path, S_PATHLEN, "%s", "/etc/openvpn/server.conf");
	} else {
		get_vpnconf_file(&openvpn_pid, path);
	}

	path[strlen(path) - 1] = 0;
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_openvpn_unuse_key");
	fp = fopen(path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		sscanf(line, "%s", title);
		if (strcmp(title, "ca") == 0) {
			ca = 1;
		}
		if (strcmp(title, "cert") == 0) {
			cert = 1;
		}
		if (strcmp(title, "key") == 0) {
			key = 1;
		}
	}
	fclose(fp);
	if (ca && cert && key) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_mongodb_rest_interface_enable(cJSON *array)
{
	char cmdline[4096] = {0};

	if (ignore_risk_key("app_check_mongodb_rest_interface_enable")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (mongod_pid <= 0) {
		return;
	}

	if (get_proc_cmdline(mongod_pid, cmdline, sizeof(cmdline)) < 0) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	if (strstr(cmdline, "--rest")) {  // 启动mongodb时添加--rest参数,有风险
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_mongodb_rest_interface_enable");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_rsync_auth_users_empty(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;
	char *ptr = NULL;
	char set[S_LINELEN] = {0};

	if (ignore_risk_key("app_check_rsync_auth_users_empty")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_rsync_auth_users_empty");
	fp = fopen("/etc/rsyncd.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "auth users")) {
			continue;
		}

		ptr = strstr(line, "=");
		if (!ptr) {
			continue;
		}
		sscanf(ptr + 1, "%s", set);

		if (set[0] == 0) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_rsync_readonly_true(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_rsync_readonly_true")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_rsync_readonly_true");
	fp = fopen("/etc/rsyncd.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "read only")) {
			continue;
		}

		if (!strstr(line, "true")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_mongodb_open_auth(cJSON *array)
{
	char cmdline[4096] = {0};

	if (ignore_risk_key("app_check_mongodb_open_auth")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (mongod_pid <= 0) {
		return;
	}

	if (get_proc_cmdline(mongod_pid, cmdline, sizeof(cmdline)) < 0) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	if (strstr(cmdline, "--auth")) {  // 启动mongodb时添加--auth参数,没有风险
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_mongodb_open_auth");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_bind_allow_transfer(cJSON *array)
{
	int ret = 0;

	if (ignore_risk_key("app_check_bind_allow_transfer")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_bind_allow_transfer");

	ret = check_line_value("/etc/named.conf", "allow-query", "any", value);
	if (ret == -1 || ret == 1) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_bind_allow_recursion(cJSON *array)
{
	int ret = 0;

	if (ignore_risk_key("app_check_bind_allow_recursion")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_bind_allow_recursion");

	ret = check_line_value("/etc/named.conf", "allow-recursion", "none", value);
	if (ret == -1 || ret == 1) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_vsftpd_login_otherway(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *ptr = NULL;
	char *set = NULL;
	char content1[S_NAMELEN] = {0}, content2[S_NAMELEN] = {0};
	char username[S_NAMELEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_vsftpd_login_otherway")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_vsftpd_login_otherway");
	fp = fopen("/etc/vsftpd/vsftpd.conf", "r");
	if (!fp) {
		fp = fopen("/etc/vsftpd.conf", "r");
	}
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		ptr = skip_headspace(line);
		if (*ptr == '#') {
			continue;
		}
		if (strstr(ptr, "guest_enable")) {
			set = strstr(ptr, "=");
			if (set) {
				sscanf(set + 1, "%s", content1);
			}
		}

		if (strstr(ptr, "guest_username")) {
			set = strstr(ptr, "=");
			if (set) {
				sscanf(set + 1, "%s", content2);
			}
		}
	}
	fclose(fp);
	if (content1[0] == 0 || content2[0] == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		goto end;
	}

	if (strcasecmp(content1, "yes") != 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		goto end;
	}

	fp = fopen("/etc/passwd", "r");
	while (fgets(line, S_LINELEN, fp)) {
		sscanf(line, "%[^:]", username);
		if (strcmp(username, content2) == 0) {
			if (strstr(line, "/sbin/nologin") || strstr(line, "/bin/false")) {
				ret = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

end:
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_vsftpd_anonymous_enable(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_vsftpd_anonymous_enable")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_vsftpd_anonymous_enable");
	fp = fopen("/etc/vsftpd/vsftpd.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "anonymous_enable")) {
			continue;
		}

		if (strstr(line, "YES")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_squid_acl_http_access(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_squid_acl_http_access")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_squid_acl_http_access");
	fp = fopen("/etc/squid/squid.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "http_access")) {
			if (strstr(line, "allow all")) {
				ca = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_squid_proxy_host(cJSON *array)
{
	FILE *pcmd = NULL;
	char line[S_LINELEN] = {0};
	int ret = 0, num = 0, num1 = 0, num2 = 0;
	char *ptr = NULL;
	char cmdline[S_ARGSLEN] = {0};
	char path[S_PATHLEN] = {0};

	if (ignore_risk_key("app_check_squid_proxy_host")) {
		return;
	}

	if (squid_pid <= 0) {  // 先看进程在不在，不在直接返回没有风险，符合条件，未安装的情况自然也是没有风险
		return;
	}
	if (get_proc_exe(squid_pid, cmdline) < 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_squid_proxy_host");
	snprintf(path, S_PATHLEN, "%s -v", cmdline);

	pcmd = popen(path, "r");
	if (!pcmd) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, pcmd)) {
		ptr = strstr(line, "Version");
		if (!ptr) {
			continue;
		}
		ret = sscanf(ptr, "%*s%d.%d.%d", &num, &num1, &num2);
		if (ret != 3) {
			pclose(pcmd);
			cJSON_Delete(value);
			cJSON_Delete(arguments);
			return;
		}
		break;
	}
	if (num > 3 || (num == 3 && num1 > 1) || (num == 3 && num1 == 1 && num2 >= 20)) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}
	pclose(pcmd);
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_mysql_skip_grant_tables(cJSON *array)
{
	char cmdline[4096] = {0};

	if (ignore_risk_key("app_check_mysql_skip_grant_tables")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (mysql_pid <= 0) {
		return;
	}

	if (get_proc_cmdline(mysql_pid, cmdline, sizeof(cmdline)) < 0) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	if (strstr(cmdline, "--skip-grant-tables")) {  // 启动mysql时添加--skip-grant-tables参数,有风险
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_mysql_skip_grant_tables");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_mysql_root_auth(cJSON *array)
{
	if (mysql_pid <= 0) {
		return;
	}

	if (ignore_risk_key("app_check_mysql_root_auth")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_mysql_root_auth");

	if (check_app_uid_gid(&mysql_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

/* MySQL安全插件 */
char so_file_ext[][64] = {"adt_null.so", "auth_socket.so", "connection_control.so",
			  "innodb_engine.so", "libmemcached.so", "mysql_no_login.so",
			  "qa_auth_interface.so", "semisync_master.so", "test_udf_services.so",
			  "validate_password.so", "auth.so", "auth_test_plugin.so",
			  "ha_example.so", "libdaemon_example.so", "mypluglib.so",
			  "qa_auth_client.so", "qa_auth_server.so", "semisync_slave.so",
			  "udf_example.so", "validate_password.so", "connection_control.so",
			  "libaudit_plugin.so", "mysql_native_password.so", ""};
static int check_sofile_dir_inpath(char *path, cJSON *value)
{
	int i = 0;
	DIR *Dir = NULL;
	struct dirent *ent = NULL;

	if (!path) {
		return 0;
	}

	Dir = opendir(path);
	if (!Dir) {
		return 0;
	}

	while ((ent = readdir(Dir)) != NULL) {
		int res = 0;

		if (DT_DIR == ent->d_type) {  // 跳过子目录
			continue;
		}

		if (!strstr(ent->d_name, ".so")) {
			continue;
		}

		i = 0;
		while (so_file_ext[i][0]) {
			if (strcmp(ent->d_name, so_file_ext[i]) == 0) {
				res = 1;
				break;
			}
			i++;
		}
		if (!res) {
			closedir(Dir);
			return 1;
		}
	}
	closedir(Dir);

	return 0;
}

void app_check_mysql_plugin_sofile(cJSON *array)
{
	int ret = 0;
	char *path = NULL;

	if (ignore_risk_key("app_check_mysql_plugin_sofile")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_mysql_plugin_sofile");

	if (plugin_path[0] == 0) {
		if (access("/usr/lib64/mysql/plugin", F_OK) == 0) {
			path = "/usr/lib64/mysql/plugin";
		} else {
			path = "/usr/lib/mysql/plugin";
		}
	} else {
		path = plugin_path;
	}

	ret = check_sofile_dir_inpath(path, value);
	if (ret == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);  // 没有风险
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);  // 有风险
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_mysql_test_database(cJSON *array)
{
	if (ignore_risk_key("app_check_mysql_test_database")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (access("/var/lib/mysql/test", F_OK) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_mysql_test_database");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

int check_dir_cvs(char *path)
{
	DIR *dirp = NULL;
	struct dirent *ptr;
	char subpath[PATH_MAX] = {0};

	dirp = opendir(path);
	if (!dirp) {
		return 0;
	}

	while ((ptr = readdir(dirp)) != NULL) {
		if (ptr->d_type != DT_DIR) {
			continue;
		}
		if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
			continue;
		}

		if (strstr(ptr->d_name, "cvs") || strstr(ptr->d_name, "CVS")) {
			closedir(dirp);
			return 1;
		}
		snprintf(subpath, PATH_MAX, "%s/%s", path, ptr->d_name);
		if (check_dir_cvs(subpath)) {
			/* 找到可疑目录，结束检查 */
			closedir(dirp);
			return 1;
		}
	}
	closedir(dirp);
	return 0;
}

/* CVS服务目录信息泄漏 */
void app_check_cvs_store_file(cJSON *array)
{
	int ret = 0;
	if (ignore_risk_key("app_check_cvs_store_file")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_cvs_store_file");

	ret = check_dir_cvs("/var/www/html");

	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_elasticsearch_disable_dynamic(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;
	char *set = NULL;
	int value1 = 0, value2 = 0, value3 = 0;

	if (ignore_risk_key("app_check_elasticsearch_disable_dynamic")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_elasticsearch_disable_dynamic");
	fp = fopen("/etc/elasticsearch/elasticsearch.yml", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "script.disable_dynamic")) {
			continue;
		}

		if (strstr(line, "true")) {
			ca = 1;
			break;
		}
	}

	fclose(fp);

#ifdef SNIPER_FOR_DEBIAN
	fp = popen("dpkg -l | grep elasticsearch", "r");
#else
	fp = popen("rpm -qa | grep elasticsearch", "r");
#endif

	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	fgets(line, S_LINELEN, fp);

	set = strstr(line, "elasticsearch-");
	if (!set) {
		return;
	}
	set += strlen("elasticsearch-");

	sscanf(set, "%d.%d.%d", &value1, &value2, &value3);
	if ((value1 > 1 || value2 > 4 || value3 > 6) && ca == 1) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	pclose(fp);
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_elasticsearch_groovy_sandbox(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_elasticsearch_groovy_sandbox")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_elasticsearch_groovy_sandbox");
	fp = fopen("/etc/elasticsearch/elasticsearch.yml", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "script.groovy.sandbox.enabled")) {
			continue;
		}

		if (strstr(line, "false")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

/* CVS服务存在文件信息泄漏 */
char cvs_file_ext[][64] = {"passwd", "readers", "writers", "Root", "Entries", "Repository", ""};
static int check_suspicious_dir_inpath(char *path, cJSON *value)
{
	int i = 0;
	DIR *Dir = NULL;
	struct dirent *ent = NULL;
	char subpath[PATH_MAX] = {0}, filepath[PATH_MAX] = {0};

	if (!path) {
		return 0;
	}

	Dir = opendir(path);
	if (!Dir) {
		return 0;
	}

	while ((ent = readdir(Dir)) != NULL) {
		if (DT_DIR == ent->d_type) {  // 查子目录
			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
				continue;
			}

			snprintf(subpath, PATH_MAX, "%s/%s", path, ent->d_name);
			if (check_suspicious_dir_inpath(subpath, value)) {
				/* 找到可疑文件，结束检查 */
				closedir(Dir);
				return 1;
			}
			continue;
		}

		i = 0;
		while (cvs_file_ext[i][0]) {
			if (strcmp(ent->d_name, cvs_file_ext[i]) == 0) {
				/* 记录找到的可疑文件 */
				snprintf(filepath, PATH_MAX, "%s/%s", path, ent->d_name);
				cJSON_AddItemToArray(value, cJSON_CreateString(filepath));
				/* 找到一个可疑文件，结束检查 */
				closedir(Dir);
				return 1;
			}
			i++;
		}
	}
	closedir(Dir);

	return 0;
}

void app_check_cvs_file_divulge(cJSON *array)
{
	int ret = 0;

	if (ignore_risk_key("app_check_cvs_file_divulge")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_cvs_file_divulge");

	ret = check_suspicious_dir_inpath("/var/www/html/", value);
	if (ret == 0) {							      // 没有可疑文件目录
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);  // 没有风险
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);  // 有风险
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

/* ElasticSearch 1.4.5之前版本和1.5.2之前1.5.x版本中存在目录遍历漏洞 */
void app_check_elasticsearch_site_readall(cJSON *array)
{
	int value1 = 0, value2 = 0, value3 = 0;
	char cmdline[4096] = {0};
	char *set = NULL;

	if (ignore_risk_key("app_check_elasticsearch_site_readall")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (es_pid <= 0) {
		return;
	}

	if (get_proc_cmdline(es_pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	set = strstr(cmdline, "elasticsearch-");
	if (!set) {
		INFO("NO elasticsearch home file\n");
		return;
	}

	set += strlen("elasticsearch-");
	if (sscanf(set, "%d.%d.%d", &value1, &value2, &value3) == 3) {
		DBG2(DBGFLAG_SYSDANGER, "elasticsearch version:%d.%d.%d\n", value1, value2, value3);  // 1.4.5之前版本和1.5.2之前1.5.x版本中存在目录遍历漏洞
		if ((value1 == 1 && value2 > 5) || (value1 == 1 && value2 == 5 && value3 >= 2) || (value1 == 1 && value2 == 4 && value3 >= 5)) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
		} else {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		}
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_elasticsearch_site_readall");

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_elasticsearch_running_byroot(cJSON *array)
{
	if (ignore_risk_key("app_check_elasticsearch_running_byroot")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_elasticsearch_running_byroot");

	if (check_app_uid_gid(&es_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
	return;
}

/*VNC服务存在认证绕过 -- 检测VNC的版本
 *版本低于4.1则存在安全漏洞
 */
void app_check_vnc_auth_passaway(cJSON *array)
{
	FILE *fp = NULL;
	char *ptr = NULL;
	char line[S_LINELEN] = {0};
	int first_num = 0, second_num = 0;

	if (ignore_risk_key("app_check_vnc_auth_passaway")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

#ifdef SNIPER_FOR_DEBIAN
	fp = popen("dpkg -l | grep realvnc", "r");
#else
	fp = popen("rpm -qa | grep realvnc", "r");
#endif
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	fgets(line, S_LINELEN, fp);
	ptr = line;
	while (*ptr && ((*ptr > '9') || (*ptr < '0'))) {  // 从数字开始取
		ptr++;
	}

	pclose(fp);
	if (sscanf(ptr, "%d.%d", &first_num, &second_num) != 2) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	DBG2(DBGFLAG_SYSDANGER, "realvnc version:%d.%d\n", first_num, second_num);
	if (first_num > 4 || (first_num == 4 && second_num > 1)) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_vnc_auth_passaway");

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
	return;
}

void app_check_svn_store_catalogue(cJSON *array)
{
	if (ignore_risk_key("app_check_svn_store_catalogue")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (access("/var/www/html/svn/.svn", F_OK) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_svn_store_catalogue");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_svn_entries_file(cJSON *array)
{
	if (ignore_risk_key("app_check_svn_entries_file")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (access("/var/www/html/svn/.svn/entries", F_OK) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_svn_entries_file");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_tomcat_put_readonly(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, path[S_PATHLEN] = {0};
	int ca = 0;
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	if (ignore_risk_key("app_check_tomcat_put_readonly")) {
		return;
	}

	if (tomcat_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_PATHLEN, "%sweb.xml", tomcat_path);

	fp = fopen(path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_tomcat_put_readonly");
	while (fgets(line, S_LINELEN, fp)) {
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
		if (strstr(line, "readonly")) {
			ca = 1;
			break;
		}
	}
	if (!ca) {
		fclose(fp);
		return;
	}
	fgets(line, S_LINELEN, fp);
	if (line[0] != 0 && line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;

	if (strstr(line, "false")) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	fclose(fp);

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_mysql_user_uid_gid(cJSON *array)
{
	if (ignore_risk_key("app_check_mysql_user_uid_gid")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_mysql_user_uid_gid");

	if (check_app_uid_gid(&mysql_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
	return;
}

int type_sscanf(char *value1, char *home_path)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;

	if (home_path[0] == 0) {  // 没有配置cgi目录，无风险
		return 0;
	}

	if (value1[0] == 0) {  // 没有指定cgi文件后缀，使用.cgi当作后缀名
		snprintf(value1, S_NAMELEN, "%s", ".cgi");
	}

	dirp = opendir(home_path);
	if (!dirp) {
		return 0;
	}

	while ((ent = readdir(dirp)) != NULL) {
		if (strstr(ent->d_name, value1)) {  // 从目录中看是否带有cgi后缀的文件
			DBG2(DBGFLAG_SYSDANGER, "cgi file: %s\n", ent->d_name);
			closedir(dirp);
			return 1;
		}
	}
	closedir(dirp);
	return 0;
}

void app_check_apache_cgi_file(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char key[S_NAMELEN] = {0};
	char home_path[S_LINELEN] = {0};
	char *ptr = NULL, *str = NULL;
	char *skip_head = NULL;
	char value1[S_NAMELEN] = {0};
	int ret = 0, rc = 0;

	if (ignore_risk_key("app_check_apache_cgi_file")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fp = fopen("/etc/httpd/conf/httpd.conf", "r");
	if (!fp) {
		fp = fopen("/etc/apache2/apache2.conf", "r");
	}
	if (!fp) {
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		char *buf = NULL, *set = NULL;
		unsigned int s_len = 0;
		ptr = skip_headspace(line);

		if (*ptr == '#') {
			continue;
		}

		if (sscanf(ptr, "%s", key) != 1) {
			continue;
		}
		if (strcasecmp(key, "ScriptAlias") == 0) {  // 先在conf中找配置的cgi文件目录
			sscanf(ptr, "%*[^\"]\"%[^\"]", home_path);
		}
		if (strcmp(key, "AddHandler") == 0) {
			str = strstr(ptr, "cgi-script");
			if (str) {
				str += strlen("cgi-script");
				skip_head = skip_headspace(str);
				buf = skip_head;  // 偏移用字符指针
				s_len = strlen(skip_head);
				while (buf < skip_head + s_len) {   // 判断是否已经到skip_head字符串末尾
					sscanf(buf, "%s", value1);  // 源字符串为p，不是s
					ret = type_sscanf(value1, home_path);
					if (ret) {
						rc = 1;
						break;
					}
					set = buf + strlen(value1);  // 偏移到下一个字符串
					buf = skip_headspace(set);
				}
				if (rc) {
					break;
				}
			}
		}
	}
	fclose(fp);

	if (rc) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_apache_cgi_file");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

#if 1
void app_check_apache_http_host(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ServerName = 0, UseCanonicalName = 0;
	char val[S_NAMELEN] = {0};

	if (ignore_risk_key("app_check_apache_http_host")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_apache_http_host");

	fp = fopen("/etc/httpd/conf/httpd.conf", "r");
	if (!fp) {
		fp = fopen("/etc/apache2/apache2.conf", "r");
	}
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "ServerName")) {
			ServerName = 1;
		}
		if (strstr(line, "UseCanonicalName")) {
			if (sscanf(line, "%*s%s", val) != 1) {
				continue;
			}
			if (strcmp(val, "On") == 0) {
				ServerName = 1;
			}
		}
	}

	fclose(fp);
	if (UseCanonicalName && ServerName) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}
#endif

void app_check_nginx_location_alias(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0, cert = 0;

	if (ignore_risk_key("app_check_nginx_location_alias")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_location_alias");
	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "location")) {
			if (strstr(line, "/")) {
				ca = 1;
			}
		}
		if (strstr(line, "alias")) {
			if (strstr(line, "/")) {
				cert = 1;
			}
		}
	}
	fclose(fp);
	if (ca && cert) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

#if 1
void app_check_nginx_http_header(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *tmp = NULL;
	int start = 0;
	int father_header = 0, son_header = 0;

	if (ignore_risk_key("app_check_nginx_http_header")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_http_header");

	fp = fopen(nginx_path, "r");

	if (!fp) {
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		delete_tailspace(line);
		tmp = skip_headspace(line);

		if (*tmp == '#') {
			continue;
		}

		if (start) {
			if (strstr(tmp, "add_header")) {
				son_header += 1;
			}
			if (strstr(tmp, "}")) {
				start = 0;
				continue;
			} else {
				continue;
			}
		}

		if (strstr(tmp, "{")) {
			start = 1;
		}

		if (strstr(tmp, "add_header")) {
			father_header = 1;
		}

		if (start) {
			continue;
		}
	}

	fclose(fp);
	if ((father_header && son_header) || (son_header > 1)) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}
#endif

void app_check_nginx_crlf_request_uri(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_nginx_crlf_request_uri")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_crlf_request_uri");
	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}

		if (strstr(line, "return")) {
			if (strstr(line, "$")) {
				cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
				ret = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_nginx_proxy_headers(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	if (ignore_risk_key("app_check_nginx_proxy_headers")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_proxy_headers");
	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
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
		if (strstr(line, "proxy_set_header")) {
			if (strstr(line, "$http_host") || strstr(line, "$arg"))
				ca = 1;
			break;
		}
	}
	fclose(fp);
	if (ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_nginx_valid_referers(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_nginx_valid_referers")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_valid_referers");
	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "valid_referers")) {
			if (strstr(line, "none")) {
				cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
				ca = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

#if 1
void app_check_nginx_proxy_pass(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int rc = 0;

	if (ignore_risk_key("app_check_nginx_proxy_pass")) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		cJSON_Delete(arguments);
		return;
	}

	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}

		if (strstr(line, "proxy_pass")) {
			if (strstr(line, "$")) {
				rc = 1;
				break;
			}
		}
	}

	fclose(fp);
	if (rc) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_proxy_pass");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}
#endif

void app_check_nginx_frame_access(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0, cert = 0;

	if (ignore_risk_key("app_check_nginx_frame_access")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_frame_access");
	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "add_header")) {
			if (strstr(line, "X-Frame-Options") && strstr(line, "SAMEORIGIN")) {
				ca = 1;
			}
		}
		if (strstr(line, "Access-Control-Allow-Origin")) {
			if (strstr(line, "*")) {
				cert = 1;
			}
		}
	}
	fclose(fp);
	if (ca && !cert) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

#if 1
void app_check_nginx_add_moreset_headers(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *tmp = NULL;
	int father_header = 0;

	if (ignore_risk_key("app_check_nginx_add_moreset_headers")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_add_moreset_headers");

	fp = fopen(nginx_path, "r");

	if (!fp) {
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		delete_tailspace(line);
		tmp = skip_headspace(line);

		if (*tmp == '#') {
			continue;
		}

		if (strstr(tmp, "add_header") || strstr(tmp, "more_set_headers")) {
			father_header += 1;
		}
	}

	fclose(fp);
	if (father_header > 1) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}
#endif

/* JDWP（Java Debug Wire Protocol）存在命令执行漏洞 */
/* 检测java程序的启动参数是否包含有开启jdwp的参数 */
void app_check_jdwp_open_param(cJSON *array)
{
	if (ignore_risk_key("app_check_jdwp_open_param")) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		cJSON_Delete(arguments);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_jdwp_open_param");

	if (jdwp_pid > 0) {						    // 查找是否有带jdwp参数的java进程
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);  // 有风险
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);  // 无风险
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

#if 1
void app_check_jboss_web_file(cJSON *array)
{
	char file_path[S_PATHLEN] = {0};

	if (ignore_risk_key("app_check_jboss_web_file")) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		cJSON_Delete(arguments);
		return;
	}

	snprintf(file_path, S_PATHLEN, "%s/server/default/deploy/ROOT.war", jboss_path);
	if (access(file_path, F_OK) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_jboss_web_file");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}
#endif

void app_check_tomcat_error_page(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char path[S_PATHLEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_tomcat_error_page")) {
		return;
	}
	if (tomcat_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_PATHLEN, "%sweb.xml", tomcat_path);
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_tomcat_error_page");
	fp = fopen(path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "404") && strstr(line, "<error-code>")) {
			ret = 1;
			break;
		}
	}

	if (!ret) {
		fclose(fp);
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(array, arguments);
		return;
	}

	fgets(line, S_LINELEN, fp);
	if (line[0] != 0 && line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;

	if (strstr(line, "<location>")) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}
	fclose(fp);

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_tomcat_error_location(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char path[S_PATHLEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_tomcat_error_location")) {
		return;
	}
	if (tomcat_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_PATHLEN, "%sweb.xml", tomcat_path);
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_tomcat_error_location");
	fp = fopen(path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "500")) {
			ret = 1;
			break;
		}
	}

	if (!ret) {
		fclose(fp);
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(array, arguments);
		return;
	}

	fgets(line, S_LINELEN, fp);
	if (line[0] != 0 && line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;

	if (strstr(line, "<location>")) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}
	fclose(fp);

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

static int check_struts2_devmode_inpath(char *path, char *value)
{
	int i = 0;
	DIR *Dir = NULL;
	struct dirent *ent = NULL;
	char subpath[PATH_MAX] = {0}, filepath[PATH_MAX] = {0};

	if (!path) {
		return 0;
	}

	Dir = opendir(path);
	if (!Dir) {
		return 0;
	}

	while ((ent = readdir(Dir)) != NULL) {
		if (DT_DIR == ent->d_type || DT_LNK == ent->d_type) {  // 查子目录
			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
				continue;
			}

			snprintf(subpath, PATH_MAX, "%s/%s", path, ent->d_name);
			if (check_struts2_devmode_inpath(subpath, value)) {
				/* 找到可疑文件，结束检查 */
				closedir(Dir);
				return 1;
			}
			continue;
		}

		i = 0;

		if (strcmp(ent->d_name, "struts.xml") == 0) {
			/* 记录找到的可疑文件 */
			snprintf(filepath, PATH_MAX, "%s/%s", path, ent->d_name);
			strcpy(value, filepath);
			/* 找到一个可疑文件，结束检查 */
			closedir(Dir);
			return 1;
		}
		i++;
	}
	closedir(Dir);

	return 0;
}

void app_check_struts2_devmode(cJSON *array)
{
	char file_path[S_PATHLEN] = {0};
	char path[S_PATHLEN] = {0};
	char *ptr = NULL;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;
	int ret = 0;

	if (ignore_risk_key("app_check_struts2_devmode")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	if (tomcat_path[0] != 0) {
		snprintf(path, S_LINELEN, "%s", tomcat_path);
		ptr = strstr(path, "/conf");
		if (ptr) {
			*(ptr + 1) = 0;
		}
	}

	check_struts2_devmode_inpath(path, file_path);

	fp = fopen(file_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
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

		if (strstr(tmp, "constant name")) {
			if (strstr(tmp, "struts.devMode") && strstr(tmp, "true")) {
				ret = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_struts2_devmode");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_apache_solr_basic(cJSON *array)
{
	char release_path[1024] = {0};
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int value1 = 0, value2 = 0;
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	if (ignore_risk_key("app_check_apache_solr_basic")) {
		return;
	}

	if (solr_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(release_path, 1024, "%ssolr-webapp/webapp/WEB-INF/web.xml", solr_path);

	fp = fopen(release_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_apache_solr_basic");
	while (fgets(line, S_LINELEN, fp)) {
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
		if (strstr(line, "login-config")) {
			value1 = 1;
		}
		if (strstr(line, "auth-method")) {
			value2 = 1;
		}
	}
	fclose(fp);
	if (value1 && value2) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_apache_solr_lucene(cJSON *array)
{
	char cmdline[4096] = {0};
	char *ptr = NULL;
	int value1 = 0, value2 = 0, value3 = 0;

	if (ignore_risk_key("app_check_apache_solr_lucene")) {
		return;
	}

	if (solr_pid <= 0) {
		return;
	}

	if (get_proc_cmdline(solr_pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	ptr = strstr(cmdline, "/solr-");  // TODO 暂支持命令行中带有版本号的情况
	if (!ptr) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	ptr += strlen("/solr-");
	if (sscanf(ptr, "%d.%d.%d", &value1, &value2, &value3) != 3) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	if (value1 < 7 || (value1 == 7 && value2 < 1)) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_apache_solr_lucene");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_apache_solr_uid_gid(cJSON *array)
{
	if (ignore_risk_key("app_check_apache_solr_uid_gid")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_apache_solr_uid_gid");

	if (check_app_uid_gid(&solr_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
	return;
}

void app_check_httpd_prepend_append(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char key[S_NAMELEN] = {0}, val[S_NAMELEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_httpd_prepend_append")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fp = fopen("/etc/httpd/conf/httpd.conf", "r");
	if (!fp) {
		fp = fopen("/etc/apache2/apache2.conf", "r");
	}
	if (!fp) {
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (sscanf(line, "%s%s", key, val) != 2) {
			continue;
		}
		if (strcmp(key, "AccessFileName") != 0) {
			continue;
		}

		if (strcmp(val, ".htaccess") != 0) {
			ret = 1;
			break;
		}
	}

	fclose(fp);
	if (ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_httpd_prepend_append");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_httpd_php(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_httpd_php")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fp = fopen("/etc/httpd/conf/httpd.conf", "r");
	if (!fp) {
		fp = fopen("/etc/apache2/apache2.conf", "r");
	}
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}

		if (strstr(line, "AddHandler")) {
			if (strstr(line, ".php")) {
				cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
				ret = 1;
				break;
			}
		}
	}

	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_httpd_php");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_nginx_prepend_append(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0, ret = 0;

	if (ignore_risk_key("app_check_nginx_prepend_append")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
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

		if (strstr(line, "\\.php") && strstr(line, "\\.html")) {
			ret = 1;
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			break;
		}
	}
	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_prepend_append");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

#if 1
void app_check_nginx_php(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ret = 0;
	char *ptr = NULL;

	if (ignore_risk_key("app_check_nginx_php")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fp = fopen(nginx_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}

		if (strstr(line, "location")) {
			if (strstr(line, ".php")) {
				ptr = strrstr(line, ".");
				if ((*ptr++ != '*') && (*ptr++ != 'p')) {
					cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
					ret = 1;
					break;
				}
			}
		}
	}

	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_nginx_php");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}
#endif

void app_check_tomcat_listings(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, path[S_PATHLEN] = {0};
	int ret = 0;
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	if (ignore_risk_key("app_check_tomcat_listings")) {
		return;
	}
	if (tomcat_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_PATHLEN, "%sweb.xml", tomcat_path);
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_tomcat_listings");
	fp = fopen(path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
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
		if (strstr(line, "listings") && strstr(line, "<param-name>")) {
			ret = 1;
			break;
		}
	}
	if (!ret) {
		fclose(fp);
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(array, arguments);
		return;
	}
	fgets(line, S_LINELEN, fp);
	if (line[0] != 0 && line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;

	if (strstr(line, "false")) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}
	fclose(fp);

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_tomcat_remote(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int value1 = 0, value2 = 0, value3 = 0;
	char cmdline[4096] = {0};
	char *set = NULL;

	if (ignore_risk_key("app_check_tomcat_remote")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (tomcat_pid <= 0) {
		return;
	}

	if (get_proc_cmdline(tomcat_pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	set = strstr(cmdline, "tomcat-");
	if (!set) {
		INFO("NO tomcat home file\n");
		return;
	}

	set += strlen("tomcat-");
	if (sscanf(set, "%d.%d.%d", &value1, &value2, &value3) == 3) {
		DBG2(DBGFLAG_SYSDANGER, "tomcat version:%d.%d.%d\n", value1, value2, value3);
		if (value1 > 7 || (value1 == 7 && value2 > 0) || (value1 == 7 && value2 == 0 && value3 > 39)) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
		} else {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		}
	} else {
#ifdef SNIPER_FOR_DEBIAN
		fp = popen("dpkg -l | grep tomcat", "r");
#else
		fp = popen("rpm -qa | grep tomcat", "r");
#endif
		if (!fp) {
			return;
		}

		while (fgets(line, S_LINELEN, fp)) {
			set = strstr(line, "tomcat-");
			if (!set) {
				continue;
			}
			set += strlen("tomcat-");

			if (sscanf(set, "%d.%d.%d", &value1, &value2, &value3) != 3) {
				continue;
			}
			pclose(fp);
			DBG2(DBGFLAG_SYSDANGER, "tomcat version:%d.%d.%d\n", value1, value2, value3);

			if (value1 > 7 || (value1 == 7 && value2 > 0) || (value1 == 7 && value2 == 0 && value3 > 39)) {
				cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
			} else {
				cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			}
			break;
		}
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_tomcat_remote");

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_tomcat_port_shutdown(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, path[S_PATHLEN] = {0};
	int ca = 0, cert = 0;
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;

	if (ignore_risk_key("app_check_tomcat_port_shutdown")) {
		return;
	}

	if (tomcat_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_PATHLEN, "%sserver.xml", tomcat_path);
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_tomcat_port_shutdown");
	fp = fopen(path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
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
		if (strstr(line, "8005")) {
			ca = 1;
		}
		if (strstr(line, "SHUTDOWN")) {
			cert = 1;
		}
	}
	fclose(fp);
	if (ca && cert) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_tomcat_example_docs(cJSON *array)
{
	char path[S_LINELEN] = {0}, release_path[1024] = {0};
	DIR *dirp = NULL;
	struct dirent *ptr;
	char *str = NULL;
	int rc = 0, rc1 = 0, rc2 = 0;

	if (ignore_risk_key("app_check_tomcat_example_docs")) {
		return;
	}

	if (tomcat_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_LINELEN, "%s", tomcat_path);
	str = strstr(path, "/conf");
	if (str) {
		*str = 0;
	}
	snprintf(release_path, 1024, "%s/webapps", path);

	dirp = opendir(release_path);
	if (!dirp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_tomcat_example_docs");

	while ((ptr = readdir(dirp)) != NULL) {
		if (strcmp(ptr->d_name, "examples") == 0) {
			rc = 1;
			break;
		}
		if (strcmp(ptr->d_name, "jsp-examples") == 0) {
			rc1 = 1;
			break;
		}
		if (strcmp(ptr->d_name, "docs") == 0) {
			rc2 = 1;
			break;
		}
	}
	closedir(dirp);
	if (rc || rc1 || rc2) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_influxdb_auth_enabled(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_influxdb_auth_enabled")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_influxdb_auth_enabled");
	fp = fopen("/etc/influxdb/influxdb.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "auth-enabled")) {
			continue;
		}

		if (strstr(line, "true")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_proftpd_useralias(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int UserAlias = 0;

	if (ignore_risk_key("app_check_proftpd_useralias")) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_proftpd_useralias");
	fp = fopen("/etc/proftpd.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "UserAlias")) {
			UserAlias = 1;
			break;
		}
	}

	fclose(fp);
	if (UserAlias) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_proftpd_run_root(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int ca = 0;

	if (ignore_risk_key("app_check_proftpd_run_root")) {
		return;
	}

	if (proftpd_pid <= 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_proftpd_run_root");

	if (check_app_uid_gid(&proftpd_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(array, arguments);
		return;
	}

	fp = fopen("/etc/proftpd.conf", "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}
	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (!strstr(line, "User") || !strstr(line, "Group")) {
			continue;
		}

		if (strstr(line, "root")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			ca = 1;
			break;
		}
	}

	fclose(fp);
	if (!ca) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_jenkins_use_security(cJSON *array)
{
	FILE *fp = NULL;
	char path[S_PATHLEN] = {0};
	char line[S_LINELEN] = {0};
	char *tmp = NULL;
	unsigned int len = 0;
	int start = 0;
	int rc = 0;

	if (ignore_risk_key("app_check_jenkins_use_security")) {
		return;
	}

	if (jenkins_path[0] == 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_PATHLEN, "%s/config.xml", jenkins_path);

	fp = fopen(path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
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

		if (!strstr(line, "useSecurity")) {
			continue;
		}

		if (strstr(line, "true")) {
			rc = 1;
			cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
			break;
		}
	}
	fclose(fp);

	if (!rc) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_jenkins_use_security");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void app_check_jenkins_low_auth_remote(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *set = NULL;
	int value1 = 0, value2 = 0;

	if (ignore_risk_key("app_check_jenkins_low_auth_remote")) {
		return;
	}
#ifdef SNIPER_FOR_DEBIAN
	fp = popen("dpkg -l | grep jenkins", "r");
#else
	fp = popen("rpm -qa | grep jenkins", "r");
#endif
	sleep(1);
	if (!fp) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	fgets(line, S_LINELEN, fp);
	set = strstr(line, "jenkins-");
	if (!set) {
		return;
	}

	set += strlen("jenkins-");
	sscanf(set, "%d.%d", &value1, &value2);

	DBG2(DBGFLAG_SYSDANGER, "jenkins version: %d.%d\n", value1, value2);
	if (value1 == 1 && value2 < 642) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}

	pclose(fp);
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_jenkins_low_auth_remote");

	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

#if 1
void app_check_weblogic_open_t3(cJSON *array)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char path[S_PATHLEN] = {0};
	int ret = 0;

	if (ignore_risk_key("app_check_weblogic_open_t3")) {
		return;
	}
	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	snprintf(path, S_PATHLEN, "%s/user_projects/domains/DOMAIN_NAME/config/config.xml", weblogic_path);
	fp = fopen(path, "r");

	if (!fp) {
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (strstr(line, "t3")) {
			cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
			ret = 1;
			break;
		}
	}

	fclose(fp);
	if (!ret) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_weblogic_open_t3");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}
#endif

void app_check_weblogic_running_root(cJSON *array)
{
	if (ignore_risk_key("app_check_weblogic_running_root")) {
		return;
	}

	if (weblogic_pid <= 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_weblogic_running_root");

	if (check_app_uid_gid(&weblogic_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
	return;
}

void app_check_redis_running_root(cJSON *array)
{
	if (ignore_risk_key("app_check_redis_running_root")) {
		return;
	}

	if (redis_pid <= 0) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "app_check_redis_running_root");

	if (check_app_uid_gid(&redis_pid) == 0) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	}
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
	return;
}

void app_check_redis_requirepass_empty(cJSON *array)
{
	char cmdline[4096] = {0};
	char path[S_LINELEN] = {0};
	char *redis_path = NULL;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	int rc = 0;

	if (ignore_risk_key("app_check_redis_requirepass_empty")) {
		return;
	}

	if (redis_pid <= 0) {
		return;
	}

	if (get_proc_cmdline(redis_pid, cmdline, sizeof(cmdline)) < 0) {
		return;
	}

	if (sscanf(cmdline, "%*s%s", path) != 1) {
		return;
	}

	cJSON *value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	cJSON *arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	if (strstr(path, ".conf")) {
		redis_path = path;
	} else {
		redis_path = "/etc/redis/redis.conf";
		if (access(redis_path, F_OK) != 0) {
			redis_path = "/etc/redis.conf";
		}
		if (access(redis_path, F_OK) != 0) {
			DBG2(DBGFLAG_SYSDANGER, "No redis conf file\n");
		}
	}
	DBG2(DBGFLAG_SYSDANGER, "redis_path %s\n", redis_path);

	fp = fopen(redis_path, "r");
	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (line[0] == '#') {
			continue;
		}
		if (strstr(line, "requirepass")) {
			rc = 1;
			break;
		}
	}
	fclose(fp);
	if (rc) {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_NORISK);
	} else {
		cJSON_AddNumberToObject(arguments, "status", SNIPER_RISK);
	}

	cJSON_AddStringToObject(arguments, "rule_key", "app_check_redis_requirepass_empty");
	cJSON_AddItemToArray(value, cJSON_CreateString(""));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(array, arguments);
}

void check_application_risk(cJSON *array)
{
	// TODO 可能存在一台机器上装有两个版本的应用，会导致取进程号时不是先要的结果
	int i = 0;
	get_app_pid(risk_app_info);

	while (risk_app_info[i].name_app) {
		DBG2(DBGFLAG_SYSDANGER, "%s %d\n", risk_app_info[i].sub_name, *risk_app_info[i].pid);
		i++;
	}

	nginx_conf_path(nginx_pid);
	tomcat_conf_path(tomcat_pid);
	solr_conf_path(solr_pid);
	jenkins_conf_path(jenkins_pid);
	jboss_conf_path(jboss_pid);
	mysql_plugin_path(mysql_pid);
	weblogic_conf_path(weblogic_pid);

	INFO("app_check_redis_config_not_update\n");
	app_check_redis_config_not_update(array);

	INFO("app_check_nfs_noauth_visit\n");
	app_check_nfs_noauth_visit(array);

	INFO("app_check_ntp_enlarge_dos_attack\n");
	app_check_ntp_enlarge_dos_attack(array);

	INFO("app_check_memcache_udp_listening\n");
	app_check_memcache_udp_listening(array);

	INFO("app_check_vsftpd_chroot_local_user\n");
	app_check_vsftpd_chroot_local_user(array);

	INFO("app_check_ssh_authorized_keys_file\n");
	app_check_ssh_authorized_keys_file(array);

	INFO("app_check_ssh_homefile_have_key\n");
	app_check_ssh_homefile_have_key(array);

	INFO("app_check_rsync_root_running\n");
	app_check_rsync_root_running(array);

	INFO("app_check_openvpn_unuse_key\n");
	app_check_openvpn_unuse_key(array);

	INFO("app_check_mongodb_rest_interface_enable\n");
	app_check_mongodb_rest_interface_enable(array);

	INFO("app_check_rsync_auth_users_empty\n");
	app_check_rsync_auth_users_empty(array);

	INFO("app_check_rsync_readonly_true\n");
	app_check_rsync_readonly_true(array);

	INFO("app_check_mongodb_open_auth\n");
	app_check_mongodb_open_auth(array);

	INFO("app_check_bind_allow_transfer\n");
	app_check_bind_allow_transfer(array);

	INFO("app_check_bind_allow_recursion\n");
	app_check_bind_allow_recursion(array);

	INFO("app_check_vsftpd_login_otherway\n");
	app_check_vsftpd_login_otherway(array);

	INFO("app_check_vsftpd_anonymous_enable\n");
	app_check_vsftpd_anonymous_enable(array);

	INFO("app_check_squid_acl_http_access\n");
	app_check_squid_acl_http_access(array);

	INFO("app_check_squid_proxy_host\n");
	app_check_squid_proxy_host(array);

	INFO("app_check_mysql_skip_grant_tables\n");
	app_check_mysql_skip_grant_tables(array);

	INFO("app_check_mysql_root_auth\n");
	app_check_mysql_root_auth(array);

	INFO("app_check_mysql_plugin_sofile\n");
	app_check_mysql_plugin_sofile(array);  // TODO 需要有敏感函数列表才可以检测

	INFO("app_check_mysql_test_database\n");
	app_check_mysql_test_database(array);

	INFO("app_check_cvs_store_file\n");
	app_check_cvs_store_file(array);

	INFO("app_check_elasticsearch_disable_dynamic\n");
	app_check_elasticsearch_disable_dynamic(array);

	INFO("app_check_elasticsearch_groovy_sandbox\n");
	app_check_elasticsearch_groovy_sandbox(array);

	INFO("app_check_cvs_file_divulge\n");
	app_check_cvs_file_divulge(array);

	INFO("app_check_elasticsearch_site_readall\n");
	app_check_elasticsearch_site_readall(array);

	INFO("app_check_elasticsearch_running_byroot\n");
	app_check_elasticsearch_running_byroot(array);

	INFO("app_check_vnc_auth_passaway\n");
	app_check_vnc_auth_passaway(array);

	INFO("app_check_svn_store_catalogue\n");
	app_check_svn_store_catalogue(array);

	INFO("app_check_svn_entries_file\n");
	app_check_svn_entries_file(array);

	INFO("app_check_tomcat_put_readonly\n");
	app_check_tomcat_put_readonly(array);

	INFO("app_check_mysql_user_uid_gid\n");
	app_check_mysql_user_uid_gid(array);

	INFO("app_check_apache_cgi_file\n");
	app_check_apache_cgi_file(array);

	INFO("app_check_nginx_location_alias\n");
	app_check_nginx_location_alias(array);

	INFO("app_check_nginx_crlf_request_uri\n");
	app_check_nginx_crlf_request_uri(array);

	INFO("app_check_nginx_proxy_headers\n");
	app_check_nginx_proxy_headers(array);

	INFO("app_check_nginx_valid_referers\n");
	app_check_nginx_valid_referers(array);

	INFO("app_check_nginx_frame_access\n");
	app_check_nginx_frame_access(array);

	INFO("app_check_jdwp_open_param\n");
	app_check_jdwp_open_param(array);

	INFO("app_check_tomcat_error_page\n");
	app_check_tomcat_error_page(array);

	INFO("app_check_tomcat_error_location\n");
	app_check_tomcat_error_location(array);

	INFO("app_check_struts2_devmode\n");
	app_check_struts2_devmode(array);

	INFO("app_check_apache_solr_basic\n");
	app_check_apache_solr_basic(array);

	INFO("app_check_apache_solr_lucene\n");
	app_check_apache_solr_lucene(array);

	INFO("app_check_apache_solr_uid_gid\n");
	app_check_apache_solr_uid_gid(array);

	INFO("app_check_httpd_prepend_append\n");
	app_check_httpd_prepend_append(array);

	INFO("app_check_httpd_php\n");
	app_check_httpd_php(array);

	INFO("app_check_nginx_prepend_append\n");
	app_check_nginx_prepend_append(array);

	INFO("app_check_tomcat_listings\n");
	app_check_tomcat_listings(array);

	INFO("app_check_tomcat_remote\n");
	app_check_tomcat_remote(array);

	INFO("app_check_tomcat_port_shutdown\n");
	app_check_tomcat_port_shutdown(array);

	INFO("app_check_tomcat_example_docs\n");
	app_check_tomcat_example_docs(array);

	INFO("app_check_influxdb_auth_enabled\n");
	app_check_influxdb_auth_enabled(array);

	INFO("app_check_proftpd_useralias\n");
	app_check_proftpd_useralias(array);

	INFO("app_check_proftpd_run_root\n");
	app_check_proftpd_run_root(array);

	INFO("app_check_jenkins_use_security\n");
	app_check_jenkins_use_security(array);

	INFO("app_check_jenkins_low_auth_remote\n");
	app_check_jenkins_low_auth_remote(array);

	INFO("app_check_weblogic_running_root\n");
	app_check_weblogic_running_root(array);

	INFO("app_check_redis_running_root\n");
	app_check_redis_running_root(array);

	INFO("app_check_redis_requirepass_empty\n");
	app_check_redis_requirepass_empty(array);

	INFO("app_check_jboss_web_file\n");
	app_check_jboss_web_file(array);

	INFO("app_check_nginx_proxy_pass\n");
	app_check_nginx_proxy_pass(array);

	INFO("app_check_nginx_http_header\n");
	app_check_nginx_http_header(array);

	INFO("app_check_nginx_add_moreset_headers\n");
	app_check_nginx_add_moreset_headers(array);

	INFO("app_check_nginx_php\n");
	app_check_nginx_php(array);

	INFO("app_check_weblogic_open_t3\n");
	app_check_weblogic_open_t3(array);

	INFO("app_check_apache_http_host\n");
	app_check_apache_http_host(array);

	INFO("check_application_risk done\n");
}
