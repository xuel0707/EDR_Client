#include <arpa/inet.h>
#include <crypt.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <utmp.h>

#include "header.h"
#include "stdio.h"
#include "stdlib.h"
#include "time.h"

int syslog = 0, net_promisc = 0, grub = 0, protocol_number = 0, cipher = 0, ld_file = 0, ld_env = 0, file_umask = 0;

char *trim_space(char *str)
{
	char *end = NULL;

	if (str == NULL)
		return NULL;

	while (isspace((unsigned char)*str))
		str++;

	if (*str == 0)
		return str;

	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end))
		end--;
	end[1] = '\0';

	return str;
}

static const char *white_list[] = {
    "pam_rootok.so", "pam_wheel.so",
    "pam_succeed_if.so", "pam_xauth.so", "pam_time.so", "pam_env.so",
    "pam_mail.so", "pam_limits.so", "pam_stack.so", "pam_deny.so",
    "pam_listfile.so", "pam_access.so", "pam_userdb.so", "pam_securetty.so",
    "pam_cracklib.so", "pam_pwhistroy.so", "pam_tally.so", "pam_tally2.so",
    "pam_faillock.so", "pam_unix.so", "pam_shells.so", "pam_permit.so",
    "pam_loginuid.so", "pam_console.so", "pam_warn.so", "pam_nologin.so",
    "pam_keyinit.so", "pam_ldap.so",
    /* 后补的 */
    "pam_cap.so", "pam_pwquality.so", "pam_chroot.so", "pam_sss.so", "pam_debug.so",
    "pam_echo.so", "pam_exec.so", "pam_faildelay.so", "pam_filter", "pam_filter.so",
    "pam_ftp.so", "pam_group.so", "pam_issue.so", "pam_lastlog.so", "pam_localuser.so",
    "pam_mkhomedir.so", "pam_motd.so", "pam_namespace.so", "pam_postgresok.so",
    "pam_pwhistory.so", "pam_rhosts.so", "pam_selinux.so", "pam_selinux_permit.so",
    "pam_sepermit.so", "pam_stress.so", "pam_timestamp.so", "pam_tty_audit.so",
    "pam_umask.so", "pam_unix_acct.so", "pam_unix_auth.so", "pam_unix_passwd.so",
    "pam_unix_session.so", "pam_systemd.so", "pam_oddjob_mkhomedir.so",
    "pam_gnome_keyring.so", "pam_gdm.so", "pam_fprintd.so", NULL};

static const char *app_account[] = {
    "activemq", "redis", "vsftp", "rsync", "mongod",
    "memcached", "weblogic", "jboss", "jenkins",
    "squid", "sshd", "snmpd", "svnserve", "vnc",
    "elasticsearch", "openvpn", "wildfly", "influxd",
    "mysqld", "pgsql", "pptpd", "tomcat", "proftp",
    "xinetd", "openldap", NULL};

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

/* linux_check_account_exists_suspicious_sudo_pam
 * sudo PAM文件存在非已知模块
 * 检测/pam.d/sudo文件是否加载白名单之外的模块
 */
static void linux_check_account_exists_suspicious_sudo_pam(cJSON *object)
{
	char line[PATH_MAX];
	int i = 0, found = 0;
	int status = 1; /* 0 未通过 1 通过 */
	FILE *fp = NULL;
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	char *start = NULL;
	char *tmp = NULL;
	const char *conf_file = "/etc/pam.d/sudo";

	if (ignore_risk_key("linux_check_account_exists_suspicious_sudo_pam")) {
		return;
	}

	if (object == NULL) {
		MON_ERROR("check account sudo fail object is NULL\n");
		return;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account sudo fail create object is NULL\n");
		goto end;
	}

	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account exists sudo fail create value is NULL\n");
		goto end;
	}

	fp = fopen(conf_file, "r");
	if (!fp) {
		MON_ERROR("check account sudo open file %s fail\n", conf_file);
		goto end;
	}

	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));

	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		start = trim_space(line);
		if (!start || *start == '#' || *start == '\0') {
			continue;
		}
		tmp = strstr(start, ".so");
		if (!tmp) {
			continue;
		}

		tmp += 3;
		*tmp = '\0';
		tmp--;
		while (tmp > start && !isspace((unsigned char)*tmp)) {
			tmp--;
		}
		tmp++;

		// INFO("2----%s\n", tmp);
		i = 0;
		found = 0;
		while (white_list[i]) {
			if (strncmp(white_list[i], tmp, strlen(tmp)) == 0) {
				found = 1;
				break;
			}
			i++;
		}

		if (!found) { /* 白名单中没找到 */
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(tmp));
			status = 0;
		}
	}
	fclose(fp);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_exists_suspicious_sudo_pam");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return;

end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
}

/* linux_check_account_exists_suspicious_su_pam
 * su PAM文件存在非已知模块
 * 检测/pam.d/su文件是否加载白名单之外的模块
 */
static int linux_check_account_exists_suspicious_su_pam(cJSON *object)
{
	char line[PATH_MAX];
	int ret = 0;
	int status = 1; /* 0 未通过 1 通过 */
	FILE *fp = NULL;
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	char *start = NULL;
	char *tmp = NULL;
	const char *conf_file = "/etc/pam.d/su";

	if (ignore_risk_key("linux_check_account_exists_suspicious_su_pam")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account su fail object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account su fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account exists su fail create value is NULL\n");
		goto end;
	}

	fp = fopen(conf_file, "r");
	if (!fp) {
		MON_ERROR("check account su open file %s fail\n", conf_file);
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));

	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		start = trim_space(line);
		if (!start || *start == '#' || *start == '\0') {
			continue;
		}
		tmp = strstr(start, ".so");
		if (!tmp) {
			continue;
		}

		tmp += 3;
		*tmp = '\0';
		tmp--;
		while (tmp > start && !isspace((unsigned char)*tmp)) {
			tmp--;
		}
		tmp++;
		// INFO("2----%s\n", tmp);
		int i = 0;
		ret = 0;
		while (white_list[i]) {
			if (strncmp(white_list[i], tmp, strlen(tmp)) == 0) {
				ret = 1;
				break;
			}
			i++;
		}

		if (!ret) { /* 白名单中没找到 */
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(tmp));
			status = 0;
		}
	}
	fclose(fp);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_exists_suspicious_su_pam");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;

end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/* 系统风险项 18行
 * linux_check_account_exists_suspicious_pam_auth
 * 存在非本机PAM认证方式
 * 检测是否存在非本机PAM认证方式
 */
static int linux_check_account_exists_suspicious_pam_auth(cJSON *object)
{
	char value[PATH_MAX] = {0};
	DIR *dirp = NULL;
	struct dirent *dent = NULL;
	int ret = 0, i = 0;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
#ifdef SNIPER_FOR_DEBIAN
	const char *check_dir = "/lib/x86_64-linux-gnu/security/";
#else
	const char *check_dir = "/lib64/security/";
#endif

	if (ignore_risk_key("linux_check_account_exists_suspicious_pam_auth")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account pam auth fail object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account pam auth fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account exiss pam fail create value is NULL\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);

	memset(value, 0x00, sizeof(value));

	dirp = opendir(check_dir);
	if (dirp == NULL) {
		MON_ERROR("Open dir %s failed\n", check_dir);
		return -1;
	}
	while ((dent = readdir(dirp)) != NULL) {
		if (dent->d_name[0] == '.') {
			continue;
		}
		i = 0;
		ret = 0;
		while (white_list[i]) {
			if (strncmp(white_list[i], dent->d_name, strlen(dent->d_name)) == 0) {
				ret = 1;
			}
			i++;
		}

		if (!ret) {
			// INFO("%s\n", dent->d_name);
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(dent->d_name));
			status = 0;
		}
	}
	closedir(dirp);
	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_exists_suspicious_pam_auth");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	return -1;
}

/* 系统风险项 19行
 * linux_check_account_app_allow_login
 * 应用账号可登录系统
 * 检测是否存在可登录系统及密码为弱口令的应用账号
 */
static int linux_check_account_app_allow_login(cJSON *object)
{
	char line[PATH_MAX];
	char buf2[PATH_MAX];
	char value[PATH_MAX];
	struct spwd user_info;
	struct passwd pw;
	struct passwd *pwp = NULL;
	struct spwd *user_infop = NULL;
	int ret = 0, i = 0;
	int status = 1; /* 0 未通过 1 通过 */
	FILE *fp = NULL;
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	const char *pwd_file = "/etc/passwd";

	if (ignore_risk_key("linux_check_account_app_allow_login")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account app fail object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account app fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account app allow fail create value is NULL\n");
		goto end;
	}

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("check account app allow is open pwd file fail\n");
		goto end;
	}
	memset(value, 0x00, sizeof(value));
	cJSON_AddItemToObject(arguments, "value", value_arr);

	while (1) {
	GETUSER:
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("get account info: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}

		getspnam_r(pw.pw_name, (struct spwd *)&user_info, buf2, PATH_MAX, (struct spwd **)&user_infop);
		if (user_infop == NULL) {
			break;
		}

		if (strstr(pw.pw_shell, "nologin")) {
			continue;
		}
		i = 0;
		while (app_account[i]) {
			if (strncmp(app_account[i], pw.pw_name, strlen(pw.pw_name)) == 0) {
				status = 0;
				cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
				goto GETUSER;
			}
			i++;
		}
#if 0 /* 不检查弱密码了，应用账号可登录就上报 */
        /* 检查弱密码 */
        FILE *fp_weak = fopen(WEAK_PASSWD_FILE, "r");
        if (!fp_weak) {
            MON_ERROR("get_password open weak lib fail: %s\n", strerror(errno));
            continue;
        }
        char weak_str[128];
        char salt[16];
        struct crypt_data data;
        data.initialized = 0;
        memset(weak_str, 0x00, sizeof(weak_str));
        memset(salt, 0x00, sizeof(salt));
        snprintf(salt, sizeof(salt), "%s", user_info->sp_pwdp);
        salt[11] = '\0';
        while (fgets(weak_str, sizeof(weak_str), fp_weak)) {
            weak_str[strcspn(weak_str, "\n")] = '\0';
            crypt_str = crypt_r(weak_str, salt, &data);
            if (crypt_str) {
                if (strncmp(crypt_str, user_info->sp_pwdp, len) == 0) {
                    status = 0;
                    break;
                }
            } else {
                MON_ERROR("check account app crypt weakpwd fail\n");
            }
        }
        fclose(fp_weak);
        if (!len) {
            memset(value, 0x00, sizeof(value));
            snprintf(value, sizeof(value), "%s", pw.pw_name);
        } else {
            snprintf(value+len, sizeof(value)-len, ",%s", pw.pw_name);
        }
        len += strlen(pw.pw_name);
#endif
	}
	fclose(fp);
	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_app_allow_login");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/* 系统风险项 20行
 * linux_check_account_fail_lock_empty
 * 未设置密码尝试次数锁定
 * 检测/etc/pam.d/下
 * system-auth (Cetnos)
 * common-auth (Ubuntu)
 * password-auth (Ubuntu & Centos)
 * sshd (Ubuntu & Centos) 此项配置属于远程登录的范畴
 * login (Ubuntu & Centos)
 * kde (可能没有)
 * 配置文件是否设置密码尝试次数锁定
 */
/* 检查指定文件中是否有以下配置
 * auth required pam_tally2.so deny=3 unlock_time=500 even_deny_root root_unlock_time=100
 */
static int check_account_lock_conf(const char *file)
{
	char line[PATH_MAX];
	struct stat file_st;
	int ret = 0;
	char *tmp = NULL;
	FILE *fp = NULL;

	if (file == NULL) {
		MON_ERROR("check account lock conf is NULL\n");
		return -1;
	}

	memset(line, 0x00, sizeof(line));
	if ((!stat(file, &file_st) && S_ISREG(file_st.st_mode)) == 0) {
		// MON_ERROR("check account lock conf file %s is not exist\n", file);
		return -1;
	}

	fp = fopen(file, "r");
	if (!fp) {
		MON_ERROR("check account lock conf open file %s fail\n", file);
		return -1;
	}
	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		tmp = trim_space(line);
		if (!tmp && *tmp == '#') {
			continue;
		}
		/* 检查配置项
		 * auth required pam_tally2.so deny=3 unlock_time=500 even_deny_root root_unlock_time=100
		 */
		if (strncmp(tmp, "auth", 4) != 0) {
			continue;
		}
		tmp = strstr(tmp + 4, "required");
		if (!tmp) {
			continue;
		}
		tmp = strstr(tmp, "pam_tally2.so");
		if (!tmp) {
			continue;
		}
		tmp = strstr(tmp, "unlock_time");
		if (!tmp) {
			continue;
		}
		tmp = strstr(tmp, "even_deny_root");
		if (!tmp) {
			continue;
		}
		tmp = strstr(tmp, "root_unlock_time");
		if (!tmp) {
			continue;
		}
		ret = 1;
		break;
	}
	fclose(fp);

	return ret;
}
static int linux_check_account_fail_lock_empty(cJSON *object)
{
	char value[PATH_MAX];
	const char *files[7] = {
#ifdef SNIPER_FOR_DEBIAN
	    "/etc/pam.d/common-auth",
#else
	    "/etc/pam.d/system-auth",
#endif
	    "/etc/pam.d/password-auth",
	    "/etc/pam.d/sshd",
	    // "/etc/pam.d/login",
	    NULL};
	int index = 0;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;

	if (ignore_risk_key("linux_check_account_fail_lock_empty")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account fail lock object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account fail lock create object is NULL\n");
		return -1;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		cJSON_Delete(arguments);
		MON_ERROR("check account fail lock create value is NULL\n");
		return -1;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);

	memset(value, 0x00, sizeof(value));
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_fail_lock_empty");

	while (files[index]) {
		ret = check_account_lock_conf(files[index]);
		if (ret != 1) { /* 未检测到配置项 */
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(files[index]));
			status = 0;
		} else {
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(files[index]));
			status = 1;
			break;
		}
		++index;
	}
	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
}

/* linux_check_account_exists_home_any_write
 * 账户目录任意读写
 * 检测用户账号主目录的用户组及其他用户是否权限最大只具有x权限
 */
static int linux_check_account_exists_home_any_write(cJSON *object)
{
	char line[PATH_MAX];
	char value[PATH_MAX];
	struct passwd pw = {0};
	struct stat file_st;
	const char *pwd_file = "/etc/passwd";
	mode_t check_mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;
	struct passwd *pwp = NULL;
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;
	int ret = 0;
	int status = 1; /* 0 未通过 1 通过 */

	if (ignore_risk_key("linux_check_account_exists_home_any_write")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account exists home is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account exists home object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account exists home fail create value is NULL\n");
		goto end;
	}

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("check account exists home is open pwd file fail\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(value, 0x00, sizeof(value));
	memset(line, 0x00, sizeof(line));
	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("get account info: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}
		if (strlen(pw.pw_dir) == 1) { /* 排除 / 的情况 */
			continue;
		}
		if (stat(pw.pw_dir, &file_st) < 0) {
			continue;
		}
		if (!S_ISDIR(file_st.st_mode)) {
			continue;
		}

		mode_t result_mode = file_st.st_mode & check_mode;
		// INFO("-%s---%s---%ld %ld\n", pw.pw_name, pw.pw_dir, check_mode, result_mode);
		if (result_mode == check_mode) {
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_dir));
			status = 0;
		}
	}
	fclose(fp);
	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_exists_home_any_write");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/* linux_check_account_pwd_complex_policy
 * 未设置密码复杂度限制
 * 检测/etc/pam.d/system-auth或者/etc/pam.d/common-password或/etc/security/pwquality.conf配置文件所配置的密码策略是否符合要求
 * 密码最短长度为8，至少包含一个数字、一个大写字母、一个小写字母和一个特殊字符
 */

/* 返回0出错 */
static int get_conf_int(const char *conf_str)
{
	char line[PATH_MAX];
	int ret = 0;
	char *tmp = line;
	char *start = NULL;

	if (conf_str == NULL) {
		return -1;
	}

	memset(line, 0x00, sizeof(line));
	snprintf(line, sizeof(line), "%s", conf_str);

	while (isspace((unsigned char)*tmp)) {
		tmp++;
	}

	while (!isdigit((unsigned char)*tmp)) {
		tmp++;
	}
	start = tmp;

	while (!isspace((unsigned char)*tmp)) {
		tmp++;
	}
	*tmp = '\0';

	ret = atoi(start);

	return ret;
}
/* 检查/etc/security/pwquality.conf文档的配置
 * 通过返回 1，未通过返回0
 * 检查以下项
 * minlen = 8
 * minclass = 1
 * maxrepeat = 0
 * maxclassrepeat = 4
 * lcredit = -1
 * ucredit = -1
 * dcredit = -1
 * ocredit = -1
 * difok=5
 */
static int check_pwquality_conf(const char *conf_file)
{
	char line[PATH_MAX];
	int status = 1; /* 0 未通过 1 通过 */
	FILE *fp = NULL;
	char *start = NULL;
	char *tmp = NULL;
	int minlen = 0;
	int minclass = 0;
	int maxrepeat = 0;
	int maxclassrepeat = 0;
	int lcredit = 0;
	int ucredit = 0;
	int dcredit = 0;
	int ocredit = 0;
	int difok = 0;

	if (conf_file == NULL) {
		return -1;
	}

	fp = fopen(conf_file, "r");
	if (!fp) {
		MON_ERROR("check account pwd policy open file %s fail\n", conf_file);
		return -1;
	}

	memset(line, 0x00, sizeof(line));
	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		start = trim_space(line);
		if (!start || *start == '#' || *start == '\0') {
			continue;
		}

		/* minlen 最小密码长度：8 */
		if (strncmp(start, "minlen", 6) == 0) {
			tmp = strchr(start, '=');
			if (tmp) {
				tmp++;
				minlen = atoi(tmp) >= 8 ? 1 : 0;
			} else {
				break;
			}
		}
		if (strncmp(start, "minclass", 8) == 0) {
			minclass = 1;
		}
		if (strncmp(start, "maxrepeat", 9) == 0) {
			maxrepeat = 1;
		}
		if (strncmp(start, "maxclassrepeat", 14) == 0) {
			maxclassrepeat = 1;
		}
		/* lcredit 最少小写字母：1 */
		if (strncmp(start, "lcredit", 7) == 0) {
			tmp = strchr(start, '=');
			if (tmp) {
				tmp++;
				lcredit = atoi(tmp) >= 1 ? 1 : 0;
			} else {
				break;
			}
		}
		/* ucredit 最少大写字母：1 */
		if (strncmp(start, "ucredit", 7) == 0) {
			tmp = strchr(start, '=');
			if (tmp) {
				tmp++;
				ucredit = atoi(tmp) >= 1 ? 1 : 0;
			} else {
				break;
			}
		}
		/* dcredit 最少数字：1 */
		if (strncmp(start, "dcredit", 7) == 0) {
			tmp = strchr(start, '=');
			if (tmp) {
				tmp++;
				dcredit = atoi(tmp) >= 1 ? 1 : 0;
			} else {
				break;
			}
		}
		if (strncmp(start, "ocredit", 7) == 0) {
			ocredit = 1;
		}
		/* difok 最少不同字符：3 */
		if (strncmp(start, "difok", 5) == 0) {
			tmp = strchr(start, '=');
			if (tmp) {
				tmp++;
				difok = atoi(tmp) >= 3 ? 1 : 0;
			} else {
				break;
			}
		}
	}
	fclose(fp);
	// 必须全配置
	status = minlen & minclass & maxrepeat & maxclassrepeat & lcredit & ucredit & dcredit & ocredit & difok;

	return status;
}
static int linux_check_account_pwd_complex_policy(cJSON *object)
{
	char line[PATH_MAX];
	const char *conf_file =
#ifdef SNIPER_FOR_DEBIAN
	    "/etc/pam.d/common-password";
#else
	    "/etc/pam.d/system-auth";
#endif
	// "/etc/security/pwquality.conf",
	// 只有这个文件中会配置特殊字符，Ubuntu和Centos中暂时没有这个文件

	struct stat file_st;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;
	char *tmp = NULL;
	char *start = NULL;

	if (ignore_risk_key("linux_check_account_pwd_complex_policy")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account pwd policy object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account pwd policy object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account pwd policy fail create value is NULL\n");
		goto end;
	}

	if ((!stat(conf_file, &file_st) && S_ISREG(file_st.st_mode)) == 0) {
		// MON_ERROR("check account lock conf file %s is not exist\n", file);
		goto end;
	}

	fp = fopen(conf_file, "r");
	if (!fp) {
		MON_ERROR("check account pwd policy open file %s fail\n", conf_file);
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));
	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		start = trim_space(line);
		if (!start || *start == '#' || *start == '\0') {
			continue;
		}
		/* 检查配置项
		 * password requisite pam_cracklib.so retry=5 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 dictpath=/usr/share/cracklib/pw_dict
		 * retry 尝试次数：5
		 * difok 最少不同字符：3
		 * minlen 最小密码长度：8
		 * ucredit 最少大写字母：1
		 * lcredit 最少小写字母：1
		 * dcredit 最少数字：1
		 * dictpath 密码字典：/usr/share/cracklib/pw_dict
		 */
		if (strncmp(start, "password", 8) != 0) {
			continue;
		}
		tmp = strstr(start + 8, "requisite");
		if (!tmp) {
			continue;
		}
		start = tmp;
		tmp = strstr(start, "minlen");
		if (!tmp) {
			status = 0;
			continue;
		} else {
			tmp = strchr(tmp, '=');
			if (tmp) {
				++tmp;
				ret = get_conf_int(tmp);
				if (ret < 8) {
					status = 0;
					break;
				}
			}
		}

		tmp = strstr(start, "dcredit");
		if (!tmp) {
			status = 0;
			break;
		} else {
			tmp = strchr(tmp, '=');
			if (tmp) {
				++tmp;
				ret = get_conf_int(tmp);
				if (ret < 1) {
					status = 0;
					break;
				}
			}
		}

		tmp = strstr(start, "ucredit");
		if (!tmp) {
			status = 0;
			break;
		} else {
			tmp = strchr(tmp, '=');
			if (tmp) {
				++tmp;
				ret = get_conf_int(tmp);
				if (ret < 1) {
					status = 0;
					break;
				}
			}
		}

		tmp = strstr(start, "lcredit");
		if (!tmp) {
			status = 0;
			break;
		} else {
			tmp = strchr(tmp, '=');
			if (tmp) {
				++tmp;
				ret = get_conf_int(tmp);
				if (ret < 1) {
					status = 0;
					break;
				}
			}
		}
		status = 1;
		break;
	}
	fclose(fp);
	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	} else {  // 未通过，可能是pwquality.conf设置了，再查一遍
		const char *pwquality = "/etc/security/pwquality.conf";
		ret = check_pwquality_conf(pwquality);
		if (ret == 0) {	 // 未通过，两个文件都添加到Json中，上报
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(pwquality));
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(conf_file));
			status = 0;
		} else if (ret == 1) {	// 通过
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
			status = 1;
		}
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_pwd_complex_policy");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/* linux_check_account_num
 * 存在数字账号
 * 检测是否存在账名为数字的账号，例账号名为"123"
 */
static int linux_check_account_num(cJSON *object)
{
	char line[PATH_MAX];
	char value[PATH_MAX];
	char user_name[64];
	const char *pwd_file = "/etc/passwd";
	struct passwd pw = {0};
	struct passwd *pwp = NULL;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	int username_len = 0;
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;

	if (ignore_risk_key("linux_check_account_num")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account num fail lock object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account num fail lock create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account num fail create value is NULL\n");
		goto end;
	}

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("check account num is open pwd file fail\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(value, 0x00, sizeof(value));
	memset(line, 0x00, sizeof(line));
	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("get account info: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}

		memset(user_name, 0x00, sizeof(user_name));
		snprintf(user_name, sizeof(user_name), "%s", pw.pw_name);
		username_len = strlen(user_name);

		int count = 0;
		int i = 0;
		while (user_name[i]) {
			if (isdigit(user_name[i])) {
				++count;
			}
			++i;
		}

		if (username_len != count) { /* 用户名不全为数字 */
			continue;
		}
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
		status = 0;
	}
	fclose(fp);
	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_num");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/////////////////////////////
////////////////////////////
struct user_info {
	// char user_name[64];
	unsigned int uid;
	unsigned int gid;
	struct list_head list;
};
typedef struct user_info uinfo_t;

static int generat_user_list(struct list_head *ulist)
{
	char line[PATH_MAX];
	struct passwd pw = {0};
	struct passwd *pwp = NULL;
	FILE *fp = NULL;
	int ret = 0;
	const char *pwd_file = "/etc/passwd";

	if (ulist == NULL) {
		return -1;
	}

	INIT_LIST_HEAD(ulist);

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("user list open pwd file fail\n");
		return -1;
	}

	memset(line, 0x00, sizeof(line));
	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("user list: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}
		uinfo_t *new = (uinfo_t *)calloc(1, sizeof(uinfo_t));
		if (!new) {
			MON_ERROR("user list: malloc fail: %s\n", strerror(errno));
			break;
		}
		new->uid = pw.pw_uid;

		list_add(&new->list, ulist);
	}
	fclose(fp);

	return ret;
}

static int generat_group_list(struct list_head *glist)
{
	char line[PATH_MAX];
	FILE *fp = NULL;
	int ret = 0;
	const char *group_file = "/etc/group";
	char *tmp = NULL;
	char *gid_str = NULL;

	INIT_LIST_HEAD(glist);

	fp = fopen(group_file, "r");
	if (!fp) {
		MON_ERROR("user list open pwd file fail\n");
		return -1;
	}

	memset(line, 0x00, sizeof(line));

	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		tmp = trim_space(line);
		if (!tmp) {
			continue;
		}
		tmp = strstr(tmp, ":");
		if (!tmp) {
			continue;
		}
		tmp++;
		if (!tmp) {
			continue;
		}
		tmp = strstr(tmp, ":");
		if (!tmp) {
			continue;
		}
		tmp++;
		gid_str = tmp;
		if (!tmp) {
			continue;
		}
		tmp = strstr(tmp, ":");
		if (!tmp) {
			continue;
		}
		*tmp = '\0';

		uinfo_t *new = (uinfo_t *)calloc(1, sizeof(uinfo_t));
		if (!new) {
			MON_ERROR("user list: malloc fail: %s\n", strerror(errno));
			break;
		}
		new->gid = atoi(gid_str);

		list_add(&new->list, glist);
	}
	fclose(fp);

	return ret;
}
/* 返回值代表重复的个数 */
static int is_uid_gid_unique(struct list_head *list, const unsigned int id, const int type)
{
	int ret = 0;
	uinfo_t *pos = NULL;

	if (list == NULL) {
		return -1;
	}

	if (type) { /* 查gid重复 */
		list_for_each_entry(pos, list, list)
		{
			if (pos->gid == id) {
				++ret;
				// INFO("--%d=====%d-----%d\n", pos->user_name, pos->gid, id, ret);
			}
		}
	} else { /* 查uid重复 */
		list_for_each_entry(pos, list, list)
		{
			if (pos->uid == id) {
				ret++;
			}
		}
	}

	return ret;
}
static void free_list(struct list_head *list)
{
	uinfo_t *pos = NULL;
	uinfo_t *p = NULL;

	list_for_each_entry_safe(pos, p, list, list)
	{
		list_del(&pos->list);
		free(pos);
	}
	return;
}
/* linux_check_account_gid_repeat
 * GID重复账号
 * 检测是否存在gid相同的账号。
 */
static int linux_check_account_gid_repeat(cJSON *object)
{
	char line[PATH_MAX];
	char value[PATH_MAX];
	struct list_head group_list;
	struct passwd pw = {0};
	struct passwd *pwp = NULL;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;
	const char *pwd_file = "/etc/passwd";

	if (ignore_risk_key("linux_check_account_gid_repeat")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account gid fail object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account gid fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account gid repeat fail create value is NULL\n");
		goto end;
	}

	generat_group_list(&group_list);

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("group list open pwd file fail\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));
	memset(value, 0x00, sizeof(value));

	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("group list: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}

		ret = is_uid_gid_unique(&group_list, pw.pw_gid, 1);
		if (ret > 1) { /* 有重复 */
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
			status = 0;
		}
	}
	fclose(fp);

	free_list(&group_list);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_gid_repeat");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	free_list(&group_list);
	return -1;
}

/* linux_check_account_uid_repeat
 * UID重复账号
 * 检测是否存在uid相同的账号
 */
static int linux_check_account_uid_repeat(cJSON *object)
{
	char line[PATH_MAX];
	char value[PATH_MAX];
	struct list_head user_list;
	struct passwd pw = {0};
	struct passwd *pwp = NULL;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;
	const char *pwd_file = "/etc/passwd";

	if (ignore_risk_key("linux_check_account_uid_repeat")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account gid fail object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account gid fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account uid repeat fail create value is NULL\n");
		goto end;
	}

	generat_user_list(&user_list);

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("user list open pwd file fail\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));
	memset(value, 0x00, sizeof(value));

	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("user list: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}

		ret = is_uid_gid_unique(&user_list, pw.pw_uid, 0);
		if (ret > 1) { /* 有重复 */
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
			status = 0;
		}
	}
	fclose(fp);

	free_list(&user_list);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_uid_repeat");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	free_list(&user_list);
	return -1;
}

/* linux_check_account_shadow_perm_high
 * /etc/shadow权限检查
 * 检测最大权限是否为600、用户、用户组是否为root,root/shadow
 */
static int linux_check_account_shadow_perm_high(cJSON *object)
{
	struct stat file_st;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	const char *shadow_file = "/etc/shadow";

	if (ignore_risk_key("linux_check_account_shadow_perm_high")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account fail lock object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account fail lock create object is NULL\n");
		return -1;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		cJSON_Delete(arguments);
		MON_ERROR("check account shadow fail create value is NULL\n");
		return -1;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);

	if (stat(shadow_file, &file_st) != 0) {
		status = 0;
	} else {
#ifdef SNIPER_FOR_DEBIAN
		if (file_st.st_uid != 0 || file_st.st_gid != 42 || file_st.st_mode != 33184) {
#else
		if (file_st.st_uid != 0 || file_st.st_gid != 0 || file_st.st_mode != 32768) {
#endif
			status = 0;
		}
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_shadow_perm_high");
	cJSON_AddItemToArray(value_arr, cJSON_CreateString(shadow_file));
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
}

/* linux_check_account_no_wheel_group_user_su
 * 任意用户如果获知root密码均可su到root用户
 * 判断/etc/pam.d/su文件中是否存在auth required pam_wheel.so use_uid
 */
static int linux_check_account_no_wheel_group_user_su(cJSON *object)
{
	char line[PATH_MAX];
	const char *conf_file = "/etc/pam.d/su";
	char *start = NULL;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;

	if (ignore_risk_key("linux_check_account_no_wheel_group_user_su")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account wheel fail lock object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account wheel fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account wheel fail create value is NULL\n");
		goto end;
	}

	fp = fopen(conf_file, "r");
	if (!fp) {
		MON_ERROR("check account pwd policy open file %s fail\n", conf_file);
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));
	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		start = trim_space(line);
		if (!start || *start == '#' || *start == '\0') {
			continue;
		}
		if (strncmp(start, "auth", 4) != 0) {
			continue;
		}

		start += 4;
		start = strstr(start, "required");
		if (!start) {
			status = 0;
			continue;
		}

		start += 8;
		start = strstr(start, "pam_wheel.so");
		if (!start) {
			status = 0;
			continue;
		}
		start += 12;
		start = strstr(start, "use_uid");
		if (!start) {
			status = 0;
			continue;
		}
		status = 1;
		break;
	}
	fclose(fp);

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_no_wheel_group_user_su");
	cJSON_AddItemToArray(value_arr, cJSON_CreateString(conf_file));
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/* linux_check_account_system_login
 * uid为1~499一般为系统账号，此类账号若可登录系统可能会带来一定的安全风险
 * 检测Uid为1~499的账号是否可交互登录系统
 */
static int linux_check_account_system_login(cJSON *object)
{
	char line[PATH_MAX];
	char value[PATH_MAX];
	struct passwd pw = {0};
	struct passwd *pwp = NULL;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	const char *pwd_file = "/etc/passwd";
	FILE *fp = NULL;

	if (ignore_risk_key("linux_check_account_system_login")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account fail lock object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account fail lock create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account fail lock fail create value is NULL\n");
		goto end;
	}

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("user list open pwd file fail\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));
	memset(value, 0x00, sizeof(value));
	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("user list: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}
		if (pw.pw_uid < 499 && pw.pw_uid > 0) {
			if (!strstr(pw.pw_shell, "bash")) { /* 没有找到nologin视为非法 */
				continue;
			}
			// INFO("-----%s-%d-%s\n", pw.pw_name, pw.pw_uid, pw.pw_shell);
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
			status = 0;
		}
	}
	fclose(fp);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_system_login");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/* linux_check_account_empty_pwd_sudo
 * 免密码可sudo的账号
 * 检测是否存在无需密码可sudo到其他用户的账号
 * eg.
 * user123 ALL=(ALL) NOPASSWD: ALL
 * %admin ALL=(ALL) NOPASSWD: ALL
 */
static int linux_check_account_empty_pwd_sudo(cJSON *object)
{
	char line[PATH_MAX];
	char value[PATH_MAX];
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	const char *conf_file = "/etc/sudoers";
	FILE *fp = NULL;
	char *start = NULL;
	char *tmp = NULL;

	if (ignore_risk_key("linux_check_account_empty_pwd_sudo")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account empty pwd fail object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account empty pwd fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account empty pwd fail create value is NULL\n");
		goto end;
	}

	fp = fopen(conf_file, "r");
	if (!fp) {
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(line, 0x00, sizeof(line));
	memset(value, 0x00, sizeof(value));

	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		start = trim_space(line);
		if (!start || *start == '#' || *start == '\0') {
			continue;
		}

		tmp = strchr(start, ' ');
		if (tmp) {
			*tmp = '\0';
			tmp++;
		} else {
			tmp = strchr(start, '\t');
			*tmp = '\0';
			tmp++;
		}

		tmp = strstr(tmp, "NOPASSWD");
		if (tmp) { /* 只要有NOPASSWD就算，不用管具体哪几个命令 */
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(start));
			status = 0;
		}
	}
	fclose(fp);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_empty_pwd_sudo");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/*
 * linux_check_account_exists_unnecessary
 * 检测是否存在180天未登陆且为弱口令的应用账号
 */
// TODO 代码逻辑完全错误，要重写
#define DAY180 180 * 24 * 3600
static void linux_check_account_exists_unnecessary(cJSON *object)
{
	char line[PATH_MAX] = {0};
	char buf[PATH_MAX] = {0};
	struct spwd user_info;
	struct passwd pw;
	struct passwd *pwp = NULL;
	struct spwd *user_infop = NULL;
	int ret = 0, i = 0;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;
	const char *pwd_file = "/etc/passwd";

	if (ignore_risk_key("linux_check_account_exists_unnecessary")) {
		return;
	}

	if (object == NULL) {
		MON_ERROR("check account fail lock object is NULL\n");
		return;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account exists unnecessary fail create object is NULL\n");
		return;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account exists unnecessary fail create value is NULL\n");
		cJSON_Delete(arguments);
		return;
	}

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("check account exists unnecessary is open pwd file fail\n");
		cJSON_Delete(arguments);
		cJSON_Delete(value_arr);
		return;
	}

	cJSON_AddItemToObject(arguments, "value", value_arr);

	while (1) {
		if (fgetpwent_r(fp, &pw, line, sizeof(line), &pwp) != 0) {  // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("get account info: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}

		getspnam_r(pw.pw_name, (struct spwd *)&user_info, buf, PATH_MAX, (struct spwd **)&user_infop);
		if (user_infop == NULL) {
			break;
		}
		if (pw.pw_uid == 0 || strstr(pw.pw_shell, "nologin")) {
			continue;
		}
		// INFO("----%s----=%ld\n", pw.pw_name, user_info->sp_expire);
		i = 0;
		while (app_account[i]) {
			if (strcmp(app_account[i], pw.pw_name) == 0) {
				// 账户上次登录
				struct utmp *u = NULL;
				utmpname(_PATH_WTMP);
				setutent();
				while ((u = getutent())) {
					if (u->ut_type == EMPTY || u->ut_type == RUN_LVL || u->ut_type == BOOT_TIME) {
						continue;
					}

					// if (strncmp(u->ut_user, "reboot", 6) == 0 || strncmp(u->ut_user, "runlevel", 8)) {
					//     continue;
					// }

					/*
					 * 用strcmp(u->ut_user, app_account[i])，centos8编译会报警告，
					 * 数据结构utmp声明如下，__attribute_nonstring__字符数组未必是以0结尾的
					 * struct utmp
					 * {
					 *   ......
					 *   char ut_line[UT_LINESIZE]
					 *     __attribute_nonstring__;    // Devicename.
					 *   char ut_id[4]
					 *     __attribute_nonstring__;    // Inittab ID.
					 *   char ut_user[UT_NAMESIZE]
					 *     __attribute_nonstring__;    // Username.
					 *   char ut_host[UT_HOSTSIZE]
					 *     __attribute_nonstring__;    // Hostname for remote login.
					 *   ......
					 * }
					 */
					if (strncmp(u->ut_user, app_account[i], UT_NAMESIZE) == 0) {
						time_t curr_seconds;
						time(&curr_seconds);
						if (curr_seconds - u->ut_tv.tv_sec > DAY180) {
							ret = 100;
						}
						// INFO("--%s====%d===++%ld==%ld==%ld\n",
						//                 u->ut_user, u->ut_type, u->ut_session,
						//                 u->ut_tv.tv_sec/(3600*24), curr_seconds/(3600*24));
					}
					// if (u->ut_type != 1 && u->ut_type != 2) continue;
				}
				endutent();

				if (ret != 100) {
					i++;
					continue;
				}

				if (check_weakpwd(pwp->pw_name, user_infop->sp_pwdp, NULL) < 0) {  // 未命中或出错
					i++;
					continue;
				}
				/* 是弱密码 */
				status = 0;
				cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
			}
			i++;
		}
	}
	fclose(fp);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_exists_unnecessary");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);
}

/* linux_check_account_pwd_no_expire
 * 存在不必要的系统账号
 * 检测是否存在可登陆系统，且未设置密码过期时间的非root账号。密码到期天数为-1或者99999表示未设置过期时间
 */
static int linux_check_account_pwd_no_expire(cJSON *object)
{
	char line[PATH_MAX];
	char buf2[PATH_MAX];
	char value[PATH_MAX];
	struct spwd user_info;
	struct passwd pw;
	struct passwd *pwp = NULL;
	struct spwd *user_infop = NULL;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;
	const char *pwd_file = "/etc/passwd";

	if (ignore_risk_key("linux_check_account_pwd_no_expire")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account fail lock object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account pwd no expire fail create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account pwd no expire fail create value is NULL\n");
		goto end;
	}

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("check account exists is open pwd file fail\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(value, 0x00, sizeof(value));

	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("get account info: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}

		getspnam_r(pw.pw_name, (struct spwd *)&user_info, buf2, PATH_MAX, (struct spwd **)&user_infop);
		if (user_infop == NULL) {
			break;
		}
		if (pw.pw_uid == 0 || strstr(pw.pw_shell, "nologin")) {
			continue;
		}
		// INFO("----%s----=%ld\n", pw.pw_name, user_info->sp_expire);
		if (user_infop->sp_expire == -1 || user_infop->sp_expire == 99999) {
			cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
			status = 0;
		}
	}
	fclose(fp);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_pwd_no_expire");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

/* linux_check_account_expire
 * 失效却未删除的账户
 * 检测账号到期时间，若当前时间大于设定的账号到期时间，则认为应当删除
 */
static int linux_check_account_expire(cJSON *object)
{
	char line[PATH_MAX];
	char buf2[PATH_MAX];
	char value[PATH_MAX];
	struct spwd user_info;
	struct passwd pw;
	struct passwd *pwp = NULL;
	struct spwd *user_infop = NULL;
	int ret = 1;
	int status = 1; /* 0 未通过 1 通过 */
	cJSON *arguments = NULL;
	cJSON *value_arr = NULL;
	FILE *fp = NULL;
	const char *pwd_file = "/etc/passwd";

	if (ignore_risk_key("linux_check_account_expire")) {
		return -1;
	}

	if (object == NULL) {
		MON_ERROR("check account expire object is NULL\n");
		return -1;
	}

	arguments = cJSON_CreateObject();
	if (!arguments) {
		MON_ERROR("check account expire create object is NULL\n");
		goto end;
	}
	value_arr = cJSON_CreateArray();
	if (!value_arr) {
		MON_ERROR("check account expire fail create value is NULL\n");
		goto end;
	}

	fp = fopen(pwd_file, "r");
	if (!fp) {
		MON_ERROR("check account expire is open pwd file fail\n");
		goto end;
	}
	cJSON_AddItemToObject(arguments, "value", value_arr);
	memset(value, 0x00, sizeof(value));

	while (1) {
		ret = fgetpwent_r(fp, &pw, line, sizeof(line), &pwp);
		if (ret != 0) {	 // 结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("get account info: getpwent_r fail: %s\n", strerror(errno));
			}
			/* 出错时，如ERANGE，不会自动跳过出错的行，因此出错也就退出 */
			break;
		}

		getspnam_r(pw.pw_name, (struct spwd *)&user_info, buf2, PATH_MAX, (struct spwd **)&user_infop);
		if (user_infop == NULL) {
			break;
		}
		if (pw.pw_uid == 0 || strstr(pw.pw_shell, "nologin")) {
			continue;
		}
		time_t curr_seconds;
		time(&curr_seconds);

		// INFO("1111----%s----=%ld---%ld\n", pw.pw_name, user_info->sp_expire, curr_seconds/(3600*24));
		if (user_infop->sp_expire == -1 || user_infop->sp_expire == 99999) { /* 没有设置过期的账户 */
			continue;
		} else {
			if (curr_seconds / (3600 * 24) > user_infop->sp_expire) { /* 账户过期 */
				// INFO("1111----%s----=%ld---%ld\n", pw.pw_name, user_info->sp_expire, curr_seconds/(3600*24));
				cJSON_AddItemToArray(value_arr, cJSON_CreateString(pw.pw_name));
				status = 0;
			}
		}
	}
	fclose(fp);

	if (status) {
		cJSON_AddItemToArray(value_arr, cJSON_CreateString(""));
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_account_expire");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(object, arguments);

	return ret;
end:
	if (arguments) {
		cJSON_Delete(arguments);
	}
	if (value_arr) {
		cJSON_Delete(value_arr);
	}
	if (fp) {
		fclose(fp);
	}
	return -1;
}

void test_sys_risk_check(void)
{
	cJSON *object = cJSON_CreateObject();
	cJSON *items = cJSON_CreateArray();

	cJSON_AddItemToObject(object, "items", items);

	// linux_check_account_fail_lock_empty(items);
	// linux_check_account_exists_home_any_write(items);
	linux_check_account_pwd_complex_policy(items);
	// linux_check_account_num(items);
	// linux_check_account_gid_repeat(items);
	// linux_check_account_shadow_perm_high(items);
	// linux_check_account_no_wheel_group_user_su(items);
	// linux_check_account_empty_pwd_sudo(items);
	// linux_check_account_uid_repeat(items);
	// linux_check_account_system_login(items);
	// linux_check_account_app_allow_login(items);
	// linux_check_account_exists_suspicious_pam_auth(items);
	// linux_check_account_exists_suspicious_sudo_pam(items);
	// linux_check_account_exists_suspicious_su_pam(items);
	// linux_check_account_exists_unnecessary(items);
	// linux_check_account_pwd_no_expire(items);
	// linux_check_account_expire(items);
	INFO("---%s\n", cJSON_PrintUnformatted(object));

	return;
}

char tmp_suspicious_ext[][8] = {"zip", "tar", "gz", "bz2", "rar", "c", "cpp", "jar", "sql", "elf", "pipe", ""};
/* 1.检测tmp目录下是否存在可疑文件。返回1，有可疑文件 */
// TODO 当前只报告了第一个检测到的可疑文件，后面可以改成某个短的时间里(如3秒内)找到的所有可疑文件，使得尽量一次报告所有可疑文件，又不长时间吊住
static int check_tmp_suspicious_file_inpath(char *path, cJSON *value)
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

			sprintf(subpath, "%s/%s", path, ent->d_name);
			if (check_tmp_suspicious_file_inpath(subpath, value)) {
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
		while (tmp_suspicious_ext[i][0]) {
			if (strcmp(ext, tmp_suspicious_ext[i]) == 0) {
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

static void check_tmp_suspicious_file(cJSON *object)
{
	int ret = 0;

	if (ignore_risk_key("linux_check_tmp_suspicious_file")) {
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

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_tmp_suspicious_file");

	ret = check_tmp_suspicious_file_inpath("/tmp", value);
	if (ret == 0) {
		cJSON_AddNumberToObject(arguments, "status", 1);  // 没有可疑文件，无风险
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);  // 有风险
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*2.检测系统进程中是否存在syslog相关的进程*/
void check_syslog_status(cJSON *object)
{
	DIR *dirp = NULL;
	FILE *fp = NULL;
	struct dirent *pident = 0;
	int pid = 0;
	char path[512] = {0}, buf[1024] = {0};
	char *search = NULL, *t = NULL;

	if (ignore_risk_key("linux_check_syslog_service")) {
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

	dirp = opendir("/proc");
	if (!dirp) {
		MON_ERROR("open dir fail\n");
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while ((pident = readdir(dirp))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue;  // 忽略非进程
		}
		pid = atoi(pident->d_name);

		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue;  // 忽略内核线程
		}

		snprintf(path, 512, "/proc/%d/comm", pid);
		fp = fopen(path, "r");
		if (!fp) {
			continue;
		}

		fgets(buf, 1024, fp);
		fclose(fp);
		t = strtok(buf, "\n");
		search = strstr(t, "rsyslog");
		if (search) {
			syslog = 1;
			cJSON_AddItemToArray(value, cJSON_CreateString(t));
		}
	}

	closedir(dirp);
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_syslog_service");

	if (syslog) {
		cJSON_AddNumberToObject(arguments, "status", 1);
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
	syslog = 0;
}

/*3.检测ldpreload环境变量(LD_PRELOAD)与配置文件(/etc/ld.so.preload)是否存在配置参数*/  //?????????????????????????
void check_ld_preload(cJSON *object)
{
	FILE *fp = NULL, *pp = NULL;
	char buf[1024] = {0}, pp_buf[1024] = {0};
	char *result = NULL;

	if (ignore_risk_key("linux_check_no_ldpreload")) {
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

	fp = fopen("/etc/ld.so.preload", "r");

	pp = popen("env", "r");

	if (!pp) {
		if (fp) {
			fclose(fp);
		}
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while (fgets(pp_buf, 1024, pp)) {
		// printf("%s\n", pp_buf);
		result = strstr(pp_buf, "LD_PRELOAD");
		if (result) {
			ld_env = 1;
		}
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_no_ldpreload");
	/*文件不存在，就没有配置可疑参数*/
	if (fp) {
		while (fgets(buf, 1024, fp)) {
			if (buf[0] == '#') {
				continue;
			}

			if (buf != NULL) {
				ld_file = 1;
			}
		}
		fclose(fp);
	}

	if (ld_env == 1 || ld_file == 1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		if (ld_env == 1) {
			cJSON_AddItemToArray(value, cJSON_CreateString("环境变量存在该字段"));
		} else if (ld_file == 1) {
			cJSON_AddItemToArray(value, cJSON_CreateString("文件中存在该字段"));
		}
	} else {
		cJSON_AddNumberToObject(arguments, "status", 1);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*4.检测配置文件umask值是否为期望值*/
void check_config_umask(cJSON *object)
{
	struct stat sb; /*- 定义stat结构--*/
	char buf[1024] = {0};
	unsigned int mask = 0000777;

	if (ignore_risk_key("linux_check_umask_vaule_error")) {
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
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_umask_vaule_error");

	if (stat("/etc/profile", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/profile"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode & 022)  // S_IWGRP|S_IWOTH
	{
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/etc/profile", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/etc/login.defs", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/login.defs"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33188) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/etc/login.defs", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/root/.bashrc", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/root/.bashrc"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33188) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/root/.bashrc", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/root/.bash_profile", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/root/.bash_profile"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33188) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/root/.bash_profile", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/root/.cshrc", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/root/.cshrc"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33188) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/root/.cshrc", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/root/.tcshrc", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/root/.tcshrc"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33188) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/root/.tcshrc", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/etc/bashrc", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/bashrc"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33188) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/etc/bashrc", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/etc/csh.cshrc", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/csh.cshrc"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33188) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o", "/etc/csh.cshrc", mask & sb.st_mode);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (stat("/etc/sysconfig/init", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/sysconfig/init"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	if (sb.st_mode != 33256 || sb.st_uid != 0 || sb.st_gid != 0) {
		file_umask = 1;

		snprintf(buf, 1024, "%s:%o  uid:%d  gid:%d", "/etc/sysconfig/init", mask & sb.st_mode, sb.st_uid, sb.st_gid);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	if (file_umask == 0) {
		cJSON_AddNumberToObject(arguments, "status", 1);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
	}
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*5.检测/proc/sys/net/ipv4/tcp_syncookies值是否为1*/
void check_tcp_synccookies(cJSON *object)
{
	FILE *fp = NULL;
	char buf[128] = {0};

	if (ignore_risk_key("linux_check_ipv4_tcp_syncookies")) {
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

	fp = fopen("/proc/sys/net/ipv4/tcp_syncookies", "r");

	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	fgets(buf, 128, fp);
	fclose(fp);

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_ipv4_tcp_syncookies");

	if (atoi(buf) == 1) {
		cJSON_AddNumberToObject(arguments, "status", 1);
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
	}
	buf[strlen(buf + 1)] = '\0';
	cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*6.检测/proc/sys/net/ipv4/ip_forward值是否为1*/
void check_ip_forward(cJSON *object)
{
	FILE *fp = NULL;
	char buf[128] = {0};

	if (ignore_risk_key("linux_check_ip_forward")) {
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

	fp = fopen("/proc/sys/net/ipv4/ip_forward", "r");

	if (!fp) {
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	fgets(buf, 128, fp);
	fclose(fp);

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_ip_forward");

	if (atoi(buf) == 1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
	} else {
		cJSON_AddNumberToObject(arguments, "status", 1);
	}
	buf[strlen(buf + 1)] = '\0';
	cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*7.检测网卡是否处于混杂模式(promisc)*/
void check_net_mode(cJSON *object)
{
	DIR *dirp = NULL;
	FILE *fp = NULL;
	struct dirent *pident = 0;
	char fd[512] = {0}, buf[1024] = {0};
	int result = 0;

	if (ignore_risk_key("linux_check_eth_promisc")) {
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

	dirp = opendir("/sys/class/net");
	if (!dirp) {
		MON_ERROR("open dir fail\n");
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	while ((pident = readdir(dirp))) {
		/*忽略非进程*/
		if (strcmp(pident->d_name, "lo") == 0) {
			continue;
		}

		if (pident->d_name[0] == '.') {
			continue;
		}

		snprintf(fd, 512, "/sys/class/net/%s/flags", pident->d_name);
		// printf("%s\n", pident->d_name);
		fp = fopen(fd, "r");
		if (!fp) {
			continue;
		}

		fgets(buf, 1024, fp);
		result = strtol(buf, NULL, 16);
		cJSON_AddStringToObject(arguments, "rule_key", "linux_check_eth_promisc");

		if (result == 4355) {
			net_promisc = 1;
			cJSON_AddItemToArray(value, cJSON_CreateString(pident->d_name));
		} else {
			cJSON_AddItemToArray(value, cJSON_CreateString(pident->d_name));
		}
		fclose(fp);
	}
	if (net_promisc) {
		cJSON_AddNumberToObject(arguments, "status", 0);
	} else {
		cJSON_AddNumberToObject(arguments, "status", 1);
	}
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
	net_promisc = 0;
	closedir(dirp);
}

/*8.检测/etc/grub.conf或/etc/grub.d/40_custom是否存在password字段*/
void check_grub_custom_passwd(cJSON *object)
{
	FILE *fp_grub = NULL, *fp_custom = NULL;
	char buf[1024] = {0};
	char *ret_grub = NULL, *ret_custom = NULL;

	if (ignore_risk_key("linux_check_grub_pwd_exist")) {
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

	fp_grub = fopen("/etc/grub.conf", "r");
	fp_custom = fopen("/etc/grub.d/40_custom", "r");

	if (fp_grub) {
		while (fgets(buf, 1024, fp_grub)) {
			if (buf[0] == '#') {
				continue;
			}
			ret_grub = strstr(buf, "password");
		}
		fclose(fp_grub);
	}

	if (fp_custom) {
		while (fgets(buf, 1024, fp_custom)) {
			if (buf[0] == '#') {
				continue;
			}
			ret_custom = strstr(buf, "password");
		}
		fclose(fp_custom);
	}
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_grub_pwd_exist");

	if (ret_custom) {
		grub = 1;
		cJSON_AddItemToArray(value, cJSON_CreateString("/etc/grub.d/40_custom"));
	}
	if (ret_grub) {
		grub = 1;
		cJSON_AddItemToArray(value, cJSON_CreateString("/etc/grub.conf"));
	}
	if (grub) {
		cJSON_AddNumberToObject(arguments, "status", 1);
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	}
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*9.检查var/spool/cron目录所有者、组所有者读写执行权限*/
void mode_to_letter(cJSON *object)
{
	struct stat sb; /*- 定义stat结构--*/
	char buf[512] = {0};
	unsigned int mask = 0000777;

	if (ignore_risk_key("linux_check_spool_cron")) {
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

	if (stat("/var/spool/cron", &sb) == -1) { /*-stat函数，详情请 man 2 stat 查看 -*/
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/var/spool/cron"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_spool_cron");

	if ((unsigned long)sb.st_mode == 16832 && (unsigned long)sb.st_uid == 0 && (unsigned long)sb.st_gid == 0) {
		cJSON_AddNumberToObject(arguments, "status", 1);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
		snprintf(buf, 512, "%lo, %lu, %lu", (unsigned long)sb.st_mode & mask, (unsigned long)sb.st_uid, (unsigned long)sb.st_gid);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
	// printf("/var/spool/cron：%d\n", (unsigned long)sb.st_uid);
	// printf("/var/spool/cron：%d\n", (unsigned long)sb.st_gid);
}

/*10./etc/crontab文件所有者、组所有者、权限检查*/
void mode_to_crontab(cJSON *object)
{
	struct stat sb; /*- 定义stat结构--*/
	char buf[512] = {0};
	unsigned int mask = 0000777;

	if (ignore_risk_key("linux_check_etc_crontab")) {
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

	if (stat("/etc/crontab", &sb) == -1) { /*-stat函数，详情请 man 2 stat 查看 -*/
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/crontab"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_etc_crontab");
	// printf("%d\n", (unsigned long)sb.st_mode);
	if ((unsigned long)sb.st_mode == 33188 && (unsigned long)sb.st_uid == 0 && (unsigned long)sb.st_gid == 0) {
		cJSON_AddNumberToObject(arguments, "status", 1);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
		snprintf(buf, 512, "%lo, %lu, %lu", (unsigned long)sb.st_mode & mask, (unsigned long)sb.st_uid, (unsigned long)sb.st_gid);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*11./etc/anacrontab 文件所有者、组所有者、权限检查*/
void mode_to_anacrontab(cJSON *object)
{
	struct stat sb; /*- 定义stat结构--*/
	char buf[512] = {0};
	unsigned int mask = 0000777;

	if (ignore_risk_key("linux_check_etc_anacrontab")) {
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

	if (stat("/etc/anacrontab", &sb) == -1) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/anacrontab"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_etc_anacrontab");
	// printf("+++%d, %d\n", (unsigned long)sb.st_uid, (unsigned long)sb.st_gid);
	if ((unsigned long)sb.st_mode == 33188 && (unsigned long)sb.st_uid == 0 && (unsigned long)sb.st_gid == 0) {
		cJSON_AddNumberToObject(arguments, "status", 1);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
		snprintf(buf, 512, "%lo, %lu, %lu", (unsigned long)sb.st_mode & mask, (unsigned long)sb.st_uid, (unsigned long)sb.st_gid);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*12./etc/passwd权限检查*/
void mode_to_passwd(cJSON *object)
{
	struct stat sb; /*- 定义stat结构--*/
	char buf[512] = {0};
	unsigned int mask = 0000777;

	if (ignore_risk_key("linux_check_etc_passwd")) {
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

	if (stat("/etc/passwd", &sb) == -1) { /*-stat函数，详情请 man 2 stat 查看 -*/
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/passwd"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	// printf("%d\n", (unsigned long)sb.st_mode);
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_etc_passwd");
	if ((unsigned long)sb.st_mode == 33188 && (unsigned long)sb.st_uid == 0 && (unsigned long)sb.st_gid == 0) {
		cJSON_AddNumberToObject(arguments, "status", 1);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
		snprintf(buf, 512, "%lo, %lu, %lu", (unsigned long)sb.st_mode & mask, (unsigned long)sb.st_uid, (unsigned long)sb.st_gid);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*13./etc/gshadow权限检查*/
void mode_to_gshadow(cJSON *object)
{
	struct stat sb; /*- 定义stat结构--*/
	char buf[512] = {0};
	unsigned int mask = 0000777;

	if (ignore_risk_key("linux_check_etc_gshadow")) {
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

	if (stat("/etc/gshadow", &sb) == -1) { /*-stat函数，详情请 man 2 stat 查看 -*/
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("没有文件/etc/gshadow"));
		cJSON_AddItemToObject(arguments, "value", value);
		cJSON_AddItemToArray(object, arguments);
		return;
	}
	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_etc_gshadow");
	// printf("%d\n", (unsigned long)sb.st_mode);
	if ((unsigned long)sb.st_mode == 33024 && (unsigned long)sb.st_uid == 0 && (unsigned long)sb.st_gid == 0) {
		cJSON_AddNumberToObject(arguments, "status", 1);
		cJSON_AddItemToArray(value, cJSON_CreateString(""));
	} else {
		cJSON_AddNumberToObject(arguments, "status", 0);
		snprintf(buf, 512, "%lo, %lu, %lu", (unsigned long)sb.st_mode & mask, (unsigned long)sb.st_uid, (unsigned long)sb.st_gid);
		cJSON_AddItemToArray(value, cJSON_CreateString(buf));
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*14.检测SSH配置文件Protocol值是否为2*/
void check_sshd_protocol(cJSON *object)
{
	FILE *fp = NULL;
	char buf[1024] = {0}, protocol[128] = {0};
	char *text = NULL;

	if (ignore_risk_key("linux_check_ssh_ver")) {
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
		MON_ERROR("open file /etc/ssh/sshd_config failed\n");
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_ssh_ver");

	while (fgets(buf, 1024, fp)) {
		if (buf[0] == '#') {
			continue;
		}
		text = strstr(buf, "Protocol");
		if (text) {
			protocol_number = 1;
			// printf("%s\n", text);
			sscanf(text, "%*s %s", protocol);
			INFO("Item /etc/ssh/sshd_config protocol:%d\n", atoi(protocol));
			if (atoi(protocol) == 2) {
				cJSON_AddNumberToObject(arguments, "status", 1);
				cJSON_AddItemToArray(value, cJSON_CreateString(""));
			} else {
				cJSON_AddNumberToObject(arguments, "status", 0);
				cJSON_AddItemToArray(value, cJSON_CreateString(protocol));
			}
		}
	}
	if (!protocol_number) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		cJSON_AddItemToArray(value, cJSON_CreateString("No Text Protocol!"));
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
	fclose(fp);
	protocol_number = 0;
}

/*15.检测配置文件Ciphers值是否包含aes128-ctr,aes192-ctr,aes256-ctr*/
void check_sshd_ciphers(cJSON *object)
{
	FILE *fp = NULL;
	char buf[1024] = {0};
	char *text = NULL;
	char *first = NULL, *second = NULL, *third = NULL;

	if (ignore_risk_key("linux_check_ssh_ciphers_pro")) {
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
		MON_ERROR("open file /etc/ssh/sshd_config failed\n");
		cJSON_Delete(value);
		cJSON_Delete(arguments);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_ssh_ciphers_pro");

	while (fgets(buf, 1024, fp)) {
		if (buf[0] == '#') {
			continue;
		}
		buf[strlen(buf + 1)] = '\0';

		text = strstr(buf, "Ciphers");
		if (text) {
			first = strstr(text, "aes128-ctr");

			second = strstr(text, "aes192-ctr");

			third = strstr(text, "aes256-ctr");
			if (first && third && second) {
				cJSON_AddNumberToObject(arguments, "status", 1);
				cJSON_AddItemToArray(value, cJSON_CreateString(""));
			} else {
				cipher = 1;
			}
			break;
		}
	}

	if (cipher) {
		cJSON_AddNumberToObject(arguments, "status", 0);
		// cJSON_AddItemToArray(value, cJSON_CreateString(buf + 7));
	}

	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
	fclose(fp);
}

static void build_check_time_result(cJSON *object, int status, char *timestr)
{
	cJSON *value = NULL, *arguments = NULL;

	if (!object || !timestr) {
		return;
	}

	value = cJSON_CreateArray();
	if (value == NULL) {
		return;
	}

	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(value);
		return;
	}

	cJSON_AddStringToObject(arguments, "rule_key", "linux_check_server_time");
	cJSON_AddNumberToObject(arguments, "status", status);
	cJSON_AddItemToArray(value, cJSON_CreateString(timestr));
	cJSON_AddItemToObject(arguments, "value", value);
	cJSON_AddItemToArray(object, arguments);
}

/*16.判断服务器时间和标准时间是否存在差值*/
void check_time(cJSON *object)
{
	int sock_fd = 0;
	struct sockaddr_in addr_serv;
	char recv_buf[1024] = {0};
	struct tm *local = NULL;
	time_t t = 0;
	char *ptr = NULL, *ptr2 = NULL, *server_timestr = "";
	char timestr[32] = {0};
	char *send_buf = "GET /getSysTime.do HTTP/1.1\r\nHost: quan.suning.com\r\n\r\n\r\n";
	char *time_server = "quan.suning.com";
	int port = 80;
	struct hostent *hostInfo = NULL;

	if (ignore_risk_key("linux_check_server_time")) {
		return;
	}

	t = time(NULL);
	local = localtime(&t);
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", local);

	// 域名通过gethostbyname转换
	hostInfo = gethostbyname(time_server);
	if (NULL == hostInfo) {
		MON_ERROR("check_time fail, gethostbyname %s error: %s\n", time_server, strerror(errno));
		build_check_time_result(object, 0, timestr);
		return;
	}
	memset(&addr_serv, 0, sizeof(addr_serv));
	addr_serv.sin_family = AF_INET;
	addr_serv.sin_port = htons(port);
	memcpy(&addr_serv.sin_addr, &(*hostInfo->h_addr_list[0]), hostInfo->h_length);

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		MON_ERROR("check_time fail, socket error: %s\n", strerror(errno));
		build_check_time_result(object, 0, timestr);
		return;
	}

	if (connect(sock_fd, (struct sockaddr *)(&addr_serv), sizeof(addr_serv)) < 0) {
		MON_ERROR("check_time fail, connect %s error: %s\n", time_server, strerror(errno));
		build_check_time_result(object, 0, timestr);
		close(sock_fd);
		return;
	}

	if (send(sock_fd, send_buf, strlen(send_buf), 0) < 0) {
		MON_ERROR("check_time fail, sendto %s error: %s\n", time_server, strerror(errno));
		build_check_time_result(object, 0, timestr);
		close(sock_fd);
		return;
	}

	if (recv(sock_fd, recv_buf, strlen(recv_buf), 0) < 0) {
		MON_ERROR("check_time fail, recvfrom %s error: %s\n", time_server, strerror(errno));
		build_check_time_result(object, 0, timestr);
		close(sock_fd);
		return;
	}

	close(sock_fd);

	// 解析服务器返回的时间数据，由于数据结构比较简单，就没有使用json解析
	/*
	 * 服务器返回结果如下所示
	 *  HTTP/1.1 200 OK
	 *  Date: Thu, 04 Nov 2021 13:19:13 GMT
	 *  Content-Type: text/html;charset=UTF-8
	 *  Content-Length: 62
	 *  Connection: keep-alive
	 *  Server: styx
	 *  Set-Cookie: tradeLdc=NJYH;Expires=Fri, 05-Nov-21 01:19:13 GMT
	 *  Strict-Transport-Security: max-age=300
	 *  Cache-Control: no-cache,no-store,max-age=0,s-maxage=0
	 *  Access-Control-Allow-Credentials: true
	 *  X-Ser: BC38_yd-jiangsu-suzhou-11-cache-5
	 *  X-Cache: MISS from BC38_yd-jiangsu-suzhou-11-cache-5(baishan)
	 *
	 *  {"sysTime2":"2021-11-04 21:19:13","sysTime1":"20211104211913"}
	 */
	DBG2(DBGFLAG_SYSDANGER, "%s return: %s\n", time_server, recv_buf);
	ptr = strstr(recv_buf, "sysTime2");
	if (ptr) {
		ptr2 = strchr(ptr, '-');
		if (ptr2) {
			server_timestr = ptr2 - 4;
		}
	}

	DBG2(DBGFLAG_SYSDANGER, "localtime %s, servertime %s\n", timestr, server_timestr);
	/* 不比秒，一分钟内视为相同。TODO 这种比法不准确，比如21:18:59和21:19:01会认为不同，建议转为秒数比较 */
	if (strncmp(timestr, server_timestr, 16) == 0) {  // 时间相同
		build_check_time_result(object, 1, timestr);
	} else {
		build_check_time_result(object, 0, timestr);
	}
}

void check_sys_danger(task_recv_t *msg)
{
	cJSON *data = NULL, *total = NULL;
	cJSON *object = NULL, *array = NULL;
	char reply[REPLY_MAX] = {0};
	char *post = NULL, *datastr = NULL;

	if (msg == NULL || sniper_other_loadoff == 1) {
		return;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}

	array = cJSON_CreateArray();
	if (array == NULL) {
		cJSON_Delete(object);
		return;
	}

	data = cJSON_CreateObject();
	if (data == NULL) {
		cJSON_Delete(object);
		cJSON_Delete(array);
		return;
	}

	total = cJSON_CreateObject();
	if (total == NULL) {
		cJSON_Delete(object);
		cJSON_Delete(array);
		cJSON_Delete(data);
		return;
	}

	cJSON_AddStringToObject(total, "uuid", Sys_info.sku);

	cJSON_AddStringToObject(data, "cmd_id", msg->cmd_id);
	cJSON_AddNumberToObject(data, "cmd_type", msg->cmd_type);
	cJSON_AddNumberToObject(data, "result", 1);

	INFO("check_tmp_suspicious_file\n");
	check_tmp_suspicious_file(array);

	INFO("check_syslog_status\n");
	check_syslog_status(array);

	INFO("check_ld_preload\n");
	check_ld_preload(array);

	INFO("check_config_umask\n");
	check_config_umask(array);

	INFO("check_tcp_synccookies\n");
	check_tcp_synccookies(array);

	INFO("check_ip_forward\n");
	check_ip_forward(array);

	INFO("check_net_mode\n");
	check_net_mode(array);

	INFO("check_grub_custom_passwd\n");
	check_grub_custom_passwd(array);

	INFO("mode_to_letter\n");
	mode_to_letter(array);

	INFO("mode_to_crontab\n");
	mode_to_crontab(array);

	INFO("mode_to_anacrontab\n");
	mode_to_anacrontab(array);

	INFO("mode_to_passwd\n");
	mode_to_passwd(array);

	INFO("mode_to_gshadow\n");
	mode_to_gshadow(array);

	INFO("check_sshd_protocol\n");
	check_sshd_protocol(array);

	INFO("check_sshd_ciphers\n");
	check_sshd_ciphers(array);

	INFO("check_time\n");
	check_time(array);

	INFO("linux_check_account_fail_lock_empty\n");
	linux_check_account_fail_lock_empty(array);

	INFO("linux_check_account_exists_home_any_write\n");
	linux_check_account_exists_home_any_write(array);

	INFO("linux_check_account_pwd_complex_policy\n");
	linux_check_account_pwd_complex_policy(array);

	INFO("linux_check_account_num\n");
	linux_check_account_num(array);

	INFO("linux_check_account_gid_repeat\n");
	linux_check_account_gid_repeat(array);

	INFO("linux_check_account_shadow_perm_high\n");
	linux_check_account_shadow_perm_high(array);

	INFO("linux_check_account_no_wheel_group_user_su\n");
	linux_check_account_no_wheel_group_user_su(array);

	INFO("linux_check_account_empty_pwd_sudo\n");
	linux_check_account_empty_pwd_sudo(array);

	INFO("linux_check_account_uid_repeat\n");
	linux_check_account_uid_repeat(array);

	INFO("linux_check_account_system_login\n");
	linux_check_account_system_login(array);

	INFO("linux_check_account_app_allow_login\n");
	linux_check_account_app_allow_login(array);

	INFO("linux_check_account_exists_suspicious_pam_auth\n");
	linux_check_account_exists_suspicious_pam_auth(array);

	INFO("linux_check_account_exists_suspicious_sudo_pam\n");
	linux_check_account_exists_suspicious_sudo_pam(array);

	INFO("linux_check_account_exists_suspicious_su_pam\n");
	linux_check_account_exists_suspicious_su_pam(array);

	INFO("linux_check_account_exists_unnecessary\n");
	linux_check_account_exists_unnecessary(array);

	INFO("linux_check_account_pwd_no_expire\n");
	linux_check_account_pwd_no_expire(array);

	INFO("linux_check_account_expire\n");
	linux_check_account_expire(array);

	INFO("check_sys_danger done\n");

	check_application_risk(array);

	cJSON_AddItemToObject(object, "items", array);
	cJSON_AddItemToObject(data, "data", object);

	datastr = cJSON_PrintUnformatted(data);
	cJSON_Delete(data);

	cJSON_AddItemToObject(total, "data", cJSON_CreateString(datastr));

	post = cJSON_PrintUnformatted(total);
	DBG2(DBGFLAG_SYSDANGER, "sys_danger: %s\n", post);

	client_send_msg(post, reply, sizeof(reply), NOTIFY_URL, "task");

	cJSON_Delete(total);
	free(post);
	free(datastr);
}
