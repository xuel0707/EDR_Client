#define _GNU_SOURCE
#include "header.h"
#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <sqlite3.h>

int first_user_check = 0;
struct timeval usrchktv = {0};
sqlite3* user_db = NULL;
static void get_password(char *user, char *password);

const char crt_user_tbl_sql[1024] =
{
    "CREATE TABLE IF NOT EXISTS userinfo( "
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "name varchar(64) UNIQUE,"         //用户名
    "uid int,"                         //用户ID
    "gid int,"                         //用户组ID
    "grp varchar(64),"                 //主用户组名
    "grplist varchar(256),"            //用户所在的组列表
    "gecos varchar(256),"              //用户描述信息
    "password varchar(256),"           //用户登录密码
    "home varchar(128),"               //用户HOME目录
    "shell varchar(128),"              //用户登录shell
    "lastchk int);"                    //上次检查时间
};

const char* user_new_sql = "INSERT INTO userinfo VALUES(NULL,?,?,?,?,?,?,?,?,?,?);";
const char* user_chg_sql = "UPDATE userinfo SET lastchk=?,uid=?,gid=?,grp=?,grplist=?,gecos=?,password=?,home=?,shell=?,name=? WHERE id=?;";
const char* user_unchg_sql = "UPDATE userinfo SET lastchk=? WHERE id=?;";
const char* user_sdel_sql = "SELECT id,name,grp,lastchk FROM userinfo WHERE lastchk!=?;";
const char* user_del_sql = "DELETE FROM userinfo WHERE id=?;";

sqlite3_stmt* user_new_stmt = NULL;
sqlite3_stmt* user_chg_stmt = NULL;
sqlite3_stmt* user_unchg_stmt = NULL;
sqlite3_stmt* user_sdel_stmt = NULL;
sqlite3_stmt* user_del_stmt = NULL;

/*
 * 口令的格式如下面的样子
 * $6$gDV2ODDy$raRnOJ88F2RDLl74CM8vh7iGxtZZxCORSXWxCkcvaPWp5VTdjOzg8y2BF9taIzptX8xvGFnZpvItwB5yDM3G11
 * $是分隔符，第一个字段是加密方法，6代表sha512；第二个字段gDV2ODDy是salt；第三个字段raR...G11是加密后的密码
 * 但crypt()函数要求的salt值是$6$gDV2ODDy$
 */
static int get_salt(char *salt, const char *passwd)
{
	char *ptr = NULL;

	if (!salt || !passwd) {
		return 0;
	}

	snprintf(salt, S_NAMELEN, "%s", passwd);
	if (salt[0] != '$' || salt[2] != '$' || !isdigit(salt[1])) {
		return 0;
	}

	ptr = strchr(salt+3, '$');
	if (!ptr) {
		return 0;
	}

	*(ptr+1) = 0;
	return 1;
}

static int check_passwd_same_as_account(const char *username, const char *passwd)
{
	char salt[S_NAMELEN] = {0};
	char *crypt_str = NULL;
	struct crypt_data data = {{0}};

	if (!username || !passwd) {
		return 0;
	}

	DBG2(DBGFLAG_USER, "check_passwd_same_as_account user %s, passwd %s\n", username, passwd);
	if (!get_salt(salt, passwd)) {
		return 0;
	}

	crypt_str = crypt_r(username, salt, &data);
	if (!crypt_str) {
		DBG2(DBGFLAG_USER, "check_passwd_same_as_account fail, crypt error %s\n", strerror(errno));
		return 0;
	}
	if (strcmp(passwd, crypt_str) == 0) {
		DBG2(DBGFLAG_USER, "check_passwd_same_as_account true\n");
		return 1;
	}

	return 0;
}

/*
 * 检查用户密码是否为弱密码
 *  出错返回-1
 *  未命中返回 0
 *  命中弱密码库返回 PwdInWeakLib
 *  用户名密码相同返回 PwdSameAsAccount
 *  result记录弱密码的值
 */ 
//TODO username123这样的形式也是弱密码
int check_weakpwd(char *username, const char *passwd, char *result)
{
	char weak_str[WEAK_LEN] = {0};
	char salt[S_NAMELEN] = {0};
	char *crypt_str = NULL, *ptr = NULL;
	FILE *fp = NULL;

	if (username == NULL || passwd == NULL) {
		MON_ERROR("check user weakpwd is NULL\n");
		return -1;
	}

	/* 用户名和密码相同 */
	if (check_passwd_same_as_account(username, passwd)) {
		if (result) {
			snprintf(result, 64, "%s", username);
		}
		return PwdSameAsAccount;
	}

	fp = fopen(WEAK_PASSWD_FILE, "r");
	if (!fp) {
		MON_ERROR("get_password open weak lib fail: %s\n", strerror(errno));
		return -1;
	}

	get_salt(salt, passwd);
	while (fgets(weak_str, WEAK_LEN, fp)) {
		struct crypt_data data = {{0}};

		if (!weak_str[0]) {
			continue;
		}

		/* 清除尾部的换行符，但不能清除尾部的空格，因为密码尾部可以带空格，不过弱密码未必有这种情况 */
		ptr = weak_str + strlen(weak_str) -1;
		while (*ptr == '\r' || *ptr == '\n') {
			*ptr-- = '\0';
		}
		data.initialized = 0;
		crypt_str = crypt_r(weak_str, salt, &data);
		if (!crypt_str) {
			DBG2(DBGFLAG_USER, "check_weakpwd fail, crypt error %s\n", strerror(errno));
			continue;
		}

		/* 命中弱密码库 */
		if (strcmp(crypt_str, passwd) == 0) {
			if (result) {
				snprintf(result, WEAK_LEN, "%s", weak_str);
			}
			fclose(fp);
			return PwdInWeakLib;
		}
	}

	fclose(fp);
	return 0;
}

/* 
 * username, 要检查的用户名
 * app_type, 类型说明,1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
 */
int check_weak_passwd_whitelist(char *username, const unsigned int app_type)
{
	int i = 0, j = 0, ret = 0;
	char *str = NULL;

	if (!username) {
		return 0;
	}

	pthread_rwlock_rdlock(&rule_white_global.lock);
	for (i = 0; i < rule_white_global.risk.weak_passwd_num; i++) {
		for (j = 0; j < rule_white_global.risk.weak_passwd[i].rule.type_num; j++) {
			/* 匹配应用类型 */
			if (app_type == rule_white_global.risk.weak_passwd[i].rule.app_type[j].list) {
				ret = 1;
				break;
			}
		}
		if (!ret) {
			continue;
		}
		for (j = 0; j < rule_white_global.risk.weak_passwd[i].rule.list_num; j++) {
			str = rule_white_global.risk.weak_passwd[i].rule.list[j].list;
			if (strcmp(username, str) == 0) {
				DBG2(DBGFLAG_USER, "%s match weak_passwd_white_user[%d][%d] %s\n", username, i, j, str);
				pthread_rwlock_unlock(&rule_white_global.lock);
				return 1;
			}
		}
	}
	pthread_rwlock_unlock(&rule_white_global.lock);
	return 0;
}

/*
 * TODO 锁定、不可登录、禁用、启用的规则如下：
 * 口令是*或以!开头，锁定（根据passwd -S username的结果）
 * shell是/sbin/nologin或/usr/sbin/nologin、/bin/false、/bin/sync、/sbin/halt或/usr/sbin/halt、/sbin/shutdown或/usr/sbin/shutdown 不可登录
 * 密码过期，禁用
 * 剩下的即启用
 *
 * !锁定的密码，可以同时检测是否是弱密码的
 * 应用弱密码检测，增加app_type的类型，类型分为 1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
 */
/* 管控端下发任务执行弱密码检查 */
void check_user_weakpwd(task_recv_t *msg)
{
	char buf[PATH_MAX] = {0};
	char buf2[PATH_MAX] = {0};
	char reply[REPLY_MAX] = {0};
	char weak_str[WEAK_LEN] = {0};
	struct spwd spw;
	struct passwd pw;
	struct passwd *pwp = NULL;
	struct spwd *spwp = NULL;
	char *post = NULL, *tmp = NULL;
	int error = 0;
	int account_status = 1;    // 0禁用 1启用 2锁定 3不可登录
	int weak_type = 0;         // 1 空口令 2密码与用户名相同 3常见弱口令
	int ftp_ret = -1;

	if (msg == NULL || sniper_other_loadoff == 1) {
		return;
	}

	cJSON *object = cJSON_CreateObject();
	cJSON *data = cJSON_CreateObject();
	cJSON *list = cJSON_CreateObject();
	cJSON *items = cJSON_CreateArray();

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);

	cJSON_AddStringToObject(data, "cmd_id", msg->cmd_id);
	cJSON_AddNumberToObject(data, "cmd_type", msg->cmd_type);
	cJSON_AddNumberToObject(data, "result", 1);

	cJSON_AddItemToObject(data, "data", list);
	cJSON_AddItemToObject(list, "items", items);

	DBG2(DBGFLAG_USER, "check_user_weakpwd Start\n");

	/* 检测应用弱密码
	 * 检查FTP是否配置了虚拟用户，因为FTP可以使用系统用户登录
	 * 如果没有配置则在系统用户的检查结果中再加一份FTP的
	 */
	check_app_user(items, &ftp_ret);

	setpwent();
	while (1) {
		error = getpwent_r(&pw, buf, PATH_MAX, &pwp);
		if (error != 0) {
			DBG2(DBGFLAG_USER, "check_user_weakpwd fail, getpwent_r error %d\n", error);
			break;
		}

		getspnam_r(pw.pw_name, (struct spwd *)&spw, buf2, PATH_MAX, (struct spwd **)&spwp);
		if (spwp == NULL) {
			break;
		}

		/* 检查白名单 */
		if (check_weak_passwd_whitelist(pw.pw_name, 1)) {
			continue;
		}
		DBG2(DBGFLAG_USER, "check_user_weakpwd checking user:%s\n", pw.pw_name);
		// printf("%s (%d)\tHOME %s\tSHELL %s", pwp->pw_name, pwp->pw_uid, pwp->pw_dir, pwp->pw_shell);
		// printf("sp_pwdp: %s, %ld\n", spw->sp_pwdp, spw->sp_lstchg);
		/* 上次更改口令以来经过的时间 sp_lstchg
		 * 经过多少天后允许更改      sp_min
		 * 要求更改尚余天数          sp_max
		 * 到期告警天数             sp_warn
		 * 账户不活动之前剩余天数     sp_inact
		 * 账户到期天数             sp_expire
		 * 保留                    sp_flag
		 */

		memset(weak_str, 0x00, sizeof(weak_str));
		if (!spwp->sp_pwdp[0]) { /* 空密码 */
			weak_type = 1;
			if (strstr(pwp->pw_shell, "nologin")) { /* 如果是nologin，标记为锁定状态 */
				account_status = 0;
			} else {
				account_status = 1;
			}
		} else {
			//TODO 如果存在/etc/nologin文件，除了root，其他用户都不能登录

			if (spwp->sp_pwdp[0] == '*' || spwp->sp_pwdp[0] == '!') { /* 锁定/禁用 */
				account_status = 0;
				continue;
			}

			weak_type = check_weakpwd(pwp->pw_name, spwp->sp_pwdp, weak_str);
			if (weak_type <= 0) { /* 未命中或出错 */
				continue;
			}

			account_status = 1;
		}

		cJSON *item = cJSON_CreateObject();

		cJSON_AddNumberToObject(item , "uid", pw.pw_uid);
		cJSON_AddNumberToObject(item , "weak_type", weak_type);
		// 1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
		cJSON_AddNumberToObject(item , "app_type", 1);
		cJSON_AddStringToObject(item , "username", pwp->pw_name);
		cJSON_AddStringToObject(item , "passwd", weak_str);
		cJSON_AddStringToObject(item , "hash", spwp->sp_pwdp);
		cJSON_AddNumberToObject(item , "account_status", account_status);

		cJSON_AddItemToArray(items, item);

		/* 表示FTP没有配置虚拟用户，使用的是系统用户，若系统用户是弱密码，则也复制一份给FTP */
		if (ftp_ret == 0) {
			/* 检查白名单 */
			if (check_weak_passwd_whitelist(pwp->pw_name, 3)) {
				continue;
			}
			cJSON *item = cJSON_CreateObject();
			cJSON_AddNumberToObject(item , "uid", pw.pw_uid);
			cJSON_AddNumberToObject(item , "weak_type", weak_type);
			// 1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
			cJSON_AddNumberToObject(item , "app_type", 3);
			cJSON_AddStringToObject(item , "username", pwp->pw_name);
			cJSON_AddStringToObject(item , "passwd", weak_str);
			cJSON_AddStringToObject(item , "hash", spwp->sp_pwdp);
			cJSON_AddNumberToObject(item , "account_status", account_status);
			cJSON_AddItemToArray(items, item);
		}
	}
	endpwent();

	tmp = cJSON_PrintUnformatted(data);
	if (tmp) {
		cJSON_AddItemToObject(object, "data", cJSON_CreateString(tmp));

		post = cJSON_PrintUnformatted(object);
		if (post) {
			DBG2(DBGFLAG_USER, "--weak_pwd--%s\n", post);
			client_send_msg(post, reply, sizeof(reply), NOTIFY_URL, "task");
			free(post);
		}
		free(tmp);
	}
	cJSON_Delete(object);

	DBG2(DBGFLAG_USER, "check_user_weakpwd End\n");
}

/* 检查用户是否具有sudo权限
   sudo权限返回 1
   非sudo权限返回 0
   无sudo权限用户返回 2
   出错返回 -1 */
static int check_sudo_permissions(const char *username)
{
	/* Centos 检查wheel用户组
	   Ubuntu 检查sudo用户组 */
	char line[PATH_MAX];
	int ret = 0;
	int len = 0;
	char *tmp = NULL;

	if (username == NULL) {
		return -1;
	}
	if (strcmp(username, "root") == 0) {
		return 0; //排除root用户
	}

	len = strlen(username);

	FILE *fp = fopen("/etc/group", "r");
	if (!fp) {
		MON_ERROR("get_password open /etc/group fail: %s\n", strerror(errno));
		return -1;
	}

	memset(line, 0x00, sizeof(line));

	while (fgets(line, sizeof(line), fp)) {
#ifdef SNIPER_FOR_DEBIAN
		if (strncasecmp(line, "sudo", 4) != 0) {
#else
		if (strncasecmp(line, "wheel", 5) != 0) {
#endif
			continue;
		}

		tmp = strchr(line, ':');
		tmp ++;
		tmp = strchr(tmp, ':');
		tmp ++;
		tmp = strchr(tmp, ':');

		/* 如果tmp是空表示该用户组下无用户, 返回值为 2 */
		if (!tmp) {
			ret = 2;
			break;
		}

		while (tmp) {
			++ tmp;
			if (strncmp(username, tmp, len) == 0) {
				ret = 1;
				break;
			}
			tmp = strchr(tmp, ',');
		}
		break;
	}
	fclose(fp);

	return ret;
}
/* 检查当前用户对应的应用是否存在
 * 返回 1 查到用户对应的服务文件
 * 返回 0 没查到用户对应的服务文件，作为风险上报
 * 返回 -2 未服务名，不作为风险上报
 * 此处只比较默认服务名，只能用strcmp比较，例，smb和smbabc
 * TODO 当前只判断了服务的默认路径下的文件
 * 优化检索服务进程，判断是否有对应的服务
 * 对于自定义安装的服务又没有启动的情况，还要再确定下检测方案
 */
static int check_user_app(const char *username)
{
	int ret = 0;
	struct stat buf;
	char *file = NULL;

	if (username == NULL) {
		return -1;
	}

	if ((strcmp(username, "smb") == 0) || (strcmp(username, "samba") == 0)) {
		file = "/etc/samba/smb.conf";
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "ftp") == 0) { /* vsftp */
		file = "/etc/vsftpd/vsftpd.conf";
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "www") == 0 || strcmp(username, "www-data") == 0) {
#ifdef SNIPER_FOR_DEBIAN
		file = "/etc/apache2/apache2.conf";
#else
		file = "/etc/httpd/conf/httpd.conf";
#endif
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "telnetd") == 0) {
		file = "/usr/lib/systemd/system/xinetd.service";
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "sshd") == 0) {
		file = "/etc/ssh/sshd_config";
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "apache") == 0) {
		file = "/lib/systemd/system/apache2.service";
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "postgres") == 0) {
#ifdef SNIPER_FOR_DEBIAN
		file = "/var/lib/postgresql/9.5/main/postgresql.conf";
#else
		file = "/var/lib/pgsql/data/postgresql.conf";
#endif
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "mysql") == 0) {
#ifdef SNIPER_FOR_DEBIAN
		file = "/etc/mysql/my.cnf";
#else
		file = "/etc/my.cnf";
#endif
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "oracle") == 0) {
		file = "/data/oracle/product/11.2.0/network/admin/listener.ora";
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else if (strcmp(username, "nfsnobody") == 0) {
		file = "/etc/exports";
		ret = (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 1 : 0;
	} else {
		ret = -2;
	}

	return ret;
}

static int check_risk_account_whitelist(char *username)
{
	int i = 0, j = 0;
	char *str = NULL;

	if (!username) {
		return 0;
	}

	pthread_rwlock_rdlock(&rule_white_global.lock);
	for (i = 0; i < rule_white_global.risk.account_num; i++) {
		for (j = 0; j < rule_white_global.risk.account[i].rule.list_num; j++) {
			str = rule_white_global.risk.account[i].rule.list[j].list;
			if (strcmp(username, str) == 0) {
				DBG2("%s match risk_account_white_user[%d][%d] %s\n", username, i, j, str);
				pthread_rwlock_unlock(&rule_white_global.lock);
				return 1;
			}
		}
	}
	pthread_rwlock_unlock(&rule_white_global.lock);
	return 0;
}

/*
 * 风险账号
 * 只检测可登录的账号（禁用/锁定账号也是不可登录的），且
 * 密码与用户名相同；或有可疑的高权限；或疑似服务账号的账号但没有对应的服务
 *
 * TODO
 * 可疑的高权限账号，指非操作系统内置的管理员账号。目前是检测sudo账号，但这会误报，如ubuntu系统总有sudo账户，通过白名单过滤？
 * 疑似服务账号的账号应该都不能登录，能登录的反而有问题。oracle账户是个特例？待验证
 */
void detect_risk_account(task_recv_t *msg)
{
	char reply[REPLY_MAX] = {0};
	char *post = NULL, *tmp = NULL;

	if (msg == NULL || sniper_other_loadoff == 1) {
		MON_ERROR("detect_risk_account fail, null task msg\n");
		return;
	}

	cJSON *object = cJSON_CreateObject();
	cJSON *data   = cJSON_CreateObject();
	cJSON *list   = cJSON_CreateObject();
	cJSON *items  = cJSON_CreateArray();

	if (!object || !data || !list || !items) {
		if (object) free(object);
		if (data)   free(data);
		if (list)   free(list);
		if (items)  free(items);
		MON_ERROR("detect_risk_account fail, no memory\n");
		return;
	}

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);

	cJSON_AddStringToObject(data, "cmd_id", msg->cmd_id);
	cJSON_AddNumberToObject(data, "cmd_type", msg->cmd_type);

	cJSON_AddItemToObject(data, "data", list);
	cJSON_AddItemToObject(list, "items", items);

	if (sniper_other_loadoff == 1) {
		INFO("detect_risk_account fail, sniper loadover, do nothing\n");
		cJSON_AddNumberToObject(data, "result", 0); //检测失败
		cJSON_AddStringToObject(data, "reason", "客户端程序负载过高，暂时关闭监控功能");
		goto out;
	}

	DBG2(DBGFLAG_USER, "detect_risk_account Start\n");

	setpwent();
	while (1) {
		int ret = 0;
		struct spwd spw;
		struct spwd *spwp = NULL;
		struct passwd pw;
		struct passwd *pwp = NULL;
		int risk_type = 0;  // 1 空口令 2密码与账户名相同 3可疑高权限 4疑似服务账户的账户无对应服务
		char buf[4096] = {0}, buf2[4096] = {0};

		memset(&pw, 0, sizeof(pw));
		memset(&spw, 0, sizeof(spw));

		errno = 0; //下面判断passwd文件是否解析完毕要用到errno，因此这里将其置0，以免受其他过程干扰
		ret = getpwent_r(&pw, buf, 4096, &pwp);
		if (ret != 0) {
			if (ret == ENOENT && errno == 0) {
				break; //passwd文件解析完毕
			}

			snprintf(buf, 4096, "检查passwd文件失败，返回值%d，错误码%d：%s", ret, errno, strerror(errno));

			endpwent();

			MON_ERROR("detect_risk_account fail, getpwent_r ret %d: %s\n", ret, strerror(errno));
			cJSON_AddNumberToObject(data, "result", 0); //检测失败
			cJSON_AddStringToObject(data, "reason", buf);
			goto out;
		}

		if (check_risk_account_whitelist(pw.pw_name)) {
			continue; //过滤白名单账号
		}

		//TODO
		// 1. 排除以下异常情况
		//    1.1 /bin/nologin是指向/bin/bash的软链接或硬链接
		//    1.2 shell程序名叫/bin/sysnologin或/usr/local/bin/nologin之类的
		// 2. shell程序如果不存在，是不能登录的，但这种情况是否也应视为异常
		// 3. 如果shell字段是空的，账号是可以登录的，用/bin/sh做shell，这是否视为异常
		if (strstr(pwp->pw_shell, "nologin") || strstr(pwp->pw_shell, "false")) {
			continue; //过滤不可登录账号
		}

		getspnam_r(pw.pw_name, &spw, buf2, 4096, &spwp);
		if (spwp == NULL) {
			MON_ERROR("detect_risk_account: user %s no shadow passwd line\n", pw.pw_name);
			continue; //TODO 这是一种异常，即使没有密码，也应该有密码条目的，但由于没有对应的风险类型，暂时视为空密码处理
		}

		if (spwp->sp_pwdp[0] == 0 || strcmp(spwp->sp_pwdp, "!") == 0) {
			continue; //过滤空密码
		}

		if (spwp->sp_pwdp[0] == '*' || spwp->sp_pwdp[0] == '!') {
			continue; //过滤锁定/禁用的账号
		}

		if (risk_type == 0) {
			if (check_passwd_same_as_account(pwp->pw_name, spwp->sp_pwdp)) {
				risk_type = 2; //密码与账户名相同
			} else if (check_sudo_permissions(pwp->pw_name) == 1) {
				risk_type = 3; //有sudo权限
			} else if (check_user_app(pwp->pw_name) == 0) {
				risk_type = 4; //一些认为是服务账号的账号没有对应的服务
			}
		}

		if (risk_type == 0) {
			continue; //过滤非风险账号
		}

		cJSON *item = cJSON_CreateObject();

		cJSON_AddNumberToObject(item, "uid", pw.pw_uid);
		cJSON_AddStringToObject(item, "username", pwp->pw_name);
		cJSON_AddNumberToObject(item, "account_type", risk_type);
		cJSON_AddNumberToObject(item, "account_status", 1); //只考察可登录的账号。0禁用 1启用 2锁定 3不可登录

		cJSON_AddItemToArray(items, item);
	}
	endpwent();

	cJSON_AddNumberToObject(data, "result", 1); //检测成功

out:
	tmp = cJSON_PrintUnformatted(data);
	if (tmp) {
		cJSON_AddItemToObject(object, "data", cJSON_CreateString(tmp));

		post = cJSON_PrintUnformatted(object);
		if (post) {
			DBG2(DBGFLAG_USER, "--risk_account--%s\n", post);
			client_send_msg(post, reply, sizeof(reply), NOTIFY_URL, "task");
			free(post);
		} else {
			MON_ERROR("detect_risk_account fail, no memory\n");
		}
		free(tmp);
	} else {
		MON_ERROR("detect_risk_account fail, no memory\n");
	}
	cJSON_Delete(object);

	DBG2(DBGFLAG_USER, "detect_risk_account End\n");
}

static void user_db_init(void)
{
	char dbfile[128] = {0};

	snprintf(dbfile, 128, "%s/%s", WORKDIR, DBDIR);
	if (access(dbfile, F_OK) != 0) {
		mkdir(dbfile, 0700);
	}

	snprintf(dbfile, 128, "%s/%s/user.db", WORKDIR, DBDIR);
	user_db = connectDb(dbfile, crt_user_tbl_sql, NULL, &first_user_check);
	if (user_db == NULL) {
		return;
	}

	sqlite3_busy_handler(user_db, db_busy_callback, NULL );
	sqlite3_prepare_v2(user_db, user_new_sql   ,-1, &user_new_stmt   , NULL);
	sqlite3_prepare_v2(user_db, user_chg_sql   ,-1, &user_chg_stmt   , NULL);
	sqlite3_prepare_v2(user_db, user_unchg_sql ,-1, &user_unchg_stmt , NULL);
	sqlite3_prepare_v2(user_db, user_sdel_sql  ,-1, &user_sdel_stmt  , NULL);
	sqlite3_prepare_v2(user_db, user_del_sql   ,-1, &user_del_stmt   , NULL);
}

void user_db_release(void)
{
	if (user_db == NULL) {
		return;
	}

	sqlite3_finalize(user_new_stmt);
	sqlite3_finalize(user_chg_stmt);
	sqlite3_finalize(user_unchg_stmt);
	sqlite3_finalize(user_sdel_stmt);
	sqlite3_finalize(user_del_stmt);
	sqlite3_close_v2(user_db);
}

static void send_user_msg(const char *name, const char* new_name, 
				const char *group, const char *new_group, const char *operation)
{
	char reply[REPLY_MAX] = {0};
	char uuid[S_UUIDLEN] = {0};
	struct timeval tv = {0};
	unsigned long event_time = 0;
	char *post = NULL;
	char *log_name = "AccountChange";
	cJSON *object = NULL;
	cJSON *arguments = NULL;

	if (operation == NULL) {
		return;
	}

	/* 用户变更开关 */
	if (protect_policy_global.account.user_change.enable != MY_TURNON ||
			protect_policy_global.account.user_change.user.enable != MY_TURNON) {
		return;
	}

	/* 第一次创建数据库时，不发变化日志 */
	if (first_user_check) {
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) { //没取到uuid
		return;
	}
	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + tv.tv_usec / 1000;

	object = cJSON_CreateObject();
	arguments = cJSON_CreateObject();

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Account");
	cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddNumberToObject(object, "level", 1);    /* 关键 */
	cJSON_AddNumberToObject(object, "behavior", 0); /* 无 */
	cJSON_AddNumberToObject(object, "result", 0);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddStringToObject(object, "operating", operation);
	cJSON_AddNumberToObject(object, "terminate", 0); /* 策略配置的阻断开关 */

	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "ipv6_address", If_info.ipv6);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);		
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur); /* 策略ID */
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	/* 执行操作的用户 */
	cJSON_AddStringToObject(arguments, "subject_user", "root"); // 执行操作的用户，目前inotify拿不到写成root

	if (strncmp(operation, "Created", 7) == 0) {
		cJSON_AddStringToObject(arguments, "user", new_name); // 被操作的用户名
		cJSON_AddStringToObject(arguments, "new_user", new_name); //重命名后的用户名（重命名操作必传，其他情况可以为空）
		cJSON_AddStringToObject(arguments, "user_group", group); // 被操作用户的用户组 （多个用户组逗号间隔）
		cJSON_AddStringToObject(arguments, "user_new_group", group); // 变更后的用户组（多个用户组逗号间隔）
		cJSON_AddStringToObject(arguments, "user_permissions", name); // 被操作用户的权限 root/当前用户
		cJSON_AddStringToObject(arguments, "user_new_permissions", ""); // 变更后的用户权限
	} else if (strncmp(operation, "Deleted", 7) == 0) {
		cJSON_AddStringToObject(arguments, "user", name);
		cJSON_AddStringToObject(arguments, "new_user", new_name);
		cJSON_AddStringToObject(arguments, "user_group", group);
		cJSON_AddStringToObject(arguments, "user_new_group", "");
		cJSON_AddStringToObject(arguments, "user_permissions", name);
		cJSON_AddStringToObject(arguments, "user_new_permissions", "");
	} else if (strncmp(operation, "ChangeGroup", 11) == 0) {
		cJSON_AddStringToObject(arguments, "user", name);
		cJSON_AddStringToObject(arguments, "new_user", new_name);
		cJSON_AddStringToObject(arguments, "user_group", group);
		cJSON_AddStringToObject(arguments, "user_new_group", new_group);
		cJSON_AddStringToObject(arguments, "user_permissions", name);
		cJSON_AddStringToObject(arguments, "user_new_permissions", "");
	} else if (strncmp(operation, "ChangePermissions", 17) == 0) {
		cJSON_AddStringToObject(arguments, "user", name);
		cJSON_AddStringToObject(arguments, "new_user", new_name);
		cJSON_AddStringToObject(arguments, "user_group", group);
		cJSON_AddStringToObject(arguments, "user_new_group", new_group);
		cJSON_AddStringToObject(arguments, "user_permissions", name);
		cJSON_AddStringToObject(arguments, "user_new_permissions", new_group);
	} else if (strncmp(operation, "ChangePassword", 14) == 0) {
		cJSON_AddStringToObject(arguments, "user", name);
		cJSON_AddStringToObject(arguments, "new_user", new_name);
		cJSON_AddStringToObject(arguments, "user_group", group);
		cJSON_AddStringToObject(arguments, "user_new_group", new_group);
		cJSON_AddStringToObject(arguments, "user_permissions", name);
		cJSON_AddStringToObject(arguments, "user_new_permissions", group);
	} else if (strncmp(operation, "Rename", 6) == 0) { /* 用户重命名 */
		cJSON_AddStringToObject(arguments, "user", name);
		if (new_name) {
			cJSON_AddStringToObject(arguments, "new_user", new_name); //重命名后的用户名（重命名操作必传，其他情况可以为空）
		} else {
			cJSON_AddStringToObject(arguments, "new_user", "");
		}
		cJSON_AddStringToObject(arguments, "user_group", group);
		cJSON_AddStringToObject(arguments, "user_new_group", new_group);
		cJSON_AddStringToObject(arguments, "user_permissions", name);
		cJSON_AddStringToObject(arguments, "user_new_permissions", group);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	if (post) {
		DBG2(DBGFLAG_USER, "--user change--%s\n", post);
		client_send_msg(post, reply, sizeof(reply), LOG_URL, "inotify");
		free(post);
	}

	cJSON_Delete(object);
}

static void get_password(char *user, char *password)
{
        char line[1024] = {0};
        FILE *fp = fopen("/etc/shadow", "r");

        if (!fp) {
                MON_ERROR("get_password open /etc/shadow fail: %s\n", strerror(errno));
                return;
        }

        while (fgets(line, sizeof(line), fp)) {
                char name[64] = {0};
                char passwd[256] = {0};

                if (sscanf(line, "%63[^:]:%255[^:]", name, passwd) < 2) {
			continue;
		}
                if (strcmp(user, name) == 0) {
                        strncpy(password, passwd, 255);
                        break;
                }
        }
        fclose(fp);
}

/* 检查非root用户uid是否为0，是否空密码，是否用户名和密码相同 */
static void abnormal_account_detection(const char *username, const char *passwd, const uid_t uid)
{
	char reply[REPLY_MAX] = {0};
	char uuid[S_UUIDLEN] = {0};
	struct timeval tv;
	unsigned long event_time;
	int abnormal = 0;
	char *account_type = NULL;
	char *post = NULL;

	if (username == NULL || passwd == NULL) {
		return;
	}
	if (uid == 0 && strcmp(username, "root") != 0) { //只有root用户的uid才会为0
		abnormal = 1;
		account_type = "AbnormalAccount";
	}
	if (!abnormal && passwd) {
		if (passwd[0] == '!' || passwd[0] == '*') { //无效密码
			return;
		}

		if (!passwd[0]) { //空密码
			account_type = "EmptyPwd";
			abnormal = 1;
		} else if (check_passwd_same_as_account(username, passwd)) { //用户名和密码相同
			account_type = "PwdSameAsAccount";
			abnormal = 1;
		}
	}

	if (!abnormal) {
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) { //没取到uuid
		return;
	}
	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + tv.tv_usec / 1000;

	cJSON *object = cJSON_CreateObject();
	cJSON *arguments = cJSON_CreateObject();
	cJSON_AddItemToObject(object, "arguments", arguments);

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "AbnormalAccount");
	cJSON_AddStringToObject(object, "log_category", "AbnormalAccount");
	  cJSON_AddBoolToObject(object, "event", true);
	cJSON_AddStringToObject(object, "event_category", "AbnormalAccount");
	cJSON_AddNumberToObject(object, "level", MY_LOG_MIDDLE_RISK);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
	cJSON_AddNumberToObject(object, "result", MY_RESULT_ZERO);
	cJSON_AddStringToObject(object, "operating", "");
	cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);		
	cJSON_AddStringToObject(object, "user", username);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	/* arguments */
	cJSON_AddStringToObject(arguments, "account", username);
	cJSON_AddStringToObject(arguments, "account_abnormal_type", account_type);

	post = cJSON_PrintUnformatted(object);
	if (post) {
		DBG2(DBGFLAG_USER, "--abnormal_account--%s\n", post);
		client_send_msg(post, reply, sizeof(reply), LOG_URL, "inotify");
		free(post);
	}
	cJSON_Delete(object);
}

static void handle_user(struct passwd *pw)
{
	int rc = 0, id = 0;
	int nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	int old_uid = 0, old_gid = 0;
	char *old_gecos = NULL, *old_home = NULL, *old_shell = NULL;
	char *old_group = NULL, *old_grplist = NULL, *old_password = NULL;
	char buf[1024] = {0};
	char grplist[S_GRPLISTLEN] = {0}, gecos[256] = {0}, password[256] = {0};
	char name[64] = {0}, group[64] = {0}, home[128] = {0}, shell[128] = {0};

	if (!pw) {
		return;
	}
	if (pw->pw_name) {
		snprintf(name, sizeof(name), "%s", pw->pw_name);
	}
	if (pw->pw_gecos) {
		snprintf(gecos, sizeof(gecos), "%s", pw->pw_gecos);
	}
	if (pw->pw_dir) {
		snprintf(home, sizeof(home), "%s", pw->pw_dir);
	}
	if (pw->pw_shell) {
		snprintf(shell, sizeof(shell), "%s", pw->pw_shell);
	}

	get_user_grplist(name, pw->pw_gid, group, sizeof(group), grplist, sizeof(grplist));
	get_password(name, password);

	snprintf(buf, sizeof(buf), "SELECT id,uid,gid,grp,grplist,gecos,password,home,shell FROM userinfo WHERE name='%s';", name);
	rc = sqlite3_get_table(user_db, buf, &azResult, &nrow, &ncolumn, NULL);
	// DBG2(DBGFLAG_USER, "SELECT user %s, rc %d(%d), nrow %d\n", name, rc, SQLITE_OK, nrow);
	if (rc != SQLITE_OK) {
		MON_ERROR("Query userinfo failed\n");
		sqlite3_free_table(azResult);
		return;
	}

	if (nrow == 0) { //新用户
		/* 重命名用户，usermod -l newname oldname */
		memset(buf, 0x00, sizeof(buf));
		snprintf(buf, sizeof(buf), "SELECT id,name,gid,grp,grplist,gecos,password,home,shell,lastchk FROM userinfo WHERE uid='%u';", pw->pw_uid);
		if (sqlite3_get_table(user_db, buf, &azResult, &nrow, &ncolumn, NULL) == SQLITE_OK) {
			if (nrow) {
				id = atoi(azResult[ncolumn]);
				char *tmp_name = azResult[ncolumn+1];
				char *tmp_group = azResult[ncolumn+3];
				int tmp_len = strlen(name);
				int tmp_len2 = strlen(tmp_name);
				/* 名字相同，uid相同不视为重命名 */
				if (tmp_len == tmp_len2 && strncmp(tmp_name, name, tmp_len) == 0) {
					return;
				}
				send_user_msg(tmp_name, name, tmp_group, group, "Rename");
				/* 更新数据库 */
				sqlite3_reset(user_chg_stmt);
				sqlite3_bind_int(user_chg_stmt,1,usrchktv.tv_sec);
				sqlite3_bind_int(user_chg_stmt,2,pw->pw_uid);
				sqlite3_bind_int(user_chg_stmt,3,pw->pw_gid);
				sqlite3_bind_text(user_chg_stmt,4,group,-1,SQLITE_STATIC);
				sqlite3_bind_text(user_chg_stmt,5,grplist,-1,SQLITE_STATIC);
				sqlite3_bind_text(user_chg_stmt,6,gecos,-1,SQLITE_STATIC);
				sqlite3_bind_text(user_chg_stmt,7,password,-1,SQLITE_STATIC);
				sqlite3_bind_text(user_chg_stmt,8,home,-1,SQLITE_STATIC);
				sqlite3_bind_text(user_chg_stmt,9,shell,-1,SQLITE_STATIC);
				sqlite3_bind_text(user_chg_stmt,10,name,-1,SQLITE_STATIC);
				sqlite3_bind_int(user_chg_stmt,11,id);

				if ((rc = sqlite3_step(user_chg_stmt)) != SQLITE_DONE) {
					MON_ERROR("sql update rename user fail: %s(%d)\n", sqlite3_errstr(rc), rc);
				} else {
					// DBG2(DBGFLAG_USER, "sql rename user %s success. lastchktime %d\n", name, usrchktv.tv_sec);
				}

				sqlite3_free_table(azResult);
				return;
			}
		}

		send_user_msg(NULL, name, group, NULL, "Created");

		sqlite3_reset(user_new_stmt);
		sqlite3_bind_text(user_new_stmt,1,name,-1,SQLITE_STATIC);
		sqlite3_bind_int(user_new_stmt,2,pw->pw_uid);
		sqlite3_bind_int(user_new_stmt,3,pw->pw_gid);
		sqlite3_bind_text(user_new_stmt,4,group,-1,SQLITE_STATIC);
		sqlite3_bind_text(user_new_stmt,5,grplist,-1,SQLITE_STATIC);
		sqlite3_bind_text(user_new_stmt,6,gecos,-1,SQLITE_STATIC);
		sqlite3_bind_text(user_new_stmt,7,password,-1,SQLITE_STATIC);
		sqlite3_bind_text(user_new_stmt,8,home,-1,SQLITE_STATIC);
		sqlite3_bind_text(user_new_stmt,9,shell,-1,SQLITE_STATIC);
		sqlite3_bind_int(user_new_stmt,10,usrchktv.tv_sec);
		if ((rc = sqlite3_step(user_new_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql insert new user %s:%s fail: %s(%d)\n",
				name, group, sqlite3_errstr(rc), rc);
		} else {
			// DBG2(DBGFLAG_USER, "sql insert new user %s. time %d\n", name, usrchktv.tv_sec);
		}

		sqlite3_free_table(azResult);

		/* 检查新用户的密码是否异常 */
		if (protect_policy_global.account.abnormal_user.enable) {
			abnormal_account_detection(name, password, pw->pw_uid);
		}
		return;
	}

	id = atoi(azResult[ncolumn]);
	old_uid = atoi(azResult[ncolumn+1]);
	old_gid = atoi(azResult[ncolumn+2]);
	old_group = azResult[ncolumn+3];
	old_grplist = azResult[ncolumn+4];
	old_gecos = azResult[ncolumn+5];
	old_password = azResult[ncolumn+6];
	old_home = azResult[ncolumn+7];
	old_shell = azResult[ncolumn+8];

	if (pw->pw_uid == old_uid &&
	    pw->pw_gid == old_gid &&
	    strcmp(group, old_group) == 0 &&
	    strcmp(grplist, old_grplist) == 0 &&
	    strcmp(gecos, old_gecos) == 0 &&
	    strcmp(password, old_password) == 0 &&
	    strcmp(home, old_home) == 0 &&
	    strcmp(shell, old_shell) == 0) {
		sqlite3_reset(user_unchg_stmt);
		sqlite3_bind_int(user_unchg_stmt,1,usrchktv.tv_sec);
		sqlite3_bind_int(user_unchg_stmt,2,id);
		if ((rc = sqlite3_step(user_unchg_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql update unchg user fail: %s(%d)\n", sqlite3_errstr(rc), rc);
		} else {
			// DBG2(DBGFLAG_USER, "sql update unchg user %s lastchktime %d\n", name, usrchktv.tv_sec);
		}

		sqlite3_free_table(azResult);
		return;
	}

	if (strcmp(password, old_password) != 0) {
		send_user_msg(name, NULL, group, NULL, "ChangePassword");
		/* 检查修改后的密码是否异常 */
		if (protect_policy_global.account.abnormal_user.enable) {
			abnormal_account_detection(name, password, pw->pw_uid);
		}
	}

	if (pw->pw_uid != old_uid && pw->pw_uid == 0) {
		send_user_msg(name, NULL, group, NULL, "ChangePermissions"); //异常：把普通用户uid改为0
	} else if (pw->pw_uid != old_uid ||
		   pw->pw_gid != old_gid ||
		   strcmp(group, old_group) != 0 ||
		   strcmp(grplist, old_grplist) != 0 ||
		   strcmp(gecos, old_gecos) != 0 ||
		   strcmp(home, old_home) != 0 ||
		   strcmp(shell, old_shell) != 0) {
		send_user_msg(name, NULL, old_group, group, "ChangePermissions");
	}

	sqlite3_reset(user_chg_stmt);
	sqlite3_bind_int(user_chg_stmt,1,usrchktv.tv_sec);
	sqlite3_bind_int(user_chg_stmt,2,pw->pw_uid);
	sqlite3_bind_int(user_chg_stmt,3,pw->pw_gid);
	sqlite3_bind_text(user_chg_stmt,4,group,-1,SQLITE_STATIC);
	sqlite3_bind_text(user_chg_stmt,5,grplist,-1,SQLITE_STATIC);
	sqlite3_bind_text(user_chg_stmt,6,gecos,-1,SQLITE_STATIC);
	sqlite3_bind_text(user_chg_stmt,7,password,-1,SQLITE_STATIC);
	sqlite3_bind_text(user_chg_stmt,8,home,-1,SQLITE_STATIC);
	sqlite3_bind_text(user_chg_stmt,9,shell,-1,SQLITE_STATIC);
	sqlite3_bind_text(user_chg_stmt,10,name,-1,SQLITE_STATIC);
	sqlite3_bind_int(user_chg_stmt,11,id);

	if ((rc = sqlite3_step(user_chg_stmt)) != SQLITE_DONE) {
		MON_ERROR("sql update chg user fail: %s(%d)\n", sqlite3_errstr(rc), rc);
	} else {
		// DBG2(DBGFLAG_USER, "sql chg user %s success. lastchktime %d\n", name, usrchktv.tv_sec);
	}

	sqlite3_free_table(azResult);
}

void check_user(void)
{
	int rc = 0, ret = 0;
	FILE *fp = NULL;

	DBG2(DBGFLAG_USER, "check user\n");

	if (!user_db) {
		user_db_init();
	}
	if (!user_db) {
		return;
	}

	fp = sniper_fopen("/etc/passwd", "r", FILE_GET);
	if (!fp) {
		MON_ERROR("check_user open /etc/user fail: %s\n", strerror(errno));
		return;
	}

	gettimeofday(&usrchktv, NULL);

	sqlite3_exec(user_db,"BEGIN;",0,0,0);

	while (1) {
		char buf[4096] = {0};
		struct passwd pw = {0};
		struct passwd *pwp = NULL;

		/*
		 * getpwent_r不仅处理本机passwd文件，还会处理NIS、LDAP，但网络操作有可能吊住
		 * 故还是用fgetpwent_r保守地仅处理本机passwd文件。
		 * 对内容错误的行，fgetpwent_r能解析则解析，但会得到错误的结果，不能解析则忽略该行
		 * buf长4096，远超通常的行长，fgetpwent_r几乎不可能出现ERANGE错误，导致处理中断
		 */
		ret = fgetpwent_r(fp, &pw, buf, 4096, &pwp);
		if (ret != 0) { //结束，或出错了
			/* 行长超过4096，继续解析该行剩下的，通常会因不能解析而忽略之 */
			if (errno == ERANGE) {
                		MON_ERROR("check_user getpwent_r fail: %s\n", strerror(errno));
				continue;
			}
			break;
		}

		handle_user(&pw);
	}

	sniper_fclose(fp, FILE_GET);

	sqlite3_exec(user_db,"COMMIT;",0,0,0);

	// DBG2(DBGFLAG_USER, "check deleted user\n");

	sqlite3_reset(user_sdel_stmt);
	sqlite3_bind_int(user_sdel_stmt,1,usrchktv.tv_sec);
	while (sqlite3_step(user_sdel_stmt) == SQLITE_ROW) {
		int id = sqlite3_column_int(user_sdel_stmt,0);
		const char *name = (const char *)sqlite3_column_text(user_sdel_stmt,1);
		const char *group = (const char *)sqlite3_column_text(user_sdel_stmt,2);
		int lastchk = sqlite3_column_int(user_sdel_stmt,3);

		send_user_msg(name, NULL, group, NULL, "Deleted");

		DBG2(DBGFLAG_USER, "delete id:%d, user %s, lastchktime %d, now %d\n", id, name, lastchk, usrchktv.tv_sec);
		sqlite3_reset(user_del_stmt);
		sqlite3_bind_int(user_del_stmt,1,id);
		if ((rc = sqlite3_step(user_del_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql del user %s fail: %s(%d)\n", name, sqlite3_errstr(rc), rc);
		} else {
			// DBG2(DBGFLAG_USER, "sql del user %s success\n", name);
		}
	}

	DBG2(DBGFLAG_USER, "check user end\n");
}

int can_login(uid_t uid)
{
	int canlogin = 1;
	FILE *fp = NULL;

	fp = sniper_fopen("/etc/passwd", "r", INFO_GET);
	if (!fp) {
		MON_ERROR("can_login: open /etc/passwd fail: %s\n", strerror(errno));
		return -1;
	}

	while (1) {
		char buf[4096] = {0};
		struct passwd pw = {0}, *pwp = NULL;

		if (fgetpwent_r(fp, &pw, buf, 4096, &pwp) != 0) {
			//结束，或出错
			if (errno != ENOENT) {
				MON_ERROR("can_login: getpwent_r fail: %s\n", strerror(errno));
			}
			break;
		}
		if (pw.pw_uid == uid) {
			if (strstr(pw.pw_shell, "/nologin") ||
			    strstr(pw.pw_shell, "/false")   || strstr(pw.pw_shell, "/sync") ||
			    strstr(pw.pw_shell, "/shutdown")|| strstr(pw.pw_shell, "/halt")) {
				canlogin = 0;
			}
			break;
		}
	}

	sniper_fclose(fp, INFO_GET);
	return canlogin;
}
