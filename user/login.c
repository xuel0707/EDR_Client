#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <paths.h>
#include <pcre.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>
#include <utmpx.h>

#include "header.h"
#include "list.h"

int current_login_num = 0;

int local_login_check = 0;
int local_login_auth_check = 0;
int remote_login_check = 0;
int remote_login_crack_check = 0;
int remote_login_crack_interval = 0;
int remote_login_crack_try_num = 0;
int remote_login_crack_locking = 0;
int user_change_check = 0;
int in_fixed_time = 0, in_fixed_location = 0, is_fixed_local_time = 0, remote_white = 0, local_white = 0;

static unsigned long authoff;
static unsigned long mysqloff;

int black = 0, t = 0, local_black = 0;

char utype[10][16] =
    {
	"EMPTY",
	"RUN_LVL",
	"BOOT_TIME",
	"NEW_TIME",
	"OLD_TIME",
	"INIT_PROCESS",
	"LOGIN_PROCESS",
	"USER_PROCESS",
	"DEAD_PROCESS",
	"ACCOUNTING"};

struct fail_ssh {
	char ip[S_IPLEN];
	time_t time;
	int count;
	int reported;
};

struct paminfo {
	time_t t;
	pid_t pid;
	char *result;
	char user[S_NAMELEN];
	char new_user[S_NAMELEN];
	char cmd[S_CMDLEN];
};

struct passwdinfo {
	int event_id;
	int behavior_id;
	int level;
	time_t t;
	char name[S_NAMELEN];
	char *result;
};

struct syslog_header {
	time_t t;
	pid_t pid;
	char module[S_LINELEN];
};

#define LEVEL_DANGER 4
#define COMM_MAX 128
#define PROCESS_MAX 16
#define HOSTNAME_MAX 100
#define MAX_FAIL_CONNECT 1000

#define OVECCOUNT 30

char *path_auth = NULL;
char *path_auth_ub = "/var/log/auth.log";
char *path_auth_rh = "/var/log/secure";
char *path_wtmp = "/var/log/wtmp";
char *path_btmp = "/var/log/btmp";
char *crack_conf_path = "/opt/snipercli/.download/LogConf.txt";
char path_mysqld[PATH_MAX] = {0};

char *fail_str1 = "pam_unix(gdm:auth): authentication failure";
char *fail_str2 = "pam_unix(lightdm:auth): authentication failure";
char *fail_str3 = "pam_unix(gdm-password:auth): authentication failure";
char *fail_str4 = "pam_unix(remote:auth): authentication failure";
char *fail_str5 = "pam_unix(login:auth): authentication failure";
char *passwd_str = "pam_unix(passwd:chauthtok):";

struct fail_ssh fail_ssh_info[MAX_FAIL_CONNECT];

#define CACHE_MAGIC 0xcac0e002	// cac0e表示cache，002是版本号
struct login_cache_info {
	unsigned int unique;  /* connect time as unique id */
	unsigned int magic;   /* 用来区分老的缓冲记录格式 */
	struct timeval tv;    /* connect time */
	char tty[S_TTYLEN];   /* tty device path */
	char user[S_NAMELEN]; /* username */
	pid_t pid;
	int event_id;
	int behavior_id;
	int loglevel;
	char login_type[8];
	char login_ip[S_IPLEN];
	char session_uuid[S_UUIDLEN];
};
#define FLAG_VIOLATION 0x1
#define FLAG_LOCKING 0x2
#define FLAG_FILTER 0x4
#define FLAG_REPORTED 0x8
#define FLAG_ILLEGALTIME 0x1
#define FLAG_ILLEGALLOCATION 0x2
struct login_info {
	unsigned int unique;  /* connect time as unique id */
	struct timeval tv;    /* connect time */
	struct timeval endtv; /* broken time */
	char tty[S_TTYLEN];   /* tty device path */
	char user[S_NAMELEN]; /* user name */
	char logincmd[S_CMDLEN];
	char session_uuid[S_UUIDLEN];
	pid_t pid;
	pid_t ppid;
	pid_t connpid;

	time_t check_strategy_time;
	int event_id;
	int behavior_id;
	int loglevel;
	int terminate;
	int locking;
	int flag;
	int illegal_flag;
	int failed_count;
	char operating[8];
	char login_type[8];
	char login_ip[S_IPLEN];
	char *result;
	char *defence_result;
	char *detection_rule;
	struct list_head list;
	int attack_time;
	char crack_user[S_CRACKNAMELEN];
};

struct failinfo {
	int count;
	int pid;
	time_t t;
	char ip[S_IPLEN];
	char user[S_NAMELEN];
	char hostname[S_NAMELEN];
	char login_type[8];
	char session_uuid[S_UUIDLEN];
	char success_ip[S_IPLEN];
	char success_user[256];
};

struct authok_user_info {
	time_t t;
	char login_type[8];
	char ip[S_IPLEN];
	char user[S_NAMELEN];
};

char invalid_ssh_user[64] = {0};
char last_crack_userlist[1024] = {0};

pid_t mysqldpid = 0;
static app_module login_app_info[] = {
    {&mysqldpid, "mysqld", "mysqld"},
    {0, NULL, NULL}};

unsigned long wtmp_inode = 0;
unsigned long last_wtmp_count = 0;
struct list_head all_conn;
pthread_mutex_t sshconn_lock;

sqlite3 *crack_user_db = NULL;
sqlite3 *crack_db = NULL;
int first_crack_check = 0;

const char crack_tbl[1024] =
    {
	"CREATE TABLE IF NOT EXISTS crack_tbl( "
	"id integer PRIMARY KEY AUTOINCREMENT,"
	"ip varchar(128),"
	"type varchar(64),"
	//"crack_status int,"
	"last_report_time int,"
	"policy_time int,"
	"time int);"};
//"crack_count int,"
//"queue_count int,"
//"userlist varchar(256),"
//"crackok_userlist varchar(256));"};

const char crack_user_tbl_sql[1024] =
    {
	"CREATE TABLE IF NOT EXISTS login_fail_tbl( "
	"id integer PRIMARY KEY AUTOINCREMENT,"
	"name  varchar(256),"
	"crack_ip  varchar(128),"
	"type varchar(64),"
	"last_time int,"
	"policy_time int,"
	"time int,"
	//"crack_status int,"
	"queue_count int);"};

// 创建表   login_type_conf
const char login_type_conf_sql[1024] =
    {
	"CREATE TABLE IF NOT EXISTS login_type_conf("
	"id integer PRIMARY KEY AUTOINCREMENT,"
	"type varchar(64),"
	"path varchar(256),"
	"fd   int,"
	"wd   int,"
	"inode int,"
	"off   int);"};

const char fail_log_sql[1024] =
    {
	"CREATE TABLE IF NOT EXISTS login_fail_log("
	"id integer PRIMARY KEY AUTOINCREMENT,"
	"type varchar(64),"
	"faillog varchar(512));"};

const char success_log_sql[1024] =
    {
	"CREATE TABLE IF NOT EXISTS login_success_log("
	"id integer PRIMARY KEY AUTOINCREMENT,"
	"type varchar(64),"
	"successlog varchar(512));"};

const char *crack_tbl_new = "INSERT INTO crack_tbl VALUES(NULL,?,?,?,?,?);";
sqlite3_stmt *crack_tbl_stmt = NULL;

const char *select_crack_tbl = "select ip,type,last_report_time from crack_tbl where (((?-last_report_time)%60) = 0) and (?>last_report_time);";  // 查询crack_tbl表中是否存在该ip的记录
sqlite3_stmt *select_crack_stmt = NULL;

const char *select_to_del_tbl = "select ip,type from crack_tbl where policy_time<=?;";	// 查询crack_tbl表中是否存在该ip的记录
sqlite3_stmt *select_to_del_stmt = NULL;

const char *fail_tbl_new = "INSERT INTO login_fail_tbl VALUES(NULL,?,?,?,?,?,?,?);";
sqlite3_stmt *fail_tbl_stmt = NULL;

const char *select_del_fail_tbl = "select crack_ip,type from login_fail_tbl where  (?-last_time) >?;";	// 查询login_fail_tbl表中是否存在该ip的记录
sqlite3_stmt *select_del_fail_stmt = NULL;

const char *crack_time_sql = "UPDATE crack_tbl SET time=time+1 where id > 0;";
sqlite3_stmt *crack_time_stmt = NULL;

const char *login_fail_sql = "UPDATE login_fail_tbl SET time=time+1 where id > 0;";
sqlite3_stmt *login_fail_stmt = NULL;

const char *select_fd_sql = "SELECT fd FROM login_type_conf WHERE fd >= 0;";
sqlite3_stmt *select_fd_stmt = NULL;

const char *select_max_fd = "SELECT MAX(fd) FROM login_type_conf;";
sqlite3_stmt *select_max_stmt = NULL;

const char *start_fail_time_fd = "SELECT time,last_time FROM login_fail_tbl where crack_ip=? and type=?;";
sqlite3_stmt *start_fail_time_stmt = NULL;

const char *update_off_sql = "UPDATE login_type_conf SET off=? WHERE type=?;";
sqlite3_stmt *update_off_stmt = NULL;

const char *update_last_report_time_sql = "UPDATE crack_tbl SET last_report_time=? WHERE ip=? and type=?;";
sqlite3_stmt *update_last_report_time_stmt = NULL;

const char *update_policy_time_sql = "UPDATE crack_tbl SET policy_time=policy_time+? where ip=? and type=?;";
sqlite3_stmt *update_policy_time_stmt = NULL;

// login_type_conf表中新加或更新字段
const char *type_new_sql = "INSERT INTO login_type_conf VALUES(NULL,?,?,?,?,?,?)";
const char *type_update_sql = "UPDATE login_type_conf SET fd=? WHERE fd>=0;";
const char *select_typefd_sql = "SELECT type,path,fd,off FROM login_type_conf WHERE fd >= 0;";
const char *off_update_sql = "UPDATE login_type_conf SET off=? WHERE type='?';";

const char *select_wd_fd = "SELECT fd,wd FROM login_type_conf WHERE fd>0;";
const char *delete_type_conf = "DELETE FROM login_type_conf";

const char *faillog_new_sql = "INSERT INTO login_fail_log VALUES(NULL,?,?)";
const char *delete_faillog_sql = "DELETE FROM login_fail_log";

const char *successlog_new_sql = "INSERT INTO login_success_log VALUES(NULL,?,?)";
const char *delete_successlog_sql = "DELETE FROM login_success_log";

// CRACK线程中删除数据库记录语句
const char *delete_login_fail_tbl_sql = "DELETE FROM login_fail_tbl WHERE crack_ip=? and type=?;";
const char *delete_crack_tbl_sql = "DELETE FROM crack_tbl WHERE ip=? and type=?;";

const char *delete_from_db= "delete from ? where id in (select id from ? order by id limit 0,?);";

sqlite3_stmt *type_new_stmt = NULL;
sqlite3_stmt *type_update_stmt = NULL;
sqlite3_stmt *select_typefd_stmt = NULL;
sqlite3_stmt *off_update_stmt = NULL;

sqlite3_stmt *select_wd_fd_stmt = NULL;
sqlite3_stmt *delete_type_stmt = NULL;

sqlite3_stmt *faillog_new_stmt = NULL;
sqlite3_stmt *delete_faillog_stmt = NULL;

sqlite3_stmt *successlog_new_stmt = NULL;
sqlite3_stmt *delete_successlog_stmt = NULL;

sqlite3_stmt *delete_login_fail_tbl_stmt = NULL;
sqlite3_stmt *delete_crack_tbl_stmt = NULL;

sqlite3_stmt *delete_from_db_stmt = NULL;

/* 将ipv4映射的ipv6地址，如::ffff:192.168.153.128, 转成ipv4地址，观察到telnet有这种情况 */
char *nullip = "None";
char *handle_mapped_ipv4(char *ip)
{
	if (!ip) {
		return nullip;
	}
	if (strncasecmp(ip, "::ffff:", 7) == 0) {
		return ip + 7;
	}
	return ip;
}

/* 消除ip尾部的空格符、回车和换行符,特殊符号 */
void delete_ip_tailspace(char *str)
{
	int i = 0, len = strlen(str);

	for (i = len - 1; i >= 0; i--) {
		if (!isspace(str[i]) && !ispunct(str[i])) {
			return;
		}
		str[i] = 0;
	}
}

/* 如果有mysqld进程，取其正在使用的errorlog文件名 */
static void get_mysqld_errorlog_path(pid_t *pid, char *path, int path_len)
{
	FILE *fp = NULL;
	char comm[16] = {0}, fdpath[128] = {0};
	char line[S_LINELEN] = {0}, tmp[S_NAMELEN] = {0};
	char file_path[S_PATHLEN] = {0};
	int num = 0;

	if (!pid || !path) {
		return;
	}
	*pid = 0;
	memset(path, 0, path_len);

	fp = fopen("/etc/my.cnf", "r");
	if (fp) {
		while (fgets(line, S_LINELEN, fp)) {
			sscanf(line, "%s%*s%s", tmp, fdpath);
			if (strcmp(tmp, "general_log_file") == 0) {
				snprintf(file_path, S_PATHLEN, "%s", fdpath);
			}

			if (strcmp(tmp, "general_log") == 0) {
				sscanf(line, "%s%*s%d", tmp, &num);
				if (num == 1) {
					snprintf(path, path_len, "%s", file_path);
					fclose(fp);
					return;
				}
			}
		}
		fclose(fp);
	}

	/* mysqld.pid文件取mysqld进程的pid */
	fp = fopen("/var/run/mysqld/mysqld.pid", "r");
	if (fp) {
		if (fscanf(fp, "%d", pid) == 1) {
			get_proc_comm(*pid, comm);
			if (strcmp(comm, "mysqld") != 0) {  // 此进程已不是mysqld
				*pid = 0;
			}
		}
		fclose(fp);
	}

	/* 遍历/proc查找mysqld进程 */
	if (*pid <= 0) {
		get_app_pid(login_app_info);
	}

	if (*pid > 0) {
		DBG2(DBGFLAG_SSH, "%s %d\n", login_app_info[0].sub_name, *login_app_info[0].pid);
		snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/1", *pid);
		readlink(fdpath, path, path_len - 1);
	}

	if (path[0] == 0) {
		snprintf(path, path_len, "no mysqld log");
	}
}

static void crack_db_init(void)
{
	char dbfile[128] = {0};

	snprintf(dbfile, sizeof(dbfile), "%s/%s", WORKDIR, DBDIR);
	if (access(dbfile, F_OK) != 0) {
		mkdir(dbfile, 0700);
	}

	snprintf(dbfile, sizeof(dbfile), "%s/%s/crack_user.db", WORKDIR, DBDIR);
	crack_user_db = connect_five_tbl(dbfile, crack_tbl, crack_user_tbl_sql, login_type_conf_sql, fail_log_sql, success_log_sql, NULL, &first_crack_check);
	if (crack_user_db == NULL) {
		return;
	}

	sqlite3_busy_handler(crack_user_db, db_busy_callback, NULL);
	// sqlite3_prepare_v2(crack_user_db, crack_new_sql, -1, &crack_new_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, select_fd_sql, -1, &select_fd_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, select_max_fd, -1, &select_max_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, crack_tbl_new, -1, &crack_tbl_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, select_crack_tbl, -1, &select_crack_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, select_to_del_tbl, -1, &select_to_del_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, fail_tbl_new, -1, &fail_tbl_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, select_del_fail_tbl, -1, &select_del_fail_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, crack_time_sql, -1, &crack_time_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, login_fail_sql, -1, &login_fail_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, type_new_sql, -1, &type_new_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, type_update_sql, -1, &type_update_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, select_typefd_sql, -1, &select_typefd_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, off_update_sql, -1, &off_update_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, select_wd_fd, -1, &select_wd_fd_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, delete_type_conf, -1, &delete_type_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, faillog_new_sql, -1, &faillog_new_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, delete_faillog_sql, -1, &delete_faillog_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, successlog_new_sql, -1, &successlog_new_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, delete_successlog_sql, -1, &delete_successlog_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, start_fail_time_fd, -1, &start_fail_time_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, update_off_sql, -1, &update_off_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, update_last_report_time_sql, -1, &update_last_report_time_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, update_policy_time_sql, -1, &update_policy_time_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, delete_login_fail_tbl_sql, -1, &delete_login_fail_tbl_stmt, NULL);
	sqlite3_prepare_v2(crack_user_db, delete_crack_tbl_sql, -1, &delete_crack_tbl_stmt, NULL);

	sqlite3_prepare_v2(crack_user_db, delete_from_db, -1, &delete_from_db_stmt, NULL);

	sqlite3_exec(crack_user_db, "PRAGMA synchronous = OFF", 0, 0, 0);
}

void crack_db_release(void)
{
	if (crack_user_db == NULL) {
		return;
	}
	sqlite3_finalize(select_fd_stmt);
	sqlite3_finalize(select_max_stmt);

	sqlite3_finalize(crack_time_stmt);
	sqlite3_finalize(login_fail_stmt);

	sqlite3_finalize(crack_tbl_stmt);
	sqlite3_finalize(select_crack_stmt);
	sqlite3_finalize(select_to_del_stmt);

	sqlite3_finalize(fail_tbl_stmt);
	sqlite3_finalize(select_del_fail_stmt);

	sqlite3_finalize(type_new_stmt);
	sqlite3_finalize(type_update_stmt);
	sqlite3_finalize(select_typefd_stmt);
	sqlite3_finalize(off_update_stmt);

	sqlite3_finalize(select_wd_fd_stmt);
	sqlite3_finalize(delete_type_stmt);

	sqlite3_finalize(faillog_new_stmt);
	sqlite3_finalize(delete_faillog_stmt);

	sqlite3_finalize(successlog_new_stmt);
	sqlite3_finalize(delete_successlog_stmt);

	sqlite3_finalize(start_fail_time_stmt);
	sqlite3_finalize(update_off_stmt);
	sqlite3_finalize(update_last_report_time_stmt);
	sqlite3_finalize(update_policy_time_stmt);

	sqlite3_finalize(delete_login_fail_tbl_stmt);
	sqlite3_finalize(delete_crack_tbl_stmt);

	sqlite3_close_v2(crack_user_db);
}

/* 显示一条登录记录 */
static void show_utmpx(struct utmpx *u)
{
	char buf[64] = {0};
	time_t t = 0;

	if (!u) {
		return;
	}

	t = u->ut_time;
	ctime_r(&t, buf);
	delete_tailspace(buf);
	printf("%s: login type %s, user %s, pid %d, tty %s, host %s\n",
	       buf, utype[u->ut_type], u->ut_user, u->ut_pid, u->ut_line, u->ut_host);
}

/* 显示/var/run/utmp、/var/log/wtmp、/var/log/wtmp.1的内容 */
void show_wtmp(char *file)
{
	struct utmpx *u = NULL;

	if (file) {
		utmpname(file);
	}
	setutxent();
	while ((u = getutxent()) != NULL) {
		show_utmpx(u);
	}
	endutxent();
}

/* 获取当前登录的用户列表，客户端注册时上报 */
char login_users[S_LINELEN] = {0};

void get_login_users(void)
{
	int len = 0;
	char *ptr = NULL;
	struct utmpx *u = NULL;
	char *tmp = NULL;
	int tmp_len = 0;

	setutxent();
	while ((u = getutxent()) != NULL) {
		char user[S_NAMELEN] = {0};

		/* 忽略不知道用户的条目，这是图形登录界面在等待选择登录的用户名 */
		if (strcmp(u->ut_user, "(unknown)") == 0) {
			continue;
		}

		if (u->ut_type != USER_PROCESS) {
			continue;
		}

		/* ut_user的大小是32字节，所以user[62]应当是0 */
		snprintf(user, sizeof(user), ",%s,", u->ut_user);
		if (user[S_NAMELEN - 2] != 0) {
			MON_ERROR("get_login_users: bad utmp record, username too long\n");
			show_utmpx(u);
			continue;
		}

		/* login_users包含,xxx,或开头是xxx, */
		len = strlen(user);
		if (strstr(login_users, user) || strncmp(login_users, user + 1, len - 1) == 0) {
			continue;  // 忽略已经记录的用户名
		}

		/* 用户名拼接在用户列表尾部 */
		len = strlen(login_users);
		tmp = login_users + len;
		tmp_len = S_LINELEN - len;
		snprintf(tmp, tmp_len, "%s,", u->ut_user);

		len = strlen(login_users);
		if (len == S_LINELEN - 1) {
			INFO("get_login_users: too many logined users\n");
			break;	// 用户列表满了
		}
	}
	endutxent();

	ptr = strrchr(login_users, ',');
	if (ptr) {
		*ptr = 0;  // 消除用户列表结尾的,
	}

	INFO("login_users: %s\n", login_users);
}

void init_ssh(void)
{
	pthread_mutex_init(&sshconn_lock, NULL);
	INIT_LIST_HEAD(&all_conn);
}

void fini_ssh(void)
{
	/*TODO free connlist */

	pthread_mutex_destroy(&sshconn_lock);
}

/* 看当前是不是运维或学习模式，是返回1，不是返回0 */
int is_learning_or_operation_mode(void)
{
	if (client_mode_global == LEARNING_MODE ||
	    client_mode_global == OPERATION_MODE) {
		return 1;
	} else {
		return 0;
	}
}

//增加len参数，以确保ptr不会越界
static int sscanf_userlist_string(char *ptr, char *user_name, int len)
{
	char value[S_LINELEN] = {0};
	int  ptr_len = 0;

	if (!ptr || !user_name) {
		return 0;
	}

	if (sscanf(ptr, "%511s", value) == 1) {
		if (strcmp(value, user_name) == 0) {
			return 1;
		}

		ptr_len = len - strlen(value);
		if (ptr_len <= 0) {
			return 0;
		}

		return sscanf_userlist_string(ptr + strlen(value) + 1, user_name, ptr_len);
	}
	return 0;
}

/*
 * session_uuid=ttypath_ctime+ttyname
 * 不能用终端设备的mtime，一直在变化，终端输出视为改写终端内容
 */
void get_session_uuid(char *tty, char *session_uuid)
{
	struct stat st = {0};
	char ttypath[128] = {0}, *ptr = NULL;
	int session_uuid_len = 64;

	if (!session_uuid) {
		return;
	}
	if (!tty) {
		session_uuid[0] = 0;
		return;
	}

	/*
	 * tty终端的设备路径为/dev/ttyn，登录和进程监控记录取到的设备名都是ttyn
	 * pts伪终端的设备路径为/dev/pts/n，登录监控取到的设备名是pts/n，进程监控取到的是ptsn
	 */
	if (strncmp(tty, "pts", 3) == 0) {
		if (tty[3] == '/') {
			snprintf(ttypath, sizeof(ttypath), "/dev/%s", tty);
		} else {
			/* 将进程监控取到的设备名ptsn转成设备路径/dev/pts/n */
			snprintf(ttypath, sizeof(ttypath), "/dev/pts/%s", tty + 3);
		}
	} else {
		snprintf(ttypath, sizeof(ttypath), "/dev/%s", tty);
	}

	/* 取终端设备文件的ctime，即创建设备文件的时间 */
	// TODO 对于登录终端是:0的情况，如centos8和suse上，如何取登录终端设备时间待研究
	if (stat(ttypath, &st) < 0) {
		session_uuid[0] = 0;
		return;
	}

	ptr = strchr(tty, '/');
	if (ptr) {
		/* 登录取到的终端设备名是pts/n，进程监控取到的是ptsn，将pts/n转成ptsn，使得登录和其后进程的session_uuid相同 */
		*ptr = 0;
		snprintf(session_uuid, session_uuid_len, "%ld-%s%s", st.st_ctime, tty, ptr + 1);
		*ptr = '/';
	} else {
		snprintf(session_uuid, session_uuid_len, "%ld-%s", st.st_ctime, tty);
	}
}

#if 1
// 将登录成功的ip和时间存入数据库
static void save_attackip_info(char *crack_user, char *crack_ip, unsigned long crack_time, char *login_type)
{
	int ret = 0;
	char *attack_new_sql = NULL;
	int nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	char buf[1024] = {0};
	int rc = 0, count = 0;

	DBG2(DBGFLAG_SSH, "success login %s, %lu, %s\n", crack_ip, crack_time, login_type);

	char *create_tbl_sql = {
	    "CREATE TABLE IF NOT EXISTS crack_success_tbl("
	    "id integer PRIMARY KEY AUTOINCREMENT,"
	    "crack_count int,"
	    "crack_user  varchar(256),"
	    "crack_time  int,"
	    "crack_ip    varchar(128),"
	    "login_type  varchar(32));"};

	rc = sqlite3_exec(crack_user_db, create_tbl_sql, 0, 0, 0);
	if (rc != SQLITE_OK) {
		return;
	}

	snprintf(buf, sizeof(buf), "SELECT queue_count FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", crack_ip, login_type);
	ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);

	if (ret == SQLITE_OK && nrow != 0) {
		count = atoi(azResult[ncolumn]);
	}

	sqlite3_free_table(azResult);
	snprintf(buf, sizeof(buf), "SELECT id FROM crack_success_tbl WHERE crack_ip='%s' and login_type='%s';", crack_ip, login_type);
	ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
	if (ret == SQLITE_OK) {
		if (nrow == 0) {
			/* last_time = atoi(azResult[ncolumn]); */
			attack_new_sql = sqlite3_mprintf("INSERT INTO crack_success_tbl VALUES(NULL,'%d','%s','%lu','%s','%s')", count, crack_user, crack_time, crack_ip, login_type);
			ret = sqlite3_exec(crack_user_db, attack_new_sql, 0, 0, 0);
			DBG2(DBGFLAG_SSH, "save_attackip_info ret %d\n", ret);
		} else {
			sqlite3_free_table(azResult);
			snprintf(buf, sizeof(buf), "SELECT crack_user FROM crack_success_tbl WHERE crack_ip='%s' and login_type='%s';", crack_ip, login_type);	// 判断表中name字段是否已经存在相同用户名
			rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
			if (azResult[1] == NULL) {
				sqlite3_free_table(azResult);
				return;
			}
			ret = sscanf_userlist_string(azResult[1], crack_user, strlen(azResult[1]));
			if (!ret) {
				sqlite3_free_table(azResult);
				snprintf(buf, sizeof(buf), "update crack_success_tbl set crack_user=crack_user || ' %s' where crack_ip = '%s' and login_type='%s';", crack_user, crack_ip, login_type);	 // 在表中上个用户后面拼接当前失败用户
				rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
				DBG2(DBGFLAG_SSH, "update attackip crack_user ret %d\n", ret);
			}
			sqlite3_free_table(azResult);
			snprintf(buf, sizeof(buf), "update crack_success_tbl set crack_count='%d',crack_time='%lu' where crack_ip = '%s' and login_type='%s';", count, crack_time, crack_ip, login_type);  // 更新失败次数
			rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
			DBG2(DBGFLAG_SSH, "update attackip crack_count ret %d\n", ret);
		}
	}
	sqlite3_free_table(azResult);

	/*     if (last_time != crack_time) {
		attack_new_sql = sqlite3_mprintf("REPLACE INTO crack_success_tbl VALUES(NULL,'%lu','%s','%s')", crack_time, crack_ip, login_type);
		ret = sqlite3_exec(crack_user_db, attack_new_sql, 0, 0, 0);
		DBG2(DBGFLAG_SSH, "save_attackip_info ret %d\n", ret);
	    } */
}
#endif

/*
 * 用于判断远程登录成功是否为暴力密码破解成功
 * login_ip查询最近的crack_time
 * login_time - crack_time < 策略配置的暴力破解时间,返回报告暴力破解成功
 */
static int select_attackip_info(char *login_ip, unsigned long login_time, char *login_type)
{
	sqlite3 *db = NULL;
	int ret = 0;
	char buf[128] = {0};
	int nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	int nresult = 0, crack_time = 0;
	int interval = protect_policy_global.account.login.crack.interval;

	ret = sqlite3_open("/opt/snipercli/.mondb/crack_user.db", &db);

	if (ret) {
		/*  fprintf函数格式化输出错误信息到指定的stderr文件流中  */
		MON_ERROR("Can't open database: %s\n", sqlite3_errmsg(db));
		return 0;
	}

	snprintf(buf, 128, "select last_report_time from crack_tbl where ip = '%s' and type = '%s';", login_ip, login_type);

	nresult = sqlite3_get_table(db, buf, &azResult, &nrow, &ncolumn, 0);

	if (nresult != SQLITE_OK) {
		sqlite3_free_table(azResult);
		sqlite3_close(db);
		return 0;
	}

	if (nrow != 0) {
		crack_time = atoi(azResult[ncolumn]);
		DBG2(DBGFLAG_SSH, "select_attackip: %s/%s %d. login time %lu\n", login_ip, login_type, crack_time, login_time);
		if (login_time - crack_time < interval * 60) {
			sqlite3_free_table(azResult);
			sqlite3_close(db);
			return 1;
		}
	}

	sqlite3_free_table(azResult);
	sqlite3_close(db);
	return 0;
}

/* 发送暴力密码破解成功事件 */
static void send_crack_success_msg(struct failinfo *conn, unsigned long event_time, char *login_type)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0};
	struct tm time_info = {0};
	char log_time[128] = {0}, start_attack_time[128] = {0};
	char *post = NULL;
	char reply[REPLY_MAX] = {0};
	struct timeval tvstamp = {0};
	unsigned long time = 0;
	time_t t = 0;
	int start_time = 0, last_time = 0, crack_count = 0;
	int len = 0, nrow = 0, ncolumn = 0;
	char buf[1024] = {0};
	char ippath[S_SHORTPATHLEN] = {0};
	// struct defence_msg defmsg = {0};
	char **azResult = NULL;

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

	gettimeofday(&tvstamp, NULL);
	time = (tvstamp.tv_sec + serv_timeoff) * 1000 + (int)tvstamp.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_category", "Login");
	cJSON_AddNumberToObject(object, "result", MY_HANDLE_NO);

	cJSON_AddStringToObject(object, "operating", "");
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", conn->success_user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "event_category", "Login");

	int i = 0, j = 0, k = 0, found = 0;

	/* 信任名单中的ip的破解报普通日志 */
	pthread_rwlock_rdlock(&rule_trust_global.lock);
	for (i = 0; i < rule_trust_global.ip_num; i++) {
		for (j = 0; j < rule_trust_global.ip[i].ip_num; j++) {
			for (k = 0; k < rule_trust_global.ip[i].event_num; k++) {
				if (strcmp(rule_trust_global.ip[i].event_names[k].list, "Crack") != 0) {
					continue;
				}

				if (check_ip_is_match(conn->success_ip, rule_trust_global.ip[i].ip_list[j].list)) {
					found = 1;
					break;
				}
			}
		}
	}
	pthread_rwlock_unlock(&rule_trust_global.lock);

	if (!found) {
		cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
		cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_ABNORMAL);
	} else {
		cJSON_AddNumberToObject(object, "level", MY_LOG_NORMAL);
		cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_NORMAL);
	}

	if (OPERATION_MODE == client_mode_global || found) {
		cJSON_AddBoolToObject(object, "event", false);
	} else {
		cJSON_AddBoolToObject(object, "event", true);
	}

	t = event_time + serv_timeoff;
	localtime_r(&t, &time_info);
	strftime(log_time, 128, "%Y-%m-%d %H:%M:%S", &time_info);

	/* sqlite3_reset(start_fail_time_stmt);
	sqlite3_bind_text(start_fail_time_stmt, 1, conn->success_ip, -1, SQLITE_STATIC);
	sqlite3_bind_text(start_fail_time_stmt, 2, login_type, -1, SQLITE_STATIC);
	printf("%s, %s\n", conn->success_ip, login_type);
	while (sqlite3_step(start_fail_time_stmt) == SQLITE_ROW) {
	    printf("0000000\n");
	    start_time = sqlite3_column_int(start_fail_time_stmt, 0);
	    last_time = sqlite3_column_int(start_fail_time_stmt, 1);
	} */

	snprintf(buf, sizeof(buf), "select time from login_fail_tbl where crack_ip='%s' and type='%s';", conn->success_ip, login_type);
	sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
	start_time = atoi(azResult[ncolumn]);

	sqlite3_free_table(azResult);

	snprintf(buf, sizeof(buf), "select last_time from login_fail_tbl where crack_ip='%s' and type='%s';", conn->success_ip, login_type);
	sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
	last_time = atoi(azResult[ncolumn]);

	if (conn->count == 0) {
		sqlite3_free_table(azResult);
		snprintf(buf, sizeof(buf), "select queue_count from login_fail_tbl where crack_ip='%s' and type='%s';", conn->success_ip, login_type);
		sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
		crack_count = atoi(azResult[ncolumn]);

		conn->count = crack_count;
	}

	sqlite3_free_table(azResult);
	t = start_time + serv_timeoff;
	localtime_r(&t, &time_info);
	strftime(start_attack_time, 128, "%Y-%m-%d %H:%M:%S", &time_info);

	len = strlen(conn->success_user);
	if (conn->success_user[len - 1] == ',') {
		conn->success_user[len - 1] = 0;
	}

	cJSON_AddStringToObject(object, "log_name", "Crack");
	snprintf(ippath, sizeof(ippath), "%s/%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR, conn->success_ip);
	/* 确认ip是否锁成功 */
	if (protect_policy_global.account.login.crack.terminate) {
		if (access(ippath, F_OK) == 0) {
			cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK_LOCKIP_OK);
		} else if (!is_learning_or_operation_mode()) {
			cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK_LOCKIP_FAIL);
		} else {
			cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
		}
	} else {
		cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
	}

	cJSON_AddNumberToObject(arguments, "attack_duration", last_time - start_time);
	cJSON_AddStringToObject(arguments, "account", conn->success_user);
	cJSON_AddStringToObject(arguments, "compromised_account", conn->success_user);
	cJSON_AddNumberToObject(arguments, "crack_result", 1);
	cJSON_AddStringToObject(arguments, "remote_ip", handle_mapped_ipv4(conn->success_ip));
	cJSON_AddStringToObject(arguments, "remote_hostname", "");
	cJSON_AddStringToObject(arguments, "login_time", log_time);

	// TODO mysql,redis,暴力破解成功还未检测出来，login_type暂时有ssh和telnet两种情况
	cJSON_AddStringToObject(arguments, "login_type", login_type);
	cJSON_AddNumberToObject(arguments, "crack_count", conn->count);
	cJSON_AddNumberToObject(arguments, "lock_duration", protect_policy_global.account.login.crack.locking_time);
	if (protect_policy_global.account.login.crack.terminate && !found) {
		cJSON_AddBoolToObject(arguments, "is_lock", true);
	} else {
		cJSON_AddBoolToObject(arguments, "is_lock", false);
	}

	// 攻击开始时间
	cJSON_AddStringToObject(arguments, "attack_start_time", start_attack_time);

	cJSON_AddStringToObject(arguments, "session_uuid", conn->session_uuid);
	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	if (post) {
		DBG2(DBGFLAG_SSH, "Brute force password cracking success: %s\n", post);
		client_send_msg(post, reply, sizeof(reply), LOG_URL, "login");
		free(post);
	} else {
		MON_ERROR("NOT report %s %s brute force password cracking success, no memory\n", conn->success_ip, login_type);
	}

	cJSON_Delete(object);
}

static void send_login_msg(struct login_info *conn)
{
	struct timeval tv = {0};
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL, *arguments = NULL;
	char *post = NULL;
	char uuid[S_UUIDLEN] = {0};
	char session_uuid[S_UUIDLEN] = {0};
	time_t t = 0;
	struct tm time_info = {0};
	unsigned long event_time = 0;
	char log_time[128] = {0}, crack_time[128] = {0}, start_attack_time[128] = {0};
	struct timeval tvstamp = {0};
	struct defence_msg defmsg = {0};
	char ippath[S_SHORTPATHLEN] = {0};
	const char *province = NULL;
	int start_time = 0, last_time = 0;
	ACCOUNT_LOGIN *login_terminate = &protect_policy_global.account.login;
	int len = 0, nrow = 0, ncolumn = 0;
	char buf[1024] = {0};
	char **azResult = NULL;

	if (!conn) {
		return;
	}

	province = select_location_d(conn->login_ip);

	if (strcmp(conn->operating, "Logout") == 0) {
		/* 没有登出记录时，取当前时间为登出时间 */
		if (conn->endtv.tv_sec == 0) {
			gettimeofday(&conn->endtv, NULL);
		}
		if (conn->endtv.tv_sec <= conn->tv.tv_sec) {
			conn->endtv.tv_sec = conn->tv.tv_sec + 1;
		}
		tv.tv_sec = conn->endtv.tv_sec;
		tv.tv_usec = conn->endtv.tv_usec;
	} else {
		tv.tv_sec = conn->tv.tv_sec;
		tv.tv_usec = conn->tv.tv_usec;
		conn->flag |= FLAG_REPORTED;
	}

	gettimeofday(&tvstamp, NULL);
	event_time = (tvstamp.tv_sec + serv_timeoff) * 1000 + (int)tvstamp.tv_usec / 1000;

	t = tv.tv_sec + serv_timeoff;
	localtime_r(&t, &time_info);
	strftime(log_time, 128, "%Y-%m-%d %H:%M:%S", &time_info);

	t = conn->attack_time + serv_timeoff;
	localtime_r(&t, &time_info);
	strftime(crack_time, 128, "%Y-%m-%d %H:%M:%S", &time_info);

	len = strlen(conn->crack_user);
	if (conn->crack_user[len - 1] == ',') {
		conn->crack_user[len - 1] = 0;
	}

	len = strlen(conn->user);
	if (conn->user[len - 1] == ',') {
		conn->user[len - 1] = 0;
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

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_category", "Login");
	if (conn->result && conn->event_id != LOGIN_PASSWD_CRACK) {
		if (strcmp(conn->result, "Success") == 0) {
			cJSON_AddNumberToObject(object, "result", MY_HANDLE_WARNING);
		} else {
			cJSON_AddNumberToObject(object, "result", MY_HANDLE_BLOCK_OK);
		}
	} else {
		cJSON_AddNumberToObject(object, "result", MY_HANDLE_NO);
	}
	cJSON_AddStringToObject(object, "operating", conn->operating);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", conn->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	switch (conn->event_id) {
		case LOGIN_LOCAL_USER:	// 本地用户登录
			if (!local_login_check) {
				cJSON_Delete(object);
				cJSON_Delete(arguments);
				return;
			}
			cJSON_AddBoolToObject(object, "event", false);
			cJSON_AddStringToObject(object, "event_category", "");
			cJSON_AddNumberToObject(object, "level", MY_LOG_KEY);
			cJSON_AddStringToObject(object, "log_name", "LocalLogin");
			cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
			cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);
			cJSON_AddStringToObject(arguments, "user", conn->user);
			cJSON_AddStringToObject(arguments, "login_time", log_time);
			break;

		case LOGIN_ILLEGAL_USER:  // 非法本地用户登录
			cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
			cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_ABNORMAL);
			cJSON_AddStringToObject(object, "event_category", "Login");

			if (OPERATION_MODE == client_mode_global || strcmp(conn->operating, "Logout") == 0) {
				cJSON_AddBoolToObject(object, "event", false);
			} else {
				cJSON_AddBoolToObject(object, "event", true);
			}
			cJSON_AddStringToObject(object, "log_name", "IllegalLoginAccount");
			if (login_terminate->local.terminate || local_black || local_white) {
				if (conn->defence_result && strcmp(conn->defence_result, "Success") == 0) {
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK);
					defmsg.result = MY_RESULT_OK;
				} else if (!is_learning_or_operation_mode()) {
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_FAIL);
					defmsg.result = MY_RESULT_FAIL;
				} else {
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
				}

				if (!is_learning_or_operation_mode()) {
					// 报告本地非法登录防御日志
					defmsg.event_tv.tv_sec = tvstamp.tv_sec;
					defmsg.event_tv.tv_usec = tvstamp.tv_usec;
					defmsg.operation = termstr;
					defmsg.user = conn->user;
					defmsg.log_name = "IllegalLoginAccount";
					defmsg.log_id = uuid;
					defmsg.object = conn->user;
					send_defence_msg(&defmsg, "login");
				}
			} else {
				cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
			}
			cJSON_AddStringToObject(arguments, "login_time", log_time);

			if (local_black) {
				cJSON_AddStringToObject(arguments, "account", conn->user);
				cJSON_AddStringToObject(arguments, "detection_rule", "BlackUser");
			} else if (local_white) {
				cJSON_AddStringToObject(arguments, "account", conn->user);
				cJSON_AddStringToObject(arguments, "detection_rule", "WhiteUser");
			} else if (protect_policy_global.account.login.local.time.enable && !is_fixed_local_time) {
				cJSON_AddStringToObject(arguments, "account", conn->user);
				cJSON_AddStringToObject(arguments, "detection_rule", "IllegalLoginTime");
				if (strcmp(conn->operating, "Login") == 0) {
					if (conn->illegal_flag & FLAG_ILLEGALTIME) {
						cJSON_Delete(object);
						cJSON_Delete(arguments);
						is_fixed_local_time = 0;
						local_black = 0;
						local_white = 0;
						return;
					}
					conn->illegal_flag |= FLAG_ILLEGALTIME;
				}
			} else {
				cJSON_AddStringToObject(arguments, "session_uuid", conn->session_uuid);
				cJSON_AddItemToObject(object, "arguments", arguments);

				post = cJSON_PrintUnformatted(object);

				DBG2(DBGFLAG_SSH, "无登录描述---%s\n", post);
				cJSON_Delete(object);
				free(post);
				is_fixed_local_time = 0;
				local_black = 0;
				local_white = 0;
				return;
			}
			break;

		case LOGIN_REMOTE:	   // 远程登录
		case LOGIN_REMOTE_FAILED:  // 远程登录失败
			if (!protect_policy_global.account.login.remote.enable || !remote_login_check) {
				cJSON_Delete(object);
				cJSON_Delete(arguments);
				in_fixed_time = 0;
				return;
			}
			cJSON_AddBoolToObject(object, "event", false);
			cJSON_AddStringToObject(object, "event_category", "");
			cJSON_AddNumberToObject(object, "level", MY_LOG_KEY);
			cJSON_AddStringToObject(object, "log_name", "RemoteLogin");
			cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
			cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);

			cJSON_AddStringToObject(arguments, "user", conn->user);
			cJSON_AddStringToObject(arguments, "remote_ip", handle_mapped_ipv4(conn->login_ip));
			cJSON_AddStringToObject(arguments, "remote_hostname", "");
			cJSON_AddStringToObject(arguments, "login_type", conn->login_type);
			cJSON_AddStringToObject(arguments, "login_time", log_time);
			break;

		case LOGIN_ILLEGAL_REMOTE:  // 非法远程登录
			cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
			cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_ABNORMAL);
			cJSON_AddStringToObject(object, "event_category", "Login");

			if (OPERATION_MODE == client_mode_global || strcmp(conn->operating, "Logout") == 0) {
				cJSON_AddBoolToObject(object, "event", false);
			} else {
				cJSON_AddBoolToObject(object, "event", true);
			}
			cJSON_AddStringToObject(object, "log_name", "IllegalLoginIp");
			if (login_terminate->remote.terminate || black || remote_white) {
				if (conn->defence_result && strcmp(conn->defence_result, "Success") == 0) {
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK);
					defmsg.result = MY_RESULT_OK;
				} else {
					defmsg.result = MY_RESULT_FAIL;
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
				}

				if (!is_learning_or_operation_mode()) {
					// 报告远程非法登录防御日志
					defmsg.event_tv.tv_sec = tvstamp.tv_sec;
					defmsg.event_tv.tv_usec = tvstamp.tv_usec;
					defmsg.operation = termstr;
					defmsg.user = conn->user;
					defmsg.log_name = "IllegalLoginIp";
					defmsg.log_id = uuid;
					defmsg.object = conn->login_ip;
					send_defence_msg(&defmsg, "login");
				}
			} else {
				cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
			}
			cJSON_AddStringToObject(arguments, "user", conn->user);
			cJSON_AddStringToObject(arguments, "remote_ip", handle_mapped_ipv4(conn->login_ip));
			cJSON_AddStringToObject(arguments, "remote_hostname", "");
			cJSON_AddStringToObject(arguments, "login_type", conn->login_type);
			cJSON_AddStringToObject(arguments, "login_time", log_time);
			if (province) {
				cJSON_AddStringToObject(arguments, "country", province);
				cJSON_AddStringToObject(arguments, "province", "");
				cJSON_AddStringToObject(arguments, "city", "");
			} else {
				cJSON_AddStringToObject(arguments, "country", "局域网");
				cJSON_AddStringToObject(arguments, "province", "");
				cJSON_AddStringToObject(arguments, "city", "");
			}
			// printf("%d, %d\n", protect_policy_global.account.login.remote.time.enable, in_fixed_time);
			if (black) {
				cJSON_AddStringToObject(arguments, "detection_rule", "BlackIP");
			} else if (remote_white) {
				cJSON_AddStringToObject(arguments, "detection_rule", "WhiteIP");
			} else if (protect_policy_global.account.login.remote.time.enable && !in_fixed_time) {
				cJSON_AddStringToObject(arguments, "detection_rule", "IllegalLoginTime");
				if (strcmp(conn->operating, "Login") == 0) {
					if (conn->illegal_flag & FLAG_ILLEGALTIME) {
						cJSON_Delete(object);
						cJSON_Delete(arguments);
						in_fixed_time = 0;
						in_fixed_location = 0;
						black = 0;
						remote_white = 0;
						return;
					}
					conn->illegal_flag |= FLAG_ILLEGALTIME;
				}
			} else if (protect_policy_global.account.login.remote.location.enable && !in_fixed_location) {
				cJSON_AddStringToObject(arguments, "detection_rule", "IllegalLoginLocation");
				if (strcmp(conn->operating, "Login") == 0) {
					if (conn->illegal_flag & FLAG_ILLEGALLOCATION) {
						cJSON_Delete(object);
						cJSON_Delete(arguments);
						in_fixed_time = 0;
						in_fixed_location = 0;
						black = 0;
						remote_white = 0;
						return;
					}
					conn->illegal_flag |= FLAG_ILLEGALLOCATION;
				}
			} else {
				cJSON_AddStringToObject(arguments, "session_uuid", conn->session_uuid);
				cJSON_AddItemToObject(object, "arguments", arguments);

				post = cJSON_PrintUnformatted(object);

				DBG2(DBGFLAG_SSH, "无登录描述---%s\n", post);
				cJSON_Delete(object);
				free(post);
				in_fixed_time = 0;
				in_fixed_location = 0;
				black = 0;
				remote_white = 0;
				return;
			}
			break;

		case LOGIN_PASSWD_CRACK:  // 暴力密码破解
			/* 不监控密码暴力破解，不报密码暴力破解日志 */
			if (!remote_login_crack_check) {
				cJSON_Delete(object);
				cJSON_Delete(arguments);
				return;
			}
			if (conn->behavior_id == BEHAVIOR_NORMAL) {
				cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_NORMAL);
			} else {
				cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_ABNORMAL);
			}
			cJSON_AddStringToObject(object, "event_category", "Login");
			if (conn->loglevel == MY_LOG_NORMAL) {
				cJSON_AddNumberToObject(object, "level", MY_LOG_NORMAL);
			} else {
				cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
			}

			if (OPERATION_MODE == client_mode_global || conn->loglevel == MY_LOG_NORMAL) {
				cJSON_AddBoolToObject(object, "event", false);
			} else {
				cJSON_AddBoolToObject(object, "event", true);
			}

			cJSON_AddStringToObject(object, "log_name", "Crack");
			snprintf(ippath, sizeof(ippath), "%s/%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR, conn->login_ip);
			/* 确认ip是否锁成功 */
			if (protect_policy_global.account.login.crack.terminate) {
				if (access(ippath, F_OK) == 0) {
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK_LOCKIP_OK);
					defmsg.result = MY_RESULT_OK;
				} else if (!is_learning_or_operation_mode()) {
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK_LOCKIP_FAIL);
					defmsg.result = MY_RESULT_FAIL;
				} else {
					cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
				}

				if (!is_learning_or_operation_mode() && conn->locking != 0) {
					// 报告暴力密码破解防御日志
					defmsg.event_tv.tv_sec = tvstamp.tv_sec;
					defmsg.event_tv.tv_usec = tvstamp.tv_usec;
					defmsg.operation = lockstr;
					defmsg.user = conn->user;
					defmsg.log_name = "Crack";
					defmsg.log_id = uuid;
					defmsg.object = conn->login_ip;
					send_defence_msg(&defmsg, "login");
				}
			} else {
				cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
			}

			snprintf(buf, sizeof(buf), "select time from login_fail_tbl where crack_ip='%s' and type='%s';", conn->login_ip, conn->login_type);
			sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
			start_time = atoi(azResult[ncolumn]);

			sqlite3_free_table(azResult);

			snprintf(buf, sizeof(buf), "select last_time from login_fail_tbl where crack_ip='%s' and type='%s';", conn->login_ip, conn->login_type);
			sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
			last_time = atoi(azResult[ncolumn]);

			t = start_time + serv_timeoff;
			localtime_r(&t, &time_info);
			strftime(start_attack_time, 128, "%Y-%m-%d %H:%M:%S", &time_info);

			cJSON_AddNumberToObject(arguments, "attack_duration", last_time - start_time);

			cJSON_AddStringToObject(arguments, "account", conn->crack_user);

			// sqlite3_exec(crack_user_db, del_sql, 0, 0, 0);

			cJSON_AddStringToObject(arguments, "remote_ip", handle_mapped_ipv4(conn->login_ip));
			cJSON_AddStringToObject(arguments, "remote_hostname", "");
			cJSON_AddStringToObject(arguments, "login_time", crack_time);
			cJSON_AddStringToObject(arguments, "compromised_account", "");
			cJSON_AddNumberToObject(arguments, "crack_result", 0);

			/* //存攻击ip和报告暴力破解的时间到数据库
			if (strcmp(conn->login_type, "SSH") == 0) {
			    save_attackip_info(conn->crack_user, conn->login_ip, conn->attack_time, "SSH");
			} else if (strcmp(conn->login_type, "TELNET") == 0) {
			    save_attackip_info(conn->crack_user, conn->login_ip, conn->attack_time, "TELNET");
			} */

			// printf("%s\n", crack_user);
			cJSON_AddStringToObject(arguments, "login_type", conn->login_type);
			cJSON_AddNumberToObject(arguments, "crack_count", conn->failed_count);
			cJSON_AddNumberToObject(arguments, "lock_duration", protect_policy_global.account.login.crack.locking_time);
			if (protect_policy_global.account.login.crack.terminate && conn->locking != 0) {
				cJSON_AddBoolToObject(arguments, "is_lock", true);
				cJSON_AddStringToObject(arguments, "lock_ip", handle_mapped_ipv4(conn->login_ip));
			} else {
				cJSON_AddBoolToObject(arguments, "is_lock", false);
			}
			cJSON_AddStringToObject(arguments, "attack_start_time", start_attack_time);

			sqlite3_free_table(azResult);
			break;

		default:
			MON_ERROR("%s %s %s %s : bad event_id %d\n",
				  conn->user, conn->operating,
				  conn->login_type, conn->login_ip,
				  conn->event_id);
			cJSON_Delete(object);
			cJSON_Delete(arguments);
			return;
	}

	if (conn->session_uuid[0] == 0) {
		get_session_uuid(conn->tty, session_uuid);
		cJSON_AddStringToObject(arguments, "session_uuid", session_uuid);
	} else {
		cJSON_AddStringToObject(arguments, "session_uuid", conn->session_uuid);
	}
	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);

	DBG2(DBGFLAG_SSH, "登录---%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "login");

	black = 0;
	in_fixed_location = 0;
	in_fixed_time = 0;
	is_fixed_local_time = 0;
	local_black = 0;
	local_white = 0;
	remote_white = 0;

	cJSON_Delete(object);
	free(post);
}

static int get_netlogin_info(struct login_info *conn, char *comm, sockinfo_t *sinfo)
{
	FILE *fp = NULL;
	pid_t mypid = 0;
	char path[S_PROCPATHLEN] = {0};
	char str[S_NAMELEN] = {0};
	char buf[S_LINELEN] = {0};
	int ret = 0;

	if (!conn || !comm || !sinfo) {
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/stat", conn->pid);
	fp = sniper_fopen(path, "r", LOGIN_GET);
	if (!fp) {
		if (errno != ENOENT) {
			MON_ERROR("open %s fail: %s\n", path, strerror(errno));
		}
		return -1;
	}

	if (!fgets(buf, sizeof(buf), fp)) {
		sniper_fclose(fp, LOGIN_GET);
		MON_ERROR("read %s fail: %s\n", path, strerror(errno));
		return -1;
	}
	sniper_fclose(fp, LOGIN_GET);

	/* 对于987 ((sd-pam)) S 986 ...这样的情况，用"%d (%[^)]) %*c %d"会报错 */
	/* 对于963 (JS Sour~ Thread) S 907 ...这样的情况，用"%d %s %*c %d"会报错 */
	ret = sscanf(buf, "%d %63s %*c %d", &mypid, str, &conn->ppid);
	if (ret != 3) {
		MON_ERROR("read invalid string from %s : %s\n", path, buf);
		return -1;
	}

	/* centos5/6/7的utmp/wtmp登录记录里的pid是bash进程，ubuntu/centos8是sshd */

	if (strcmp(str, "(bash)") != 0 && strcmp(str, "(login)") != 0) {  // 登录进程即连接进程
		get_proc_exe(conn->pid, comm);
		if (get_process_socket_info(conn->pid, sinfo, 0) >= 0) {
			conn->connpid = conn->pid;
			return 0;
		}

		/* 如果没取到登录进程的网络连接信息，尝试下面取父进程的网络连接信息 */
		INFO("get login process %s(%d)[user %s, tty %s] connection information fail, try its parent %d\n",
		     comm, conn->pid, conn->user, conn->tty, conn->ppid);
	}

	/* 登录记录里的pid是bash/login进程，非连接进程，用登录进程的父进程pid作为连接进程pid */
	conn->connpid = conn->ppid;
	get_proc_exe(conn->ppid, comm);

	return get_process_socket_info(conn->ppid, sinfo, 0);
}

static void do_locking_defence(char *login_ip)
{
	struct defence_msg defmsg = {0};
	char uuid[S_UUIDLEN] = {0};
	int locking_time = protect_policy_global.account.login.crack.locking_time * 60;

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	if (!protect_policy_global.account.login.crack.terminate) {
		return;
	}

	if (lock_ip(login_ip, LOGIN_ILLEGAL_REMOTE, locking_time, "Crack", uuid) < 0) {
		defmsg.result = 0;
	} else {
		INFO("lock：%s\n", login_ip);
		defmsg.result = 1;
	}

	gettimeofday(&defmsg.event_tv, NULL);
	defmsg.operation = lockstr;

	// defmsg.event_id = login_info->event_id;
	// defmsg.user = login_info->user；
	// defmsg.ip = login_info->login_ip;
	//    	defmsg.desc = LOG_NET_BLOCK_ACCESSIP;
	// defmsg.count = crack_count;
	// send_defence_msg(&defmsg, "login");
}

/* 如果连接进程是连接服务程序，不杀。避免误杀sshd服务 */
static int should_stop_connection_process(pid_t connpid, pid_t loginpid)
{
	FILE *fp = NULL;
	char path[S_PROCPATHLEN] = {0};
	char buf[S_LINELEN] = {0};
	char comm[S_COMMLEN] = {0};
	pid_t ppid = 0, mypid = 0;
	int ret = 0;

	if (connpid == 0 || connpid == loginpid) {
		return 0;
	}

	snprintf(path, sizeof(path), "/proc/%d/stat", connpid);
	fp = sniper_fopen(path, "r", LOGIN_GET);
	if (!fp) {
		return 0;
	}

	fgets(buf, sizeof(buf), fp);
	sniper_fclose(fp, LOGIN_GET);

	ret = sscanf(buf, "%d (%15[^)]) %*c %d", &mypid, comm, &ppid);
	if (ret != 3) {
		return 0;
	}

	if (ppid <= 2) {
		// printf("NOT Stop connection process %s(%d), as its parent is %d\n",
		//	comm, connpid, ppid);
		// return 0;
		printf("\n\n\n======Warning======Stop connection process %s(%d), but its parent is %d\n\n\n", comm, connpid, ppid);
		INFO("\n\n\n======Warning======Stop connection process %s(%d), but its parent is %d\n\n\n", comm, connpid, ppid);
	}

	return 1;
}

static void break_illegal_login(struct login_info *conn, int locking)
{
	int killed = 0;
	int i = 0, ret = 0, locked = 0;
	pid_t pgid = 0, connpgid = 0;
	struct timespec req = {0, 1000000};
	char uuid[S_UUIDLEN] = {0};

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	INFO("break_illegal_login: %s %s %s %s %s %s pid %d event_id %d\n",
	     conn->operating, conn->login_type, conn->user, conn->tty,
	     conn->login_ip, conn->session_uuid, conn->pid, conn->event_id);

	if (conn->login_ip[0]) {
		INFO("Stop %s %s login%s. from %s, tty %s, pid %d, pgid %d\n",
		     conn->user, conn->login_type, ret == 0 ? "" : " fail",
		     conn->login_ip, conn->tty, conn->pid, pgid);

		// TODO 确认杀进程组是否会过度防御，导致远程登录服务也被杀
		/*
		 * 不使用kill(conn->pid, SIGKILL)，只kill了进程，处理的不完善。
		 * 子进程仍在，连接没断。要杀进程组
		 * 用SIGTERM，使能产生logout记录
		 */
		pgid = mygetpgid(conn->pid);
		if (pgid <= 0) {
			INFO("Warning: get process %d group fail: %s\n",
			     conn->pid, strerror(errno));
			ret = mykill(conn->pid, SIGTERM);
		} else {
			ret = mykillpg(pgid, SIGTERM);
		}
	} else {
		INFO("Stop %s %s login%s. tty %s, pid %d, pgid %d\n",
		     conn->user, conn->login_type, ret == 0 ? "" : " fail",
		     conn->tty, conn->pid, pgid);

		/* 本地登录只杀登录进程，不杀进程组，以免误杀图形登录服务程序，使得在suse上图形登录界面消失 */

		/* 进程之前睡一秒，防止出现下面的问题：
		   suse上踢出登录的用户，然后立刻再用此用户登录，仍然登录成功并进了图形界面 */
		sleep(1);
		ret = mykill(conn->pid, SIGTERM);
	}

	if (should_stop_connection_process(conn->connpid, conn->pid) && conn->login_ip[0]) {
		connpgid = mygetpgid(conn->connpid);
		if (connpgid <= 0) {
			INFO("Warning: get process %d group fail: %s\n",
			     conn->connpid, strerror(errno));
			ret = mykill(conn->connpid, SIGTERM);
		} else {
			ret = mykillpg(connpgid, SIGTERM);
		}
		INFO("Stop %s connect process from %s. pid %d, pgid %d, ret %d\n",
		     conn->user, conn->login_ip, conn->connpid, connpgid, ret);
	}

	/* 多给killpg一点时间，每1毫秒检查1次 */
	for (i = 0; i < 1000; i++) {
		if ((killed = mykill(conn->pid, 0)) == 0) {
			nanosleep(&req, NULL);
			continue;
		}
		break;
	}

	if (killed < 0) {
		conn->defence_result = succstr;
		return;
	}

	INFO("process %d not stopped, kill it again\n", conn->pid);
	/* 前面SIGTERM没杀成功，再SIGKILL杀一次 */
	if (pgid <= 0) {
		ret = mykill(conn->pid, SIGKILL);
	} else {
		ret = mykillpg(pgid, SIGKILL);
	}
	if (should_stop_connection_process(conn->connpid, conn->pid) && conn->login_ip[0]) {
		if (connpgid <= 0) {
			ret = mykill(conn->connpid, SIGKILL);
		} else {
			ret = mykillpg(connpgid, SIGKILL);
		}
	}

	/* 多给killpg一点时间，每1毫秒检查1次 */
	for (i = 0; i < 1000; i++) {
		if ((killed = mykill(conn->pid, 0)) == 0) {
			nanosleep(&req, NULL);
			continue;
		}
		break;
	}

	if (killed < 0) {
		INFO("process %d killed\n", conn->pid);
		conn->defence_result = succstr;
	} else if (strcmp(conn->login_type, "SYSTEM") == 0) {
		INFO("process %d NOT killed\n", conn->pid);
		conn->defence_result = failstr;
	} else if (locked < 0) {
		INFO("process %d NOT killed, and %s NOT locked\n", conn->pid, conn->login_ip);
		conn->defence_result = failstr;
	} else {
		INFO("process %d NOT killed, but %s locked\n", conn->pid, conn->login_ip);
		conn->defence_result = succstr;
	}
}

static void free_login(struct login_info *pos)
{
	pthread_mutex_lock(&sshconn_lock);
	list_del(&pos->list);
	pthread_mutex_unlock(&sshconn_lock);
	sniper_free(pos, sizeof(struct login_info), LOGIN_GET);
}

static void post_closed_login(struct login_info *pos)
{
	snprintf(pos->operating, sizeof(pos->operating), "Logout");
	// send_login_msg(pos);

	free_login(pos);
}

/* 处理非法登录 */
static void deal_illegal_login(struct login_info *conn,
			       int login_reported,
			       int event_id, int locking, int login_num)
{
	/* 学习模式和运维模式不阻断不锁ip */
	if (client_mode_global == OPERATION_MODE) {
		/* 这是一个新的非法登录 */
		if (!login_reported) {
			conn->event_id = event_id;
			conn->behavior_id = BEHAVIOR_VIOLATION;
			conn->loglevel = LOG_HIGH_RISK;
			snprintf(conn->operating, sizeof(conn->operating), "Login");
			send_login_msg(conn);
			return;
		}

		/* 之前有按正常报过登录动作，现在根据新策略认为是非法登录 */
		/* 先结束原正常登录动作 */
		snprintf(conn->operating, sizeof(conn->operating), "Login");
		gettimeofday(&conn->endtv, NULL);
		send_login_msg(conn);

		/* 再代之以一个非法登录 */
		conn->event_id = event_id;
		conn->behavior_id = BEHAVIOR_VIOLATION;
		conn->loglevel = LOG_HIGH_RISK;
		snprintf(conn->operating, sizeof(conn->operating), "Login");
		conn->result = succstr;
		/* 为了避免和之前的正常登录日志冲突，登录时间+1s */
		conn->tv.tv_sec++;
		// send_login_msg(conn);
		return;
	}

	/* 这是一个新的非法登录 */
	if (!login_reported) {
		conn->event_id = event_id;
		conn->behavior_id = BEHAVIOR_VIOLATION;
		conn->loglevel = LOG_HIGH_RISK;
		conn->terminate = 2;
		conn->locking = locking;
		snprintf(conn->operating, sizeof(conn->operating), "Login");

		/* 阻断非法登录，并报告防御日志 */
		if (conn->event_id == LOGIN_ILLEGAL_USER) {
			if (protect_policy_global.account.login.local.terminate || local_black || local_white) {
				break_illegal_login(conn, locking);
			}
		} else if (conn->event_id == LOGIN_ILLEGAL_REMOTE) {
			if (protect_policy_global.account.login.remote.terminate || black || remote_white) {
				break_illegal_login(conn, locking);
			}
		}

		/*
		 * 对于一次新的非法登录，
		 * 阻断成功，报非法登录失败
		 * 阻断失败，报非法登录成功
		 */
		if (conn->defence_result == succstr) {
			conn->result = failstr;
			send_login_msg(conn);
			login_num--;
			/* 阻断成功，报告非法登录失败，后继不需要再报登出 */
			free_login(conn);
		} else {
			conn->result = succstr;
			send_login_msg(conn);
		}
		return;
	}

	/* 如果之前有报过登录动作，要先结束原登录动作，再代之以一个非法登录 */
	/* 报告原登录结束 */
	conn->event_id = event_id;
	conn->behavior_id = BEHAVIOR_VIOLATION;
	conn->loglevel = LOG_HIGH_RISK;
	conn->terminate = 2;
	conn->locking = locking;

	/* 报告一条非法登录日志 */
	conn->result = succstr;
	/* 为了避免和之前的正常登录日志冲突，登录时间+1s */
	conn->tv.tv_sec++;

	/* 阻断非法登录，并报告防御日志 */
	if (conn->event_id == LOGIN_ILLEGAL_USER &&
	    protect_policy_global.account.login.local.terminate_mode) {
		if (protect_policy_global.account.login.local.terminate || local_black || local_white) {
			break_illegal_login(conn, locking);
		}
	} else if (conn->event_id == LOGIN_ILLEGAL_REMOTE &&
		   protect_policy_global.account.login.remote.terminate_mode) {
		if (protect_policy_global.account.login.remote.terminate || black || remote_white) {
			break_illegal_login(conn, locking);
		}
	}

	if (conn->defence_result == succstr) {
		conn->result = failstr;
		send_login_msg(conn);
	} else {
		conn->result = succstr;
		send_login_msg(conn);
	}

	/*
	 * 对于修改策略使已存在的登录变成非法登录，
	 * 阻断失败，等真正登出的时候再报告非法登录结束
	 * 阻断成功，报告非法登录失败
	 */
	if (conn->defence_result == succstr) {
		snprintf(conn->operating, sizeof(conn->operating), "Logout");
		if (conn->endtv.tv_sec == 0) {
			gettimeofday(&conn->endtv, NULL);
		} else {
			conn->endtv.tv_sec++;
		}
		post_closed_login(conn);
	}
}

/* 检查本地登录 */
static int check_local_login(char *login_user)
{
	char *user = NULL;
	char times[128] = {0};
	int i = 0, j = 0, checked = 0, is_white = 0;
	int today_hour = 0, today_min = 0;
	int my_start_hour = 0, my_start_min = 0, my_end_hour = 0, my_end_min = 0;
	LOGIN_LOCAL *local = &protect_policy_global.account.login.local;

	if (!login_user) {
		return 0;
	}

	if (!is_learning_or_operation_mode()) {
		/* 检查黑名单用户 */
		pthread_rwlock_rdlock(&rule_black_global.lock);

		for (i = 0; i < rule_black_global.user_num; i++) {
			for (j = 0; j < rule_black_global.user[i].user_num; j++) {
				user = rule_black_global.user[i].user_list[j].list;
				if (strcmp(login_user, user) == 0) {
					pthread_rwlock_unlock(&rule_black_global.lock);
					local_black = 1;
					return FLAG_VIOLATION;
				}
			}
		}

		pthread_rwlock_unlock(&rule_black_global.lock);

		/* 检查白名单用户 */
		pthread_rwlock_rdlock(&rule_white_global.lock);
		for (i = 0; i < rule_white_global.user_num; i++) {
			for (j = 0; j < rule_white_global.user[i].user_num; j++) {
				user = rule_white_global.user[i].user_list[j].list;
				if (is_valid_str(user)) {
					checked++;
				}
				if (strcmp(login_user, user) == 0) {
					is_white = 1;
					break;
				}
			}
		}
		if (checked && !is_white) {
			local_white = 1;
			pthread_rwlock_unlock(&rule_white_global.lock);
			return FLAG_VIOLATION;
		}

		pthread_rwlock_unlock(&rule_white_global.lock);
	}

	pthread_rwlock_rdlock(&protect_policy_global.lock);
	if (local->time.enable) {
		time_t t;
		time(&t);
		sscanf(ctime(&t), "%*s %*s %*s %127s", times);
		sscanf(times, "%d:%d:%*d", &today_hour, &today_min);
		// printf("%d, %d\n", today_hour, today_min);

		for (i = 0; i < local->time.list_num; i++) {
			sscanf(local->time.list[i].start_time, "%d:%d", &my_start_hour, &my_start_min);
			sscanf(local->time.list[i].end_time, "%d:%d", &my_end_hour, &my_end_min);
			if ((today_hour * 60 + today_min) >= (my_start_hour * 60 + my_start_min) && (today_hour * 60 + today_min) <= (my_end_hour * 60 + my_end_min)) {
				is_fixed_local_time = 1;
				break;
			}
		}
		if (!is_fixed_local_time) {
			pthread_rwlock_unlock(&protect_policy_global.lock);
			return FLAG_VIOLATION;
		}
	}
	pthread_rwlock_unlock(&protect_policy_global.lock);
	return 0;
}

/* 检查远程登录 */
static int check_remote_login(char *login_ip, int login_reported, int login_time)
{
	char *ip = NULL;
	int i = 0, j = 0;
	int ip_d1 = 0, ip_d2 = 0, ip_d3 = 0, ip_d6 = 0;
	int ip_my1 = 0, ip_my2 = 0, ip_my3 = 0;
	char *str = NULL, *ptr = NULL, times[128] = {0};
	int today_hour = 0, today_min = 0;
	int my_start_hour = 0, my_start_min = 0, my_end_hour = 0, my_end_min = 0;
	int checked = 0, is_white = 0, flag = 0;
	const char *location_name = NULL;
	LOGIN_MY_REMOTE *remote = &protect_policy_global.account.login.remote;
	struct tm time_info = {0};
	char log_time[128] = {0};
	time_t t;

	if (!protect_policy_global.account.login.remote.enable || !login_ip) {
		return 0;
	}

	if (!is_learning_or_operation_mode()) {
		/* 检查黑名单ip */
		pthread_rwlock_rdlock(&rule_black_global.lock);
		for (i = 0; i < rule_black_global.ip_num; i++) {
			for (j = 0; j < rule_black_global.ip[i].ip_num; j++) {
				ip = rule_black_global.ip[i].ip_list[j].list;
				if (check_ip_is_match(login_ip, ip)) {
					black = 1;
					/* 远程登录黑名单不锁ip，在解析网络策略时禁 */
					pthread_rwlock_unlock(&rule_black_global.lock);
					return FLAG_VIOLATION;
				}
			}
		}
		pthread_rwlock_unlock(&rule_black_global.lock);

		/*检查白名单ip*/
		pthread_rwlock_rdlock(&rule_global_global.lock);
		for (i = 0; i < rule_white_global.ip_num; i++) {
			for (j = 0; j < rule_white_global.ip[i].ip_num; j++) {
				ip = rule_white_global.ip[i].ip_list[j].list;
				if (is_valid_str(ip)) {
					checked++;
				}
				if (check_ip_is_match(login_ip, ip)) {
					is_white = 1;
					break;
				}
			}
		}
		pthread_rwlock_unlock(&rule_global_global.lock);

		if (checked && !is_white) {
			flag = FLAG_VIOLATION;
			remote_white = 1;
			/* 学习模式和运维模式不阻断不锁ip */
			if (client_mode_global == OPERATION_MODE) {
				flag |= FLAG_LOCKING;
			}
			return flag;
		}
	}

	// 判断是否是常用时间内登录
	pthread_rwlock_rdlock(&protect_policy_global.lock);
	if (remote->time.enable) {
		t = login_time + serv_timeoff;
		localtime_r(&t, &time_info);
		strftime(log_time, 128, "%Y-%m-%d %H:%M:%S", &time_info);
		sscanf(log_time, "%*s %127s", times);
		sscanf(times, "%d:%d:%*d", &today_hour, &today_min);

		DBG2(DBGFLAG_SSH, "远程登录时间---%s\n", log_time);
		for (i = 0; i < remote->time.list_num; i++) {
			DBG2(DBGFLAG_SSH, "远程登录合规时间---%s, %s\n", remote->time.list[i].start_time, remote->time.list[i].end_time);
			sscanf(remote->time.list[i].start_time, "%d:%d", &my_start_hour, &my_start_min);
			sscanf(remote->time.list[i].end_time, "%d:%d", &my_end_hour, &my_end_min);
			if ((today_hour * 60 + today_min) >= (my_start_hour * 60 + my_start_min) && (today_hour * 60 + today_min) <= (my_end_hour * 60 + my_end_min)) {
				in_fixed_time = 1;
				break;
			}
		}
		if (!in_fixed_time) {
			pthread_rwlock_unlock(&protect_policy_global.lock);
			return FLAG_VIOLATION;
		}
	}

	// 判断是否是常用地点内登录
	if (remote->location.enable) {
		if (is_internet_ip(login_ip)) {
			location_name = select_location_d(login_ip);
			if (location_name) {
				if (ip_my1 == ip_d1 && ip_my2 == ip_d2 && (ip_my3 >= ip_d3 && ip_my3 <= ip_d6)) {
					for (i = 0; i < remote->location.list_num; i++) {
						str = strstr(location_name, remote->location.list[i].city);
						ptr = strstr(location_name, remote->location.list[i].province);
						if (str || ptr) {
							in_fixed_location = 1;
						}
					}
					if (remote->location.list_num == 0) {
						in_fixed_location = 1;
					}
				}
			}
		} else {
			in_fixed_location = 1;
		}

		if (!in_fixed_location) {
			pthread_rwlock_unlock(&protect_policy_global.lock);
			return FLAG_VIOLATION;
		}
	}
	pthread_rwlock_unlock(&protect_policy_global.lock);

	/* 该登录动作已报告给管控中心，则不可过滤，否则没有对应的登出了 */
	if (login_reported) {
		in_fixed_time = 0;
		return 0;
	}

	return 0;
}

time_t login_strategy_time = 0;	 // TODO 每次策略改变时设置
/* 检查登录动作的属性：违规，过滤，还是普通 */
static void check_login(struct login_info *conn)
{
	int login_reported = 0;

	if (!conn) {
		return;
	}

	/* 已按最新登录策略检查过该登录，不用重复检查 */
	if (conn->check_strategy_time >= login_strategy_time) {
		return;
	}
	conn->check_strategy_time = login_strategy_time;
	conn->flag &= FLAG_REPORTED;

	if (strcmp(conn->login_type, "SYSTEM") == 0) {
		conn->flag |= check_local_login(conn->user);
	} else {
		login_reported = conn->flag & FLAG_REPORTED;
		conn->flag |= check_remote_login(conn->login_ip, login_reported, conn->tv.tv_sec);
	}
}

struct authok_user_info authok_users[16] = {{0}};
static void set_authok_user(struct failinfo *msg)
{
	int i = 0, idx = 0;
	time_t oldest_t = 0;

	if (!msg) {
		return;
	}

	oldest_t = authok_users[0].t;
	for (i = 0; i < 16; i++) {
		if (strcmp(msg->user, authok_users[i].user) == 0 &&
		    strcmp(msg->login_type, authok_users[i].login_type) == 0 &&
		    strcmp(msg->ip, authok_users[i].ip) == 0) {
			authok_users[i].t = time(NULL);
			DBG2(DBGFLAG_SSH, "update_authok_user: [%d] %s %s %s %lu\n",
			     idx, msg->ip, msg->user, msg->login_type, authok_users[i].t);
			return;
		}

		if (authok_users[i].t < oldest_t) {
			idx = i;
			oldest_t = authok_users[i].t;
		}
	}

	authok_users[idx].t = time(NULL);
	snprintf(authok_users[idx].ip, sizeof(authok_users[idx].ip), "%s", msg->ip);
	snprintf(authok_users[idx].user, sizeof(authok_users[idx].user), "%s", msg->user);
	snprintf(authok_users[idx].login_type, sizeof(authok_users[idx].login_type), "%s", msg->login_type);

	DBG2(DBGFLAG_SSH, "set_authok_user: [%d] %s %s %s %lu\n",
	     idx, msg->ip, msg->user, msg->login_type, authok_users[idx].t);
}

static void post_crack_events(struct login_info *conn)
{
	char buf[1024] = {0};
	int rc = 0, nrow = 0, ncolumn = 0, i = 0, j = 0, k = 0;
	char **azResult = NULL;
	int crack_try_num = protect_policy_global.account.login.crack.limit;
	struct timeval tvstamp = {0};
	struct failinfo info = {0};
	int ret = 0;
	unsigned long success_time = 0;
	// char *str = NULL;

	int policy_time = protect_policy_global.account.login.crack.interval * 60;

	gettimeofday(&tvstamp, NULL);
	conn->tv.tv_sec = tvstamp.tv_sec;

	// select user from login_fail_tbl where ip = ? and type = ? and count >= ?;
	snprintf(buf, sizeof(buf), "select name from login_fail_tbl where crack_ip='%s' and type='%s' and queue_count>='%d';", conn->login_ip, conn->login_type, crack_try_num);
	rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);

	if (rc != SQLITE_OK) {
		sqlite3_free_table(azResult);
		return;
	}

	if (nrow) {
		for (i = 1; i <= nrow; i++) {
			if (azResult[i]) {
				snprintf(conn->crack_user, sizeof(conn->crack_user), "%s", azResult[i]);

				for (j = 0; j < strlen(conn->crack_user); j++) {
					if (conn->crack_user[j] == ' ') {
						conn->crack_user[j] = ',';
					}
				}
			}
		}

		conn->event_id = LOGIN_PASSWD_CRACK;
		conn->behavior_id = BEHAVIOR_ABNORMAL;
		conn->loglevel = MY_LOG_HIGH_RISK;

		if (remote_login_crack_locking) {
			conn->terminate = 1;
			conn->locking = 1;
		} else {
			conn->terminate = 0;
			conn->locking = 0;
		}

		pthread_rwlock_rdlock(&rule_trust_global.lock);
		for (i = 0; i < rule_trust_global.ip_num; i++) {
			for (j = 0; j < rule_trust_global.ip[i].ip_num; j++) {
				for (k = 0; k < rule_trust_global.ip[i].event_num; k++) {
					if (strcmp(rule_trust_global.ip[i].event_names[k].list, "Crack") != 0) {
						continue;
					}

					if (check_ip_is_match(conn->login_ip, rule_trust_global.ip[i].ip_list[j].list)) {
						conn->terminate = 0;
						conn->locking = 0;
						conn->event_id = LOGIN_PASSWD_CRACK;
						conn->behavior_id = BEHAVIOR_NORMAL;
						conn->loglevel = MY_LOG_NORMAL;
						break;
					}
				}
			}
		}
		pthread_rwlock_unlock(&rule_trust_global.lock);

		// TODO 将此次暴破事件存入crack_tbl，表示处于爆破态 1
		sqlite3_free_table(azResult);
		snprintf(buf, sizeof(buf), "SELECT * FROM crack_tbl WHERE ip='%s' and type='%s';", conn->login_ip, conn->login_type);
		rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);

		if (!nrow) {  // 新纪录才报告，后面的报告归crack_monitor管理
			sqlite3_free_table(azResult);
			snprintf(buf, sizeof(buf), "select queue_count from login_fail_tbl where crack_ip='%s' and type='%s';", conn->login_ip, conn->login_type);
			rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
			conn->failed_count = atoi(azResult[ncolumn]);

			sqlite3_free_table(azResult);
			snprintf(buf, sizeof(buf), "select last_time from login_fail_tbl where crack_ip='%s' and type='%s';", conn->login_ip, conn->login_type);
			rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
			conn->attack_time = atoi(azResult[ncolumn]);
			sqlite3_free_table(azResult);

			send_login_msg(conn);

			if (!is_learning_or_operation_mode() && protect_policy_global.account.login.crack.terminate != 0) {  // 是否锁定ip
				do_locking_defence(conn->login_ip);
			}

			snprintf(buf, sizeof(buf), "SELECT crack_time FROM crack_success_tbl WHERE crack_ip='%s' and login_type='%s';", conn->login_ip, conn->login_type);
			ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
			if (ret == SQLITE_OK && nrow != 0) {
				if ((tvstamp.tv_sec - atoi(azResult[ncolumn])) < policy_time) {
					success_time = atoi(azResult[ncolumn]);

					sqlite3_free_table(azResult);
					snprintf(buf, sizeof(buf), "SELECT crack_user FROM crack_success_tbl WHERE crack_ip='%s' and login_type='%s';", conn->login_ip, conn->login_type);
					ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
					snprintf(info.success_user, sizeof(info.success_user), "%s", azResult[ncolumn]);

					for (i = 0; i < strlen(info.success_user); i++) {
						if (info.success_user[i] == ' ') {
							info.success_user[i] = ',';
						}
					}
					sqlite3_free_table(azResult);
					snprintf(buf, sizeof(buf), "SELECT crack_count FROM crack_success_tbl WHERE crack_ip='%s' and login_type='%s';", conn->login_ip, conn->login_type);
					ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
					info.count = atoi(azResult[ncolumn]) + crack_try_num;

					snprintf(info.success_ip, sizeof(info.success_ip), "%s", conn->login_ip);
					send_crack_success_msg(&info, success_time, conn->login_type);

					sqlite3_free_table(azResult);
					snprintf(buf, sizeof(buf), "UPDATE login_fail_tbl SET queue_count=queue_count+'%d' WHERE crack_ip='%s' and type='%s';", atoi(azResult[ncolumn]), conn->login_ip, conn->login_type);
					sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
				}
			}

			sqlite3_reset(crack_tbl_stmt);
			sqlite3_bind_text(crack_tbl_stmt, 1, conn->login_ip, -1, SQLITE_STATIC);
			sqlite3_bind_text(crack_tbl_stmt, 2, conn->login_type, -1, SQLITE_STATIC);
			sqlite3_bind_int(crack_tbl_stmt, 3, conn->tv.tv_sec);
			sqlite3_bind_int(crack_tbl_stmt, 4, conn->tv.tv_sec + policy_time);
			sqlite3_bind_int(crack_tbl_stmt, 5, conn->tv.tv_sec);

			if ((rc = sqlite3_step(crack_tbl_stmt)) != SQLITE_DONE) {
				MON_ERROR("sql insert new crack_tbl fail: %s(%d)\n", sqlite3_errstr(rc), rc);
			}
		}
	}
	sqlite3_free_table(azResult);
}

static void post_fail_connection(struct failinfo *msg)
{
	int flag = 0, rc = 0;  // 标志
	char buf[1024] = {0};
	struct login_info login_info = {0};
	int nrow = 0, ncolumn = 0;
	char **azResult = NULL, **azResult_time = NULL, **azResult_name = NULL;
	struct timeval tvstamp = {0};
	int ret = 0;
	int policy_time = protect_policy_global.account.login.crack.interval * 60;

	if (!msg) {
		return;
	}

	flag = check_remote_login(msg->ip, 0, 0);
	if (flag & FLAG_FILTER) {
		return;
	}

	gettimeofday(&tvstamp, NULL);
	login_info.tv.tv_sec = tvstamp.tv_sec;

	snprintf(login_info.login_type, sizeof(login_info.login_type), "%s", msg->login_type);
	snprintf(login_info.login_ip, sizeof(login_info.login_ip), "%s", msg->ip);
	snprintf(login_info.user, sizeof(login_info.user), "%s", msg->user);
	snprintf(login_info.operating, sizeof(login_info.operating), "Login");
	login_info.failed_count = msg->count;
	login_info.result = failstr;

	// TODO 查询login_fail_tbl表中是否有ip user type，没有记录报告日志，存入数据库
	snprintf(buf, sizeof(buf), "SELECT * FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", login_info.login_ip, login_info.login_type);
	rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);

	if (rc != SQLITE_OK) {
		sqlite3_free_table(azResult);
		return;
	}
	sqlite3_free_table(azResult);

	login_info.event_id = LOGIN_REMOTE_FAILED;

	if (!nrow) {
		send_login_msg(&login_info);  // 上报登录失败日志
		sqlite3_reset(fail_tbl_stmt);
		sqlite3_bind_text(fail_tbl_stmt, 1, login_info.user, -1, SQLITE_STATIC);
		sqlite3_bind_text(fail_tbl_stmt, 2, login_info.login_ip, -1, SQLITE_STATIC);
		sqlite3_bind_text(fail_tbl_stmt, 3, login_info.login_type, -1, SQLITE_STATIC);
		sqlite3_bind_int(fail_tbl_stmt, 4, login_info.tv.tv_sec);
		sqlite3_bind_int(fail_tbl_stmt, 5, login_info.tv.tv_sec + policy_time);
		sqlite3_bind_int(fail_tbl_stmt, 6, login_info.tv.tv_sec);
		// sqlite3_bind_int(fail_tbl_stmt, 5, 0);
		sqlite3_bind_int(fail_tbl_stmt, 7, login_info.failed_count);

		if ((rc = sqlite3_step(fail_tbl_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql insert new crack user fail: %s(%d)\n", sqlite3_errstr(rc), rc);
		}

		//sqlite_limit("/opt/snipercli/.mondb/crack_user.db", CRACKUSER_DB, crack_user_db, delete_from_db_stmt);

	} else {
		// TODO 表中有记录,检查是否报告登录失败,不是爆破态都报告
		snprintf(buf, sizeof(buf), "SELECT last_time FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", login_info.login_ip, login_info.login_type);
		rc = sqlite3_get_table(crack_user_db, buf, &azResult_time, &nrow, &ncolumn, 0);

		if (rc == SQLITE_OK) {
			sqlite3_free_table(azResult_time);
			snprintf(buf, sizeof(buf), "SELECT id FROM crack_tbl WHERE ip='%s' and type='%s';", login_info.login_ip, login_info.login_type);
			rc = sqlite3_get_table(crack_user_db, buf, &azResult_time, &nrow, &ncolumn, 0);
			if (!nrow) {  // 不是爆破态
				send_login_msg(&login_info);
			}

			// 更新最近一次登录时间和失败次数
			sqlite3_free_table(azResult_time);
			snprintf(buf, sizeof(buf), "UPDATE login_fail_tbl SET last_time='%ld',queue_count=queue_count+'%d' WHERE crack_ip='%s' and type='%s';", login_info.tv.tv_sec, login_info.failed_count, login_info.login_ip, login_info.login_type);
			rc = sqlite3_get_table(crack_user_db, buf, &azResult_time, &nrow, &ncolumn, 0);

			snprintf(buf, sizeof(buf), "SELECT name FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", login_info.login_ip, login_info.login_type);  // 判断表中name字段是否已经存在相同用户名
			rc = sqlite3_get_table(crack_user_db, buf, &azResult_name, &nrow, &ncolumn, 0);

			if (azResult_name[1] == NULL) {
				sqlite3_free_table(azResult_time);
				return;
			}

			ret = sscanf_userlist_string(azResult_name[1], login_info.user, strlen(azResult_name[1]));
			if (!ret) {
				// 将失败登登录用户名拼接起来
				sqlite3_free_table(azResult_name);
				snprintf(buf, sizeof(buf), "update login_fail_tbl set name=name || ' %s' where crack_ip = '%s' and type='%s';", login_info.user, login_info.login_ip, login_info.login_type);  // 在表中上个用户后面拼接当前失败用户
				rc = sqlite3_get_table(crack_user_db, buf, &azResult_name, &nrow, &ncolumn, 0);
			}
		}

		sqlite3_free_table(azResult_time);
		sqlite3_free_table(azResult_name);
	}

	if (!remote_login_crack_check) {
		return;
	}

	post_crack_events(&login_info);
	// authok_callback(msg);
}

static void post_local_fail(struct failinfo *msg)
{
	int flag = 0;
	struct login_info login_info = {0};
	struct timeval tvstamp = {0};

	if (!msg) {
		return;
	}
	flag = check_local_login(msg->user);

	snprintf(login_info.login_type, sizeof(login_info.login_type), "SYSTEM");
	snprintf(login_info.user, sizeof(login_info.user), "%s", msg->user);
	snprintf(login_info.operating, sizeof(login_info.operating), "Login");
	login_info.result = failstr;

	gettimeofday(&tvstamp, NULL);
	login_info.pid = msg->pid;
	login_info.tv.tv_sec = tvstamp.tv_sec;
	get_session_uuid(login_info.tty, login_info.session_uuid);

	if (flag & FLAG_VIOLATION) {
		login_info.event_id = LOGIN_ILLEGAL_USER;
		login_info.behavior_id = BEHAVIOR_VIOLATION;
		login_info.loglevel = LOG_HIGH_RISK;
	} else {
		login_info.event_id = LOGIN_LOCAL_USER;
		login_info.behavior_id = BEHAVIOR_NORMAL;
		login_info.loglevel = LOG_KEY;
	}

	send_login_msg(&login_info);
}

void tty2ip(char *ptsnum, char *ip)
{
	struct login_info *pos = NULL;
	int ip_len = 64;

	pthread_mutex_lock(&sshconn_lock);
	list_for_each_entry(pos, &all_conn, list)
	{
		if (strcmp(ptsnum, pos->tty + 4) == 0) {
			snprintf(ip, ip_len, "%s", pos->login_ip);
			ip[S_IPLEN - 1] = 0;
			break;
		}
	}
	pthread_mutex_unlock(&sshconn_lock);
}

/* 根据u->ut_host判断是否终端登录 */
static int ut_host_is_terminal(char *ut_host)
{
	if (!ut_host) {
		return 1;
	}
	/* ut_host是空 */
	if (ut_host[0] == 0) {
		return 1;
	}
	/* ut_host是:0或:0.0这样的形式 */
	if (ut_host[0] == ':' && isdigit(ut_host[1])) {
		return 1;
	}
	return 0;
}

/*
 * 初始化一次登录。如果是远程登录，类型统一设为SSH
 * 本函数不试图通过对登录进程的检测，以获得准确的远程登录类型
 * 后面遍历完所有登录后，将对活跃登录一起做一遍进程相关检测
 */
static struct login_info *new_login(struct utmpx *u)
{
	int flag = 0;
	unsigned int unique = 0;
	struct login_info *new = NULL;
	char rip[S_IPLEN] = {0};
	struct in_addr inaddr = {0};
	time_t t = time(NULL);
	/*
	 * telnet的登录记录里u->ut_addr_v6[0]是0，
	 * 故不可根据u->ut_addr_v6[0]判断是否网络登录，还是本地登录
	 * 在centos7.2上观察到此现象。其实telnet是会记录ip的，为0可能是没取到ip
	 * 还发现有记录是promote.cache-dns.local，或192.168.18.14（错误的ip）
	 * 这些现象可能不仅会在centos7.2上会发生
	 */

	/* 图形界面登录后，在图形界面里起字符终端，不认为是新登录 */
	if (u->ut_addr_v6[0] == 0 &&
	    u->ut_line[0] == 'p' &&
	    ut_host_is_terminal(u->ut_host)) {
		return NULL;
	}

	/*
	 * tty终端总认为是本地登录。centos6.5上last见过下面的记录
	 * root     tty1         192.168.207.140  Sat Dec 22 19:17   still logged in
	 * :加数字形式的终端也认为是本地登录。suse上last见过下面记录
	 * zzh      :1           :1               Tue Nov 30 10:23 - 10:23  (00:00)
	 */
	if (u->ut_line[0] != 't' && u->ut_line[0] != ':') {
		if (u->ut_addr_v6[0] != 0) {  // TODO 目前只处理了IPV4
			inaddr.s_addr = u->ut_addr_v6[0];
			inet_ntop(AF_INET, &inaddr, rip, S_IPLEN);
		} else if (!ut_host_is_terminal(u->ut_host)) {
			snprintf(rip, sizeof(rip), "%s", u->ut_host);
			/* promote.cache-dns.local可能是路由器未设置缺省域名，而导致的异常 */
			if (strcmp(u->ut_host, "promote.cache-dns.local") != 0) {
				get_ip_from_hostname(rip, u->ut_host);
			}
		}
	}

	if (rip[0]) {
		flag = check_remote_login(rip, 0, u->ut_tv.tv_sec);
		/* 过滤名单 */
		if (flag == FLAG_FILTER) {
			return NULL;
		}
	} else {
		flag = check_local_login(u->ut_user);
	}

	new = (struct login_info *)sniper_malloc(sizeof(struct login_info), LOGIN_GET);
	if (!new) {
		MON_ERROR("new_login NOMEM!\n");
		return NULL;
	}

	unique = u->ut_tv.tv_sec * 1000 + u->ut_tv.tv_usec / 1000;
	new->unique = unique;
	new->tv.tv_sec = u->ut_tv.tv_sec;
	new->tv.tv_usec = u->ut_tv.tv_usec;

	memset(new->tty, 0, sizeof(new->tty));
	memcpy(new->tty, u->ut_line, sizeof(new->tty) - 1);

	snprintf(new->user, sizeof(new->user), "%s", u->ut_user);

	new->pid = u->ut_pid;

	if (rip[0] == 0) {
		/* 有user root, tty tty1, host 192.168.207.140, ipaddr 0
		 *   user root, tty tty1, host 192.168.207.133, ipaddr 0
		 * 难道是telnet
		 */
		// printf("local login? pid %d, user %s, tty %s, host %s, ipaddr %x\n", u->ut_pid, u->ut_user, u->ut_line, u->ut_host, u->ut_addr_v6[0]);
		snprintf(new->login_type, sizeof(new->login_type), "SYSTEM");
		new->event_id = LOGIN_LOCAL_USER;
	} else {
		snprintf(new->login_type, sizeof(new->login_type), "SSH");
		new->event_id = LOGIN_REMOTE;
		snprintf(new->login_ip, sizeof(new->login_ip), "%s", rip);
	}

	snprintf(new->operating, sizeof(new->operating), "Login");
	new->result = succstr;
	new->behavior_id = BEHAVIOR_NORMAL;
	new->loglevel = LOG_KEY;
	new->flag = flag;
	new->check_strategy_time = t;

	get_session_uuid(new->tty, new->session_uuid);

	pthread_mutex_lock(&sshconn_lock);
	list_add(&new->list, &all_conn);
	pthread_mutex_unlock(&sshconn_lock);

	return new;
}

static void check_remote_login_type(struct login_info *conn)
{
	int ret = 0;
	sockinfo_t sinfo = {0};
	char cmd[S_CMDLEN] = {0};

	if (!conn || conn->tty[0] == 't') {
		return;
	}

	ret = get_netlogin_info(conn, cmd, &sinfo);
	get_session_uuid(conn->tty, conn->session_uuid);
	if (ret < 0) {
		return;
	}

	/* 之前是按本地登录检查的，实际是远程登录，重新检查一遍 */
	/* 这种情况很少发生，遇到过telnet登录从utmp看像本地登录的，
	   这是路由器没有设置默认域名导致的，和是promote.cache-dns.local一类问题 */
	if (strcmp(conn->login_type, "SYSTEM") == 0) {
		INFO("login %s -> %s(%d) in log is local, but remote really\n",
		     sinfo.src_ip, cmd, conn->pid);
		/* 检查时间清零，否则check_login里会视为重复检查而忽略 */
		conn->check_strategy_time = 0;
		/* 不改login_type，check_login就还按本地登录检查了 */
		snprintf(conn->login_type, sizeof(conn->login_type), "SSH");
		check_login(conn);
	}

	/* sinfo里src_ip用来保存本机ip，dst_ip保存对方ip */
	snprintf(conn->login_ip, sizeof(conn->login_ip), "%s", sinfo.dst_ip);
	conn->event_id = LOGIN_REMOTE;

	if (strstr(cmd, "telnet") || sinfo.src_port == 23) {
		snprintf(conn->login_type, sizeof(conn->login_type), "TELNET");
	} else {
		snprintf(conn->login_type, sizeof(conn->login_type), "SSH");
	}
}

/*
 * 返回0，读取缓存的wtmp inode失败
 * 返回inode，
 * 1）读取上次解析到的位置（last_wtmp_count）和之前的登录信息都成功
 * 2）读取到部分信息，读到多少算多少，漏掉的不管了
 */
static unsigned long get_cached_login(void)
{
	struct login_info *new = NULL;
	char path[S_SHORTPATHLEN] = {0};
	struct login_cache_info info = {0};
	int fd = 0, ret = 0, size = sizeof(info);
	unsigned long inode = 0;

	snprintf(path, sizeof(path), "%s/%s/%s", WORKDIR, DBDIR, LOGINED);
	fd = sniper_open(path, O_RDONLY, LOGIN_GET);
	if (fd < 0) {
		if (errno != ENOENT) {
			MON_ERROR("open %s fail: %s\n", path, strerror(errno));
		}
		return 0;
	}

	if (read(fd, &inode, sizeof(unsigned long)) < 0) {
		MON_ERROR("read %s fail: %s\n", path, strerror(errno));
		sniper_close(fd, LOGIN_GET);
		return 0;
	}

	if (read(fd, &last_wtmp_count, sizeof(int)) < 0) {
		MON_ERROR("read %s fail: %s\n", path, strerror(errno));
		sniper_close(fd, LOGIN_GET);
		return inode;
	}

	while ((ret = read(fd, &info, size)) == size) {
		if (info.magic != CACHE_MAGIC) {
			INFO("old cached login information format, skip\n");
			break;
		}
		if (info.pid == 0) {
			INFO("cached login information may corrupted, skip\n");
			break;
		}

		new = (struct login_info *)sniper_malloc(sizeof(struct login_info), LOGIN_GET);
		if (!new) {
			MON_ERROR("malloc new connection fail!\n");
			sniper_close(fd, LOGIN_GET);
			return inode;
		}

		new->unique = info.unique;
		new->tv = info.tv;

		new->pid = info.pid;
		new->event_id = info.event_id;
		new->behavior_id = info.behavior_id;
		new->loglevel = info.loglevel;
		new->result = succstr;

		snprintf(new->operating, sizeof(new->operating), "Login");
		snprintf(new->tty, sizeof(new->tty), "%s", info.tty);
		snprintf(new->user, sizeof(new->user), "%s", info.user);
		snprintf(new->login_type, sizeof(new->login_type), "%s", info.login_type);
		snprintf(new->login_ip, sizeof(new->login_ip), "%s", info.login_ip);
		snprintf(new->session_uuid, sizeof(new->session_uuid), "%s", info.session_uuid);

		check_login(new);

		new->flag = FLAG_REPORTED;

		pthread_mutex_lock(&sshconn_lock);
		list_add(&new->list, &all_conn);
		pthread_mutex_unlock(&sshconn_lock);
	}
	if (ret < 0) {
		MON_ERROR("read %s fail: %s\n", path, strerror(errno));
	}

	sniper_close(fd, LOGIN_GET);
	return inode;
}

static void cache_login_info(void)
{
	int fd = 0;
	char path[64] = {0};
	struct login_cache_info info = {0};
	struct login_info *pos = NULL;

	/* 本地缓存当前登录信息 */
	snprintf(path, sizeof(path), "%s/%s/%s", WORKDIR, DBDIR, LOGINED);
	fd = sniper_open_mode(path, O_CREAT | O_WRONLY | O_TRUNC, 0600, LOGIN_GET);
	if (fd < 0) {
		MON_ERROR("open %s fail: %s\n", path, strerror(errno));
		return;
	}
	if (write(fd, &wtmp_inode, sizeof(unsigned long)) < 0) {
		MON_ERROR("write %s fail: %s\n", path, strerror(errno));
		sniper_close(fd, LOGIN_GET);
		return;
	}
	if (write(fd, &last_wtmp_count, sizeof(int)) < 0) {
		MON_ERROR("write %s fail: %s\n", path, strerror(errno));
		sniper_close(fd, LOGIN_GET);
		return;
	}
	list_for_each_entry(pos, &all_conn, list)
	{
		info.unique = pos->unique;
		info.tv = pos->tv;
		info.magic = CACHE_MAGIC;
		info.pid = pos->pid;
		info.event_id = pos->event_id;
		info.behavior_id = pos->behavior_id;
		info.loglevel = pos->loglevel;

		snprintf(info.tty, sizeof(info.tty), "%s", pos->tty);
		snprintf(info.user, sizeof(info.user), "%s", pos->user);
		snprintf(info.login_type, sizeof(info.login_type), "%s", pos->login_type);
		snprintf(info.login_ip, sizeof(info.login_ip), "%s", pos->login_ip);
		snprintf(info.session_uuid, sizeof(info.session_uuid), "%s", pos->session_uuid);
		if (write(fd, &info, sizeof(info)) < 0) {
			MON_ERROR("write %s fail: %s\n", path, strerror(errno));
			sniper_close(fd, LOGIN_GET);
			return;
		}
	}
	sniper_close(fd, LOGIN_GET);
}

/* pos->rip[0]非0表示活跃的网络登录，u->ut_addr_v6[0]非0可能是个历史的网络登录 */
/* 监测本地登录和远程登录。第一次运行时还报告历史登录情况 */
static void check_ssh(void)
{
	struct utmpx u = {0};
	struct login_info *pos = NULL, *p = NULL;
	int fd = 0, ret = 0;
	unsigned int unique = 0;
	unsigned int unique_diff = 0;
	long onelogsize = sizeof(struct utmpx);
	long off = onelogsize * last_wtmp_count;

	fd = sniper_open(path_wtmp, O_RDONLY, LOGIN_GET);
	if (fd < 0) {
		/* TODO 报告wtmp文件损坏 */
		MON_ERROR("open %s fail: %s\n", path_wtmp, strerror(errno));
		return;
	}

	lseek(fd, off, SEEK_SET);
	while ((ret = read(fd, &u, onelogsize)) == onelogsize) {
		// printf("type %d %s, pid %d, tty %s, user %s, host %s, time %d\n",
		// u.ut_type, utype[u.ut_type], u.ut_pid, u.ut_line,
		// u.ut_user, u.ut_host, u.ut_tv.tv_sec);
		last_wtmp_count++;

		if (u.ut_type == BOOT_TIME) {
			/* 报告所有登录退出 */
			list_for_each_entry_safe(pos, p, &all_conn, list)
			{
				/* 如果本终端登录尚未报告，先补报告之 */
				if (!(pos->flag & FLAG_REPORTED)) {
					send_login_msg(pos);
				}

				pos->endtv.tv_sec = u.ut_tv.tv_sec;
				pos->endtv.tv_usec = u.ut_tv.tv_usec;
				post_closed_login(pos);
			}
			continue;
		}

		/* 忽略不知道用户的条目，这是图形登录界面在等待选择登录的用户名 */
		if (strcmp(u.ut_user, "(unknown)") == 0) {
			continue;
		}

		if (u.ut_type == USER_PROCESS) {
			int found = 0;

			/* 无效的记录 */
			if (u.ut_user[0] == 0 || u.ut_pid == 0) {
				INFO(
				    "ignore invalid login record: type %d %s, "
				    "pid %d, tty %s, user %s, host %s, time %d\n",
				    u.ut_type, utype[u.ut_type], u.ut_pid, u.ut_line,
				    u.ut_user, u.ut_host, u.ut_tv.tv_sec);
				continue;
			}

			list_for_each_entry_safe(pos, p, &all_conn, list)
			{
				if (strcmp(pos->tty, u.ut_line) != 0) {
					continue;
				}

				unique = u.ut_tv.tv_sec * 1000 + u.ut_tv.tv_usec / 1000;
				if (pos->unique >= unique) {
					unique_diff = pos->unique - unique;
				} else {
					unique_diff = unique - pos->unique;
				}
				/* 登录时刻在3秒内的同终端登录，认为是同一次登录 */
				/* 缘起是为了处理rh53图形登录产生3条日志的问题 */
				if (unique_diff <= 3000) {
					found = 1;
					break;
				}

				/* 这是一个新的登录，先报告老的本终端登录已经退出 */

				/* 如果本终端登录尚未报告，先补报告之 */
				if (!(pos->flag & FLAG_REPORTED)) {
					send_login_msg(pos);
				}

				pos->endtv.tv_sec = u.ut_tv.tv_sec;
				pos->endtv.tv_usec = u.ut_tv.tv_usec;
				snprintf(pos->operating, sizeof(pos->operating), "Logout");
				// send_login_msg(pos);

				break;
			}

			if (found) {
				continue;
			}

			/* 登记新的登录 */
			new_login(&u);

			continue;
		}

		if (u.ut_type == DEAD_PROCESS) {
			/* TODO u.ut_pid为0的是否要视为无效的记录，待观察 */
			/* 有看到u.ut_pid为0的，但确实是结束记录的情况 */

			list_for_each_entry_safe(pos, p, &all_conn, list)
			{
				/* 报告登出 */
				if (strcmp(pos->tty, u.ut_line) == 0) {
					/* 如果本终端登录尚未报告，先补报告之 */
					if (!(pos->flag & FLAG_REPORTED)) {
						send_login_msg(pos);
					}

					pos->endtv.tv_sec = u.ut_tv.tv_sec;
					pos->endtv.tv_usec = u.ut_tv.tv_usec;
					snprintf(pos->operating, sizeof(pos->operating), "Logout");
					send_login_msg(pos);
					free_login(pos);
					break;
				}
			}
		}
	}
	/* TODO 如果ret不等于0，报告wtmp文件损坏 */

	sniper_close(fd, LOGIN_GET);
}

int host_halting = 0;
/* 检测主机当前是否在关机或重起。返回1，是；0，否 */
int is_halting(void)
{
	char oldlevel = 0, nowlevel = 0;
	struct utmpx u = {0};
	int fd = 0, size = sizeof(u);

	/* 之前已经检测到在halting态，不需要再重复检测
	   重起过程中utmp RUN_LVL的值可能会被清0 */
	if (host_halting) {
		return 1;
	}

	fd = open("/var/run/utmp", O_RDONLY);
	if (fd < 0) {
		MON_ERROR("check halting fail, open /var/run/utmp error: %s\n", strerror(errno));
		return 0;
	}

	/* getutent/getutxent取到的总是老的值，如53 0 0 0，原因不明。用read可以取到54 53 0 0 */
	while (read(fd, (char *)&u, size) > 0) {
		if (u.ut_type == RUN_LVL) {
			close(fd);

			/* ut_pid的低8位是当前的运行级别，8~15位是上一次的运行级别 */
			nowlevel = u.ut_pid & 0xff;
			oldlevel = (u.ut_pid & 0xff00) >> 8;
			if (nowlevel == '0') {
				INFO("host in shutdown\n");
				host_halting = 1;
				return 1;
			}
			if (nowlevel == '6') {
				INFO("host in reboot\n");
				host_halting = 1;
				return 1;
			}
			/* 和runlevel命令的结果一致，如N 5或5 3，后者表示从级别5切换到了级别3，如init 3 */
			INFO("runlevel: %c %c\n", oldlevel == 0 ? 'N' : oldlevel, nowlevel);
			return 0;
		}
	}
	close(fd);

	return 0;
}

/* 用utmp检查当前登录状态，阻断非法远程登录 */
static void check_ssh_utmp(int only_count_login_num)
{
	int i = 0, login_reported = 0;
	struct utmpx *u = NULL;
	struct login_info *pos = NULL, *p = NULL;
	int login_num = 0;

	utmpname("/var/run/utmp");
	setutxent();
	while ((u = getutxent()) != NULL) {
		int found = 0;

		// printf("check_ssh_utmp: login type %d, user: %s, pid: %d, tty: %s, host: %s\n",
		// u->ut_type, u->ut_user, u->ut_pid, u->ut_line, u->ut_host);

		/* 忽略不知道用户的条目，这是图形登录界面在等待选择登录的用户名 */
		if (strcmp(u->ut_user, "(unknown)") == 0) {
			continue;
		}

		/*
		 * ubuntu16.04出现字符终端不能登录的情况，原因是，
		 * check_ssh查看的/var/log/wtmp里新记录的类型是USER_PROCESS，
		 * 而check_ssh_utmp查看的/var/run/utmp里是LOGIN_PROCESS
		 * 下面两处对LOGIN_PROCESS的判断，就是处理这种情况
		 *
		 * 2018/12/22 不能登录的原因，应该是认为登录已登出，但检测到实际并未登出，
		 * 然后削足适履地为了制造登出，而错误地做了kill
		 */
		if (u->ut_type != USER_PROCESS) {
			continue;
		}
		/* 无效的记录 */
		if (u->ut_pid == 0 || u->ut_user[0] == 0) {
			INFO(
			    "ignore invalid login record: type %d %s, "
			    "pid %d, tty %s, user %s, host %s, time %d\n",
			    u->ut_type, utype[u->ut_type], u->ut_pid, u->ut_line,
			    u->ut_user, u->ut_host, u->ut_tv.tv_sec);
			continue;
		}

		list_for_each_entry_safe(pos, p, &all_conn, list)
		{
			if (strcmp(u->ut_line, pos->tty) == 0) {
				found = 1;
				break;
			}
		}

		if (found) {
			continue;
		}

		/* 登录进程已不存在，忽略 */
		/*
		 * debian8出现telnet登出时额外报了1条ssh登录和1条ssh登出
		 * 原因是wtmp和utmp登记的内容不同：
		 * root     109165    887  0 17:44 ?        00:00:00 in.telnetd: 192.167.5.111
		 * root     109166 109165  0 17:44 pts/0    00:00:00 login -h 192.167.5.111 -p
		 * jessie   109168 109166  0 17:44 pts/0    00:00:00 -bash
		 * wtmp里登记的是109868, utmp里登记的是109166
		 *
		 * 为何登录时不会多报，因为比较的是ut_line
		 * 登出时ut_line已从缓存的all_conn里删除，结果utmp里的记录就被当作新连接处理了
		 */
		// TODO debian8上观察到有telnet登录记录里无ip的情况，既未报远程登录也未报本地登录
		if (mykill(u->ut_pid, 0) < 0) {
			continue;
		}
		new_login(u);
	}
	endutxent();

	login_num = 0;
	/* check current logins */
	list_for_each_entry_safe(pos, p, &all_conn, list)
	{
		login_reported = pos->flag & FLAG_REPORTED;
		/* 登录进程不存在，报告已登出 */
		if (mykill(pos->pid, 0) < 0) {
			if (!login_reported) {
				send_login_msg(pos);
			}
			post_closed_login(pos);
			continue;
		}
		login_num++;
		/* 仅统计当前登录用户数 */
		if (only_count_login_num) {
			continue;
		}
		/* 该登录动作没报告过，确认真正的远程登录类型 */
		if (!login_reported) {
			check_remote_login_type(pos);
		}

		/* 处理本地登录 */
		if (strcmp(pos->login_type, "SYSTEM") == 0) {
			pos->flag |= check_local_login(pos->user);
			/* 处理违规操作 */
			if (pos->flag & FLAG_VIOLATION) {
				deal_illegal_login(pos, login_reported,
						   LOGIN_ILLEGAL_USER, 0, login_num);
				/* 阻断成功，当前登录数减1 */
				continue;
			}
			/* 该登录动作没报告过，补报 */
			if (!login_reported) {
				send_login_msg(pos);
			}
			continue;
		}

		/* 处理远程登录 */
		/* 此ip的登录失败次数清零 */
		for (i = 0; i < MAX_FAIL_CONNECT; i++) {
			if (strcmp(pos->login_ip, fail_ssh_info[i].ip) == 0) {
				memset(fail_ssh_info[i].ip, 0, S_IPLEN);
				fail_ssh_info[i].time = 0;
				fail_ssh_info[i].count = 1;
				fail_ssh_info[i].reported = 0;
				break;
			}
		}

		/* 处理违规操作 */
		pos->flag |= check_remote_login(pos->login_ip, login_reported, pos->tv.tv_sec);
		if (pos->flag & (FLAG_VIOLATION) || (black == 1)) {
			deal_illegal_login(pos, login_reported,
					   LOGIN_ILLEGAL_REMOTE, 0, login_num);
			/* 阻断成功，当前登录数减1 */
			continue;
		}

		/* 该登录动作没报告过，补报 */
		if (!login_reported) {
			send_login_msg(pos);
		}
	}

	/* 统计的当前登录数 */
	current_login_num = login_num ? login_num : 0;
}

/*
 * sshd[21355]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.58.150  user=zx
 * sshd[21355]: PAM 2 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.58.150  user=zx
 *
 * 如果是非本机用户尝试登录，则有
 * sshd[22469]: Invalid user zx2 from 192.168.58.150 port 49736
 * sshd[22469]: input_userauth_request: invalid user zx2 [preauth]
 * sshd[22469]: pam_unix(sshd:auth): check pass; user unknown
 * sshd[22469]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.58.150
 * sshd[22469]: Failed password for invalid user zx2 from 192.168.58.150 port 49736 ssh2
 * 上面的I/invalid user行，sshd_config里要开了AUTHPRIV才有，有的机器可能没开
 */
static int get_ssh_fail_msg(char *buff, struct failinfo *msg)
{
	int ret = 0;
	char *ptr = NULL;

	if (!buff || !msg) {
		return 0;
	}

	delete_tailspace(buff);

	ptr = strstr(buff, "rhost=");
	if (!ptr) {
		DBG2(DBGFLAG_SSH, "bad ssh fail info: %s\n", buff);
		return 0;
	}

	memset(msg->hostname, 0, sizeof(msg->hostname));
	memset(msg->user, 0, sizeof(msg->user));
	ret = sscanf(ptr, "rhost=%63s user=%63s", msg->hostname, msg->user);
	if (ret != 2) {
		if (ret == 1 && msg->hostname[0] && invalid_ssh_user[0]) {
			snprintf(msg->user, sizeof(msg->user), "%s", invalid_ssh_user);
			DBG2(DBGFLAG_SSH, "use %s as ssh user\n", invalid_ssh_user);
		} else {
			snprintf(msg->user, sizeof(msg->user), "%s", "unknow");
			DBG2(DBGFLAG_SSH, "bad ssh fail info: %s\n", buff);
		}
	}

	msg->count = 1;
	ptr = strstr(buff, "PAM");
	if (ptr) {
		sscanf(ptr, "PAM %d", &msg->count);
	}

	msg->t = time(NULL);  // 不取日志中的时间，用当前时间作为登录失败时间

	if (hostname_to_ip(msg->hostname, msg->ip) < 0) {
		snprintf(msg->ip, sizeof(msg->ip), "%s", msg->hostname);
	}

	return 1;
}

static void check_current_logins(void)
{
	struct login_info *pos = NULL, *p = NULL;

	/* check current logins */
	list_for_each_entry_safe(pos, p, &all_conn, list)
	{
		int login_reported = pos->flag & FLAG_REPORTED;

		/* 登录进程不存在，报告已登出 */
		if (mykill(pos->pid, 0) < 0) {
			if (!login_reported) {
				send_login_msg(pos);
			}
			post_closed_login(pos);
		}
	}
}

/*
 * sshd[21355]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.58.150  user=zx
 * sshd[21355]: PAM 2 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.58.150  user=zx
 *
 * 如果是非本机用户尝试登录，则有
 * sshd[22469]: Invalid user zx2 from 192.168.58.150 port 49736
 * sshd[22469]: input_userauth_request: invalid user zx2 [preauth]
 * sshd[22469]: pam_unix(sshd:auth): check pass; user unknown
 * sshd[22469]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.58.150
 * sshd[22469]: Failed password for invalid user zx2 from 192.168.58.150 port 49736 ssh2
 * 上面的I/invalid user行，sshd_config里要开了AUTHPRIV才有，有的机器可能没开
 */

// TODO TELNET爆破

static int get_local_fail_msg(char *buff, struct failinfo *msg)
{
	char *user = NULL;

	memset(msg, 0, sizeof(struct failinfo));

	/* 不是本地登录 */
	if (strstr(buff, "sshd[")) {
		return 0;
	}

	if (strstr(buff, "authentication failure") == NULL) {
		return 0;
	}

	user = strstr(buff, " user=");
	if (user == NULL) {
		return 0;
	}

	user += 6;
	delete_tailspace(user);

	if (*user == 0) {
		return 0;
	}

	snprintf(msg->user, sizeof(msg->user), "%s", user);
	msg->user[S_NAMELEN - 1] = 0;

	msg->t = time(NULL);

	return 1;
}

/*
 * pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/pts/5 ruser= rhost=192.168.58.153  user=zx
 */
// TODO TELNET爆破
#if 1
static int get_telnet_fail_msg(char *buff, struct failinfo *msg)
{
	return get_ssh_fail_msg(buff, msg);
}
#endif

#if 0
/* centos:Accepted password for root from 192.168.153.130 port 60186 ssh2
 * ubuntu:Accepted password for zzh from 192.168.153.128 port 47202 ssh2
 * suse:  Accepted keyboard-interactive/pam for root from 192.168.153.128 port 38500 ssh2
 */
/*该ip已经产生了爆破失败事件即crack_tbl中有此ip，type数据
 *如果没有，记录该次登录成功
 */
static void crack_success(char *buff, struct failinfo *msg, char *type)
{
    time_t now = time(NULL);
    int ret = 0;
    char buf[1024] = {0};
    char **azResult = NULL;
    int nrow = 0, ncolumn = 0;
    int policy_time = protect_policy_global.account.login.crack.interval * 60;

    snprintf(buf, sizeof(buf), "SELECT id FROM crack_tbl WHERE ip='%s' and type='%s';", msg->success_ip, type);
    ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
    if (ret == SQLITE_OK && nrow != 0) {
        snprintf(buf, sizeof(buf), "SELECT queue_count FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", msg->success_ip, type);
        ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
        if (ret == SQLITE_OK && nrow != 0) {
            msg->count = atoi(azResult[1]);
        }
        if (msg->count == 0) {
            msg->count = 1;
        }
        snprintf(buf, sizeof(buf), "SELECT last_time FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", msg->success_ip, type);
        ret = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
        if ((now - atoi(azResult[ncolumn])) < policy_time) { // TODO  有就算爆破成功
            send_crack_success_msg(msg, now, type);
        }

        sqlite3_free_table(azResult);
        return;
    }

    // snprintf(msg->login_type, sizeof(msg->login_type), type);

    save_attackip_info(msg->success_user, msg->success_ip, now, type);
    DBG2(DBGFLAG_SSH, "ssh_authok: %s %s %lu. select_attackip_info ret %d\n", msg->success_ip, msg->success_user, now, ret);

    /* 缓存身份认证成功日志，下次检测到爆破事件时回看该次成功是否为爆破成功 */
    set_authok_user(msg);
}
#endif

// TODO TELNET爆破
#if 1
static void telnet_crack_success(char *buff, struct failinfo *msg)
{
	time_t now = time(NULL);
	char *ptr = NULL;
	int ret = 0;
	char *ip = NULL, ipstr[S_IPLEN] = {0};
	char pts[64] = {0};

	ptr = strstr(buff, "LOGIN");
	if (!ptr) {
		return;
	}

	snprintf(msg->login_type, sizeof(msg->login_type), "TELNET");
	sscanf(ptr, "%*s %*s %63s %*s %63s %*s %63s", pts, msg->user, ipstr);
	ip = handle_mapped_ipv4(ipstr);
	snprintf(msg->ip, sizeof(msg->ip), "%s", ip);

	get_session_uuid(pts, msg->session_uuid);

	ret = select_attackip_info(ip, now, "TELNET");

	if (ret == 1) {
		send_crack_success_msg(msg, now, "TELNET");
		return;
	}

	/* 缓存身份认证成功日志，下次检测到爆破事件时回看该次成功是否为爆破成功 */
	set_authok_user(msg);
}
#endif

int regular_crack_match(char *bematch, char *pattern, struct failinfo *msg, char *flag)
{
	pcre *re;
	const char *error;
	int erroffset;
	int ovector[OVECCOUNT];
	int rc_exec, rc_string;
	const char *username = NULL;
	const char *hostip = NULL;
	const char *count = NULL;
	char *ptr = NULL;

	re = pcre_compile(pattern, PCRE_CASELESS | PCRE_MULTILINE, &error, &erroffset, NULL);
	if (re == NULL) {
		MON_ERROR("webshell compile rull failed at offset %d: %s\n", erroffset, error);
		return -1;
	}

	rc_exec = pcre_exec(re, NULL, bematch, strlen(bematch), 0, 0, ovector, OVECCOUNT);
	if (rc_exec < 0) {
		free(re);
		return 0;
	}

	rc_string = pcre_get_named_substring(re, bematch, ovector, rc_exec, "USER", &username);

	rc_string = pcre_get_named_substring(re, bematch, ovector, rc_exec, "HOST", &hostip);
	if (rc_string < 0) {
		snprintf(invalid_ssh_user, sizeof(invalid_ssh_user), "%s", username);  // 保存非本机用户名
		free(re);
		return 0;
	}

	ptr = strstr(pattern, "PAM");
	if (ptr) {
		rc_string = pcre_get_named_substring(re, bematch, ovector, rc_exec, "COUNT", &count);
	}

	if (count) {
		msg->count = atoi(count);
	}

	if (username) {
		if (strcmp(flag, "fail") == 0) {
			snprintf(msg->user, sizeof(msg->user), "%s", username);
			msg->user[S_NAMELEN - 1] = 0;
		} else {
			snprintf(msg->success_user, sizeof(msg->success_user), "%s", username);
			msg->success_user[S_NAMELEN - 1] = 0;
		}
	}

	if (hostip) {
		if (strcasecmp(hostip, "localhost") == 0) {
			free(re);
			return 0;
		}

		if (strcmp(flag, "fail") == 0) {
			snprintf(msg->ip, sizeof(msg->ip), "%s", hostip);
			msg->ip[S_IPLEN - 1] = 0;
		} else {
			snprintf(msg->success_ip, sizeof(msg->success_ip), "%s", hostip);
			msg->success_ip[S_IPLEN - 1] = 0;
		}
	}
	// printf("%s, %s, %s, %s\n", msg->user, msg->success_user, msg->ip, msg->success_ip);

	free(re);
	return 1;
}

int sscanf_all_string(char *buff, struct failinfo *msg)
{
	char key[S_NAMELEN] = {0};
	int ret = 1;

	if (sscanf(buff, "%63s", key) == 1) {
		ret = is_valid_ip(key);
		if (ret) {
			snprintf(msg->ip, sizeof(msg->ip), "%s", key);
			msg->ip[S_IPLEN - 1] = 0;
			return 1;
		}
		return sscanf_all_string((strstr(buff, key) + 1), msg);
	}
	return 0;
}

#if 0
static void check_app_log(const char *type_name, const char *type_path, int off)
{
    FILE *fp = NULL;
    char buff[S_LINELEN] = {0};
    char buf_fail_sql[S_LINELEN] = {0}, buf_success_sql[S_LINELEN] = {0};
    int nrow = 0, ncolumn = 0, nrow_success = 0, ncolumn_success = 0;
    char **azResult = NULL, **azResult_success = NULL;
    int i = 0, j = 0, res = 0;
    char type[8] = {0};
    char *ptr = NULL;

    fp = fopen(type_path, "r"); // TODO path
    if (!fp) {
        MON_ERROR("check_auth fail, open %s : %s",
                  type_path, strerror(errno));
        return;
    }

    fseek(fp, off, SEEK_SET);

    snprintf(type, sizeof(type), "%s", type_name);

    //从login_fail_log表中查询失败日志样式
    snprintf(buf_fail_sql, sizeof(buf_fail_sql), "SELECT faillog FROM login_fail_log WHERE type = '%s';", type);
    sqlite3_get_table(crack_user_db, buf_fail_sql, &azResult, &nrow, &ncolumn, 0);

    //从login_success_log表中查询失败日志样式
    snprintf(buf_success_sql, sizeof(buf_success_sql), "SELECT successlog FROM login_success_log WHERE type = '%s';", type);
    sqlite3_get_table(crack_user_db, buf_success_sql, &azResult_success, &nrow_success, &ncolumn_success, 0);

    while (fgets(buff, sizeof(buff), fp)) {
        struct failinfo msg = {0};
        off = ftell(fp);
        // TODO 失败日志会有记录次数的

         for (i = 1; i <= nrow; i++) {
            res = regular_crack_match(buff, azResult[i], &msg, "fail"); //返回1代表匹配到了，0代表没有匹配到
            if (res) {
                DBG2(DBGFLAG_SSH, "fail: %s, %s\n", buff, azResult[i]);
#if 0 
                ret = sscanf_all_string(buff, &msg); 
                if (ret) {
                    printf("!!!!!! %s\n", msg.ip);
                } else {
                    continue;
                }
#endif
                if (msg.ip[0] == 0) { //如果ip没取到
                    continue;
                }

                if (msg.user[0] == 0 && invalid_ssh_user[0]) {
                    snprintf(msg.user, sizeof(msg.user), "%s", invalid_ssh_user);
                }

                ptr = strstr(azResult[i], "PAM");
                if (!ptr) {
                    msg.count = 1;
                }

                snprintf(msg.login_type, sizeof(msg.login_type), "%s", type);
                msg.login_type[7] = 0;
                post_fail_connection(&msg); //报告日志
                break;
            }
        }

        for (j = 1; j <= nrow_success; j++) {
            res = regular_crack_match(buff, azResult_success[j], &msg, "success"); //返回1代表匹配到了，0代表没有匹配到
            if (res) {
                DBG2(DBGFLAG_SSH, "success: %s, %s\n", buff, azResult_success[j]);
                if (msg.success_ip[0] == 0 || msg.success_user[0] == 0) { //如果ip或user没取到
                    continue;
                }

                crack_success(buff, &msg, type);
                break;
            }
        }

        if (strstr(buff, fail_str1) || strstr(buff, fail_str2) ||
            strstr(buff, fail_str3) || strstr(buff, fail_str4)) {
            if (!local_login_check) {
                continue;
            }
            if (get_local_fail_msg(buff, &msg) > 0) {
                post_local_fail(&msg);
            }
            continue;
        }
    }

    // TODO 没取到用户名或ip，先不误报

#if 0
    /*
        这种方法在这里无法更新数据库，虽然结果执行成功，但数据库的数据未发生变化
        改用下面sqlite3_exec执行语句
    */
    sqlite3_reset(off_update_stmt);
    sqlite3_bind_int(off_update_stmt, 1, off);
    sqlite3_bind_text(off_update_stmt, 2, type_name, -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(off_update_stmt)) != SQLITE_DONE) {
        MON_ERROR("sql update unchg conn fail: %s(%d)\n", sqlite3_errstr(rc), rc);
    }
#endif
    sqlite3_free_table(azResult);
    sqlite3_free_table(azResult_success);

    int rc = 0;

    sqlite3_reset(update_off_stmt);
    sqlite3_bind_int(update_off_stmt,1,off);
    sqlite3_bind_text(update_off_stmt,2,type,-1,SQLITE_STATIC);
    if ((rc = sqlite3_step(update_off_stmt)) != SQLITE_DONE) {
        MON_ERROR("sql update off fail: %s(%d)\n", sqlite3_errstr(rc), rc);
    }

    if (fp) {
        fclose(fp);
    }
    return;
}
#endif

static int get_mysql_fail_msg(char *buff, struct failinfo *msg)
{
	char *ptr = NULL;
	char str1[S_LINELEN] = {0};
	char user[S_NAMELEN] = {0}, ip[S_IPLEN] = {0};
	int ret = 0;
	struct timeval tvstamp = {0};

	ptr = strstr(buff, "user");
	if (!ptr) {
		return 0;
	}

	sscanf(ptr, "%*s %s", str1);

	if (*str1 == '\'') {
		ret = sscanf(str1, "\'%[^\']\'", user);
	}

	gettimeofday(&tvstamp, NULL);
	msg->t = tvstamp.tv_sec;

	ptr = strchr(str1, '@') + 1;
	if (!ptr) {
		return 0;
	}
	sscanf(ptr, "\'%[^\']\'", ip);
	if (strcmp(ip, "localhost") == 0) {
		strncpy(msg->ip, "127.0.0.1", S_IPLEN);
	} else {
		strncpy(msg->ip, ip, S_IPLEN);
	}

	if (ret) {
		strncpy(msg->user, user, S_NAMELEN);
		return 1;
	}

	return 0;
}

/* centos:Accepted password for root from 192.168.153.130 port 60186 ssh2
 * ubuntu:Accepted password for zzh from 192.168.153.128 port 47202 ssh2
 * suse:  Accepted keyboard-interactive/pam for root from 192.168.153.128 port 38500 ssh2
 */
static void ssh_crack_success(char *buff, struct failinfo *msg)
{
	time_t now = time(NULL);
	char *ptr = NULL;
	int ret = 0;

	ptr = strstr(buff, "Accepted");
	if (!ptr) {
		return;
	}

	snprintf(msg->login_type, sizeof(msg->login_type), "SSH");
	sscanf(ptr, "%*s %*s %*s %63s %*s %63s", msg->user, msg->ip);

	ret = select_attackip_info(msg->ip, now, "SSH");
	DBG2(DBGFLAG_SSH, "ssh_authok: %s %s %lu. select_attackip_info ret %d\n", msg->ip, msg->user, now, ret);

	snprintf(msg->success_ip, 64, "%s", msg->ip);
	snprintf(msg->success_user, 256, "%s", msg->user);

	if (ret == 1) {
		send_crack_success_msg(msg, now, "SSH");
		return;
	}

	save_attackip_info(msg->user, msg->ip, now, msg->login_type);
	/* 缓存身份认证成功日志，下次检测到爆破事件时回看该次成功是否为爆破成功 */
	set_authok_user(msg);
}

/* check auth and fail login */
static void check_auth(void)
{
	FILE *fp = NULL;
	char buff[S_LINELEN] = {0};

#if 0
	if (!remote_login_check && !remote_login_crack_check &&
	    !local_login_check && !local_login_auth_check) {
		return;
	}
#endif

	fp = sniper_fopen(path_auth, "r", LOGIN_GET);
	if (!fp) {
		MON_ERROR("check_auth fail, open %s : %s",
			  path_auth, strerror(errno));
		return;
	}

	fseek(fp, authoff, SEEK_SET);

	while (fgets(buff, S_LINELEN, fp)) {
		struct failinfo msg = {0};
		char *ptr = NULL;

		// TODO Error in service module是用非本机用户远程登录时出现的日志
		// 取消跳过keyboard-interactive/pam，在suse上检测密码认证成功时会有Accepted keyboard-interactive/pam for root from，防止下面匹配不到Accepted
		if (strstr(buff, "Error in service module")) {
			continue;
		}

		authoff = ftell(fp);

		if (strstr(buff, "authentication failure") && strstr(buff, "tty=ssh")) {
			if (!remote_login_check) {
				continue;
			}

			if (get_ssh_fail_msg(buff, &msg) > 0) {
				DBG2(DBGFLAG_SSH, "ssh fail: %s\n", buff);
				strncpy(msg.login_type, "SSH", 8);
				post_fail_connection(&msg);
			}
			continue;
		}

		if ((strstr(buff, fail_str4) || strstr(buff, fail_str5)) && !strstr(buff, "rhost= ")) {
			if (!remote_login_check) {
				continue;
			}

			if (get_telnet_fail_msg(buff, &msg) > 0) {
				strncpy(msg.login_type, "TELNET", 8);
				post_fail_connection(&msg);
			}
			continue;
		}

		ptr = strstr(buff, "nvalid user");
		if (ptr && strstr(buff, "sshd")) {
			sscanf(ptr, "nvalid user %63s", invalid_ssh_user);
		}

		if (strstr(buff, "Accepted")) {	 // suse，centos，ubuntu上密码认证成功均为Accepted开头
			ssh_crack_success(buff, &msg);
			continue;
		}

		if (strstr(buff, "LOGIN ON")) {	 // telnet密码认证成功
			telnet_crack_success(buff, &msg);
			continue;
		}

		if (strstr(buff, fail_str1) || strstr(buff, fail_str2) ||
		    strstr(buff, fail_str3) || strstr(buff, fail_str4)) {
			if (!local_login_check) {
				continue;
			}
			if (get_local_fail_msg(buff, &msg) > 0) {
				post_local_fail(&msg);
			}
			continue;
		}
	}

	if (fp) {
		sniper_fclose(fp, LOGIN_GET);
	}
	return;
}

// mysql错误日志文件的标准目录
static void check_mysql_log(void)
{
	FILE *fp = NULL;
	char buff[S_LINELEN] = {0};

	fp = fopen(path_mysqld, "r");
	if (!fp) {
		MON_ERROR("check_mysql_log fail, open %s : %s",
			  path_mysqld, strerror(errno));
		return;
	}

	fseek(fp, mysqloff, SEEK_SET);

	while (fgets(buff, S_LINELEN, fp)) {
		struct failinfo msg = {0};

		mysqloff = ftell(fp);

		if (strstr(buff, "Access denied")) {
			if (get_mysql_fail_msg(buff, &msg) > 0) {
				strncpy(msg.login_type, "MYSQL", 8);
				post_fail_connection(&msg);
			}
		}
	}

	if (fp) {
		fclose(fp);
	}
	return;
}

static void init_myinotify(int *fd, int *wd, char *path, unsigned long *inode, unsigned long *size)
{
	struct stat st = {0};

	/* fd,wd,inode,size不会是NULL */
	if (!path) {
		DBG2(DBGFLAG_SSH, "init_myinotify fail, NULL file\n");
		*fd = -1;
		return;
	}

	// DBG2(DBGFLAG_SSH, "init_myinotify file(%s)\n", path);
	if (stat(path, &st) < 0) {
		// DBG2(DBGFLAG_SSH, "init_myinotify stat file(%s) fail: %s\n", path, strerror(errno));
		*fd = -1;
		return;
	}

	*fd = inotify_init(); /* Create inotify instance */
	if (*fd < 0) {
		MON_ERROR("inotify_init file(%s) fail: %s\n", path, strerror(errno));
		return;
	}

	*wd = inotify_add_watch(*fd, path, IN_MODIFY);
	if (*wd < 0) {
		DBG2(DBGFLAG_SSH, "inotify_add_watch file(%s) fail: %s\n", path, strerror(errno));
		close(*fd);
		*fd = -1;
		return;
	}

	DBG2(DBGFLAG_SSH, "inotify file(%s) ok\n", path);
	*inode = st.st_ino;
	*size = st.st_size;
}

/*
 * return -1, error
 *         0, not reinit
 *         1, do reinit
 */
static int reinit_myinotify(int *fd, int *wd, char *path, unsigned long *inode, unsigned long *size)
{
	struct stat st = {0};

	/* fd,wd,inode,size不会是NULL */
	if (*fd < 0) {
		init_myinotify(fd, wd, path, inode, size);
		return 1;
	}

	if (!path) {
		DBG2(DBGFLAG_SSH, "reinit_myinotify fail, NULL file\n");
		inotify_rm_watch(*fd, *wd);
		close(*fd);
		*fd = -1;
		return -1;
	}

	/* 如果文件改变了，监听新的文件 */
	if (stat(path, &st) < 0) {
		MON_ERROR("reinit_myinotify fail, stat file(%s) error: %s\n", path, strerror(errno));
		inotify_rm_watch(*fd, *wd);
		close(*fd);
		*fd = -1;
		return -1;
	}

	if (st.st_ino != *inode) {
		inotify_rm_watch(*fd, *wd);
		close(*fd);
		*fd = -1;

		init_myinotify(fd, wd, path, inode, size);
		if (*fd >= 0) {
			DBG2(DBGFLAG_SSH, "reinit_myinotify file(%s) ok\n", path);
			*size = 0;
			return 1;
		}

		DBG2(DBGFLAG_SSH, "reinit_myinotify file(%s) fail\n", path);
		return -1;
	}

	return 0;
}

static void get_login_strategy(void)
{
	remote_login_check = 0;
	remote_login_crack_check = 0;
	remote_login_crack_locking = 0;
	remote_login_crack_interval = 0;
	remote_login_crack_try_num = 0;
	local_login_check = 0;
	local_login_auth_check = 0;

	pthread_rwlock_rdlock(&protect_policy_global.lock);
	if (protect_policy_global.account.login.enable) {
		if (protect_policy_global.account.login.remote.enable) {
			remote_login_check = 1;
		}

		if (protect_policy_global.account.login.local.enable) {
			local_login_check = 1;
		}

		if (protect_policy_global.account.login.crack.enable) {
			remote_login_check = 1;
			remote_login_crack_check = 1;
			remote_login_crack_locking = 1;
		}
	}
	pthread_rwlock_unlock(&protect_policy_global.lock);
}

/* 在/etc/syslog.conf的尾部添加auth,authpriv.*  /var/log/secure
   或在/etc/syslog-ng/syslog-ng.conf的尾部添加auth,authpriv.*  /var/log/auth.log */
static void append_syslog_conf(char *path)
{
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0}, str1[64] = {0}, str2[64] = {0};

	if (!path) {
		return;
	}

	fp = fopen(path, "r");
	if (!fp) {
		MON_ERROR("cant monitor login crack, read %s fail: %s\n", path, strerror(errno));
		return;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "%63s %63s", str1, str2) == 2 &&
		    strcmp(str1, "auth,authpriv.*") == 0 &&
		    strcmp(str2, path_auth) == 0) {
			/* 已经有log文件的设置了 */
			fclose(fp);
			return;
		}
	}
	fclose(fp);

	fp = fopen(path, "a");
	if (!fp) {
		MON_ERROR("cant monitor login crack, write %s fail: %s\n", path, strerror(errno));
		return;
	}

	fprintf(fp, "\nauth,authpriv.*  %s", path_auth);
	fclose(fp);
}

/* 增加身份认证日志设置，并重启系统日志服务 */
static void create_path_auth(void)
{
	FILE *fp = NULL;

	if (access("/etc/rsyslog.d", F_OK) == 0) {
		fp = fopen("/etc/rsyslog.d/auth_sniper.conf", "w");
		if (!fp) {
			MON_ERROR(
			    "cant monitor login crack, create "
			    "/etc/rsyslog.d/auth_sniper.conf fail: %s\n",
			    strerror(errno));
			return;
		}

		fprintf(fp, "auth,authpriv.*  %s", path_auth);
		fclose(fp);
		system("systemctl restart rsyslog");
		return;
	}

	if (access("/etc/syslog.conf", F_OK) == 0) {  // centos5
		append_syslog_conf("/etc/syslog.conf");
		system("service syslog restart");
		return;
	}

	if (access("/etc/syslog-ng/syslog-ng.conf", F_OK) == 0) {  // suse11.4
		append_syslog_conf("/etc/syslog-ng/syslog-ng.conf");
		system("service syslog restart");
		return;
	}

	MON_ERROR("cant monitor login crack, unknown syslog.conf\n");
}

static void get_auth_path(void)
{
#ifdef SNIPER_FOR_DEBIAN
	path_auth = path_auth_ub;
#else
	path_auth = path_auth_rh;
#endif

	if (access(path_auth, F_OK) < 0) {
		create_path_auth();
	}

	if (access(path_auth, F_OK) < 0) {
		if (access("/sbin/rsyslogd", F_OK) == 0 || access("/usr/sbin/rsyslogd", F_OK) == 0) {
			DBG2(DBGFLAG_SSH, "rsyslog not started, unable to monitor login\n");
			report_dependency_msg("或 未运行服务rsyslog");
		} else {
			DBG2(DBGFLAG_SSH, "syslog not started, unable to monitor login\n");
			report_dependency_msg("或 未运行服务syslog");
		}
	}

	// TODO 检测syslog/rsyslog服务进程是否存在，auth.log或secure文件存在不代表服务存在
	//      centos5是/sbin/syslogd，suse11.4是/sbin/syslog-ng，centos6.0是/sbin/rsyslogd，其他/usr/sbin/rsyslogd
}

int get_log_path(char *type, char *path)
{
	char conf_path[S_PATHLEN] = {0};
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char *ptr = NULL;
	int path_len = 4096;

	if (strcmp(type, "ssh") == 0) {
#ifdef SNIPER_FOR_DEBIAN
		snprintf(path, path_len, "/var/log/auth.log");
#else
		snprintf(path, path_len, "/var/log/secure");
#endif
		return 1;
	}

	snprintf(conf_path, sizeof(conf_path), "/etc/%s.conf", type);

	fp = fopen(conf_path, "r");
	if (!fp) {
		snprintf(conf_path, sizeof(conf_path), "/etc/%s/%s.conf", type, type);
		fp = fopen(conf_path, "r");
	}
	// 标准安装方式路径获取，先取etc下的配置文件
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			ptr = strstr(line, "/var/log");
			if (ptr) {
				snprintf(path, path_len, "%s", ptr);
				fclose(fp);
				return 1;
			}
		}
	}

	// 非标准安装方式路径获取,先取配置文件conf

	return 0;
}

#if 0
int get_crack_conf(void)
{
    char type[S_NAMELEN] = {0}, path[S_PATHLEN] = {0};
    char fail_log[S_LINELEN] = {0}, success_log[S_LINELEN] = {0};
    int rc = 0;
    //管控接收文件
    FILE *fp = NULL;
    char line[S_LINELEN] = {0};
    int ret = 0, sql_ret = 0;
    char cmd[S_CMDLEN] = {0};

    unlink(crack_conf_path);
    snprintf(cmd, sizeof(cmd), "unzip -d %s %s > /dev/null 2>&1", DOWNLOAD_DIR, CRACK_FILE);
    system(cmd);

    if (access(crack_conf_path, F_OK) < 0) {
        create_file(crack_conf_path);
    }

    fp = fopen(crack_conf_path, "r");
    if (!fp) {
        //尝试再次拉取配置文件
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        //新定义
        int fd = -1, wd = -1;
        unsigned long inode = 0, off = 0;
        char *set = NULL;

        if (line[0] == '-') {
            continue;
        }

        //存入login_success_log表后跳到下一行
        set = strstr(line, "SUCCESSLOG:");
        if (set) {
            set += strlen("SUCCESSLOG:");
            snprintf(success_log, sizeof(success_log), "%s", set);
            delete_tailspace(success_log);
            sqlite3_reset(successlog_new_stmt);
            sqlite3_bind_text(successlog_new_stmt, 1, type, -1, SQLITE_STATIC);
            sqlite3_bind_text(successlog_new_stmt, 2, success_log, -1, SQLITE_STATIC);

            if ((rc = sqlite3_step(successlog_new_stmt)) != SQLITE_DONE) {
                MON_ERROR("sql insert new success_log fail: %s(%d)\n", sqlite3_errstr(rc), rc);
            }
            continue;
        }

        //存入login_fail_log表后跳到下一行
        set = strstr(line, "FAILLOG:");
        if (set) {
            set += strlen("FAILLOG:");
            snprintf(fail_log, sizeof(fail_log), "%s", set);
            delete_tailspace(fail_log);
            sqlite3_reset(faillog_new_stmt);
            sqlite3_bind_text(faillog_new_stmt, 1, type, -1, SQLITE_STATIC);
            sqlite3_bind_text(faillog_new_stmt, 2, fail_log, -1, SQLITE_STATIC);

            if ((rc = sqlite3_step(faillog_new_stmt)) != SQLITE_DONE) {
                MON_ERROR("sql insert new fail log fail: %s(%d)\n", sqlite3_errstr(rc), rc);
            }
            continue;
        }

        if (sscanf(line, "NAME:%63s", type) == 1) {
            ret = 0;
            sql_ret = 0;
            if (strcmp(type, "mysqld") == 0) {
                get_mysqld_errorlog_path(&mysqldpid, path, sizeof(path));

                init_myinotify(&fd, &wd, path, &inode, &off); //把解析到的类型，路径，对应的fd，wd，inode，off存入数据库

                sqlite3_reset(type_new_stmt);
                sqlite3_bind_text(type_new_stmt, 1, type, -1, SQLITE_STATIC);
                sqlite3_bind_text(type_new_stmt, 2, path, -1, SQLITE_STATIC);
                sqlite3_bind_int(type_new_stmt, 3, fd);
                sqlite3_bind_int(type_new_stmt, 4, wd);
                sqlite3_bind_int(type_new_stmt, 5, inode);
                sqlite3_bind_int(type_new_stmt, 6, off);

                if ((rc = sqlite3_step(type_new_stmt)) != SQLITE_DONE) {
                    MON_ERROR("sql insert new type login fail: %s(%d)\n", sqlite3_errstr(rc), rc);
                }
                sql_ret = 1;
            }
            // TODO先从系统获取应用对应的日志路径
            ret = get_log_path(type, path);
            if (access(path, F_OK) != 0) { //如果取出的文件正好被删除，不存在，则仍使用配置文件的配置路径
                ret = 0;
                continue;
            }

            if (ret) {                                        //取到了且文件存在，存入数据库
                init_myinotify(&fd, &wd, path, &inode, &off); //把解析到的类型，路径，对应的fd，wd，inode，off存入数据库

                sqlite3_reset(type_new_stmt);
                sqlite3_bind_text(type_new_stmt, 1, type, -1, SQLITE_STATIC);
                sqlite3_bind_text(type_new_stmt, 2, path, -1, SQLITE_STATIC);
                sqlite3_bind_int(type_new_stmt, 3, fd);
                sqlite3_bind_int(type_new_stmt, 4, wd);
                sqlite3_bind_int(type_new_stmt, 5, inode);
                sqlite3_bind_int(type_new_stmt, 6, off);

                if ((rc = sqlite3_step(type_new_stmt)) != SQLITE_DONE) {
                    MON_ERROR("sql insert new type login fail: %s(%d)\n", sqlite3_errstr(rc), rc);
                }
            }
            continue;
        }

        if (ret || sql_ret) { //应用信息已存入数据库，该应用无需再解析
            continue;
        }

        if (sscanf(line, "PATH:%4095s", path) == 1) {
            if (access(path, F_OK) != 0) {
                continue;
            }
        }

        if (strcmp(type, "ssh") == 0) { // TODO 日志没有记录Accepted和Failed处理
            get_auth_path(path);
        }

        init_myinotify(&fd, &wd, path, &inode, &off); //把解析到的类型，路径，对应的fd，wd，inode，off存入数据库

        sqlite3_reset(type_new_stmt);
        sqlite3_bind_text(type_new_stmt, 1, type, -1, SQLITE_STATIC);
        sqlite3_bind_text(type_new_stmt, 2, path, -1, SQLITE_STATIC);
        sqlite3_bind_int(type_new_stmt, 3, fd);
        sqlite3_bind_int(type_new_stmt, 4, wd);
        sqlite3_bind_int(type_new_stmt, 5, inode);
        sqlite3_bind_int(type_new_stmt, 6, off);

        if ((rc = sqlite3_step(type_new_stmt)) != SQLITE_DONE) {
            MON_ERROR("sql insert new type login fail: %s(%d)\n", sqlite3_errstr(rc), rc);
        }
    }
    fclose(fp);
    return 0;
}


void update_inotify(void)
{
    int rc = 0;
    // 1.清空数据库 2.inotify_rm_watch fd>0 3.close fd 4.scanf reinotify
    sqlite3_reset(select_wd_fd_stmt);
    while (sqlite3_step(select_wd_fd_stmt) == SQLITE_ROW) {
        int fd_num = sqlite3_column_int(select_wd_fd_stmt, 0);
        int wd_num = sqlite3_column_int(select_wd_fd_stmt, 1);

        inotify_rm_watch(fd_num, wd_num);
        close(fd_num);
    }

    sqlite3_reset(delete_type_stmt);
    sqlite3_reset(delete_faillog_stmt);
    sqlite3_reset(delete_successlog_stmt);

    rc = sqlite3_step(delete_type_stmt);
    if (rc != SQLITE_DONE) {
        DBG2(DBGFLAG_SSH, "delete_type_stmt error\n");
    } else {
        DBG2(DBGFLAG_SSH, "delete_type_stmt success\n");
    }

    rc = sqlite3_step(delete_faillog_stmt);
    if (rc != SQLITE_DONE) {
        DBG2(DBGFLAG_SSH, "delete_faillog_stmt error\n");
    } else {
        DBG2(DBGFLAG_SSH, "delete_faillog_stmt success\n");
    }

    rc = sqlite3_step(delete_successlog_stmt);
    if (rc != SQLITE_DONE) {
        DBG2(DBGFLAG_SSH, "delete_successlog_stmt error\n");
    } else {
        DBG2(DBGFLAG_SSH, "delete_successlog_stmt success\n");
    }

    get_crack_conf();
    mysleep(5);
}
#endif

#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

#if 0 
/*
 * 流程：
 * 1、初始化阶段：get_cached_info、check_ssh、check_ssh_utmp、check_login
 * 2、监测阶段：1）wtmp有改变，check_ssh、check_ssh_utmp、check_login
 *              2）check时间小于策略改变时间，check_login
 */
void *login_monitor(void *ptr)
{
    int wtmpfd = -1;
    int wtmpwd = -1, max_fd = 0;
    char buf[BUF_LEN] = {0};
    unsigned long wtmpinode = 0;
    unsigned long wtmpoff = 0;
    struct login_info *pos = NULL, *p = NULL;
    int ncolumn = 0, nrow_max_fd = 0;
    const char *type_name = NULL;
    const char *type_path = NULL;
    int rc = 0;

    prctl(PR_SET_NAME, "login_monitor");
    save_thread_pid("login", SNIPER_THREAD_LOGIN);

    memset(fail_ssh_info, 0, (sizeof(struct fail_ssh) * MAX_FAIL_CONNECT));

    if (!crack_user_db) {
        crack_db_init();
    }

    rc = get_crack_conf();

    /* 监控ssh登录成功事件 */
    init_myinotify(&wtmpfd, &wtmpwd, path_wtmp, &wtmp_inode, &wtmpoff);
    if (wtmpfd >= 0) {
        /* 读缓存的登录信息 */
        wtmpinode = get_cached_login();
        if (wtmpinode != wtmp_inode) {
            /* wtmp文件变了，check_ssh时应从头开始读 */
            last_wtmp_count = 0;
        }
    }

    get_login_strategy();
    check_ssh();
    check_ssh_utmp(0);

    /* 缓存最新的登录信息 */
    cache_login_info();

    while (Online) {
        char **azResult_max_fd = NULL;
        fd_set rfds;
        struct timeval tv = {0};
        int retval = 0;

        /* 检查待转储的日志文件 */
        check_log_to_send("login");

        /* 如果过期/停止防护了，什么也不做 */
        if (conf_global.licence_expire || sniper_other_loadoff == 1) {
            mysleep(EXPIRE_WAIT_TIME);
            continue;
        }

        get_login_strategy();
        /* 如果不监控登录和认证，仅60秒统计一次当前登录用户数 */
        if (!remote_login_check && !remote_login_crack_check &&
            !local_login_check && !local_login_auth_check &&
            !user_change_check) {
            check_ssh_utmp(1);
            mysleep(60);
            continue;
        }

        FD_ZERO(&rfds);
        if (wtmpfd >= 0) {
            FD_SET(wtmpfd, &rfds);
        }
#if 0
        if (authfd >= 0) {
            FD_SET(authfd, &rfds);
        }
        if (mysqlfd >= 0) {
            FD_SET(mysqlfd, &rfds);
        }
#endif

        int j = 0, rc = 0;
        /* const char *select_fd_sql = "SELECT fd FROM login_type_conf WHERE fd >= 0;";
        rc = sqlite3_get_table(crack_user_db, select_fd_sql, &azResult, &nrow, &ncolumn, 0);
        if (rc != SQLITE_OK) {
            MON_ERROR("Query fd failed\n");
        }

        for (i = 1; i <= nrow; i++) {
            FD_SET(atoi(azResult[i]), &rfds);
        }
        sqlite3_free_table(azResult); */
        if (crack_user_db && rc != -1) {
            sqlite3_reset(select_fd_stmt);
            while (sqlite3_step(select_fd_stmt) == SQLITE_ROW) {
                int fd = sqlite3_column_int(select_fd_stmt, 0);
                FD_SET(fd, &rfds);
            }

            /*  if (wtmpfd < 0 && nrow <= 0) {
                mysleep(5);
                last_wtmp_count = 0;
                // reinit_myinotify(&fd, &wd, path, &inode, &off);
                continue;
            } */

            char select_max_fd[1024] = {0};
            // const char *select_max_fd = "SELECT MAX(fd) FROM login_type_conf;";
            snprintf(select_max_fd, sizeof(select_max_fd), "SELECT MAX(fd) FROM login_type_conf;");
            rc = sqlite3_get_table(crack_user_db, select_max_fd, &azResult_max_fd, &nrow_max_fd, &ncolumn, 0);
            if (rc != SQLITE_OK) {
                MON_ERROR("Query MAX(fd) failed\n");
            }

            for (j = 1; j <= nrow_max_fd; j++) {
                if (!azResult_max_fd[j]) {
                    break;
                }
                max_fd = atoi(azResult_max_fd[j]); // max_fd = authfd > wtmpfd ? authfd : wtmpfd;
            }

            sqlite3_free_table(azResult_max_fd);
        }

        if (max_fd < wtmpfd) {
            max_fd = wtmpfd;
        }

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        retval = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            MON_ERROR("login inotify select fail: %s\n", strerror(errno));
        } else if (retval) {
            DBG2(DBGFLAG_SSH, "Data is available now.\n");

#if 0
            if (authfd >= 0 && FD_ISSET(authfd, &rfds) &&
                read(authfd, buf, BUF_LEN) > 0) {
                check_auth();
            }

            if (mysqlfd >= 0 && FD_ISSET(mysqlfd, &rfds) &&
                read(mysqlfd, buf, BUF_LEN) > 0) {
                check_mysql_log();
            }
#endif
            if (crack_user_db && rc != -1) {
                sqlite3_reset(select_typefd_stmt);
                while (sqlite3_step(select_typefd_stmt) == SQLITE_ROW) {
                    type_name = (const char *)sqlite3_column_text(select_typefd_stmt, 0);
                    type_path = (const char *)sqlite3_column_text(select_typefd_stmt, 1);
                    int fd_num = sqlite3_column_int(select_typefd_stmt, 2);
                    int off_num = sqlite3_column_int(select_typefd_stmt, 3);

                    if (FD_ISSET(fd_num, &rfds) &&
                        read(fd_num, buf, BUF_LEN) > 0) {
                        check_app_log(type_name, type_path, off_num);
                    }
                }
            }

            if (wtmpfd >= 0 && FD_ISSET(wtmpfd, &rfds) &&
                read(wtmpfd, buf, BUF_LEN) > 0) {
                if (remote_login_check || local_login_check) {
                    /* check_ssh之后总跟个check_ssh_utmp，补漏和阻断 */
                    check_ssh();
                    check_ssh_utmp(0);

                    /* 缓存最新的登录信息 */
                    cache_login_info();
                } else {
                    /* 仅统计当前登录用户数目 */
                    check_ssh_utmp(1);
                }
            }
        }

        /* 没有新的登录，但策略有变化，检查当前登录的状态 */
        if (remote_login_check || local_login_check) {
            if (is_update_task) {
                check_ssh_utmp(0);

                /* 缓存最新的登录信息 */
                cache_login_info();
                is_update_task = 0;
            } else {
                /*
                 * 登录退出时，可能没更新wtmp或utmp，比如last看到有
                 * root   tty1   192.168.207.140  Sat Dec 22 19:17   gone - no logout
                 */
                check_current_logins();
            }
        }

        /* 有被锁定的ip这里不检查，连接断开的时候自然会检查
           锁定ip的事件也不影响登录的定性 */

        /* 即使不监控登录，统计当前用户登录数目也要求监控wtmp */
        if (reinit_myinotify(&wtmpfd, &wtmpwd, path_wtmp, &wtmp_inode, &wtmpoff) == 1) {
            last_wtmp_count = 0;

            if (remote_login_check || local_login_check) {
                /* wtmp文件变了，为了避免老wtmp有记录没读到，再用utmp确认一次远程连接 */
                check_ssh_utmp(0);

                /* 缓存最新的登录信息 */
                cache_login_info();
            }
        }

        // TODO reinit_myinotify(&fd, &wd, path, &inode, &off);

        // TODO 新的应用进程，重新初始化
#if 0
        /* 是新的mysqld进程，重新初始化 */
        if (new_mysqld) {
            if (mysqlfd >= 0) {
                inotify_rm_watch(mysqlfd, mysqlwd);
                close(mysqlfd);
                mysqlfd = -1;
            }
            get_mysqld_errorlog_path(&mysqldpid, path_mysqld, sizeof(path_mysqld));
            init_myinotify(&mysqlfd, &mysqlwd, path_mysqld, &mysqlinode, &mysqloff);
        }
#endif

        if (is_update_conf) {
            update_inotify();
            is_update_conf = 0;
        }
    }

    if (wtmpfd >= 0) {
        inotify_rm_watch(wtmpfd, wtmpwd);
        close(wtmpfd);
    }

    if (crack_user_db && rc != -1) {
        sqlite3_reset(select_wd_fd_stmt);
        while (sqlite3_step(select_wd_fd_stmt) == SQLITE_ROW) {
            int fd_num = sqlite3_column_int(select_wd_fd_stmt, 0);
            int wd_num = sqlite3_column_int(select_wd_fd_stmt, 1);

            inotify_rm_watch(fd_num, wd_num);
            close(fd_num);
        }
    }

    list_for_each_entry_safe(pos, p, &all_conn, list)
    {
        free_login(pos);
    }

    INFO("login thread exit\n");
    return 0;
}
#endif

/*
 * 流程：
 * 1、初始化阶段：get_cached_info、check_ssh、check_ssh_utmp、check_login
 * 2、监测阶段：1）wtmp有改变，check_ssh、check_ssh_utmp、check_login
 *              2）check时间小于策略改变时间，check_login
 */
void *login_monitor(void *ptr)
{
	int wtmpfd = -1, authfd = -1, mysqlfd = -1;
	int wtmpwd = -1, authwd = -1, mysqlwd = -1, max_fd = 0;
	int new_mysqld = 0;
	char buf[BUF_LEN] = {0}, mysqldcomm[16] = {0};
	unsigned long wtmpinode = 0, authinode = 0, mysqlinode = 0;
	unsigned long wtmpoff = 0;
	struct login_info *pos = NULL, *p = NULL;

	save_thread_pid("login", SNIPER_THREAD_LOGIN);

	memset(fail_ssh_info, 0, (sizeof(struct fail_ssh) * MAX_FAIL_CONNECT));

	if (!crack_user_db) {
		crack_db_init();
	}

	/* 监控ssh登录成功事件 */
	init_myinotify(&wtmpfd, &wtmpwd, path_wtmp, &wtmp_inode, &wtmpoff);
	if (wtmpfd >= 0) {
		/* 读缓存的登录信息 */
		wtmpinode = get_cached_login();
		if (wtmpinode != wtmp_inode) {
			/* wtmp文件变了，check_ssh时应从头开始读 */
			last_wtmp_count = 0;
		}
	}

	/* 监控ssh暴力密码破解，包括ssh登录和hydra远程执行命令2种破解方式 */
	get_auth_path();
	init_myinotify(&authfd, &authwd, path_auth, &authinode, &authoff);

	/* 监控mysql connect暴力密码破解 */
	get_mysqld_errorlog_path(&mysqldpid, path_mysqld, sizeof(path_mysqld));
	init_myinotify(&mysqlfd, &mysqlwd, path_mysqld, &mysqlinode, &mysqloff);

	get_login_strategy();
	check_ssh();
	check_ssh_utmp(0);

	/* 缓存最新的登录信息 */
	cache_login_info();

	while (Online) {
		fd_set rfds;
		struct timeval tv = {0};
		int retval = 0;

		/* 检查待转储的日志文件 */
		check_log_to_send("login");

		/* 如果停止防护了，什么也不做 */
		if (sniper_other_loadoff == TURN_MY_ON) {
			mysleep(STOP_WAIT_TIME);
			continue;
		}

		/* 如果过期/停止客户端工作，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			mysleep(STOP_WAIT_TIME);
			continue;
		}

		get_login_strategy();
		/* 如果不监控登录和认证，仅60秒统计一次当前登录用户数 */
		if (!remote_login_check && !remote_login_crack_check &&
		    !local_login_check && !local_login_auth_check &&
		    !user_change_check) {
			check_ssh_utmp(1);
			mysleep(60);
			continue;
		}

		FD_ZERO(&rfds);
		if (wtmpfd >= 0) {
			FD_SET(wtmpfd, &rfds);
		}
		if (authfd >= 0) {
			FD_SET(authfd, &rfds);
		}
		if (mysqlfd >= 0) {
			FD_SET(mysqlfd, &rfds);
		}

		if (wtmpfd < 0 && authfd < 0 && mysqlfd < 0) {
			mysleep(5);
			last_wtmp_count = 0;
			reinit_myinotify(&wtmpfd, &wtmpwd, path_wtmp, &wtmp_inode, &wtmpoff);
			reinit_myinotify(&authfd, &authwd, path_auth, &authinode, &authoff);
			reinit_myinotify(&mysqlfd, &mysqlwd, path_mysqld, &mysqlinode, &mysqloff);
			continue;
		}

		max_fd = authfd > wtmpfd ? authfd : wtmpfd;
		if (max_fd < mysqlfd) {
			max_fd = mysqlfd;
		}

		tv.tv_sec = 5;
		tv.tv_usec = 0;

		retval = select(max_fd + 1, &rfds, NULL, NULL, &tv);
		if (retval == -1) {
			MON_ERROR("login inotify select fail: %s\n", strerror(errno));
		} else if (retval) {
			DBG2(DBGFLAG_SSH, "Data is available now.\n");

			if (authfd >= 0 && FD_ISSET(authfd, &rfds) &&
			    read(authfd, buf, BUF_LEN) > 0) {
				check_auth();
			}

			if (mysqlfd >= 0 && FD_ISSET(mysqlfd, &rfds) &&
			    read(mysqlfd, buf, BUF_LEN) > 0) {
				check_mysql_log();
			}

			if (wtmpfd >= 0 && FD_ISSET(wtmpfd, &rfds) &&
			    read(wtmpfd, buf, BUF_LEN) > 0) {
				if (remote_login_check || local_login_check) {
					/* check_ssh之后总跟个check_ssh_utmp，补漏和阻断 */
					check_ssh();
					check_ssh_utmp(0);

					/* 缓存最新的登录信息 */
					cache_login_info();
				} else {
					/* 仅统计当前登录用户数目 */
					check_ssh_utmp(1);
				}
			}
		}

		/* 没有新的登录，但策略有变化，检查当前登录的状态 */
		if (remote_login_check || local_login_check) {
			if (is_update_task) {
				check_ssh_utmp(0);

				/* 缓存最新的登录信息 */
				cache_login_info();
				is_update_task = 0;
			} else {
				/*
				 * 登录退出时，可能没更新wtmp或utmp，比如last看到有
				 * root   tty1   192.168.207.140  Sat Dec 22 19:17   gone - no logout
				 */
				check_current_logins();
			}
		}

		/* 有被锁定的ip这里不检查，连接断开的时候自然会检查
		   锁定ip的事件也不影响登录的定性 */

		/* 即使不监控登录，统计当前用户登录数目也要求监控wtmp */
		if (reinit_myinotify(&wtmpfd, &wtmpwd, path_wtmp, &wtmp_inode, &wtmpoff) == 1) {
			last_wtmp_count = 0;

			if (remote_login_check || local_login_check) {
				/* wtmp文件变了，为了避免老wtmp有记录没读到，再用utmp确认一次远程连接 */
				check_ssh_utmp(0);

				/* 缓存最新的登录信息 */
				cache_login_info();
			}
		}

		reinit_myinotify(&authfd, &authwd, path_auth, &authinode, &authoff);

		/* 还是原来的mysqld进程，检查日志是否转储了 */
		new_mysqld = 1;
		memset(mysqldcomm, 0, sizeof(mysqldcomm));
		if (mysqldpid > 0) {
			get_proc_comm(mysqldpid, mysqldcomm);
			if (strcmp(mysqldcomm, "mysqld") == 0) {
				new_mysqld = 0;
				reinit_myinotify(&mysqlfd, &mysqlwd, path_mysqld, &mysqlinode, &mysqloff);
			}
		}

		/* 是新的mysqld进程，重新初始化 */
		if (new_mysqld) {
			if (mysqlfd >= 0) {
				inotify_rm_watch(mysqlfd, mysqlwd);
				close(mysqlfd);
				mysqlfd = -1;
			}
			get_mysqld_errorlog_path(&mysqldpid, path_mysqld, sizeof(path_mysqld));
			init_myinotify(&mysqlfd, &mysqlwd, path_mysqld, &mysqlinode, &mysqloff);
		}
	}

	if (wtmpfd >= 0) {
		inotify_rm_watch(wtmpfd, wtmpwd);
		close(wtmpfd);
	}
	if (authfd >= 0) {
		inotify_rm_watch(authfd, authwd);
		close(authfd);
	}
	if (mysqlfd >= 0) {
		inotify_rm_watch(mysqlfd, mysqlwd);
		close(mysqlfd);
	}

	list_for_each_entry_safe(pos, p, &all_conn, list)
	{
		free_login(pos);
	}

	crack_db_release();
	INFO("login thread exit\n");
	return 0;
}

void download_crack_conf(task_recv_t *msg)
{
	int ret = 0;

	INFO("download crack conf version %s\n", msg->new_version);
	ret = download_rule_file(DOWNLOAD_CONF_URL, msg->new_version, CRACK_FILE);
	if (ret < 0) {
		MON_ERROR("download crack conf Failed\n");
		return;
	}
	INFO("download crack conf ok\n");
}

void *crack_monitor(void *ptr)
{
	char buf[S_LINELEN] = {0};
	int rc = 0, nrow = 0, ncolumn = 0;
	char crack_ip[S_IPLEN] = {0}, crack_type[8] = {0};
	char login_fail_ip[S_IPLEN] = {0}, login_fail_type[S_NAMELEN] = {0};
	struct timeval tvstamp = {0};
	struct login_info login_info = {0};
	int i = 0, j = 0, k = 0;
	int policy_time = protect_policy_global.account.login.crack.interval * 60;
	int crack_try_num = protect_policy_global.account.login.crack.limit;
	char tmp[S_NAMELEN] = {0};

	prctl(PR_SET_NAME, "pwcrack_monitor");
	save_thread_pid("crack", SNIPER_THREAD_CRACK);

	while (Online) {
		/* 如果过期了/停止客户端工作，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			sleep(STOP_WAIT_TIME);
			continue;
		}

		if (crack_user_db) {
			char **azResult = NULL;
			gettimeofday(&tvstamp, NULL);

			sqlite3_reset(select_crack_stmt);
			sqlite3_bind_int(select_crack_stmt, 1, tvstamp.tv_sec);
			sqlite3_bind_int(select_crack_stmt, 2, tvstamp.tv_sec);
			while (sqlite3_step(select_crack_stmt) == SQLITE_ROW) {
				const char *ip = (const char *)sqlite3_column_text(select_crack_stmt, 0);
				const char *type = (const char *)sqlite3_column_text(select_crack_stmt, 1);
				int last_report_time = sqlite3_column_int(select_crack_stmt, 2);

				int time = tvstamp.tv_sec;

				snprintf(crack_ip, sizeof(crack_ip), "%s", ip);
				snprintf(crack_type, sizeof(crack_type), "%s", type);

				snprintf(buf, sizeof(buf), "SELECT last_time FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", crack_ip, crack_type);
				rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
				if (rc != SQLITE_OK) {
					continue;
				}
				login_info.attack_time = atoi(azResult[ncolumn]);

				snprintf(buf, sizeof(buf), "SELECT queue_count FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", crack_ip, crack_type);
				rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
				if (rc != SQLITE_OK) {
					continue;
				}
				login_info.failed_count = atoi(azResult[ncolumn]);

				if (rc == SQLITE_OK && nrow != 0) {
					if ((login_info.attack_time > last_report_time) && (login_info.attack_time <= time) && (login_info.failed_count > crack_try_num)) {
						DBG2(DBGFLAG_SSH, "1 min ready to report crack\n");

						snprintf(buf, sizeof(buf), "SELECT name FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", crack_ip, crack_type);
						rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);
						if (rc != SQLITE_OK) {
							continue;
						}

						snprintf(login_info.crack_user, sizeof(login_info.crack_user), "%s", azResult[ncolumn]);
						for (i = 0; i < strlen(login_info.crack_user); i++) {  // 将字符串中的空格替换为逗号
							if (login_info.crack_user[i] == ' ') {
								login_info.crack_user[i] = ',';
							}
						}

						sscanf(login_info.crack_user, "%63[^,]", tmp);
						snprintf(login_info.user, sizeof(login_info.user), "%s", tmp);
						snprintf(login_info.login_ip, sizeof(login_info.login_ip), "%s", crack_ip);
						snprintf(login_info.login_type, sizeof(login_info.login_type), "%s", crack_type);

						login_info.event_id = LOGIN_PASSWD_CRACK;
						login_info.behavior_id = BEHAVIOR_ABNORMAL;
						login_info.loglevel = MY_LOG_HIGH_RISK;

						pthread_rwlock_rdlock(&rule_trust_global.lock);
						for (i = 0; i < rule_trust_global.ip_num; i++) {  // 判断是否为可信ip
							for (j = 0; j < rule_trust_global.ip[i].ip_num; j++) {
								for (k = 0; k < rule_trust_global.ip[i].event_num; k++) {
									if (strcmp(rule_trust_global.ip[i].event_names[k].list, "Crack") != 0) {
										continue;
									}
									if (check_ip_is_match(crack_ip, rule_trust_global.ip[i].ip_list[j].list)) {
										login_info.terminate = 0;
										login_info.locking = 0;
										login_info.event_id = LOGIN_PASSWD_CRACK;
										login_info.behavior_id = BEHAVIOR_NORMAL;
										login_info.loglevel = MY_LOG_NORMAL;
										break;
									}
								}
							}
						}
						pthread_rwlock_unlock(&rule_trust_global.lock);
						send_login_msg(&login_info);

						// 报完更新last_report_time
						sqlite3_reset(update_last_report_time_stmt);
						sqlite3_bind_int(update_last_report_time_stmt, 1, tvstamp.tv_sec);
						sqlite3_bind_text(update_last_report_time_stmt, 2, crack_ip, -1, SQLITE_STATIC);
						sqlite3_bind_text(update_last_report_time_stmt, 3, crack_type, -1, SQLITE_STATIC);

						if ((rc = sqlite3_step(update_last_report_time_stmt)) != SQLITE_DONE) {
							MON_ERROR("sql update last_report_time fail: %s(%d)\n", sqlite3_errstr(rc), rc);
						}
					}
				}
			}

			gettimeofday(&tvstamp, NULL);

			/*
			 * ip不属于暴力密码破解时，清理过期登录
			 */
			#if 1
			sqlite3_reset(select_del_fail_stmt);
			sqlite3_bind_int(select_del_fail_stmt, 1, tvstamp.tv_sec);
			sqlite3_bind_int(select_del_fail_stmt, 2, policy_time);

			while (sqlite3_step(select_del_fail_stmt) == SQLITE_ROW) {  // 到策略配置的时间阈值，删除login_fail_tbl对应ip记录
				const char *fail_ip = (const char *)sqlite3_column_text(select_del_fail_stmt, 0);
				const char *fail_type = (const char *)sqlite3_column_text(select_del_fail_stmt, 1);

				snprintf(login_fail_ip, sizeof(login_fail_ip), "%s", fail_ip);
				snprintf(login_fail_type, sizeof(login_fail_type), "%s", fail_type);

				snprintf(buf, sizeof(buf), "SELECT last_time FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", login_fail_ip, login_fail_type);
				sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);

				DBG2(DBGFLAG_SSH, "overtime login fail info,sys_time %d and last_login_time %d, ip:%s, type:%s, policy_time:%d\n", tvstamp.tv_sec, atoi(azResult[ncolumn]), login_fail_ip, login_fail_type, policy_time);

				snprintf(buf, sizeof(buf), "SELECT id FROM crack_tbl WHERE ip='%s' and type='%s';", login_fail_ip, login_fail_type);
				rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);

				if (rc == SQLITE_OK && nrow == 0) {
					DBG2(DBGFLAG_SSH, "clear overtime login fail info,then del %s and %s from login_fail_tbl\n", login_fail_ip, login_fail_type);

					sqlite3_reset(delete_login_fail_tbl_stmt);
					sqlite3_bind_text(delete_login_fail_tbl_stmt, 1, login_fail_ip, -1, SQLITE_STATIC);
					sqlite3_bind_text(delete_login_fail_tbl_stmt, 2, login_fail_type, -1, SQLITE_STATIC);

					if ((rc = sqlite3_step(delete_login_fail_tbl_stmt)) != SQLITE_DONE) {
						MON_ERROR("sql delete from login_fail_tbl fail: %s(%d)\n", sqlite3_errstr(rc), rc);
					}
					memset(invalid_ssh_user, 0, sizeof(invalid_ssh_user));
				}
			}
			#endif

			/*
			 * ip曾处于暴力密码破解状态，清理过期登录
			 */
			sqlite3_reset(select_to_del_stmt);
			sqlite3_bind_int(select_to_del_stmt, 1, tvstamp.tv_sec);
			// 到策略配置的时间阈值，删除crack_tbl login_fail_tbl对应ip记录
			while (sqlite3_step(select_to_del_stmt) == SQLITE_ROW) {
				const char *ip_name = (const char *)sqlite3_column_text(select_to_del_stmt, 0);
				const char *type_name = (const char *)sqlite3_column_text(select_to_del_stmt, 1);

				snprintf(crack_ip, sizeof(crack_ip), "%s", ip_name);
				snprintf(crack_type, sizeof(crack_type), "%s", type_name);

				snprintf(buf, sizeof(buf), "SELECT last_time FROM login_fail_tbl WHERE crack_ip='%s' and type='%s';", crack_ip, crack_type);
				rc = sqlite3_get_table(crack_user_db, buf, &azResult, &nrow, &ncolumn, 0);

				// 当前时间-最后一次登录失败时间小于策略时间，仍处于爆破态，增加一个策略时间段
				if ((tvstamp.tv_sec - atoi(azResult[ncolumn])) < policy_time) {
					sqlite3_reset(update_policy_time_stmt);
					sqlite3_bind_int(update_policy_time_stmt, 1, policy_time);
					sqlite3_bind_text(update_policy_time_stmt, 2, crack_ip, -1, SQLITE_STATIC);
					sqlite3_bind_text(update_policy_time_stmt, 3, crack_type, -1, SQLITE_STATIC);

					if ((rc = sqlite3_step(update_policy_time_stmt)) != SQLITE_DONE) {
						MON_ERROR("sql update policy_time fail: %s(%d)\n", sqlite3_errstr(rc), rc);
					}
				} else {
					DBG2(DBGFLAG_SSH, "Time threshold to policy configuration,del %s and %s\n", crack_ip, crack_type);

					sqlite3_reset(delete_login_fail_tbl_stmt);
					sqlite3_bind_text(delete_login_fail_tbl_stmt, 1, crack_ip, -1, SQLITE_STATIC);
					sqlite3_bind_text(delete_login_fail_tbl_stmt, 2, crack_type, -1, SQLITE_STATIC);

					if ((rc = sqlite3_step(delete_login_fail_tbl_stmt)) != SQLITE_DONE) {
						MON_ERROR("sql delete from login_fail_tbl fail: %s(%d)\n", sqlite3_errstr(rc), rc);
					}

					sqlite3_reset(delete_crack_tbl_stmt);
					sqlite3_bind_text(delete_crack_tbl_stmt, 1, crack_ip, -1, SQLITE_STATIC);
					sqlite3_bind_text(delete_crack_tbl_stmt, 2, crack_type, -1, SQLITE_STATIC);

					if ((rc = sqlite3_step(delete_crack_tbl_stmt)) != SQLITE_DONE) {
						MON_ERROR("sql delete from crack_tbl fail: %s(%d)\n", sqlite3_errstr(rc), rc);
					}
					memset(invalid_ssh_user, 0, sizeof(invalid_ssh_user));
				}
			}

			sqlite3_free_table(azResult);
		}
		sleep(1);
	}

	INFO("crack thread exit\n");
	return 0;
}
