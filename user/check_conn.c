#include <sqlite3.h>

#include "header.h"

#define SNIPER_SQLITE3 1

typedef union iaddr iaddr;
struct timeval conchktv = {0};
int new_conn_count = 0;

struct info {
	int local_port;
	int rem_port;
	char local_ip[64];
	char rem_ip[64];
	unsigned long inode;
	int state;
	uid_t uid;
};

union iaddr {
	unsigned u;
	unsigned char b[4];
};

sqlite3 *conn_db = NULL;
int first_conn_check = 0;

const char conn_tbl[1024] = {
    "CREATE TABLE IF NOT EXISTS conninfo("
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "local_ip varchar(64),"
    "local_port int,"
    "rem_ip varchar(64),"
    "rem_port int,"
    "uid int,"
    "inode int UNIQUE,"
    "comm varchar(64),"
    "proto varchar(64),"
    "cmdpath varchar(256),"
    "pid int,"
    "lastchk int,"
    "state varchar(64),"
    "direction int);"};

const char conn_socket_info_tbl[2048] = {
    "CREATE TABLE IF NOT EXISTS socketinfo("
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "pid int,"
    "socket UNSIGNED BIG INT UNIQUE);"};

const char *conn_new_sql = "INSERT INTO conninfo VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?);";
const char *conn_unchg_sql = "UPDATE conninfo SET lastchk=? WHERE id=?;";
const char *conn_sdel_sql = "SELECT id,local_ip,rem_ip,comm,proto,pid,local_port,rem_port,cmdpath,direction FROM conninfo WHERE lastchk!=?;";
const char *conn_del_sql = "DELETE FROM conninfo WHERE id=?;";

const char *socket_new_sql = "INSERT INTO socketinfo VALUES(NULL,?,?);";
const char *select_pid_sql = "SELECT pid FROM socketinfo WHERE socket=?;";

const char *select_direction_sql = "SELECT state FROM conninfo WHERE local_port = ?;";

sqlite3_stmt *conn_new_stmt = NULL;
sqlite3_stmt *conn_unchg_stmt = NULL;
sqlite3_stmt *conn_sdel_stmt = NULL;
sqlite3_stmt *conn_del_stmt = NULL;

sqlite3_stmt *socket_new_stmt = NULL;
sqlite3_stmt *select_pid_stmt = NULL;

sqlite3_stmt *select_direction_stmt = NULL;

static void conn_db_init(void)
{
	char dbfile[128] = {0};
	snprintf(dbfile, 128, "%s/%s", WORKDIR, DBDIR);

	if (access(dbfile, F_OK) != 0) {
		mkdir(dbfile, 0700);
	}

	snprintf(dbfile, 128, "%s/%s/conn.db", WORKDIR, DBDIR);

	conn_db = connect_to_Db(dbfile, conn_tbl, conn_socket_info_tbl, NULL, &first_conn_check);

	if (conn_db == NULL) {
		return;
	}

	sqlite3_busy_handler(conn_db, db_busy_callback, NULL);
	sqlite3_prepare_v2(conn_db, conn_new_sql, -1, &conn_new_stmt, NULL);
	sqlite3_prepare_v2(conn_db, conn_unchg_sql, -1, &conn_unchg_stmt, NULL);
	sqlite3_prepare_v2(conn_db, conn_sdel_sql, -1, &conn_sdel_stmt, NULL);
	sqlite3_prepare_v2(conn_db, conn_del_sql, -1, &conn_del_stmt, NULL);

	sqlite3_prepare_v2(conn_db, socket_new_sql, -1, &socket_new_stmt, NULL);
	sqlite3_prepare_v2(conn_db, select_pid_sql, -1, &select_pid_stmt, NULL);

	sqlite3_prepare_v2(conn_db, select_direction_sql, -1, &select_direction_stmt, NULL);
}

void conn_db_release(void)
{
	if (conn_db == NULL) {
		return;
	}

	sqlite3_finalize(conn_new_stmt);
	sqlite3_finalize(conn_unchg_stmt);
	sqlite3_finalize(conn_sdel_stmt);
	sqlite3_finalize(conn_del_stmt);

	sqlite3_finalize(socket_new_stmt);
	sqlite3_finalize(select_pid_stmt);

	sqlite3_finalize(select_direction_stmt);

	sqlite3_close_v2(conn_db);
}

sqlite3 *location_db = NULL;
int first_conn_location = 0;

const char conn_location_tbl[512] = {
    "CREATE TABLE IF NOT EXISTS locationinfo("
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "ip1 int,"
    "ip2 int,"
    "ip3 int,"
    "ip4 int,"
    "ip5 int,"
    "ip6 int,"
    "ip7 int,"
    "ip8 int,"
    "location varchar(64));"};

const char *location_select_sql = "SELECT ip2,ip3,ip4,ip6,ip7,ip8,location FROM locationinfo WHERE ip1 = ?;";

sqlite3_stmt *location_select_stmt = NULL;

void location_db_init(void)
{
	char dbfile[128] = {0};

	snprintf(dbfile, 128, "%s", WORKDIR);
	if (access(dbfile, 0) != 0) {
		mkdir(dbfile, 0700);
	}

	snprintf(dbfile, 128, "%s/sniper_location.db", WORKDIR);
	location_db = connectDb(dbfile, conn_location_tbl, NULL, &first_conn_location);
	if (location_db == NULL) {
		return;
	}

	sqlite3_busy_handler(location_db, db_busy_callback, NULL);
	sqlite3_prepare_v2(location_db, location_select_sql, -1, &location_select_stmt, NULL);
}

void location_db_release(void)
{
	if (location_db == NULL) {
		return;
	}

	sqlite3_finalize(location_select_stmt);

	sqlite3_close_v2(location_db);
}

/*获取/proc/pid/fd pid对应socket信息*/
static void socket_pid_info(void)
{
	int pid = 0;
	DIR *dirp = NULL, *fddirp = NULL;
	struct dirent *ent = NULL, *fdent = NULL;
	char fddir[64] = {0}, fdpath[512] = {0}, buf[1024] = {0};

	int rc = 0, nrow = 0, ncolumn = 0;
	char **azResult = NULL;

	dirp = opendir("/proc");
	if (dirp == NULL) {
		DBG2(DBGFLAG_CONN, "update process socket information fail, open /proc error: %s\n", strerror(errno));
		return;
	}

	while ((ent = readdir(dirp))) {
		if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
			continue;  // 忽略非进程
		}
		pid = atoi(ent->d_name);

		if (pid <= 2) {
			continue;  // 忽略1号2号进程
		}
		if (is_kernel_thread(pid)) {
			continue;  // 忽略内核线程
		}

		snprintf(fddir, 64, "/proc/%d/fd", pid);
		fddirp = opendir(fddir);
		if (!fddirp) {
			continue;
		}

		while ((fdent = readdir(fddirp))) {
			char linkname[64] = {0};
			unsigned long inode = 0;

			if (fdent->d_name[0] < '0' || fdent->d_name[0] > '9') {
				continue;
			}

			snprintf(fdpath, 512, "%s/%s", fddir, fdent->d_name);

			readlink(fdpath, linkname, 63);
			if (sscanf(linkname, "socket:[%lu]", &inode) != 1) {
				continue;
			}

			snprintf(buf, 1024, "SELECT id FROM socketinfo WHERE socket='%lu';", inode);
			rc = sqlite3_get_table(conn_db, buf, &azResult, &nrow, &ncolumn, NULL);
			if (rc == SQLITE_OK) {
				if (nrow == 0) {
					sqlite3_reset(socket_new_stmt);

					sqlite3_bind_int(socket_new_stmt, 1, pid);
					sqlite3_bind_int64(socket_new_stmt, 2, inode);
					if ((sqlite3_step(socket_new_stmt)) != SQLITE_DONE) {
						DBG2(DBGFLAG_CONN, "insert new socket(pid %d, inode %lu) fail\n", pid, inode);
					}
				}
			}
			sqlite3_free_table(azResult);
		}
		closedir(fddirp);
	}
	closedir(dirp);
}

/*查找inode对应pid*/
static int inode_pid_info(unsigned long inode)
{
	//(SELECT pid FROM socketinfo where socket='%d',inode)
	sqlite3_reset(select_pid_stmt);
	sqlite3_bind_int64(select_pid_stmt, 1, inode);

	while (sqlite3_step(select_pid_stmt) == SQLITE_ROW) {
		int pid = sqlite3_column_int(select_pid_stmt, 0);
		return pid;
	}
	return -1;
}

#if 1
/* 查询ip归属地 */
const char *select_location_d(char *ip)
{
	const char *location_name = NULL;
	int ip1 = 0;
	char cat_ip1[S_IPLEN] = {0}, cat_ip2[S_IPLEN] = {0};

	if (!is_internet_ip(ip)) {
		return "局域网";
	}

	sscanf(ip, "%d.%*s.%*s.%*s", &ip1);  // 解析出要查询ip的第一段数字

	if (ip1 == 214 || ip1 == 215) {
		location_name = "美国";
		return location_name;
	}
	// printf("%s\n", ip);
	if (location_db) {
		sqlite3_reset(location_select_stmt);
		sqlite3_bind_int(location_select_stmt, 1, ip1);
		while (sqlite3_step(location_select_stmt) == SQLITE_ROW) {
			int ip_2 = sqlite3_column_int(location_select_stmt, 0);
			int ip_3 = sqlite3_column_int(location_select_stmt, 1);
			int ip_4 = sqlite3_column_int(location_select_stmt, 2);
			int ip_6 = sqlite3_column_int(location_select_stmt, 3);
			int ip_7 = sqlite3_column_int(location_select_stmt, 4);
			int ip_8 = sqlite3_column_int(location_select_stmt, 5);
			location_name = (const char *)sqlite3_column_text(location_select_stmt, 6);
			snprintf(cat_ip1, S_IPLEN, "%d.%d.%d.%d", ip1, ip_2, ip_3, ip_4);  // 将查询到的开始ip拼接
			snprintf(cat_ip2, S_IPLEN, "%d.%d.%d.%d", ip1, ip_6, ip_7, ip_8);  // 将查询到的结束ip拼接
			if (htonl(inet_addr(ip)) >= htonl(inet_addr(cat_ip1)) &&
			    htonl(inet_addr(ip)) <= htonl(inet_addr(cat_ip2))) {  // 通过转成大端无符号长整型，比较范围内的行
				return location_name;
			}
		}
	}
	return NULL;
}
#endif

/* 屏蔽客户端相关的网络连接 */
static int is_sniper(char *cmdpath)
{
	if (!cmdpath) {
		return 0;
	}

	if (strcmp(cmdpath, SNIPER_PROG) == 0) {
		return 1;
	}

	if (strcmp(cmdpath, "/usr/sbin/sniper") == 0) {
		/* 确认/sbin/sniper和/usr/sbin/sniper是同一个程序 */
		struct stat st1 = {0}, st2 = {0};
		stat(SNIPER_PROG, &st1);
		stat("/usr/sbin/sniper", &st2);
		if (st1.st_ino == st2.st_ino) {
			return 1;
		}
	}

	return 0;
}

static int is_filter_ip(char *ip)
{
	int i, j;

	if (!ip) {
		return 0;
	}

	if (client_mode_global == LEARNING_MODE) {
		return 0;
	}

	pthread_rwlock_rdlock(&rule_filter_global.lock);
	for (i = 0; i < rule_filter_global.ip_num; i++) {
		for (j = 0; j < rule_filter_global.ip[i].ip_num; j++) {
			if (check_ip_is_match(ip, rule_filter_global.ip[i].ip_list[j].list)) {
				pthread_rwlock_unlock(&rule_filter_global.lock);
				return 1;
			}
		}
	}
	pthread_rwlock_unlock(&rule_filter_global.lock);

	return 0;
}

/*检查网络连接变化*/
static void check_conn(struct info *con_inf, const char *proto, const char *state)
{
	int rc = 0, nrow = 0, ncolum = 0, id = 0;
	char **azResult = NULL;
	char buf[1024] = {0}, port_str[64];
	int pid = 0;
	char comm[64] = {0}, uuid[64] = {0}, cmd[S_CMDLEN] = {0};
	unsigned long event_time = 0;
	cJSON *object = NULL, *arguments = NULL;
	char *post = NULL;
	int behavior = 0, level = 0, result = 0, direction = 0;
	taskstat_t *taskstat = NULL;
	char reply[REPLY_MAX] = {0};
	char md5[S_MD5LEN] = {0};
	char sha256[S_SHALEN] = {0};

	if (!con_inf || !proto || !state) {
		return;
	}

	event_time = (conchktv.tv_sec + serv_timeoff) * 1000 + (int)conchktv.tv_usec / 1000;

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	snprintf(buf, sizeof(buf), "SELECT id FROM conninfo WHERE inode='%lu';", con_inf->inode);

	rc = sqlite3_get_table(conn_db, buf, &azResult, &nrow, &ncolum, NULL);

	if (rc != SQLITE_OK) {
		sqlite3_free_table(azResult);
		return;
	}

	if (nrow != 0) {  // 老的连接
		id = atoi(azResult[ncolum]);
		sqlite3_free_table(azResult);

		sqlite3_reset(conn_unchg_stmt);
		sqlite3_bind_int(conn_unchg_stmt, 1, conchktv.tv_sec);
		sqlite3_bind_int(conn_unchg_stmt, 2, id);

		if ((rc = sqlite3_step(conn_unchg_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql update unchg conn fail: %s(%d)\n", sqlite3_errstr(rc), rc);
		}
		return;
	}
	sqlite3_free_table(azResult);

	/* 新的连接 */
	new_conn_count++;  // 需要更新socket信息的进程数目加一
	DBG2(DBGFLAG_CONN, "new %s:%d -- %s:%d, inode %lu. new_conn_count %d\n",
	     con_inf->local_ip, con_inf->local_port, con_inf->rem_ip, con_inf->rem_port,
	     con_inf->inode, new_conn_count);

	// location_name = select_location_d(con_inf->rem_ip); //ip归属地由管控端解析

	pid = inode_pid_info(con_inf->inode);
	if (pid == -1) {
		DBG2(DBGFLAG_CONN, "not report this time, to report next time after process socket information updated\n");
		return;
	}
	new_conn_count--;  // 需要更新socket信息的进程数目减一

	// 获取进程的comm
	if (get_proc_comm(pid, comm) < 0) {
		return;
	}

	taskstat = get_taskstat_rdlock(pid, NETWORK_GET);

	if (taskstat) {
		if (is_sniper(taskstat->cmd)) {
			put_taskstat_unlock(taskstat);
			return;
		}
		snprintf(cmd, sizeof(cmd), "%s", taskstat->cmd);
	} else {
		// 获取进程的命令路径
		get_proc_exe(pid, cmd);

		// 屏蔽客户端相关的网络连接
		if (is_sniper(cmd)) {
			return;
		}

		// 获取md5
		if (md5_file(cmd, md5) < 0) {
			md5[0] = 'X';
			md5[1] = '\0';
		}

		// 获取sha256
		if (sha256_file(cmd, sha256) < 0) {
			sha256[0] = 'X';
			sha256[1] = '\0';
		}
	}

	// 从数据库中查询本地端口相同且为listen状态的连接，如果查到，则为连入；否则为连出
	sqlite3_reset(select_direction_stmt);
	sqlite3_bind_int(select_direction_stmt, 1, con_inf->local_port);
	while (sqlite3_step(select_direction_stmt) == SQLITE_ROW) {
		const char *state = (const char *)sqlite3_column_text(select_direction_stmt, 0);
		// printf("%d, %s\n", con_inf->rem_port, state);
		if (strcmp(state, "LISTEN") == 0) {
			direction = CONN_IN;
			break;
		}
	}

	if (direction != CONN_IN) {
		direction = CONN_OUT;
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

	// printf("New:%s  local_ip:%s  rem_ip:%s, %s, pid:%d/program name:%s\n",
	// proto, con_inf->local_ip, con_inf->rem_ip, state, pid, comm);
	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "Network");
	cJSON_AddStringToObject(object, "log_category", "Network");
	cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "Connect");
	cJSON_AddNumberToObject(object, "terminate", 0);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	if (taskstat) {
		cJSON_AddStringToObject(object, "user", taskstat->user);
		cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);
		cJSON_AddStringToObject(arguments, "process_name", safebasename(taskstat->cmd));
		cJSON_AddNumberToObject(arguments, "process_id", pid);
		cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
		cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);
		cJSON_AddStringToObject(arguments, "md5", taskstat->md5);
		cJSON_AddStringToObject(arguments, "sha256", taskstat->sha256);
		put_taskstat_unlock(taskstat);
	} else {
		cJSON_AddStringToObject(object, "user", "root");
		cJSON_AddStringToObject(arguments, "process_uuid", "");
		cJSON_AddStringToObject(arguments, "process_name", comm);
		cJSON_AddNumberToObject(arguments, "process_id", pid);
		cJSON_AddStringToObject(arguments, "process_path", cmd);
		cJSON_AddStringToObject(arguments, "process_commandline", cmd);
		cJSON_AddStringToObject(arguments, "md5", md5);
		cJSON_AddStringToObject(arguments, "sha256", sha256);
	}
	cJSON_AddNumberToObject(arguments, "thread_id", 0);

	cJSON_AddStringToObject(arguments, "protocol", proto);
	cJSON_AddStringToObject(arguments, "source_ip", con_inf->local_ip);

	// memset(port_str, 0x00, sizeof(port_str));
	snprintf(port_str, sizeof(port_str), "%d", con_inf->local_port);
	cJSON_AddStringToObject(arguments, "source_port", port_str);
	cJSON_AddStringToObject(arguments, "source_portname", "");
	cJSON_AddStringToObject(arguments, "destination_ip", con_inf->rem_ip);

	// memset(port_str, 0x00, sizeof(port_str));
	snprintf(port_str, sizeof(port_str), "%d", con_inf->rem_port);
	cJSON_AddStringToObject(arguments, "destination_port", port_str);
	cJSON_AddStringToObject(arguments, "destination_portname", "");
	cJSON_AddStringToObject(arguments, "destination_hostname", "");
	cJSON_AddNumberToObject(arguments, "direction", direction);

	cJSON_AddStringToObject(arguments, "country", "");
	cJSON_AddStringToObject(arguments, "province", "");
	cJSON_AddStringToObject(arguments, "city", "");
	cJSON_AddStringToObject(arguments, "location", "");

	if (is_internet_ip(con_inf->rem_ip) == 0) {
		cJSON_AddNumberToObject(arguments, "intranet", 1);
	} else {
		cJSON_AddNumberToObject(arguments, "intranet", 0);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);

	/* 将新增的连接存入数据库 */
	sqlite3_reset(conn_new_stmt);

	sqlite3_bind_text(conn_new_stmt, 1, con_inf->local_ip, -1, SQLITE_STATIC);
	sqlite3_bind_int(conn_new_stmt, 2, con_inf->local_port);
	sqlite3_bind_text(conn_new_stmt, 3, con_inf->rem_ip, -1, SQLITE_STATIC);
	sqlite3_bind_int(conn_new_stmt, 4, con_inf->rem_port);
	sqlite3_bind_int(conn_new_stmt, 5, con_inf->uid);
	sqlite3_bind_int(conn_new_stmt, 6, con_inf->inode);
	sqlite3_bind_text(conn_new_stmt, 7, comm, -1, SQLITE_STATIC);
	sqlite3_bind_text(conn_new_stmt, 8, proto, -1, SQLITE_STATIC);
	sqlite3_bind_text(conn_new_stmt, 9, cmd, -1, SQLITE_STATIC);
	sqlite3_bind_int(conn_new_stmt, 10, pid);
	sqlite3_bind_int(conn_new_stmt, 11, conchktv.tv_sec);
	sqlite3_bind_text(conn_new_stmt, 12, state, -1, SQLITE_STATIC);
	sqlite3_bind_int(conn_new_stmt, 13, direction);

	if ((rc = sqlite3_step(conn_new_stmt)) != SQLITE_DONE) {
		printf("sql insert new conn fail\n");
		DBG2(DBGFLAG_CONN, "insert new conn (%s:%d -- %s:%d, inode %lu) fail: %s(%d)\n",
		     con_inf->local_ip, con_inf->local_port, con_inf->rem_ip, con_inf->rem_port,
		     con_inf->inode, sqlite3_errstr(rc), rc);
	}

	/* 不报告监听端口，和本机内部的网络连接 */
	if (strcmp(con_inf->rem_ip, "0.0.0.0") == 0 || strcmp(con_inf->rem_ip, "127.0.0.1") == 0) {
		cJSON_Delete(object);
		return;
	}

	/* 匹配过滤的动作放在操作数据库之后，防止过滤时有一条连接，取消过滤后断开连接无日志 */
	if (is_filter_ip(con_inf->rem_ip)) {
		return;
	}

	post = cJSON_PrintUnformatted(object);

	cJSON_Delete(object);

	if (post) {
		client_send_msg(post, reply, sizeof(reply), LOG_URL, "selfcheck");
		DBG2(DBGFLAG_CONN, "新增网络连接---%s\n", post);
		free(post);
	} else {
		DBG2(DBGFLAG_CONN, "report new conn (%s:%d -- %s:%d, inode %lu) fail, no memory\n",
		     con_inf->local_ip, con_inf->local_port, con_inf->rem_ip, con_inf->rem_port, con_inf->inode);
	}
}

/* 从/proc/net/[tcp/tcp6/udp/udp6]获取网络连接信息 */
static void ipv(const char *filename, const char *label)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	fp = fopen(filename, "r");
	if (!fp) {
		return;
	}

	fgets(line, S_LINELEN, fp);
	while (fgets(line, S_LINELEN, fp)) {
		sockinfo_t sockinfo = {0};
		struct info con_inf = {0};
		char *state = NULL;

		if (get_socket_info(line, &sockinfo) < 0) {
			continue;
		}

		if (strcmp(sockinfo.dst_ip, Serv_conf.ip) == 0) {
			if (sockinfo.dst_port == Serv_conf.port || sockinfo.dst_port == 8000) {
				continue;  // 忽略客户端与管控的连接
			}
		} else if (strcmp(sockinfo.dst_ip, "127.0.0.1") == 0) {
			continue;  // 忽略本机内部连接
		}

		state = socket_state[sockinfo.state];
		if (strcmp(state, "ESTABLISHED") != 0 && strcmp(state, "LISTEN") != 0 && strcmp(state, "CLOSED") != 0) {
			continue;
		}

		strncpy(con_inf.local_ip, sockinfo.src_ip, 63);
		strncpy(con_inf.rem_ip, sockinfo.dst_ip, 63);
		con_inf.local_port = sockinfo.src_port;
		con_inf.rem_port = sockinfo.dst_port;
		con_inf.inode = sockinfo.inode;
		con_inf.uid = sockinfo.uid;

		check_conn(&con_inf, label, state);
	}

	fclose(fp);
}

static void check_del_conn(void)
{
	int rc = 0;
	cJSON *object = NULL, *arguments = NULL;
	taskstat_t *taskstat = NULL;
	char uuid[64] = {0}, comm[64] = {0}, cmdpath[256] = {0}, rem_ip[64] = {0};
	char reply[REPLY_MAX] = {0}, port_str[64] = {0};
	char *post = NULL;
	unsigned long event_time = 0;

	event_time = (conchktv.tv_sec + serv_timeoff) * 1000 + (int)conchktv.tv_usec / 1000;

	sqlite3_reset(conn_sdel_stmt);
	sqlite3_bind_int(conn_sdel_stmt, 1, conchktv.tv_sec);
	while (sqlite3_step(conn_sdel_stmt) == SQLITE_ROW) {
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

		int id = sqlite3_column_int(conn_sdel_stmt, 0);
		const char *local_ip = (const char *)sqlite3_column_text(conn_sdel_stmt, 1);
		const char *rem_ip2 = (const char *)sqlite3_column_text(conn_sdel_stmt, 2);
		const char *comm2 = (const char *)sqlite3_column_text(conn_sdel_stmt, 3);
		const char *proto = (const char *)sqlite3_column_text(conn_sdel_stmt, 4);
		int pid = sqlite3_column_int(conn_sdel_stmt, 5);
		int local_port = sqlite3_column_int(conn_sdel_stmt, 6);
		int rem_port = sqlite3_column_int(conn_sdel_stmt, 7);
		const char *cmdpath2 = (const char *)sqlite3_column_text(conn_sdel_stmt, 8);
		int direction = sqlite3_column_int(conn_sdel_stmt, 9);

		/* 此处是为了消除编译警告，cmdpath2是const char *类型，直接当char *用，编译会警告 */
		strncpy(comm, comm2, 63);
		strncpy(cmdpath, cmdpath2, 255);
		strncpy(rem_ip, rem_ip2, 63);

		/* 不报告断开连接日志，只删数据库条目 */
		if (strcmp(rem_ip, "0.0.0.0") == 0 || strcmp(rem_ip, "127.0.0.1") == 0 || is_filter_ip(rem_ip)) {
			cJSON_Delete(object);
			cJSON_Delete(arguments);
			goto do_del;
		}

		if (is_sniper(cmdpath)) {
			cJSON_Delete(object);
			cJSON_Delete(arguments);
			goto do_del;
		}

		cJSON_AddStringToObject(object, "id", uuid);
		cJSON_AddStringToObject(object, "log_name", "Network");
		cJSON_AddStringToObject(object, "log_category", "Network");
		cJSON_AddBoolToObject(object, "event", false);
		cJSON_AddStringToObject(object, "event_category", "");
		cJSON_AddNumberToObject(object, "level", 0);
		cJSON_AddNumberToObject(object, "behavior", 0);
		cJSON_AddNumberToObject(object, "result", 0);
		cJSON_AddStringToObject(object, "operating", "Terminated");
		cJSON_AddNumberToObject(object, "terminate", 0);
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

		taskstat = get_taskstat_rdlock(pid, NETWORK_GET);
		if (taskstat) {
			cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);
			cJSON_AddStringToObject(arguments, "process_name", safebasename(taskstat->cmd));
			cJSON_AddNumberToObject(arguments, "process_id", pid);
			cJSON_AddNumberToObject(arguments, "thread_id", taskstat->gid);
			cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
			cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);

			cJSON_AddStringToObject(arguments, "md5", taskstat->md5);
			cJSON_AddStringToObject(arguments, "sha256", taskstat->sha256);
			put_taskstat_unlock(taskstat);
		} else {
			char md5[256] = {0};
			if (md5_file(cmdpath, md5) < 0) {
				md5[0] = 'X';
				md5[1] = '\0';
			}

			char sha256[256] = {0};
			if (sha256_file(cmdpath, sha256) < 0) {
				sha256[0] = 'X';
				sha256[1] = '\0';
			}

			cJSON_AddStringToObject(arguments, "process_uuid", "");
			cJSON_AddStringToObject(arguments, "process_name", comm);
			cJSON_AddNumberToObject(arguments, "process_id", pid);
			cJSON_AddNumberToObject(arguments, "thread_id", 0);
			cJSON_AddStringToObject(arguments, "process_path", cmdpath);
			cJSON_AddStringToObject(arguments, "process_commandline", cmdpath);

			cJSON_AddStringToObject(arguments, "md5", md5);
			cJSON_AddStringToObject(arguments, "sha256", sha256);
		}

		cJSON_AddStringToObject(arguments, "protocol", proto);
		cJSON_AddStringToObject(arguments, "source_ip", local_ip);

		snprintf(port_str, sizeof(port_str), "%d", local_port);
		cJSON_AddStringToObject(arguments, "source_port", port_str);
		cJSON_AddStringToObject(arguments, "source_portname", "");
		cJSON_AddStringToObject(arguments, "destination_ip", rem_ip);

		snprintf(port_str, sizeof(port_str), "%d", rem_port);
		cJSON_AddStringToObject(arguments, "destination_port", port_str);
		cJSON_AddStringToObject(arguments, "destination_portname", "");
		cJSON_AddStringToObject(arguments, "destination_hostname", "");
		cJSON_AddNumberToObject(arguments, "direction", direction);

		cJSON_AddStringToObject(arguments, "country", "");
		cJSON_AddStringToObject(arguments, "province", "");
		cJSON_AddStringToObject(arguments, "city", "");
		cJSON_AddStringToObject(arguments, "location", "");

		if (is_internet_ip(rem_ip) == 0) {
			cJSON_AddNumberToObject(arguments, "intranet", 1);
		} else {
			cJSON_AddNumberToObject(arguments, "intranet", 0);
		}

		cJSON_AddItemToObject(object, "arguments", arguments);

		post = cJSON_PrintUnformatted(object);

		cJSON_Delete(object);

		if (post) {
			client_send_msg(post, reply, sizeof(reply), LOG_URL, "selfcheck");
			DBG2(DBGFLAG_CONN, "断开网络连接---%s\n", post);
			free(post);
		} else {
			DBG2(DBGFLAG_CONN, "report closed conn (%s:%d -- %s:%d, %d/%s) fail, no memory\n",
			     local_ip, local_port, rem_ip, rem_port, pid, comm);
		}

	do_del:
		sqlite3_reset(conn_del_stmt);
		sqlite3_bind_int(conn_del_stmt, 1, id);

		if ((rc = sqlite3_step(conn_del_stmt)) != SQLITE_DONE) {
			MON_ERROR("sql delete closed conn (%s:%d -- %s:%d, %d/%s) fail: %s(%d)\n",
				  local_ip, local_port, rem_ip, rem_port, pid, comm, sqlite3_errstr(rc), rc);
		}
	}
}

void check_conn_status(void)
{
	if (!conn_db) {
		conn_db_init();
	}

	if (!conn_db) {
		return;
	}

	gettimeofday(&conchktv, NULL);
	new_conn_count = 0;

	sqlite3_exec(conn_db, "BEGIN;", 0, 0, 0);

	ipv("/proc/net/tcp", "tcp");
	ipv("/proc/net/tcp6", "tcp6");
	ipv("/proc/net/udp", "udp");
	ipv("/proc/net/udp6", "udp6");

	sqlite3_exec(conn_db, "COMMIT;", 0, 0, NULL);

	DBG2(DBGFLAG_CONN, "check deleted conn\n");
	check_del_conn();

	/* 每次都遍历所有进程的socket号开销大，仅当有新增网络连接时，才去获取 */
	if (new_conn_count) {
		DBG2(DBGFLAG_CONN, "update process socket information\n");
		socket_pid_info();
		new_conn_count = 0;
	}
}
