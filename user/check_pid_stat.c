#include "header.h"

int count_pid_cpu = 0, count_pid_mem = 0;

sqlite3 *cpu_db = NULL;

/* sql statements */
sqlite3_stmt *cpu_new_stmt = NULL;
sqlite3_stmt *cpu_chg_stmt = NULL;
sqlite3_stmt *select_cpu_stmt = NULL;

sqlite3_stmt *pid_cpu_new_stmt = NULL;
sqlite3_stmt *pid_mem_new_stmt = NULL;
sqlite3_stmt *pid_cpu_chg_stmt = NULL;
sqlite3_stmt *pid_mem_chg_stmt = NULL;
sqlite3_stmt *res_del_stmt = NULL;
sqlite3_stmt *mem_del_stmt = NULL;

sqlite3_stmt *select_highcpu_stmt = NULL;
sqlite3_stmt *select_highmem_stmt = NULL;

sqlite3_stmt *reset_cpu_count_stmt = NULL;
sqlite3_stmt *reset_mem_count_stmt = NULL;

/* 初始化数据库环境 */
static void cpu_db_init(void)
{
	int rc = 0;
	char path[128] = {0};

	char *creat_cpuinfo_tbl_sql = {
	    "CREATE TABLE IF NOT EXISTS cpuinfo( "
	    "id integer PRIMARY KEY AUTOINCREMENT,"
	    "pid int UNIQUE,"
	    "proc_time int,"
	    "total_time int);"};

	char *creat_cpu_count_tbl_sql = {
	    "CREATE TABLE IF NOT EXISTS cpuoverrun( "
	    "id integer PRIMARY KEY AUTOINCREMENT,"
	    "pid int UNIQUE,"
	    "cpu_usage int,"
	    "cpu_count int);"};

	char *creat_mem_count_tbl_sql = {
	    "CREATE TABLE IF NOT EXISTS memoverrun( "
	    "id integer PRIMARY KEY AUTOINCREMENT,"
	    "pid int UNIQUE,"
	    "mem_usage int,"
	    "mem_count int);"};

	char *cpu_new_sql = "INSERT INTO cpuinfo VALUES(NULL,?,?,?);";
	char *cpu_chg_sql = "UPDATE cpuinfo SET proc_time=?,total_time=? WHERE pid=?;";
	char *select_cpu_sql = "SELECT proc_time,total_time FROM cpuinfo WHERE pid=?;";

	char *pid_cpu_new_sql = "INSERT INTO cpuoverrun VALUES(NULL,?,?,?);";
	char *pid_mem_new_sql = "INSERT INTO memoverrun VALUES(NULL,?,?,?);";

	char *pid_cpu_chg_sql = "UPDATE cpuoverrun SET cpu_usage=?,cpu_count=? WHERE pid=?;";
	char *pid_mem_chg_sql = "UPDATE memoverrun SET mem_usage=?,mem_count=? WHERE pid=?;";
	char *pid_del_sql = "DELETE FROM cpuoverrun WHERE pid=?;";
	char *mem_del_sql = "DELETE FROM memoverrun WHERE pid=?;";

	char *select_highcpu_sql = "SELECT pid,cpu_usage FROM cpuoverrun WHERE cpu_count=?;";
	char *select_highmem_sql = "SELECT pid,mem_usage FROM memoverrun WHERE mem_count=?;";

	char *reset_cpu_count_sql = "UPDATE cpuoverrun SET cpu_count = 0;";
	char *reset_mem_count_sql = "UPDATE memoverrun SET mem_count = 0;";

	/* 如果数据库目录不存在，创建数据库目录 */
	snprintf(path, sizeof(path), "%s/%s", WORKDIR, DBDIR);
	if (access(path, F_OK) != 0) {
		mkdir(path, 0700);
	}

	/* 打开进程cpu时间数据库，创建cpu时间表 */
	snprintf(path, sizeof(path), "%s/%s/cpu_time.db", WORKDIR, DBDIR);
	cpu_db = connectDb(path, creat_cpuinfo_tbl_sql, NULL, &rc);

	if (!cpu_db) {
		return;
	}

	/* 创建资源信息表 */
	rc = sqlite3_exec(cpu_db, creat_cpu_count_tbl_sql, NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		sqlite3_close_v2(cpu_db);
		cpu_db = NULL;
		return;
	}

	rc = sqlite3_exec(cpu_db, creat_mem_count_tbl_sql, NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		sqlite3_close_v2(cpu_db);
		cpu_db = NULL;
		return;
	}

	sqlite3_busy_handler(cpu_db, db_busy_callback, NULL);
	sqlite3_prepare_v2(cpu_db, cpu_new_sql, -1, &cpu_new_stmt, NULL);
	sqlite3_prepare_v2(cpu_db, cpu_chg_sql, -1, &cpu_chg_stmt, NULL);
	sqlite3_prepare_v2(cpu_db, select_cpu_sql, -1, &select_cpu_stmt, NULL);

	sqlite3_prepare_v2(cpu_db, pid_cpu_new_sql, -1, &pid_cpu_new_stmt, NULL);
	sqlite3_prepare_v2(cpu_db, pid_mem_new_sql, -1, &pid_mem_new_stmt, NULL);

	sqlite3_prepare_v2(cpu_db, pid_cpu_chg_sql, -1, &pid_cpu_chg_stmt, NULL);
	sqlite3_prepare_v2(cpu_db, pid_mem_chg_sql, -1, &pid_mem_chg_stmt, NULL);
	sqlite3_prepare_v2(cpu_db, pid_del_sql, -1, &res_del_stmt, NULL);
	sqlite3_prepare_v2(cpu_db, mem_del_sql, -1, &mem_del_stmt, NULL);

	sqlite3_prepare_v2(cpu_db, select_highcpu_sql, -1, &select_highcpu_stmt,
			   NULL);
	sqlite3_prepare_v2(cpu_db, select_highmem_sql, -1, &select_highmem_stmt,
			   NULL);

	sqlite3_prepare_v2(cpu_db, reset_cpu_count_sql, -1, &reset_cpu_count_stmt,
			   NULL);
	sqlite3_prepare_v2(cpu_db, reset_mem_count_sql, -1, &reset_mem_count_stmt,
			   NULL);
}

/* 释放数据库环境 */
void cpu_db_release(void)
{
	if (cpu_db == NULL) {
		return;
	}

	sqlite3_finalize(cpu_new_stmt);
	sqlite3_finalize(cpu_chg_stmt);
	sqlite3_finalize(select_cpu_stmt);

	sqlite3_finalize(pid_cpu_new_stmt);
	sqlite3_finalize(pid_mem_new_stmt);

	sqlite3_finalize(pid_cpu_chg_stmt);
	sqlite3_finalize(pid_mem_chg_stmt);
	sqlite3_finalize(res_del_stmt);

	sqlite3_finalize(select_highcpu_stmt);
	sqlite3_finalize(select_highmem_stmt);

	sqlite3_finalize(reset_cpu_count_stmt);
	sqlite3_finalize(reset_mem_count_stmt);

	sqlite3_close_v2(cpu_db);
}

/* 系统CPU时间=user+nice+system+idle+iowait+irq+softirq+stolen */
unsigned long get_total_cpu(void)
{
	int ret = 0;
	FILE *fp = NULL;
	unsigned long user = 0, nice = 0, system = 0, idle = 0;
	unsigned long iowait = 0, irq = 0, softirq = 0, stolen = 0;

	fp = fopen("/proc/stat", "r");
	if (fp) {
		ret = fscanf(fp, "%*s %lu %lu %lu %lu %lu %lu %lu %lu", &user, &nice,
			     &system, &idle, &iowait, &irq, &softirq, &stolen);
		fclose(fp);
	}

	if (ret < 4) {
		return 0;
	}
	return (user + nice + system + idle + iowait + irq + softirq + stolen);
}

/*
 * 进程CPU时间=进程user+进程system+子进程user+子进程system
 *
 * 进程不wait子进程结束，子进程的CPU时间不会算到进程的cutime和cstime里
 *
 * 子进程退出的时候，子进程的utime和stime才会算到cutime和cstime里
 * 进程的CPU时间可能突然暴涨，比如子进程运行了1小时，但子进程结束时，这1小时的开销才算到父进程头上
 * 检测进程CPU开销，是连续检测一段时间，如10分钟，而不是检测到一次高峰就报，所以不会误报
 */
unsigned long get_process_cpu(pid_t pid)
{
	int ret = 0;
	FILE *fp = NULL;
	char path[128] = {0}, line[S_LINELEN] = {0}, *ptr = NULL;
	unsigned long utime = 0, stime = 0, cutime = 0, cstime = 0;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fp = fopen(path, "r");
	if (fp) {
		fgets(line, sizeof(line), fp);
		fclose(fp);

		/* 下面的处理方法考虑了进程名是(xxx yyy)的情况 */
		ptr = strrchr(line, ')');
		if (ptr) {
			ptr += 2;
			ret = sscanf(
			    ptr, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu %lu %lu",
			    &utime, &stime, &cutime, &cstime);
		}
	}

	if (ret < 4) {
		return 0;
	}
	return (utime + stime + cutime + cstime);
}

/* 获取第一个时刻的CPU占用率 */
static void get_proc_cpu_loop1(pid_t pid)
{
	int rc = 0, nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	char buf[1024] = {0};
	unsigned long proc_time = 0, total_time = 0;

	proc_time = get_process_cpu(pid);  // 获取进程cpu时间
	total_time = get_total_cpu();	   // 获取系统cpu时间

	snprintf(buf, sizeof(buf), "SELECT * FROM cpuinfo WHERE pid='%d';", pid);
	rc = sqlite3_get_table(cpu_db, buf, &azResult, &nrow, &ncolumn, NULL);

	if (rc == SQLITE_OK) {
		if (nrow == 0) {  // 数据库中无此pid的记录，插入新记录
			sqlite3_reset(cpu_new_stmt);
			sqlite3_bind_int(cpu_new_stmt, 1, pid);
			sqlite3_bind_int(cpu_new_stmt, 2, proc_time);
			sqlite3_bind_int(cpu_new_stmt, 3, total_time);

			if ((rc = sqlite3_step(cpu_new_stmt)) != SQLITE_DONE) {
				DBG2(DBGFLAG_RESCHECK, "sql insert %d cpu time fail: %s(%d)\n", pid,
				     sqlite3_errstr(rc), rc);
			}
		} else {  // 数据库中有此pid的记录，修改老记录
			sqlite3_reset(cpu_chg_stmt);
			sqlite3_bind_int(cpu_chg_stmt, 1, pid);
			sqlite3_bind_int(cpu_chg_stmt, 2, proc_time);
			sqlite3_bind_int(cpu_chg_stmt, 3, total_time);
			if ((rc = sqlite3_step(cpu_chg_stmt)) != SQLITE_DONE) {
				DBG2(DBGFLAG_RESCHECK, "sql update %d cpu time fail: %s(%d)\n", pid,
				     sqlite3_errstr(rc), rc);
			}
		}
	}

	sqlite3_free_table(azResult);
}

/*
 * 通过pid查询数据库中与之对应的第一个时刻的cpu使用率
 * 获取第二个时刻进程和系统的cpu时间，与第一个时刻的cpu使用率计算获得pid的使用率
 * 返回结果pcpu为float型
 */
static float get_proc_cpu_loop2(pid_t pid)
{
	float pcpu = 0.0;
	unsigned long proc_time = 0, total_time = 0;
	unsigned long prev_proc_time = 0, prev_total_time = 0;

	proc_time = get_process_cpu(pid);  // 获取进程cpu时间
	total_time = get_total_cpu();	   // 获取系统cpu时间

	sqlite3_reset(select_cpu_stmt);
	sqlite3_bind_int(select_cpu_stmt, 1, pid);

	/*
	 * sqlite3_step的返回值是SQLITE_ROW或SQLITE_DONE，不会返回SQLITE_OK
	 * SQLITE_ROW， 表示当前的statement中包含一行的结果数据
	 * SQLITE_DONE，表示已经遍历完成了所有结果集的行
	 *
	 * pid是unique唯一的，只有一个结果，因此这里不用while
	 */
	if (sqlite3_step(select_cpu_stmt) == SQLITE_ROW) {
		prev_proc_time = sqlite3_column_int(select_cpu_stmt, 0);
		prev_total_time = sqlite3_column_int(select_cpu_stmt, 1);

		if (total_time != prev_total_time) {
			pcpu =
			    100.0 * (proc_time - prev_proc_time) / (total_time - prev_total_time);
			pcpu = pcpu * Sys_info.cpu_count;
		}
	}

	return pcpu;
}

/* 获取进程占用内存，单位KB */
unsigned long get_proc_mem(pid_t pid)
{
	unsigned long vmrss = 0;
	char path[128] = {0}, line[S_LINELEN] = {0};
	FILE *fp = NULL;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);

	fp = fopen(path, "r");
	if (!fp) {
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "VmRSS: %lu", &vmrss) == 1) {
			break;
		}
	}

	fclose(fp);

	return vmrss;
}

/* 发送进程cpu超限日志 */
static void send_pid_cpu_overload(int cpu_pid, int cpu_usage)
{
	struct timeval tv = {0};
	char *post = NULL, reply[REPLY_MAX] = {0}, uuid[S_UUIDLEN] = {0};
	unsigned long event_time = 0;
	cJSON *object = NULL, *arguments = NULL;
	taskstat_t *taskstat = NULL, tmp_taskstat = {0};

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
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ProcessHighCpuUsage");
	cJSON_AddStringToObject(object, "log_category", "SystemResource");
	cJSON_AddBoolToObject(object, "event", true);
	cJSON_AddStringToObject(object, "event_category", "SystemMonitor");
	cJSON_AddNumberToObject(object, "level", MY_LOG_LOW_RISK);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
	cJSON_AddNumberToObject(object, "result", 0);
	cJSON_AddStringToObject(object, "operating", "");
	cJSON_AddNumberToObject(object, "terminate", 1);
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

	if (cpu_usage) {
		cJSON_AddNumberToObject(arguments, "cpu", cpu_usage);
	}

	cJSON_AddNumberToObject(arguments, "cpu_threshold",
				fasten_policy_global.resource.process.cpu.limit);
	cJSON_AddBoolToObject(arguments, "cpu_overload", true);
	cJSON_AddNumberToObject(arguments, "cpu_overload_duration",
				fasten_policy_global.resource.process.cpu.interval);

	taskstat = get_taskstat_rdlock(cpu_pid, PROCESS_GET);

	if (!taskstat) {
		/* 没取到进程的缓存信息，手工取 */
		taskstat = &tmp_taskstat;
		taskstat->pid = cpu_pid;
		get_proc_stat(taskstat);
		get_proc_exe(cpu_pid, taskstat->cmd);
		taskstat->cmdlen = strlen(taskstat->cmd);
		get_proc_cmdline(cpu_pid, taskstat->args, S_ARGSLEN);
		if (taskstat->args[0] == 0) {  // 没取到命令行，用命令替代
			snprintf(taskstat->args, sizeof(taskstat->args), "%s", taskstat->cmd);
		}
		taskstat->argslen = strlen(taskstat->args);
		set_taskuuid(taskstat->uuid, taskstat->proctime, taskstat->pid, 0);
		uidtoname(taskstat->uid, taskstat->user);
	}

	cJSON_AddStringToObject(object, "user", taskstat->user);

	cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);
	cJSON_AddNumberToObject(arguments, "process_id", cpu_pid);
	cJSON_AddStringToObject(arguments, "process_name",
				safebasename(taskstat->cmd));
	cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
	cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);

	if (taskstat != &tmp_taskstat) {
		put_taskstat_unlock(taskstat);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);
	post = cJSON_PrintUnformatted(object);
	if (post) {
		client_send_msg(post, reply, sizeof(reply), LOG_URL, "selfcheck");
		cJSON_Delete(object);
		free(post);
	}
}

/* 发送进程内存超限日志 */
static void send_pid_mem_overload(int mem_pid, int mem_usage)
{
	struct timeval tv = {0};
	char *post = NULL, reply[REPLY_MAX] = {0}, uuid[S_UUIDLEN] = {0};
	unsigned long event_time = 0;
	cJSON *object = NULL, *arguments = NULL;
	taskstat_t *taskstat = NULL, tmp_taskstat = {0};

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
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ProcessHighMemoryUsage");
	cJSON_AddStringToObject(object, "log_category", "SystemResource");
	cJSON_AddBoolToObject(object, "event", true);
	cJSON_AddStringToObject(object, "event_category", "SystemMonitor");
	cJSON_AddNumberToObject(object, "level", MY_LOG_LOW_RISK);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
	cJSON_AddNumberToObject(object, "result", 0);
	cJSON_AddStringToObject(object, "operating", "");
	cJSON_AddNumberToObject(object, "terminate", 1);
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

	cJSON_AddNumberToObject(arguments, "memory", mem_usage);
	cJSON_AddNumberToObject(arguments, "memory_threshold",
				fasten_policy_global.resource.process.memory.limit);
	cJSON_AddBoolToObject(arguments, "memory_overload", true);
	cJSON_AddNumberToObject(
	    arguments, "memory_overload_duration",
	    fasten_policy_global.resource.process.memory.interval);

	taskstat = get_taskstat_rdlock(mem_pid, PROCESS_GET);

	if (!taskstat) {
		/* 没取到进程的缓存信息，手工取 */
		taskstat = &tmp_taskstat;
		taskstat->pid = mem_pid;
		get_proc_stat(taskstat);
		get_proc_exe(mem_pid, taskstat->cmd);
		taskstat->cmdlen = strlen(taskstat->cmd);
		get_proc_cmdline(mem_pid, taskstat->args, S_ARGSLEN);
		if (taskstat->args[0] == 0) {  // 没取到命令行，用命令替代
			snprintf(taskstat->args, sizeof(taskstat->args), "%s", taskstat->cmd);
		}
		taskstat->argslen = strlen(taskstat->args);
		set_taskuuid(taskstat->uuid, taskstat->proctime, taskstat->pid, 0);
		uidtoname(taskstat->uid, taskstat->user);
	}

	cJSON_AddStringToObject(object, "user", taskstat->user);

	cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);
	cJSON_AddNumberToObject(arguments, "process_id", mem_pid);
	cJSON_AddStringToObject(arguments, "process_name",
				safebasename(taskstat->cmd));
	cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
	cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);

	if (taskstat != &tmp_taskstat) {
		put_taskstat_unlock(taskstat);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);
	post = cJSON_PrintUnformatted(object);
	if (post) {
		client_send_msg(post, reply, sizeof(reply), LOG_URL, "selfcheck");
		cJSON_Delete(object);
		free(post);
	}
}

/* 获取主机总内存大小，单位KB */
static unsigned long get_total_mem(void)
{
	unsigned long total = 0;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	fp = fopen("/proc/meminfo", "r");
	if (fp == NULL) {
		MON_ERROR("get_total_mem fail, open /proc/meminfo error: %s\n",
			  strerror(errno));
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "MemTotal: %lu", &total) == 1) {
			break;
		}
	}
	fclose(fp);

	return total;
}

static void record_cpu_overrun(int pid, int cpu)
{
	char buf[1024] = {0};
	int rc = 0, nrow = 0, ncolum = 0;
	char **azResult = NULL;
	int cpu_limit = 0;

	cpu_limit = fasten_policy_global.resource.process.cpu.limit;

	snprintf(buf, sizeof(buf),
		 "SELECT id,cpu_count FROM cpuoverrun WHERE pid='%d';", pid);
	rc = sqlite3_get_table(cpu_db, buf, &azResult, &nrow, &ncolum, NULL);
	if (rc == SQLITE_OK) {
		if (nrow == 0) {  // 记录新超限的进程
			sqlite3_reset(pid_cpu_new_stmt);

			sqlite3_bind_int(pid_cpu_new_stmt, 1, pid);
			sqlite3_bind_int(pid_cpu_new_stmt, 2, cpu);
			if (cpu > cpu_limit) {
				sqlite3_bind_int(pid_cpu_new_stmt, 3, 1);
			} else {
				sqlite3_bind_int(pid_cpu_new_stmt, 3, 0);
			}

			sqlite3_step(pid_cpu_new_stmt);
		} else {  // 更新已超限进程的超限次数
			int cpu_count = atoi(azResult[ncolum + 1]);

			sqlite3_reset(pid_cpu_chg_stmt);
			sqlite3_bind_int(pid_cpu_chg_stmt, 1, cpu);
			if (cpu > cpu_limit) {
				sqlite3_bind_int(pid_cpu_chg_stmt, 2, cpu_count + 1);
			} else {
				sqlite3_bind_int(pid_cpu_chg_stmt, 2, cpu_count);
			}

			sqlite3_bind_int(pid_cpu_chg_stmt, 3, pid);

			sqlite3_step(pid_cpu_chg_stmt);
		}
	}
	sqlite3_free_table(azResult);
}

static void record_memory_overrun(int pid, int mem)
{
	char buf[1024] = {0};
	char **azResult = NULL;
	int rc = 0, nrow = 0, ncolum = 0;
	int mem_limit = fasten_policy_global.resource.process.memory.limit;

	snprintf(buf, sizeof(buf),
		 "SELECT id,mem_count FROM memoverrun WHERE pid='%d';", pid);
	rc = sqlite3_get_table(cpu_db, buf, &azResult, &nrow, &ncolum, NULL);
	if (rc == SQLITE_OK) {
		if (nrow == 0) {  // 记录新超限的进程
			sqlite3_reset(pid_mem_new_stmt);

			sqlite3_bind_int(pid_mem_new_stmt, 1, pid);
			sqlite3_bind_int(pid_mem_new_stmt, 2, mem);
			if (mem > mem_limit) {
				sqlite3_bind_int(pid_mem_new_stmt, 3, 1);
			} else {
				sqlite3_bind_int(pid_mem_new_stmt, 3, 0);
			}

			sqlite3_step(pid_mem_new_stmt);
		} else {  // 更新已超限进程的超限次数
			int mem_count = atoi(azResult[ncolum + 1]);

			sqlite3_reset(pid_mem_chg_stmt);
			sqlite3_bind_int(pid_mem_chg_stmt, 1, mem);
			if (mem > mem_limit) {
				sqlite3_bind_int(pid_mem_chg_stmt, 2, mem_count + 1);
			} else {
				sqlite3_bind_int(pid_mem_chg_stmt, 2, mem_count);
			}

			sqlite3_bind_int(pid_mem_chg_stmt, 3, pid);

			sqlite3_step(pid_mem_chg_stmt);
		}
	}
	sqlite3_free_table(azResult);
}

static void proc_pid_info(int mem_flag, int cpu_flag)
{
	DIR *dir = NULL;
	unsigned long num;
	struct dirent *pident = NULL;
	int pid = 0;
	int cpu_limit = 0, mem_limit = 0;
	float cpu_precent = 0;

	cpu_limit = fasten_policy_global.resource.process.cpu.limit;
	mem_limit = fasten_policy_global.resource.process.memory.limit;

	dir = opendir("/proc");
	if (dir == NULL) {
		printf("check_pid_status: Open dir /proc fail!");
		return;
	}

	/* 事务处理，提高大量数据库操作的效率 */
	sqlite3_exec(cpu_db, "BEGIN;", 0, 0, 0);

	while ((pident = readdir(dir))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue;  // 忽略非进程
		}
		pid = atoi(pident->d_name);

		if (pid <= 0) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue;  // 忽略内核线程
		}

		if (mem_flag) {
			unsigned long mem_total = get_total_mem();
			num = get_proc_mem(pid);
			double mem_precent = (double)num / mem_total * 100.0;

			if (mem_precent > mem_limit) {
				record_memory_overrun(pid, (int)mem_precent);
			} else {
				sqlite3_reset(mem_del_stmt);
				sqlite3_bind_int(mem_del_stmt, 1, pid);
				sqlite3_step(mem_del_stmt);
			}
			continue;
		}

		if (cpu_flag) {
			get_proc_cpu_loop1(pid);
		} else {
			cpu_precent = get_proc_cpu_loop2(pid);

			if (cpu_precent > cpu_limit) {
				record_cpu_overrun(pid, (int)cpu_precent);
			} else {
				/*
				 * 如果cpu和内存都没超限，从数据库中删除此进程的记录
				 * 虽然有很多无效的删除动作，比如进程本来就不在数据库中
				 * 但这么做可以简单地就防止了数据库变得较大
				 */
				sqlite3_reset(res_del_stmt);
				sqlite3_bind_int(res_del_stmt, 1, pid);
				sqlite3_step(res_del_stmt);
			}
		}
	}

	sqlite3_exec(cpu_db, "COMMIT;", 0, 0, 0);
	closedir(dir);
}

// TODO 只统计run的进程，用时间而不是次数来判断
/*
 * 遍历所有进程process，获取每个进程的cpu和内存使用率
 * 通过pid查询数据库，如果是新的pid则插入；如果pid不变，cpu内存变化的，则change；如果查询不到，则删除pid数据行
 * 超限一次，对应pid的count+1
 */
void check_pid_status(void)
{
	char buf[1024] = {0}, tmp[1024] = {0};
	int cpu_limit = 0;
	FILE *fp = NULL;

	cpu_limit = fasten_policy_global.resource.process.cpu.limit;

	if (!cpu_db) {
		cpu_db_init();
	}
	if (!cpu_db) {
		return;
	}

	if (!fasten_policy_global.resource.process.cpu.enable) {
		goto mem;
	}

	proc_pid_info(0, 1);

	usleep(500000);

	proc_pid_info(0, 0);
	count_pid_cpu++;

	if (count_pid_cpu >= fasten_policy_global.resource.process.cpu
				 .interval) {  // 一个cpu采样周期结束
		sqlite3_reset(select_highcpu_stmt);
		sqlite3_bind_int(select_highcpu_stmt, 1, count_pid_cpu);

		while (sqlite3_step(select_highcpu_stmt) == SQLITE_ROW) {
			int cpu_pid = sqlite3_column_int(select_highcpu_stmt, 0);

			if (fasten_policy_global.resource.process.cpu.enable) {
				snprintf(tmp, 1024, "ps aux|grep %d|grep -v grep|awk '{printf $3}'",
					 cpu_pid);
				fp = popen(tmp, "r");

				if (fp) {
					fgets(buf, 1024, fp);
					pclose(fp);

					if (atof(buf) < cpu_limit) {
						continue;
					}
					DBG2(DBGFLAG_PROCESSRES, "send_pid_cpu_overload:%d, %d\n", cpu_pid, atoi(buf));
					send_pid_cpu_overload(cpu_pid, atoi(buf));
				} else {
					int cpu_usage = sqlite3_column_int(select_highcpu_stmt, 1);
					DBG2(DBGFLAG_PROCESSRES, "send_pid_cpu_overload:%d, %d\n", cpu_pid, cpu_usage);
					send_pid_cpu_overload(cpu_pid, cpu_usage);
				}
			}
		}

		count_pid_cpu = 0;
		/* 采样周期结束，清空所有曾超限进程的cpu count */
		sqlite3_step(reset_cpu_count_stmt);
	}

mem:
	if (!fasten_policy_global.resource.process.memory.enable) {
		return;
	}

	proc_pid_info(1, 0);
	count_pid_mem++;

	if (count_pid_mem >= fasten_policy_global.resource.process.memory
				 .interval) {  // 一个mem采样周期结束
		sqlite3_reset(select_highmem_stmt);
		sqlite3_bind_int(select_highmem_stmt, 1, count_pid_mem);

		while (sqlite3_step(select_highmem_stmt) == SQLITE_ROW) {
			int mem_pid = sqlite3_column_int(select_highmem_stmt, 0);
			int mem_usage = sqlite3_column_int(select_highmem_stmt, 1);
			DBG2(DBGFLAG_PROCESSRES, "send_pid_mem_overload:%d, %d\n", mem_pid, mem_usage);
			send_pid_mem_overload(mem_pid, mem_usage);
		}

		count_pid_mem = 0;
		/* 采样周期结束，清空所有曾超限进程的mem count */
		sqlite3_step(reset_mem_count_stmt);
	}
}
