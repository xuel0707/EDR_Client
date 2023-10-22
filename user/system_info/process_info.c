/*************************************************************************
    > File Name: process_info.c
    > Author: Qushb
    > Created Time: Wed 23 Dec 2020 15:57:08 PM CST
 ************************************************************************/

#include "sys_info.h"
#include "process_info.h"

#ifndef HZ
#define HZ 100
#endif

static char *sql_process = 
                "CREATE TABLE IF NOT EXISTS sys_process(Id INTERGER PRIMARY KEY, \
                                    pid   INTEGER, \
                                    name  TEXT, \
                                    user  TEXT, \
                                    path  TEXT, \
                                  cmdline TEXT, \
                                    state TEXT, \
                                  version TEXT, \
                                      pkg TEXT, \
                                      md5 TEXT, \
        /* process create time */  pctime INTEGER, \
                                   ppuser TEXT, \
                                    ppcmd TEXT, \
        /* create time */           ctime TIMESTAMP, \
        /* last check time */       ltime TIMESTAMP);";

static time_t uptime_sec = 0;
/* 取系统启动时间，参考user/sysinfo.c的get_boot_time() */
static void get_sys_boot_time(void)
{
    char boottime[64] = {0}, nowtime[64] = {0};
    struct stat st = {0};

    if (stat("/proc/1", &st) < 0) {
        time_t now = time(NULL);

        ctime_r(&now, nowtime);    //1643376605 -> "Fri Jan 28 21:30:05 2022\n"
        nowtime[63] = 0;
        delete_tailspace(nowtime); //去掉尾部的换行符

        elog("get_boot_time stat /proc/1 error: %s\n", strerror(errno));
        dlog("use now time %s(%ld) as boot time\n", nowtime, now);

        uptime_sec = now;
        return;
    }

    uptime_sec = st.st_mtime;

    ctime_r(&uptime_sec, boottime);
    boottime[63] = 0;
    delete_tailspace(boottime);

    dlog("boot at %s(%ld)\n", boottime, uptime_sec);
}

/* get_proc_stat()引用了ps的实现代码 */
static int get_proc_stat(process_t *taskstat)
{
    char path[PATH_MAX] = {0};
    char buf[PATH_MAX] = {0};
    proc_t P;
    time_t tval1 = 0;
    time_t tval2 = 0;
    FILE *fp = NULL;
    char *ptr = NULL;
    int ret = 0;

    if (!taskstat) {
        elog("get_proc_stat fail: NULL taskstat\n");
        return -1;
    }

    memset(&P, 0, sizeof(proc_t));

    snprintf(path, sizeof(path), "/proc/%d/stat", taskstat->pid);

    fp = fopen(path, "r");
    if (!fp) {
        if (errno != ENOENT) {
            elog("open %s fail: %s\n", path, strerror(errno));
        }
        return -1;
    }

    fgets(buf, sizeof(buf)-1, fp);
    /* 考虑到进程名带)的情况，倒着找) */
    ptr = strrchr(buf, ')');
    if (!ptr) {
        elog("bad %s info: %s\n", path, buf);
        fclose(fp);
        return -1;
    }

    /* 跳过头上的两项tid, cmd */
    ptr += 2;
    ret = sscanf(ptr,
        "%c "
        "%d %d %d %d %d "
        "%lu %lu %lu %lu %lu "
        "%Lu %Lu %Lu %Lu "  /* utime stime cutime cstime */
        "%ld %ld "
        "%d "
        "%lu "
        "%lu ",
        &P.state,
        &P.ppid, &P.pgrp, &P.session, &P.tty, &P.tpgid,
        &P.flags, &P.min_flt, &P.cmin_flt, &P.maj_flt, &P.cmaj_flt,
        &P.utime, &P.stime, &P.cutime, &P.cstime,
        &P.priority, &P.nice,
        &P.nlwp,
        &tval1,
        &tval2);
            
    if (ret < 20) {
        elog("bad %s info: %d\n", path, ret);
        fclose(fp);
        return -1;
    }

    /* 较新的Linux版本tval1的位置固定放了个0 */
    if (tval1 == 0) {
        P.start_time = tval2 / HZ;
        taskstat->proctime = tval2;
    } else {
        P.start_time = tval1 / HZ;
        taskstat->proctime = tval1;
    }

    //DBG("my start time from boot: %lu\n", P.start_time);

    taskstat->state[0] = P.state;
    taskstat->pinfo.task[0].pid = P.ppid;
    /* P.start_time是相对时间，taskstat->event_tv是绝对时间 */
    taskstat->event_tv.tv_sec = P.start_time + uptime_sec;
    taskstat->event_tv.tv_usec = 0;

    fclose(fp);
    return 0;
}

/* 从/proc/PID/status里读tgid(进程组号)、uid、gid */
static int get_proc_status(process_t *taskstat)
{
    char line[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char comm[16] = {0};
    char state[16] = {0};
    pid_t tgid = 0;
    uid_t uid = 0;
    uid_t euid = 0;
    uid_t suid = 0;
    uid_t fsuid = 0;
    gid_t gid = 0;
    gid_t egid = 0;
    gid_t sgid = 0;
    gid_t fsgid = 0;
    FILE *fp = NULL;
    int len = 0;
    int count = 0;

    if (!taskstat) {
        elog("get_proc_status fail: NULL taskstat\n");
        return -1;
    }

    snprintf(path, sizeof(path), "/proc/%d/status", taskstat->pid);

    fp = fopen(path, "r");
    if (!fp) {
        if (errno != ENOENT) {
            dlog("open %s fail: %s\n", path, strerror(errno));
        }
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (count == 5) break;

        if(strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name:\t%s\n", comm);
            count++;
            continue;
        }

        if (strncmp(line, "State:", 6) == 0) {
            sscanf(line, "State:\t%s\n", state);
            ++count;
            continue;
        }

        if(strncmp(line, "Tgid:", 5) == 0) {
            sscanf(line, "Tgid:\t%d\n", &tgid);
            count++;
            continue;
        }

        if(strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%d\t%d\t%d\t%d\n",&uid, &euid, &suid, &fsuid);
            count++;
            continue;
        }

        if(strncmp(line, "Gid:", 4) == 0) {
            sscanf(line, "Gid:\t%d\t%d\t%d\t%d\n", &gid, &egid, &sgid, &fsgid);
            count++;
            continue;
        }
    }
    fclose(fp);

    if (tgid != taskstat->pid) {
        taskstat->pinfo.task[0].pid = tgid;
    }
    taskstat->uid = uid;
    taskstat->euid = euid;
    taskstat->fsuid = fsuid;
    taskstat->gid = gid;
    taskstat->egid = egid;
    taskstat->fsgid = fsgid;

    /* CentOS 5没有/proc/PID/comm，内核线程在这里取命令名和参数 */
    len = strlen(comm);
    taskstat->cmdlen = len;
    snprintf(taskstat->cmd, sizeof(taskstat->cmd), "%s", comm);
    taskstat->cmd[len] = 0;

    if (taskstat->pid == 2 || taskstat->pinfo.task[0].pid == 2) { //内核线程
        taskstat->argslen = len+2;
        snprintf(taskstat->args, sizeof(taskstat->args), "[%s]", comm);
        taskstat->argv0len = len+2;

        snprintf(taskstat->md5, sizeof(taskstat->md5), "%s", "None");
        snprintf(taskstat->version, sizeof(taskstat->version), "%s", "None");
    } else {
        taskstat->argslen = len;
        snprintf(taskstat->args, sizeof(taskstat->args), "%s", comm);
        taskstat->argv0len = len;
    }

    snprintf(taskstat->state, sizeof(taskstat->state), "%s", state);

    return 0;
}

/* 读/proc/PID/status里的进程Name，返回读到的进程名长度 */
static int get_proc_comm(pid_t pid, char *comm)
{
    char line[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    FILE *fp = NULL;
    int len = -1;

    if (pid == 0 || !comm) {
        return -1;
    }

    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    fp = fopen(path, "r");
    if (!fp) {
        if (errno != ENOENT) {
            dlog("open %s fail: %s\n", path, strerror(errno));
        }
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if(strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name:\t%s\n", comm);
            len = strlen(comm);
            break;
        }
    }

    fclose(fp);

    return len;
}

/* 读/proc/PID/exe链接内容，返回读到的命令路径名长度 */
static int get_proc_exe(pid_t pid, char *cmd)
{
    char buf[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char *ptr = NULL;
    int len = 0;

    if (!cmd || pid <= 0) {
        elog("get_proc_exe fail, NULL cmd buffer\n");
        return -1;
    }

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    /* readlink() does not append a null byte to buf, end bufstr byself */
    len = readlink(path, buf, sizeof(path)-1);
    if (len <= 0) {
        return len;
    }
    buf[len] = 0;

    /*
     * 进程运行中程序被删除，取exe会有(deleted)标识，去掉此标识
     * /usr/sbin/console-kit-daemon.#prelink#.BOl1wo (deleted)这样的取/usr/sbin/console-kit-daemon
     */
    if ((ptr = strstr(buf, ".#prelink#."))) {
        *ptr = 0;
        len = ptr - buf;
    } else if ((ptr = strstr(buf, " (deleted)"))) {
        *ptr = 0;
        len = ptr - buf;
    }

    memcpy(cmd, buf, len);
    cmd[len] = 0;

    return len;
}

int is_kernel_thread(pid_t pid)
{
    char cmd[PATH_MAX] = {0};

    if (get_proc_exe(pid, cmd) < 0) {
        return 1;
    }
    return 0;
}

static int get_proc_cmdline(process_t *taskstat)
{
    char path[PATH_MAX] = {0};
    char buf[PATH_MAX] = {0};
    int fd = 0;
    int i = 0;
    int len = 0;

    if (!taskstat) {
        elog("get_proc_cmdline fail, NULL taskstat\n");
        return -1;
    }

    /* 读进程的cmdline信息 */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", taskstat->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (taskstat->cmdlen == 0) {
            elog("open %s fail: %s\n", path, strerror(errno));
            return -1;
        }

        elog("open %s fail: %s. use cmd %s as args\n", path, strerror(errno), taskstat->cmd);
        taskstat->argslen = taskstat->cmdlen;
        memcpy(taskstat->args, taskstat->cmd, taskstat->cmdlen+1);
        taskstat->argv0len = taskstat->cmdlen;
        return 0;
    }

    len = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (len < 0) {
        dlog("read %s fail: %s. use cmd %s as args\n", path, strerror(errno), taskstat->cmd);
        taskstat->argslen = taskstat->cmdlen;
        memcpy(taskstat->args, taskstat->cmd, taskstat->cmdlen+1);
        taskstat->argv0len = taskstat->cmdlen;
        return 0;
    }
    if (len == 0) {
        //dlog("read 0 byte from %s. use cmd %s as args\n", path, taskstat->cmd);
        taskstat->argslen = taskstat->cmdlen;
        memcpy(taskstat->args, taskstat->cmd, taskstat->cmdlen+1);
        taskstat->argv0len = taskstat->cmdlen;
        return 0;
    }

    taskstat->argv0len = 0;
    /*
     * 整理取到的cmdline
     * 把所有0转成空格, 包括最后结尾的0，如果结尾是0的话
     */
    for (i = 0; i < len; i++) {
        /* 截断换行之后的参数 */
        if (buf[i] == '\n') {
            buf[i] = 0;
            len = i;
            if (i < sizeof(taskstat->args)-4) {
                buf[i] = '.';
                buf[i+1] = '.';
                buf[i+2] = '.';
                buf[i+3] = 0;
                len = i + 3;
            }
            break;
        }
        if (buf[i] != 0) {
            continue;
        }

        if (!taskstat->argv0len) {
            taskstat->argv0len = i;
        }
        buf[i] = ' ';
        if (i == len - 1) { //遍历到头
            break;
        }
        if (i == PATH_MAX) {
            break;
        }

        taskstat->argc++;
    }
    if (len >= PATH_MAX) {
        len = PATH_MAX - 1;
    }
    /* 消除命令尾部的空格 */
    for (i = len - 1; i > 0; i--) {
        if (buf[i] == ' ') {
            len--;
            continue;
        }
        break;
    }
    snprintf(taskstat->args, sizeof(taskstat->args)-1, "%s", buf);
    if (len >= sizeof(taskstat->args)) {
        len = sizeof(taskstat->args)-1;
    }
    taskstat->args[len] = 0;
    taskstat->argslen = len;

    return 0;
}

void uidtoname(uid_t uid, char *name, const int name_len)
{
    struct passwd pwd;
    struct passwd *result = NULL;
    char *buf = NULL;
    long bufsize = 0;
    int ret = 0;

    if (uid == 0 || name == NULL || name_len <= 0) {
        strncpy(name, "root", 5);
        return;
    }

    memset(&pwd, 0x00, sizeof(pwd));

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize <= 0 || bufsize > 16384) {
        bufsize = 16384;        
    }

    buf = malloc(bufsize);
    if (buf == NULL) {
        elog("uidtoname malloc fail\n");
        snprintf(name, name_len, "uid(%d)", uid);
        return;
    }

    /* On success, getpwuid_r() return zero, and set *result to pwd.
       If no match, return 0, and store NULL in *result.
       In case of error, return errno, and NULL is stored in *result. */
    ret = getpwuid_r(uid, &pwd, buf, bufsize, &result);
    if (result) {
        snprintf(name, name_len, "%s", pwd.pw_name);
    } else {
        snprintf(name, name_len, "uid(%d)", uid);
        if (ret) {
            elog("uid %d to name error: %s\n", uid, strerror(ret));
        }
    }

    free(buf);
}

static char *safebasename(char *path)
{
    char *baseptr = NULL;

    if (path == NULL) {
        return "";
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

extern char *parse_pkgname(char *str);
static int is_rpm_dpkg_install_version(process_t *process)
{
    int ret = 0;
    char cmd[PATH_MAX] = {0};
    char line[NAME_MAX] = {0};

    if (!process || process->cmd[0] != '/') {
        return -1;
    }

    if (strcmp(process->cmd, "/sbin/sniper") == 0 ||
        strcmp(process->cmd, "/sbin/assist_sniper") == 0 ||
        strcmp(process->cmd, "/usr/sbin/sniper") == 0 ||
        strcmp(process->cmd, "/usr/sbin/assist_sniper") == 0 ||
        strncmp(process->cmd, "/opt/snipercli/", 15) == 0) {
        snprintf(process->version, sizeof(process->version), "%s", SNIPER_VERSION);
        snprintf(process->pkg, sizeof(process->pkg), "sniper-linux-%s", SNIPER_VERSION);
        return 0;
    }

    memset(process->pkg, 0x00, sizeof(process->pkg));

#ifdef SNIPER_FOR_DEBIAN
    snprintf(cmd, sizeof(cmd), "dpkg-query -S %s", process->cmd);
    ret = popen_filter_one_keystr(cmd, NULL, line, sizeof(line));
    if (ret < 0) {
        snprintf(process->version, sizeof(process->version), "%s", "None");
        snprintf(process->pkg, sizeof(process->pkg), "%s", "None");
        return -1;
    }

    /* 这里已经取到了包名，再按照“包名 版本”的格式取一次，和rpm查询结果格式一致，统一处理 */
    snprintf(cmd, sizeof(cmd), "dpkg-query -W -f='${Package} ${Version}' %s", parse_pkgname(line));
#else
    snprintf(cmd, sizeof(cmd), "rpm -qf --qf \"%{NAME} %{VERSION}\" %s", process->cmd);
#endif

    ret = popen_filter_one_keystr(cmd, NULL, line, sizeof(line));
    /* 如果文件没有对应的软件包，rpm会返回file xxx is not owned by any package */
    if (ret < 0 || strstr(line, "not owned")) {
        snprintf(process->version, sizeof(process->version), "%s", "None");
        snprintf(process->pkg, sizeof(process->pkg), "%s", "None");
        return -1;
    }

    ret = sscanf(line, "%255s %63s", process->pkg, process->version);
    if (ret != 2) {
        snprintf(process->version, sizeof(process->version), "%s", "None");
        snprintf(process->pkg, sizeof(process->pkg), "%s", "None");
        return -1;
    }

    return 0;
}

static sqlite3_stmt * software_stmt = NULL;
/* 查询service中的软件包名 */
static int query_rpm_dpkg_name_from_DB(sys_info_t *data)
{
    char *query_software_name = "select name,rpm from sys_service;";
    const char *zTail;
    int ret = 0;

    if (data == NULL || data->db == NULL) {
        return -1;
    }

    if (software_stmt == NULL) {
        ret = sqlite3_prepare_v2(data->db, query_software_name, -1, &software_stmt, &zTail);
        if (ret !=SQLITE_OK){
            elog("No service info\n");
        }
    }

    return ret;
}

static int is_service_process(process_t *process)
{
    int ret = 0;
    int len = 0;

    if (process == NULL) {
        return -1;
    }

    len = strlen(process->pkg);

    while (sqlite3_step(software_stmt) == SQLITE_ROW) {
        const char *service_name = sqlite3_column_text(software_stmt, 0);
        const char *software_name = sqlite3_column_text(software_stmt, 1);

        if (strncmp(software_name, "file /", 6) == 0 || 
            strncmp(software_name, "None", 4) == 0) {
            continue;
        }

        if (len && strncmp(process->pkg, software_name, len) == 0) {
            process->is_service_process = 1;
            break;
        } else {
            process->is_service_process = 0;
        }
    }

    return ret;
}

extern char *handle_single_quota(char *old, char *new, int newlen);
static int save_process_info(sys_info_t *data, const process_t *process, const process_t *pprocess)
{
    char upsert_sql[PATH_MAX] = {0};
    char buf[PATH_MAX] = {0};
    char *process_args = NULL;
    char version[NAME_MAX] = "None";
    char pkg[NAME_MAX]     = "None";
    char md5[33]           = "None";
    int ret = 0;
    const char *upsert_str = "INSERT OR REPLACE INTO sys_process \
                   (pid, name, user, path, cmdline, state, version, pkg,  md5,  pctime, ppuser, ppcmd, ctime) \
            VALUES (%ld, '%s', '%s', '%s', '%s',    '%s',  '%s',    '%s', '%s', '%s',   '%s',   %ld,   '%s');";
    
    if (!data || !process || !pprocess ) {
        return -1;
    }

    if (strlen(process->version)) {
        snprintf(version, sizeof(version), "%s", process->version);
    }

    if (strlen(process->pkg)) {
        snprintf(pkg, sizeof(pkg), "%s", process->pkg);
    }

    if (strlen(process->md5)) {
        snprintf(md5, sizeof(md5), "%s", process->md5);
    }

    /* 拼接sql语句时，如果参数中带了单引号'，要转义成''，或替换成空格。双引号"不需要转义 */
    process_args = handle_single_quota((char *)process->args, buf, sizeof(buf));
    if (!process_args || process_args[0] == 0) {
        process_args = buf;
        process_args[0] = '-';
        process_args[1] = 0;
    }

    snprintf(upsert_sql, sizeof(upsert_sql), upsert_str,
        process->pid, process->cmd, process->user, process->cmd, process_args,
        process->state, version, pkg, md5,
        pprocess->user, pprocess->cmd, process->event_tv.tv_sec, data->time_str);

    slog("%s\n", upsert_sql);

    ret = exec_sql(data->db, upsert_sql);
    if (ret) {
        elog("update process failed, sql:%s\n", upsert_sql);
    }

    return ret;
}

static void check_process(sys_info_t *data, pid_t pid)
{
    char id[8] = {0};
    process_t taskstat;
    process_t ptaskstat;
    pid_t ppid = 0;
    int ret = 0;

    if (data == NULL || data->object == NULL || pid <= 0) return ;
    cJSON *process_list = data->object;

    if (uptime_sec == 0) get_sys_boot_time();

    memset(&taskstat , 0x00, sizeof(process_t));
    memset(&ptaskstat, 0x00, sizeof(process_t));

    taskstat.pid = pid;
    if (get_proc_stat(&taskstat) < 0 || get_proc_status(&taskstat) < 0) {
        return;
    }

    ppid = taskstat.pinfo.task[0].pid;
    if (pid != 2 && ppid != 2) {
        get_proc_exe(pid, taskstat.cmd);
        get_proc_cmdline(&taskstat);

        is_rpm_dpkg_install_version(&taskstat);
        is_service_process(&taskstat);

        /* process md5 */
        if (is_file(taskstat.cmd) == 0) {
            ret = sys_md5_file(taskstat.cmd, taskstat.md5, sizeof(taskstat.md5));
        }
        if (ret) {
            snprintf(taskstat.md5, sizeof(taskstat.md5), "%s", "None");
        }
    }

    uidtoname(taskstat.uid, taskstat.user, sizeof(taskstat.user));
    snprintf(taskstat.uuid, sizeof(taskstat.uuid), "%llu-%d", taskstat.proctime + uptime_sec, pid);

    if (ppid == 0) {
        snprintf(ptaskstat.uuid, sizeof(ptaskstat.uuid), "%lu-0", uptime_sec);
        snprintf(ptaskstat.cmd, sizeof(ptaskstat.cmd), "%s", "Linux-Kernel");
        snprintf(ptaskstat.user, sizeof(ptaskstat.user), "%s", "root");
    } else {
        ptaskstat.pid = ppid;
        if (get_proc_stat(&ptaskstat) < 0 || get_proc_status(&ptaskstat) < 0) {
            return;
        }
        uidtoname(ptaskstat.uid, ptaskstat.user, sizeof(taskstat.user));
        snprintf(ptaskstat.uuid, sizeof(ptaskstat.uuid), "%llu-%d", ptaskstat.proctime + uptime_sec, ppid);
    }
    snprintf(id, sizeof(id), "%d", pid);


    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "process_id", id);
    cJSON_AddStringToObject(object, "process_name", safebasename(taskstat.cmd));
    cJSON_AddStringToObject(object, "process_user", taskstat.user);
    cJSON_AddStringToObject(object, "process_path", taskstat.cmd);
    cJSON_AddStringToObject(object, "process_commandline", taskstat.args);
    cJSON_AddStringToObject(object, "process_version", taskstat.version);

    //TODO 简陋地暂时把没有标准输入输出的root进程视为系统进程
    if (taskstat.uid == 0) {
        char path[128] = {0}, fd0path[64] = {0}, fd1path[64] = {0};

        snprintf(path, 128, "/proc/%d/fd/0", taskstat.pid);
        readlink(path, fd0path, 63);
        snprintf(path, 128, "/proc/%d/fd/1", taskstat.pid);
        readlink(path, fd1path, 63);

        if (strncmp(fd0path, "/dev/tty", 8) != 0 &&
            strncmp(fd0path, "/dev/pts", 8) != 0 &&
            strncmp(fd1path, "/dev/tty", 8) != 0 &&
            strncmp(fd1path, "/dev/pts", 8) != 0) {
            cJSON_AddNumberToObject(object, "process_type", 1); //系统进程
        } else {
            cJSON_AddNumberToObject(object, "process_type", 2);
        }
    } else {
        cJSON_AddNumberToObject(object, "process_type", 2);
    }

    /* 0 默认 1 僵尸进程 2 不可中断睡眠进程 3 运行状态 4 暂停状态  5 退出状态 */
    int process_st = 0;
    if (taskstat.state[0] == 'Z') {
        process_st = 1;
    }
    else if (taskstat.state[0] == 'D') {
        process_st = 2;
    }
    else if (taskstat.state[0] == 'R') {
        process_st = 3;
    }
    else if (taskstat.state[0] == 'T') {
        process_st = 4;
    }
    else if (taskstat.state[0] == 'X') {
        process_st = 5;
    }
    cJSON_AddNumberToObject(object, "process_status", process_st);

    cJSON_AddStringToObject(object, "hash_value", taskstat.md5);

    time_t time = taskstat.event_tv.tv_sec;
    struct tm* p_time = localtime(&time);
    char str_t[26] = {0};
    strftime(str_t, 26, "%Y-%m-%d %H:%M:%S", p_time);
    cJSON_AddStringToObject(object, "start_time", str_t);

    cJSON_AddNumberToObject(object, "parent_process_id", ptaskstat.pid);
    cJSON_AddStringToObject(object, "parent_process_path", ptaskstat.cmd);
    cJSON_AddStringToObject(object, "parent_process_commandline", ptaskstat.cmd);
    cJSON_AddNumberToObject(object, "is_service_process", taskstat.is_service_process);
    if (strncmp(taskstat.pkg, "None", 4) == 0) {
        cJSON_AddStringToObject(object, "is_pkg_manage_install", "0");
    } else {
        cJSON_AddStringToObject(object, "is_pkg_manage_install", "1");
    }
    cJSON_AddStringToObject(object, "parent_process_name", safebasename(ptaskstat.cmd));
    cJSON_AddStringToObject(object, "parent_process_user", ptaskstat.user);
    cJSON_AddStringToObject(object, "process_uuid", taskstat.uuid);

    cJSON_AddItemToArray(process_list, object);

    save_process_info(data, &taskstat, &ptaskstat);
}

/* JSON process */
void *sys_process_info(sys_info_t *data)
{
    int pid = 0;
    int ret = 0;
    DIR *procdirp = NULL;
    struct dirent *pident = NULL;
    struct stat st = {0};

    if (data->object == NULL || data->db == NULL) return NULL;

    query_rpm_dpkg_name_from_DB(data);

    ret = exec_sql(data->db, sql_process);
    if (ret) {
        elog("Create process table failed, ret:%d\n", ret);
        return NULL;
    }

    ret = exec_sql(data->db, "BEGIN;");
    if (ret) {
        elog("Process BEGIN failed\n");
        return NULL;
    }

    stat("/proc", &st);

    procdirp = opendir("/proc");
    if (procdirp == NULL) {
        return NULL;
    }

    /* 遍历/proc获得当前进程信息 */
    while ((pident = readdir(procdirp))) {
        if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
            continue; //忽略非进程项信息
        }

        pid = atoi(pident->d_name);
        if (pid <= 0) {
            continue;
        }
        if (st.st_nlink > 1024 && pid >= 300 && is_kernel_thread(pid)) {
            continue; //进程数超过1024时，忽略300号以上的内核线程
        }

        check_process(data, pid);
    }
    closedir(procdirp);

    ret = exec_sql(data->db, "COMMIT;");
    if (ret) {
        elog("Process COMMIT failed\n");
        return NULL;
    }

    sqlite3_finalize(software_stmt);

    return NULL;
}
void *sys_process_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}
