#define _GNU_SOURCE //for strcasestr

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <shadow.h>
#include <netinet/tcp.h>

#include "../list.h"
#include "../cJSON.h"
#include "sys_info.h"
#include "sys_db_op.h"

#define USER_SLICE "/sys/fs/cgroup/systemd/user.slice/"
#define SYSTEM_SLICE "/sys/fs/cgroup/systemd/system.slice/"

extern int is_dir(const char *file);

int get_proc_socket_info(char *line, sock_info_t *info)
{
    char more[128] = {0};
    char src_addr[64] = {0};
    char dst_addr[64] = {0};
    char ip6[64] = {0};
    struct in6_addr in6;
    unsigned long addr = 0;
    int num = 0;
    int slot = 0;
    
    memset(&in6, 0x00, sizeof(in6));

    num = sscanf(line,
        "%d: %63[0-9A-Fa-f]:%X %63[0-9A-Fa-f]:%X "
        "%X %*s %*s %*s %d %*s %lu %127s",
        &slot, src_addr, &info->src_port, dst_addr, &info->dst_port,
        &info->state, &info->uid, &info->inode, more);
    if (num != 9) {
        return -1;
    }
    
    if (strlen(src_addr) > 8) { // tcp6/udp6
        sscanf(src_addr, "%08X%08X%08X%08X", &in6.s6_addr32[0], &in6.s6_addr32[1], &in6.s6_addr32[2], &in6.s6_addr32[3]);
        inet_ntop(AF_INET6, &in6, ip6, sizeof(ip6));
        if (strncmp(ip6, "::ffff:", 7) == 0) {
            snprintf(info->src_ip, sizeof(info->src_ip)-1, "%s", ip6 + 7);
        } else {
            snprintf(info->src_ip, sizeof(info->src_ip)-1, "%s", ip6);
        }

        sscanf(dst_addr, "%08X%08X%08X%08X", &in6.s6_addr32[0], &in6.s6_addr32[1], &in6.s6_addr32[2], &in6.s6_addr32[3]);
        inet_ntop(AF_INET6, &in6, ip6, sizeof(ip6));
        if (strncmp(ip6, "::ffff:", 7) == 0) {
            snprintf(info->dst_ip, sizeof(info->dst_ip)-1, "%s", ip6 + 7);
        } else {
            snprintf(info->dst_ip, sizeof(info->dst_ip)-1, "%s", ip6);
        }
    } else {
        addr = strtoul(src_addr, NULL, 16);
        inet_ntop(AF_INET, &addr, info->src_ip, sizeof(info->src_ip));

        addr = strtoul(dst_addr, NULL, 16);
        inet_ntop(AF_INET, &addr, info->dst_ip, sizeof(info->dst_ip));
    }

    // if (strcmp(info->src_ip, "::") == 0) {
    //     strcpy(info->src_ip, "0.0.0.0");
    // } else if (strcmp(info->src_ip, "::1") == 0) {
    //     strcpy(info->src_ip, "127.0.0.1");
    // }

    // if (strcmp(info->dst_ip, "::") == 0) {
    //     strcpy(info->dst_ip, "0.0.0.0");
    // } else if (strcmp(info->dst_ip, "::1") == 0) {
    //     strcpy(info->dst_ip, "127.0.0.1");
    // }

    return 0;
}

static time_t os_install_time;
time_t get_os_install_time()
{
    return os_install_time;
}
int set_os_install_time(time_t new_time)
{
    os_install_time = new_time;
    return 0;
}

static cJSON *software_info = NULL;

static const char *sql_software = 
        "CREATE TABLE IF NOT EXISTS sys_software(Id INTEGER PRIMARY KEY, \
                                    name  TEXT NOT NULL UNIQUE, \
                                    pid   int,  \
                                    stat  TEXT, \
                                    ports TEXT, \
                                  cmdline TEXT, \
        /* create time */           ctime TIMESTAMP, \
        /* last check time */       ltime TIMESTAMP);";

/* JSON software */
void *sys_software_info(sys_info_t *data)
{
    int ret = 0;

    if (data->object == NULL || data->db == NULL) return NULL;

#ifdef SNIPER_FOR_DEBIAN
    ret = sys_deb_packages(data);
#else
    ret = sys_rpm_packages(data);
#endif
    if(ret) {
        elog("Get software info failed, ret:%d\n", ret);
    }

    software_info = data->object;

    return NULL;
}
void *sys_software_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static int get_first_uid_gid(const char *name, unsigned int *uid, unsigned int *gid)
{
    char line[PATH_MAX];
    char *ptr = NULL;
    FILE *fp = NULL;
    int ret = 0;
    int tmp_first_uid = 0;
    int tmp_first_gid = 0;
    int last_system_uid = 0;
    int last_system_gid = 0;

    if (name == NULL || uid == NULL || gid == NULL) return -1;

    fp = fopen(name, "r");
    if (fp == NULL) {
        //elog("Read %s failed\n", name);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "FIRST_UID")) {
            ret = 1;
            ptr = strchr(line, '=');
            if (ptr) {
                tmp_first_uid = atoi(ptr+1);
            }
            continue;
        }
        if (strstr(line, "FIRST_GID")) {
            ptr = strchr(line, '=');
            if (ptr) {
                tmp_first_gid = atoi(ptr+1);
            }
            continue;
        }
        if (strstr(line, "LAST_SYSTEM_UID")) {
            ret = 1;
            ptr = strchr(line, '=');
            if (ptr) {
                last_system_uid = atoi(ptr+1);
            }
            continue;
        }
        if (strstr(line, "LAST_SYSTEM_GID")) {
            ptr = strchr(line, '=');
            if (ptr) {
                last_system_uid = atoi(ptr+1);
            }
            continue;
        }
    }
    fclose(fp);

    if (tmp_first_uid > 0) {
        *uid = tmp_first_uid;
    } else if (last_system_uid > 0) {
        *uid = last_system_uid + 1;
    }

    if (tmp_first_gid > 0) {
        *gid = tmp_first_gid;
    } else if (last_system_gid > 0) {
        *gid = last_system_gid + 1;
    }
    
    return ret;
}
static int is_sudo_user(const char *user_name)
{
    char cmd[PATH_MAX];
    char buf[PATH_MAX];
    char *ptr = NULL;
    const char *key = "ALL";
    int ret = 0;

    if (user_name == NULL) return -1;

    memset(cmd, 0x00, sizeof(cmd));
    memset(buf, 0x00, sizeof(buf));
    
    snprintf(cmd, sizeof(cmd), "sudo -l -U %s", user_name);

    ret = popen_filter_one_keystr(cmd, key, buf, sizeof(buf)-1);
    if (!ret) {
        ptr = strstr(buf, key);
        if (ptr) {
            ret = 1;
        }
    }

    return ret;
}

static int is_locked_user(const char *user_name)
{
    char cmd[PATH_MAX];
    char buf[PATH_MAX];
    char *ptr = NULL;
    const char *key = "locked.";
    int ret = 0;

    if (user_name == NULL) return -1;

    memset(cmd, 0x00, sizeof(cmd));
    memset(buf, 0x00, sizeof(buf));
    
    snprintf(cmd, sizeof(cmd), "passwd -S %s", user_name);

    ret = popen_filter_one_keystr(cmd, key, buf, sizeof(buf)-1);
    if (!ret) {
        ptr = strstr(buf, key);
        if (ptr) {
            ret = 1;
        }
    } 

    return ret;
}
/* 0 无密码 1 有密码 */
static int is_nopasswd_user(const char *user_name)
{
    char buf[PATH_MAX];
    FILE *fp = NULL;
    char *ptr = NULL;
    char *tmp = NULL;
    int ret = 1;

    if (user_name == NULL) return -1;

    memset(buf, 0x00, sizeof(buf));
    
    fp = fopen("/etc/sudoers", "r");
    if (!fp) {
        return -1;
    }

    while (fgets(buf, sizeof(buf)-1, fp) == NULL) {
        if (buf[0] == '#') continue;

        ptr = strstr(buf, user_name);
        if (ptr) {
            tmp = ptr + strlen(user_name);
            ptr = strstr(tmp, "NOPASSWD");
            if (ptr) {
                ret = 0;
            }
        }
    }

    fclose(fp);    

    return ret;
}

static int is_user_assword_expires(const char *user_name)
{
    char cmd[PATH_MAX];
    char buf[NAME_MAX];
    char *ptr = NULL;
    char *tmp = NULL;
    const char *key = "Password expires";
    int ret = 0;

    if (user_name == NULL) return -1;

    memset(cmd, 0x00, sizeof(cmd));
    memset(buf, 0x00, sizeof(buf));
    snprintf(cmd, sizeof(cmd), "chage -l %s", user_name);

    ret = popen_filter_one_keystr(cmd, key, buf, sizeof(buf)-1);
    if (!ret) {
        ptr = strstr(buf, key);
        if (ptr) {
            tmp = ptr + strlen(key);
            ptr = strchr(buf, ':');
        }
    } 
    if (!ptr) return 0;

    ptr += 2;
    if (strncmp(ptr, "never", strlen("never")) != 0) {
        /* date -d "Mar 26, 2020" */
        memset(cmd, 0x00, sizeof(cmd));
        memset(buf, 0x00, sizeof(buf));
        snprintf(cmd, sizeof(cmd), "date -d %s", ptr);
        ret = popen_filter_one_keystr(cmd, NULL, buf, sizeof(buf)-1);
        if (!ret) {
            /* date -d 'Thu Mar 26 00:00:00 CST 2020' +%s */
            memset(cmd, 0x00, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "date -d %s", buf);
            memset(buf, 0x00, sizeof(buf));
            popen_filter_one_keystr(cmd, NULL, buf, sizeof(buf)-1);
        }

        time_t t = time(NULL);

        if (t < atol(buf)) {
            ret = 0;
        }
        else {
            ret = 1;
        }
    }
    else {
        ret = 0;
    }

    return ret;
}

/* JSON account */
void *sys_account_info(sys_info_t *data)
{
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
    struct passwd pw;
    struct lastlog llog;
    struct tm tm;
    char lltimestr[128];
    struct passwd *pwp = NULL;
    FILE *fp = NULL;
    unsigned int first_uid = 1000;
    unsigned int first_gid = 1000;
    int i = 0;
    int canlogin = 0;
    int ret = 0;
    time_t ll_time = 0;
    

    if (data->object == NULL) return NULL;
    cJSON *users_info = data->object;

    setpwent();
    while (1) {
        i = getpwent_r(&pw, buf, PATH_MAX, &pwp);
        if (i) break;

        memset(&llog, 0x00, sizeof(struct lastlog));
        fp = fopen("/var/log/lastlog", "r");
        if (fp) { /* read /var/log/lastlog */
            fseek(fp, pw.pw_uid*sizeof(struct lastlog), SEEK_SET);
            if (fread(&llog, sizeof(struct lastlog), 1, fp) > 0) {
                memset(lltimestr, 0x00, sizeof(lltimestr));
                ll_time = llog.ll_time;;
                if (ll_time == 0) {
                    snprintf(lltimestr, sizeof(lltimestr)-1, "%s", "Never logged in");
                } else {
                    memset(&tm, 0x00, sizeof(struct tm));
                    localtime_r(&ll_time, &tm);
                    strftime(lltimestr, sizeof(lltimestr), "%F %T", &tm);
                }
            }
            fclose(fp);
        }
        else {
            snprintf(lltimestr, sizeof(lltimestr)-1, "%s", "N/A");
        }

        canlogin = 1;
        if (strstr(pw.pw_shell, "/nologin") || strstr(pw.pw_shell, "/false") ||
            strstr(pw.pw_shell, "/sync") || strstr(pw.pw_shell, "/shutdown")|| 
            strstr(pw.pw_shell, "/halt")) {
            canlogin = 0;
        } 
        else { /* Can login user */
            if (ret == 0) {
                ret = get_first_uid_gid("/etc/adduser.conf", &first_uid, &first_gid);
            }
            if (ret == 1) {
                /* 如果没有从/etc/adduser.conf里取到新用户默认开始分配的uid号，则默认使用1000，如果实际是500，这里做个调整 */
                if (pw.pw_uid && pw.pw_uid < 1000) {
                    first_uid = 500;
                    first_gid = 500;
                }
            }
        }
#if 0
        if (pw.pw_uid < first_uid || strcmp(pw.pw_name, "nobody") == 0) {
            /* 不上报不可登录的系统用户到主机详情里 */
            /* 不可登录却登录过的，要报 */
            if (!canlogin && llog.ll_time == 0) {
                continue;
            }
        }
#endif
        cJSON *object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "user_name", pw.pw_name);
        struct group *ugroup = getgrgid(pw.pw_gid);
        if (ugroup) {
            cJSON_AddStringToObject(object, "group_name", ugroup->gr_name);
        } else {
            cJSON_AddStringToObject(object, "group_name", "");
        }
        cJSON_AddNumberToObject(object, "account_status", 1);
        if (pw.pw_uid == 0) {
            cJSON_AddNumberToObject(object, "account_type", 2); /* 管理员账户 */
        } else if (pw.pw_uid < first_uid || strcmp(pw.pw_name, "nobody") == 0) {
            cJSON_AddNumberToObject(object, "account_type", 1); /* 系统账户 */
        } else {
            cJSON_AddNumberToObject(object, "account_type", 1); /* 普通账户 */
        }
        cJSON_AddNumberToObject(object, "login_type", canlogin);

        cJSON_AddStringToObject(object, "home_dir", pw.pw_dir);
        cJSON_AddStringToObject(object, "account_desc", pw.pw_gecos);
        cJSON_AddNumberToObject(object, "password_status", is_nopasswd_user(pw.pw_name));

        cJSON_AddNumberToObject(object, "uid", pw.pw_uid);
        cJSON_AddNumberToObject(object, "gid", pw.pw_gid);
        cJSON_AddNumberToObject(object, "sudo", is_sudo_user(pw.pw_name));
        cJSON_AddStringToObject(object, "last_login_time", lltimestr);
        cJSON_AddStringToObject(object, "last_pwd_time", "0000");

        ////////////////////////////////////////////////////////////
        cJSON_AddStringToObject(object, "shell", pw.pw_shell);
        cJSON_AddNumberToObject(object, "locked", is_locked_user(pw.pw_name));
        cJSON_AddNumberToObject(object, "nopasswd", is_nopasswd_user(pw.pw_name));
        cJSON_AddNumberToObject(object, "expires", is_user_assword_expires(pw.pw_name));

        cJSON_AddItemToArray(users_info, object);
    }
    endpwent();

    return NULL;
}
void *sys_account_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static int is_process_has_inode(const char *pid, const unsigned long inode)
{
    char run_path[PATH_MAX];
    char result_path[PATH_MAX];
    char inode_str[64];
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    char *tmp = NULL;
    long iter_fd = 0;
    int len = 0;
    int ret = 0;

    if (pid == NULL || inode == 0) return 0;

    memset(run_path, 0x00, sizeof(run_path));
    memset(result_path, 0x00, sizeof(result_path));

    snprintf(run_path, sizeof(run_path), "/proc/%s/fd", pid);
    dirp = opendir(run_path);
    if (dirp == NULL) {
        elog("Open dir %s failed\n", run_path);
        return 0;
    }
    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] < '0' || dent->d_name[0] > '9' || (iter_fd=atol(dent->d_name))<=0) {
            continue;
        }

        memset(run_path, 0x00, sizeof(run_path));
        snprintf(run_path, sizeof(run_path), "/proc/%s/fd/%s", pid, dent->d_name);
        len = readlink(run_path, result_path, sizeof(result_path));
        if (len < 10) continue;

        len = 0;
        memset(inode_str, 0x00, sizeof(inode_str));
        if (strncmp(result_path, "socket:[", 8) != 0) continue;

        tmp = strchr(result_path+8, ']');
        if (tmp == NULL) continue;

        *tmp = '\0';
        tmp = result_path + 8;
        if (inode == atol(tmp)) {
            ret = 1;
            break;
        }
    }
    closedir(dirp);

    return ret;
}

static int get_ports_info(sys_info_t *data, const char *ports_file, const int port_state)
{
    char run_path[PATH_MAX];
    char line_info[PATH_MAX];
    char cmdline[PATH_MAX];
    sock_info_t ip_info;
    sqlite3_stmt * stmt = NULL;
    FILE *fp = NULL;
    pid_t pid = 0;
    int ret = 0;
    char *tmp = NULL;

    if (data == NULL || data->ret == NULL || ports_file == NULL) return -1;

    cJSON *ports_info = data->object;
    stmt = (sqlite3_stmt*)data->ret;

    memset(run_path, 0x00, sizeof(run_path));
    snprintf(run_path, sizeof(run_path), "/proc/net/%s", ports_file);
    
    fp = fopen(run_path, "r");
    if (!fp) return -1;

    memset(line_info, 0x00, sizeof(line_info));

    fgets(line_info, sizeof(line_info), fp);
    while (fgets(line_info, sizeof(line_info), fp)) {
        pid = 0;
        memset(&ip_info, 0x00, sizeof(ip_info));
        if (get_proc_socket_info(line_info, &ip_info) != 0) {
            continue;
        }
        if (ip_info.state != TCP_LISTEN) {
            continue;
        }
        if (strncmp(ip_info.src_ip, "127.0.0.1", 9) == 0) {
            ip_info.state = 2;
        }
        else {
            ip_info.state = 1;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *process_path = sqlite3_column_text(stmt, 0);
            const char *pid_str = sqlite3_column_text(stmt, 1);
            if (process_path[0] != '/') continue;

            pid = atol(pid_str);
            ret = is_process_has_inode(pid_str, ip_info.inode);
            if (ret) {
                memset(cmdline, 0x00, sizeof(cmdline));
                tmp = get_cmd_line_by_pid(pid_str);
                if (tmp) {
                    snprintf(cmdline, sizeof(cmdline), "%s", tmp);
                    free(tmp);
                    tmp = NULL;
                } else {
                    cmdline[0] = '-';
                }
                memset(run_path, 0x00, sizeof(run_path));
                snprintf(run_path, sizeof(run_path), "%s", process_path);
                break;
            }
        }
        sqlite3_reset(stmt);

        if (ret) { /* find out the inode in program */
            cJSON *object = cJSON_CreateObject();
            cJSON_AddItemToArray(ports_info, object);

            /* 端口类型 1 对外端口 2 对内端口 */
            cJSON_AddNumberToObject(object, "port_type", ip_info.state);
            cJSON_AddStringToObject(object, "protocol", ports_file);
            cJSON_AddNumberToObject(object, "process_id", pid);
            cJSON_AddStringToObject(object, "process_name", basename(run_path));
            cJSON_AddStringToObject(object, "process_path", run_path);
            cJSON_AddStringToObject(object, "process_commandline", cmdline);
            cJSON_AddNumberToObject(object, "local_port", ip_info.src_port);
            cJSON_AddNumberToObject(object, "remote_port", ip_info.dst_port);
            cJSON_AddStringToObject(object, "local_addr", ip_info.src_ip);
            cJSON_AddStringToObject(object, "remote_addr", ip_info.dst_ip);
        }
    }
    fclose(fp);

    return 0;
}

/* JSON port */
void *sys_port_info(sys_info_t *data)
{
    sqlite3_stmt * stmt = NULL;
    const char *zTail;
    int ret = 0;

    if (data->object == NULL || data->db == NULL) return NULL;

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, "SELECT path,pid FROM sys_process;", -1, &stmt, &zTail);
    if (ret !=SQLITE_OK){
        elog("No process\n");
    }
    else {
        data->ret = (void*)stmt;
    }

    get_ports_info(data, "tcp", TCP_LISTEN);
    get_ports_info(data, "udp", TCP_CLOSE);
    get_ports_info(data, "tcp6", TCP_LISTEN);
    get_ports_info(data, "udp6", TCP_CLOSE);

    sqlite3_finalize(stmt);

    return NULL;
}
void *sys_port_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

char *service_run_state[] = { "-", "running", "suspend", "stop" };
char *service_start_type[] = { "-", "manual", "auto", "masked", "trigger/auto(delay)" };
typedef struct _sys_service{
    char serv_path[PATH_MAX];
    char exec_path[PATH_MAX];
    char serv_name[NAME_MAX];
    char pkg_name[NAME_MAX];
    char desc[NAME_MAX];
    int start_type;
    int run_state;
} serv_info_t;

static const char *sql_service = 
        "CREATE TABLE IF NOT EXISTS sys_service(Id INTERGER PRIMARY KEY, \
                                    name  TEXT NOT NULL UNIQUE, \
                                    path  TEXT, \
                                    exec  TEXT, \
                              start_type  INT, \
                                    state INT, \
                                    desc  TEXT, \
                                    rpm   TEXT, \
        /* create time */           ctime TIMESTAMP, \
        /* last check time */       ltime TIMESTAMP);";

/* 将单引号'转义成'' */
static int escape_single_quota(char *old, char *new, int newlen)
{
    int i = 0, j = 0;

    if (!old || !new || newlen <= 0) {
        return -1;
    }

    while (old[i]) {
        if (old[i] == '\'') {
            if (j+1 >= newlen) {
                return -1;
            }

            new[j]   = '\'';
            new[j+1] = '\'';
            j += 2;

        } else {

            if (j >= newlen) {
                return -1;
            }

            new[j] = old[i];
            j++;
        }

        i++;
    }

    return 0;
}
/* 将单引号'替换成空格 */
static void remove_single_quota(char *str)
{
    int i = 0;

    if (str) {
        return;
    }

    while (str[i]) {
        if (str[i] == '\'') {
            str[i] = ' ';
        }
        i++;
    }
}
/* 拼接sql语句时，如果参数中带了单引号'，要转义成''，或替换成空格。双引号"不需要转义 */
char *handle_single_quota(char *old, char *new, int newlen)
{
    /* 转义单引号 */
    if (escape_single_quota(old, new, newlen) == 0) {
        return new;
    }

    /* 转义失败，替换成空格 */
    remove_single_quota(old);
    return old;
}

static void update_service_name(serv_info_t *serv, sys_info_t *data)
{
    char upsert_sql[PATH_MAX] = {0};
    char buf[PATH_MAX] = {0};
    char *exec_path = NULL;
    int ret = 0;
 
    if (!serv || !data || !data->db) {
        return;
    }

    /* 拼接sql语句时，如果参数中带了单引号'，要转义成''，或替换成空格。双引号"不需要转义 */
    exec_path = handle_single_quota(serv->exec_path, buf, sizeof(buf));

    slog("%s, %s, %s\n", serv->serv_name,
         service_run_state[serv->run_state],
         service_start_type[serv->start_type]);

    snprintf(upsert_sql, sizeof(upsert_sql),
            "INSERT INTO sys_service (name, path, exec, start_type, state, desc, rpm, ctime) "
                             "VALUES ('%s', '%s', '%s', '%d',       '%d', '%s', '%s', '%s');",
            serv->serv_name, serv->serv_path, exec_path, serv->start_type, serv->run_state, 
            serv->desc, serv->pkg_name, data->time_str);

    slog("%s\n", upsert_sql);

    ret = exec_sql(data->db, upsert_sql);
    if (ret) {
        elog("update service failed, sql:%s\n", upsert_sql);
    }
}

char *nullstr = "None";
char *parse_pkgname(char *str)
{
    int len = 0;
    char *ptr = NULL, *name = NULL;

    if (!str) {
        return nullstr;
    }

    name = skip_headspace(str);
    delete_tailspace(name);
    ptr = strchr(name, ' ');
    if (ptr) {
        *ptr = 0;;
    }

    len = strlen(name);
    if (name[len-1] == ':') {
        name[len-1] = 0;;
    }

    return name;
}

static void find_current_rpm(serv_info_t *serv, char *path)
{
    char cmd[PATH_MAX] = {0};
    char name[NAME_MAX] = {0};
    int ret = 0, len = 0;

    if (!serv || !path) {
        return;
    }

#ifdef SNIPER_FOR_DEBIAN
    snprintf(cmd, sizeof(cmd), "dpkg-query -S %s", path);
#else
    snprintf(cmd, sizeof(cmd), "rpm -qf %s", path);
#endif

    ret = popen_filter_one_keystr(cmd, NULL, name, sizeof(name));
    /* 如果文件没有对应的软件包，rpm会返回file xxx is not owned by any package */
    if (ret < 0 || strstr(name, "not owned")) {
        snprintf(serv->pkg_name, sizeof(serv->pkg_name), "%s", "None");
        return;
    }

    snprintf(serv->pkg_name, sizeof(serv->pkg_name), "%s", parse_pkgname(name));
}

static void make_service_json(sys_info_t *data)
{
    sqlite3_stmt *stmt = NULL;
    const char *zTail = NULL;
    int ret = 0;

    if (!data || !data->object || !data->db) {
        return;
    }

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, "SELECT name,path,exec,start_type,state,desc,rpm FROM sys_service;", -1, &stmt, &zTail);
    if (ret != SQLITE_OK){
        elog("Service query failed\n");
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *service_name = sqlite3_column_text(stmt, 0);
        const char *service_path = sqlite3_column_text(stmt, 1);
        const char *service_exec = sqlite3_column_text(stmt, 2);
        const int start_type = sqlite3_column_int(stmt, 3);
        const int service_state = sqlite3_column_int(stmt,4);
        const char *service_desc = sqlite3_column_text(stmt, 5);
        
        cJSON *object = cJSON_CreateObject();

        cJSON_AddStringToObject(object, "service_name", service_name);
        cJSON_AddStringToObject(object, "execute_path", service_exec);
        cJSON_AddNumberToObject(object, "start_type",   start_type);
        cJSON_AddStringToObject(object, "model_file_path", service_path);
        cJSON_AddNumberToObject(object, "service_status",  service_state);
        cJSON_AddStringToObject(object, "service_desc",    service_desc);

        cJSON_AddItemToArray(data->object, object);
    }

    sqlite3_finalize(stmt);
}

/* 取服务的运行状态，service_name是xxxx.service的形式 */
static int get_service_run_state(char *service_name)
{
    char path[PATH_MAX] = {0};
    char line[S_LINELEN] = {0};
    FILE *fp = NULL;

    snprintf(path, PATH_MAX, "%s/%s/tasks", SYSTEM_SLICE, service_name);
    fp = fopen(path, "r");
    if (!fp) {
        return 3;
    }

    fgets(line, sizeof(line), fp);
    fclose(fp);

    if (line[0]) {
        //TODO 如果某个服务就是加载一个内核模块，服务状态应是怎样的
        return 1; //tasks里有pid内容，说明服务仍在运行
    }
    return 3; //停止
}

/*
 * 处理下面的情况
 * ExecStart=/usr/bin/dockerd-current \
 * --add-runtime docker-runc=/usr/libexec/docker/docker-runc-current \
 * ...
 */
char *delete_tail_backslash(char *str)
{
    if (str) {
        int len = strlen(str);
        if (str[len-1] == '\\') {
            str[len-1] = 0;
            delete_tailspace(str);
        }
    }
    return str;
}

/* debian上strace systemctl is-enabled xxxx得到的服务配置路径 */
char *service_conf_path[] = {
    "/etc/systemd/system.control/",
    "/run/systemd/system.control/",
    "/run/systemd/transient/",
    "/etc/systemd/system/",
    "/run/systemd/system/",
    "/usr/local/lib/systemd/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/init.d/",
    NULL
};

static void get_service_info_from_conf(serv_info_t *service, char *service_conf_name)
{
    int i = 0, found = 0;
    char *ptr = NULL, *ptr2 = NULL;
    char path[PATH_MAX] = {0};
    char realpath[PATH_MAX] = {0};
    char line[S_LINELEN] = {0};
    FILE *fp = NULL;
    struct stat st = {0};

    if (!service || !service_conf_name) {
        return;
    }

    snprintf(path, sizeof(path), "%s", service->serv_path);

    /*
     * 启动类型 0 无 | 1 手动   | 2 自动  | 3 禁用 | 4 自动(延迟) 
     *               | disabled | enabled | masked | static
     * enabled  : 已建立启动链接
     * disabled : 没建立启动链接
     * static   : 不可以自己启动，不过可能会被其它的 enabled 的服务来唤醒。
     *            该配置文件没有[Install]部分（无法执行），只能作为其他配置文件的依赖
     * mask     : 无论如何都无法被启动！因为已经被强制注销。可通过 systemctl unmask 改回原来的状态
     *            该配置文件被禁止建立启动链接
     */
    readlink(service->serv_path, realpath, sizeof(realpath)-1);
    if (strcmp(realpath, "/dev/null") == 0) {
        service->start_type = 3; //禁用 masked。在运行的服务也可以禁止掉，使得下次无法运行

        /* 这已经是安装服务时的配置文件，指向/dev/null说明已经彻底禁用销毁，没必要再解析了 */
        if (strstr(service->serv_path, "/lib/")) {
            return;
        }

        /* 查找安装服务时的原始配置文件 */
        i = 0;
        found = 0;
        while (service_conf_path[i]) {
            if (!strstr(service_conf_path[i], "/lib/")) {
                i++;
                continue; // /etc和/run下的配置文件不是安装服务时的原始配置文件
            }

            snprintf(path, sizeof(path), "%s%s.service", service_conf_path[i], service_conf_name);
            if (access(path, F_OK) == 0) {
                found = 1;
                break;
            }
            i++;
        }

        if (found = 0) {
            return; //没有安装服务时的原始配置文件
        }

    } else {
        if (strncmp(service->serv_path, "/etc/systemd/", 13) == 0) {
            service->start_type = 2; //自动
        }

        /*
         * 对于/etc/systemd/system/sshd.service -> /lib/systemd/system/ssh.service的情况，
         * 如果sshd.service的运行状态为停止，再取一次ssh.service的运行状态
         */
        if (service->run_state != 1) {
            ptr  = strrchr(service->serv_path, '/');
            ptr2 = strrchr(realpath, '/');
            if (ptr && ptr2 && strcmp(ptr, ptr2) != 0) {
                service->run_state = get_service_run_state(ptr2+1);
            }
        }
    }

    /* 安全性检查，防止path非普通文件，导致下面的fgets总也读不完文件 */
    if (stat(path, &st) < 0) {
        elog("stat service conf %s fail: %s\n", path, strerror(errno));
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        elog("service conf %s bad type %o\n", path, st.st_mode);
        return;
    }

    /* 解析服务配置文件，获取服务的描述、启动的命令、是否可配置为开机自动运行 */
    fp = fopen(path, "r");
    if (!fp) {
        elog("open service conf %s fail: %s\n", path, strerror(errno));
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char key[S_LINELEN] = {0};
        char value[S_LINELEN] = {0};

        if (get_key_value_from_line(line, key, sizeof(key),
                                    value, sizeof(value), '=') < 0) {
            ptr = skip_headspace(line);
            if (strncmp(ptr, "[Install]", 9) == 0) {
                if (service->start_type != 2) {
                    /* 允许配置成开机自动起，但没有配，视为手动起 */
                    service->start_type = 1;
                }
            }
            continue;
        }

        if (strcmp(key, "Description") == 0) {
            snprintf(service->desc, sizeof(service->desc), "%s", delete_tail_backslash(value));
            continue;
        }

        if (strcmp(key, "ExecStart") == 0) {
            snprintf(service->exec_path, sizeof(service->exec_path), "%s", delete_tail_backslash(value));
            continue;
        }

        /* 如果没有start命令，存reload命令 */
        if (service->exec_path[0] == 0 && strcmp(key, "ExecReload") == 0) {
            snprintf(service->exec_path, sizeof(service->exec_path), "%s", delete_tail_backslash(value));
            continue;
        }

        /* 如果没有start命令，存stop命令。如clean-mount-point@.service就只有stop命令 */
        if (service->exec_path[0] == 0 && strcmp(key, "ExecStop") == 0) {
            snprintf(service->exec_path, sizeof(service->exec_path), "%s", delete_tail_backslash(value));
            continue;
        }
    }

    fclose(fp);

    /* 不允许配置启动方式，通常是由其他行为触发，视为自动(延迟) */
    if (service->start_type == 0) {
        service->start_type = 4;
    }

    find_current_rpm(service, path);
}

static void get_service_info(serv_info_t *service, char *service_conf_name)
{
    int i = 0, found = 0;
    char *ptr = NULL;

    if (!service || !service_conf_name) {
        return;
    }

    /* 查找服务配置文件 */
    while (service_conf_path[i]) {
        snprintf(service->serv_path, sizeof(service->serv_path),
                 "%s%s.service", service_conf_path[i], service_conf_name);
        if (access(service->serv_path, F_OK) == 0) {
            found = 1;
            break;
        }
        i++;
    }

    if (strncmp(service->serv_path, "/etc/init.d/", 12) == 0) {
        ptr = strstr(service->serv_path, ".service");
        if (ptr) {
            *ptr = 0;
            if (access(service->serv_path, F_OK) == 0) {
                found = 1;
            }
        }
    }

    /* 没有找到配置文件，也报告出来，使得可以看到异常 */
    if (!found) {
        memset(service->serv_path, 0, sizeof(service->serv_path));
        return;
    }

    /* /etc/init.d/任务在get_initd_services()里处理 */
    if (strncmp(service->serv_path, "/etc/init.d/", 12) == 0) {
        return;
    }

    get_service_info_from_conf(service, service_conf_name);
}

/* 如果没有描述，用服务名作为描述 */
static void adjust_service_desc(serv_info_t *service)
{
    char name[S_LINELEN] = {0};
    char *ptr = NULL;

    if (!service) {
        return;
    }

    if (service->desc[0]) {
        return;
    }

    snprintf(name, sizeof(name), "%s", service->serv_name);
    ptr = strchr(name, '@');
    if (ptr) {
        *ptr = 0; //消除服务名称@之后的部分
    }
    snprintf(service->desc, sizeof(service->desc), "%s service", name);

    ptr = service->desc;
    while (*ptr) {
        if (*ptr == '-') {
            *ptr = ' '; // Accounts-daemon service -> Accounts daemon service
        }
        ptr++;
    }
    if (islower(service->desc[0])) {
        service->desc[0] += 'A' - 'a'; //首字母大写
    }
}

/* 确认服务的启动方式是手动还是自动 */
static int get_service_start_type(char *serv_path)
{
    int i = 0, len = 0;
    struct stat st1 = {0}, st2 = {0};
    char path[PATH_MAX] = {0}, *ptr = NULL;
    DIR *dirp = NULL;
    struct dirent *dent = NULL;

    if (!serv_path) {
        return 1; //手动
    }

    if (stat(serv_path, &st1) < 0) {
        return 1; //默认手动
    }

    while (service_conf_path[i]) {
        if (strncmp(service_conf_path[i], "/etc/systemd/", 13) != 0) {
            i++;
            continue;
        }

        dirp = opendir(service_conf_path[i]);
        if (!dirp) {
            if (errno != ENOENT) {
                elog("open %s fail: %s\n", service_conf_path[i], strerror(errno));
            }
            i++;
            continue;;
        }

        while ((dent = readdir(dirp)) != NULL) {
            /* 服务应以.service结尾 */
            len = strlen(dent->d_name);
            if (len <= 8) {
                continue;
            }

            ptr = dent->d_name + len - 8;
            if (strcmp(ptr, ".service") != 0) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", service_conf_path[i], dent->d_name);
            if (stat(path, &st2) == 0 && st2.st_ino == st1.st_ino) {
                closedir(dirp);
                return 2; //inode号相同，说明是同一个文件，视为开机自动启动
            }
        }

        closedir(dirp);
        i++;
    }

    return 1; //手动
}

static void get_systemd_active_services(sys_info_t *data)
{
    DIR *dirp = NULL;
    struct dirent *dent = NULL;

    if (!data) {
        return;
    }

    /*
     * 从/sys/fs/cgroup/systemd/system.slice/下取active的服务
     * active running 正在运行的，active exited 曾经运行过，已经结束了
     */
    dirp = opendir(SYSTEM_SLICE);
    if (!dirp) {
        if (errno == ENOENT) {
            dlog("no %s\n", SYSTEM_SLICE);
        } else {
            elog("open %s fail: %s\n", SYSTEM_SLICE, strerror(errno));
        }
        return;
    }

    while ((dent = readdir(dirp)) != NULL) {
        int len = 0;
        char *ptr = NULL;
        char service_conf_name[S_LINELEN] = {0};
        serv_info_t service;

        memset(&service, 0, sizeof(serv_info_t));

        /* 取服务名 */
        snprintf(service.serv_name, sizeof(service.serv_name), "%s", dent->d_name);

        /* 服务应以.service结尾 */
        len = strlen(service.serv_name);
        if (len <= 8) {
            continue;
        }

        ptr = service.serv_name + len - 8;
        if (strcmp(ptr, ".service") != 0) {
            continue;
        }
        *ptr = 0; //bluetooth.service -> bluetooth

        /* 如果服务名包含@，如getty@tty1，取服务的配置名getty@，用于获取服务配置 */
        snprintf(service_conf_name, sizeof(service_conf_name), "%s", service.serv_name);
        ptr = strchr(service_conf_name, '@');
        if (ptr) {
            *(ptr+1) = 0; //getty@tty1 -> getty@
        }

        /* 取服务状态：1 已启动、2 已暂停、3 已停止 */
        service.run_state = get_service_run_state(dent->d_name);

        get_service_info(&service, service_conf_name);

        /* /etc/init.d/任务在get_initd_services()里处理 */
        if (strncmp(service.serv_path, "/etc/init.d/", 12) == 0) {
            continue;
        }

        adjust_service_desc(&service);

        /*
         * 对于/etc/systemd/system/sshd.service -> /lib/systemd/system/ssh.service的情况，
         * ssh.service运行过，但因无/etc/systemd/system/ssh.service，而启动方式为手动，
         * 再确认一次，是否有其他服务指向了他
         */
        if (service.start_type == 1 && strstr(service.serv_path, "/lib/") && !strchr(service_conf_name, '@')) {
            service.start_type = get_service_start_type(service.serv_path);
        }

        update_service_name(&service, data);
    }

    closedir(dirp);
}

/* Debian上systemctl list-units -t service有user@服务，而CentOS上则不视为服务 */
static void get_systemd_user_services(sys_info_t *data)
{
    DIR *dirp = NULL;
    struct dirent *dent = NULL;

    if (!data) {
        return;
    }

    /*
     * 从/sys/fs/cgroup/systemd/user.slice/下取active的服务
     * active running 正在运行的，active exited 曾经运行过，已经结束了
     */
    dirp = opendir(USER_SLICE);
    if (!dirp) {
        if (errno == ENOENT) {
            dlog("no %s\n", USER_SLICE);
        } else {
            elog("open %s fail: %s\n", USER_SLICE, strerror(errno));
        }
        return;
    }

    while ((dent = readdir(dirp)) != NULL) {
        char *ptr = NULL;
        serv_info_t service;

        if (strncmp(dent->d_name, "user-", 5) != 0) {
            continue;
        }

        memset(&service, 0, sizeof(serv_info_t));

        /* 取服务名 */
        snprintf(service.serv_name, sizeof(service.serv_name), "%s", dent->d_name);

        ptr = strchr(service.serv_name, '.');
        if (ptr) {
            *ptr = 0; //user-1000.slice -> user-1000
        }
        service.serv_name[4] = '@'; //user-1000 -> user@1000

        service.run_state = 1; //服务仍在运行
        service.start_type = 4; //user服务禁止配置启动方式，视为自动(延迟)

        get_service_info(&service, "user@");
        if (service.serv_path[0] == 0) {
            continue; //无配置文件，视为无此服务
        }

        adjust_service_desc(&service);

        update_service_name(&service, data);
    }

    closedir(dirp);
}

static void get_systemd_inactive_services_bypath(char *dir, sys_info_t *data)
{
    DIR *dirp = NULL;
    struct dirent *dent = NULL;

    if (!dir || !data || !data->db) {
        return;
    }

    dirp = opendir(dir);
    if (dirp == NULL) {
        if (errno == ENOENT) {
            dlog("no %s\n", dir);
        } else {
            elog("open %s fail: %s\n", dir, strerror(errno));
        }
        return;
    }

    while ((dent = readdir(dirp)) != NULL) {
        int len = 0;
        char *ptr = NULL;
        serv_info_t service;
        struct stat st = {0};
        char buf[1024] = {0};
        int rc = 0;
        int nrow = 0, ncolumn = 0;
        char **azResult = NULL;

        memset(&service, 0, sizeof(serv_info_t));

        /* 取服务名 */
        snprintf(service.serv_name, sizeof(service.serv_name), "%s", dent->d_name);

        /* 服务应以.service结尾 */
        len = strlen(service.serv_name);
        if (len <= 8) {
            continue;
        }

        ptr = service.serv_name + len - 8;
        if (strcmp(ptr, ".service") != 0) {
            continue;
        }
        *ptr = 0; //bluetooth.service -> bluetooth

        /* 如果服务名带@，如user@，库里可能已经有user@1000，这时要查找是否有user@开头的记录 */
        if (*(ptr-1) == '@') {
            snprintf(buf, sizeof(buf), "SELECT id FROM sys_service WHERE name LIKE '%s%%';", service.serv_name);
        } else {
            snprintf(buf, sizeof(buf), "SELECT id FROM sys_service WHERE name='%s';", service.serv_name);
        }
        rc = sqlite3_get_table(data->db, buf, &azResult, &nrow, &ncolumn, NULL);
        sqlite3_free_table(azResult);

        if (rc != SQLITE_OK) {
            elog("Query service %s fail\n", service.serv_name);
            continue;
        }

        if (nrow != 0) {
            continue; //统计过的服务不重复统计
        }

        service.run_state = 3; //停止

        snprintf(service.serv_path, sizeof(service.serv_path), "%s%s", dir, dent->d_name);

        get_service_info_from_conf(&service, service.serv_name);

        /*
         * 忽略配置文件不存在的服务，如
         * /lib/systemd/system/dbus-org.freedesktop.network1.service -> systemd-networkd.service
         * 但systemd-networkd.service不存在
         */
        if (service.exec_path[0] == 0) {
            if (stat(service.serv_path, &st) < 0) {
                continue;
            }
        }

        adjust_service_desc(&service);

        update_service_name(&service, data);
    }

    closedir(dirp);
}

static void get_systemd_inactive_services(sys_info_t *data)
{
    int i = 0;

    /* 从服务配置目录下获取没运行过的服务列表 */
    while (service_conf_path[i]) {
        if (strcmp(service_conf_path[i], "/etc/init.d/") == 0) {
            break;
        }

        get_systemd_inactive_services_bypath(service_conf_path[i], data);
        i++;
    }
}

static void get_systemd_services(sys_info_t *data)
{
    get_systemd_user_services(data);
    get_systemd_active_services(data);
    get_systemd_inactive_services(data);
}

/* 自动：存在/etc/rc.d/rc[runlevel].d/Sxxx -> serv_path */
static int get_initd_service_start_type(char *serv_path, int runlevel)
{
    char path[PATH_MAX] = {0};
    char dir[PATH_MAX] = {0};
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    struct stat st1 = {0}, st2 = {0};

    if (!serv_path) {
        return 1; //默认手动
    }
    if (stat(serv_path, &st1) < 0) {
        return 1; //默认手动
    }

    snprintf(dir, PATH_MAX, "/etc/rc.d/rc%d.d/", runlevel);

    dirp = opendir(dir);
    if (dirp == NULL) {
        if (errno != ENOENT) {
            elog("open %s fail: %s\n", dir, strerror(errno));
            return 1; //默认手动
        }

        snprintf(dir, PATH_MAX, "/etc/rc%d.d/", runlevel);
        dirp = opendir(dir);
        if (dirp == NULL) {
            elog("open %s fail: %s. also no /etc/rc.d/rc%d.d/\n", dir, strerror(errno), runlevel);
            return 1; //默认手动
        }
    }

    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] != 'S') {
            continue; //不是启动任务
        }

        snprintf(path, sizeof(path), "%s%s", dir, dent->d_name);
        if (stat(path, &st2) == 0 && st2.st_ino == st1.st_ino) {
            closedir(dirp);
            return 2; //inode号相同，说明是同一个文件，视为开机自动启动
        }
    }

    closedir(dirp);

    return 1; //默认手动
}

/* 服务状态：1 已启动、2 已暂停、3 已停止 */
static int get_initd_service_status(char *serv_path)
{
    int can_status = 0;
    char cmd[PATH_MAX] = {0};
    char line[S_LINELEN] = {0};
    char *ptr = NULL, *str = NULL;
    FILE *fp = NULL;
    const char *running_en = "is running";
    const char *running_ch = "正在运行";
    const char *operational= "is operational";
    const char *stopped_en = "is stopped";
    const char *stopped_other = "is not running";
    const char *stopped_ch = "已停";
    const char *not_operational= "is not operational";

    if (!serv_path) {
        return 0; //不确定
    }

    fp = fopen(serv_path, "r");
    if (!fp) {
        elog("get service %s status fail: %s\n", serv_path, strerror(errno));
        return 0; //不确定
    }

    while (fgets(line, sizeof(line), fp)) {
        char buf[S_LINELEN] = {0};
        char *ptr = line;
        char *str = buf;

        while (*ptr) {
            if (!isspace(*ptr) && *ptr != '\'' && *ptr != '"') {
                *str = *ptr;
                str++;
            }
            ptr++;
        }

        if (strcmp(ptr, "start)") == 0 || strstr(ptr, "[$1=status]")) {
            can_status = 1;
        }
    }

    fclose(fp);

    /*
     * 如果脚本中没有定义status操作，则不查
     * 遇见过一个很坑的不规范脚本，脚本的作用是断网
     * 由于没有status，一查状态就离线了
     */
    if (!can_status) {
        return 0; //不确定
    }

    snprintf(cmd, sizeof(cmd), "%s status 2>/dev/null", serv_path);
    fp = popen(cmd, "r");
    if (!fp) {
        elog("get service %s status fail, do %s error %s\n", serv_path, cmd, strerror(errno));
        return 0; //不确定
    }

    fgets(line, sizeof(line), fp);
    pclose(fp);

    if (strstr(line, running_en) || strstr(line, operational) || strstr(line, running_ch)) {
        return 1; //运行
    }

    if (strstr(line, stopped_en) || strstr(line, stopped_other) ||
        strstr(line, not_operational) || strstr(line, stopped_ch)) { /* stop */
        return 3; //停止
    }

    return 0; //不确定
}

static void get_initd_service_desc(serv_info_t *service)
{
    FILE *fp = NULL;
    char line[S_LINELEN] = {0};
    char *ptr = NULL, *desc = NULL;

    if (!service) {
        return;
    }

    fp = fopen(service->serv_path, "r");
    if (!fp) {
        elog("open %s fail: %s\n", service->serv_path, strerror(errno));
        return;
    }

    /* 找# Short-Description: xxxx或# Description: xxxx */
    while (fgets(line, sizeof(line), fp)) {
        ptr = skip_headspace(line);
        if (line[0] != '#') {
            continue;
        }

        desc = strcasestr(line, "Description");
        if (!desc) {
            continue;
        }

        ptr = strchr(desc+11, ':');
        if (ptr) {
            desc = skip_headspace(ptr+1);
            delete_tailspace(desc);
            snprintf(service->desc, sizeof(service->desc), "%s", delete_tail_backslash(desc));
            break;
        }
    }

    fclose(fp);
}

static int get_runlevel(void)
{
    char oldlevel = 0, nowlevel = 0;
    struct utmpx u = {0};
    int fd = 0, size = sizeof(u);

    fd = open("/var/run/utmp", O_RDONLY);
    if (fd < 0) {
        elog("get_runlevel fail, open /var/run/utmp error: %s\n", strerror(errno));
        return 0;
    }

    /* getutent/getutxent取到的总是老的值，如53 0 0 0，原因不明。用read可以取到54 53 0 0 */
    while (read(fd, (char *)&u, size) > 0) {
        if (u.ut_type == RUN_LVL) {
            /* ut_pid的低8位是当前的运行级别，8~15位是上一次的运行级别 */
            nowlevel = u.ut_pid & 0xff;
            oldlevel = (u.ut_pid & 0xff00) >> 8;

            /* 和runlevel命令的结果一致，如N 5或5 3，后者表示从级别5切换到了级别3，如init 3 */
            dlog("runlevel: %c %c\n", oldlevel == 0 ? 'N' : oldlevel, nowlevel);
            nowlevel -= '0';
            break;
        }
    }
    close(fd);

    return nowlevel;
}

static void get_initd_services(sys_info_t *data)
{
    int runlevel = 0;
    DIR *dirp = NULL;
    struct dirent *dent = NULL;

    if (!data || !data->db) {
        return;
    }

    runlevel = get_runlevel(); //取当前系统运行级别
    if (runlevel == 0) {
        runlevel = 3; //默认3级
    }

    dirp = opendir("/etc/init.d/");
    if (dirp == NULL) {
        if (errno == ENOENT) {
            dlog("no /etc/init.d/\n");
        } else {
            elog("open /etc/init.d/ fail: %s\n", strerror(errno));
        }
        return;
    }

    while ((dent = readdir(dirp)) != NULL) {
        char *ptr = NULL;
        serv_info_t service;
        char buf[1024] = {0};
        int rc = 0;
        int nrow = 0, ncolumn = 0;
        char **azResult = NULL;

        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
            continue;
        }

        memset(&service, 0, sizeof(serv_info_t));

        /* 获取服务名 */
        snprintf(service.serv_name, sizeof(service.serv_name), "%s", dent->d_name);

        snprintf(buf, sizeof(buf), "SELECT id,path FROM sys_service WHERE name='%s';", service.serv_name);
        rc = sqlite3_get_table(data->db, buf, &azResult, &nrow, &ncolumn, NULL);
        sqlite3_free_table(azResult);

        if (rc != SQLITE_OK) {
            elog("Query service %s fail\n", service.serv_name);
            continue;
        }

        if (nrow != 0) {
            continue; //统计过的服务不重复统计
        }

        snprintf(service.serv_path, sizeof(service.serv_path), "/etc/init.d/%s", dent->d_name);
        snprintf(service.exec_path, sizeof(service.exec_path), "%s start", service.serv_path);
        service.start_type = get_initd_service_start_type(service.serv_path, runlevel);

        service.run_state = get_initd_service_status(service.serv_path);
        /* /etc/init.d/xxx status的结果可能和systemctl status xxx一样，再按systemd方法试一下 */
        if (service.run_state == 0) {
            char service_name[S_LINELEN] = {0};

            snprintf(service_name, S_LINELEN, "%s.service", service.serv_name);
            service.run_state = get_service_run_state(service_name);
        }

        get_initd_service_desc(&service);
        adjust_service_desc(&service);

        find_current_rpm(&service, service.serv_path);

        update_service_name(&service, data);
    }

    closedir(dirp);
}

/* JSON service */
void *sys_service_info(sys_info_t *data)
{
    int ret = 0;

    if (!data || !data->object || !data->db) {
        return NULL;
    }

    /* create service table */
    ret = exec_sql(data->db, sql_service);
    if (ret) {
        elog("Create service table failed, ret:%d\n", ret);
        return NULL;
    }

    ret = exec_sql(data->db, "BEGIN;");
    if (ret) {
        elog("Service BEGIN failed\n");
        return NULL;
    }

    get_systemd_services(data);
    get_initd_services(data);

    ret = exec_sql(data->db, "COMMIT;");
    if (ret) {
        elog("Service COMMIT failed\n");
        return NULL;
    }

    /* make JSON */
    make_service_json(data);

    return NULL;
}
void *sys_service_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static int check_keystr(char *str, char *key)
{
    int keylen = 0;
    char *ptr = NULL;

    if (str == NULL || key == NULL) return 0;

    keylen = strlen(key);

    if (strncmp(str, key, keylen) != 0) {
        return 0;
    }

    ptr = str + keylen;
    while (isspace(*ptr)) {
        ptr++;
    }
    if (*ptr == '=') {
        return 1;
    }
    return 0;
}
static char *get_file_vendor(char *filepath)
{
    char cmd[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char vendor[NAME_MAX] = {0};
#ifdef SNIPER_FOR_DEBIAN
    char package[NAME_MAX] = {0};
#endif
    char *ptr = NULL;
    int ret = 0;

    if (filepath == NULL) {
        return strdup("None");
    } 

#ifdef SNIPER_FOR_DEBIAN
    /* 查文件属于哪个软件包 */
    snprintf(cmd, sizeof(cmd), "dpkg-query -S %s", filepath);
    if (popen_filter_one_keystr(cmd, NULL, package, sizeof(package)) < 0) {
        return strdup("None");
    }

    ptr = strchr(package, ':'); //如coreutils: /bin/ls
    if (ptr) *ptr = '\0';

    /* 检查是否为有效的包名 */
    ptr = skip_headspace(package);
    delete_tailspace(package);
    if (package[0] == 0 || strchr(package, ' ')) {
        return strdup("None");
    }

    /* 查软件包的厂商 */
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "dpkg-query -W --showformat='${Maintainer}' %s", package);
#else
    snprintf(cmd, sizeof(cmd), "rpm -qf --qf \"%{VENDOR}\" %s", filepath);
#endif

    ret = popen_filter_one_keystr(cmd, NULL, vendor, sizeof(vendor));
    /* 如果文件没有对应的软件包，rpm会返回file xxx is not owned by any package */
    if (ret < 0 || strstr(vendor, "not owned")) {
        return strdup("None");
    }

    return strdup(vendor);
}

/* JSON starter */
void *sys_starter_info(sys_info_t *data)
{
    DIR *dp = NULL;
    struct dirent *ent = NULL;

    if (data->object == NULL) return NULL;

    cJSON *autostart_list = data->object;

    dp = opendir("/etc/xdg/autostart");
    if (dp == NULL) {
    return NULL;
    }

    while ((ent = readdir(dp))) {
        char path[PATH_MAX] = {0};
        char line[PATH_MAX] = {0};
        char exec[PATH_MAX] = {0};
        char name[NAME_MAX] = {0};
        char desc[NAME_MAX] = {0};
        char title[NAME_MAX] = {0};
        FILE *fp = NULL;
        int len = 0;
        char *str = NULL;
        char *value = NULL;

        if (strstr(ent->d_name, ".desktop") == NULL) {
            continue;
        }
        len = strlen(ent->d_name) - 8;
        /* len最大247, name长度S_LINELEN(512) */
        memcpy(name, ent->d_name, len);
        name[len] = 0;

        snprintf(path, sizeof(path), "/etc/xdg/autostart/%s", ent->d_name);
        fp = fopen(path, "r");
        if (fp == NULL) {
                continue;
        }

        while (fgets(line, sizeof(line), fp) != NULL) {
            str = trim_space(line);
            value = strchr(str, '=');
            if (!value) {
                continue;
            }
            value++;

            /* value长度小于S_LINELEN */
            /* 中文注释优先采用 */
            if (check_keystr(str, "Name[zh_CN]")) {
                strncpy(title, value, sizeof(title));
            }
            else if (title[0] == 0 && check_keystr(str, "Name")) {
                strncpy(title, value, sizeof(title));
            }
            else if (check_keystr(str, "Comment[zh_CN]")) {
                strncpy(desc, value, sizeof(desc));
            }
            else if (desc[0] == 0 && check_keystr(str, "Comment")) {
                strncpy(desc, value, sizeof(desc));
            }
            else if (check_keystr(str, "Exec")) {
                strncpy(exec, value, sizeof(exec));
            }
        }
        fclose(fp);

        if (desc[0] == 0) {
            if (title[0]) {
                strncpy(desc, title, sizeof(desc)-1);
            } else {
                strncpy(desc, name, sizeof(desc)-1);
            }
        }

        cJSON *object = cJSON_CreateObject();

        cJSON_AddStringToObject(object, "item_name", name);
        cJSON_AddStringToObject(object, "item_user", "root");
        /* 0 默认值 1启动 2禁用 */
        cJSON_AddNumberToObject(object, "start_type", 1);
        cJSON_AddStringToObject(object, "cmd_line", exec);
        cJSON_AddStringToObject(object, "item_desc", desc);

        if (strcmp(ent->d_name, "snipertray.desktop") == 0) {
            cJSON_AddStringToObject(object, "vendor", SNIPER_VENDOR);
        } else {
            str = get_file_vendor(path);
            if (str) {
                cJSON_AddStringToObject(object, "vendor", str);
                free(str);
            } else {
                cJSON_AddStringToObject(object, "vendor", "None");
            }
        }

        cJSON_AddItemToArray(autostart_list, object);
    }

    closedir(dp);

    return NULL;
}
void *sys_starter_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static char *trim_left(char *pStr)
{
    char *p = NULL;
    char *pEnd = NULL;
    int nDestLen = 0;

    if (pStr == NULL) return pStr;

    pEnd = pStr + strlen(pStr);
    for (p=pStr; p<pEnd; p++) {
        if (!(' ' == *p|| '\n' == *p || '\r' == *p || '\t' == *p)) {
            break;
        }
    }

    if ( p == pStr) {
        return pStr;
    }

    nDestLen = (pEnd - p) + 1; //including \0
    memmove(pStr, p, nDestLen);

    return pStr;
}

static int get_samb_info(sys_info_t *data)
{
    char line[PATH_MAX];
    char smb_name[NAME_MAX];
    FILE *fp = NULL;
    char *p_str = NULL;
    char *description = NULL;
    char *nallstr = "N/A";
    int i = 0;
    int len = 0;

    if (data->object == NULL) return -1;

    fp = fopen("/etc/samba/smb.conf", "r");
    if (fp == NULL) {
        return -1;
    }

    memset(&line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strlen(line) < 2) continue;
        if (line[0] == '#' || line[0] == ';') continue;

        p_str =  trim_left(line);
        if (p_str[0] == '#' || p_str[0] == ';') continue;

        memset(&smb_name, 0x00, sizeof(smb_name));
        if (sscanf(p_str, "[%[^]]", smb_name) == 1) {
            if (strstr(smb_name, "global") || strstr(smb_name, "homes") || strstr(smb_name, "printers")) {
                continue;
            }

            //printf("name:%s\n", smb_name);
            char smb_desc[64] = {0};
            char smb_path[64] = {0};
            for (i = 0; i < 8; i++) {
                if (fgets(line, sizeof(line), fp) == NULL) break;
                if (line[0] == '[') break;

                p_str = trim_left(line);
                if (p_str[0] == ';') continue;

                len = strlen(p_str);
                if (len == 0) break;

                //printf("---line:%s---\n", p_str);
                if (strncmp(p_str, "comment =", 9) == 0) {
                    strncpy(smb_desc, p_str + 10, len - 11);
                }

                if (strncmp(p_str, "path =", 6) == 0) {
                    strncpy(smb_path, p_str + 7, len - 8);
                }
            }
            //printf("---name:%s, path:%s, comment:%s---\n", smb_name, smb_path, smb_desc);
            if (strlen(smb_name) > 2) {
                cJSON *smb_info = cJSON_CreateObject();
                cJSON_AddItemToArray(data->object, smb_info);
                cJSON_AddStringToObject(smb_info,"share_name", smb_name);
                cJSON_AddStringToObject(smb_info,"share_path", smb_path);
                cJSON_AddStringToObject(smb_info,"share_type", "SAMBA");
                if(smb_desc[0] == 0) {
                    description = nallstr;
                }
                else {
                    description = smb_desc;
                }
                cJSON_AddStringToObject(smb_info,"share_desc", description);
            }
        }
    }
    fclose(fp);

    return 0;
}

/* JSON share */
void *sys_share_info(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    get_samb_info(data);
    
    //todo
    //get_ntfs_list(data);

    return NULL;
}
void *sys_share_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

/* JSON env */
void *sys_env_info(sys_info_t *data)
{
    char *env_names[] = {"CONSOLETYPE", "CVS_RSH", "HISTCONTROL", "HISTSIZE", "HOME", "HOSTNAME",
                        "LANG", "LC_ADDRESS", "LC_IDENTIFICATION", "LC_MEASUREMENT", "LC_MONETARY",
                        "LC_NAME", "LC_NUMERIC", "LC_PAPER", "LC_TELEPHONE", "LC_TIME", "LOGNAME",
                        "MAIL", "PATH", "QTDIR", "QTINC", "QTLIB", "RUNLEVEL", "SHELL", "TERM",
                        "TZ", "XDG_RUNTIME_DIR", "XDG_SESSION_ID", NULL};
    char *value = NULL;
    int i = 0;

    if (data->object == NULL) return NULL;
    cJSON *env_info = data->object;

    while (env_names[i] != NULL) {
        value = getenv(env_names[i]);
        if(value == NULL) {
            i++;
            continue;
        }

        cJSON *object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "env_name", env_names[i]);
        cJSON_AddStringToObject(object, "variable_type", "SYSTEM");
        cJSON_AddStringToObject(object, "env_user", "root");
        cJSON_AddStringToObject(object, "env_value", value);
        cJSON_AddItemToArray(env_info, object);
        i++;
    }

    return NULL;
}
void *sys_env_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

extern void get_cron_list(cJSON *cron);
void *sys_task_info(sys_info_t *data)
{
    if (data && data->object) {
        cJSON *cron = data->object;
        get_cron_list(cron);
    }

    return NULL;   
}

void *sys_task_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

/* JSON database */
extern void get_databases_list(const char *pid, cJSON *databases_modules, const char *cmdline);
void *sys_database_info(sys_info_t *data)
{
    int ret = 0;
    sqlite3_stmt *stmt = NULL;
    const char *path = NULL, *pid = NULL, *cmdline = NULL;

    if (!data || !data->object || !data->db) return NULL;

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, "SELECT path,pid,cmdline FROM sys_process;", -1, &stmt, NULL);
    if (ret != SQLITE_OK){
        elog("sqlite3_prepare_v2\n");
        return NULL;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        path = sqlite3_column_text(stmt, 0);
        if (path[0] != '/') {
            continue;
        }

        pid = sqlite3_column_text(stmt, 1);
        cmdline = sqlite3_column_text(stmt, 2);

        get_databases_list(pid, data->object, cmdline);
    }

    sqlite3_finalize(stmt);

    return NULL;
}
void *sys_database_info_destroy(sys_info_t *data)
{
    return NULL;
}

/* JSON pkg_install */
void *sys_pkg_install_info(sys_info_t *data)
{
    if (data == NULL || data->object == NULL) return NULL;

    if (software_info) { // software数据已有
        data->object = cJSON_Duplicate(software_info, 1);
        return NULL;
    }

#ifdef SNIPER_FOR_DEBIAN
    sys_deb_packages(data);
#else
    sys_rpm_packages(data);
#endif
    return NULL;
}
void *sys_pkg_install_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static char *sql_jar = 
            "CREATE TABLE IF NOT EXISTS jar_info(Id INTERGER PRIMARY KEY, \
                                     pid TEXT, \
                                jar_name TEXT, \
                                 version TEXT, \
                              is_execute INTEGER, \
                                jar_path TEXT NOT NULL UNIQUE, \
                                     md5 TEXT, \
    /* create time */           ctime TIMESTAMP, \
    /* last check time */       ltime TIMESTAMP);";

/*
 * 将Jar的信息存储到DB中
 * 先根据jar包绝对路径查询，若已有则需要拼接pid，否则插入新的jar包信息
 */
static int update_db_jar_info(sys_info_t *data, const char *pid, const char *name, const char *version, 
                    const int is_execute, const char *md5, const char *jar_path)
{
    char cmd_sql[PATH_MAX] = {0};
    char pid_all[PATH_MAX] = {0};
    sqlite3_stmt *stmt = NULL;
    const char *zTail = NULL;
    const char *select_sql = "select pid from jar_info where jar_path='%s'";
    const char *update_sql = 
        "INSERT OR REPLACE INTO jar_info (pid,jar_name,version,is_execute,jar_path,md5,ctime) \
            VALUES('%s', '%s', '%s', '%d', '%s', '%s', '%s');";
    int ret = 0;
    int len = 0;

    if (!data || !data->db || !pid || !name || !version || !md5 || !jar_path) {
        return -1;
    }

    snprintf(cmd_sql, sizeof(cmd_sql), select_sql, jar_path);
    ret = sqlite3_prepare_v2(data->db, cmd_sql, -1, &stmt, &zTail);
    if (ret != SQLITE_OK) {
        elog("No Jar\n");
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *tmp_pid = sqlite3_column_text(stmt, 0);
        snprintf(pid_all, sizeof(pid_all), "%s", tmp_pid);
    }

    sqlite3_finalize(stmt);

    if (pid_all[0]) {
        if (strstr(pid_all, pid)) { // 已记录过pid
            return 0;
        }
        len = strlen(pid_all);
        snprintf(pid_all+len, sizeof(pid_all)-len, ",%s", pid);
    } else {
        snprintf(pid_all, sizeof(pid_all), "%s", pid);
    }

    snprintf(cmd_sql, sizeof(cmd_sql), update_sql, 
            pid_all, name, version, is_execute, jar_path, md5, data->time_str);

    ret = exec_sql(data->db, cmd_sql);
    if (ret) {
        elog("update jar info failed, sql:%s\n", cmd_sql);
    }

    return ret;
}
/* 查询数据库jar_info表生成Jar包的Json数据 */
static int generate_jar_info(sys_info_t *data)
{
    sqlite3_stmt *stmt = NULL;
    int ret = 0;
    const char *zTail = NULL;
    const char *update_sql = "select group_concat(pid),jar_name, \
                    version,is_execute,jar_path,md5 from jar_info group by jar_path;";

    if (data == NULL || data->db == NULL || data->object == NULL) {
        return -1;
    }

    cJSON *jar_info = data->object;

    /* query jar info from db */
    ret = sqlite3_prepare_v2(data->db, update_sql, -1, &stmt, &zTail);
    if (ret !=SQLITE_OK){
        elog("No Jar\n");
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *pids = sqlite3_column_text(stmt, 0);
        const char *jar_nam = sqlite3_column_text(stmt, 1);
        const char *version = sqlite3_column_text(stmt, 2);
        const int is_execute = sqlite3_column_int(stmt, 3);
        const char *jar_path = sqlite3_column_text(stmt, 4);
        const char *md5 = sqlite3_column_text(stmt, 5);

        cJSON *object = cJSON_CreateObject();
        if (*version == ' ') {
            cJSON_AddStringToObject(object, "jar_name_e", jar_nam);
            cJSON_AddStringToObject(object, "version_e", version);
            /* # jar 类型   # 0 默认值 1 应用程序，2 系统类库，3 web服务自带库，4 其他依赖包' */
            cJSON_AddNumberToObject(object, "jar_type_e", 0);
            cJSON_AddNumberToObject(object, "is_execute_e", is_execute);
            cJSON_AddStringToObject(object, "abs_path_e", jar_path);
            cJSON_AddStringToObject(object, "md5_e", md5);
            cJSON_AddNumberToObject(object, "is_citation_e", 0);
            cJSON_AddStringToObject(object, "jar_process_e", " ");
            cJSON_AddStringToObject(object, "pids_e", pids);
        } else {
            cJSON_AddStringToObject(object, "jar_name", jar_nam);
            cJSON_AddStringToObject(object, "version", version);
            /* # jar 类型   # 0 默认值 1 应用程序，2 系统类库，3 web服务自带库，4 其他依赖包' */
            cJSON_AddNumberToObject(object, "jar_type", 0);
            cJSON_AddNumberToObject(object, "is_execute", is_execute);
            cJSON_AddStringToObject(object, "abs_path", jar_path);
            cJSON_AddStringToObject(object, "md5", md5);
            cJSON_AddNumberToObject(object, "is_citation", 0);
            cJSON_AddStringToObject(object, "jar_process", " ");
            cJSON_AddStringToObject(object, "pids", pids);
        }
        cJSON_AddItemToArray(jar_info, object);
    }

    sqlite3_finalize(stmt);

    return 0;
}

/* 这里docker容器，是指运行在docker某个镜像上的容器进程，ps 可以看到一个容器即一个进程
 * 多个容器可以运行在同一个镜像上，镜像不可更改。容器内更改只发生在自身容器范围内，不影响镜像和其它容器
 * 查找当前docker容器的进程的信息，确定docker容器存储目录
 */
static int check_docker_container_path(const char *pid, char *result_path, unsigned int path_len)
{
    char line[PATH_MAX];
    char path[PATH_MAX];
    char *end = NULL;
    char *tmp = NULL;
    int len = 0;
    int fd = 0;

    if (pid == NULL || result_path == NULL || path_len == 0) {
        return -1;
    }
    /* 先查cmdline是不是以docker开头的
     * /docker-java-home/jre/bin/java 
     * -Djava.util.logging.config.file=/usr/local/tomcat/conf/logging.properties 
     * -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager 
     * -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources 
     * -classpath /usr/local/tomcat/bin/bootstrap.jar:/usr/local/tomcat/bin/tomcat-juli.jar 
     * -Dcatalina.base=/usr/local/tomcat -Dcatalina.home=/usr/local/tomcat 
     * -Djava.io.tmpdir=/usr/local/tomcat/temp org.apache.catalina.startup.Bootstrap star
     */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    tmp = strstr(line, "docker-java");
    if (!tmp) { /* 当前docker运行的不是java的环境，不检查 */
        return -1;
    }

    /* 再查当前docker容器进程的mountinfo信息，找workdir=关键字，确定docker的存储路径 */
    /* 513 393 0:55 / / rw,relatime - overlay overlay rw,context="system_u:object_r:container_file_t:s0:c498,c574",
     * lowerdir=/var/lib/docker/overlay2/l/CWPHELQCBHPK6IKYMQOYV5JJOZ:/var/lib/docker/overlay2/l/AVQFMMIEPOBJK3IHBASSADNBX2
     * :/var/lib/docker/overlay2/l/EXGTMD2XKUIDAPJT5TY2LLY7IN:/var/lib/docker/overlay2/l/I4ACEF4PT6HNTZ42N2S6ZVO6UB
     * :/var/lib/docker/overlay2/l/B5STVCMJ3C75TH6RMDI5PIDZMI:/var/lib/docker/overlay2/l/MTTTYFCRZC3MZ2SRUFRBSFSCMX
     * :/var/lib/docker/overlay2/l/PZMPKS67HNRRPRRNQUEAOVORH5:/var/lib/docker/overlay2/l/LWCBRCKQAQPOUJSOPG5NRCXPR3
     * :/var/lib/docker/overlay2/l/P6K73HL7S7DY2DZYWIZPWKWYEV:/var/lib/docker/overlay2/l/IOQCBT3T74PQURFAW5VFB2B4FY
     * :/var/lib/docker/overlay2/l/LRGG3SX7PNSXDK2TWECWBINZKU:/var/lib/docker/overlay2/l/GCDQFBHFST7Z2ABAME2XEKQFVA
     * :/var/lib/docker/overlay2/l/YRZU56DALA2LLFXLPWVAKPGDLR:/var/lib/docker/overlay2/l/AIULSBWK3ZGCBEP2F2446FX63G
     * :/var/lib/docker/overlay2/l/MYFCUVM46XGWNDNMX4SJSFF5ZD:/var/lib/docker/overlay2/l/KCXRQXW3DC2UGN2AFJ2LNEZIJX
     * :/var/lib/docker/overlay2/l/MYZDAI6POK474STWRXAWFXLCUQ,upperdir=/var/lib/docker/overlay2/ac8550ec46cef3d13cb3d51a1335e7accfb9ec04ce498d5159e697140c29fd1d/diff,
     * workdir=/var/lib/docker/overlay2/ac8550ec46cef3d13cb3d51a1335e7accfb9ec04ce498d5159e697140c29fd1d/work
     * 514 513 0:58 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
     * 515 513 0:59 / /dev rw,nosuid - tmpfs tmpfs rw,context="system_u:object_r:container_file_t:s0:c498,c574",mode=755
     * 516 515 0:60 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,context="system_u:object_r:container_file_t:s0:c498,c574",gid=5,mode=620,ptmxmode=666
     * 517 513 0:61 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro,seclabel
     * 518 517 0:62 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,context="system_u:object_r:container_file_t:s0:c498,c574",mode=755
     * 519 518 0:22 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/systemd ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd
     * 520 518 0:24 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/devices ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,devices
     * 521 518 0:25 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/net_prio,net_cls ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,net_prio,net_cls
     * 522 518 0:26 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/memory ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,memory
     * 523 518 0:27 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/cpuacct,cpu ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,cpuacct,cpu
     * 524 518 0:28 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/pids ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,pids
     * 525 518 0:29 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/freezer ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,freezer
     * 526 518 0:30 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/hugetlb ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,hugetlb
     * 527 518 0:31 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/perf_event ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,perf_event
     * 528 518 0:32 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/cpuset ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,cpuset
     * 529 518 0:33 /system.slice/docker-576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503.scope /sys/fs/cgroup/blkio ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,blkio
     * 530 515 0:57 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw,seclabel
     * 531 513 253:0 /var/lib/docker/containers/576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503/resolv.conf /etc/resolv.conf rw,relatime - xfs /dev/mapper/centos-root rw,seclabel,attr2,inode64,noquota
     * 532 513 253:0 /var/lib/docker/containers/576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503/hostname /etc/hostname rw,relatime - xfs /dev/mapper/centos-root rw,seclabel,attr2,inode64,noquota
     * 533 513 253:0 /var/lib/docker/containers/576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503/hosts /etc/hosts rw,relatime - xfs /dev/mapper/centos-root rw,seclabel,attr2,inode64,noquota
     * 534 515 0:56 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,context="system_u:object_r:container_file_t:s0:c498,c574",size=65536k
     * 535 513 253:0 /var/lib/docker/containers/576419e9cddd7133e504493b17290e5b6b1aaf69529f3d2c7728a7eea0ae0503/secrets /run/secrets rw,relatime - xfs /dev/mapper/centos-root rw,seclabel,attr2,inode64,noquota
     * 394 514 0:58 /asound /proc/asound ro,nosuid,nodev,noexec,relatime - proc proc rw
     * 396 514 0:58 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
     * 431 514 0:58 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
     * 432 514 0:58 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
     * 433 514 0:58 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
     * 434 514 0:58 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
     * 435 514 0:63 / /proc/acpi ro,relatime - tmpfs tmpfs ro,seclabel
     * 436 514 0:59 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,context="system_u:object_r:container_file_t:s0:c498,c574",mode=755
     * 437 514 0:59 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,context="system_u:object_r:container_file_t:s0:c498,c574",mode=755
     * 438 514 0:59 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,context="system_u:object_r:container_file_t:s0:c498,c574",mode=755
     * 439 514 0:59 /null /proc/timer_stats rw,nosuid - tmpfs tmpfs rw,context="system_u:object_r:container_file_t:s0:c498,c574",mode=755
     * 440 514 0:59 /null /proc/sched_debug rw,nosuid - tmpfs tmpfs rw,context="system_u:object_r:container_file_t:s0:c498,c574",mode=755
     * 441 514 0:64 / /proc/scsi ro,relatime - tmpfs tmpfs ro,seclabel
     * 442 517 0:65 / /sys/firmware ro,relatime - tmpfs tmpfs ro,seclabel
     */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/mountinfo", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    tmp = strstr(line, "workdir=");
    if (!tmp) {
        return -1;
    }
    tmp += 8;
    memset (result_path, 0x00, path_len);
    snprintf(result_path, path_len, "%s", tmp);

    tmp = strstr(result_path, "work");
    if (!tmp) {
        return -1;
    }
    *tmp = '\0';
    len = strlen(result_path);
    /* 容器不会修改原始镜像，真正存储目录不是work，而是merged目录 */
    snprintf(result_path+len, path_len-len, "%s", "merged");
    if (is_dir(result_path) != 0) {
        return -1;
    }

    return 0;
}

/* 根据/proc/pid/fd目录下的jar文件查找被加载的jar文件 */
static int get_jar_info(sys_info_t *data)
{
    char cmd[PATH_MAX];
    char proc_path[PATH_MAX];
    char result_path[PATH_MAX];
    char run_path[PATH_MAX];
    char name[NAME_MAX];
    char tmp[NAME_MAX];
    char version[NAME_MAX];
    long iter_fd = 0;
    DIR *iter_dirp = NULL;
    struct dirent *iter_ent = NULL;
    sqlite3_stmt * stmt = NULL;
    int ret = 0;
    int flag = 0;
    int len = 0;

    if (data == NULL || data->object == NULL || data->ret == NULL) return -1;

    ret = exec_sql(data->db, sql_jar);
    if (ret) {
        elog("Create jar table failed, ret:%d\n", ret);
        return -1;
    }

    /* 这里是SELECT path,pid FROM sys_process的查询结果 */
    stmt = (sqlite3_stmt*)data->ret;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *process_path = sqlite3_column_text(stmt, 0);
        const char *pid = sqlite3_column_text(stmt, 1);

        /* search jar */
        memset(proc_path, 0x00, sizeof(proc_path));
        snprintf(proc_path, sizeof(proc_path), "/proc/%s/fd/", pid);
        
        iter_dirp = opendir(proc_path);
        if (!iter_dirp) {
            elog("open %s fail: %s\n", proc_path, strerror(errno));
            continue;
        }

        while ((iter_ent = readdir(iter_dirp))) {
            if (iter_ent->d_name[0] < '0' || iter_ent->d_name[0] > '9' ||
                (iter_fd=atol(iter_ent->d_name))<=0) {
                //MON_ERROR("Error process fd fail: %s\n", strerror(errno));
                continue;
            }

            memset(run_path, 0x00, sizeof(run_path));
            memset(result_path, 0x00, sizeof(result_path));
            snprintf(run_path, 128, "/proc/%s/fd/%ld", pid, iter_fd);
            len = -1;
            len = readlink(run_path, result_path, PATH_MAX);
            if (len < 0) {
                continue;
            }
            else {
                /* 非/开头 和 /dev 的进程路径不检查 */
                if (result_path[0] != '/' 
                    || (result_path[0] == '/' && result_path[1] == 'd' 
                        && result_path[2] == 'e' && result_path[3] == 'v')) {
                    continue;
                }
                memset(tmp, 0x00, sizeof(tmp));
                memset(name, 0x00, sizeof(name));
                snprintf(tmp, sizeof(tmp), "%s", basename(result_path));
                /* 判断下jar文件在不在，如果不在，再去docker的默认目录下找 */
                if (is_file(result_path) != 0) {
                    /* 先找/proc/pid/mountinfo中workdir=关键字，用以确定jar包所在目录 */
                    if (check_docker_container_path(pid, run_path, sizeof(run_path)) != 0) {
                        /* docker目录没找到 */
                        continue;
                    }
                    len = strlen(run_path);
                    snprintf(run_path+len, sizeof(run_path)-len, "%s", result_path);
                    memset(result_path, 0x00, sizeof(result_path));
                    snprintf(result_path, sizeof(result_path), "%s", run_path);
                }
                len = strlen(tmp);
                
                if (strncmp(tmp+len-4, ".jar", 4) == 0) {
                    snprintf(name, sizeof(name), "%s", tmp);
                    tmp[len-4] = '\0';
                    /* jar包版本信息因为META-INF/MANIFEST.MF中的Version关键字不同，也可能完全没有
                     * 所以暂定从文件名中获取，正常情况下文件名中的版本信息与ETA-INF/MANIFEST.MF是一样的
                     * 找文件名中第一个 '-' 字符后，数字开头的位置
                     */
                    memset(version, 0x00, sizeof(version));
                    char *ptr = strchr(tmp, '-');
                    if (ptr) {
                        ++ ptr;
                        while (*ptr) {
                            if (!isdigit(*ptr)) {
                                ++ ptr;
                                continue;
                            } else {
                                snprintf(version, sizeof(version), "%s", ptr);
                                break;
                            }
                        }
                    }
                    if (!version[0]) { /* 没获取版本的默认是空格 */
                        version[0] = ' ';
                    }
                    /* # 0 不能执行 1 可执行 */
                    memset(cmd, 0x00, sizeof(cmd));
                    flag = 0;
                    snprintf(cmd, sizeof(cmd), "unzip -q -c %s META-INF/MANIFEST.MF", result_path);
                    if (popen_filter_one_keystr(cmd, "Main-Class:", run_path, sizeof(run_path)) == 0) {
                        if (strstr(run_path, "Main-Class:")) flag = 1;
                    }
                    char md5[33] = {0};
                    if (sys_md5_file(result_path, md5, sizeof(md5)) != 0) {
                        snprintf(md5, sizeof(md5), "%s", "None");
                    }
                    /* 更新jar包信息到数据库jar_info表中 */
                    update_db_jar_info(data, pid, name, version, flag, md5, result_path);
                }
            }
        }
        closedir(iter_dirp);
    }
    /* 从数据库jar_info表中查询信息生成Jar的Json */
    generate_jar_info(data);

    return ret;
}
/* JSON jar */
void *sys_jar_info(sys_info_t *data)
{
    sqlite3_stmt * stmt = NULL;
    const char *zTail;
    int ret = 0;

    if (data->object == NULL || data->db == NULL) return NULL;

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, "SELECT path,pid FROM sys_process;", -1, &stmt, &zTail);
    if (ret !=SQLITE_OK){
        elog("No process\n");
    }
    else {
        data->ret = (void*)stmt;
    }

    ret = get_jar_info(data);
    if (ret) {
        elog("Get sys ports info failed\n");
    }

    sqlite3_finalize(stmt);

    return NULL;
}
void *sys_jar_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

/* JSON kernel */
void *sys_kernel_info(sys_info_t *data)
{
    FILE *fp = NULL;
    cJSON *ker_object = NULL;
    char buf[512] = {0}, *ptr = NULL;

    if (data->object == NULL) return NULL;

    ker_object = data->object;

    fp = fopen("/proc/modules", "r");
    if (!fp) {
        elog("open /proc/modules fail: %s\n", strerror(errno));
        return NULL;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        int ret = 0, len = 0;
        int memsize = 0;
        int loaded_time = 0;
        char name[64] = {0};
        char dependency[256] = {0};
        char state[64] = {0};
        char offset[64] = {0};
        char cmd[256] = {0};
        char desc[PATH_MAX] = {0};
        char path[PATH_MAX] = {0};
        char version[64] = {0};
        FILE *pp = NULL;
        struct stat st = {0};

        ret = sscanf(buf, "%63s %d %d %255s %63s %63s\n",
                     name, &memsize, &loaded_time, dependency, state, offset);
        if (ret != 6) {
            continue;
        }

        len = strlen(dependency);
        if (len > 0 && ',' == dependency[len-1]) {
            dependency[len-1] = '\0';
        }

        snprintf(cmd, sizeof(cmd), "/sbin/modinfo %s", name);
        pp = popen(cmd, "r");
        if (pp) {
            while (fgets(buf, sizeof(buf), pp) != NULL) {
                if (strncmp(buf, "filename:", 9) == 0) { /* 内核模块绝对路径 */
                    snprintf(path, sizeof(path), "%s", trim_space(buf+9));
                    continue;
                }
                if (strncmp(buf, "description:", 12) == 0) { /* 描述，也可能没有 */
                    snprintf(desc, sizeof(desc), "%s", trim_space(buf+12));
                    continue;
                }
                if (strncmp(buf, "version:", 8) == 0) { 
                    snprintf(version, sizeof(version), "%s", trim_space(buf+8));
                    continue;
                }
            }
            pclose(pp);
        }

        if (path[0] == 0) {
            snprintf(path, sizeof(path), "%s", "Unknown");
            snprintf(desc, sizeof(desc), "%s", "Unknown");
            snprintf(version, sizeof(version), "%s", "Unknown");
        }

        /*
         * 没有描述的话，取模块路径信息作为描述，如
         * /lib/modules/4.9.0-7-amd64/kernel/fs/btrfs/btrfs.ko -> fs btrfs driver
         * /lib/modules/4.9.0-7-amd64/kernel/drivers/cdrom/cdrom.ko -> cdrom driver
         */
        if (desc[0] == 0) {
            snprintf(buf, sizeof(buf), "%s", path);
            ptr = strrchr(buf, '/');
            if (ptr) {
                *ptr = 0; // /lib/modules/4.9.0-7-amd64/kernel/fs/btrfs
            }

            ptr = strstr(buf, "/drivers/");
            if (ptr) {
                snprintf(desc, sizeof(desc), "%s driver", ptr+9); // cdrom driver
            } else {
                ptr = strstr(buf, "/kernel/");
                if (ptr) {
                    snprintf(desc, sizeof(desc), "%s driver", ptr+8); // fs/btrfs driver
                }
            }

            ptr = desc;
            while (*ptr) {
                if (*ptr == '/') {
                    *ptr = ' ';  // fs btrfs driver
                }
                ptr++;
            }
        }
        if (islower(desc[0])) {
            desc[0] += 'A' - 'a'; //首字符大写
        }

        /* 没有版本的话，用内核的版本 */
        if (version[0] == 0) {
            snprintf(buf, sizeof(buf), "%s", path);
            ptr = strstr(buf, "/kernel/");
            if (ptr) {
                *ptr = 0;  // /lib/modules/4.9.0-7-amd64
            }
            snprintf(version, sizeof(version), "%s", buf+13); // 4.9.0-7-amd64
        }

        stat(path, &st);

        cJSON *object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "model_name", name);
        cJSON_AddStringToObject(object, "version", version);
        cJSON_AddStringToObject(object, "model_desc", desc);
        cJSON_AddStringToObject(object, "model_path", path);
        cJSON_AddNumberToObject(object, "size", st.st_size > 0 ? st.st_size/1024 : memsize/1024);

        cJSON_AddNumberToObject(object, "loaded_time", loaded_time);
        cJSON_AddStringToObject(object, "dependency", dependency);
        cJSON_AddStringToObject(object, "state", state);
        cJSON_AddStringToObject(object, "offset", offset);
            
        cJSON_AddItemToObject(ker_object, "linux_kernel_modules", object);
    }

    fclose(fp);

    return NULL;
}
void *sys_kernel_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static char *get_container_ports(const char *shell_cmd) 
{
    char ports[PATH_MAX] = {0};
    char line[NAME_MAX] = {0};
    int offset = 0;
    FILE *fp = NULL;
    char *tmp = NULL;

    if (!shell_cmd) {
        return strdup("None");
    }

    fp = popen(shell_cmd, "r");
    if (!fp) {
        return strdup("None");
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        tmp = strchr(line, '/');
        if (tmp) {
            *tmp = '\0';
            if (offset) {
                snprintf(ports+offset, sizeof(ports)-offset, ",%s", line);
                offset += strlen(line) + 1;
            }
            else { /* first */
                snprintf(ports+offset, sizeof(ports)-offset, "%s", line);
                offset += strlen(line);
            }
        }
    }
    pclose(fp);

    return strdup(ports);
}

/* JSON container */
void *sys_container_info(sys_info_t *data)
{
    char line_info[PATH_MAX];
    char ports[PATH_MAX];
    char image[NAME_MAX];
    char original[NAME_MAX];
    char shell_cmd[128];
    char tmp_name[128];
    char name[128];
    char image_id[128];
    char container_created[64];
    char status[64];
    char size[32];
    char command[32];
    char container_id[16];
    char *tmp = NULL;
    FILE *fp = NULL;
    long image_size = 0;
    int flag = 0;
    int len = 0;

    if (data->object == NULL) {
        return NULL;
    }
    cJSON *docker_object = data->object;

    memset(line_info, 0x00, sizeof(line_info));
    fp = popen("docker ps -a 2>&1", "r");
    if (fp == NULL) {
        elog("get docker container fail: %s\n", strerror(errno));
        return NULL;
    }

    while (fgets(line_info, sizeof(line_info), fp) != NULL) {
        if (flag == 0) {
            flag = 1;
            continue;
        }
        cJSON *object = cJSON_CreateObject();
        
        sscanf(line_info, "%s %s \"%[^\"]s\" %s %s %s %s", 
            container_id, image, command, container_created, status, ports, name);

        if (container_id[0]) {
            memset(shell_cmd, 0x00, sizeof(shell_cmd));
            memset(status, 0x00, sizeof(status));
            memset(name, 0x00, sizeof(name));
            memset(tmp_name, 0x00, sizeof(tmp_name));
            memset(original, 0x00, sizeof(original));
            /* name && status */
            snprintf(shell_cmd, sizeof(shell_cmd), 
                "docker inspect --format '{{ .State.Status }} {{ .Name }} {{ .Image }}' %s", container_id);
            if (popen_filter_one_keystr(shell_cmd, NULL, line_info, sizeof(line_info)) == 0) {
                if (len=sscanf(line_info, "%s %s %s", status, tmp_name, original), len != 3) {
                    snprintf(status, sizeof(status), "%s%c", "None", '\0');
                    snprintf(tmp_name, sizeof(tmp_name), "%s%c", "None", '\0');
                }
            } else {
                snprintf(status, sizeof(status), "%s%c", "None", '\0');
                snprintf(tmp_name, sizeof(tmp_name), "%s%c", "None", '\0');
            }
            if (tmp_name[0] == '/') {
                snprintf(name, sizeof(name), "%s", tmp_name+1);
            } else {
                snprintf(name, sizeof(name), "%s", tmp_name);
            }
            /* ports */
            memset (shell_cmd, 0x00, sizeof(shell_cmd));
            memset(ports, 0x00, sizeof(ports));
            snprintf(shell_cmd, sizeof(shell_cmd), "docker port %s", container_id);
            tmp = get_container_ports(shell_cmd);
            snprintf(ports, sizeof(ports), "%s", tmp);
            if (tmp) {
                free(tmp);
                tmp = NULL;
            }
            /* image id */
            tmp = strchr(original, ':');
            if (tmp) {
                ++ tmp;
                snprintf(image_id, sizeof(image_id), "%s", tmp);
            } else {
                snprintf(image_id, sizeof(image_id), "%s%c", "None", '\0');
            }
            /* image size */
            if (strncmp(image_id, "None", 4) == 0) {
                snprintf(size, sizeof(size), "%s", "None");
            } else {
                memset (shell_cmd, 0x00, sizeof(shell_cmd));
                snprintf(shell_cmd, sizeof(shell_cmd), "docker inspect --format '{{ .Size }}' %s", image_id);
                if (popen_filter_one_keystr(shell_cmd, NULL, line_info, sizeof(line_info)) == 0) {
                    image_size = atol(line_info);
                    //elog("%s-%s--%ld\n", image_id, line_info, image_size);
                    snprintf(size, sizeof(size), "%ld MB", image_size/(1000*1000));
                } else {
                    snprintf(size, sizeof(size), "%s%c", "None", '\0');
                }
            }
            //elog("|%s|%s|%s|\n", container_id, image, status);
            cJSON_AddStringToObject(object, "container_id", container_id);
            cJSON_AddStringToObject(object, "container_name", name);
            cJSON_AddStringToObject(object, "container_status", status);
            cJSON_AddStringToObject(object, "ports", ports);
            cJSON_AddStringToObject(object, "command", command);
            cJSON_AddStringToObject(object, "image_id", image_id);
            cJSON_AddStringToObject(object, "image_size", size);
            cJSON_AddStringToObject(object, "image_name", image);
        }
        cJSON_AddItemToObject(docker_object, "docker_info", object);
    }
    pclose(fp);

    return NULL;
}
void *sys_container_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

/* JSON vuln */
void *sys_vuln_info(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}
void *sys_vuln_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

#ifdef SNIPER_FOR_DEBIAN
/* 取目录下最小的修改时间 */
static unsigned long get_debian_install_time()
{
    char file_path[PATH_MAX];
    struct stat buf;
    time_t min_time = time(NULL);
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    char *path = "/var/log/installer/";

    if (os_install_time) { // 查询软件包信息的时候获取过直接使用
        return os_install_time;
    }

    dirp = opendir(path);
    if (dirp == NULL) {
        elog("Open dir %s failed\n", path);
        return 0;
    }
    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] == '.') continue;
        memset(file_path, 0x00, sizeof(file_path));
        snprintf(file_path, sizeof(file_path), "%s%s", path, dent->d_name);
        memset(&buf, 0x00, sizeof(struct stat));
        stat(file_path, &buf);
        if (buf.st_ctime < min_time) {
            min_time = buf.st_ctime;
        }
    }
    closedir(dirp);

    return min_time;
}
#else
static unsigned long get_centos_install_time()
{
    char package_list_cmd[PATH_MAX];
    char desc[PATH_MAX];
    char line[PATH_MAX];
    char name[NAME_MAX];
    char version[64];
    time_t install_time = 0;
    struct tm t;
    FILE *fp = NULL;
    int ret = 0;

    if (os_install_time) {
        return os_install_time;
    }

    memset(package_list_cmd, 0x00, sizeof(package_list_cmd));
    memset(line, 0x00, sizeof(line));

    snprintf(package_list_cmd, sizeof(package_list_cmd), "%s", 
        "rpm -qa --qf \"++%{NAME} %{VERSION} %{INSTALLTIME} %{Description}\n\"");

    if ((fp = popen(package_list_cmd, "r")) == NULL) {
        goto End;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        memset(name, 0x00, sizeof(name));
        memset(version, 0x00, sizeof(version));
        memset(desc, 0x00, sizeof(desc));

        if (sscanf(line, "++%s %s %lu %s\n", name, version, &install_time, desc) != 4) {
            continue;
        }
        if (os_install_time == 0) {
            os_install_time = install_time;
        }

        localtime_r(&install_time, &t);
        // strftime(idate, sizeof(idate), "%Y-%m-%d %H:%M:%S", &t);
        if (install_time < os_install_time) {
            os_install_time = install_time;
        }
    }
    fclose(fp);

    return os_install_time;

End:
    localtime_r(&install_time, &t);
    return install_time;
}
#endif

/* 取系统启动时间，参考user/sysinfo.c的get_boot_time() */
static time_t get_boot_time(void)
{
    char boottime[64] = {0}, nowtime[64] = {0};
    struct stat st = {0};
    time_t uptime_sec = 0;

    if (stat("/proc/1", &st) < 0) {
        time_t now = time(NULL);

        ctime_r(&now, nowtime);    //1643376605 -> "Fri Jan 28 21:30:05 2022\n"
        nowtime[63] = 0;
        delete_tailspace(nowtime); //去掉尾部的换行符

        elog("get_boot_time stat /proc/1 error: %s\n", strerror(errno));
        dlog("use now time %s(%ld) as boot time\n", nowtime, now);

        uptime_sec = now;
        return uptime_sec;
    }

    uptime_sec = st.st_mtime;

    ctime_r(&uptime_sec, boottime);
    boottime[63] = 0;
    delete_tailspace(boottime);

    dlog("boot at %s(%ld)\n", boottime, uptime_sec);
    return uptime_sec;
}
/* 取系统上次关机时间，参考user/sysinfo.c的sys_boot_time() */
static time_t get_shutdown_time(time_t boot_time)
{
    struct utmp *u = NULL;
    char halttime[64] = {0};
    time_t shutdown_time = 0;

    //TODO 上次关机时间可能不准，比如突然死机，比如
    //halt -w / reboot -w不关机，只写wtmp
    //reboot -d不写wtmp

    /* 从文件头遍历到文件尾，最后取的值就是最新的 */
        utmpname("/var/log/wtmp");
        setutent();
        while ((u = getutent())) {
        if (u->ut_type == RUN_LVL && strcmp(u->ut_user, "shutdown") == 0) {
            shutdown_time = u->ut_tv.tv_sec;
                }
        }
        endutent();

    /* 关机时间没取到，再试试wtmp.1 */
    if (shutdown_time == 0 && access("/var/log/wtmp.1", F_OK) == 0) {
            utmpname("/var/log/wtmp.1");
            setutent();
            while ((u = getutent())) {
            if (u->ut_type == RUN_LVL && strcmp(u->ut_user, "shutdown") == 0) {
                shutdown_time = u->ut_tv.tv_sec;
                    }
            }
            endutent();
    }

    if (shutdown_time == 0) {
        dlog("not get last shutdown time, use 1min before boot time\n");
        shutdown_time = boot_time - 60;
    } else if (shutdown_time > boot_time) {
        dlog("Warning: last shutdown time %ld later than boot time %ld, use 1min before boot time\n",
            shutdown_time, boot_time);
        shutdown_time = boot_time - 60;
    }

    ctime_r(&shutdown_time, halttime);
    halttime[63] = 0;
    delete_tailspace(halttime);
    dlog("last shutdown at %s(%ld)\n", halttime, shutdown_time);

    return shutdown_time;
}

/* JSON os */
void *sys_os_info(sys_info_t *data)
{
    char name[NAME_MAX] = {0};
    char line[NAME_MAX] = {0};
    char version[64] = {0};
    char lang[NAME_MAX] = {0};
    char serial[NAME_MAX] = {0};
    char arch[64] = {0};
    time_t last_boot_time = 0;
    time_t last_shutdown_time = 0;
    char *tmp = NULL;
    FILE *fp = NULL;
    int len = 0;

    if (data->object == NULL) return NULL;

    cJSON *os = data->object;

    /* name */
    fp = fopen("/etc/os-release", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strncmp(line, "NAME=\"", 6) == 0) {
                tmp = line + 6;
                char *end = strchr(tmp, '"');
                if (end) {
                    *end = '\0';
                }
                snprintf(name, sizeof(name), "%s", tmp);
            }
        }
        fclose(fp);
    }
    if (!name[0]) {
        snprintf(name, sizeof(name), "%s", "None");
    }

    /* arch */
    if (popen_filter_one_keystr("getconf LONG_BIT", NULL, line, sizeof(line)) == 0) {
        if (isdigit(line[0]) != 0 && isdigit(line[1]) != 0) {
            snprintf(arch, sizeof(arch), "%s", line);
            len = strlen(arch);
            if (len > 0) arch[len-1] = '\0';
        }
        else {
            snprintf(arch, sizeof(arch), "%s", "None");
        }
    } else {
        snprintf(arch, sizeof(arch), "%s", "None");
    }
    
    /* kernel */
    if (return_file_first_line("/proc/version", line, sizeof(line)) == 0) {
        snprintf(version, sizeof(version)-1, "%s", line);
        len = strlen(version);
        if (version[len-1] == '\n') {
            version[len-1] = '\0';
        }
        tmp = strchr(version, '(');
        if (tmp) {
            *tmp = '\0';
        }
    } else {
        snprintf(version, sizeof(version), "%s", "None");
    }
    
    /* lang */
    if (popen_filter_one_keystr("locale", NULL, line, sizeof(line)) == 0) {
        tmp = strstr(line, "LANG=");
        if (tmp) {
            tmp += 5;
            snprintf(lang, sizeof(lang), "%s", tmp);
            len = strlen(lang);
            if (len > 0) lang[len-1] = '\0';
        }
        else {
            snprintf(lang, sizeof(lang), "%s", "None");
        }
    } else {
        snprintf(lang, sizeof(lang), "%s", "None");
    }
    
    /* serial number */
    if (return_file_first_line("/sys/class/dmi/id/product_serial", line, sizeof(line)) == 0) {
        snprintf(serial, sizeof(serial), "%s", line);
        len = strlen(serial);
        if (serial[len-1] == '\n') serial[len-1] = '\0';
    } else {
        if (get_machine_serial(serial, sizeof(serial)) != 0) {
            snprintf(serial, sizeof(serial), "%s", "None");
        }
    }
    
    /* last boot/shutdown time */
    last_boot_time = get_boot_time();
    last_shutdown_time = get_shutdown_time(last_boot_time);

    cJSON_AddStringToObject(os, "os", name);
    cJSON_AddStringToObject(os, "os_arch", arch);
    cJSON_AddStringToObject(os, "os_kernel", version);
    cJSON_AddStringToObject(os, "os_lang", lang);
    cJSON_AddStringToObject(os, "serial_number", serial);
#ifdef SNIPER_FOR_DEBIAN
    cJSON_AddNumberToObject(os, "install_time", get_debian_install_time());
#else
    cJSON_AddNumberToObject(os, "install_time", get_centos_install_time());
#endif
    cJSON_AddNumberToObject(os, "last_boot_time", last_boot_time);
    cJSON_AddNumberToObject(os, "last_shutdown_time", last_shutdown_time);

    return NULL;
}
void *sys_os_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

void *sys_partition_info(sys_info_t *data)
{
    struct mntent *ent = NULL;
#ifdef _LARGEFILE64_SOURCE
    struct statfs64 stat;
#else
    struct statfs stat;
#endif
    int len = 0;
    char partitions[4096] = {0}, partstr[128] = {0};

    if (data->object == NULL) return NULL;

    cJSON *partition_object = data->object;

    FILE *fp = setmntent(MOUNTED,"r"); //MOUNTED在mntent.h中定义, /etc/mtab

    while(ent = getmntent(fp)){
        /* 只显示磁盘设备分区，排除伪文件系统和loop设备 */
        if (strncmp(ent->mnt_fsname, "/dev/", 5) != 0 ||
            strncmp(ent->mnt_fsname, "/dev/loop", 9) == 0) {
            continue;
        }
        /* 分区排除光盘挂载 */
        if (strncmp(ent->mnt_fsname, "/dev/sr0", 8) == 0
            || strncmp(ent->mnt_fsname, "/dev/cdrom", 10) == 0) {
            continue;
        }

        memset(&stat, 0x00, sizeof(struct statfs));
#ifdef _LARGEFILE64_SOURCE
        if(statfs64(ent->mnt_dir, &stat) < 0){
#else
        if(statfs(ent->mnt_dir, &stat) < 0){
#endif
            continue;
        }

        /* 分区的大小和df -h的结果一致，规则是，先除以1024转成KB，再除以1000*1000转成GB */

        //每个目录的总空间大小
        long all = (long)stat.f_blocks * (long)stat.f_bsize / 1024;
        if(all == 0) {
            continue;
        }

        /* 过滤重复的分区 */
        snprintf(partstr, 128, "%s ", ent->mnt_fsname);
        if (strstr(partitions, partstr)) { //如strstr("/dev/sda1 /dev/sda2 ", "/dev/sda2 ")
            continue;
        }
        len = strlen(partitions);
        snprintf(partitions+len, 4096-len, "%s", partstr);

        //非超级用户可用空间
        long free = (long)stat.f_bavail * (long)stat.f_bsize / 1024;
        //超级用户可用空间
        long free_to_root = (long)stat.f_bfree * (long)stat.f_bsize / 1024;

        double used = all - free;

        char all_str[16] = {0};
        char used_str[16] = {0};
        char free_str[16] = {0};

        double tmp = (double)all / (1000*1000);
        snprintf(all_str, sizeof(all_str), "%.2f", tmp);

        tmp = (double)used / (1000*1000);
        snprintf(used_str, sizeof(used_str), "%.2f", tmp);

        tmp = (double)free / (1000*1000);
        snprintf(free_str, sizeof(free_str), "%.2f", tmp);

        cJSON *object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "partition_name", ent->mnt_fsname);
        cJSON_AddStringToObject(object, "mount_point", ent->mnt_dir);
        cJSON_AddStringToObject(object, "total", all_str);
        cJSON_AddStringToObject(object, "used", used_str);
        cJSON_AddStringToObject(object, "free", free_str);

        cJSON_AddItemToObject(partition_object, "docker_info", object);
    }
    endmntent(fp);

    return NULL;
}
void *sys_partition_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}
