/*************************************************************************
    > File Name: database_info.c
    > Author: Qushb
    > Mail: Qushb@magic-shield.com 
    > Created Time: Mon 28 Dec 2020 10:32:35 AM CST
 ************************************************************************/


#include "sys_info.h"

void get_proc_fd_path(char *pid, int fd, char *fdpath, int fdpath_len)
{
        int len = 0;
        char buf[PATH_MAX] = {0};
        char path[128] = {0}, *ptr = NULL;

        if (!pid || !fdpath) {
                return;
        }

        snprintf(path, sizeof(path), "/proc/%s/fd/%d", pid, fd);

        len = readlink(path, buf, sizeof(buf)-1);
        if (len <= 0) {
                return;
        }

        /* readlink() does not append a null byte, end byself */
        buf[len] = 0;

        ptr = strstr(buf, " (deleted)");
        if (ptr) {
                *ptr = 0;
        }

        len = strlen(buf);
        if (len <= 0) {
                return;
        }

        snprintf(fdpath, fdpath_len, "%s", buf);
}

void get_proc_cwd(char *pid, char *cwd, int cwd_len)
{
        int len = 0;
        char buf[PATH_MAX] = {0};
        char path[128] = {0}, *ptr = NULL;

        if (!pid || !cwd) {
                return;
        }

        snprintf(path, sizeof(path), "/proc/%s/cwd", pid);

        len = readlink(path, buf, sizeof(buf)-1);
        if (len <= 0) {
                return;
        }

        /* readlink() does not append a null byte, end byself */
        buf[len] = 0;

        snprintf(cwd, cwd_len, "%s", buf);
}

static void get_name_by_pid(const char *pid, char *user_name, const int user_len)
{
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    uid_t uid = 0, euid = 0, suid = 0, fsuid = 0;
    FILE *fp = NULL;

    if (pid == NULL || user_name == NULL || user_len <= 0) return;

    snprintf(path, sizeof(path), "/proc/%s/status", pid);

    fp = fopen(path, "r");
    if (!fp) {
        elog("open /proc/%s/status failed\n", pid);
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "Uid: %d %d %d %d", &uid, &euid, &suid, &fsuid) == 4) {
            break;
        }
    }
    fclose(fp);

    uidtoname(uid, user_name, user_len);
}

static int found_port_inode(const char *pid, const unsigned long inode)
{
    char run_path[PATH_MAX] = {0};
    char result_path[PATH_MAX] = {0};
    char inode_str[64];
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    char *tmp = NULL;
    long iter_fd = 0;
    int len = 0;
    int ret = 0;

    if (pid == NULL || inode == 0) return 0;

    snprintf(run_path, sizeof(run_path), "/proc/%s/fd", pid);
    dirp = opendir(run_path);
    if (dirp == NULL) {
        elog("Open dir %s failed\n", run_path);
        return 0;
    }

    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] < '0' || dent->d_name[0] > '9') {
            continue;
        }

        iter_fd = atol(dent->d_name);
        if (iter_fd <= 0) {
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

static int get_db_ipv4_listen_port(const char *pid, char *buf, const int buf_len)
{
    char line_info[PATH_MAX];
    char ipv4_listen[PATH_MAX];
    sock_info_t ip_info;
    int i = 0;
    FILE *fp = NULL;

    if (pid == NULL || buf == NULL || buf_len <= 0) {
        return -1;
    }

    memset(buf, 0x00, sizeof(buf_len));
    memset(line_info, 0x00, sizeof(line_info));
    memset(ipv4_listen, 0x00, sizeof(ipv4_listen));
    memset(&ip_info, 0x00, sizeof(ip_info));

    fp = fopen("/proc/net/tcp", "r");
    if (fp) {
        fgets(line_info, sizeof(line_info), fp);
        while (fgets(line_info, sizeof(line_info), fp)) {
            if (get_proc_socket_info(line_info, &ip_info) < 0) {
                continue;
            }

            if (ip_info.state != TCP_LISTEN) {
                continue;
            }

            if (found_port_inode(pid, ip_info.inode) == 0) { /* current db not found inode */
                continue;
            }

            if (!ipv4_listen[0]) {
                snprintf(ipv4_listen, sizeof(ipv4_listen), "%s:%d", ip_info.src_ip, ip_info.src_port);
            }
            else {
                i = strlen(ipv4_listen);
                snprintf(ipv4_listen+i, sizeof(ipv4_listen)-i, ";%s:%d", ip_info.src_ip, ip_info.src_port);
            }
        }
        fclose(fp);
    }

    snprintf(buf, buf_len, "%s", ipv4_listen);
    
    return 0;
}

static int get_db_ipv6_listen_port(const char *pid, char *buf, const int buf_len)
{
    char line_info[PATH_MAX];
    char ipv6_listen[PATH_MAX];
    sock_info_t ip_info;
    int i = 0;
    char port[8];
    FILE *fp = NULL;

    if (pid == NULL | buf == NULL || buf_len <= 0) {
        return -1;
    }

    memset(buf, 0x00, buf_len);
    memset(line_info, 0x00, sizeof(line_info));
    memset(ipv6_listen, 0x00, sizeof(ipv6_listen));
    memset(&ip_info, 0x00, sizeof(ip_info));

    fp = fopen("/proc/net/tcp6", "r");
    if (fp) {
        fgets(line_info, sizeof(line_info), fp);
        while (fgets(line_info, sizeof(line_info), fp)) {
            if (get_proc_socket_info(line_info, &ip_info) < 0) {
                continue;
            }

            if (ip_info.state != TCP_LISTEN) {
                continue;
            }

            if (found_port_inode(pid, ip_info.inode) == 0) { /* current db not found inode */
                continue;
            }

            if (!ipv6_listen[0]) {
                snprintf(ipv6_listen, sizeof(ipv6_listen), "%s:%d", ip_info.src_ip, ip_info.src_port);
            }
            else {
                i = strlen(ipv6_listen);
                snprintf(ipv6_listen+i, sizeof(ipv6_listen)-i, ";%s:%d", ip_info.src_ip, ip_info.src_port);
            }
        }
        fclose(fp);
    }

    snprintf(buf, buf_len, "%s", ipv6_listen);

    return 0;
}

static void get_database_version(char *cmd, char *version, int version_len)
{
    FILE *fp = NULL;

    if (!cmd || !version) {
        return;
    }

    fp = popen(cmd, "r");
    if (fp == NULL) {
        elog("get version by %s fail: %s\n", cmd, strerror(errno));
        return;
    }

    fgets(version, version_len, fp);
    pclose(fp);

    delete_tailspace(version);
}

static cJSON *get_postgres_info(const char *pid, const char *comm)
{
    char log_path[PATH_MAX];
    char conf_path[PATH_MAX];
    char run_path[PATH_MAX];
    char line_info[PATH_MAX];
    char listen_port[PATH_MAX];
    char install_path[PATH_MAX];
    char user_name[64];
    char version[PATH_MAX] = "-";
    char port[8];
    FILE *fp = NULL;
    char *tmp = NULL;
    char *cmd = NULL;
    int i = 0;
    int len = 0;
    int fd = 0;
    cJSON *object = cJSON_CreateObject();

    if (pid == NULL || comm == NULL) return object;

    /* default config path */
    /* logging_collector = on */
    /* log_directory = 'pg_log' 可自定义路径 */
    /* log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log' 日志文件名 */
    memset(conf_path, 0x00, sizeof(conf_path));
    memset(run_path, 0x00, sizeof(run_path));
    /* cmdline中的-D选项指向配置文件所在路径 */
    snprintf(run_path, sizeof(run_path), "/proc/%s/cmdline", pid);
    fd = open(run_path, O_RDONLY);
    if (fd < 0) {
        snprintf(conf_path, sizeof(conf_path), "%s", "None");
    }
    else {
        memset(line_info, 0x00, sizeof(line_info));
        len = read(fd, line_info, sizeof(line_info)-1);
        if (len <= 0) {
            snprintf(conf_path, sizeof(conf_path), "%s", "None");
        }
        else {
            for (i=0; i<len; i++) {
                if (line_info[i] == 0) line_info[i] = ' ';
                if (line_info[i] == '\n') line_info[i] = '\0';
            }
            for (; len>0; len--) {
                if (line_info[len] == ' ') {
                    line_info[len] = '\0';
                    continue;
                }
                break;
            }
        }
        close(fd);

        cmd = strdup(line_info);

        tmp = strstr(line_info, "-D");
        if (tmp) {
            tmp += 2;
            while (*tmp == ' ') ++tmp;
            memset(conf_path, 0x00, sizeof(conf_path));
            snprintf(conf_path, sizeof(conf_path), "%s", tmp);
            tmp = strchr(conf_path, ' ');
            if (tmp) {
                *tmp = '\0';
            }
            memset(line_info, 0x00, sizeof(line_info));
            snprintf(line_info, sizeof(line_info), "%s/%s", conf_path, "postgresql.conf");
            if (is_file(line_info) == 0) {
                i = strlen(conf_path);
                snprintf(conf_path+i, sizeof(conf_path)-i, "/%s", "postgresql.conf");
            }
        }
    }
    memset(log_path, 0x00, sizeof(log_path));
    if (is_file(conf_path) == 0) {
        memset(line_info, 0x00, sizeof(line_info));
        fp = fopen(conf_path, "r");
        if (fp == NULL) {
            elog("get mysql conf fail: %s\n", strerror(errno));
            snprintf(conf_path, sizeof(conf_path), "%s", "None");
        }
        else {
            while (fgets(line_info, sizeof(line_info), fp) != NULL) {
                if (line_info[0] == '#') continue;

                if (strncmp(line_info, "log_filename", 12) == 0) {
                    tmp = line_info;
                    while (*tmp != '\'') {
                        ++tmp;
                    }
                    ++ tmp;
                    snprintf(log_path, sizeof(log_path), "%s", tmp);
                    tmp = strchr(log_path, '\'');
                    if (tmp) {
                        *tmp = '\0';
                    }
                    break;
                }
            }
            fclose(fp);
            if (!log_path[0]) {
                snprintf(log_path, sizeof(log_path), "%s", "None");
            }
        }
    }
    else {
        snprintf(log_path, sizeof(log_path), "%s", "None");
    }

    /* version */
    memset(run_path, 0x00, sizeof(run_path));
    tmp = strstr(cmd, "postgres");
    if (tmp) {
        tmp += strlen("postgres");
        *tmp = '\0';
    }

    snprintf(run_path, sizeof(run_path), "%s --version", cmd);
    get_database_version(run_path, version, sizeof(version));
    if (cmd) free(cmd);


    /* listen port */
    get_db_ipv4_listen_port(pid, listen_port, sizeof(listen_port));

    i = strlen(listen_port);
    if (i > 0) {
        *(listen_port+i) = ';';
        get_db_ipv6_listen_port(pid, listen_port+i+1, sizeof(listen_port)-i-1);
    }
    else {
        get_db_ipv6_listen_port(pid, listen_port, sizeof(listen_port));
    }

    i = strlen(listen_port);
    if (i > 0 && listen_port[i-1] == ';') {
        listen_port[i-1] = 0;
    }

    memset(user_name, 0x00, sizeof(user_name));
    get_name_by_pid(pid, user_name, sizeof(user_name));

    memset(install_path, 0x00, sizeof(install_path));
    snprintf(install_path, sizeof(install_path), "/proc/%s/cmdline", pid);
    if (return_file_first_line(install_path, line_info, sizeof(line_info)) == 0) {
        memset(install_path, 0x00, sizeof(install_path));
        snprintf(install_path, sizeof(install_path), "%s", line_info);
    }
    else {
        snprintf(install_path, sizeof(install_path), "%s", "None");
    }

    cJSON_AddStringToObject(object, "listen_port", listen_port);
    
    dlog("postgre |%s|%s|%s|\n", version, conf_path, port);

    cJSON_AddStringToObject(object, "db_name", "postgres");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "run_user", user_name);
    cJSON_AddStringToObject(object, "install_path", dirname(install_path));
    cJSON_AddStringToObject(object, "conf_path", conf_path);
    cJSON_AddStringToObject(object, "log_path", log_path);

    dlog("postgre done ...\n");

    return object;
}

static cJSON *get_mysql_info(char *pid, char *comm)
{
    char line[256] = {0};
    char user_name[64] = {0};
    char listen_port[256] = {0};
    char log_path[PATH_MAX] = {0};
    char install_path[PATH_MAX] = "-";
    char version[PATH_MAX] = "-";
    int len = 0;
    cJSON *object = NULL;

    if (!pid) {
        return NULL;
    }
    
    /* listen port, 3306 & 3307 */
    get_db_ipv4_listen_port(pid, listen_port, sizeof(listen_port));

    len = strlen(listen_port);
    if (len > 0) {
        if (len < PATH_MAX) {
            listen_port[len] = ';';
            get_db_ipv6_listen_port(pid, listen_port+len+1, sizeof(listen_port)-len-1);
        }
    } else {
        get_db_ipv6_listen_port(pid, listen_port, sizeof(listen_port));
    }
    len = strlen(listen_port);
    if (len == 0) {
        return NULL; //没有listen的端口，说明这不是数据库进程
    }

    if (len > 0 && listen_port[len-1] == ';') {
        listen_port[len-1] = 0;
    }

    /* version
     * 因mysql版本差异，统一使用mysql来获取版本信息，而不使用mysqld
     * mysql  Ver 14.14 Distrib 5.7.32, for Linux (x86_64) using  EditLine wrapper
     */
    get_database_version("mysql --version", version, sizeof(version));

    /* 不从配置文件取log-error或log_error的值，取进程fd1的路径名 */
    get_proc_fd_path(pid, 1, log_path, sizeof(log_path));

    get_name_by_pid(pid, user_name, sizeof(user_name));

    /* 取数据库目录作为安装目录 */
    get_proc_cwd(pid, install_path, sizeof(install_path));

    object = cJSON_CreateObject();
    if (!object) {
        return NULL;
    }

    cJSON_AddStringToObject(object, "listen_port", listen_port);

    dlog("mysql |%s|%s|%s|%s|\n", version, user_name, install_path, log_path);

    cJSON_AddStringToObject(object, "db_name", "mysql");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "run_user", user_name);
    cJSON_AddStringToObject(object, "install_path", install_path);
    cJSON_AddStringToObject(object, "log_path", log_path);

    /*
     * mysqld --verbose --help says
     * Default options are read from the following files in the given order:
     * /etc/my.cnf /etc/mysql/my.cnf ~/.my.cnf
     * --defaults-file=#         Only read default options from the given file #.
     */
    if (access("/etc/my.cnf", F_OK) == 0) {
        cJSON_AddStringToObject(object, "conf_path", "/etc/my.cnf");
    } else {
        cJSON_AddStringToObject(object, "conf_path", "/etc/mysql/my.cnf");
    }

    return object;
}

static cJSON *get_redis_info(const char *pid, const char *comm)
{
    char path[PATH_MAX];
    char line_info[PATH_MAX];
    char listen_port[PATH_MAX];
    char install_path[PATH_MAX];
    char conf_path[PATH_MAX];
    char user_name[64];
    char version[PATH_MAX] = "-";
    FILE *fp = NULL;
    int i = 0;
    int ret = 0;
    const char *conf = "redis.conf";
    cJSON *object = cJSON_CreateObject();
    char *tmp = NULL;

    if (pid == NULL || comm == NULL) {
        return object;
    }

    get_database_version("redis-server --version", version, sizeof(version));

    memset(listen_port, 0x00, sizeof(listen_port));
    get_db_ipv4_listen_port(pid, listen_port, sizeof(listen_port));

    i = strlen(listen_port);
    if (i > 0) {
        *(listen_port+i) = ';';
        get_db_ipv6_listen_port(pid, listen_port+i+1, sizeof(listen_port)-i-1);
    }
    else {
        get_db_ipv6_listen_port(pid, listen_port, sizeof(listen_port));
    }

    i = strlen(listen_port);
    if (i > 0 && listen_port[i-1] == ';') {
        listen_port[i-1] = 0;
    }

    memset(user_name, 0x00, sizeof(user_name));
    get_name_by_pid(pid, user_name, sizeof(user_name));

    memset(path, 0x00, sizeof(path));
    memset(install_path, 0x00, sizeof(install_path));
    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    ret = readlink(path, install_path, sizeof(install_path));
    if (ret > 0) {
        install_path[ret] = '\0';
    } else {
        install_path[0] = '\0';
    }

    memset(conf_path, 0x00, sizeof(conf_path));
    if (install_path[0]) {
        snprintf(conf_path, sizeof(conf_path), "%s/%s", dirname(install_path), conf);
    } else {
        snprintf(conf_path, sizeof(conf_path), "%s", conf);
    }

    memset(path, 0x00, sizeof(path));
    if (!is_file(conf_path)) {
        fp = fopen(conf_path, "r");
        if (fp == NULL) {
            elog("get redis conf fail: %s\n", strerror(errno));
            snprintf(path, sizeof(path), "%s", "None");
        }
        else {
            while (fgets(line_info, sizeof(line_info), fp) != NULL) {
                if (line_info[0] == '#' || line_info[0] == '[') continue;

                if (strncmp(line_info, "logfile", 7) == 0) {
                    i = strlen(line_info);
                    line_info[i-1] = '\0';
                    snprintf(path, sizeof(path), "%s", line_info+10);
                    break;
                }
            }
            fclose(fp);
        }
    }
    else {
        snprintf(path, sizeof(path), "%s", "None");
    }

    cJSON_AddStringToObject(object, "listen_port", listen_port);
    cJSON_AddStringToObject(object, "db_name", "redis");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "run_user", user_name);
    cJSON_AddStringToObject(object, "install_path", dirname(install_path));
    cJSON_AddStringToObject(object, "conf_path", conf_path);
    cJSON_AddStringToObject(object, "log_path", path);

    return object;
}


static cJSON *get_hbase_info(const char *pid, const char *cmdline)
{
    char path[PATH_MAX];
    char line_info[PATH_MAX];
    char listen_port[PATH_MAX];
    char install_path[PATH_MAX];
    char conf_path[PATH_MAX];
    char user_name[64];
    char version[PATH_MAX] = "-";
    FILE *fp = NULL;
    int i = 0;
    int ret = 0;
    const char *conf = "conf";
    cJSON *object = cJSON_CreateObject();
    char *tmp = NULL;

    if (pid == NULL || cmdline == NULL) {
        return object;
    }

    get_database_version("hbase version", version, sizeof(version));

    memset(listen_port, 0x00, sizeof(listen_port));
    get_db_ipv4_listen_port(pid, listen_port, sizeof(listen_port));

    i = strlen(listen_port);
    if (i > 0) {
        *(listen_port+i) = ';';
        get_db_ipv6_listen_port(pid, listen_port+i+1, sizeof(listen_port)-i-1);
    }
    else {
        get_db_ipv6_listen_port(pid, listen_port, sizeof(listen_port));
    }

    i = strlen(listen_port);
    if (i > 0 && listen_port[i-1] == ';') {
        listen_port[i-1] = 0;
    }

    memset(user_name, 0x00, sizeof(user_name));
    get_name_by_pid(pid, user_name, sizeof(user_name));

    memset(path, 0x00, sizeof(path));
    memset(install_path, 0x00, sizeof(install_path));
    snprintf(path, sizeof(path), "%s", cmdline);
    tmp = strchr(path, '/');
    if (tmp) {
        snprintf(install_path, sizeof(install_path), "%s", tmp);
    }

    tmp = strchr(install_path, ' ');
    if (tmp) {
        *tmp = '\0';
    }

    memset(conf_path, 0x00, sizeof(conf_path));
    if (install_path[0]) {
        snprintf(conf_path, sizeof(conf_path), "%s", install_path);
        tmp = strstr(conf_path, "bin");
        if (tmp) {
            *tmp = '\0';
            i = strlen(conf_path);
            snprintf(conf_path+i, sizeof(conf_path)-i, "%s", conf);
        }
    } else {
        snprintf(conf_path, sizeof(conf_path), "%s", conf);
    }

    memset(path, 0x00, sizeof(path));
    if (install_path[0]) {
        snprintf(path, sizeof(path), "%s", install_path);
        tmp = strstr(path, "bin");
        if (tmp) {
            *tmp = '\0';
            i = strlen(path);
            snprintf(path+i, sizeof(path)-i, "%s", "logs");
        }
    } else {
        snprintf(path, sizeof(path), "%s", "logs");
    }

    cJSON_AddStringToObject(object, "listen_port", listen_port);
    cJSON_AddStringToObject(object, "db_name", "hbase");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "run_user", user_name);
    cJSON_AddStringToObject(object, "install_path", dirname(install_path));
    cJSON_AddStringToObject(object, "conf_path", conf_path);
    cJSON_AddStringToObject(object, "log_path", path);

    return object;
}

static cJSON *get_mongo_info(const char *pid, const char *comm)
{
    char path[PATH_MAX];
    char line_info[PATH_MAX];
    char listen_port[PATH_MAX];
    char install_path[PATH_MAX];
    char conf_path[PATH_MAX];
    char user_name[64];
    char version[PATH_MAX] = "-";
    FILE *fp = NULL;
    int i = 0;
    int ret = 0;
    const char *conf = "mongodbserver/etc/mongodb.conf";
    cJSON *object = cJSON_CreateObject();
    char *tmp = NULL;

    if (pid == NULL || comm == NULL) {
        return object;
    }

    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    if (return_file_first_line(path, line_info, sizeof(line_info)) == 0) {
        i = strlen(line_info);
        snprintf(line_info+i, sizeof(line_info)-i, " %s", "--version");
        get_database_version(line_info, version, sizeof(version));
    }

    memset(listen_port, 0x00, sizeof(listen_port));
    get_db_ipv4_listen_port(pid, listen_port, sizeof(listen_port));

    i = strlen(listen_port);
    if (i > 0) {
        *(listen_port+i) = ';';
        get_db_ipv6_listen_port(pid, listen_port+i+1, sizeof(listen_port)-i-1);
    }
    else {
        get_db_ipv6_listen_port(pid, listen_port, sizeof(listen_port));
    }

    i = strlen(listen_port);
    if (i > 0 && listen_port[i-1] == ';') {
        listen_port[i-1] = 0;
    }

    memset(user_name, 0x00, sizeof(user_name));
    get_name_by_pid(pid, user_name, sizeof(user_name));

    memset(path, 0x00, sizeof(path));
    memset(install_path, 0x00, sizeof(install_path));
    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    ret = readlink(path, install_path, sizeof(install_path));
    if (ret > 0) {
        install_path[ret] = '\0';
    } else {
        install_path[0] = '\0';
    }

    memset(conf_path, 0x00, sizeof(conf_path));
    if (install_path[0]) {
        snprintf(conf_path, sizeof(conf_path), "%s", dirname(install_path));
        i = strlen(conf_path);
        if (conf_path[i-2] == 'b' && conf_path[i-1] == 'i' && conf_path[i] == 'n') {
            conf_path[i-3] = '\0';
        }
        snprintf(conf_path+i-3, sizeof(conf_path)-i+2, "%s", conf);
    } else {
        snprintf(conf_path, sizeof(conf_path), "%s", conf);
    }

    memset(path, 0x00, sizeof(path));
    if (is_file(conf_path) == 0) {
        fp = fopen(conf_path, "r");
        if (fp == NULL) {
            elog("get redis conf fail: %s\n", strerror(errno));
            snprintf(path, sizeof(path), "%s", "None");
        }
        else {
            while (fgets(line_info, sizeof(line_info), fp) != NULL) {
                if (line_info[0] == '#') continue;

                if (strncmp(line_info, "logpath", 7) == 0) {
                    i = strlen(line_info);
                    line_info[i-1] = '\0';
                    snprintf(path, sizeof(path), "%s", line_info+10);
                    break;
                }
            }
            fclose(fp);
        }
    }
    else {
        snprintf(path, sizeof(path), "%s", "None");
    }

    cJSON_AddStringToObject(object, "listen_port", listen_port);
    cJSON_AddStringToObject(object, "db_name", "mongodb");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "run_user", user_name);
    cJSON_AddStringToObject(object, "install_path", dirname(install_path));
    cJSON_AddStringToObject(object, "conf_path", conf_path);
    cJSON_AddStringToObject(object, "log_path", path);

    return object;
}

static cJSON *get_oracle_info(const char *pid, const char *cmdline)
{
    char path[PATH_MAX];
    char line_info[PATH_MAX];
    char listen_port[PATH_MAX];
    char install_path[PATH_MAX];
    char conf_path[PATH_MAX];
    char user_name[64];
    char version[PATH_MAX] = "-";
    FILE *fp = NULL;
    int i = 0;
    int ret = 0;
    char *tmp = NULL;
    const char *conf = "conf";
    cJSON *object = cJSON_CreateObject();

    if (pid == NULL || cmdline == NULL) {
        return object;
    }

    /* Oracle 没有可以直接执行查询版本的命令，暂时以目录的名的版本信息作为版本信息 */
    tmp = strstr(cmdline, "/oracle/product/");
    tmp += 16;
    snprintf(version, sizeof(version), "%s", tmp);
    tmp = strchr(version, '/');
    if (tmp) {
        *tmp = '\0';
    }

    memset(listen_port, 0x00, sizeof(listen_port));
    get_db_ipv4_listen_port(pid, listen_port, sizeof(listen_port));

    i = strlen(listen_port);
    if (i > 0) {
        *(listen_port+i) = ';';
        get_db_ipv6_listen_port(pid, listen_port+i+1, sizeof(listen_port)-i-1);
    }
    else {
        get_db_ipv6_listen_port(pid, listen_port, sizeof(listen_port));
    }

    i = strlen(listen_port);
    if (i > 0 && listen_port[i-1] == ';') {
        listen_port[i-1] = 0;
    }

    memset(user_name, 0x00, sizeof(user_name));
    get_name_by_pid(pid, user_name, sizeof(user_name));

    memset(path, 0x00, sizeof(path));
    memset(install_path, 0x00, sizeof(install_path));
    snprintf(path, sizeof(path), "%s", cmdline);
    tmp = strchr(path, '/');
    if (tmp) {
        snprintf(install_path, sizeof(install_path), "%s", tmp);
    }

    tmp = strchr(install_path, ' ');
    if (tmp) {
        *tmp = '\0';
    }

    memset(conf_path, 0x00, sizeof(conf_path));
    if (install_path[0]) {
        snprintf(conf_path, sizeof(conf_path), "%s", install_path);
        tmp = strstr(conf_path, "bin");
        if (tmp) {
            *tmp = '\0';
            i = strlen(conf_path);
            snprintf(conf_path+i, sizeof(conf_path)-i, "%s", conf);
        }
    } else {
        snprintf(conf_path, sizeof(conf_path), "%s", conf);
    }

    memset(path, 0x00, sizeof(path));
    if (install_path[0]) {
        snprintf(path, sizeof(path), "%s", install_path);
        tmp = strstr(path, "bin");
        if (tmp) {
            *tmp = '\0';
            i = strlen(path);
            snprintf(path+i, sizeof(path)-i, "%s", "log");
        }
    } else {
        snprintf(path, sizeof(path), "%s", "log");
    }

    cJSON_AddStringToObject(object, "listen_port", listen_port);
    cJSON_AddStringToObject(object, "db_name", "oracle");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "run_user", user_name);
    cJSON_AddStringToObject(object, "install_path", dirname(install_path));
    cJSON_AddStringToObject(object, "conf_path", conf_path);
    cJSON_AddStringToObject(object, "log_path", path);

    return object;
}

static cJSON *get_memcached_info(const char *pid, const char *cmdline)
{
    char path[PATH_MAX];
    char line_info[PATH_MAX];
    char listen_port[PATH_MAX];
    char install_path[PATH_MAX];
    char conf_path[PATH_MAX];
    char user_name[64];
    char version[PATH_MAX] = "-";
    FILE *fp = NULL;
    int i = 0;
    int ret = 0;
    char *tmp = NULL, *ptr = NULL;
    const char *conf = "redis.conf";
    cJSON *object = cJSON_CreateObject();

    if (pid == NULL || cmdline == NULL) {
        return object;
    }

    // todo
    /* memcached数据库没有获取版本命令，后期可以查询rpm包的版本当作数据库的版本 */
    // version = get_database_version("memcache --version");

    memset(listen_port, 0x00, sizeof(listen_port));
    get_db_ipv4_listen_port(pid, listen_port, sizeof(listen_port));

    i = strlen(listen_port);
    if (i > 0) {
        *(listen_port+i) = ';';
        get_db_ipv6_listen_port(pid, listen_port+i+1, sizeof(listen_port)-i-1);
    }
    else {
        get_db_ipv6_listen_port(pid, listen_port, sizeof(listen_port));
    }

    i = strlen(listen_port);
    if (i > 0 && listen_port[i-1] == ';') {
        listen_port[i-1] = 0;
    }

    memset(user_name, 0x00, sizeof(user_name));
    get_name_by_pid(pid, user_name, sizeof(user_name));

    memset(path, 0x00, sizeof(path));
    memset(install_path, 0x00, sizeof(install_path));
    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    ret = readlink(path, install_path, sizeof(install_path));
    if (ret > 0) {
        install_path[ret] = '\0';
    } else {
        install_path[0] = '\0';
    }

    memset(conf_path, 0x00, sizeof(conf_path));
    snprintf(conf_path, sizeof(conf_path), "%s", "/etc/sysconfig/memcached");

    /* log默认没有，在指定-v/-vv/-vvv的情况下重定向才有，因此-v后面都取做是日志 */
    memset(path, 0x00, sizeof(path));
    tmp = strstr(cmdline, "-v");
    if (tmp) {
        tmp = strchr(tmp, '>'); /* 查找重定向> */
        if (tmp) {
            tmp++;
            if (*tmp == '>') { //重定向>>
                tmp++;
            }
        }
    }

    if (tmp) {
        ptr = skip_headspace(tmp);
        delete_tailspace(ptr);
        snprintf(path, sizeof(path), "%s", ptr);
    }
    else {
        snprintf(path, sizeof(path), "%s", "None");
    }

    cJSON_AddStringToObject(object, "listen_port", listen_port);
    cJSON_AddStringToObject(object, "db_name", "memcached");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "run_user", user_name);
    cJSON_AddStringToObject(object, "install_path", dirname(install_path));
    cJSON_AddStringToObject(object, "conf_path", conf_path);
    cJSON_AddStringToObject(object, "log_path", path);

    return object;
}

/* 读/proc/PID/status里的进程Name，返回读到的进程名长度 */
int get_proc_comm(char *pid, char *comm, int comm_len)
{
        int len = -1;
        FILE *fp = NULL;
        char buf[16] = {0}; 
        char line[256] = {0};
        char path[128] = {0};

        if (!pid || !comm) {
                return -1;
        }

        snprintf(path, sizeof(path), "/proc/%s/status", pid);

        fp = fopen(path, "r");
        if (!fp) {
                if (errno != ENOENT) {
                        elog("get_proc_comm open %s fail: %s\n", path, strerror(errno));
                }
                return -1;
        }

        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "Name: %15s", buf) == 1) {
                        snprintf(comm, comm_len, "%s", buf);
                        len = strlen(comm);
                        break;
                }
        }

        fclose(fp);

        return len;
}

int get_proc_ppid(char *pid, char *ppid, int ppid_len)
{
        int len = -1;
        FILE *fp = NULL;
        char buf[16] = {0}; 
        char line[256] = {0};
        char path[128] = {0};

        if (!pid || !ppid) {
                return -1;
        }

        snprintf(path, sizeof(path), "/proc/%s/status", pid);

        fp = fopen(path, "r");
        if (!fp) {
                if (errno != ENOENT) {
                        elog("open %s fail: %s\n", path, strerror(errno));
                }
                return -1;
        }

        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "PPid: %15s", buf) == 1) {
                        snprintf(ppid, ppid_len, "%s", buf);
                        len = strlen(ppid);
                        break;
                }
        }

        fclose(fp);

        return len;
}

/* 读/proc/PID/exe链接内容，返回读到的命令路径名长度 */
int get_proc_exe(char *pid, char *cmd, int cmd_len)
{
        int len = 0;
        char buf[PATH_MAX] = {0};
        char path[128] = {0}, *ptr = NULL;

        if (!pid || !cmd) {
                return -1;
        }

        snprintf(path, sizeof(path), "/proc/%s/exe", pid);

        len = readlink(path, buf, sizeof(buf)-1);
        if (len < 0) {
                return -errno;
        }
        if (len == 0) {
                return 0;
        }

        /* readlink() does not append a null byte, end byself */
        buf[len] = 0;

        /*
         * 进程运行中程序被删除，取exe会有(deleted)标识，去掉此标识
         * /usr/sbin/console-kit-daemon.#prelink#.BOl1wo (deleted)这样的取/usr/sbin/console-kit-daemon
         */
        ptr = strstr(buf, ".#prelink#.");
        if (ptr) {
                *ptr = 0;
                len = ptr - buf;
        } else {
                ptr = strstr(buf, " (deleted)");
                if (ptr) {
                        *ptr = 0;
                        len = ptr - buf;
                }
        }

        snprintf(cmd, cmd_len, "%s", buf);

        return len;
}

void get_databases_list(char *pid, cJSON *object, char *cmdline)
{
    char cmd[PATH_MAX] = {0};
    char pcmd[PATH_MAX] = {0};
    char process_name[16] = {0};
    char ppid[16] = {0};
    cJSON *data = NULL;

    if (!pid || !object || !cmdline ) {
        return;
    }

    if (atoi(pid) < 300) {
        return; //忽略300号以下的系统保留进程
    }
    if (get_proc_exe(pid, cmd, sizeof(cmd)) <= 0) {
        return; //忽略没有执行程序的进程
    }
    if (get_proc_ppid(pid, ppid, sizeof(ppid)) <= 0) {
        return; //忽略没有父进程的进程
    }
    if (get_proc_exe(ppid, pcmd, sizeof(pcmd)) <= 0) {
        return; //忽略父进程没有执行程序的进程
    }
    if (strcmp(cmd, pcmd) == 0) {
        return; //忽略子进程。不需要考察数据库进程的子进程
    }

    if (get_proc_comm(pid, process_name, sizeof(process_name)) <= 0) {
        return;
    }

    /* postgres早期版本进程名叫postmaster */
    if (strncmp(process_name, "postgres", strlen("postgres")) == 0 ||
        strncmp(process_name, "postmaster", strlen("postmaster")) == 0) {
        cJSON_AddItemToObject(object, "postgres", get_postgres_info(pid, process_name));
        return;
    }

    if (strncmp(process_name, "mongod", strlen("mongod")) == 0) {
        /* 启动mongodb数据库
        * mongod --dbpath /var/lib/mongo --logpath /var/log/mongodb/mongod.log --fork
        * 进程名是mongod，此处匹配的是进程名
        */
        cJSON_AddItemToObject(object, "mongodb", get_mongo_info(pid, process_name));
        return;
    }

    if (strncmp(process_name, "redis-server", strlen("redis-server")) == 0) {
        /* redis */
        cJSON_AddItemToObject(object, "redis", get_redis_info(pid, process_name));
        return;
    }

    if (strncmp(process_name, "memcached", strlen("memcached")) == 0){
        /* memcached */
        cJSON_AddItemToObject(object, "memcached", get_memcached_info(pid, cmdline));
        return;
    }

    if (strncmp(process_name, "mysqld", strlen("mysqld")) == 0){
        data = get_mysql_info(pid, process_name);
        if (data) {
            cJSON_AddItemToObject(object, "mysql", data);
        }
        return;
    }

    /* hbase是脚本启动的Java程序 */
    if (strstr(cmdline, "hbase-daemon")) {
        cJSON_AddItemToObject(object, "hbase", get_hbase_info(pid, cmdline));
        return;
    }

    /* Oracle数据库 */
    if (strstr(cmdline, "/oracle/product/")) {
        cJSON_AddItemToObject(object, "oracle", get_oracle_info(pid, cmdline));
        return;
    }
}
