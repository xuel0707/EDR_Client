/*
 * 弱密码检测
 * 应用类的弱密码检测，Tomcat/ftp/redis等
 */

#include <shadow.h>

#include "header.h"
#include "common.h"

static int call_sys_cmd(const char *cmd)
{
    int ret = 0;
    int status;
    
    if (cmd == NULL) return -1;

    status = system(cmd);
    if (status == -1){
        ret = -1;
    }
    else{
        if (WIFEXITED(status)){
            if (WEXITSTATUS(status) == 0){
                ret = 0;
            }
            else{
                MON_ERROR("run command fail and exit code is %d\n", WEXITSTATUS(status));
                ret = -1;
            }
        }
        else{
            MON_ERROR("exit status = %d\n", WEXITSTATUS(status));
            ret = -2;
        }
    }

    return ret;
}
/* 明文弱密码检测
 */
static int check_pwd_txt(const char *pwd) 
{
    char weak_str[WEAK_LEN] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    int ret = 0;

    if (pwd == NULL) {
        return -1;
    }

    fp = fopen(WEAK_PASSWD_FILE, "r");
    if (!fp) {
        MON_ERROR("get_password open weak lib fail: %s\n", strerror(errno));
        return -1;
    }

    while (fgets(weak_str, sizeof(weak_str), fp)) {
        if (!weak_str[0]) {
            continue;
        }

        /* 清除尾部的换行符，但不能清除尾部的空格，因为密码尾部可以带空格，不过弱密码未必有这种情况 */
        tmp = weak_str + strlen(weak_str) -1;
        while (*tmp == '\r' || *tmp == '\n') {
            *tmp-- = '\0';
        }

        if (strcmp(weak_str, pwd) == 0) {
            ret = PwdInWeakLib;
            break;
        }
    }
    fclose(fp);

    return ret;
}

static int get_fd_inode(const char *pid, const unsigned long inode)
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
        MON_ERROR("Open dir %s failed\n", run_path);
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

static int get_process_listen_port(const char *pid, const char *path, 
                        char *buf, const int buf_len, const int flag)
{
    char line_info[PATH_MAX];
    char ip_listen[PATH_MAX];
    sockinfo_t ip_info;
    int i = 0;
    FILE *fp = NULL;

    if (pid == NULL || path == NULL || buf == NULL || buf_len <= 0) {
        return -1;
    }

    memset(buf, 0x00, sizeof(buf_len));
    memset(line_info, 0x00, sizeof(line_info));
    memset(ip_listen, 0x00, sizeof(ip_listen));
    memset(&ip_info, 0x00, sizeof(ip_info));

    fp = fopen(path, "r");
    if (fp) {
        fgets(line_info, sizeof(line_info), fp);
        while (fgets(line_info, sizeof(line_info), fp)) {
            if (get_socket_info(line_info, &ip_info) < 0) {
                continue;
            }

            if (ip_info.state != TCP_LISTEN) {
                continue;
            }

            if (get_fd_inode(pid, ip_info.inode) == 0) { /* current db not found inode */
                continue;
            }

            /* 过滤localhost的端口*/
            if (flag && strcmp(ip_info.src_ip, "::") == 0) {
                continue;
            } else if (flag && strcmp(ip_info.src_ip, "::1") == 0) {
                continue;
            } else if (flag && strcmp(ip_info.src_ip, "127.0.0.1") == 0) {
                continue;
            }

            if (!ip_listen[0]) {
                snprintf(ip_listen, sizeof(ip_listen), "%d", ip_info.src_port);
            }
            else { /* 要拼上所有监听的端口，有的应用会同时监听两个以上的端口 */
                i = strlen(ip_listen);
                snprintf(ip_listen+i, sizeof(ip_listen)-i, ":%d", ip_info.src_port);
            }
        }
        fclose(fp);
    }

    snprintf(buf, buf_len, "%s", ip_listen);
    
    return 0;
}

static int covert_weak_lib_file(const char *weak_lib)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    FILE *fp = NULL;
    FILE *fp2 = NULL;
    char *tmp = NULL;
    int ret = 0;

    if (weak_lib == NULL) {
        return -1;
    }

    /* 转换弱密码文件CRLF,不然hydra匹配不上 */
    memset (path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s/%s", WORKDIR, weak_lib);

    fp = fopen(WEAK_PASSWD_FILE, "rb");
    if (!fp) {
        MON_ERROR("covert weak failed, ret:%d\n", errno);
        return -1;
    }
    fp2 = fopen(path, "wb");
    if (!fp2) {
        MON_ERROR("covert weak failed, ret:%d\n", errno);
        fclose(fp);
        return -1;
    }
    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        tmp = line;
        tmp += strlen(line) -2;
        if (tmp && (*tmp == '\r' || *tmp == '\n')) {
            *tmp = '\n';
            *(tmp+1) = '\0';
        }
        fprintf(fp2, "%s", line);
    }
    fclose(fp);
    fclose(fp2);

    return ret;
}

static int del_file(const char *filename) 
{
    char path[PATH_MAX] = {0};

    if (filename == NULL) {
        return -1;
    }

    snprintf(path, sizeof(path), "%s/%s", WORKDIR, filename);
    unlink(path);

    return 0;
}

/* 查找redis配置中明文密码
 * 找到明文密码返回1，其它返回非1
 */
static int check_redis_conf(char *cmdline, cJSON *object)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char pwd[64];
    FILE *fp = NULL;
    char *tmp = NULL;
    char *default_conf = "/etc/redis.conf";
    int ret = 0;

    if (cmdline == NULL || object == NULL) {
        return -1;
    }

    /* cmdline中可以指定redis配置文件的路径
     * ./redis-server /opt/redis-3.2.3/redis.conf
     * 默认/etc/redis.conf
     */
    tmp = strstr(cmdline, "redis-server");
    if (!tmp) {
        return -1;
    }
    tmp += 12;
    tmp = strchr(tmp, '/');
    if (!tmp) {
        tmp = default_conf;
    }

    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    
    snprintf(path, sizeof(path), "%s", tmp);
    tmp = strchr(path, ' ');
    if (tmp) {
        *tmp = '\0';
    }

    fp = fopen(path, "r");
    if (!fp) {
        MON_ERROR("check vsftp conf fail: %s\n", strerror(errno));
        return -1;
    }

    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        tmp = line + strlen(line) -1;
        if (*tmp == '\n') {
            *tmp = '\0';
        }

        tmp = line;
        while (isspace((unsigned char)*tmp)) {
            ++ tmp;
        }

        if (*tmp == '#') {
            continue;
        }
        /* 先比较开始的字符 */
        if (strncmp(tmp, "requirepass", 11) != 0) {
            continue;
        }
        tmp += 11;

        while (isspace((unsigned char)*tmp)) {
            ++ tmp;
        }
        memset (pwd, 0x00, sizeof(pwd));
        snprintf(pwd, sizeof(pwd), "%s", tmp);

        if (check_pwd_txt(pwd) == PwdInWeakLib) {
            /* redis没有用户名，所以不用检查白名单 */
            cJSON *item = cJSON_CreateObject();
            cJSON_AddNumberToObject(item , "uid", 0);
            cJSON_AddNumberToObject(item , "weak_type", PwdInWeakLib);
            // 1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
            cJSON_AddNumberToObject(item , "app_type", 4);
            cJSON_AddStringToObject(item , "username", "");
            cJSON_AddStringToObject(item , "passwd", pwd);
            cJSON_AddStringToObject(item , "hash", "");
            // 0禁用 1启用 2锁定 3不可登录
            cJSON_AddNumberToObject(item , "account_status", 1);
            cJSON_AddItemToArray(object, item);
        }
        ret = 1;
        break;
    }
    fclose(fp);

    return ret;
}
static int detect_redis_pwd(const char* app_pid, char *cmdline, cJSON *object)
{
    char port_str[2048];
    char path[PATH_MAX];
    char sys_cmd[PATH_MAX];
    char line[PATH_MAX];
    FILE *fp = NULL;
    char *tmp = NULL;
    char *weakpasswd = NULL;
    const char *weak_log = "weak.log";
    const char *unix_weak_lib = "weak_lib";
    int ret = 0;

    if (app_pid == NULL || cmdline == NULL || object == NULL) {
        return -1;
    }

    memset (port_str, 0x00, sizeof(port_str));
    get_process_listen_port(app_pid, "/proc/net/tcp", port_str, sizeof(port_str), 0);
    if (!port_str[0]) {
        memset (port_str, 0x00, sizeof(port_str));
        get_process_listen_port(app_pid, "/proc/net/tcp6", port_str, sizeof(port_str), 0);
    }
    if (!port_str[0]) {
        return -1;
    }
    
    if (covert_weak_lib_file(unix_weak_lib) != 0) {
        return -1;
    }

    memset (sys_cmd, 0x00, sizeof(sys_cmd));
    memset (line, 0x00, sizeof(line));

    /* 命中结果有拿不全的情况，因此全部重定向到文件中再取 */
    snprintf(sys_cmd, sizeof(sys_cmd), "%s/sniper_chkweakpasswd -P %s/%s 127.0.0.1 -f redis -s %s -o %s/%s 2>/dev/null", 
                WORKDIR, WORKDIR, unix_weak_lib, port_str, WORKDIR, weak_log);
    /* 执行命令，不判断返回值是否是0，命中的话有的系统可能返回255 */
    call_sys_cmd(sys_cmd);

    memset (path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s/%s", WORKDIR, weak_log);
    fp = fopen(path, "r");
    if (!fp) {
        del_file(unix_weak_lib);
        return -1;
    }
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        /* 有效结果以 [ 开头, 类似于 [!] 127.0.0.1 .. not require password */
        if (line[0] != '[') {
            continue;
        }
        if (strstr(line, "not require password")) {
            ret = EmptyPwd;
            break;
        } else if (strstr(line, port_str)){
            tmp = strstr(line, "password: ");
            if (!tmp) {
                continue;
            }
            weakpasswd = tmp + 10;
            if (weakpasswd) {
                ret = PwdInWeakLib;
            }
            tmp = strchr(weakpasswd, '\n');
            if (tmp) {
                *tmp = '\0';
            }
            break;
        }
        weakpasswd = NULL;
    }
    fclose(fp);

    del_file(weak_log);

    // 1 空口令 2密码与用户名相同 3常见弱口令
    if (ret == EmptyPwd || ret == PwdSameAsAccount || ret == PwdInWeakLib) {
        /* redis没有用户名，所以不用检查白名单 */
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item , "uid", 0);
        cJSON_AddNumberToObject(item , "weak_type", ret);
        // 1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
        cJSON_AddNumberToObject(item , "app_type", 4);
        cJSON_AddStringToObject(item , "username", "");
        if (weakpasswd) {
            cJSON_AddStringToObject(item , "passwd", weakpasswd);
        } else {
            cJSON_AddStringToObject(item , "passwd", "");
        }
        cJSON_AddStringToObject(item , "hash", "");
        // 0禁用 1启用 2锁定 3不可登录
        cJSON_AddNumberToObject(item , "account_status", 1);
        cJSON_AddItemToArray(object, item);
    }

    del_file(unix_weak_lib);

    return ret;
}
/*  检测tomcat设置的弱密码 */
static int detect_tomcat_pwd(const char* app_pid, char *cmdline, cJSON *object)
{
    char line[PATH_MAX];
    char path[PATH_MAX];
    FILE *fp = NULL;
    char *tmp = NULL;
    char *username = NULL;
    char *passwd = NULL;
    unsigned int len = 0;
    int ret = -1;
    /* 标记注释 */
    int start = 0;

    if (app_pid == NULL || cmdline == NULL || object == NULL) {
        return -1;
    }

    tmp = strstr(cmdline, "-Dcatalina.base=");
    if (!tmp) {
        return -1;
    }
    tmp += 16;
    if (!tmp) {
        return -1;
    }

    /* install path */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", tmp);
    tmp = strchr(path, ' ');
    if (tmp) {
        *tmp = '\0';
    }

    len = strlen(path);
    if (len >= sizeof(path)) {
        return -1;
    }
    /* 配置文件目录，安装目录+/conf/tomcat-users.xml */
    snprintf(path+len, sizeof(path)-len, "%s", "/conf/tomcat-users.xml");
    
    DBG2(DBGFLAG_USER, "check_tomcat_weakpwd conf:%s\n", path);
    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        if (strstr(line, "<?")) { /* XML文件声明行 */
            continue;
        }
        if (line[0] == '\n') {
            continue;
        }
        tmp = line;
        while (*tmp == ' ') {
            ++ tmp;
        }

        if (start) { /* 已在多行注释中 */
            if (*tmp == '-' && *(++tmp) == '-' && *(++tmp) == '>') {
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
                -- tmp;
            }
            while (*tmp == ' ') {
                -- tmp;
            }
            if (*tmp == '>' && *(--tmp) == '-' && *(--tmp) == '-') { /* 单行的注释结束 */
                start = 0;
                continue;
            }
        }

        if (start) {
            continue;
        }

        /* 不同版本此属性名可能不同，统一改为name= */
        tmp = strstr(line, "name=");
        if (!tmp) {
            continue;
        }
        tmp += 5;
        tmp = strchr(tmp, '\"');
        if (tmp) {
            ++ tmp;
            username = tmp;
        }

        tmp = strstr(tmp, "password=");
        if (!tmp) {
            continue;
        }
        tmp += 9;
        tmp = strchr(tmp, '\"');
        if (tmp) {
            ++ tmp;
            passwd = tmp;
        }

        if (!username || !passwd) {
            username = NULL;
            passwd = NULL;
            continue;
        }
        tmp = strchr(username, '\"');
        if (tmp) {
            *tmp = '\0';
        } else {
            continue;
        }

        tmp = strchr(passwd, '\"');
        if (tmp) {
            *tmp = '\0';
        } else {
            continue;
        }

        DBG2(DBGFLAG_USER, "check_tomcat_weakpwd user:%s,pwd:%s\n", username, passwd);
        if (strlen(passwd) == 0) {
            ret = EmptyPwd;
        } else if (strcmp(username, passwd) == 0) {
            ret = PwdSameAsAccount;
        } else {
            ret = check_pwd_txt(passwd);
        }
        // 1 空口令 2密码与用户名相同 3常见弱口令
        if (ret == EmptyPwd || ret == PwdSameAsAccount || ret == PwdInWeakLib) {
            /* 检查白名单 */
            if (check_weak_passwd_whitelist(username, 5)) {
                continue;
            }
            cJSON *item = cJSON_CreateObject();
            cJSON_AddNumberToObject(item , "uid", 0);
            cJSON_AddNumberToObject(item , "weak_type", ret);
            // 1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
            cJSON_AddNumberToObject(item , "app_type", 5);
            cJSON_AddStringToObject(item , "username", username);
            cJSON_AddStringToObject(item , "passwd", passwd);
            cJSON_AddStringToObject(item , "hash", "");
            // 0禁用 1启用 2锁定 3不可登录
            cJSON_AddNumberToObject(item , "account_status", 1);
            cJSON_AddItemToArray(object, item);
        }

        username = NULL;
        passwd = NULL;
        ret = -1;
    }
    fclose(fp);

    return 0;
}
#if 0
/* 生成ftp的用户列表 */
static int generate_ftp_user_name(const char *username)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
    struct spwd user_info;
    struct passwd pw;
    struct passwd *pwp = NULL;
    struct spwd *user_infop = NULL;
    FILE *fp = NULL;
    int ret = 0;

    if (username == NULL) {
        return -1;
    }

    memset (path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s/%s", WORKDIR, username);
    fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }

    memset (buf, 0x00, sizeof(buf));
    memset (buf2, 0x00, sizeof(buf2));

    setpwent();
    while (1) {
        ret = getpwent_r(&pw, buf, sizeof(buf), &pwp);
        if (ret != 0) {
            DBG2(DBGFLAG_USER, "ftp get sys user fail, ret:%d\n", ret);
            break;
        }

        getspnam_r(pw.pw_name, (struct spwd *)&user_info, buf2, sizeof(buf2), (struct spwd **)&user_infop);
        if (user_infop == NULL) {
            break;
        }

        snprintf(line, sizeof(line), "%s\n", pw.pw_name);
        fprintf(fp, "%s", line);
    }
    endpwent();

    fclose(fp);

    return 0;
}


/* 暂时不关心conf中userlist_deny的配置/etc/vsftpd/user_list中的内容也不用看
 * 使用hydra可以用不允许登录的用户测试，不会卡住，顶多是不命中
 * 所以取所有系统用户进行弱密码检测即可
 */
static int detect_ftp_pwd(const char* app_pid, char *cmdline, cJSON *object)
{
    char port_str[2048];
    char path[PATH_MAX];
    char line[PATH_MAX];
    char sys_cmd[PATH_MAX];
    char repeat_name[USER_MAX];
    const char *weak_log = "weak.log";
    const char *unix_weak_lib = "weak_lib";
    const char *ftp_user_name = "ftp_users";
    char *weakpasswd = NULL;
    char *username = NULL;
    FILE *fp = NULL;
    char *tmp = NULL;
    int ret = 0;
    int len = 0;

    if (app_pid == NULL || cmdline == NULL || object == NULL) {
        return -1;
    }

    memset (port_str, 0x00, sizeof(port_str));
    get_process_listen_port(app_pid, "/proc/net/tcp", port_str, sizeof(port_str), 0);
    if (!port_str[0]) {
        memset (port_str, 0x00, sizeof(port_str));
        get_process_listen_port(app_pid, "/proc/net/tcp6", port_str, sizeof(port_str), 0);
    }
    if (!port_str[0]) {
        DBG2(DBGFLAG_USER, "get ftp port fail\n");
        return -1;
    }

    if (covert_weak_lib_file(unix_weak_lib) != 0) {
        return -1;
    }

    if (generate_ftp_user_name(ftp_user_name) != 0) {
        DBG2(DBGFLAG_USER, "get ftp users fail\n");
        return -1;
    }

    memset (sys_cmd, 0x00, sizeof(sys_cmd));
    snprintf(sys_cmd, sizeof(sys_cmd), "%s/sniper_chkweakpasswd -L %s/%s -e nsr -P %s/%s -o %s/%s 127.0.0.1 ftp -s %s 2>/dev/null", 
            WORKDIR, WORKDIR, ftp_user_name, WORKDIR, unix_weak_lib, WORKDIR, weak_log, port_str);
    call_sys_cmd(sys_cmd);

    memset (path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s/%s", WORKDIR, weak_log);
    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    
    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        if (line[0] == '#') {
            continue;
        } 
        if (line[0] != '[') {
            continue;
        }
        tmp = line;
        len = strlen(line);
        tmp += len -1;
        if (*tmp == '\n') {
            *tmp = '\0';
        }

        tmp = strstr(line, "password: ");
        if (tmp) {
            tmp += 10;
            weakpasswd = tmp;
        } else { /* 没有找到password是重复的结果的开始，排除掉 */
            memset (repeat_name, 0x00, sizeof(repeat_name));
            weakpasswd = NULL;
        }

        if (weakpasswd == NULL) {
            tmp = strstr(line, "login: ");
            if (tmp) {
                tmp += 7;
                username = tmp;
            }
            snprintf(repeat_name, sizeof(repeat_name), "%s", username);
        } else {
            tmp = strstr(line, "login: ");
            if (tmp) {
                tmp += 7;
                username = tmp;
            }
            tmp = strchr(username, ' ');
            if (tmp) {
                *tmp = '\0';
            }
            if (strcmp(username, repeat_name) != 0) {
                DBG2(DBGFLAG_USER, "check_ftp_weakpwd user:%s, passwd:%s\n", username, weakpasswd);
                /* TODO 
                 * ftp用户的空密码和相同密码从结果上区分不出来，需要考虑其它方法
                 */
                if (strcmp(username, weakpasswd) == 0) {
                    ret = PwdSameAsAccount;
                } else if (strcmp(username, weakpasswd) != 0) {
                    ret = PwdInWeakLib;
                }
                if (ret == EmptyPwd || ret == PwdSameAsAccount || ret == PwdInWeakLib) {
                    /* 检查白名单 */
                    if (check_weak_passwd_whitelist(username, 3)) {
                        continue;
                    }
                    cJSON *item = cJSON_CreateObject();
                    cJSON_AddNumberToObject(item , "uid", 0);
                    cJSON_AddNumberToObject(item , "weak_type", ret);
                    // 1-Linux 2-Win 3-FTP 4-REDIS 5-TOMCAT
                    cJSON_AddNumberToObject(item , "app_type", 3);
                    cJSON_AddStringToObject(item , "username", username);
                    cJSON_AddStringToObject(item , "passwd", weakpasswd);
                    cJSON_AddStringToObject(item , "hash", "");
                    // 0禁用 1启用 2锁定 3不可登录
                    cJSON_AddNumberToObject(item , "account_status", 1);
                    cJSON_AddItemToArray(object, item);
                }
            }
        }
    }
    fclose(fp);

    del_file(unix_weak_lib);
    del_file(weak_log);
    del_file(ftp_user_name);

    return ret;
}
#endif

/* 检查vsftp是否配置了虚拟用户
 * 找到虚拟用户配置，返回 1， 没找到返回 0，出错返回 -1
 */
static int check_vsftp_conf(const char *path)
{
    char line[S_LINELEN] = {0};
    char lib[S_LINELEN] = {0};
    FILE *fp = NULL;
    char *tmp = NULL, *ptr = NULL;
    int found = 0;
    int auth_flag = 0;
    int account_flag = 0;

    if (path == NULL) {
        return -1;
    }

    /* 先检查/etc/vsftpd.conf配置中，开启了pam_service_name=vsftpd */
    fp = fopen(path, "r");
    if (!fp) {
        MON_ERROR("check vsftp conf fail: %s\n", strerror(errno));
        return -1;
    }

    /* 查找pam_service_name=vsftpd，或pam_service_name = vsftpd这样的行 */
    while (fgets(line, sizeof(line), fp) != NULL) {
        tmp = skip_headspace(line);
        if (*tmp == '#') {
            continue;
        }

        /* 先比较开始的字符 */
        if (strncmp(tmp, "pam_service_name", 16) != 0) {
            continue;
        }

        ptr = tmp + 16;
        tmp = skip_headspace(ptr);

        if (*tmp != '=') {
            continue;
        }

        ptr = tmp + 1;
        tmp = skip_headspace(ptr);

        if (strncmp(tmp, "vsftpd", 6) == 0) {
            found = 1;
            break;
        }
    }
    fclose(fp);

    if (found == 0) { /* 没有找到 */
        return 0;
    } 

    /* 再检查 /etc/pam.d/vsftpd 中配置了下面的信息
     * auth    required  pam_userdb.so db=/etc/vsftpd/login
     * account required  pam_userdb.so db=/etc/vsftpd/login
     * 或
     * auth required /lib/security/pam_userdb.so db=/etc/vsftpd_login
     * account required /lib/security/pam_userdb.so db=/etc/vsftpd_login
     */
    fp = fopen("/etc/pam.d/vsftpd", "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        tmp = skip_headspace(line);
        if (*tmp == '#') {
            continue;
        }

        if (sscanf(tmp, "auth required %s", lib) == 1) {
            if (strstr(tmp, "pam_userdb.so")) {
                auth_flag = 1;
            }
        } else if (sscanf(tmp, "account required %s", lib) == 1) {
            if (strstr(tmp, "pam_userdb.so")) {
                account_flag = 1;
            }
        }
    }
    fclose(fp);

    /* 都找到了返回 1，否则返回 0 */
    return auth_flag & account_flag;
}

/* 查找进程
 * is_vuser_ftp是 1表示vsftp配置了虚拟用户，0 表示没有设置虚拟用户，采用系统用户的检查结果
 */
int check_app_user(cJSON *object, int *is_vuser_ftp)
{
    char path[PATH_MAX];
    char cmdline[PATH_MAX];
    DIR *procdirp = NULL;
    struct dirent *pident = NULL;
    char *tmp = NULL;
    char *end = NULL;
    int fd = 0;
    int len = 0;
    pid_t pid = 0;

    if (object == NULL) {
        return -1;
    }

    procdirp = opendir("/proc");
    if (procdirp == NULL) {
        return -1;
    }

    /* 遍历/proc获得当前进程信息 */
    while ((pident = readdir(procdirp))) {
        /* 忽略非进程项信息 */
        if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
            continue;
        }

        pid = atoi(pident->d_name);
        if (pid <= 2) {
            continue;
        }
        if (is_kernel_thread(pid)) {
            continue; //忽略内核线程
        }

        /* /proc/pid/cmdline */
        memset (cmdline, 0x00, sizeof(cmdline));
        memset (path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

        fd = open(path, O_RDONLY);
        if (fd < 0) {
            continue;
        }
        len = read(fd, cmdline, sizeof(cmdline)-1);
        if (len > sizeof(cmdline)) {
            close(fd);
            continue;
        }
        end = cmdline + len;
        if (!end) {
            close(fd);
            continue;
        }
        for (tmp=cmdline; tmp<end; tmp++) {
            if (*tmp == 0) {
                *tmp = ' ';
            }
        }
        close(fd);

        if (strstr(cmdline, "-Dcatalina.base")) { /* tomcat */
            detect_tomcat_pwd(pident->d_name, cmdline, object);
        } else if (strstr(cmdline, "redis-server")) { /* redis */
            if (check_redis_conf(cmdline, object) != 1) { 
                /* 没找到明文密码，调用工具检查运行中的redis是否是空/弱密码 */
                detect_redis_pwd(pident->d_name, cmdline, object);
            }
        } else if (strstr(cmdline, "vsftpd")) { /* vsftpd */
            tmp = strstr(cmdline, "vsftpd /");
            if (tmp) {
                tmp += 7;
                memset (path, 0x00, sizeof(path));
                snprintf(path, sizeof(path), "%s", tmp);
                tmp = strchr(path, ' ');
                if (tmp) {
                    *tmp = '\0';
                }

                /* 检查FTP是否配置了虚拟用户 */
                *is_vuser_ftp = check_vsftp_conf(path);
                if (*is_vuser_ftp == 1) { /* 有虚拟用户配置，再查虚拟用户 */
                    // TODO 读取Berkeley DB使用虚拟用户查 */
                    // detect_ftp_pwd(pident->d_name, cmdline, object);
                }
            }
        }
    }
    closedir(procdirp);

    return 0;
}
