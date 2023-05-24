/*************************************************************************
    > File Name: asset_list.c
    > Author: Qushb
    > Created Time: Thu 7 Dec 2020 14:25:38 PM CST
 ************************************************************************/


#include "sys_info.h"
#include <sys/resource.h> //setrlimit

//////////////////////////////////////////////////////////////////////


asset_context main_board = {
    SYS_MNAME_MAIN_BOARD,
    0,
    (asset_routine)sys_main_board,
    (asset_routine)sys_main_board_destroy
};
asset_context cpu_info = {
    SYS_MNAME_CPU,
    0,
    (asset_routine)sys_cpu_info,
    (asset_routine)sys_cpu_info_destroy
};
asset_context memory_info = {
    SYS_MNAME_MEMORY,
    0,
    (asset_routine)sys_memory_info,
    (asset_routine)sys_memory_info_destroy
};
asset_context disk_info = {
    SYS_MNAME_DISK,
    0,
    (asset_routine)sys_disk_info,
    (asset_routine)sys_disk_info_destroy
};
asset_context nic_info = {
    SYS_MNAME_NIC,
    0,
    (asset_routine)sys_nic_info,
    (asset_routine)sys_nic_info_destroy
};
asset_context sound_card_info = {
    SYS_MNAME_AUDIO,
    0,
    (asset_routine)sys_sound_card_info,
    (asset_routine)sys_sound_card_info_destroy
};
asset_context display_card_info = {
    SYS_MNAME_CARD,
    0,
    (asset_routine)sys_display_card_info,
    (asset_routine)sys_display_card_info_destroy
};
asset_context display_device_info = {
    SYS_MNAME_MONITOR,
    0,
    (asset_routine)sys_display_device_info,
    (asset_routine)sys_display_device_info_destroy
};
asset_context bios_info = {
    SYS_MNAME_BIOS,
    0,
    (asset_routine)sys_bios_info,
    (asset_routine)sys_bios_info_destroy
};


asset_context partition_info = {
    SYS_MNAME_PARTITION,
    0,
    (asset_routine)sys_partition_info,
    (asset_routine)sys_partition_info_destroy
};
asset_context software_info = {
    SYS_MNAME_SOFTWARE,
    0,
    (asset_routine)sys_software_info,
    (asset_routine)sys_software_info_destroy
};
asset_context account_info = {
    SYS_MNAME_ACCOUNT,
    0,
    (asset_routine)sys_account_info,
    (asset_routine)sys_account_info_destroy
};
asset_context process_info = {
    SYS_MNAME_PROCESS,
    0,
    (asset_routine)sys_process_info,
    (asset_routine)sys_process_info_destroy
};
asset_context port_info = {
    SYS_MNAME_PORT,
    0,
    (asset_routine)sys_port_info,
    (asset_routine)sys_port_info_destroy
};
asset_context service_info = {
    SYS_MNAME_SERVICE,
    0,
    (asset_routine)sys_service_info,
    (asset_routine)sys_service_info_destroy
};
asset_context starter_info = {
    SYS_MNAME_STARTER,
    0,
    (asset_routine)sys_starter_info,
    (asset_routine)sys_starter_info_destroy
};
asset_context share_info = {
    SYS_MNAME_SHARE,
    0,
    (asset_routine)sys_share_info,
    (asset_routine)sys_share_info_destroy
};
asset_context env_info = {
    SYS_MNAME_ENV,
    0,
    (asset_routine)sys_env_info,
    (asset_routine)sys_env_info_destroy
};
asset_context task_info = {
    SYS_MNAME_CRON,
    0,
    (asset_routine)sys_task_info,
    (asset_routine)sys_task_info_destroy
};

asset_context database_info = {
    SYS_MNAME_DATABASE,
    0,
    (asset_routine)sys_database_info,
    (asset_routine)sys_database_info_destroy
};
asset_context pkg_install_info = {
    SYS_MNAME_PKGINSTALL,
    0,
    (asset_routine)sys_pkg_install_info,
    (asset_routine)sys_pkg_install_info_destroy
};
asset_context jar_info = {
    SYS_MNAME_JAR,
    0,
    (asset_routine)sys_jar_info,
    (asset_routine)sys_jar_info_destroy
};
asset_context kernel_info = {
    SYS_MNAME_KERNEL,
    0,
    (asset_routine)sys_kernel_info,
    (asset_routine)sys_kernel_info_destroy
};
asset_context container_info = {
    SYS_MNAME_CONTAINER,
    0,
    (asset_routine)sys_container_info,
    (asset_routine)sys_container_info_destroy
};
asset_context vuln_info = {
    SYS_MNAME_VULN,
    0,
    (asset_routine)sys_vuln_info,
    (asset_routine)sys_vuln_info_destroy
};
asset_context os_info = {
    SYS_MNAME_OS,
    0,
    (asset_routine)sys_os_info,
    (asset_routine)sys_os_info_destroy
};


asset_context web_site_info = {
    SYS_MNAME_WEB_SITE,
    0,
    (asset_routine)sys_web_site_info,
    (asset_routine)sys_web_site_info_destroy
};
asset_context web_middler_info = {
    SYS_MNAME_WEB_MIDDLER,
    0,
    (asset_routine)sys_web_middler_info,
    (asset_routine)sys_web_middler_info_destroy
};
asset_context web_app_info = {
    SYS_MNAME_WEB_APP,
    0,
    (asset_routine)sys_web_app_info,
    (asset_routine)sys_web_app_info_destroy
};
asset_context web_framework_info = {
    SYS_MNAME_WEB_FRAMEWORK,
    0,
    (asset_routine)sys_web_framework_info,
    (asset_routine)sys_web_framework_info_destroy
};

sys_module system_infomation[] = {
        /* hardware */
        //////////////////////////////////////////
        {{{0}}, &main_board,           NULL}, 
        {{{0}}, &cpu_info,             NULL},
        {{{0}}, &memory_info,          NULL},
        {{{0}}, &disk_info,            NULL},
        {{{0}}, &nic_info,             NULL},
        {{{0}}, &sound_card_info,      NULL},
        {{{0}}, &display_device_info,  NULL},
        {{{0}}, &display_card_info,    NULL},
        {{{0}}, &bios_info,            NULL},
        {{{0}}, &partition_info,       NULL},
        
        /* system */
        //////////////////////////////////////////
        {{{0}}, &service_info,         NULL},
        /* 安装包的状态依赖服务，所以服务需要先于安装包执行 */
        {{{0}}, &software_info,        NULL},
        {{{0}}, &pkg_install_info,     NULL},
        {{{0}}, &process_info,         NULL},
        {{{0}}, &port_info,            NULL},
        {{{0}}, &database_info,        NULL},
        {{{0}}, &jar_info,             NULL},
        {{{0}}, &container_info,       NULL},

        //////////////////////////////////////////
        {{{0}}, &account_info,         NULL},
        {{{0}}, &starter_info,         NULL},
        {{{0}}, &share_info,           NULL},
        {{{0}}, &env_info,             NULL},
        {{{0}}, &task_info,            NULL},
        {{{0}}, &kernel_info,          NULL},

        //////////////////////////////////////////
        /* 下面的检测顺序不能反，一定要先检测中间件 */
        /* 先检测中间件 */
        {{{0}}, &web_middler_info,     NULL},
        /* 有的应用不依赖中间件，但顺序不能变 */
        {{{0}}, &web_app_info,         NULL},
        /* 依赖中间件的站点 */
        {{{0}}, &web_site_info,        NULL},
        /* 依赖中间件的框架 */
        {{{0}}, &web_framework_info,   NULL},

        //////////////////////////////////////////
        {{{0}}, &vuln_info,            NULL},
        {{{0}}, &os_info,              NULL},
        {{{0}}, NULL,                  NULL}
        };



//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
/////                  common                                     ////
//////////////////////////////////////////////////////////////////////

/* 
 * Execute cmd to search for keywords and return the first result
 * Return 0 on success, -1 on failure
 * key为NULL，取整行；key非NULL，取包含key的第一行
 */
int popen_filter_one_keystr(const char *cmd, const char *key, char *buf, const unsigned int buf_len)
{
    FILE *fp = NULL;

    if (!cmd || !buf || buf_len == 0) return -1;

    if ((fp = popen(cmd, "r")) == NULL) {
        return -1;
    }

    memset(buf, 0, buf_len);
    while (fgets(buf, buf_len, fp)) {
        if (key == NULL || strstr(buf, key)) {
            pclose(fp);
            return 0;
        }
    }
    pclose(fp);
    memset(buf, 0, buf_len);
 
    return -1;
}

/* 消除头部的空格符 */
char *skip_headspace(char *str)
{
    char *ptr = str;

    while (isspace(*ptr)) {
        ptr++;
    }
    return ptr;
}
/* 消除尾部的空格符、回车和换行符 */
void delete_tailspace(char *str)
{
    int i = 0, len = strlen(str);

    for (i = len-1; i >= 0; i--) {
        if (!isspace(str[i])) {
            return;
        }
        str[i] = 0;
    }
}

/*
 * 从一行中取key的名字和value的值
 * key: 存key的名字。key_len: key的空间大小。value: 存key的值。value_len: value的空间大小
 * delim: key和value之间的分割符，如'='、':'、' '等
 * 返回0，成功。-1，失败
 */
int get_key_value_from_line(char *line, char *key, int key_len, char *value, int value_len, char delim)
{
    char *ptr = NULL, *leftkey = NULL, *rightval = NULL;

    if (!line || !key || !value) {
        return -1;
    }

    ptr = strchr(line, delim);
    if (!ptr) {
        return -1;
    }
    *ptr = 0; //将line分成leftkey和rightval两段

    leftkey = skip_headspace(line);
    delete_tailspace(leftkey);
    snprintf(key, key_len, "%s", leftkey);

    rightval = skip_headspace(ptr+1);
    delete_tailspace(rightval);
    snprintf(value, value_len, "%s", rightval);

    return 0;
}

/* Read the contents of the file and return the first line of results 
 * Return 0 on success, -1 on failure
 */
int return_file_first_line(const char *file_path, char *buf, const unsigned buf_len)
{
    FILE *fp = NULL;
    char *ptr = NULL;
    char line[S_LINELEN] = {0};

    if (!file_path || !buf || buf_len == 0) {
        return -1;
    }

    memset(buf, 0, buf_len);

    fp = fopen(file_path, "r");
    if (!fp) {
        return -1;
    }

    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* 取消头尾的空格符，包括回车换行 */
    ptr = skip_headspace(line);
    delete_tailspace(ptr);

    snprintf(buf, buf_len, "%s", ptr);
    return 0;
}

int is_file(const char *file)
{
    struct stat buf;

    return (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 0 : -1;
}

int is_dir(const char *file)
{
    struct stat file_status;
    if (stat(file, &file_status) < 0) {
        return (-1);
    }
    if (S_ISDIR(file_status.st_mode)) {
        return (0);
    }

    return (-1);
}

char *get_cmd_line_by_pid(const char *pid)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char *tmp = NULL;
    char *end = NULL;
    int fd = 0;
    int len = 0;

    if (pid == NULL) {
        return NULL;
    }

    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    return strdup(line);
}

int system_call(const char *cmd)
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
                elog("run command fail and exit code is %d\n", WEXITSTATUS(status));
                ret = -1;
            }
        }
        else{
            elog("exit status = %d\n", WEXITSTATUS(status));
            ret = -2;
        }
    }

    return ret;
}

char *trim_space(char *str)
{
  char *end = NULL;

  if (str == NULL) return NULL;

  while(isspace((unsigned char)*str)) str++;

  if(*str == 0) return str;

  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;
  end[1] = '\0';

  return str;
}

int sys_md5_file(const char *fname, char *output, int output_len)
{
    FILE *fp = NULL;
    MD5_CTX ctx;
    unsigned char buf[1024] = {0};
    unsigned char digest[16] = {0};
    size_t n = 0;

    if (!fname || !output || output_len < 33) {
        return -1;
    }

    memset(output, 0, output_len);

    fp = fopen(fname, "rb");
    if (!fp) {
        return -1;
    }

    MD5_Init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        MD5_Update(&ctx, buf, (unsigned)n);
    }

    MD5_Final(digest, &ctx);

    for (n = 0; n < 16; n++) {
        snprintf(output, 3, "%02x", digest[n]);
        output += 2;
    }

    fclose(fp);

    return 0;
}

/* 取软件是否有服务：0 无服务 1 启动 2 禁用 */
int software_service_state(const char *pkg_name, sys_info_t *data)
{
    char buf[1024] = {0};
    int rc = 0, start_type = 0;
    int nrow = 0, ncolumn = 0;
    char **azResult = NULL;

    if (!pkg_name || !data || !data->db) return 0;

    snprintf(buf, sizeof(buf), "SELECT start_type FROM sys_service WHERE rpm='%s';", pkg_name);
    rc = sqlite3_get_table(data->db, buf, &azResult, &nrow, &ncolumn, NULL);

    if (rc != SQLITE_OK) {
        sqlite3_free_table(azResult);
        elog("Query service for software %s fail\n", pkg_name);
        return 0;
    }

    if (nrow == 0) {
        sqlite3_free_table(azResult);
        return 0;
    }

    start_type = atoi(azResult[ncolumn]);
    sqlite3_free_table(azResult);

    if (start_type == 3) {
        return 2; //禁用
    }

    return 1; //启动
}
//////////////////////////////////////////////////////////////////////

void *generate_json_file(const sys_module *modules, const char *info_file, const char *zip_file) 
{
    char basic_name[PATH_MAX];
    cJSON *hardware = cJSON_CreateObject();
    cJSON *system = cJSON_CreateObject();
    int i = 0;
    char *string = NULL;
    FILE *fp = NULL;

    if (modules == NULL) return NULL;

    while (modules[i].context) {
        if (i < 10) {/* hardware */
            if (modules[i].context->is_on == 1) {
                cJSON_AddItemToObject(hardware, modules[i].context->name, modules[i].data.object);
            } else if (modules[i].context->is_on == 2) {
                cJSON_Delete(modules[i].data.object);
            }
        }
        else {/* system */
            if (modules[i].context->is_on == 1) { /* 1表示需要上报采集的信息 */
                cJSON_AddItemToObject(system, modules[i].context->name, modules[i].data.object);
            } else if (modules[i].context->is_on == 2) { /* 2表示被依赖的模块，不上报采集信息 */
                cJSON_Delete(modules[i].data.object);
            }
        }

        i++;
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToObject(object, "hardware", hardware);
    cJSON_AddItemToObject(object, "system", system);

    memset(basic_name, 0x00, sizeof(basic_name));
    if (info_file) {
        snprintf(basic_name, sizeof(basic_name), "%s", info_file);
    }
    else {
        snprintf(basic_name, sizeof(basic_name), "%s", SYSINFO_FILE);
    }
    fp = fopen(basic_name, "w+");
    if (fp == NULL) {
        printf("fopen %s file failed!\n", SYSINFO_FILE);
        cJSON_Delete(object);
        return NULL;
    }

    string = cJSON_PrintUnformatted(object);
    fprintf(fp, "%s", string);
    fflush(fp);
    fclose(fp);

    cJSON_Delete(object);
    free(string);

    if (zip_file) { /* file to gzip */
#if 0
        if (sys_compress_gzfile(basic_name, zip_file)) {
            elog("zip failed error\n");
        }
#endif
    }

    return NULL;
}

static void help_sysinfo(void)
{
    int i = 0;

    printf("  systeminformation: [-b basicinfo] [-z zip-file] [-s check-modules] [-S check-module]\n");
    printf("    -b          result file\n");
    printf("    -z          File name after compression\n");
    printf("    -s          bits of modules to check\n");
    printf("    -S          bit of module to check\n");

    printf("\nbit of modules:\n");
    while (system_infomation[i].context) {
        printf("%d: %s\n", i, system_infomation[i].context->name);
        i++;
    }
    printf(" \n");
    exit(1);
}

static void set_system_module_st(enum mname_t name, const int is_switch, enum mname_t depend)
{   
    if (name < 0 || is_switch < 0 || depend > enull) {
        return;
    }

    /* 如果有依赖先检查依赖模块是否已打开 */
    if (is_switch && depend != enull) {
        /* 如果依赖模块是0，表示是默认，设置为2，表示依赖模块运行，但不会上依赖模块采集的信息 */
        if (system_infomation[depend].context->is_on ==0) {
            system_infomation[depend].context->is_on = 2;
        }
    }
    system_infomation[name].context->is_on = is_switch;
    if (is_switch) {
        // printf("%d+++++++++++%s\n", name, system_infomation[name].context->name);
    }

    return ;
}

static void adjust_collection_module(unsigned int module_bit)
{
    int i = 0;
    const int on = 1;
    const int off = 0;
    int turn_on = 0;

    if (!module_bit) { /* 为0时表示使用默认，采集全部模块 */
        while (system_infomation[i].context) {
            system_infomation[i].context->is_on = 1;
            i++;
        }
        return ;
    }

    if (module_bit & 1) { /* hardware */
        while (system_infomation[i].context) {
            if (i < 10) {
                system_infomation[i].context->is_on = 1;
            }
            i++;
        }
    }
    
    i = 1;
    /* partition */
    // turn_on = module_bit & (i<<epartition_info) ? on : off; 
    // set_system_module_st(epartition_info, turn_on, enull);

    /* services 和 process被依赖，所以先设置 */
    /* services */
    turn_on = module_bit & (i<<eservice_info) ? on : off;
    set_system_module_st(eservice_info, turn_on, enull);
    /* software */
    turn_on = module_bit & (i<<esoftware_info) ? on : off;
    set_system_module_st(esoftware_info, turn_on, eservice_info);
    /* install_pkg */
    turn_on = module_bit & (i<<epkg_install_info) ? on : off;
    set_system_module_st(epkg_install_info, turn_on, enull);
    /* process */
    turn_on = module_bit & (i<<eprocess_info) ? on : off;
    set_system_module_st(eprocess_info, turn_on, enull);
    /* port */
    turn_on = module_bit & (i<<eport_info) ? on : off;
    set_system_module_st(eport_info, turn_on, eprocess_info);
    /* database */
    turn_on = module_bit & (i<<edatabase_info) ? on : off;
    set_system_module_st(edatabase_info, turn_on, eprocess_info);
    /* jar */
    turn_on = module_bit & (i<<ejar_info) ? on : off;
    set_system_module_st(ejar_info, turn_on, eprocess_info);

    /* container */
    turn_on = module_bit & (i<<econtainer_info) ? on : off;
    set_system_module_st(econtainer_info, turn_on, enull);
    /* account */
    turn_on = module_bit & (i<<eaccount_info) ? on : off;
    set_system_module_st(eaccount_info, turn_on, enull);
    /* starter */
    turn_on = module_bit & (i<<estarter_info) ? on : off;
    set_system_module_st(estarter_info, turn_on, enull);
    /* share */
    turn_on = module_bit & (i<<eshare_info) ? on : off;
    set_system_module_st(eshare_info, turn_on, enull);
    /* env */
    turn_on = module_bit & (i<<eenv_info) ? on : off;
    set_system_module_st(eenv_info, turn_on, enull);
    /* task */
    turn_on = module_bit & (i<<etask_info) ? on : off;
    set_system_module_st(etask_info, turn_on, enull);
    /* kernel */
    turn_on = module_bit & (i<<ekernel_info) ? on : off;
    set_system_module_st(ekernel_info, turn_on, enull);

    /* web_middleware */
    turn_on = module_bit & (i<<eweb_middler_info) ? on : off;
    set_system_module_st(eweb_middler_info, turn_on, eprocess_info);
    /* web_app */
    turn_on = module_bit & (i<<eweb_app_info) ? on : off;
    set_system_module_st(eweb_app_info, turn_on, eweb_middler_info);
    /* website */
    turn_on = module_bit & (i<<eweb_site_info) ? on : off;
    set_system_module_st(eweb_site_info, turn_on, eweb_middler_info);
    /* web_framework */
    turn_on = module_bit & (i<<eweb_framework_info) ? on : off;
    set_system_module_st(eweb_framework_info, turn_on, eweb_middler_info);

    /* vuln */
    turn_on = module_bit & (i<<evuln_info) ? on : off;
    set_system_module_st(evuln_info, turn_on, enull);
    /* os */
    turn_on = on;
    set_system_module_st(eos_info, turn_on, enull);

    return ;
}

char sys_vendor[64] = {0};
int sniper_debug = 0;
#ifndef SYSINFO_PIDFILE
#define SYSINFO_PIDFILE         "/var/run/systeminformation.pid"
#endif
/* entry */
int main(int argc, char *argv[])
{
    time_t t = 0;
    sqlite3 *sys_db = NULL;
    char *info_file = NULL;
    char *zip_file = NULL;
    int i = 0, ret = 0, n = 0;
    unsigned int module_bit = 0;
    FILE *fp = NULL;
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY};

    /* 关闭继承自父进程的打开文件，主要是为了避免占用netlink socket */
    for (i = 3; i < 1024; i++) {
        close(i);
    }
    errno = 9;

    if (setrlimit(RLIMIT_CORE, &rlim) < 0) {
        printf("ulimit -c unlimited fail: %s\n", strerror(errno));
    }

    dlog("main ...\n");

    while ((i = getopt(argc, argv, "b:z:s:S:h")) != -1) {
        switch (i)
        {
        case 'b':
            if (!optarg) {
                printf("-b needs an argument\n");
            }
            info_file = optarg;
            break;
        case 'z':
            if (!optarg) {
                printf("-z needs an argument\n");
            }
            zip_file = optarg;
            break;
        case 's':
            if (!optarg) {
                printf("-s needs an argument\n");
            }
            module_bit = atoi(optarg);
            break;
        case 'S':
            if (!optarg) {
                printf("-S needs an argument\n");
            }
            sniper_debug = 1;
            n = atoi(optarg);
            if (n < 10) {
                module_bit = 1;
            } else if (i == 13) { //process
                module_bit = 1 << n;
            } else {
                module_bit = (1 << n) + (1 << 13);
            }
            break;
        case 'h':
            help_sysinfo();
            break;
        default:
            break;
        }
    }

    /* 用bit位表示需要采集的资产模块 */
    adjust_collection_module(module_bit);

    /* get current time */
    t = time(NULL);

    unlink("/tmp/SysInfo.db");

    /* init database */
    sys_db = init_sys_db("/tmp/SysInfo.db", NULL, 0);
    if (sys_db == NULL) {
        elog("create db failed\n");
        return -1;
    }

    /* systeminformation时间太长，记录pid用于查看是否完成或强制终止 */
    fp = fopen(SYSINFO_PIDFILE, "w");
    if (fp) {
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }

    return_file_first_line("/sys/class/dmi/id/sys_vendor", sys_vendor, sizeof(sys_vendor));
    if (sys_vendor[0] == 0) {
        snprintf(sys_vendor, sizeof(sys_vendor), "%s", "NoNE"); //None
    }

    /* start */
    i = 0;
    while (system_infomation[i].context) {
        char ch[64];
        time_t t2;
        t2 = time(NULL);

        /* 0表示不采集当前模块信息
         * 1表示需要采集信息，并上报
         * 2表示被依赖的模块，采集但不上报
         */
        if (system_infomation[i].context->is_on == 0) {
            i++;
            continue;
        }
        memset(ch, 0x00, sizeof(ch));
        strftime(ch, sizeof(ch)-1, "%Y-%m-%d %H:%M:%S", localtime(&t2));
        dlog("name:%s, time:%s\n", system_infomation[i].context->name, ch);

        strftime(system_infomation[i].data.time_str, sizeof(system_infomation[i].data.time_str)-1, 
                    "%Y-%m-%d %H:%M:%S", localtime(&t));

        if (strncmp(system_infomation[i].context->name, SYS_MNAME_OS, strlen(SYS_MNAME_OS)) == 0) {
            system_infomation[i].data.object = cJSON_CreateObject();
        }
        else {
            system_infomation[i].data.object = cJSON_CreateArray();
        }
        system_infomation[i].data.db = sys_db;
        system_infomation[i].data.name = system_infomation[i].context->name;
        system_infomation[i].context->start((void*)&system_infomation[i].data);

        i++;
    }

    dlog("json file\n");
    generate_json_file(system_infomation, info_file, zip_file);

    close_db(sys_db);

    unlink("/tmp/SysInfo.db");
    unlink(SYSINFO_PIDFILE);

    return ret;
}
