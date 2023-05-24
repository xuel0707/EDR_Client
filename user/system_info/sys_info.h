/*************************************************************************
    > File Name: sys_info.h
    > Author: Qushb
    > Created Time: Fri 11 Dec 2020 10:05:38 PM CST
 ************************************************************************/

#ifndef __SYS_INFO_H__
#define __SYS_INFO_H__

#include "../system_type.h"
#ifndef SNIPER_FOR_DEBIAN
#include <db.h>
#endif

/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

/*get_opt */
#include <getopt.h> 

/* time */
#include <time.h>

/* file operation */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

/* libcurl */
#include <curl/curl.h>
#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/md5.h>

#include <sys/prctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <mntent.h>
#include <sys/statvfs.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <utmp.h>
#include <utmpx.h>
#include <sys/sysinfo.h>
#include <pwd.h>
#include <grp.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <zlib.h>
#include <sys/wait.h>
#include <sys/statfs.h>
#include <time.h>

#include "../../include/vendor_sniper.h"
#include "../cJSON.h"
#include "../sqlite3.h"
#include "debug.h"
#include "sys_db_op.h"

#define OS_BINARY  0
#define OS_TEXT    1

#ifndef S_LINELEN
#define S_LINELEN 256
#endif

/* hardware */
#define SYS_MNAME_MAIN_BOARD    "main_board"
#define SYS_MNAME_CPU           "cpu"
#define SYS_MNAME_MEMORY        "memory"
#define SYS_MNAME_DISK          "disk"
#define SYS_MNAME_NIC           "network_card"
#define SYS_MNAME_AUDIO         "sound_card"
#define SYS_MNAME_CARD          "display_card"
#define SYS_MNAME_MONITOR       "display_device"
#define SYS_MNAME_BIOS          "bios"

/* system */
#define SYS_MNAME_PARTITION     "partition"
#define SYS_MNAME_SOFTWARE      "software"
#define SYS_MNAME_ACCOUNT       "account"
#define SYS_MNAME_PROCESS       "process"
#define SYS_MNAME_PORT          "port"
#define SYS_MNAME_SERVICE       "services"
#define SYS_MNAME_STARTER       "starter"
#define SYS_MNAME_SHARE         "share"
#define SYS_MNAME_ENV           "env"
#define SYS_MNAME_CRON          "task"
#define SYS_MNAME_DATABASE      "database"
#define SYS_MNAME_PKGINSTALL    "install_pkg"
#define SYS_MNAME_JAR           "jar"
#define SYS_MNAME_KERNEL        "kernel"
#define SYS_MNAME_CONTAINER     "container"
#define SYS_MNAME_VULN          "vuln"
#define SYS_MNAME_OS            "os"

#define SYS_MNAME_WEB_SITE      "website"
#define SYS_MNAME_WEB_MIDDLER   "web_middleware"
#define SYS_MNAME_WEB_APP       "web_app"
#define SYS_MNAME_WEB_FRAMEWORK "web_framework"

#define SYSINFO_FILE "./basic.json"

enum mname_t {
    emain_board=0,
    ecpu_info,
    ememory_info,
    edisk_info,
    enic_info,
    esound_card_info,
    edisplay_device_info,
    edisplay_card_info,
    ebios_info,
    /////////////////////////////////
    epartition_info,
    eservice_info,
    esoftware_info,
    epkg_install_info,
    eprocess_info,
    eport_info,
    edatabase_info,
    ejar_info,
    econtainer_info,
    /////////////////////////////////
    eaccount_info,
    estarter_info,
    eshare_info,
    eenv_info,
    etask_info,
    ekernel_info,
    /////////////////////////////////
    eweb_middler_info,
    eweb_app_info,
    eweb_site_info,
    eweb_framework_info,
    /////////////////////////////////
    evuln_info,
    eos_info,
    enull
};


typedef struct _sys_info {
    char time_str[32];          // 时间戳
    cJSON *object;              // Json
    void *ret;                  // 返回结果
    sqlite3 *db;                // 用于打开本地数据库
    const char *name;           // 模块名
} sys_info_t;


typedef void* (*asset_routine)(void*);

typedef struct asset_context {
    const char *name;
    int is_on;
    asset_routine start;
    asset_routine destroy;
} asset_context;

typedef struct asset_module {
    sys_info_t data;
    asset_context *context;
    char *tag;
}sys_module;

/* common */
extern char sys_vendor[64];
typedef struct _socket_info {
    char src_ip[128];
    char dst_ip[128];
    unsigned long inode;
    int  src_port;
    int  dst_port;
    uid_t  uid;
    int  state;
    int  direction;
} sock_info_t;
int get_proc_socket_info(char *line, sock_info_t *info);
int popen_filter_one_keystr(const char *cmd, const char *key, char *buf, const unsigned int buf_len);
int return_file_first_line(const char *file_path, char *buf, const unsigned buf_len);
int is_file(const char *file);
char *get_cmd_line_by_pid(const char *pid);
int system_call(const char *cmd);
char *trim_space(char *str);
int sys_md5_file(const char *fname, char *output, int output_len);
char *skip_headspace(char *str);
void delete_tailspace(char *str);
int software_service_state(const char *pkg_name, sys_info_t *data);
int get_key_value_from_line(char *line, char *key, int key_len, char *value, int value_len, char delim);

/* hardware */
void *sys_main_board(sys_info_t *data);
void *sys_main_board_destroy(sys_info_t *data);

void *sys_cpu_info(sys_info_t *data);
void *sys_cpu_info_destroy(sys_info_t *data);

void *sys_memory_info(sys_info_t *data);
void *sys_memory_info_destroy(sys_info_t *data);

void *sys_disk_info(sys_info_t *data);
void *sys_disk_info_destroy(sys_info_t *data);

void *sys_nic_info(sys_info_t *data);
void *sys_nic_info_destroy(sys_info_t *data);

void *sys_sound_card_info(sys_info_t *data);
void *sys_sound_card_info_destroy(sys_info_t *data);

void *sys_bios_info(sys_info_t *data);
void *sys_bios_info_destroy(sys_info_t *data);

void *sys_display_card_info(sys_info_t *data);
void *sys_display_card_info_destroy(sys_info_t *data);

void *sys_display_device_info(sys_info_t *data);
void *sys_display_device_info_destroy(sys_info_t *data);

/* system */
void *sys_partition_info(sys_info_t *data);
void *sys_partition_info_destroy(sys_info_t *data);

void *sys_software_info(sys_info_t *data);
void *sys_software_info_destroy(sys_info_t *data);

void *sys_account_info(sys_info_t *data);
void *sys_account_info_destroy(sys_info_t *data);

void *sys_process_info(sys_info_t *data);
void *sys_process_info_destroy(sys_info_t *data);

void *sys_port_info(sys_info_t *data);
void *sys_port_info_destroy(sys_info_t *data);

void *sys_service_info(sys_info_t *data);
void *sys_service_info_destroy(sys_info_t *data);

void *sys_starter_info(sys_info_t *data);
void *sys_starter_info_destroy(sys_info_t *data);

void *sys_share_info(sys_info_t *data);
void *sys_share_info_destroy(sys_info_t *data);

void *sys_env_info(sys_info_t *data);
void *sys_env_info_destroy(sys_info_t *data);

void *sys_task_info(sys_info_t *data);
void *sys_task_info_destroy(sys_info_t *data);

void *sys_database_info(sys_info_t *data);
void *sys_database_info_destroy(sys_info_t *data);

void *sys_pkg_install_info(sys_info_t *data);
void *sys_pkg_install_info_destroy(sys_info_t *data);

void *sys_jar_info(sys_info_t *data);
void *sys_jar_info_destroy(sys_info_t *data);

void *sys_kernel_info(sys_info_t *data);
void *sys_kernel_info_destroy(sys_info_t *data);

void *sys_container_info(sys_info_t *data);
void *sys_container_info_destroy(sys_info_t *data);

void *sys_vuln_info(sys_info_t *data);
void *sys_vuln_info_destroy(sys_info_t *data);

void *sys_os_info(sys_info_t *data);
void *sys_os_info_destroy(sys_info_t *data);


void *sys_web_site_info(sys_info_t *data);
void *sys_web_site_info_destroy(sys_info_t *data);

void *sys_web_middler_info(sys_info_t *data);
void *sys_web_middler_info_destroy(sys_info_t *data);

void *sys_web_app_info(sys_info_t *data);
void *sys_web_app_info_destroy(sys_info_t *data);

void *sys_web_framework_info(sys_info_t *data);
void *sys_web_framework_info_destroy(sys_info_t *data);

#ifndef SNIPER_FOR_DEBIAN
int sys_rpm_packages(sys_info_t *data);
#else
int sys_deb_packages(sys_info_t *sys_data);
#endif
time_t get_os_install_time(void);
int set_os_install_time(time_t new_time);
time_t stat_dpkglist(char *name, char *vendorstr);
int get_machine_serial(char *sn, unsigned int sn_len);

void uidtoname(uid_t uid, char *name, const int name_len);

#endif

