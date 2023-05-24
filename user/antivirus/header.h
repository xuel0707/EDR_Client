#ifndef _HEADER_H
#define _HEADER_H

/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <malloc.h>
#include <pwd.h>
#include <stdbool.h>
#include <locale.h>

/*get_opt */
#include <getopt.h>

/* file operation */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

/* libcurl */
#include <curl/curl.h>
#include <pthread.h>

/*sqlite*/
#include <sqlite3.h>

/* zip */
#include <zlib.h>

/* http*/
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <openssl/crypto.h>

#include <sys/vfs.h>

#include "../../include/common.h"
#include "logger.h"
#include "msg_queue.h"
#include "cJSON.h"
#include "policy.h"

#define OS_WINDOWS 1
#define OS_LINUX   2

#define ASK_ME                          0
#define AUTO_PROCESS                    1

#define PKGM_RPM  1
#define PKGM_DPKG 2

#define OTHER_GET   0
#define SCAN_GET    1
#define INFO_GET    2
#define POLICY_GET  3
#define GETTYPE_MIN OTHER_GET
#define GETTYPE_MAX 4

#define INPUT_LEN       4

#define KB_SIZE         (1024)
#define MB_SIZE         (1024*1024)
#define GB_SIZE         (1024*1024*1024)

#define MIN_SERV_TIMEOFF 60 //一分钟内的时间偏差不调整

#define MIN_SEC         60
#define HOUR_SEC        (60*60)

#define OP_LEN_MAX      20
#define LOG_NAME_MAX    40
#define EVENT_NAME_MAX  40
#define TIME_LEN  40

#define MY_RESULT_ZERO    0
#define MY_RESULT_OK      1
#define MY_RESULT_FAIL    2
#define MY_RESULT_CANCEL  3

#define MY_LOG_NORMAL           0
#define MY_LOG_KEY              1
#define MY_LOG_LOW_RISK         2
#define MY_LOG_MIDDLE_RISK      3
#define MY_LOG_HIGH_RISK        4

#define MY_BEHAVIOR_NO          0 //无
#define MY_BEHAVIOR_ABNORMAL    1 //异常
#define MY_BEHAVIOR_VIOLATION   2 //违规

#define MY_HANDLE_NO                   0
#define MY_HANDLE_WARNING              1
#define MY_HANDLE_BLOCK_OK             2
#define MY_HANDLE_BLOCK_FAIL           3
#define MY_HANDLE_BLOCK_OK_LOCKIP_OK   4
#define MY_HANDLE_BLOCK_OK_LOCKIP_FAIL 5

/* 消息 */
#define REPLY_MAX       1024            /* 接收管控回复的消息最大长度 */
#define FILE_MAX        1024*1024*4
#define RULE_MAX        FILE_MAX        /* 暂定规则消息和策略文件大小相同*/
#define CONF_MAX        4096            /* 暂定配置消息为4096大小*/
#define URL_MAX         128             /* 管控接口api url最大长度 */
#define HMAC_MAX        17              /* 接收hmac最大长度，实际长度为固定的16 */
#define SEC_LEN_MAX     12              /* 时间的字符串最大长度，单位为秒，实际长度为固定的10 */

#define SKUFILE                         "/etc/sniper-sku"
#define SINGLE_LOG_URL                  "api/client/log"              //单条日志接口
#define SAMPLE_URL                      "api/client/sample/upload"
#define QUERY_URL                       "api/client/sample/query"
#define CURRENT_SERVER                  "/opt/snipercli/current_server"
#define CONF_JSON                       "/opt/snipercli/conf.json"

#define ANTIVIRUS_PROGRAM_TYPE          13298
#define ANTIVIRUS_ENGINE_DIRPATH        "/opt/snipercli/bin"
#define ANTIVIRUS_VDFS_DIRPATH          "/opt/snipercli/vdf"
#define ANTIVIRUS_AVLL_DIRPATH          ANTIVIRUS_ENGINE_DIRPATH
#define ANTIVIRUS_KEY_FILENAME          "/opt/snipercli/bin/hbedv.key"
#define ANTIVIRUS_PIDDIR                "/opt/snipercli/.pid"

#define ANTIVIRUS_LOGDIR                "/opt/snipercli/log/"
#define ANTIVIRUS_LOGFILE               "/opt/snipercli/log/antivirus_antiapt.log"
#define ANTIVIRUS_LOGFILE1              "/opt/snipercli/log/antivirus_antiapt.log.1"
#define POLICY_ZIP_FILE                 "/opt/snipercli/policy.zip.lst"
#define POLICY_FILE                     "/opt/snipercli/policy.lst"

#define DBGFLAG_ANTIVIRUS               "/tmp/antivirus.df"
#define DBGFLAG_ANTIVIRUS_POLCIY        "/tmp/antivirus_policy.df"
#define DBGFLAG_ANTIVIRUS_SYSINFO       "/tmp/antivirus_sysinfo.df"
#define DBGFLAG_ANTIVIRUS_SCAN          "/tmp/antivirus_scan.df"
#define DBGFLAG_ANTIVIRUS_OPERATE       "/tmp/antivirus_operate.df"
#define DBGFLAG_ANTIVIRUS_HTTP          "/tmp/antivirus_http.df"
#define DBGFLAG_ANTIVIRUS_QUEUE         "/tmp/antivirus_queue.df"

#define WORKDIR                         "/opt/snipercli"
#define VIRUSDB                         ".virusdb"

#define ANTIVIRUS_PIDFILE               ".sniper_antivirus.pid"
#define PIDFILE                         "/var/run/antiapt.pid"

#define QUARANTINE_DIR                  "/opt/snipercli/.quarantine"
#define INOTIFY_QUARANTINE_DIR          "/opt/snipercli/.quarantine_inotify/"

#define SQLITE_OPEN_MODE SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_SHAREDCACHE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE

#define LOGNAME_MAX                     80
#define MAX_WHILE                       10000 //循环的最大次数

extern sqlite3* virus_db;
extern char crt_virus_tbl_sql[1024];
extern int force_flag;
extern int force_number;
extern int log_flag;
extern FILE *logfp;
extern char logname[LOGNAME_MAX];
extern uid_t exec_uid;
extern struct passwd *my_info;

enum PATH_TYPE_VALUES {
	PATH_TYPE_OTHER = 0, /* other types (i.e devices, pipes, sockets, etc.) */
	PATH_TYPE_DIR   = 1, /* path is a directory */
	PATH_TYPE_FILE  = 2, /* path is a regular file */
};

typedef struct _file_stat {
	mode_t mode;
	uid_t uid;
	gid_t gid;
	int  mtime;
	char md5[S_MD5LEN];
	char path[PATH_MAX];
}file_stat_t;

struct defence_msg {
	char *user;     //不可NULL
	char *operation;//"Teminate" or "Lockip"
	char *virus_name; //病毒防护时不可为NULL
	char *virus_type; //病毒防护时不可为NULL
	int result;
	struct timeval event_tv; //可以0

	/* event_data */
	char *log_name; //触发防御的事件名称
	char *log_id;   //触发防御的事件id
	char *object;   //防御操作的对象，例如 阻断的进程名称 或者 锁定的ip
};

extern long serv_timeoff;
extern char *nullstr;

/* main.c */
extern void show_usage(void);

/* common.c */
#ifndef sniper_free
#define sniper_free(BUF, SIZE, GETTYPE)  do_sniper_free(BUF, SIZE, GETTYPE);BUF = NULL
#endif
extern int round_size(int size);
extern void *sniper_malloc(int size, int gettype);
extern void do_sniper_free(void *buf, int size, int gettype);
extern int sniper_open(char *path, int flags, int gettype);
extern int sniper_close(int fd, int gettype);
extern FILE *sniper_fopen(char *path, char *mode, int gettype);
extern int sniper_fclose(FILE *fp, int gettype);
extern void dump_sniperfd(void);
extern DIR *sniper_opendir(char *path, int gettype);
extern int sniper_closedir(DIR *dirp, int gettype);
extern char *thestring(char *str);
extern int is_this_running(uid_t uid);
extern void get_random_uuid(char *uuid, int uuid_len);
extern char *safebasename(char *path);
extern void safedirname(char *path, char *dirname, int dirlen);
extern void delete_tailspace(char *str);
extern char *skip_headspace(char *str);
extern void get_time_string(int mtime, char *timestr, int timestr_len);
extern void get_log_name(char *name, int name_len);
extern void get_input_result(char *output, char *input, int len);
extern int sniper_adjust_time(void);
extern unsigned long get_dir_size(char *dir);
extern unsigned long get_path_disk_size(char *path);

/* hash_file.c */
extern int md5_string(char *string, char *file_md5);
extern int md5_file(char *pathname, char *file_md5);
extern int md5_filter_large_file(char *pathname, char *file_md5);
extern int sha256_file(char *pathname, char *file_sha256);

/* policy.c */
extern int client_mode_global;
extern int load_local_policy(void);
extern void load_local_conf(void);
extern void dump_policy_antivirus(void);

/* http.c */
extern int http_post(char *api_str, char *post_data, char *reply_data);
extern int http_upload_sample(char *file, time_t event_time, char *log_name, char *log_id, char *user, char *md5_input);

/* sqlite3 */
extern int db_busy_callback(void *data, int count);

/* scan.c */
extern int scan_mode(int argc, char **argv);
extern int copy_file(char *old_file, char *new_file);
extern int query_db_path_record(char *path);

/* trust.c */
extern sqlite3* trust_db;
extern int add_trust_path(int argc, char **argv);
extern int delete_trust_path(int argc, char **argv);
extern int query_trust_path(int argc);
extern int clean_trust_path(int argc);
extern int trust_path_operate(int argc, char **argv);

/* operate.c */
extern int quarantine_files_operate(int argc, char **argv);
extern void get_original_path(char *path, char *ori_path);
extern void get_show_path(char *path, char *show_path);

/* virus_msg_queue.c */
extern int virus_msg_count;

/* handle_msg_queue.c */
extern int handle_msg_count;

/* sysinfo.c*/
extern char os_dist[S_NAMELEN];
extern char hostname[S_NAMELEN];
extern char host_sku[S_UUIDLEN+1];
extern char host_mac[S_IPLEN];
extern char host_ip[S_IPLEN];
struct sniper_ethinfo {
	char name[IFNAMSIZ];
	struct sniper_ip ip;
	struct sniper_ip netmask;
	unsigned char mac[6];
};

typedef struct {
	unsigned int port;
	char ip[S_IPLEN];
	char webproto[S_PROTOLEN];
} serverconf_t;
extern serverconf_t Serv_conf;

extern int get_os_release(char *dist, int dist_len);
extern int get_sku(char sku[S_UUIDLEN+1]);
extern int get_current_ethinfo(void);
extern int get_serverconf(void);

/* sqlutil.c */
extern sqlite3* connectDb(char *dbname, const char *crt_tbl_sql, char *pwd, int *first_time);
#endif /* _HEADER_H */
