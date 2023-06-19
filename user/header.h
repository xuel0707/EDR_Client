/*
 * 应用程序公共头文件
 * Author: zhengxiang
 */

#ifndef _HEADER_H
#define _HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <dirent.h>
#include <zlib.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/sysinfo.h>
#include <sys/prctl.h>        //prctl

/* for WEXITSTATUS */
#include <sys/wait.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

/* netlink */
#include <sys/socket.h>
#include <linux/netlink.h>

/* libbpf */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sqlite3.h>

#include <curl/curl.h>

#include "../include/common.h"

#include "cJSON.h"
#include "lst.h"
#include "policy.h"
#include "rule.h"
#include "logger.h"
#include "process.h"
#include "list.h"
#include "msg_queue.h"
#include "types.h"
#include "file.h"
#include "websocket.h"

#include "system_type.h"
#include "avira.h"

#define SNIPER_SQLITE3 1

/* url */
#define LOG_URL                 "api/client/log/upload"       //批量日志接口
#define SINGLE_LOG_URL          "api/client/log"              //单条日志接口
#define TASK_ACK_URL            "api/client/task-ack"         //任务消息回应接口，只能单条发送
#define NOTIFY_URL              "api/client/notify"
#define SYNC_INFO_URL           "api/client/info"

#define ASSET_URL               "api/client/asset/upload/"
#define DEBUG_LOG_URL           "api/client/debug/log/upload"
#define SAMPLE_URL              "api/client/sample/upload"
#define QUERY_URL               "api/client/sample/query"
#define CONF_URL                "api/client/conf"
#define RULE_URL                "api/client/rule"
#define DOWNLOAD_URL            "api/client/download"
#define DOWNLOAD_CONF_URL        "api/client/download/conf"
#define DOWNLOAD_RULE_URL       "api/client/download/rule"
#define DOWNLOAD_VIRUS_URL      "api/client/download/virus"
#define DOWNLOAD_ANTIVIRUS_URL  "api/client/download/virus/linux"
#define DOWNLOAD_PLUGIN_URL     "api/client/download/plugin"
#define DOWNLOAD_CRACK_CONF		"api/client/download/conf/linux-crack20220516.dat"
#define UPDATE_URL              "api/client/version"

#define DBGFLAG_CRON            "/tmp/cron.df"
#define DBGFLAG_POST            "/tmp/post.df"
#define DBGFLAG_POST_LEVEL2     "/tmp/post_level2.df"
#define DBGFLAG_USER            "/tmp/user.df"
#define DBGFLAG_GROUP           "/tmp/group.df"
#define DBGFLAG_VMRSS           "/tmp/vmrss.df"
#define DBGFLAG_INOTIFY         "/tmp/inotify.df"
#define DBGFLAG_UEVENT          "/tmp/uevent.df"
#define DBGFLAG_STARTER         "/tmp/starter.df"
#define DBGFLAG_WEBSOCKET       "/tmp/websocket.df"
#define DBGFLAG_WEBSOCKET2      "/tmp/websocket2.df"
#define DBGFLAG_TASK            "/tmp/task.df"
#define DBGFLAG_FILE            "/tmp/file.df"
#define DBGFLAG_FILEDEBUG       "/tmp/filedebug.df"
#define DBGFLAG_VIRUS           "/tmp/virus.df"
#define DBGFLAG_FILTERDEBUG     "/tmp/filterdebug.df"
#define DBGFLAG_VIRUSDEBUG      "/tmp/virusdebug.df"
#define DBGFLAG_WEBSHELL	"/tmp/webshell.df"
#define DBGFLAG_COMMON          "/tmp/common.df"
#define DBGFLAG_HEARTBEAT       "/tmp/heartbeat.df"
#define DBGFLAG_SSH             "/tmp/login.df"
#define DBGFLAG_CONN            "/tmp/conn.df"
#define DBGFLAG_SELFCHECK       "/tmp/selfcheck.df"
#define DBGFLAG_PROCESSRES      "/tmp/processres.df"
#define DBGFLAG_NET             "/tmp/net.df"
#define DBGFLAG_POLICY          "/tmp/policy.df"
#define DBGFLAG_PROCESS         "/tmp/process.df"
#define DBGFLAG_RESCHECK        "/tmp/rescheck.df"
#define DBGFLAG_SYSDANGER       "/tmp/sysdanger.df"
#define DBGFLAG_BASELINE        "/tmp/baseline.df"
#define DBGFLAG_CPUBUSY         "/tmp/cpubusy.df"
#define DBGFLAG_PRIVUP          "/tmp/privup.df"
#define DBGFLAG_USB             "/tmp/usb.df"
#define DBGFLAG_USBDEBUG        "/tmp/usbdebug.df"  //打印usb检测过程的详细信息
#define DBGFLAG_BASELINE        "/tmp/baseline.df"
#define DBGFLAG_ENCRYPT         "/tmp/encrypt.df"
#define DBGFLAG_PRINT           "/tmp/print.df"
#define DBGFLAG_CDROM           "/tmp/cdrom.df"
#define DBGFLAG_LOGSEND         "/tmp/logsend.df"   //打印出错信息
#define DBGFLAG_LOGSENDOk       "/tmp/logsendok.df" //打印日志发送成功信息
#define DBGFLAG_ASSIST          "/tmp/assist.df"
#define DBGFLAG_PROCESSDEBUG    "/tmp/processdebug.df"
#define DBGFLAG_NOMODULE        "/tmp/nomodule.df"  //控制加载内核模块
#define DBGFLAG_TTT             "/tmp/ttt.df"  //控制加载内核模块

/* sniper->f94b0d: 's'-'e'=f, ..., 'r'-'e'=d */
#define SNIPER_MAGIC 0xf94b0d51 //sniper51

/* 顺序要和main.c里sniper_thread[]的内容一致 */
#define SNIPER_THREAD_HEARTBEAT        0  //心跳
#define SNIPER_THREAD_KEXECMSG         1  //收取内核进程消息
#define SNIPER_THREAD_KFILEMSG         2  //收取内核文件消息
#define SNIPER_THREAD_KNETMSG          3  //收取内核网络消息
#define SNIPER_THREAD_WEBSOCKET        4  //接收管控下发的任务
#define SNIPER_THREAD_LOGSEND          5  //发送客户端日志
#define SNIPER_THREAD_RESCHECK         6  //客户端程序自身负载监控
#define SNIPER_THREAD_PROCESS          7  //处理进程消息
#define SNIPER_THREAD_FILEMON          8  //处理文件消息
#define SNIPER_THREAD_NETWORK          9  //处理网络消息
#define SNIPER_THREAD_LOGIN            10 //处理登录事件
#define SNIPER_THREAD_CRACK            11 //处理爆破事件
#define SNIPER_THREAD_TASK             12 //处理管控下发的任务
#define SNIPER_THREAD_CDROM            13 //刻录监控
#define SNIPER_THREAD_INOTIFY          14 //处理inotify事件，目前仅监控打印日志
#define SNIPER_THREAD_UEVENT           15 //处理设备事件，目前仅监控u盘拔插
#define SNIPER_THREAD_SELFCHECK        16 //系统整体的负载监控，和各进程的负载是否超限

#ifdef USE_AVIRA //小红伞杀毒可用
#define SNIPER_THREAD_KFILTERMSG       17 //收取内核病毒消息
#define SNIPER_THREAD_FILTER           18 //过滤传给杀毒线程的一部分消息
#define SNIPER_THREAD_ANTIVIRUS        19 //处理病毒消息
#define SNIPER_THREAD_NUMS             20
#define SNIPER_THREAD_MAX              21 //SNIPER_THREAD_NUMS+1
#else            //小红伞杀毒不支持
#define SNIPER_THREAD_NUMS             18
#define SNIPER_THREAD_MAX              19 //SNIPER_THREAD_NUMS+1
#endif

#define MAX_WHILE                      10000 //循环的最大次数

struct sniper_thread_struct {
	pid_t pid;                 //线程的pid
	pthread_t *thread;         //线程数据结构
	void *(*func)(void *);     //线程功能函数
	char desc[16];             //对线程的描述
};
extern struct sniper_thread_struct sniper_thread[SNIPER_THREAD_MAX];

typedef struct app_info {
	pid_t *pid;
	char *name_app;
	char *sub_name;
} app_module;

/* 客户端程序运行状态 */
#define SNIPER_RUNNING 1  //客户端运行成功
#define SNIPER_FAILURE 2  //客户端运行失败
#define SNIPER_ANOTHER 3  //其他客户端在运行

/* socket状态 */
#define SOCKSTATS 12
extern char socket_state[SOCKSTATS][16];

extern char *logsender; //"1"表示sniper主程序，"2"表示辅助小程序

/*
 * volatile的作用是防止优化编译器把变量从内存装入CPU寄存器中。
 * 如果变量被装入寄存器，那么两个线程有可能一个使用内存中的变量，一个使用寄存器中的变量。
 * volatile让编译器每次操作该变量时一定要从内存中真正取出，而不是使用已经存在寄存器中的值。
 *
 * 但具体到本程序，Online/Expired并不需要volatile，
 * 即使出现线程取的值不一致，问题也不大，顶多是按原来的模式多处理了一次。
 */
extern unsigned char Online;
extern unsigned char Expired;
extern unsigned char Protect_switch;
extern unsigned char tool_mode;
extern unsigned char Debug;
extern unsigned char tasklist_ready;
extern unsigned char process_inited;

extern unsigned char localmode;
extern unsigned char client_registered;
extern char curr_servip[S_IPLEN];
extern unsigned short curr_servport;
extern char orig_servip[S_IPLEN];
extern unsigned short orig_servport;

extern struct kern_process_rules prule;

extern unsigned char Heartbeat_fail;
extern time_t uptime_sec;

extern int is_update_task;
extern int is_update_conf;

extern char *nullstr;

extern pid_t sniper_pid;
extern int selfexit;

/*assist.c*/
extern char sku_info[S_UUIDLEN+1];

extern msg_queue_t *task_msg_queue;

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC	1000000000L
#endif

#define KB_SIZE		(1024)
#define MB_SIZE		(1024*1024)
#define GB_SIZE		(1024*1024*1024)

extern long serv_timeoff;
#define MIN_SERV_TIMEOFF 60 //一分钟内的时间偏差不调整

extern time_t login_strategy_time;

#define LOCAL_TYPE	1
#define TELNET_TYPE	2

#define QUIET_MODE	1
#define VERBOSE_MODE	2

/* windows端是l，统一到l。兼容1 */
#define TOKEN   "ZH94f2J1cH19Tnx0"
#define TOKENL  "ZH94f2JlcH19Tnx0"

#define UNINSTALL_KEY  "Akj6578w*aPLas3w"

#define SNIPER_CONF	"/etc/sniper.conf"
#define CURRENT_SERVER	"/opt/snipercli/current_server"
#define SNIPER_PROG     "/sbin/sniper"
#define ANTIVIRUS_PROG  "/bin/sniper_antivirus"
#define SNIPER_NAME     "sniper"

#define MODULE_NAME             "sniper_edr"
#define MODULE_FILE_NAME        "sniper_edr.ko"

#define EBPF_EXECVE_HOOK_PROGRAM	"lsm_kern.o"
#define EBPF_FILE_HOOK_PROGRAM  "ebpf_file_kern.o"

#define LOGFILE                 "/var/log/antiapt.log"
#define LOGFILE1                "/var/log/antiapt.log.1"
#define PIDFILE                 "/var/run/antiapt.pid"
#define VERSION_FILE            "/var/run/antiapt.version"
#define VIRUSLIB_VERSION_FILE   "/opt/snipercli/viruslib.version"
#define ANTIVIRUS_VERSION_FILE  "/opt/snipercli/antivirus.version"
#define IPWRY_VERSION_FILE      "/opt/snipercli/ipwry.version"
#define BASELINE_VERSION_FILE   "/opt/snipercli/baseline.version"
#define WEAKPASSWD_VERSION_FILE "/opt/snipercli/weakpasswd.version"
#define WEBSHELL_VERSION_FILE   "/opt/snipercli/webshell.version"
#define CRACK_VERSION_FILE      "/opt/snipercli/crack.version"
#define CLIENT_DISABLE          "/opt/snipercli/sniper_client_disable"
#define STATUSFILE              "/var/run/antiapt.status"
#define SYSINFO_PIDFILE         "/var/run/systeminformation.pid"

#define ASSISTLOGFILE           "/var/log/assist.log"
#define ASSIST_PIDFILE		"/var/run/assist.pid"

#define STRATEGY_FILE           "/opt/snipercli/lst.conf"
#define OPERATION_FILE          "/opt/snipercli/operation.conf"
#define LEARNING_FILE           "/opt/snipercli/learning.conf"
#define SNIPER_EVENT_LOG	"/opt/snipercli/event.log"
#define SNIPER_BACKUP_LOG	"/opt/snipercli/backup.log"
#define LST_NAME_FILE		"/opt/snipercli/lst.conf.name"
#define LST_MODE_FILE		"/opt/snipercli/lst.conf.mode"
#define LST_CONF_PROCESS	"/opt/snipercli/lst.conf.process"
#define LST_CONF_FILE		"/opt/snipercli/lst.conf.file"
#define LST_CONF_NETWORK	"/opt/snipercli/lst.conf.network"
#define LST_CONF_SYSTEM		"/opt/snipercli/lst.conf.system"
#define LST_CONF_DEVICE		"/opt/snipercli/lst.conf.device"
#define LST_CONF_RULE		"/opt/snipercli/lst.conf.rule"
#define LST_CONF_OTHER		"/opt/snipercli/lst.conf.other"
#define LOCALLOG_DIR            "/opt/snipercli/offlinelog"
#define LOG_SEND_DIR            "/opt/snipercli/offlinelog/send"
#define LOCALLOG                "/opt/snipercli/offlinelog/antiapt.log"
#define SAMPLE_DIR		"/opt/snipercli/sample/"
#define DOWNLOAD_DIR		"/opt/snipercli/.download/"
#define EDR_FILE_BAK            "/opt/snipercli/.download/edr.zip.bak"
#define EDR_FILE                "/opt/snipercli/.download/edr.zip"
#define IPWRY_FILE_BAK          "/opt/snipercli/.download/ipwry.dat.bak"
#define IPWRY_FILE              "/opt/snipercli/.download/ipwry.dat"
#define BASELINE_FILE_BAK       "/opt/snipercli/.download/baseline.dat.bak"
#define BASELINE_FILE           "/opt/snipercli/.download/baseline.dat"
#define CRACK_FILE_BAK          "/opt/snipercli/.download/linux-crack.dat.bak"
#define CRACK_FILE              "/opt/snipercli/.download/linux-crack.dat"
#define WEBSHELL_FILE_BAK       "/opt/snipercli/.download/webshell.dat.bak"
#define WEBSHELL_FILE           "/opt/snipercli/.download/webshell.dat"
#define WEAK_PASSWD_FILE_BAK    "/opt/snipercli/.download/weakpwd.dat.bak"
#define WEAK_PASSWD_FILE        "/opt/snipercli/.download/weakpwd.dat"
#define VIRUS_LIB_FILE          "/opt/snipercli/.download/anti-lib.zip"
#define ANTIVIRUS_FILE          "/opt/snipercli/.download/antivirus.zip"
#define CONF_INFO_FILE          "/opt/snipercli/conf.info"
#define CONF_INFO_FILE_EN       "/opt/snipercli/conf.info_en"
#define RULE_INFO_FILE          "/opt/snipercli/rule.info"
#define RULE_INFO_FILE_EN       "/opt/snipercli/rule.info_en"
#define POLICY_FILE		"/opt/snipercli/policy.lst"
#define POLICY_ZIP_FILE		"/opt/snipercli/policy.zip.lst"
#define POLICY_ZIP_FILEBAK	"/opt/snipercli/policy.zip.bak"
#define POLICY_PROTECT_FILE	"/opt/snipercli/protect.lst.file"
#define POLICY_PROTECT_FILE_EN	"/opt/snipercli/protect.lst.file_en"
#define POLICY_FASTEN_FILE	"/opt/snipercli/fasten.lst.file"
#define POLICY_FASTEN_FILE_EN	"/opt/snipercli/fasten.lst.file_en"
#define POLICY_ANTIVIRUS_FILE		"/opt/snipercli/antivirus.lst.file"
#define POLICY_ANTIVIRUS_FILE_EN	"/opt/snipercli/antivirus.lst.file_en"
#define POLICY_OTHER_FILE	"/opt/snipercli/other.lst.file"
#define POLICY_OTHER_FILE_EN	"/opt/snipercli/other.lst.file_en"
#define POLICY_SELFINFO_FILE	"/opt/snipercli/selfinfo.lst.file"
#define POLICY_SELFINFO_FILE_EN	"/opt/snipercli/selfinfo.lst.file_en"
#define POLICY_SENSITIVE_TXT	"/opt/snipercli/sensitive.txt"
#define POLICY_LOGDELETE_TXT	"/opt/snipercli/log_delete.txt"
#define POLICY_SAFE_TXT         "/opt/snipercli/safe.txt"
#define POLICY_LOGCOLLECTOR_TXT "/opt/snipercli/logcollector.txt"
#define POLICY_ILLEGAL_SCRIPT_TXT       "/opt/snipercli/illegal_script.txt"
#define POLICY_WEBSHELL_DETECT_TXT      "/opt/snipercli/webshell_detect.txt"
#define POLICY_FILEBLACK_TXT    "/opt/snipercli/fileblack.txt"
#define POLICY_FILEFILTER_TXT   "/opt/snipercli/filefilter.txt"
#define POLICY_FILEUSB_TXT      "/opt/snipercli/fileusb.txt"
#define POLICY_ENCRYPT_TXT	"/opt/snipercli/encrypt.txt"
#define POLICY_JSON		"/opt/snipercli/policy.json"
#define RULE_JSON		"/opt/snipercli/rule.json"
#define CONF_JSON		"/opt/snipercli/conf.json"
#define RANDOM_NUMBER_FILE	"/opt/snipercli/random_number"
#define CUPSD_FLAGFILE		"/opt/snipercli/cupsd_disabled"
#define LANGFILE		"/opt/snipercli/.language"
#define SNIPER_TMPDIR		"/opt/snipercli/.tmp"
#define QUARANTINE_DIR          "/opt/snipercli/.quarantine"
#define ROOT_QUARANTINE_DIR	"/opt/snipercli/.quarantine/root"
#define INOTIFY_QUARANTINE_DIR	"/opt/snipercli/.quarantine_inotify/"
#define ANTIVIRUS_PIDDIR                "/opt/snipercli/.pid"
#define ANTIVIRUS_LOGDIR                "/opt/snipercli/log/"

#define SKUFILE        "/etc/sniper-sku"
#define TOKENFILE      "/etc/sniper-installtoken"
#define WORKDIR        "/opt/snipercli"
#define DBSTAMP        ".stamp"
#define DBSTAMPFV1     ".stampfv1"
#define DBSTAMPFV2     ".stampfv2"
#define DBDIR          ".mondb"
#define FILEDB         ".filedb"
#define VIRUSDB        ".virusdb"
#define SSHDIR         ".sshpeer"
#define CMDDIR         ".cmd"
#define FILE_DIR       ".file"
#define DENYIPDIR      ".denyip"
#define CONFIGDIR      ".config"
#define BACKUP         ".backup"
#define FILEBACKUP     ".filebackup"
#define LOGINED        ".logined"
#define NODEINFO       ".nodeinfo"
#define LANGINFO       ".language"
#define QUARANTINE     ".quarantine"

extern time_t mondb_create_time;

extern char sniper_net_loadoff;
extern char sniper_file_loadoff;
extern char sniper_process_loadoff;
extern char sniper_other_loadoff;

#define THREEMIN  180           /* 60*3  */
#define TENMIN	  600           /* 60*10 */
#define ONEHOUR   3600          /* 60*60 */
#define ONEDAY    86400         /* 3600*24 */
#define ONEWEEK   604800        /* 3600*24*7 */
#define ONEMONTH  2592000       /* 3600*24*30 */
#define ONEYEAR   31536000      /* 3600*24*365 */

#define STOP_WAIT_TIME   60 // 60 seconds

/* 消息 */
#define REPLY_MAX       1024            /* 接收管控回复的消息最大长度 */
#define FILE_MAX        1024*1024*4
#define RULE_MAX        FILE_MAX	/* 暂定规则消息和策略文件大小相同*/
#define CONF_MAX        4096            /* 暂定配置消息为4096大小*/
#define URL_MAX         128             /* 管控接口api url最大长度 */
#define HMAC_MAX        17              /* 接收hmac最大长度，实际长度为固定的16 */
#define SEC_LEN_MAX     12              /* 时间的字符串最大长度，单位为秒，实际长度为固定的10 */

//TODO 动态分配
#define HOSTIP_MAX 64
extern char hostip[HOSTIP_MAX][S_IPLEN];

/* 弱密码长度，与服务端弱密码字段100个字符的长度保持一致 */
#define WEAK_LEN 100
#define EmptyPwd         1 //空口令
#define PwdSameAsAccount 2 //密码与用户名相同
#define PwdInWeakLib     3 //命中弱密码库

/* gettaskstat act */
/* 如果这里改变了，get_process_status.c里的gettype[]也要相应变 */
#define OTHER_GET   0
#define PROCESS_GET 1
#define FILE_GET    2
#define NETWORK_GET 3
#define LOGIN_GET   4
#define INFO_GET    5
#define POLICY_GET  6
#define GETTYPE_MIN OTHER_GET
#define GETTYPE_MAX 7

#define PKGM_RPM  1
#define PKGM_DPKG 2

#define TOKEN_LEN	32
typedef struct {
	char version[16];         //5.1.02.1024
	char hostname[S_NAMELEN];
	char cpu_model[S_NAMELEN];
	char machine_model[S_NAMELEN];
	char dmi_sn[S_NAMELEN];
	char vmtype[16];

	char os_dist[S_NAMELEN];    //os release
	char os_arch[16];           //x86_64
	char os_kernel[S_NAMELEN];  //os kernel
	char os_sn[S_NAMELEN];      //os serial number

	char memtotal[16];

	time_t os_install_time;
	time_t boot_time;
	time_t last_shutdown_time;

	short cpu_count;
	short core_count;

	char pkgmanage;

	char rootfs_uuid[S_SNLEN+1];
	char disk_sn[S_SNLEN+1];
	char dmi_uuid[S_SNLEN+1];
	char sku[S_UUIDLEN+1];
	char token[TOKEN_LEN + 1];
} sysinfo_t;
extern sysinfo_t Sys_info;

typedef struct {
	unsigned int port;
	char ip[S_IPLEN];
	char webproto[S_PROTOLEN];
} serverconf_t;
extern serverconf_t Serv_conf;

typedef struct {
	char ip[S_IPLEN];
	char ipv6[S_IPLEN];
	char netmask[S_IPLEN];
	char mac[S_IPLEN];	/* 00-00-00-00-00-00 */
	char ifname[IFNAMSIZ];	/* if name, e.g. "eth0" */
} ifinfo_t;
extern ifinfo_t If_info;

#define MAX_IF_NUM  8
struct net_interface {
	char name[IF_NAMESIZE];
	char ip[S_IPLEN];
};

extern pthread_rwlock_t ethinfo_lock;
struct sniper_ethinfo {
	char name[IFNAMSIZ];
	struct sniper_ip ip;
	struct sniper_ip netmask;
	unsigned char mac[6];
};
extern struct sniper_ethinfo *ethinfo;
extern int ethinfo_num;

struct socket_info {
	int  src_port;
	int  dst_port;
	char src_ip[S_IPLEN];
	char dst_ip[S_IPLEN];
	uid_t  uid;
	unsigned long inode;
	int  state;
	int  direction;
};
typedef struct socket_info sockinfo_t;

struct defence_msg {
	char *user;	//不可NULL
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


#define OS_WINDOWS 1
#define OS_LINUX   2

extern char *succstr;
extern char *failstr;
extern char *termstr;
extern char *lockstr;
extern char *qurstr;
extern char *startstr;
extern char *stopstr;

#define MODE_OPEN	1

extern unsigned char current_operation_mode;
extern unsigned char current_learning_mode;
extern int first_group_check;
extern int first_user_check;

/* process_strategy.c */
extern pthread_rwlock_t middleware_lock;
extern struct sniper_middleware sniper_mid[SNIPER_MIDDLEWARE_NUM];

extern char *copy_stringvalue(char *buf, char *str);
extern void update_kernel_process_rules(void);
extern void close_kernel_process_rules(void);
extern int is_black_cmd(taskstat_t *taskstat);
extern int is_white_cmd(taskstat_t *taskstat);
extern int is_trust_cmd(taskstat_t *taskstat);
extern int is_filter_cmd(taskstat_t *taskstat);
extern int is_valid_str(char *str);
extern void update_kernel_pmiddleware(void);
extern void init_kernel_pmiddleware(void);

/* net_strategy.c */
extern int net_connect_status(void);
extern void close_kernel_net_rules(void);
extern void update_kernel_net_policy(void);
extern void update_asset_conf(void);
extern void update_kernel_net_server(unsigned char *server_count);
extern void update_kernel_net_host_quarantine(const int host_quarantine);
extern int check_ip_is_match(char *match_ip, char *rule_ip);

/* usb.c */
extern void check_usb_info(int init);

/* sysinfo.c */
extern void get_sku(char *sku);
extern void init_systeminfo(sysinfo_t *s_info);
extern struct sniper_ethinfo *get_current_ethinfo(int *num);

/* serverconf.c */
extern void init_serverconf(void);
extern void init_assist_serverconf(void);
extern int save_servaddr(unsigned short port, char *server, char *file);
extern void read_servaddr(unsigned short *port, char *server, char *file);
extern int hostname_to_ip(char* hostname, char *ip);

/* ifinfo.c */
extern int init_ifinfo(ifinfo_t *info, serverconf_t *conf);

/* strcodec.c */
extern char *base64(const void *binaryData, int len, int *flen);
extern char *url_encode(char *str);
extern char *url_decode(char *str);

/* download.c */
typedef struct {
	char	*data;
	size_t	len;
	int	pos;
} buffer_t;
extern int download(buffer_t *buffer);
extern int get_large_data_resp(char *api_str, char *post, buffer_t *buffer);

/* httppost.c */
extern int http_post(char *api_str, char *post_data, char *reply, int reply_len);
extern int http_assist_post(char *api_str, char *post_data, char *reply, int reply_len);
extern int http_put(char *api_str, char *put_data, char *reply, int reply_len);
extern int http_get(char *api_str, char *get_data, char *reply, int reply_len);
extern int http_post_data(char *url, char *post_data, char *reply, int reply_len);
extern int http_upload_file(char *filename, char *api_str);
extern int http_upload_sample(char *file, time_t event_time, char *log_name, char *log_id, char *user, char *md5);
extern int upload_file(char *filepath, char* url);
extern int query_sample_exist(char *filepath, char *md5);
extern int check_http_port(int port);
extern void set_default_webproto(void);

/* hash_file.c */
extern int md5_string(char *string, char *file_md5);
extern int md5_file(char *pathname, char *file_md5);
extern int md5_filter_large_file(char *pathname, char *file_md5);
extern int sha256_file(char *pathname, char *file_sha256);

/* main.c */
extern char server_version[VER_LEN_MAX];
extern char ws_ip[S_IPLEN];
extern char ws_path[URL_MAX];
extern int  ws_port;
extern void sniper_cleanup(void);
extern int sniper_adjust_time(void);
extern void save_thread_pid(char *thread_name, unsigned int thread_seq);
extern void save_thread_time(unsigned int thread_seq);

/* kebpf.c */
enum {
    EBPF_EXECVE = 0,
	EBPF_FILE = 1,
    EBPF_PROGRAMS_NUM,
};
extern int load_ebpf_program(void);
extern int unload_ebpf_program(void);
extern struct bpf_object *get_bpf_object(int type);

/* kmod.c */
// extern int load_module(void);
// extern int del_module(char *module_name);
// extern int register_module(void);
// extern void unregister_module(void);

/* process.c */
extern void *process_monitor(void *ptr);
extern void report_taskexit(taskstat_t *taskstat);
extern int is_webshell(taskstat_t *taskstat);
extern int is_webexecute(taskstat_t *taskstat, taskstat_t *ptaskstat);
extern void check_tasklist_event(void);

/* update.c */
extern void update_client(task_recv_t *msg);
extern void send_client_change_resp(char *old_version, char *new_version, int result, char *operating);
extern int download_file(char *url, FILE *fp);
extern void check_update_result(int value);

/* selfcheck.c */
extern int client_disable;
extern void *self_check(void *ptr);
extern unsigned long get_self_mem(void);
extern void debug_vmrss(char *str);
extern int getNetRates(long *download_rates, long *send_rates);
extern int upload_sysinfo(int sync);

/* file.c */
extern char *get_path_types(char *path);
extern int check_dir_maxsize(char *path, unsigned long maxsize);
extern int file_monitor_check_file(char *username, char *cmdname, char *filename, off_t size);
extern void get_file_event_operating(int type, char *operating);
extern int check_filter_after(char *pathname, char *md5, char *process_path);
extern int upload_file_sample(struct file_msg_args *msg, char *log_name, char *log_id, int type, char*md5);
extern int check_process_filter_pro(char *process, char*md5);
extern void *file_monitor(void *ptr);

/* virusfilter.c */
extern void *virusfilter_monitor(void *ptr);

/* antivirus.c */
#define UPDATE_VIRUS_LIB	1
#define UPDATE_VIRUS_PRO	2

extern pthread_mutex_t virus_datebase_update_lock;
extern void init_virus_db(void);
extern void fini_virus_db(void);
extern void *antivirus_monitor(void *ptr);
extern int check_policy_trust_path(char *path);
extern void update_virus_database_my(task_recv_t *msg);
extern int update_virus_lib(char *lib_version, char *lib_md5);
extern int get_antivirus_mem(void);
extern void finish_savapi(void);

/* log_send.c */
extern int client_send_msg(char *post, char *reply, int reply_len, char *url, char *logtype);
extern void check_log_to_send(char *logtype);
extern void send_defence_msg(struct defence_msg *msg, char *logtype);
extern void send_unlockip_msg(char *ip, int result);
extern void report_dependency_msg(char *string);
extern void cJSON_AddCommonHeader(cJSON *object);
extern void *log_send(void *ptr);

/* login.c */
extern void *login_monitor(void *ptr);
extern void init_ssh(void);
extern void fini_ssh(void);
extern void tty2ip(char *ptsnum, char *ip);
extern int is_halting(void);
extern void get_session_uuid(char *tty, char *session_uuid);
extern char login_users[S_LINELEN];
extern void get_login_users(void);
extern void show_wtmp(char *file);
extern void *crack_monitor(void *ptr);
extern void crack_db_release(void);

/* net.c */
extern void *net_monitor(void *ptr);
extern int sniper_ipcmp(struct sniper_ip *firstip, struct sniper_ip *secondip);
extern void check_lockedip(int dolock);
extern char *search_domain_cache_ip(char *domain);
extern int lock_ip(char *ip, int reason, int lock_time, char *log_name, char *log_id);
extern int unlock_ip(char *ip);

/* burn_mgr.c */
extern void *burn_mgr(void *ptr);
extern void cdrom_terminate_post_data(struct file_msg_args *msg);

/* printer.c */
extern unsigned long printer_filesize;
extern unsigned long printer_fileinode;
extern struct _print_job print_job_old[JOB_MAX];
extern int job_count_old;
extern int get_job_list(struct _print_job *print_job, int *job_count);
extern void printer_terminate_post_data(taskstat_t *taskstat);
extern void check_printer_files(void);

/* inotify.c */
extern void *inotify_monitor(void *ptr);

/* websocket.c */
extern void *websocket_monitor(void *ptr);

/* task.c */
extern void *task_monitor(void *ptr);
extern void send_update_client_task_resp(task_recv_t *recv_msg, int result, char *old_version, char *new_version);
extern void send_task_resp(task_recv_t *recv_msg, int result, char *reason);
extern void uninstall_sniper(task_recv_t *recv_msg);
extern int copy_file(char *old_file, char *new_file);
extern void file_quarantine(task_recv_t *recv_msg);
extern void send_sync_info(int type, char *string);
extern void send_update_virus_database_task_resp(task_recv_t *recv_msg, int result, char *old_version, char *new_version);
extern void download_crack_conf(task_recv_t *msg);
//extern void update_inotify(task_recv_t *msg);

/* conf.c */
extern void free_valuestring(char *str);
extern void update_conf_my(task_recv_t *msg);
extern void get_client_mode_global(void);
extern int download_rule_file(char *url, char *name, char *path);
extern void extract_virus_version(char *zipname, char *version);

/* rule.c */
extern void update_rule_my(task_recv_t *msg);

/* uevent.c */
extern void *uevent_monitor(void *ptr);

/* get_process_status.c */
extern int init_psbuf(void);
extern void fini_psbuf(int lockflag);
extern pid_t get_proc_ppid(pid_t pid);
extern uid_t get_proc_euid(pid_t pid);
extern int get_proc_comm(pid_t pid, char *comm);
extern int get_proc_exe(pid_t pid, char *cmd);
extern int get_proc_stat(taskstat_t *taskstat);
extern int get_proc_status(taskstat_t *taskstat);
extern int get_proc_cmdline(pid_t pid, char *buf, int buflen);
extern int is_kernel_thread(pid_t pid);
extern taskstat_t *the_ptaskstat(taskstat_t *taskstat);
extern int is_danger(taskstat_t *taskstat);
extern int is_danger_cmd(char *cmd);
extern int is_chopper_cmd(char *cmd);

#if 0
extern taskstat_t *get_ptaskstat_from_pinfo(struct parent_info *pinfo);
extern taskstat_t *get_ptaskstat_from_pinfo_rdlock(struct parent_info *pinfo);
#else
extern taskstat_t *get_ptaskstat_from_pinfo(struct ebpf_parent_info *pinfo);
extern taskstat_t *get_ptaskstat_from_pinfo_rdlock(struct ebpf_parent_info *pinfo);
#endif

extern taskstat_t *alloc_taskstat(void);
extern void add_tasklist_tail(taskstat_t *taskstat);
extern taskstat_t *get_taskstat_nolock(pid_t pid, int type);
extern taskstat_t *get_taskstat_rdlock(pid_t pid, int type);
extern taskstat_t *get_taskstat_wrlock(pid_t pid, int type, unsigned long t);
extern void put_taskstat_unlock(taskstat_t *taskstat);
extern void save_exec_ptaskstat(taskstat_t *taskstat);
extern void check_exit_process(void);
extern int get_taskstat_num(void);
extern int get_exehash_num(void);
extern void count_file_hash(taskstat_t *taskstat);
extern exehash_t *get_exehash_by_inode(unsigned long ino);
extern void get_mem_usage(taskstat_t *taskstat);
extern taskstat_t *init_one_process(pid_t pid);
extern int is_remoteshell(taskstat_t *taskstat);
extern void set_taskstat_flags(taskstat_t *taskstat, taskstat_t *ptaskstat);

#if 0
extern pid_t get_orphan_process_ppid(taskreq_t *req);
#else
extern pid_t get_orphan_process_ppid(struct ebpf_taskreq_t *req);
#endif

extern void stop_systeminformation(void);

/* dmidecode.c */
extern void get_machine_model(char *model, char *vmtype, char *sn, char *uuid, int verbose);

/* common.c */
struct rulefile_info
{
	int size;
	char path[PATH_MAX];
};
extern int prepare_rulefile(char *rule, int size, char *desc, struct rulefile_info *rfinfo);

#ifndef sniper_free
#define sniper_free(BUF, SIZE, GETTYPE)  do_sniper_free(BUF, SIZE, GETTYPE);BUF = NULL
#endif

extern int netlinknum;
extern int get_netlink_num(void);
extern int lang;
extern int get_language(void);
extern char *skip_headspace(char *str);
extern void delete_tailspace(char *str);
extern char *thestring(char *str);
extern void get_random_uuid(char *uuid);
extern int is_this_running(char *name, char *pidfile, int *pid_fd, char *version_file);
extern void save_sniper_status(char *info);
extern pid_t mygetpgid(pid_t pid);
extern int mykill(pid_t pid, int sig);
extern int mykillpg(int pgrp, int sig);
extern void kill_assist(void);
extern void mysleep(int secs);
extern time_t procrealtime(time_t sec);
extern time_t proc2servtime(time_t sec);
extern void prepare_netlink_socket(void);
extern void close_netlink_socket(void);
extern int init_engine(int type, struct nlmsghdr *nlh);
extern void fini_engine(int type, struct nlmsghdr *nlh);
extern char *get_req(struct nlmsghdr *nlh, int sockfd);
extern void uidtoname(uid_t uid, char *name);
extern int nametouid(uid_t *uid, char *name);
extern int is_su_sudo(char *cmd);
extern int in_suid_set(char *cmd);
extern int is_skip_suid(taskstat_t *taskstat);
extern int is_bash_waiting_cmd(char *cmd, pid_t pid);
extern int is_shell(char *execargs);
extern int send_data_to_kern(int type, char *data, int datalen);
extern int set_kern_processrules(char *rule, int size);
extern char *safebasename(char *path);
extern void safedirname(char *path, char *dirname, int dirlen);
extern int find_symbol_positon(char *str, char c, int n);
extern int my_system(char *cmd, int print_mode);
extern int ip_match(char *ip, char *myip);
extern char *get_ip_from_hostname(char *ip, char *hostname);
extern int get_socket_info(char *line, sockinfo_t *info);
extern int get_process_socket_info(pid_t pid, sockinfo_t *info, int check_udp);
extern int get_connout_socket_info(pid_t pid, sockinfo_t *info, int port);
extern int get_conn_process_by_inode(unsigned long inode, pid_t *out_pid, char *cmd);
extern int process_alive(pid_t pid);
extern int stop_cmd(struct process_msg_args *msg, char *reason);
extern int check_shell_tty(pid_t pid);
extern int is_internet_ip(char *ip);
extern int istcp(char *proto);
extern int isudp(char *proto);
extern int is_valid_ip(char *ip);
extern int check_isip(char *str);
extern void set_taskuuid(char *uuid, unsigned long long t, pid_t pid, int extra);
extern int round_size(int size);
extern void *sniper_malloc(int size, int gettype);
extern void do_sniper_free(void *buf, int size, int gettype);
extern int sniper_open(char *path, int flags, int gettype);
extern int sniper_open_const(const char *path, int flags, int gettype);
extern int sniper_open_mode(char *path, int flags, mode_t mode, int gettype);
extern int sniper_socket(int domain, int type, int protocol, int gettype);
extern int sniper_close(int fd, int gettype);
extern FILE *sniper_fopen(char *path, char *mode, int gettype);
extern FILE *sniper_fopen_const(const char *path, char *mode, int gettype);
extern int sniper_fclose(FILE *fp, int gettype);
extern void dump_sniperfd(void);
extern void sniper_inc_opencount(int gettype);
extern void sniper_dec_opencount(int gettype);
extern DIR *sniper_opendir(char *path, int gettype);
extern int sniper_closedir(DIR *dirp, int gettype);
extern int get_key_value_from_line(char *line, char *key, int key_len, char *value, int value_len, char delim);
extern int get_value_of_key_from_line(char *line, char *key, char *value, int value_len, char delim);
extern int get_value_of_key_from_file(char *path, char *key, char *value, int value_len, char delim);
extern int remove_dir(char *dir);
extern int wildcard_string_match(char *pattern, char *string);
extern unsigned long get_dir_size(char *dir);
extern unsigned long get_path_disk_size(char *path);
extern void save_lib_version(char *name, char *version);

/* port_forward.c */
extern int is_port_forward(taskstat_t *taskstat, int to_report_task_exit);

/* file_type.c */
extern int get_file_type(char *path);

/* tools.c */
extern int monstatus(int type, pid_t pid);
extern int monstop(char *token, int uninstall);
extern int monuninstall(char *token);
extern int monforece_uninstall(char *token);
extern int monrecovery_file(char *path);
extern int monallowip(char *ip);
extern int monrandom(void);
extern int mondisplay(void);
extern void kill_snipertray(void);
extern void hostinfo(void);
extern int check_module(char *module_name);
#define FULL_MATCH 1 //完全一样
#define HEAD_MATCH 2 //头部相同
#define SUB_MATCH  3 //包含
extern int search_proc(char *procname, int match_type);

/* kexec_msg_queue.c */
extern int get_kexec_msg_count(void);
extern void search_kexec_msg(char *cmdname, pid_t pid);

/* get_fileinfo_from_rpmdb.c */
extern int get_fileinfo_from_rpmdb(char *cmd, exeinfo_t *exeinfo, char *md5, char *sha256);

/* get_fileinfo_from_dpkginfo.c */
extern int get_fileinfo_from_dpkginfo(char *cmd, exeinfo_t *exeinfo);

/* sqlutil.c */
extern int db_busy_callback(void *data, int count);
extern sqlite3* connectDb(char *dbname, const char *crt_tbl_sql, char *pwd, int *first_time);
extern sqlite3* connect_to_Db(char *dbname, const char *crt_tbl_sql, const char *crt_tbl_sql2, char *pwd, int *first_time);
extern sqlite3* connect_five_tbl(char *dbname, const char *crt_tbl_sql, const char *crt_tbl_sql1, const char *crt_tbl_sql2, const char *crt_tbl_sql3, const char *crt_tbl_sql4, char *pwd, int *first_time);

/* check_group.c */
extern void check_group(void);
extern void get_user_grplist(char *user, gid_t gid, char *group, int group_len, char *grplist, int grplist_len);
extern void group_db_release(void);
extern gid_t get_cdrom_gid(void);

/* check_user.c */
extern void check_user(void);
extern void user_db_release(void);
extern int can_login(uid_t uid);
extern void check_user_weakpwd(task_recv_t *msg);
extern int check_app_user(cJSON *items, int *is_vuser_ftp);
extern void detect_risk_account(task_recv_t *msg);
extern int check_weakpwd(char *username, const char *pwd_str, char *result);
extern int check_weak_passwd_whitelist(char *username, const unsigned int app_type);

/* blackmail_protect.c */
extern void operate_encrypt_trap_files(int hide, int type);
extern void init_encrypt_db(void);
extern void fini_encrypt_db(void);
extern void create_file(char *path);
extern void check_dir_trap_files(char *path, int hide, int type);
#if 0
extern void add_record_to_encrypt_db(filereq_t *rep, struct file_msg_args *msg);
extern void report_encrypt_msg(filereq_t *rep, struct file_msg_args *msg);
#else
extern void add_record_to_encrypt_db(struct ebpf_filereq_t *rep, struct file_msg_args *msg);
extern void report_encrypt_msg(struct ebpf_filereq_t *rep, struct file_msg_args *msg);
#endif

/* check_sys_danger.c*/
extern void check_sys_danger(task_recv_t *msg);
extern void test_sys_risk_check(void);
void check_application_risk(cJSON *array);
extern char *strrstr(const char *string, const char *str);

/* baseline.c */
extern pid_t nginx_pid, apache_pid, tomcat_pid, mysql_pid, solr_pid;
extern char tomcat_path[S_LINELEN], nginx_path[S_LINELEN];
extern int parse_baseline_database(task_recv_t *msg, int rule_id, int *whitelist_id, int white_size);
extern int baseline_stop(task_recv_t *msg);
extern void get_app_pid(app_module *app_info);
extern void tomcat_conf_path(pid_t pid);
extern void nginx_conf_path(pid_t pid);

/* check_conn.c */
extern void conn_db_release(void);
extern void location_db_release(void);
extern void location_db_init(void);
extern const char *select_location_d(char *ip);
extern void check_conn_status(void);

/* check_pid_stat.c */
extern void pid_info_init(void);
extern void check_pid_status(void);
extern void cpu_db_release(void);
extern unsigned long get_process_cpu(pid_t pid);
extern unsigned long get_total_cpu(void);
extern unsigned long get_proc_mem(pid_t pid);

/* self_resource_check.c */
extern void myexit(void);
extern void myrestart(void);
extern unsigned long upload_bytes;
extern void *resource_check(void *ptr);

#endif /* _HEADER_H */
