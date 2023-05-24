#ifndef _POLICY_H
#define _POLICY_H

#include "common.h"
#include "websocket.h"

#define TURN_MY_OFF 0
#define TURN_MY_ON  1

#define WEBSHELL_EASY_MOD	1
#define WEBSHELL_HARD_MOD	2

#define POLICY_ID_LEN_MAX       8
#define POLICY_NAME_LEN_MAX     256
#define POLICY_TIME_LEN_MAX     40

extern int policy_ver;

/* -防护策略- */
/* --恶意行为防护-- */
/* ---挖矿行为--- */
typedef struct _BEHAVIOUR_POOL{
	int enable;
	int terminate;
	int locking;
	int locking_time;
}BEHAVIOUR_POOL, *PBEHAVIOUR_POOL;
/* ---挖矿行为--- */

/* ---勒索行为--- */
/* ----追踪防护引擎---- */
typedef struct _RANSOMWARE_TRACK{
	int enable;
	int terminate;
	POLICY_LIST ext;
}RANSOMWARE_TRACK;
/* ----追踪防护引擎---- */

/* ----加密防护引擎---- */
/* -----文件备份----- */
typedef struct _ENCRYPT_BACKUP{
	int enable;
	int neglect_min;
	int neglect_size;
	int backup_size;
}ENCRYPT_BACKUP;
/* -----文件备份----- */

/* -----linux配置----- */
typedef struct _ENCRYPT_MY_LINUX{
	POLICY_LIST ext;
}ENCRYPT_MY_LINUX;
/* -----linux配置----- */

typedef struct _RANSOMWARE_ENCRYPT{
	int enable;
	int terminate;
	int hide;
	POLICY_LIST ext;
	ENCRYPT_MY_LINUX my_linux;
	ENCRYPT_BACKUP backup;
}RANSOMWARE_ENCRYPT;
/* ----加密防护引擎---- */

typedef struct _BEHAVIOUR_RANSOMWARE{
	RANSOMWARE_TRACK track;
	RANSOMWARE_ENCRYPT encrypt;
}BEHAVIOUR_RANSOMWARE;
/* ---勒索行为--- */

typedef struct _PROTECT_BEHAVIOUR{
	BEHAVIOUR_POOL pool;
	BEHAVIOUR_RANSOMWARE ransomware;
}PROTECT_BEHAVIOUR,*PPROTECT_BEHAVIOUR;
/* --恶意行为防护-- */

/* --进程异常防护-- */
/* ---反弹shell--- */
typedef struct _PROCESS_REVERSE_SHELL{
	int enable;
	int terminate;
	int locking;
	int locking_time;
}PROCESS_REVERSE_SHELL;
/* ---反弹shell--- */

/* ---非法提权--- */
typedef struct _PROCESS_MY_PRIVILEGE{
	int enable;
	int terminate;
}PROCESS_MY_PRIVILEGE;
/* ---非法提权--- */

/* ---MBR防护--- */
typedef struct _PROCESS_MY_MBR{
	int enable;
	int terminate;
}PROCESS_MY_MBR;
/* ---MBR防护--- */

/* ---可疑命令执行--- */
typedef struct _PROCESS_DANGEROUS_COMMAND{
	int enable;
	int terminate;
}PROCESS_DANGEROUS_COMMAND;
/* ---可疑命令执行--- */

/* ---中国菜刀命令执行--- */
typedef struct _PROCESS_MY_WEBSHELL{
	int enable;
	int terminate;
}PROCESS_MY_WEBSHELL;
/* ---中国菜刀命令执行--- */

/* ---中国菜刀命令执行--- */
typedef struct _PROCESS_SERVICE_PROCESS{
	int enable;
	int terminate;
}PROCESS_SERVICE_PROCESS;
/* ---中国菜刀命令执行--- */

/* ---伪造系统进程运行--- */
typedef struct _PROCESS_FAKE_SYS{
	int enable;
	int terminate;
}PROCESS_FAKE_SYS;
/* ---伪造系统进程运行--- */

/* ---隧道搭建--- */
typedef struct _PROCESS_TUNNEL{
	int enable;
	int terminate;
}PROCESS_TUNNEL;
/* ---隧道搭建--- */

/* ---危险命令--- */
typedef struct _PROCESS_RISK_COMMAND{
	int enable;
	int terminate;
}PROCESS_RISK_COMMAND;
/* ---危险命令--- */

/* ---异常程序--- */
typedef struct _PROCESS_ABNORMAL_PROCESS{
	int enable;
	int terminate;
}PROCESS_ABNORMAL_PROCESS;
/* ---异常程序--- */

typedef struct _PROTECT_PROCESS{
	int command_num;
	PROCESS_REVERSE_SHELL reverse_shell;
	PROCESS_MY_PRIVILEGE privilege;
	PROCESS_MY_MBR mbr;
	PROCESS_DANGEROUS_COMMAND dangerous_command;
	PROCESS_MY_WEBSHELL webshell;
	PROCESS_SERVICE_PROCESS service_process;
	PROCESS_FAKE_SYS fake_sys_process;
	PROCESS_TUNNEL tunnel;
	PROCESS_RISK_COMMAND risk_command;
	PROCESS_ABNORMAL_PROCESS abnormal_process;
	PPOLICY_LIST command_table_list;
}PROTECT_PROCESS,*PPROTECT_PROCESS;
/* --进程异常防护-- */

/* --异常网络防护-- */
/* ---访问恶意域名--- */
typedef struct _NETWORK_DOMAIN{
	int enable;
	int terminate;
}NETWORK_DOMAIN;
/* ---访问恶意域名--- */

/* ---非法连接互联网--- */
typedef struct _NETWORK_ILLEGAL_CONNECT{
	int enable;
	int terminate;
	int addr_num;
	int interval;
	PPOLICY_LIST address;
}NETWORK_ILLEGAL_CONNECT, *PNETWORK_ILLEGAL_CONNECT;
/* ---非法连接互联网--- */

/* -----端口列表----- */
typedef struct _SENSITIVE_LIST{
	int port;
}SENSITIVE_LISTi, *PSENSITIVE_LIST;
/* -----端口列表----- */

/* ----敏感端口扫描防护---- */
typedef struct _PORT_SENSITIVE{
	int enable;
	int list_num;
	PSENSITIVE_LIST list;
}PORT_SENSITIVE, *PPORT_SENSITIVE;
/* ----敏感端口扫描防护---- */

/* ---端口扫描防护--- */
typedef struct _NETWORK_PORT{
	int enable;
	int terminate;
	int request_period;
	int count;
	int locking_time;
	PORT_SENSITIVE sensitive;
}NETWORK_PORT, *PNETWORK_PORT;
/* ---端口扫描防护--- */

/* ---端口诱捕--- */
typedef struct _NETWORK_SENSITIVE_PORT{
	int enable;
	int terminate;
	int locking_time;
	int list_num;
	PSENSITIVE_LIST list;
}NETWORK_SENSITIVE_PORT, *PNETWORK_SENSITIVE_PORT;
/* ---端口诱捕--- */

/* ---登录--- */
typedef struct _NETWORK_LOGIN{
	int enable;
	int local_enable;
	int remote_enable;
}NETWORK_LOGIN;
/* ---登录--- */

typedef struct _PROTECT_NETWORK{
	NETWORK_DOMAIN domain;
	NETWORK_ILLEGAL_CONNECT illegal_connect; 
	NETWORK_PORT port;
	NETWORK_SENSITIVE_PORT sensitive_port;
	NETWORK_LOGIN login;
}PROTECT_NETWORK, *PPROTECT_NETWORK;
/* --异常网络防护-- */

/* ---异常登录--- */
typedef struct _TIME_LIST{
	char *start_time;
	char *end_time;
}TIME_LIST, *PTIME_LIST;

typedef struct _LOCATION_LIST{
	char *city;
	char *province;
}LOCATION_LIST, *PLOCATION_LIST;

/* -----常用登录时间设置----- */
typedef struct _LOGIN_MY_TIME{
	int enable;
	int list_num;
	PTIME_LIST list;
}LOGIN_MY_TIME;
/* -----常用登录时间设置----- */

/* -----常用登录时间设置----- */
typedef struct _LOGIN_MY_LOCATION{
	int enable;
	int list_num;
	PLOCATION_LIST list;
}LOGIN_MY_LOCATION;
/* -----常用登录时间设置----- */

/* ----本地用户登录监控---- */
typedef struct _LOGIN_LOCAL{
	int enable;
	int terminate;
	int terminate_mode;
	LOGIN_MY_TIME time;
}LOGIN_LOCAL;
/* ----本地用户登录监控---- */

/* ----远程登录监控---- */
typedef struct _LOGIN_MY_REMOTE{
	int enable;
	int terminate;
	int terminate_mode;
	LOGIN_MY_TIME time;
	LOGIN_MY_LOCATION location;
}LOGIN_MY_REMOTE;
/* ----远程登录监控---- */

/* ----暴力密码破解防护---- */
typedef struct _LOGIN_CRACK{
	int enable;
	int interval;
	int limit;
	int terminate;
	int locking_time;
}LOGIN_CRACK;
/* ----暴力密码破解防护---- */

typedef struct _ACCOUNT_LOGIN{
	int enable;
	LOGIN_LOCAL local;
	LOGIN_MY_REMOTE remote;
	LOGIN_CRACK crack;
}ACCOUNT_LOGIN;
/* ---异常登录--- */

/* ---异常账号--- */
typedef struct _ACCOUNT_ABNORMAL_USER{
	int enable;
}ACCOUNT_ABNORMAL_USER;
/* ---异常账号--- */

/* ---用户变更监控--- */
/* ----用户变更---- */
typedef struct _CHANGE_MY_USER{
	int enable;
}CHANGE_MY_USER;
/* ----用户变更---- */

/* ----用户组变更---- */
typedef struct _CHANGE_MY_GROUP{
	int enable;
}CHANGE_MY_GROUP;
/* ----用户组变更---- */

typedef struct _ACCOUNT_USER_CHANGE{
	int enable;
	CHANGE_MY_USER user;
	CHANGE_MY_GROUP group;
}ACCOUNT_USER_CHANGE;
/* ---用户变更监控--- */

/* --异常账户防护-- */
typedef struct _PROTECT_ACCOUNT{
	ACCOUNT_LOGIN login;
	ACCOUNT_ABNORMAL_USER abnormal_user;
	ACCOUNT_USER_CHANGE user_change;
}PROTECT_ACCOUNT, *PPROTECT_ACCOUNT;
/* --异常账户防护-- */

/* --敏感信息防护-- */
/* ---敏感文件--- */
typedef struct _SENSITIVE_FILE{
	int enable;
	int terminate;
	int list_num;
	PPOLICY_LIST list;
}SENSITIVE_FILE, *PSENSITIVE_FILE;
/* ---敏感文件--- */

/* ---日志异常删除--- */
typedef struct _SENSITIVE_LOG_DELETE{
	int enable;
	int list_num;
	PPOLICY_LIST list;
}SENSITIVE_LOG_DELETE, *PSENSITIVE_LOG_DELETE;
/* ---日志异常删除--- */

/* ----文件列表---- */
typedef struct _SAFE_FILE_LIST{
	int status;
	char *path;
	char *real_path;
	char *name;
	char *process;
	char *operation;
}SAFE_FILE_LIST,*PSAFE_FILE_LIST;
/* ----文件列表---- */

/* ---文件防篡改--- */
typedef struct _SENSITIVE_SAFE_FILE{
	int enable;
	int list_num;
	PSAFE_FILE_LIST list;
}SENSITIVE_SAFE_FILE, *PSENSITIVE_SAFE_FILE;
/* ---文件防篡改--- */

/* ---usb文件监控--- */
typedef struct _SENSITIVE_FILE_USB{
	int enable;
	char *extension;
}SENSITIVE_FILE_USB, *PSENSITIVE_FILE_USB;
/* ---usb文件监控--- */

/* ---中间件识别--- */
/* ----脚本识别---- */
typedef struct _MIDDLEWARE_MY_SCRIPT{
	int enable;
	int terminate;
	char *ext;
}MIDDLEWARE_MY_SCRIPT;
/* ----脚本识别---- */

/* ----可执行文件识别---- */
typedef struct _MIDDLEWARE_EXECUTABLE{
	int enable;
	int terminate;
	int exclude;
	char *ext;
}MIDDLEWARE_EXECUTABLE;
/* ----可执行文件识别---- */

typedef struct _SENSITIVE_MIDDLEWARE{
	int enable;
	char *target;
	MIDDLEWARE_MY_SCRIPT script_files;
	MIDDLEWARE_EXECUTABLE executable_files;
}SENSITIVE_MIDDLEWARE, *PSENSITIVE_MIDDLEWARE;
/* ---中间件识别--- */

/* ---非法脚本识别--- */
/* ----监控的路径和文件类型---- */
typedef struct _ILLEGAL_SCRIPT_TARGET{
	char *path;
	char *real_path;
	char *extension;
}ILLEGAL_SCRIPT_TARGET, *PILLEGAL_SCRIPT_TARGET;
/* ----监控的路径和文件类型---- */

typedef struct _SENSITIVE_ILLEGAL_SCRIPT{
	int enable;
	int terminate;
	int use_default_keyword;
	int target_num;
	int default_keyword_num;
	int keyword_num;
	PPOLICY_LIST keyword;
	PPOLICY_LIST default_keyword;
	PILLEGAL_SCRIPT_TARGET target;
}SENSITIVE_ILLEGAL_SCRIPT, *PSENSITIVE_ILLEGAL_SCRIPT;
/* ---非法脚本识别--- */

/* ---webshell文件检测--- */
/* ----监控的路径和文件类型---- */
typedef struct _WEBSHELL_DETECT_TARGET{
	char *path;
	char *real_path;
	char *extension;
}WEBSHELL_DETECT_TARGET, *PWEBSHELL_DETECT_TARGET;
/* ----监控的路径和文件类型---- */

typedef struct _SENSITIVE_WEBSHELL_DETECT{
	int enable;
	int terminate;
	int use_default_rule;
	int detect_mode;
	int target_num;
	PWEBSHELL_DETECT_TARGET target;
}SENSITIVE_WEBSHELL_DETECT, *PSENSITIVE_WEBSHELL_DETECT;
/* ---webshell文件检测--- */

/* 930版本将非法脚本和webshell放到backdoor里面，结构体跟旧版本保持一致 */
/* ---后面检测--- */
typedef struct _SENSITIVE_BACKDOOR{
	int enable;
}SENSITIVE_BACKDOOR;
/* ---后面检测--- */

typedef struct _PROTECT_SENSITIVE{
	SENSITIVE_FILE sensitive_file;
	SENSITIVE_LOG_DELETE log_delete;
	SENSITIVE_SAFE_FILE file_safe;
	SENSITIVE_FILE_USB file_usb;
	SENSITIVE_MIDDLEWARE middleware;
	SENSITIVE_ILLEGAL_SCRIPT illegal_script;
	SENSITIVE_WEBSHELL_DETECT webshell_detect;
	SENSITIVE_BACKDOOR backdoor;
}PROTECT_SENSITIVE, *PPROTECT_SENSITIVE;
/* --敏感信息防护-- */

/* --日志采集-- */
/* ---日志采集文件列表--- */
typedef struct _LOGCOLLECTOR_FILE_LIST{
	char *filepath;
	char *real_path;
	char *extension;
}LOGCOLLECTOR_FILE_LIST, *PLOGCOLLECTOR_FILE_LIST;
/* ---日志采集文件列表--- */

typedef struct _PROTECT_LOGCOLLECTOR{
	int process_enable;
	int file_enable;
	int network_enable;
	int dnsquery_enable;
	int file_list_num;
	PLOGCOLLECTOR_FILE_LIST file_list;
}PROTECT_LOGCOLLECTOR;
/* --日志采集-- */

typedef struct _PROTECT_POLICY{
	PROTECT_BEHAVIOUR behaviour;
	PROTECT_PROCESS process;
	PROTECT_NETWORK network;
	PROTECT_ACCOUNT account;
	PROTECT_SENSITIVE sensitive_info;
	PROTECT_LOGCOLLECTOR logcollector;
	pthread_rwlock_t lock;
}PROTECT_POLICY;
/* -防护策略- */

/* -加固策略- */
/* --系统-- */
typedef struct _FASTEN_SYSTEM{
        int load_enable;
        int load_cpu;
        int load_memory;
        int load_disk;
}FASTEN_SYSTEM;
/* --系统-- */

/* --资源监控-- */
/* ---系统负载监控--- */
/* ----CPU---- */
typedef struct _SYS_CPU{
        int enable;
        int interval;
        int limit;
}SYS_CPU;
/* ----CPU---- */

/* ----内存---- */
typedef struct _SYS_MEMORY{
        int enable;
        int interval;
        int limit;
}SYS_MEMORY;
/* ----内存---- */

/* ----磁盘---- */
typedef struct _SYS_DISK{
        int enable;
        int interval;
        int limit;
}SYS_DISK;
/* ----磁盘---- */

/* ----网络---- */
typedef struct _SYS_NETFLOW{
        int enable;
        int interval;
        int up;
        int down;
}SYS_NETFLOW;
/* ----网络---- */

typedef struct _RESOUCE_SYS{
	int enable;
	SYS_CPU cpu;
	SYS_MEMORY memory;
	SYS_DISK disk;
	SYS_NETFLOW netflow;
}RESOUCE_SYS;
/* ---系统负载监控--- */

/* ---进程负载监控--- */
/* ----CPU---- */
typedef struct _PROCESS_CPU{
        int enable;
        int interval;
        int limit;
}PROCESS_CPU;
/* ----CPU---- */

/* ----内存---- */
typedef struct _PROCESS_MEMORY{
        int enable;
        int interval;
        int limit;
}PROCESS_MEMORY;
/* ----内存---- */

typedef struct _RESOUCE_PROCESS{
	int enable;
	PROCESS_CPU cpu;
	PROCESS_MEMORY memory;
}RESOUCE_PROCESS;
/* ---进程负载监控--- */

typedef struct _FASTEN_RESOUCE{
	RESOUCE_SYS sys;
	RESOUCE_PROCESS process;
}FASTEN_RESOUCE;
/* --资源监控-- */

/* --设备-- */
/* ---USB存储接入--- */
typedef struct _DEVICE_MY_USB{
	int enable;
	int terminate;
	int exclude_num;
	PPOLICY_LIST exclude;
}DEVICE_MY_USB, *PDEVICE_MY_USB;
/* ---USB存储接入--- */

/* ---打印机监控--- */
typedef struct _DEVICE_MY_PRINTER{
	int enable;
	int terminate;
	int ext_num;
	PPOLICY_LIST ext;
}DEVICE_MY_PRINTER, *PDEVICE_MY_PRINTER;
/* ---打印机监控--- */

/* ---刻录机监控--- */
typedef struct _DEVICE_MY_CDROM{
	int enable;
	int terminate;
	int ext_num;
	PPOLICY_LIST ext;
}DEVICE_MY_CDROM, *PDEVICE_MY_CDROM;
/* ---刻录机监控--- */

typedef struct _FASTEN_DEVICE{
	int exclude_num;
	DEVICE_MY_USB usb;
	DEVICE_MY_PRINTER printer;
	DEVICE_MY_CDROM cdrom;
	PPOLICY_LIST exclude_uuid;
}FASTEN_DEVICE;
/* --设备-- */

typedef struct _FASTEN_POLICY{
	FASTEN_SYSTEM system;
	FASTEN_RESOUCE resource;
	FASTEN_DEVICE device;
	pthread_rwlock_t lock;
}FASTEN_POLICY;
/* -加固策略- */

/* -病毒防护- */
/* --实时检测-- */
typedef struct _ANTIVIRUS_CHECK{
	int enable;
}ANTIVIRUS_CHECK;
/* --实时检测-- */

/* --扫描查杀-- */
/* ---定时扫描--- */
typedef struct _SCANNING_CRON{
	int enable;
	int scanning_way;
	int day;
	char *time_type;
	char *time;
}SCANNING_CRON;
/* ---定时扫描--- */

typedef struct _ANTIVIRUS_SCANNING{
	int enable;
	SCANNING_CRON cron;
}ANTIVIRUS_SCANNING;
/* --扫描查杀-- */

typedef struct _ANTIVIRUS_POLICY{
	int reserved_space;
	int automate;
	int neglect_size;
	int list_num;
	ANTIVIRUS_CHECK real_time_check;
	ANTIVIRUS_SCANNING scanning_kill;
	PPOLICY_LIST trust_list;
        pthread_rwlock_t lock;
}ANTIVIRUS_POLICY;
/* -病毒防护- */

/* -其他配置- */
/* --是否允许卸载客户端-- */
typedef struct _OTHER_UNINSTALL{
	int enable;
}OTHER_UNINSTALL;
/* --是否允许卸载客户端-- */

/* --是否显示客户端界面-- */
typedef struct _OTHER_UI{
	int enable;
}OTHER_UI;
/* --是否显示客户端界面-- */

typedef struct _OTHER_POLICY{
	OTHER_UNINSTALL allow_uninstall;
	OTHER_UI allow_ui_tray;
	pthread_rwlock_t lock;
}OTHER_POLICY;
/* -其他配置- */

extern char policy_id_cur[POLICY_ID_LEN_MAX];
extern char policy_name_cur[POLICY_NAME_LEN_MAX];
extern char policy_time_cur[POLICY_TIME_LEN_MAX];

extern PROTECT_POLICY protect_policy_global;
extern FASTEN_POLICY fasten_policy_global;
extern ANTIVIRUS_POLICY antivirus_policy_global;
extern OTHER_POLICY other_policy_global;

extern void check_cupsd(int do_start);
extern int init_policy(void);
extern void fini_policy(void);
extern int list_policy(void);
extern int update_policy(char *reason);
extern int update_policy_my(task_recv_t *msg);
extern void close_kernel_file_policy(void);
extern void update_kernel_file_policy(void);
extern void record_policy_to_file(void);
extern void update_kernel_policy(void);

extern void dbg_record_to_file(char *flagfile, char *path, char *buf, int size);
#endif
