#ifndef _COMMON_H
#define _COMMON_H

#define VER_LEN_MAX     40              /* 版本号最大长度 */

#define WHILE_MAX       1000		/* 循环的最大次数 */

#define LOGID_SIZE_MAX          40
#define SAMPLE_NUM_MAX          5

#define LOGOUT_NEXT	0
#define LOGOUT_NOW	1

#define MY_TURNON	1
#define MY_TURNOFF	0

#define HIDE_TURNON     MY_TURNON
#define HIDE_TURNOFF    MY_TURNOFF
#define OP_CREATE       1
#define OP_DELETE       2

#define BATCH_LOG_MODE  1  // 日志采集模式 1 批量打包上传
#define SINGLE_LOG_MODE 2

#define STRLEN_MAX       1024
#define USB_MAX          32

#define KEY_LEN         40 //json数据key的长度
#define SUFFIX_LEN      16 //下载的库后缀名的长度

extern int backup_space_full;
extern int last_encrypt_enable;
extern int hide_mode;

struct _ip_list{
	char ip[S_IPLEN];
};

typedef struct _POLICY_LIST{
	char *list;
}POLICY_LIST, *PPOLICY_LIST;

typedef struct _POLICY_INT_LIST{
	int list;
}POLICY_INT_LIST, *PPOLICY_INT_LIST;

/* usb.c */
#define USB_NO          0
#define USB_IN          1
#define USB_OUT         2
#define USB_CHANGE      3

struct _mount_info{
	int major;
	int minor;
};
extern int mount_num;
extern struct _mount_info mount_info[USB_MAX];
extern void get_mount_info(void);

extern char *check_my_switch(int type);
extern char *check_my_switch_permit(int type);
extern char *check_my_switch_yes(int type);
extern char *check_my_switch_yes_en(int type);
extern char *check_webshell_mode(int mode);
extern char *get_my_valuestring(cJSON *item);
extern char *get_customize_valuestring(void);

/* download lib */
struct _lib_info {
	char name[S_NAMELEN];
	char url[S_URLLEN];
	char md5[S_MD5LEN];
	char key[KEY_LEN];
	char ver_file[PATH_MAX];
	char suffix[SUFFIX_LEN];
	int type;
};

/* global */
typedef struct _GLOBAL_CONF{
	int agent_cpu_limit;                    // 客户端CPU限制百分比
	int agent_memory_limit;                 // 客户端内存限制(MB)
	int agent_network_limit;                // 客户端网络限制(KB/s)
	int offline_space_size;                 // 离线日志空间大小 (默认MB单位)
	int isolation_space_size;               // 客户端隔离保留空间大小 (默认MB单位)
	int heartbeat_interval;                 // 心跳间隔时长
	int log_collect_mode;                   // 日志采集模式 1 http 文件打包上传
	int log_collect_interval;               // 批量日志发送时间间隔 (默认s单位)
	int licence_expire;                     // 许可是否过期 0 未过期 1 过期 (过期后客户端只维持心跳，不收集数据)
	int allow_upload_sample;                // 是否允许上传样本
	int module_num;
	int server_num;
	PPOLICY_LIST licence_module;		//许可的模块
	PPOLICY_LIST server_ip;
	pthread_rwlock_t lock;
}GLOBAL_CONF, *PGLOBAL_CONF;

typedef struct _CONF_COLLECT_ITEMS {
	char *name;                             //采集项的名称
}CONF_COLLECT_ITEMS, *PCONF_COLLECT_ITEMS;

/* asset */
typedef struct _ASSET_CONF {
	int cycle;				// 周期  默认按天为单位  0 代表一次 1天 7天
	int num;                                // collect_items的数量
	unsigned int module_st;                 // 表示资产清点模块是否启用的bit
	PCONF_COLLECT_ITEMS collect_items;      //采集项 相对对主机信息采集部分
	pthread_rwlock_t lock;
}ASSET_CONF;

/* policy */
typedef struct _POLICY_CONF {
	char *policy_id;                        //策略ID
	char *policy_name;                      //策略名称
	char *policy_time;                      //策略名称
	pthread_rwlock_t lock;
}POLICY_CONF;

/* md5 */
typedef struct _MD5_CONF {
	char weak_passwd_md5[S_MD5LEN];         //弱口令
	char ipwry_ver_md5[S_MD5LEN];           //ip库
	char baseline_ver_md5[S_MD5LEN];        //基线库
	char webshell_ver_md5[S_MD5LEN];        //webshell检测库
	char virus_lib_ver_md5[S_MD5LEN];       //病毒库
	char crack_ver_md5[S_MD5LEN];           //暴力密码库
}MD5_CONF;

/* webshell */
typedef struct _WEBSHELL_RULE {
	int id;
	int level;
	char *regex;
	char *description;
}WEBSHELL_RULE, *PWEBSHELL_RULE;

typedef struct _WEBSHELL_DETECT {
	int  rule_num;
	PWEBSHELL_RULE webshell_rule;
	pthread_rwlock_t lock;
}WEBSHELL_DETECT;

extern GLOBAL_CONF conf_global;
extern ASSET_CONF conf_asset;
extern POLICY_CONF conf_policy;
extern MD5_CONF md5_policy;
extern WEBSHELL_DETECT webshell_detect_global;

extern int is_uninstall_global;
extern int qr_status_global;
extern int is_sync_global;
extern int is_sync_once;     /* 配置更新时与is_sync_global值相同，只用在资产清点手动上报时执行一次 */
extern int client_mode_global;

extern char client_ver_global[VER_LEN_MAX];
extern char collect_ver_global[VER_LEN_MAX];
extern char virus_lib_ver_global[VER_LEN_MAX];
extern char antivirus_ver_global[VER_LEN_MAX];
extern char vuln_ver_global[VER_LEN_MAX];
extern char baseline_ver_global[VER_LEN_MAX];
extern char webshell_ver_global[VER_LEN_MAX];
extern char weak_passwd_ver_global[VER_LEN_MAX];
extern char ipwry_ver_global[VER_LEN_MAX];

extern void init_conf(void);
extern void fini_conf(void);
extern int get_conf(char *reason, int reason_len);
extern void load_last_local_conf(void);
extern void check_backup_free_size(void);
#endif
