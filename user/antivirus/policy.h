#ifndef _POLICY_H
#define _POLICY_H

#define TURN_MY_OFF 0
#define TURN_MY_ON  1

#define POLICY_ID_LEN_MAX       8
#define POLICY_NAME_LEN_MAX     256
#define POLICY_TIME_LEN_MAX     40

typedef struct _POLICY_LIST{
	char *list;
}POLICY_LIST, *PPOLICY_LIST;

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

extern char policy_id_cur[POLICY_ID_LEN_MAX];
extern char policy_name_cur[POLICY_NAME_LEN_MAX];
extern char policy_time_cur[POLICY_TIME_LEN_MAX];
extern ANTIVIRUS_POLICY antivirus_policy_global;

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

extern GLOBAL_CONF conf_global;
extern GLOBAL_CONF old_conf_global;
#endif
