#ifndef _RULE_H
#define _RULE_H

#include "common.h"

/* -可信名单- */
/* --进程-- */
typedef struct _TRUST_PROCESS {
	int event_num;
	int event_flags;
	char *process_name;
	char *process_path;
	char *process_commandline;
	char *param;
	char *md5;
	char *process_user;
	char *parent_process_name;
	char *remote_ip;
	PPOLICY_LIST event_names;
}TRUST_PROCESS, *PTRUST_PROCESS;
/* --进程-- */

/* --文件-- */
typedef struct _TRUST_FILE {
	int event_num;
	int event_flags;
	char *filename;
	char *filepath;
	char *extension;
	char *md5;
/* 5.0.9新增 */
	char *process_name;
	char *process_path;
/* 5.0.9新增 */
	PPOLICY_LIST event_names;
}TRUST_FILE, *PTRUST_FILE;
/* --文件-- */

/* --ip-- */
typedef struct _TRUST_IP {
	int ip_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST ip_list;
	PPOLICY_LIST event_names;
}TRUST_IP, *PTRUST_IP;
/* --ip-- */

/* --域名-- */
typedef struct _TRUST_DOMAIN {
	int domain_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST domain_list;
	PPOLICY_LIST event_names;
}TRUST_DOMAIN,*PTRUST_DOMAIN;
/* --域名-- */

typedef struct _RULE_TRUST {
	int process_num;
	int file_num;
	int ip_num;
	int domain_num;
	PTRUST_PROCESS process;
	PTRUST_FILE file;
	PTRUST_IP ip;
	PTRUST_DOMAIN domain;
	pthread_rwlock_t lock;
}RULE_TRUST;
/* -可信名单- */

/* -过滤名单- */
/* --进程-- */
typedef struct _FILTER_PROCESS {
	int event_num;
	int event_flags;
	char *process_name;
	char *process_path;
	char *process_commandline;
	char *param;
	char *md5;
	char *process_user;
	char *parent_process_name;
	char *remote_ip;
	PPOLICY_LIST event_names;
}FILTER_PROCESS, *PFILTER_PROCESS;
/* --进程-- */

/* --文件-- */
typedef struct _FILTER_FILE {
	int event_num;
	int event_flags;
	char *filename;
	char *filepath;
	char *extension;
	char *md5;
/* 5.0.9新增 */
	char *process_name;
	char *process_path;
/* 5.0.9新增 */
	PPOLICY_LIST event_names;
}FILTER_FILE, *PFILTER_FILE;
/* --文件-- */

/* --ip-- */
typedef struct _FILTER_IP {
	int ip_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST ip_list;
	PPOLICY_LIST event_names;
}FILTER_IP, *PFILTER_IP;
/* --ip-- */

/* --域名-- */
typedef struct _FILTER_DOMAIN {
	int domain_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST domain_list;
	PPOLICY_LIST event_names;
}FILTER_DOMAIN,*PFILTER_DOMAIN;
/* --域名-- */

typedef struct _RULE_FILTER {
	int process_num;
	int file_num;
	int ip_num;
	int domain_num;
	PFILTER_PROCESS process;
	PFILTER_FILE file;
	PFILTER_IP ip;
	PFILTER_DOMAIN domain;
	pthread_rwlock_t lock;
}RULE_FILTER;
/* -过滤名单- */

typedef struct _CONNECT_LIST {
	char *direction;
	char *protocol;
	char *ip;
	char *port;
}CONNECT_LIST, *PCONNECT_LIST;

/* -黑名单- */
/* --进程-- */
typedef struct _BLACK_PROCESS {
	int event_num;
	int event_flags;
	char *process_name;
	char *process_path;
	char *process_commandline;
	char *param;
	char *md5;
	char *process_user;
	char *parent_process_name;
	char *remote_ip;
	PPOLICY_LIST event_names;
}BLACK_PROCESS, *PBLACK_PROCESS;
/* --进程-- */

/* --文件-- */
typedef struct _BLACK_FILE {
	int event_num;
	int event_flags;
	char *filename;
	char *filepath;
	char *extension;
	char *md5;
	PPOLICY_LIST event_names;
}BLACK_FILE, *PBLACK_FILE;
/* --文件-- */

/* --ip-- */
typedef struct _BLACK_IP {
	int ip_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST ip_list;
	PPOLICY_LIST event_names;
}BLACK_IP, *PBLACK_IP;
/* --ip-- */

/* --域名-- */
typedef struct _BLACK_DOMAIN {
	int domain_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST domain_list;
	PPOLICY_LIST event_names;
}BLACK_DOMAIN,*PBLACK_DOMAIN;
/* --域名-- */

/* --用户-- */
typedef struct _BLACK_USER {
	int user_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST user_list;
	PPOLICY_LIST event_names;
}BLACK_USER, *PBLACK_USER;
/* --用户-- */

/* --访问控制-- */
typedef struct _BLACK_ACCESS_CONTROL {
	int connect_num;
	int event_num;
	int event_flags;
	PCONNECT_LIST connect_list;
	PPOLICY_LIST event_names;
}BLACK_ACCESS_CONTROL, *PBLACK_ACCESS_CONTROL;
/* --访问控制-- */

typedef struct _RULE_BLACK {
	int process_num;
	int file_num;
	int ip_num;
	int domain_num;
	int user_num;
	int access_control_num;
	PBLACK_PROCESS process;
	PBLACK_FILE file;
	PBLACK_IP ip;
	PBLACK_DOMAIN domain;
	PBLACK_USER user;
	PBLACK_ACCESS_CONTROL access_control;
	pthread_rwlock_t lock;
}RULE_BLACK;
/* -黑名单- */

/* -白名单- */
/* --ip-- */
typedef struct _WHITE_IP {
	int ip_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST ip_list;
	PPOLICY_LIST event_names;
}WHITE_IP, *PWHITE_IP;
/* --ip-- */

/* --域名-- */
typedef struct _WHITE_DOMAIN {
	int domain_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST domain_list;
	PPOLICY_LIST event_names;
}WHITE_DOMAIN,*PWHITE_DOMAIN;
/* --域名-- */

/* --用户-- */
typedef struct _WHITE_USER {
	int user_num;
	int event_num;
	int event_flags;
	PPOLICY_LIST user_list;
	PPOLICY_LIST event_names;
}WHITE_USER, *PWHITE_USER;
/* --用户-- */

/* --访问控制-- */
typedef struct _WHITE_ACCESS_CONTROL {
	int connect_num;
	int event_num;
	int event_flags;
	PCONNECT_LIST connect_list;
	PPOLICY_LIST event_names;
}WHITE_ACCESS_CONTROL, *PWHITE_ACCESS_CONTROL;
/* --访问控制-- */

typedef struct _LIST_RULE {
	int list_num;
	PPOLICY_LIST list;
}LIST_RULE, *PLIST_RULE;

typedef struct _RISK_LIST {
	int id;
	LIST_RULE rule;
}RISK_LIST, *PRISK_LIST;

typedef struct _PASSWD_LIST_RULE {
	int list_num;
	int type_num;
	PPOLICY_INT_LIST app_type;
	PPOLICY_LIST list;
}PASSWD_LIST_RULE, *PPASSWD_LIST_RULE;

typedef struct _RISK_PASSWD {
	int id;
	PASSWD_LIST_RULE rule;
}RISK_PASSWD, *PRISK_PASSWD;

/* --风险发现-- */
typedef struct _WHITE_RISK {
	int weak_passwd_num;
	int account_num;
	int sys_num;
	PRISK_PASSWD weak_passwd;
	PRISK_LIST account;
	PRISK_LIST sys;
}WHITE_RISK;
/* --风险发现-- */

typedef struct _RULE_WHITE {
	int ip_num;
	int domain_num;
	int user_num;
	int access_control_num;
	WHITE_RISK risk;
	PWHITE_IP ip;
	PWHITE_DOMAIN domain;
	PWHITE_USER user;
	PWHITE_ACCESS_CONTROL access_control;
	pthread_rwlock_t lock;
}RULE_WHITE;
/* -白名单- */

/* -global- */
/* --可信名单-- */
/* ---可信证书--- */
typedef struct _TRUST_SIGN {
	char *company;
	char *fingerprint;
}TRUST_SIGN, *PTRUST_SIGN;
/* ---可信证书--- */

typedef struct _GLOBAL_TRUST {
	int sign_num;
	PTRUST_SIGN sign;
}GLOBAL_TRUST;
/* -可信名单- */

/* -黑名单- */
typedef struct _GLOBAL_BLACK {
        int domain_num;
	int minner_num;
	PPOLICY_LIST domain;
	PPOLICY_LIST minner;
}GLOBAL_BLACK;
/* -黑名单- */

typedef struct _RULE_GLOBAL {
	int sensitive_file_num;
	GLOBAL_TRUST trust;
	GLOBAL_BLACK black;
	pthread_rwlock_t lock;
}RULE_GLOBAL;
/* -global- */

extern RULE_TRUST rule_trust_global;
extern RULE_FILTER rule_filter_global;
extern RULE_BLACK rule_black_global;
extern RULE_WHITE rule_white_global;
extern RULE_GLOBAL rule_global_global;

extern void init_rule(void);
extern void fini_rule(void);
#endif
