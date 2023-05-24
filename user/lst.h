#ifndef _LIST_H
#define _LIST_H

//TODO 下面的宏统一，比如用MY_XXX替代XXX
#define TRUE 1
#define FALSE 0

#define TURNOFF 1
#define TURNON  2

#define ASK_ME                          0
#define AUTO_PROCESS                    1

/* 日志的操作 */
#define OPERATE_FAIL  2
#define OPERATE_OK    1

/* 任务通知的操作*/
#define RESULT_FAIL  0
#define RESULT_OK    1

#define SNIPER_NORISK 1  //无风险，通过检查
#define SNIPER_RISK   0  //有风险，未通过检查

#define MY_RESULT_ZERO    0
#define MY_RESULT_OK      1
#define MY_RESULT_FAIL    2
#define MY_RESULT_CANCEL  3

#define CONN_LISTEN  0
#define CONN_IN      1
#define CONN_OUT     2
#define CONN_CLOSE   3
#define LISTEN_CLOSE 4

#define MY_HANDLE_NO                   0
#define MY_HANDLE_WARNING              1
#define MY_HANDLE_BLOCK_OK             2
#define MY_HANDLE_BLOCK_FAIL           3
#define MY_HANDLE_BLOCK_OK_LOCKIP_OK   4
#define MY_HANDLE_BLOCK_OK_LOCKIP_FAIL 5

#define LOG_NORMAL		1
#define LOG_KEY			2
#define LOG_LOW_RISK		3
#define LOG_MIDDLE_RISK		4
#define LOG_HIGH_RISK		5

#define MY_LOG_NORMAL		0
#define MY_LOG_KEY		1
#define MY_LOG_LOW_RISK		2
#define MY_LOG_MIDDLE_RISK	3
#define MY_LOG_HIGH_RISK	4

#define BEHAVIOR_NORMAL		1 //一般
#define BEHAVIOR_ABNORMAL	2 //异常
#define BEHAVIOR_VIOLATION	3 //违规
#define BEHAVIOR_LEARNING	4 //学习
#define BEHAVIOR_MAINTENANCE	5 //运维

#define MY_BEHAVIOR_NO          0 //无
#define MY_BEHAVIOR_ABNORMAL    1 //异常
#define MY_BEHAVIOR_VIOLATION   2 //违规

//TODO 下面的宏还在用，但也是老的定义，可以考虑逐步淘汰
/*日志事件类别*/
/*process*/
#define PROCESS_NORMAL					1000 //一般
#define PROCESS_SCHEDULE				1001 //计划任务
#define PROCESS_ABNORMAL				1002 //异常
#define PROCESS_SUSPICIOUS				1003 //可疑
#define PROCESS_DANGEROUS				1004 //危险
#define PROCESS_VIOLATION				1005 //违规
#define PROCESS_MIDDLE_EXECUTION			1006 //中间件执行
#define PROCESS_PRIVILEGE_ESCALATION			1007 //提权
#define PROCESS_PHISHING_ATTACKS			1008 //钓鱼
#define PROCESS_REBOUND_SHELL				1009 //反弹shell
#define PROCESS_REMOTE_EXECUTION			1010 //远程执行
#define PROCESS_WEBSHELL_EXECUTION			1011 //webshell
#define PROCESS_ROOTKIT					1012 //rootkit
#define PROCESS_GATHER_INFORMATION			1013 //收集信息
#define PROCESS_PORT_FORWARD				1014 //端口转发
#define PROCESS_UNUSUAL_OPERATION			1015 //异常人为操作
#define PROCESS_ENDDING					1016 //进程结束
#define PROCESS_MINERWARE				1017 //挖矿
#define PROCESS_MBRWARE					1018 //MBR监控
#define PROCESS_MBR_PROTECT				1019 //MBR防护
#define PROCESS_FIREWALL_CHANGE				1020 //非法修改防火墙规则
#define PROCESS_FAKE_SYSPROCESS				1021 //伪造系统进程

#define NET_ILLEGAL_CONNECTION				4003	

/*login*/
#define LOGIN_LOCAL_USER				2000
#define LOGIN_ILLEGAL_USER				2001
#define LOGIN_REMOTE					2002
#define LOGIN_REMOTE_FAILED				2003
#define LOGIN_ILLEGAL_REMOTE				2004
#define LOGIN_PASSWD_CRACK				2005

///////////////////////////////////////////////////////////////////////////////
//
//策略结构体
//
///////////////////////////////////////////////////////////////////////////////


typedef struct _RULE_LIST{
	char *list;
}RULE_LIST, *PRULE_LIST;

typedef struct _RULE_IP_LIST{
	char ip[S_IPLEN];
	int type;
}RULE_IP_LIST,*PRULE_IP_LIST;

typedef struct _MIDDLE_PROCESS_LIST{
        char *process;
}MIDDLE_PROCESS_LIST, *PMIDDLE_PROCESS_LIST;

/*network*/
typedef struct _NET_REMOTE{
	int enable;
}NET_REMOTE;

typedef struct _NET_CRACK{
	int enable;
	int interval;
	int try_num;
	int locking;
}NET_CRACK;

typedef struct _CONNECT_ITEMS{
	int ip_type;
	int port;
	int num;
}CONNECT_ITEMS, *PCONNECT_ITEMS;

typedef struct _CONNECT_IMPORTANT{
	int enable;
	int num;
	PMIDDLE_PROCESS_LIST process_list;
}CONNECT_IMPORTANT;

typedef struct _NET_CONNECT{
	int enable;
	CONNECT_IMPORTANT important_connect;
}NET_CONNECT;

typedef struct _NET_INTERNET{
        int enable;
	int num;
	PRULE_IP_LIST ip_list;
}NET_INTERNET;

typedef struct _HONEY_PORTS{
	int port;
}HONEY_PORTS, *PHONEY_PORTS;

typedef struct _NET_HONEY{
	int enable;
	int locking;
	int num;
	PHONEY_PORTS ports;
}NET_HONEY;

typedef struct _NET_PORTSCAN{
	int enable;
	int locking;
	int num;
	PHONEY_PORTS ports;
}NET_PORTSCAN;

typedef struct _PORT_MAPPING{
        int level;
	int enable;
}PORT_MAPPING;

typedef struct _PORT_LISTENING{
        int level;
	int enable;
}PORT_LISTENING;

typedef struct _NET_PORT{
	int enable;
	PORT_MAPPING mapping;
	PORT_LISTENING listening; 
}NET_PORT;

typedef struct _NET_DOMAIN{
        int enable;
}NET_DOMAIN;

typedef struct _ILLEGAL_COMM{
	int conn_terminate;
} ILLEGAL_CONN;
typedef struct _NET_MONITOR{
	int enable;
	NET_REMOTE remote_login;
	NET_CRACK crack;
	NET_CONNECT connect;
	NET_INTERNET internet_limit;
	NET_HONEY honey;
	NET_PORTSCAN port_scan;
	NET_PORT port;
	NET_DOMAIN domain;
	ILLEGAL_CONN illegal_conn;
	pthread_rwlock_t lock;
}NET_MONITOR, *PNET_MONITOR;

/*filter;trust;white;black*/
typedef struct _RULE_PUBLIC{
	int enable;
	int num;
	PRULE_LIST rule_list;
}RULE_PUBLIC;

typedef struct _RULE_PROCESS_LIST{
       	char *process_name;
	char *process_path;
	char *process_commandline;
	char *md5;
	int log_name;
	int filter_type;
	int event_id;
}RULE_PROCESS_LIST, *PRULE_PROCESS_LIST;

typedef struct _RULE_PROCESS{
	int enable;
	int process_num;
	PRULE_PROCESS_LIST process_list;
}RULE_PROCESS;

typedef struct _RULE_FILE_LIST{
	int event_id;
	char *filename;
	char *filepath;
	char *md5;
}RULE_FILE_LIST, *PRULE_FILE_LIST;

typedef struct _RULE_FILE{
	int enable;
	int file_num;
	PRULE_FILE_LIST file_list;
}RULE_FILE;

typedef struct _RULE_NETWORK{
	int enable;
	int honey_num;
	int honey_num_v6;
	int login_num;
	int connect_num;
	PRULE_IP_LIST honey_ip_list;	/*网络端口诱捕*/
	PRULE_IP_LIST login_ip_list;	/*与管控策略名称保持一致,过滤规则中为远程登录，可行规则中为暴力密码破解*/
	PRULE_IP_LIST connect_ip_list;	/*网络连接*/
}RULE_NETWORK;

typedef struct _RULE_DOMAIN_LIST{
        char *domain;
}RULE_DOMAIH_LIST,*PRULE_DOMAIN_LIST;

typedef struct _RULE_DOMAIN{
	int enable;
	int domain_num;
	PRULE_DOMAIN_LIST domain_list;
}RULE_DOMAIN;

typedef struct _RULE_CONNECT_LIST{
	char *protocol;
	char *ip;
	int fromport;
	int toport;
}RULE_CONNECT_LIST, *PRULE_CONNECT_LIST;

typedef struct _RULE_CONNECT_BOUND{
	int enable;
	int connect_num;
	PRULE_CONNECT_LIST connect_list;
}RULE_CONNECT_BOUND;

typedef struct _RULE_CONNECT{
	RULE_CONNECT_BOUND inbound;
	RULE_CONNECT_BOUND outbound;
}RULE_CONNECT;

typedef struct _RULE_WHITE_IP{
	int enable;
	int num;
	PRULE_LIST rule_list;
	int locking;
}RULE_WHITE_IP;

typedef struct _FILTER_MONITOR{
        int enable;
        RULE_PROCESS process;
	RULE_FILE file;
	RULE_NETWORK network;
	RULE_DOMAIN domain;
	pthread_rwlock_t lock;
}FILTER_MONITOR, *PFILTER_MONITOR;

typedef struct _TRUST_MONITOR{
	int enable;
	RULE_PROCESS process;
	RULE_FILE file;
	RULE_NETWORK network;
	RULE_DOMAIN domain;
	pthread_rwlock_t lock;
}TRUST_MONITOR, *PTRUST_MONITOR;

typedef struct _WHITE_MONITOR{
	int enable;
	RULE_PROCESS process;
	RULE_PUBLIC service;
	RULE_PUBLIC user;
	RULE_CONNECT connect;
	RULE_DOMAIN domain;
	RULE_WHITE_IP remote_login;
	pthread_rwlock_t lock;
}WHITE_MONITOR, *PWHITE_MONITOR;

typedef struct _BLACK_MONITOR{
	int enable;
	RULE_PROCESS process;
	RULE_FILE file;
	RULE_PUBLIC service;
	RULE_PUBLIC user;
	RULE_PUBLIC remote_login;
	RULE_CONNECT connect;
	RULE_DOMAIN domain;
	RULE_DOMAIN malicious_domain;
	pthread_rwlock_t lock;
}BLACK_MONITOR, *PBLACK_MONITOR;

extern NET_MONITOR net_rule;
extern FILTER_MONITOR filter_rule;
extern TRUST_MONITOR trust_rule;
extern WHITE_MONITOR white_rule;
extern BLACK_MONITOR black_rule;

#endif
