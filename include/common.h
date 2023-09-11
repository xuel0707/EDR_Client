#ifndef _KERN_USER_COMMON_H_
#define _KERN_USER_COMMON_H_

#include "vendor_sniper.h"

#define ANTIVIRUS_VER   "5.0.9.0708"

#define NORMAL_MODE             0 //代码中用了非0来判断是运维或学习，不要调整NORMAL_MODE的值
#define OPERATION_MODE          1
#define LEARNING_MODE           2

#define UNINSTALL_DISABLE       "/opt/snipercli/sniper_uninstall_disable"
#define AVIRA_ENABLE            "/opt/snipercli/avira_enable"
#define FORCE_UNINSTALL         "/tmp/.sniper_b4n6WEmbst"
#define BACKUP_DIR              "/opt/snipercli/.filebackup"
#define TRAP_FILE_NOHIDE        "sniper_safe_file"
#define TRAP_FILE_HIDE          ".sniper_safe_file"

#ifndef RESERVED_PIDS
#define RESERVED_PIDS 300
#endif

#define NL_MAX_PAYLOAD 4096    /* netlink max payload we use */
#define NLMSGLEN NLMSG_SPACE(NL_MAX_PAYLOAD)
#define ARGS_LEN NL_MAX_PAYLOAD

/* 参考专用机的主审软件约定，默认使用24,25,31 */
#define NETLINK_SNIPER 24
#define OLD_NETLINK_SNIPER 30

/* msg number */
/* operation msg number */
#define NLMSG_REG                       0x40
#define NLMSG_EXEC                      0x41
#define NLMSG_NET                       0x42
#define NLMSG_FILE                      0x43
#define NLMSG_VIRUS                     0x44
#define NLMSG_MINENGINE  NLMSG_EXEC
#define NLMSG_MAXENGINE  NLMSG_VIRUS
#define NLMSG_CDROM_GID                 0x45
#define NLMSG_EXEC_LOADOFF              0x46
#define NLMSG_NET_LOADOFF               0x47
#define NLMSG_FILE_LOADOFF              0x48
#define NLMSG_SNIPER_INODE              0x49
#define NLMSG_CLIENT_MODE               0x50 //客户端模式：普通、学习、运维

/* process submsg number */
#define NLMSG_WAKEUP                    0x400
#define NLMSG_PMIDDLEWARE               0x401
#define NLMSG_PROCESS_RULES             0x402
#define NLMSG_BLACK_PROCESS             0x403
#define NLMSG_WHITE_PROCESS             0x404
#define NLMSG_TRUST_PROCESS             0x405
#define NLMSG_FILTER_PROCESS            0x406
#define NLMSG_COMMAND_TABLE             0x407
#define NLMSG_MINE_POOL                 0x408

/* file submsg number */
#define NLMSG_FILE_POLICY               0x500
#define NLMSG_FILE_SENSITIVE            0X501
#define NLMSG_FILE_LOG_DELETE           0X502
#define NLMSG_FILE_SAFE                 0x503
#define NLMSG_FILE_LOGCOLLECTOR         0x504
#define NLMSG_FILE_MIDDLE_TARGET        0x505
#define NLMSG_FILE_BINARY_FILTER	0x506
#define NLMSG_FILE_MIDDLE_SCRIPT	0x507
#define NLMSG_FILE_ILLEGAL_SCRIPT       0x508
#define NLMSG_FILE_WEBSHELL_DETECT      0x509
#define NLMSG_FILE_ENCRYPT              0x510
#define NLMSG_FILE_BLACK                0x511
#define NLMSG_FILE_FILTER               0x512
#define NLMSG_FILE_USB                  0x513
#define NLMSG_FILE_ENCRYPT_PROCESS      0x514

/* net submsg number */
#define NLMSG_NET_RULES                 0x600 //网络监控总开关、网络连接监控、域名监控、禁止互联网
#define NLMSG_NET_CONNECT_LIMIT         0x601 //端口连接数限制
#define NLMSG_NET_LANIP                 0x602 //特殊内网IP
#define NLMSG_NET_HONEYPORT             0x603 //诱捕端口
#define NLMSG_NET_HONEYPORT_FILTERIP    0x604 //端口诱捕过滤IP
#define NLMSG_NET_HONEYPORT_TRUSTIP     0x605 //端口诱捕可信IP
#define NLMSG_NET_DNSFILTER             0x606 //域名过滤名单
#define NLMSG_NET_DNSBLACK              0x607 //域名黑名单
#define NLMSG_NET_DNSWHITE              0x608 //域名白名单
#define NLMSG_NET_DNSTRUST              0x609 //域名可信名单
#define NLMSG_NET_WHITEIN               0x610 //连入白名单
#define NLMSG_NET_WHITEOUT              0x611 //连出白名单
#define NLMSG_NET_BLACKIN               0x612 //连入黑名单
#define NLMSG_NET_BLACKOUT              0x613 //连出黑名单
#define NLMSG_NET_CONNECTION_FILTERIP   0x614 //网络连接过滤IP
#define NLMSG_NET_SERVERIP              0x615 //管控中心IP
#define NLMSG_NET_LOCKIP                0x616 //锁IP
#define NLMSG_NET_HOSTQUARANTINE        0x617 //主机隔离，只允许与管控通信，最高优先级
#define NLMSG_NET_HONEYPORT_TRUSTIPV6   0x618 //端口诱捕可信IPv6

/* 进程过滤名单适用的日志类型。2是系统日志 */
#define PROCESS_FILTER_FOR_ALL     0
#define PROCESS_FILTER_FOR_PROCESS 1
#define PROCESS_FILTER_FOR_FILE    3
#define PROCESS_FILTER_FOR_NET     4

/* 用255表示解析错误的ip，不能用0，0已被用来表示匹配所有ip */
#define SNIPER_BADIP 255

/* 协议标志 */
#define SNIPER_TCP  0x1
#define SNIPER_UDP  0x2
#define SNIPER_ICMP 0x4

/* 连接方向 */
#define SNIPER_NETIN    1
#define SNIPER_NETOUT   2

/* 连接数限制是每IP限几个还是所有IP共限几个 */
#define SNIPER_LIMIT_SINGLEIP  1
#define SNIPER_LIMIT_MULTIIP   2

/* process common */
#define S_PROTOLEN      16
#define S_COMMLEN       16
#define S_TTYLEN        30  //之前保存到盘上的登录历史记录tty字段长度是30
#define S_SNLEN         32
#define S_IPLEN         64
#define S_PORTLEN       8
#define S_UUIDLEN       64
#define S_NAMELEN       64
#define S_CWDLEN        200 //128不够用，比如docker程序
#define S_CMDLEN        400
#define S_ARGSLEN       512
#define S_LINELEN       512
#define S_FILENAMELEN   1024
#define S_MD5LEN        33
#define S_SHALEN        65
#define S_CONNUUIDLEN   128
#define S_DIRLEN	256
#define S_DOMAIN_NAMELEN  256
#define S_PROCPATHLEN   512
#define S_SHORTPATHLEN  512
#define S_GRPLISTLEN	1024
#define S_CRACKNAMELEN   1024
#define S_PATHLEN	4096
#define S_URLLEN	128

//TODO PSR_XXX标志逐步废弃掉
#define PSR_TTY			0x1		//带终端
#define PSR_CRON		0x2		//定时任务
#define PSR_NETWORK		0x4		//带网络
#define PSR_EXEC		0x8		//exec钩子
#define PSR_STOPED		0x10		//危险命令已被阻断
#define PSR_KILLSNIPER		0x20		//非法中断sniper
#define PSR_DIRTYCOW		0x40		//脏牛
#define PSR_EXIT		0x80		//进程退出
#define PSR_PRIVUP		0x100		//提权
#define PSR_PRIVUP_FORK		0x200		//提权态下fork
#define PSR_PRIVUP_EXEC		0x400		//提权态下exec
#define PSR_WEBSHELL		0x800		//菜刀
#define PSR_WEBEXECUTE_NORMAL	0x1000		//web中间件执行普通命令
#define PSR_WEBEXECUTE_DANGER	0x2000		//web中间件执行危险命令
#define PSR_PIPEIN		0x4000		//管道入方
#define PSR_PIPEOUT		0x8000		//管道出方
#define PSR_TRUST		0x10000		//信任命令
#define PSR_BLACK		0x20000		//黑名单，或非白名单
#define PSR_FILTER		0x40000		//过滤命令
#define PSR_DANGER		0x80000		//危险命令
#define PSR_MINER		0x100000	//挖矿命令
#define PSR_DISK_READ		0x200000	//读打开盘设备
#define PSR_DISK_WRITE		0x400000	//写打开盘设备
#define PSR_WRITE_FORBIDDEN	0x800000	//禁止写
#define PSR_ELF32		0x1000000	//elf32格式命令
#define PSR_AOUT		0x2000000	//a.out格式命令
#define PSR_RANSOMWARE		0x4000000	//勒索软件
#define PSR_PORT_FORWARD	0x8000000	//端口转发
#define PSR_PHISHING		0x10000000	//钓鱼
#define PSR_REMOTE_EXECUTION	0x20000000	//远程执行
#define PSR_ABNORMAL		0x40000000	//异常程序，如在/tmp目录下的程序
#define PSR_DIRTYPIPE		0x80000000      //脏管道

/* 仅警告不阻断 */
#define PSR_WARNING_WEBEXECUTE	0x1		//web中间件
#define PSR_WARNING_PRIVILEGE	0x2		//提权

#define NSR_BLACKIN		0x1		//连入黑名单
#define NSR_BLACKOUT		0x2		//连出黑名单
#define NSR_BLACKIN_PORT	0x4		//连入黑名单之端口防护
#define NSR_BLACKOUT_PORT	0x8		//连出黑名单之端口防护
#define NSR_HONEYPORT		0x10		//端口捕获
#define NSR_LOCKEDIP		0x20		//已被锁的IP
#define NSR_INTERNET		0x40		//连接互联网
#define NSR_CONNLIMIT		0x80		//连接数量限制
#define NSR_FIREWALL_PROTECT	0x100		//禁止修改防火墙规则
#define NSR_BLACKDNS		0x200		//黑名单域名
#define NSR_MINEPOOL		0x400		//矿池

/* 事件类型标志位 */
#define EVENT_DetectedByUsers           0x1
#define EVENT_ReflectiveLoadingAttack   0x2
#define EVENT_ScriptBasedAttack         0x4
#define EVENT_ExsitingMalware           0x8
#define EVENT_DownloadExecution         0x10
#define EVENT_Mining                    0x20
#define EVENT_Ransomeware               0x40
#define EVENT_PrivilegeEscalation       0x80
#define EVENT_Chopper                   0x100
#define EVENT_Tunnel                    0x200
#define EVENT_FakeSystemProcess         0x400
#define EVENT_SensitiveProgram          0x800
#define EVENT_ServiceProcess            0x1000
#define EVENT_MBRAttack                 0x2000
#define EVENT_ReverseShell              0x4000
#define EVENT_Powershell                0x8000
#define EVENT_CommonProcess             0x10000
#define EVENT_SensitiveFile             0x20000
#define EVENT_PortScan                  0x40000
#define EVENT_HoneyPort                 0x80000
#define EVENT_RemoteLogin               0x100000
#define EVENT_RequestMaliciousDomain    0x200000
#define EVENT_DNSQuery                  0x400000
#define EVENT_LocalLogin                0x800000
#define EVENT_RiskCommand               0x1000000
#define EVENT_AbnormalProcess           0x2000000
#define EVENT_ExecutableFiles           0x4000000
#define EVENT_ScriptFiles               0x8000000
#define EVENT_IllegalScriptFiles        0x10000000
#define EVENT_Webshell_detect           0x20000000
#define EVENT_AntivirusProtection       0x40000000

/* 规则标志位 */
#define RULE_FLAG_PARAM_EQUAL   0x1
#define RULE_FLAG_PARAM_INCLUDE 0x2
#define RULE_FLAG_PARAM_EXCLUDE 0x4
#define RULE_FLAG_UID           0x8

/* sniper程序的inode号和所在的磁盘设备号 */
struct sniper_inode {
	unsigned int major;
	unsigned int minor;
	unsigned long ino;
};

struct task_flags {
	unsigned long tty : 1,
		     cron : 1,
		  network : 1,
		   pipein : 1,
		  pipeout : 1,
		     aout : 1,
		    elf32 : 1,
		shellcode : 1,
		   docker : 1,

		    trust : 1,
		    black : 1,
		  locking : 1,
		terminate : 1,
	   operation_mode : 1,

		     exec : 1,
		     exit : 1,
		     fork : 1,
		 dirtycow : 1,
		dirtypipe : 1,
		     kill : 1,
	       killsniper : 1,
	     modifysniper : 1,
		   privup : 1,
	      privup_suid : 1,
	   privup_notsuid : 1,
	privup_notsyssuid : 1,
	      privup_exec : 1,
	      privup_file : 1,
	    privup_parent : 1,

		   danger : 1,
		 abnormal : 1,
	      remote_exec : 1,
		 webshell : 1,
		    miner : 1,
		 minepool : 1,
	     port_forward : 1,
	   webexec_normal : 1,
	   webexec_danger : 1,
	       ransomware : 1,
		 phishing : 1,

		 readdisk : 1,
		writedisk : 1,

	      commandline : 1,
		    shell : 1,
	shell_nologinuser : 1,
	  program_changed : 1;
};

#ifdef __KERNEL__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
struct timeval {
		__kernel_old_time_t	tv_sec;		/* seconds */
		__kernel_suseconds_t	tv_usec;	/* microseconds */
};
typedef __kernel_long_t time_t;
#endif
#endif

#define SNIPER_PGEN 8
struct task_simple_info {
	uid_t uid;
	uid_t euid;
	pid_t pid;
	int did_exec;
	char comm[S_COMMLEN];
	unsigned long proctime; //进程创建时间，作为进程标识
};
struct parent_info {
	struct task_simple_info task[SNIPER_PGEN];
};
struct task_request { //size 656
	uid_t uid;
	uid_t euid;
	pid_t pid;
	pid_t tgid;
	struct parent_info pinfo;
	unsigned long proctime;   //进程创建时间，作为进程标识
	struct timeval event_tv;  //进程事件时间，比如进程执行命令的时刻
	unsigned short size;      //包的总大小: 头+命令参数信息
	unsigned short trust_event_id;
	unsigned short cmdlen;
	unsigned short argslen;
	unsigned short cwdlen;
	unsigned short options;
	unsigned short argc;
	unsigned short argv0len;
	unsigned int trust_events;
	unsigned int flags;
	struct task_flags pflags;
	unsigned long pipein;
	unsigned long pipeout;
	unsigned long exeino;
	struct file *exe_file;
	union {
		pid_t webmid_pid;          //执行命令的网络中间件
		pid_t root_pid;            //使用提权后特权的进程
	};
	unsigned short webmid_port;
	char ip[S_IPLEN];
	char tty[S_TTYLEN];
	char nodename[S_NAMELEN+1];
	char md5[S_MD5LEN];
	char target_cmd[S_COMMLEN];        //保存中间件名或提权执行的命令
	char args;
};
typedef struct task_request taskreq_t;

// NOTE(luoyinhong): should be consistent with sniper-ebpf/structs.h

struct ebpf_task_simple_info {
	uid_t uid;
	uid_t euid;
	pid_t pid;
	int did_exec;
	char comm[16];
	unsigned long proctime; //进程创建时间，作为进程标识
};


struct ebpf_parent_info {
	struct ebpf_task_simple_info task[4];
};

struct ebpf_taskreq_t {
	int uid;       // The user id.
	int pid;       // The process id.
	int ppid;      // parent process id
	unsigned int euid;      // effective user id.
	int tgid;      // Thread Group id.buf
	unsigned long proctime;      // the time that process started.
	unsigned long pipein;        // The pipe used to input.
	unsigned long pipeout;       // The pipe used to output.
	unsigned long exeino;        // ???
	unsigned short cmdlen;
	unsigned short argslen;
	unsigned short cwdlen;
	unsigned short argc;         // the number of the arguments.
	unsigned short options;      // the number of the arguments starting with "-".
	unsigned int mnt_id;
	struct ebpf_parent_info pinfo;    // The parent processes information (Up to 4 generations).
	struct file *exe_file;       // ???
	char comm[16];
	char tty[S_TTYLEN];
	char nodename[S_NAMELEN+1];
	char cmd[S_CMDLEN];
	char cwd[S_CWDLEN];
	char args[8][32];           // Used to store the arguments, max 8.
};

/*operate_file_type*/
#define OP_OPEN 1
#define OP_CLOSE 2
#define OP_UNLINK 3
#define OP_RENAME 4
#define OP_LINK 5
#define OP_SYMLINK 6
#define OP_READ 7
#define OP_WRITE 8
#define OP_OPEN_W 9
#define OP_OPEN_C 10
#define OP_OPEN_R 11

#define OP_OPEN_FIREWALL 18
#define OP_UNLINK_FIREWALL 19
#define OP_RENAME_FIREWALL 20
#define OP_WRITE_FIREWALL 21
#define OP_SYMLINK_FIREWALL 22
#define MAX_SNIPER_FILEOP 24

#define F_SENSITIVE             1
#define F_LOG_DELETE		2
#define F_SAFE                  3
#define F_LOGCOLLECTOR		4
#define F_MIDDLE_TARGET		5
#define F_BINARY_FILTER		6
#define F_MIDDLE_SCRIPT		7
#define F_ILLEGAL_SCRIPT	8
#define F_WEBSHELL_DETECT       9
#define F_PRINTER               10
#define F_CDROM                 11
#define F_ENCRYPT_BACKUP        12
#define F_ENCRYPT_REPORT        13
#define F_ENCRYPT               14
#define F_BLACK_AFTER           15
#define F_ABNORMAL              16
#define F_USB                   17
#define F_VIRUS                 18

#define NET_MPORT_SCAN          0x01
#define NET_MHONEY_PORT         0x02
#define NET_MODULE_ALL          0x03

extern char sniper_fileop[MAX_SNIPER_FILEOP][S_NAMELEN];

struct file_request {
	uid_t uid;
	pid_t pid;
	int did_exec;
	struct ebpf_parent_info pinfo;
	unsigned long proctime;
	struct timeval event_tv;
	unsigned short op_type;  //1:open 2:close 3:unlink 4:rename 5:symlink
	unsigned short type;     //1:sensitive 2:log_delete 3:safe 4:logcollector
	unsigned short size;     //request size: head + args
	char parent_comm[S_COMMLEN];
	char md5[S_MD5LEN];
	char tty[S_TTYLEN];
	unsigned short path_len;
	unsigned short pro_len;
	unsigned short newpath_len;
	loff_t file_size;
	loff_t newfile_size;
	unsigned int peerip;
	int terminate;
	int is_trust;
	long mtime_sec;
	long mtime_nsec;
	char args;
};
typedef struct file_request filereq_t;

struct ebpf_filereq_t {
	uid_t uid;       // The user id.
	int tgid;      // The Thread Group id.
	pid_t pid;       // The process id.
	// int did_exec;  // The flag that whether a file is over.
	// struct my_timeval event_tv;
	unsigned long proctime;      // the time that process started.
	// unsigned long pipein;        // The pipe used to input.
	// unsigned long pipeout;       // The pipe used to output.
	// unsigned long exeino;        // ???
	// struct file *exe_file;       // ???
	unsigned short op_type;      // The file operation (1:open 2:close 3:unlink 4:rename 5:symlink)
	unsigned short type;         // 1:sensitive 2:log_delete 3:safe 4:logcollector
	unsigned short size;         // request size: head + args
	unsigned int mode;
	unsigned int flags;
	unsigned int mnt_id;
	long mtime_sec;              // The mtime of the file, unit is second.
	long mtime_nsec;             // The mtime of the filem unit is nanosecond.
	long long int file_size;
	long long int newfile_size;
	struct parent_info pinfo;    // The parent processes information (Up to 4 generations).
	char filename[64];
	unsigned int path_len;
	char new_filename[64];
	unsigned int newpath_len;
	char pro_pathname[64];
	unsigned int pro_len;
	int terminate;               // Been Abandoned, used to Judge whether the Block is needed.
	char tty[S_TTYLEN];
	char nodename[S_NAMELEN+1];
	// char cmd[S_CMDLEN];
	// char cwd[S_CWDLEN];
	char args[8][64];            // Used to store the arguments.
	char comm[16];
	char parent_comm[16];
	int argc;
};

struct sniper_ip {
	unsigned char ip[4];
};

struct sniper_ipv6 {
	unsigned char ipv6[16];
};

#define IPSTR(IP) (IP)->ip[0],(IP)->ip[1],(IP)->ip[2],(IP)->ip[3]
#define IPV6STR(IP) (IP)->ipv6[0],(IP)->ipv6[1],(IP)->ipv6[2],(IP)->ipv6[3],(IP)->ipv6[4], \
	(IP)->ipv6[5],(IP)->ipv6[6],(IP)->ipv6[7],(IP)->ipv6[8],(IP)->ipv6[9], \
	(IP)->ipv6[10],(IP)->ipv6[11],(IP)->ipv6[12],(IP)->ipv6[13],(IP)->ipv6[14], (IP)->ipv6[15]
#define MACSTR(MAC) (MAC)[0],(MAC)[1],(MAC)[2],(MAC)[3],(MAC)[4],(MAC)[5]

struct net_flags {
	unsigned long      blackin : 1,
			  blackout : 1,
			notwhitein : 1,
		       notwhiteout : 1,
			 honeyport : 1,
			  portscan : 1,
			  lockedip : 1, //指示这是已经被锁的ip，事件类型为非法网络连接
			  internet : 1,
			    domain : 1,
		       blackdomain : 1,
			  minepool : 1,

		 blackin_terminate : 1,
		blackout_terminate : 1,
	       honeyport_terminate : 1,
		portscan_terminate : 1,
		lockedip_terminate : 1,
		internet_terminate : 1,
	     blackdomain_terminate : 1,
		minepool_terminate : 1,

			     trust : 1,
			   locking : 1, //指示事件的防御动作包括了锁ip
			 terminate : 1,
			       tty : 1,
			       tcp : 1,
			       udp : 1,
			      icmp : 1,

			    lockip : 1, //发锁ip消息时使用
			  unlockip : 1; //发解锁ip消息时使用
};
struct net_request {
	uid_t uid;
	pid_t pid;
	pid_t tgid;
	char comm[S_COMMLEN];
	unsigned short size; //包的总大小: 头+命令参数信息
	struct ebpf_parent_info pinfo;
	unsigned long exeino;
	unsigned long proctime; //进程创建时间，作为进程标识
	struct timeval event_tv;  //事件时间，比如进行连接的时刻
	struct net_flags flags;
	unsigned short sport;
	unsigned short dport;
	struct sniper_ip srcip;
	struct sniper_ip dstip;
	struct sniper_ipv6 srcipv6;
	struct sniper_ipv6 dstipv6;
	unsigned int repeat;
	int domain_query_type;
	unsigned int effective_time; // 端口扫描超限时间
	unsigned int portscan_lockip_time; // 端口扫描超限远程IP锁定时间
	unsigned int portscan_max;   // 最大端口扫描数量
	unsigned int honey_lockip_time; //端口诱捕锁定IP时间
	unsigned int ports_count;    // 端口扫描次数
	unsigned short reason;
	char ip[S_IPLEN];
	char domain[S_DOMAIN_NAMELEN];
};
typedef struct net_request netreq_t;

struct ebpf_netreq_t {
	unsigned char comm[16];
	unsigned short sport; // __u16
	unsigned short dport; // __be16
	unsigned int saddr;   // __be32
	unsigned int daddr;   // __be32
	unsigned int pid;     // __u32
	unsigned char  containerid[32];
};

struct port_scan {
	unsigned long effective_time; // 端口扫描超限时间
	unsigned long first_time; // 端口扫描初始时间
	unsigned int portscan_lockip_time; // 端口扫描超限远程IP锁定时间
	unsigned int portscan_max;   // 最大端口扫描数量
	unsigned int ports_count;    // 已记录的端口数量
	unsigned int ports[0];
};
typedef struct port_scan pscan_t;

#define KILL_DANGEROUS_WEBEXE 1
#define KILL_WEBEXE 2
struct kern_process_rules {
	unsigned long	process_engine_on : 1,

				normal_on : 1,
				danger_on : 1,
			      abnormal_on : 1,
			     privilege_on : 1,
			remote_execute_on : 1, //即反弹shell
			      webshell_on : 1, //目前仅监控中国菜刀
				   mbr_on : 1,
				 miner_on : 1,
			  port_forward_on : 1,
			    webexecute_on : 1, //似乎多余
		     normal_webexecute_on : 1,
		     danger_webexecute_on : 1,
		       fake_sysprocess_on : 1,

			      danger_kill : 1,
			    abnormal_kill : 1,
			   privilege_kill : 1,
		      remote_execute_kill : 1,
			    webshell_kill : 1,
				 mbr_kill : 1,
			       miner_kill : 1,
			port_forward_kill : 1,
		   normal_webexecute_kill : 1,
		   danger_webexecute_kill : 1,
		     fake_sysprocess_kill : 1,
			       black_kill : 1,
			   not_white_kill : 1, //考虑用于仅告警不阻断的学习

		    remote_execute_lockip : 1,
			  webshell_lockip : 1,
			     miner_lockip : 1;

	unsigned short webmiddle_count;
	unsigned short command_count;
	unsigned short black_count;
	unsigned short filter_count;
	unsigned short trust_count;
	unsigned short minepool_count;
	unsigned short miner_lockip_seconds;
	unsigned short remote_execute_lockip_seconds;
};

struct kern_file_rules {
	unsigned int    operation_on;
	char usb_types[256];            // |doc||xls||ppt||pptx|
	char doc_types[256];            // |doc||xls||ppt||pptx|
	char midd_procs[256];           // |apache||httpd||mysqld||scp|
	unsigned short important_path_num;
	unsigned short important_link_num;
	unsigned short control_num;
	unsigned short illegal_script_num;
	unsigned short illegal_link_num;
	unsigned short black_file_num;
	unsigned int    file_engine_on : 1,
			 file_black_on : 1,
		     file_important_on : 1,
			   file_usb_on : 1,
		       file_control_on : 1,
			   file_doc_on : 1,
			  file_midd_on : 1,
		file_illegal_script_on : 1;
};

/* 有count的，count非0表示watch */
struct kern_net_rules {
	unsigned int    net_engine_on : 1,

			    dns_watch : 1,
		       internet_watch : 1,
		     connection_watch : 1,

			   dns_reject : 1,
		      internet_reject : 1,
		     honeyport_reject : 1,
		    blackwhite_reject : 1,

		     honeyport_lockip : 1,
		     port_scan_lockip : 1,
	       illegal_conn_terminate : 1,
		       local_dnsproxy : 1; //本地dns代理X，如dnsmasq。dns请求统一发给X，由X去查询并返回结果

	unsigned short connection_filterip_count;
	unsigned short sshlogin_filterip_count;
	unsigned short lanip_count;
	unsigned short honeyport_count;
	unsigned short honeyport_filterip_count;
	unsigned short honeyport_trustip_count;
	unsigned short honeyport_trustipv6_count;
	unsigned short dnsfilter_count;
	unsigned short dnsblack_count;
	unsigned short dnsmalicious_count;
	unsigned short dnswhite_count;
	unsigned short dnstrust_count;
	unsigned short whitein_count;
	unsigned short whiteout_count;
	unsigned short blackin_count;
	unsigned short blackout_count;

	unsigned char myip_count;
	unsigned char server_count;
	unsigned short listenport_count;
	unsigned short zipterm; //默认是压缩一分钟内的日志，可调整
	unsigned int portscan_time; // 单个IP端口扫描时间范围
	unsigned int portscan_max;  // 最大端口扫描端口数量
	unsigned int portscan_lock_time; // 恶意IP端口扫描锁定时间
	unsigned int honey_lockip_seconds; /* 端口诱捕IP锁定时间 */

	pid_t dnsproxy_pid;
	char dnsproxy[S_COMMLEN]; //本地dns代理
};

struct important_link_length{
	unsigned short pathlen;
	unsigned short extlen;
};
#define FILE_LINK_MAX  20

struct sniper_iprange {
	struct sniper_ip fromip;
	struct sniper_ip toip;
	int type;
};
#define sniper_ipmask toip.ip[1]

struct sniper_connrule {
	unsigned short fromport;
	unsigned short toport;
	unsigned short tcp : 1,
		       udp : 1,
		      icmp : 1;
	struct sniper_iprange ipr;
};

/* active表示主机当前正在使用此服务器，同时只能有一个active的服务器
   防止备用服务器被利用来通过指定端口攻击本机，有这种可能吗?
   应该有可能，比如对方通过修改发送的包来固定用8000端口扫描本机 */
struct sniper_server {
	struct sniper_ip ip;
	unsigned short port;
	unsigned short wsport; //websocket port
	int active;
};
struct sniper_server_ipv6 {
	struct sniper_ipv6 ipv6;
	unsigned short port;
	unsigned short wsport; //websocket port
	int active;
};

struct sniper_lockip {
	struct sniper_ip ip;
	unsigned int reason;
	time_t lock_time;
};

#define MID_SET   1   //设置中间件信息
#define MID_CLOSE 2   //删除中间件信息
#define SNIPER_MIDDLEWARE_NUM 256   //最多考察256个监听端口，64个不够，看到有接近128的，装了多个容器
struct sniper_middleware {
	char name[S_COMMLEN];  //中间件名
	unsigned short port;   //中间件监听的端口
	pid_t pid;             //中间件进程号
	int fd;                //监听端口对应的fd
	int action;            //设置或删除中间件信息
	unsigned long ino;     //监听端口socket对应的inode号
};

struct kern_file_policy {
	unsigned int       file_engine_on : 1, //总开关
			file_sensitive_on : 1, //敏感文件
		      file_sensitive_kill : 1, //敏感文件阻断
			  file_log_delete : 1, //日志异常删除
			     file_safe_on : 1, //文件防篡改
		     file_logcollector_on : 1, //文件行为采集
			   file_middle_on : 1, //中间件识别
		    file_middle_binary_on : 1, //可执行文件识别
	       file_middle_binary_exclude : 1, //可执行文件过滤
	     file_middle_binary_terminate : 1, //可执行文件识别阻断
		    file_middle_script_on : 1, //脚本文件识别
	     file_middle_script_terminate : 1, //脚本文件识别阻断
		   file_illegal_script_on : 1, //非法脚本识别
	    file_illegal_script_terminate : 1, //非法脚本识别阻断
		  file_webshell_detect_on : 1, //webshell文件检测
	   file_webshell_detect_terminate : 1, //webshell文件阻断
			       printer_on : 1, //打印监控开关
			printer_terminate : 1, //打印监控禁止
				 cdrom_on : 1, //刻录监控开关
			  cdrom_terminate : 1, //刻录监控禁止
			       encrypt_on : 1, //勒索加密防护开关
			encrypt_terminate : 1, //勒索加密防护禁止
			encrypt_backup_on : 1, //勒索加密防护文件备份开关
		       encrypt_space_full : 1, //勒索加密防护文件备份空间是否已满
			  encrypt_hide_on : 1, //勒索加密防护隐藏诱捕文件开关
			      usb_file_on : 1, //usb文件监控开关
			     antivirus_on : 1; //病毒防护开关

	unsigned short sensitive_count;
	unsigned short log_delete_count;
	unsigned short safe_count;
	unsigned short logcollector_count;
	unsigned short illegal_script_count;
	unsigned short webshell_detect_count;
	unsigned short printer_count;
	unsigned short cdrom_count;
	unsigned short black_count;
	unsigned short filter_count;
	unsigned short usb_count;
	unsigned int neglect_min;
	unsigned int neglect_size;
};

#endif
