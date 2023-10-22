#ifndef _KERN_USER_COMMON_H_
#define _KERN_USER_COMMON_H_

#include "vendor_sniper.h"
#define ANTIVIRUS_VER   		"5.0.9.0708"  			// 病毒防护软件版本号

#define NORMAL_MODE             0  						// 正常模式，在代码中用非零值判断是否为运维或学习模式，不要修改NORMAL_MODE的值
#define OPERATION_MODE          1  						// 运维模式
#define LEARNING_MODE           2  						// 学习模式

#define UNINSTALL_DISABLE       "/opt/snipercli/sniper_uninstall_disable"  		// 禁止卸载的文件路径
#define AVIRA_ENABLE            "/opt/snipercli/avira_enable"  					// 启用Avira的文件路径
#define FORCE_UNINSTALL         "/tmp/.sniper_b4n6WEmbst"  						// 强制卸载的文件路径
#define BACKUP_DIR              "/opt/snipercli/.filebackup"  					// 文件备份目录路径
#define TRAP_FILE_NOHIDE        "sniper_safe_file"  							// 未隐藏的陷阱文件名
#define TRAP_FILE_HIDE          ".sniper_safe_file"  							// 隐藏的陷阱文件名

#ifndef RESERVED_PIDS															// 保留的进程ID数量
#define RESERVED_PIDS 			300  
#endif

#define NL_MAX_PAYLOAD 			4096    										// Netlink消息的最大有效载荷大小
#define NLMSGLEN 				NLMSG_SPACE(NL_MAX_PAYLOAD)  					// Netlink消息的总长度
#define ARGS_LEN 				NL_MAX_PAYLOAD  								// 参数的最大长度

/* 参考专用机的主审软件约定，默认使用24,25,31 */
#define NETLINK_SNIPER 			24  // Sniper程序的Netlink协议号
#define OLD_NETLINK_SNIPER 		30  // 旧版本Sniper程序的Netlink协议号

/* 消息编号 */
/* 操作消息编号 */
#define NLMSG_REG                       0x40  // 注册消息
#define NLMSG_EXEC                      0x41  // 执行消息
#define NLMSG_NET                       0x42  // 网络消息
#define NLMSG_FILE                      0x43  // 文件消息
#define NLMSG_VIRUS                     0x44  // 病毒消息
#define NLMSG_MINENGINE  				NLMSG_EXEC  // 最小的引擎消息编号
#define NLMSG_MAXENGINE  				NLMSG_VIRUS  // 最大的引擎消息编号
#define NLMSG_CDROM_GID                 0x45  // CDROM组ID消息
#define NLMSG_EXEC_LOADOFF              0x46  // 执行消息加载偏移量
#define NLMSG_NET_LOADOFF               0x47  // 网络消息加载偏移量
#define NLMSG_FILE_LOADOFF              0x48  // 文件消息加载偏移量
#define NLMSG_SNIPER_INODE              0x49  // Sniper程序的inode号消息
#define NLMSG_CLIENT_MODE               0x50  // 客户端模式：普通、学习、运维

/* 进程子消息编号 */
#define NLMSG_WAKEUP                    0x400  // 唤醒子消息
#define NLMSG_PMIDDLEWARE               0x401  // 中间件子消息
#define NLMSG_PROCESS_RULES             0x402  // 进程规则子消息
#define NLMSG_BLACK_PROCESS             0x403  // 黑名单进程子消息
#define NLMSG_WHITE_PROCESS             0x404  // 白名单进程子消息
#define NLMSG_TRUST_PROCESS             0x405  // 信任进程子消息
#define NLMSG_FILTER_PROCESS            0x406  // 过滤进程子消息
#define NLMSG_COMMAND_TABLE             0x407  // 命令表子消息
#define NLMSG_MINE_POOL                 0x408  // 矿池子消息

/* 文件子消息编号 */
#define NLMSG_FILE_POLICY               0x500  // 文件策略子消息
#define NLMSG_FILE_SENSITIVE            0X501  // 敏感文件子消息
#define NLMSG_FILE_LOG_DELETE           0X502  // 日志删除子消息
#define NLMSG_FILE_SAFE                 0x503  // 文件安全子消息
#define NLMSG_FILE_LOGCOLLECTOR         0x504  // 文件行为采集子消息
#define NLMSG_FILE_MIDDLE_TARGET        0x505  // 中间件目标子消息
#define NLMSG_FILE_BINARY_FILTER		0x506  // 二进制文件过滤子消息
#define NLMSG_FILE_MIDDLE_SCRIPT		0x507  // 中间件脚本子消息
#define NLMSG_FILE_ILLEGAL_SCRIPT       0x508  // 非法脚本文件子消息
#define NLMSG_FILE_WEBSHELL_DETECT      0x509  // WebShell检测子消息
#define NLMSG_FILE_ENCRYPT              0x510  // 文件加密子消息
#define NLMSG_FILE_BLACK                0x511  // 文件黑名单子消息
#define NLMSG_FILE_FILTER               0x512  // 文件过滤子消息
#define NLMSG_FILE_USB                  0x513  // USB文件子消息
#define NLMSG_FILE_ENCRYPT_PROCESS      0x514  // 文件加密进程子消息

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
#define PROCESS_FILTER_FOR_ALL     		0   // 适用于所有日志类型
#define PROCESS_FILTER_FOR_PROCESS 		1   // 适用于进程日志类型
#define PROCESS_FILTER_FOR_FILE    		3   // 适用于文件日志类型
#define PROCESS_FILTER_FOR_NET     		4   // 适用于网络日志类型

/* 用255表示解析错误的ip，不能用0，0已被用来表示匹配所有ip */
#define SNIPER_BADIP 					255 // 表示解析错误的IP地址

/* 协议标志 */
#define SNIPER_TCP  					0x1 // TCP协议标志
#define SNIPER_UDP  					0x2 // UDP协议标志
#define SNIPER_ICMP 					0x4 // ICMP协议标志

/* 连接方向 */
#define SNIPER_NETIN    				1   // 连接方向为进入系统
#define SNIPER_NETOUT   				2   // 连接方向为从系统出去

/* 连接数限制是每IP限几个还是所有IP共限几个 */
#define SNIPER_LIMIT_SINGLEIP  			1   // 每个IP限制的连接数
#define SNIPER_LIMIT_MULTIIP   			2   // 所有IP共同限制的连接数

/* process common */
#define S_PROTOLEN      				16  	// 协议名称长度
#define S_COMMLEN       				16  	// 进程名称长度
#define S_TTYLEN        				30  	// 终端设备名称长度（登录历史记录中的tty字段长度为30）
#define S_SNLEN         				32  	// 序列号长度
#define S_IPLEN         				64  	// IP地址长度
#define S_PORTLEN       				8   	// 端口号长度
#define S_UUIDLEN       				64  	// UUID长度
#define S_NAMELEN       				64  	// 名称长度
#define S_CWDLEN        				200 	// 当前工作目录路径长度（用于docker程序）
#define S_CMDLEN        				400 	// 命令行长度
#define S_ARGSLEN       				512 	// 参数长度
#define S_LINELEN       				512 	// 行长度
#define S_FILENAMELEN   				1024 	// 文件名长度
#define S_MD5LEN        				33  	// MD5值长度
#define S_SHALEN        				65  	// SHA值长度
#define S_CONNUUIDLEN   				128 	// 连接UUID长度
#define S_DIRLEN						256 	// 目录路径长度
#define S_DOMAIN_NAMELEN  				256 	// 域名长度
#define S_PROCPATHLEN   				512 	// 进程路径长度
#define S_SHORTPATHLEN  				512 	// 短路径长度
#define S_GRPLISTLEN					1024 	// 组列表长度
#define S_CRACKNAMELEN   				1024 	// 破解软件名称长度
#define S_PATHLEN						4096 	// 路径长度
#define S_URLLEN						128 	// URL长度

//TODO PSR_XXX标志逐步废弃掉
#define PSR_TTY							0x1			//带终端
#define PSR_CRON						0x2			//定时任务
#define PSR_NETWORK						0x4			//带网络
#define PSR_EXEC						0x8			//exec钩子
#define PSR_STOPED						0x10		//危险命令已被阻断
#define PSR_KILLSNIPER					0x20		//非法中断sniper
#define PSR_DIRTYCOW					0x40		//脏牛
#define PSR_EXIT						0x80		//进程退出
#define PSR_PRIVUP						0x100		//提权
#define PSR_PRIVUP_FORK					0x200		//提权态下fork
#define PSR_PRIVUP_EXEC					0x400		//提权态下exec
#define PSR_WEBSHELL					0x800		//菜刀
#define PSR_WEBEXECUTE_NORMAL			0x1000		//web中间件执行普通命令
#define PSR_WEBEXECUTE_DANGER			0x2000		//web中间件执行危险命令
#define PSR_PIPEIN						0x4000		//管道入方
#define PSR_PIPEOUT						0x8000		//管道出方
#define PSR_TRUST						0x10000		//信任命令
#define PSR_BLACK						0x20000		//黑名单，或非白名单
#define PSR_FILTER						0x40000		//过滤命令
#define PSR_DANGER						0x80000		//危险命令
#define PSR_MINER						0x100000	//挖矿命令
#define PSR_DISK_READ					0x200000	//读打开盘设备
#define PSR_DISK_WRITE					0x400000	//写打开盘设备
#define PSR_WRITE_FORBIDDEN				0x800000	//禁止写
#define PSR_ELF32						0x1000000	//elf32格式命令
#define PSR_AOUT						0x2000000	//a.out格式命令
#define PSR_RANSOMWARE					0x4000000	//勒索软件
#define PSR_PORT_FORWARD				0x8000000	//端口转发
#define PSR_PHISHING					0x10000000	//钓鱼
#define PSR_REMOTE_EXECUTION			0x20000000	//远程执行
#define PSR_ABNORMAL					0x40000000	//异常程序，如在/tmp目录下的程序
#define PSR_DIRTYPIPE					0x80000000  //脏管道
#define PSR_RequestMaliciousDomain		0x90000000  //请求恶意域名事件



/* 仅警告不阻断 */
#define PSR_WARNING_WEBEXECUTE			0x1		//web中间件
#define PSR_WARNING_PRIVILEGE			0x2		//提权

#define NSR_BLACKIN						0x1		//连入黑名单
#define NSR_BLACKOUT					0x2		//连出黑名单
#define NSR_BLACKIN_PORT				0x4		//连入黑名单之端口防护
#define NSR_BLACKOUT_PORT				0x8		//连出黑名单之端口防护
#define NSR_HONEYPORT					0x10	//端口捕获
#define NSR_LOCKEDIP					0x20	//已被锁的IP
#define NSR_INTERNET					0x40	//连接互联网
#define NSR_CONNLIMIT					0x80	//连接数量限制
#define NSR_FIREWALL_PROTECT			0x100	//禁止修改防火墙规则
#define NSR_BLACKDNS					0x200	//黑名单域名
#define NSR_MINEPOOL					0x400	//矿池

/* 事件类型标志位 */
#define EVENT_DetectedByUsers           0x1   		// 被用户检测到的事件
#define EVENT_ReflectiveLoadingAttack   0x2   		// 反射加载攻击事件
#define EVENT_ScriptBasedAttack         0x4   		// 基于脚本的攻击事件
#define EVENT_ExsitingMalware           0x8   		// 现有恶意软件事件
#define EVENT_DownloadExecution         0x10  		// 下载执行事件
#define EVENT_Mining                    0x20  		// 挖矿事件
#define EVENT_Ransomeware               0x40  		// 勒索软件事件
#define EVENT_PrivilegeEscalation       0x80  		// 权限提升事件
#define EVENT_Chopper                   0x100 		// Chopper事件
#define EVENT_Tunnel                    0x200 		// 隧道事件
#define EVENT_FakeSystemProcess         0x400 		// 伪造系统进程事件
#define EVENT_SensitiveProgram          0x800 		// 敏感程序事件
#define EVENT_ServiceProcess            0x1000 		// 服务进程事件
#define EVENT_MBRAttack                 0x2000 		// MBR攻击事件
#define EVENT_ReverseShell              0x4000 		// 反向Shell事件
#define EVENT_Powershell                0x8000 		// Powershell事件
#define EVENT_CommonProcess             0x10000 	// 通用进程事件
#define EVENT_SensitiveFile             0x20000 	// 敏感文件事件
#define EVENT_PortScan                  0x40000 	// 端口扫描事件
#define EVENT_HoneyPort                 0x80000 	// Honey Port事件
#define EVENT_RemoteLogin               0x100000 	// 远程登录事件
#define EVENT_RequestMaliciousDomain    0x200000 	// 请求恶意域名事件
#define EVENT_DNSQuery                  0x400000 	// DNS查询事件
#define EVENT_LocalLogin                0x800000 	// 本地登录事件
#define EVENT_RiskCommand               0x1000000 	// 风险命令事件
#define EVENT_AbnormalProcess           0x2000000 	// 异常进程事件
#define EVENT_ExecutableFiles           0x4000000 	// 可执行文件事件
#define EVENT_ScriptFiles               0x8000000 	// 脚本文件事件
#define EVENT_IllegalScriptFiles        0x10000000 	// 非法脚本文件事件
#define EVENT_Webshell_detect           0x20000000 	// WebShell检测事件
#define EVENT_AntivirusProtection       0x40000000 	// 病毒防护事件

/* 规则标志位 */
#define RULE_FLAG_PARAM_EQUAL   		0x1   // 参数相等规则标志
#define RULE_FLAG_PARAM_INCLUDE 		0x2   // 参数包含规则标志
#define RULE_FLAG_PARAM_EXCLUDE 		0x4   // 参数排除规则标志
#define RULE_FLAG_UID           		0x8   // UID规则标志

/* sniper程序的inode号和所在的磁盘设备号 */
struct sniper_inode {
	unsigned int major;       // 磁盘设备号的主设备号
	unsigned int minor;       // 磁盘设备号的次设备号
	unsigned long ino;        // inode号
};


struct task_flags {
	unsigned long 	tty					: 1,    // 终端设备标志
					cron				: 1,    // cron任务标志
					network				: 1,    // 网络操作标志
					pipein 				: 1,    // 输入管道标志
					pipeout 			: 1,    // 输出管道标志
					aout 				: 1,    // a.out文件标志
					elf32 				: 1,    // ELF32文件标志
					shellcode 			: 1,    // shellcode标志
					docker 				: 1,    // Docker标志

					trust 				: 1,    // 信任标志
					black 				: 1,    // 黑名单标志
					locking 			: 1,    // 锁定标志
					terminate 			: 1,    // 终止标志
					operation_mode 		: 1,    // 操作模式标志

					exec 				: 1,    // 执行标志
					exit 				: 1,    // 退出标志
					fork 				: 1,    // fork标志
					dirtycow 			: 1,    // Dirty COW标志
					dirtypipe 			: 1,    // Dirty Pipe标志
					kill 				: 1,    // Kill标志
					killsniper 			: 1,    // Kill Sniper标志
					modifysniper 		: 1,    // 修改Sniper标志
					privup 				: 1,    // 提权标志
					privup_suid 		: 1,    // 提权(SUID)标志
					privup_notsuid 		: 1,    // 提权(非SUID)标志
					privup_notsyssuid 	: 1,    // 提权(非SUID、非SYSSUID)标志
					privup_exec 		: 1,    // 提权(执行程序)标志
					privup_file 		: 1,    // 提权(文件)标志
					privup_parent 		: 1,    // 提权(父进程)标志

					danger 				: 1,    // 危险操作标志
					abnormal 			: 1,    // 异常操作标志
					remote_exec 		: 1,    // 远程执行标志
					webshell 			: 1,    // WebShell标志
					miner 				: 1,    // 挖矿标志
					minepool 			: 1,    // 挖矿池标志
					port_forward 		: 1,    // 端口转发标志
					webexec_normal 		: 1,    // Web执行(正常)标志
					webexec_danger 		: 1,    // Web执行(危险)标志
					ransomware 			: 1,    // 勒索软件标志
					phishing 			: 1,    // 钓鱼攻击标志

					readdisk 			: 1,    // 读磁盘标志
					writedisk 			: 1,    // 写磁盘标志

					commandline 		: 1,    // 命令行标志
					shell 				: 1,    // Shell标志
					shell_nologinuser 	: 1,    // Shell(非登录用户)标志
					program_changed 	: 1;    // 程序变更标志
};

#define SNIPER_PGEN 8  					// 父进程信息中最大的父进程数量

struct task_simple_info {
	uid_t uid;              			// 用户ID
	uid_t euid;             			// 有效用户ID
	pid_t pid;             			 	// 进程ID
	int did_exec;           			// 标志进程是否执行过exec操作
	char comm[S_COMMLEN];   			// 进程的命令名
	unsigned long proctime; 			// 进程创建时间，用作进程标识
};

struct parent_info {
	struct task_simple_info task[SNIPER_PGEN];  // 父进程信息数组，保存最多SNIPER_PGEN个父进程的信息
};


struct task_request {
    uid_t uid;                    // 用户ID
    uid_t euid;                   // 有效用户ID
    pid_t pid;                    // 进程ID
    pid_t tgid;                   // 线程组ID
    struct parent_info pinfo;     // 父进程信息
    unsigned long proctime;       // 进程创建时间，作为进程标识
    struct timeval event_tv;      // 进程事件时间，比如进程执行命令的时刻
    unsigned short size;          // 包的总大小: 头+命令参数信息
    unsigned short trust_event_id;// 信任事件ID
    unsigned short cmdlen;        // 命令长度
    unsigned short argslen;       // 参数长度
    unsigned short cwdlen;        // 当前工作目录长度
    unsigned short options;       // 选项
    unsigned short argc;          // 参数个数
    unsigned short argv0len;      // 参数0的长度
    unsigned int trust_events;    // 信任事件数
    unsigned int flags;           // 标志位
    struct task_flags pflags;     // 进程标志位
    unsigned long pipein;         // 输入管道
    unsigned long pipeout;        // 输出管道
    unsigned long exeino;         // 可执行文件索引号
    struct file *exe_file;        // 可执行文件
    union {
        pid_t webmid_pid;         // 执行命令的网络中间件
        pid_t root_pid;           // 使用提权后特权的进程
    };
    unsigned short webmid_port;   // 网络中间件端口
    char ip[S_IPLEN];             // IP地址
    char tty[S_TTYLEN];           // 终端设备名
    char nodename[S_NAMELEN+1];   // 节点名称
    char md5[S_MD5LEN];           // MD5值
    char target_cmd[S_COMMLEN];   // 保存中间件名或提权执行的命令
    char args;                    // 参数
};

typedef struct task_request taskreq_t; // 使用 taskreq_t 简化结构体类型的名称


// NOTE(luoyinhong): should be consistent with sniper-ebpf/structs.h
struct ebpf_task_simple_info {
	uid_t 			uid;              // 用户ID
	uid_t 			euid;             // 有效用户ID
	pid_t 			pid;              // 进程ID
	int 			did_exec;         // 标志进程是否执行过exec操作
	char 			comm[16];         // 进程的命令名
	unsigned long 	proctime;         // 进程创建时间，用作进程标识
};

struct ebpf_parent_info {
	struct ebpf_task_simple_info task[4];  // 父进程信息数组，保存最多4个父进程的信息
};


/* 操作文件类型 */
#define OP_OPEN 				1        	// 打开文件
#define OP_CLOSE 				2        	// 关闭文件
#define OP_UNLINK 				3        	// 删除文件
#define OP_RENAME 				4        	// 重命名文件
#define OP_LINK 				5        	// 创建硬链接
#define OP_SYMLINK 				6        	// 创建符号链接
#define OP_READ 				7        	// 读取文件内容
#define OP_WRITE 				8        	// 写入文件内容
#define OP_OPEN_W 				9        	// 打开文件（写入模式）
#define OP_OPEN_C 				10       	// 打开文件（创建模式）
#define OP_OPEN_R 				11       	// 打开文件（只读模式）

#define OP_OPEN_FIREWALL 		18        	// 打开文件防火墙
#define OP_UNLINK_FIREWALL 		19        	// 删除文件防火墙
#define OP_RENAME_FIREWALL 		20        	// 重命名文件防火墙
#define OP_WRITE_FIREWALL 		21        	// 写入文件防火墙
#define OP_SYMLINK_FIREWALL 	22			// 创建符号链接防火墙
#define MAX_SNIPER_FILEOP 		24         	// 最大文件操作类型数量

#define F_SENSITIVE 			1                	// 敏感文件
#define F_LOG_DELETE 			2               	// 日志异常删除
#define F_SAFE 					3                   // 安全文件
#define F_LOGCOLLECTOR 			4             		// 日志采集
#define F_MIDDLE_TARGET 		5            		// 中间件目标文件
#define F_BINARY_FILTER 		6            		// 可执行文件过滤
#define F_MIDDLE_SCRIPT 		7           		// 中间件脚本文件
#define F_ILLEGAL_SCRIPT 		8           		// 非法脚本文件
#define F_WEBSHELL_DETECT 		9          			// Webshell文件检测
#define F_PRINTER 				10                 	// 打印监控
#define F_CDROM 				11                  // 刻录监控
#define F_ENCRYPT_BACKUP 		12          		// 勒索加密文件备份
#define F_ENCRYPT_REPORT 		13          		// 勒索加密报告
#define F_ENCRYPT 				14                 	// 勒索加密防护
#define F_BLACK_AFTER 			15             		// 文件黑名单
#define F_ABNORMAL 				16                	// 异常文件
#define F_USB 					17                  // USB文件监控
#define F_VIRUS 				18                  // 病毒文件

#define NET_MPORT_SCAN 			0x01          		// 端口扫描
#define NET_MHONEY_PORT 		0x02         		// 蜜罐端口
#define NET_MODULE_ALL 			0x03          		// 所有模块
#define NET_TCP_CONNECT_BASH 	0x04
#define NET_ILLEGAL_CONNECT     0x05       		
#define TASK_COMM_LEN 			16
#define MAX_FILENAME_LEN 		512

extern char sniper_fileop[MAX_SNIPER_FILEOP][S_NAMELEN];  // 文件操作类型字符串数组

struct timeval2 {
	long tv_sec;    
	long tv_usec;    
};

struct ebpf_filereq_t {              
	int uid;                         	
	int pid;
	int tgid;                          
	char comm[TASK_COMM_LEN];         
	char parent_comm[TASK_COMM_LEN];    
	char filename[32];
	int size;
	int path_len;
	char tty[S_TTYLEN];
	char args[4][64];
	int pro_len;
	char abs_path[256];    

	int did_exec;  
	struct timeval2 event_tv;
	unsigned long proctime;					
	unsigned long pipein;            
	unsigned long pipeout;           
	unsigned long exeino;             
	struct file *exe_file;             
	unsigned short op_type;            
	unsigned short type;                    
	unsigned int mode;                
	unsigned int flags;                
	unsigned int mnt_id;               
	long mtime_sec;                    
	long mtime_nsec;                 
	long long int file_size;          
	long long int newfile_size;       
	struct parent_info pinfo;          
	           
	char new_filename[64];             
	unsigned int newpath_len;          
	char pro_pathname[64];             
       
	int terminate;                             
	char nodename[S_NAMELEN+1];       
	char cmd[S_CMDLEN];              
	char cwd[S_CWDLEN];               
    int argc;        
};

struct ebpf_netreq_t {
	unsigned int uid; 
	unsigned int gid;                        	
	unsigned int pid;
	unsigned int tgid;
	unsigned int net_type;   
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned int parent_pid;
	unsigned char protocol; 
	unsigned short res1: 4;
	unsigned short doff: 4;
	unsigned short fin: 1;
	unsigned short syn: 1;
	unsigned short rst: 1;
	unsigned short psh: 1;
	unsigned short ack: 1;
	unsigned short urg: 1;
	unsigned short ece: 1;
	unsigned short cwr: 1;                
	unsigned short dport;                       
	unsigned short sport;  
	unsigned int daddr;                      
	unsigned int saddr;
	unsigned int sessionid;
	unsigned long start_time;
	char pathname[64];
	char parent_pathname[64];   
	struct ebpf_parent_info pinfo;     
	unsigned long exeino;               
	unsigned long proctime;             
	struct timeval2 event_tv; 
	unsigned short type;          
    
	unsigned int repeat;                
	int domain_query_type;              
	unsigned int effective_time;        
	unsigned int portscan_lockip_time;  
	unsigned int portscan_max;         
	unsigned int honey_lockip_time;    
	unsigned int ports_count;           
	unsigned short reason;             
	char ip[S_IPLEN];                   
	char domain[S_DOMAIN_NAMELEN];      
};

struct ebpf_taskreq_t {
	int uid;                                        
	int ppid;                     
	unsigned int euid;            
	unsigned int pid;
	unsigned int tgid;
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned parent_pid;
	char args[8][32];   

	unsigned long proctime;      
	unsigned long pipein;        
	unsigned long pipeout;      
	unsigned long exeino;        
	unsigned short cmdlen;      
	unsigned short argslen;     
	unsigned short cwdlen;     
	unsigned short argc;         
	unsigned short options;      
	unsigned int mnt_id;       
	struct ebpf_parent_info pinfo; 
	struct file *exe_file;        
	char tty[S_TTYLEN];          
	char nodename[S_NAMELEN+1];    
	char cmd[S_CMDLEN];          
	char cwd[S_CWDLEN];                 
};

/* definition of a sample sent to user-space from BPF program */
struct fevent {
	unsigned uid;                         	
	unsigned int pid;
	unsigned int tgid;                          
	char comm[TASK_COMM_LEN];
	char parent_comm[TASK_COMM_LEN]; 
	char filename[32];
	unsigned int pro_len;
	unsigned int size;
	unsigned int path_len;
	char tty[S_TTYLEN];
	char args[4][64];
	char abs_path[256];                     
};

struct sock_event {
	unsigned int uid; 
	unsigned int gid;                        	
	unsigned int pid;
	unsigned int tgid;
	unsigned int net_type;   
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned int parent_pid;
	unsigned char protocol; 
	unsigned short res1: 4;
	unsigned short doff: 4;
	unsigned short fin: 1;
	unsigned short syn: 1;
	unsigned short rst: 1;
	unsigned short psh: 1;
	unsigned short ack: 1;
	unsigned short urg: 1;
	unsigned short ece: 1;
	unsigned short cwr: 1;             
	unsigned short dport;                       
	unsigned short sport;  
	unsigned int daddr;                      
	unsigned int saddr;
	unsigned int sessionid;
	unsigned long start_time;
	char pathname[64];
	char parent_pathname[64];                         
};

struct process_event {                 	
	unsigned int pid;
	unsigned int tgid;
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned parent_pid;
	char args[8][32]; 
	unsigned short argc;  
	struct parent_info pinfo;        // 父进程信息（最多4代）                      
};
struct sniper_ip {
	unsigned char ip[4];                 // IPv4地址
};

struct sniper_ipv6 {
	unsigned char ipv6[16];              // IPv6地址
};

/* 将IP地址转换为字符串格式 */
#define IPSTR(IP) (IP)->ip[0],(IP)->ip[1],(IP)->ip[2],(IP)->ip[3]
/* 将IPv6地址转换为字符串格式 */
#define IPV6STR(IP) (IP)->ipv6[0],(IP)->ipv6[1],(IP)->ipv6[2],(IP)->ipv6[3],(IP)->ipv6[4], \
	(IP)->ipv6[5],(IP)->ipv6[6],(IP)->ipv6[7],(IP)->ipv6[8],(IP)->ipv6[9], \
	(IP)->ipv6[10],(IP)->ipv6[11],(IP)->ipv6[12],(IP)->ipv6[13],(IP)->ipv6[14],(IP)->ipv6[15]
/* 将MAC地址转换为字符串格式 */
#define MACSTR(MAC) (MAC)[0],(MAC)[1],(MAC)[2],(MAC)[3],(MAC)[4],(MAC)[5]

struct net_flags {
	unsigned long   	blackin 	: 1,           	// 标志位：黑名单入站
						blackout 	: 1,          	// 标志位：黑名单出站
						notwhitein 	: 1,         	// 标志位：非白名单入站
						notwhiteout : 1,        	// 标志位：非白名单出站
						honeyport 	: 1,         	// 标志位：蜜罐端口
						portscan 	: 1,         	// 标志位：端口扫描
						lockedip 	: 1,         	// 标志位：已锁定IP，用于非法网络连接事件类型
						internet 	: 1,         	// 标志位：互联网连接
						domain 		: 1,         	// 标志位：域名连接
						blackdomain : 1,     		// 标志位：黑名单域名连接
						minepool 	: 1,        	// 标志位：矿池连接

						blackin_terminate 		: 1,     	// 标志位：黑名单入站阻断
						blackout_terminate 		: 1,    	// 标志位：黑名单出站阻断
						honeyport_terminate 	: 1,   		// 标志位：蜜罐端口阻断
						portscan_terminate 		: 1,   		// 标志位：端口扫描阻断
						lockedip_terminate 		: 1,   		// 标志位：已锁定IP阻断
						internet_terminate 		: 1,   		// 标志位：互联网连接阻断
						blackdomain_terminate 	: 1,  		// 标志位：黑名单域名连接阻断
						minepool_terminate 		: 1,  		// 标志位：矿池连接阻断

						trust 					: 1,         // 标志位：信任
						locking 				: 1,         // 标志位：锁定IP
						terminate 				: 1,         // 标志位：终止连接
						tty 					: 1,         // 标志位：TTY连接
						tcp 					: 1,         // 标志位：TCP连接
						udp 					: 1,         // 标志位：UDP连接
						icmp 					: 1,         // 标志位：ICMP连接
						lockip 					: 1,         // 标志位：锁定IP消息
						unlockip 				: 1;         // 标志位：解锁IP消息
};

struct port_scan {
	unsigned long effective_time;      // 端口扫描超限时间
	unsigned long first_time;          // 端口扫描初始时间
	unsigned int portscan_lockip_time; // 端口扫描超限远程IP锁定时间
	unsigned int portscan_max;         // 最大端口扫描数量
	unsigned int ports_count;          // 已记录的端口数量
	unsigned int ports[0];             // 端口列表
};
typedef struct port_scan pscan_t;

#define KILL_DANGEROUS_WEBEXE 1
#define KILL_WEBEXE 2

struct kern_process_rules {
	unsigned long	process_engine_on 	: 1,          	// 进程引擎开启标志
					normal_on 			: 1,            // 普通进程监控开启标志
					danger_on 			: 1,            // 危险进程监控开启标志
					abnormal_on 		: 1,            // 异常进程监控开启标志
					privilege_on 		: 1,            // 提权进程监控开启标志
				remote_execute_on 		: 1,            // 反弹shell监控开启标志
					webshell_on 		: 1,            // Webshell监控开启标志
						mbr_on 			: 1,            // MBR攻击监控开启标志
					miner_on 			: 1,            // 挖矿程序监控开启标志
				port_forward_on 		: 1,            // 端口转发监控开启标志
					webexecute_on 		: 1,            // Web执行监控开启标志（似乎多余）
				normal_webexecute_on 	: 1,         	// 普通Web执行监控开启标志
				danger_webexecute_on 	: 1,         	// 危险Web执行监控开启标志
					fake_sysprocess_on 	: 1,          	// 伪造系统进程监控开启标志

					danger_kill 		: 1,             // 危险进程阻断标志
					abnormal_kill 		: 1,             // 异常进程阻断标志
					privilege_kill 		: 1,             // 提权进程阻断标志
				remote_execute_kill 	: 1,          	 // 反弹shell阻断标志
					webshell_kill 		: 1,             // Webshell阻断标志
					mbr_kill 			: 1,             // MBR攻击阻断标志
						miner_kill 		: 1,             // 挖矿程序阻断标志
				port_forward_kill 		: 1,             // 端口转发阻断标志
				normal_webexecute_kill 	: 1,      		 // 普通Web执行阻断标志
				danger_webexecute_kill 	: 1,       		 // 危险Web执行阻断标志
				fake_sysprocess_kill 	: 1,        	 // 伪造系统进程阻断标志
						black_kill 		: 1,             // 黑名单阻断标志
					not_white_kill 		: 1,             // 非白名单阻断标志（考虑用于学习模式下的告警）
				remote_execute_lockip 	: 1,         	 // 反弹shell锁定IP标志
				webshell_lockip 		: 1,             // Webshell锁定IP标志
					miner_lockip 		: 1;             // 挖矿程序锁定IP标志

		unsigned short webmiddle_count;       			// Web中间件数量
		unsigned short command_count;         			// 命令规则数量
		unsigned short black_count;           			// 黑名单数量
		unsigned short filter_count;          			// 过滤器数量
		unsigned short trust_count;           			// 信任列表数量
		unsigned short minepool_count;        			// 矿池数量
		unsigned short miner_lockip_seconds;  			// 挖矿程序锁定IP时间（秒）
		unsigned short remote_execute_lockip_seconds;  	// 反弹shell锁定IP时间（秒）
};

struct kern_file_rules {
	unsigned int    		operation_on;             	// 文件操作监控开启标志
	char 					usb_types[256];           	// USB文件类型
	char 					doc_types[256];           	// 文档文件类型
	char 					midd_procs[256];          	// 中间件进程名
	unsigned short 			important_path_num;         // 重要文件路径数量
	unsigned short 			important_link_num;         // 重要文件链接数量
	unsigned short 			control_num;                // 控制文件数量
	unsigned short 			illegal_script_num;         // 非法脚本文件数量
	unsigned short 			illegal_link_num;           // 非法链接文件数量
	unsigned short 			black_file_num;             // 黑名单文件数量
	unsigned int    	file_engine_on 			: 1,	// 文件引擎开启标志
			 			file_black_on 			: 1,	// 黑名单文件监控开启标志
		     			file_important_on 		: 1,	// 重要文件监控开启标志
			   			file_usb_on 			: 1,    // USB文件监控开启标志
		       			file_control_on 		: 1,    // 控制文件监控开启标志
			   			file_doc_on 			: 1,    // 文档文件监控开启标志
			  			file_midd_on 			: 1,    // 中间件文件监控开启标志
						file_illegal_script_on 	: 1;    // 非法脚本文件监控开启标志
};

struct kern_net_rules {
	unsigned int    net_engine_on 		: 1,           	// 网络引擎开启标志
					dns_watch 			: 1,			// DNS监控开启标志
					internet_watch 		: 1,            // Internet监控开启标志
					connection_watch 	: 1,          	// 连接监控开启标志

					dns_reject 			: 1,  			// 拒绝DNS连接标志
					internet_reject 	: 1,            // 拒绝Internet连接标志
					honeyport_reject 	: 1,          	// 端口诱捕拒绝连接标志
					blackwhite_reject 	: 1,         	// 黑白名单拒绝连接标志

					honeyport_lockip 		: 1,          	// 端口诱捕锁定IP标志
					port_scan_lockip 		: 1,         	// 端口扫描锁定IP标志
					illegal_conn_terminate 	: 1,    		// 非法连接终止标志
					local_dnsproxy 			: 1;          	// 本地DNS代理开关，如dnsmasq。DNS请求统一发给代理，由代理查询并返回结果

				unsigned short connection_filterip_count;       // 连接过滤IP数量
				unsigned short sshlogin_filterip_count;         // SSH登录过滤IP数量
				unsigned short lanip_count;                      // 本地IP数量
				unsigned short honeyport_count;                  // 端口诱捕数量
				unsigned short honeyport_filterip_count;         // 端口诱捕过滤IP数量
				unsigned short honeyport_trustip_count;          // 端口诱捕信任IP数量
				unsigned short honeyport_trustipv6_count;        // 端口诱捕信任IPv6数量
				unsigned short dnsfilter_count;                   // DNS过滤数量
				unsigned short dnsblack_count;                    // DNS黑名单数量
				unsigned short dnsmalicious_count;                // 恶意DNS数量
				unsigned short dnswhite_count;                    // DNS白名单数量
				unsigned short dnstrust_count;                    // DNS信任列表数量
				unsigned short whitein_count;                     // 入站白名单数量
				unsigned short whiteout_count;                    // 出站白名单数量
				unsigned short blackin_count;                     // 入站黑名单数量
				unsigned short blackout_count;                    // 出站黑名单数量

				unsigned char myip_count;                         // 本机IP数量
				unsigned char server_count;                       // 服务器数量
				unsigned short listenport_count;                  // 监听端口数量
				unsigned short zipterm;                           // 默认压缩日志时长（分钟），可调整
				unsigned int portscan_time;                       // 单个IP端口扫描时间范围
				unsigned int portscan_max;                        // 最大端口扫描端口数量
				unsigned int portscan_lock_time;                  // 恶意IP端口扫描锁定时间
				unsigned int honey_lockip_seconds;                // 端口诱捕IP锁定时间

				pid_t dnsproxy_pid;                               // DNS代理进程ID
				char dnsproxy[S_COMMLEN];                         // 本地DNS代理名称
};

struct important_link_length {
	unsigned short pathlen;                                // 重要文件路径长度
	unsigned short extlen;                                 // 重要文件扩展名长度
};
#define FILE_LINK_MAX  20

struct sniper_iprange {
	struct sniper_ip fromip;                                 	// 起始IP地址
	struct sniper_ip toip;                                    	// 终止IP地址
	int type;                                                   // 类型
};
#define sniper_ipmask toip.ip[1]                                // IP掩码

struct sniper_connrule {
	unsigned short fromport;                               		// 源端口
	unsigned short toport;                                  	// 目标端口
	unsigned short 	tcp		: 1,                                // TCP标志
					udp		: 1,                                // UDP标志
					icmp	: 1;                                // ICMP标志
	struct sniper_iprange ipr;                              	// IP范围
};

struct sniper_server {
	struct sniper_ip ip;                                 	// 服务器IP地址
	unsigned short port;                                    // 服务器端口
	unsigned short wsport;                                 	// WebSocket端口
	int active;                                             // 活动状态标志
};
struct sniper_server_ipv6 {
	struct sniper_ipv6 ipv6;                                  // IPv6服务器地址
	unsigned short port;                                      // 服务器端口
	unsigned short wsport;                                    // WebSocket端口
	int active;                                               // 活动状态标志
};

struct sniper_lockip {
	struct sniper_ip ip;                                        // 锁定IP地址
	unsigned int reason;                                    	// 锁定原因
	time_t lock_time;                                           // 锁定时间
};

#define MID_SET   1                                         	// 设置中间件信息
#define MID_CLOSE 2                                       		// 删除中间件信息
#define SNIPER_MIDDLEWARE_NUM 256            					// 最多考察256个监听端口，64个不够，看到有接近128的，装了多个容器
struct sniper_middleware {
	char name[S_COMMLEN];                               		// 中间件名称
	unsigned short port;                                   		// 监听端口
	pid_t pid;                                                 	// 中间件进程号
	int fd;                                                     // 监听端口对应的文件描述符
	int action;                                                 // 设置或删除中间件信息
	unsigned long ino;                                        	// 监听端口socket对应的inode号
};

struct kern_file_policy {
unsigned int	file_engine_on 					: 1,                    		// 文件引擎开关
				file_sensitive_on 				: 1,                        	// 敏感文件监控开关
				file_sensitive_kill 			: 1,                         	// 敏感文件阻断开关
				file_log_delete 				: 1,                         	// 日志异常删除开关
				file_safe_on 					: 1,                         	// 文件防篡改开关
				file_logcollector_on 			: 1,                          	// 文件行为采集开关
				file_middle_on 					: 1,                           	// 中间件识别开关
				file_middle_binary_on 			: 1,                            // 可执行文件识别开关
				file_middle_binary_exclude 		: 1,                    		// 可执行文件过滤开关
				file_middle_binary_terminate 	: 1,                  			// 可执行文件识别阻断开关
				file_middle_script_on 			: 1,                            // 脚本文件识别开关
				file_middle_script_terminate 	: 1,                    		// 脚本文件识别阻断开关
				file_illegal_script_on 			: 1,                            // 非法脚本识别开关
				file_illegal_script_terminate 	: 1,                   			// 非法脚本识别阻断开关
				file_webshell_detect_on 		: 1,                         	// WebShell文件检测开关
				file_webshell_detect_terminate 	: 1,                  			// WebShell文件阻断开关
				printer_on 						: 1,                            // 打印监控开关
				printer_terminate 				: 1,                            // 打印监控禁止开关
				cdrom_on 						: 1,                            // 刻录监控开关
				cdrom_terminate 				: 1,                            // 刻录监控禁止开关
				encrypt_on 						: 1,                            // 勒索加密防护开关
				encrypt_terminate 				: 1,                            // 勒索加密防护禁止开关
				encrypt_backup_on 				: 1,                            // 勒索加密防护文件备份开关
				encrypt_space_full 				: 1,                          	// 勒索加密防护文件备份空间是否已满
				encrypt_hide_on 				: 1,                            // 勒索加密防护隐藏诱捕文件开关
				usb_file_on 					: 1,                            // USB文件监控开关
				antivirus_on 					: 1;                            // 病毒防护开关

			unsigned short sensitive_count;                       				// 敏感文件数量
			unsigned short log_delete_count;                    				// 异常日志删除数量
			unsigned short safe_count;                              			// 安全文件数量
			unsigned short logcollector_count;                					// 文件行为采集数量
			unsigned short illegal_script_count;                  				// 非法脚本数量
			unsigned short webshell_detect_count;          						// WebShell文件检测数量
			unsigned short printer_count;                            			// 打印监控数量
			unsigned short cdrom_count;                             			// 刻录监控数量
			unsigned short black_count;                                 		// 黑名单文件数量
			unsigned short filter_count;                                 		// 文件过滤数量
			unsigned short usb_count;                                    		// USB文件监控数量
			unsigned int neglect_min;                                     		// 忽略的最小文件大小（字节）
			unsigned int neglect_size;                                     		// 忽略的文件大小（字节）
};


#endif
