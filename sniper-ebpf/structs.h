#ifndef STRUCTS_H
#define STRUCTS_H

#define S_TTYLEN        		30  //之前保存到盘上的登录历史记录tty字段长度是30
#define S_NAMELEN       		64
#define S_CWDLEN        		200
#define S_CMDLEN        		400

#define MAX_ARGS    			8

#define MAX_LABEL_SIZE 			100
#define MAX_MSG_SIZE 			200
#define MAX_STR_SIZE 			200 
#define TASK_COMM_LEN 			16
#define MAX_FILENAME_LEN 		512
enum Event_type {

	FUNCTION_CALL 	= 0,

	SYS_CALL_ENTER	= 5,
	SYS_CALL_EXIT	= 6,

	MEMBER_SUINT 	= 9,
	MEMBER_UINT 	= 10,
	MEMBER_LUINT 	= 11,
	MEMBER_LINT 	= 12,
	MEMBER_LLINT 	= 13,
	MEMBER_STR 	= 15,

	STRUCT_FILE 	= 100,
	STRUCT_DENTRY 	= 101,
	STRUCT_QSTR 	= 102,
};

/* Generic event interface */
typedef struct Event {
	enum Event_type etype;
	char label[MAX_LABEL_SIZE];
} Event;


/* Function call events */
typedef struct func_call_Event {
	Event super;
	char name[MAX_MSG_SIZE];
	char args[MAX_MSG_SIZE];
} func_call_Event;

typedef unsigned short int umode_t;  // umode_t类型定义为unsigned short int


struct task_simple_info {
	uid_t uid;
	uid_t euid;
	pid_t pid;
	int did_exec;
	char comm[16];
	unsigned long proctime; //进程创建时间，作为进程标识
};

struct parent_info {
	struct task_simple_info task[4];  // 父进程信息，最多4代
};

struct timeval2 {
	long tv_sec;     // 秒
	long tv_usec;    // 微秒
};

struct ebpf_filereq_t {
	int uid;                         		// 用户ID
	int tgid;                          		// 线程组ID
	int pid;                         		// 进程ID
	int did_exec;  // The flag that whether a file is over.
	struct timeval2 event_tv;
	unsigned long proctime;					// 进程启动时间
	unsigned long pipein;              // 输入管道
	unsigned long pipeout;             // 输出管道
	unsigned long exeino;              // 执行文件的inode号
	struct file *exe_file;             // 执行文件的文件指针
	unsigned short op_type;            // 文件操作类型 (1:打开 2:关闭 3:删除 4:重命名 5:符号链接)
	unsigned short type;               // 1:敏感文件 2:日志删除 3:安全文件 4:日志收集器
	unsigned short size;               // 请求大小：头部 + 参数
	unsigned int mode;                 // 文件权限
	unsigned int flags;                // 文件标志
	unsigned int mnt_id;               // 挂载点ID
	long mtime_sec;                    // 文件的修改时间（秒）
	long mtime_nsec;                   // 文件的修改时间（纳秒）
	long long int file_size;           // 文件大小
	long long int newfile_size;        // 新文件大小
	struct parent_info pinfo;          // 父进程信息（最多4代）
	char comm[TASK_COMM_LEN];          // 当前进程的名称
	char parent_comm[16];              // 父进程的名称
	char filename[MAX_FILENAME_LEN];   // 文件名
	unsigned int path_len;             // 文件名路径长度
	char new_filename[64];             // 新文件名
	unsigned int newpath_len;          // 新文件名路径长度
	char pro_pathname[64];             // 处理路径名
	unsigned int pro_len;              // 处理路径名长度
	int terminate;                     // 已废弃，用于判断是否需要阻塞
	char tty[S_TTYLEN];                // 终端设备名称
	char nodename[S_NAMELEN+1];        // 节点名称
	char cmd[S_CMDLEN];                // 命令名称
	char cwd[S_CWDLEN];                // 当前工作目录
	char args[8][64];                  // 参数数组，用于存储参数，最多存储8个参数，每个参数长度最多为64字节
	int argc;
};

struct netreq_t {
	uid_t uid;                                              
	pid_t tgid;
	unsigned int pid;  

	char comm[TASK_COMM_LEN]; 
	unsigned short protocol; 
	unsigned short sport;                  
	unsigned short dport;
	unsigned int saddr;                        
	unsigned int daddr;       
 
	unsigned long exeino;               
	unsigned long proctime;             
	struct timeval2 event_tv;           
    
	unsigned int repeat;                
	int domain_query_type;              
	unsigned int effective_time;        
	unsigned int portscan_lockip_time;  
	unsigned int portscan_max;         
	unsigned int honey_lockip_time;    
	unsigned int ports_count;           
	unsigned short reason;             
   
};

struct filereq_t {
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

struct taskreq_t {
	int uid;                         // 用户ID
	int pid;                         // 进程ID
	int ppid;                        // 父进程ID
	unsigned int euid;               // 有效用户ID
	int tgid;                        // 线程组ID
	unsigned long proctime;          // 进程启动时间
	unsigned long pipein;            // 输入管道
	unsigned long pipeout;           // 输出管道
	unsigned long exeino;            // 执行文件的inode号
	unsigned short cmdlen;           // 命令长度
	unsigned short argslen;          // 参数长度
	unsigned short cwdlen;           // 当前工作目录长度
	unsigned short argc;             // 参数个数
	unsigned short options;          // 以"-"开头的参数个数
	unsigned int mnt_id;             // 挂载点ID
	struct parent_info pinfo;        // 父进程信息（最多4代）
	struct file *exe_file;           // 执行文件的文件指针
	char tty[S_TTYLEN];               // 终端设备名称
	char nodename[S_NAMELEN+1];       // 节点名称
	char cmd[S_CMDLEN];               // 命令名称
	char cwd[S_CWDLEN];               // 当前工作目录
	char args[MAX_ARGS][32];         // 参数数组，用于存储参数，最多存储MAX_ARGS个参数，每个参数长度最多为32字节
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

struct sys_enter_execve_args {
	char unused[16];             // 未使用的字段
	const char *filename;        // 可执行文件的路径
	const char **argv;           // 进程的参数数组
};

struct sys_enter_file_open_args {
	// unsigned short common_type;
	// unsigned char common_flags;
	// unsigned char common_preempt_count;
	// int common_pid;
	char buf[8];                 // 未使用的字段
	int __syscall_nr;            // 系统调用号
	const char *filename;        // 文件路径
	long flags;                  // 文件标志
	long mode;                   // 文件权限
};

struct sys_enter_file_openat_args {
	// unsigned short common_type;
	// unsigned char common_flags;
	// unsigned char common_preempt_count;
	// int common_pid;
	char buf[24];                // 未使用的字段
	const char *filename;        // 文件路径
	long flags;                  // 文件标志
	long mode;                   // 文件权限
};

struct sys_enter_file_rename_args {
	// unsigned short common_type;
	// unsigned char common_flags;
	// unsigned char common_preempt_count;
	// int common_pid;
	char buf[16];                // 未使用的字段
	const char *old_filename;    // 原文件路径
	const char *new_filename;    // 新文件路径
};

struct TestStruct {
	int length;                  // 长度
	char title[50];              // 标题
	char author[50];             // 作者
};


#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 10
#if 0
struct event {
	long pid;                    
	char data[32];              
};
#else
struct event {
    int pid;
    char comm[16];
    char name[200];
	char args[200];
};
#endif

struct kern_file_policy {
	unsigned int	file_engine_on 		: 1,			// 文件引擎总开关
					file_sensitive_on 	: 1,			// 敏感文件开关
	       file_sensitive_kill 			: 1,			// 敏感文件阻断开关
	       file_log_delete 				: 1,            // 日志异常删除开关
	       file_safe_on 				: 1,            // 文件防篡改开关
	       file_logcollector_on 		: 1,          	// 文件行为采集开关
	       file_middle_on 				: 1,            // 中间件识别开关
	       file_middle_binary_on 		: 1,         	// 可执行文件识别开关
	       file_middle_binary_exclude 	: 1,    		// 可执行文件过滤开关
	       file_middle_binary_terminate : 1,  			// 可执行文件识别阻断开关
	       file_middle_script_on 		: 1,         	// 脚本文件识别开关
	       file_middle_script_terminate : 1,  			// 脚本文件识别阻断开关
	       file_illegal_script_on 		: 1,        	// 非法脚本识别开关
	       file_illegal_script_terminate 	: 1,		// 非法脚本识别阻断开关
	       file_webshell_detect_on 			: 1,       	// webshell文件检测开关
	       file_webshell_detect_terminate 	: 1,		// webshell文件阻断开关
	       printer_on 						: 1,        // 打印监控开关
	       printer_terminate 				: 1,        // 打印监控禁止开关
	       cdrom_on 						: 1,        // 刻录监控开关
	       cdrom_terminate 					: 1,        // 刻录监控禁止开关
	       encrypt_on 						: 1,        // 勒索加密防护开关
	       encrypt_terminate 				: 1,        // 勒索加密防护禁止开关
	       encrypt_backup_on 				: 1,        // 勒索加密防护文件备份开关
	       encrypt_space_full 				: 1,        // 勒索加密防护文件备份空间是否已满
	       encrypt_hide_on 					: 1,        // 勒索加密防护隐藏诱捕文件开关
	       usb_file_on 						: 1,        // USB文件监控开关
	       antivirus_on 					: 1;        // 病毒防护开关

	unsigned short		sensitive_count;                    // 敏感文件计数
	unsigned short    	log_delete_count;                   // 日志异常删除计数
	unsigned short    	safe_count;                          // 文件防篡改计数
	unsigned short    	logcollector_count;                  // 文件行为采集计数
	unsigned short    	illegal_script_count;                // 非法脚本识别计数
	unsigned short    	webshell_detect_count;               // webshell文件检测计数
	unsigned short    	printer_count;                       // 打印监控计数
	unsigned short    	cdrom_count;                         // 刻录监控计数
	unsigned short    	black_count;                         // 黑名单计数
	unsigned short    	filter_count;                        // 过滤器计数
	unsigned short    	usb_count;                           // USB计数
	unsigned int      	neglect_min;                         // 忽略的最小值
	unsigned int      	neglect_size;                        // 忽略的文件大小
};


#endif
