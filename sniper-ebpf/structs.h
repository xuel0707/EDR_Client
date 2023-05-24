#ifndef STRUCTS_H
#define STRUCTS_H

#define S_TTYLEN        30  //之前保存到盘上的登录历史记录tty字段长度是30
#define S_NAMELEN       64
#define S_CWDLEN        200
#define S_CMDLEN        400

#define MAX_ARGS    8

struct task_simple_info {
	uid_t uid;
	uid_t euid;
	pid_t pid;
	int did_exec;
	char comm[16];
	unsigned long proctime; //进程创建时间，作为进程标识
};

struct parent_info {
	struct task_simple_info task[4];
};

struct taskreq_t {
	int uid;       // The user id.
	int pid;       // The process id.
	int ppid;      // parent process id
	unsigned int euid;      // effective user id.
	int tgid;      // Thread Group id.
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
	struct parent_info pinfo;    // The parent processes information (Up to 4 generations).
	struct file *exe_file;       // ???
	char tty[S_TTYLEN];
	char nodename[S_NAMELEN+1];
	char cmd[S_CMDLEN];
	char cwd[S_CWDLEN];
	char args[MAX_ARGS][32];           // Used to store the arguments.
};

struct sys_enter_execve_args{
	char unused[16];
	const char *filename;   // the path of the executable file.
	const char **argv ;     // the arguments of the process.
};

struct TestStruct {
	int length;
    char title[50];
    char author[50];
};

struct event{
	long pid;
	char data[32];
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
