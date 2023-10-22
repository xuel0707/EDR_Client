#ifndef _PROCESS_H
#define _PROCESS_H

#include "list.h"

extern char *procpost, *procreply;

/* 进程日志参数 */
struct process_msg_args {
	struct timeval event_tv;
	struct timeval stop_tv;

        pid_t pid;
        char uuid[S_UUIDLEN];
        char cmd[S_CMDLEN];
        char cmdline[S_ARGSLEN];
	char user[S_NAMELEN];
	char md5[S_MD5LEN];
	char sha256[S_SHALEN];

        pid_t ppid;
        char puuid[S_UUIDLEN];
        char pcmd[S_CMDLEN];
        char pcmdline[S_ARGSLEN];
	char puser[S_NAMELEN];
	char pmd5[S_MD5LEN];

        char cwd[S_CWDLEN];
        char ip[S_IPLEN];
	char product[S_NAMELEN];
	char vendor[S_NAMELEN];
	char mem[S_NAMELEN];
	char tty[S_TTYLEN];
	char domain[S_DOMAIN_NAMELEN];
        unsigned short event_id;
        char loglevel;
	char behavior_id;
	char terminate;
	char blockip;
        char *result;
        char *terminate_result;
        char *blockip_result;
	unsigned int trust_events; 
	unsigned long flags; 
	struct task_flags pflags;
	unsigned int repeat;
        char session_uuid[S_UUIDLEN];
	char dangerous_command[S_COMMLEN];
	char middleware[S_COMMLEN];
	char listening_ports[S_NAMELEN];
        char myip[S_IPLEN];
	unsigned short myport;
	unsigned short port;
	char desc[S_LINELEN];
};
typedef struct process_msg_args proc_msg_t;

/* 进程状态数组 sizeof(taskstat_t) 2264 */
struct task_status {
	uid_t uid;
	uid_t euid;
	gid_t gid;
	gid_t egid;
	uid_t fsuid;
	gid_t fsgid;
	uid_t loginuid;
	pid_t pid;
#if 0
	struct parent_info pinfo;
#else
    struct ebpf_parent_info pinfo;
#endif
	unsigned long long proctime; //进程创建时间，作为进程标识
	struct timeval event_tv;  //进程事件时间，比如进程执行命令的时刻
	struct timeval stop_tv;   //进程退出时间
	unsigned short cmdlen;
	unsigned short argslen;
	unsigned short cwdlen;
	unsigned short options;
	unsigned short argc;
	unsigned short argv0len;
	unsigned long pipein;
	unsigned long pipeout;
        char tty[S_TTYLEN];
        char ip[S_IPLEN];
        char childcmd[S_COMMLEN];
	int ipnum;
	int retval;
	unsigned long flags;
	struct task_flags pflags;
        char myip[S_IPLEN];
	unsigned short myport;
	unsigned short port;

	char cwd[S_CWDLEN];
	char cmd[S_CMDLEN];
	char args[S_ARGSLEN];

	int repeat;
	int event_id;
	unsigned int trust_events;
	char exec_times;
	char refcount;
	char uuid[S_UUIDLEN];
	char user[S_NAMELEN];
	char md5[S_MD5LEN];
	char sha256[S_SHALEN];

	char vendor[S_NAMELEN];
	char product[S_NAMELEN];
	char mem[S_NAMELEN];

	char session_uuid[S_UUIDLEN];

	struct task_status *exec_ptaskstat;
	struct list_head list;
};
typedef struct task_status taskstat_t;
extern taskstat_t *orphan_taskstat;
extern taskstat_t *idle_taskstat;

#define TASK_TTY		    PSR_TTY		    //0x1		带终端
#define TASK_CRON		    PSR_CRON	    //0x2		定时任务
#define TASK_NETWORK		PSR_NETWORK	    //0x4		带网络
#define TASK_EXEC		    PSR_EXEC	    //0x8		进程执行命令
#define TASK_STOPED		    PSR_STOPED	    //0x10		危险命令已被阻断
#define TASK_KILLSNIPER		PSR_KILLSNIPER	//0x20		非法中断sniper
#define TASK_DIRTYCOW		PSR_DIRTYCOW	//0x40		脏牛
#define TASK_EXIT		    PSR_EXIT	    //0x80		进程退出
#define TASK_PRIVUP		    PSR_PRIVUP	    //0x100		提权
#define TASK_PRIVUP_FORK	PSR_PRIVUP_FORK	//0x200		提权态下fork
#define TASK_PRIVUP_EXEC	PSR_PRIVUP_EXEC	//0x400		提权态下exec
#define TASK_WEBSHELL		PSR_WEBSHELL	//0x800		菜刀  
#define TASK_WEBEXECUTE_NORMAL	PSR_WEBEXECUTE_NORMAL	//0x1000	web中间件执行普通命令
#define TASK_WEBEXECUTE_DANGER	PSR_WEBEXECUTE_DANGER	//0x2000	web中间件执行危险命令
#define TASK_PIPEIN		    PSR_PIPEIN	    //0x4000	管道入方
#define TASK_PIPEOUT		PSR_PIPEOUT	    //0x8000	管道出方
#define TASK_TRUST		    PSR_TRUST	    //0x10000	信任命令
#define TASK_BLACK		    PSR_BLACK	    //0x20000	黑名单，或非白名单
#define TASK_FILTER		    PSR_FILTER	    //0x40000	过滤命令
#define TASK_DANGER		    PSR_DANGER	    //0x80000	危险命令
#define TASK_MINER		    PSR_MINER	    //0x100000	挖矿命令
#define TASK_DISK_READ		PSR_DISK_READ	//0x200000	读打开盘设备
#define TASK_DISK_WRITE		PSR_DISK_WRITE	//0x400000	写打开盘设备
#define TASK_WRITE_FORBIDDEN	PSR_WRITE_FORBIDDEN	//0x800000	禁止写
#define TASK_ELF32		    PSR_ELF32	    //0x1000000	elf32格式命令
#define TASK_AOUT		    PSR_AOUT	    //0x2000000	a.out格式命令
#define TASK_RANSOMWARE		PSR_RANSOMWARE	//0x4000000	勒索软件
#define TASK_PORT_FORWARD	PSR_PORT_FORWARD  //0x8000000	端口转发
#define TASK_FAKE_SYSPROCESS	0x10000000	//伪造系统进程
#define TASK_DOCKER		        0x20000000	//docker内进程
#define TASK_ABNORMAL		PSR_ABNORMAL    //0x40000000	异常程序，如在/tmp目录下的程序
#define TASK_DIRTYPIPE		PSR_DIRTYPIPE   //0x80000000    脏管道
#define TASK_RequestMaliciousDomain		PSR_RequestMaliciousDomain  //请求恶意域名事件


#define TASK_SU					        0x100000000	    //su/sudo
#define TASK_SUID		  		        0x200000000	    //suid程序
#define TASK_SHELL				        0x400000000	    //shell
#define TASK_REMOTE_EXECUTE			    0x800000000	    //远程执行/反弹shell
#define TASK_MAY_REMOTE_EXECUTE			0x1000000000	//疑似远程执行/反弹shell
#define TASK_REPORTED				    0x2000000000	//命令已报告管控中心
#define TASK_DROP				        0x4000000000	//此类命令不报告管控中心
#define TASK_DROPCHILD				    0x8000000000	//此类命令的子命令不报告管控中心
#define TASK_PARENT_TTY				    0x10000000000	//父进程有TTY
#define TASK_SSH				        0x20000000000	//是ssh登录或执行命令
#define TASK_PARENT_BLACK			    0x40000000000	//父进程是违规进程
#define TASK_PROGRAM_CHANGED			0x80000000000   //程序在安装后被修改过

#define TASK_WEBEXECUTE (TASK_WEBEXECUTE_DANGER|TASK_WEBEXECUTE_NORMAL)
#define TASK_TTYFLAGS	(TASK_TTY|TASK_PARENT_TTY|TASK_WEBSHELL|TASK_WEBEXECUTE|TASK_REMOTE_EXECUTE)
//TODO 参考set_taskstat_flags()修改TASK_INHERIT
#define TASK_INHERIT	(TASK_TTY|TASK_PARENT_TTY|TASK_CRON|TASK_NETWORK)

#define TASKMAX  4096

struct task_list {
	struct list_head queue;
	pthread_rwlock_t lock;
};
typedef struct task_list tasklist_t;
extern tasklist_t *tasklist;

struct exefile_info {
	off_t  install_fsize;
	off_t  fsize;
	mode_t install_fmode;
	mode_t fmode;
	time_t install_mtime;
	time_t mtime;
	time_t pkginstalltime;
	time_t ctime;
	char vendor[S_NAMELEN];
	char product[S_NAMELEN];
	char username[S_NAMELEN];
	char groupname[S_NAMELEN];
	char pkginstallsize[S_NAMELEN];
	char install_digest[S_SHALEN];
	char digest[S_SHALEN];
};
typedef struct exefile_info exeinfo_t;

/* 程序hash值是单向链表，新程序总是插在头部，认为新程序接着被查询的几率更大 */
struct exe_hash {
	struct exe_hash *next;
	dev_t dev;
	unsigned long ino;
	unsigned long size;
	time_t mtime;
	time_t ctime;
	mode_t mode;
	pid_t pid; //最近一个执行该程序的进程
	char vendor[S_NAMELEN];
	char product[S_NAMELEN];
	char md5[S_MD5LEN];
	char sha256[S_SHALEN];
	char program_changed;
};
typedef struct exe_hash exehash_t;
struct exe_list {
	struct exe_hash *head;
};
typedef struct exe_list exelist_t;
#define EXEMAX 1024

/* 下面的数据结构引用了ps的实现代码 */
#define P_G_SZ 20
typedef struct proc_t {
// 1st 16 bytes
    int
        tid,            // (special)       task id, the POSIX thread ID (see also: tgid)
        ppid;           // stat,status     pid of parent process
    unsigned
        pcpu;           // stat (special)  %CPU usage (is not filled in by readproc!!!)
    char
        state,          // stat,status     single-char code for process state (S=sleeping)
        pad_1,          // n/a             padding
        pad_2,          // n/a             padding
        pad_3;          // n/a             padding
// 2nd 16 bytes
    unsigned long long
        utime,          // stat            user-mode CPU time accumulated by process
        stime,          // stat            kernel-mode CPU time accumulated by process
// and so on...
        cutime,         // stat            cumulative utime of process and reaped children
        cstime,         // stat            cumulative stime of process and reaped children
        start_time;     // stat            start time of process -- seconds since 1-1-70
#ifdef SIGNAL_STRING
    char
        // Linux 2.1.7x and up have 64 signals. Allow 64, plus '\0' and padding.
        signal[18],     // status          mask of pending signals, per-task for readtask() but per-proc for readproc()
        blocked[18],    // status          mask of blocked signals
        sigignore[18],  // status          mask of ignored signals
        sigcatch[18],   // status          mask of caught  signals
        _sigpnd[18];    // status          mask of PER TASK pending signals
#else
    long long
        // Linux 2.1.7x and up have 64 signals.
        signal,         // status          mask of pending signals, per-task for readtask() but per-proc for readproc()
        blocked,        // status          mask of blocked signals
        sigignore,      // status          mask of ignored signals
        sigcatch,       // status          mask of caught  signals
        _sigpnd;        // status          mask of PER TASK pending signals
#endif
    unsigned long
        start_code,     // stat            address of beginning of code segment
        end_code,       // stat            address of end of code segment
        start_stack,    // stat            address of the bottom of stack for the process
        kstk_esp,       // stat            kernel stack pointer
        kstk_eip,       // stat            kernel instruction pointer
        wchan;          // stat (special)  address of kernel wait channel proc is sleeping in
    long
        priority,       // stat            kernel scheduling priority
        nice,           // stat            standard unix nice level of process
        rss,            // stat            resident set size from /proc/#/stat (pages)
        alarm,          // stat            ?
    // the next 7 members come from /proc/#/statm
        size,           // statm           total # of pages of memory
        resident,       // statm           number of resident set (non-swapped) pages (4k)
        share,          // statm           number of pages of shared (mmap'd) memory
        trs,            // statm           text resident set size
        lrs,            // statm           shared-lib resident set size
        drs,            // statm           data resident set size
        dt;             // statm           dirty pages
    unsigned long
        vm_size,        // status          same as vsize in kb
        vm_lock,        // status          locked pages in kb
        vm_rss,         // status          same as rss in kb
        vm_data,        // status          data size
        vm_stack,       // status          stack size
        vm_exe,         // status          executable size
        vm_lib,         // status          library size (all pages, not just used ones)
        rtprio,         // stat            real-time priority
        sched,          // stat            scheduling class
        vsize,          // stat            number of pages of virtual memory ...
        rss_rlim,       // stat            resident set size limit?
        flags,          // stat            kernel flags for the process
        min_flt,        // stat            number of minor page faults since process start
        maj_flt,        // stat            number of major page faults since process start
        cmin_flt,       // stat            cumulative min_flt of process and child processes
        cmaj_flt;       // stat            cumulative maj_flt of process and child processes
    char
        **environ,      // (special)       environment string vector (/proc/#/environ)
        **cmdline;      // (special)       command line string vector (/proc/#/cmdline)
    char
        // Be compatible: Digital allows 16 and NT allows 14 ???
        euser[P_G_SZ],  // stat(),status   effective user name
        ruser[P_G_SZ],  // status          real user name
        suser[P_G_SZ],  // status          saved user name
        fuser[P_G_SZ],  // status          filesystem user name
        rgroup[P_G_SZ], // status          real group name
        egroup[P_G_SZ], // status          effective group name
        sgroup[P_G_SZ], // status          saved group name
        fgroup[P_G_SZ], // status          filesystem group name
        cmd[16];        // stat,status     basename of executable file in call to exec(2)
    struct proc_t
        *ring,          // n/a             thread group ring
        *next;          // n/a             various library uses
    int
        pgrp,           // stat            process group id
        session,        // stat            session id
        nlwp,           // stat,status     number of threads, or 0 if no clue
        tgid,           // (special)       task group ID, the POSIX PID (see also: tid)
        tty,            // stat            full device number of controlling terminal
        euid, egid,     // stat(),status   effective
        ruid, rgid,     // status          real
        suid, sgid,     // status          saved
        fuid, fgid,     // status          fs (used for file access only)
        tpgid,          // stat            terminal process group id
        exit_signal,    // stat            might not be SIGCHLD
        processor;      // stat            current (or most recent?) CPU
} proc_t;
#endif /* _PROCESS_H */
