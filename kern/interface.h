#ifndef _MONITOR_INTERFACE_H
#define _MONITOR_INTERFACE_H

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/inet_sock.h>     // for struct inet_sock
#include <linux/tty.h>         // for current->signal->tty
#include <linux/vmalloc.h>
#include <linux/elf.h>
#include <linux/delay.h>       // for msleep, get_monotonic_boottime
#include <linux/in.h>          // for centos5 struct in_addr
#include <linux/utsname.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/mm.h>    // for get_task_mm
#endif

#include "../include/common.h"
#include "sniper_custom.h"
#include "lsm_hooks.h"
#include "file_moni.h"
#include "mem_trace.h"

#ifndef RESERVED_PIDS
#define RESERVED_PIDS 300
#endif

#define MB_SIZE		(1024*1024)
#define GB_SIZE		(1024*1024*1024)

/* 压缩一分钟内的同类网络日志 */
#define ZIPTERM 60
extern unsigned short zipterm;

/*限制最大循环数*/
#define FOR_MAX         1000
#define WHILE_MAX       1000

#define sniper_badptr(PTR)	is_err_or_null((unsigned long)PTR, #PTR)

extern unsigned long put_task_struct_addr;
extern unsigned long security_ops_addr;
extern unsigned long security_hook_heads_addr;
extern unsigned long init_mm_addr;
extern unsigned long mount_lock_addr;
extern unsigned long vfsmount_lock_func_addr;
extern unsigned long vfsmount_unlock_func_addr;

typedef void (*put_task_struct_t)(struct task_struct *t);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
/* kernel >= 3.19.0 not define f_dentry */
#ifndef f_dentry
#define f_dentry f_path.dentry
#endif
#endif

#define myprintk(fmt, args...) printk(KERN_INFO "sniper: " fmt, ## args)
#define mypdebug(fmt, args...) if (exec_debug) printk(KERN_INFO "sniper: " fmt, ## args)
#define myndebug(fmt, args...) if (net_debug)  printk(KERN_INFO "sniper: " fmt, ## args)
#define myfdebug(fmt, args...) if (file_debug)  printk(KERN_INFO "sniper: " fmt, ## args)
#define myvdebug(fmt, args...) if (virus_debug)  printk(KERN_INFO "sniper: " fmt, ## args)
extern int loopdebug;
#define dprintk(fmt, args...)  if (loopdebug) printk(KERN_INFO "sniper: " fmt, ## args)

#define PDEBUG_DEVELOP     99   //用于开发调试，不起sniper，仅加载sniper_edr.ko，只监控不上报
#define PDEBUG_FDS         100  //显示打印执行命令时，进程打开的文件
#define PDEBUG_PLIST_MATCH 101  //显示与规则命令比较的过程
#define PDEBUG_FILTER      102  //打印执行的过滤名单中的命令
#define PDEBUG_COMM        103  //打印进程名与进程执行的程序命令名不同的情况
#define PDEBUG_WEBEXEC     104  //中间件执行
#define PDEBUG_CMD_MATCH   105  //中间件执行的特殊命令列表匹配情况
#define mypdebug2(level, fmt, args...) if (exec_debug == level) printk(KERN_INFO "sniper: " fmt, ## args)
#define mypdebug3(fmt, args...) if (exec_debug == PDEBUG_PLIST_MATCH) printk(KERN_INFO "sniper: " fmt, ## args)
#define mypdebug4(fmt, args...) if (exec_debug == PDEBUG_FILTER) printk(KERN_INFO "sniper: " fmt, ## args)

#define NDEBUG_DOMAINLIST  100
#define NDEBUG_LISTEN      101
#define myndebug2(level, fmt, args...) if (net_debug == level)  printk(KERN_INFO "sniper: " fmt, ## args)

#define myfdebug2(type, fmt, args...) if (file_debug == type) printk(KERN_INFO "sniper: " fmt, ## args)

#define myaddr2ip(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define PEER_CONN  1
#define LOCAL_CONN 2
struct connection_info {
	int family;
	unsigned short sport;
	unsigned short dport;
	u32 saddr;
	u32 daddr;
	struct in6_addr saddr_6;
	struct in6_addr daddr_6;
	struct inode *inode;
};
typedef struct connection_info conninfo_t;

extern unsigned long original_cr0;

extern int sniper_netlink;
extern int sniper_dump;
extern int exec_debug;
extern int file_debug;
extern int virus_debug;
extern int net_debug;
extern int mem_debug;
extern int filesize_threshold;

extern pid_t sniper_pid;
extern pid_t nl_exec_pid;
extern pid_t nl_file_pid;
extern pid_t nl_virus_pid;
extern pid_t nl_net_pid;
extern gid_t sniper_cdrom_gid;
extern char sniper_exec_loadoff;
extern char sniper_net_loadoff;
extern char sniper_file_loadoff;

extern time_t nodeboottime;

struct sniper_file_list{
	char *path;
	char *ext;
};

struct sniper_file_control{
	char *path;
	char *name;
	char *pro;
};

struct sniper_file_black_list {
	char *filename;
	char *filepath;
	char *md5;
};
typedef struct sniper_file_black_list sniper_flist_t;

struct sniper_process_list {
	char *cmdname;
	char *cmdpath;
	char *cmdline;
	char *md5;
	char *pcmdname;
	char *rip;
	unsigned char flag;
	uid_t uid;
	int event_flag;
};
typedef struct sniper_process_list sniper_plist_t;

struct sniper_command_table {
	char *command;
};
typedef struct sniper_command_table sniper_cmdtbl_t;

struct call_info {
	char comm[16];
	char cron_comm[16];
	int repeat;
};
typedef struct call_info callinfo_t;
struct cmd_info {
	char *cmd;
	char *args;
	char *cwd;
	time_t last;
	int repeat;
	spinlock_t lock;
	int calls;
	callinfo_t callinfo[8];
	void *morecallinfo;
};
typedef struct cmd_info cmdinfo_t;
#define CMDLISTNUM 27
struct cmd_list {
	struct list_head queue;
	spinlock_t lock;
};
typedef struct cmd_list cmdlist_t;
extern cmdlist_t *cmdlist;

/*
 * 命令信息索引
 * md5根据程序文件的大小计算得到
 * md5_2根据程序文件的ELF头指示的有效大小计算得到，针对在程序尾部拼接随机数据逃避检测的场景
 */
struct exe_info {
	ino_t ino;
	dev_t dev;
	time_t ctime;
	char md5[S_MD5LEN];
	char md5_2[S_MD5LEN];
	struct list_head list;
};
typedef struct exe_info exeinfo_t;
struct exe_list {
	struct list_head queue;
	rwlock_t lock;
};
typedef struct exe_list exelist_t;
#define EXELISTNUM 10
extern exelist_t exelist[EXELISTNUM];

struct sniper_iplist {
	struct list_head queue;
	rwlock_t lock;
	int count;
};
typedef struct sniper_iplist iplist_t;
#define IPLISTNUM 65536 //x.x.0.0~x.x.255.255

extern iplist_t lockiplist[IPLISTNUM];
extern iplist_t lockipmsg[IPLISTNUM];
extern iplist_t blackinmsg[IPLISTNUM];
extern iplist_t blackoutmsg[IPLISTNUM];
extern iplist_t honeyportmsg[IPLISTNUM];
extern iplist_t portscanmsg[IPLISTNUM];

/* 阻断ip索引 */
struct lockip_info {
	struct sniper_ip ip;
	unsigned int reason;
	time_t time_locked;      //被锁的时刻，即主机当前运行了多久
	time_t time_unlock;
	struct list_head list;
};
typedef struct lockip_info lockipinfo_t;

/* 计时采用机器时间，现实时间如果修改会导致计时不准 */
struct msgip_info {
	struct net_flags flags;
	struct sniper_ip ip;     //访问的internet ip
	struct sniper_ip myip;   //本机ip
	unsigned short port;     //访问的internet端口
	unsigned short myport;   //本机端口
	unsigned int repeat;     //压缩期内重复了多少次
	time_t last_report_time; //即开始压缩的机器时间
	struct timeval last_report_tv; //即开始压缩的现实时间
	char comm[S_COMMLEN];    //访问internet的进程
	unsigned int portlist_size;  //端口列表空间大小
	unsigned int ports_count;    //端口扫描次数
	unsigned short *portlist;    //扫描的端口列表
	struct list_head list;
};
typedef struct msgip_info msgipinfo_t;

struct connack_info {
	unsigned short peerport; //对方端口
	short ackcount;  //>=2，表示存在连接；-1表示断开连接期间
	time_t lastackt; //最后一个ack包的时间，用于超时清理
	struct list_head list;
};
typedef struct connack_info connackinfo_t; //用ack包的计数来准确判断是否是连接


struct sniper_domain_table {
	char *domain;
};
typedef struct sniper_domain_table domaintbl_t;

struct sniper_dnslist {
	struct list_head queue;
	rwlock_t lock;
};
typedef struct sniper_dnslist dnslist_t;
struct dnsquery_info {
	time_t queryt;
	uid_t uid;
	pid_t pid;
	pid_t tgid;
	char comm[S_COMMLEN];
	unsigned long long proctime;
	unsigned short id; //answer的id要配对
	unsigned short flags;
	char domain[S_DOMAIN_NAMELEN];
	struct list_head list;
};
typedef struct dnsquery_info dnsqinfo_t;

struct msgdns_info {
	char domain[S_DOMAIN_NAMELEN];
	char ip[S_IPLEN];
	time_t last_report_time; //即开始压缩的机器时间
	struct timeval last_report_tv; //即开始压缩的现实时间
	unsigned int repeat;     //压缩期内重复了多少次
	char comm[S_COMMLEN];    //访问dns的进程
	pid_t pid;
	uid_t uid;
	unsigned long long proctime;
	unsigned char terminate; //是否阻断访问dns
	unsigned char black; //是否黑名单
	struct list_head list;
};
typedef struct msgdns_info msgdnsinfo_t;

extern dnslist_t dnsqlist;
extern dnslist_t dnsmsglist;


/* 记录非root进程的用户id和capability信息，用于检查是否有提权 */
struct uid_cred {
	uid_t uid,euid,fsuid;
	gid_t gid,egid,fsgid;
};
struct cap_cred {
	kernel_cap_t   cap_permitted;
};
struct priv_status {
	pid_t not_root_pid;
	time_t start_time;
	struct uid_cred uidcred;
	struct cap_cred capcred;
	int once_raised;
};
//TODO 可废弃Probe_xxx
enum probetype {
	Probe_exec = 1,
	Probe_execret,
	Probe_proc,
	Probe_readdir,
	Probe_forkret,
	Probe_fork,
	Probe_inode_permission,
	Probe_generic_permission,
	Probe_capable,
	Probe_dirtycow,
	Probe_dirtypipe,
	Probe_exit,
	Probe_privup,
	Probe_kill,
	Probe_file,
	Probe_fput,
	Probe_net,
	Probe_opendisk
};

extern int my_pid_max;
extern struct priv_status *mypriv;

struct file_stat {
	unsigned long process_ctime;
	loff_t process_size;
};

/* 进程策略相关数据结构 */
extern struct kern_process_rules sniper_prule;

extern rwlock_t sniper_prule_lock;
extern rwlock_t sniper_pmiddleware_lock;
extern rwlock_t sniper_pblack_lock;
extern rwlock_t sniper_pwhite_lock;
extern rwlock_t sniper_ptrust_lock;
extern rwlock_t sniper_pfilter_lock;
extern rwlock_t sniper_pcommand_lock;
extern rwlock_t sniper_pminepool_lock;

extern unsigned int sniper_prule_ver;
extern unsigned int sniper_pmiddleware_ver;
extern unsigned int sniper_pblack_ver;
extern unsigned int sniper_pwhite_ver;
extern unsigned int sniper_ptrust_ver;
extern unsigned int sniper_pfilter_ver;
extern unsigned int sniper_pcommand_ver;
extern unsigned int sniper_pminepool_ver;

extern char *sniper_pmiddleware;
extern int   sniper_pmiddleware_count;

extern char *sniper_pblack;
extern int   sniper_pblack_count;

extern char *sniper_pwhite;
extern int   sniper_pwhite_count;

extern char *sniper_ptrust;
extern int   sniper_ptrust_count;

extern char *sniper_pfilter;
extern int   sniper_pfilter_count;

extern char *sniper_pcommand;
extern int   sniper_pcommand_count;

extern domaintbl_t *sniper_pminepool;
extern int sniper_pminepool_count;

#define SNIPER_FILTER_PIDS 128
extern int next_filter_pid_arrayidx;
struct sniper_filter_pid {
	pid_t pid;
	unsigned long long proctime;
};
extern struct sniper_filter_pid sniper_pfilter_pid[SNIPER_FILTER_PIDS];

/* 文件策略相关数据结构 */
extern struct kern_file_policy sniper_fpolicy;

extern rwlock_t sniper_fpolicy_lock;
extern rwlock_t sniper_fsensitive_lock;
extern rwlock_t sniper_flog_delete_lock;
extern rwlock_t sniper_fsafe_lock;
extern rwlock_t sniper_flogcollector_lock;
extern rwlock_t sniper_fmiddle_target_lock;
extern rwlock_t sniper_fmiddle_binary_lock;
extern rwlock_t sniper_fmiddle_script_lock;
extern rwlock_t sniper_fillegal_script_lock;
extern rwlock_t sniper_fwebshell_detect_lock;
extern rwlock_t sniper_fblack_lock;
extern rwlock_t sniper_ffilter_lock;
extern rwlock_t sniper_fusb_lock;
extern rwlock_t sniper_fencrypt_lock;

extern unsigned int sniper_fpolicy_ver;
extern unsigned int sniper_fsensitive_ver;
extern unsigned int sniper_flog_delete_ver;
extern unsigned int sniper_fsafe_ver;
extern unsigned int sniper_flogcollector_ver;
extern unsigned int sniper_fmiddle_target_ver;
extern unsigned int sniper_fmiddle_binary_ver;
extern unsigned int sniper_fmiddle_script_ver;
extern unsigned int sniper_fillegal_script_ver;
extern unsigned int sniper_fwebshell_detect_ver;
extern unsigned int sniper_fblack_ver;
extern unsigned int sniper_ffilter_ver;
extern unsigned int sniper_fusb_ver;
extern unsigned int sniper_fencrypt_ver;

extern char *sniper_fsensitive;
extern int  sniper_fsensitive_count;

extern char *sniper_flog_delete;
extern int  sniper_flog_delete_count;

extern char *sniper_fsafe;
extern int  sniper_fsafe_count;

extern char *sniper_flogcollector;
extern int  sniper_flogcollector_count;

extern char *sniper_fmiddle_target;
extern char *sniper_fmiddle_binary;
extern char *sniper_fmiddle_script;

extern char *sniper_fillegal_script;
extern int  sniper_fillegal_script_count;

extern char *sniper_fwebshell_detect;
extern int  sniper_fwebshell_detect_count;

extern char *sniper_fblack;
extern char *sniper_fblack;
extern int  sniper_fblack_count;

extern char *sniper_ffilter;
extern int  sniper_ffilter_count;

extern char *sniper_fusb;
extern int  sniper_fusb_count;

extern char *sniper_fencrypt;

typedef struct sniper_my_file_list {
	char *file;
}sniper_my_flist_t;

typedef struct sniper_file_safe {
	unsigned char status;
	char *path;
	char *real_path;
	char *name;
	char *process;
	char *operation;
}sniper_fsafe_t;

typedef struct sniper_file_logcollector {
	char *filepath;
	char *real_path;
	char *extension;
}sniper_flogcollector_t;

typedef struct sniper_file_illegal_script {
	char *filepath;
	char *real_path;
	char *extension;
}sniper_fillegal_script_t;

typedef struct sniper_file_webshell_detect {
	char *filepath;
	char *real_path;
	char *extension;
}sniper_fwebshell_detect_t;

typedef struct sniper_file_black {
	char *filename;
	char *filepath;
	char *md5;
}sniper_fblack_t;

typedef struct sniper_file_filter {
	char *filename;
	char *filepath;
	char *md5;
}sniper_ffilter_t;

typedef struct sniper_file_usb {
	int major;
	int minor;
	char *extension;
}sniper_fusb_t;

typedef struct sniper_file_encrypt_process {
	char *command;
}sniper_fencrypt_process_t;

typedef struct sniper_file_encrypt {
	char *extension;
}sniper_fencrypt_t;


/* 网络策略相关数据结构 */
extern struct kern_net_rules sniper_nrule;
extern unsigned int lockterm;

extern rwlock_t sniper_nrule_lock;
extern rwlock_t sniper_nconnection_lock;
extern rwlock_t sniper_nsshlogin_lock;
extern rwlock_t sniper_nlanip_lock;
extern rwlock_t sniper_nhoneyport_lock;
extern rwlock_t sniper_ndns_lock; //控制对策略的访问
extern rwlock_t sniper_nwhitein_lock;
extern rwlock_t sniper_nwhiteout_lock;
extern rwlock_t sniper_nblackin_lock;
extern rwlock_t sniper_nblackout_lock;
extern rwlock_t sniper_nserver_lock;
extern rwlock_t sniper_ndnsquery_lock; //控制对待解析域名链表的访问
extern rwlock_t domain_cache_lock;
extern rwlock_t sniper_ipv6_lock;

extern unsigned int sniper_nrule_ver;
extern unsigned int sniper_nconnection_filterip_ver;
extern unsigned int sniper_nsshlogin_filterip_ver;
extern unsigned int sniper_nlanip_ver;
extern unsigned int sniper_nhoneyport_ver;
extern unsigned int sniper_nhoneyport_filterip_ver;
extern unsigned int sniper_nhoneyport_trustip_ver;
extern unsigned int sniper_nhoneyport_trustipv6_ver;
extern unsigned int sniper_ndnsfilter_ver;
extern unsigned int sniper_ndnsblack_ver;
extern unsigned int sniper_ndnswhite_ver;
extern unsigned int sniper_ndnstrust_ver;
extern unsigned int sniper_nwhitein_ver;
extern unsigned int sniper_nwhiteout_ver;
extern unsigned int sniper_nblackin_ver;
extern unsigned int sniper_nblackout_ver;
extern unsigned int sniper_nserver_ver;

extern char *sniper_nconnection_filterip;
extern int   sniper_nconnection_filterip_count;

extern char *sniper_nsshlogin_filterip;
extern int   sniper_nsshlogin_filterip_count;

extern char *sniper_nlanip;
extern int   sniper_nlanip_count;

extern char *sniper_nhoneyport;
extern int   sniper_nhoneyport_count;
extern char *sniper_nhoneyport_filterip;
extern int   sniper_nhoneyport_filterip_count;
extern char *sniper_nhoneyport_trustip;
extern int   sniper_nhoneyport_trustip_count;
extern int   sniper_nhoneyport_trustipv6_count;
extern int   depend_current_mode(const int ret_st);

extern domaintbl_t *sniper_ndnsfilter;
extern int sniper_ndnsfilter_count;

extern domaintbl_t *sniper_ndnsblack;
extern int sniper_ndnsblack_count;

extern domaintbl_t *sniper_ndnswhite;
extern int sniper_ndnswhite_count;

extern domaintbl_t *sniper_ndnstrust;
extern int sniper_ndnstrust_count;

extern char *sniper_nwhitein;
extern int   sniper_nwhitein_count;

extern char *sniper_nwhiteout;
extern int   sniper_nwhiteout_count;

extern char *sniper_nblackin;
extern int   sniper_nblackin_count;

extern char *sniper_nblackout;
extern int   sniper_nblackout_count;

extern char *sniper_nserver;
extern int   sniper_nserver_count;

extern int host_quarantine;

extern int client_mode;

/* 用于init_taskreq()的flag参数 */
#define INIT_WITH_PINFO 0x1
#define INIT_WITH_CMD   0x2

/* common.c */
extern int sniper_ipv6_addr_loopback(const struct in6_addr *a);
extern void my_addr2ip(void *addr, char *ip, int family);
extern int is_err_or_null(unsigned long addr, char *desc);
extern void current_interrupt_status(char *str);
extern void disable_memory_write_protection(void);
extern void restore_memory_write_protection(void);
extern char *safebasename(char *path);
extern void safedirname(char *path, char *dir, int dir_len);
extern void my_put_task_struct(struct task_struct *t);
extern struct task_struct *get_task_from_pid(pid_t pid);
extern pid_t get_ppid(void);
extern struct task_struct *get_parent(struct task_struct *task);
extern void get_parent_info(int *flags, struct parent_info *info);
extern void sniper_do_gettimeofday(struct timeval *tv);
extern time_t sniper_uptime(void);
extern unsigned long long get_process_time(struct task_struct *task);
extern taskreq_t *init_taskreq(int flag);
extern taskreq_t *init_taskreq_pid(pid_t pid);
extern void get_current_comm(char *comm, unsigned long *ino);
extern void set_taskreq_cmd(taskreq_t *req, struct task_struct *task);
extern int skip_current(int *flags, struct parent_info *pinfo);
extern void my_bind_cpu(void);
extern void my_unbind_cpu(cpumask_t *newmask);
extern int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr);
extern int process_engine_status(void);
extern char *get_exe_file_path(struct file *exe_file, char *buf, int buflen);
extern void get_current_process(char *process, int len);
extern int sniper_getpath(struct dentry *dentry, struct vfsmount *mnt, char *buf, int buflen, int *flag);
extern int getcwdpath(char *buf, int buflen);
extern int using_network(void);
extern int current_using_network(void);
extern int parent_is_shell_script(void);
extern int diff_fds_from_parent(void);
extern void print_task_fds(struct files_struct *files);
extern int is_commandline(void);
extern int get_current_peer(conninfo_t *info);
extern int get_task_peer(conninfo_t *info, struct task_struct *task);
extern int task_using_socket(struct task_struct *task, struct inode *sock_inode);
extern int is_pipe_peer(struct task_struct *task, unsigned long ino, char *act);
extern int is_current_pipe_peer(struct task_struct *task);
extern char *stringsep(char **s, const char *ct);
extern int is_match_control_file(char *file, char *cmd);
extern int ipstr2ip(char *ipstr, struct sniper_ip *ip);
extern int get_process_program_name(struct task_struct *task, char __user *buffer, int buflen);
extern struct file *my_get_mm_exe_file(struct mm_struct *mm);
extern struct file *my_fcheck_files(struct files_struct *files, unsigned int fd);
extern void net_ipv6_conf_reset(void);
extern int net_ipv6_conf_insert(struct sniper_ipv6 *ipv6);
extern void get_tty_from_fd1(char *tty);
extern int get_file_stat(char *pathname, struct file_stat *stat);

/*cmd_score.c */
extern int get_command_weight(char *cmd, char *cmdline);
extern int is_danger_cmd(char *cmdline);

/* msg.c */
extern int msg_init(void);
extern void msg_exit(void);
extern void send_data_to_user(char *buffer, int len, pid_t pid, int type);
extern void send_msg_to_user(char *buffer, int len, pid_t nlmsg_pid);
extern void sniper_freerules(void);
extern void sniper_netlink_release(void);
extern int ksniperd_netin_stopped;

/* exec_hook.c */
extern int exec_hook_init(void);
extern void exec_hook_exit(void);
extern int is_trust_cmd(taskreq_t *req, int event_flag, struct linux_binprm *bprm, char *mid_md5);
extern int is_filter_cmd(taskreq_t *req, struct linux_binprm *bprm);

/* antikill.c */
extern int antikill_init(pid_t pid);
extern void antikill_exit(void);

/* readdir_hook.c */
extern int readdir_hook_init(void);
extern void readdir_hook_exit(void);

/* check_privup.c */
#define PRIVUP_EXEC    1  //提权进程执行命令
#define PRIVUP_FILE    2  //提权进程访问文件
#define PRIVUP_SUID    1  //suid程序提权
#define PRIVUP_NOTSUID 2  //非suid程序提权
#define PRIVUP_NOTSYSSUID 3  //非系统路径下的suid程序提权
#define PRIVUP_STOP    4
extern int check_privup(struct parent_info *pinfo, int flag, char *target);
extern void copy_pinfo(taskreq_t *req, struct parent_info *pinfo);

/* dirtycow_hook.c */
extern int dirtycow_hook_init(void);
extern void dirtycow_hook_exit(void);

/* exit_hook.c */
extern int exit_hook_init(void);
extern void exit_hook_exit(void);
extern int is_valid_str(char *str);

/* file_moni.c */
#define ENC_CACHE_NUM 4
struct _encrypt_info{
	char encrypt_cmd[S_CMDLEN];
	char md5[S_MD5LEN];
};
extern int next_encidx;
extern struct _encrypt_info encrypt_info[ENC_CACHE_NUM];

extern int  file_hook_init(void);
extern void file_hook_exit(void);

/* rename_moni.c */
extern int  rename_hook_init(void);
extern void rename_hook_exit(void);

/* md5.c */
extern int md5_file(struct file *file, char *output, size_t size);
extern int md5_path(char *pathname, char *output, size_t size);
extern int md5_string(char *string, char *output);

/* lookup_symbols.c */
extern int sniper_lookup_symbols(void);

/* file_moni_security_ops.c */
extern int security_add_sniper_file_permission_hook(void);
extern int security_del_sniper_file_permission_hook(void);

/* netfilter.c */
extern int net_hook_init(void);
extern void net_hook_exit(void);
extern int net_hook_ipv6_init(void);
extern void net_hook_ipv6_exit(void);
extern void sniper_del_lockip(struct sniper_ip *ip);
extern void sniper_add_lockip(struct sniper_ip *ip, unsigned int reason, time_t lock_time);
extern int is_internet(struct sniper_ip *ip);
extern int is_service_port(unsigned short myport);

/* dns.c */
extern int handle_dns_answer(char *dns_hdr, int udp_len, struct kern_net_rules *nrule);
extern void handle_dns_query(char *udp_header, struct kern_net_rules *nrule);
extern void clean_expired_dnsquery(void);

/* procfs.c */
#define SNIPER_PROCFS_BUFSIZE 1048576
extern int procfs_init(void);
extern void procfs_exit(void);

/* entry.c */
extern unsigned long sniper_ctime;

/* 日志级别摘自user/lst.h */
#define LOG_NORMAL              1
#define LOG_KEY                 2
#define LOG_LOW_RISK            3
#define LOG_MIDDLE_RISK         4
#define LOG_HIGH_RISK           5

/* 进程事件和锁ip的事件定义摘自user/lst.h */
#define PROCESS_NORMAL                                  1000 //一般
#define PROCESS_SCHEDULE                                1001 //计划任务
#define PROCESS_ABNORMAL                                1002 //异常
#define PROCESS_SUSPICIOUS                              1003 //可疑
#define PROCESS_DANGEROUS                               1004 //危险
#define PROCESS_VIOLATION                               1005 //违规
#define PROCESS_MIDDLE_EXECUTION                        1006 //中间件执行
#define PROCESS_PRIVILEGE_ESCALATION                    1007 //提权
#define PROCESS_PHISHING_ATTACKS                        1008 //钓鱼
#define PROCESS_REBOUND_SHELL                           1009 //反弹shell
#define PROCESS_REMOTE_EXECUTION                        1010 //远程执行
#define PROCESS_WEBSHELL_EXECUTION                      1011 //webshell
#define PROCESS_ROOTKIT                                 1012 //rootkit
#define PROCESS_GATHER_INFORMATION                      1013 //收集信息
#define PROCESS_PORT_FORWARD                            1014 //端口转发
#define PROCESS_UNUSUAL_OPERATION                       1015 //异常人为操作
#define PROCESS_ENDDING                                 1016 //进程结束
#define PROCESS_MINERWARE                               1017 //挖矿
#define PROCESS_MBRWARE                                 1018 //MBR监控
#define PROCESS_MBR_PROTECT                             1019 //MBR防护
#define PROCESS_FIREWALL_CHANGE                         1020 //非法修改防火墙规则
#define PROCESS_RANSOMWARE                              1021 //勒索软件

#define LOGIN_ILLEGAL_REMOTE                            2004 //非法远程登录
#define LOGIN_PASSWD_CRACK                              2005 //暴力密码破解
#define FILE_UPLOAD_RECOGNITION                         3009 //上传漏洞
#define NET_PORT_SCAN                                   4001 //端口扫描
#define NET_PORT_HONEY                                  4002 //端口诱捕



/* getXid */
#include <linux/audit.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#define currentuid()		(current->uid)
#define currenteuid()		(current->euid)
#define currentsuid()		(current->suid)
#define currentfsuid()		(current->fsuid)
#define taskuid(t)		(t->uid)
#define taskeuid(t)		(t->euid)
#define tasksuid(t)		(t->suid)
#define taskfsuid(t)		(t->fsuid)
#define currentgid()		(current->gid)
#define currentegid()		(current->egid)
#define currentsgid()		(current->sgid)
#define currentfsgid()		(current->fsgid)
#define taskgid(t)		(t->gid)
#define taskegid(t)		(t->egid)
#define tasksgid(t)		(t->sgid)
#define taskfsgid(t)		(t->fsgid)
#define fileuid(f)		(f->f_uid)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#include <linux/cred.h>
#define currentuid()		current_uid()
#define currenteuid()		current_euid()
#define currentsuid()		current_suid()
#define currentfsuid()		current_fsuid()
#define taskuid(t)		(task_cred_xxx((t), uid))
#define taskeuid(t)		(task_cred_xxx((t), euid))
#define tasksuid(t)		(task_cred_xxx((t), suid))
#define taskfsuid(t)		(task_cred_xxx((t), fsuid))
#define currentgid()		current_gid()
#define currentegid()		current_egid()
#define currentsgid()		current_sgid()
#define currentfsgid()		current_fsgid()
#define taskgid(t)		(task_cred_xxx((t), gid))
#define taskegid(t)		(task_cred_xxx((t), egid))
#define tasksgid(t)		(task_cred_xxx((t), sgid))
#define taskfsgid(t)		(task_cred_xxx((t), fsgid))
#define fileuid(f)		(f->f_cred->uid)
#else
#include <linux/cred.h>
#define currentuid()		from_kuid(&init_user_ns, current_uid())
#define currenteuid()		from_kuid(&init_user_ns, current_euid())
#define currentsuid()		from_kuid(&init_user_ns, current_suid())
#define currentfsuid()		from_kuid(&init_user_ns, current_fsuid())
#define taskuid(t)		from_kuid(&init_user_ns, (task_cred_xxx((t), uid)))
#define taskeuid(t)		from_kuid(&init_user_ns, (task_cred_xxx((t), euid)))
#define tasksuid(t)		from_kuid(&init_user_ns, (task_cred_xxx((t), suid)))
#define taskfsuid(t)		from_kuid(&init_user_ns, (task_cred_xxx((t), fsuid)))
#define currentgid()		from_kgid(&init_user_ns, current_gid())
#define currentegid()		from_kgid(&init_user_ns, current_egid())
#define currentsgid()		from_kgid(&init_user_ns, current_sgid())
#define currentfsgid()		from_kgid(&init_user_ns, current_fsgid())
#define taskgid(t)		from_kgid(&init_user_ns, (task_cred_xxx((t), gid)))
#define taskegid(t)		from_kgid(&init_user_ns, (task_cred_xxx((t), egid)))
#define tasksgid(t)		from_kgid(&init_user_ns, (task_cred_xxx((t), sgid)))
#define taskfsgid(t)		from_kgid(&init_user_ns, (task_cred_xxx((t), fsgid)))
#define fileuid(f)		from_kuid(&init_user_ns, f->f_cred->uid)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define loginuid(t)	audit_get_loginuid(t->audit_context)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#define loginuid(t)	audit_get_loginuid(t)
#else
#define loginuid(t)	from_kuid(&init_user_ns, audit_get_loginuid(t))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
extern ssize_t kernel_my_write(struct file *file, const char *buf, size_t count, loff_t pos);
#endif
extern int copy_file_backup(char *pathname, size_t size, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_encrypt(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int report_trap_file_change(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_loop_open(struct inode *inode);
extern int get_file_md5_from_inode(struct inode *inode, char *pathname, char *output, size_t size);
extern int check_black_file_after(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_abnormal_change(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int send_virus_file_msg(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
#endif /* _MONITOR_INTERFACE_H */
