#ifndef _MEM_TRACE_H_
#define _MEM_TRACE_H_

enum {
	KMALLOC_EXELIST = 1,      //触发场景：应用带md5条件的进程规则名单
	KMALLOC_REALCMD,          //触发场景: 在当前目录下执行命令，如./sniper -l
	KMALLOC_TASKREQ,          //触发场景：进程监控
	KMALLOC_LOOKUPPATH,
	KMALLOC_GETPATH,
	KMALLOC_FDNAME,
	KMALLOC_SENSITIVEFILE,
	KMALLOC_LOGDELETE,
	KMALLOC_FILESAFE,
	KMALLOC_LOGCOLLECT,
	KMALLOC_USB,
	KMALLOC_MIDBINARY,
	KMALLOC_MIDSCRIPT,
	KMALLOC_ILLSCRIPT,
	KMALLOC_WEBSHELL,
	KMALLOC_ILLPRINTER,
	KMALLOC_ILLBURNING,
	KMALLOC_FILEBUF,
	KMALLOC_BACKUPFILE,
	KMALLOC_ENCRYPT,
	KMALLOC_TRAPFILE,
	KMALLOC_ABNORMALCHANGE,
	KMALLOC_BLACKFILE,
	KMALLOC_VIRUS,
	KMALLOC_UNLINKPATH,
	KMALLOC_CREATEPATH,
	KMALLOC_LINKPATH,
	KMALLOC_OPENPATH,
	KMALLOC_RENAMEOLDPATH,
	KMALLOC_RENAMENEWPATH,
	KMALLOC_MD5FILE,
	KMALLOC_SYSCONNECT,
	KMALLOC_DNSQUERY,
	KMALLOC_CREATESTR,
	KMALLOC_CREATENODE,
	KMALLOC_LOCKIP,           //触发场景：客户端程序启动时加载上次锁定的ip，和锁定新的ip
	KMALLOC_PORTLIST,
	KMALLOC_BLACKIN,
	KMALLOC_HONEYPORT,
	KMALLOC_PORTSCAN,
	KMALLOC_BLACKOUT,
	VMALLOC_PCMDTBLMEM,       /* 从这里往下是策略使用的空间 ---> */
	VMALLOC_PCMDTBLRULE,
	VMALLOC_PBLACKMEM,
	VMALLOC_PBLACKRULE,
	VMALLOC_PFILTERMEM,
	VMALLOC_PFILTERRULE,
	VMALLOC_PTRUSTMEM,
	VMALLOC_PTRUSTRULE,
	VMALLOC_FSENSITIVEMEM,
	VMALLOC_FSENSITIVERULE,
	VMALLOC_FLOGDELETEMEM,
	VMALLOC_FLOGDELETERULE,
	VMALLOC_FSAFEMEM,
	VMALLOC_FSAFERULE,
	VMALLOC_FLOGCOLLECTMEM,
	VMALLOC_FLOGCOLLECTRULE,
	VMALLOC_FMIDDLE,
	VMALLOC_FMIDDLEBINARY,
	VMALLOC_FMIDDLESCRIPT,
	VMALLOC_ILLSCRIPTMEM,
	VMALLOC_ILLSCRIPTRULE,
	VMALLOC_FWEBSHELLMEM,
	VMALLOC_FWEBSHELLRULE,
	VMALLOC_FBLACKMEM,
	VMALLOC_FBLACKRULE,
	VMALLOC_FFILTERMEM,
	VMALLOC_FFILTERRULE,
	VMALLOC_FUSBMEM,
	VMALLOC_FUSBRULE,
	VMALLOC_FENCRYPTMEM,
	VMALLOC_FENCRYPTRULE,
	VMALLOC_CONNFILTERIP,
	VMALLOC_LANIP,
	VMALLOC_HONEYPORT,
	VMALLOC_PORTSCAN_FILTERIP,
	VMALLOC_PORTSCAN_TRUSTIP,
	VMALLOC_PORTSCAN_TRUSTIPV6,
	VMALLOC_NWHITEIN,
	VMALLOC_NWHITEOUT,
	VMALLOC_NBLACKIN,
	VMALLOC_NBLACKOUT,
	VMALLOC_NSERVER,          //触发场景：修改服务器列表
	VMALLOC_MINEPOOLMEM,      //触发场景：修改矿池列表
	VMALLOC_MINEPOOLRULE,
	VMALLOC_DNSBLACKMEM,      //触发场景：修改域名黑名单
	VMALLOC_DNSBLACKRULE,
	VMALLOC_DNSWHITEMEM,      //触发场景：修改域名白名单
	VMALLOC_DNSWHITERULE,
	VMALLOC_DNSFILTERMEM,     //触发场景：修改域名过滤名单
	VMALLOC_DNSFILTERRULE,
	VMALLOC_DNSTRUSTMEM,      //触发场景：修改域名可信名单
	VMALLOC_DNSTRUSTRULE,     /* <--- 从这里往上是策略使用的空间 */
	VMALLOC_CDROMGID,         //客户端程序启动时自动分配并释放一次
	VMALLOC_EXEC_LOADOFF,     //客户端程序负载高时停止进程监控
	VMALLOC_FILE_LOADOFF,     //客户端程序负载高时停止文件监控
	VMALLOC_NET_LOADOFF,      //客户端程序负载高时停止网络监控
	VMALLOC_PMIDDLE,          //触发场景：有新的网络服务
	VMALLOC_CHECKNSCD,        //触发场景：有nscd服务，并访问域名
	VMALLOC_PROCFS_PROC,      //触发场景：cat /proc/sys/sniper/process_strategy
	VMALLOC_PROCFS_FILE,      //触发场景：cat /proc/sys/sniper/file_strategy
	VMALLOC_PROCFS_NET,       //触发场景：cat /proc/sys/sniper/net_strategy
	VMALLOC_PROCFS_MID,       //触发场景：cat /proc/sys/sniper/middleware
	VMALLOC_PROCFS_MEM,       //触发场景：cat /proc/sys/sniper/mem_usage
	SNIPER_MALLOC_TYPES       //总是放最后，表示分配空间的总的场景数量
};

extern int alloc_sniper_memuse(void);
extern void free_sniper_memuse(void);

#define sniper_kmalloc(size, flag, type)    sniper_kmalloc_trace(size, flag, type, __FILE__, __func__, __LINE__)
#define sniper_kfree(addr, size, type)      sniper_kfree_trace(addr, size, type, __FILE__, __func__, __LINE__); addr = NULL
#define sniper_vmalloc(size, type)          sniper_vmalloc_trace(size, type, __FILE__, __func__, __LINE__)
#define sniper_vfree(addr, size, type)      sniper_vfree_trace(addr, size, type, __FILE__, __func__, __LINE__); addr = NULL

extern void *sniper_kmalloc_trace(int size, int flag, int type, char *file, const char *func, int line);
extern void sniper_kfree_trace(void *addr, int size, int type, char *file, const char *func, int line);

extern void *sniper_vmalloc_trace(int size, int type, char *file, const char *func, int line);
extern void sniper_vfree_trace(void *addr, int size, int type, char *file, const char *func, int line);

extern void show_sniper_memuse(void);
extern void print_memusage(char *buffer, int buffer_len);

#endif
