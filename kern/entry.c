/*
 * main kernel module entry
 */

#include "interface.h"
#include <linux/proc_fs.h>

int sniper_netlink = NETLINK_SNIPER;
int sniper_dump = 1;
int exec_debug = 0;
int file_debug = 0;
int virus_debug = 0;
int net_debug = 0;
int mem_debug = 0;
int filesize_threshold = 30; //用于监控写打开大文件

atomic_t sniper_usage[SNIPER_HOOKS_NUM];

struct kern_process_rules sniper_prule = {0};
struct kern_file_policy sniper_fpolicy = {0};
struct kern_net_rules sniper_nrule = {0};

rwlock_t sniper_prule_lock;
rwlock_t sniper_pmiddleware_lock;
rwlock_t sniper_pblack_lock;
rwlock_t sniper_pwhite_lock;
rwlock_t sniper_ptrust_lock;
rwlock_t sniper_pfilter_lock;
rwlock_t sniper_pcommand_lock;
rwlock_t sniper_pminepool_lock;

/* 策略版本号，每变更一次加1 */
unsigned int sniper_prule_ver = 0;
unsigned int sniper_pmiddleware_ver = 0;
unsigned int sniper_pblack_ver = 0;
unsigned int sniper_pwhite_ver = 0;
unsigned int sniper_ptrust_ver = 0;
unsigned int sniper_pfilter_ver = 0;
unsigned int sniper_pcommand_ver = 0;
unsigned int sniper_pminepool_ver = 0;


rwlock_t sniper_fpolicy_lock;
rwlock_t sniper_fsensitive_lock;
rwlock_t sniper_flog_delete_lock;
rwlock_t sniper_fsafe_lock;
rwlock_t sniper_flogcollector_lock;
rwlock_t sniper_fmiddle_target_lock;
rwlock_t sniper_fmiddle_binary_lock;
rwlock_t sniper_fmiddle_script_lock;
rwlock_t sniper_fillegal_script_lock;
rwlock_t sniper_fwebshell_detect_lock;
rwlock_t sniper_fblack_lock;
rwlock_t sniper_ffilter_lock;
rwlock_t sniper_fusb_lock;
rwlock_t sniper_fencrypt_lock;

unsigned int sniper_fpolicy_ver = 0;
unsigned int sniper_fsensitive_ver = 0;
unsigned int sniper_flog_delete_ver = 0;
unsigned int sniper_fsafe_ver = 0;
unsigned int sniper_flogcollector_ver = 0;
unsigned int sniper_fmiddle_target_ver = 0;
unsigned int sniper_fmiddle_binary_ver = 0;
unsigned int sniper_fmiddle_script_ver = 0;
unsigned int sniper_fillegal_script_ver = 0;
unsigned int sniper_fwebshell_detect_ver = 0;
unsigned int sniper_fblack_ver = 0;
unsigned int sniper_ffilter_ver = 0;
unsigned int sniper_fusb_ver = 0;
unsigned int sniper_fencrypt_ver = 0;


rwlock_t sniper_nrule_lock;
rwlock_t sniper_nconnection_lock;
rwlock_t sniper_nlanip_lock;
rwlock_t sniper_nhoneyport_lock;
rwlock_t sniper_ndns_lock;
rwlock_t sniper_nwhitein_lock;
rwlock_t sniper_nwhiteout_lock;
rwlock_t sniper_nblackin_lock;
rwlock_t sniper_nblackout_lock;
rwlock_t sniper_nserver_lock;
rwlock_t sniper_ipv6_lock;

/* 防御黑名单域名和矿池，会将之解析成0.0.0.0，但为了报日志的时候能报出ip，
   建一个domian cache来存他们的真实ip。这个cache的插入和查询由下面的锁控制 */
rwlock_t domain_cache_lock;

unsigned int sniper_nrule_ver = 0;
unsigned int sniper_nconnection_filterip_ver = 0;
unsigned int sniper_nlanip_ver = 0;
unsigned int sniper_nhoneyport_ver = 0;
unsigned int sniper_nhoneyport_filterip_ver = 0;
unsigned int sniper_nhoneyport_trustip_ver = 0;
unsigned int sniper_nhoneyport_trustipv6_ver = 0;
unsigned int sniper_ndnsfilter_ver = 0;
unsigned int sniper_ndnsblack_ver = 0;
unsigned int sniper_ndnswhite_ver = 0;
unsigned int sniper_ndnstrust_ver = 0;
unsigned int sniper_nwhitein_ver = 0;
unsigned int sniper_nwhiteout_ver = 0;
unsigned int sniper_nblackin_ver = 0;
unsigned int sniper_nblackout_ver = 0;
unsigned int sniper_nserver_ver = 0;


exelist_t exelist[EXELISTNUM]    = {{{0}}};
iplist_t lockiplist[IPLISTNUM]   = {{{0}}};
iplist_t lockipmsg[IPLISTNUM]    = {{{0}}};
iplist_t blackinmsg[IPLISTNUM]   = {{{0}}};
iplist_t blackoutmsg[IPLISTNUM]  = {{{0}}};
iplist_t honeyportmsg[IPLISTNUM] = {{{0}}};
iplist_t portscanmsg[IPLISTNUM]  = {{{0}}};

rwlock_t sniper_ndnsquery_lock;
dnslist_t dnsqlist = {{0}};
dnslist_t dnsmsglist = {{0}};

unsigned long sniper_ctime = 0;

static void init_exelist(void)
{
	int i = 0;

	for (i = 0; i < EXELISTNUM; i++) {
		rwlock_init(&exelist[i].lock);
		INIT_LIST_HEAD(&exelist[i].queue);
	}
}

static void init_iplist(iplist_t *iplist)
{
	int i = 0;

	for (i = 0; i < IPLISTNUM; i++) {
		rwlock_init(&(iplist->lock));
		INIT_LIST_HEAD(&(iplist->queue));
		iplist++;
	}
}
static void init_dnslist(void)
{
	rwlock_init(&dnsqlist.lock);
	INIT_LIST_HEAD(&dnsqlist.queue);

	rwlock_init(&dnsmsglist.lock);
	INIT_LIST_HEAD(&dnsmsglist.queue);
}

static void sniper_rwlock_init(void)
{
	/* 进程策略相关的锁 */
	rwlock_init(&sniper_prule_lock);
	rwlock_init(&sniper_pmiddleware_lock);
	rwlock_init(&sniper_pblack_lock);
	rwlock_init(&sniper_pwhite_lock);
	rwlock_init(&sniper_ptrust_lock);
	rwlock_init(&sniper_pfilter_lock);
	rwlock_init(&sniper_pcommand_lock);
	rwlock_init(&sniper_pminepool_lock);

	/* 文件策略相关的锁 */
	rwlock_init(&sniper_fpolicy_lock);
	rwlock_init(&sniper_fsensitive_lock);
	rwlock_init(&sniper_flog_delete_lock);
	rwlock_init(&sniper_fsafe_lock);
	rwlock_init(&sniper_flogcollector_lock);
	rwlock_init(&sniper_fmiddle_target_lock);
	rwlock_init(&sniper_fmiddle_binary_lock);
	rwlock_init(&sniper_fmiddle_script_lock);
	rwlock_init(&sniper_fillegal_script_lock);
	rwlock_init(&sniper_fwebshell_detect_lock);
	rwlock_init(&sniper_fblack_lock);
	rwlock_init(&sniper_ffilter_lock);
	rwlock_init(&sniper_fusb_lock);
	rwlock_init(&sniper_fencrypt_lock);

	/* 网络策略相关的锁 */
	rwlock_init(&sniper_nrule_lock);
	rwlock_init(&sniper_nconnection_lock);
	rwlock_init(&sniper_nlanip_lock);
	rwlock_init(&sniper_nhoneyport_lock);
	rwlock_init(&sniper_ndns_lock);
	rwlock_init(&sniper_nwhitein_lock);
	rwlock_init(&sniper_nwhiteout_lock);
	rwlock_init(&sniper_nblackin_lock);
	rwlock_init(&sniper_nblackout_lock);
	rwlock_init(&sniper_nserver_lock);
	rwlock_init(&sniper_ndnsquery_lock);
	rwlock_init(&domain_cache_lock);
	rwlock_init(&sniper_ipv6_lock);
}

static int __init monitor_init(void)
{
	int i = 0, ret = 0, size = 0;
	struct file_stat stat = {0};

	if (sniper_lookup_symbols() < 0) {
		printk("Sniper init Fail!\n");
		return -1;
	}

	sniper_rwlock_init();

	if (alloc_sniper_memuse() < 0) {
		printk("Mem usage init fail, Sniper init fail!\n");
		return -1;
	}

	if ((ret = msg_init()) != 0) {
		free_sniper_memuse();
		printk("Msg queue init fail, Sniper init fail!\n");
		return -1;
	}

	init_exelist();

	init_iplist(lockiplist);
	init_iplist(lockipmsg);
	init_iplist(blackinmsg);
	init_iplist(blackoutmsg);
	init_iplist(honeyportmsg);
	init_iplist(portscanmsg);

	init_dnslist();

	for (i = 0; i < SNIPER_HOOKS_NUM; i++) {
		atomic_set(&sniper_usage[i], 1);
	}


	size = SNIPER_MIDDLEWARE_NUM * sizeof(struct sniper_middleware);
	sniper_pmiddleware = sniper_vmalloc(size, VMALLOC_PMIDDLE);
	if (sniper_badptr(sniper_pmiddleware)) {
		myprintk("malloc %d bytes sniper_pmiddleware fail, no memory\n", size);
		sniper_pmiddleware = NULL;
	} else {
		memset(sniper_pmiddleware, 0, size);
	}

	lsm_hooks_init();
	// net_hook_init();

	//TODO 20220507 不完善，可能导致内核core，屏蔽
	//net_hook_ipv6_init();

	// dirtycow_hook_init();

	procfs_init();

	/* 获取sniper进程的ctime时间, 防勒索功能中与其他进程文件ctime做比较 */
	if (get_file_stat("/sbin/sniper", &stat) < 0) {
		sniper_ctime = 0;
	} else {
		sniper_ctime = stat.process_ctime;
	}

	printk("Sniper on\n");
	return 0;
}

static void clean_exelist(void)
{
	int i = 0;
	exeinfo_t *exeinfo = NULL, *tmp = NULL;

	for (i = 0; i < EXELISTNUM; i++) {
		write_lock(&exelist[i].lock);
		list_for_each_entry_safe(exeinfo, tmp, &exelist[i].queue, list) {
			list_del(&exeinfo->list);
			sniper_kfree(exeinfo, sizeof(exeinfo_t), KMALLOC_EXELIST);
		}
		write_unlock(&exelist[i].lock);
	}
}

void clean_lockiplist(void)
{
	int i = 0;
	iplist_t *iplist = lockiplist;
	lockipinfo_t *info = NULL, *tmp = NULL;
	int size = sizeof(lockipinfo_t);

	for (i = 0; i < IPLISTNUM; i++, iplist++) {
		write_lock_bh(&iplist->lock);
		list_for_each_entry_safe(info, tmp, &iplist->queue, list) {
			list_del(&info->list);
			iplist->count--;
			sniper_kfree(info, size, KMALLOC_LOCKIP);
		}
		write_unlock_bh(&iplist->lock);
	}
}

void clean_iplist(iplist_t *iplist, char *desc, int type)
{
	int i = 0;
	msgipinfo_t *info = NULL, *tmp = NULL;
	int size = sizeof(msgipinfo_t);

	for (i = 0; i < IPLISTNUM; i++, iplist++) {
		write_lock_bh(&iplist->lock);
		list_for_each_entry_safe(info, tmp, &iplist->queue, list) {
			list_del(&info->list);
			iplist->count--;
			sniper_kfree(info->portlist, info->portlist_size, KMALLOC_PORTLIST);
			sniper_kfree(info, size, type);
		}
		if (iplist->count != 0) {
			if (desc) {
				myprintk("%s[%d].count %d\n", desc, i, iplist->count);
			} else {
				myprintk("(malloc type %d)[%d].count %d\n", type, i, iplist->count);
			}
		}
		write_unlock_bh(&iplist->lock);
	}
}

void clean_dnslist(dnslist_t *dnslist)
{
	dnsqinfo_t *info = NULL, *tmp = NULL;

	write_lock_bh(&dnslist->lock);
	list_for_each_entry_safe(info, tmp, &dnslist->queue, list) {
		list_del(&info->list);
		sniper_kfree(info, sizeof(dnsqinfo_t), KMALLOC_DNSQUERY);
	}
	write_unlock_bh(&dnslist->lock);
}

static void __exit monitor_fini(void)
{
	int i = 0, loops = 0, num = 0;
	int size = 0;

        nl_exec_pid = 0;
        nl_file_pid = 0;
        nl_virus_pid = 0;
        nl_net_pid = 0;

	sniper_freerules();

	msg_exit();

	procfs_exit();

        // net_hook_exit();
	// net_hook_ipv6_exit();
	lsm_hooks_exit();
	// dirtycow_hook_exit();

	/* 等待正在使用hook的进程用完hook */
	loops = 0;
	while (1) {
		int doprint = 0, inuse = 0;

		if (loops % 100 == 0) {
			doprint = 1;
		}

		for (i = 0; i < SNIPER_HOOKS_NUM; i++) {
			num = atomic_read(&sniper_usage[i]);
			if (num != 1) {
				inuse = 1;
				if (doprint) {
					printk("sniper_usage[%d] %d\n", i, num);
				}
			}
		}

		if (!inuse) {
			break;
		}

		loops++;
		msleep(10);
	}
	if (loops) {
		myprintk("wait %d * 10ms before off\n", loops); 
	}

	/* 等待ksniperd_netin线程结束 */
	loops = 0;
	while (1) {
		if (ksniperd_netin_stopped) {
			break;
		}
		if (loops % 100 == 0) {
			printk("wait ksniperd_netin stopped\n");
		}
		loops++;
		msleep(10);
	}
	if (loops) {
		myprintk("wait %d * 10ms before ksniperd_netin stopped\n", loops); 
	}
	sniper_netlink_release();

	clean_exelist();

	clean_lockiplist();
	clean_iplist(lockipmsg, "lockipmsg", KMALLOC_LOCKIP);
	clean_iplist(blackinmsg, "blackinmsg", KMALLOC_BLACKIN);
	clean_iplist(blackoutmsg, "blackoutmsg", KMALLOC_BLACKOUT);
	clean_iplist(honeyportmsg, "honeyportmsg", KMALLOC_HONEYPORT);
	clean_iplist(portscanmsg, "portscanmsg", KMALLOC_PORTSCAN);
	clean_dnslist(&dnsqlist);
	clean_dnslist(&dnsmsglist);

	size = SNIPER_MIDDLEWARE_NUM * sizeof(struct sniper_middleware);
	sniper_vfree(sniper_pmiddleware, size, VMALLOC_PMIDDLE);

	show_sniper_memuse();
	free_sniper_memuse();

	printk("Sniper off\n");
}

module_init(monitor_init);
module_exit(monitor_fini);
MODULE_AUTHOR("<admin@sniper.com>");
MODULE_DESCRIPTION("AntiAPT EDR");
MODULE_LICENSE("GPL");
MODULE_VERSION(SNIPER_VERSION);
