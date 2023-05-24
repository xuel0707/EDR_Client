/*
 * kernel-user communication
 *
 * 在锁期间不做vmalloc/vfree，避免拿着锁睡眠，否则centos5上会死机
 */

#include "interface.h"

#include <linux/kthread.h>
#include <linux/skbuff.h>
#include <net/netlink.h>   //centos5需要

static struct sock *nl_sk = NULL;

pid_t sniper_pid = 0;
pid_t nl_exec_pid = 0;
pid_t nl_file_pid = 0;
pid_t nl_virus_pid = 0;
pid_t nl_net_pid = 0;
gid_t sniper_cdrom_gid = 0;
char sniper_exec_loadoff = 0;
char sniper_net_loadoff = 0;
char sniper_file_loadoff = 0;

struct sniper_inode sniper_inode = {0};
static void update_sniper_inode(struct nlmsghdr *nlh)
{
	memcpy(&sniper_inode, nlmsg_data(nlh), sizeof(struct sniper_inode));
}

static char *get_newrule_count(struct nlmsghdr *nlh, int size, int *count, char *desc, int ruletype)
{
	int datalen = 0;
	char *newrule = NULL;

	datalen = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (datalen <= 0) {
		myprintk("update %s fail: bad datalen %d\n", desc, datalen);
		return NULL;
	}

	*count = datalen / size;

	newrule = sniper_vmalloc(datalen, ruletype);
	if (!newrule) {
		myprintk("update %s fail, alloc %d memory fail\n", desc, datalen);
		return NULL;
	}

	/* 更新 */
	memcpy(newrule, nlmsg_data(nlh), datalen);

	return newrule;
}

static char *get_newrule(struct nlmsghdr *nlh, int size, int count, char *desc, int ruletype)
{
	int datalen = 0, n = 0;
	char *newrule = NULL;

	datalen = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (datalen <= 0) {
		myprintk("update %s fail: bad datalen %d\n", desc, datalen);
		return NULL;
	}
	n = datalen / size;
	if (count != n) {
		myprintk("update %s fail: bad datalen %d/%d=%d not %d\n", desc, datalen, size, n, count);
		return NULL;
	}

	if (ruletype == KMALLOC_LOCKIP) {
		newrule = sniper_kmalloc(datalen, GFP_ATOMIC, ruletype);
	} else {
		newrule = sniper_vmalloc(datalen, ruletype);
	}
	if (!newrule) {
		myprintk("update %s fail, alloc %d memory fail\n", desc, datalen);
		return NULL;
	}

	/* 更新 */
	memcpy(newrule, nlmsg_data(nlh), datalen);

	return newrule;
}

/* 从文件中读size字节存到buf里 */
static int readfile(char *path, char *buf, int size)
{
	struct file *file = NULL;
	int count = 0;
	loff_t pos = 0;
	ssize_t bytes = 0;

	if (!path || !buf) {
		return -1;
	}

	file = filp_open(path, O_RDONLY, 0);
	if (file == NULL || IS_ERR(file)) {
		myprintk("read %s fail: %ld\n", path, PTR_ERR(file));
		return -1;
	}

	pos = 0;
	while (pos < size) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
		bytes = kernel_read(file, pos, buf, PAGE_SIZE);
		pos += bytes;
#else
		bytes = kernel_read(file, buf, PAGE_SIZE, &pos);
#endif
		if (bytes < 0) {
			myprintk("read %s error: %ld\n", path, bytes);
			break;
		}

		/* 读到文件尾 */
		if (bytes == 0) {
			if (pos < size) {
				myprintk("read %s error: -EIO\n", path);
			}
			break;
		}

		buf += bytes;
		count += bytes;
	}

	filp_close(file, 0);

	return count; //返回读到的字节数
}

/* 进程策略更新 */
char *sniper_pmiddleware = NULL;
int  sniper_pmiddleware_count = 0;

char *sniper_pcommand = NULL;
char *sniper_pcommand_mem = NULL;
int pcommand_memsize = 0;
int pcommand_rulesize = 0;
int  sniper_pcommand_count = 0;

domaintbl_t *sniper_pminepool = NULL;
char *sniper_pminepool_mem = NULL;
int pminepool_memsize = 0;
int pminepool_rulesize = 0;
int  sniper_pminepool_count = 0;

char *sniper_pblack = NULL;     //black array
char *sniper_pblack_mem = NULL; //black values
int pblack_memsize = 0;
int pblack_rulesize = 0;
int  sniper_pblack_count = 0;

char *sniper_pfilter = NULL;     //filter array
char *sniper_pfilter_mem = NULL; //filter values
int pfilter_memsize = 0;
int pfilter_rulesize = 0;
int  sniper_pfilter_count = 0;

char *sniper_ptrust = NULL;     //trust array
char *sniper_ptrust_mem = NULL; //trust values
int ptrust_memsize = 0;
int ptrust_rulesize = 0;
int  sniper_ptrust_count = 0;

/* 插入新的中间件信息，或设置某个中间件信息的端口号 */
static void set_middleware(struct sniper_middleware *mid)
{
	int i = 0, freei = -1;
	struct sniper_middleware *oldmid = (struct sniper_middleware *)sniper_pmiddleware;

	if (!oldmid) {
		return;
	}

	for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++, oldmid++) {
		if (oldmid->pid == 0) {
			if (freei < 0) {
				freei = i; //获取第一个空闲的数组项索引
			}
			continue; //忽略空闲的数组项
		}

		/* 某中间件listen的时候没指定端口，sniper程序查询分配的端口，并在这里填上 */
		if (oldmid->pid == mid->pid && oldmid->ino == mid->ino) {
			oldmid->port = mid->port;
			oldmid->fd = mid->fd;
			return;
		}
	}

	if (freei < 0) {
		myprintk("Error: too listen ports than %d, %s(%d)[listen %d] not recorded\n",
			SNIPER_MIDDLEWARE_NUM, mid->name, mid->pid, mid->port);
		return;
	}

	/* 插入新的中间件信息 */
	oldmid = (struct sniper_middleware *)sniper_pmiddleware;
	oldmid[freei].pid  = mid->pid;
	oldmid[freei].port = mid->port;
	oldmid[freei].ino  = mid->ino;
	oldmid[freei].fd   = mid->fd;
	snprintf(oldmid[freei].name, sizeof(oldmid[freei].name), "%s", mid->name);
}

/* 对于关闭的端口，删除对应的中间件信息 */
static void close_middleware(struct sniper_middleware *mid)
{
	int i = 0;
	struct sniper_middleware *oldmid = (struct sniper_middleware *)sniper_pmiddleware;

	if (!oldmid) {
		return;
	}

	for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++, oldmid++) {
		if (oldmid->pid == 0) {
			continue; //忽略空闲的数组项
		}
		if (oldmid->pid == mid->pid && oldmid->ino == mid->ino) {
			memset(oldmid, 0, sizeof(struct sniper_middleware));
			return;
		}
	}
}

/* pmiddleware独立于prule，即使进程策略没开，也可加载给网络引擎用 */
static void update_pmiddleware(struct nlmsghdr *nlh)
{
	int i = 0, count = 0, datalen = 0;
	int size = sizeof(struct sniper_middleware);
	struct sniper_middleware *mid = NULL;

	if (!nlh) {
		return;
	}

	if (!sniper_pmiddleware) {
		return;
	}

	datalen = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (datalen <= 0) {
		myprintk("update pmiddleware fail: bad datalen %d\n", datalen);
		return;
	}
	count = datalen / size;

	/* 网络引擎会在软中断中加读锁，因此这里加写锁时禁止软中断，避免死锁 */
	write_lock_bh(&sniper_pmiddleware_lock);

	mid = (struct sniper_middleware *)nlmsg_data(nlh);
	for (i = 0; i < count; i++, mid++) {
		if (mid->action == MID_SET) {
			set_middleware(mid);
		} else if (mid->action == MID_CLOSE) {
			close_middleware(mid);
		}
	}

	count = 0;
	mid = (struct sniper_middleware *)sniper_pmiddleware;
	if (mid) {
		for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++, mid++) {
			if (mid->pid > 0) {
				count++;
			}
		}
	}
	sniper_pmiddleware_ver++;
	sniper_pmiddleware_count = count;

	write_unlock_bh(&sniper_pmiddleware_lock);
}

static void update_pcmdtbl(struct nlmsghdr *nlh)
{
	int i = 0, j = 0, len = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	int in_count = 0, in_size = 0;
	int intsize = sizeof(int);
	char *ptr = NULL, c = 0;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_cmdtbl_t *pcommand = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_prule.command_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_PCMDTBLMEM);
	if (!newmem) {
		myprintk("update cmdtable fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	ptr = newmem;
	in_size = *(int *)ptr;
	ptr += intsize;
	in_count = *(int *)ptr;
	ptr += intsize;
	if (in_size != mem_size) { //可能是构建名单出错，或传进内核出错
		myprintk("update cmdtable error, size %d != %d\n", mem_size, in_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PCMDTBLMEM);
		return;
	}
	if (in_count > count) { //可能是构建名单出错，或传进内核出错
		myprintk("update cmdtable error, count %d > %d\n", in_count, count);
		sniper_vfree(newmem, mem_size, VMALLOC_PCMDTBLMEM);
		return;
	}
	if (in_count < count) { //可能是名单中有本机没有的用户名，忽略掉了几项
		myprintk("update cmdtable count %d < %d\n", in_count, count);
		count = in_count;
	}

	rule_size = count * sizeof(sniper_cmdtbl_t);
	newrule = sniper_vmalloc(rule_size, VMALLOC_PCMDTBLRULE);
	if (!newrule) {
		myprintk("update cmdtable fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PCMDTBLMEM);
		return;
	}

	pcommand = (sniper_cmdtbl_t *)newrule;
	for (i = 0; i < count; i++) {
		pcommand->command = ptr;
		len = strlen(pcommand->command);
		ptr += len + 1;

		for (j = 0; j < len; j++) {
			c = pcommand->command[j];
			if (c == ' ' || c == '@') {
				pcommand->command[j] = 0;
				break;
			}
		}

		pcommand++;
	}

	oldrule = sniper_pcommand;
	oldmem  = sniper_pcommand_mem;
	old_rulesize = pcommand_rulesize;
	old_memsize = pcommand_memsize;

	write_lock(&sniper_pcommand_lock);
	sniper_pcommand = newrule;
	sniper_pcommand_mem = newmem;
	pcommand_rulesize = rule_size;
	pcommand_memsize = mem_size;
	sniper_pcommand_count = count;
	sniper_prule.command_count = count; //如果in_count < count，做修正
	write_unlock(&sniper_pcommand_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_PCMDTBLRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_PCMDTBLMEM);

	sniper_pcommand_ver++;
}

struct domain_tblinfo {
	int memsize;
	int rulesize;
	domaintbl_t *domaintbl;
	char *domainmem;
};
static int update_domaintbl(struct nlmsghdr *nlh, struct domain_tblinfo *info, int count, char *desc, int memtype, int ruletype)
{
	int i = 0, size = 0, ret = 0, memsize = 0, rulesize = 0;
	char *ptr = NULL, *domainmem = NULL, *path = NULL;
	domaintbl_t *domaintbl = NULL;

	if (!count) {
		return 1; //没有域名，将清空
	}

	if (!nlh) {
		return 0;
	}

	size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (size <= sizeof(int)) {
		return 0;
	}

	memsize = *(int *)nlmsg_data(nlh);
	path = nlmsg_data(nlh) + sizeof(int);

	domainmem = sniper_vmalloc(memsize, memtype);
	if (!domainmem) {
		myprintk("update %s fail, alloc %d memory fail\n", desc, memsize);
		return 0;
	}

	ret = readfile(path, domainmem, memsize);
	if (ret != memsize) {
		myprintk("update %s fail, read rulefile %s fail, ret %d expect %d\n", desc, path, ret, memsize);
		sniper_vfree(domainmem, memsize, memtype);
		return 0;
	}

	rulesize = count * sizeof(domaintbl_t);
	domaintbl = (domaintbl_t *)sniper_vmalloc(rulesize, ruletype);
	if (!domaintbl) {
		myprintk("update %s fail, alloc %d memory fail\n", desc, rulesize);
		sniper_vfree(domainmem, memsize, memtype);
		return 0;
	}

	ptr = domainmem;
	for (i = 0; i < count; i++) {
		domaintbl[i].domain = ptr;
		ptr += strlen(ptr) + 1;
	}

	info->domaintbl = domaintbl;
	info->domainmem = domainmem;
	info->memsize = memsize;
	info->rulesize = rulesize;

	return 1;
}

static void update_pminepool(struct nlmsghdr *nlh)
{
	struct domain_tblinfo info = {0};
	char *oldrule = NULL, *oldmem = NULL;
	int count = sniper_prule.minepool_count;
	int old_memsize = 0, old_rulesize = 0;

	/* update_domaintbl()里有vmalloc，可能睡眠，
	   因此不能在update_domaintbl()前做write_lock_bh() */
	if (update_domaintbl(nlh, &info, count, "mine pool", VMALLOC_MINEPOOLMEM, VMALLOC_MINEPOOLRULE)) {
		oldrule = (char *)sniper_pminepool;
		oldmem  = sniper_pminepool_mem;
		old_memsize = pminepool_memsize;
		old_rulesize = pminepool_rulesize;

		write_lock_bh(&sniper_pminepool_lock);
		sniper_pminepool = info.domaintbl;
		sniper_pminepool_mem = info.domainmem;
		pminepool_rulesize = info.rulesize;
		pminepool_memsize = info.memsize;
		sniper_pminepool_count = count;
		write_unlock_bh(&sniper_pminepool_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_MINEPOOLRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_MINEPOOLMEM);

		sniper_pminepool_ver++;
	}
}

/* 进程策略更新后，释放空名单的空间 */
static void post_prule_update(void)
{
	char *oldrule = NULL, *oldmem = NULL;
	int old_rulesize = 0, old_memsize = 0;

	if (sniper_prule.command_count == 0) {
		oldrule = sniper_pcommand;
		oldmem  = sniper_pcommand_mem;
		old_rulesize = pcommand_rulesize;
		old_memsize = pcommand_memsize;

		write_lock(&sniper_pcommand_lock);
		sniper_pcommand = NULL;
		sniper_pcommand_mem = NULL;
		pcommand_rulesize = 0;
		pcommand_memsize = 0;
		sniper_pcommand_count = 0;
		write_unlock(&sniper_pcommand_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_PCMDTBLRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_PCMDTBLMEM);
	}

	if (sniper_prule.minepool_count == 0) {
		oldrule = (char *)sniper_pminepool;
		oldmem  = sniper_pminepool_mem;
		old_rulesize = pminepool_rulesize;
		old_memsize = pminepool_memsize;

		write_lock(&sniper_pminepool_lock);
		sniper_pminepool = NULL;
		sniper_pminepool_mem = NULL;
		pminepool_rulesize = 0;
		pminepool_memsize = 0;
		sniper_pminepool_count = 0;
		write_unlock(&sniper_pminepool_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_MINEPOOLRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_MINEPOOLMEM);
	}

	if (sniper_prule.black_count == 0) {
		oldrule = sniper_pblack;
		oldmem  = sniper_pblack_mem;
		old_rulesize = pblack_rulesize;
		old_memsize = pblack_memsize;

		write_lock(&sniper_pblack_lock);
		sniper_pblack = NULL;
		sniper_pblack_mem = NULL;
		pblack_rulesize = 0;
		pblack_memsize = 0;
		sniper_pblack_count = 0;
		write_unlock(&sniper_pblack_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_PBLACKRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_PBLACKMEM);
	}

	if (sniper_prule.filter_count == 0) {
		oldrule = sniper_pfilter;
		oldmem  = sniper_pfilter_mem;
		old_rulesize = pfilter_rulesize;
		old_memsize = pfilter_memsize;

		write_lock(&sniper_pfilter_lock);
		sniper_pfilter = NULL;
		sniper_pfilter_mem = NULL;
		pfilter_rulesize = 0;
		pfilter_memsize = 0;
		sniper_pfilter_count = 0;
		write_unlock(&sniper_pfilter_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_PFILTERRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_PFILTERMEM);
	}

	if (sniper_prule.trust_count == 0) {
		oldrule = sniper_ptrust;
		oldmem  = sniper_ptrust_mem;
		old_rulesize = ptrust_rulesize;
		old_memsize = ptrust_memsize;

		write_lock(&sniper_ptrust_lock);
		sniper_ptrust = NULL;
		sniper_ptrust_mem = NULL;
		ptrust_rulesize = 0;
		ptrust_memsize = 0;
		sniper_ptrust_count = 0;
		write_unlock(&sniper_ptrust_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_PTRUSTRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_PTRUSTMEM);
	}
}

static void free_prule(void)
{
	memset(&sniper_prule, 0, sizeof(sniper_prule));
	post_prule_update();
}

static void update_pblack(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	int in_count = 0, in_size = 0;
	int intsize = sizeof(int), uidsize = sizeof(uid_t);
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_plist_t *pblack = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_prule.black_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_PBLACKMEM);
	if (!newmem) {
		myprintk("update_pblack fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	ptr = newmem;
	in_size = *(int *)ptr;
	ptr += intsize;
	in_count = *(int *)ptr;
	ptr += intsize;
	if (in_size != mem_size) { //可能是构建名单出错，或传进内核出错
		myprintk("update pblack error, size %d != %d\n", mem_size, in_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PBLACKMEM);
		return;
	}
	if (in_count > count) { //可能是构建名单出错，或传进内核出错
		myprintk("update pblack error, count %d > %d\n", in_count, count);
		sniper_vfree(newmem, mem_size, VMALLOC_PBLACKMEM);
		return;
	}
	if (in_count < count) { //可能是名单中有本机没有的用户名，忽略掉了几项
		myprintk("update pblack count %d < %d\n", in_count, count);
		count = in_count;
	}

	rule_size = count * sizeof(sniper_plist_t);

	newrule = sniper_vmalloc(rule_size, VMALLOC_PBLACKRULE);
	if (!newrule) {
		myprintk("update_pblack fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PBLACKMEM);
		return;
	}

	pblack = (sniper_plist_t *)newrule;
	for (i = 0; i < count; i++) {
		pblack->cmdname  = ptr;  ptr += strlen(pblack->cmdname) + 1;
		pblack->cmdpath  = ptr;  ptr += strlen(pblack->cmdpath) + 1;
		pblack->cmdline  = ptr;  ptr += strlen(pblack->cmdline) + 1;
		pblack->md5      = ptr;  ptr += strlen(pblack->md5) + 1;
		pblack->pcmdname = ptr;  ptr += strlen(pblack->pcmdname) + 1;
		pblack->rip      = ptr;  ptr += strlen(pblack->rip) + 1;

		pblack->flag       = *ptr;           ptr += 1;
		pblack->uid        = *(uid_t *)ptr;  ptr += uidsize;
		pblack->event_flag = *(int *)ptr;    ptr += intsize;

		pblack++;
	}

	oldrule = sniper_pblack;
	oldmem  = sniper_pblack_mem;
	old_rulesize = pblack_rulesize;
	old_memsize = pblack_memsize;

	write_lock(&sniper_pblack_lock);
	sniper_pblack = newrule;
	sniper_pblack_mem = newmem;
	pblack_rulesize = rule_size;
	pblack_memsize = mem_size;
	sniper_pblack_count = count;
	sniper_prule.black_count = count; //如果in_count < count，做修正
	write_unlock(&sniper_pblack_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_PBLACKRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_PBLACKMEM);

	sniper_pblack_ver++;
}

static void update_pfilter(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	int in_count = 0, in_size = 0;
	int intsize = sizeof(int), uidsize = sizeof(uid_t);
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_plist_t *pfilter = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_prule.filter_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_PFILTERMEM);
	if (!newmem) {
		myprintk("update_pfilter fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	ptr = newmem;
	in_size = *(int *)ptr;
	ptr += intsize;
	in_count = *(int *)ptr;
	ptr += intsize;
	if (in_size != mem_size) { //可能是构建名单出错，或传进内核出错
		myprintk("update pfilter error, size %d != %d\n", mem_size, in_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PFILTERMEM);
		return;
	}
	if (in_count > count) { //可能是构建名单出错，或传进内核出错
		myprintk("update pfilter error, count %d > %d\n", in_count, count);
		sniper_vfree(newmem, mem_size, VMALLOC_PFILTERMEM);
		return;
	}
	if (in_count < count) { //可能是名单中有本机没有的用户名，忽略掉了几项
		myprintk("update pfilter count %d < %d\n", in_count, count);
		count = in_count;
	}

	rule_size = count * sizeof(sniper_plist_t);

	newrule = sniper_vmalloc(rule_size, VMALLOC_PFILTERRULE);
	if (!newrule) {
		myprintk("update_pfilter fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PFILTERMEM);
		return;
	}

	pfilter = (sniper_plist_t *)newrule;
	for (i = 0; i < count; i++) {
		pfilter->cmdname  = ptr;  ptr += strlen(pfilter->cmdname) + 1;
		pfilter->cmdpath  = ptr;  ptr += strlen(pfilter->cmdpath) + 1;
		pfilter->cmdline  = ptr;  ptr += strlen(pfilter->cmdline) + 1;
		pfilter->md5      = ptr;  ptr += strlen(pfilter->md5) + 1;
		pfilter->pcmdname = ptr;  ptr += strlen(pfilter->pcmdname) + 1;
		pfilter->rip      = ptr;  ptr += strlen(pfilter->rip) + 1;

		pfilter->flag       = *ptr;           ptr += 1;
		pfilter->uid        = *(uid_t *)ptr;  ptr += uidsize;
		pfilter->event_flag = *(int *)ptr;    ptr += intsize;

		pfilter++;
	}

	oldrule = sniper_pfilter;
	oldmem  = sniper_pfilter_mem;
	old_rulesize = pfilter_rulesize;
	old_memsize = pfilter_memsize;

	write_lock(&sniper_pfilter_lock);
	sniper_pfilter = newrule;
	sniper_pfilter_mem = newmem;
	pfilter_rulesize = rule_size;
	pfilter_memsize = mem_size;
	sniper_pfilter_count = count;
	sniper_prule.filter_count = count; //如果in_count < count，做修正
	write_unlock(&sniper_pfilter_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_PFILTERRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_PFILTERMEM);

	sniper_pfilter_ver++;
}

static void update_ptrust(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	int in_count = 0, in_size = 0;
	int intsize = sizeof(int), uidsize = sizeof(uid_t);
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_plist_t *ptrust = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_prule.trust_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_PTRUSTMEM);
	if (!newmem) {
		myprintk("update_ptrust fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	ptr = newmem;
	in_size = *(int *)ptr;
	ptr += intsize;
	in_count = *(int *)ptr;
	ptr += intsize;
	if (in_size != mem_size) { //可能是构建名单出错，或传进内核出错
		myprintk("update ptrust error, size %d != %d\n", mem_size, in_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PTRUSTMEM);
		return;
	}
	if (in_count > count) { //可能是构建名单出错，或传进内核出错
		myprintk("update ptrust error, count %d > %d\n", in_count, count);
		sniper_vfree(newmem, mem_size, VMALLOC_PTRUSTMEM);
		return;
	}
	if (in_count < count) { //可能是名单中有本机没有的用户名，忽略掉了几项
		myprintk("update ptrust count %d < %d\n", in_count, count);
		count = in_count;
	}

	rule_size = count * sizeof(sniper_plist_t);

	newrule = sniper_vmalloc(rule_size, VMALLOC_PTRUSTRULE);
	if (!newrule) {
		myprintk("update_ptrust fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_PTRUSTMEM);
		return;
	}

	ptrust = (sniper_plist_t *)newrule;
	for (i = 0; i < count; i++) {
		ptrust->cmdname  = ptr;  ptr += strlen(ptrust->cmdname) + 1;
		ptrust->cmdpath  = ptr;  ptr += strlen(ptrust->cmdpath) + 1;
		ptrust->cmdline  = ptr;  ptr += strlen(ptrust->cmdline) + 1;
		ptrust->md5      = ptr;  ptr += strlen(ptrust->md5) + 1;
		ptrust->pcmdname = ptr;  ptr += strlen(ptrust->pcmdname) + 1;
		ptrust->rip      = ptr;  ptr += strlen(ptrust->rip) + 1;

		ptrust->flag       = *ptr;           ptr += 1;
		ptrust->uid        = *(uid_t *)ptr;  ptr += uidsize;
		ptrust->event_flag = *(int *)ptr;    ptr += intsize;

		ptrust++;
	}

	oldrule = sniper_ptrust;
	oldmem  = sniper_ptrust_mem;
	old_rulesize = ptrust_rulesize;
	old_memsize = ptrust_memsize;

	write_lock(&sniper_ptrust_lock);
	sniper_ptrust = newrule;
	sniper_ptrust_mem = newmem;
	ptrust_rulesize = rule_size;
	ptrust_memsize = mem_size;
	sniper_ptrust_count = count;
	sniper_prule.trust_count = count; //如果in_count < count，做修正
	write_unlock(&sniper_ptrust_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_PTRUSTRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_PTRUSTMEM);

	sniper_ptrust_ver++;
}

#define limit_count(COUNT)  if (COUNT > FOR_MAX) { COUNT = FOR_MAX; }
static void update_prule(struct nlmsghdr *nlh)
{
	write_lock(&sniper_prule_lock);

	memcpy(&sniper_prule, nlmsg_data(nlh), sizeof(sniper_prule));

	limit_count(sniper_prule.command_count);
	limit_count(sniper_prule.black_count);
	limit_count(sniper_prule.filter_count);
	limit_count(sniper_prule.trust_count);

	write_unlock(&sniper_prule_lock);

	post_prule_update(); //释放无效的子策略空间
	sniper_prule_ver++;
}


/* 文件策略更新 */
char *sniper_fsensitive = NULL;
char *sniper_fsensitive_mem = NULL;
int fsensitive_memsize = 0;
int fsensitive_rulesize = 0;
int  sniper_fsensitive_count = 0;

char *sniper_flog_delete = NULL;
char *sniper_flog_delete_mem = NULL;
int flogdelete_memsize = 0;
int flogdelete_rulesize = 0;
int  sniper_flog_delete_count = 0;

char *sniper_fsafe = NULL;
char *sniper_fsafe_mem = NULL;
int fsafe_memsize = 0;
int fsafe_rulesize = 0;
int  sniper_fsafe_count = 0;

char *sniper_flogcollector = NULL;
char *sniper_flogcollector_mem = NULL;
int flogcollector_memsize = 0;
int flogcollector_rulesize = 0;
int  sniper_flogcollector_count = 0;

char *sniper_fmiddle_target = NULL;
int fmiddle_rulesize = 0;
char *sniper_fmiddle_binary = NULL;
int fmidbinary_rulesize = 0;
char *sniper_fmiddle_script = NULL;
int fmidscript_rulesize = 0;

char *sniper_fillegal_script = NULL;
char *sniper_fillegal_script_mem = NULL;
int fillscript_memsize = 0;
int fillscript_rulesize = 0;
int  sniper_fillegal_script_count = 0;

char *sniper_fwebshell_detect = NULL;
char *sniper_fwebshell_detect_mem = NULL;
int fwebshell_memsize = 0;
int fwebshell_rulesize = 0;
int  sniper_fwebshell_detect_count = 0;

char *sniper_fblack = NULL;
char *sniper_fblack_mem = NULL;
int fblack_memsize = 0;
int fblack_rulesize = 0;
int  sniper_fblack_count = 0;

char *sniper_ffilter = NULL;
char *sniper_ffilter_mem = NULL;
int ffilter_memsize = 0;
int ffilter_rulesize = 0;
int  sniper_ffilter_count = 0;

char *sniper_fusb = NULL;
char *sniper_fusb_mem = NULL;
int fusb_memsize = 0;
int fusb_rulesize = 0;
int  sniper_fusb_count = 0;
int   sniper_fusb_size = 0; //file usb path string size

char *sniper_fencrypt = NULL;
char *sniper_fencrypt_mem = NULL;
int fencrypt_memsize = 0;
int fencrypt_rulesize = 0;

/* 新文件策略更新后，释放空名单的空间 */
static void post_fpolicy_update(void)
{
	char *oldrule = NULL, *oldmem = NULL;
	int old_rulesize = 0, old_memsize = 0;

	if (sniper_fpolicy.file_sensitive_on == 0 || sniper_fpolicy.sensitive_count == 0) {
		oldrule = sniper_fsensitive;
		oldmem  = sniper_fsensitive_mem;
		old_rulesize = fsensitive_rulesize;
		old_memsize = fsensitive_memsize;

		write_lock(&sniper_fsensitive_lock);
		sniper_fsensitive = NULL;
		sniper_fsensitive_mem = NULL;
		fsensitive_rulesize = 0;
		fsensitive_memsize = 0;
		sniper_fsensitive_count = 0;
		write_unlock(&sniper_fsensitive_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FSENSITIVERULE);
		sniper_vfree(oldmem, old_rulesize, VMALLOC_FSENSITIVEMEM);
	}

	if (sniper_fpolicy.file_log_delete == 0 || sniper_fpolicy.log_delete_count == 0) {
		oldrule = sniper_flog_delete;
		oldmem  = sniper_flog_delete_mem;
		old_rulesize = flogdelete_rulesize;
		old_memsize = flogdelete_memsize;

		write_lock(&sniper_flog_delete_lock);
		sniper_flog_delete = NULL;
		sniper_flog_delete_mem = NULL;
		flogdelete_rulesize = 0;
		flogdelete_memsize = 0;
		sniper_flog_delete_count = 0;
		write_unlock(&sniper_flog_delete_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FLOGDELETERULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FLOGDELETEMEM);
	}

	if (sniper_fpolicy.file_safe_on == 0 || sniper_fpolicy.safe_count == 0) {
		oldrule = sniper_fsafe;
		oldmem  = sniper_fsafe_mem;
		old_rulesize = fsafe_rulesize;
		old_memsize = fsafe_memsize;

		write_lock(&sniper_fsafe_lock);
		sniper_fsafe = NULL;
		sniper_fsafe_mem = NULL;
		fsafe_rulesize = 0;
		fsafe_memsize = 0;
		sniper_fsafe_count = 0;
		write_unlock(&sniper_fsafe_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FSAFERULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FSAFEMEM);
	}

	if (sniper_fpolicy.file_logcollector_on == 0 || sniper_fpolicy.logcollector_count == 0) {
		oldrule = sniper_flogcollector;
		oldmem  = sniper_flogcollector_mem;
		old_rulesize = flogcollector_rulesize;
		old_memsize = flogcollector_memsize;

		write_lock(&sniper_flogcollector_lock);
		sniper_flogcollector = NULL;
		sniper_flogcollector_mem = NULL;
		flogcollector_rulesize = 0;
		flogcollector_memsize = 0;
		sniper_flogcollector_count = 0;
		write_unlock(&sniper_flogcollector_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FLOGCOLLECTRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FLOGCOLLECTMEM);
	}

	if (sniper_fpolicy.file_middle_binary_on == 0) {
		oldrule = sniper_fmiddle_binary;
		old_rulesize = fmidbinary_rulesize;

		write_lock(&sniper_fmiddle_binary_lock);
		sniper_fmiddle_binary = NULL;
		fmidbinary_rulesize = 0;
		write_unlock(&sniper_fmiddle_binary_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FMIDDLEBINARY);
	}

	if (sniper_fpolicy.file_middle_script_on == 0) {
		oldrule = sniper_fmiddle_script;
		old_rulesize = fmidscript_rulesize;

		write_lock(&sniper_fmiddle_script_lock);
		sniper_fmiddle_script = NULL;
		fmidscript_rulesize = 0;
		write_unlock(&sniper_fmiddle_script_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FMIDDLESCRIPT);
	}

	/* 中间件识别关闭时，可执行文件和脚本文件必定关闭，已经在前面释放 */
	if (sniper_fpolicy.file_middle_on == 0) {
		oldrule = sniper_fmiddle_target;
		old_rulesize = fmiddle_rulesize;

		write_lock(&sniper_fmiddle_target_lock);
		sniper_fmiddle_target = NULL;
		fmiddle_rulesize = 0;
		write_unlock(&sniper_fmiddle_target_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FMIDDLE);
	}

	if (sniper_fpolicy.file_illegal_script_on == 0 || sniper_fpolicy.illegal_script_count == 0) {
		oldrule = sniper_fillegal_script;
		oldmem  = sniper_fillegal_script_mem;
		old_rulesize = fillscript_rulesize;
		old_memsize = fillscript_memsize;

		write_lock(&sniper_fillegal_script_lock);
		sniper_fillegal_script = NULL;
		sniper_fillegal_script_mem = NULL;
		fillscript_rulesize = 0;
		fillscript_memsize = 0;
		sniper_fillegal_script_count = 0;
		write_unlock(&sniper_fillegal_script_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_ILLSCRIPTRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_ILLSCRIPTMEM);
	}

	if (sniper_fpolicy.file_webshell_detect_on == 0 || sniper_fpolicy.webshell_detect_count == 0) {
		oldrule = sniper_fwebshell_detect;
		oldmem  = sniper_fwebshell_detect_mem;
		old_rulesize = fwebshell_rulesize;
		old_memsize = fwebshell_memsize;

		write_lock(&sniper_fwebshell_detect_lock);
		sniper_fwebshell_detect = NULL;
		sniper_fwebshell_detect_mem = NULL;
		fwebshell_rulesize = 0;
		fwebshell_memsize = 0;
		sniper_fwebshell_detect_count = 0;
		write_unlock(&sniper_fwebshell_detect_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FWEBSHELLRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FWEBSHELLMEM);
	}

	if (sniper_fpolicy.black_count == 0) {
		oldrule = sniper_fblack;
		oldmem  = sniper_fblack_mem;
		old_rulesize = fblack_rulesize;
		old_memsize = fblack_memsize;

		write_lock(&sniper_fblack_lock);
		sniper_fblack = NULL;
		sniper_fblack_mem = NULL;
		fblack_rulesize = 0;
		fblack_memsize = 0;
		sniper_fblack_count = 0;
		write_unlock(&sniper_fblack_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FBLACKRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FBLACKMEM);
	}

	if (sniper_fpolicy.filter_count == 0) {
		oldrule = sniper_ffilter;
		oldmem  = sniper_ffilter_mem;
		old_rulesize = ffilter_rulesize;
		old_memsize = ffilter_memsize;

		write_lock(&sniper_ffilter_lock);
		sniper_ffilter = NULL;
		sniper_ffilter_mem = NULL;
		ffilter_rulesize = 0;
		ffilter_memsize = 0;
		sniper_ffilter_count = 0;
		write_unlock(&sniper_ffilter_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FFILTERRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FFILTERMEM);
	}

	if (sniper_fpolicy.usb_count == 0) {
		oldrule = sniper_fusb;
		oldmem  = sniper_fusb_mem;
		old_rulesize = fusb_rulesize;
		old_memsize = fusb_memsize;

		write_lock(&sniper_fusb_lock);
		sniper_fusb = NULL;
		sniper_fusb_mem = NULL;
		fusb_rulesize = 0;
		fusb_memsize = 0;
		sniper_fusb_count = 0;
		write_unlock(&sniper_fusb_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FUSBRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FUSBMEM);
	}

	if (sniper_fpolicy.encrypt_on == 0 || sniper_fpolicy.encrypt_backup_on == 0) {
		oldrule = sniper_fencrypt;
		oldmem  = sniper_fencrypt_mem;
		old_rulesize = fencrypt_rulesize;
		old_memsize = fencrypt_memsize;

		write_lock(&sniper_fencrypt_lock);
		sniper_fencrypt = NULL;
		sniper_fencrypt_mem = NULL;
		fencrypt_rulesize = 0;
		fencrypt_memsize = 0;
		write_unlock(&sniper_fencrypt_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_FENCRYPTRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_FENCRYPTMEM);
	}
}

static void free_fpolicy(void)
{
	memset(&sniper_fpolicy, 0, sizeof(sniper_fpolicy));
	post_fpolicy_update();
}

static void update_file_sensitive(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_my_flist_t *flist = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.sensitive_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FSENSITIVEMEM);
	if (!newmem) {
		myprintk("update file sensitive fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_my_flist_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FSENSITIVEMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FSENSITIVERULE);
	if (!newrule) {
		myprintk("update file sensitive fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FSENSITIVEMEM);
		return;
	}

	ptr = newmem;
	flist = (sniper_my_flist_t *)newrule;
	for (i = 0; i < count; i++) {
		flist->file = ptr;  ptr += strlen(flist->file) + 1;

		flist++;
	}

	oldrule = sniper_fsensitive;
	oldmem  = sniper_fsensitive_mem;
	old_rulesize = fsensitive_rulesize;
	old_memsize = fsensitive_memsize;

	write_lock(&sniper_fsensitive_lock);
	sniper_fsensitive = newrule;
	sniper_fsensitive_mem = newmem;
	fsensitive_rulesize = rule_size;
	fsensitive_memsize = mem_size;
	sniper_fsensitive_count = count;
	write_unlock(&sniper_fsensitive_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FSENSITIVERULE);
	sniper_vfree(oldmem, old_rulesize, VMALLOC_FSENSITIVEMEM);

	sniper_fsensitive_ver++;
}

static void update_file_log_delete(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_my_flist_t *flist = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.log_delete_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FLOGDELETEMEM);
	if (!newmem) {
		myprintk("update file log delete fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_my_flist_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FLOGDELETEMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FLOGDELETERULE);
	if (!newrule) {
		myprintk("update file log delete fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FLOGDELETEMEM);
		return;
	}

	ptr = newmem;
	flist = (sniper_my_flist_t *)newrule;
	for (i = 0; i < count; i++) {
		flist->file = ptr;  ptr += strlen(flist->file) + 1;

		flist++;
	}

	oldrule = sniper_flog_delete;
	oldmem  = sniper_flog_delete_mem;
	old_rulesize = flogdelete_rulesize;
	old_memsize = flogdelete_memsize;

	write_lock(&sniper_flog_delete_lock);
	sniper_flog_delete = newrule;
	sniper_flog_delete_mem = newmem;
	flogdelete_rulesize = rule_size;
	flogdelete_memsize = mem_size;
	sniper_flog_delete_count = count;
	write_unlock(&sniper_flog_delete_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FLOGDELETERULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FLOGDELETEMEM);

	sniper_flog_delete_ver++;
}

static void update_file_safe(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_fsafe_t *fsafe = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.safe_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FSAFEMEM);
	if (!newmem) {
		myprintk("update_fsafe fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_fsafe_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FSAFEMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FSAFERULE);
	if (!newrule) {
		myprintk("update_fsafe fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FSAFEMEM);
		return;
	}

	ptr = newmem;
	fsafe = (sniper_fsafe_t *)newrule;
	for (i = 0; i < count; i++) {
		fsafe->path = ptr;  ptr += strlen(fsafe->path) + 1;
		fsafe->real_path = ptr;  ptr += strlen(fsafe->real_path) + 1;
		fsafe->name = ptr; ptr += strlen(fsafe->name) + 1;
		fsafe->process = ptr; ptr += strlen(fsafe->process) + 1;
		fsafe->operation = ptr; ptr += strlen(fsafe->operation) + 1;
		fsafe->status = *ptr; ptr += 4;

		fsafe++;
	}

	oldrule = sniper_fsafe;
	oldmem  = sniper_fsafe_mem;
	old_rulesize = fsafe_rulesize;
	old_memsize = fsafe_memsize;

	write_lock(&sniper_fsafe_lock);
	sniper_fsafe = newrule;
	sniper_fsafe_mem = newmem;
	fsafe_rulesize = rule_size;
	fsafe_memsize = mem_size;
	sniper_fsafe_count = count;
	write_unlock(&sniper_fsafe_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FSAFERULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FSAFEMEM);

	sniper_fsafe_ver++;
}

static void update_file_logcollector(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_flogcollector_t *flogcollector = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.logcollector_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FLOGCOLLECTMEM);
	if (!newmem) {
		myprintk("update_flogcollector fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_flogcollector_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FLOGCOLLECTMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FLOGCOLLECTRULE);
	if (!newrule) {
		myprintk("update_flogcollector fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FLOGCOLLECTMEM);
		return;
	}

	ptr = newmem;
	flogcollector = (sniper_flogcollector_t *)newrule;
	for (i = 0; i < count; i++) {
		flogcollector->filepath = ptr;  ptr += strlen(flogcollector->filepath) + 1;
		flogcollector->real_path = ptr;  ptr += strlen(flogcollector->real_path) + 1;
		flogcollector->extension = ptr; ptr += strlen(flogcollector->extension) + 1;

		flogcollector++;
	}

	oldrule = sniper_flogcollector;
	oldmem  = sniper_flogcollector_mem;
	old_rulesize = flogcollector_rulesize;
	old_memsize = flogcollector_memsize;

	write_lock(&sniper_flogcollector_lock);
	sniper_flogcollector = newrule;
	sniper_flogcollector_mem = newmem;
	flogcollector_rulesize = rule_size;
	flogcollector_memsize = mem_size;
	sniper_flogcollector_count = count;
	write_unlock(&sniper_flogcollector_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FLOGCOLLECTRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FLOGCOLLECTMEM);

	sniper_flogcollector_ver++;
}

static void update_file_middle_target(struct nlmsghdr *nlh)
{
	int size = 0;
	char *newrule = NULL;
	char *oldrule = NULL;
	int old_rulesize = 0;

	if (!nlh) {
		return;
	}

	size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!size) {
		return;
	}

	newrule = sniper_vmalloc(size, VMALLOC_FMIDDLE);
	if (!newrule) {
		myprintk("update_file_middle_target fail, alloc %d memory fail\n", size);
		return;
	}
	memcpy(newrule, nlmsg_data(nlh), size);

	oldrule = sniper_fmiddle_target;
	old_rulesize = fmiddle_rulesize;

	write_lock(&sniper_fmiddle_target_lock);
	sniper_fmiddle_target = newrule;
	fmiddle_rulesize = size;
	write_unlock(&sniper_fmiddle_target_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FMIDDLE);

	sniper_fmiddle_target_ver++;
}

static void update_file_middle_binary(struct nlmsghdr *nlh)
{
	int size = 0;
	char *newrule = NULL;
	char *oldrule = NULL;
	int old_rulesize = 0;

	if (!nlh) {
		return;
	}

	size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!size) {
		return;
	}

	newrule = sniper_vmalloc(size, VMALLOC_FMIDDLEBINARY);
	if (!newrule) {
		myprintk("update_file_middle_binary fail, alloc %d memory fail\n", size);
		return;
	}
	memcpy(newrule, nlmsg_data(nlh), size);

	oldrule = sniper_fmiddle_binary;
	old_rulesize = fmidbinary_rulesize;

	write_lock(&sniper_fmiddle_binary_lock);
	sniper_fmiddle_binary = newrule;
	fmidbinary_rulesize = size;
	write_unlock(&sniper_fmiddle_binary_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FMIDDLEBINARY);

	sniper_fmiddle_binary_ver++;
}

static void update_file_middle_script(struct nlmsghdr *nlh)
{
	int size = 0;
	char *newrule = NULL;
	char *oldrule = NULL;
	int old_rulesize = 0;

	if (!nlh) {
		return;
	}

	size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!size) {
		return;
	}

	newrule = sniper_vmalloc(size, VMALLOC_FMIDDLESCRIPT);
	if (!newrule) {
		myprintk("update_file_middle_script fail, alloc %d memory fail\n", size);
		return;
	}
	memcpy(newrule, nlmsg_data(nlh), size);

	oldrule = sniper_fmiddle_script;
	old_rulesize = fmidscript_rulesize;

	write_lock(&sniper_fmiddle_script_lock);
	sniper_fmiddle_script = newrule;
	fmidscript_rulesize = size;
	write_unlock(&sniper_fmiddle_script_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FMIDDLESCRIPT);

	sniper_fmiddle_script_ver++;
}

static void update_file_illegal_script(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_fillegal_script_t *fillegal_script = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.illegal_script_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_ILLSCRIPTMEM);
	if (!newmem) {
		myprintk("update_fillegal_script fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_fillegal_script_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_ILLSCRIPTMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_ILLSCRIPTRULE);
	if (!newrule) {
		myprintk("update_fillegal_script fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_ILLSCRIPTMEM);
		return;
	}

	ptr = newmem;
	fillegal_script = (sniper_fillegal_script_t *)newrule;
	for (i = 0; i < count; i++) {
		fillegal_script->filepath  = ptr; ptr += strlen(fillegal_script->filepath)  + 1;
		fillegal_script->real_path = ptr; ptr += strlen(fillegal_script->real_path) + 1;
		fillegal_script->extension = ptr; ptr += strlen(fillegal_script->extension) + 1;

		fillegal_script++;
	}

	oldrule = sniper_fillegal_script;
	oldmem  = sniper_fillegal_script_mem;
	old_rulesize = fillscript_rulesize;
	old_memsize = fillscript_memsize;

	write_lock(&sniper_fillegal_script_lock);
	sniper_fillegal_script = newrule;
	sniper_fillegal_script_mem = newmem;
	fillscript_rulesize = rule_size;
	fillscript_memsize = mem_size;
	sniper_fillegal_script_count = count;
	write_unlock(&sniper_fillegal_script_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_ILLSCRIPTRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_ILLSCRIPTMEM);

	sniper_fillegal_script_ver++;
}

static void update_file_webshell_detect(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_fwebshell_detect_t *fwebshell_detect = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.webshell_detect_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FWEBSHELLMEM);
	if (!newmem) {
		myprintk("update_fwebshell_detect fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_fwebshell_detect_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FWEBSHELLMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FWEBSHELLRULE);
	if (!newrule) {
		myprintk("update_fwebshell_detect fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FWEBSHELLMEM);
		return;
	}

	ptr = newmem;
	fwebshell_detect = (sniper_fwebshell_detect_t *)newrule;
	for (i = 0; i < count; i++) {
		fwebshell_detect->filepath = ptr;  ptr += strlen(fwebshell_detect->filepath) + 1;
		fwebshell_detect->real_path = ptr;  ptr += strlen(fwebshell_detect->real_path) + 1;
		fwebshell_detect->extension = ptr; ptr += strlen(fwebshell_detect->extension) + 1;

		fwebshell_detect++;
	}

	oldrule = sniper_fwebshell_detect;
	oldmem  = sniper_fwebshell_detect_mem;
	old_rulesize = fwebshell_rulesize;
	old_memsize = fwebshell_memsize;

	write_lock(&sniper_fwebshell_detect_lock);
	sniper_fwebshell_detect = newrule;
	sniper_fwebshell_detect_mem = newmem;
	fwebshell_rulesize = rule_size;
	fwebshell_memsize = mem_size;
	sniper_fwebshell_detect_count = count;
	write_unlock(&sniper_fwebshell_detect_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FWEBSHELLRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FWEBSHELLMEM);

	sniper_fwebshell_detect_ver++;
}

static void update_file_black(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_fblack_t *fblack = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.black_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FBLACKMEM);
	if (!newmem) {
		myprintk("update_fblack fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_fblack_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FBLACKMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FBLACKRULE);
	if (!newrule) {
		myprintk("update_fblack fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FBLACKMEM);
		return;
	}

	ptr = newmem;
	fblack = (sniper_fblack_t *)newrule;
	for (i = 0; i < count; i++) {
		fblack->filename = ptr;  ptr += strlen(fblack->filename) + 1;
		fblack->filepath = ptr;  ptr += strlen(fblack->filepath) + 1;
		fblack->md5 = ptr; ptr += strlen(fblack->md5) + 1;

		fblack++;
	}

	oldrule = sniper_fblack;
	oldmem  = sniper_fblack_mem;
	old_rulesize = fblack_rulesize;
	old_memsize = fblack_memsize;

	write_lock(&sniper_fblack_lock);
	sniper_fblack = newrule;
	sniper_fblack_mem = newmem;
	fblack_rulesize = rule_size;
	fblack_memsize = mem_size;
	sniper_fblack_count = count;
	write_unlock(&sniper_fblack_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FBLACKRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FBLACKMEM);

	sniper_fblack_ver++;
}

static void update_file_filter(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_ffilter_t *ffilter = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.filter_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FFILTERMEM);
	if (!newmem) {
		myprintk("update_ffilter fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_ffilter_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FFILTERMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FFILTERRULE);
	if (!newrule) {
		myprintk("update_ffilter fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem,mem_size, VMALLOC_FFILTERMEM);
		return;
	}

	ptr = newmem;
	ffilter = (sniper_ffilter_t *)newrule;
	for (i = 0; i < count; i++) {
		ffilter->filename = ptr;  ptr += strlen(ffilter->filename) + 1;
		ffilter->filepath = ptr;  ptr += strlen(ffilter->filepath) + 1;
		ffilter->md5 = ptr; ptr += strlen(ffilter->md5) + 1;

		ffilter++;
	}

	oldrule = sniper_ffilter;
	oldmem  = sniper_ffilter_mem;
	old_rulesize = ffilter_rulesize;
	old_memsize = ffilter_memsize;

	write_lock(&sniper_ffilter_lock);
	sniper_ffilter = newrule;
	sniper_ffilter_mem = newmem;
	ffilter_rulesize = rule_size;
	ffilter_memsize = mem_size;
	sniper_ffilter_count = count;
	write_unlock(&sniper_ffilter_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FFILTERRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FFILTERMEM);

	sniper_ffilter_ver++;
}

static void update_file_usb(struct nlmsghdr *nlh)
{
	int i = 0, count = 0;
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_fusb_t *fusb = NULL;

	if (!nlh) {
		return;
	}

	count = sniper_fpolicy.usb_count;
	if (!count) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FUSBMEM);
	if (!newmem) {
		myprintk("update_fusb fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = count * sizeof(sniper_fusb_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FUSBMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FUSBRULE);
	if (!newrule) {
		myprintk("update_fusb fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FUSBMEM);
		return;
	}

	ptr = newmem;
	fusb = (sniper_fusb_t *)newrule;
	for (i = 0; i < count; i++) {
		fusb->major = *ptr;  ptr += 4;
		fusb->minor = *ptr;  ptr += 4;
		fusb->extension = ptr; ptr += strlen(fusb->extension) + 1;

		fusb++;
	}

	oldrule = sniper_fusb;
	oldmem  = sniper_fusb_mem;
	old_rulesize = fusb_rulesize;
	old_memsize = fusb_memsize;

	write_lock(&sniper_fusb_lock);
	sniper_fusb = newrule;
	sniper_fusb_mem = newmem;
	fusb_rulesize = rule_size;
	fusb_memsize = mem_size;
	sniper_fusb_count = count;
	write_unlock(&sniper_fusb_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FUSBRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FUSBMEM);

	sniper_fusb_ver++;
}

static void update_file_encrypt(struct nlmsghdr *nlh)
{
	int mem_size = 0, rule_size = 0;
	int old_memsize = 0, old_rulesize = 0;
	char *ptr = NULL;
	char *newrule = NULL, *newmem = NULL;
	char *oldrule = NULL, *oldmem = NULL;
	sniper_fencrypt_t *fencrypt = NULL;

	if (!nlh) {
		return;
	}

	mem_size = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (!mem_size) {
		return;
	}

	newmem = sniper_vmalloc(mem_size, VMALLOC_FENCRYPTMEM);
	if (!newmem) {
		myprintk("update_fencrypt fail, alloc %d memory fail\n", mem_size);
		return;
	}
	memcpy(newmem, nlmsg_data(nlh), mem_size);

	rule_size = sizeof(sniper_fencrypt_t);
	if (!rule_size) {
		sniper_vfree(newmem, mem_size, VMALLOC_FENCRYPTMEM);
		return;
	}

	newrule = sniper_vmalloc(rule_size, VMALLOC_FENCRYPTRULE);
	if (!newrule) {
		myprintk("update_fencrypt fail, alloc %d memory fail\n", rule_size);
		sniper_vfree(newmem, mem_size, VMALLOC_FENCRYPTMEM);
		return;
	}

	ptr = newmem;
	fencrypt = (sniper_fencrypt_t *)newrule;
	fencrypt->extension = ptr;  ptr += strlen(fencrypt->extension) + 1;


	oldrule = sniper_fencrypt;
	oldmem  = sniper_fencrypt_mem;
	old_rulesize = fencrypt_rulesize;
	old_memsize = fencrypt_memsize;

	write_lock(&sniper_fencrypt_lock);
	sniper_fencrypt = newrule;
	sniper_fencrypt_mem = newmem;
	fencrypt_rulesize = rule_size;
	fencrypt_memsize = mem_size;
	write_unlock(&sniper_fencrypt_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_FENCRYPTRULE);
	sniper_vfree(oldmem, old_memsize, VMALLOC_FENCRYPTMEM);

	sniper_fencrypt_ver++;
}

static void update_fpolicy(struct nlmsghdr *nlh)
{
	write_lock(&sniper_fpolicy_lock);

	memcpy(&sniper_fpolicy, nlmsg_data(nlh), sizeof(sniper_fpolicy));

	limit_count(sniper_fpolicy.safe_count);

	write_unlock(&sniper_fpolicy_lock);

//	post_fpolicy_update(); //释放无效的子策略空间
	sniper_fpolicy_ver++;
}

/* 网络策略更新 */
char *sniper_nconnection_filterip = NULL;
int nconnection_size = 0;
int  sniper_nconnection_filterip_count = 0;

char *sniper_nlanip = NULL;
int nlanip_size = 0;
int  sniper_nlanip_count = 0;

char *sniper_nhoneyport = NULL;
int nhoneyport_size = 0;
int  sniper_nhoneyport_count = 0;

char *sniper_nhoneyport_filterip = NULL;
int nhoneyport_filterip_size = 0;
int  sniper_nhoneyport_filterip_count = 0;

char *sniper_nhoneyport_trustip = NULL;
int nhoneyport_trustip_size = 0;
int  sniper_nhoneyport_trustip_count = 0;

char *sniper_nhoneyport_trustipv6 = NULL;
int nhoneyport_trustipv6_size = 0;
int  sniper_nhoneyport_trustipv6_count = 0;

domaintbl_t *sniper_ndnsfilter = NULL;
char *sniper_ndnsfilter_mem = NULL;
int ndnsfilter_memsize = 0;
int ndnsfilter_rulesize = 0;
int  sniper_ndnsfilter_count = 0;

domaintbl_t *sniper_ndnsblack = NULL;
char *sniper_ndnsblack_mem = NULL;
int ndnsblack_memsize = 0;
int ndnsblack_rulesize = 0;
int  sniper_ndnsblack_count = 0;

domaintbl_t *sniper_ndnswhite = NULL;
char *sniper_ndnswhite_mem = NULL;
int ndnswhite_memsize = 0;
int ndnswhite_rulesize = 0;
int  sniper_ndnswhite_count = 0;

domaintbl_t *sniper_ndnstrust = NULL;
char *sniper_ndnstrust_mem = NULL;
int ndnstrust_memsize = 0;
int ndnstrust_rulesize = 0;
int  sniper_ndnstrust_count = 0;

char *sniper_nwhitein = NULL;
int nwhitein_size = 0;
int  sniper_nwhitein_count = 0;

char *sniper_nwhiteout = NULL;
int nwhiteout_size = 0;
int  sniper_nwhiteout_count = 0;

char *sniper_nblackin = NULL;
int nblackin_size = 0;
int  sniper_nblackin_count = 0;

char *sniper_nblackout = NULL;
int nblackout_size = 0;
int  sniper_nblackout_count = 0;

char *sniper_nserver = NULL;
int nserver_size = 0;
int  sniper_nserver_count = 0;

int client_mode = 0;
int host_quarantine = 0;

static void update_client_mode(struct nlmsghdr *nlh)
{
	int val = 0;
	int datalen = nlh->nlmsg_len - NLMSG_HDRLEN;

	if (datalen <= 0) {
		myprintk("set client_mode fail: bad datalen %d\n", datalen);
		return;
	}

	memcpy(&val, NLMSG_DATA(nlh), datalen);
	if (val < NORMAL_MODE || val > LEARNING_MODE) {
		myprintk("set client_mode fail: invalid value %d\n", val);
		return;
	}

	if (client_mode != val) {
		myprintk("change client_mode %d -> %d\n", client_mode, val);
		client_mode = val;
	}
}

static void update_host_quarantine(struct nlmsghdr *nlh)
{
	int val = 0;
	int datalen = nlh->nlmsg_len - NLMSG_HDRLEN;

	if (datalen <= 0) {
		myprintk("set host quarantine fail: bad datalen %d\n", datalen);
		return;
	}

	memcpy(&val, NLMSG_DATA(nlh), datalen);
	if (val != 1 && val != 0) {
		myprintk("set host_quarantine fail: invalid value %d\n", val);
		return;
	}

	if (host_quarantine != val) {
		host_quarantine = val;
		myprintk("set host_quarantine %d\n", host_quarantine);
	}
}

static void update_nconnection_filterip(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_iprange);
	count = sniper_nrule.connection_filterip_count;

	newrule = get_newrule(nlh, size, count, "connection filterip", VMALLOC_CONNFILTERIP);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nconnection_filterip;
	old_rulesize = nconnection_size;

	write_lock_bh(&sniper_nconnection_lock);
	sniper_nconnection_filterip = newrule;
	sniper_nconnection_filterip_count = count;
	nconnection_size = datalen;
	write_unlock_bh(&sniper_nconnection_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_CONNFILTERIP);

	sniper_nconnection_filterip_ver++;
}

static void update_nlanip(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_iprange);
	count = sniper_nrule.lanip_count;

	newrule = get_newrule(nlh, size, count, "LAN IP", VMALLOC_LANIP);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nlanip;
	old_rulesize = nlanip_size;

	write_lock_bh(&sniper_nlanip_lock);
	sniper_nlanip = newrule;
	sniper_nlanip_count = count;
	nlanip_size = datalen;
	write_unlock_bh(&sniper_nlanip_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_LANIP);

	sniper_nlanip_ver++;
}

static void update_nhoneyport(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(int);
	count = sniper_nrule.honeyport_count;

	newrule = get_newrule(nlh, size, count, "honeyport", VMALLOC_HONEYPORT);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nhoneyport;
	old_rulesize = nhoneyport_size;

	write_lock_bh(&sniper_nhoneyport_lock);
	sniper_nhoneyport = newrule;
	sniper_nhoneyport_count = count;
	nhoneyport_size = datalen;
	write_unlock_bh(&sniper_nhoneyport_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_HONEYPORT);

	sniper_nhoneyport_ver++;
}

static void update_nhoneyport_filterip(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_iprange);
	count = sniper_nrule.honeyport_filterip_count;

	newrule = get_newrule(nlh, size, count, "portscan filterip", VMALLOC_PORTSCAN_FILTERIP);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nhoneyport_filterip;
	old_rulesize = nhoneyport_filterip_size;

	write_lock_bh(&sniper_nhoneyport_lock);
	sniper_nhoneyport_filterip = newrule;
	sniper_nhoneyport_filterip_count = count;
	nhoneyport_filterip_size = datalen;
	write_unlock_bh(&sniper_nhoneyport_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_PORTSCAN_FILTERIP);

	sniper_nhoneyport_filterip_ver++;
}

static void update_nhoneyport_trustip(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_iprange);
	count = sniper_nrule.honeyport_trustip_count;

	newrule = get_newrule(nlh, size, count, "portscan trustip", VMALLOC_PORTSCAN_TRUSTIP);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nhoneyport_trustip;
	old_rulesize = nhoneyport_trustip_size;

	write_lock_bh(&sniper_nhoneyport_lock);
	sniper_nhoneyport_trustip = newrule;
	sniper_nhoneyport_trustip_count = count;
	nhoneyport_trustip_size = datalen;
	write_unlock_bh(&sniper_nhoneyport_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_PORTSCAN_TRUSTIP);

	sniper_nhoneyport_trustip_ver++;
}

static void update_nhoneyport_trustipv6(struct nlmsghdr *nlh)
{
	int count = 0, size = 0, i = 0;
	char *newrule = NULL, *oldrule = NULL;
	struct sniper_ipv6 *result;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_ipv6);
	count = sniper_nrule.honeyport_trustipv6_count;

	newrule = get_newrule(nlh, size, count, "portscan trustipv6", VMALLOC_PORTSCAN_TRUSTIPV6);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nhoneyport_trustipv6;
	old_rulesize = nhoneyport_trustipv6_size;

	sniper_nhoneyport_trustipv6 = newrule;
	sniper_nhoneyport_trustipv6_count = count;
	nhoneyport_trustipv6_size = datalen;

	sniper_vfree(oldrule, old_rulesize, VMALLOC_PORTSCAN_TRUSTIPV6);

	sniper_nhoneyport_trustipv6_ver++;

	/* 重置配置 */
	net_ipv6_conf_reset();
	result = (struct sniper_ipv6 *)sniper_nhoneyport_trustipv6;

	for (i=0; i<sniper_nhoneyport_trustipv6_count; i++) {
		net_ipv6_conf_insert(result);
		// myprintk("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
		// result->ipv6[0],result->ipv6[1],result->ipv6[2],result->ipv6[3],result->ipv6[4],result->ipv6[5],result->ipv6[6],
		// result->ipv6[7],result->ipv6[8],result->ipv6[9],result->ipv6[10],result->ipv6[11],result->ipv6[12],result->ipv6[13],
		// result->ipv6[14],result->ipv6[15]);
		result ++;
	}
}

static void update_ndnsfilter(struct nlmsghdr *nlh)
{
	struct domain_tblinfo info = {0};
	int count = sniper_nrule.dnsfilter_count;
	char *oldrule = NULL, *oldmem = NULL;
	int old_memsize = 0, old_rulesize = 0;

	if (update_domaintbl(nlh, &info, count, "filter domain", VMALLOC_DNSFILTERMEM, VMALLOC_DNSFILTERRULE)) {
		oldrule = (char *)sniper_ndnsfilter;
		oldmem  = sniper_ndnsfilter_mem;
		old_memsize = ndnsfilter_memsize;
		old_rulesize = ndnsfilter_rulesize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnsfilter = info.domaintbl;
		sniper_ndnsfilter_mem = info.domainmem;
		ndnsfilter_rulesize = info.rulesize;
		ndnsfilter_memsize = info.memsize;
		sniper_ndnsfilter_count = count;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSFILTERRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSFILTERMEM);

		sniper_ndnsfilter_ver++;
	}
}
static void update_ndnsblack(struct nlmsghdr *nlh)
{
	struct domain_tblinfo info = {0};
	int count = sniper_nrule.dnsblack_count;
	char *oldrule = NULL, *oldmem = NULL;
	int old_memsize = 0, old_rulesize = 0;

	if (update_domaintbl(nlh, &info, count, "black domain", VMALLOC_DNSBLACKMEM, VMALLOC_DNSBLACKRULE)) {
		oldrule = (char *)sniper_ndnsblack;
		oldmem  = sniper_ndnsblack_mem;
		old_memsize = ndnsblack_memsize;
		old_rulesize = ndnsblack_rulesize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnsblack = info.domaintbl;
		sniper_ndnsblack_mem = info.domainmem;
		ndnsblack_rulesize = info.rulesize;
		ndnsblack_memsize = info.memsize;
		sniper_ndnsblack_count = count;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSBLACKRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSBLACKMEM);

		sniper_ndnsblack_ver++;
	}
}
static void update_ndnswhite(struct nlmsghdr *nlh)
{
	struct domain_tblinfo info = {0};
	int count = sniper_nrule.dnswhite_count;
	char *oldrule = NULL, *oldmem = NULL;
	int old_memsize = 0, old_rulesize = 0;

	if (update_domaintbl(nlh, &info, count, "white domain", VMALLOC_DNSWHITEMEM, VMALLOC_DNSWHITERULE)) {
		oldrule = (char *)sniper_ndnswhite;
		oldmem  = sniper_ndnswhite_mem;
		old_memsize = ndnswhite_memsize;
		old_rulesize = ndnswhite_rulesize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnswhite = info.domaintbl;
		sniper_ndnswhite_mem = info.domainmem;
		ndnswhite_rulesize = info.rulesize;
		ndnswhite_memsize = info.memsize;
		sniper_ndnswhite_count = count;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSWHITERULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSWHITEMEM);

		sniper_ndnswhite_ver++;
	}
}
static void update_ndnstrust(struct nlmsghdr *nlh)
{
	struct domain_tblinfo info = {0};
	int count = sniper_nrule.dnstrust_count;
	char *oldrule = NULL, *oldmem = NULL;
	int old_memsize = 0, old_rulesize = 0;

	if (update_domaintbl(nlh, &info, count, "trust domain", VMALLOC_DNSTRUSTMEM, VMALLOC_DNSTRUSTRULE)) {
		oldrule = (char *)sniper_ndnstrust;
		oldmem  = sniper_ndnstrust_mem;
		old_memsize = ndnstrust_memsize;
		old_rulesize = ndnstrust_rulesize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnstrust = info.domaintbl;
		sniper_ndnstrust_mem = info.domainmem;
		ndnstrust_rulesize = info.rulesize;
		ndnstrust_memsize = info.memsize;
		sniper_ndnstrust_count = count;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSTRUSTRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSTRUSTMEM);

		sniper_ndnstrust_ver++;
	}
}
static void update_nwhitein(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_connrule);
	count = sniper_nrule.whitein_count;

	newrule = get_newrule(nlh, size, count, "whitein", VMALLOC_NWHITEIN);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nwhitein;
	old_rulesize = nwhitein_size;

	write_lock_bh(&sniper_nwhitein_lock);
	sniper_nwhitein = newrule;
	sniper_nwhitein_count = count;
	nwhitein_size = datalen;
	write_unlock_bh(&sniper_nwhitein_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_NWHITEIN);

	sniper_nwhitein_ver++;
}

static void update_nwhiteout(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_connrule);
	count = sniper_nrule.whiteout_count;

	newrule = get_newrule(nlh, size, count, "whiteout", VMALLOC_NWHITEOUT);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nwhiteout;
	old_rulesize = nwhiteout_size;

	write_lock_bh(&sniper_nwhiteout_lock);
	sniper_nwhiteout = newrule;
	nwhiteout_size = datalen;
	sniper_nwhiteout_count = count;
	write_unlock_bh(&sniper_nwhiteout_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_NWHITEOUT);

	sniper_nwhiteout_ver++;
}

static void update_nblackin(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_connrule);
	count = sniper_nrule.blackin_count;

	newrule = get_newrule(nlh, size, count, "blackin", VMALLOC_NBLACKIN);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nblackin;
	old_rulesize = nblackin_size;

	write_lock_bh(&sniper_nblackin_lock);
	sniper_nblackin = newrule;
	sniper_nblackin_count = count;
	nblackin_size = datalen;
	write_unlock_bh(&sniper_nblackin_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_NBLACKIN);

	sniper_nblackin_ver++;
}

static void update_nblackout(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_connrule);
	count = sniper_nrule.blackout_count;

	newrule = get_newrule(nlh, size, count, "blackout", VMALLOC_NBLACKOUT);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nblackout;
	old_rulesize = nblackout_size;

	write_lock_bh(&sniper_nblackout_lock);
	sniper_nblackout = newrule;
	sniper_nblackout_count = count;
	nblackout_size = datalen;
	write_unlock_bh(&sniper_nblackout_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_NBLACKOUT);

	sniper_nblackout_ver++;
}

static void update_nserver(struct nlmsghdr *nlh)
{
	int count = 0, size = 0;
	char *newrule = NULL, *oldrule = NULL;
	int datalen =nlh->nlmsg_len - NLMSG_HDRLEN;
	int old_rulesize = 0;

	size = sizeof(struct sniper_server);

	newrule = get_newrule_count(nlh, size, &count, "server", VMALLOC_NSERVER);
	if (!newrule) {
		return;
	}

	oldrule = sniper_nserver;
	old_rulesize = nserver_size;

	write_lock_bh(&sniper_nserver_lock);
	sniper_nserver = newrule;
	sniper_nserver_count = count;
	sniper_nrule.server_count = count;
	nserver_size = datalen;
	write_unlock_bh(&sniper_nserver_lock);

	sniper_vfree(oldrule, old_rulesize, VMALLOC_NSERVER);

	sniper_nserver_ver++;
}

static void update_nlockip(struct nlmsghdr *nlh)
{
	int size = 0;
	struct sniper_lockip *rule = NULL;

	size = sizeof(struct sniper_lockip);

	/* lockip统计类别为KMALLOC_LOCKIP */
	rule = (struct sniper_lockip *)get_newrule(nlh, size, 1, "lockip", KMALLOC_LOCKIP);
	if (!rule) {
		return;
	}

	if (rule->reason) {
		sniper_add_lockip(&rule->ip, rule->reason, rule->lock_time);
	} else {
		sniper_del_lockip(&rule->ip);
	}

	sniper_kfree(rule, size, KMALLOC_LOCKIP);
}

static void post_nrule_update(void)
{
	char *oldrule = NULL, *oldmem = NULL;
	int old_rulesize = 0, old_memsize = 0;

	if (sniper_nrule.connection_filterip_count == 0) {
		oldrule = sniper_nconnection_filterip;
		old_rulesize = nconnection_size;

		write_lock_bh(&sniper_nconnection_lock);
		sniper_nconnection_filterip_count = 0;
		sniper_nconnection_filterip = NULL;
		nconnection_size = 0;
		write_unlock_bh(&sniper_nconnection_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_CONNFILTERIP);
	}

	if (sniper_nrule.lanip_count == 0) {
		oldrule = sniper_nlanip;
		old_rulesize = nlanip_size;

		write_lock_bh(&sniper_nlanip_lock);
		sniper_nlanip_count = 0;
		sniper_nlanip = NULL;
		nlanip_size = 0;
		write_unlock_bh(&sniper_nlanip_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_LANIP);
	}

	if (sniper_nrule.honeyport_count == 0) {
		oldrule = sniper_nhoneyport;
		old_rulesize = nhoneyport_size;

		write_lock_bh(&sniper_nhoneyport_lock);
		sniper_nhoneyport_count = 0;
		sniper_nhoneyport = NULL;
		nhoneyport_size = 0;
		write_unlock_bh(&sniper_nhoneyport_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_HONEYPORT);
	}

	if (sniper_nrule.honeyport_filterip_count == 0) {
		oldrule = sniper_nhoneyport_filterip;
		old_rulesize = nhoneyport_filterip_size;

		write_lock_bh(&sniper_nhoneyport_lock);
		sniper_nhoneyport_filterip_count = 0;
		sniper_nhoneyport_filterip = NULL;
		nhoneyport_filterip_size = 0;
		write_unlock_bh(&sniper_nhoneyport_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_PORTSCAN_FILTERIP);
	}

	if (sniper_nrule.honeyport_trustip_count == 0) {
		oldrule = sniper_nhoneyport_trustip;
		old_rulesize = nhoneyport_trustip_size;

		write_lock_bh(&sniper_nhoneyport_lock);
		sniper_nhoneyport_trustip_count = 0;
		sniper_nhoneyport_trustip = NULL;
		nhoneyport_trustip_size = 0;
		write_unlock_bh(&sniper_nhoneyport_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_PORTSCAN_TRUSTIP);
	}

	if (sniper_nrule.honeyport_trustipv6_count == 0) {
		oldrule = sniper_nhoneyport_trustipv6;
		old_rulesize = nhoneyport_trustipv6_size;

		sniper_nhoneyport_trustipv6_count = 0;
		sniper_nhoneyport_trustipv6 = NULL;
		nhoneyport_trustipv6_size = 0;

		sniper_vfree(oldrule, old_rulesize, VMALLOC_PORTSCAN_TRUSTIPV6);
	}

	if (sniper_nrule.dnsfilter_count == 0) {
		oldrule = (char *)sniper_ndnsfilter;
		oldmem  = sniper_ndnsfilter_mem;
		old_rulesize = ndnsfilter_rulesize;
		old_memsize = ndnsfilter_memsize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnsfilter_count = 0;
		sniper_ndnsfilter = NULL;
		sniper_ndnsfilter_mem = NULL;
		ndnsfilter_rulesize = 0;
		ndnsfilter_memsize = 0;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSFILTERRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSFILTERMEM);
	}

	if (sniper_nrule.dnsblack_count == 0) {
		oldrule = (char *)sniper_ndnsblack;
		oldmem  = sniper_ndnsblack_mem;
		old_rulesize = ndnsblack_rulesize;
		old_memsize = ndnsblack_memsize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnsblack_count = 0;
		sniper_ndnsblack = NULL;
		sniper_ndnsblack_mem = NULL;
		ndnsblack_rulesize = 0;
		ndnsblack_memsize = 0;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSBLACKRULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSBLACKMEM);
	}

	if (sniper_nrule.dnswhite_count == 0) {
		oldrule = (char *)sniper_ndnswhite;
		oldmem  = sniper_ndnswhite_mem;
		old_rulesize = ndnswhite_rulesize;
		old_memsize = ndnswhite_memsize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnswhite_count = 0;
		sniper_ndnswhite = NULL;
		sniper_ndnswhite_mem = NULL;
		ndnswhite_rulesize = 0;
		ndnswhite_memsize = 0;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSWHITERULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSWHITEMEM);
	}

	if (sniper_nrule.dnstrust_count == 0) {
		oldrule = (char *)sniper_ndnstrust;
		oldmem  = sniper_ndnstrust_mem;
		old_rulesize = ndnstrust_rulesize;
		old_memsize = ndnstrust_memsize;

		write_lock_bh(&sniper_ndns_lock);
		sniper_ndnstrust_count = 0;
		sniper_ndnstrust = NULL;
		sniper_ndnstrust_mem = NULL;
		ndnstrust_rulesize = 0;
		ndnstrust_memsize = 0;
		write_unlock_bh(&sniper_ndns_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_DNSWHITERULE);
		sniper_vfree(oldmem, old_memsize, VMALLOC_DNSWHITEMEM);
	}

	if (sniper_nrule.whitein_count == 0) {
		oldrule = sniper_nwhitein;
		old_rulesize = nwhitein_size;

		write_lock_bh(&sniper_nwhitein_lock);
		sniper_nwhitein_count = 0;
		sniper_nwhitein = NULL;
		nwhitein_size = 0;
		write_unlock_bh(&sniper_nwhitein_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_NWHITEIN);
	}

	if (sniper_nrule.whiteout_count == 0) {
		oldrule = sniper_nwhiteout;
		old_rulesize = nwhiteout_size;

		write_lock_bh(&sniper_nwhiteout_lock);
		sniper_nwhiteout_count = 0;
		sniper_nwhiteout = NULL;
		nwhiteout_size = 0;
		write_unlock_bh(&sniper_nwhiteout_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_NWHITEOUT);
	}

	if (sniper_nrule.blackin_count == 0) {
		oldrule = sniper_nblackin;
		old_rulesize = nblackin_size;

		write_lock_bh(&sniper_nblackin_lock);
		sniper_nblackin_count = 0;
		sniper_nblackin = NULL;
		nblackin_size = 0;
		write_unlock_bh(&sniper_nblackin_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_NBLACKIN);
	}

	if (sniper_nrule.blackout_count == 0) {
		oldrule = sniper_nblackout;
		old_rulesize = nblackout_size;

		write_lock_bh(&sniper_nblackout_lock);
		sniper_nblackout_count = 0;
		sniper_nblackout = NULL;
		nblackout_size = 0;
		write_unlock_bh(&sniper_nblackout_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_NBLACKOUT);
	}

	if (sniper_nrule.server_count == 0) {
		oldrule = sniper_nserver;
		old_rulesize = nserver_size;

		write_lock_bh(&sniper_nserver_lock);
		sniper_nserver_count = 0;
		sniper_nserver = NULL;
		nserver_size = 0;
		write_unlock_bh(&sniper_nserver_lock);

		sniper_vfree(oldrule, old_rulesize, VMALLOC_NSERVER);
	}
}

static void free_nrule(void)
{
	memset(&sniper_nrule, 0, sizeof(sniper_nrule));
	post_nrule_update();
}

static void update_nrule(struct nlmsghdr *nlh)
{
	write_lock(&sniper_nrule_lock);
	memcpy(&sniper_nrule, nlmsg_data(nlh), sizeof(sniper_nrule));
	write_unlock(&sniper_nrule_lock);

	post_nrule_update(); //释放无效的子策略空间
	sniper_nrule_ver++;
}

void sniper_freerules(void)
{
	free_prule();
	free_nrule();
	free_fpolicy();
}

static void update_cdrom_gid(struct nlmsghdr *nlh)
{
	int size = sizeof(gid_t);
	gid_t *rule = NULL;

	rule = (gid_t *)get_newrule(nlh, size, 1, "cdrom_gid", VMALLOC_CDROMGID);
	if (!rule) {
		return;
	}
	sniper_cdrom_gid = *rule;
	sniper_vfree(rule, size, VMALLOC_CDROMGID);
}

static void update_exec_loadoff(struct nlmsghdr *nlh)
{
	int size = sizeof(char);
	char *rule = NULL;

	rule = (char *)get_newrule(nlh, size, 1, "exec_loadoff", VMALLOC_EXEC_LOADOFF);
	if (!rule) {
		return;
	}
	sniper_exec_loadoff = *rule;
	sniper_vfree(rule, size, VMALLOC_EXEC_LOADOFF);
	//printk("sniper_exec_loadoff %d\n", sniper_exec_loadoff);
}
static void update_net_loadoff(struct nlmsghdr *nlh)
{
	int size = sizeof(char);
	char *rule = NULL;

	rule = (char *)get_newrule(nlh, size, 1, "net_loadoff", VMALLOC_FILE_LOADOFF);
	if (!rule) {
		return;
	}
	sniper_net_loadoff = *rule;
	sniper_vfree(rule, size, VMALLOC_FILE_LOADOFF);
	//printk("sniper_net_loadoff %d\n", sniper_net_loadoff);
}
static void update_file_loadoff(struct nlmsghdr *nlh)
{
	int size = sizeof(char);
	char *rule = NULL;

	rule = (char *)get_newrule(nlh, size, 1, "file_loadoff", VMALLOC_NET_LOADOFF);
	if (!rule) {
		return;
	}
	sniper_file_loadoff = *rule;
	sniper_vfree(rule, size, VMALLOC_NET_LOADOFF);
	//printk("sniper_file_loadoff %d\n", sniper_file_loadoff);
}

static void set_engine_status(void)
{
	int process_engine_on = 0;
	int file_engine_on = 0;

	if (sniper_prule.normal_on ||
	    sniper_prule.danger_on ||
	    sniper_prule.privilege_on ||
	    sniper_prule.remote_execute_on ||
	    sniper_prule.webshell_on ||
	    sniper_prule.mbr_on ||
	    sniper_prule.miner_on ||
	    sniper_prule.port_forward_on ||
	    sniper_prule.webexecute_on ||
	    sniper_prule.fake_sysprocess_on ||
	    sniper_pblack_count) {
		process_engine_on = 1;
	}

	if (sniper_fpolicy.file_sensitive_on ||
	    sniper_fpolicy.file_log_delete ||
	    sniper_fpolicy.file_safe_on ||
	    sniper_fpolicy.file_logcollector_on ||
	    sniper_fpolicy.file_middle_on ||
	    sniper_fpolicy.file_illegal_script_on ||
	    sniper_fpolicy.file_webshell_detect_on ||
	    sniper_fpolicy.encrypt_on ||
	    sniper_fpolicy.usb_file_on ||
	    sniper_fpolicy.antivirus_on) {
		file_engine_on = 1;
	}

	sniper_prule.process_engine_on = process_engine_on;
	sniper_fpolicy.file_engine_on = file_engine_on;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static void hello_nl_recv_msg(struct sock *sk, int len)
#else
static void hello_nl_recv_msg(struct sk_buff *skb)
#endif
{
	struct nlmsghdr *nlh = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	struct sk_buff *skb = skb_dequeue(&sk->sk_receive_queue);
#endif

	if (!skb) {
		return;
	}

	nlh = (struct nlmsghdr *)skb->data;
	if (!nlh) {
		return;
	}

	/* 动态挂钩子和卸钩子 */
	switch (nlh->nlmsg_type) {
		case NLMSG_REG:
			sniper_pid = nlh->nlmsg_pid;
			if (nlh->nlmsg_pid == 0) {
				nl_exec_pid = 0;
				nl_file_pid = 0;
				nl_virus_pid = 0;
				nl_net_pid = 0;

#if 0 //这里不做exit，以免卸载模块时netlink_release core，可能是有重复释放
				lsm_hooks_exit();
				net_hook_exit();
				net_hook_ipv6_exit();
				dirtycow_hook_exit();
#endif
			}
			break;

		case NLMSG_EXEC:
			nl_exec_pid = nlh->nlmsg_pid;
			break;

		case NLMSG_PROCESS_RULES:
			update_prule(nlh);
			break;

		case NLMSG_SNIPER_INODE:
			update_sniper_inode(nlh);
			break;

		case NLMSG_PMIDDLEWARE:
			update_pmiddleware(nlh);
			break;

		case NLMSG_COMMAND_TABLE:
			update_pcmdtbl(nlh);
			break;

		case NLMSG_MINE_POOL:
			update_pminepool(nlh);
			break;

		case NLMSG_BLACK_PROCESS:
			update_pblack(nlh);
			break;
		case NLMSG_FILTER_PROCESS:
			update_pfilter(nlh);
			break;
		case NLMSG_TRUST_PROCESS:
			update_ptrust(nlh);
			break;

		case NLMSG_FILE:
			nl_file_pid = nlh->nlmsg_pid;
			break;

		case NLMSG_FILE_POLICY:
			update_fpolicy(nlh);
			break;

		case NLMSG_FILE_SENSITIVE:
			update_file_sensitive(nlh);
			break;

		case NLMSG_FILE_LOG_DELETE:
			update_file_log_delete(nlh);
			break;

		case NLMSG_FILE_SAFE:
			update_file_safe(nlh);
			break;

		case NLMSG_FILE_LOGCOLLECTOR:
			update_file_logcollector(nlh);
			break;

		case NLMSG_FILE_MIDDLE_TARGET:
			update_file_middle_target(nlh);
			break;

		case NLMSG_FILE_BINARY_FILTER:
			update_file_middle_binary(nlh);
			break;

		case NLMSG_FILE_MIDDLE_SCRIPT:
			update_file_middle_script(nlh);
			break;

		case NLMSG_FILE_ILLEGAL_SCRIPT:
			update_file_illegal_script(nlh);
			break;

		case NLMSG_FILE_WEBSHELL_DETECT:
			update_file_webshell_detect(nlh);
			break;

		case NLMSG_FILE_BLACK:
			update_file_black(nlh);
			break;

		case NLMSG_FILE_FILTER:
			update_file_filter(nlh);
			break;

		case NLMSG_FILE_USB:
			update_file_usb(nlh);
			break;

		case NLMSG_FILE_ENCRYPT:
			update_file_encrypt(nlh);
			break;

		case NLMSG_VIRUS:
			nl_virus_pid = nlh->nlmsg_pid;
			break;

		case NLMSG_NET:
			nl_net_pid = nlh->nlmsg_pid;
			break;

		case NLMSG_NET_RULES:
			update_nrule(nlh);
			break;

		case NLMSG_NET_CONNECTION_FILTERIP:
			update_nconnection_filterip(nlh);
			break;

		case NLMSG_NET_LANIP:
			update_nlanip(nlh);
			break;

		case NLMSG_NET_HONEYPORT:
			update_nhoneyport(nlh);
			break;

		case NLMSG_NET_HONEYPORT_FILTERIP:
			update_nhoneyport_filterip(nlh);
			break;

		case NLMSG_NET_HONEYPORT_TRUSTIP:
			update_nhoneyport_trustip(nlh);
			break;
		case NLMSG_NET_HONEYPORT_TRUSTIPV6:
			update_nhoneyport_trustipv6(nlh);
			break;

		case NLMSG_NET_DNSBLACK:
			update_ndnsblack(nlh);
			break;
		case NLMSG_NET_DNSWHITE:
			update_ndnswhite(nlh);
			break;
		case NLMSG_NET_DNSTRUST:
			update_ndnstrust(nlh);
			break;
		case NLMSG_NET_DNSFILTER:
			update_ndnsfilter(nlh);
			break;

		case NLMSG_NET_WHITEIN:
			update_nwhitein(nlh);
			break;

		case NLMSG_NET_WHITEOUT:
			update_nwhiteout(nlh);
			break;

		case NLMSG_NET_BLACKIN:
			update_nblackin(nlh);
			break;

		case NLMSG_NET_BLACKOUT:
			update_nblackout(nlh);
			break;

		case NLMSG_NET_SERVERIP:
			update_nserver(nlh);
			break;

		case NLMSG_NET_LOCKIP:
			update_nlockip(nlh);
			break;

		case NLMSG_NET_HOSTQUARANTINE:
			update_host_quarantine(nlh);
			break;

		case NLMSG_CLIENT_MODE:
			update_client_mode(nlh);
			break;

		case NLMSG_CDROM_GID:
			update_cdrom_gid(nlh);
			break;

		case NLMSG_EXEC_LOADOFF:
			update_exec_loadoff(nlh);
			break;

		case NLMSG_NET_LOADOFF:
			update_net_loadoff(nlh);
			break;

		case NLMSG_FILE_LOADOFF:
			update_file_loadoff(nlh);
			break;

		default:
			myprintk("Bad nlmsg type %x\n", nlh->nlmsg_type);
	}

	set_engine_status();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	kfree_skb(skb);
#endif
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
struct netlink_kernel_cfg cfg = {
	.input = hello_nl_recv_msg,
};
#endif

static int linux_netlink_create(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
	nl_sk = netlink_kernel_create(&init_net, sniper_netlink, &cfg);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3,6,0)
	nl_sk = netlink_kernel_create(&init_net, sniper_netlink, THIS_MODULE, &cfg);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
	nl_sk = netlink_kernel_create(&init_net, sniper_netlink, 0, hello_nl_recv_msg, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21)
	nl_sk = netlink_kernel_create(sniper_netlink, 0, hello_nl_recv_msg, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
	nl_sk = netlink_kernel_create(sniper_netlink, 0, hello_nl_recv_msg, THIS_MODULE);
#else
	nl_sk = netlink_kernel_create(sniper_netlink, hello_nl_recv_msg);
#endif
	/* 这里错误返回NULL */
	if (!nl_sk) {
		myprintk("create netlink %d fail\n", sniper_netlink);
		return -ENODEV;
	}
	if (IS_ERR(nl_sk)) {
		int err = PTR_ERR(nl_sk);
		myprintk("create netlink %d fail: %d\n", sniper_netlink, err);
		return -err;
	}

	return 0;
}

static int sniper_netlink_create(void)
{
	int i = 0;

	/* 参考专用机的主审软件约定，默认使用24,25,31 */
	sniper_netlink = NETLINK_SNIPER; //24
	if (linux_netlink_create() == 0) {
		return 0;
	}

	sniper_netlink = 25;
	if (linux_netlink_create() == 0) {
		return 0;
	}

	sniper_netlink = 31;
	if (linux_netlink_create() == 0) {
		return 0;
	}

	for (i = 30; i > 0; i--) {
		if (i == 24 || i == 25) {
			continue;
		}
		sniper_netlink = i;
		if (linux_netlink_create() == 0) {
			return 0;
		}
	}

	sniper_netlink = 0;
	return -ENODEV;
}

void sniper_netlink_release(void)
{
	if (nl_sk) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
		sock_release(nl_sk->sk_socket);
#else
		netlink_kernel_release(nl_sk);
#endif
		nl_sk = NULL;
	}
}

/*
 * 应用层已有队列缓冲，内核里进程和文件消息不重复缓冲
 * 至于网络消息，由于入包是在中断中处理的，为了避免在中断里等待，内核里使用消息队列异步发送
 */
static unsigned long failed_proc_msgs = 0;
static unsigned long failed_file_msgs = 0;
static unsigned long failed_virus_msgs = 0;
static unsigned long failed_net_msgs = 0;

int ksniperd_netin_stopped = 0;

static struct task_struct *ksniperd_netin = NULL;
static LIST_HEAD(netin_msg_queue);
static wait_queue_head_t netin_queue;

void send_msg_to_user(char *buffer, int len, pid_t nlmsg_pid)
{
	int ret = 0;
	struct nlmsghdr *nlh = NULL;
	struct sk_buff *skb_out = NULL;

	if (nlmsg_pid == 0 || nl_sk == NULL) {
		return;
	}

	skb_out = nlmsg_new(NLMSG_SPACE(len), 0);
	if (!skb_out) {
		myprintk("send_msg_to_user fail, no memory\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, len, 0);
	if (!nlh) {
		myprintk("send_msg_to_user fail, get null nlh\n");
		return;
	}

	memcpy(nlmsg_data(nlh), buffer, len);

	ret = nlmsg_unicast(nl_sk, skb_out, nlmsg_pid);
	if (ret == 0) {
		return;
	}

	if (nlmsg_pid == nl_exec_pid) {
		failed_proc_msgs++;
		if ((failed_proc_msgs & 0x3ff) != 0) {
			return;
		}
		myprintk("send_proc_msg_to_user error: %d\n", ret);
		myprintk("Total %lu proc msgs fail\n", failed_proc_msgs);
		return;
	}
	if (nlmsg_pid == nl_file_pid) {
		failed_file_msgs++;
		if ((failed_file_msgs & 0x3ff) != 0) {
			return;
		}
		myprintk("send_file_msg_to_user error: %d\n", ret);
		myprintk("Total %lu file msgs fail\n", failed_file_msgs);
		return;
	}
	if (nlmsg_pid == nl_virus_pid) {
		failed_virus_msgs++;
		if ((failed_virus_msgs & 0x3ff) != 0) {
			return;
		}
		myprintk("send_virus_msg_to_user error: %d\n", ret);
		myprintk("Total %lu virus msgs fail\n", failed_virus_msgs);
		return;
	}
	if (nlmsg_pid == nl_net_pid) {
		failed_net_msgs++;
		if ((failed_net_msgs & 0x3ff) != 0) {
			return;
		}
		myprintk("send_net_msg_to_user error: %d\n", ret);
		myprintk("Total %lu net msgs fail\n", failed_net_msgs);
		return;
	}
}

void send_data_to_user(char *buffer, int len, pid_t nlpid, int type)
{
	send_msg_to_user(buffer, len, nlpid);
}

static void report_netin_msg(msgipinfo_t *info)
{
	netreq_t req = {0};

	req.flags = info->flags;
	req.repeat = info->repeat;

	req.srcip = info->ip;
	req.sport = info->port;

	req.dstip = info->myip;
	req.dport = info->myport;

	sniper_do_gettimeofday(&req.event_tv);

	req.portscan_lockip_time = sniper_nrule.honey_lockip_seconds;

	req.size = sizeof(netreq_t);

	send_msg_to_user((char *)&req, req.size, nl_net_pid);
}

static void report_portscan_msg(msgipinfo_t *info)
{
	netreq_t *req = NULL;
	char *buf = NULL, *tmp = NULL, *ptr = NULL;
	int i = 0, n = 0, k = 0, len = 0, buflen = 0, tmp_len = 0;

	req = (netreq_t *)sniper_kmalloc(PAGE_SIZE, GFP_ATOMIC, KMALLOC_PORTSCAN);
	if (!req) {
		return;
	}
	memset(req, 0, PAGE_SIZE);

	req->flags = info->flags;
	req->repeat = info->repeat;

	req->srcip = info->ip;
	req->sport = info->port;

	req->dstip = info->myip;
	req->dport = info->myport;

	req->ports_count = info->ports_count;

	req->portscan_lockip_time = sniper_nrule.portscan_lock_time;
	req->portscan_max = sniper_nrule.portscan_max;
	req->effective_time = sniper_nrule.portscan_time;

	sniper_do_gettimeofday(&req->event_tv);

	buf = (char *)req + sizeof(netreq_t);
	buflen = PAGE_SIZE - sizeof(netreq_t);

	n = info->portlist_size / sizeof(int);
	for (i = 0; i < n; i++) {
		k = 2 * i;

		len = strlen(buf);
		tmp = buf + len,
		tmp_len = buflen - len;
		if (info->portlist[k] == info->portlist[k+1]) {
			snprintf(tmp, tmp_len, "%d,", info->portlist[k]);
		} else {
			snprintf(tmp, tmp_len, "%d-%d,", info->portlist[k], info->portlist[k+1]);
		}
	}

	ptr = strrchr(buf, ',');
	if (ptr) {
		*ptr = 0;
	}
	req->size = sizeof(netreq_t) + strlen(buf) + 1;

	send_msg_to_user((char *)req, req->size, nl_net_pid);

	sniper_kfree(req, PAGE_SIZE, KMALLOC_PORTSCAN);
}

static void handle_netin_msg_onetype(iplist_t *iplist_type, char *desc, int type)
{
	int i = 0, count = 0, expire_time = ZIPTERM, size = sizeof(msgipinfo_t);
	iplist_t *iplist = NULL;
	msgipinfo_t *info = NULL, *tmp = NULL, *dupinfo = NULL;
	unsigned short *portlist = NULL;
	time_t now = sniper_uptime();

	if (type == KMALLOC_PORTSCAN) {
		expire_time = sniper_nrule.portscan_time;
	}

	for (i = 0; i < IPLISTNUM; i++) {
		iplist = &iplist_type[i];
		if (iplist->count == 0) {
			continue;
		}

		write_lock_bh(&iplist->lock);
		count = 0;
		list_for_each_entry_safe(info, tmp, &iplist->queue, list) {
			count++;

			/* 处理新的未报告过的消息 */
			if (info->last_report_time == 0) {
				if (info->flags.portscan) {
					/* 还没有累计到足够的次数报端口扫描超限 */
					if (info->ports_count < sniper_nrule.portscan_max) {
						continue;
					}

					/* 复制一个消息用来报告。复制消息失败不报告。
					   原消息留在原队列里用来压缩1分钟内的同样消息 */
					dupinfo = (msgipinfo_t *)sniper_kmalloc(size, GFP_ATOMIC, type);
					if (!dupinfo) {
						continue;
					}
					/* 复制被扫描的端口列表 */
					portlist = (unsigned short *)sniper_kmalloc(info->portlist_size, GFP_ATOMIC, KMALLOC_PORTLIST);
					if (!portlist) {
						sniper_kfree(dupinfo, size, type);
						continue;
					}

					memcpy(dupinfo, info, size);
					memcpy(portlist, info->portlist, info->portlist_size);
					dupinfo->portlist = portlist;
					INIT_LIST_HEAD(&dupinfo->list);
					list_add_tail(&dupinfo->list, &netin_msg_queue);

					info->repeat = 0;
					info->last_report_time = now;
					continue;
				} else {
					/* 复制一个消息用来报告。复制消息失败不报告。
					   原消息留在原队列里用来压缩1分钟内的同样消息 */
					dupinfo = (msgipinfo_t *)sniper_kmalloc(size, GFP_ATOMIC, type);
					if (!dupinfo) {
						continue;
					}

					memcpy(dupinfo, info, size);
					INIT_LIST_HEAD(&dupinfo->list);
					list_add_tail(&dupinfo->list, &netin_msg_queue);

					info->last_report_time = now;
					continue;
				}
			}

			/* 处理报告过的且留存1分钟以上的消息 */
			if (now - info->last_report_time >= expire_time) {
				list_del(&info->list);
				iplist->count--;
				count--;

				if (info->repeat) {
					/* 把消息移入netin_msg_queue，后面会报告重复了多少次 */
					list_add_tail(&info->list, &netin_msg_queue);
				} else {
					/* 一分钟内没有重复的，本目标已报过，不重复报 */
					sniper_kfree(info->portlist, info->portlist_size, KMALLOC_PORTLIST);
					sniper_kfree(info, sizeof(msgipinfo_t), type);
				}
			}
		}

		if (iplist->count != count) {
			if (desc) {
				myprintk("fix %s[%d].count %d to %d\n", desc, i, iplist->count, count);
			} else {
				myprintk("fix (malloc type %d)[%d].count %d to %d\n", type, i, iplist->count, count);
			}
			iplist->count = count;
		}
		write_unlock_bh(&iplist->lock);
	}
}

/* 清理blackoutmsg中用于压缩重复消息的info，清理存活时间超过2分钟的，避免一直占用内存 */
static void clean_expired_blackoutmsg(void)
{
	int i = 0, count = 0, expire_time = 2 * ZIPTERM, size = sizeof(msgipinfo_t);
	iplist_t *iplist = blackoutmsg;
	msgipinfo_t *info = NULL, *tmp = NULL;
	time_t now = sniper_uptime();

	for (i = 0; i < IPLISTNUM; i++, iplist++) {
		if (iplist->count == 0) {
			continue;
		}
		write_lock(&iplist->lock);
		count = 0;
		list_for_each_entry_safe(info, tmp, &iplist->queue, list) {
			count++;
			//TODO info增加个创建时间的字段，用来代替last_report_time判断是否过期
			if (now - info->last_report_time >= expire_time) {
				list_del(&info->list);
				iplist->count--;
				count--;
				sniper_kfree(info, size, KMALLOC_BLACKOUT);
			}
		}
		if (iplist->count != count) {
			myprintk("fix blackoutmsg[%d].count %d to %d\n", i, iplist->count, count);
			iplist->count = count;
		}
		write_unlock(&iplist->lock);
	}
}

static int get_kmalloc_type(msgipinfo_t *info)
{
	if (sniper_badptr(info)) {
		return 0;
	}
	if (info->flags.portscan) {
		return KMALLOC_PORTSCAN;
	}
	if (info->flags.honeyport) {
		return KMALLOC_HONEYPORT;
	}
	if (info->flags.lockedip) {
		return KMALLOC_LOCKIP;
	}
	if (info->flags.blackin || info->flags.notwhitein) {
		return KMALLOC_BLACKIN;
	}
	return 0;
}

static int handle_netin_msg(void *arg)
{
	int size = sizeof(msgipinfo_t);
	msgipinfo_t *info = NULL, *tmp = NULL;

	while (1) {
		wait_event_interruptible_timeout(netin_queue,
						kthread_should_stop(),
						msecs_to_jiffies(100));

		if (kthread_should_stop()) {
			/* 丢弃未发送的消息 */
			list_for_each_entry_safe(info, tmp, &netin_msg_queue, list) {
				list_del(&info->list);
				sniper_kfree(info->portlist, info->portlist_size, KMALLOC_PORTLIST);
				sniper_kfree(info, size, get_kmalloc_type(info));
			}
			break;
		}

		/* 将要发送的消息移到netin_msg_queue里 */
		if (sniper_nrule.honeyport_count) {
			handle_netin_msg_onetype(honeyportmsg, "honeyportmsg", KMALLOC_HONEYPORT);
		}
		if (sniper_nrule.portscan_max) {
			handle_netin_msg_onetype(portscanmsg, "portscanmsg", KMALLOC_PORTSCAN);
		}
		if (sniper_nrule.blackin_count || sniper_nrule.whitein_count) {
			handle_netin_msg_onetype(blackinmsg, "blackinmsg", KMALLOC_BLACKIN);
		}
		if (sniper_nrule.honeyport_lockip ||
		    sniper_prule.miner_lockip ||
		    sniper_prule.webshell_lockip ||
		    sniper_prule.remote_execute_lockip) {
			handle_netin_msg_onetype(lockipmsg, "lockipmsg", KMALLOC_LOCKIP);
		}

		/* 发送netin消息 */
		list_for_each_entry_safe(info, tmp, &netin_msg_queue, list) {
			list_del(&info->list);

			if (info->flags.portscan) {
				report_portscan_msg(info);
			} else {
				report_netin_msg(info);
			}

			sniper_kfree(info->portlist, info->portlist_size, KMALLOC_PORTLIST);
			sniper_kfree(info, size, get_kmalloc_type(info));
		}

		clean_expired_blackoutmsg();
		clean_expired_dnsquery();
	}

	ksniperd_netin_stopped = 1;
	myprintk("ksniperd_netin stopped\n");
	return 0;
}

int msg_init(void)
{
	int err = 0;

	if (sniper_netlink_create() < 0) {
		myprintk("msg_init fail, create netlink error\n");
		return -ENODEV;
	}

	init_waitqueue_head(&netin_queue);

	/*
	 * 创建核心线程，报告连入相关的事件
	 * netfilter inhook不可直接发送netlink消息，因为它是在中断态，而发送netlink消息可能睡眠
	 */
	ksniperd_netin = kthread_run(handle_netin_msg, NULL, "ksniperd_netin");
	if (IS_ERR(ksniperd_netin)) {
		err = PTR_ERR(ksniperd_netin);
		myprintk("run ksniperd_netin fail: %d\n", err);
		ksniperd_netin = NULL;
		sniper_netlink_release();
		return err;
	}

	return 0;
}

void msg_exit(void)
{
	if (ksniperd_netin) {
		kthread_stop(ksniperd_netin);
		ksniperd_netin = NULL;
	}
}
