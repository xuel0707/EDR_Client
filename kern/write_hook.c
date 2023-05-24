#include "interface.h"

/* Dirtypipe漏洞影响范围：5.8 <= Linux 内核版本 < 5.16.11 / 5.15.25 / 5.10.102 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,10,102)
#define HANDLE_DIRTYPIPE 1
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,15,25)
#define HANDLE_DIRTYPIPE 1
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,16,11)
#define HANDLE_DIRTYPIPE 1
#endif

#ifdef HANDLE_DIRTYPIPE
/* 参考了report_dirtycow() */
static void report_dirtypipe(int *ret)
{
	int do_stop = 1, trust = 0;
	taskreq_t *req = NULL;

	req = init_taskreq(INIT_WITH_PINFO|INIT_WITH_CMD);
	if (!req) {
		return;
	}

	req->flags = PSR_DIRTYPIPE;
	req->pflags.dirtypipe = 1;

	if (is_filter_cmd(req, NULL)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	trust = is_trust_cmd(req, EVENT_PrivilegeEscalation, NULL, NULL);
	if (!trust && sniper_prule.privilege_kill && client_mode == NORMAL_MODE) {
		do_stop = 1;
		req->pflags.terminate = 1;
		*ret = -1; //设置调用者的返回值
	}

	myprintk("%s/%d(uid %d) may Dirtypipe! %s\n", current->comm, current->pid,
	req->uid, do_stop ? "forbidden" : "only warning");

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;
	send_data_to_user((char *)req, req->size, nl_exec_pid, Probe_dirtypipe);

	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
}

/* 从file取pipe，失败返回NULL */
static struct pipe_inode_info *get_pipe(struct file *file)
{
	struct inode *inode = NULL;
	struct pipe_inode_info *pipe = NULL;

	if (sniper_badptr(file) || sniper_badptr(file->f_dentry)) {
		return NULL;
	}
	inode = file->f_dentry->d_inode;

	if (sniper_badptr(inode) || inode->i_sb->s_magic != PIPEFS_MAGIC) {
		return NULL;
	}
	pipe = (struct pipe_inode_info *)file->private_data;

	return pipe;
}

/*
 * Dirtypipe本质上是个操作系统bug，会导致文件内容被破坏，因此，
 * 如果buf->page对应的是某个文件的缓冲页，总是禁用PIPE_BUF_FLAG_CAN_MERGE，防止数据被破坏
 * 如果当前用户为普通用户，而buf->page对应的是root的文件，视为提权访问
 * 返回1，表示提权访问；返回0，非提权访问
 */
static int check_dirtypipe(struct pipe_inode_info *pipe)
{
	int i = 0, ret = 0;
	uid_t myuid = 0, uid = 0;
	struct pipe_buffer *buf = NULL;
	struct address_space *mapping = NULL;
	struct page *page = NULL;
	struct inode *inode = NULL;

	if (sniper_badptr(pipe)) {
		return 0;
	}

	myuid = currenteuid();

	for (i = 0; i < pipe->ring_size; i++) {
		buf = pipe->bufs + i;
		if (sniper_badptr(buf)) {
			continue;
		}

		page = buf->page;
		if (sniper_badptr(page)) {
			continue;
		}

		mapping = page->mapping;
		if (sniper_badptr(mapping)) {
			continue;
		}

		if ((unsigned long)mapping & PAGE_MAPPING_ANON) {
			continue;
		}

		inode = mapping->host;
		if (sniper_badptr(inode)) {
			continue;
		}

		if (buf->flags != PIPE_BUF_FLAG_CAN_MERGE) {
			continue;
		}
		buf->flags = 0; //总是置0，防止文件数据损坏

		if (0 != myuid) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
			uid = inode->i_uid;
#else
			uid = __kuid_val(inode->i_uid);
#endif
			if (0 == uid) {
				ret = 1; //提权访问文件
			}
		}
	}

	return ret;
}
#endif

static int is_disk_device(struct dentry *dentry)
{
	int major = 0;
	struct inode *inode = NULL;

	if (sniper_badptr(dentry) || sniper_badptr(dentry->d_inode)) {
		return 0;
	}
	inode = dentry->d_inode;
	if (!S_ISBLK(inode->i_mode)) {
		return 0;
	}

        major = MAJOR(inode->i_rdev);
        /* Documentation/devices.txt: 8,9,65-71,128-135,240-254 */
        if (major == SCSI_DISK0_MAJOR || major == MD_MAJOR ||
            (major >= SCSI_DISK1_MAJOR && major <= SCSI_DISK7_MAJOR) ||
            (major >= SCSI_DISK8_MAJOR && major <= SCSI_DISK15_MAJOR) ||
            (major >= 240 && major <= 254)) {
                return 1;
        }

        return 0;
}

time_t last_illegal_distwrite_time = 0; //not report in 1s
int  last_illegal_distwrite_status = 0; //0 允许，-1 禁止。1秒内的重复操作是否允许，按上次同样的处理

/* retval: -1 deny, 0 allow */
static int report_illegal_diskwrite(char *devname)
{
	int trust = 0, do_stop = 0;
	time_t now = sniper_uptime();
	time_t last = last_illegal_distwrite_time;
	taskreq_t *req = NULL;

	if (sniper_badptr(devname)) {
		return 0;
	}

	/* 每次都更新上次写裸盘时间，不重复报告连续1秒内的写裸盘行为 */
	last_illegal_distwrite_time = now;

	/* 不做mbr防护时，last_illegal_distwrite_status复位 */
	if (last_illegal_distwrite_status < 0 &&
	    (!sniper_prule.mbr_kill || client_mode != NORMAL_MODE)) {
		last_illegal_distwrite_status = 0;
	}

	if (now == last || now == last + 1) {
		return last_illegal_distwrite_status;
	}

	req = init_taskreq(INIT_WITH_PINFO|INIT_WITH_CMD);
	if (!req) {
		return last_illegal_distwrite_status;
	}

	req->flags = PSR_DISK_WRITE;
	req->pflags.writedisk = 1;

	if (is_filter_cmd(req, NULL)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;
	}

	trust = is_trust_cmd(req, EVENT_MBRAttack, NULL, NULL);
	if (!trust && sniper_prule.mbr_kill && client_mode == NORMAL_MODE) {
		do_stop = 1;
		req->flags |= PSR_WRITE_FORBIDDEN | PSR_STOPED;
		req->pflags.terminate = 1;
	}

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		myprintk("Warning: %s/%d write disk %s\n", current->comm, current->pid, devname);
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;
        send_data_to_user((char *)req, req->size, nl_exec_pid, Probe_opendisk);

	/* 没必要打印uid，只有root有权限写盘设备 */
	if (do_stop) {
		myprintk("Forbid %s/%d write disk %s\n", current->comm, current->pid, devname);
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return -1;
	}

	myprintk("Warning: %s/%d write disk %s\n", current->comm, current->pid, devname);
	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
	return 0;
}

extern int dirtycow_on;
extern void check_dirtycow_selfmem(void);
static int is_proc_self_mem(struct dentry *dentry)
{
	struct dentry *droot = NULL;
	struct dentry *dparent = NULL, *dgrandpa = NULL;
	char pidstr[S_NAMELEN] = {0};
	char tpidstr[S_NAMELEN] = {0};

	if (sniper_badptr(dentry) ||
	    sniper_badptr(dentry->d_sb) ||
	    sniper_badptr(dentry->d_parent) ||
	    strcmp(dentry->d_name.name, "mem") != 0) {
		return 0;
	}

	/* 检查是否为/proc/xxx/mem */
	droot = dentry->d_sb->s_root;
	dparent = dentry->d_parent;
	dgrandpa = dentry->d_parent->d_parent;
	if (sniper_badptr(droot) || dgrandpa != droot) {
		return 0;
	}

	/* 检查是否为自己的或者进程组的mem文件 */
	snprintf(pidstr, S_NAMELEN, "%d", current->pid);
	snprintf(pidstr, S_NAMELEN, "%d", current->group_leader->pid);
	if (strcmp(dparent->d_name.name, pidstr) == 0 ||
	    strcmp(dparent->d_name.name, tpidstr) == 0) {
		return 1;
	}
	return 0;
}

static int my_file_permission(struct file *file, int mask)
{
#ifdef HANDLE_DIRTYPIPE
	struct pipe_inode_info *pipe = NULL;
#endif
	struct dentry *dentry = NULL;

	/* 只处理写的情况 */
	if (mask != MAY_WRITE) {
		return 0;
	}

	if (sniper_badptr(file) || sniper_badptr(file->f_dentry)) {
		return 0;
	}
	dentry = file->f_dentry;

#ifdef HANDLE_DIRTYPIPE
	/* 处理dirtypipe提权 */
	pipe = get_pipe(file);
	if (pipe) {
		int ret = 0;
		if (check_dirtypipe(pipe)) {
			report_dirtypipe(&ret);
			return ret;
		}
		return 0;
	}
#endif

	if (process_engine_status()) {
		/* MBR防护 */
		if (sniper_prule.mbr_on && is_disk_device(dentry)) {
			last_illegal_distwrite_status = report_illegal_diskwrite((char *)dentry->d_name.name);
			return last_illegal_distwrite_status;
		}

		/* 龙芯不支持kprobe，通过检测写/proc/self/mem，来检测dirtyc0w程序 */
		/* 这里仅检测，阻断在应用层做 */
		if (sniper_prule.privilege_on && !dirtycow_on &&
		    currenteuid() != 0 && is_proc_self_mem(dentry)) {
			check_dirtycow_selfmem();
			return 0;
		}
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_file_permission(struct file *file, int mask)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_WRITE]);

	ret = my_file_permission(file, mask);
	if (ret < 0) {
		atomic_dec(&sniper_usage[SNIPER_WRITE]);
		return ret;
	}

	if (original_file_permission) {
		ret = original_file_permission(file, mask);
	}

	atomic_dec(&sniper_usage[SNIPER_WRITE]);

	return ret;
}
#else
int sniper_file_permission(struct file *file, int mask)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_WRITE]);

	ret = my_file_permission(file, mask);

	atomic_dec(&sniper_usage[SNIPER_WRITE]);

	return ret;
}
#endif
