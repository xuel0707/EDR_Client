#include "interface.h"

static void report_modify_sniper(void)
{
	taskreq_t *req = NULL;

	req = init_taskreq(INIT_WITH_PINFO|INIT_WITH_CMD);
	if (NULL == req) {
		return;
	}

	req->flags |= PSR_KILLSNIPER;
	req->pflags.killsniper = 1;
	req->pflags.modifysniper = 1;

	if (is_filter_cmd(req, NULL)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;
	send_data_to_user((char *)req, req->size, nl_exec_pid, Probe_kill);

	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
}

extern struct sniper_inode sniper_inode;
int is_sniper_inode(struct inode *inode)
{
	unsigned int major = 0, minor = 0;

	if (sniper_pid && sniper_inode.ino == inode->i_ino) {
		if (!sniper_badptr(inode->i_sb)) {
			major = MAJOR(inode->i_sb->s_dev);
			minor = MINOR(inode->i_sb->s_dev);
		}
		if (sniper_inode.major == major && sniper_inode.minor == minor) {
			report_modify_sniper();
			return 1;
		}
	}
	return 0;
}

int isnum(char *str)
{
	char *ptr = str;

	if (!str) {
		return 0;
	}

	while (*ptr != 0) {
		if (*ptr >= '0' && *ptr <= '9') {
			return 0;
		}
		ptr++;
	}
	return 1;
}

static int my_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int flags = 0;
	int ret = 0, sensitive_ret = 0, safe_ret = 0, encrypt_ret = 0;
	char *pathname = NULL, *suffix = NULL;
	const char *name = NULL;
	struct inode *inode = NULL;
	struct parent_info pinfo = {{{0}}};
	size_t size = 0;
	usb_dev_t usb_dev = {0};
	dev_t dev = 0;

	if (sniper_badptr(dir) || sniper_badptr(dentry)) {
		return 0;
	}
	inode = dentry->d_inode;
	if (sniper_badptr(inode)) {
		return 0;
	}
	if (is_sniper_inode(inode)) {
		myprintk("forbid %s(%d) delete sniper routine\n", current->comm, current->pid);
		return -1;
	}

	/* file thread not ready or monitor off */
	if (nl_file_pid == 0 || !sniper_fpolicy.file_engine_on || sniper_file_loadoff) {
		return 0;
	}

	name = dentry->d_name.name;
	suffix = strrchr(name, '.');

	if (skip_file(name)) {
		return 0;
	}

	size = i_size_read(inode);
	if (S_ISREG(inode->i_mode) && size == 0) {
		/* 不监控删除0字节的文件。目前只过滤部分 */
		if (suffix) {
			if (strcmp(suffix, "lock") == 0) {
				return 0;
			}
			if (isnum(suffix) == 0) {
				return 0;
			}
		}
	}

	/* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
                return 0;
        }

        pathname = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_UNLINKPATH);
        if (pathname == NULL) {
                myprintk("unlink: Out of memory!\n");
		goto out;
        }

	if (sniper_lookuppath(dir, dentry, pathname, PATH_MAX, SNIPER_UNLINK) < 0) {
		/* 报错太多， 屏蔽 */
		goto out;
	}

	/* 忽略/proc和/sys下的伪文件 */
	if (strncmp(pathname, "/proc/", 6) == 0 || strncmp(pathname, "/sys/", 5) == 0) {
		goto out;
	}

	myfdebug2(SNIPER_UNLINK, "%s(%d) unlink %s\n", current->comm, current->pid, pathname);

	if (dir->i_sb && dir->i_sb->s_dev) {
		dev = dir->i_sb->s_dev;
		usb_dev.major = MAJOR(dev);
		usb_dev.minor = MINOR(dev);
	}

	check_black_file_after(pathname, NULL, &pinfo, OP_UNLINK, inode);

	/* 检查异常文件修改 */
	check_abnormal_change(pathname, NULL, &pinfo, OP_UNLINK, inode);

	/* 诱捕文件被修改后均需要通知用户层恢复 */
	encrypt_ret = check_encrypt(pathname, NULL, &pinfo, OP_UNLINK, inode);
	if (encrypt_ret < 0) {
		/* 返回值为-2时需要阻断 */
		if (encrypt_ret == -2) {
			ret = -1;
		}
		report_trap_file_change(pathname, NULL, &pinfo, OP_UNLINK, inode);
		goto out;
	}

/* 4.10及以上版本在vfs_unlink会执行vfs_lock(target)->down_write加写锁, 如果此时执行kernel_read，调用xfs_ilock会执行加读锁的动作, 导致死锁 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
	inode_unlock(inode);
#endif
	copy_file_backup(pathname, size, &pinfo, OP_UNLINK, inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
	inode_lock(inode);
#endif

	sensitive_ret = check_sensitive_file(pathname, NULL, &pinfo, OP_UNLINK, inode);
	check_log_delete(pathname, NULL, &pinfo, OP_UNLINK, inode);
	check_logcollector(pathname, NULL, &pinfo, OP_UNLINK, inode);
	check_usb_path(pathname, NULL, &pinfo, OP_UNLINK, inode, &usb_dev);
	safe_ret = check_safe(pathname, NULL, &pinfo, OP_UNLINK, inode);
	ret = safe_ret < 0 ? safe_ret : sensitive_ret;

out:
	if (pathname) {
		sniper_kfree(pathname, PATH_MAX, KMALLOC_UNLINKPATH);
	}

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_UNLINK]);

	ret = my_inode_unlink(dir, dentry);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_UNLINK]);
		return ret;
	}

	if (original_inode_unlink) {
		ret = original_inode_unlink(dir, dentry);
	}

        atomic_dec(&sniper_usage[SNIPER_UNLINK]);

	return ret;
}
#else
int sniper_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_UNLINK]);

	ret = my_inode_unlink(dir, dentry);

        atomic_dec(&sniper_usage[SNIPER_UNLINK]);

	return ret;
}
#endif
