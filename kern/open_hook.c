#include "interface.h"

/* 移植的原close hook */
int check_open_write(char *pathname, struct parent_info *pinfo, int op_type, struct inode *inode, struct _usb_dev *dev)
{
	int ret = 0, sensitive_ret = 0, safe_ret = 0;

	if (skip_file(safebasename(pathname))) {
		return 0;
	}

	check_abnormal_change(pathname, NULL, pinfo, op_type, inode);
	check_logcollector(pathname, NULL, pinfo, op_type, inode);
	check_usb_path(pathname, NULL, pinfo, op_type, inode, dev);
	check_middle_target(pathname, NULL, pinfo, op_type, inode);
	check_illegal_script(pathname, NULL, pinfo, op_type, inode);
	check_webshell_detect(pathname, NULL, pinfo, op_type, inode);
	sensitive_ret = check_sensitive_file(pathname, NULL, pinfo, op_type, inode);
	safe_ret = check_safe(pathname, NULL, pinfo, op_type, inode);
	ret = safe_ret < 0 ? safe_ret : sensitive_ret;

	return ret;
}

/*
 * 检查是否任意用户可访问此文件。任意人可访问的文件，用不着检查是否被提权访问
 * 返回值：0，no；1，yes
 * 参数：mask，访问文件的方式：读、写
 *       mode，文件的访问权限设置
 */
static int anyone_can_access_file(int mask, int mode)
{
	if (mask & MAY_READ) {
		if (!(mode & S_IROTH)) { //不允许其他用户读
			return 0;
		}
	}
	if (mask & (MAY_WRITE|MAY_APPEND)) {
		if (!(mode & S_IWOTH)) { //不允许其他用户写
			return 0;
		}
	}
	return 1;
}

static int my_inode_permission(struct inode *inode, int mask)
{
	int flags = 0, ret = 0;
	char *pathname = NULL;
	struct parent_info pinfo = {{{0}}};
	struct dentry *dentry = NULL;
	size_t size = 0, size_mb = 0;
	usb_dev_t usb_dev = {0};
	dev_t dev = 0;
	int encrypt_ret = 0;

	/*
	 * 忽略所有的access行为
	 * 如删除文件时，unlink之前会先调用faccessat(AT_FDCWD, filename, W_OK)
	 * 又如文件管理器打开目录时，也会调用faccessat检查目录下的每个文件是否可写
	 */
	/* 2.6.27版本以下没有MAY_ACCESS宏定义 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	if (mask & MAY_ACCESS) {
		return 0;
	}
#endif

	if (sniper_badptr(inode)) {
                return 0;
	}

	if (mask & MAY_WRITE && is_sniper_inode(inode)) {
		myprintk("forbid %s(%d) modify sniper routine\n", current->comm, current->pid);
                return -1;
	}

	if (nl_file_pid == 0 || !sniper_fpolicy.file_engine_on || sniper_file_loadoff) {
                return 0;
	}

	/* 只管文件 */
	if (!S_ISREG(inode->i_mode)) {
                return 0;
       	}

        /* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
                return 0;
        }

	dentry = d_find_alias(inode);
	if (!dentry) {
		return 0;
	}

	pathname = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_OPENPATH);
	if (pathname == NULL) {
		myprintk("open: Out of memory!\n");
		goto out;
	}

	if (sniper_lookuppath(inode, dentry, pathname, PATH_MAX, SNIPER_OPEN) < 0) {
		goto out;
	}

	/* 忽略/proc和/sys下的伪文件 */
	if (strncmp(pathname, "/proc/", 6) == 0 || strncmp(pathname, "/sys/", 5) == 0) {
		goto out;
	}

	/* 仅针对不可随意访问的文件，检查是否被提权访问 */
	if (anyone_can_access_file(mask, inode->i_mode) == 0) {
		if (check_privup(&pinfo, PRIVUP_FILE, pathname) == PRIVUP_STOP) {
			myprintk("forbid privup-process %s(%d) access %s\n", current->comm, current->pid, pathname);
			ret = -1;
			goto out;
		}
	}

#if 0
	if (check_loop_open(inode) == 1) {
		goto out;
	}
#endif

	if (inode->i_sb && inode->i_sb->s_dev) {
		dev = inode->i_sb->s_dev;
		usb_dev.major = MAJOR(dev);
		usb_dev.minor = MINOR(dev);
	}

	if (mask & (MAY_WRITE|MAY_APPEND)) {
		if (sniper_fpolicy.antivirus_on) {
			send_virus_file_msg(pathname, NULL, &pinfo, OP_OPEN_W, inode);
		}
		check_black_file_after(pathname, NULL, &pinfo, OP_OPEN_W, inode);

		myfdebug2(SNIPER_OPEN, "%s(%d) open write %s(%ld)\n",
			current->comm, current->pid, pathname, (size_t)i_size_read(inode));
		size = i_size_read(inode);
		if (file_debug == 20) {
			size_mb = size / MB_SIZE;
			if (size_mb >= filesize_threshold) {
				myprintk("%s(%d) open write largefile %s(%ldM)\n",
					 current->comm, current->pid, pathname, size_mb);
			}
		}

		/* 诱捕文件被修改后均需要通知用户层恢复 */
		encrypt_ret = check_encrypt(pathname, NULL, &pinfo, OP_OPEN_W, inode);
		if (encrypt_ret < 0) {
			/* 返回值为-2时需要阻断 */
			if (encrypt_ret == -2) {
				ret = -1;
			}
			report_trap_file_change(pathname, NULL, &pinfo, OP_OPEN_W, inode);
			goto out;
		}
	
		copy_file_backup(pathname, size, &pinfo, OP_OPEN_W, inode);

		ret = check_open_write(pathname, &pinfo, OP_OPEN_W, inode, &usb_dev);
	} else {
		check_black_file_after(pathname, NULL, &pinfo, OP_OPEN, inode);
	}

out:
	if (pathname) {
		sniper_kfree(pathname, PATH_MAX, KMALLOC_OPENPATH);
	}
	dput(dentry);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
int sniper_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) && LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
int sniper_inode_permission(struct inode *inode, int mask, unsigned flags)
#else
int sniper_inode_permission(struct inode *inode, int mask)
#endif
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_OPEN]);

	ret = my_inode_permission(inode, mask);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_OPEN]);
		return ret;
	}

	if (original_inode_permission) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		ret = original_inode_permission(inode, mask, nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) && LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
		ret = original_inode_permission(inode, mask, flags);
#else
		ret = original_inode_permission(inode, mask);
#endif
	}

        atomic_dec(&sniper_usage[SNIPER_OPEN]);

	return ret;
}
#else
int sniper_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_OPEN]);

	ret = my_inode_permission(inode, mask);

        atomic_dec(&sniper_usage[SNIPER_OPEN]);

	return ret;
}
#endif
