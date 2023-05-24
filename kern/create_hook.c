#include "interface.h"

static int my_inode_create(struct inode *dir, struct dentry *dentry, sniper_mode_t mode)
{
	char *pathname = NULL;
	int flags = 0;
	struct parent_info pinfo = {{{0}}};
	struct inode *inode = NULL;
	int ret = 0;
	usb_dev_t usb_dev = {0};
	dev_t dev = 0;

	/* file thread not ready or monitor off */
	if (nl_file_pid == 0 || !sniper_fpolicy.file_engine_on || sniper_file_loadoff) {
		return 0;
	}

	inode = dentry->d_inode;
	/* 只管文件 */
	if (inode && !S_ISREG(inode->i_mode)) {
                return 0;
       	}

	if (skip_file(dentry->d_name.name)) {
                return 0;
       	}

        /* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
                return 0;
        }

	pathname = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_CREATEPATH);
	if (pathname == NULL) {
		myprintk("open: Out of memory!\n");
		return 0;
	}

	if (sniper_lookuppath(dir, dentry, pathname, PATH_MAX, SNIPER_CREATE) < 0) {
		goto out;
	}

	if (strncmp(pathname, "/proc/", 6) == 0 || strncmp(pathname, "/sys/", 5) == 0) {
		goto out;
	}

	myfdebug2(SNIPER_CREATE, "%s(%d) create %s\n", current->comm, current->pid, pathname);

	if (dir->i_sb && dir->i_sb->s_dev) {
		dev = dir->i_sb->s_dev;
		usb_dev.major = MAJOR(dev);
		usb_dev.minor = MINOR(dev);
	}

	if (sniper_fpolicy.antivirus_on) {
		send_virus_file_msg(pathname, NULL, &pinfo, OP_OPEN_C, inode);
	}
	check_black_file_after(pathname, NULL, &pinfo, OP_OPEN_C, inode);
	ret = check_open_write(pathname, &pinfo, OP_OPEN_C, inode, &usb_dev);

out:
	if (pathname) {
		sniper_kfree(pathname, PATH_MAX, KMALLOC_CREATEPATH);
	}
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_inode_create(struct inode *dir, struct dentry *dentry, sniper_mode_t mode)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_OPEN]);

	ret = my_inode_create(dir, dentry, mode);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_OPEN]);
		return ret;
	}

	if (original_inode_create) {
		ret = original_inode_create(dir, dentry, mode);
	}

        atomic_dec(&sniper_usage[SNIPER_OPEN]);

	return ret;
}
#else
int sniper_inode_create(struct inode *dir, struct dentry *dentry, sniper_mode_t mode)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_OPEN]);

	ret = my_inode_create(dir, dentry, mode);

        atomic_dec(&sniper_usage[SNIPER_OPEN]);

	return ret;
}
#endif
