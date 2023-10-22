#include "interface.h"

static int my_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	int flags = 0;
	int ret = 0;
	char *pathname = NULL;
	struct parent_info pinfo = {{{0}}};
	struct inode *inode = NULL;
	usb_dev_t usb_dev = {0};
	dev_t dev = 0;

	/* link目的都不允许是sniper程序 */
	if (sniper_badptr(dir)) {
		return 0;
	}

	if (!sniper_badptr(new_dentry)) {
		inode = new_dentry->d_inode;
		if (!sniper_badptr(inode) && is_sniper_inode(inode)) {
			myprintk("forbid %s(%d) replace sniper routine\n", current->comm, current->pid);
			return -1;
		}
	}

	/* file thread not ready or monitor off */
	if (nl_file_pid == 0 || !sniper_fpolicy.file_engine_on || sniper_file_loadoff) {
		return 0;
	}

	inode = new_dentry->d_inode;

	/* 只管文件 */
	if (inode && !S_ISREG(inode->i_mode)) {
		return 0;
	}

	if (new_dentry && skip_file(new_dentry->d_name.name)) {
		return 0;
	}

	/* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
		return 0;
	}

	pathname = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_LINKPATH);
	if (pathname == NULL) {
		myprintk("link: Out of memory!\n");
		goto out;
	}

	if (sniper_lookuppath(dir, new_dentry, pathname, PATH_MAX, SNIPER_LINK) < 0) {
		myprintk("link: get newpath failed!\n");
		goto out;
	}

	if (strncmp(pathname, "/proc/", 6) == 0 || strncmp(pathname, "/sys/", 5) == 0) {
		goto out;
	}

	if (dir->i_sb && dir->i_sb->s_dev) {
		dev = dir->i_sb->s_dev;
		usb_dev.major = MAJOR(dev);
		usb_dev.minor = MINOR(dev);
	}

	myfdebug2(SNIPER_LINK, "%s(%d) link %s\n", current->comm, current->pid, pathname);

	if (sniper_fpolicy.antivirus_on) {
		send_virus_file_msg(pathname, NULL, &pinfo, OP_LINK, inode);
	}
	check_black_file_after(pathname, NULL, &pinfo, OP_LINK, inode);
	ret = check_open_write(pathname, &pinfo, OP_LINK, inode, &usb_dev);

out:
	if (pathname) {
		sniper_kfree(pathname, PATH_MAX, KMALLOC_LINKPATH);
	}

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_LINK]);

	ret = my_inode_link(old_dentry, dir, new_dentry);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_LINK]);
		return ret;
	}

	if (original_inode_link) {
		ret = original_inode_link(old_dentry, dir, new_dentry);
	}

        atomic_dec(&sniper_usage[SNIPER_LINK]);

	return ret;
}
#else
int sniper_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_LINK]);

	ret = my_inode_link(old_dentry, dir, new_dentry);

        atomic_dec(&sniper_usage[SNIPER_LINK]);

	return ret;
}
#endif
