#include "interface.h"

static int my_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	int flags = 0;
	int ret = 0, sensitive_ret = 0, safe_ret = 0;
	char *oldpath = NULL, *newpath = NULL;
	struct parent_info pinfo = {{{0}}};
	struct inode *inode = NULL;
	size_t size = 0;
	dev_t old_dev = 0;
	dev_t new_dev = 0;
	usb_dev_t usb_dev = {0};
	int op_type = OP_RENAME;
	int encrypt_ret = 0;

	/* rename的源和目的都不允许是sniper程序 */
	if (sniper_badptr(old_dir) || sniper_badptr(old_dentry) || sniper_badptr(new_dir)) {
		return 0;
	}
	inode = old_dentry->d_inode;
	if (sniper_badptr(inode)) {
		return 0;
	}
	if (is_sniper_inode(inode)) {
		myprintk("forbid %s(%d) move sniper routine\n", current->comm, current->pid);
		return -1;
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

	inode = old_dentry->d_inode;
	size = i_size_read(inode);

	/* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
                return 0;
        }

	if (new_dentry && skip_file(new_dentry->d_name.name)) {
		return 0;
	}

        oldpath = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_RENAMEOLDPATH);
        if (oldpath == NULL) {
                myprintk("rename: Out of memory!\n");
		goto out;
        }

	if (sniper_lookuppath(old_dir, old_dentry, oldpath, PATH_MAX, SNIPER_RENAME) < 0) {
                myprintk("rename: get oldpath failed!\n");
		goto out;
	}

	if (old_dir->i_sb && old_dir->i_sb->s_dev) {
		old_dev = old_dir->i_sb->s_dev;
		usb_dev.major = MAJOR(old_dev);
		usb_dev.minor = MINOR(old_dev);
	}

	newpath = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_RENAMENEWPATH);
        if (newpath == NULL) {
                myprintk("rename: Out of memory!\n");
		goto out;
        }

	if (sniper_lookuppath(new_dir, new_dentry, newpath, PATH_MAX, SNIPER_RENAME) < 0) {
                myprintk("rename: get newpath failed!\n");
		goto out;
	}

	if (new_dir->i_sb && new_dir->i_sb->s_dev) {
		new_dev = new_dir->i_sb->s_dev;
		usb_dev.new_major = MAJOR(new_dev);
		usb_dev.new_minor = MINOR(new_dev);
	}

	myfdebug2(SNIPER_RENAME, "%s(%d) rename %s -> %s\n", current->comm, current->pid, oldpath, newpath);

	/* vi操作的rename调用，当做是修改来处理*/
	if (check_vim_change(oldpath, newpath)) {
		op_type = OP_OPEN_W;
	}
	if (sniper_fpolicy.antivirus_on) {
		send_virus_file_msg(oldpath, newpath, &pinfo, op_type, inode);
	}
	check_black_file_after(oldpath, newpath, &pinfo, op_type, inode);

	/* 检查异常文件修改 */
	check_abnormal_change(oldpath, newpath, &pinfo, op_type, inode);

	/* 诱捕文件被修改后均需要通知用户层恢复 */
	encrypt_ret = check_encrypt(oldpath, newpath, &pinfo, op_type, inode);
	if (encrypt_ret < 0) {
		/* 返回值为-2时需要阻断 */
		if (encrypt_ret == -2) {
			ret = -1;
		}

		report_trap_file_change(oldpath, newpath, &pinfo, op_type, inode);
		goto out;
	}

	copy_file_backup(oldpath, size, &pinfo, op_type, inode);

	sensitive_ret = check_sensitive_file(oldpath, newpath, &pinfo, op_type, inode);
	check_log_delete(oldpath, newpath, &pinfo, op_type, inode);
	check_logcollector(oldpath, newpath, &pinfo, op_type, inode);
	check_usb_path(oldpath, newpath, &pinfo, op_type, inode, &usb_dev);
	check_middle_target(oldpath, newpath, &pinfo, op_type, inode);
	check_illegal_script(oldpath, newpath, &pinfo, op_type, inode);
	check_webshell_detect(oldpath, newpath, &pinfo, op_type, inode);
	safe_ret = check_safe(oldpath, newpath, &pinfo, op_type, inode);
	ret = safe_ret < 0 ? safe_ret : sensitive_ret;

out:
	if (oldpath) {
		sniper_kfree(oldpath, PATH_MAX, KMALLOC_RENAMEOLDPATH);
	}

	if (newpath) {
		sniper_kfree(newpath, PATH_MAX, KMALLOC_RENAMENEWPATH);
	}

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_RENAME]);

	ret = my_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_RENAME]);
		return ret;
	}

	if (original_inode_rename) {
		ret = original_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	}

        atomic_dec(&sniper_usage[SNIPER_RENAME]);

	return ret;
}
#else
int sniper_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_RENAME]);

	ret = my_inode_rename(old_dir, old_dentry, new_dir, new_dentry);

        atomic_dec(&sniper_usage[SNIPER_RENAME]);

	return ret;
}
#endif
