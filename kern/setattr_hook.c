#include "interface.h"

/* 禁止改变sniper程序的属性，如取消可执行权限，改变属主等 */
static int my_inode_setattr(struct dentry *dentry)
{
	struct inode *inode = NULL;

	if (sniper_badptr(dentry)) {
		return 0;
	}
	inode = dentry->d_inode;
	if (sniper_badptr(inode)) {
		return 0;
	}
	if (is_sniper_inode(inode)) {
		myprintk("forbid %s(%d) change sniper attribute\n", current->comm, current->pid);
		return -1;
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_SETATTR]);

	ret = my_inode_setattr(dentry);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_SETATTR]);
		return ret;
	}

	if (original_inode_setattr) {
		ret = original_inode_setattr(dentry, attr);
	}

        atomic_dec(&sniper_usage[SNIPER_SETATTR]);

	return ret;
}
#else
int sniper_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_SETATTR]);

	ret = my_inode_setattr(dentry);

        atomic_dec(&sniper_usage[SNIPER_SETATTR]);

	return ret;
}
#endif
