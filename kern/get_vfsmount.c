#include "interface.h"
#include "mount.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/namespace.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#endif

/* 解决centos5/6上mq_open死机的问题，忽略类型为mqueue的文件系统中的文件。顺便也排除proc和sysfs */
static int skip_fstype(struct super_block *sb)
{
	const char *name = NULL;

	if (sniper_badptr(sb) || sniper_badptr(sb->s_type) || sniper_badptr(sb->s_type->name)) {
		return 1;
	}

	name = sb->s_type->name;
	if (strcmp(name, "mqueue") == 0 || strcmp(name, "proc") == 0 || strcmp(name, "sysfs") == 0) {
		return 1;
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define sniper_mount_lock() spin_lock((spinlock_t *)mount_lock_addr)
#define sniper_mount_unlock() spin_unlock((spinlock_t *)mount_lock_addr)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
void sniper_mount_lock(void)
{
	void (*lock_func)(void) = (void *)vfsmount_lock_func_addr;
	lock_func();
}
void sniper_mount_unlock(void)
{
	void (*unlock_func)(void) = (void *)vfsmount_unlock_func_addr;
	unlock_func();
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && !defined(USE_MOUNT_LOCK)
#include <linux/lglock.h>
#define sniper_mount_lock() br_read_lock((struct lglock *)mount_lock_addr)
#define sniper_mount_unlock() br_read_unlock((struct lglock *)mount_lock_addr)

#else
#define sniper_mount_lock() read_seqlock_excl((seqlock_t *)mount_lock_addr)
#define sniper_mount_unlock() read_sequnlock_excl((seqlock_t *)mount_lock_addr)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
struct vfsmount *get_vfsmount(struct inode *inode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
        struct namespace *ns = current->namespace;
#else
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
#endif
        struct super_block *sb = inode->i_sb;
        struct vfsmount *vfsmnt = NULL;

	sniper_mount_lock();
        list_for_each_entry(vfsmnt, &ns->list, mnt_list) {
                if (vfsmnt->mnt_sb == sb) {
			sniper_mount_unlock();
                        return vfsmnt;
                }
        }
	sniper_mount_unlock();
        return NULL;
}

int sniper_lookuppath(struct inode *inode, struct dentry *dentry, char *buf, int buflen, int op)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
        struct namespace *ns = current->namespace;
#else
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
#endif
	struct super_block *sb = inode->i_sb;
	struct vfsmount *vfsmnt = NULL;
	char *mntstr = NULL;
	char tmp[64] = {0};
	char *name = (char *)dentry->d_name.name;
	int i = 0, nofile = 0, len = 0;

	if (skip_fstype(sb)) {
		return -1;
	}

	/* 取inode对应的vfsmount */
	sniper_mount_lock();
	list_for_each_entry(vfsmnt, &ns->list, mnt_list) {
                if (vfsmnt->mnt_sb == sb) {
			break;
		}
	}
	sniper_mount_unlock();

	if (!vfsmnt) { //没取到vfsmount，返回失败
		return -1;
	}

	/* 获取全路径名 */
	memset(buf, 0, buflen);
	if (sniper_getpath(dentry, vfsmnt, buf, buflen, &nofile) > 0) {
		if (nofile && op != SNIPER_CREATE) { //除了创建文件的情况，文件都应该存在
			myprintk("sniper_lookuppath: %s deleted, skip\n", buf);
			return -1;
		}

		if (strcmp(safebasename(buf), name) == 0) { //文件名应当一致
			return 0;
		}
	}

	/* 未取到全路径，或获取的全路径不对，再次遍历vfsmount */

	mntstr = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_LOOKUPPATH);
	if (mntstr == NULL) {
		return -1;
	}
	memset(mntstr, 0, PATH_MAX);
	snprintf(mntstr, PATH_MAX, "|%p|", vfsmnt);

	for (i = 0; i < 1000; i++) { //以防万一，避免无限循环
		vfsmnt = NULL;
		sniper_mount_lock();
        	list_for_each_entry(vfsmnt, &ns->list, mnt_list) {
                	if (vfsmnt->mnt_sb == sb) {
				snprintf(tmp, 64, "|%p|", vfsmnt);
				if (!strstr(mntstr, tmp)) { //忽略已经尝试过的vfsmount
					break;
				}
			}
		}
		sniper_mount_unlock();

		/* 没取到inode对应的vfsmount */
		if (!vfsmnt) {
			sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
			return -1;
		}

		nofile = 0;
		memset(buf, 0, buflen);
		if (sniper_getpath(dentry, vfsmnt, buf, buflen, &nofile) > 0) {
			if (nofile && op != SNIPER_CREATE) { //除了创建文件的情况，文件都应该存在
				myprintk("sniper_lookuppath: %s deleted, skip\n", buf);
				sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
				return -1;
			}

			if (strcmp(safebasename(buf), name) == 0) { //文件名应当一致
				sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
				return 0;
			}
		}

		/* 添加已经检查过的vfsmount */
		len = strlen(mntstr);
		snprintf(mntstr+len, PATH_MAX-len, "|%p|", vfsmnt);
	}

	myprintk("sniper_lookuppath: something wrong. loop %d\n", i);
	sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
	return -1;
}
#else
struct vfsmount *get_vfsmount(struct inode *inode)
{
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
	struct super_block *sb = inode->i_sb;
	struct mount *mnt = NULL;

	sniper_mount_lock();
	list_for_each_entry(mnt, &ns->list, mnt_list) {
		if (mnt->mnt.mnt_sb == sb) {
			sniper_mount_unlock();
			return &mnt->mnt;
		}
	}
	sniper_mount_unlock();
	return NULL;
}

/*
 * 返回0，成功；返回-1，失败
 *
 * suse系统上根盘会挂载在多个目录上，如
Filesystem              1K-blocks    Used Available Use% Mounted on
devtmpfs                  2003728     104   2003624   1% /dev
tmpfs                     4596260      84   4596176   1% /dev/shm
tmpfs                     2015596   76000   1939596   4% /run
tmpfs                     2015596       0   2015596   0% /sys/fs/cgroup
/dev/mapper/system-root  62914560 6030892  55309556  10% /
/dev/mapper/system-root  62914560 6030892  55309556  10% /.snapshots
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/tmp
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/lib/named
/dev/mapper/system-root  62914560 6030892  55309556  10% /srv
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/lib/libvirt/images
/dev/mapper/system-root  62914560 6030892  55309556  10% /boot/grub2/x86_64-efi
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/lib/mariadb
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/lib/pgsql
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/lib/mailman
/dev/mapper/system-root  62914560 6030892  55309556  10% /home
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/opt
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/lib/mysql
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/crash
/dev/mapper/system-root  62914560 6030892  55309556  10% /tmp
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/lib/machines
/dev/mapper/system-root  62914560 6030892  55309556  10% /opt
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/cache
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/log
/dev/mapper/system-root  62914560 6030892  55309556  10% /usr/local
/dev/mapper/system-root  62914560 6030892  55309556  10% /boot/grub2/i386-pc
/dev/mapper/system-root  62914560 6030892  55309556  10% /var/spool
tmpfs                      403120      24    403096   1% /run/user/0
 * 因此不能仅凭super_block一致，就认为是inode的vfsmnt，还要确认是否能正确解析出文件名
 * 注意，不能加着锁，获取全路径名，否则会死锁
 */
int sniper_lookuppath(struct inode *inode, struct dentry *dentry, char *buf, int buflen, int op)
{
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
	struct super_block *sb = inode->i_sb;
	struct mount *mnt = NULL;
	struct vfsmount *vfsmnt = NULL;
	char *mntstr = NULL;
	char tmp[64] = {0};
	char *name = (char *)dentry->d_name.name;
	int i = 0, nofile = 0, len = 0;

	if (skip_fstype(sb)) {
		return -1;
	}

	/* 取inode对应的vfsmount */
	sniper_mount_lock();
	list_for_each_entry(mnt, &ns->list, mnt_list) {
		if (mnt->mnt.mnt_sb == sb) {
			vfsmnt = &mnt->mnt;
			break;
		}
	}
	sniper_mount_unlock();

	if (!vfsmnt) { //没取到vfsmount，返回失败
		return -1;
	}

	/* 获取全路径名 */
	memset(buf, 0, buflen);
	if (sniper_getpath(dentry, vfsmnt, buf, buflen, &nofile) > 0) {
		if (nofile && op != SNIPER_CREATE && op != SNIPER_LINK) { //除了创建文件和硬链接的情况，文件都应该存在
			myprintk("sniper_lookuppath: %s deleted, skip\n", buf);
			return -1;
		}

		if (strcmp(safebasename(buf), name) == 0) { //文件名应当一致
			return 0;
		}
	}

	/* 未取到全路径，或获取的全路径不对，再次遍历vfsmount */

	mntstr = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_LOOKUPPATH);
	if (mntstr == NULL) {
		return -1;
	}
	memset(mntstr, 0, PATH_MAX);
	snprintf(mntstr, PATH_MAX, "|%p|", mnt);

	for (i = 0; i < 1000; i++) { //以防万一，避免无限循环
		vfsmnt = NULL;
		sniper_mount_lock();
		list_for_each_entry(mnt, &ns->list, mnt_list) {
			if (mnt->mnt.mnt_sb == sb) {
				snprintf(tmp, 64, "|%p|", mnt);
				if (!strstr(mntstr, tmp)) { //忽略已经尝试过的vfsmount
					vfsmnt = &mnt->mnt;
					break;
				}
			}
		}
		sniper_mount_unlock();

		/* 没取到inode对应的vfsmount */
		if (!vfsmnt) {
			sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
			return -1;
		}

		nofile = 0;
		memset(buf, 0, buflen);
		if (sniper_getpath(dentry, vfsmnt, buf, buflen, &nofile) > 0) {
			if (nofile && op != SNIPER_CREATE && op != SNIPER_LINK) { //除了创建文件和硬链接的情况，文件都应该存在
				myprintk("sniper_lookuppath: %s deleted, skip\n", buf);
				sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
				return -1;
			}

			if (strcmp(safebasename(buf), name) == 0) { //文件名应当一致
				sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
				return 0;
			}
		}

		/* 添加已经检查过的vfsmount */
		len = strlen(mntstr);
		snprintf(mntstr+len, PATH_MAX-len, "|%p|", mnt);
	}

	myprintk("sniper_lookuppath: something wrong. loop %d\n", i);
	sniper_kfree(mntstr, PATH_MAX, KMALLOC_LOOKUPPATH);
	return -1;
}
#endif
