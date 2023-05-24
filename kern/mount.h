#ifndef _SNIPER_MOUNT_H
#define _SNIPER_MOUNT_H

#include <linux/mount.h>

/* centos7.4-7.9移植了更高版本的内核代码，范围在3.13-3.18之间 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
#include <linux/ns_common.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
struct mnt_namespace {
        atomic_t                count;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
        struct ns_common        ns;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
        unsigned int            proc_inum;
#endif
        struct mount *  root;
        struct list_head        list;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mount {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) || defined(USE_MOUNT_LOCK)
	struct hlist_head mnt_hash;
#else
        struct list_head mnt_hash;
#endif
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
	/* union的大小和struct rcu_head一样大 */
        union {
                struct rcu_head mnt_rcu;
                struct llist_node mnt_llist;
        };
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) || defined(USE_MOUNT_LOCK)
        struct rcu_head mnt_rcu;
#endif
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,0)
	atomic_t mnt_longterm;		/* how many of the refs are longterm */
#endif
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
        /* 只用到mnt_list，下面的数据结构都用不着，保留几个用于对齐，也许没必要，但也没关系 */
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
};
#endif

#endif
