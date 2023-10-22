#include "interface.h"

/*
 * lsm1.0在一些操作中设置了安全检查点，如execve中的bprm_check_security，
 * 安装检查函数可以有多种具体实现，如selinux、apparmor，但主机运行时只能设置一种实现方法生效，
 * 比如采用selinux的方法，那么所有安全检查点都采用selinux安全操作集(security_operations)里对应的函数来做检查，
 * 比如execve使用selinux_bprm_check_security()
 *
 * lsm1.0的钩子方法，是替换当前安全操作集中的函数指针，使调用sniper的对应的安全检查函数
 *
 *
 * lsm2.0是堆栈式实现，允许多种安全检查方法同时生效，安全检查点进行一系列的检查，所有检查方法都通过，才算通过
 * 同类检查函数以链表的形式串起来，lsm2.0的钩子方法，是将sniper的安全检查函数，插入同类检查函数链表的头部
 *
 */

/* lsm1.0钩子方法 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
static struct security_operations *current_security_ops = NULL;

/* execve */
int (*original_bprm_check_security)(struct linux_binprm *brpm);

/* kill */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
int (*original_task_kill)(struct task_struct *p, struct siginfo *info, int sig);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
int (*original_task_kill)(struct task_struct *p, struct siginfo *info, int sig, u32 secid);
#else
int (*original_task_kill)(struct task_struct *p, sniper_siginfo_t *info, int sig, const struct cred *cred);
#endif

/* open */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
int (*original_inode_permission)(struct inode *inode, int mask, struct nameidata *nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) && LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
int (*original_inode_permission)(struct inode *inode, int mask, unsigned flags);
#else
int (*original_inode_permission)(struct inode *inode, int mask);
#endif

/* create */
int (*original_inode_create)(struct inode *dir, struct dentry *dentry, sniper_mode_t mode);

/* rename */
int (*original_inode_rename)(struct inode *old_dir, struct dentry *old_dentry,
                             struct inode *new_dir, struct dentry *new_dentry);

/* link */
int (*original_inode_link)(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);

/* unlink */
int (*original_inode_unlink)(struct inode *dir, struct dentry *dentry);

/* symlink */
int (*original_inode_symlink)(struct inode *dir, struct dentry *dentry, const char *old_name);

/* read, write */
int (*original_file_permission)(struct file *file, int mask);

/* ioctl */
int (*original_file_ioctl)(struct file *file, unsigned int cmd, unsigned long arg);

/* setattr */
int (*original_inode_setattr)(struct dentry *dentry, struct iattr *attr);

/* sendmsg, recvmsg */
#ifdef CONFIG_SECURITY_NETWORK
int (*original_socket_sendmsg)(struct socket *sock, struct msghdr *msg, int size);
int (*original_socket_recvmsg)(struct socket *sock, struct msghdr *msg, int size, int flags);
int (*original_socket_listen)(struct socket *sock, int backlog);
#endif


#define SNIPER_ADD_HOOK(HOOK)  \
	original_##HOOK = current_security_ops->HOOK; \
	current_security_ops->HOOK = sniper_##HOOK

#define SNIPER_DEL_HOOK(HOOK)  current_security_ops->HOOK = original_##HOOK

static int security_add_sniper_hooks(void)
{
	unsigned long *security_ops = NULL;

	if (security_ops_addr == 0) {
		return -1;
	}

	/* 获取当前安全操作集的指针地址 */
	security_ops = (unsigned long *)security_ops_addr;
	current_security_ops = (struct security_operations *)*security_ops;
	if (!current_security_ops) {
		return -1;
	}

	/* 插入钩子，用钩子函数替代安全操作集中的函数，在钩子函数中调用原来的函数 */
	SNIPER_ADD_HOOK(bprm_check_security);  //execve
// 	SNIPER_ADD_HOOK(task_kill);
// 	SNIPER_ADD_HOOK(inode_permission);     //open
// 	SNIPER_ADD_HOOK(inode_create);
// 	SNIPER_ADD_HOOK(inode_rename);
// 	SNIPER_ADD_HOOK(inode_link);
// 	SNIPER_ADD_HOOK(inode_unlink);
// 	SNIPER_ADD_HOOK(file_permission);      //read, write
// 	SNIPER_ADD_HOOK(file_ioctl);
// 	SNIPER_ADD_HOOK(inode_setattr);        //chmod, chown
// #ifdef CONFIG_SECURITY_NETWORK
// 	SNIPER_ADD_HOOK(socket_sendmsg);
// 	SNIPER_ADD_HOOK(socket_recvmsg);
// 	SNIPER_ADD_HOOK(socket_listen);
// #endif

	return 0;
}

static int security_del_sniper_hooks(void)
{
	if (!current_security_ops) {
		return -1;
	}

	/* 移除钩子，恢复调用原来的函数 */
	SNIPER_DEL_HOOK(bprm_check_security);  //execve
// 	SNIPER_DEL_HOOK(task_kill);
// 	SNIPER_DEL_HOOK(inode_permission);     //open
// 	SNIPER_DEL_HOOK(inode_create);
// 	SNIPER_DEL_HOOK(inode_rename);
// 	SNIPER_DEL_HOOK(inode_link);
// 	SNIPER_DEL_HOOK(inode_unlink);
// 	SNIPER_DEL_HOOK(file_permission);      //read, write
// 	SNIPER_DEL_HOOK(file_ioctl);
// 	SNIPER_DEL_HOOK(inode_setattr);        //chmod, chown
// #ifdef CONFIG_SECURITY_NETWORK
// 	SNIPER_DEL_HOOK(socket_sendmsg);
// 	SNIPER_DEL_HOOK(socket_recvmsg);
// 	SNIPER_DEL_HOOK(socket_listen);
// #endif

	return 0;
}

#else

/* lsm2.0钩子方法 */
#include <linux/lsm_hooks.h>
#define SNIPER_HOOK_INIT(HEAD)  { .hook = { .HEAD = sniper_##HEAD } }
static struct security_hook_list sniper_hooks[] = {
	SNIPER_HOOK_INIT(bprm_check_security),  //execve
// 	SNIPER_HOOK_INIT(task_kill),
// 	SNIPER_HOOK_INIT(inode_permission),     //open
// 	SNIPER_HOOK_INIT(inode_create),
// 	SNIPER_HOOK_INIT(inode_rename),
// 	SNIPER_HOOK_INIT(inode_link),
// 	SNIPER_HOOK_INIT(inode_unlink),
// 	SNIPER_HOOK_INIT(file_permission),      //read, write
// 	SNIPER_HOOK_INIT(file_ioctl),
// 	SNIPER_HOOK_INIT(inode_setattr),        //chmod, chown
// #ifdef CONFIG_SECURITY_NETWORK
// 	SNIPER_HOOK_INIT(socket_sendmsg),
// 	SNIPER_HOOK_INIT(socket_recvmsg),
// 	SNIPER_HOOK_INIT(socket_listen),
// #endif
};

static int security_add_sniper_hooks(void)
{
	int i = 0;
	struct security_hook_heads *my_security_hook_heads = NULL;

	/* 取安全操作集链表头的指针地址 */
	if (security_hook_heads_addr == 0) {
		return -1;
	}
	my_security_hook_heads = (struct security_hook_heads *)security_hook_heads_addr;

	/* 取钩子函数同类操作链表的表头 */
	sniper_hooks[SNIPER_EXECVE].head     = &my_security_hook_heads->bprm_check_security;
// 	sniper_hooks[SNIPER_KILL].head       = &my_security_hook_heads->task_kill;
// 	sniper_hooks[SNIPER_OPEN].head       = &my_security_hook_heads->inode_permission;
// 	sniper_hooks[SNIPER_CREATE].head     = &my_security_hook_heads->inode_create;
// 	sniper_hooks[SNIPER_RENAME].head     = &my_security_hook_heads->inode_rename;
// 	sniper_hooks[SNIPER_LINK].head       = &my_security_hook_heads->inode_link;
// 	sniper_hooks[SNIPER_UNLINK].head     = &my_security_hook_heads->inode_unlink;
// 	sniper_hooks[SNIPER_WRITE].head      = &my_security_hook_heads->file_permission;
// 	sniper_hooks[SNIPER_IOCTL].head      = &my_security_hook_heads->file_ioctl;
// 	sniper_hooks[SNIPER_SETATTR].head    = &my_security_hook_heads->inode_setattr;
// #ifdef CONFIG_SECURITY_NETWORK
// 	sniper_hooks[SNIPER_SENDMSG].head    = &my_security_hook_heads->socket_sendmsg;
// 	sniper_hooks[SNIPER_RECVMSG].head    = &my_security_hook_heads->socket_recvmsg;
// 	sniper_hooks[SNIPER_LISTEN].head     = &my_security_hook_heads->socket_listen;
// #endif

	disable_memory_write_protection();

	/* 把钩子函数插在同类操作链表的表头 */
	for (i = 0; i < SNIPER_HOOKS_NUM; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
		INIT_LIST_HEAD(&sniper_hooks[i].list);
		list_add_rcu(&sniper_hooks[i].list, sniper_hooks[i].head);
#else
		INIT_HLIST_NODE(&sniper_hooks[i].list);
		hlist_add_head_rcu(&sniper_hooks[i].list, sniper_hooks[i].head);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,10,0)
		sniper_hooks[i].lsm = "sniper";
		// sniper_hooks[i].lsmid->lsm = "sniper";
#endif
	}

	restore_memory_write_protection();

	return 0;
}

static int security_del_sniper_hooks(void)
{
	int i = 0;

	if (security_hook_heads_addr == 0) {
		return -1;
	}

	disable_memory_write_protection();

	/* 从链表中移除钩子 */
	for (i = 0; i < SNIPER_HOOKS_NUM; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
		list_del_rcu(&sniper_hooks[i].list);
#else
		hlist_del_rcu(&sniper_hooks[i].list);
#endif
	}

	restore_memory_write_protection();

	return 0;
}
#endif

static int lsm_hooks_on = 0;

int lsm_hooks_init(void)
{
        if (!lsm_hooks_on) {
		if (security_add_sniper_hooks() < 0) {
			return -1;
		}

        	lsm_hooks_on = 1;
        	myprintk("sniper security engine on\n");
	}

	return 0;
}

void lsm_hooks_exit(void)
{
        if (lsm_hooks_on) {
		security_del_sniper_hooks();
        	lsm_hooks_on = 0;
        	myprintk("sniper security engine off\n");
	}
}
