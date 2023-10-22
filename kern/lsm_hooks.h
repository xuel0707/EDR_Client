#ifndef _LSM_HOOKS_H
#define _LSM_HOOKS_H

#include <linux/security.h>

enum {
	SNIPER_EXECVE = 0,
	SNIPER_HOOKS_NUM,
	SNIPER_KILL,
	SNIPER_OPEN,
	SNIPER_CREATE,
	SNIPER_RENAME,
	SNIPER_LINK,
	SNIPER_UNLINK,
	SNIPER_WRITE,
	SNIPER_IOCTL,
	SNIPER_SETATTR,
	SNIPER_SENDMSG,
	SNIPER_RECVMSG,
	SNIPER_LISTEN,
};
extern atomic_t sniper_usage[SNIPER_HOOKS_NUM];

extern int lsm_hooks_init(void);
extern void lsm_hooks_exit(void);


/* sniper钩子函数 */
/* execve */
extern int sniper_bprm_check_security(struct linux_binprm *bprm);

/* kill */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
extern int sniper_task_kill(struct task_struct *p, struct siginfo *info, int sig);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
extern int sniper_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid);
#else
extern int sniper_task_kill(struct task_struct *p, sniper_siginfo_t *info, int sig, const struct cred *cred);
#endif

/* open */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
extern int sniper_inode_permission(struct inode *inode, int mask, struct nameidata *nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) && LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
extern int sniper_inode_permission(struct inode *inode, int mask, unsigned flags);
#else
extern int sniper_inode_permission(struct inode *inode, int mask);
#endif

/* create */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
typedef int sniper_mode_t;
#else
typedef umode_t sniper_mode_t;
#endif
extern int sniper_inode_create(struct inode *dir, struct dentry *dentry, sniper_mode_t mode);

/* rename */
extern int sniper_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                               struct inode *new_dir, struct dentry *new_dentry);

/* link */
extern int sniper_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);

/* unlink */
extern int is_sniper_inode(struct inode *inode);
extern int sniper_inode_unlink(struct inode *dir, struct dentry *dentry);

/* symlink */
extern int sniper_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name);

/* write */
extern int sniper_file_permission(struct file *file, int mask);

/* ioctl */
extern int sniper_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* setattr */
extern int sniper_inode_setattr(struct dentry *dentry, struct iattr *attr);

/* sendmsg, recvmsg */
#ifdef CONFIG_SECURITY_NETWORK
extern int sniper_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);
extern int sniper_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags);
extern int sniper_socket_listen(struct socket *sock, int backlog);
#endif


/*
 * 被钩的原始函数
 * 和上面的钩子函数声明对应，把sniper_xxxx换成(*original_xxxx)即可
 */

/* execve */
extern int (*original_bprm_check_security)(struct linux_binprm *brpm);

/* kill */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
extern int (*original_task_kill)(struct task_struct *p, struct siginfo *info, int sig);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
extern int (*original_task_kill)(struct task_struct *p, struct siginfo *info, int sig, u32 secid);
#else
extern int (*original_task_kill)(struct task_struct *p, sniper_siginfo_t *info, int sig, const struct cred *cred);
#endif

/* open */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
extern int (*original_inode_permission)(struct inode *inode, int mask, struct nameidata *nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) && LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
extern int (*original_inode_permission)(struct inode *inode, int mask, unsigned flags);
#else
extern int (*original_inode_permission)(struct inode *inode, int mask);
#endif


/* create */
extern int (*original_inode_create)(struct inode *dir, struct dentry *dentry, sniper_mode_t mode);

/* rename */
extern int (*original_inode_rename)(struct inode *old_dir, struct dentry *old_dentry,
                                    struct inode *new_dir, struct dentry *new_dentry);

/* link */
extern int (*original_inode_link)(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);

/* unlink */
extern int (*original_inode_unlink)(struct inode *dir, struct dentry *dentry);

/* symlink */
extern int (*original_inode_symlink)(struct inode *dir, struct dentry *dentry, const char *old_name);

/* write */
extern int (*original_file_permission)(struct file *file, int mask);

/* ioctl */
extern int (*original_file_ioctl)(struct file *file, unsigned int cmd, unsigned long arg);

/* setattr */
extern int (*original_inode_setattr)(struct dentry *dentry, struct iattr *attr);

/* sendmsg, recvmsg */
#ifdef CONFIG_SECURITY_NETWORK
extern int (*original_socket_sendmsg)(struct socket *sock, struct msghdr *msg, int size);
extern int (*original_socket_recvmsg)(struct socket *sock, struct msghdr *msg, int size, int flags);
extern int (*original_socket_listen)(struct socket *sock, int backlog);
#endif

#endif
