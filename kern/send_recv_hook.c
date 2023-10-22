#include "interface.h"
#include <net/af_unix.h>

#ifdef CONFIG_SECURITY_NETWORK

/*
 * 修改socket inode的读写时间，用于辅助判断命令执行和文件访问是否为远程操作引发的
 * 不考虑sendmsg/recvmsg失败的情况，失败也表明有网络通信的意图
 */
static int my_send_recv(struct socket *sock, struct msghdr *msg, int send_recv)
{
	struct file *file = NULL;
	struct inode *inode = NULL;

	if (sniper_badptr(sock) || sniper_badptr(sock->sk)) {
		return 0;
	}

	if (sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6) {
		return 0; //目前只关注IP网络通信
	}

	file = sock->file;
	if (sniper_badptr(file) || sniper_badptr(file->f_dentry)) {
		return 0;
	}
	inode = file->f_dentry->d_inode;
	if (sniper_badptr(inode)) {
		return 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
	if (SNIPER_SENDMSG == send_recv) {
		inode->i_mtime = current_fs_time(inode->i_sb); //发送设置写时间
	} else {
		inode->i_atime = current_fs_time(inode->i_sb); //接收设置读时间
	}
#else
	if (SNIPER_SENDMSG == send_recv) {
		inode->i_mtime = current_time(inode); //发送设置写时间
	} else {
		inode->i_atime = current_time(inode); //接收设置读时间
	}
#endif

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_SENDMSG]);

	ret = my_send_recv(sock, msg, SNIPER_SENDMSG);
	if (ret < 0) {
		atomic_dec(&sniper_usage[SNIPER_SENDMSG]);
		return ret;
	}

	if (original_socket_sendmsg) {
		ret = original_socket_sendmsg(sock, msg, size);
	}

	atomic_dec(&sniper_usage[SNIPER_SENDMSG]);

	return ret;
}
int sniper_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_RECVMSG]);

	ret = my_send_recv(sock, msg, SNIPER_RECVMSG);
	if (ret < 0) {
		atomic_dec(&sniper_usage[SNIPER_RECVMSG]);
		return ret;
	}

	if (original_socket_recvmsg) {
		ret = original_socket_recvmsg(sock, msg, size, flags);
	}

	atomic_dec(&sniper_usage[SNIPER_RECVMSG]);

	return ret;
}
#else
int sniper_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_SENDMSG]);

	ret = my_send_recv(sock, msg, SNIPER_SENDMSG);

	atomic_dec(&sniper_usage[SNIPER_SENDMSG]);

	return ret;
}
int sniper_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_RECVMSG]);

	ret = my_send_recv(sock, msg, SNIPER_RECVMSG);

	atomic_dec(&sniper_usage[SNIPER_RECVMSG]);

	return ret;
}
#endif

#endif
