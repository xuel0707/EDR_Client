#include "interface.h"

#ifdef CONFIG_SECURITY_NETWORK

static int my_socket_listen(struct socket *sock)
{
	int i = 0, freei = -1, found = 0;
	struct inet_sock *inet = NULL;
	unsigned short port = 0;
	struct file *exe_file = NULL;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	struct sniper_middleware *mid = NULL;
	unsigned long ino = 0;
	char *comm = current->comm;
	pid_t pid = current->pid; 

	if (sniper_badptr(sock) || sniper_badptr(sock->sk)) {
		return 0;
	}
	if (sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6) {
		return 0; //目前只关注IP网络通信
	}

	inet = (struct inet_sock *)(sock->sk);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	port = ntohs(inet->inet_sport);
#else
	port = ntohs(inet->sport);
#endif

	if (sniper_badptr(sniper_pmiddleware)) {
		myndebug2(NDEBUG_LISTEN, "null sniper_pmiddleware, "
				"%s(%d) listen %d not recorded\n",
				current->comm, current->pid, port);
		return 0;
	}

	/* 取进程程序名，防止进程改名后再做LISTEN */
	exe_file = my_get_mm_exe_file(current->mm); //用完要put
	if (sniper_badptr(exe_file)) {
		myprintk("%s(%d)[listen %d] bad exe_file(%p)\n",
			comm, pid, port, exe_file);
	} else {
		dentry = exe_file->f_dentry;
		if (sniper_badptr(dentry)) {
			myprintk("%s(%d)[listen %d] bad exe_file dentry(%p)\n",
				comm, pid, port, dentry);
		} else {
			comm = (char *)dentry->d_name.name;
		}
	}

	/*
	 * listen之前如果没做bind，则此处sport为0，listen过程中会分配一个端口
	 * 以nc为例，
	 * nc -l -p 1234，指定监听端口，则系统调用过程是socket、bind、listen
	 * nc -l，      不指定监听端口，则系统调用过程是socket、listen
	 *
	 * 由用户层sniper程序填写真正的端口号
	 */

	/* 取socket的inode号 */
	if (sniper_badptr(sock->file)) {
		myprintk("%s(%d)[listen %d] bad socket file(%p)\n",
			comm, pid, port, sock->file);
	} else {
		dentry = sock->file->f_dentry;
		if (sniper_badptr(dentry)) {
			myprintk("%s(%d)[listen %d] bad socket dentry(%p)\n",
				comm, pid, port, dentry);
		} else {
			inode = dentry->d_inode;
			if (sniper_badptr(inode)) {
				myprintk("%s(%d)[listen %d] bad socket inode(%p)\n",
					comm, pid, port, inode);
			} else {
				ino = inode->i_ino;
			}
		}
	}

	myndebug2(NDEBUG_LISTEN, "%s(%d) listen %d, inode %lu\n", comm, pid, port, ino);

	/* 网络引擎会在软中断中加读锁，因此这里加写锁时禁止软中断，避免死锁 */
	write_lock_bh(&sniper_pmiddleware_lock);

	/* 插入新监听的端口记录 */
	mid = (struct sniper_middleware *)sniper_pmiddleware;
	for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++, mid++) {
		if (mid->pid == 0) {
			if (freei < 0) {
				freei = i;
			}
			continue;
		}

		if (mid->pid == current->pid && mid->port == port && mid->ino == ino) {
			found = 1;
			break;
		}
	}
	if (!found) {
		if (freei < 0) {
			myprintk("Error: too listen ports than %d, %s(%d)[listen %d] not recorded\n", 
				SNIPER_MIDDLEWARE_NUM, comm, pid, port);
		} else {
			mid = (struct sniper_middleware *)sniper_pmiddleware;
			mid[freei].pid  = current->pid;
			mid[freei].port = port;
			mid[freei].ino  = ino;
			mid[freei].fd   = -1;
			memset(mid[freei].name, 0, S_COMMLEN);
			strncpy(mid[freei].name, comm, S_COMMLEN-1);

			sniper_pmiddleware_ver++;
			sniper_pmiddleware_count++;
		}
	}


	write_unlock_bh(&sniper_pmiddleware_lock);

	if (!sniper_badptr(exe_file)) {
		fput(exe_file); //前面get了，用完要put
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_socket_listen(struct socket *sock, int backlog)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_LISTEN]);

	ret = my_socket_listen(sock);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_LISTEN]);
		return ret;
	}

	if (original_socket_listen) {
		ret = original_socket_listen(sock, backlog);
	}

        atomic_dec(&sniper_usage[SNIPER_LISTEN]);

	return ret;
}
#else
int sniper_socket_listen(struct socket *sock, int backlog)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_LISTEN]);

	ret = my_socket_listen(sock);

        atomic_dec(&sniper_usage[SNIPER_LISTEN]);

	return ret;
}
#endif

#endif
