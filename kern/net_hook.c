/*
 * get connect arguments
 */

#include "interface.h"

#include <linux/file.h>
#include <linux/fs_struct.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
#include <linux/fdtable.h>  //低版本无此文件，都包含在file.h里
#endif

#include <linux/slab.h> //for kmalloc/kfree

#include <linux/socket.h>
#include <net/inet_sock.h>

static void init_netreq(netreq_t *req, int type)
{
	if (!req) {
		return;
	}

	req->uid = currenteuid();
	req->pid = current->pid;
	strncpy(req->comm, current->comm, 16);
	req->proctime = get_process_time(current);
}

static int my_move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage)) {
printk("111 ulen %d. sizeof(struct sockaddr) %ld\n", ulen, sizeof(struct sockaddr_storage));
		return -EINVAL;
	}
	if (ulen == 0) {
printk("222\n");
		return 0;
	}
	if (copy_from_user(kaddr, uaddr, ulen)) {
printk("333\n");
		return -EFAULT;
	}
	return 1;
}

int hook_sys_connect(struct kprobe *p, struct pt_regs *regs)
{
	netreq_t *req = NULL;
	cpumask_t *oldmask = &current->cpus_allowed;
	struct parent_info pinfo = {{{0}}};
	int flags = 0;
	struct sockaddr_storage address_storage = {0};
	struct sockaddr *address = (struct sockaddr *)&address_storage;
	struct sockaddr_in *usin = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	int sockfd = regs->rdi;
	struct sockaddr __user *uservaddr = (struct sockaddr __user *)regs->rsi;
	int addrlen = regs->rdx;
#else
	int sockfd = regs->di;
	struct sockaddr __user *uservaddr = (struct sockaddr __user *)regs->si;
	int addrlen = regs->dx;
#endif

	/* network thread not ready or monitor off */
	if (nl_net_pid == 0 || !sniper_nrule.net_engine_on) {
//		return 0;
	}

        /* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
		return 0;
	}

	my_bind_cpu();

	if (my_move_addr_to_kernel(uservaddr, addrlen, address) <= 0) {
		//myprintk("hook connect fail: get address fail\n");
		my_unbind_cpu(oldmask);
		return 0;
	}

	if (address->sa_family != AF_INET && address->sa_family != AF_INET6) {
		//if (address->sa_family == AF_INET6) {
		//	myprintk("sa_family AF_INET6, skip this connect\n");
		//}
		my_unbind_cpu(oldmask);
		return 0;
	}
	usin = (struct sockaddr_in *)address;
	if (((unsigned char *)&usin->sin_addr.s_addr)[0] == 127) {
		return 0;
	}
if (address->sa_family == AF_INET6) {
	myprintk("sa_family AF_INET6\n");
}
printk("connect %u.%u.%u.%u:%u\n", myaddr2ip(usin->sin_addr.s_addr), ntohs(usin->sin_port));

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_SYSCONNECT);
	if (!req) {
		myprintk("hook connect fail: no memory!\n");
		my_unbind_cpu(oldmask);
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	init_netreq(req, Probe_connect);
	req->sockfd = sockfd;

	memcpy(&req->pinfo, &pinfo, sizeof(struct parent_info));

#if 0
	if (req->flags & PSR_FILTER) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_SYSCONNECT);
		my_unbind_cpu(oldmask);
		return 0;
	}
#endif

#if 0 //debug
	myprintk("%s(%d) exec %s(%s) in %s. argc %d. "
		 "uid %d/%d. loginuid %d. flags %#x. "
		 "tty %s, cron %#x, ip %s. "
		 "%s(%d) %s(%d) %s(%d)\n",
		 current->comm, current->pid,
		 cmd, args, cwd, req->argc,
		 req->uid, req->euid, loginuid(current),
		 req->flags, req->tty, req->flags&PSR_CRON, req->ip,
		 req->pinfo.task[0].comm, req->pinfo.task[0].pid,
		 req->pinfo.task[1].comm, req->pinfo.task[1].pid,
		 req->pinfo.task[2].comm, req->pinfo.task[2].pid);
#endif

	req->size = sizeof(netreq_t);
printk("==send_data_to_user\n");
	send_data_to_user((char *)req, req->size, nl_net_pid, Probe_connect);

	sniper_kfree(req, ARGS_LEN, KMALLOC_SYSCONNECT);
	my_unbind_cpu(oldmask);

	return 0;
}

static int connect_on = 0;
static struct kprobe connect_kp = {{0}};
static char *connect_symbolname = "sys_connect";

static int connect_ret_on = 0;
static struct kretprobe connect_kretp = {{{0}}};

void myprint_connection(int sockfd, int retval)
{
	int err = 0;
	struct socket *sock = NULL;
	struct inet_sock *inet = NULL;
	char testip[20] = {0};

	sock = sockfd_lookup(sockfd, &err);
	if (sock) {
		//inet = (struct inet_sock *)(sock->sk);
		inet = inet_sk(sock->sk);
		printk("%s(%d) socket type %d, stat %d. "
			"sk_family %d, sk_state %d, sk_reuse %d, sk_protocol %d, sk_type %d, sk_err %d. "
			"src %u.%u.%u.%u:%u, dst %u.%u.%u.%u:%u, retval %d\n",
			current->comm, current->pid,
			sock->type, sock->state,
			sock->sk->sk_family, sock->sk->sk_state, sock->sk->sk_reuse, sock->sk->sk_protocol, sock->sk->sk_type, sock->sk->sk_err,
			myaddr2ip(inet->saddr), ntohs(inet->sport),
			myaddr2ip(inet->daddr), ntohs(inet->dport), retval);

		sockfd_put(sock);

	//TODO verify里struct socket *sock->ops->shutdown(sock, how); 并返回-1
		snprintf(testip, 20, "%u.%u.%u.%u", myaddr2ip(inet->daddr));
		if (strcmp(testip, "192.168.207.133") == 0) {
			printk("111 close connection to %s\n", testip);
			sock->ops->shutdown(sock, SHUT_RDWR);
		} else if (strncmp(testip, "192.168", 7) != 0 &&
			   strncmp(testip, "127.", 4) != 0 &&
			   strcmp(testip, "180.169.86.227") != 0) {
			printk("222 close connection to %s\n", testip);
			sock->ops->shutdown(sock, SHUT_RDWR);
		}
	}
}

static int connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct parent_info pinfo = {{{0}}};
	int flags = 0;
	cpumask_t *oldmask = &current->cpus_allowed;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	int ret = regs->rax;
#else
	int ret = regs->ax;
#endif

	/* network thread not ready or monitor off */
	if (nl_net_pid == 0 || !sniper_nrule.net_engine_on) {
//		return 0;
	}

        /* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
		return 0;
	}

	my_bind_cpu();

if (strcmp(current->comm, "sniper") == 0)
printk("%s(%d) connect_ret_handler %d\n", current->comm, current->pid, ret);
	verify_connect_msg(ret);

	my_unbind_cpu(oldmask);

        return 0;
}

void net_hook_exit(void)
{
	if (connect_on) {
		unregister_kprobe(&connect_kp);
		connect_on = 0;
		myprintk("connect-engine off\n");
	}

	if (connect_ret_on) {
		unregister_kretprobe(&connect_kretp);
		connect_ret_on = 0;
		myprintk("connect-engine-callback off\n");
	}
}

int net_hook_init(void)
{
	int ret = 0;

	/* 先connect_ret_on，以免connect_on与connect_ret_on之间的connection无人处理 */
	if (!connect_ret_on) {
                memset(&connect_kretp, 0, sizeof(struct kretprobe));
                connect_kretp.kp.symbol_name = connect_symbolname;
                connect_kretp.kp.fault_handler = handler_fault;
                connect_kretp.handler = connect_ret_handler;
                connect_kretp.maxactive = 20;
                ret = register_kretprobe(&connect_kretp);
                if (ret < 0) {
			myprintk("connect-engine-callback fail : %d\n", ret);
                        goto out;
                }
                connect_ret_on = 1;

		myprintk("connect-engine-callback on\n");
	}

	if (!connect_on) {
		memset(&connect_kp, 0, sizeof(struct kprobe));
		connect_kp.symbol_name = connect_symbolname;
		connect_kp.pre_handler = hook_sys_connect;
		ret = register_kprobe(&connect_kp);
		if (ret < 0) {
			myprintk("connect-engine fail : %d\n", ret);
			goto out;
		}
		connect_on = 1;

		myprintk("connect-engine on\n");
	}

	return 0;

out:
	net_hook_exit();

	return -1;
}
