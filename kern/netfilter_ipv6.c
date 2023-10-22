#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/udp.h> 
#include <linux/tcp.h> 
#include <linux/icmp.h> 
#include <linux/netfilter_ipv6.h>
#include "interface.h"
#include "radix.h"

/* <--- for CentOS5 */
#include <linux/in.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
enum nf_inet_hooks {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS
};
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define skb_set_transport_header(skb, offset) do {} while(0)
#define ipv6_hdr(skb)  (skb)->nh.ipv6h
#define tcp_hdr(skb) (skb)->h.th;
#define udp_hdr(skb) (skb)->h.uh;
#define icmp_hdr(skb) (skb)->h.icmph;
#endif
/* for CentOS5 ---> */

static trie_node *conf_root = NULL;
static trie_node *dynamic_root = NULL;

/* 不阻断时，标志用来指示是否做后继的检查，及上报什么事件 */
#define SNIPER_SERVER_IP 1
#define SNIPER_BLACK_IP  2

static int is_internet_ipv6(struct sniper_ipv6 *ip);

/* 不检查本机内部的通信：1、源ip和目的ip相同；2、源ip是本地环回地址类型 */
static int skip_package(struct ipv6hdr *ipv6_header)
{
	/* 过滤 ::/128 空类型地址 */
	if (ipv6_addr_any(&ipv6_header->saddr) || ipv6_addr_any(&ipv6_header->daddr)) {
		return 1;
	}

	/* 过滤源地址和目的地址相等的报文 */
	if (ipv6_addr_equal(&ipv6_header->saddr, &ipv6_header->daddr)) {
		return 1;
	}

	/* 过滤环回地址报文 ::1/128 */
	if (sniper_ipv6_addr_loopback(&ipv6_header->saddr) ||
	    sniper_ipv6_addr_loopback(&ipv6_header->daddr)) {
		return 1;
	}

	return 0;
}
static void sniper_addr2ipv6(struct sniper_ipv6 *ipv6, unsigned char *addr)
{
	unsigned long *ul1 = (unsigned long *) addr;
	unsigned long *ul2 = (unsigned long *) ipv6;
	ul2[0] = ul1[0];
	ul2[1] = ul1[1];
}

static int is_same_ipv6(struct sniper_ipv6 *ip1, struct sniper_ipv6 *ip2)
{
	const unsigned long *ul1 = (const unsigned long *) ip1;
	const unsigned long *ul2 = (const unsigned long *) ip2;

	return ((ul1[0] ^ ul2[0]) | (ul1[1] ^ ul2[1])) == 0UL ? 1 : 0;
}

/* 网络引擎中不需要read_lock_bh()，占着读锁被中断，不会导致死锁，加写锁的地方才需要禁中断 */
static int is_server(unsigned short port, struct sniper_ipv6 *ip)
{
	int i = 0;
	struct sniper_server_ipv6 *server = NULL;

	read_lock(&sniper_nserver_lock);

	server = (struct sniper_server_ipv6 *)sniper_nserver;
	if (!server) {
		read_unlock(&sniper_nserver_lock);
		return 0;
	}

	for (i = 0; i < sniper_nserver_count; i++) {
		if (port == server[i].port && is_same_ipv6(ip, &server[i].ipv6)) {
			read_unlock(&sniper_nserver_lock);
			return 1;
		}
	}

	read_unlock(&sniper_nserver_lock);
	return 0;
}

static int is_portscan_flag(struct tcphdr *h)
{
	if (!h->syn && !h->rst && !h->psh && !h->ack && !h->urg) {
		if (h->fin) {
			//myprintk("fin scan\n");
		} else {
			//myprintk("null scan\n");
		}
		return 1;
	}

	if (!h->syn && !h->rst && !h->ack && h->fin && h->psh && h->urg) {
		//myprintk("xmas scan\n");
		return 1;
	}

	return 0;
}

static int is_honeyport(const unsigned short port)
{
	int i = 0;
	unsigned short *honeyport = NULL;

	read_lock(&sniper_nhoneyport_lock);

	honeyport = (unsigned short *)sniper_nhoneyport;
	if (!honeyport) {
		read_unlock(&sniper_nhoneyport_lock);
		return 0;
	}

	/* 是否为诱捕端口 */
	for (i = 0; i < sniper_nhoneyport_count; i++) {
		if (port != honeyport[i]) {
			continue;
		}

		read_unlock(&sniper_nhoneyport_lock);
		return 1;
	}

	read_unlock(&sniper_nhoneyport_lock);
	return 0;
}

static int is_internet_ipv6(struct sniper_ipv6 *ip)
{
    // |         n bits         |   m bits  |       128-n-m bits         |
    // +------------------------+-----------+----------------------------+
    // | global routing prefix  | subnet ID |       interface ID         |
    // +------------------------+-----------+----------------------------+
	/* 电信是240e开头的(240e::/20)
     * 移动是2409开头的(2409:8000::/20)
	 * 联通是2408开头的(2408:8000::/20)
	 */
	if (ip->ipv6[0] == 0x24 || (ip->ipv6[1] == 0x0e || ip->ipv6[1] == 0x08 || ip->ipv6[1] == 0x09)) {
		return 1;
	}
	// 目前已经分配的全球路由前缀的前3bit均为001
	if ((ip->ipv6[0] & (0<<8)) && (ip->ipv6[0] & (0<<7) && (ip->ipv6[0] & (1<<6)))) {
		return 1;
	}

	return 0;
}

static void report_netout_package(netreq_t *req,
				  struct sniper_ipv6 *srcip, unsigned short sport,
				  struct sniper_ipv6 *dstip, unsigned short dport,
				  struct ipv6hdr *ipv6_header, struct tcphdr *tcp_header,
				  char *desc)
{
	/* 对于连出，myip即srcip */
	req->flags.tcp = 1;
	req->flags.trust = 1;
	req->flags.terminate = 1;
	req->flags.locking = 1;
	req->srcipv6 = *srcip;
	req->sport = sport;
	req->dstipv6 = *dstip;
	req->dport = dport;
	sniper_do_gettimeofday(&req->event_tv);
	req->size = sizeof(netreq_t);

	send_msg_to_user((char *)req, req->size, nl_net_pid);
}

static void get_real_comm(char *comm)
{
	if (!strchr(current->comm, ' ')) {
		strncpy(comm, current->comm, S_COMMLEN-1);
		return;
	}

	/* 虽然进程名带了空格，但进程执行了命令，这个空格是命令名的空格 */
	if (!(current->flags & PF_FORKNOEXEC)) {
		strncpy(comm, current->comm, S_COMMLEN-1);
		return;
	}

	/* 如果与线程组长的名字不同，则用线程组长的名字 */
	if (strcmp(current->comm, current->group_leader->comm) != 0) {
		strncpy(comm, current->group_leader->comm, S_COMMLEN-1);
		return;
	}

	/* 如果与父进程的名字不同，则用父进程的名字 */
	if (strcmp(current->comm, current->parent->comm) != 0) {
		strncpy(comm, current->parent->comm, S_COMMLEN-1);
		return;
	}

	/* 父进程也是个线程，用父进程的线程组长的名字 */
	if (current->parent->pid != current->parent->tgid) {
		strncpy(comm, current->parent->group_leader->comm, S_COMMLEN-1);
		return;
	}

	/* 还是用自己的 */
	strncpy(comm, current->comm, S_COMMLEN-1);
}
static void print_package(struct sniper_ipv6 *srcip, unsigned short sport,
			  struct sniper_ipv6 *dstip, unsigned short dport,
			  struct ipv6hdr *ipv6_header, struct tcphdr *tcp_header,
			  char *desc)
{
	char comm[16] = {0};
	char commstr[64] = {0};

	if (!net_debug) {
		return;
	}

	if (!in_interrupt()) {
		get_real_comm(comm);
		snprintf(commstr, 64, "%s(%d)", comm, current->pid);
	}
	if (tcp_header) {
		printk("%s %s === %pI6c:%d -> %pI6c:%d, "
			"state fin%d/syn%d/rst%d/psh%d/ack%d/urg%d. "
			"payloadlen %d, TTL %d, Window %d\n",
			commstr, desc, (struct in6_addr*)&srcip, sport, (struct in6_addr*)&dstip, dport,
			tcp_header->fin, tcp_header->syn, tcp_header->rst, tcp_header->psh, 
			tcp_header->ack, tcp_header->urg, ipv6_header->payload_len, 
			ipv6_header->hop_limit, tcp_header->window);
	} else {
		printk("%s %s === %pI6c:%d -> %pI6c:%d\n",
			commstr, desc, (struct in6_addr*)&srcip, sport, (struct in6_addr*)&dstip, dport);
	}

}

static unsigned short csum(unsigned short *buf, int nwords)
{
        unsigned long sum;
        for (sum = 0; nwords > 0; nwords--) {
                sum += *buf++;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return ~sum;
}

/* 命中可信IP 返回 1，否则返回 0 */
static int is_trust_ipv6(const struct sniper_ipv6 *ipv6)
{
	int ret = 0;
	trie_node *result_node = NULL;

	if (ipv6 == NULL) {
		return 0;
	}

	read_lock(&sniper_ipv6_lock);
	if (sniper_nhoneyport_trustipv6_count) {
		result_node = search_nodes(conf_root, (char*)&ipv6);
		if (result_node) {
			ret = 1;
		}
	}
	read_lock(&sniper_ipv6_lock);

	return ret;
}

static int report_honeyport_portscan(const struct sniper_ipv6 *srcip, const unsigned short srcport,
							const struct sniper_ipv6 *dstip, const unsigned short dstport, const int type)
{
	netreq_t req = {0};

	if (srcip == NULL || dstip == NULL) {
		return -1;
	}
	req.flags.tcp = 1;
	req.flags.trust = is_trust_ipv6(srcip);
	req.flags.terminate = 1;
	if (type) {
		req.flags.honeyport = 1;
	} else {
		req.flags.portscan = 1;
	}
	req.flags.locking = 1;
	// req.proctime = get_process_time(current);
	// if (current->signal && current->signal->tty) {
	// 	req.flags.tty = 1;
	// }
	req.srcipv6 = *srcip;
	req.sport = srcport;
	req.dstipv6 = *dstip;
	req.dport = dstport;
	sniper_do_gettimeofday(&req.event_tv);
	req.size = sizeof(netreq_t);

	send_msg_to_user((char *)&req, req.size, nl_net_pid);

	return 0;
}

static int report_portscan(const struct sniper_ipv6 *srcip, const unsigned short srcport,
									const struct sniper_ipv6 *dstip, const unsigned short dstport,
									const pscan_t *data)
{
	netreq_t *req = NULL;
	int payload = 0;
	
	if (srcip == NULL || dstip == NULL || data == NULL) {
		return -1;
	}

	payload = data->portscan_max * sizeof(int);
	
	req = (netreq_t *)sniper_kmalloc(sizeof(netreq_t) + payload, GFP_ATOMIC, KMALLOC_PORTSCAN);
	if (!req) {
		myprintk("scan port malloc fail\n");
		report_honeyport_portscan(srcip, srcport, dstip, dstport, 0);
		return 1;
	}

	req->flags.tcp = 1;
	req->flags.trust = is_trust_ipv6(srcip);
	req->flags.terminate = 1;
	req->flags.locking = 1;
	req->flags.portscan = 1;
	req->repeat = data->ports_count;
	req->srcipv6 = *srcip;
	req->sport = srcport;
	req->dstipv6 = *dstip;
	req->dport = dstport;
	sniper_do_gettimeofday(&req->event_tv);
	req->size = sizeof(netreq_t) + payload;

	memcpy(req+1, data->ports, payload);
	send_msg_to_user((char *)req, req->size, nl_net_pid);

	sniper_kfree(req, sizeof(netreq_t) + payload, KMALLOC_PORTSCAN);

	return 0;
}

static int honey_port_match(trie_node *result_node, 
							const struct sniper_ipv6 *srcip, const unsigned short srcport,
							const struct sniper_ipv6 *dstip, const unsigned short dstport, 
							const struct kern_net_rules *nrule)
{
	time_t now = sniper_uptime();
	if (result_node->honeyport_locked && (now - result_node->honey_port_last_repor <= nrule->portscan_lock_time)) {
		/* 锁定时间内不重复上报 */
		return depend_current_mode(NF_DROP);
	}
	if (nrule->honeyport_reject && result_node->honey_port_conf) {
		if (nrule->honeyport_lockip) {
			/* 当前IPv6标记为锁定 */
			result_node->honeyport_locked = 1;
		}
		/* 发送敏感端口日志 */
		report_honeyport_portscan(srcip, srcport, dstip, dstport, 1);
		result_node->honey_port_last_repor = now;
	}
	/* 特殊扫描，命中敏感端口，锁定IPv6 */
	if (nrule->honeyport_lockip && result_node->honeyport_locked) {
		/* 用户空间判断发送防御日志 */
		return depend_current_mode(NF_DROP);
	}

	return NF_ACCEPT;
}

static int port_scan_match(trie_node *result_node,
							const struct sniper_ipv6 *srcip, const unsigned short srcport,
							const struct sniper_ipv6 *dstip, const unsigned short dstport, 
							const struct kern_net_rules *nrule)
{
	pscan_t *tmp = NULL;
	time_t now;

	if (!(nrule->portscan_lock_time && nrule->portscan_max)) {
		return NF_ACCEPT;
	}

	now = sniper_uptime();

	if (result_node->portscan_locked) { /* 当前IPv6为锁定的状态 */
		tmp = (pscan_t*)result_node->data;
		if (tmp && (now - tmp->first_time > tmp->portscan_lockip_time)) { 
			/* 当前IPv6解锁 */
			result_node->portscan_locked = 0;
			/* 因为配置可能发生变化，释放端口扫描的data数据 */
			if (result_node->data) {
				sniper_kfree(result_node->data, sizeof(trie_node), KMALLOC_CREATENODE);
				result_node->data = NULL;
			}

			return NF_ACCEPT;
		}

		return depend_current_mode(NF_DROP);
	}

	if (!result_node->data) {
		int size = sizeof(pscan_t)+sizeof(unsigned int)*(nrule->portscan_max+1);
		tmp = (pscan_t*)sniper_kmalloc(size, GFP_ATOMIC, KMALLOC_CREATENODE);
		if (!tmp) {
			myprintk("kmalloc port scan conf fail\n");
		} else {
			memset (tmp, 0x00, size);
			/* 锁定时间 */
			tmp->portscan_lockip_time = nrule->portscan_lock_time;
			/* 端口扫描超限数量 */
			tmp->portscan_max = nrule->portscan_max;
			tmp->effective_time = nrule->portscan_time;
			tmp->first_time = now;
			tmp->ports_count = 0;
			result_node->data = (void*)tmp;
		}
	} else {
		tmp = (pscan_t*)result_node->data;
	}

	if (now - tmp->first_time > tmp->effective_time) { /* 端口扫描时间到 */

		if (tmp->ports_count >= tmp->portscan_max) {
			/* 一但锁定，此时的first_time用作锁定计时的初始时间 */
			tmp->first_time = now;
			/* 当前IPv6标记为锁定 */
			result_node->portscan_locked = 1;
			/* 发送端口扫描日志 */
			report_portscan(srcip, srcport, dstip, dstport, tmp);

			return depend_current_mode(NF_DROP);
		} else { /* 扫描时间到，释放存储的端口数据，进入下一个周期 */
			// todo
			// 也可以把扫描的结果发送出去，对于APT式的扫描可以积累总的扫描端口数再做分析
			if (result_node->data) {
				sniper_kfree(result_node->data, sizeof(trie_node), KMALLOC_CREATENODE);
				result_node->data = NULL;
			}
			result_node->portscan_locked = 0;

			return NF_ACCEPT;
		}

	} else { /* 扫描端口时间未到 */

		if (tmp->ports_count >= tmp->portscan_max) { /* 扫描次数达到设置的最大，发送日志 */
			result_node->portscan_locked = 1;
			/* 一但锁定，此时的first_time用作锁定计时的初始时间 */
			tmp->first_time = now;
			/* 发送端口扫描日志 */
			report_portscan(srcip, srcport, dstip, dstport, tmp);

			return depend_current_mode(NF_DROP);
		} else { /* 更新端口 */
			int i = 0;
			for (; i < tmp->portscan_max; i++) {
				if (tmp->ports[i] == srcport) {
					break;
				} else {
					if (tmp->ports[i] == 0) {
						tmp->ports[i] = srcport;
					}
				}
			} /* end for */
			/* 重复扫描端口与扫描新的端口，两种情况累计 */
			++ tmp->ports_count;

			return NF_ACCEPT;
		}

	}

	return NF_ACCEPT;
}

static int match_dynamic_tree(const struct sniper_ipv6 *srcip, const unsigned short srcport,
							const struct sniper_ipv6 *dstip, const unsigned short dstport, 
							const int type, const struct kern_net_rules *nrule)
{
	trie_node *result_node = NULL;
	unsigned char ipv6_str[64];

	if (srcip == NULL || dstip == NULL || nrule == NULL) {
		return NF_ACCEPT;
	}

	if (!(nrule->honeyport_lockip || nrule->portscan_lock_time)) {
		return NF_ACCEPT;
	}

	snprintf(ipv6_str, sizeof(ipv6_str), "%pI6", (unsigned char*)srcip);

	result_node = search_nodes(dynamic_root, (unsigned char*)&ipv6_str);
	if (!result_node) { /* not found */
		result_node = insert(dynamic_root, (unsigned char*)&ipv6_str);
		if (!result_node) {
			myprintk("insert %pI6c fail\n", (unsigned char*)srcip);
			return NF_ACCEPT;
		}
		/* 默认敏感端口和端口扫描都置为有效,后面会再根据nrule中的配置做判断是否需要锁定IPv6 */
		result_node->scan_port = 1;
		result_node->honey_port_conf = 1;
	}

	if (type) { /* 敏感端口 */
		return honey_port_match(result_node, srcip, srcport, dstip, dstport, nrule);
	} else { /* 端口扫描 */
		return port_scan_match(result_node, srcip, srcport, dstip, dstport, nrule);
	}

	return NF_ACCEPT;
}

static int match_conf(struct sniper_ipv6 *srcip, unsigned short srcport,
		      struct sniper_ipv6 *dstip, unsigned short dstport, int direct,
		      struct kern_net_rules *nrule, struct tcphdr *tcp_header)
{
	netreq_t req = {0};
	trie_node *result_node = NULL;

	if (srcip == NULL || dstip == NULL || nrule == NULL || tcp_header == NULL) {
		return NF_ACCEPT;
	}
	req.flags.tcp = 1;
	req.flags.trust = 1;

	read_lock(&sniper_ipv6_lock);
	result_node = search_nodes(conf_root, (char*)&srcip);
	read_unlock(&sniper_ipv6_lock);
	if (!result_node) {
		return NF_ACCEPT;
	}

	if (result_node->trust_conf) { /* 可信名单 */
		req.flags.trust = 1;
		req.srcipv6 = *srcip;
		req.sport = srcport;
		req.dstipv6 = *dstip;
		req.dport = dstport;
		sniper_do_gettimeofday(&req.event_tv);
		req.size = sizeof(netreq_t);
		send_msg_to_user((char *)&req, req.size, nl_net_pid);
		return NF_ACCEPT;
	}

	if (result_node->white_conf) { /* 命中白名单 */
		return NF_ACCEPT;
	}

	if (result_node->filter_conf) { /* 命中过滤名单 */
		return NF_ACCEPT;
	}

	if (result_node->black_conf) { /* 命中黑名单 */
		//netreq_t req = {0};
		memset(&req, 0, sizeof(netreq_t));
		req.flags.tcp = 1;
		if (direct) {
			req.flags.blackin = 1;
		} else {
			req.flags.blackout = 1;
			// unsigned long now_in_interrupt = in_interrupt();
			// if (!now_in_interrupt) {
			// 	req.pid = current->pid;
			// 	req.uid = currentuid();
			// 	get_current_comm(req.comm);
			// 	report_netout_package(&req, &srcip, sport, &dstip, dport,
			// 			      ipv6_header, tcp_header, "blackout");
			// }
		}
		req.flags.terminate = nrule->blackwhite_reject;

		if (req.flags.terminate) {
			// 添加到发送队列，准备发送日志
			return depend_current_mode(NF_DROP);
		}
		/* 只检查local_in的包，黑白名单不阻断，则只报连接包，避免日志太多 */
		if (direct && tcp_header->syn) {
			// 报连接包
		}
		return NF_ACCEPT;
	}
	return -1;
}

/* always in_softirq */
/* NF_INET_LOCAL_IN */
/* 有的版本与内核主线不符，可能打了补丁，如centos7.2-6
   故不能根据版本号来调整函数定义，改为直接取当前编译环境里的函数定义 */
static unsigned int local_in_hook(NF_HOOKFN_ARGS)
{
	struct ipv6hdr *ipv6_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	unsigned short sport;
	unsigned short dport;
	struct sniper_ipv6 srcip = {{0}};
	struct sniper_ipv6 dstip = {{0}};
	struct kern_net_rules nrule = {0};
	struct kern_process_rules prule = {0};
	int tcp_watch = 1, udp_watch = 1, icmp_watch = 1;
	int ret = NF_ACCEPT;

	/* 对标志的使用不加锁，即使值错误或改变，也不会像指针那样产生严重后果，
	   顶多是少做一次或多做一次，锁用错的风险更高 */
	nrule = sniper_nrule;
	prule = sniper_prule;

	/* 网络引擎关闭时，如果挖矿策略开启，检测是否解析矿池域名 */
	if (!nrule.net_engine_on || sniper_net_loadoff) {
		tcp_watch = 0;
		icmp_watch = 0;

		if (!prule.process_engine_on || !prule.miner_on || sniper_exec_loadoff) {
			udp_watch = 0;
			return NF_ACCEPT;
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	ipv6_header = ipv6_hdr(*skb);
#else
	ipv6_header = ipv6_hdr(skb);
#endif
	if (!ipv6_header) {
		return NF_ACCEPT;
	}

	sniper_addr2ipv6(&srcip, (unsigned char *)&ipv6_header->saddr);
	sniper_addr2ipv6(&dstip, (unsigned char *)&ipv6_header->daddr);

	if (tcp_watch && ipv6_header->nexthdr == IPPROTO_TCP) {
		if (skip_package(ipv6_header)) {
			return NF_ACCEPT;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
		skb_set_transport_header(*skb, sizeof(struct ipv6hdr));   
		tcp_header = tcp_hdr(*skb);
#else
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));   
		tcp_header = tcp_hdr(skb);
#endif
		dport = ntohs(tcp_header->dest);
		sport = ntohs(tcp_header->source);

		/* 检测特殊的端口扫描包，如FIN扫描、NULL扫描、Xmax扫描 */
		if (is_portscan_flag(tcp_header)) {
			/* 特殊扫描命中敏感端口也要上报与后面正常连接报敏感端口事件不冲突
			   端口扫描命中和敏感端口命中都会上报 */
			if (is_honeyport(dport)) {
				ret = match_dynamic_tree(&srcip, sport, &dstip, dport, 1, &nrule);
			}

			if (ret == NF_DROP) {
				/* 增加端口扫描计数 */
				match_dynamic_tree(&srcip, sport, &dstip, dport, 0, &nrule);
				return depend_current_mode(NF_DROP);
			}

			ret = match_dynamic_tree(&srcip, sport, &dstip, dport, 0, &nrule);
			if (ret == NF_DROP) {
				return depend_current_mode(NF_DROP);
			}
		}

		/* 忽略out connection上的数据包 */
		/* 除了端口扫描的syn1ack0包，其他与本机非服务端口的通信，视为out connection通信 */
		if (!is_service_port(dport)) { //不是服务端口
			/* 只关注连接包，其他是数据包 */
			if (!tcp_header->syn || tcp_header->ack) {
				return NF_ACCEPT;
			}
		}

		if (net_debug &&
		    (tcp_header->fin || tcp_header->rst || tcp_header->syn) &&
		    !is_server(dport, &dstip)) {
			print_package(&srcip, sport, &dstip, dport, ipv6_header, tcp_header, "==in");
		}

		/* 查找当前IPv是否已在黑/白/过滤名单中 */
		ret = match_conf(&srcip, sport, &dstip, dport, 1, &nrule, tcp_header);
		if (ret != -1) {
			return ret;
		}

		return NF_ACCEPT;
	} /* end TCP */

 	if (icmp_watch && ipv6_header->nexthdr == 58) { /* ping6命令 */
		return NF_ACCEPT;
	} /* end ICMP */

	if (udp_watch && ipv6_header->nexthdr == IPPROTO_UDP) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
		skb_set_transport_header(*skb, sizeof(struct ipv6hdr));   
		udp_header = udp_hdr(*skb);
#else
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));   
		udp_header = udp_hdr(skb);
#endif
		dport = ntohs(udp_header->dest);
		sport = ntohs(udp_header->source);

		if (skip_package(ipv6_header)) {
			/* 发给本机DNS代理程序(如dnsmasq)的DNS查询包不过滤，否则不报告域名查询日志 */
			if (sport != 53) {
				return NF_ACCEPT;
			}
		}

		if (sport == 53) {
			char *dns_hdr = NULL;
			int len = udp_header->len - sizeof(struct udphdr);
			int csum_changed = 0, nwords = 0;
			unsigned short *buf = NULL;

			dns_hdr = (char *)udp_header + sizeof(struct udphdr);
			csum_changed = handle_dns_answer(dns_hdr, len, &nrule);
			if (csum_changed) {
				nwords = udp_header->len >> 1;
				buf = (unsigned short *)udp_header;
				udp_header->check = 0;
				udp_header->check = csum(buf, nwords);
			}
			return NF_ACCEPT;
		}

		return NF_ACCEPT;
	} /* end UDP */

	return NF_ACCEPT;
}

static struct nf_hook_ops local_in_ops =
{
    .hook = local_in_hook,
    .pf = PF_INET6,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP6_PRI_FIRST
};

/* 可能在softirq里，也可能不在softirq里，
 * 观察到发给管控的包就有很多在softirq里，不仅仅是失败重发才会在softirq里 */
/* NF_INET_LOCAL_OUT */
static unsigned int local_out_hook(NF_HOOKFN_ARGS)
{
	struct ipv6hdr *ipv6_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	unsigned short sport = 0;
	unsigned short dport = 0;
	struct sniper_ipv6 srcip = {{0}};
	struct sniper_ipv6 dstip = {{0}};
	netreq_t req = {0};
	struct kern_net_rules nrule = {0};
	struct kern_process_rules prule = {0};
	int tcp_watch = 0, udp_watch = 0, icmp_watch = 0;
	int miner_watch = 0;
	int ret = 0;

	/* 若处于中断上下文中，则当前是重试的包，只检测（并在需要阻断时阻断）。
	   不报告，此时取的进程信息是中断前的进程，不准的，并非真正要发包的进程 */
	unsigned long now_in_interrupt = in_interrupt();

	/* 对标志的使用不加锁，即使值错误或改变，也不会像指针那样产生严重后果，
	   顶多是少做一次或多做一次，锁用错的风险更高 */
	nrule = sniper_nrule;
	prule = sniper_prule;

	if (nl_exec_pid && prule.process_engine_on && !sniper_exec_loadoff) {
		if (prule.miner_on) {
			miner_watch = 1;
		}
	}

	/* 网络引擎关闭时，如果挖矿策略开启，检测是否解析矿池域名 */
	//TODO 加上检测是否连接矿池IP
	if (nrule.net_engine_on && !sniper_net_loadoff) {
		icmp_watch = 1;
		//TODO 根据策略设置tcp_watch/udp_watch
		tcp_watch = 1;
		udp_watch = 1;
	} else {
		if (miner_watch) {
			udp_watch = 1;
		}
	}

	if (tcp_watch == 0 && udp_watch == 0 && icmp_watch == 0) {
		return NF_ACCEPT;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	ipv6_header = ipv6_hdr(*skb);
#else
	ipv6_header = ipv6_hdr(skb);
#endif
	sniper_addr2ipv6(&srcip, (unsigned char *)&ipv6_header->saddr);
	sniper_addr2ipv6(&dstip, (unsigned char *)&ipv6_header->daddr);

	if (tcp_watch && ipv6_header->nexthdr == IPPROTO_TCP) {
		if (skip_package(ipv6_header)) {
			return NF_ACCEPT;
		}

		req.flags.tcp = 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
		skb_set_transport_header(*skb, sizeof(struct ipv6hdr));   
		tcp_header = tcp_hdr(*skb);  
#else
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));   
		tcp_header = tcp_hdr(skb);  
#endif
		dport = ntohs(tcp_header->dest);
		sport = ntohs(tcp_header->source);

		if (net_debug && !now_in_interrupt &&
		    (tcp_header->fin || tcp_header->rst || tcp_header->syn) &&
		    !is_server(dport, &dstip)) {
			print_package(&srcip, sport, &dstip, dport, ipv6_header, tcp_header, "out==");
		}

		/* 忽略in connection上的数据包 */
		if (is_service_port(sport)) {
			/* 减少in connection的计数 */
			if (tcp_header->rst) {
			}

			return NF_ACCEPT;
		}

		/* 总是允许与管控中心的日志通信 */
		if (is_server(dport, &dstip)) {
			return NF_ACCEPT;
		}
		/* 主机隔离状态 */
		if (host_quarantine) {
			return depend_current_mode(NF_DROP);
		}
		/* 非法连接互联网,阻断开关打开,只允许联接管制中心 */
		if (nrule.illegal_conn_terminate) {
			return depend_current_mode(NF_DROP);
		}

		ret = match_conf(&dstip, dport, &srcip, sport, 0, &nrule, tcp_header);
		if (ret != -1) {
			return ret;
		}
#if 1
		/* 禁止连接互联网 */
		if (nrule.internet_watch && is_internet_ipv6(&dstip)) {
			req.flags.internet = 1;
			req.flags.terminate = nrule.internet_reject;

			/* 不管是否阻断，都只报连接包，避免日志太多 */
			if (!now_in_interrupt && tcp_header->syn && !tcp_header->ack) {
				req.pid = current->pid;
				req.uid = currentuid();
				get_current_comm(req.comm, &req.exeino);

				report_netout_package(&req, &srcip, sport, &dstip, dport,
						      ipv6_header, tcp_header, "internet");
			}
			req.flags.internet = 0;

			if (req.flags.terminate) {
				return depend_current_mode(NF_DROP);
			}
		}
#endif
		return NF_ACCEPT;
 	}

	if (udp_watch && ipv6_header->nexthdr == IPPROTO_UDP) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
		skb_set_transport_header(*skb, sizeof(struct ipv6hdr));   
		udp_header = udp_hdr(*skb);
#else
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));   
		udp_header = udp_hdr(skb);
#endif
		/* 非法连接互联网,阻断开关打开,只允许联接管制中心 */
		if (nrule.illegal_conn_terminate) {
			return depend_current_mode(NF_DROP);
		}
		dport = ntohs(udp_header->dest);
		sport = ntohs(udp_header->source);

		if (dport == 53) {
			char *dns_hdr = (char *)udp_header + sizeof(struct udphdr);

			handle_dns_query(dns_hdr, &nrule);
			return NF_ACCEPT;
		}

		return NF_ACCEPT;
	}

	if (icmp_watch && ipv6_header->nexthdr == IPPROTO_ICMP) {
		/* 非法连接互联网,阻断开关打开,只允许联接管制中心
		 * TODO 有一种APT攻击方式是通过ICMP传输数据 */
		// if (nrule.illegal_conn_terminate) {
		// 	return NF_DROP;
		// }
#if 1
		if (nrule.internet_watch && is_internet_ipv6(&dstip)) {
			req.flags.internet = 1;
			req.flags.terminate = nrule.internet_reject;
			req.flags.internet_terminate = nrule.internet_reject;
			req.flags.icmp = 1;

			if (!now_in_interrupt) {
				req.pid = current->pid;
				req.uid = currentuid();
				get_current_comm(req.comm, &req.exeino);

				report_netout_package(&req, &srcip, sport, &dstip, 0,ipv6_header, NULL, "internet");
			}

			req.flags.internet = 0;
			if (req.flags.terminate) {
				return depend_current_mode(NF_DROP);
			}
		}
#endif
		return NF_ACCEPT;
	}

	if (net_debug && !now_in_interrupt &&
	    ipv6_header->nexthdr != IPPROTO_TCP &&
	    ipv6_header->nexthdr != IPPROTO_UDP &&
	    ipv6_header->nexthdr != IPPROTO_ICMP) {
		printk("===%s(%d) out===protocol %d: %pI6c -> %pI6c\n",
			current->comm, current->pid, ipv6_header->nexthdr, &ipv6_header->saddr, &ipv6_header->daddr);
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops local_out_ops =
{
    .hook = local_out_hook,
    .pf = PF_INET6,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP6_PRI_FIRST
};

static int net6_on = 0;

int net_hook_ipv6_init(void)
{
	if (!net6_on) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		//nf_register_hook(&pre_routing_ops);
		//nf_register_hook(&post_routing_ops);
		//nf_register_hook(&forward_ops);
	
		nf_register_hook(&local_in_ops);
		nf_register_hook(&local_out_ops);
#else
		//nf_register_net_hook(&init_net, &pre_routing_ops);
		//nf_register_net_hook(&init_net, &post_routing_ops);
		//nf_register_net_hook(&init_net, &forward_ops);
	
		nf_register_net_hook(&init_net, &local_in_ops);
		nf_register_net_hook(&init_net, &local_out_ops);
#endif
		conf_root = create_node();
		dynamic_root = create_node();

		net6_on = 1;
		myprintk("net engine ipv6 on\n");
	}

	return 0;
}

void net_hook_ipv6_exit(void)
{
	if (net6_on) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		//nf_unregister_hook(&pre_routing_ops);
		//nf_unregister_hook(&post_routing_ops);
		//nf_unregister_hook(&forward_ops);
	
		nf_unregister_hook(&local_in_ops);
		nf_unregister_hook(&local_out_ops);
#else
		//nf_unregister_net_hook(&init_net, &pre_routing_ops);
		//nf_unregister_net_hook(&init_net, &post_routing_ops);
		//nf_unregister_net_hook(&init_net, &forward_ops);
	
		nf_unregister_net_hook(&init_net, &local_in_ops);
		nf_unregister_net_hook(&init_net, &local_out_ops);
#endif
		destroy_tree(conf_root);
		destroy_tree(dynamic_root);

		net6_on = 0;
		myprintk("net engine ipv6 off\n");
	}
}

void net_ipv6_conf_reset(void)
{
	write_lock_bh(&sniper_ipv6_lock);
	destroy_tree(conf_root);
	conf_root = create_node();
	write_unlock_bh(&sniper_ipv6_lock);
}

int net_ipv6_conf_insert(struct sniper_ipv6 *ipv6)
{
	unsigned char ipv6_str[64];
	int ret = 0;
	trie_node *result_node = NULL;

	if (ipv6 == NULL) {
		return -1;
	}

	snprintf(ipv6_str, sizeof(ipv6_str), "%pI6", (unsigned char*)ipv6);

	result_node = insert(conf_root, (unsigned char*)&ipv6_str);
	if (result_node) {
		result_node->white_conf = 1;
	} else {
		ret = -1;
	}

	return ret;
}

int depend_current_mode(const int ret_st)
{
	if (client_mode == NORMAL_MODE) { /* 正常模式 */
		return ret_st;
	}

	return NF_ACCEPT;
}
