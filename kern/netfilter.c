#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/udp.h> 
#include <linux/tcp.h> 
#include <linux/icmp.h> 
#include <linux/netfilter_ipv4.h>

#include "interface.h"

/* <--- for CentOS5 */
#include <linux/in.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25) //老版本定义的是NF_IP_XXX
enum nf_inet_hooks {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS
};
#endif
#ifndef HAVE_SKB_SET_TRANSPORT_HEADER //5.0, 5.1
#define skb_set_transport_header(skb, offset) do {} while(0)
#define ip_hdr(skb)   (skb)->nh.iph
#define tcp_hdr(skb)  skb_header_pointer((skb), (skb)->nh.iph->ihl*4, sizeof(th), &th)
#define udp_hdr(skb)  skb_header_pointer((skb), (skb)->nh.iph->ihl*4, sizeof(uh), &uh)
#define icmp_hdr(skb) skb_header_pointer((skb), (skb)->nh.iph->ihl*4, sizeof(ih), &ih)
#endif
/* for CentOS5 ---> */

/* 不阻断时，标志用来指示是否做后继的检查，及上报什么事件 */
#define SNIPER_SERVER_IP 1
#define SNIPER_BLACK_IP  2

/* 不检查本机内部的通信：1、源ip和目的ip相同；2、源ip是127.x.x.x */
static int skip_package(struct iphdr *ip_header)
{
	int ip1 = 0;
	int ip4 = 0;

	if (ip_header->saddr == ip_header->daddr) {
		return 1;
	}
	ip1 = ((unsigned char *)&(ip_header->saddr))[0];
	ip4 = ((unsigned char *)&(ip_header->saddr))[3];
	if (ip1 == 127 || ip1 == 255 || ip4 == 255 || ip4 == 224) { /* 本地和广播地址不做检查 */
		return 1;
	}

	return 0;
}

static void sniper_addr2ip(struct sniper_ip *ip, unsigned char *addr)
{
	ip->ip[0] = addr[0];
	ip->ip[1] = addr[1];
	ip->ip[2] = addr[2];
	ip->ip[3] = addr[3];
}

static unsigned long sniper_ip2addr(struct sniper_ip *ip)
{
	return ( (((unsigned long)ip->ip[0]) << 24) +
		 (((unsigned long)ip->ip[1]) << 16) +
		 (((unsigned long)ip->ip[2]) <<  8) +
		  ((unsigned long)ip->ip[3]) );
}

static int is_same_proto(unsigned short proto, int tcp_rule, int udp_rule)
{
	if (proto == SNIPER_TCP) {
		if (tcp_rule) {
			return 1;
		}
		return 0;
	}

	if (proto == SNIPER_UDP) {
		if (udp_rule) {
			return 1;
		}
		return 0;
	}

	return 0;
}

static int is_same_ip(struct sniper_ip *ip1, struct sniper_ip *ip2)
{
	if (ip1->ip[0] == ip2->ip[0] && ip1->ip[1] == ip2->ip[1] &&
	    ip1->ip[2] == ip2->ip[2] && ip1->ip[3] == ip2->ip[3]) {
		return 1;
	}
	return 0;
}

static int ip_inrange(struct sniper_ip *ip, struct sniper_iprange *ipr)
{
	unsigned long ipaddr = sniper_ip2addr(ip);
	unsigned long fromaddr = sniper_ip2addr(&ipr->fromip);
	unsigned long toaddr = sniper_ip2addr(&ipr->toip);
	int n = 0;

	/* 0.0.0.0表示任意ip */
	if (fromaddr == 0) {
		return 1;
	}

	/* x.x.x.x - y.y.y.y */
	if (ipr->toip.ip[0] != 0) {
		/* fromip <= ip <= toip */
		if (fromaddr <= ipaddr && ipaddr <= toaddr) {
			return 1;
		}
		return 0;
	}

	/* x.x.x.x */
	if (ipr->sniper_ipmask == 0) {
		if (ipaddr == fromaddr) {
			return 1;
		}
		return 0;
	}

	/* x.x.x.x/z */
	n = 32 - ipr->sniper_ipmask;
	if ( (ipaddr >> n) == (fromaddr >> n)) {
		return 1;
	}

	return 0;
}

/* 网络引擎中不需要read_lock_bh()，占着读锁被中断，不会导致死锁，加写锁的地方才需要禁中断 */
/* 检测对方是否为管控，要求对方ip为管控ip，对方端口为通信端口或websocket端口 */
/* 通信端口一般为443。websocket端口是客户端注册时，从管控取得的，目前是8000 */
static int is_server(unsigned short port, struct sniper_ip *ip)
{
	int i = 0;
	struct sniper_server *server = NULL;

	read_lock(&sniper_nserver_lock);

	server = (struct sniper_server *)sniper_nserver;
	if (!server) {
		read_unlock(&sniper_nserver_lock);
		return 0;
	}

	for (i = 0; i < sniper_nserver_count; i++) {
		if ((port == server[i].port || port == server[i].wsport) &&
		    is_same_ip(ip, &server[i].ip)) {
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
		//if (h->fin) {
		//	myprintk("fin scan\n");
		//} else {
		//	myprintk("null scan\n");
		//}
		return 1;
	}

	if (!h->syn && !h->rst && !h->ack && h->fin && h->psh && h->urg) {
		//myprintk("xmas scan\n");
		return 1;
	}

	return 0;
}

/* 可信IP 返回 1，否则返回 0 */
static int is_trustip(struct sniper_ip *ip)
{
	struct sniper_iprange *trustipr = NULL;
	int ret = 0;
	int j = 0;

	if (ip == NULL) {
		return 0;
	}

	read_lock(&sniper_nhoneyport_lock);
	/* 扫描还是扫描，但日志级别报普通 */
	trustipr = (struct sniper_iprange *)sniper_nhoneyport_trustip;
	if (trustipr) {
		for (j = 0; j < sniper_nhoneyport_trustip_count; j++) {
			if (ip_inrange(ip, &trustipr[j])) {
				ret |= trustipr[j].type;
				if (ret == NET_MODULE_ALL) { /* 当前可信IP对应的两个模块，端口扫描类型1，敏感端口类型2 */
					read_unlock(&sniper_nhoneyport_lock);
					return ret;
				} else {/* 分开配置的，进行累计 */
					ret |= trustipr[j].type;
					if (ret >= NET_MODULE_ALL) {
						ret = NET_MODULE_ALL;
						read_unlock(&sniper_nhoneyport_lock);
						return ret;
					}
				}
			}
		}
	}
	read_unlock(&sniper_nhoneyport_lock);
	if (ret >= 3) {
		ret = 3;
	}
	return ret;
}

static int is_honeyport(unsigned short port, struct sniper_ip *ip, int *trust_flag)
{
	int i = 0, j = 0;
	struct sniper_iprange *filteripr = NULL;
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

		/* 这里过滤的语义是不care是否扫描，直接忽略 */
		filteripr = (struct sniper_iprange *)sniper_nhoneyport_filterip;
		if (filteripr) {
			for (j = 0; j < sniper_nhoneyport_filterip_count; j++) {
				if (ip_inrange(ip, &filteripr[j])) {
					read_unlock(&sniper_nhoneyport_lock);
					return 0;
				}
			}
		}

		read_unlock(&sniper_nhoneyport_lock);
		return 1;
	}

	read_unlock(&sniper_nhoneyport_lock);
	return 0;
}

static int port_inrange(unsigned short port, unsigned short fromport, unsigned short toport)
{
	if (fromport == 0 && toport == 0) { //端口是0表示任意端口都命中
		return 1;
	}
	if (port < fromport || port > toport) { //端口不在fromport-toport的范围内
		return 0;
	}
	return 1;
}

/* 规则名单仅对普通模式生效，运维和学习模式下无效 */
static int client_mode_skip_rule(void)
{
	if (client_mode != NORMAL_MODE) {
		return 1;
	}
	return 0;
}

static int is_blackin_ip(unsigned short port, struct sniper_ip *ip, unsigned short proto)
{
	int i = 0;
	struct sniper_connrule *rule = NULL;

	if (client_mode_skip_rule()) {
		return 0;
	}

	read_lock(&sniper_nblackin_lock);

	rule = (struct sniper_connrule *)sniper_nblackin;
	if (!rule) {
		read_unlock(&sniper_nblackin_lock);
		return 0;
	}

	for (i = 0; i < sniper_nblackin_count; i++) {
		if (!is_same_proto(proto, rule[i].tcp, rule[i].udp) ||
		    !port_inrange(port, rule[i].fromport, rule[i].toport)) {
			continue;
		}

		if (ip_inrange(ip, &rule[i].ipr)) {
			read_unlock(&sniper_nblackin_lock);
			return 1;
		}
	}

	read_unlock(&sniper_nblackin_lock);
	return 0;
}
static int is_blackout_ip(unsigned short port, struct sniper_ip *ip, unsigned short proto)
{
	int i = 0;
	struct sniper_connrule *rule = NULL;

	if (client_mode_skip_rule()) {
		return 0;
	}

	read_lock(&sniper_nblackout_lock);

	rule = (struct sniper_connrule *)sniper_nblackout;
	if (!rule) {
		read_unlock(&sniper_nblackout_lock);
		return 0;
	}

	for (i = 0; i < sniper_nblackout_count; i++) {
		if (!is_same_proto(proto, rule[i].tcp, rule[i].udp) ||
		    !port_inrange(port, rule[i].fromport, rule[i].toport)) {
			continue;
		}

		if (ip_inrange(ip, &rule[i].ipr)) {
			read_unlock(&sniper_nblackout_lock);
			return 1;
		}
	}

	read_unlock(&sniper_nblackout_lock);
	return 0;
}

static int valid_rule(struct sniper_connrule *rule)
{
	/* 不需要检查rule->port<65536，unsigned short类型最大65535 */

	if (!rule->tcp && !rule->udp) {
		return 0;
	}
	if (rule->ipr.fromip.ip[0] == SNIPER_BADIP) {
		return 0;
	}

	return 1;
}

/* 非白名单返回1。没有白名单，或在白名单内，返回0 */
/* 不考虑规则的冲突，规则“允许192.168.1.1连入”和规则“允许192.188.1.1连入本机22端口”都有效 */
static int not_whitein_ip(unsigned short port, struct sniper_ip *ip, struct sniper_ip *myip, unsigned short proto)
{
	int i = 0, white_valid = 0;
	struct sniper_connrule *rule = NULL;

	if (client_mode_skip_rule()) {
		return 0; //忽略白名单
	}

	if (ip->ip[0] == 127 || is_same_ip(ip, myip)) {
		return 0; //忽略本机内部通信
	}

	read_lock(&sniper_nwhitein_lock);

	rule = (struct sniper_connrule *)sniper_nwhitein;
	if (!rule) {
		read_unlock(&sniper_nwhitein_lock);
		return 0; //没有白名单
	}

	for (i = 0; i < sniper_nwhitein_count; i++) {
		if (!valid_rule(&rule[i])) {
			continue;
		}
		white_valid = 1;

		if (!is_same_proto(proto, rule[i].tcp, rule[i].udp) ||
		    !port_inrange(port, rule[i].fromport, rule[i].toport)) {
			continue;
		}

		if (ip_inrange(ip, &rule[i].ipr)) {
			read_unlock(&sniper_nwhitein_lock);
			return 0; //命中白名单
		}
	}

	read_unlock(&sniper_nwhitein_lock);

	if (!white_valid) {
		return 0; //没有有效的白名单
	}

	return 1; //白名单外
}
static int not_whiteout_ip(unsigned short port, struct sniper_ip *ip, struct sniper_ip *myip, unsigned short proto)
{
	int i = 0, white_valid = 0;
	struct sniper_connrule *rule = NULL;

	if (client_mode_skip_rule()) {
		return 0; //忽略白名单
	}

	if (ip->ip[0] == 127 || is_same_ip(ip, myip)) {
		return 0; //忽略本机内部通信
	}

	read_lock(&sniper_nwhiteout_lock);

	rule = (struct sniper_connrule *)sniper_nwhiteout;
	if (!rule) {
		read_unlock(&sniper_nwhiteout_lock);
		return 0; //没有白名单
	}

	for (i = 0; i < sniper_nwhiteout_count; i++) {
		if (!valid_rule(&rule[i])) {
			continue;
		}
		white_valid = 1;

		if (!is_same_proto(proto, rule[i].tcp, rule[i].udp) ||
		    !port_inrange(port, rule[i].fromport, rule[i].toport)) {
			continue;
		}

		if (ip_inrange(ip, &rule[i].ipr)) {
			read_unlock(&sniper_nwhiteout_lock);
			return 0; //命中白名单
		}
	}

	read_unlock(&sniper_nwhiteout_lock);

	if (!white_valid) {
		return 0; //没有有效的白名单
	}

	return 1; //白名单外
}

/* 检测端口是否服务端口，用来识别网络包对应的业务是连入还是连出 */
/* 1 命中中间件端口，是服务端口；0，未命中 */
int is_service_port(unsigned short myport)
{
	int i = 0;
	struct sniper_middleware *mid = NULL;

	read_lock(&sniper_pmiddleware_lock);

	if (sniper_pmiddleware_count == 0 || !sniper_pmiddleware) {
		read_unlock(&sniper_pmiddleware_lock);
		return 0;
	}

	mid = (struct sniper_middleware *)sniper_pmiddleware;
	for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++, mid++) {
		if (mid->pid == 0) {
			continue;
		}

		if (mid->port == myport) {
			read_unlock(&sniper_pmiddleware_lock);
			return 1;
		}
	}

	read_unlock(&sniper_pmiddleware_lock);
	return 0;
}

int is_internet(struct sniper_ip *ip)
{
	int i = 0;
	struct sniper_iprange *lanip = NULL;

	/* 127.x.x.x, 10.0.0.0/8 */
	if (ip->ip[0] == 127 || ip->ip[0] == 10) {
		return 0;
	}

	/* 192.168.0.0/16 */
	if (ip->ip[0] == 192 && ip->ip[1] == 168) {
		return 0;
	}

	/* 172.16.0.0/12： 172.16.0.0 -- 172.31.255.255 */
	if (ip->ip[0] == 172 && ip->ip[1] >= 16 && ip->ip[1] <= 31) {
		return 0;
	}

	/* 224.0.0.251:5353 是 mDNS协议广播地址
	   224.0.0.252:5355 是 LLMNR协议广播地址
	   都是用来在局域网内查找主机名对应的ip，不视为互联网地址
	   TODO 但以后要考虑如何防中间人欺骗，或提示风险 */
	if (ip->ip[0] == 224 && ip->ip[1] == 0 && ip->ip[2] == 0 &&
	    (ip->ip[3] == 251 || ip->ip[3] == 252)) {
		return 0;
	}

	/* 如果使用了特殊的局域网网段，检查ip是否在其中 */
	read_lock(&sniper_nlanip_lock);

	lanip = (struct sniper_iprange *)sniper_nlanip;
	if (lanip) {
		for (i = 0; i < sniper_nlanip_count; i++) {
			if (ip_inrange(ip, &lanip[i])) {
				read_unlock(&sniper_nlanip_lock);
				return 0;
			}
		}
	}

	read_unlock(&sniper_nlanip_lock);
	return 1;
}

static int ipidx(struct sniper_ip *ip)
{
	return (ip->ip[2] * 256 + ip->ip[3]);
}

static lockipinfo_t *get_lockipinfo(struct sniper_ip *ip)
{
	int idx = ipidx(ip);
	lockipinfo_t *info = NULL, *tmp = NULL;

	list_for_each_entry_safe(info, tmp, &lockiplist[idx].queue, list) {
		if (is_same_ip(ip, &info->ip)) {
			return info;
		}
	}
	return NULL;
}

void sniper_add_lockip(struct sniper_ip *ip, unsigned int reason, time_t lock_time)
{
	int idx = ipidx(ip);
	int size = sizeof(lockipinfo_t);
	lockipinfo_t *info = NULL, *oldinfo = NULL;
	time_t now = sniper_uptime();

	if (sniper_badptr(ip)) {
		return;
	}

	write_lock_bh(&lockiplist[idx].lock);
	/* 已经被锁的ip，不重复锁。预先检查，避免多次无效的kmalloc/kfree */
	oldinfo = get_lockipinfo(ip);
	if (oldinfo) {
		write_unlock_bh(&lockiplist[idx].lock);
		return;
	}
	write_unlock_bh(&lockiplist[idx].lock);

	info = sniper_kmalloc(size, GFP_ATOMIC, KMALLOC_LOCKIP);
        if (!info) {
                myprintk("%s(%d) cache lockip %d.%d.%d.%d fail: no memory!\n",
                        current->comm, current->pid, IPSTR(ip));
		return;
        }

        info->ip = *ip;
        info->reason = reason;
	info->time_locked = now;
	info->time_unlock = now + lock_time;

	write_lock_bh(&lockiplist[idx].lock);

	/* 已经被锁的ip，不重复锁。再查一次，避免在kmalloc期间有其他进程抢先锁了此ip */
	oldinfo = get_lockipinfo(ip);
	if (oldinfo) {
		write_unlock_bh(&lockiplist[idx].lock);
		if (mem_debug == KMALLOC_LOCKIP) {
                	myprintk("%s(%d): %d.%d.%d.%d already locked\n",
				current->comm, current->pid, IPSTR(ip));
		}
		sniper_kfree(info, size, KMALLOC_LOCKIP);
		return;
	}

	list_add_tail(&info->list, &lockiplist[idx].queue);
	lockiplist[idx].count++;
	write_unlock_bh(&lockiplist[idx].lock);

	myprintk("lock ip %u.%u.%u.%u. reason %u\n", IPSTR(ip), reason);

	/* 不需要单独report_lockip往外报锁ip的动作，触发锁ip的事件里有这个信息，一起处理 */
}

static void print_package(struct sniper_ip *srcip, unsigned short sport,
			  struct sniper_ip *dstip, unsigned short dport,
			  struct iphdr *ip_header, struct tcphdr *tcp_header,
			  char *desc)
{
	char comm[S_COMMLEN] = {0};
	char tag[64] = "Interrupt";

	if (!net_debug) {
		return;
	}

	if (!in_interrupt()) {
		get_current_comm(comm, NULL);
		snprintf(tag, sizeof(tag), "%s(%d)", comm, current->pid);
	}
	if (tcp_header) {
		printk("%s %s === %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d, "
			"state fin%d/syn%d/rst%d/psh%d/ack%d/urg%d. "
			"hdrlen %d, len %d, TTL %d, id %d, Window %d\n",
			tag, desc, IPSTR(srcip), sport, IPSTR(dstip), dport,
			tcp_header->fin, tcp_header->syn,
			tcp_header->rst, tcp_header->psh,
			tcp_header->ack, tcp_header->urg,
			ip_header->ihl*4, ip_header->tot_len, ip_header->ttl,
			ip_header->id, tcp_header->window);
	} else {
		printk("%s %s === %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
			tag, desc, IPSTR(srcip), sport, IPSTR(dstip), dport);
	}
}

/*
 * 把port插入portlist
 * portlist是一个unsigned short类型的数组，
 * 如80,80,82,84,88,88，表示端口范围80,82-84,88
 */
static void insert_portscan(msgipinfo_t *info, unsigned short port)
{
	int i = 0, k = 0, n = 0;
	int size = 0, type = KMALLOC_PORTLIST;
	int shortsize = sizeof(short);
	int intsize = sizeof(int); //即2个unsigned short
	unsigned short *buf = NULL;

	if (sniper_badptr(info)) {
		return;
	}
	info->ports_count++;
	if (info->myport == port) {
		return; //忽略相同的端口
	}

	/* 第一次合并 */
	if (!info->portlist) {
		size = 2 * intsize;
		info->portlist = (unsigned short *)sniper_kmalloc(size, GFP_ATOMIC, type);
		if (!info->portlist) {
			return; //内存不足啥也不做
		}

		info->portlist_size = size;
		// info->ports_count = 2;
		if (info->myport > port) {
			info->portlist[0] = port;
			info->portlist[1] = port;
			info->portlist[2] = info->myport;
			info->portlist[3] = info->myport;
		} else {
			info->portlist[0] = info->myport;
			info->portlist[1] = info->myport;
			info->portlist[2] = port;
			info->portlist[3] = port;
		}
		return;
	}

 	/*
	 * 插入新端口后，portlist变化如下所示
	 * port + portlist           =  new portlist
	 * 60     80,80,82,84,88,88     60,60,80,80,82,84,88,88
	 * 79     80,80,82,84,88,88     79,80,82,84,88,88
	 * 81     80,80,82,84,88,88     80,84,88,88
	 * 85     80,80,82,84,88,88     80,80,82,85,88,88
	 * 86     80,80,82,84,88,88     80,80,82,84,86,86,88,88
	 * 87     80,80,82,84,88,88     80,80,82,84,87,88
	 * 89     80,80,82,84,88,88     80,80,82,84,88,89
	 * 90     80,80,82,84,88,88     80,80,82,84,88,88,90,90
	 */
	n = info->portlist_size / intsize; //原端口列表有n对端口
	for (i = 0; i < n; i++) {
		k = 2 * i;

		if (port >= info->portlist[k] && port <= info->portlist[k+1]) {
			return; //忽略已经包含的端口
		}

		/* 新端口小于[k]的端口 */
		if (port < info->portlist[k]) {
			/* 如插入79和87 */
			if (port == info->portlist[k] - 1) {
				info->portlist[k] = port;
				// info->ports_count++;
				return;
			}

			size = info->portlist_size + intsize;
			buf = (unsigned short *)sniper_kmalloc(size, GFP_ATOMIC, type);
			if (!buf) {
				return; //内存不足啥也不做
			}

			/* 如插入60和86, new = old[...k-1] + port, port + old[k...] */
			memcpy(buf, info->portlist, i * intsize); 
			buf[k] = port;
			buf[k+1] = port;
			memcpy(&buf[k+2], &info->portlist[k], (n - i) * intsize);

			sniper_kfree(info->portlist, info->portlist_size, type);
			info->portlist = buf;
			info->portlist_size = size;
			// info->ports_count++;

			return;
		}

		/* 新端口大于[k+1]的端口，且与之连续 */
		if (port == info->portlist[k+1] + 1) {
			/* 如在尾部插入89 */
			if (i == n - 1) {
				info->portlist[k+1] = port;
				// info->ports_count++;
				return;
			}

			/* 如插入81，把前后两段端口连起来了 */
			if (port == info->portlist[k+2] - 1) {
				size = info->portlist_size - intsize;
				buf = (unsigned short *)sniper_kmalloc(size, GFP_ATOMIC, type);
				if (!buf) {
					return; //内存不足啥也不做
				}

				/* new = old[...k] + old[k+3...]，新列表变小了，少了2个端口 */
				memcpy(buf, info->portlist, (k+1) * shortsize); 
				memcpy(&buf[k+1], &info->portlist[k+3], (2*n-k-3) * shortsize);

				sniper_kfree(info->portlist, info->portlist_size, type);
				info->portlist = buf;
				info->portlist_size = size;
				// info->ports_count++;

				return;
			}

			/* 如插入85 */
			info->portlist[k+1] = port;
			// info->ports_count++;
			return;
		}

		/*
		 * 新端口大于[k+1]的端口，且与之不连续，则检查与下一对端口的关系
		 * 除非已经到老的端口列表尾部了，那就直接加在尾部，如插入90
		 */
		if (i == n - 1) {
			size = info->portlist_size + intsize;
			buf = (unsigned short *)sniper_kmalloc(size, GFP_ATOMIC, type);
			if (!buf) {
				return; //内存不足啥也不做
			}

			/* new = old[...] + port, port */
			memcpy(buf, info->portlist, n * intsize); 
			k = 2 * n;
			buf[k] = port;
			buf[k+1] = port;

			sniper_kfree(info->portlist, info->portlist_size, type);
			info->portlist = buf;
			info->portlist_size = size;
			// info->ports_count++;

			return;
		}
	}
}

/*
 * netin的消息都在软中断中，不可睡眠等待，故不直接netlink发出内核，以免出现睡眠等待
 * 插入各事件的消息队列中，由ksniperd_netin线程读取报告
 * 插入消息队列时，做压缩，批量报告同类事件
 * 对于端口扫描事件，还有一个累积次数的作用，ksniperd_netin线程只报告满足阈值的端口扫描消息
 */
static void zip_netin_msg(netreq_t *req, iplist_t *iplist,
			  struct sniper_ip *myip, unsigned short myport,
			  struct sniper_ip *peerip, unsigned short peerport, int type)
{
        msgipinfo_t *info = NULL, *tmp = NULL;
	int size = 0;

	if (sniper_badptr(iplist)) {
		return;
	}

	size = sizeof(req->flags);

	write_lock_bh(&iplist->lock);

	/* 有同类消息，重复次数加1 */
	list_for_each_entry_safe(info, tmp, &iplist->queue, list) {
		/* 对于锁定的ip，匹配对方ip，不匹配端口，否则日志太多 */
		if (req->flags.lockedip) {
			if (is_same_ip(&info->ip, peerip) &&
			    memcmp(&info->flags, &req->flags, size) == 0) {
				info->repeat++;
				write_unlock_bh(&iplist->lock);
				return;
			}

			continue;
		}

		/* 对于端口扫描，匹配对方ip，并统计和记录被扫描的端口 */
		if (req->flags.portscan) {
			if (is_same_ip(&info->ip, peerip) &&
			    memcmp(&info->flags, &req->flags, size) == 0) {
				info->repeat++;
				insert_portscan(info, myport);
				write_unlock_bh(&iplist->lock);
				return;
			}

			continue;
		}

		/* 对于接入黑名单和端口诱捕，匹配对方ip和本地端口 */
		if (info->myport == myport &&
		    is_same_ip(&info->ip, peerip) &&
		    memcmp(&info->flags, &req->flags, size) == 0) {
			info->repeat++;
			write_unlock_bh(&iplist->lock);
			return;
		}
	}

	size = sizeof(msgipinfo_t);
	info = (msgipinfo_t *)sniper_kmalloc(size, GFP_ATOMIC, type);
	if (!info) {
		write_unlock_bh(&iplist->lock);
		myprintk("zip_netin_msg cache %d.%d.%d.%d:%d fail: no memory!\n",
			IPSTR(peerip), peerport);
		return;
	}
	memset(info, 0, size);

	info->ip = *peerip;
	info->port = peerport;
	info->ports_count = 1;
	info->myip = *myip;
	info->myport = myport;
	info->repeat = 0;
	info->flags = req->flags;
	info->last_report_time = 0;
	sniper_do_gettimeofday(&info->last_report_tv);

	list_add_tail(&info->list, &iplist->queue);
	iplist->count++;

	write_unlock_bh(&iplist->lock);
}

static void zip_netin_package(netreq_t *req,
			     struct sniper_ip *srcip, unsigned short sport,
			     struct sniper_ip *dstip, unsigned short dport)
{
	int idx = ipidx(dstip);
	iplist_t *iplist = NULL;

	/* 对于连入，myip是dstip */

	if (req->flags.blackin || req->flags.notwhitein) {
		iplist = &blackinmsg[idx];
		zip_netin_msg(req, iplist, dstip, dport, srcip, sport, KMALLOC_BLACKIN);
		return;
	}

	if (req->flags.honeyport) {
		iplist = &honeyportmsg[idx];
		zip_netin_msg(req, iplist, dstip, dport, srcip, sport, KMALLOC_HONEYPORT);
		return;
	}
	if (req->flags.portscan) {
		iplist = &portscanmsg[idx];
		zip_netin_msg(req, iplist, dstip, dport, srcip, sport, KMALLOC_PORTSCAN);
	}

	if (req->flags.lockedip) {
		iplist = &lockipmsg[idx];
		zip_netin_msg(req, iplist, dstip, dport, srcip, sport, KMALLOC_LOCKIP);
		return;
	}
}

static void report_netout_msg(msgipinfo_t *info)
{
	netreq_t req = {0};

	req.proctime = get_process_time(current);
	if (current->signal && current->signal->tty) {
		req.flags.tty = 1;
	}

	req.flags = info->flags;
	req.repeat = info->repeat;

	req.srcip = info->myip;
	req.sport = info->myport;

	req.dstip = info->ip;
	req.dport = info->port;

	/* 事件时间=开始被压缩的时间+压缩期 */
	req.event_tv.tv_sec = info->last_report_tv.tv_sec + ZIPTERM;
	req.event_tv.tv_usec = info->last_report_tv.tv_usec;

	req.size = sizeof(netreq_t);

	send_msg_to_user((char *)&req, req.size, nl_net_pid);
}

/* 这里的comm使用current->comm，以方便比较压缩 */
static void zip_netout_msg(netreq_t *req, iplist_t *iplist,
			   struct sniper_ip *myip, unsigned short myport,
			   struct sniper_ip *peerip, unsigned short peerport)
{
        msgipinfo_t *info = NULL, *tmp = NULL;
	time_t now = sniper_uptime();
	int size = sizeof(unsigned int), found = 0;

	if (sniper_badptr(iplist)) {
		return;
	}

	/* 这里不用write_lock_bh禁止软中断，因为不报告软中断里的包 */
	write_lock(&iplist->lock);

        list_for_each_entry_safe(info, tmp, &iplist->queue, list) {
		/* 有同样的包 */
		if (info->port == peerport &&
                    is_same_ip(&info->ip, peerip) &&
		    strcmp(info->comm, current->comm) == 0 &&
		    memcmp(&info->flags, &req->flags, size) == 0) {
			found = 1;
			info->repeat++;

			/* 压缩期外，报告消息 */ 
			if (now - info->last_report_time >= ZIPTERM) {
				list_del(&info->list);
				iplist->count--;
				report_netout_msg(info);
				sniper_kfree(info, sizeof(msgipinfo_t), KMALLOC_BLACKOUT);
			}

                        continue;
                }

		/* 不是要找的目标，但其超过压缩期，报日志，并释放空间 */
		if (now - info->last_report_time >= ZIPTERM) {
			list_del(&info->list);
			iplist->count--;
			/* 如果ZIPTERM内没有重复的消息，则无需重复报告 */
			if (info->repeat) {
				report_netout_msg(info);
			}
			sniper_kfree(info, sizeof(msgipinfo_t), KMALLOC_BLACKOUT);
		}
        }

	if (found) {
		write_unlock(&iplist->lock);
		return;
	}

	info = (msgipinfo_t *)sniper_kmalloc(sizeof(msgipinfo_t), GFP_ATOMIC, KMALLOC_BLACKOUT);
	if (!info) {
		myprintk("%s(%d) cache %d.%d.%d.%d:%d fail: no memory!\n",
			current->comm, current->pid, IPSTR(peerip), peerport);
		write_unlock(&iplist->lock);
		return;
	}

	info->ip = *peerip;
	info->port = peerport;
	info->myip = *myip;
	info->myport = myport;
	info->repeat = 0;
	info->flags = req->flags;
	info->last_report_time = now;
	sniper_do_gettimeofday(&info->last_report_tv);
	snprintf(info->comm, sizeof(info->comm), "%s", current->comm);
	list_add_tail(&info->list, &iplist->queue);
	iplist->count++;
	write_unlock(&iplist->lock);

	req->proctime = get_process_time(current);
	if (current->signal && current->signal->tty) {
		req->flags.tty = 1;
	}
	req->srcip = *myip;
	req->sport = myport;

	req->dstip = *peerip;
	req->dport = peerport;

	sniper_do_gettimeofday(&req->event_tv);

	req->size = sizeof(netreq_t);

	send_msg_to_user((char *)req, req->size, nl_net_pid);
}

/* 目前只有违规外连会report_netout_package */
static void report_netout_package(netreq_t *req,
				  struct sniper_ip *srcip, unsigned short sport,
				  struct sniper_ip *dstip, unsigned short dport,
				  struct iphdr *ip_header, struct tcphdr *tcp_header,
				  char *desc)
{
	int idx = ipidx(dstip);
	iplist_t *iplist = NULL;

	print_package(srcip, sport, dstip, dport, ip_header, tcp_header, desc);

	/* 对于连出，myip即srcip */

	if (req->flags.blackout || req->flags.notwhiteout) {
		iplist = &blackoutmsg[idx];
		zip_netout_msg(req, iplist, srcip, sport, dstip, dport);
		return;
	}
}

//TODO 改成也用ksniperd_netin发
void report_unlockip(struct sniper_ip *ip, int reason)
{
	netreq_t req = {0};

	req.flags.unlockip = 1;
	req.reason = reason;
	snprintf(req.ip, sizeof(req.ip), "%u.%u.%u.%u", IPSTR(ip));
	req.size = sizeof(netreq_t);
	//sniper_do_gettimeofday(&req->event_tv);

	//send_data_to_user((char *)&req, req.size, nl_net_pid, Probe_net);
	send_msg_to_user((char *)&req, req.size, nl_net_pid);
}

void sniper_del_lockip(struct sniper_ip *ip)
{
	int idx = ipidx(ip);
	lockipinfo_t *lockipinfo = NULL;
	int size = sizeof(lockipinfo_t);

	/* update_nlockip()会调用本函数，因此这里要用write_lock_bh */
	write_lock_bh(&lockiplist[idx].lock);
	lockipinfo = get_lockipinfo(ip);
	if (lockipinfo) {
		list_del(&lockipinfo->list);
		lockiplist[idx].count--;
		sniper_kfree(lockipinfo, size, KMALLOC_LOCKIP);
		myprintk("unlock ip %u.%u.%u.%u\n", IPSTR(ip));
	}
	write_unlock_bh(&lockiplist[idx].lock);
}

#define SNIPER_JUSTCHECK   1
#define SNIPER_CHECKUPDATE 2
/*
 * ip未锁，后面锁
 * ip已经被锁，1)已到解锁时间，报告被锁期间剩余的未报告阻断数，并释放ip记录
 *             2)未到解锁时间，2.1)锁后第一个非法连接，报告
 *                             2.2)距上次报告时间不足1分钟，待报告阻断数+1
 *                             2.3)距上次报告时间超过1分钟，报告阻断数
 */
static int is_lockedip(struct sniper_ip *ip)
{
	int reason = 0;
	int idx = ipidx(ip);
	time_t now = 0, time_unlock = 0;
	lockipinfo_t *lockipinfo = NULL;

	/* 这里不用read_lock_bh，因为已经在软中断里了 */
	read_lock(&lockiplist[idx].lock);
	lockipinfo = get_lockipinfo(ip);
	if (!lockipinfo) {
		read_unlock(&lockiplist[idx].lock);
		return 0;
	}
	time_unlock = lockipinfo->time_unlock;
	reason = lockipinfo->reason;
	read_unlock(&lockiplist[idx].lock);

	now = sniper_uptime();

	/* 超过解锁时间，删除记录 */
	if (now >= time_unlock) {
		sniper_del_lockip(ip);
		report_unlockip(ip, reason); //自动解锁报告解锁日志
		return 0;
	}

	return 1;
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

static int check_portscan(struct iphdr *ip_header, struct tcphdr *tcp_header,
			  int trust, int honeyport,
			  struct sniper_ip *srcip, unsigned short sport,
			  struct sniper_ip *dstip, unsigned short dport)
{
	netreq_t req = {0};

	/* 管控中心扫描被阻断的话，不影响日志通信 */
	/* ip:port型白名单，比如x.x.x.x:22，如果x.x.x.x扫描了本机，
	   则ip被锁，禁止x.x.x.x与本机22之外的其他端口通信 */
	/* ip型白名单，如果x.x.x.x扫描了本机，ip不锁，仅报警 */
	if (honeyport) {
		/* 端口诱捕 */
		req.flags.tcp = 1;
		req.flags.honeyport = 1;
		if (trust >= 2) {
			req.flags.trust = 1;
		}
		// req.flags.trust = (trust & 0x02);
		if (sniper_nrule.honeyport_reject) {
			req.flags.terminate = 1;
		}
		if (sniper_nrule.honeyport_lockip && req.flags.trust == 0) {
			if (depend_current_mode(NF_DROP) == NF_DROP) {
				sniper_add_lockip(srcip, NET_PORT_HONEY, sniper_nrule.honey_lockip_seconds*60);
			}
			req.flags.locking = 1;
			req.honey_lockip_time = sniper_nrule.honey_lockip_seconds;
		}
		zip_netin_package(&req, srcip, sport, dstip, dport);

		return NF_ACCEPT;
	}

	/* 端口扫描 */
	if (sniper_nrule.portscan_time) { /* 设置被扫描端口的时效，后面会按照扫描的IP归类 */
		req.flags.portscan = 1;
		if (trust == 1 || trust == 3) {
			req.flags.trust = 1;
		}
		req.flags.trust = (trust & 0x01);
		req.portscan_lockip_time = sniper_nrule.portscan_lock_time;
		req.effective_time = sniper_nrule.portscan_time;
		req.portscan_max = sniper_nrule.portscan_max;
		req.flags.locking = sniper_nrule.port_scan_lockip;
		if (sniper_nrule.port_scan_lockip) {
			req.flags.terminate = 1;
			if (depend_current_mode(NF_DROP) == NF_DROP) {
				sniper_add_lockip(srcip, NET_PORT_SCAN, sniper_nrule.portscan_lock_time*60);
			}
		}
		zip_netin_package(&req, srcip, sport, dstip, dport);
	}

	return NF_ACCEPT;
}

/* always in_softirq */
/* NF_INET_LOCAL_IN */
/* 有的版本与内核主线不符，可能打了补丁，如centos7.2-6
   故不能根据版本号来调整函数定义，改为直接取当前编译环境里的函数定义 */
static unsigned int local_in_hook(NF_HOOKFN_ARGS)
{
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	struct icmphdr *icmp_header = NULL;
	unsigned short sport = 0;
	unsigned short dport = 0;
	struct sniper_ip srcip = {{0}};
	struct sniper_ip dstip = {{0}};
	netreq_t req = {0};
	struct kern_net_rules nrule = {0};
	struct kern_process_rules prule = {0};
	int trust = 0;
	int tcp_watch = 1, udp_watch = 1, icmp_watch = 1;
#ifdef SKB_PTR_PTR
	struct sk_buff *myskb = *skb;
#else
	struct sk_buff *myskb = skb;
#endif

#ifndef HAVE_SKB_SET_TRANSPORT_HEADER
	struct tcphdr th;
	struct udphdr uh;
	struct icmphdr ih;
#endif

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

	ip_header = ip_hdr(myskb);

	sniper_addr2ip(&srcip, (unsigned char *)&ip_header->saddr);
	sniper_addr2ip(&dstip, (unsigned char *)&ip_header->daddr);

	if (tcp_watch && ip_header->protocol == IPPROTO_TCP) {
		if (skip_package(ip_header)) {
			return NF_ACCEPT;
		}

		req.flags.tcp = 1;
		req.flags.udp = 0;

		skb_set_transport_header(myskb, sizeof(struct iphdr));   
		tcp_header = tcp_hdr(myskb);

		dport = ntohs(tcp_header->dest);
		sport = ntohs(tcp_header->source);

		/* 总是允许与管控中心的消息通信 */
		if (is_server(sport, &srcip)) {
			return NF_ACCEPT;
		}

		/* 普通和运维模式下，隔离主机生效。学习模式下，不生效 */
		if (host_quarantine && client_mode != LEARNING_MODE) {
			return NF_DROP;
		}

		/* 检测特殊的端口扫描包，如FIN扫描、NULL扫描、Xmax扫描 */
		if (is_portscan_flag(tcp_header)) {
			trust = is_trustip(&srcip);
			/* 特殊扫描命中敏感端口既上报端口诱捕，也参加端口扫描超限的统计 */
			if (is_honeyport(dport, &srcip, &trust)) {
				check_portscan(ip_header, tcp_header, trust, 1,
					      &srcip, sport, &dstip, dport);
			}

			//TODO 特殊扫描，有就可以报告端口扫描事件，不像连接扫描需要累计次数做判断
			//     报告特殊扫描的类型
			/* 已经确定是特殊扫描，不需要再做更多其他检测 */
			return check_portscan(ip_header, tcp_header, trust, 0,
					      &srcip, sport, &dstip, dport);
		}

		/* 忽略out connection上的数据包 */
		/* 除了端口扫描的syn1ack0包，其他与本机非服务端口的通信，
		   视为out connection通信 */
		if (!is_service_port(dport)) { //不是服务端口
			/* 只关注连接包，其他是数据包 */
			if (!tcp_header->syn || tcp_header->ack) {
				return NF_ACCEPT;
			}
			/* 正常TCP连接的扫描与特殊扫描累计 */
			trust = is_trustip(&srcip);
			if (is_honeyport(dport, &srcip, &trust)) {
				check_portscan(ip_header, tcp_header, trust, 1,
						&srcip, sport, &dstip, dport);
			}
			check_portscan(ip_header, tcp_header, trust, 0, &srcip, sport, &dstip, dport);
		}
		/* 不用检查是否与管控中心的通信，此通信是个out connection */

		if (net_debug && (tcp_header->fin || tcp_header->rst || tcp_header->syn)) {
			print_package(&srcip, sport, &dstip, dport, ip_header, tcp_header, "==in");
		}

		/* 考察所有的包，以阻断已经存在的非法连接 */

		/* 禁止对方srcip访问本机dport端口 */
		/* 黑名单生效则必阻断 */
		/* 非白名单同黑名单处理，notwhite标志用于指示检测规则是白名单 */
		if (is_blackin_ip(dport, &srcip, SNIPER_TCP)) { 
			req.flags.blackin = 1;
		} else if (not_whitein_ip(dport, &srcip, &dstip, SNIPER_TCP)) {
			req.flags.notwhitein = 1;
		}
		if (req.flags.blackin || req.flags.notwhitein) {
			req.flags.terminate = 1;

			print_package(&srcip, sport, &dstip, dport, ip_header, tcp_header, "blackin");
			zip_netin_package(&req, &srcip, sport, &dstip, dport);
			return NF_DROP;
		}

		/* is_lockedip()检查ip是否已锁，解锁到期的ip */
		/* 已锁定的ip在学习和运维模式下继续阻断，要提前解锁，需手工解锁 */
		if (is_lockedip(&srcip)) {
			req.flags.lockedip = 1;
			req.flags.terminate = 1;
			/* 如果有锁定的ip，可能就会打印很多，因此不打印 */
			if (net_debug) {
				print_package(&srcip, sport, &dstip, dport, ip_header, tcp_header, "lockedip");
			}
			zip_netin_package(&req, &srcip, sport, &dstip, dport);
			return NF_DROP;
		}

		return NF_ACCEPT;
	}

	/* 普通和运维模式下，隔离主机生效。学习模式下，不生效 */
	if (host_quarantine && client_mode != LEARNING_MODE) {
		return NF_DROP;
	}

 	if (icmp_watch && ip_header->protocol == IPPROTO_ICMP) {
		if (skip_package(ip_header)) {
			return NF_ACCEPT;
		}

		skb_set_transport_header(myskb, sizeof(struct iphdr));   
		icmp_header = icmp_hdr(myskb);

		if (icmp_header->type == ICMP_ECHO) {
			/* 自己ping自己不打印。另外，ping黑名单域名时，
			   因黑名单域名解析成0.0.0.0，也变成ping自己 */
			if (net_debug) {
				myprintk("%d.%d.%d.%d ping me(%d.%d.%d.%d)\n",
					IPSTR(&srcip), IPSTR(&dstip));
			}
    			return NF_ACCEPT;
		}

		if (net_debug) {
			printk("ICMP In %d.%d.%d.%d -> %d.%d.%d.%d, type %d, code %d\n",
				IPSTR(&srcip), IPSTR(&dstip), icmp_header->type, icmp_header->code);
		}
    		return NF_ACCEPT;
	}

	if (udp_watch && ip_header->protocol == IPPROTO_UDP) {
		skb_set_transport_header(myskb, sizeof(struct iphdr));   
		udp_header = udp_hdr(myskb);

		dport = ntohs(udp_header->dest);
		sport = ntohs(udp_header->source);

		if (skip_package(ip_header)) {
			/* 发给本机DNS代理程序(如dnsmasq)的DNS查询包不过滤，否则不报告域名查询日志 */
			if (sport != 53) {
				return NF_ACCEPT;
			}
		}

		req.flags.udp = 1;
		req.flags.tcp = 0;

		/* 禁止对方srcip访问本机dport端口 */
		/* 黑名单生效则必阻断 */
		/* 非白名单同黑名单处理，notwhite标志用于指示检测规则是白名单 */
		if (is_blackin_ip(dport, &srcip, SNIPER_UDP)) {
			req.flags.blackin = 1;
		} else if (not_whitein_ip(dport, &srcip, &dstip, SNIPER_UDP)) {
			req.flags.notwhitein = 1;
		}
		if (req.flags.blackin || req.flags.notwhitein) {
			req.flags.terminate = 1;

			print_package(&srcip, sport, &dstip, dport, ip_header, NULL, "blackin");
			zip_netin_package(&req, &srcip, sport, &dstip, dport);
			return NF_DROP;
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

				nwords = ip_header->tot_len >> 1;
				buf = (unsigned short *)ip_header;
				ip_header->check = 0;
				ip_header->check = csum(buf, nwords);
			}
			return NF_ACCEPT;
		}

		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops local_in_ops =
{
    .hook = local_in_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST
};

/* 可能在softirq里，也可能不在softirq里，
 * 观察到发给管控的包就有很多在softirq里，不仅仅是失败重发才会在softirq里 */
/* NF_INET_LOCAL_OUT */
static unsigned int local_out_hook(NF_HOOKFN_ARGS)
{
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	unsigned short sport = 0;
	unsigned short dport = 0;
	struct sniper_ip srcip = {{0}};
	struct sniper_ip dstip = {{0}};
	netreq_t req = {0};
	struct kern_net_rules nrule = {0};
	struct kern_process_rules prule = {0};
	int tcp_watch = 0, udp_watch = 0, icmp_watch = 0;
	int miner_watch = 0;
#ifdef SKB_PTR_PTR
	struct sk_buff *myskb = *skb;
#else
	struct sk_buff *myskb = skb;
#endif

#ifndef HAVE_SKB_SET_TRANSPORT_HEADER
	struct tcphdr th;
	struct udphdr uh;
	//struct icmphdr ih;
#endif

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

	if (!now_in_interrupt) {
		int flags = 0;
		struct parent_info pinfo = {{{0}}};

		/* Skip sniper self */
		if (skip_current(&flags, &pinfo)) {
			return NF_ACCEPT;
		}
	}

	ip_header = ip_hdr(myskb);

	sniper_addr2ip(&srcip, (unsigned char *)&ip_header->saddr);
	sniper_addr2ip(&dstip, (unsigned char *)&ip_header->daddr);

	if (tcp_watch && ip_header->protocol == IPPROTO_TCP) {
		if (skip_package(ip_header)) {
			return NF_ACCEPT;
		}

		req.flags.tcp = 1;
		req.flags.udp = 0;

		skb_set_transport_header(myskb, sizeof(struct iphdr));   
		tcp_header = tcp_hdr(myskb);  

		dport = ntohs(tcp_header->dest);
		sport = ntohs(tcp_header->source);

		//TODO 判断是否为sniper相关程序，防止潮水攻击管控
		/* 总是允许与管控中心的日志通信 */
		if (is_server(dport, &dstip)) {
			return NF_ACCEPT;
		}

		/* 普通和运维模式下，隔离主机生效。学习模式下，不生效 */
		if (host_quarantine && client_mode != LEARNING_MODE) {
			return NF_DROP;
		}

		if (net_debug && !now_in_interrupt &&
		    (tcp_header->fin || tcp_header->rst || tcp_header->syn)) {
			print_package(&srcip, sport, &dstip, dport, ip_header, tcp_header, "out==");
		}

		/* 忽略in connection上的数据包 */ 
		if (is_service_port(sport)) {
			if (is_lockedip(&dstip)) {
				return NF_DROP;
			}

			return NF_ACCEPT;
		}

		/* 连出黑名单禁止访问远端dstip的端口dport */
		/* 黑名单生效则必阻断 */
		/* 非白名单同黑名单处理，notwhite标志用于指示检测规则是白名单 */
		if (is_blackout_ip(dport, &dstip, SNIPER_TCP)) {
			req.flags.blackout = 1;
		} else if (not_whiteout_ip(dport, &dstip, &srcip, SNIPER_TCP)) {
			req.flags.notwhiteout = 1;
		}
		if (req.flags.blackout || req.flags.notwhiteout) {
			req.flags.terminate = 1;

			if (!now_in_interrupt) {
				req.pid = current->pid;
				req.uid = currentuid();
				get_current_comm(req.comm, &req.exeino);

				report_netout_package(&req, &srcip, sport, &dstip, dport,
						      ip_header, tcp_header, "blackout");
			}
			return NF_DROP;
		}

		/* is_lockedip()检查ip是否已锁，解锁到期的ip */
		/* 已锁定的ip在学习和运维模式下继续阻断，要提前解锁，需手工解锁 */
		if (is_lockedip(&dstip)) {
			return NF_DROP;
		}

		return NF_ACCEPT;
 	}

	/* 普通和运维模式下，隔离主机生效。学习模式下，不生效 */
	if (host_quarantine && client_mode != LEARNING_MODE) {
		return NF_DROP;
	}

	if (udp_watch && ip_header->protocol == IPPROTO_UDP) {
		skb_set_transport_header(myskb, sizeof(struct iphdr));   
		udp_header = udp_hdr(myskb);

		dport = ntohs(udp_header->dest);
		sport = ntohs(udp_header->source);
		myndebug("udp out sport:%u, dport:%u\n", sport, dport);

		req.flags.udp = 1;
		req.flags.tcp = 0;

		/* 连出黑名单禁止访问远端dstip的端口dport */
		/* 黑名单生效则必阻断 */
		/* 非白名单同黑名单处理，notwhite标志用于指示检测规则是白名单 */
		if (is_blackout_ip(dport, &dstip, SNIPER_UDP)) {
			req.flags.blackout = 1;
		} else if (not_whiteout_ip(dport, &dstip, &srcip, SNIPER_UDP)) {
			req.flags.notwhiteout = 1;
		}
		if (req.flags.blackout || req.flags.notwhiteout) {
			req.flags.terminate = 1;

			if (!now_in_interrupt) {
				req.pid = current->pid;
				req.uid = currentuid();
				get_current_comm(req.comm, &req.exeino);

				report_netout_package(&req, &srcip, sport, &dstip, dport,
						      ip_header, NULL, "blackout");
			}

			return NF_DROP;
		}

		if (dport == 53) {
			char *dns_hdr = (char *)udp_header + sizeof(struct udphdr);

			handle_dns_query(dns_hdr, &nrule);
			return NF_ACCEPT;
		}

		return NF_ACCEPT;
	}

	if (icmp_watch && ip_header->protocol == IPPROTO_ICMP) {
		/* 非法连接互联网,阻断开关打开,只允许联接管制中心
		 * TODO 有攻击方式是通过ICMP传输数据 */
		return NF_ACCEPT;
	}

	if (net_debug && !now_in_interrupt &&
	    ip_header->protocol != IPPROTO_TCP &&
	    ip_header->protocol != IPPROTO_UDP &&
	    ip_header->protocol != IPPROTO_ICMP) {
		printk("===%s(%d) out===protocol %d: %d.%d.%d.%d -> %d.%d.%d.%d\n",
			current->comm, current->pid, ip_header->protocol,
			myaddr2ip(ip_header->saddr), myaddr2ip(ip_header->daddr));
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops local_out_ops =
{
    .hook = local_out_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST
};

static int net_on = 0;

int net_hook_init(void)
{
	if (!net_on) {
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

		net_on = 1;
		myprintk("net engine on\n");
	}

	return 0;
}

void net_hook_exit(void)
{
	if (net_on) {
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

		net_on = 0;
		myprintk("net engine off\n");
	}
}
