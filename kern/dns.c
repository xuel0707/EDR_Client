/*
 * 下面是一些域名相关的基础知识
 *
 * RR: Resource Record 资源记录
 *
 * DNS报文的数据格式是大端格式
 * 大端模式，是指数据的低字节保存在内存的高地址中，而数据的高字节，保存在内存的低地址中
 * 例1，一个short类型数0x1234，高字节是0x12，低字节是0x34，内存的摆放如下
 *  ------------------------------------------------------
 *  |          | 0xffffffff80000000 | 0xffffffff80000001 |
 *  ------------------------------------------------------
 *  | 大端格式 |        0x12        |        0x34        |
 *  ------------------------------------------------------
 *  | 小端格式 |        0x34        |        0x12        |
 *  ------------------------------------------------------
 * 例2，一个int类型数0x12345678
 *  ------------------------------------------------------------------------------------------------
 *  |          | 0xffffffff80000000 | 0xffffffff80000001 | 0xffffffff80000002 | 0xffffffff80000003 |
 *  ------------------------------------------------------------------------------------------------
 *  | 大端格式 |        0x12        |        0x34        |        0x56        |        0x78        |
 *  ------------------------------------------------------------------------------------------------
 *  | 小端格式 |        0x78        |        0x56        |        0x34        |        0x12        |
 *  ------------------------------------------------------------------------------------------------
 *
 *
 * DNS查询和应答报文的格式相同，如下所示
 *
 *  0                                                              31
 *  -----------------------------------------------------------------
 *  |        事务ID Transaction ID    |           标志Flags         |
 *  -----------------------------------------------------------------
 *  |        问题计数Questions        |  回答资源记录数Answers RRs  |
 *  -----------------------------------------------------------------
 *  | 权威名称服务器计数Authority RRs | 附加资源记录数Aditional RRs |
 *  -----------------------------------------------------------------
 *  |                     查询问题区域Quries                        |
 *  -----------------------------------------------------------------
 *  |                     回答问题区域Answers                       |
 *  -----------------------------------------------------------------
 *  |          权威名称服务器区域Authoritative nameservers          |
 *  -----------------------------------------------------------------
 *  |                附加信息区域Aditional records                  |
 *  -----------------------------------------------------------------
 *
 * 事务ID、标志、问题计数、回答资源记录数、权威名称服务器计数、附加资源记录数这6个字段是DNS的报文首部，共12个字节
 *
 * 事务ID：DNS报文的ID标识。对于请求报文和其对应的应答报文，该字段的值是相同的。通过它可以对应DNS应答报文是对哪个请求进行响应的
 *
 * 标志
 *  0    1        5    6    7    8    9   12      15
 *  ------------------------------------------------
 *  | QR | Opcode | AA | TC | RD | RA |  Z | rcode |
 *  ------------------------------------------------
 *
 * QR（Response）：查询请求/响应的标志信息。查询请求时，值为0；响应时，值为1。
 * Opcode：操作码。其中，0表示标准查询；1表示反向查询；2表示服务器状态请求。
 * AA（Authoritative）：授权应答。不用管
 * TC（Truncated）：表示是否被截断。不用管
 * RD（Recursion Desired）：期望递归。不用管
 * RA（Recursion Available）：可用递归。不用管
 * Z：保留字段
 * rcode（Reply code）：返回码字段，表示响应的差错状态。
 *                      当值为 0 时，表示没有错误；
 *                      当值为 1 时，表示报文格式错误（Format error），服务器不能理解请求的报文；
 *                      当值为 2 时，表示域名服务器失败（Server failure），因为服务器的原因导致没办法处理这个请求；
 *                      当值为 3 时，表示名字错误（Name Error），只有对授权域名解析服务器有意义，指出解析的域名不存在；
 *                      当值为 4 时，表示查询类型不支持（Not Implemented），即域名服务器不支持查询类型；
 *                      当值为 5 时，表示拒绝（Refused），一般是服务器由于设置的策略拒绝给出应答，如服务器不希望对某些请求者给出应答
 *
 *
 * 问题部分：通常只有一个问题。
 * 回答部分：可能有多个查询到的结果
 *
 * 问题部分和回答部分都是下面的格式
 *  ---------------------
 *  |    查询的域名     |
 *  ---------------------
 *  | 查询类型 | 查询类 |
 *  ---------------------
 * 查询类型：2个字节。DNS查询请求的资源类型。通常查询类型为A类型，值1，表示由域名获取对应的IP地址。类型CNAME，值5，获取域名别名。类型PTR，值12，反向查询
 * 查询类：2个字节。地址类型，通常为互联网地址，值为1
 *
 * DNS应答报文里也包含了问题部分
 *
 *
 * 一个DNS请求报文例子
 *   0000   a0 7d 01 00 00 01 00 00 00 00 00 00 03 77 77 77  .}...........www
 *   0010   03 31 36 33 03 63 6f 6d 00 00 01 00 01           .163.com.....
 *
 *   1. 头部(12B)
 *   ao 7d：标识
 *   01 00：标志字段中，QR置0，表示查询，RD置1，表示期望递归查询
 *   00 01：问题数为1
 *   00 00：资源记录数为0
 *   00 00：授权记录数为0
 *   00 00：额外资源记录数为0
 *
 *   2. 查询问题部分
 *   1) 查询名字段
 *   03 77 77 77 03 31 36 33 03 63 6f 6d 00
 *   03 77 77 77：03表示后面标识符有3个字符，77表示’w’ ,03 77 77 77 合起来：www
 *   03 31 36 33：03表示后面标识符有3个字符，31为’1’,36为’6’，33表示’3’,合起来：163
 *   03 63 6f 6d：03表示后面标识符有3个字符，63为’c’，6f为’o’，6d为’m’，合起来：com
 *   00：结束
 *   2) 查询类型 00 01
 *   00 01：type为A，表示期望获得域名的IP地址
 *   3) 查询类 00 01
 *   00 01：class为IN，表示互联网地址
 *
 *
 * 一个DNS应答报文例子
 *   0000   a0 7d 81 80 00 01 00 04 00 02 00 02 03 77 77 77  .}...........www
 *   0010   03 31 36 33 03 63 6f 6d 00 00 01 00 01 c0 0c 00  .163.com........
 *   0020   05 00 01 00 00 2a 2d 00 19 03 77 77 77 05 63 61  .....*-...www.ca
 *   0030   63 68 65 04 67 73 6c 62 07 6e 65 74 65 61 73 65  che.gslb.netease
 *   0040   c0 14 c0 29 00 01 00 01 00 00 00 27 00 04 79 c3  ...).......'..y.
 *   0050   b2 eb c0 29 00 01 00 01 00 00 00 27 00 04 79 c3  ...).......'..y.
 *   0060   b2 e9 c0 29 00 01 00 01 00 00 00 27 00 04 79 c3  ...).......'..y.
 *   0070   b2 ea c0 33 00 02 00 01 00 00 00 27 00 08 05 67  ...3.......'...g
 *   0080   73 6c 62 32 c0 38 c0 33 00 02 00 01 00 00 00 27  slb2.8.3.......'
 *   0090   00 08 05 67 73 6c 62 31 c0 38 c0 92 00 01 00 01  ...gslb1.8......
 *   00a0   00 00 45 d3 00 04 3d 87 ff 8f c0 7e 00 01 00 01  ..E...=....~....
 *   00b0   00 00 21 7b 00 04 dc b5 1c a8                    ..!{......
 *
 *   1. 头部(12B)
 *   a0 7d 81 80 00 01 00 04 00 02 00 02
 *   a0 7d：标识
 *   81 80：标志字段中，QR置1，表示响应；RD置1，在响应中返回；RA置1，表示名字服务器支持递归查询。
 *   00 01：问题数为1
 *   00 04：资源记录数为4
 *   00 02：授权记录数为2
 *   00 02：额外资源记录数为2
 *
 *   2. 查询问题部分(17B)
 *   0000                                       03 77 77 77  .}...........www
 *   0010   03 31 36 33 03 63 6f 6d 00 00 01 00 01
 *   03 77 77 77 03 31 36 33 03 63 6f 6d 00：域名为www.163.com
 *   00 01：查询类型为1
 *   00 01：查询类为1
 *
 *   3. 回答(37B)
 *   回答1：
 *   0000                                          c0 0c 00  .163.com........
 *   0020   05 00 01 00 00 2a 2d 00 19 03 77 77 77 05 63 61  .....*-...www.ca
 *   0030   63 68 65 04 67 73 6c 62 07 6e 65 74 65 61 73 65  che.gslb.netease
 *   0040   c0 14
 *   c0 0c：域名，采用压缩方法，表示从DNS报文开始处偏移0x0c即12个字节的内容：03 77 77 77 03 31 36 33 03 63 6f 6d 00 即：www.163.com
 *   00 05：查询类型为CNMAE（5），表示资源数据是另一主机的别名
 *   00 01：查询类为1
 *   00 00 2a 2d：生存时间（TTL）
 *   00 16：资源数据长度，值为25
 *   03 77 77 77 05 63 61 63 68 65 04 67 73 6c 62 07 6e 65 74 65 61 73 65 c0 14
 *   资源数据的前23个字节内容为：www.cache.gslb.netease
 *   后两个字节c0 14：压缩数据 ，表示从DNS报文开始处偏移0x14即20个字节的内容：03 63 6f 6d 即：com
 *   两部分连结起来即为：www.cache.gslb.netease.com
 *
 *   回答2：
 *   0040         c0 29 00 01 00 01 00 00 00 27 00 04 79 c3  ...).......'..y.
 *   0050   b2 eb
 *   c0 29：压缩数据，表示从DNS报文开始处偏移0x29即41个字节的内容：03 77 77 77 05 63 61 63 68 65 04 67 73 6c 62 07 6e 65 74 65 61 73 65 c0 14 即域名为：www.cache.gslb.netease.com
 *   00 01：查询类型为1
 *   00 01：查询类为1
 *   00 00 00 27：生存时间（TTL）
 *   00 04：资源数据长度为4
 *   79 c3 b2 eb：IP地址为121.195.178.235
 *
 *   回答3：
 *   0050         c0 29 00 01 00 01 00 00 00 27 00 04 79 c3  ...).......'..y.
 *   0060   b2 e9
 *   c0 29：压缩数据，表示从DNS报文开始处偏移0x29即41个字节的内容：03 77 77 77 05 63 61 63 68 65 04 67 73 6c 62 07 6e 65 74 65 61 73 65 c0 14即域名为：www.cache.gslb.netease.com
 *   00 01：查询类型为1
 *   00 01：查询类为1
 *   00 00 00 27：生存时间（TTL）
 *   00 04：资源数据长度为4
 *   79 c3 b2 e9：IP地址为121.195.178.233
 *
 *   回答4：
 *   0060         c0 29 00 01 00 01 00 00 00 27 00 04 79 c3  ...).......'..y.
 *   0070   b2 ea
 *   c0 29：压缩数据，表示从DNS报文开始处偏移0x29即41个字节的内容：03 77 77 77 05 63 61 63 68 65 04 67 73 6c 62 07 6e 65 74 65 61 73 65 c0 14即域名为：www.cache.gslb.netease.com
 *   00 01：查询类型为1
 *   00 01：查询类为1
 *   00 00 00 27：生存时间（TTL）
 *   00 04：资源数据长度为4
 *   79 c3 b2 ea：IP地址为121.195.178.234
 *
 */

#include "interface.h"
#include "dns.h"

#ifndef HFIXEDSZ
#define HFIXEDSZ 12
#endif

#ifndef RRFIXEDSZ
#define RRFIXEDSZ 10
#endif

#ifndef T_A
#define T_A     1  //Host address
#define T_AAAA 28  //Ip6 Address
#endif

/* 域名只有黑白名单和过滤名单，无可信名单 */
#define DNS_MINEPOOL        0x1
#define DNS_MINEPOOL_DROP   0x2
#define DNS_MINEPOOL_LOCKIP 0x4
#define DNS_MINER_TERMINATE 0x8
#define DNS_BLACK           0x10
#define DNS_BLACK_DROP      0x20
#define DNS_INTERNET        0x40
#define DNS_INTERNET_DROP   0x80
#define DNS_PROXY           0x100
#define DNS_FILTER          0x200

void decode_header(unsigned char *data, struct resolv_header *h)
{
	h->id = (data[0] << 8) | data[1];
	h->qr = (data[2] & 0x80) ? 1 : 0;
	h->opcode = (data[2] >> 3) & 0x0f;
	h->aa = (data[2] & 0x04) ? 1 : 0;
	h->tc = (data[2] & 0x02) ? 1 : 0;
	h->rd = (data[2] & 0x01) ? 1 : 0;
	h->ra = (data[3] & 0x80) ? 1 : 0;
	h->rcode = data[3] & 0x0f;
	h->qdcount = (data[4] << 8) | data[5];
	h->ancount = (data[6] << 8) | data[7];
	h->nscount = (data[8] << 8) | data[9];
	h->arcount = (data[10] << 8) | data[11];
}

void extract_dns_request(struct dnsquery *dns_query, char *request)
{
	unsigned int i, j, k;
	char *curr = dns_query->qname;
	unsigned int size;

	size = curr[0];

	j = 0;
	i = 1;
	while (size > 0) {
		for(k = 0; k < size; k++) {
			request[j++] = curr[i+k];
		}
		request[j++] = '.';
		i += size;
		size = curr[i++];
	}

	if (j > 1) {
		request[--j] = '\0';
	}
}

static int length_question(const unsigned char *data, int maxlen)
{
	const unsigned char *start;
	unsigned int b;

	if (!data)
		return -1;

	start = data;
	for (;;) {
		if (maxlen <= 0)
			return -1;
		b = *data++;
		if (b == 0)
			break;
		if ((b & 0xc0) == 0xc0) {
			/* It's a "compressed" name. */
			data++; /* skip lsb of redirected offset */
			maxlen -= 2;
			break;
		}
		data += b;
		maxlen -= (b + 1); /* account for data + + above */
	}
	/* Up to here we were skipping encoded name */

	/* Account for QTYPE and QCLASS fields */
	if (maxlen < 4)
		return -1;
	return data - start + 2 + 2;
}

static int decode_dotted(const unsigned char *packet, int offset, int packet_len, char *dest, int dest_len)
{
	unsigned int b, total = 0, used = 0;
	int measure = 1;
	int offset0 = offset;
	time_t start = sniper_uptime(), now = start;

	if (!packet)
		return -1;

	for (;;) {
		/* 20220907 在一个k8s node上出现soft lockup 22s, rip寄存器值在decode_answer里
		   猜测可能数据有错导致此处循环时间过长了，为了避免soft lockup，限制循环时间不超过2s */
		now = sniper_uptime();
		if (now - start >= 2) {
			myprintk("dns decode_dotted failed as >2s，offset %d, packet_len %d\n", offset0, packet_len);
			return -1;
		}

		if (offset >= packet_len)
			return -1;
		b = packet[offset++];
		if (b == 0)
			break;

		if (measure)
			total++;

		if ((b & 0xc0) == 0xc0) {
			if (offset >= packet_len)
				return -1;
			if (measure)
				total++;
			/* compressed item, redirect */
			offset = ((b & 0x3f) << 8) | packet[offset];
			measure = 0;
			continue;
		}

		if (used + b + 1 >= dest_len || offset + b >= packet_len)
			return -1;
		memcpy(dest + used, packet + offset, b);
		offset += b;
		used += b;

		if (measure)
			total += b;

		if (packet[offset] != 0)
			dest[used++] = '.';
		else
			dest[used++] = '\0';
	}

	if (measure)
		total++;

	return total;
}

static int decode_answer(unsigned char *message, int offset, int len, struct resolv_answer *a)
{
	int i;

	i = decode_dotted(message, offset, len, a->dotted, sizeof(a->dotted));
	if (i < 0)
		return i;

	message += offset + i;
	len -= i + RRFIXEDSZ + offset;
	if (len < 0)
		return len;

	a->atype = (message[0] << 8) | message[1];
	message += 2;
	a->aclass = (message[0] << 8) | message[1];
	message += 2;
	a->ttl = (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | (message[3] << 0);
	message += 4;
	a->rdlength = (message[0] << 8) | message[1];
	message += 2;
	a->rdata = message;
	a->rdoffset = offset + i + RRFIXEDSZ;

	if (len < a->rdlength)
		return -1;
	return i + RRFIXEDSZ + a->rdlength;
}

static char *inet_ntop4(struct in_addr *addr, char *buf, int buf_len)
{
	uint8_t *a = (uint8_t *)addr;

	snprintf(buf, buf_len, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);

	return buf;
}

static char *inet_ntop6(struct in6_addr *addr, char *buf, int buf_len)
{
	int i = 0;
	char *obuf = buf;
	uint8_t *a = (uint8_t *)addr;

	for (i = 0; i < 16; i++) {
		if (buf_len < 2) {
			return 0;        /* can't convert */
		}
		snprintf(buf, buf_len, "%02x", a[i]);
		buf += 2;
		buf_len -= 2;
		if (i > 0 && i < 15 && i % 2 == 1){
			if (buf_len < 1) {
				return 0;
			}
			buf[0] = ':';
			buf++;
			buf_len--;
		}
	}
	if (buf_len < 1) {
		return 0;
	}
	buf[0] = 0;
	return obuf;
}

static char *my_inet_ntop(int af, const void *addr, char *buf, int len)
{
	switch(af){
		case AF_INET:
			return inet_ntop4((struct in_addr *)addr, buf, len);
		case AF_INET6:
			return inet_ntop6((struct in6_addr *)addr, buf, len);
	}
	return NULL;
}

#define DOMAIN_CACHE_NUM 256
int next_domain_cache = 0;
struct domain_cache {
	char domain[S_DOMAIN_NAMELEN];
	char ip[S_IPLEN];
} domain_cache[DOMAIN_CACHE_NUM] = {{{0}}};

static void cache_domain_ip(char *domain, char *ip)
{
	int i = 0;

	write_lock(&domain_cache_lock);
	for (i = 0; i < DOMAIN_CACHE_NUM; i++) {
		if (domain_cache[i].domain[0] == 0) {
			break;
		}
		if (strcmp(domain_cache[i].domain, domain) == 0 &&
		    strcmp(domain_cache[i].ip, ip) == 0) {
			write_unlock(&domain_cache_lock);
			return;
		}
	}
	i = next_domain_cache;
	snprintf(domain_cache[i].domain, sizeof(domain_cache[i].domain), "%s", domain);
	snprintf(domain_cache[i].ip, sizeof(domain_cache[i].ip), "%s", ip);
	next_domain_cache = (i + 1) & 0xff;
	write_unlock(&domain_cache_lock);
}

static void get_domain_ip_from_cache(char *domain, char *ip, int ip_len)
{
	int i = 0;

	if (!read_trylock(&domain_cache_lock)) {
		myprintk("trylock domain_cache fail, skip get %s ip\n", domain);
		snprintf(ip, ip_len, "0.0.0.0");
		return;
	}
	for (i = 0; i < DOMAIN_CACHE_NUM; i++) {
		/* 域名数组已经搜索完 */
		if (domain_cache[i].domain[0] == 0) {
			snprintf(ip, ip_len, "0.0.0.0");
			break;
		}

		/* 找到域名 */
		if (strcmp(domain_cache[i].domain, domain) == 0) {
			snprintf(ip, ip_len, "%s", domain_cache[i].ip);
			break;
		}
	}
	read_unlock(&domain_cache_lock);
}

static int report_domain(dnsqinfo_t *info, char *ip, char *name, const int type)
{
	int size = 0;
	netreq_t req = {0};

	/* 本地dns代理程序不报，只报真正要使用域名的程序 */
	if (info->flags & DNS_PROXY) {
		return 0;
	}
	if (info->flags & DNS_FILTER) {
		return 0;
	}

/* 理论上域名应有缓冲，不会反复解析，但观察到有反复解析，
   且有多个线程同时解析相同域名的情况，故还是需要压缩，但在应用层做 */
#if 0
	req.repeat = zip_dnsmsg(dns, 1);
	if (req.repeat) {
		return;
	}
#endif

	req.uid = info->uid;

	req.pid = info->pid;
	snprintf(req.comm, sizeof(req.comm), "%s", info->comm);
	req.proctime = info->proctime;
	sniper_do_gettimeofday(&req.event_tv);

	req.flags.domain = 1;
	if (info->flags & DNS_BLACK) {
		req.flags.blackdomain = 1;
		if (info->flags & DNS_BLACK_DROP) {
			req.flags.blackdomain_terminate = 1;
			req.flags.terminate = 1;
		}
	}

	if (info->flags & DNS_MINEPOOL) {
		req.flags.minepool = 1;
		if (info->flags & DNS_MINEPOOL_DROP) {
			req.flags.minepool_terminate = 1;
			req.flags.terminate = 1;
			if (info->flags & DNS_MINEPOOL_LOCKIP) {
				req.flags.locking = 1;
			}
		}
	}

	req.repeat = 1;
	req.domain_query_type = type;

	if (strcmp(ip, "0.0.0.0") == 0) {
		get_domain_ip_from_cache(info->domain, req.ip, sizeof(req.ip));
	} else {
		snprintf(req.ip, sizeof(req.ip), "%s", ip);
	}

	snprintf(req.domain, sizeof(req.domain), "%s", info->domain);
	size = sizeof(netreq_t) - S_DOMAIN_NAMELEN;
	req.size = size + strlen(req.domain) + 1;

	send_msg_to_user((char *)&req, req.size, nl_net_pid);

	return req.flags.terminate;

#if 0 
	//TODO 暂不报域名别名
	if (strcmp(info->domain, name) != 0) {
		snprintf(req.domain, sizeof(req.domain), "%s", name);
		req.size = size + strlen(req.domain) + 1;
		send_msg_to_user((char *)&req, req.size, nl_net_pid);
	}
#endif

}


static int in_domaintbl(char *domain, domaintbl_t *tbl, int count, char *tblname)
{
	int i = 0;

	if (!domain) {
		myndebug("not in %s domaintbl: null domain\n", tblname);
		return 0;
	}
	if (!tbl) {
		myndebug("not in %s domaintbl: domain %s, no tbl\n", tblname, domain);
		return 0;
	}

	myndebug("%s domain table count %d\n", tblname, count);
	for (i = 0; i < count; i++) {
		myndebug2(NDEBUG_DOMAINLIST, "domain compare %d: =%s=, =%s=\n", i, tbl[i].domain, domain);
		if (strstr(domain, tbl[i].domain)) {
			myndebug("%s domain %d match\n", tblname, i);
			return 1;
		}
	}
	myndebug("no %s domain match\n", tblname);
	return 0;
}

static void check_dns_event(dnsqinfo_t *info, struct sniper_ip *ip,
			    int af, struct kern_net_rules *nrule)
{
	if (af == AF_INET) {
		if (info->flags & DNS_MINEPOOL_LOCKIP) {
			sniper_add_lockip(ip, PROCESS_MINERWARE, sniper_prule.miner_lockip_seconds);
		}
	}

	read_lock(&sniper_ndns_lock);

	/* 检查DNS黑名单 */
	if (in_domaintbl(info->domain, sniper_ndnsblack, sniper_ndnsblack_count, "dnsblack")) {
		info->flags |= DNS_BLACK;
		info->flags |= DNS_BLACK_DROP;
		read_unlock(&sniper_ndns_lock);
		return;
	}

	/* 检查DNS白名单 */
	if (sniper_ndnswhite && sniper_ndnswhite_count > 0) { /* 有白名单 */
		if (!in_domaintbl(info->domain, sniper_ndnswhite, sniper_ndnswhite_count, "dnswhite")) {
			/* 不在白名单中，视为黑名单 */
			info->flags |= DNS_BLACK;
			info->flags |= DNS_BLACK_DROP;
			read_unlock(&sniper_ndns_lock);
			return;
		}
	}

	/* 域名过滤名单 */
	if (in_domaintbl(info->domain, sniper_ndnsfilter, sniper_ndnsfilter_count, "dnsfilter")) {
		info->flags |= DNS_FILTER; //放行, 但不报日志
		read_unlock(&sniper_ndns_lock);
		return;
	}

	read_unlock(&sniper_ndns_lock);

//TODO 检查进程过滤
}

/* return 1 修改了dns包内容; 0 没有修改 */
int handle_dns_answer(char *dns_hdr, int udp_len, struct kern_net_rules *nrule)
{
	struct resolv_header answer_header = {0};
	struct resolv_answer answer = {{0}};
	char ipstr[S_IPLEN] = {0};
	int pos, i, size, af, ret = 0;
	int in_addr_size = sizeof(struct in_addr);
	int in6_addr_size = sizeof(struct in6_addr);
	dnsqinfo_t *dnsinfo = NULL, *info = NULL, *tmp = NULL;
	struct sniper_ip ip = {{0}};
	int answer_pos = 0, change = 0;

	decode_header(dns_hdr, &answer_header);
	if (!answer_header.qr || answer_header.rcode || answer_header.ancount <= 0) {
		return 0;
	}

	pos = HFIXEDSZ;
	for (i = 0; i < answer_header.qdcount; i++) {
		if (pos >= udp_len || pos < 0) {
			return 0;
		}

		size = length_question(dns_hdr + pos, udp_len - pos);
		if (size < 0) {
			return 0;
		}
		pos += size;
	}

	answer_pos = pos;
	for (i = 0; i < answer_header.ancount; i++) {
		if (pos >= udp_len || pos < 0) {
			return 0;
		}

		size = decode_answer(dns_hdr, pos, udp_len, &answer);
		if (size < 0) {
			if (i && answer_header.tc) {
				break;
			}
			return 0;
		}
		pos += size;

		if (!(answer.atype == T_A && answer.rdlength == in_addr_size) &&
		    !(answer.atype == T_AAAA && answer.rdlength == in6_addr_size)) {
			continue;
		}

		af = answer.atype == T_A ? AF_INET : AF_INET6;
		if (!my_inet_ntop(af, answer.rdata, ipstr, S_IPLEN)) {
			printk("inet_ntop error\n");
			continue;
		}

		if (mem_debug == KMALLOC_DNSQUERY) {
			myprintk("%s(%d): %s -- %s. id %x\n",
				current->comm, current->pid, answer.dotted, ipstr, answer_header.id);
		}

		if (af == AF_INET) {
			ipstr2ip(ipstr, &ip);
		}

		if (!dnsinfo) {
			write_lock(&sniper_ndnsquery_lock);
			list_for_each_entry_safe(info, tmp, &dnsqlist.queue, list) {
				if (info->id == answer_header.id) {
					list_del(&info->list);
					dnsinfo = info;
					break;
				}
			}
			write_unlock(&sniper_ndnsquery_lock);
		}

		if (dnsinfo) {
			/* 对于查询到的别名，不单独检查事件，和域名同事件 */
			check_dns_event(dnsinfo, &ip, af, nrule);

			//TODO 暂时不报ipv6地址的
			if (af == AF_INET) {
				ret = report_domain(dnsinfo, ipstr, answer.dotted, answer.atype);
			}

			if (ret) {
				if (ipstr[0]) {
					cache_domain_ip(dnsinfo->domain, ipstr);
				}
				/* 去清除域名解析结果 */
				if (client_mode == NORMAL_MODE) { /* 正常模式 */
					change = 1;
				} else { /* 运维或学习模式 */
					change = 0;
				}
				break;
			}

			//TODO 只报告一个ip，后面考虑如何全报并压缩日志
			if (ipstr[0]) {
				break;
			}
		}
	}

	/* 一个域名可能有多个ip，处理所有ip后，释放查询包 */
	if (dnsinfo) {
		if (mem_debug == KMALLOC_DNSQUERY) {
			myprintk("%s(%d) free cached dns %s\n", current->comm, current->pid, dnsinfo->domain);
		}
		sniper_kfree(dnsinfo, sizeof(dnsqinfo_t), KMALLOC_DNSQUERY);
	}

	if (!change) {
		return 0;
	}

	/* 清除域名解析结果 */
	pos = answer_pos;
	for (i = 0; i < answer_header.ancount; i++) {
		if (pos >= udp_len || pos < 0) {
			break;
		}

		size = decode_answer(dns_hdr, pos, udp_len, &answer);
		if (size < 0) {
			break;
		}
		pos += size;

		memset(answer.rdata, 0, answer.rdlength);
	}
	return 1;
}

static int i_am_dnsproxy(struct kern_net_rules *nrule)
{
	if (nrule->local_dnsproxy &&
	    current->pid == nrule->dnsproxy_pid &&
	    strcmp(current->comm, nrule->dnsproxy) == 0) {
		return 1;
	}
	return 0;
}

#if 0
/* 返回0，压缩不报日志；>0，返回压缩包的数量供上报 */
static int check_msgdnsinfo_report(char *dns, int terminate)
{
	msgdnsinfo_t *info = NULL, *tmp = NULL;
	time_t now = sniper_uptime();
	int repeat = 0;

	list_for_each_entry_safe(info, tmp, &dnsmsglist.queue, list) {
		if (info->uid == currentuid() &&
		    info->terminate == terminate &&
		    strcmp(info->dns, dns) == 0 &&
		    strcmp(info->comm, current->comm) == 0) {
			/* 压缩期内仅计数加1，不报日志 */
			info->repeat++;
			repeat = info->repeat;

			/* 压缩期外，返回压缩次数，并重置计数和计时 */
			if (now - info->last_report_time >= ZIPTERM) {
				sniper_do_gettimeofday(&info->last_report_tv);
				info->last_report_time = now;
				info->repeat = 0;
				return repeat;
			}

			return 0;
		}

		/* 不是要找的目标，但其超过压缩期，报日志，并释放空间 */
		if (now - info->last_report_time >= ZIPTERM) {
			list_del(&info->list);
			/* 一分钟内没有重复的，本目标已报过，不重复报 */
			if (info->repeat) {
				report_msgdnsinfo(info);
			}
			sniper_kfree(info, sizeof(dnsqinfo_t), KMALLOC_DNSQUERY);
		}
	}

	info = (msgdnsinfo_t *)kmalloc(sizeof(msgdnsinfo_t), GFP_ATOMIC);
	if (!info) {
		myprintk("%s(%d) cache dns %s msg fail: no memory!\n",
			current->comm, current->pid, request);
		/* 虽然没有缓存成功，但仍然可以上报日志的 */
		return 1;
	}
	info->pid = current->pid;
	info->proctime = get_process_time(current);
	info->repeat = 1;
	info->terminate = terminate;
	info->last_report_time = now;
	sniper_do_gettimeofday(&info->last_report_tv);
	snprintf(info->comm, sizeof(info->comm), "%s", current->comm);
	snprintf(info->dns, sizeof(info->dns), "%s", dns);
	list_add_tail(&info->list, &iplist->queue);
	return 1;
}

static int zip_dnsmsg(char *dns, int terminate)
{
	int repeat = 0;

	write_lock(&dnsmsglist.lock);
	repeat = check_msgdnsinfo_report(dns, terminate);
	write_unlock(&dnsmsglist.lock);

	return repeat;
}
#endif

/* check_miner里已经确认了要监测挖矿，此处不重复确认 */
static void report_miner(int flags, char *domain)
{
	char *ptr = NULL;
	int trust = 0, len = 0;
	taskreq_t *req = NULL;

	myndebug("report_miner %s(%d) uid:%d %s\n",
		current->comm, current->pid, currentuid(), domain ? domain : "");

	req = init_taskreq(INIT_WITH_PINFO|INIT_WITH_CMD);
	if (!req) {
		return;
	}

	req->flags |= PSR_MINER;
	req->pflags.minepool = 1;

	if (is_filter_cmd(req, NULL)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	trust = is_trust_cmd(req, EVENT_Mining, NULL, NULL);
	if (!trust && sniper_prule.miner_kill && client_mode == NORMAL_MODE) {
		if (flags & DNS_MINER_TERMINATE) {
			req->flags |= PSR_STOPED;
			req->pflags.terminate = 1;
		}
		if (flags & DNS_MINEPOOL_LOCKIP) {
			req->pflags.locking = 1;
		}
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;

	/* 将矿池域名附在请求包的尾部传出 */
	if (domain) {
		len = strlen(domain);
		if (len > ARGS_LEN - req->size - 1) {
			len = ARGS_LEN - req->size - 1;
		}

		ptr = &req->args + req->cmdlen + req->argslen + req->cwdlen + 3;
		memcpy(ptr, domain, len);
		req->size += len+1; //包大小加上域名长度（含结尾的0）
	}

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	send_msg_to_user((char *)req, req->size, nl_exec_pid);

	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
}

static int check_minepool(char *domain, struct kern_net_rules *nrule)
{
	int miner_kill = 0, miner_lockip = 0, flags = 0;

	if (!nl_exec_pid) {
		return 0;
	}

	myndebug("process_engine_on %d, miner_on %d\n", sniper_prule.process_engine_on, sniper_prule.miner_on);
	if (!process_engine_status() || !sniper_prule.miner_on) {
		return 0;
	}
	miner_kill = sniper_prule.miner_kill;
	miner_lockip = sniper_prule.miner_lockip;

	read_lock(&sniper_pminepool_lock);
	if (in_domaintbl(domain, sniper_pminepool, sniper_pminepool_count, "minepool")) {
		myndebug("%s(%d) access minepool %s\n", current->comm, current->pid, domain);
		flags = DNS_MINEPOOL;
		if (miner_kill) {
			flags |= DNS_MINEPOOL_DROP | DNS_MINER_TERMINATE;
		}
		if (miner_lockip) {
			flags |= DNS_MINEPOOL_LOCKIP;
		}
	}
	read_unlock(&sniper_pminepool_lock);

	return flags;
}

void clean_expired_dnsquery(void)
{
	int size = sizeof(dnsqinfo_t);
	dnsqinfo_t *info = NULL, *tmp = NULL;
	time_t now = sniper_uptime();

	write_lock_bh(&sniper_ndnsquery_lock);
	list_for_each_entry_safe(info, tmp, &dnsqlist.queue, list) {
		/* 释放超过一分钟没应答的域名请求缓存，避免内存泄漏 */
		if (now - info->queryt > 60) {
			list_del(&info->list);
			report_domain(info, "0.0.0.0", info->domain, T_A);
			if (mem_debug == KMALLOC_DNSQUERY) {
				myprintk("%s(%d) free dns %s, cached time > 60s\n",
					current->comm, current->pid, info->domain);
			}
			sniper_kfree(info, size, KMALLOC_DNSQUERY);
		}
	}
	write_unlock_bh(&sniper_ndnsquery_lock);
}

/* 被阻断的dns直接报告了，不会插入队列等待与ip配对
   black表示dns在黑名单里，但当前运维或学习模式只告警不阻断
   id用于与answer的id匹配，确认回答是本查询的回答 */
static void add_dnsquery_queue(char *domain, unsigned short id, int flags)
{
	int skip = 0, size = sizeof(dnsqinfo_t);
	dnsqinfo_t *info = NULL, *tmp = NULL;
	time_t now = sniper_uptime();

	if (sniper_badptr(domain)) {
		return;
	}

	write_lock_bh(&sniper_ndnsquery_lock);
	list_for_each_entry_safe(info, tmp, &dnsqlist.queue, list) {
		/* 忽略同一个进程对域名的重复查询 */
		if (info->pid == current->pid && strcmp(info->domain, domain) == 0) {
			skip = 1;
			continue;
		}

		/* 释放超过一分钟没应答的域名请求缓存，避免内存泄漏 */
		if (now - info->queryt > 60) {
			list_del(&info->list);
			report_domain(info, "0.0.0.0", info->domain, T_A);
			if (mem_debug == KMALLOC_DNSQUERY) {
				myprintk("%s(%d) free dns %s, cached time > 60s\n",
					current->comm, current->pid, domain);
			}
			sniper_kfree(info, size, KMALLOC_DNSQUERY);
			continue;
		}
	}
	write_unlock_bh(&sniper_ndnsquery_lock);
	if (skip) {
		return;
	}

	info = sniper_kmalloc(sizeof(dnsqinfo_t), GFP_ATOMIC, KMALLOC_DNSQUERY);
	if (!info) {
		myprintk("%s(%d) cache dns %s fail: no memory!\n",
			 current->comm, current->pid, domain);
		return;
	}
	if (mem_debug == KMALLOC_DNSQUERY) {
		myprintk("%s(%d) cache dns %s\n", current->comm, current->pid, domain);
	}

	info->uid = currentuid();
	info->id = id;
	info->flags = flags;
	info->queryt = sniper_uptime();
	snprintf(info->domain, sizeof(info->domain), "%s", domain);
	info->pid = current->pid;
	info->proctime = get_process_time(current);
	get_current_comm(info->comm, NULL);

	/* 插入队列dnsqlist尾部 */
	write_lock_bh(&sniper_ndnsquery_lock);
	list_add_tail(&info->list, &dnsqlist.queue);
	write_unlock_bh(&sniper_ndnsquery_lock);
}

/* 必须要在out hook里取查询的域名，因为回答的可能是该域名的别名，
   这里不取，in的时候可能会漏过一些名单上的域名 */
void handle_dns_query(char *dns_hdr, struct kern_net_rules *nrule)
{
	int flags = 0;
	struct dnsquery dns_query = {0};
	char domain[S_DOMAIN_NAMELEN] = {0};
	struct resolv_header query_header = {0};
	unsigned long now_in_interrupt = in_interrupt();

	decode_header(dns_hdr, &query_header);
	/* qr 0查询，1应答，opcode 0标准查询，1反向查询
	   只处理正向标准查询 */
	if (query_header.qr != 0 || query_header.opcode != 0) {
		return;
	}

	dns_query.qname = dns_hdr + sizeof(struct dnshdr);
	extract_dns_request(&dns_query, domain);

	/* 过滤一些遇到的特殊域名
	   如mail，是sendmail未配置邮件服务器时用的初始虚假域名
	   in-addr.arpa是反向查询 */
	if (strcmp(domain, "local") == 0 ||
	    strcmp(domain, "mail") == 0 ||
	    strstr(domain, "in-addr.arpa")) {
		return;
	}
	myndebug("handle_dns_query %s\n", domain);

	/*
	 * 1、挖矿监控关闭，flags = 0
	 * 2、挖矿监控开着
	 *    2.1、命中矿池，报告挖矿日志
	 *         flags是(DNS_MINEPOOL,DNS_MINEPOOL_DROP,DNS_MINEPOOL_LOCKIP,
	 *                 DNS_MINER_TERMINATE)的组合
	 *    2.2、未命中矿池，flags = 0
	 */
	flags = check_minepool(domain, nrule);

	/* dns代理不报日志不阻断，但该禁domain禁domain，该锁ip锁ip */
	if (i_am_dnsproxy(nrule)) {
		flags |= DNS_PROXY;
	} else if (flags & DNS_MINEPOOL && !now_in_interrupt) {
		report_miner(flags, domain);
	}

	/* 不监控DNS，且不防御矿池 */
	if (!nrule->dns_watch && !(flags & DNS_MINEPOOL_DROP)) {
		return;
	}

	/* 将domain加入dns查询缓存队列，
	   后面查询到结果时报告日志，或阻断，或锁ip */
	/* 对于矿池，如果策略设置为阻断则总是禁止访问，对于可信进程也禁止访问，但不杀进程 */
	/* 不缓存中断态的dns查询，可能是系统自动重试 */
	if (!now_in_interrupt) {
		add_dnsquery_queue(domain, query_header.id, flags);
	}

	/* 由用户层检测是否可信进程及阻断 */
}
