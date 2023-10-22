#include <ifaddrs.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>

#include "header.h"

char hostname[S_NAMELEN] = {0};
char os_dist[S_NAMELEN] = {0};
char host_sku[S_UUIDLEN+1] = {0};
char host_mac[S_IPLEN] = {0};
char host_ip[S_IPLEN] = {0};
serverconf_t Serv_conf = {0};

char sysname[16] = "Linux";

/* return -1 error, 0 success */
static int get_release_from_file(const char *filename, char *dist, int dist_len, const char *keystr)
{
	char *line = NULL;
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0};
	int len = 0, keylen = 0, found = 0;

	MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get release from %s\n", filename);

	snprintf(dist, dist_len, "Linux");

	fp = fopen(filename, "r");
	if (!fp) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "open %s error: %s\n", filename, strerror(errno));
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		line = skip_headspace(buf);
		if (*line == '#' || *line == 0) { //忽略空行和注释行
			continue;
		}

		if (!keystr) {
			found = 1;
			break;
		}
		keylen = strlen(keystr);
		if (strncmp(buf, keystr, keylen) == 0) {
			line += keylen;
			found = 1;
			break;
		}
	}
	fclose(fp);

	if (!found) {
		return -1;
	}

	delete_tailspace(line);

	/* 消除头部的无效字符 */
	while (*line != 0) {
		if (*line == ' ' || *line == '\t' || *line == '"' || *line == '=') {
			line++;
			continue;
		}

		break;
	}

	/* 消除尾部的双引号 */
	len = strlen(line);
	if (len == 0) {
		return -1;
	}
	if (line[len-1] == '"') {
		line[len-1] = 0;
	}

	/* 再次消除尾部的空格 */
	delete_tailspace(line);
	len = strlen(line);
	if (len == 0) {
		return -1;
	}

#ifdef KYLIN
	/*
	 * 管控中心显式发行版信息，做了处理，使CentOS x.y显式为CentOSx，目的是为了便于统计操作系统类型
	 * 对于Kylin 4.0.2这样的，就显示成了Kylin4，客户希望还是显示Kylin 4.0.2，故做此临时处理
	 */
	//TODO 针对不同os类型处理，或为管控中心增加一个os类型字段，或管控中心自行增加一个os类型字段
	int i = 0;
	while (*line != 0) {
		if (*line != ' ') {
			dist[i] = *line;
			i++;
		}
		line++;
	}
#else
	/* 如果发行版信息中未带Linux字样，则添加Linux，以显式表明这是Linux系统 */
	if (!strstr(line, "linux") && !strstr(line, "Linux") && !strstr(line, "LINUX")) {
		snprintf(dist, dist_len, "%s %s", line, sysname);
	} else {
		snprintf(dist, dist_len, "%s", line);
	}
#endif

	MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "os dist: %s\n", dist);

	return 0;
}

/* 获取系统的release信息 */
int get_os_release(char *dist, int dist_len)
{
	if (access("/etc/neokylin-release", F_OK) == 0 &&
	    get_release_from_file("/etc/neokylin-release", dist, dist_len, NULL) == 0) {
		return 0;
	}

	if (access("/etc/system-release", F_OK) == 0 &&
	    get_release_from_file("/etc/system-release", dist, dist_len, NULL) == 0) {
		return 0;
	}

	if (access("/etc/centos-release", F_OK) == 0 &&
	    get_release_from_file("/etc/centos-release", dist, dist_len, NULL) == 0) {
		return 0;
	}

	if (access("/etc/redhat-release", F_OK) == 0 &&
	    get_release_from_file("/etc/redhat-release", dist, dist_len, NULL) == 0) {
		return 0;
	}

	if (access("/etc/lsb-release", F_OK) == 0 &&
	    get_release_from_file("/etc/lsb-release", dist, dist_len, "DISTRIB_DESCRIPTION=") == 0) {
		return 0;
	}

	if (access("/etc/os-release", F_OK) == 0 &&
	    get_release_from_file("/etc/os-release", dist, dist_len, "PRETTY_NAME=") == 0) {
		return 0;
	}

	return -1;
}

/* 读取文件中记录的sku信息 */
int get_sku(char sku[S_UUIDLEN+1])
{
	int fd = 0, ret = 0, size = S_UUIDLEN;
	struct stat st = {0};

	fd = open(SKUFILE, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		return -1;
	}

	/**/
	if (st.st_size < 33) {
		size = 32;
	}
	ret = read(fd, sku, size);
	close(fd);

	if (ret == size) {
		return 0;
	} else {
		return -1;
	}
}

void sniper_addr2ip(struct sniper_ip *ip, unsigned char *addr)
{
	ip->ip[0] = addr[0];
	ip->ip[1] = addr[1];
	ip->ip[2] = addr[2];
	ip->ip[3] = addr[3];
}

/* 获取当前使用的网卡信息 */
int get_current_ethinfo(void)
{
	int i = 0, j = 0, sockfd = 0, count = 0, size = 0, ethnum = 0;
	int numreqs = 30;
	struct ifconf ifc = {0};
	struct ifreq *ifr = NULL;
	struct sniper_ethinfo *info = NULL;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "check ip create socket failed!\n");
		return -1;
	}

	/* 取所有网卡 */
	while (1) {
		size = sizeof(struct ifreq) * numreqs;
		ifc.ifc_len = size;
		if (ifc.ifc_buf) {
			free(ifc.ifc_buf);
		}
		ifc.ifc_buf = malloc(size);
		if (!ifc.ifc_buf) {
			MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get current ip fail, no memory\n");
			close(sockfd);
			return -1;
		}

		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get current ip fail, ioctl %s\n", strerror(errno));
			close(sockfd);
			free(ifc.ifc_buf);
			return -1;
		}

		if (ifc.ifc_len == size) {
			/* assume it overflowed and try again */
			numreqs += 10;
			continue;
		}
		break;
	}

	count = ifc.ifc_len / sizeof(struct ifreq);

	/* 算网卡数目 */
	ethnum = 0;
	ifr = ifc.ifc_req;
	for (i = 0; i < count; i++) {
		if (strcmp(ifr[i].ifr_name, "lo") == 0) {
			continue;
		}
		ethnum++;
	}

	/* 没有网卡 */
	if (ethnum == 0) {
		free(ifc.ifc_buf);
		close(sockfd);
		return -1;
	}

	size = ethnum * sizeof(struct sniper_ethinfo);
	info = (struct sniper_ethinfo *)malloc(size);
	if (!info) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get current ip fail, no memory. "
			"eth device num: %d\n", ethnum);
		free(ifc.ifc_buf);
		close(sockfd);
		return -1;
	}
	/* 清零，否则后面比较新老ethinfo时，虽然有效信息一致，但memcmp可能会认为不同 */
	memset(info, 0, size);

	/* 取网卡详细信息 */
	ifr = ifc.ifc_req;
	for (i = 0; i < count; i++) {
		struct ifreq hwifr = {{{0}}};
		struct ifreq maskifr = {{{0}}};
		struct sockaddr_in *sa = NULL;

		if (strcmp(ifr[i].ifr_name, "lo") == 0) {
			continue;
		}

		snprintf(info[j].name, sizeof(info[j].name), "%s", ifr[i].ifr_name);

		sa = (struct sockaddr_in *)&ifr[i].ifr_addr;
		sniper_addr2ip(&info[j].ip, (unsigned char *)&sa->sin_addr);

		snprintf(hwifr.ifr_name, sizeof(hwifr.ifr_name), "%s", ifr[i].ifr_name);
		if (ioctl(sockfd, SIOCGIFHWADDR, &hwifr) < 0) {
			MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get %s mac error: %s\n", hwifr.ifr_name);
		} else {
			memcpy(info[j].mac, hwifr.ifr_hwaddr.sa_data, 6);
		}

		snprintf(maskifr.ifr_name, sizeof(maskifr.ifr_name), "%s", ifr[i].ifr_name);
		if (ioctl(sockfd, SIOCGIFNETMASK, &maskifr) < 0) {
			MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get %s netmask error: %s\n", maskifr.ifr_name);
		} else {
			sa = (struct sockaddr_in *)&maskifr.ifr_addr;
			sniper_addr2ip(&info[j].netmask, (unsigned char *)&sa->sin_addr);
		}

//		MON_DBG2(DBGFLAG_HEARTBEAT, "[%d] %s, %d.%d.%d.%d, %d.%d.%d.%d, %02X-%02X-%02X-%02X-%02X-%02X\n",
//		     j, info[j].name, IPSTR(&info[j].ip), IPSTR(&info[j].netmask), MACSTR(info[j].mac));
		j++;
	}

	free(ifc.ifc_buf);
	close(sockfd);

	snprintf(host_mac, sizeof(host_mac), "%02X-%02X-%02X-%02X-%02X-%02X", MACSTR(info[0].mac));
	snprintf(host_ip, sizeof(host_ip), "%d.%d.%d.%d", IPSTR(&info[0].ip));

	return 0;
}

/* hostname转换为ip地址 */
static int hostname_to_ip(char* hostname, char *ip, int ip_len)
{
	int ret = 0;
	struct addrinfo hints;
	struct addrinfo *res, *res_p;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;       /* Allow IPv4 or IPv6 */
	//hints.ai_socktype = SOCK_STREAM;
	//hints.ai_flags = AI_CANONNAME;
	hints.ai_socktype = SOCK_DGRAM;    /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;             /* Any protocol */

	/*
	 * 问题：管控中心采用域名，断网起sniper后联网，一直解析不出管控中心ip
	 * 解决办法：res_init()更新域名配置
	 */
	res_init();

	ret = getaddrinfo(hostname, NULL, &hints, &res);
	if (ret != 0) {
		struct hostent *hptr = NULL;

		hptr = gethostbyname(hostname);
		if (!hptr) {
			MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get host(%s) ip fail, getaddrinfo error: %s. "
				"gethostbyname error: %s\n",
				hostname, gai_strerror(ret), strerror(errno));
			return -1;
		}

		inet_ntop(hptr->h_addrtype, *(hptr->h_addr_list), ip, S_IPLEN);
		if (strncmp(ip, "::ffff:", 7) == 0) { //ipv4映像地址
			char hostip[S_IPLEN] = {0};

			snprintf(hostip, sizeof(hostip), "%s", ip+7);
			snprintf(ip, ip_len, "%s", hostip);
		}
		return 0;
	}

	for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
		char hostip[S_IPLEN] = {0};

		ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, hostip,
					S_IPLEN, NULL, 0, NI_NUMERICHOST);
		if (ret == 0) {
			if (strncmp(hostip, "::ffff:", 7) == 0) { //ipv4映像地址
				snprintf(ip, ip_len, "%s", hostip+7);
			} else {
				snprintf(ip, ip_len, "%s", hostip);
			}
			break;
		}
	}

	freeaddrinfo(res);
	if (ret != 0) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "get host(%s) ip fail, getnameinfo error: %s\n",
			hostname, gai_strerror(ret));
		return -1;
	}
	return 0;
}

/* 从/opt/snipercli/current_server里读服务器当前配置信息 */
void read_servaddr(unsigned int *port, char server[S_LINELEN], char *file)
{
	int p = 0, i = 0, j = 0, len = 0;
	FILE *fp = NULL;
	char *ptr = NULL;
	char buf[S_LINELEN] = {0};
	char str[S_LINELEN] = {0}; //S_LINELEN的长度为512
	int ret = 0;

	fp = fopen(file, "r");
	if (!fp) {
		return;
	}
	while (fgets(buf, sizeof(buf), fp)) {
		if (strchr(buf, '#')) { //跳过注释行
			continue;
		}

		/* 511的长度为S_LINELEN - 1 */
		if (strchr(buf, '[') == NULL) {
			ret = sscanf(buf, "%511[^:]:%d", str, &p);
		} else {
			ret = sscanf(buf, "[%511[^]]]:%d", str, &p);
		}

		if (ret != 2) {
			continue;
		}

		len = strlen(str);
		if (len <= 0) {
			continue;
		}
		if (p <= 0 || p > 65535) {
			continue;
		}

		/* 消除开头的空格 */
		ptr = str;
		for (i = 0; i < len; i++) {
			if (!isspace(*ptr)) {
				break;
			}
			ptr++;
		}
		if (i == len) {
			continue;
		}

		/* 服务器名或ip应都是可打印字符，且不包含空格 */
		len = strlen(ptr);
		j = 0;
		for (i = 0; i < len; i++) {
			if (!isgraph(*ptr)) {
				break;
			}
			server[j] = *ptr;
			j++;
			ptr++;
		}

		if (i < len) {
			memset(server, 0, S_LINELEN);
			continue;
		}

		*port = p;
		break;
	}
	fclose(fp);
}

/* 获取当前连接的管控ip和端口 */
int get_serverconf(void)
{
	/* 只看current_server文件里的记录 */
	if (access(CURRENT_SERVER, F_OK) < 0) {
		return -1;
	}

	char curr_server[S_LINELEN] = {0};

	read_servaddr(&Serv_conf.port, curr_server, CURRENT_SERVER);
	/* 记录的是hostname的话转换成ip */
	if (Serv_conf.port) {
		hostname_to_ip(curr_server, Serv_conf.ip, sizeof(Serv_conf.ip));
	}

	/* ip或port获取不对的话直接返回 */
	if (Serv_conf.ip[0] == 0 || Serv_conf.port == 0) {
		return -1;
	}
	MON_DBG2(DBGFLAG_ANTIVIRUS_SYSINFO, "ip:%s, port:%d\n", Serv_conf.ip, Serv_conf.port);

	return 0;
}
