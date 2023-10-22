#include "servaddr.h"
#include <QApplication>
#include <stdlib.h>
#include "../single.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

/* 消除头部的空格符 */
char *skip_headspace(char *str)
{
	char *ptr = str;

	while (isspace(*ptr)) {
		ptr++;
	}
	return ptr;
}
/* 消除尾部的空格符、回车和换行符 */
void delete_tailspace(char *str)
{
	int i = 0, len = strlen(str);

	for (i = len-1; i >= 0; i--) {
		if (!isspace(str[i])) {
			return;
		}
		str[i] = 0;
	}
}

int hostname_to_ip(char *hostname, char *ip, int ip_len)
{
	int ret = 0, i = 0;
	int digit = 0, alpha = 0, other = 0;
	int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
	struct addrinfo hints;
	struct addrinfo *res, *res_p;

	if (!hostname || !ip) {
		return -1;
	}

	i = 0;
	while (hostname[i] != 0) {
		if (isdigit(hostname[i])) {
			digit = 1;
		} else if (isalpha(hostname[i])) {
			alpha = 1;
		} else if (hostname[i] != '.') {
			other = 1;
		}
		i++;
	}
	if (!digit && !alpha) { //主机名或IP不包含数字和字母
		printf("Error: Invalid hostname or ip\n");
		return -1;
	}
	if (!alpha && !other) { //只包含数据和点的视为ip
		ret = sscanf(hostname, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
		if (ret != 4) {
			printf("Error: Invalid ip\n");
			return -1;
		}
		if (ip1 < 1 || ip1 > 254 || ip2 < 0 || ip2 > 255 ||
		    ip3 < 0 || ip3 > 255 || ip4 < 1 || ip4 > 254) {
			printf("Error: Invalid ip\n");
			return -1;
		}
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;       /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM;    /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;             /* Any protocol */
 
	/* 问题：管控中心采用域名，断网起sniper后联网，一直解析不出管控中心ip
	   解决办法：res_init()更新域名配置 */
	res_init();

	/* getaddrinfo处理ipv4和ipv6，gethostbyname处理ipv4 */
	ret = getaddrinfo(hostname, NULL, &hints, &res);
	if (ret != 0) {
		struct hostent *hptr = NULL;
		char hostip[S_IPLEN] = {0};

		hptr = gethostbyname(hostname);
		if (!hptr) {
			printf("get host(%s) ip fail: %s. %s\n",
			       hostname, gai_strerror(ret), errno ? strerror(errno) : "");
			return -1;
		}

		/* inet_ntop会在ip最后自动加0，如果size<strlen(ip)+1，会报ENOSPC */
		inet_ntop(hptr->h_addrtype, *(hptr->h_addr_list), hostip, sizeof(hostip));
		if (strncmp(hostip, "::ffff:", 7) == 0) { //ipv4映像地址
			snprintf(ip, ip_len, "%s", hostip+7);
		} else {
			snprintf(ip, ip_len, "%s", hostip);
		}
		return 0;
	}
 
	for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
		char hostip[S_IPLEN] = {0};

		ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, hostip,
				  sizeof(hostip), NULL, 0, NI_NUMERICHOST);
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
		printf("get host(%s) ip fail:  %s\n", hostname, gai_strerror(ret));
		return -1;
	}
	return 0;
}

/* save_servaddr()和read_servaddr()与user/serverconf.c里相同 */
int save_servaddr(unsigned short port, char *server, char *file)
{
	FILE *fp = NULL;

	fp = fopen(file, "w");
	if (!fp) {
		return -1;
	}

	fprintf(fp, "%s:%u", server, port);
	fflush(fp);
	fclose(fp);
	return 0;
}

/*
 * 从/etc/sniper.conf里读服务器原始配置信息
 * 从/opt/snipercli/current_server里读服务器当前配置信息
 * 如果配置无效，则视为无配置
 */
void read_servaddr(unsigned short *port, char *server, int server_len, char *file)
{
	int p = 0, len = 0;
	FILE *fp = NULL;
	char *ptr = NULL;
	char line[S_LINELEN] = {0};
	char str[S_LINELEN] = {0};
	char ip[S_IPLEN] = {0};

	if (!file || !server || !port) {
		return;
	}

	fp = fopen(file, "r");
	if (!fp) {
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strchr(line, '#')) { //跳过注释行
			continue;
		}

		if (sscanf(line, "%[^:]:%d", str, &p) != 2) {
			continue;
		}

		if (p <= 0 || p > 65535) {
			continue;
		}

		ptr = skip_headspace(str);
		delete_tailspace(ptr);
		len = strlen(ptr);
		if (len <= 0 || len >= server_len) {
			continue;
		}

		if (hostname_to_ip(ptr, ip, sizeof(ip)) < 0) {
			continue;
		}

		snprintf(server, server_len, "%s", ptr);
		*port = p;
		break;
	}
	fclose(fp);
} 

static int get_servaddr(void)
{
	int len = 0, port = 0;
	unsigned short old_port = 0;
	char *ptr = NULL;
	char server[S_HOSTNAMELEN] = {0}, ip[S_IPLEN] = {0};
	char old_server[S_HOSTNAMELEN] = {0};
	char line[S_LINELEN] = {0};
	char *file = (char *)SNIPER_CONF; //不直接用SNIPER_CONF，是为了避免编译警告

	read_servaddr(&old_port, old_server, sizeof(old_server), file);

	if (old_server[0]) {
		printf("Server name or ip [%s]: ", old_server);
	} else {
		printf("Server name or ip: ");
	}

	snprintf(server, sizeof(server), "%s", old_server);
	if (fgets(line, sizeof(line), stdin)) {
		ptr = skip_headspace(line);
		delete_tailspace(ptr);
		len = strlen(ptr);
		if (len > 0) {
			if (len >= (int)sizeof(server)) {
				printf("Error: Too long Server name %s\n", server);
				return 1;
			}
			snprintf(server, sizeof(server), "%s", ptr);
		}
	}

	len = strlen(server);
	if (len == 0) {
		printf("Error: NULL server\n");
		return 1;
	}
	if (hostname_to_ip(server, ip, sizeof(ip)) < 0) {
		printf("Error: Invalid server, cannot get valid ip by %s\n", server);
		return 1;
	}
	if (strcmp(server, ip) != 0) {
		printf("Server ip: %s\n", ip); //用户输入的参数是主机名，打印出其ip
	}

	if (old_port) {
		printf("Server port [%d]: ", old_port);
	} else {
		printf("Server port: ");
	}

	port = old_port;
	memset(line, 0, sizeof(line));
	if (fgets(line, sizeof(line), stdin)) {
		ptr = skip_headspace(line);
		delete_tailspace(ptr);
		if (strlen(ptr) > 0) {
			int i = 0;
			while (ptr[i] != 0) {
				if (!isdigit(ptr[i])) {
					printf("Error: invalid server port\n");
					return 1;
				}
				i++;
			}
			port = atoi(ptr);
		}
	}

	if (port <= 0 || port > 65535) {
		printf("Error: invalid server port\n");
		return 1;
	}

	if (port == old_port && strcmp(server, old_server) == 0) {
		printf("server config is %s:%d\n", server, port);
		return 0;
	}

	if (save_servaddr(port, server, file) < 0) {
		printf("save server config %s:%d error: %s\n",
			server, port, strerror(errno));
		return 1;
	}

	printf("server config is %s:%d\n", server, port);
	return 0;
}

static int set_servaddr(char *arg)
{
	int len = 0, port = 0;
	char *ptr = NULL;
	char server[S_HOSTNAMELEN] = {0};
	char str[S_LINELEN] = {0};
	char ip[S_IPLEN] = {0};

	if (getuid() != 0) {
	    printf("Permission denied. Try again as root\n");
	    return 1;
	}

	if (!arg || strlen(arg) >= (int)sizeof(str)) {
		return 1;
	}

	if (sscanf(arg, "%[^:]:%d", str, &port) != 2) {
		return 1;
	}

	if (port <= 0 || port > 65535) {
		printf("Error: invalid server port\n");
		return 1;
	}

	ptr = skip_headspace(str);
	delete_tailspace(ptr);
	len = strlen(ptr);
	if (len == 0) {
		printf("Error: NULL server\n");
		return 1;
	}
	if (len >= (int)sizeof(server)) {
		printf("Error: Too long Server name %s\n", ptr);
		return 1;
	}

	if (hostname_to_ip(ptr, ip, sizeof(ip)) < 0) {
		printf("Error: Invalid server, cannot get valid ip by %s\n", ptr);
		return 1;
	}

	snprintf(server, sizeof(server), "%s", ptr);
	if (save_servaddr(port, server, (char *)SNIPER_CONF) < 0) {
		printf("save server config %s:%d error: %s\n",
			server, port, strerror(errno));
		return 1;
	}
	printf("server config is %s:%d\n", server, port);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc == 2) {
		return set_servaddr(argv[1]);
	}

	if (getenv("DISPLAY") == NULL) {
		return get_servaddr();
	}

	if (is_this_running("servaddr") > 0) {
		return 1;
	}

	QApplication a(argc, argv);
	ServAddr w;
	w.show();

	return a.exec();
}
