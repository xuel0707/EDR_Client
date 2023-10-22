/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* file operation */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "header.h"

serverconf_t Serv_conf = {0};

int hostname_to_ip(char* hostname, char *ip)
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
 
	/* 问题：管控中心采用域名，断网起sniper后联网，一直解析不出管控中心ip
	   解决办法：res_init()更新域名配置 */
	res_init();

        ret = getaddrinfo(hostname, NULL, &hints, &res);
        if (ret != 0) {
                struct hostent *hptr = NULL;

                hptr = gethostbyname(hostname);
                if (!hptr) {
                        MON_ERROR("get host(%s) ip fail, getaddrinfo error: %s. "
                                "gethostbyname error: %s\n",
                                hostname, gai_strerror(ret), strerror(errno));
                        return -1;
                }

                inet_ntop(hptr->h_addrtype, *(hptr->h_addr_list), ip, S_IPLEN);
		if (strncmp(ip, "::ffff:", 7) == 0) { //ipv4映像地址
                	char hostip[S_IPLEN] = {0};

			strncpy(hostip, ip+7, S_IPLEN);
			strncpy(ip, hostip, S_IPLEN);
		}
                return 0;
        }
 
        for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
                char hostip[S_IPLEN] = {0};

                ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, hostip,
					S_IPLEN, NULL, 0, NI_NUMERICHOST);
                if (ret == 0) {
			if (strncmp(hostip, "::ffff:", 7) == 0) { //ipv4映像地址
				strncpy(ip, hostip+7, S_IPLEN);
			} else {
				strncpy(ip, hostip, S_IPLEN);
			}
			break;
                }
        }
 
        freeaddrinfo(res);
        if (ret != 0) {
                MON_ERROR("get host(%s) ip fail, getnameinfo error: %s\n",
			hostname, gai_strerror(ret));
                return -1;
        }
        return 0;
}

/* save_servaddr()和read_servaddr()与qt/servaddr/main.cpp里相同 */
int save_servaddr(unsigned short port, char *server, char *file)
{
	FILE *fp = NULL;

	fp = fopen(file, "w");
	if (!fp) {
		return -1;
	}

	if (strchr(server, ':') == NULL) {
		fprintf(fp, "%s:%u", server, port);
	} else {
		fprintf(fp, "[%s]:%u", server, port);
	}
	fflush(fp);
	fclose(fp);
	return 0;
}

/* 从/etc/sniper.conf里读服务器原始配置信息
   从/opt/snipercli/current_server里读服务器当前配置信息 */
void read_servaddr(unsigned short *port, char server[S_LINELEN], char *file)
{
	int p = 0, i = 0, j = 0, len = 0;
	FILE *fp = NULL;
	char *ptr = NULL;
	char buf[S_LINELEN] = {0};
	char str[S_LINELEN] = {0};
	int ret = 0;

	fp = fopen(file, "r");
	if (!fp) {
		return;
	}
	while (fgets(buf, S_LINELEN, fp)) {
		if (strchr(buf, '#')) { //跳过注释行
			continue;
		}

		if (strchr(buf, '[') == NULL) {
			ret = sscanf(buf, "%[^:]:%d", str, &p);
		} else {
			ret = sscanf(buf, "[%[^]]]:%d", str, &p);
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

unsigned short curr_servport = 0;
char curr_servip[S_IPLEN] = {0};
unsigned short orig_servport = 0;
char orig_servip[S_IPLEN] = {0};
unsigned char localmode = 0;

void init_serverconf(void)
{
	localmode = 1;

	if (access(CURRENT_SERVER, F_OK) == 0) {
		char curr_server[S_LINELEN] = {0};

		read_servaddr(&curr_servport, curr_server, CURRENT_SERVER);
		if (curr_servport) {
			hostname_to_ip(curr_server, curr_servip);
		}
		localmode = 0;
	}

	if (access(SNIPER_CONF, F_OK) == 0) {
		char orig_server[S_LINELEN] = {0};

		read_servaddr(&orig_servport, orig_server, SNIPER_CONF);
		if (orig_servport) {
			hostname_to_ip(orig_server, orig_servip);
		}
		localmode = 0;
	}
}

void init_assist_serverconf(void)
{
	unsigned short port = 0;
	char ip[S_IPLEN] = {0};

	if (access(CURRENT_SERVER, F_OK) == 0) {
		char curr_server[S_LINELEN] = {0};

		read_servaddr(&port, curr_server, CURRENT_SERVER);
		if (port) {
			hostname_to_ip(curr_server, ip);
			Serv_conf.port = port;
			snprintf(Serv_conf.ip, sizeof(Serv_conf.ip), "%s", ip);
		}
		INFO("ip:%s, port:%d\n", Serv_conf.ip, Serv_conf.port);
	}
}
