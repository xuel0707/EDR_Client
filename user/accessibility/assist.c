/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

/* setrlimit */
#include <sys/resource.h>

/*get_opt */
#include <getopt.h>

/* time */
#include <time.h>

/* file operation */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

/* libcurl */
#include <curl/curl.h>
#include <pthread.h>

#include <openssl/crypto.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/prctl.h>
#include <malloc.h>

#include "header.h"
#include "logger.h"

char sku_info[S_UUIDLEN+1] = {0};
serverconf_t Serv_conf = {0};

static int get_sku(char sku[S_UUIDLEN+1])
{
	FILE *fp = NULL;

	memset(sku, 0, S_UUIDLEN+1);
	fp = fopen(SKUFILE, "r");
	if (!fp) {
		MON_ERROR("open %s fail: %s\n", SKUFILE, strerror(errno));
		return -1;
	}

	/* 下面的fgets最多S_UUIDLEN，最后填0 */
	if (!fgets(sku, S_UUIDLEN+1, fp)) {
		MON_ERROR("read %s fail: %s\n", SKUFILE, strerror(errno));
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

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

/* 从/opt/snipercli/current_server里读服务器当前配置信息 */
void read_servaddr(unsigned int *port, char server[S_LINELEN], char *file)
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

void init_serverconf(void)
{

	if (access(CURRENT_SERVER, F_OK) == 0) {
		char curr_server[S_LINELEN] = {0};

		read_servaddr(&Serv_conf.port, curr_server, CURRENT_SERVER);
		if (Serv_conf.port) {
			hostname_to_ip(curr_server, Serv_conf.ip);
		}
		INFO("ip:%s, port:%d\n", Serv_conf.ip, Serv_conf.port);
	}
}

int parse_assist_reply(char*string)
{
	cJSON *json, *data, *sync_log;
	int ret = 0;

	json = cJSON_Parse(string);
	if (!json) {
		MON_ERROR("parse assist reply fail\n");
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("assist reply get data error\n");
		goto out;
	}

	sync_log = cJSON_GetObjectItem(data, "offline_sync_log");
	if (!sync_log) {
		DBG2(DBGFLAG_HEARTBEAT, "assist reply get sync_log error\n");
	} else {
		if (sync_log->valueint == 1) {
			INFO("assist start upload log\n");
			if (access(LOGFILE1, F_OK) == 0) {
				ret = upload_file(LOGFILE1, DEBUG_LOG_URL);
				if (ret < 0) {
					MON_ERROR("assist upload log:%s failed\n", LOGFILE1);
				} else {
					INFO("assist upload log:%s success\n", LOGFILE1);
				}
			}
			ret = upload_file(LOGFILE, DEBUG_LOG_URL);
			if (ret < 0) {
				MON_ERROR("assist upload log:%s failed\n", LOGFILE);
			} else {
				INFO("assist upload log:%s success\n", LOGFILE);
			}
		}
	}

	cJSON_Delete(json);
	return 0;
out:
	cJSON_Delete(json);
	return -1;
}

int main(int argc, char *argv[])
{
	char reply[REPLY_MAX] = {0};
	int ret = 0;
	cJSON *object = NULL;
	char *post = NULL;
	pthread_t inotify_tr;

	/* 不预分虚拟空间，以免线程起来后虚拟内存飙升，
	* 预分的虚拟空间实际上没使用，不影响，但不好看 */
	mallopt(M_ARENA_MAX, 1);

	moni_log_init(&g_moni_log);

	/* set timezone to China */
	setenv("TZ", "GMT-8", 1);
	tzset();

	if (is_this_running() > 0) {
		exit(1);
	}

	INFO("sniper_assist is start running\n");

	while(1) {
		ret = get_sku(sku_info);
		if (ret == 0) {
			break;
		}
		sleep(5);
	}
	INFO("sniper_assist get sku success:%s\n", sku_info);

	init_serverconf();

	object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "uuid", sku_info);
        post = cJSON_PrintUnformatted(object);

	pthread_create(&inotify_tr, NULL, inotify_monitor, NULL);

	while(1) {

		if (Serv_conf.ip[0] == 0 || Serv_conf.port == 0) {
			sleep(5);
			continue;
		}

		ret = http_post("api/client/debug/setting", post, reply);
		if (ret < 0) {
			sleep(5);
			continue;
		}

		DBG2(DBGFLAG_ASSIST, "post:%s, reply:%s\n" , post, reply);
		/* sku错误的原因导致返回404，重新获取一下sku */
		if (strstr(reply, "\"code\":404") != NULL) {
			get_sku(sku_info);
			sleep(5);
			continue;
		}
		parse_assist_reply(reply);
		
		sleep(30);
	}

	cJSON_Delete(object);
	free(post);
	return 0;
}
