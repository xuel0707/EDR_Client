#ifndef _HEADER_H
#define _HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <dirent.h>
#include <zlib.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/sysinfo.h>
#include <curl/curl.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "cJSON.h"
#include "logger.h"

#define REPLY_MAX               1024            /* 接收管控回复的消息最大长度 */
#define S_PROTOLEN              16
#define S_IPLEN                 64
#define S_UUIDLEN               64
#define S_LINELEN		512
#define S_SHORTPATHLEN          512

#define ASSIST_TYPE		"2"		/* 小程序上传日志 */

#define LOGFILE                 "/var/log/antiapt.log"
#define LOGFILE1                "/var/log/antiapt.log.1"
#define ASSISTLOGFILE           "/var/log/assist.log"
#define ASSISTLOGFILE1          "/var/log/assist.log.1"
#define SKUFILE                 "/etc/sniper-sku"
#define CURRENT_SERVER          "/opt/snipercli/current_server"
#define DBGFLAG_POST            "/tmp/post.df"
#define DBGFLAG_HEARTBEAT       "/tmp/heartbeat.df"
#define DBGFLAG_INOTIFY         "/tmp/inotify.df"
#define DBGFLAG_ASSIST          "/tmp/assist.df"
#define DEBUG_LOG_URL           "api/client/debug/log/upload"
#define ASSIST_PIDFILE 		"/var/run/assist.pid"

typedef struct {
	unsigned int port;
	char ip[S_IPLEN];
	char webproto[S_PROTOLEN];
} serverconf_t;
extern serverconf_t Serv_conf;

extern char *nullstr;
extern char curr_servip[S_IPLEN];
extern unsigned short curr_servport;
extern char sku_info[S_UUIDLEN+1];

extern char *safebasename(char *path);
extern off_t my_zip(char *filepath, char *gz_path);

extern int upload_file(char *filepath, char* url);
extern int http_post(char *api_str, char *post_data, char *reply_data);
extern void *inotify_monitor(void *ptr);
extern int is_this_running(void);
extern void init_serverconf(void);
#endif /* _HEADER_H */
