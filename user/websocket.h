#ifndef _WEBSOCKET_H
#define _WEBSOCKET_H

#include <stdint.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h> 

#include <stdbool.h>

#include "common.h"

#define SYNC_IP                                 1
#define SYNC_IPV6                               2
#define SYNC_BASELINE_VER                       3
#define SYNC_WEBSHELL_VER                       4
#define SYNC_WEAK_PASSWD_VER                    5
#define SYNC_VIRUS_LIB_VER                      6
#define SYNC_ANTIVIRUS_VER                      7
#define SYNC_IPWRY_VER                          8
#define SYNC_CRACK_VER                          9
#define SYNC_ALL                                10

//发包数据量 10K, 现在的场景只用到上线时发送uuid数据,数据较短用SEND_PKG_MIN
#define SEND_PKG_MAX (10240)
#define SEND_PKG_MIN (100)

//收包缓冲区大小11k(包含16个字节的数据头以及收到的数据除data以外的json字段,如果data以外的json字段,注意此处1024-16后的大小是否满足)
#define RECV_PKG_MAX (SEND_PKG_MAX + 1024)

#define TASK_NULL                               0
#define TASK_HOSTS_QUARANTINE                   1
#define TASK_CANCEL_HOSTS_QUARANTINE            2
#define TASK_STOP_PROTECT                       3
#define TASK_START_PROTECT                      4
#define TASK_REBOOT_HOSTS                       5
#define TASK_UPDATE_POLICY                      6
#define TASK_UPDATE_CONF                        7
#define TASK_SYNC_HOST_INFO                     8
#define TASK_UNINSTALL                          9
#define TASK_GET_PROCESS                        10
#define TASK_KILL_PROCESS                       11
#define TASK_PROCESS_QUARANTINE                 12
#define TASK_FILE_QUARANTINE                    13
#define TASK_CANCEL_FILE_QUARANTINE             14
#define TASK_UNLOCK_IP                          15
#define TASK_UPDATE_RULE                        16
#define TASK_ANTIVIRUS                          100
#define TASK_WEBSHELL_SCAN                      101
#define TASK_BASELINE_CHECK                     102
#define TASK_BASELINE_STOP                      103
#define TASK_UPDATE_CLIENT                      110
#define TASK_UPDATE_VIRUS_DATABASE              111
#define TASK_DETECT_WEAK_ACCOUNT_PWD            121
#define TASK_DETECT_RISK_ACCOUNT                122
#define TASK_SYS_DANGEROUS                      123
#define TASK_INFO_SYNC                          130
#define TASK_UPDATE_CRACK_CONF                  140

// websocket根据data[0]判别数据包类型,比如0x81 = 0x80 | 0x1 为一个txt类型数据包
typedef enum
{
	WDT_NULL = 0, // 非标准数据包
	WDT_MINDATA,  // 0x0：中间数据包
	WDT_TXTDATA,  // 0x1：txt类型数据包
	WDT_BINDATA,  // 0x2：bin类型数据包
	WDT_DISCONN,  // 0x8：断开连接类型数据包 收到后需手动 close(fd)
	WDT_PING,     // 0x8：ping类型数据包 ws_recv 函数内自动回复pong
	WDT_PONG,     // 0xA：pong类型数据包
} WsData_Type;

/*
 * 包含了所有任务需要的字段，根据管控功能增删，
 * 每个成员后面备注哪些任务用到,有改动时修改注释说明
 * 各任务处理只需赋值需要的字段
 */
struct task_recv_info {
	int cmd_type;				//任务类型(公共成员)
	int process_id;				//进程号(文件隔离，取消文件隔离)
	int upgrade_type;			//升级类型(防病毒升级)
	char cmd_id[64];			//任务id(公共成员)
	char log_id[LOGID_SIZE_MAX];		//日志id(文件隔离，取消文件隔离)
	char ip[S_IPLEN];			//ip(解锁ip)
	char md5[S_MD5LEN];			//md5值(文件隔离，取消文件隔离)
	char filepath[PATH_MAX];		//文件路径(文件隔离，取消文件隔离)
	char new_version[VER_LEN_MAX];		//新版本号(升级客户端，更新本地爆破配置,防病毒升级)
	char old_version[VER_LEN_MAX];		//旧版本号(防病毒升级)
};
typedef struct task_recv_info task_recv_t;

int websocket_connect_to_server(char *ip, int port, char *path, int timeout);
int websocket_send(int fd, char *data, int dataLen, bool mask, WsData_Type type);
int websocket_recv(int fd, char *data, int dataMaxLen, WsData_Type *type);
extern char *sha1_hash(const char *source);
extern int ws_base64_encode(const uint8_t *bindata, char *base64, int binlength);
extern void creat_random_string(char *buff, unsigned int len);
extern void creat_random_number(char *buff, unsigned int len);
extern int htoi(const char s[], int start, int len);
#endif
