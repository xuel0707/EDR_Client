#include <malloc.h>
#include "header.h"

char *logsender = "2"; //"1"表示sniper主程序，"2"表示辅助小程序

unsigned char Heartbeat_fail = 0;
unsigned char client_registered = 0;
unsigned char Online = 1;
long serv_timeoff = 0;
int client_operation_global = 0;

/* 停止客户端的工作 */
static void disable_client(void)
{
	FILE *fp = NULL;

	if (access(CLIENT_DISABLE, F_OK) == 0) {
		return;
	}

	fp = fopen(CLIENT_DISABLE, "w");
	if (fp) {
		INFO("stop client work\n");
		return;
	}

	MON_ERROR("stop client work fail: %s\n", strerror(errno));
}

/* 唤醒客户端的工作 */
static void enable_client(void)
{
	
	if (access(CLIENT_DISABLE, F_OK) != 0) {
		return;
	}

	if (unlink(CLIENT_DISABLE) == 0) {
		INFO("start client work\n");
		return;
	}

	MON_ERROR("stop client work fail: %s\n", strerror(errno));
}

/* 解析小程序和管控通信返回的数据*/
static void parse_assist_reply(char *string)
{
	cJSON *json = NULL, *data = NULL, *sync_log = NULL, *client_operation = NULL;

	if (!string) {
		return;
	}

	json = cJSON_Parse(string);
	if (!json) {
		MON_ERROR("parse assist reply %s fail\n", string);
		return;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("get data from assist reply %s error\n", string);
		cJSON_Delete(json);
		return;
	}

	/* client_operation 值为1的时候各个功能停止，值为2的时候重新工作 */
	client_operation = cJSON_GetObjectItem(data, "client_operation");
	if (!client_operation) {
		DBG2(DBGFLAG_HEARTBEAT, "get client_operation from assist reply %s error\n", string);
		cJSON_Delete(json);
		return;
	}

	if (client_operation->valueint == 1) {
		disable_client();
	} else if (client_operation->valueint == 2) {
		enable_client();
	}

	/* offline_sync_log 值为1的时候上传日志 */
	sync_log = cJSON_GetObjectItem(data, "offline_sync_log");
	if (!sync_log) {
		DBG2(DBGFLAG_HEARTBEAT, "get offline_sync_log from assist reply %s error\n", string);
		cJSON_Delete(json);
		return;
	}

	if (sync_log->valueint == 1) {
		/* 注意：要传antiapt.log，不是assist.log */
		INFO("assist start upload log\n");

		/* antiapt.log1存在的话也要上传 */
		if (access(LOGFILE1, F_OK) == 0) {
			if (upload_file(LOGFILE1, DEBUG_LOG_URL) < 0) {
				MON_ERROR("assist upload log %s failed\n", LOGFILE1);
			} else {
				INFO("assist upload log %s success\n", LOGFILE1);
			}
		}
		if (upload_file(LOGFILE, DEBUG_LOG_URL) < 0) {
			MON_ERROR("assist upload log %s failed\n", LOGFILE);
		} else {
			INFO("assist upload log %s success\n", LOGFILE);
		}
	}

	cJSON_Delete(json);
}

int main(int argc, char *argv[])
{
	char reply[REPLY_MAX] = {0};
	int assist_fd = 0, size = sizeof(struct stat);
	cJSON *object = NULL;
	char *post = NULL;
	struct stat st = {0}, newst = {0};

	/* 不预分虚拟空间，以免线程起来后虚拟内存飙升，
	 * 预分的虚拟空间实际上没使用，不影响，但不好看 */
	mallopt(M_ARENA_MAX, 1);

	moni_log_init(&g_moni_log, ASSISTLOGFILE);

	/* set timezone to China */
	setenv("TZ", "GMT-8", 1);
	tzset();

	if (is_this_running("Assist", ASSIST_PIDFILE, &assist_fd, NULL) > 0) {
		exit(1);
	}

	INFO("sniper_assist start\n");

	/* 
	 * 主程序会记录sku到文件中，
	 * 小程序如果启动后获取sku失败，可以等到while循环中再获取
	 */
	while(1) {
		get_sku(sku_info);
		if (sku_info[0] != 0) {
			break;
		}
		sleep(5);
	}
	INFO("sku: %s\n", sku_info);

	stat(CURRENT_SERVER, &st);

	/* 获取管控信息 */
	init_assist_serverconf();

	object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "uuid", sku_info);
        post = cJSON_PrintUnformatted(object);

	while(1) {
		if (stat(CURRENT_SERVER, &newst) == 0) {
			/* 管控改变了，使用新管控 */
			if (memcmp(&newst, &st, size) != 0) {
				st = newst;
				init_assist_serverconf();
			}
		}

		if (Serv_conf.ip[0] == 0 || Serv_conf.port == 0) {
			sleep(5);
			continue;
		}

		if (http_assist_post("api/client/debug/setting", post, reply, sizeof(reply)) < 0) {
			printf("http_assist_post < 0 post:%s, reply:%s\n" , post, reply);
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
	close(assist_fd);
	return 0;
}
