/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include <pthread.h>
#include <curl/curl.h>

#include "msg_queue.h"
#include "header.h"
#include "file.h"

#define MALLOC_FAIL 1
#define ENGINE_FAIL 2
#define NOTIFY_CC   4

static int virus_msg_queue_inited = 0;
static struct list_head virus_msg_queue = {0};
static pthread_mutex_t virus_msg_queue_lock = {{0}};
static int virus_msg_count = 0;

static unsigned long droped_full_msgs = 0;
static unsigned long last_droped_full_msgs = 0;
static unsigned long last_report_dropfull_time = 0;
static unsigned long droped_repeat_msgs = 0;
static unsigned long last_droped_repeat_msgs = 0;
static unsigned long last_report_droprepeat_time = 0;
static int report_dropfull_threshold = DEBUG_REPORT_FREQ;
static int report_droprepeat_threshold = DEBUG_REPORT_FREQ;

/* init virus msg queue */
int virus_msg_queue_init(void)
{
	pthread_mutex_init(&virus_msg_queue_lock, NULL);
	INIT_LIST_HEAD(&virus_msg_queue);
	virus_msg_queue_inited = 1;

	return 0;
}

/* destory msg queue */
void virus_msg_queue_destroy(void)
{
	virus_msg_t *msg = NULL, *m = NULL;

	pthread_mutex_lock(&virus_msg_queue_lock);
	list_for_each_entry_safe(msg, m, &virus_msg_queue, list) {
		list_del(&msg->list);
		sniper_free(msg->data, msg->datalen, FILE_GET);
		sniper_free(msg, sizeof(struct virus_msg), FILE_GET);
	}

	pthread_mutex_unlock(&virus_msg_queue_lock);
	pthread_mutex_destroy(&virus_msg_queue_lock);
}

/* 报告消息队列满，丢弃新消息 */
int virus_msg_queue_full(void)
{
	int i = 0;
	time_t now = time(NULL);

	if (virus_msg_count < MAX_VIRUS_QUEUE_DEPTH) {
		return 0;
	}

	droped_full_msgs++;

	if (droped_full_msgs == 1) {
		INFO("full queue(%d msgs), drop new virus msg\n",
			virus_msg_count);
		return 1;
	}

	i = droped_full_msgs - last_droped_full_msgs;
	if (last_report_dropfull_time < now - DEBUG_REPORT_INTERVAL) {
		report_dropfull_threshold = DEBUG_REPORT_FREQ;
	} else {
		report_dropfull_threshold += DEBUG_REPORT_FREQ;
	}
	if (i >= report_dropfull_threshold) {
		INFO("full queue(%d msgs), %d virus msgs droped\n",
			virus_msg_count, i);
		last_droped_full_msgs = droped_full_msgs;
		last_report_dropfull_time = now;
	}

	return 1;
}

/* 报告自上次报告后，又被丢弃的消息数量 */
void print_droped_virus_msgs(void)
{
	int i = droped_repeat_msgs - last_droped_repeat_msgs;
	time_t now = time(NULL);

	if (last_report_droprepeat_time < now - DEBUG_REPORT_INTERVAL) {
		/* 非调试日志高峰，恢复默认报告频度 */
		report_droprepeat_threshold = DEBUG_REPORT_FREQ;
	} else {
		/* 调试日志高峰，降低报告频度 */
		report_droprepeat_threshold += DEBUG_REPORT_FREQ;
	}

	if (i >= report_droprepeat_threshold) {
		INFO("%d similar virus msgs droped\n", i);
		last_droped_repeat_msgs = droped_repeat_msgs;
		last_report_droprepeat_time = now;
	}
}

static virus_msg_t *req2msg(struct virus_msg_args *req)
{
	virus_msg_t *msg = NULL;

	if (!req) {
		return NULL;
	}

	msg = (virus_msg_t *)sniper_malloc(sizeof(struct virus_msg), FILE_GET);
	if (msg == NULL) {
		MON_ERROR("virus_msgd malloc msg fail\n");
		return NULL;
	}

	msg->datalen = sizeof(struct virus_msg_args);
	msg->data = sniper_malloc(msg->datalen, FILE_GET);
	if (msg->data == NULL) {
		MON_ERROR("virus_msgd malloc databuf fail\n");
		sniper_free(msg, sizeof(struct virus_msg), FILE_GET);
		return NULL;
	}

	memcpy(msg->data, req, msg->datalen);

	return msg;
}

/* 新获得的消息插入命令队列尾部 */
static void add_virus_msg_queue_tail(virus_msg_t *msg)
{
	pthread_mutex_lock(&virus_msg_queue_lock);
	list_add_tail(&msg->list, &virus_msg_queue);
	virus_msg_count++;
	pthread_mutex_unlock(&virus_msg_queue_lock);
}

/* push msg to queue */
void virus_msg_queue_push(struct virus_msg_args *req)
{
	virus_msg_t *msg = NULL;

	if (!req) {
		return;
	}

	msg = req2msg(req);
	if (!msg) {
		return;
	}

	/* 新的virus消息插入队列尾部 */
	add_virus_msg_queue_tail(msg);
}

/* pop msg from queue */
virus_msg_t *get_virus_msg(void)
{
	virus_msg_t *msg = NULL;

	if (!virus_msg_queue_inited) {
		return NULL;
	}

	pthread_mutex_lock(&virus_msg_queue_lock);
	if (!list_empty(&virus_msg_queue)) {
		msg = list_entry(virus_msg_queue.next, virus_msg_t, list);
		if (msg) {
			list_del(&msg->list);
			virus_msg_count--;
		}
	}
	pthread_mutex_unlock(&virus_msg_queue_lock);

	return msg;
}
