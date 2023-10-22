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

static int handle_msg_queue_inited = 0;
static struct list_head handle_msg_queue = {0};
static pthread_mutex_t handle_msg_queue_lock = {{0}};
int handle_msg_count = 0;

static unsigned long droped_full_msgs = 0;
static unsigned long last_droped_full_msgs = 0;
static unsigned long last_report_dropfull_time = 0;
static int report_dropfull_threshold = DEBUG_REPORT_FREQ;

/* init handle msg queue */
int handle_msg_queue_init(void)
{
	pthread_mutex_init(&handle_msg_queue_lock, NULL);
	INIT_LIST_HEAD(&handle_msg_queue);
	handle_msg_queue_inited = 1;

	return 0;
}

/* destory msg queue */
void handle_msg_queue_destroy(void)
{
	handle_msg_t *msg = NULL, *m = NULL;

	pthread_mutex_lock(&handle_msg_queue_lock);
	list_for_each_entry_safe(msg, m, &handle_msg_queue, list) {
		list_del(&msg->list);
		sniper_free(msg->data, msg->datalen, SCAN_GET);
		sniper_free(msg, sizeof(struct handle_msg), SCAN_GET);
	}

	pthread_mutex_unlock(&handle_msg_queue_lock);
	pthread_mutex_destroy(&handle_msg_queue_lock);
}

/* 报告消息队列满，丢弃新消息 */
int handle_msg_queue_full(void)
{
	int i = 0;
	time_t now = time(NULL);

	if (handle_msg_count < MAX_VIRUS_QUEUE_DEPTH) {
		return 0;
	}

	droped_full_msgs++;

	if (droped_full_msgs == 1) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_QUEUE, "full queue(%d msgs), drop new handle msg\n",
			handle_msg_count);
		return 1;
	}

	i = droped_full_msgs - last_droped_full_msgs;
	if (last_report_dropfull_time < now - DEBUG_REPORT_INTERVAL) {
		report_dropfull_threshold = DEBUG_REPORT_FREQ;
	} else {
		report_dropfull_threshold += DEBUG_REPORT_FREQ;
	}
	if (i >= report_dropfull_threshold) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_QUEUE, "full queue(%d msgs), %d handle msgs droped\n",
			handle_msg_count, i);
		last_droped_full_msgs = droped_full_msgs;
		last_report_dropfull_time = now;
	}

	return 1;
}

static handle_msg_t *req2msg(virus_info_t *req)
{
	handle_msg_t *msg = NULL;

	if (!req) {
		return NULL;
	}

	msg = (handle_msg_t *)sniper_malloc(sizeof(struct handle_msg), SCAN_GET);
	if (msg == NULL) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_QUEUE, "handle_msgd malloc msg fail\n");
		return NULL;
	}

	msg->datalen = sizeof(struct virus_info);
	msg->data = sniper_malloc(msg->datalen, SCAN_GET);
	if (msg->data == NULL) {
		MON_DBG2(DBGFLAG_ANTIVIRUS_QUEUE, "handle_msgd malloc databuf fail\n");
		sniper_free(msg, sizeof(struct handle_msg), SCAN_GET);
		return NULL;
	}

	memcpy(msg->data, req, msg->datalen);

	return msg;
}

/* 新获得的消息插入命令队列尾部 */
static void add_handle_msg_queue_tail(handle_msg_t *msg)
{
	pthread_mutex_lock(&handle_msg_queue_lock);
	list_add_tail(&msg->list, &handle_msg_queue);
	handle_msg_count++;
	pthread_mutex_unlock(&handle_msg_queue_lock);
}

/* push msg to queue */
void handle_msg_queue_push(virus_info_t *req)
{
	handle_msg_t *msg = NULL;

	if (!req) {
		return;
	}

	msg = req2msg(req);
	if (!msg) {
		return;
	}

	/* 新的handle消息插入队列尾部 */
	add_handle_msg_queue_tail(msg);
}

/* pop msg from queue */
handle_msg_t *get_handle_msg(void)
{
	handle_msg_t *msg = NULL;

	if (!handle_msg_queue_inited) {
		return NULL;
	}

	pthread_mutex_lock(&handle_msg_queue_lock);
	if (!list_empty(&handle_msg_queue)) {
		msg = list_entry(handle_msg_queue.next, handle_msg_t, list);
		if (msg) {
			list_del(&msg->list);
			handle_msg_count--;
		}
	}
	pthread_mutex_unlock(&handle_msg_queue_lock);

	return msg;
}
