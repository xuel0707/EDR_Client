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

#define MALLOC_FAIL 1
#define ENGINE_FAIL 2
#define NOTIFY_CC   4

static int kvirus_msg_queue_inited = 0;
static struct list_head kvirus_msg_queue = {0};
static pthread_mutex_t kvirus_msg_queue_lock = {{0}};
static int kvirus_msg_count = 0;

static unsigned long droped_full_msgs = 0;
static unsigned long last_droped_full_msgs = 0;
static unsigned long last_report_dropfull_time = 0;
static unsigned long droped_repeat_msgs = 0;
static unsigned long last_droped_repeat_msgs = 0;
static unsigned long last_report_droprepeat_time = 0;
static int report_dropfull_threshold = DEBUG_REPORT_FREQ;
static int report_droprepeat_threshold = DEBUG_REPORT_FREQ;

/* init kvirus msg queue */
int kvirus_msg_queue_init(void)
{
	pthread_mutex_init(&kvirus_msg_queue_lock, NULL);
	INIT_LIST_HEAD(&kvirus_msg_queue);
	kvirus_msg_queue_inited = 1;

	return 0;
}

/* destory msg queue */
void kvirus_msg_queue_destroy(void)
{
	kvirus_msg_t *msg = NULL, *m = NULL;

	pthread_mutex_lock(&kvirus_msg_queue_lock);
	list_for_each_entry_safe(msg, m, &kvirus_msg_queue, list) {
		list_del(&msg->list);
		sniper_free(msg->data, msg->datalen, FILE_GET);
		sniper_free(msg, sizeof(struct kvirus_msg), FILE_GET);
	}

	pthread_mutex_unlock(&kvirus_msg_queue_lock);
	pthread_mutex_destroy(&kvirus_msg_queue_lock);
}

/* 报告消息队列满，丢弃新消息 */
int kvirus_msg_queue_full(void)
{
	int i = 0;
	time_t now = time(NULL);

	if (kvirus_msg_count < MAX_FILTER_QUEUE_DEPTH) {
		return 0;
	}

	droped_full_msgs++;

	/* 队里已经满了不再继续往里面存 */
	if (droped_full_msgs == 1) {
		INFO("full queue(%d msgs), drop new kvirus msg\n",
			kvirus_msg_count);
		return 1;
	}

	/* 报告最少间隔一分钟 */
	i = droped_full_msgs - last_droped_full_msgs;
	if (last_report_dropfull_time < now - DEBUG_REPORT_INTERVAL) {
		report_dropfull_threshold = DEBUG_REPORT_FREQ;
	} else {
		report_dropfull_threshold += DEBUG_REPORT_FREQ;
	}
	if (i >= report_dropfull_threshold) {
		INFO("full queue(%d msgs), %d kvirus msgs droped\n",
			kvirus_msg_count, i);
		last_droped_full_msgs = droped_full_msgs;
		last_report_dropfull_time = now;
	}

	return 1;
}

/* 报告自上次报告后，又被丢弃的消息数量 */
void print_droped_kvirus_msgs(void)
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
		INFO("%d similar kvirus msgs droped\n", i);
		last_droped_repeat_msgs = droped_repeat_msgs;
		last_report_droprepeat_time = now;
	}
}

/* 转换消息内容 */
#if 0
static kvirus_msg_t *req2msg(filereq_t *req)
#else
static kvirus_msg_t *req2msg(struct ebpf_filereq_t *req)
#endif
{
	kvirus_msg_t *msg = NULL;

	if (!req) {
		return NULL;
	}

	msg = (kvirus_msg_t *)sniper_malloc(sizeof(struct kvirus_msg), FILE_GET);
	if (msg == NULL) {
		MON_ERROR("kvirus_msgd malloc msg fail\n");
		return NULL;
	}

	msg->datalen = req->size;
	msg->data = sniper_malloc(msg->datalen, FILE_GET);
	if (msg->data == NULL) {
		MON_ERROR("kvirus_msgd malloc databuf fail\n");
		sniper_free(msg, sizeof(struct kvirus_msg), FILE_GET);
		return NULL;
	}

	memcpy(msg->data, req, msg->datalen);

	return msg;
}

/* 新获得的消息插入命令队列尾部 */
static void add_kvirus_msg_queue_tail(kvirus_msg_t *msg)
{
	pthread_mutex_lock(&kvirus_msg_queue_lock);
	list_add_tail(&msg->list, &kvirus_msg_queue);
	kvirus_msg_count++;
	pthread_mutex_unlock(&kvirus_msg_queue_lock);
}

/* push msg to queue */
#if 0
void kvirus_msg_queue_push(filereq_t *req)
#else
void kvirus_msg_queue_push(struct ebpf_filereq_t *req)
#endif
{
	kvirus_msg_t *msg = NULL;

	if (!req) {
		return;
	}

	msg = req2msg(req);
	if (!msg) {
		return;
	}

	/* 新的kvirus消息插入队列尾部 */
	add_kvirus_msg_queue_tail(msg);
}

/* pop msg from queue */
kvirus_msg_t *get_kvirus_msg(void)
{
	kvirus_msg_t *msg = NULL;

	if (!kvirus_msg_queue_inited) {
		return NULL;
	}

	pthread_mutex_lock(&kvirus_msg_queue_lock);
	if (!list_empty(&kvirus_msg_queue)) {
		msg = list_entry(kvirus_msg_queue.next, kvirus_msg_t, list);
		if (msg) {
			list_del(&msg->list);
			kvirus_msg_count--;
		}
	}
	pthread_mutex_unlock(&kvirus_msg_queue_lock);

	return msg;
}

#ifdef USE_AVIRA
void *kvirus_msgd(void *ptr)
{
	struct nlmsghdr *nlh = NULL;
	int reported = 0, engine_on = 0;
#if 0
	filereq_t *req = NULL;
#else
	struct ebpf_filereq_t *req = NULL;
#endif

	prctl(PR_SET_NAME, "antivirus_mq");
	save_thread_pid("kvirus_msgd", SNIPER_THREAD_KFILTERMSG);

	kvirus_msg_queue_init();

	while (Online) {
		/* 许可到期/停止防护/引擎关闭，这边不做处理，由接收消息的地方处理 */
		if (!nlh) {
			nlh = (struct nlmsghdr *)sniper_malloc(NLMSGLEN, FILE_GET);
			if (nlh == NULL) {
				if (!(reported & MALLOC_FAIL)) {
					MON_ERROR("kvirus_msgd malloc nlh fail\n");
					reported |= MALLOC_FAIL;
				}
				/* TODO 报告管控中心 */
				sleep(1);
				continue;
			}
		}

		if (!engine_on) {
			if (init_engine(NLMSG_VIRUS, nlh) < 0) {
				if (!(reported & ENGINE_FAIL)) {
					MON_ERROR("virus engine init fail\n");
					reported |= ENGINE_FAIL;
				}
				/* TODO 报告管控中心 */
				sleep(1);
				continue;
			}
			engine_on = 1;
		}

		/* 获取病毒数据 */
#if 0
		req = (filereq_t *)get_req(nlh, NLMSG_VIRUS);
#else
		req = (struct ebpf_filereq_t *)get_req(nlh, NLMSG_VIRUS);
#endif
		if (req == NULL) {
			continue;
		}

		/* 队列满则丢弃所有新消息 */
		if (kvirus_msg_queue_full()) {
			continue;
		}

		/* 病毒实时检测功能关闭时，丢弃所有新消息 */
		if (antivirus_policy_global.real_time_check.enable == TURN_MY_OFF) {
			continue;
		}

		/* 转发到消息队列里 */
		kvirus_msg_queue_push(req);
		print_droped_kvirus_msgs();
	}

	/* 结束接收内核消息,释放空间 */
	fini_engine(NLMSG_VIRUS, nlh);
	if (nlh) {
		sniper_free(nlh, NLMSGLEN, FILE_GET);
	}

	/* 销毁病毒数据消息队列 */
	kvirus_msg_queue_destroy();

	INFO("kvirus_msgd thread exit\n");
	return NULL;
}
#endif
