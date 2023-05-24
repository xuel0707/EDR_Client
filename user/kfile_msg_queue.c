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

static int kfile_msg_queue_inited = 0;
static struct list_head kfile_msg_queue = {0};
static pthread_mutex_t kfile_msg_queue_lock = {{0}};
static int kfile_msg_count = 0;

static unsigned long droped_full_msgs = 0;
static unsigned long last_droped_full_msgs = 0;
static unsigned long last_report_dropfull_time = 0;
static unsigned long droped_repeat_msgs = 0;
static unsigned long last_droped_repeat_msgs = 0;
static unsigned long last_report_droprepeat_time = 0;
static int report_dropfull_threshold = DEBUG_REPORT_FREQ;
static int report_droprepeat_threshold = DEBUG_REPORT_FREQ;

/* init file msg queue */
int kfile_msg_queue_init(void)
{
	pthread_mutex_init(&kfile_msg_queue_lock, NULL);
	INIT_LIST_HEAD(&kfile_msg_queue);
	kfile_msg_queue_inited = 1;

	return 0;
}


/* destory msg queue */
void kfile_msg_queue_destroy(void)
{
	kfile_msg_t *msg = NULL, *m = NULL;

	pthread_mutex_lock(&kfile_msg_queue_lock);
	list_for_each_entry_safe(msg, m, &kfile_msg_queue, list) {
		list_del(&msg->list);
		sniper_free(msg->data, msg->datalen, FILE_GET);
		sniper_free(msg, sizeof(struct kfile_msg), FILE_GET);
	}

	pthread_mutex_unlock(&kfile_msg_queue_lock);
	pthread_mutex_destroy(&kfile_msg_queue_lock);
}

/* 报告消息队列满，丢弃新消息 */
static int file_msg_queue_full(void)
{
	int i = 0;
	time_t now = time(NULL);

	if (kfile_msg_count < MAX_QUEUE_DEPTH) {
		return 0;
	}

	droped_full_msgs++;

	if (droped_full_msgs == 1) {
		INFO("full queue(%d msgs), drop new file msg\n",
			kfile_msg_count);
		return 1;
	}

	i = droped_full_msgs - last_droped_full_msgs;
	if (last_report_dropfull_time < now - DEBUG_REPORT_INTERVAL) {
		report_dropfull_threshold = DEBUG_REPORT_FREQ;
	} else {
		report_dropfull_threshold += DEBUG_REPORT_FREQ;
	}
	if (i >= report_dropfull_threshold) {
		INFO("full queue(%d msgs), %d file msgs droped\n",
			kfile_msg_count, i);
		last_droped_full_msgs = droped_full_msgs;
		last_report_dropfull_time = now;
	}

	return 1;
}

/* 报告自上次报告后，又被丢弃的消息数量 */
void print_droped_file_msgs(void)
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
		INFO("%d similar file msgs droped\n", i);
		last_droped_repeat_msgs = droped_repeat_msgs;
		last_report_droprepeat_time = now;
	}
}

static kfile_msg_t *req2msg(filereq_t *req)
{
	kfile_msg_t *msg = NULL;

	if (!req) {
		return NULL;
	}

	msg = (kfile_msg_t *)sniper_malloc(sizeof(struct kfile_msg), FILE_GET);
	if (msg == NULL) {
		MON_ERROR("kfile_msgd malloc msg fail\n");
		return NULL;
	}

	msg->datalen = req->size;
	msg->data = sniper_malloc(msg->datalen, FILE_GET);
	if (msg->data == NULL) {
		MON_ERROR("kfile_msgd malloc databuf fail\n");
		sniper_free(msg, sizeof(struct kfile_msg), FILE_GET);
		return NULL;
	}

	memcpy(msg->data, req, msg->datalen);

	return msg;
}

/* 新获得的消息插入命令队列尾部 */
static void add_kfile_msg_queue_tail(kfile_msg_t *msg)
{
	pthread_mutex_lock(&kfile_msg_queue_lock);
	list_add_tail(&msg->list, &kfile_msg_queue);
	kfile_msg_count++;
	DBG2(DBGFLAG_TTT, "kfile get msg count:(%d)\n", kfile_msg_count);
	pthread_mutex_unlock(&kfile_msg_queue_lock);
}

/* push msg to queue */
void kfile_msg_queue_push(filereq_t *req)
{
	kfile_msg_t *msg = NULL;

	if (!req) {
		return;
	}

	msg = req2msg(req);
	if (!msg) {
		return;
	}

	/* 新的file消息插入队列尾部 */
	add_kfile_msg_queue_tail(msg);
}

/* pop msg from queue */
kfile_msg_t *get_kfile_msg(void)
{
	kfile_msg_t *msg = NULL;

	if (!kfile_msg_queue_inited) {
		return NULL;
	}

	pthread_mutex_lock(&kfile_msg_queue_lock);
	if (!list_empty(&kfile_msg_queue)) {
		msg = list_entry(kfile_msg_queue.next, kfile_msg_t, list);
		if (msg) {
			list_del(&msg->list);
			kfile_msg_count--;
			DBG2(DBGFLAG_TTT, "kfile get msg count:(%d)\n", kfile_msg_count);
		}
	}
	pthread_mutex_unlock(&kfile_msg_queue_lock);

	return msg;
}

void *kfile_msgd(void *ptr)
{
	struct nlmsghdr *nlh = NULL;
	int reported = 0, engine_on = 0;
	filereq_t *req = NULL;

	prctl(PR_SET_NAME, "file_mq");
	save_thread_pid("kfile_msgd", SNIPER_THREAD_KFILEMSG);

	kfile_msg_queue_init();

	while (Online) {
		/* 许可到期/停止防护/引擎关闭，这边不做处理，由接收消息的地方处理 */
		if (!nlh) {
			nlh = (struct nlmsghdr *)sniper_malloc(NLMSGLEN, FILE_GET);
			if (nlh == NULL) {
				if (!(reported & MALLOC_FAIL)) {
					MON_ERROR("kfile_msgd malloc nlh fail\n");
					reported |= MALLOC_FAIL;
				}
				/* TODO 报告管控中心 */
				sleep(1);
				continue;
			}
		}

		if (!engine_on) {
			if (init_engine(NLMSG_FILE, nlh) < 0) {
				if (!(reported & ENGINE_FAIL)) {
					MON_ERROR("file engine init fail\n");
					reported |= ENGINE_FAIL;
				}
				/* TODO 报告管控中心 */
				sleep(1);
				continue;
			}
			engine_on = 1;
		}

		req = (filereq_t *)get_req(nlh, NLMSG_FILE);
		if (req == NULL) {
			continue;
		}

		/* 队列满则丢弃所有新消息 */
		if (file_msg_queue_full()) {
			continue;
		}

		kfile_msg_queue_push(req);
		print_droped_file_msgs();
	}

        fini_engine(NLMSG_FILE, nlh);
        if (nlh) {
                sniper_free(nlh, NLMSGLEN, FILE_GET);
        }
        kfile_msg_queue_destroy();

	INFO("kfile_msgd thread exit\n");
	return NULL;
}
