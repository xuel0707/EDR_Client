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

#include "header.h"

static int knet_msg_queue_inited = 0;
static struct list_head knet_msg_queue = {0};
static pthread_mutex_t knet_msg_queue_lock = {{0}};
static int knet_msg_count = 0;

int get_knet_msg_count(void)
{
	return knet_msg_count;
}

/* init knet msg queue */
static void knet_msg_queue_init(void)
{
	pthread_mutex_init(&knet_msg_queue_lock, NULL);
	INIT_LIST_HEAD(&knet_msg_queue);
	knet_msg_queue_inited = 1;
}

/* destory msg queue */
static void knet_msg_queue_destroy(void)
{
        knet_msg_t *msg = NULL, *m = NULL;

	pthread_mutex_lock(&knet_msg_queue_lock);
	list_for_each_entry_safe(msg, m, &knet_msg_queue, list) {
		list_del(&msg->list);
		sniper_free(msg->data, msg->datalen, NETWORK_GET);
		sniper_free(msg, sizeof(struct knet_msg), NETWORK_GET);
	}

	pthread_mutex_unlock(&knet_msg_queue_lock);
	pthread_mutex_destroy(&knet_msg_queue_lock);
}

#if 0
static knet_msg_t *req2msg(netreq_t *req)
#else
static knet_msg_t *req2msg(struct ebpf_netreq_t *req)
#endif
{
	knet_msg_t *msg = NULL;

	if (!req) {
		return NULL;
	}

        msg = (knet_msg_t *)sniper_malloc(sizeof(struct knet_msg), NETWORK_GET);
	if (!msg) {
		MON_ERROR("malloc knet msg fail\n");
		return NULL;
	}

	msg->datalen = sizeof(struct ebpf_netreq_t);
	msg->data = sniper_malloc(msg->datalen, NETWORK_GET);
	if (!msg->data) {
		MON_ERROR("malloc knet msg databuf fail\n");
		sniper_free(msg, sizeof(struct knet_msg), NETWORK_GET);
		return NULL;
	}
	memset(msg->data, 0, msg->datalen);
	memcpy(msg->data, req, msg->datalen);
	msg->repeat = 0;

	return msg;
}

static unsigned long droped_full_msgs = 0;
static unsigned long last_droped_full_msgs = 0;
static unsigned long last_report_dropfull_time = 0;
static unsigned long droped_repeat_msgs = 0;
static unsigned long last_droped_repeat_msgs = 0;
static unsigned long last_report_droprepeat_time = 0;
static int report_dropfull_threshold = DEBUG_REPORT_FREQ;
static int report_droprepeat_threshold = DEBUG_REPORT_FREQ;
static unsigned long pushed_msgs = 0;

/* 报告自上次报告后，又被丢弃的消息数量 */
static void print_droped_msgs(void)
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
		INFO("%d similar net msgs zipped. total zipped %lu, pushed %lu msgs\n",
		     i, droped_repeat_msgs, pushed_msgs);
		last_droped_repeat_msgs = droped_repeat_msgs;
		last_report_droprepeat_time = now;
	}
}

/* 报告消息队列满，丢弃新消息 */
static int msg_queue_full(void)
{
	int i = 0;
	time_t now = time(NULL);
	
	if (knet_msg_count < MAX_QUEUE_DEPTH) {
		return 0;
	}

	droped_full_msgs++;

	if (droped_full_msgs == 1) {
		INFO("full queue(%d msgs), drop new net msg\n",
		     knet_msg_count);
		return 1;
	}

	i = droped_full_msgs - last_droped_full_msgs;
	if (last_report_dropfull_time < now - DEBUG_REPORT_INTERVAL) {
		report_dropfull_threshold = DEBUG_REPORT_FREQ;
	} else {
		report_dropfull_threshold += DEBUG_REPORT_FREQ;
	}
	if (i >= report_dropfull_threshold) {
		INFO("full queue(%d msgs), %d net msgs droped\n",
		     knet_msg_count, i);
		last_droped_full_msgs = droped_full_msgs;
		last_report_dropfull_time = now;
	}

	return 1;
}

/* 新获得的消息插入命令队列尾部 */
static void add_knet_msg_queue_tail(knet_msg_t *msg)
{
	pthread_mutex_lock(&knet_msg_queue_lock);
	list_add_tail(&msg->list, &knet_msg_queue);
	knet_msg_count++;
	pthread_mutex_unlock(&knet_msg_queue_lock);
}

/* push msg to queue */
#if 0
void knet_msg_queue_push(netreq_t *req)
#else
void knet_msg_queue_push(struct ebpf_netreq_t *req)
#endif
{
	knet_msg_t *msg = NULL;

	if (!req) {
		return;
	}

	msg = req2msg(req);
	if (!msg) {
		return;
	}

	/* 新的net消息插入队列尾部 */
	pushed_msgs++;
	add_knet_msg_queue_tail(msg);
}

/* 从命令队列中取一个消息处理 */
knet_msg_t *get_knet_msg(void)
{
	knet_msg_t *msg = NULL;

	if (!knet_msg_queue_inited) {
		return NULL;
	}

	pthread_mutex_lock(&knet_msg_queue_lock);
	if (!list_empty(&knet_msg_queue)) {
		msg = list_entry(knet_msg_queue.next, knet_msg_t, list);
		if (msg) {
			list_del(&msg->list);
			knet_msg_count--;
		}
	}
	pthread_mutex_unlock(&knet_msg_queue_lock);

	return msg;
}

static int handle_netreq_ringbuf_event(void *ctx, void *data, size_t data_sz) {
    struct ebpf_netreq_t *req = data;

	if (msg_queue_full()) {
		return 0;
	}
	knet_msg_queue_push(req);
    return 0;
}

#define MALLOC_FAIL 1
#define ENGINE_FAIL 2
#define NOTIFY_CC   4
void *knet_msgd(void *ptr)
{
#if 0 
	struct nlmsghdr *nlh = NULL;
	int reported = 0, engine_on = 0;
	netreq_t *req = NULL;
#else
#endif

	prctl(PR_SET_NAME, "network_mq");
	save_thread_pid("knet_msgd", SNIPER_THREAD_KNETMSG);

	knet_msg_queue_init();
	struct bpf_object *net_program_obj = NULL;
	struct bpf_map *netreq_ringbuf_map = NULL;
	struct ring_buffer *netreq_ringbuf = NULL;

    while (Online) {
#if 0
		/* 许可到期/停止防护/引擎关闭，这边不做处理，由接收消息的地方处理 */
		if (!nlh) {
			nlh = (struct nlmsghdr *)sniper_malloc(NLMSGLEN, NETWORK_GET);
			if (nlh == NULL) {
				if (!(reported & MALLOC_FAIL)) {
					MON_ERROR("knet_msgd malloc nlh fail\n");
					reported |= MALLOC_FAIL;
				}
				/* TODO 报告管控中心 */
				sleep(1);
				continue;
			}
        	}

		if (!engine_on) {
			if (init_engine(NLMSG_NET, nlh) < 0) {
				if (!(reported & ENGINE_FAIL)) {
                        		MON_ERROR("net engine init fail\n");
					reported |= ENGINE_FAIL;
				}
				/* TODO 报告管控中心 */
				sleep(1);
				continue;
			}
			engine_on = 1;
                }

		req = (netreq_t *)get_req(nlh, NLMSG_NET);
		if (!req) {
			continue;
		}

		/* 队列满则丢弃所有新消息 */
		if (msg_queue_full()) {
			continue;
		}

		knet_msg_queue_push(req);
#else
#endif

		if (!net_program_obj) {
			net_program_obj = get_bpf_object(EBPF_NET);
			if (!net_program_obj) {
				sleep(1);
				continue;
			}
		}

		if (!netreq_ringbuf) {
			netreq_ringbuf_map = bpf_object__find_map_by_name(net_program_obj, "netreq_ringbuf");
			int ringbuf_map_fd = bpf_map__fd(netreq_ringbuf_map);
			netreq_ringbuf = ring_buffer__new(ringbuf_map_fd, handle_netreq_ringbuf_event, NULL, NULL);
			if (!netreq_ringbuf) {
				sleep(1);
				continue;
			}
		}

		int err = ring_buffer__poll(netreq_ringbuf, 100 /* timeout, ms */);
		if (err < 0) {
			printf("Error polling netreq_ringbuf: %d\n", err);
		}	

		print_droped_msgs();
	}

#if 0
	fini_engine(NLMSG_NET, nlh);
	if (nlh) {
		sniper_free(nlh, NLMSGLEN, NETWORK_GET);
	}
#else
#endif

	knet_msg_queue_destroy();

	INFO("knet_msgd thread exit\n");
	return NULL;
}
