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
#include <sys/resource.h> 

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


static knet_msg_t *req2msg(struct ebpf_netreq_t *req)
{
	knet_msg_t *msg  = sniper_malloc(sizeof(struct knet_msg), NETWORK_GET);

	if (!msg) {
		MON_ERROR("malloc knet msg fail\n");
		return NULL;
	}

	msg->datalen = sizeof(struct ebpf_netreq_t);
	msg->data = req;

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
void knet_msg_queue_push(struct ebpf_netreq_t *req)
{
	knet_msg_t *msg = NULL;

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

void bump_memlock_rlimit2(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if(setrlimit(RLIMIT_MEMLOCK, &rlim_new)){
		printf("Failed to increase RLIMIT_MEMLOCK limit@%s line:%d\r\n",__FILE__,__LINE__);
		exit(1);
	}
}

static int ringbuf_event2(void *ctx, void *data, size_t data_sz) {
	const struct sock_event  *e=data;

	struct ebpf_netreq_t *req=malloc(sizeof(struct ebpf_netreq_t));
	if(!req) return -1;

	memset(req,0,sizeof(struct ebpf_netreq_t));

	req->uid=e->uid;
    req->gid=e->gid;
	req->pid=e->pid;
    req->tgid=e->tgid;
    req->net_type=e->net_type;

	req->dport=e->dport;
	req->daddr=e->daddr;
	req->sport=e->sport;
	req->saddr=e->saddr;
	req->protocol=e->protocol;

	req->sessionid=e->sessionid;
    req->start_time=e->start_time;
	req->parent_pid=e->parent_pid;
	req->fin=e->fin;
	req->syn=e->syn;
	req->ack=e->ack;

	memcpy(req->parent_pathname,e->parent_pathname,sizeof(e->parent_pathname));
    memcpy(req->parent_comm,e->parent_comm,sizeof(e->parent_comm));
    memcpy(req->pathname,e->pathname,sizeof(e->pathname));
	memcpy(req->comm,e->comm,sizeof(e->comm));

	if (msg_queue_full()) {
		return 0;
	}
	knet_msg_queue_push(req);

    return 0;
}


void *knet_msgd(void *ptr)
{
	prctl(PR_SET_NAME, "network_mq");
	save_thread_pid("knet_msgd", SNIPER_THREAD_KNETMSG);

	knet_msg_queue_init();

	printf("knet_msgd thread start...\r\n");

	// Bump RLIMIT_MEMLOCK to create BPF maps 
	bump_memlock_rlimit2();

	// get_bpf_object
	struct bpf_object *net_program_obj = get_bpf_object(EBPF_NET_OBJ);
	if (!net_program_obj) printf("get_bpf_object@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_object__find_map_by_name
	struct bpf_map *p_ringbuf_map = bpf_object__find_map_by_name(net_program_obj, "net_event_ringbuf");
	if (!p_ringbuf_map) printf("bpf_object__find_map_by_name@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_map__fd
	int ringbuf_map_fd =bpf_map__fd(p_ringbuf_map);
	if (!ringbuf_map_fd<0) printf("bpf_map__fd[%d]@%s line:%d\r\n",ringbuf_map_fd,__FILE__,__LINE__);

	// ring_buffer__new
	struct ring_buffer *p_ringbuf2 = ring_buffer__new(ringbuf_map_fd, ringbuf_event2, NULL, NULL);
	if (!p_ringbuf2){
		printf("failed to create ringbuf@%s line:%d\r\n",__FILE__,__LINE__);
		goto clean_up;
	} 

    while (Online) {

		int err = ring_buffer__poll(p_ringbuf2, 100 /* timeout, ms */);
		if (err < 0) {
			printf("Error polling netreq_ringbuf: %d\n", err);
		}	

		print_droped_msgs();
	}

	knet_msg_queue_destroy();
clean_up:
	/* Clean up */
	ring_buffer__free(p_ringbuf2);
	bpf_object__close(net_program_obj);
	printf("knet_msgd thread exit\n");
	return NULL;
}
