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
#include <sys/resource.h> 

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

/* if message queue is full, dropping new message */
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
		printf("full queue(%d msgs), drop new file msg@%s line:%d\n",kfile_msg_count,__FILE__,__LINE__);
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
		printf("full queue(%d msgs), %d file msgs droped@%s line:%d\n",kfile_msg_count, i,__FILE__,__LINE__);
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
#if 0
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
#else
static kfile_msg_t *req2msg(struct ebpf_filereq_t *req)
{

	kfile_msg_t *msg = (kfile_msg_t *)sniper_malloc(sizeof(struct kfile_msg), FILE_GET);
	if (!msg) {
		printf("kfile_msg_t malloc fail @%s line:%d\n",__FILE__,__LINE__);
		return NULL;
	}

	msg->datalen = sizeof(struct ebpf_filereq_t);

	msg->data = req;

	return msg;
}
#endif

/* add kfile msg to queue tail */
static void add_kfile_msg_queue_tail(kfile_msg_t *msg)
{
	pthread_mutex_lock(&kfile_msg_queue_lock);
	list_add_tail(&msg->list, &kfile_msg_queue);
	kfile_msg_count++;
	pthread_mutex_unlock(&kfile_msg_queue_lock);
}

/* push msg to queue */
void kfile_msg_queue_push(struct ebpf_filereq_t *req)
{				
	kfile_msg_t *msg = req2msg(req);
	if (!msg) {
		printf("msg is null @%s line:%d\r\n",__FILE__,__LINE__);
		return;
	}

	/* add kfile msg to queue tail */
	add_kfile_msg_queue_tail(msg);
}

/* pop msg from queue */
kfile_msg_t *get_kfile_msg(void)
{
	kfile_msg_t *msg = NULL;

	if (!kfile_msg_queue_inited) 
		return NULL;

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

void bump_memlock_rlimit(void)
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

static int ringbuf_event(void *ctx, void *data, size_t size) {

	const struct fevent *e = data;

	struct ebpf_filereq_t *req=malloc(sizeof(struct ebpf_filereq_t));
	if(!req) return -1;

	memset(req,0,sizeof(struct ebpf_filereq_t));
	
	req->pid=e->pid;
	req->tgid=e->tgid;
	req->uid=e->uid;
	req->path_len=e->path_len;
	req->pro_len=e->pro_len;
	req->size=e->size;

	memcpy(req->comm,e->comm,sizeof(e->comm));
	memcpy(req->parent_comm,e->parent_comm,sizeof(e->parent_comm));
	memcpy(req->filename,e->filename,sizeof(e->filename));
	memcpy(req->tty,e->tty,sizeof(e->tty));
	memcpy(req->args,e->args,sizeof(e->args));
	memcpy(req->abs_path,e->abs_path,sizeof(e->abs_path));

	// Only handle vim processes
	if(strcmp(req->comm,"vim")!=0)
		return 0;

	if (file_msg_queue_full())
		return 0;
	
	kfile_msg_queue_push(req);

    return 0;
}

// TODO: Adapt to the ebpf ringbuf....
void *kfile_msgd(void *ptr)
{
	prctl(PR_SET_NAME, "file_mq");
	save_thread_pid("kfile_msgd", SNIPER_THREAD_KFILEMSG);

	kfile_msg_queue_init();

	printf("kfile_msgd thread start...\r\n");

	// Bump RLIMIT_MEMLOCK to create BPF maps 
	bump_memlock_rlimit();

	// get_bpf_object
	struct bpf_object *file_bpf_obj = get_bpf_object(EBPF_FILE);
	if (!file_bpf_obj) printf("get_bpf_object@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_object__find_map_by_name
	struct bpf_map *p_ringbuf_map = bpf_object__find_map_by_name(file_bpf_obj, "fileopen_ringbuf");
	if (!p_ringbuf_map) printf("bpf_object__find_map_by_name@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_map__fd
	int ringbuf_map_fd =bpf_map__fd(p_ringbuf_map);
	if (!ringbuf_map_fd<0) printf("bpf_map__fd[%d]@%s line:%d\r\n",ringbuf_map_fd,__FILE__,__LINE__);

	// ring_buffer__new
	struct ring_buffer *p_ringbuf = ring_buffer__new(ringbuf_map_fd, ringbuf_event, NULL, NULL);
	if (!p_ringbuf){
		printf("failed to create ringbuf@%s line:%d\r\n",__FILE__,__LINE__);
		goto clean_up;
	} 

	while (Online) {

		int err = ring_buffer__poll(p_ringbuf, 100 /* timeout, ms */);
		if (err < 0) {
			printf("Error polling filereq_ringbuf: %d\n", err);
			goto clean_up;
		}
		print_droped_file_msgs();
	}

	kfile_msg_queue_destroy();

clean_up:
	/* Clean up */
	ring_buffer__free(p_ringbuf);
	bpf_object__close(file_bpf_obj);
	printf("kfile_msgd thread exit\n");
	return NULL;
}
