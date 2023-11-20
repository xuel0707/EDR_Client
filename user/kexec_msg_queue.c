/*
 * 取内核进程消息，插入进程消息队列，进程工作线程消费消息
 * Author: zhengxiang
 */

#include "header.h"

static int kexec_msg_queue_inited = 0;
static struct list_head kexec_msg_queue = {0};
static pthread_mutex_t kexec_msg_queue_lock = {{0}};
static int kexec_msg_count = 0;

int get_kexec_msg_count(void)
{
	return kexec_msg_count;
}

/* init kexec msg queue */
static void kexec_msg_queue_init(void)
{
	pthread_mutex_init(&kexec_msg_queue_lock, NULL);
	INIT_LIST_HEAD(&kexec_msg_queue);
	kexec_msg_queue_inited = 1;  //消息队列已备标志
}

/* destory msg queue */
static void kexec_msg_queue_destroy(void)
{
        kexec_msg_t *msg = NULL, *m = NULL;

	pthread_mutex_lock(&kexec_msg_queue_lock);

	list_for_each_entry_safe(msg, m, &kexec_msg_queue, list) {
		list_del(&msg->list);
		sniper_free(msg->data, msg->datalen, PROCESS_GET);
		sniper_free(msg, sizeof(struct kexec_msg), PROCESS_GET);
	}

	pthread_mutex_unlock(&kexec_msg_queue_lock);

	pthread_mutex_destroy(&kexec_msg_queue_lock);
}

#define SHELLS 6
#define SCRIPTS 12
static char scriptprogram[SCRIPTS][8] = {
	"sh", "bash", "csh", "ksh", "tcsh", "dash",
	"python", "perl", "php", "php5", "java", ""
	};
static int is_scriptprogram(char *path)
{
	int i;
	char *cmd = safebasename(path);

	for (i = 0; i < SCRIPTS; i++) {
		if (strcmp(cmd, scriptprogram[i]) == 0) {
			return 1;
		}
	}
	return 0;
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
		INFO("%d similar exec msgs zipped. total zipped %lu, pushed %lu msgs\n",
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
	
	if (kexec_msg_count < MAX_QUEUE_DEPTH) {
		return 0;
	}

	droped_full_msgs++;

	if (droped_full_msgs == 1) {
		INFO("full queue(%d msgs), drop new exec msg\n", kexec_msg_count);
		return 1;
	}

	i = droped_full_msgs - last_droped_full_msgs;
	if (last_report_dropfull_time < now - DEBUG_REPORT_INTERVAL) {
		report_dropfull_threshold = DEBUG_REPORT_FREQ;
	} else {
		report_dropfull_threshold += DEBUG_REPORT_FREQ;
	}
	if (i >= report_dropfull_threshold) {
		INFO("full queue(%d msgs), %d exec msgs droped\n", kexec_msg_count, i);
		last_droped_full_msgs = droped_full_msgs;
		last_report_dropfull_time = now;
	}

	return 1;
}

static void drop_msg(kexec_msg_t *msg)
{
	droped_repeat_msgs++;

	if (msg) {
		/* 释放丢弃的消息 */
		sniper_free(msg->data, msg->datalen, PROCESS_GET);
		sniper_free(msg, sizeof(struct kexec_msg), PROCESS_GET);
	}
}

/* 新获得的消息插入命令队列尾部 */
static void add_kexec_msg_queue_tail(kexec_msg_t *msg)
{
	pthread_mutex_lock(&kexec_msg_queue_lock);
	list_add_tail(&msg->list, &kexec_msg_queue);
	kexec_msg_count++;
	pthread_mutex_unlock(&kexec_msg_queue_lock);
}

#if 0
/* 判断sh -c xxx和sh -c yyy是否类似 */
static int similar_shellcmd(char *cmdline1, char *cmdline2)
{
	char *cmd1 = NULL, *cmd2 = NULL;
	char *ptr1 = NULL, *ptr2 = NULL;
	int len1 = 0, len2 = 0;

	if (!cmdline1 || !cmdline2) {
		return 0;
	}
	cmd1 = strstr(cmdline1, " -c ");
	cmd2 = strstr(cmdline2, " -c ");

	if (!cmd1 && !cmd1) {
		if (strcmp(cmdline1, cmdline2) == 0) {
			return 1;
		}
		return 0;
	}

	if ((cmd1 && !cmd2) || (!cmd1 && cmd2)) {
		return 0;
	}

	cmd1 += 4;
	cmd2 += 4;
	ptr1 = strchr(cmd1, ' ');
	ptr2 = strchr(cmd2, ' ');

	if (!ptr1 && !ptr2) {
		if (strcmp(cmd1, cmd2) == 0) {
			return 1;
		}
		return 0;
	}

	if ((ptr1 && !ptr2) || (!ptr1 && ptr2)) {
		return 0;
	}

	len1 = ptr1 - cmd1;
	len2 = ptr2 - cmd2;
	if (len1 != len2) {
		return 0;
	}
	if (strncmp(cmd1, cmd2, len1) == 0) {
		return 1;
	}
	return 0;
}
#endif

/* 调用者加锁 */
static int zip_msg(kexec_msg_t *msg)
{
	kexec_msg_t *msgptr = NULL;
	taskreq_t *req = NULL;
	taskreq_t *oldreq = NULL;
	char *cmd = NULL, *oldcmd = NULL;
	char *args = NULL, *oldargs = NULL;
	char *cwd = NULL, *oldcwd = NULL;
	int is_script = 0;
	int pflags_size = sizeof(struct task_flags);

	if (!msg) {
		return 1;
	}
	req = (taskreq_t *)msg->data;
	if (!req) {
		return 1;
	}
	if (req->cmdlen >= S_CMDLEN) {
		MON_ERROR("%s(%d) bad cmdlen %d\n",
			  &req->args, req->pid, req->cmdlen);
		return 1;
	}

	/* 事件日志和命令行审计日志不压缩 */
	if (req->pflags.killsniper || req->pflags.commandline    ||
	    req->pflags.privup     || req->pflags.dirtycow       ||
	    req->pflags.minepool   || req->pflags.miner          ||
	    req->pflags.danger     || req->pflags.abnormal       ||
	    req->pflags.writedisk  || req->pflags.port_forward   ||
	    req->pflags.webshell   || req->pflags.webexec_danger ||
	    req->pflags.black) {
		return 0;
	}

	cmd  = &req->args;
	args = cmd + req->cmdlen + 1;
	cwd  = args + req->argslen + 1;
	is_script = is_scriptprogram(cmd);

	list_for_each_entry(msgptr, &kexec_msg_queue, list) {
		oldreq = (taskreq_t *)msgptr->data;
		if (!oldreq) {
			list_del(&msgptr->list);
			drop_msg(msgptr);
			kexec_msg_count--;
		}

#if 0
		if (oldreq->flags & PSR_NOTZIP) {
			continue;
		}
#endif

		oldcmd  = &oldreq->args;
		oldargs = oldcmd + oldreq->cmdlen + 1;
		oldcwd  = oldargs + oldreq->argslen + 1;

		//TODO 需要要求相同目录吗？
		/* 压缩同一个用户在同一个目录下同一个父进程做的同一类命令 */
		/* 命令相同，参数数目相同，参数选项数目相同，进程标志相同 */
		if (req->euid != oldreq->euid ||
		    req->argc != oldreq->argc ||
		    req->flags != oldreq->flags ||
		    req->options != oldreq->options ||
		    req->cmdlen != oldreq->cmdlen ||
		    strcmp(cmd, oldcmd) != 0 ||
		    strcmp(cwd, oldcwd) != 0 ||
		    memcmp(&req->pflags, &oldreq->pflags, pflags_size) != 0 ||
		    strcmp(req->pinfo.task[0].comm, oldreq->pinfo.task[0].comm) != 0) {
			/* 不同，和队列里的下一个比较 */
			continue;
		}

		/* 对于脚本语言程序，参数完全一致才合并 */
		if (is_script) {
#if 0
			/* shell -c的情况，比较-c后的命令名 */
			/* 非shell脚本，命令完全相同才压缩。*/
			/* TODO 是否也有如shell -c的用法 */
			if (is_script > SHELLS) {
				if (strcmp(str, oldstr) != 0) {
					continue;
				}
			} else if (!similar_shellcmd(str, oldstr)) {
				continue;
			}
#else
			if (strcmp(args, oldargs) != 0) {
				continue;
			}
#endif
		}

		msgptr->repeat++;
		if (msgptr->repeat < 5) {
			break;
		}
		msgptr->zipt = time(NULL);

		/* TODO 设置TASK_DROP标志，令被丢弃进程的子进程也丢弃? */

		drop_msg(msg);
		return 1;
	}

	return 0;
}

static void get_entire_filename(struct ebpf_taskreq_t *req) {
	int is_container = 1;
	int ret;
	int file_inode;
	struct stat file_stat;
	char container_prefix[128] = {0};

	if (strncmp(req->nodename, "docker", 6)!=0 ){
		// printf("The file is from HOST\n");
		return;
	}
	else {
		// printf("The file is from Container!\nNodename is %s\n", file_data->nodename);
		struct bpf_object *file_program_obj = NULL;
		file_program_obj = get_bpf_object(EBPF_FILE_OBJ);
		if (!file_program_obj) {
			printf("can't find the ebpf file program\n");
			return;
		}
		struct bpf_map *file_map = bpf_object__find_map_by_name(file_program_obj, "container_prefix_map");
		int file_map_fd = bpf_map__fd(file_map);
		memset(container_prefix, 0, sizeof(container_prefix));
		ret = bpf_map_lookup_elem(file_map_fd, req->nodename, container_prefix);
		if (ret!=0) {
			printf("No prefix value been found...\n");
			return ;
		}
		// printf("prefix is %s\nfilename is %s\n", container_prefix, req->cmd);
		strncat(container_prefix, req->cmd, sizeof(container_prefix)-strlen(container_prefix)-1);
		// container_prefix[sizeof(container_prefix)-1] = 0;
		strncpy(req->cmd, container_prefix, sizeof(req->cmd)-1);
		req->cmd[sizeof(req->cmd)-1] = 0;
		req->cmdlen = strlen(req->cmd);  // req->cmd is changed, so update cmdlen.
		// printf("Last Filename is %s\n", req->cmd);
		return;

	}
}

/* 将内核命令请求封装成命令消息 */
#if 0
static kexec_msg_t *req2msg(taskreq_t *req)
{
	kexec_msg_t *msg = NULL;

	if (!req) {
		return NULL;
	}

    msg = (kexec_msg_t *)sniper_malloc(sizeof(struct kexec_msg), PROCESS_GET);
	if (!msg) {
		MON_ERROR("malloc kexec msg fail\n");
		return NULL;
	}

	msg->datalen = req->size;
	msg->data = sniper_malloc(msg->datalen, PROCESS_GET);
	if (!msg->data) {
		MON_ERROR("malloc kexec msg databuf fail\n");
		sniper_free(msg, sizeof(struct kexec_msg), PROCESS_GET);
		return NULL;
	}

	memcpy(msg->data, req, msg->datalen);
	msg->repeat = 0;

	return msg;
}
#else
static kexec_msg_t *req2msg(struct ebpf_taskreq_t *req)
{
	kexec_msg_t *msg = NULL;

	if (!req) {
		return NULL;
	}

	msg = (kexec_msg_t *)sniper_malloc(sizeof(struct kexec_msg), PROCESS_GET);
	if (!msg) {
		MON_ERROR("malloc kexec msg fail\n");
		return NULL;
	}

	msg->datalen = sizeof(struct ebpf_taskreq_t);
	msg->data = sniper_malloc(msg->datalen, PROCESS_GET);
	if (!msg->data) {
		MON_ERROR("malloc kexec msg databuf fail\n");
		sniper_free(msg, sizeof(struct kexec_msg), PROCESS_GET);
		return NULL;
	}
	memset(msg->data, 0, msg->datalen);
	memcpy(msg->data, req, msg->datalen);
	msg->repeat = 0;
	get_entire_filename((struct ebpf_taskreq_t *)msg->data);

	return msg;
}
#endif

/* push msg to queue */
#if 0
void kexec_msg_queue_push(taskreq_t *req)
{
	kexec_msg_t *msg = NULL;
	int drop = 0;

	if (!req) {
		return;
	}

	msg = req2msg(req);
	if (!msg) {
		return;
	}

	/* 压缩相似消息 */
	pthread_mutex_lock(&kexec_msg_queue_lock);
	drop = zip_msg(msg);
	pthread_mutex_unlock(&kexec_msg_queue_lock);
	if (drop) {
		return;
	}

	/* 新的exec消息插入队列尾部 */
	msg->queuet = time(NULL);
	pushed_msgs++;
	add_kexec_msg_queue_tail(msg);
}
#else
void kexec_msg_queue_push(struct ebpf_taskreq_t *req)
{
	kexec_msg_t *msg = NULL;
	// int drop = 0;

	if (!req) {
		return;
	}

	msg = req2msg(req);
	if (!msg) {
		return;
	}

	// NOTE(luoyinhong): disable zip for now
	/* 压缩相似消息 */
	// pthread_mutex_lock(&kexec_msg_queue_lock);
	// drop = zip_msg(msg);
	// pthread_mutex_unlock(&kexec_msg_queue_lock);
	// if (drop) {
		// return;
	// }

	/* 新的exec消息插入队列尾部 */
	msg->queuet = time(NULL);
	pushed_msgs++;
	add_kexec_msg_queue_tail(msg);
}
#endif
/* proccess线程从命令队列中取一个消息处理 */
kexec_msg_t *get_kexec_msg(void)
{
	kexec_msg_t *msg = NULL, *m = NULL;
	time_t now = time(NULL);

	if (!kexec_msg_queue_inited) {
		return NULL;
	}

	pthread_mutex_lock(&kexec_msg_queue_lock);

	/*
	 * 为了提高消息压缩率，令压缩过的消息在队列里多待一会儿:
	 * 上次重复时间5秒内，且入队列时间不满5分钟的，不出队列
	 */
	list_for_each_entry_safe(msg, m, &kexec_msg_queue, list) {
		if (now - msg->zipt < 5 && now - msg->queuet < 300) {
			continue;
		}
		list_del(&msg->list);
		kexec_msg_count--;

		pthread_mutex_unlock(&kexec_msg_queue_lock);
		return msg;
	}

	pthread_mutex_unlock(&kexec_msg_queue_lock);
	return NULL;
}

static int handle_taskreq_ringbuf_event(void *ctx, void *data, size_t data_sz) {
    struct ebpf_taskreq_t *req = data;

	if (msg_queue_full()) {
		return 0;
	}
	kexec_msg_queue_push(req);
    return 0;
}

#define MALLOC_FAIL 1 //已经报过分配空间失败，不重复报
#define ENGINE_FAIL 2 //已经报告引擎初始化失败，不重复报
void *kexec_msgd(void *ptr)
{
#if 0
	int reported = 0, engine_on = 0;
	struct nlmsghdr *nlh = NULL;
	taskreq_t *req = NULL;
#else
#endif

	prctl(PR_SET_NAME, "process_mq");
	save_thread_pid("kexec_msgd", SNIPER_THREAD_KEXECMSG);

	kexec_msg_queue_init();

	struct bpf_object *execve_program_obj = NULL;
	struct bpf_map *taskreq_ringbuf_map = NULL;
	struct ring_buffer *taskreq_ringbuf = NULL;

	while (Online) {
		/* 许可到期/停止防护/引擎关闭，这边不做处理，由接收消息的地方处理 */
#if 0
		// if (!nlh) {
		// 	nlh = (struct nlmsghdr *)sniper_malloc(NLMSGLEN, PROCESS_GET);
		// 	if (nlh == NULL) {
		// 		if (!(reported & MALLOC_FAIL)) {
		// 			MON_ERROR("kexec_msgd malloc nlh fail\n");
		// 			reported |= MALLOC_FAIL;
		// 		}
		// 		/* TODO 报告管控中心 */
		// 		sleep(1);
		// 		continue;
		// 	}
		// }
		// TODO(luoyinhong): replace
		// if (!engine_on) {
		// 	if (init_engine(NLMSG_EXEC, nlh) < 0) {
		// 		if (!(reported & ENGINE_FAIL)) {
        //                 		MON_ERROR("process engine init fail\n");
		// 			reported |= ENGINE_FAIL;
		// 		}
		// 		/* TODO 报告管控中心 */
		// 		sleep(1);
		// 		continue;
		// 	}
		// 	engine_on = 1;
		// 	INFO("process engine on\n");
		// }
#else

		if (!execve_program_obj) {
			execve_program_obj = get_bpf_object(EBPF_EXECVE_OBJ);
			if (!execve_program_obj) {
				sleep(1);
				continue;
			}
		}
		if (!taskreq_ringbuf) {
			taskreq_ringbuf_map = bpf_object__find_map_by_name(execve_program_obj, "taskreq_ringbuf");
			int ringbuf_map_fd = bpf_map__fd(taskreq_ringbuf_map);
			taskreq_ringbuf = ring_buffer__new(ringbuf_map_fd, handle_taskreq_ringbuf_event, NULL, NULL);
			if (!taskreq_ringbuf) {
				sleep(1);
				continue;
			}
		}
#endif

#if 0
		/* 读取内核命令消息 */
		req = (taskreq_t *)get_req(nlh, NLMSG_EXEC);
		if (!req) {
			continue;
		}

		/* 队列满则丢弃所有新消息 */
		if (msg_queue_full()) {
			continue;
		}

		/* 将核命令消息入消息队列 */
		kexec_msg_queue_push(req);
#else
		int err = ring_buffer__poll(taskreq_ringbuf, 100 /* timeout, ms */);
		if (err < 0) {
			printf("Error polling taskreq_ringbuf: %d\n", err);
		}	
#endif
		print_droped_msgs();
	}

#if 0
	fini_engine(NLMSG_EXEC, nlh);
	if (nlh) {
		sniper_free(nlh, NLMSGLEN, PROCESS_GET);
	}
#else
#endif
	kexec_msg_queue_destroy();

	INFO("kexec_msgd thread exit\n");
	return NULL;
}
