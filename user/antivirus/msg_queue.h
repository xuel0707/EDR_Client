#ifndef _MONI_MQ_H
#define _MONI_MQ_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "list.h"

#define VNAME_MAX        128
#define VTYPE_MAX        128

#define USER_MAX         64
#define S_UUIDLEN        64
#define S_MD5LEN         33

typedef struct virus_info {
	char pathname[PATH_MAX];
	char virus_name[VNAME_MAX];
	char virus_type[VTYPE_MAX];
	char uuid[S_UUIDLEN+1];
	char md5[S_MD5LEN]; 
	char user[USER_MAX];
	int result;
	struct timeval tv;
}virus_info_t;

typedef struct log_msg
{
	char *post_data;
	int  data_len;
	struct log_msg *next;
} log_msg_t;

typedef struct msg_queue
{
	log_msg_t  *head;
	log_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
	int max_depth;
} msg_queue_t;

extern int init_task_msg_queue(void);
extern void destroy_task_msg_queue(void);
extern int http_post_mq(char *post, msg_queue_t *p_queue);
extern int msg_queue_count(msg_queue_t *p_queue);
extern log_msg_t *msg_queue_pop(msg_queue_t *p_queue);

/* 病毒队列最大允许消息数 */
#define MAX_VIRUS_QUEUE_DEPTH         100000
/* 压缩同类的调试日志数量，每N条报一次 */
#define DEBUG_REPORT_FREQ       100
/* 同类调试日志的时间间隔，间隔小于阈值，说明日志量大频繁，需要继续降低报告的频率 */
#define DEBUG_REPORT_INTERVAL   60

/* virus */
typedef struct virus_msg
{
	char *data;
	int datalen;
	struct list_head list;
} virus_msg_t;

typedef struct virus_msg_queue
{
	virus_msg_t  *head;
	virus_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
} virus_msg_queue_t;

extern int virus_msg_queue_init(void);
extern virus_msg_t *get_virus_msg(void);
extern int virus_msg_queue_full(void);
extern void virus_msg_queue_push(virus_info_t *req);
extern void virus_msg_queue_destroy(void);

/* handle */
typedef struct handle_msg
{
	char *data;
	int datalen;
	struct list_head list;
} handle_msg_t;

typedef struct handle_msg_queue
{
	handle_msg_t  *head;
	handle_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
} handle_msg_queue_t;

extern int handle_msg_queue_init(void);
extern handle_msg_t *get_handle_msg(void);
extern int handle_msg_queue_full(void);
extern void handle_msg_queue_push(virus_info_t *req);
extern void handle_msg_queue_destroy(void);

#endif
