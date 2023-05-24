#ifndef _MONI_MQ_H
#define _MONI_MQ_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include "list.h"

/* 任务成员 */
typedef struct log_msg
{
	char *post_data;
	int  data_len;
	struct log_msg *next;
} log_msg_t;

/* 任务消息队列 */
typedef struct msg_queue
{
	log_msg_t  *head;
	log_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
	int max_depth;
} msg_queue_t;

/* 初始化任务队列 */
extern int init_task_msg_queue(void);
/* 销毁任务队列 */
extern void destroy_task_msg_queue(void);
extern int http_post_mq(char *post, msg_queue_t *p_queue);
extern int msg_queue_count(msg_queue_t *p_queue);
extern log_msg_t *msg_queue_pop(msg_queue_t *p_queue);

/* 队列最大允许消息数 */
#define MAX_QUEUE_DEPTH         10000
/* 病毒待过滤队列最大允许消息数 */
#define MAX_FILTER_QUEUE_DEPTH         100000
/* 病毒队列最大允许消息数 */
#define MAX_VIRUS_QUEUE_DEPTH         100000
/* 压缩同类的调试日志数量，每N条报一次 */
#define DEBUG_REPORT_FREQ       100
/* 同类调试日志的时间间隔，间隔小于阈值，说明日志量大频繁，需要继续降低报告的频率 */
#define DEBUG_REPORT_INTERVAL   60

typedef struct kexec_msg
{
	char *data;
	int datalen;
	int repeat;
	time_t queuet;
	time_t zipt;
	struct list_head list;
} kexec_msg_t;

typedef struct kexec_msg_queue
{
	kexec_msg_t  *head;
	kexec_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
} kexec_msg_queue_t;

extern kexec_msg_t *get_kexec_msg(void);
extern void *kexec_msgd(void *ptr);

/*file*/
typedef struct kfile_msg
{
	char *data;
	int datalen;
	int repeat;
	struct list_head list;
} kfile_msg_t;

typedef struct kfile_msg_queue
{
	kfile_msg_t  *head;
	kfile_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
} kfile_msg_queue_t;

extern int file_engine_on;
extern void *kfile_msgd(void *ptr);
extern kfile_msg_t *get_kfile_msg(void);

/*kvirus*/
typedef struct kvirus_msg
{
	char *data;
	int datalen;
	int repeat;
	struct list_head list;
} kvirus_msg_t;

typedef struct kvirus_msg_queue
{
	kvirus_msg_t  *head;
	kvirus_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
} kvirus_msg_queue_t;

extern void *kvirus_msgd(void *ptr);
extern kvirus_msg_t *get_kvirus_msg(void);

/*virus*/
typedef struct virus_msg
{
	char *data;
	int datalen;
	int repeat;
	struct list_head list;
} virus_msg_t;

typedef struct virus_msg_queue
{
	virus_msg_t  *head;
	virus_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
} virus_msg_queue_t;

extern virus_msg_t *get_virus_msg(void);

/*net*/
typedef struct knet_msg
{
	char *data;
	int datalen;
	int repeat;
	struct list_head list;
} knet_msg_t;

typedef struct knet_msg_queue
{
	knet_msg_t  *head;
	knet_msg_t  *tail;
	pthread_mutex_t lock;
	int count;
} knet_msg_queue_t;

extern void *knet_msgd(void *ptr);
extern knet_msg_t *get_knet_msg(void);

#endif
