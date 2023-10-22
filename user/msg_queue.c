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

msg_queue_t *task_msg_queue = NULL;

int init_task_msg_queue(void)
{
	task_msg_queue = (msg_queue_t *)malloc(sizeof(msg_queue_t));
	if (task_msg_queue == NULL) {
		MON_ERROR("malloc task_msg_queue failed!\n");
		return -1;
	}

	task_msg_queue->head = NULL;
	task_msg_queue->tail = NULL;
	task_msg_queue->count = 0;
	pthread_mutex_init (&(task_msg_queue->lock), NULL);

	return 0;
}

/* destory msg queue */
int msg_queue_destory(msg_queue_t *msg_queue)
{
	log_msg_t *p_msg;
	log_msg_t *p_tmp_msg;

	p_msg = msg_queue->head;
	while (p_msg != NULL) {
		p_tmp_msg = p_msg;
		p_msg = p_msg->next;

		free(p_tmp_msg->post_data);
		free(p_tmp_msg);
	}

	pthread_mutex_destroy(&(msg_queue->lock));

	sniper_free(msg_queue, sizeof(msg_queue_t), OTHER_GET);
	return 0;
}

void destroy_task_msg_queue(void)
{
	msg_queue_destory(task_msg_queue);
}

/* push msg to queue */
int msg_queue_push(msg_queue_t *p_queue, log_msg_t *p_msg)
{
	pthread_mutex_lock(&(p_queue->lock));

	p_msg->next = NULL;
        if (p_queue->tail == NULL) {
                p_queue->head = p_msg;
        } else {
                p_queue->tail->next = p_msg;
        }

        p_queue->tail = p_msg;
	p_queue->count ++;

	DBG2(DBGFLAG_TASK, "task push msg count:(%d)\n", p_queue->count);
        //printf("push msg:%d---\n", p_queue->count);
	pthread_mutex_unlock(&(p_queue->lock));

        return 0;
}

/* pop msg from queue */
log_msg_t *msg_queue_pop(msg_queue_t *p_queue)
{
	log_msg_t *p_msg = NULL;

	pthread_mutex_lock(&(p_queue->lock));

	p_msg = p_queue->head;
        if (p_msg == NULL) {
		pthread_mutex_unlock(&(p_queue->lock));
           	return NULL;
        }

	if (p_msg != NULL) {
		p_queue->head = p_msg->next;
		if (p_queue->head == NULL) {
			p_queue->tail = NULL;
		}
		p_queue->count --;
	}

	DBG2(DBGFLAG_TASK, "task pop msg count:(%d)\n", p_queue->count);
        //printf("pop msg:%d---\n", p_queue->count);
	pthread_mutex_unlock(&(p_queue->lock));

	return p_msg;
}

int msg_queue_count(msg_queue_t *p_queue)
{
	int cnt = 0;
	pthread_mutex_lock(&(p_queue->lock));
	cnt = p_queue->count;
	pthread_mutex_unlock(&(p_queue->lock));
	return cnt;
}
	
/* return 0: ok
 * 	 -1: failed!
 */
int http_post_mq(char *post, msg_queue_t *p_queue)
{
	int ret = -1;
	int len = 0;
        log_msg_t *p_msg = NULL;

	if(post == NULL || p_queue == NULL) {
		return -1;
	}

        p_msg = (log_msg_t *)malloc(sizeof(log_msg_t));
	if (p_msg == NULL) {
		MON_ERROR("malloc p_msg failed!\n");
		return -1;
	}
	
	len = strlen(post);	
        p_msg->post_data = malloc(len+1);
	if (p_msg->post_data == NULL) {
		MON_ERROR("malloc p_msg.post_data failed!\n");
		free(p_msg);
		return -1;
	}

	memset(p_msg->post_data, 0, len+1);
        strncpy(p_msg->post_data, post, len);
	p_msg->data_len = len;

	//printf("---push queue msg:%s---\n",post);
        ret = msg_queue_push(p_queue, p_msg);

	return ret;
}

#if 0
/* 1) dump msg queue to a file
 * 2) zip the file (gzip) 
 * 3) send to server */
int send_mq_msg()
{
	int i = 0 ;
	int ret = 0;
	char filename[64] = {0};
	log_msg_t *p_msg;
	gzFile gzfile;
	time_t t;
	struct tm now;
	int msg_cnt = 0;

	msg_cnt = msg_queue_count(g_msg_queue);
	//printf("---call send_mq_msg(%d)----\n",msg_cnt);
	if (msg_cnt > 0) {
		//printf("---dump msg_cnt:%d---\n", msg_cnt);
		t = time(NULL);
		localtime_r(&t, &now);
		sprintf(filename, "/tmp/%04d%02d%02d%02d%02d%02d.gz",now.tm_year+1900, now.tm_mon+1,
				now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec);

		gzfile = gzopen(filename, "wb");

		for (i=0; i< msg_cnt; i++) {
			p_msg = msg_queue_pop(g_msg_queue);
			if (p_msg != NULL) {
				gzprintf(gzfile,"%s\n",p_msg->post_data);
				free(p_msg->post_data);
				free(p_msg);
			}
		}

		gzclose(gzfile);

		ret = http_upload_file(filename, "api/logs");
		if (ret == 0) {
			unlink(filename);
		}
	}

	return ret;
}
#endif
