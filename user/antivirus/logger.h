#ifndef _LOGGER_H
#define _LOGGER_H

#define LOG_LINE_MAX    2048
#define MAX_PATH_SIZE 	256

typedef struct moni_log {
	unsigned long 	max_size;
	unsigned long 	count;      //cur_size
	FILE 		*log_fp;
	pthread_mutex_t lock;
} moni_log_t;

extern moni_log_t g_moni_log;

extern void moni_log_init(moni_log_t *p_log, char *logfile);
extern void mon_log(moni_log_t *p_log, const char *caption, const char *text, const int bflush);
extern void moni_log_destroy(moni_log_t *p_log);

extern void MON_ERROR(const char *format, ...);
extern void MON_DBG(const char *format, ...);
extern void INFO(const char *format, ...);
extern void DBG(const char *format, ...);
extern void DBG2(char *flagfile, const char *format, ...);
extern void MON_DBG2(char *flagfile, const char *format, ...);
extern void check_clean_log(void);
extern void print_tips(void);

#endif
