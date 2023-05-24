#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>

#include "logger.h"
#include "header.h"

moni_log_t g_moni_log;

void moni_log_init(moni_log_t *p_log)
{
	struct stat st = {0};

	pthread_mutex_init(&p_log->lock, NULL);

	memset(p_log, 0, sizeof(moni_log_t));
	p_log->max_size = 1048576 * 10; //10MB

	/* 如果日志超过10M，转存 */
	stat(ASSISTLOGFILE, &st);
	if (st.st_size >= p_log->max_size) {
		rename(ASSISTLOGFILE, ASSISTLOGFILE1);
		p_log->count = 0;
	} else {
		p_log->count = st.st_size;
	}

	p_log->log_fd = fopen(ASSISTLOGFILE, "a+");
	if (!p_log->log_fd) {
		printf("open antiapt.log fail: %s\n", strerror(errno));
		p_log->log_fd = stdout;
	} else {
		/* 原打算用syslog()记在系统日志里，但在centos7.6上core在syslog()里 */
		if (st.st_size >= p_log->max_size) {
			printf("rotate antiapt.log\n");
			fprintf(p_log->log_fd, "rotate antiapt.log\n");
			fflush(p_log->log_fd);
		}
	}

	chmod(ASSISTLOGFILE, 0644); //允许普通用户看，便于查错
}

static void rotate_log_file(moni_log_t *p_log)
{
	fclose(p_log->log_fd);
	rename(ASSISTLOGFILE, ASSISTLOGFILE1);

	p_log->log_fd = fopen(ASSISTLOGFILE, "a+");
	if (!p_log->log_fd) {
		printf("open antiapt.log fail: %s\n", strerror(errno));
		p_log->log_fd = stdout;
	} else {
		printf("rotate antiapt.log\n");
		fprintf(p_log->log_fd, "rotate antiapt.log\n");
		fflush(p_log->log_fd);
	}

	chmod(ASSISTLOGFILE, 0644);
	p_log->count = 0;
}

void mon_log(moni_log_t *p_log, const char *caption, const char *text, const int bflush)
{
	int ret = 0;
	struct tm now = {0};
	time_t t = time(NULL);

	/* 没有打开日志文件，比如sniper作工具用时，则打印到屏幕 */
	if (!p_log->log_fd || p_log->log_fd == stdout) {
		if (strcmp(caption, "DEBUG") != 0) {
			printf("%s", text);
		}
		return;
	}

	pthread_mutex_lock(&p_log->lock);

	/* rotate log file */
	if (p_log->max_size && p_log->count > p_log->max_size) {
		rotate_log_file(p_log);
	}

	/* Convert time to a microsecond timestamp */
	localtime_r(&t, &now);

	ret = fprintf(p_log->log_fd, "%04d%02d%02d%02d%02d%02d %d %s -> %s",
			now.tm_year+1900, now.tm_mon+1, now.tm_mday,
			now.tm_hour, now.tm_min, now.tm_sec, getpid(), caption, text);

	/*  flush log */
	if (bflush) {
		fflush(p_log->log_fd);
	}

	if (ret > 0) {
		p_log->count += ret;
	}

	pthread_mutex_unlock(&p_log->lock);
}

void moni_log_destroy(moni_log_t *p_log)
{
	pthread_mutex_destroy(&p_log->lock);
	if (p_log->log_fd && p_log->log_fd != stdout) {
		fclose(p_log->log_fd);
		p_log->log_fd = stdout;
	}
}

void INFO(const char *format, ...)
{
	va_list args;
	char text[LOG_LINE_MAX] = {0};

	va_start(args, format);
	vsnprintf(text, LOG_LINE_MAX, format, args);
	va_end(args);

	if (text[LOG_LINE_MAX - 1] != 0) {
		text[LOG_LINE_MAX - 1] = 0;
		text[LOG_LINE_MAX - 2] = 0;
	}
	mon_log((&g_moni_log), "INFO ", text, 1);
}

void DBG(const char *format, ...)
{
	va_list args;
	char text[LOG_LINE_MAX] = {0};

	va_start(args, format);
	vsnprintf(text, LOG_LINE_MAX, format, args);
	va_end(args);

	if (text[LOG_LINE_MAX - 1] != 0) {
		text[LOG_LINE_MAX - 1] = 0;
		text[LOG_LINE_MAX - 2] = 0;
	}
	mon_log((&g_moni_log), "DEBUG", text, 1);
}

void DBG2(char *flagfile, const char *format, ...)
{
	va_list args;
	char text[LOG_LINE_MAX] = {0};

	if (!flagfile || access(flagfile, F_OK) != 0) {
		return;
	}

	va_start(args, format);
	vsnprintf(text, LOG_LINE_MAX, format, args);
	va_end(args);

	if (text[LOG_LINE_MAX - 1] != 0) {
		text[LOG_LINE_MAX - 1] = 0;
		text[LOG_LINE_MAX - 2] = 0;
	}
	mon_log((&g_moni_log), "DEBUG", text, 1);
}

void MON_ERROR(const char *format, ...)
{
	va_list args;
	char text[LOG_LINE_MAX] = {0};

	va_start(args, format);
	vsnprintf(text, LOG_LINE_MAX, format, args);
	va_end(args);

	if (text[LOG_LINE_MAX - 1] != 0) {
		text[LOG_LINE_MAX - 1] = 0;
		text[LOG_LINE_MAX - 2] = 0;
	}
	mon_log((&g_moni_log), "ERROR", text, 1);
}
