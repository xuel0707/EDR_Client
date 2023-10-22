#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>

#include "logger.h"
#include "header.h"

moni_log_t g_moni_log;
unsigned char Debug = 0;

void moni_log_init(moni_log_t *p_log, char *logfile)
{
	pthread_mutex_init(&p_log->lock, NULL);

	memset(p_log, 0, sizeof(moni_log_t));
	p_log->max_size = 10485760; //10MB

	if (!logfile) {
		p_log->log_fp = stdout;
		return;
	}

	p_log->log_fp = fopen(logfile, "a");
	if (!p_log->log_fp) {
		/* 原打算用syslog()记在系统日志里，但在centos7.6上core在syslog()里，原因未明 */
		printf("open %s fail: %s\n", logfile, strerror(errno));
		p_log->log_fp = stdout;
		return;
	}

	p_log->count = ftell(p_log->log_fp);
	//printf("%s size %lu\n", logfile, p_log->count);

	chmod(logfile, 0644); //允许普通用户看，便于查错
}

static void rotate_log_file(moni_log_t *p_log)
{
	int fd = 0;
	pid_t pid = 0;
	char path[256] = {0};
	char logfile[256] = {0};
	char oldlogfile[512] = {0};

	if (!p_log->log_fp || p_log->log_fp == stdout) {
		return;
	}

	fd = fileno(p_log->log_fp);
	if (fd < 0) {
		printf("rotate_log_file: get log fd fail: %s\n", strerror(errno));
		return;
	}

	pid = getpid();
	snprintf(path, 256, "/proc/%d/fd/%d", pid, fd);
	if (readlink(path, logfile, 255) <= 0) {
		printf("rotate_log_file: readlink %s fail: %s\n", path, strerror(errno));
		return;
	}

	snprintf(oldlogfile, 512, "%s.1", logfile);

	fclose(p_log->log_fp);
	if (rename(logfile, oldlogfile) < 0) {
		printf("rotate_log_file: rename %s to %s fail: %s\n", logfile, oldlogfile, strerror(errno));
		return;
	}

	p_log->count = 0;

	p_log->log_fp = fopen(logfile, "a");
	if (!p_log->log_fp) {
		printf("rotate_log_file: open %s fail: %s\n", logfile, strerror(errno));
		p_log->log_fp = stdout;
		return;
	}

	printf("%s rotated\n", logfile);
	fprintf(p_log->log_fp, "Log rotated\n");
	fflush(p_log->log_fp);

	chmod(logfile, 0644); //允许普通用户看，便于查错
}

void mon_log(moni_log_t *p_log, const char *caption, const char *text, const int bflush)
{
	int ret = 0;
	struct tm now = {0};
	time_t t = time(NULL);

	/* 没有打开日志文件，比如sniper作工具用时，则打印到屏幕 */
	if (!p_log->log_fp || p_log->log_fp == stdout) {
		if (strcmp(caption, "DEBUG") != 0) {
			printf("%s", text);
		}
		return;
	}

	pthread_mutex_lock(&p_log->lock);

	/* 如果日志超过10M，转存 */
	if (p_log->max_size && p_log->count > p_log->max_size) {
		rotate_log_file(p_log);
	}

	/* Convert time to a microsecond timestamp */
	localtime_r(&t, &now);

	ret = fprintf(p_log->log_fp, "%04d%02d%02d%02d%02d%02d %d %s -> %s",
			now.tm_year+1900, now.tm_mon+1, now.tm_mday,
			now.tm_hour, now.tm_min, now.tm_sec, getpid(), caption, text);

	/*  flush log */
	if (bflush) {
		fflush(p_log->log_fp);
	}

	if (ret > 0) {
		p_log->count += ret;
	}

	pthread_mutex_unlock(&p_log->lock);
}

void moni_log_destroy(moni_log_t *p_log)
{
	pthread_mutex_destroy(&p_log->lock);
	if (p_log->log_fp && p_log->log_fp != stdout) {
		fclose(p_log->log_fp);
		p_log->log_fp = stdout;
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

	if (Debug == 0)
		return;

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

void MON_WARNING(const char *format, ...)
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
	mon_log((&g_moni_log), "WARNING", text, 1);
}
