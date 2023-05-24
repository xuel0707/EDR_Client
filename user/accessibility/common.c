#include "header.h"

char *nullstr = "";

off_t my_zip(char *filepath, char *gz_path)
{
	int len = 0;
	off_t size = 0;
	char *filename = NULL;
	FILE *fp = NULL;
	gzFile gz_fp;
        char buf[512] = {0};
	struct stat st = {0};

	if (!filepath || !gz_path) {
		return 0;
	}

	if (stat(filepath, &st) < 0) {
		MON_ERROR("my_zip stat %s: %s\n", filepath, strerror(errno));
                return 0;
	}

        fp = fopen(filepath, "rb");
        if (!fp) {
		MON_ERROR("my_zip open %s: %s\n", filepath, strerror(errno));
                return 0;
	}

	filename = safebasename(filepath);
        snprintf(gz_path, S_SHORTPATHLEN, "/tmp/%s.gz", filename);
        gz_fp = gzopen(gz_path, "wb");
        if (!gz_fp) {
                fclose(fp);
                return 0;
        }

        while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		size += len;
                gzwrite(gz_fp, buf, len);
        }

	if (size != st.st_size) {
		INFO("Warning! %s size %lu, my_zip %lu\n",
		     filepath, st.st_size, size);
	}

        fclose(fp);
        gzclose(gz_fp);

	return st.st_size;
}

char *safebasename(char *path)
{
        char *baseptr = NULL;

        if (path == NULL) {
                return nullstr;
        }

	/* 不是以/或.开头的，basename即path，如events/0核心线程 */
	if (path[0] != '/' && path[0] != '.') {
		return path;
	}

        baseptr = strrchr(path, '/');
        if (baseptr) {
                return baseptr+1;
        }

        return path;
}

/*
 * 检查客户端程序是否已经在运行，防止重复运行客户端程序
 * 返回0，没有客户端程序在运行
 * 返回1，有客户端程序在运行
 * 返回-1，视为没有客户端程序在运行，但有错误发生
 */
int is_this_running(void)
{
	int pid_fd = 0;
	char buf[32] = {0};
	int ver_fd = -1;
	int len = 0;
	struct flock fl = {0};

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	pid_fd = open(ASSIST_PIDFILE, O_RDWR|O_CREAT, 0644);
	if (pid_fd < 0) {
		fprintf(stderr, "Open %s fail: %s\n", ASSIST_PIDFILE, strerror(errno));
		MON_ERROR("Open %s fail: %s\n", ASSIST_PIDFILE, strerror(errno));
		return -1;
	}
	fchmod(pid_fd, 0644); //防止umask屏蔽掉0044

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		/* lock file failed means another is running */
		INFO("Sniper already running\n");
		close(pid_fd);
		return 1;
	}

	len = snprintf(buf, 32, "%d", getpid());
	if (len < 0 ) {
		fprintf(stderr, "get pid fail: %s\n", strerror(errno));
		MON_ERROR("get pid fail: %s\n", strerror(errno));
		close(pid_fd);
		return -1;
	}

	if (write(pid_fd, buf, len+1) < 0) {
		fprintf(stderr, "Wrtie %s fail: %s\n", ASSIST_PIDFILE, strerror(errno));
		MON_ERROR("Wrtie %s fail: %s\n", ASSIST_PIDFILE, strerror(errno));
		close(pid_fd);
		return -1;
	}

	return 0;
}
