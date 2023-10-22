#ifndef __QT_SINGLE_H_
#define __QT_SINGLE_H_

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

static int is_this_running(const char *type)
{
	int fd = 0, len = 0;
	char pidfile[S_SHORTPATHLEN] = {0};
	char buf[S_NAMELEN] = {0};
	struct flock fl;

	snprintf(pidfile, S_SHORTPATHLEN, "/tmp/sniper_%s.%d", type, geteuid());
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;	

	fd = open(pidfile, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		/* error */
		//fprintf(stderr, "Open %s fail: %s\n", pidfile, strerror(errno));
		return -1;
	}

	if (fcntl(fd, F_SETLK, &fl) < 0) {
		/* lock file failed means another is running */
		//fprintf(stderr, "Sniper %s already running\n", type);
		close(fd);
		return 1;
	}

	len = snprintf(buf, S_NAMELEN, "%d", getpid());
	if (write(fd, buf, len+1) < 0) {
		//fprintf(stderr, "save sniper_%s pid fail: %s\n", type, strerror(errno));
	}
	return 0;
}
#endif
