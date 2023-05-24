#include "tray.h"
#include <QApplication>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <sys/prctl.h>

/*
 * 安装时起托盘程序，需要在安装脚本中先取并设置下面3个环境变量：
 * 1、DBUS_SESSION_BUS_ADDRESS
 *    如DBUS_SESSION_BUS_ADDRESS=unix:abstract=/tmp/dbus-7i4aPubkTA
 *    安装时需要在terminal里提升到root权限，但托盘程序需要运行在原来的普通用户权限，
 *    DBUS_SESSION_BUS_ADDRESS用来指示托盘程序与dbus总线的通信地址，
 *    值要与普通用户起terminal时相同，否则托盘程序起不来
 * 2、GNOME_DESKTOP_SESSION_ID
 *    如GNOME_DESKTOP_SESSION_ID=this-is-deprecated
 *    指示窗口显示的风格，使root下起的窗口和普通用户下起的外观一样
 * 3、HOME
 *    如HOME=/home/jessie
 *    HOME目录恢复普通用户的，否则禁止重复起托盘程序，和保存信息的默认目录，都不对
 */

/* 托盘程序长期存在，因此pid文件不放在/tmp目录里，以免被清理了 */
/*
 * check is another process is already runnning?
 * return -1 if failed, 1 if another is running, 0 if successfully
 */
static int is_this_running(uid_t uid)
{
	char pidfile[1024] = {0};
	char buf[32] = {0};
	int pid_fd = 0;
	int len = 0;
	struct flock fl;
	FILE *fp = NULL;
	pid_t pid = getpid();

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	snprintf(pidfile, 1024, "/dev/shm/%s.%u", TRAY_PIDFILE, uid);
	pid_fd = open(pidfile, O_RDWR|O_CREAT, 0644);
	if (pid_fd < 0) {
		/* error */
		fprintf(stderr, "Open %s fail: %s\n", pidfile, strerror(errno));
		fp = fopen("/tmp/snipertray.error", "a");
		chmod("/tmp/snipertray.error", 0777);
		if (fp) {
			fprintf(fp, "process %d Open %s fail: %s\n",
				pid, pidfile, strerror(errno));
			fclose(fp);
		}
		return -1;
	}

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		/* lock file failed means another is running */
		fprintf(stderr, "snipertray already running\n");
		close(pid_fd);
		return 1;
	}

	len = snprintf(buf, 32, "%d", pid);

	if (write(pid_fd, buf, len+1) < 0) {
		fp = fopen("/tmp/snipertray.error", "a");
		chmod("/tmp/snipertray.error", 0777);
		fprintf(stderr, "Write %s fail: %s\n", pidfile, strerror(errno));
		if (fp) {
			fprintf(fp, "process %d Write %s fail: %s\n",
				pid, pidfile, strerror(errno));
			fclose(fp);
		}
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
    uid_t uid = 0;
    pid_t pid = 0, pgid = 0;

    if (argc > 2) {
        printf("Usage: %s [username]\n", argv[0]);
        exit(1);
    }

    if (argc == 2) {
        uid = atoi(argv[1]);
	if (setuid(uid) < 0) {
		printf("setuid from %u to %u fail: %s\n", getuid(), uid, strerror(errno));
	}
    } else {
	uid = getuid(); //没有带uid参数，则使用当前进程的uid
    }
    if (is_this_running(uid) == 1) {
        return 0;
    }

    /* 用于安装时，将snipertray剥离sniper的进程组，避免停sniper的时候把snipertray也停了 */
    pid = getpid();
    pgid = getpgrp();
    if (pid != pgid) { //手工起snipertray时，snipertray自己就是进程组头，不用做setsid
	if (setsid() < 0) {
		printf("setsid fail: %s\n", strerror(errno));
	}
    }

    QApplication app(argc, argv);
    //关闭最后一个窗口不退出程序
    QApplication::setQuitOnLastWindowClosed(false);
    MainWindow *window = new MainWindow;
    Q_UNUSED(window);
    return app.exec();
}
