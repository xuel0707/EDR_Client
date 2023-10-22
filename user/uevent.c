#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "header.h"

#define UEVENT_BUFFER_SIZE 2048  

struct timespec dev_mtime = {0};

static void handle_usb_uevent(char *buf) 
{
	struct stat st = {0};

	if (!buf) {
		return;
	}

	/* 不是usb的事件不处理 */
	if (strstr(buf, "devices") == NULL || strstr(buf, "usb") == NULL) {
		return;
	}

	/* /dev目录的内容如果没改变，说明没有u盘插入拔出
	   不能看/sys/block目录的时间，它的时间可能不会改变 */
	stat("/dev", &st);
	if (st.st_mtim.tv_sec  == dev_mtime.tv_sec &&
	    st.st_mtim.tv_nsec == dev_mtime.tv_nsec) {
		DBG2(DBGFLAG_USB, "/dev mtime %lu.%lu, no change, skip handle_usb_uevent\n",
			dev_mtime.tv_sec, dev_mtime.tv_nsec);
		return;
	}

	sleep(5);  //给一点时间让/dev/disk/by-id/和/etc/mtab也更新
	check_usb_info(0);

	/* 更新/dev的变更时间 */
	if (st.st_mtim.tv_sec == 0) {
		dev_mtime.tv_sec = time(NULL); //没有取到目录的时间，则用当前时间
	} else {
		dev_mtime.tv_sec  = st.st_mtim.tv_sec;
		dev_mtime.tv_nsec = st.st_mtim.tv_nsec;
	}
}

/* 绑定uevent netlink socket，返回绑定的socket fd */
static int bind_uevent_netlink(pid_t pid)
{
	int fd = 0, buffersize = 1024;
	struct sockaddr_nl src_addr = {0};

	fd = sniper_socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT, OTHER_GET);
	if (fd < 0) {
		MON_ERROR("uevent_monitor: nlsocket fail: %s\n", strerror(errno));
		return -1;
	}

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = pid;
	src_addr.nl_groups = 1; //receive broadcast message

	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffersize, sizeof(buffersize));

	if (bind(fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
		MON_ERROR("uevent_monitor: bind netlink%d with pid %d fail: %s\n",
			NETLINK_KOBJECT_UEVENT, src_addr.nl_pid, strerror(errno));
		sniper_close(fd, OTHER_GET);
		return -1;
	}

	return fd;
}

void *uevent_monitor(void *ptr)
{
	int i = 0, fd = 0;
	pid_t pid = 0;

	dev_mtime.tv_sec = time(NULL); //初始化/dev的时间，用于判断是否有u盘插入拔出

	/* 尝试绑定NETLINK_KOBJECT_UEVENT直到成功，某个进程可能已经用某个pid绑定，避开已用的pid */
	pid = getpid();
	for (i = 0; i < 4096; i++, pid++) {
		fd = bind_uevent_netlink(pid);
		if (fd >= 0) {
			break;
		}
	}
	if (fd < 0) {
		MON_ERROR("uevent_monitor start fail: %s\n", strerror(errno));
		return NULL;
	}

	prctl(PR_SET_NAME, "device_monitor");
	save_thread_pid("uevent", SNIPER_THREAD_UEVENT);

	while (Online) {
        	char buf[UEVENT_BUFFER_SIZE] = { 0 };
		struct timeval tv = {10, 0};
		fd_set fds;

		/* 检查待转储的日志文件 */
		check_log_to_send("uevent");

		/* 如果停止防护了，什么也不做 */
		if (sniper_other_loadoff == 1) {
			DBG2(DBGFLAG_UEVENT, "Stop protect, watch nothing\n");
			sleep(STOP_WAIT_TIME);
			continue;
		}

		/* 如果过期/停止客户端工作，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			DBG2(DBGFLAG_UEVENT, "Expired or stop protect, watch nothing\n");
			sleep(STOP_WAIT_TIME);
			continue;
		}

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		get_mount_info();
		/* select返回0表示超时，返回-1表示错误 */
		if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) {
			continue;
		}

		if (!FD_ISSET(fd, &fds)) { //fd没有准备好
			continue;
		}

		if (recv(fd, buf, sizeof(buf), 0) <= 0) { //没读到数据
			continue;
		}

		DBG2(DBGFLAG_UEVENT,"uevent: %s\n", buf);
		handle_usb_uevent(buf);
	}

	sniper_close(fd, OTHER_GET);
	INFO("uevent thread exit\n");

	/* 强制停止systeminformation进程，缩短停sniper的时间 */
	stop_systeminformation();

	return NULL;
}
