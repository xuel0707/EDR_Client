#include <sys/inotify.h>
#include "header.h"

#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

#define IN_SELF (IN_DELETE_SELF|IN_MOVE_SELF|IN_IGNORED)

#define IP_EVENT      0x1

struct watch_target {
	int wd;
	int event;
	time_t delt;
	int type;
	char path[128];
} wt[] = {
	{-1, 0, 0, IP_EVENT,  "/opt/snipercli/current_server"},
	{-1, 0, 0, 0, ""}
};

static void handle_event(int type)
{

	if (type & IP_EVENT) {
		INFO("check server ip\n");
		init_serverconf();
	}
}

/* 监控/opt/snipercli/下的current_server文件，及时切换管控ip */
void *inotify_monitor(void *ptr)
{
	int fd = 0, i = 0, count = 0;
	char buffer[REALTIME_EVENT_BUFFER + 1];
	char dir[PATH_MAX] = {0};

	INFO("inotify_monitor is start running\n");

	fd = inotify_init();
	if (fd < 0) {
		MON_ERROR("inotify monitor init fail: %s\n", strerror(errno));
		return NULL;
	}

	i = 0;
	while (wt[i].path[0]) {
		wt[i].wd = inotify_add_watch(fd, wt[i].path, IN_CREATE|IN_MODIFY|IN_MOVED_TO|IN_SELF);
		if (wt[i].wd < 0) {
			if (errno == ENOENT) {
				INFO("Warning: skip watch %s: %s\n", wt[i].path, strerror(errno));
			} else {
				MON_ERROR("watch %s fail: %s\n", wt[i].path, strerror(errno));
			}
		}
		i++;
	}
	count = i;

	while (1) {
		int type = 0, ret = 0;
		struct timeval tv;
		fd_set fds;

		/* TODO 如果所有相关的监控项都时关闭的，什么也不做 */

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		tv.tv_sec = 10;
		tv.tv_usec = 0;

		ret = select(fd+1, &fds, NULL, NULL, &tv);
		DBG2(DBGFLAG_INOTIFY, "inotify select ret %d\n", ret);
		if (ret > 0 && FD_ISSET(fd, &fds)) {
			int nread = 0, len = 0, elen = 0;

			len = read(fd, buffer, REALTIME_EVENT_BUFFER);

			while (len > 0) {
				struct inotify_event *event;
				event = (struct inotify_event *)&buffer[nread];
				DBG2(DBGFLAG_INOTIFY, "event wd %d, name %s, mask %x, len %d\n",
				     event->wd, event->name, event->mask, event->len);

				for (i = 0; i < count; i++) {
					if (event->wd != wt[i].wd) { //不是监听的目标
						continue;
					}

					if (event->mask & IN_SELF) { //监听的目标被删除了
						ret = inotify_rm_watch(fd, wt[i].wd);
						DBG2(DBGFLAG_INOTIFY, "remove watch %s : %d\n", wt[i].path, ret);
						wt[i].delt = time(NULL);
						wt[i].wd = -1;
						break;
					}

					DBG2(DBGFLAG_INOTIFY, "%s match %s\n", wt[i].path, event->name);
					wt[i].event = 1;

					break;
				}
				if (i == count) {
					/*
					 * wd的IN_DELETE_SELF事件之后，虽然做了inotify_rm_watch(fd, wd)，
					 * 但下一个select()还会有个wd的IN_IGNORED事件，丢弃之
					 */
					DBG2(DBGFLAG_INOTIFY, "event discard, wd %d no match\n", event->wd);
				}

				elen = sizeof(struct inotify_event) + event->len;
				nread += elen;
				len -= elen;
			}
		}

		for (i = 0; i < count; i++) {
			if (!wt[i].event) {
				continue;
			}
			DBG2(DBGFLAG_INOTIFY, "handle %s event\n", wt[i].path);
			type |= wt[i].type;
			wt[i].event = 0;
			wt[i].delt = 0;
		}

		handle_event(type);

		for (i = 0; i < count; i++) {
			if (wt[i].wd >= 0) {
				continue;
			}

			/* 监测未被监测的目标 */
			wt[i].wd = inotify_add_watch(fd, wt[i].path, IN_CREATE|IN_MODIFY|IN_SELF);
			if (wt[i].wd >= 0) {
				DBG2(DBGFLAG_INOTIFY, "%s rewatched, wd %d\n", wt[i].path, wt[i].wd);
			}
			/* current_server安装的时候第一次监控时还没有生成，生成的时候由于第一次监控失败，这边重新监控需要再次更新一下server的ip和端口 */
			if (i == 0) {
				INFO("inotify file agian,check server ip\n");
				init_serverconf();
			}
		}

		type = 0;
		for (i = 0; i < count; i++) {
			time_t now = 0;

			if (wt[i].delt == 0) {
				continue;
			}

			/*
			 * 修改监测对象的行为，可能是先删除老的监测对象，再创建新的监测对象，
			 * 如groupadd之于/etc/group，
			 * 因此延迟1秒处理删除事件，以正确上报修改日志，
			 * 避免先上报大量的删除日志，接着又上报大量的创建日志
			 */
			now = time(NULL);
			if (now - wt[i].delt < 1) {
				sleep(1);
			}

			if (wt[i].wd >= 0) {
				/* 被删除的对象又被重建了 */
				DBG2(DBGFLAG_INOTIFY, "handle %s rewatch event\n", wt[i].path);
			} else {
				/* 被删除的对象未被重建 */
				DBG2(DBGFLAG_INOTIFY, "handle %s removed\n", wt[i].path);
			}
			type |= wt[i].type;
			wt[i].event = 0;
			wt[i].delt = 0;
		}
		handle_event(type);
	}

	close(fd);
	INFO("----inotify thread exit---\n");
	return NULL;
}
