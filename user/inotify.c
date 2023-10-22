#include "header.h"
#include <sys/inotify.h>

#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

#define IN_SELF (IN_DELETE_SELF|IN_MOVE_SELF|IN_IGNORED)

#define CRON_EVENT              0x1
#define USER_EVENT              0x2
#define GROUP_EVENT             0x4
#define BURN_EVENT              0x8
#define PRINT_EVENT             0x10
#define START_EVENT             0x20
#define BACKUP_EVENT            0x40
#define TRAP_EVENT              0x80
#define QUARANTINE_EVENT	0x100
struct watch_target {
	int wd;
	int event;
	time_t delt;
	int type;
	char path[128];
} wt[] = {
	{-1, 0, 0, USER_EVENT,  "/etc/passwd"},
	{-1, 0, 0, USER_EVENT,  "/etc/shadow"},
	{-1, 0, 0, GROUP_EVENT|USER_EVENT, "/etc/group"},
	{-1, 0, 0, PRINT_EVENT, "/var/log/cups/access_log"},
	{-1, 0, 0, START_EVENT, "/etc/xdg/autostart/"},
	{-1, 0, 0, BACKUP_EVENT, BACKUP_DIR},
	{-1, 0, 0, TRAP_EVENT, "/"},
	{-1, 0, 0, TRAP_EVENT, "/home/"},
	{-1, 0, 0, QUARANTINE_EVENT, INOTIFY_QUARANTINE_DIR},
	{-1, 0, 0, 0, ""}
};

static int check_antivirus_dir(char *name)
{
	uid_t uid = 0;
	int len = 0;
	int match = 0;
	struct passwd *my_info;
	char dirname[PATH_MAX] = {0};
	int i = 0, ret = 0;
	
	if (!name) {
		return -1;
	}

	/* 检查name是不是uid特征 */
	len = strlen(name);
	i = 0;
	for(i= 0; i < len; i++) {
		if(name[i] < '0'|| name[i] > '9') {
			match = 1;
			break;
		}
	}

	if (match == 1) {
		return -1;
	}

	uid = atoi(name);
	my_info = getpwuid(uid);
	if (!my_info || !my_info->pw_name) {
		return -1;
	}

	/* 创建目录并修改属主属组 */
	snprintf(dirname, sizeof(dirname), "%s/%s", QUARANTINE_DIR, my_info->pw_name);
	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
		return -1;
	}

	ret = chown(dirname, uid, uid);
	if (ret < 0) {
		MON_ERROR("chown %s fail : %s\n", dirname, strerror(errno));
		unlink(dirname);
		return -1;
	}

	return 0;
}


/* passwd文件和shadow文件变化5秒后才处理 */
static void wait_adduser_end(void)
{
	struct stat st = {0};
	time_t now = 0, t = 0;

	while (1) {
		if (stat("/etc/passwd", &st) == 0) {
			t = st.st_mtime + 5;
			now = time(NULL);
			if (t > now) {
				sleep(t-now);
				continue;
			}
		}
		if (stat("/etc/shadow", &st) == 0) {
			t = st.st_mtime + 5;
			now = time(NULL);
			if (t > now) {
				sleep(t-now);
				continue;
			}
		}
		break;
	}
}

static void handle_event(int type)
{

	if (type & GROUP_EVENT) {
		check_group();
	}
	if (type & PRINT_EVENT) {
		check_printer_files();
	}
	if (type & USER_EVENT) {
		wait_adduser_end();
		check_user();
	}
	if (type & BACKUP_EVENT) {
		check_backup_free_size();

		/* 发送所有内核需要的策略 */
		update_kernel_file_policy();
	}

}

void *inotify_monitor(void *ptr)
{
	int fd = 0, i = 0, count = 0;
	char buffer[REALTIME_EVENT_BUFFER + 1];
	char dir[PATH_MAX] = {0};

	fd = inotify_init();
	if (fd < 0) {
		MON_ERROR("inotify monitor init fail: %s\n", strerror(errno));
		return NULL;
	}

	prctl(PR_SET_NAME, "inotify_monitor");
	save_thread_pid("inotify", SNIPER_THREAD_INOTIFY);

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

	while (Online) {
		int type = 0, ret = 0;
		struct timeval tv;
		fd_set fds;

		/* 检查待转储的日志文件 */
		check_log_to_send("inotify");

		/* 如果停止防护，什么也不做 */
		if (sniper_other_loadoff == TURN_MY_ON) {
			DBG2(DBGFLAG_INOTIFY, "Stop protect, watch nothing\n");
			sleep(STOP_WAIT_TIME);
			continue;
		}

		/* 如果过期/停止客户端工作，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			DBG2(DBGFLAG_INOTIFY, "Expired or stop protect, watch nothing\n");
			sleep(STOP_WAIT_TIME);
			continue;
		}

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

					/* 对根目录和home目录下的新生成的文件夹添加诱捕文件 */
					if (strcmp(wt[i].path, "/home/") == 0 &&
						event->mask & (IN_CREATE|IN_MOVED_TO)) {
						snprintf(dir, PATH_MAX, "/home/%s/", event->name);
						check_dir_trap_files(dir, HIDE_TURNON, OP_CREATE);
					}

					if (strcmp(wt[i].path, "/") == 0 &&
						event->mask & (IN_CREATE|IN_MOVED_TO)) {
						snprintf(dir, PATH_MAX, "/%s/", event->name);
						check_dir_trap_files(dir, HIDE_TURNON, OP_CREATE);
					}

					/* 检测到通知的uid文件，在病毒隔离区创建对应用户的目录 */
					if (strcmp(wt[i].path, INOTIFY_QUARANTINE_DIR) == 0 &&
						event->mask & IN_CREATE) {
						check_antivirus_dir(event->name);
					}

					break;
				}
				if (i == count) {
					/*
					 * 观察到对于groupadd/del
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
			/* 不监控打印机 */
			if (fasten_policy_global.device.printer.enable == 0 &&
			    strstr(wt[i].path, "cups")) {
				if (wt[i].wd >= 0) {
					inotify_rm_watch(fd, wt[i].wd);
				}
				continue;
			}

			if (wt[i].wd >= 0) {
				continue;
			}

			/* 监测未被监测的目标 */
			wt[i].wd = inotify_add_watch(fd, wt[i].path, IN_CREATE|IN_MODIFY|IN_SELF);
			if (wt[i].wd >= 0) {
				DBG2(DBGFLAG_INOTIFY, "%s rewatched, wd %d\n", wt[i].path, wt[i].wd);
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

	group_db_release();
	user_db_release();

	close(fd);
	INFO("inotify thread exit\n");
	return NULL;
}
