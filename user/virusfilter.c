/* std */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>

#include "header.h"
#include "file.h"

/* 过滤掉一些文件不用继续检查，返回1表示需要过滤，返回0表示不用过滤 */
static int filter_out_some_files(char *path)
{
	struct stat st;
	off_t max_size = 0;

	if (stat(path, &st) < 0) {
		return -1;
	}

	/* 大于策略设置的忽略文件大小不扫描 */
	max_size = antivirus_policy_global.neglect_size * MB_SIZE;
	if (max_size != 0 && st.st_size > max_size) {
		return 1;
	}

	return 0;
}

/* 拼接virus的结构体成员信息 */
static void build_virus_msg(struct file_msg_args *msg,  struct virus_msg_args *virus_msg)
{
	virus_msg->pid = msg->pid;
	virus_msg->file_size = msg->file_size;
	virus_msg->op_type = msg->op_type;
	virus_msg->proctime = msg->proctime;
	virus_msg->start_tv.tv_sec = msg->start_tv.tv_sec;
	virus_msg->start_tv.tv_usec = msg->start_tv.tv_usec;
	snprintf(virus_msg->pathname, sizeof(virus_msg->pathname), "%s", msg->pathname);
	snprintf(virus_msg->pathname_new, sizeof(virus_msg->pathname_new), "%s", msg->pathname_new);
	snprintf(virus_msg->cmdname, sizeof(virus_msg->cmdname), "%s", msg->cmdname);
	snprintf(virus_msg->p_cmdname, sizeof(virus_msg->p_cmdname), "%s", msg->p_cmdname);
	snprintf(virus_msg->username, sizeof(virus_msg->username), "%s", msg->username);
	snprintf(virus_msg->action, sizeof(virus_msg->action), "%s", msg->action);
	snprintf(virus_msg->taskuuid, sizeof(virus_msg->taskuuid), "%s", msg->taskuuid);
	snprintf(virus_msg->cmd, sizeof(virus_msg->cmd), "%s", msg->cmd);
	snprintf(virus_msg->args, sizeof(virus_msg->args), "%s", msg->args);
	snprintf(virus_msg->tty, sizeof(virus_msg->tty), "%s", msg->tty);
	snprintf(virus_msg->session_uuid, sizeof(virus_msg->session_uuid), "%s", msg->session_uuid);
}

#ifdef USE_AVIRA
void *virusfilter_monitor(void *ptr)
{
	filereq_t *rep = NULL;
	struct file_msg_args msg = {0};
	kfile_msg_t *kfile_msg = NULL;
	taskstat_t *taskstat = NULL;
	char *path = NULL;
	struct virus_msg_args virus_msg = {0};

	prctl(PR_SET_NAME, "virusfilter");
	save_thread_pid("virusfilter", SNIPER_THREAD_FILTER);

	virus_msg_queue_init();

	while (Online) {
		if (kfile_msg) {
			sniper_free(kfile_msg->data, kfile_msg->datalen, FILE_GET);
			sniper_free(kfile_msg, sizeof(struct kfile_msg), FILE_GET);
		}

		if (sniper_file_loadoff == TURN_MY_ON) {
			/* get_kfile_msg里不睡眠，所以此处要睡1秒，否则会显示CPU一直忙 */
			sleep(1);
			kfile_msg = (kfile_msg_t *)get_kvirus_msg();
			continue;
		}

		/* 如果过期了/停止防护了，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			sleep(STOP_WAIT_TIME);

			/* 扔掉msg queue中的数据 */
			while(1) {
				kfile_msg = (kfile_msg_t *)get_kvirus_msg();
				if (!kfile_msg) {
					break;
				}

				sniper_free(kfile_msg->data, kfile_msg->datalen, FILE_GET);
				sniper_free(kfile_msg, sizeof(struct kfile_msg), FILE_GET);
			}

			continue;
		}

		kfile_msg = (kfile_msg_t *)get_kvirus_msg();
		if (!kfile_msg) {
			sleep(1);
			continue;
		}

		rep = (filereq_t *)kfile_msg->data;
		if (rep == NULL) {
			continue;
		}

		DBG2(DBGFLAG_FILTERDEBUG, "virusfilter msg pid:%d, process:%s, path:%s, rep->type:%d,rep->op_type:%d,rep->uid:%d\n",
			rep->pid, &(rep->args), &(rep->args) + rep->pro_len + 1, rep->type,rep->op_type,rep->uid);

		memset(&msg, 0, sizeof(struct file_msg_args));
		snprintf(msg.tty, sizeof(msg.tty), "%s", rep->tty);

		msg.pid = rep->pid;
		msg.proctime = rep->proctime;
		memcpy(&msg.start_tv, &rep->event_tv, sizeof(struct timeval));

		/*
		 * 如果pathname长度小于sizeof(msg.pathname)，且结尾没有\0，
		 * 这里msg.pathname结尾主动加0，防止获取的路径有乱码
		 * 如果pathname长度大于等于sizeof(msg.pathname)，snprintf自动添加\0
		 */
		snprintf(msg.pathname, sizeof(msg.pathname), "%s", &rep->args + rep->pro_len + 1);
		if (rep->path_len < sizeof(msg.pathname)) {
			msg.pathname[rep->path_len] = 0;
		}
		/* pathname_new的处理同pathname */
		snprintf(msg.pathname_new, sizeof(msg.pathname_new), "%s", &rep->args + rep->pro_len + rep->path_len + 2);
		if (rep->newpath_len < sizeof(msg.pathname_new)) {
			msg.pathname_new[rep->newpath_len] = 0;
		}

		/* pathname为空说明内核传的值不对，或者取的地方有错，不再继续 */
		if ((msg.pathname[0] == '\0') || (rep->path_len == 0)){
//			MON_ERROR("filename is NULL\n");
			continue;
		}
		path = msg.pathname;

		snprintf(msg.cmdname, sizeof(msg.cmdname), "%s", safebasename(msg.cmd));
		snprintf(msg.p_cmdname, sizeof(msg.p_cmdname), "%s", rep->parent_comm);
		snprintf(msg.username, sizeof(msg.username), "N/A");
		uidtoname(rep->uid, msg.username);
		msg.op_type = rep->op_type;

		/* 如果是重命名的操作，新文件的文件名和长度应该为空 */
		if (rep->op_type == OP_RENAME) {
			if ((msg.pathname_new[0] == '\0') || (rep->newpath_len == 0)){
				DBG2(DBGFLAG_VIRUS, "newfilename is NULL\n");
				continue;
			}
			path = msg.pathname_new;
		}

		/* 写打开的情况下检查是否已经报告过 */
		if (rep->op_type == OP_OPEN_W) {
			if (!check_to_report(msg.pathname, rep)) {
				DBG2(DBGFLAG_VIRUS, "check virusfilter msg to report, op_type:%d, type:%d\n", rep->op_type, rep->type);
				continue;
			}
		}

		/* 过滤一部分文件 */
		if (filter_out_some_files(path) == 1) {
			continue;
		}

		/* 只检测可执行文件 */
		if (get_file_type(path) != EXEC_FILE) {
			continue;
		}

		/* 检测是否在管控设置的可信区内 */
		if (check_policy_trust_path(path) == 1) {
			continue;
		}

		/* 从进程获取不到task时，不用取父进程的task，自己赋值成员的值，以防后面用到process时不一致 */
		taskstat = get_taskstat_rdlock(rep->pid, FILE_GET);
		if (!taskstat) {
			snprintf(msg.cmd, sizeof(msg.cmd), "%s", &rep->args);
			if (rep->pro_len < sizeof(msg.cmd)) {
				msg.cmd[rep->pro_len] = 0;
			}
			if (msg.tty[0] != 0) {
				get_session_uuid(msg.tty, msg.session_uuid);
			}
		} else {
			snprintf(msg.cmd, sizeof(msg.cmd), "%s", taskstat->cmd);
			snprintf(msg.args, sizeof(msg.args), "%s", taskstat->args);
			snprintf(msg.session_uuid, sizeof(msg.session_uuid), "%s", taskstat->session_uuid);

			put_taskstat_unlock(taskstat);
		}

		if (rep->did_exec) {
			set_taskuuid(msg.taskuuid, rep->proctime, rep->pid, 0);
		} else {
			int i = 0;
			struct task_simple_info *tinfo = NULL;

			for (i = 0; i < SNIPER_PGEN; i++) {
				tinfo = &(rep->pinfo.task[i]);
				if (tinfo->did_exec) {
					set_taskuuid(msg.taskuuid,
						tinfo->proctime, tinfo->pid, 0);
					break;
				}
			}
		}

		/* 队列满则丢弃所有新消息 */
		if (virus_msg_queue_full()) {
			continue;
		}

		build_virus_msg(&msg, &virus_msg);
		virus_msg_queue_push(&virus_msg);
		print_droped_virus_msgs();
	}

	virus_msg_queue_destroy();
	INFO("virusfilter thread exit\n");

	return NULL;
}
#endif
