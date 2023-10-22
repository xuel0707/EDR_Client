/*
 * 1、内核里捕捉到命令时，检查了若干事件，在应用层又检查若干事件，
 *    choose_process_event从命中的若干事件中选择一个上报
 * 2、对于sniper启动时，已经存在的进程，init_psbuf调用init_one_process，
 *    再调用set_taskstat_flag检查事件
 * 3、关闭进程监控，后来又开，需要重新检查一下当前进程的事件
 */

/* std */
#define _GNU_SOURCE  // getpgid
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/time.h>  // gettimeofday

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* netlink */
#include <sys/socket.h>
#include <linux/netlink.h>

#include <pwd.h>
#include <linux/limits.h>

/* isspace */
#include <ctype.h>

#include "header.h"
#include "process.h"

#define SYSBINPATH_NUM 7
char sysbinpath[SYSBINPATH_NUM][16] = { "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/usr/lib64/" };

unsigned char process_inited = 0;

static int samecmd(char *path, char *cmd, char *cwd)
{
	struct stat st = {0};
	struct stat st2 = {0};
	char buf[PATH_MAX] = {0};
	char *path2 = cmd;

	if (strcmp(path, cmd) == 0) {
		return 1;
	}

	if (cmd[0] != '/') {
		snprintf(buf, sizeof(buf), "%s/%s", cwd, cmd);
		path2 = buf;
	}
	if (stat(path, &st) == 0 && stat(path2, &st2) == 0) {
		if (st.st_ino == st2.st_ino) {
			return 1;
		}
		return 0;
	}

	return 0;
}
/* return 0, 进程不存在; 1，杀死进程; -1 阻断失败 */
int stop_cmd(struct process_msg_args *msg, char *reason)
{
	int ret = 0;
	int t = 0;
	int i = 0;
	char cmd[PATH_MAX] = {0};

	if (!msg) {
		MON_ERROR("stop cmd fail, NULL msg\n");
		return -1;
	}
	msg->terminate = 1;
	msg->terminate_result = failstr;

	if (mykill(msg->pid, 0) < 0) {
		msg->terminate_result = succstr;
		return 0;
	}
	if (get_proc_exe(msg->pid, cmd) < 0) {
		msg->terminate_result = succstr;
		return 0;
	}
	if (!samecmd(cmd, msg->cmd, msg->cwd)) {
		msg->terminate_result = succstr;
		return 0;
	}

	for (i = 0; i < 3; i++) {
		mykill(msg->pid, SIGKILL);

//暂时屏蔽，防止误杀，另外这样也会杀掉自测脚本
#if 0
		/* 终端操作的话，尝试杀掉终端 */
		if (msg->flags & PSR_TTY) {
			pid_t pgid = mygetpgid(msg->pid);

			if (pgid != msg->pid) {
				mykillpg(pgid, SIGKILL);
			}

			if (msg->flags & TASK_PARENT_TTY) {
				pgid = mygetpgid(msg->ppid);
				mykillpg(pgid, SIGKILL);
			}
		}
#endif

		/* 检查阻断是否成功 */
		ret = mykill(msg->pid, 0);
		if (ret < 0) {
			INFO("%s! %s(%d) stopped. parent %s(%d). %s\n",
			     reason ? reason : "",
			     msg->cmdline, msg->pid,
			     msg->pcmdline, msg->ppid,
			     msg->ip);
			msg->terminate_result = succstr;
			return 1;
		}

		t = i + 1;
		sleep(t);

		/* 再检查阻断是否成功 */
		ret = mykill(msg->pid, 0);
		if (ret < 0) {
			INFO("%s! %s(%d) stopped. parent %s(%d). %s\n",
			     reason ? reason : "",
			     msg->cmdline, msg->pid,
			     msg->pcmdline, msg->ppid,
			     msg->ip);
			msg->terminate_result = succstr;
			return 1;
		}
		INFO("wait %ds, and retry stop %s(%d) again\n",
		     t, msg->cmdline, msg->pid);
	}

	MON_ERROR("%s! Retried 3 times, stop %s(%d) fail. %s(%d). %s\n",
		  reason ? reason : "",
		  msg->cmdline, msg->pid,
		  msg->pcmdline, msg->ppid,
		  msg->ip);
	return -1;
}

static proc_msg_t *build_process_msg(taskstat_t *taskstat)
{
	int len = 0;
	proc_msg_t *msg = NULL;
	taskstat_t *ptaskstat = NULL, tmp_taskstat = {0};

	if (!taskstat) {
		MON_ERROR("build msg fail, NULL taskstat\n");
		return NULL;
	}

	/* 这里不锁ptaskstat也无妨，因为只有process线程自己才会摘tasklist链 */
	ptaskstat = the_ptaskstat(taskstat);
	if (!ptaskstat) {
		pid_t ppid = taskstat->pinfo.task[0].pid;

		/* 遇见过50多万个nv_queue内核线程的情况(NVIDIA)，故tasklist忽略内核线程，
		   对于内核线程执行的命令，这里补上内核线程信息，允许上报 */
		if (is_kernel_thread(ppid)) {
			ptaskstat = &tmp_taskstat;
			ptaskstat->pid = ppid;
			get_proc_stat(ptaskstat);
			get_proc_status(ptaskstat);
			set_taskuuid(ptaskstat->uuid, ptaskstat->proctime, ppid, 0);
			snprintf(ptaskstat->user, sizeof(ptaskstat->user), "root");
		} else {
			INFO("build msg fail, drop %s(%d). parent %s/%d, no ptaskstat.\n",
			     taskstat->args, taskstat->pid, taskstat->pinfo.task[0].comm, ppid);

			/* 父进程丢弃，子进程也丢弃 */
			return NULL;
		}
	}

	//TODO msg里记录父进程轨迹，如果父进程非parent

#if 0
	if (ptaskstat->flags & TASK_DROP) {
		return NULL;
	}
#endif

	if (ptaskstat->uuid[0] == 0 || ptaskstat->cmd[0] == 0) {
		MON_ERROR("build msg for %s(%d) fail. %s(%d) %s(%d) %s(%d). "
			  "bad ptaskstat: pid %d, cmd %s, user %s, uuid %s\n",
			  taskstat->args, taskstat->pid,
			  taskstat->pinfo.task[0].comm, taskstat->pinfo.task[0].pid,
			  taskstat->pinfo.task[1].comm, taskstat->pinfo.task[1].pid,
			  taskstat->pinfo.task[2].comm, taskstat->pinfo.task[2].pid,
			  ptaskstat->pid, ptaskstat->cmd,
			  ptaskstat->user, ptaskstat->uuid);
		return NULL;
	}

	msg = sniper_malloc(sizeof(proc_msg_t), PROCESS_GET);
	if (!msg) {
		MON_ERROR("build msg fail, no memory\n");
		return NULL;
	}

	msg->event_tv = taskstat->event_tv;
	if (taskstat->stop_tv.tv_sec) {
		msg->stop_tv = taskstat->stop_tv;
	}
	msg->flags = taskstat->flags;
	if (taskstat->flags & TASK_STOPED) { //内核里已阻断
		msg->terminate = 1;
		msg->terminate_result = succstr;
	}

	msg->pflags = taskstat->pflags;

	msg->pid = taskstat->pid;
	snprintf(msg->uuid, sizeof(msg->uuid), "%s", taskstat->uuid);
	snprintf(msg->cmd, sizeof(msg->cmd), "%s", taskstat->cmd);
	snprintf(msg->cmdline, sizeof(msg->cmdline), "%s", taskstat->args);

	msg->ppid = ptaskstat->pid;
	snprintf(msg->puuid, sizeof(msg->puuid), "%s", ptaskstat->uuid);
	snprintf(msg->pcmd, sizeof(msg->pcmd), "%s", ptaskstat->cmd);
	if (ptaskstat->argslen > 0) {
		snprintf(msg->pcmdline, sizeof(msg->pcmdline), "%s", ptaskstat->args);
	} else {
		snprintf(msg->pcmdline, sizeof(msg->pcmdline), "%s", ptaskstat->cmd);
	}

	/* 根据pid找不到taskstat时，有时会构建一个临时taskstat用，
	   有的地方可能忘了转换用户名，保险起见，这里再确认一下 */
	if (taskstat->user[0] == 0) {
		uidtoname(taskstat->uid, taskstat->user);
	}
	if (ptaskstat->user[0] == 0) {
		uidtoname(ptaskstat->uid, ptaskstat->user);
	}
	snprintf(msg->user, sizeof(msg->user), "%s", taskstat->user);
	snprintf(msg->puser, sizeof(msg->puser), "%s", ptaskstat->user);

	if (taskstat->cwd[0] != 0) {
		snprintf(msg->cwd, sizeof(msg->cwd), "%s", taskstat->cwd);
	} else {
		if (ptaskstat->cwd[0] != 0) {
			snprintf(msg->cwd, sizeof(msg->cwd), "%s", ptaskstat->cwd);
		} else {
			msg->cwd[0] = '/';
			msg->cwd[1] = 0;
		}
	}

	snprintf(msg->ip, sizeof(msg->ip), "%s", taskstat->ip);
	snprintf(msg->myip, sizeof(msg->myip), "%s", taskstat->myip);
	msg->port = taskstat->port;
	msg->myport = taskstat->myport;

	snprintf(msg->md5, sizeof(msg->md5), "%s", taskstat->md5);
	snprintf(msg->sha256, sizeof(msg->sha256), "%s", taskstat->sha256);

	snprintf(msg->pmd5, sizeof(msg->pmd5), "%s", ptaskstat->md5);

	snprintf(msg->vendor, sizeof(msg->vendor), "%s", taskstat->vendor);
	snprintf(msg->product, sizeof(msg->product), "%s", taskstat->product);
	snprintf(msg->mem, sizeof(msg->mem), "%s", taskstat->mem);
	snprintf(msg->tty, sizeof(msg->tty), "%s", taskstat->tty);

	msg->loglevel = LOG_NORMAL;
	msg->event_id = PROCESS_NORMAL;
	msg->behavior_id = BEHAVIOR_NORMAL; //normal behavior

	msg->repeat = taskstat->repeat;

	msg->result = succstr;

	if (taskstat->session_uuid[0] != 0) {
		snprintf(msg->session_uuid, sizeof(msg->session_uuid), "%s", taskstat->session_uuid);
	}

	/* 下面的拷贝不会越界，max(len)=sizeof(desc)-1，len到max后，desc就追加不进去了 */
	len = 0;
	if (taskstat->pflags.docker) {
		snprintf(msg->desc+len, sizeof(msg->desc)-len, "%s. ", msg->product);
		len = strlen(msg->desc);
	}
	if (taskstat->pflags.shell_nologinuser) {
		snprintf(msg->desc+len, sizeof(msg->desc)-len, "shell的用户是不可登录用户。");
		len = strlen(msg->desc);
	}
	if (taskstat->pflags.dirtycow) {
		snprintf(msg->desc+len, sizeof(msg->desc)-len, "脏牛漏洞提权%s。", msg->terminate ? "被阻断" : "");
		len = strlen(msg->desc);
	}
	if (taskstat->pflags.dirtypipe) {
		snprintf(msg->desc+len, sizeof(msg->desc)-len, "脏管道漏洞提权%s。", msg->terminate ? "被阻断" : "");
		len = strlen(msg->desc);
	}
	if (taskstat->pflags.privup) {
		char *str = NULL, cmdline[S_NAMELEN] = {0};

		if (taskstat->pflags.privup_notsuid) {
			str = "非法";
		} else if (taskstat->pflags.privup_suid) {
			str = "系统SUID程序";
		} else {
			str = "用户SUID程序";
		}
		if (taskstat->childcmd[14]) {
			snprintf(cmdline, sizeof(cmdline), "%s...", taskstat->childcmd);
		} else {
			snprintf(cmdline, sizeof(cmdline), "%s", taskstat->childcmd);
		}
		snprintf(msg->desc+len, sizeof(msg->desc)-len, "%s提权后%s%s%s。", str,
			taskstat->pflags.privup_file ? "访问文件" : "执行命令",
			cmdline, msg->terminate ? "被阻断" : "");
		len = strlen(msg->desc);
	}
	if (taskstat->pflags.privup_parent) {
		snprintf(msg->desc+len, sizeof(msg->desc)-len, "父进程是非法提权进程。");
		len = strlen(msg->desc);
	}
	if (taskstat->argslen == 0 && msg->ppid != 2) { //除了内核线程，其他进程命令行参数为空是异常
		snprintf(msg->desc+len, sizeof(msg->desc)-len, "命令行参数为空。");
		len = strlen(msg->desc);
	}
	return msg;
}

/*
 * return -1，解析失败，路径用cmd
 *         0, 解析失败，路径用path
 *         1，解析成功，路径用cmd
 *         2，解析成功，路径用path
 */
static int get_cmd_fullpath(char *cmd, char *cwd, char *path, int path_len)
{
	char tmp_path[PATH_MAX] = {0};

	if (!cmd || !path) {
		return -1;
	}

	if (cmd[0] == '/') {
		return 1;
	}

	if (!cwd) {
		return -1;
	}

	snprintf(tmp_path, sizeof(tmp_path), "%s/%s", cwd, cmd);
	if (realpath(tmp_path, path)) {
		return 2;
	}

	MON_ERROR("get %s realpath fail: %s\n", tmp_path, strerror(errno));
	snprintf(path, path_len, "%s", tmp_path);
	return 0;
}

void send_upload_sample_log(proc_msg_t *msg, char *cmd, char *log_name, char *log_id, int result)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	char size_str[64] = {0};
	unsigned long event_time = 0;
	struct stat st = {0};

        get_random_uuid(uuid);
        if (uuid[0] == 0) {
                return;
        }

        object = cJSON_CreateObject();
        if (object == NULL) {
                return;
        }
        arguments = cJSON_CreateObject();
        if (arguments == NULL) {
                cJSON_Delete(object);
                return;
        }

	event_time = (msg->event_tv.tv_sec + serv_timeoff) * 1000 + msg->event_tv.tv_usec / 1000;

        cJSON_AddStringToObject(object, "id", uuid);
        cJSON_AddStringToObject(object, "log_name", "ClientSimpleUpload");
        cJSON_AddStringToObject(object, "event_category", "");
        cJSON_AddStringToObject(object, "log_category", "Client");
          cJSON_AddBoolToObject(object, "event", false);
        cJSON_AddNumberToObject(object, "level", 1);
        cJSON_AddNumberToObject(object, "behavior", 0);
        cJSON_AddNumberToObject(object, "result", result);
        cJSON_AddStringToObject(object, "operating", "Upload");
        cJSON_AddNumberToObject(object, "terminate", 0);
        cJSON_AddNumberToObject(object, "timestamp", event_time);

        cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
        cJSON_AddStringToObject(object, "ip_address", If_info.ip);
        cJSON_AddStringToObject(object, "mac", If_info.mac);
        cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
        cJSON_AddStringToObject(object, "user", msg->user);
        cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
        cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
        cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

        cJSON_AddStringToObject(object, "policy_id", policy_id_cur);

        cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
        cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
        cJSON_AddStringToObject(arguments, "policy_id", policy_id_cur);
        cJSON_AddStringToObject(arguments, "policy_name", policy_name_cur);
        cJSON_AddStringToObject(arguments, "policy_time", policy_time_cur);
        cJSON_AddStringToObject(arguments, "md5", msg->md5);
        cJSON_AddStringToObject(arguments, "file_path", cmd);
        cJSON_AddStringToObject(arguments, "file_name", safebasename(cmd));
        cJSON_AddStringToObject(arguments, "process_uuid", msg->uuid);
        cJSON_AddStringToObject(arguments, "log_name", log_name);
        cJSON_AddStringToObject(arguments, "log_id", log_id);

	if (stat(cmd, &st) < 0) {
        	cJSON_AddBoolToObject(arguments, "file_exists", false);
        	cJSON_AddStringToObject(arguments, "size", "0");
	} else {
        	cJSON_AddBoolToObject(arguments, "file_exists", true);
		snprintf(size_str, sizeof(size_str), "%ld", st.st_size);
        	cJSON_AddStringToObject(arguments, "size", size_str);
	}

        cJSON_AddItemToObject(object, "arguments", arguments);

        post = cJSON_PrintUnformatted(object);

        client_send_msg(post, reply, sizeof(reply), LOG_URL, "process");

        cJSON_Delete(object);
        free(post);
}

/* return 0，不上传；1，上传成功；-1，上传失败 */
static int upload_sample(proc_msg_t *msg, char *log_name, char *log_id)
{
	int ret = 0, result = MY_RESULT_OK;
	char path[PATH_MAX] = {0}, *cmd = NULL;

	/* 学习模式下总是要上传样本的 */
	if (!conf_global.allow_upload_sample && client_mode_global != LEARNING_MODE) {
		return 0;
	}

	if (!msg || !log_name || !log_id) {
		return 0;
	}

	ret = get_cmd_fullpath(msg->cmd, msg->cwd, path, sizeof(path));
	if (ret <= 0) {
		return -1;
	}
	if (ret == 1) {
		cmd = msg->cmd;
	} else {
		cmd = path;
	}

	ret = http_upload_sample(cmd, msg->event_tv.tv_sec, log_name, log_id, msg->user, msg->md5);
	if (ret < 0) {
		result = MY_RESULT_FAIL;
	}

	send_upload_sample_log(msg, cmd, log_name, log_id, result);

	return ret;
}

//TODO 检查suid程序是否为装机时安装的，且未被修改过
static int is_legal_suidexec(char *cmd)
{
	char *ptr = NULL;

	if (cmd) {
		if (is_su_sudo(cmd)) {
			return 1;
		}
		if (strcmp(cmd, "/usr/bin/pkexec") == 0 || strcmp(cmd, "/bin/pkexec") == 0) {
			return 1;
		}

		/*
		 * centos6       /lib64/dbus-1/dbus-daemon-launch-helper
		 * suse11/12     /lib/dbus-1/dbus-daemon-launch-helper
		 * suse15        /usr/lib/dbus-1/dbus-daemon-launch-helper
		 * ubuntu        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
		 * centos7/8     /usr/libexec/dbus-1.0/dbus-daemon-launch-helper
		 * centos7.8/7.9 /usr/libexec/dbus-1/dbus-daemon-launch-helper
		 */
		ptr = strstr(cmd, "dbus-1");
		if (ptr) {
			if (strstr(ptr, "dbus-1/dbus-daemon-launch-helper") ||
			    strstr(ptr, "dbus-1.0/dbus-daemon-launch-helper")) {
				char path[128] = {0};

				snprintf(path, sizeof(path), "%s", cmd);
				ptr = strstr(path, "dbus-1");
				if (ptr) {
					*ptr = 0;
					if (strcmp(path, "/lib64/") == 0 ||
					    strcmp(path, "/lib/") == 0 ||
					    strcmp(path, "/usr/lib/") == 0 ||
					    strcmp(path, "/usr/libexec/") == 0) {
						return 1;
					}
				}
			}
		}
	}
	return 0;
}

static int is_valid_remote_ip(char *ip)
{
	if (!ip || ip[0] == 0 || strcmp(ip, "127.0.0.1") == 0 ||
	    strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, If_info.ip) == 0) {
		return 0;
	}
	return 1;
}

static void send_process_msg(proc_msg_t *msg, taskstat_t *taskstat, int debug)
{
	int i = 0, tty = 0, lock_duration = 0;
	bool event = true;
	unsigned long event_time = 0, closed_time = 0;
	int behavior = 0, level = 0, result = MY_RESULT_OK, terminate = MY_HANDLE_WARNING;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	cJSON *object = NULL, *arguments = NULL;
	char *log_name = NULL, *event_category = "Process";
	char *opstr = "Created", *cmdname = NULL, *ip = NULL;
	char port_str[64] = {0};

	if (!msg) {
		return;
	}
	cmdname = safebasename(msg->cmd);

	if (msg->event_id < PROCESS_ABNORMAL && !protect_policy_global.logcollector.process_enable) {
		return; //不采集非事件进程日志
	}

	if (msg->flags & TASK_TTYFLAGS) {
		tty = 1;
	}

	event_time = (msg->event_tv.tv_sec + serv_timeoff) * 1000 + msg->event_tv.tv_usec / 1000;
	if (msg->stop_tv.tv_sec) {
		closed_time = (msg->stop_tv.tv_sec + serv_timeoff) * 1000 + msg->stop_tv.tv_usec / 1000;
	}

	behavior = msg->behavior_id - 1;
	if (strcmp(msg->result, failstr) == 0) {
		result = MY_RESULT_FAIL;
	}

	if (client_mode_global) { //学习模式或运维模式
		msg->terminate = 0;
		msg->blockip = 0;
	}
	if (msg->terminate) {
		if (strcmp(msg->terminate_result, failstr) == 0) {
			terminate = MY_HANDLE_BLOCK_FAIL;
		} else {
			terminate = MY_HANDLE_BLOCK_OK;
			result = MY_RESULT_FAIL;
		}
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(object, "id", uuid);

	cJSON_AddStringToObject(arguments, "source_type", "Host");
	switch (msg->event_id) {
	case PROCESS_NORMAL:
		log_name = "Process";
		event_category = "";
		level = MY_LOG_NORMAL;
		event = false;
		terminate = 0;

		if (msg->pflags.commandline) {
			/* 存在父进程是sh -c xxxx的情况 */
			if (is_shell(msg->pcmdline) > 0 || strcmp(msg->pcmdline, "-su") == 0) {
				log_name = "CommandLineAudit";
				level = MY_LOG_KEY;
			}
		}

		break;

	case PROCESS_SCHEDULE:
		log_name = "Process";
		event_category = "";
		level = MY_LOG_NORMAL;
		event = false;
		terminate = 0;
		break;

	case PROCESS_VIOLATION:
		log_name = "IllegalProcess";
		event_category = "Blocklist";
		level = MY_LOG_HIGH_RISK;
		break;

	case PROCESS_PRIVILEGE_ESCALATION:
		event_category = "Process";
		if (msg->loglevel == LOG_KEY) {
			if (msg->pflags.privup_exec && !is_legal_suidexec(msg->cmd)) {
				log_name = "PrivilegeEscalation";
			} else {
				log_name = "Privilege";
			}
			level = MY_LOG_KEY;
			terminate = 0;
			event = false;
		} else {
			log_name = "PrivilegeEscalation";
			level = MY_LOG_HIGH_RISK;
		}

		/* 在集合里面的默认是正常提权 */
		if (in_suid_set(msg->cmd)) {
			log_name = "Privilege";
			level = MY_LOG_KEY;
			terminate = 0;
			event = false;
		}
		break;

	case PROCESS_WEBSHELL_EXECUTION:
		log_name = "Webshell";
		level = MY_LOG_HIGH_RISK;
		break;

	case PROCESS_REMOTE_EXECUTION:
	case PROCESS_REBOUND_SHELL:
		log_name = "ReverseShell";
		level = MY_LOG_HIGH_RISK;

		cJSON_AddStringToObject(arguments, "remote_ip", msg->ip);

		snprintf(port_str, sizeof(port_str), "%u", msg->port);
		cJSON_AddStringToObject(arguments, "remote_port", port_str);

		cJSON_AddStringToObject(arguments, "local_ip", msg->myip);

		snprintf(port_str, sizeof(port_str), "%u", msg->myport);
		cJSON_AddStringToObject(arguments, "local_port", port_str);

		if (msg->blockip && is_valid_remote_ip(msg->ip)) {
			lock_duration = protect_policy_global.process.reverse_shell.locking_time;

			if (lock_ip(msg->ip, PROCESS_REMOTE_EXECUTION, lock_duration*60, log_name, uuid) < 0) {
				terminate = MY_HANDLE_BLOCK_OK_LOCKIP_FAIL;
			} else {
				terminate = MY_HANDLE_BLOCK_OK_LOCKIP_OK;
			}

			cJSON_AddBoolToObject(arguments, "is_lock", true);
			cJSON_AddStringToObject(arguments, "lock_ip", msg->ip);
			cJSON_AddNumberToObject(arguments, "lock_duration", lock_duration);
		} else {
			cJSON_AddBoolToObject(arguments, "is_lock", false);
			cJSON_AddStringToObject(arguments, "lock_ip", "");
			cJSON_AddNumberToObject(arguments, "lock_duration", 0);
		}
		break;

	case PROCESS_PORT_FORWARD:
		log_name = "Tunnel";
		level = MY_LOG_MIDDLE_RISK;

		cJSON_AddStringToObject(arguments, "tunnel_type", "PortForward");

		break;

	case PROCESS_DANGEROUS:
		log_name = "RiskCommand";
		level = MY_LOG_MIDDLE_RISK;
		break;

	case PROCESS_ABNORMAL:
		log_name = "AbnormalProcess";
		level = MY_LOG_MIDDLE_RISK;
		break;

	case PROCESS_MIDDLE_EXECUTION:
		log_name = "ServiceProcess";
		level = MY_LOG_LOW_RISK;

		cJSON_AddStringToObject(arguments, "dangerous_command", msg->dangerous_command);
		cJSON_AddStringToObject(arguments, "middleware", msg->middleware);
		cJSON_AddStringToObject(arguments, "listening_ports", msg->listening_ports);

		break;

	case PROCESS_MINERWARE:
		log_name = "Mining";
		event_category = "Malicious";
		level = MY_LOG_HIGH_RISK;

		cJSON_AddStringToObject(arguments, "mining_pool", msg->domain);

		ip = search_domain_cache_ip(msg->domain);
		if (!ip) {
			for (i = 0; i < 3; i++) {
				sleep(1); //可能进程日志处理的比域名日志快，等1秒
				ip = search_domain_cache_ip(msg->domain);
				if (ip) {
					break;
				}
			}
		}

		if (!ip) {
			MON_ERROR("get %s ip for miner %s fail\n", msg->domain, msg->cmd);
		}

		/* 有dns缓冲的话，曾经被阻断过的矿池域名ip会设成欺骗地址127.0.0.1 */
		if (msg->blockip && is_valid_remote_ip(ip)) {
			lock_duration = protect_policy_global.behaviour.pool.locking_time;

			if (!ip || lock_ip(ip, PROCESS_MINERWARE, lock_duration*60, log_name, uuid) < 0) {
				terminate = MY_HANDLE_BLOCK_OK_LOCKIP_FAIL;
			} else {
				terminate = MY_HANDLE_BLOCK_OK_LOCKIP_OK;
			}

			cJSON_AddBoolToObject(arguments, "is_lock", true);
			cJSON_AddStringToObject(arguments, "lock_ip", ip);
			cJSON_AddNumberToObject(arguments, "lock_duration", lock_duration);
		} else {
			cJSON_AddBoolToObject(arguments, "is_lock", false);
			cJSON_AddStringToObject(arguments, "lock_ip", "");
			cJSON_AddNumberToObject(arguments, "lock_duration", 0);
		}
		break;

	case PROCESS_MBRWARE:
		log_name = "MBR";
		level = MY_LOG_MIDDLE_RISK;

		opstr = "Read";
		cJSON_AddStringToObject(arguments, "mbr_operating", opstr);

		break;

	case PROCESS_MBR_PROTECT:
		log_name = "MBR";
		level = MY_LOG_MIDDLE_RISK;

		opstr = "Update";
		cJSON_AddStringToObject(arguments, "mbr_operating", opstr);

		break;

	default:
		cJSON_Delete(object);
		return; //TODO 其他事件类型暂不支持
	}

	if (behavior == MY_BEHAVIOR_NO) { //正常行为（包括可信）不报事件
		event = false;
		if (level != MY_LOG_KEY) { //正常行为（包括可信）不是关键日志就是普通日志
			level = MY_LOG_NORMAL;
		}
	}

	/* 被阻断的进程，允许状态是失败 */
	if (terminate == MY_HANDLE_BLOCK_OK ||
	    terminate == MY_HANDLE_BLOCK_OK_LOCKIP_OK ||
	    terminate == MY_HANDLE_BLOCK_OK_LOCKIP_FAIL) {
		result = MY_RESULT_FAIL;
	}

	/* 运维模式不阻断，不产生事件，只产生日志，日志级别有高中低危 */
	if (OPERATION_MODE == client_mode_global) {
		event = false;
	}
	if (event == true) {
		upload_sample(msg, log_name, uuid);
	}

	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddStringToObject(object, "log_category", "Process");
	  cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", opstr);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddNumberToObject(object, "timestamp", event_time);

	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);

	cJSON_AddNumberToObject(arguments, "process_id", msg->pid);
	cJSON_AddStringToObject(arguments, "process_uuid", msg->uuid);
	cJSON_AddStringToObject(arguments, "process_name", cmdname);
	cJSON_AddStringToObject(arguments, "process_path", msg->cmd);
	cJSON_AddStringToObject(arguments, "process_commandline", msg->cmdline);

	cJSON_AddNumberToObject(arguments, "parent_process_id", msg->ppid);
	cJSON_AddStringToObject(arguments, "parent_process_uuid", msg->puuid);
	cJSON_AddStringToObject(arguments, "parent_process_name", safebasename(msg->pcmd));
	cJSON_AddStringToObject(arguments, "parent_process_path", msg->pcmd);
	cJSON_AddStringToObject(arguments, "parent_process_commandline", msg->pcmdline);

	cJSON_AddStringToObject(arguments, "parent_process_md5", msg->pmd5);
	cJSON_AddStringToObject(arguments, "parent_process_user", msg->puser);

	cJSON_AddStringToObject(arguments, "work_directory", msg->cwd);
	cJSON_AddStringToObject(arguments, "memory_used", msg->mem);
	cJSON_AddStringToObject(arguments, "product", msg->product);
	cJSON_AddStringToObject(arguments, "company", msg->vendor);

	cJSON_AddNumberToObject(arguments, "closed_time", closed_time);
	cJSON_AddNumberToObject(arguments, "stater", tty);
	cJSON_AddStringToObject(arguments, "session_id", "");
	cJSON_AddStringToObject(arguments, "session_uuid", msg->session_uuid);
	cJSON_AddStringToObject(arguments, "signer", "");
	cJSON_AddStringToObject(arguments, "desc", msg->desc);
	cJSON_AddStringToObject(arguments, "md5", msg->md5);
	cJSON_AddStringToObject(arguments, "sha256", msg->sha256);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	if (!post) {
		cJSON_Delete(object);
		MON_ERROR("send_process_msg fail, null post, no memory\n");
		return;
	}

	if (level > MY_LOG_NORMAL || msg->event_id > PROCESS_SCHEDULE) {
		DBG2(DBGFLAG_PROCESS, "process event: %s\n", post);
	}


	/* 这里总按批量日志发，若为单发日志模式，client_send_msg会自动按单条日志发 */
#if 1
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "process");
#else
	// TODO(luoyinhong)
	printf("client send msg: %s\n", post);
#endif

	/* 没有发送过的进程日志，不报进程退出日志 */
	if (taskstat) {
		taskstat->flags |= TASK_REPORTED;
	}

	cJSON_Delete(object);
	free(post);

	if (terminate >= MY_HANDLE_BLOCK_OK) {
		struct defence_msg defmsg = {0};

		defmsg.event_tv.tv_sec = msg->event_tv.tv_sec;
		defmsg.event_tv.tv_usec = msg->event_tv.tv_usec;
		defmsg.operation = termstr;
		if (terminate == MY_HANDLE_BLOCK_FAIL) {
			defmsg.result = OPERATE_FAIL;
		} else {
			defmsg.result = OPERATE_OK;
		}

		defmsg.user = msg->user;
		defmsg.log_name = log_name;
		defmsg.log_id = uuid;

		defmsg.object = cmdname;

		send_defence_msg(&defmsg, "process");
	}

	if (terminate >= MY_HANDLE_BLOCK_OK_LOCKIP_OK) {
		struct defence_msg defmsg = {0};

		defmsg.event_tv.tv_sec = msg->event_tv.tv_sec;
		defmsg.event_tv.tv_usec = msg->event_tv.tv_usec;
		defmsg.operation = lockstr;
		if (terminate == MY_HANDLE_BLOCK_OK_LOCKIP_FAIL) {
			defmsg.result = OPERATE_FAIL;
		} else {
			defmsg.result = OPERATE_OK;
		}

		defmsg.user = msg->user;
		defmsg.log_name = log_name;
		defmsg.log_id = uuid;

		defmsg.object = ip ? ip : "";

		send_defence_msg(&defmsg, "process");
	}
}
#if 0
taskstat_t *req2taskstat(taskreq_t *req, taskstat_t *tmp_taskstat)
#else
taskstat_t *req2taskstat(struct ebpf_taskreq_t *req, taskstat_t *tmp_taskstat)
#endif
{
	pid_t ppid = 0;
	taskstat_t *taskstat = NULL;
	exehash_t *exehash = NULL;
	char *cmd = NULL, *args = NULL;

	if (!req) {
		return NULL;
	}
#if 0
	cmd = &req->args;
#else
	cmd = req->cmd;
#endif

	taskstat = get_taskstat_nolock(req->pid, PROCESS_GET);
	if (taskstat) {
		return taskstat;
	}

	taskstat = init_one_process(req->pid);
	if (taskstat) {
		/* 试图找回孤儿进程的真实父进程 */
		ppid = get_orphan_process_ppid(req);
		taskstat->pinfo.task[0].pid = ppid;
		return taskstat;
	}

	/* 如果与父进程的命令路径相同，可用父进程 */
	taskstat = get_ptaskstat_from_pinfo(&req->pinfo);
	if (taskstat && strcmp(taskstat->cmd, cmd) == 0) {
		return taskstat;
	}

	/* 获取最近一次做相同命令的taskstat */
	exehash = get_exehash_by_inode(req->exeino);
	if (exehash) {
		taskstat = get_taskstat_nolock(exehash->pid, PROCESS_GET);
		if (taskstat) {
			return taskstat;
		}
	}


	INFO("%s(%d) no taskstat, build byself\n", &req->args, req->pid);

	if (!tmp_taskstat) {
		return NULL;
	}

	taskstat = tmp_taskstat;
	taskstat->pid = req->pid;
	taskstat->uid = req->uid;
	uidtoname(taskstat->uid, taskstat->user);

	snprintf(taskstat->cmd, sizeof(taskstat->cmd), "%s", cmd);
	taskstat->cmdlen = strlen(taskstat->cmd);

#if 0
	args = cmd + req->cmdlen + 1;
	snprintf(taskstat->args, sizeof(taskstat->args), "%s", args);
#else
	// TODO(luoyinhong)
	args = req->args[0];
	for (int i = 0; i < req->argc; i++) {
		if (i > 0)
			strncat(taskstat->args, " ", 1);
		strncat(taskstat->args, req->args[i], 32);
	}
#endif

	taskstat->argslen = strlen(taskstat->args);

	taskstat->cwd[0] = '/';
	taskstat->cwd[1] = 0;
	taskstat->cwdlen = 1;

#if 0
	taskstat->event_tv.tv_sec  = req->event_tv.tv_sec;
	taskstat->event_tv.tv_usec  = req->event_tv.tv_usec;
#else
	// NOTE(luoyinhong): no timeofday support in ebpf
	gettimeofday(&taskstat->event_tv, NULL);
#endif

	gettimeofday(&taskstat->stop_tv, NULL);

	memcpy(&taskstat->pinfo, &req->pinfo, sizeof(req->pinfo));

	set_taskuuid(taskstat->uuid, req->proctime, req->pid, 0);

	if (exehash) {
		snprintf(taskstat->md5, sizeof(taskstat->md5), "%s", exehash->md5);
		snprintf(taskstat->sha256, sizeof(taskstat->sha256), "%s", exehash->sha256);
		snprintf(taskstat->vendor, sizeof(taskstat->vendor), "%s", exehash->vendor);
		snprintf(taskstat->product, sizeof(taskstat->product), "%s", exehash->product);
	}
	return taskstat;
}

void report_taskexit(taskstat_t *taskstat)
{
	unsigned long event_time = 0;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	cJSON *object = NULL, *arguments = NULL;

	if (!taskstat) {
		MON_ERROR("report_taskexit fail, NULL taskstat\n");
		return;
	}

	/* 进程没有报告过，则进程结束也不需要报告 */
	if (!(taskstat->flags & TASK_REPORTED)) {
		return;
	}
	/* 已经设上结束时间，说明在报告进程的时候已经带了closed_time */
	if (taskstat->stop_tv.tv_sec) {
		return;
	}

	gettimeofday(&taskstat->stop_tv, NULL);
	event_time = (taskstat->stop_tv.tv_sec + serv_timeoff) * 1000 + taskstat->stop_tv.tv_usec / 1000;

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(object, "id", uuid);

	cJSON_AddStringToObject(object, "log_name", "Process");
	cJSON_AddStringToObject(object, "log_category", "Process");
	cJSON_AddStringToObject(object, "operating", "Terminated");

	  cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddNumberToObject(object, "level", 0);
	cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_NORMAL);
	cJSON_AddNumberToObject(object, "result", 1);
	cJSON_AddNumberToObject(object, "terminate", 0);
	cJSON_AddNumberToObject(object, "timestamp", event_time);

	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", taskstat->user);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	cJSON_AddNumberToObject(arguments, "process_id", taskstat->pid);
	cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);
	cJSON_AddStringToObject(arguments, "process_name", safebasename(taskstat->cmd));
	cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
	cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);

	cJSON_AddNumberToObject(arguments, "closed_time", event_time);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);

	client_send_msg(post, reply, sizeof(reply), LOG_URL, "process");

	DBG("process exit post %s\n", post);

	cJSON_Delete(object);
	free(post);
}

void set_taskuuid(char *uuid, unsigned long long t, pid_t pid, int extra)
{
	if (!uuid) {
		MON_ERROR("set_taskuuid fail, NULL uuid\n");
		return;
	}

	/* 多级exec的process_uuid后缀保留，否则无法正确构造进程树 */
	if (extra) {
		snprintf(uuid, S_UUIDLEN, "%llu-%d-%d", t + uptime_sec, pid, extra);
	} else {
		snprintf(uuid, S_UUIDLEN, "%llu-%d", t + uptime_sec, pid);
	}
}

static void stop_dirtycow_routine(char *cmd)
{
	int pid = 0;
	FILE *fp = NULL;
	DIR *procdirp = NULL;
	struct dirent *pident = NULL;

	/* 学习模式和运维模式不阻断 */
	if (client_mode_global != NORMAL_MODE) {
		return;
	}

	if (!cmd) {
		return;
	}

	procdirp = sniper_opendir("/proc", PROCESS_GET);
	if (!procdirp) {
                MON_ERROR("stop_dirtycow_routine: open /proc fail: %s\n", strerror(errno));
		return;
	}

	/*
	 * 遍历/proc获得当前进程信息
	 */
	while ((pident = readdir(procdirp))) {
		char exe[S_CMDLEN] = {0};

		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue; //忽略非进程项信息
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

		if (get_proc_exe(pid, exe) > 0 && strcmp(exe, cmd) == 0) {
			mykill(pid, SIGKILL);
		}
	}

	sniper_closedir(procdirp, PROCESS_GET);

	/* 标志文件dirtycow_routine_stopped，用于通知自测脚本已完成阻断 */
	fp = sniper_fopen("/tmp/dirtycow_routine_stopped", "w", PROCESS_GET);
	if (fp) {
		sniper_fclose(fp, PROCESS_GET);
	}
}

/* TODO 下面程序会报nosuid提权，如5/6的hald，7的dnsmasq，但原理不明，算一种合法提权？待研究 */
#define SKIPCMDS 15
static char tmpskipcmd[SKIPCMDS][64] = {
	"awk", "gawk", "local", "jar", "tar", "crontab",
	"hald", "hald-runner", "dbus-daemon", "dnsmasq",
	"polkitd", "polkit-agent-helper-1",
	"dbus-daemon-launch-helper", "fusermount",
	"pkla-check-authorization"
};
static int mytmpskip(char *cmd)
{
	int i = 0;

	for (i = 0; i < SKIPCMDS; i++) {
		if (strcmp(cmd, tmpskipcmd[i]) == 0) {
			return 1;
		}
	}
	return 0;
}

#define PRIVUP_SUID 0
#define PRIVUP_LONG 1
#define PRIVUP_FORK 2
#define PRIVUP_EXEC 3
#define PRIVUP_SHELL 4
#define PRIVUP_NOSUID 5
#define PRIVUP_DIRTYCOW 6
#define PRIVUP_DIRTYPIPE 7
#define PRIVUP_MAX PRIVUP_DIRTYPIPE
char privupact[8][16] = {
	"privup suid",
	"privup longtime",
	"privup fork",
	"privup exec",
	"privup shell",
	"privup nosuid",
	"privup dirtycow",
	"privup dirtypipe"
};

int privup_filter(taskstat_t *taskstat, taskstat_t *ctaskstat, int type)
{
	taskstat_t *ptaskstat = the_ptaskstat(taskstat);

	INFO("Warning: %s(%d)[uid %u, euid %u] %s!\n",
	     taskstat->args, taskstat->pid, taskstat->uid, taskstat->euid, privupact[type]);
	if (ctaskstat) {
		INFO("   child %s(%d)[uid %u, euid %u]\n",
		     ctaskstat->args, ctaskstat->pid, ctaskstat->uid, ctaskstat->euid);
	}
	if (ptaskstat) {
		INFO("  parent %s(%d)[uid %u, euid %u]\n",
		     ptaskstat->args, ptaskstat->pid, ptaskstat->uid, ptaskstat->euid);
	}

	/* TODO 暂时忽略长期提权/提权fork/提权执行程序 */
	/* 鉴于误报，暂时也屏蔽非suid提权 */
	if (type <= PRIVUP_NOSUID) {
		INFO("ignore %s %s report\n", taskstat->args, privupact[type]);
		return 0;
	}

	if (is_su_sudo(taskstat->cmd) ||
	    is_skip_suid(taskstat) ||
	    mytmpskip(safebasename(taskstat->cmd))) {
		INFO("ignore %s %s report\n", taskstat->args, privupact[type]);
		return 0;
	}

	if (ptaskstat) {
		if (is_su_sudo(ptaskstat->cmd) ||
		    is_skip_suid(ptaskstat) ||
		    mytmpskip(safebasename(ptaskstat->cmd)) ||
		    strcmp(ptaskstat->cmd, "/bin/dbus-daemon") == 0) {
			INFO("ignore %s %s report, as parent is %s\n",
			     taskstat->args, privupact[type], ptaskstat->args);
			return 0;
		}
	}

	return 1;
}

/* 是被安装包安装的程序，且安装后未改变过 */
static int is_raw_installed_program(taskstat_t *taskstat)
{
	if (!taskstat ||
	    taskstat->product[0] == 0 || strcmp(taskstat->product, "N/A") == 0 ||
	    taskstat->vendor[0] == 0 || strcmp(taskstat->vendor, "N/A") == 0 ||
	    taskstat->pflags.program_changed ||
	    taskstat->flags & TASK_PROGRAM_CHANGED) {
		INFO("%s not raw installed program\n", taskstat->cmd);
		return 0;
	}

	DBG2(DBGFLAG_PROCESS, "%s is raw installed program\n", taskstat->cmd);
	return 1;
}

/* 向管控中心报告进程异常提权态 */
static void report_privup_post(taskstat_t *taskstat, taskstat_t *ctaskstat,
			      int type, struct timeval *privup_time)
{
	int size = sizeof(proc_msg_t);
	proc_msg_t *msg = NULL;
	int trust_event_id = 0;

	if (!taskstat) {
		MON_ERROR("report_privup fail, NULL taskstat\n");
		return;
	}

	/*
	 * 产生一条新的进程开始和结束记录。
	 * 提权执行程序和起shell也产生新记录，和set_taskstat_exec()里的处理脱钩
	 */
	msg = build_process_msg(taskstat);
	if (!msg) {
		MON_ERROR("Make %s(%d) %s message FAIL\n",
			  taskstat->args, taskstat->pid, privupact[type]);
		return;
	}

	/*
	 * 如果提权用户是root， 取父进程用户
	 * 比如已经提权后，才起的sniper，检查到的结果可能就是这样
	 */
	if (strcmp(msg->user, "root") == 0) {
		taskstat_t *ptaskstat = the_ptaskstat(taskstat);

		if (ptaskstat) {
			snprintf(msg->user, sizeof(msg->user), "%s", ptaskstat->user);
		}
	}

	msg->event_id = PROCESS_PRIVILEGE_ESCALATION; //提权

	/* 提权事件的时刻用内核里传出的时间 */
	if (privup_time) {
		msg->event_tv.tv_sec = privup_time->tv_sec;
		msg->event_tv.tv_usec = privup_time->tv_usec;
	}

	DBG2(DBGFLAG_PROCESS, "%s privup type %s/%d\n", taskstat->cmd, privupact[type], type);
/* 20210903 保守地，只对提权起shell报警，其他提权情况报关键日志 */
#ifdef STOP_NOTSUID_PRIVUP
	if (type == PRIVUP_SUID)
#else
	if (type != PRIVUP_SHELL && type != PRIVUP_DIRTYCOW && type != PRIVUP_DIRTYPIPE)
#endif
	{
		/*
		 * 避免误报：
		 * 1、非suid提权不报警
		 * 2、suid程序是安装后未改变过
		 */
		if (type != PRIVUP_SUID || is_raw_installed_program(taskstat)) {
			msg->behavior_id = BEHAVIOR_NORMAL;
			msg->loglevel = LOG_KEY;
			send_process_msg(msg, taskstat, 1);
			sniper_free(msg, size, PROCESS_GET);
			return;
		}
	}

	trust_event_id = is_trust_cmd(taskstat);

	if (trust_event_id & EVENT_PrivilegeEscalation) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
		send_process_msg(msg, taskstat, 1);
		sniper_free(msg, size, PROCESS_GET);
		return;
	}

	/* 非SUID提权上面报关键了，主要是避免误报 */
	/* 提权起shell/脏牛/被修改的suid程序/不是安装的suid程序，报危险 */
	msg->behavior_id = BEHAVIOR_ABNORMAL;
	msg->loglevel = LOG_HIGH_RISK;

	/* 这里不锁读prule.privilege_kill，应该也不会有什么糟糕的后果 */
	if (!prule.privilege_kill || client_mode_global) {
		INFO("Warning: privup defence policy off\n");
		send_process_msg(msg, taskstat, 1);
		sniper_free(msg, size, PROCESS_GET);
		return;
	}

	/* 避免误杀必须要用的suid程序 */
	if (type == PRIVUP_SUID && is_legal_suidexec(taskstat->cmd)) {
		INFO("Warning: %s changed, but skip defence for safety\n", taskstat->cmd);
		send_process_msg(msg, taskstat, 1);
		sniper_free(msg, size, PROCESS_GET);
		return;
	}

	/* 提权起shell，先杀shell */
	if (type == PRIVUP_SHELL && ctaskstat) {
		mykill(ctaskstat->pid, SIGKILL);
	}

	//TODO 是否stop_cmd()里进程不存在都视为阻断失败
	/* stop_cmd里设msg->terminate/terminate_result */
	if (stop_cmd(msg, privupact[type]) == 0) {
		/* 进程不存在，说明进程已经执行完了，视为阻断失败 */
		msg->terminate_result = failstr;
	}

	taskstat->pflags.terminate = 1;
	/* 停止dirtycow程序的父子兄弟进程 */
	if (taskstat->pflags.dirtycow) {
		stop_dirtycow_routine(taskstat->cmd);
	}

	/* shell被杀掉了，也算防御成功了 */
	if (msg->terminate_result != succstr &&
	    type == PRIVUP_SHELL &&
	    ctaskstat && mykill(ctaskstat->pid, 0) < 0) {
		msg->terminate_result = succstr;
	}

	/* send_process_msg里发防御消息 */
	send_process_msg(msg, taskstat, 1);

	sniper_free(msg, size, PROCESS_GET);
}

static void set_taskstat_privup_flag(taskstat_t *taskstat)
{
	struct stat st = {0};
	char *pathname = NULL;

	if (!taskstat) {
		return;
	}

	pathname = taskstat->cmd;
	taskstat->pflags.privup = 1;
	taskstat->pflags.privup_exec = 1;
	if (stat(pathname, &st) == 0) {
		if (st.st_mode & S_ISUID) {
		        if (strncmp(pathname, "/bin/", 5) == 0 ||
		            strncmp(pathname, "/usr/bin/", 9) == 0 ||
		            strncmp(pathname, "/sbin/", 6) == 0 ||
		            strncmp(pathname, "/usr/sbin/", 10) == 0 ||
		            strncmp(pathname, "/lib/", 5) == 0 ||
		            strncmp(pathname, "/lib64/", 7) == 0 ||
		            strncmp(pathname, "/usr/lib/", 9) == 0 ||
		            strncmp(pathname, "/usr/lib64/", 11) == 0 ||
		            strncmp(pathname, "/usr/libexec/", 13) == 0) {
				taskstat->pflags.privup_suid = 1;
			} else {
				taskstat->pflags.privup_notsyssuid = 1;
			}
		} else {
			taskstat->pflags.privup_notsuid = 1;
		}
	}
}
static void check_privup_shell(taskstat_t *taskstat, int init_stage)
{
	int i = 0, j = 0;
	pid_t pid = 0;
	char *comm = NULL, *comm2 = NULL;
	taskstat_t *ptaskstat = NULL, *ctaskstat = taskstat;

	if (!taskstat) {
		MON_ERROR("check_privup_shell fail, NULL taskstat\n");
		return;
	}
	if (get_proc_euid(taskstat->pid)) { //不是提权shell
		return;
	}

	/* 检查是否exp exec出的shell */
	ptaskstat = taskstat->exec_ptaskstat;
	while (ptaskstat && i < SNIPER_PGEN) {
		if (ptaskstat->uid || ptaskstat->euid) {
			goto report;
		}

		i++; //避免万一死循环
		ptaskstat = ptaskstat->exec_ptaskstat;
	}
	ptaskstat = NULL;

	/* 往上查提权的祖先进程 */
	for (i = 0; i < SNIPER_PGEN; i++) {
		if (taskstat->pinfo.task[i].pid < RESERVED_PIDS) {
			return;
		}

		/* 找到提权的祖先进程 */
		if (taskstat->pinfo.task[i].uid || taskstat->pinfo.task[i].euid) {
			/* 如果uid和euid一个是0一个非0，认为是该进程提的权
			   如果uid和euid都非0，认为是其子进程提的权 */
			if (taskstat->pinfo.task[i].uid && taskstat->pinfo.task[i].euid) {
				if (i > 0) {
					i--;
				}
			}
			comm = taskstat->pinfo.task[i].comm;
			break;
		}
	}

	/* 获取提权进程的taskstat，或同名祖先进程的taskstat */
	for (j = i; j < SNIPER_PGEN; j++) {
		if (j != i) {
			comm2 = taskstat->pinfo.task[j].comm;
			if (strcmp(comm2, comm) != 0) {
				return;
			}
		}

		pid = taskstat->pinfo.task[j].pid;
		ptaskstat = get_taskstat_nolock(pid, PROCESS_GET);
		if (!ptaskstat) {
			ptaskstat = init_one_process(pid);
		}
		if (ptaskstat) {
			break;
		}
	}

report:
	//TODO 考虑init_stage的差异
	/*
	 * exec的命令，ptaskstat的uid/euid是内核里执行该命令前的身份
	 * init阶段，ptaskstat的uid/euid是命令执行后的身份
	 * 所以，对于exec，user cmd->root cmd，user cmd是提权的命令，
	 * 对于init，user cmd->root cmd，root cmd是提权的命令
	 */

	if (ptaskstat) {
		/* 检查是否exp exec出的shell */
		if (ptaskstat->exec_ptaskstat) {
			ctaskstat = ptaskstat;
			ptaskstat = ptaskstat->exec_ptaskstat;
		}

		/* 忽略su和sudo */
		if (is_su_sudo(ptaskstat->cmd)) {
			ptaskstat->flags |= TASK_SU;
			return;
		}
		/* 避免误报，遇到过一次su的时候被阻断了，进程树显示sshd->bash */
		if (strcmp(ptaskstat->cmd, "/sbin/sshd") == 0 ||
		    strcmp(ptaskstat->cmd, "/usr/sbin/sshd") == 0) {
			return;
		}
		/*
		 * Cockpit是红帽开发的网页版图像化服务管理工具，包含远程终端功能
		 * 当输入root口令为root起终端时，进程树是
		 * cockpit-session -> cockpit-bridge -> bash
		 * 由于cockpit-session是suid程序，最后起了一个shell，所以报非法提权
		 * 银河麒麟V10服务器上可复现，从https://ip:9090进入页面
		 *
		 * 这个就是这么用的，故这里过滤掉，避免误报
		 */
		if (strcmp(safebasename(ptaskstat->cmd), "cockpit-session") == 0) {
			return;
		}

		if (is_filter_cmd(ptaskstat)) {
			return;
		}

		/* 这里ptaskstat可能是父进程，也可能是祖先进程 */
		INFO("privup shell %s/%d parent %s(%d), euid %u\n",
			ctaskstat->args, ctaskstat->pid,
			ptaskstat->args, ptaskstat->pid, ptaskstat->euid);
		set_taskstat_privup_flag(ptaskstat);
		report_privup_post(ptaskstat, ctaskstat, PRIVUP_SHELL, &ctaskstat->event_tv);
	}
}

static void info_privup_process(taskstat_t *taskstat, taskstat_t *ptaskstat)
{
	INFO("%s(%d) privup suid. [uid: %u/%u -> %u/%u], parent %s(%d)\n",
	     taskstat->args, taskstat->pid, ptaskstat->uid, ptaskstat->euid,
	     ptaskstat->gid, ptaskstat->egid, ptaskstat->args, ptaskstat->pid);
}
static void info_privup_exec(taskstat_t *taskstat, taskstat_t *ctaskstat)
{
	INFO("%s(%d) privup suid. [uid: %u/%u -> %u/%u], then exec %s(%d)\n",
	     taskstat->args, taskstat->pid, taskstat->uid, taskstat->euid,
	     ctaskstat->gid, ctaskstat->egid, ctaskstat->args, ctaskstat->pid);
}

//TODO 消除误报的一个方法，如果某程序普通用户执行后没提权，视为不会提权的程序
//在报告提权之前，在exehash里如查到程序有非提权程序标志，则是误报，不报
/*
 * report_initps时，检查当前已存在的进程是否处于提权态
 */
static void check_privup(taskstat_t *taskstat, int exec)
{
	taskstat_t *ptaskstat = NULL;
	struct stat st = {0}, cmdst = {0};
	char path[PATH_MAX] = {0}, *cmd = NULL;

	if (!taskstat) {
		MON_ERROR("check_privup fail, NULL taskstat\n");
		return;
	}
	if (taskstat->pid < RESERVED_PIDS) { //300以下的进程都是root
		return;
	}

	/* 目前仅做uid检查 */
	if (taskstat->uid && taskstat->euid) {
		return;
	}

	ptaskstat = the_ptaskstat(taskstat);
	if (!ptaskstat) {
		DBG("check_privup fail, %s(%d) NULL ptaskstat. "
		    "%s(%d) %s(%d) %s(%d)\n",
		    taskstat->args, taskstat->pid,
		    taskstat->pinfo.task[0].comm, taskstat->pinfo.task[0].pid,
		    taskstat->pinfo.task[1].comm, taskstat->pinfo.task[1].pid,
		    taskstat->pinfo.task[2].comm, taskstat->pinfo.task[2].pid);
		return;
	}

	/*
	 * 对于其他非shell程序，父进程已经是root，则认为未发生提权，
	 * 即父进程没有提权后执行命令
	 */
	if (!ptaskstat->uid || !ptaskstat->euid) {
		/* TODO req里记录的父进程uid如何用 */
		/* 考虑这种情况：程序fork子进程，然后在子进程里提权，然后子进程执行命令 */
		return;
	}

	/* 对于将要执行的命令，报告是父命令提权 */
	if (exec) {
		cmd = ptaskstat->cmd;
		/* 这里cmd首字母要么是.要么是/，核心线程已经在上面判puid的是否过滤了 */
		if (cmd[0] == '.') {
			snprintf(path, sizeof(path), "%s/%s", ptaskstat->cwd, cmd);
			cmd = path;
		}

		/* dbus-daemon-launch-helper会提权后执行程序，忽略之 */
		if (strcmp(cmd, "/lib64/dbus-1/dbus-daemon-launch-helper") == 0) {
			return;
		}

		/* 忽略su提权 */
		if (is_su_sudo(cmd)) {
			return;
		}

		/* root权限的shell，检查是否提权起的 */
		if (taskstat->pflags.shell) {
			check_privup_shell(taskstat, 0);
			return;
		}

		printf("CMD is %s\n", cmd);
		if (stat(cmd, &cmdst) < 0) {
			MON_ERROR("check_privup stat %s fail: %s"
				  "%s(%d) exec %s(%d)\n",
				  cmd, strerror(errno),
				  ptaskstat->args, ptaskstat->pid,
				  taskstat->args, taskstat->pid);
			// TODO 报告一条自己看的日志
			/* 宁漏勿误 */
			return;
		}

		//TODO 检查suid程序是否安装包安装，或后加的suid权限
		if (cmdst.st_mode & S_ISUID) {
			info_privup_exec(ptaskstat, taskstat);
			return;
		}

		report_privup_post(ptaskstat, taskstat, PRIVUP_NOSUID, &ptaskstat->event_tv);
		return;
	}

	/* 对于正在运行的命令，报告是自己提权 */
	cmd = taskstat->cmd;
	if (cmd[0] == '.') {
		snprintf(path, sizeof(path), "%s/%s", taskstat->cwd, cmd);
		cmd = path;
	}

	/* 忽略su提权 */
	if (is_su_sudo(cmd)) {
		return;
	}

	/* root权限的shell，检查是否提权起的 */
	if (taskstat->pflags.shell) {
		check_privup_shell(taskstat, 1);
		return;
	}

	/*
	 * 一种误报检查：
	 * 检查父进程是否原来是root，fork子进程后，自身做了seteuid/setuid/setreuid，
	 * 导致子进程的身份比父进程高
	 *
	 * setXuid后，/proc/PID/attr,net,task的所有者会变，其他项的所有者仍是root
	 * 就根据这个现象检测
	 *
	 * 对于setreuid，父进程setreuid后又exec，会导致/proc/PID/xx的所有者全变
	 * 这以后再考虑 TODO
	 */
	if (ptaskstat->pid != taskstat->pid) { //是父子关系，不是exec关系
		snprintf(path, sizeof(path), "/proc/%d/status", ptaskstat->pid);
		if (stat(path, &st) == 0 && st.st_uid == 0) {
			INFO("%s(%d) uid %u/%u, parent %s(%d) uid %u/%u\n"
			     "maybe root parent fork root child, then setuid, "
			     "while root child exec %s. dont look as privup\n",
			     taskstat->args, taskstat->pid,
			     taskstat->uid, taskstat->euid,
			     ptaskstat->args, ptaskstat->pid,
			     ptaskstat->uid, ptaskstat->euid,
			     taskstat->cmd);
			return;
		}
	}

	if (stat(cmd, &cmdst) < 0) {
		MON_ERROR("check_privup stat %s fail: %s. "
			  "%s(%d). parent %s(%d)\n",
			  cmd, strerror(errno),
			  taskstat->args, taskstat->pid,
			  ptaskstat->args, ptaskstat->pid);
		return;
	}
	if (cmdst.st_mode & S_ISUID) {
		info_privup_process(taskstat, ptaskstat);
		return;
	}

	/* 没有SUID的提权视为非法提权 */
	report_privup_post(taskstat, NULL, PRIVUP_NOSUID, &taskstat->event_tv);
}
static void check_privup_init(taskstat_t *taskstat)
{
	taskstat_t *ptaskstat = NULL;
	struct stat st = {0}, cmdst = {0};
	char path[PATH_MAX] = {0}, *cmd = NULL;

	if (!taskstat) {
		MON_ERROR("check_privup fail, NULL taskstat\n");
		return;
	}
	if (taskstat->pid < RESERVED_PIDS) { //300以下的进程都是root
		return;
	}

	/* 目前仅做uid检查 */
	if (taskstat->uid && taskstat->euid) {
		return;
	}

	/* root权限的shell，检查是否提权起的 */
	if (taskstat->pflags.shell) {
		check_privup_shell(taskstat, 1);
		return;
	}

//目前仅检查提权起shell
return;

	ptaskstat = the_ptaskstat(taskstat);
	if (!ptaskstat) {
		DBG("check_privup fail, %s(%d) NULL ptaskstat. "
		    "%s(%d) %s(%d) %s(%d)\n",
		    taskstat->args, taskstat->pid,
		    taskstat->pinfo.task[0].comm, taskstat->pinfo.task[0].pid,
		    taskstat->pinfo.task[1].comm, taskstat->pinfo.task[1].pid,
		    taskstat->pinfo.task[2].comm, taskstat->pinfo.task[2].pid);
		return;
	}

	/*
	 * 对于其他非shell程序，父进程已经是root，则认为未发生提权，
	 * 即父进程没有提权后执行命令
	 */
	if (!ptaskstat->uid || !ptaskstat->euid) {
		/* TODO req里记录的父进程uid如何用 */
		/* 考虑这种情况：程序fork子进程，然后在子进程里提权，然后子进程执行命令 */
		return;
	}

	/* 对于正在运行的命令，报告是自己提权 */
	cmd = taskstat->cmd;
	if (cmd[0] == '.') {
		snprintf(path, sizeof(path), "%s/%s", taskstat->cwd, cmd);
		cmd = path;
	}

	/* 忽略su提权 */
	if (is_su_sudo(cmd)) {
		return;
	}

	/*
	 * 一种误报检查：
	 * 检查父进程是否原来是root，fork子进程后，自身做了seteuid/setuid/setreuid，
	 * 导致子进程的身份比父进程高
	 *
	 * setXuid后，/proc/PID/attr,net,task的所有者会变，其他项的所有者仍是root
	 * 就根据这个现象检测
	 *
	 * 对于setreuid，父进程setreuid后又exec，会导致/proc/PID/xx的所有者全变
	 * 这以后再考虑 TODO
	 */
	if (ptaskstat->pid != taskstat->pid) { //是父子关系，不是exec关系
		snprintf(path, sizeof(path), "/proc/%d/status", ptaskstat->pid);
		if (stat(path, &st) == 0 && st.st_uid == 0) {
			INFO("%s(%d) uid %u/%u, parent %s(%d) uid %u/%u\n"
			     "maybe root parent fork root child, then setuid, "
			     "while root child exec %s. dont look as privup\n",
			     taskstat->args, taskstat->pid,
			     taskstat->uid, taskstat->euid,
			     ptaskstat->args, ptaskstat->pid,
			     ptaskstat->uid, ptaskstat->euid,
			     taskstat->cmd);
			return;
		}
	}

	if (stat(cmd, &cmdst) < 0) {
		MON_ERROR("check_privup stat %s fail: %s. "
			  "%s(%d). parent %s(%d)\n",
			  cmd, strerror(errno),
			  taskstat->args, taskstat->pid,
			  ptaskstat->args, ptaskstat->pid);
		return;
	}
	if (cmdst.st_mode & S_ISUID) {
		info_privup_process(taskstat, ptaskstat);
		return;
	}

	/* 没有SUID的提权视为非法提权 */
	report_privup_post(taskstat, NULL, PRIVUP_NOSUID, &taskstat->event_tv);
}

void check_privup_exec(taskstat_t *taskstat)
{
	check_privup(taskstat, 1);
}

static void get_ip(taskstat_t *taskstat, taskstat_t *ptaskstat)
{
	if (strncmp(taskstat->tty, "pts", 3) == 0) {
		/* 进程pts与父进程pts相同，继承父进程的ip */
		if (ptaskstat && ptaskstat->ip[0] != 0 &&
		    strcmp(taskstat->tty, ptaskstat->tty) == 0) {
			snprintf(taskstat->ip, sizeof(taskstat->ip), "%s", ptaskstat->ip);
			return;
		}

		/* 根据进程pts解析ip */
		tty2ip(taskstat->tty+3, taskstat->ip);
		return;
	}

	/* 进程没pts，继承父进程的ip */
	if (ptaskstat && ptaskstat->ip[0] != 0) {
		snprintf(taskstat->ip, sizeof(taskstat->ip), "%s", ptaskstat->ip);
		return;
	}
}

static void parse_pipeargs(taskreq_t *req, taskstat_t *taskstat)
{
	int i = 0, start = 0, end = 0, len = 0;
	unsigned long inode = 0;
	char *ptr = NULL;
	char newargs[S_ARGSLEN] = {0};
	char prev_args[S_ARGSLEN] = {0};
	char next_args[S_ARGSLEN] = {0};
	char fdpath[S_PROCPATHLEN] = {0};
	char linkname[S_NAMELEN] = {0};
	taskstat_t *prev_taskstat = NULL, *next_taskstat = NULL;

	if (req->flags & PSR_PIPEOUT) {
		taskstat->pipeout = req->pipeout;

		start = taskstat->pid + 1;
		end = taskstat->pid + 10;
		for (i = start; i <= end; i++) {
			next_taskstat = get_taskstat_nolock(i, PROCESS_GET);
			if (next_taskstat) {
				if (next_taskstat->pipein != taskstat->pipeout) {
					continue; //本进程不是command1 | command2的2
				}

				/* taskstat肯定是没拼过的，检查next_taskstat是否已经在头部拼过taskstat */
				len = taskstat->argslen;
				ptr = strchr(next_taskstat->args, '|');
				if (ptr && next_taskstat->args + len + 1 == ptr &&
				    strncmp(taskstat->args, next_taskstat->args, len) == 0) {
					snprintf(next_args, sizeof(next_args), "%s", ptr + 2);
				} else {
					snprintf(next_args, sizeof(next_args), "%s", next_taskstat->args);
				}
			} else {
				snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/0", i);
				if (readlink(fdpath, linkname, sizeof(linkname)-1) <= 0 ||
				    sscanf(linkname, "pipe:[%lu]", &inode) != 1 ||
				    inode != taskstat->pipeout) {
					continue; //本进程不是command1 | command2的2
				}

				get_proc_cmdline(i, next_args, sizeof(next_args)); //取command2的命令行
			}

			break; //本进程是command1 | command2的2
		}
	}

	if (req->flags & PSR_PIPEIN) {
		taskstat->pipein = req->pipein;

		start = taskstat->pid - 1;
		end = taskstat->pid - 10;
		for (i = start; i >= end; i--) {
			prev_taskstat = get_taskstat_nolock(i, PROCESS_GET);
			if (prev_taskstat) {
				if (prev_taskstat->pipeout != taskstat->pipein) {
					continue; //本进程不是command0 | command1的0
				}

				/* taskstat肯定是没拼过的，检查prev_taskstat是否已经在尾部拼过taskstat */
				ptr = strrchr(prev_taskstat->args, '|');
				if (ptr && *(ptr+1) == ' ' && strcmp(ptr+2, taskstat->args) == 0) {
					/* a | b，head是0，ptr是2，len=ptr-head-1 */
					len = (unsigned long)ptr - (unsigned long)prev_taskstat->args - 1;
					memcpy(prev_args, prev_taskstat->args, len);
				} else {
					snprintf(prev_args, sizeof(prev_args), "%s", prev_taskstat->args);
				}
			} else {
				snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/1", i);
				if (readlink(fdpath, linkname, sizeof(linkname)-1) <= 0 ||
				    sscanf(linkname, "pipe:[%lu]", &inode) != 1 ||
				    inode != taskstat->pipein) {
					continue; //本进程不是command0 | command1的0
				}

				get_proc_cmdline(i, prev_args, sizeof(next_args)); //取command0的命令行
			}

			break;
		}
	}

	if (prev_args[0] && next_args[0]) {
		snprintf(newargs, sizeof(newargs), "%s | %s | %s",
			thestring(prev_args), thestring(taskstat->args), thestring(next_args));
		len = strlen(newargs);

		snprintf(taskstat->args, sizeof(taskstat->args), "%s", newargs);
		taskstat->argslen = len;

		if (prev_taskstat) {
			snprintf(prev_taskstat->args, sizeof(prev_taskstat->args), "%s", newargs);
			prev_taskstat->argslen = len;
		}

		if (next_taskstat) {
			snprintf(next_taskstat->args, sizeof(next_taskstat->args), "%s", newargs);
			next_taskstat->argslen = len;
		}

		return;
	}

	if (prev_args[0]) {
		snprintf(newargs, sizeof(newargs), "%s | %s",
			thestring(prev_args), thestring(taskstat->args));
		len = strlen(newargs);

		snprintf(taskstat->args, sizeof(taskstat->args), "%s", newargs);
		taskstat->argslen = len;

		if (prev_taskstat) {
			snprintf(prev_taskstat->args, sizeof(prev_taskstat->args), "%s", newargs);
			prev_taskstat->argslen = len;
		}

		return;
	}

	if (next_args[0]) {
		snprintf(newargs, sizeof(newargs), "%s | %s",
			thestring(taskstat->args), thestring(next_args));
		len = strlen(newargs);

		snprintf(taskstat->args, sizeof(taskstat->args), "%s", newargs);
		taskstat->argslen = len;

		if (next_taskstat) {
			snprintf(next_taskstat->args, sizeof(next_taskstat->args), "%s", newargs);
			next_taskstat->argslen = len;
		}
	}
}

static int check_netsocket(char *filename, char *procfile)
{
	FILE *fp = NULL;
	char str[64] = {0};
	char buf[1024] = {0};
	unsigned long ino = 0;

	if (filename == NULL) {
		INFO("E:check socket null filename\n");
		return 0;
	}
	if (procfile == NULL) {
		INFO("E:check socket null procfile\n");
		return 0;
	}

	sscanf(filename, "socket:[%lu]", &ino);
	snprintf(str, sizeof(str), " %lu", ino);

	fp = fopen(procfile, "r");
	if (fp == NULL) {
		INFO("E: open %s fail: %s\n", procfile, strerror(errno));
		return 0;
	}

	errno = 0;
	while (1) {
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			if (errno != 0) {
				INFO("E: fgets %s fail: %s\n",
				     procfile, strerror(errno));
			}
			break;
		}
		if (strstr(buf, str)) {
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}

/* 检查是network socket还是unix socket */
int is_netsocket(char *filename)
{
	if (check_netsocket(filename, "/proc/net/tcp"))
		return 1;
	if (check_netsocket(filename, "/proc/net/tcp6"))
		return 1;
	if (check_netsocket(filename, "/proc/net/udp"))
		return 1;
	if (check_netsocket(filename, "/proc/net/udp6"))
		return 1;

	INFO("%s is unix socket\n", filename);
	return 0;
}

int skip_child(char *cmd)
{
	if (!cmd) {
		return 0;
	}

	if (strcmp(cmd, "cc") == 0 ||
	    strcmp(cmd, "gcc") == 0 ||
	    strcmp(cmd, "dhclient-script") == 0 ||
	    strcmp(cmd, "man") == 0) {
		return 1;
	}
	return 0;
}

#if 0
static void init_taskstat_common(taskreq_t *req, taskstat_t *taskstat, unsigned long flags)
#else
static void init_taskstat_common(struct ebpf_taskreq_t *req, taskstat_t *taskstat, unsigned long flags)
#endif
{
	int rpathlen = 0;
	char *cmd = NULL, *args = NULL, *cwd = NULL;
	char path[PATH_MAX] = {0}, rpath[PATH_MAX] = {0};
	taskstat_t *ptaskstat = NULL;

	if (!req || !taskstat) {
		return;
	}

	memset(taskstat, 0, sizeof(struct task_status));

#if 0
	taskstat->flags = req->flags | flags;
#else
	taskstat->flags = flags;
	if (taskstat->flags & TASK_DANGER) {
		printf("task danger when init, why?\n");
	}
#endif

	taskstat->pid = req->pid;
	memcpy(&taskstat->pinfo, &req->pinfo, sizeof(struct parent_info));

	taskstat->proctime = req->proctime;

#if 0
	taskstat->event_tv.tv_sec  = req->event_tv.tv_sec;
	taskstat->event_tv.tv_usec = req->event_tv.tv_usec;
	if (req->flags & TASK_STOPED) {
		taskstat->stop_tv.tv_sec  = req->event_tv.tv_sec;
		taskstat->stop_tv.tv_usec = req->event_tv.tv_usec;
	}
#else
	// no gettimeofday support in ebpf
	gettimeofday(&taskstat->event_tv, NULL);
#endif

	set_taskuuid(taskstat->uuid, req->proctime, req->pid, 0);

	taskstat->uid = req->uid;
	taskstat->euid = req->euid;
	uidtoname(taskstat->uid, taskstat->user);

	taskstat->argc = req->argc;
#if 0
	taskstat->argv0len = req->argv0len;
#else
	taskstat->argv0len = strlen(req->args[0]);
#endif
	taskstat->options = req->options;

#if 0
	cmd = &req->args;
	args = cmd + req->cmdlen + 1;
	cwd = args + req->argslen + 1;
#else
	cmd = req->cmd;
	// TODO(luoyinhong)

	args = req->args[0];
	cwd = req->cwd;
#endif
	/* 取命令的realpath，没取到，则还是用req里的 */
	if (cmd[0] != '/') {
		snprintf(path, sizeof(path), "%s/%s", cwd, cmd);
		if (realpath(path, rpath)) {
			rpathlen = strlen(rpath);
		}
	} else if (strstr(cmd, "//") || strstr(cmd, "./")) {
		/*
		 * 考虑这样的场景：/sbin/iptables -> xtables-multi
		 * 如果这里取了iptables的realpath，那么在管控中心显示的
		 * 命令路径是/sbin/xtables-multi。
		 * 设置/sbin/xtables-multi为白名单，且规则里不填md5，则
		 * /sbin/iptables不会被认为白名单。这与期望不符。
		 * 因此，对路径正常的的链接文件，不取realpath。
		 */
		if (realpath(cmd, rpath)) {
			rpathlen = strlen(rpath);
		}
	}
	if (rpathlen > 0 && rpathlen < S_CMDLEN) {
		memcpy(taskstat->cmd, rpath, rpathlen);
		taskstat->cmdlen = rpathlen;
		taskstat->cmd[rpathlen] = 0;
	} else {
		memcpy(taskstat->cmd, cmd, req->cmdlen);
		taskstat->cmdlen = req->cmdlen;
		taskstat->cmd[req->cmdlen] = 0;
	}

#if 0
	taskstat->pflags = req->pflags;
	if (req->pflags.docker) {
		memcpy(taskstat->sha256, req->md5, S_MD5LEN-1);
		taskstat->sha256[S_MD5LEN-1] = 0;
		memset(taskstat->sha256, 'X', S_SHALEN-1);
		taskstat->sha256[S_SHALEN-1] = 0;
		snprintf(taskstat->vendor, sizeof(taskstat->vendor), "N/A");
		snprintf(taskstat->product, sizeof(taskstat->product), "docker %s", thestring(req->nodename));
	} else {
		count_file_hash(taskstat);
	}
#else
	count_file_hash(taskstat);
#endif

#if 0
	memcpy(taskstat->args, args, req->argslen);
	taskstat->argslen = req->argslen;
	taskstat->args[req->argslen] = 0;
#else
	for (int i = 0; i < req->argc; i++) {
		if (i > 0)
			strncat(taskstat->args, " ", 1);
		strncat(taskstat->args, req->args[i], 32);
	}
	taskstat->argslen = strlen(taskstat->args);
	// printf("taskstat->args(%d): %s\n", taskstat->argslen, taskstat->args);
#endif
	/* 内核里已经检查过信任和过滤了，这里不重复检查 */

	/* 拼管道命令后会改变命令行参数值，拼之前先检查是否交互shell */
	if (is_shell(taskstat->args) > 0) {
		taskstat->pflags.shell = 1;
	} else if (is_bash_waiting_cmd(taskstat->cmd, taskstat->pid) &&
		   get_proc_exe(taskstat->pid, path) > 0 &&
		   is_bash_waiting_cmd(path, taskstat->pid)) {
		INFO("init_taskstat_common: seem %s/%d as shell\n", taskstat->args, taskstat->pid);
		taskstat->pflags.shell = 1;
	}

#if 0
	/* 拼上管道命令 */
	parse_pipeargs(req, taskstat);
#else
#endif

	memcpy(taskstat->cwd, cwd, req->cwdlen);
	taskstat->cwdlen = req->cwdlen;
	taskstat->cwd[req->cwdlen] = 0;

	if (req->tty[0] != 0) {
		snprintf(taskstat->tty, sizeof(taskstat->tty), "%s", req->tty);
		taskstat->flags |= TASK_TTY;
	}

	/* 继承父进程的session_uuid，否则本进程uuid作为session_uuid */
	ptaskstat = get_ptaskstat_from_pinfo(&req->pinfo);
	if (ptaskstat && ptaskstat->session_uuid[0] != 0) {
		memcpy(taskstat->session_uuid, ptaskstat->session_uuid, S_UUIDLEN);
	} else if (taskstat->flags & TASK_TTY) {
		//TODO 如果把webshell、反弹shell看成有tty的操作，如何设session_uuid
		get_session_uuid(taskstat->tty, taskstat->session_uuid);
	}

#if 0
	if (req->ip[0] != 0) {
		snprintf(taskstat->ip, sizeof(taskstat->ip), "%s", req->ip);
	} else {
		get_ip(taskstat, ptaskstat);
	}
#else
	// NOTE: no ip info got from ebpf
#endif
	get_mem_usage(taskstat);
}

/* set_taskstat_exec保证rep，taskstat非空 */
#if 0
static void init_taskstat_exec(taskreq_t *req, taskstat_t *taskstat)
#else
static void init_taskstat_exec(struct ebpf_taskreq_t *req, taskstat_t *taskstat)
#endif
{
	taskstat_t *ptaskstat = NULL;
#if 0
	unsigned long flags = req->flags;
#else
	unsigned long flags = 0;
#endif

	ptaskstat = get_ptaskstat_from_pinfo(&req->pinfo);
	if (ptaskstat) {
		flags |= ptaskstat->flags & TASK_INHERIT;
#if 0
		if (ptaskstat->flags & (TASK_DROP|TASK_DROPCHILD)) {
			flags |= TASK_DROP;
		}
#endif
	}

	init_taskstat_common(req, taskstat, flags);
}

/* set_taskstat_exec保证rep，taskstat非空，且已对tasklist[pid]加写锁 */
#if 0
static void init_taskstat_execplus(taskreq_t *req, taskstat_t *taskstat)
#else
static void init_taskstat_execplus(struct ebpf_taskreq_t *req, taskstat_t *taskstat)
#endif
{
	taskstat_t *exec_ptaskstat = NULL;
	int exec_times = 0, refcount = 0;
#if 0
	unsigned long flags = req->flags;
#else
	unsigned long flags = 0;
#endif

	/* 这里不能全继承，否则/tmp/sh -c df会报df是异常进程，会让人搞不懂 */
	flags |= taskstat->flags & TASK_INHERIT;

	refcount = taskstat->refcount;
	exec_times = taskstat->exec_times + 1;
	exec_ptaskstat = taskstat->exec_ptaskstat;

	init_taskstat_common(req, taskstat, flags);

	taskstat->exec_ptaskstat = exec_ptaskstat;
	taskstat->refcount = refcount;

	taskstat->exec_times = exec_times;
	set_taskuuid(taskstat->uuid, req->proctime, req->pid, exec_times);
}

/*
 * 设置进程执行命令的taskstat，发送消息由调用者做
 * 对于命令又exec新命令的多级命令执行场景，将前一个命令作为新命令的父进程信息
 * process_monitor保证rep非空
 */
#if 0
static taskstat_t *set_taskstat_exec(taskreq_t *req)
#else
static taskstat_t *set_taskstat_exec(struct ebpf_taskreq_t *req)
#endif
{
	taskstat_t *taskstat = NULL;
	pid_t pid = 0;

	if (!req) {
		MON_ERROR("set_taskstat_exec fail, NULL rep\n");
		return NULL;
	}
	/* 检查taskreq的参数，argslen可能是0，这可能是shellcode */
	/* cmdlen、argslen和cwdlen的数据类型是unsigned short，值不会小于0 */
	if (req->cmdlen == 0 || req->cmdlen >= S_CMDLEN || req->argslen >= S_ARGSLEN ||
	    req->cwdlen == 0 || req->cwdlen >= S_CWDLEN) {
		/* 不打印args，防止错误的args可能导致core */
		MON_ERROR("set_taskstat_exec fail, bad request "
			  "cmdlen/argslen/cwdlen %d/%d/%d. pid %d\n",
			  req->cmdlen, req->argslen, req->cwdlen, req->pid);
		return NULL;
	}

	pid = req->pid;
	/* 这里加写锁，避免其他线程取到值不完整的taskstat */
	taskstat = get_taskstat_wrlock(pid, PROCESS_GET, req->proctime);
	if (!taskstat) {
		/* 进程第一次执行命令 */
		taskstat = alloc_taskstat();
		if (!taskstat) {
			MON_ERROR("alloc taskstat for %s(%d) fail. "
				  "%s(%d) %s(%d) %s(%d)\n",
				  &req->args + req->cmdlen + 1, pid,
				  taskstat->pinfo.task[0].comm, taskstat->pinfo.task[0].pid,
				  taskstat->pinfo.task[1].comm, taskstat->pinfo.task[1].pid,
				  taskstat->pinfo.task[2].comm, taskstat->pinfo.task[2].pid);
			return NULL;
		}

		init_taskstat_exec(req, taskstat);

		add_tasklist_tail(taskstat);

		return taskstat;
	}

	list_del(&taskstat->list);
	put_taskstat_unlock(taskstat);

	/* 进程不是第一次执行命令, 保存上一条命令的信息 */
	save_exec_ptaskstat(taskstat);

	/* 更新taskstat */
	init_taskstat_execplus(req, taskstat);

	//count_file_hash(taskstat); //在init_taskstat_common里做了
	add_tasklist_tail(taskstat);

	return taskstat;
}

static void terminate_cmd(proc_msg_t *msg, taskstat_t *taskstat, char *desc, int init_stage)
{
	int ret = 0;
	char *cmdname = NULL;

	/* 运维和学习模式不阻断 */
	if (client_mode_global != NORMAL_MODE) {
		return;
	}

	if (!msg || !taskstat || !desc) {
		MON_ERROR("terminate_cmd fail, "
			"msg %p, taskstat %p, desc %p\n",
			msg, taskstat, desc);
		return;
	}
	msg->terminate = 1;

	INFO("terminate_cmd %s(%d) as %s. init_stage %d\n", taskstat->args, taskstat->pid, desc, init_stage);

	if (init_stage) {
		/* 杀死进程，设置msg->terminate_result */
		if (stop_cmd(msg, desc) >= 0) {
			gettimeofday(&msg->stop_tv, NULL);
			taskstat->stop_tv = msg->stop_tv;
		}
		return;
	}

	if (msg->flags & TASK_STOPED) {  //内核里阻断
		msg->terminate_result = succstr;
		return;
	}

	ret = stop_cmd(msg, desc);
	if (ret == 1) { //内核未阻断，这里阻断了
		msg->terminate_result = succstr;
		gettimeofday(&msg->stop_tv, NULL);
		taskstat->stop_tv = msg->stop_tv;
		return;
	}

	cmdname = safebasename(msg->cmd);
	/* 虽然dd写盘危险命令在阻断前已结束，但如果开了mbr防护，也可以视为防御成功 */
	if (ret == 0 && strcmp(cmdname, "dd") == 0) {
		if (prule.mbr_kill) {
			msg->terminate_result = succstr;
			return;
		}
	}

	//内核未阻断，程序已执行完，视为阻断失败
	msg->terminate_result = failstr;
}

static void stop_rinetd(void)
{
	int pid = 0;
	DIR *procdirp = NULL;
	struct dirent *pident = NULL;

	/* 学习模式和运维模式不阻断 */
	if (client_mode_global != NORMAL_MODE) {
		return;
	}

	procdirp = sniper_opendir("/proc", PROCESS_GET);
	if (!procdirp) {
                MON_ERROR("stop_rinetd: open /proc fail: %s\n", strerror(errno));
		return;
	}

	/*
	 * 遍历/proc获得当前进程信息
	 */
	while ((pident = readdir(procdirp))) {
		char comm[S_COMMLEN] = {0};

		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue; //忽略非进程项信息
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

		if (get_proc_comm(pid, comm) > 0 && strcmp(comm, "rinetd") == 0) {
			mykill(pid, SIGKILL);
		}
	}

	sniper_closedir(procdirp, PROCESS_GET);
}

int determine_msg_event(proc_msg_t *msg, int trust_events,
			int event_id,
			int event_flag, int event_loglevel)
{
	int loglevel = 0;

	if (trust_events & event_flag) {
		loglevel = LOG_NORMAL;
	} else {
		loglevel = event_loglevel;
	}

	/* 如果之前没有事件，则置当前事件 */
	if (loglevel > msg->loglevel ||
	    (loglevel == msg->loglevel &&
	     msg->event_id <= PROCESS_SCHEDULE)) {
		msg->event_id = event_id;
		msg->loglevel = loglevel;
	}

	return 0;
}

//TODO 端口转发和反弹shell检查待完善，包括日志
/* 事件优先级：黑白名单、可信、过滤、菜刀、中间件执行、危险进程、远程执行/反弹shell、
   端口转发命令、服务端口变化、可疑进程、一般进程 */
static void choose_process_event(proc_msg_t *msg, taskstat_t *taskstat, int init_stage, int trust_events)
{
	if (!msg || !taskstat) {
		MON_ERROR("choose_process_event fail, msg %p, taskstat %p\n",
			msg, taskstat);
		return;
	}

	if (msg->flags & TASK_CRON) {
		msg->event_id = PROCESS_SCHEDULE;
	}

	/* 违规进程的子进程，也视为违规进程 */
	if (msg->flags & (TASK_BLACK|TASK_PARENT_BLACK)) {
		msg->event_id = PROCESS_VIOLATION;
		msg->behavior_id = BEHAVIOR_VIOLATION; //违规
		msg->loglevel = LOG_HIGH_RISK;
		if (prule.black_kill) {
			terminate_cmd(msg, taskstat, "violation command", init_stage);
		}
		return;
	}

        /*
         * 选择事件的规则：
         * 1、按危险程度顺序选择：高危、中危、低危、关键、普通
         * 2、先选择命令本身性质的事件，再危险手段使用命令的事件:
         *    挖矿、危险命令、webshell、中间件执行
         * 3、被阻断则确定为该事件类型
	 * 4、判断是否可信
	 * 5、如果不是全局可信，要检查是否还命中其他事件
         */

	/*
	 * 内核里阻断的进程，事件是确定的，下面中的一个:
	 * PROCESS_WEBSHELL_EXECUTION, PROCESS_MIDDLE_EXECUTION,
	 * PROCESS_MINERWARE, PROCESS_PORT_FORWARD, PROCESS_ABNORMAL
	 */
	if (msg->flags & TASK_STOPED) {
		msg->behavior_id = BEHAVIOR_ABNORMAL;
		msg->terminate = 1;

		if (msg->flags & TASK_WEBSHELL) {
			msg->event_id = PROCESS_WEBSHELL_EXECUTION;
			msg->loglevel = LOG_MIDDLE_RISK;
			if (prule.webshell_lockip) {
				msg->blockip = 1;
				msg->blockip_result = succstr;
			}
			return;
		}

		if (msg->flags & TASK_MINER) {
			msg->event_id = PROCESS_MINERWARE;
			msg->loglevel = LOG_MIDDLE_RISK;
			if (prule.webshell_lockip) {
				msg->blockip = 1;
				msg->blockip_result = succstr;
			}
			return;
		}

		if (msg->flags & TASK_WEBEXECUTE) {
			msg->event_id = PROCESS_MIDDLE_EXECUTION;
			msg->loglevel = LOG_LOW_RISK;
			return;
		}

		if (msg->flags & TASK_PORT_FORWARD) {
			msg->event_id = PROCESS_PORT_FORWARD;
			msg->loglevel = LOG_MIDDLE_RISK;
			return;
		}

		if (msg->flags & TASK_DANGER) {
			msg->event_id = PROCESS_DANGEROUS;
			msg->loglevel = LOG_MIDDLE_RISK;
			return;
		}

		if (msg->flags & TASK_ABNORMAL) {
			msg->event_id = PROCESS_ABNORMAL;
			msg->loglevel = LOG_MIDDLE_RISK;
			return;
		}

		if (msg->pflags.privup_parent) {
			INFO("%s(%d) stopped, as parent %s(%d) privup\n",
				msg->cmdline, msg->pid, msg->pcmdline, msg->ppid);
		} else {
			INFO("%s(%d) stopped, why? parent is %s(%d)\n",
				msg->cmdline, msg->pid, msg->pcmdline, msg->ppid);
		}
		if (msg->flags & TASK_CRON) {
			msg->event_id = PROCESS_SCHEDULE;
		} else {
			msg->event_id = PROCESS_NORMAL;
		}
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
		return;
	}

	if (msg->flags & TASK_WEBSHELL) {
		if (determine_msg_event(msg, trust_events, PROCESS_WEBSHELL_EXECUTION,
				EVENT_Chopper, LOG_HIGH_RISK)) {
			return;
		}
	}

	if (msg->flags & TASK_WEBEXECUTE) {
		if (determine_msg_event(msg, trust_events, PROCESS_MIDDLE_EXECUTION,
				EVENT_ServiceProcess, LOG_LOW_RISK)) {
			return;
		}
	}

	if (msg->flags & TASK_MINER) {
		if (determine_msg_event(msg, trust_events, PROCESS_MINERWARE,
				EVENT_Mining, LOG_HIGH_RISK)) {
			return;
		}
	}

	/* 远程执行/反弹shell */
	if (msg->flags & TASK_REMOTE_EXECUTE) {
		if (determine_msg_event(msg, trust_events, PROCESS_REMOTE_EXECUTION,
				EVENT_ReverseShell, LOG_HIGH_RISK)) {
			return;
		}

		if (!(trust_events & EVENT_ReverseShell) && prule.remote_execute_kill) {
			msg->event_id = PROCESS_REMOTE_EXECUTION;
			msg->behavior_id = BEHAVIOR_ABNORMAL; //异常
			msg->loglevel = LOG_HIGH_RISK;
			terminate_cmd(msg, taskstat, "reverse shell", init_stage);

			if (prule.remote_execute_lockip) {
				msg->blockip = 1;
			}
			return;
		}
	}

	/* 端口转发命令 */
	if (msg->flags & TASK_PORT_FORWARD) {
		msg->event_id = PROCESS_PORT_FORWARD;

		if (determine_msg_event(msg, trust_events, PROCESS_PORT_FORWARD,
				EVENT_Tunnel, LOG_MIDDLE_RISK)) {
			return;
		}

		if (!(trust_events & EVENT_Tunnel) && prule.port_forward_kill) {
			msg->behavior_id = BEHAVIOR_ABNORMAL; //异常
			msg->loglevel = LOG_MIDDLE_RISK;
			terminate_cmd(msg, taskstat, "port forward", init_stage);
			if (strcmp(safebasename(taskstat->cmd), "rinetd") == 0) {
				stop_rinetd();
			}
			return;
		}
	}

	if (msg->flags & TASK_DANGER) {
		if (determine_msg_event(msg, trust_events, PROCESS_DANGEROUS,
				EVENT_RiskCommand, LOG_MIDDLE_RISK)) {
			return;
		}

		if (!(trust_events & EVENT_RiskCommand) && prule.danger_kill) {
			msg->behavior_id = BEHAVIOR_ABNORMAL; //异常
			msg->loglevel = LOG_MIDDLE_RISK;
			terminate_cmd(msg, taskstat, "danger command", init_stage);
			return;
		}
	}

	if (msg->flags & TASK_ABNORMAL) {
		if (determine_msg_event(msg, trust_events, PROCESS_ABNORMAL,
				EVENT_AbnormalProcess, LOG_MIDDLE_RISK)) {
			return;
		}

		if (!(trust_events & EVENT_AbnormalProcess) && prule.abnormal_kill) {
			msg->behavior_id = BEHAVIOR_ABNORMAL; //异常
			msg->loglevel = LOG_MIDDLE_RISK;
			terminate_cmd(msg, taskstat, "abnormal process", init_stage);
			return;
		}
	}

	if (msg->loglevel < LOG_LOW_RISK) {
		msg->behavior_id = BEHAVIOR_NORMAL;   //正常
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL; //异常
	}
}

/* firefox访问矿池不杀进程，否则firefox以后可能启动不了，因为firefox会自动访问之前访问的域名 */
static int not_report_process_access_minepool(taskstat_t *taskstat)
{
	char *cmdname = NULL;

	if (!taskstat || taskstat->product[0] == 0 || strcmp(taskstat->product, "N/A") == 0) {
		return 0;
	}

	cmdname = safebasename(taskstat->cmd);
	if (strncmp(cmdname, "firefox", 7) == 0 ||
	    strcmp(cmdname, "dig") == 0 ||
	    strcmp(cmdname, "ssh") == 0 ||
	    strcmp(cmdname, "wget") == 0 ||
	    strcmp(cmdname, "curl") == 0 ||
	    strcmp(cmdname, "ping") == 0 ||
	    strcmp(cmdname, "nscd") == 0 ||
	    strcmp(cmdname, "telnet") == 0 ||
	    strcmp(cmdname, "nslookup") == 0) {
		return 1;
	}
	return 0;
}

//TODO 推广到压缩所有事件的重复日志，但要先解决好进程exec进程的情况，否则会误压缩
#define MINER_CACHE_NUM 16
int next_miner_cache = 0;
struct miner_cache {
	pid_t pid;
        time_t last_report_t;
} miner_cache[MINER_CACHE_NUM] = {{0}};

#if 0
static void report_minepool_access(taskreq_t *req)
{
	char *ptr = NULL;
	int i = 0, found = 0, trust_event_id = 0;
	taskstat_t *taskstat = NULL;
	taskstat_t tmp_taskstat = {0};
	proc_msg_t *msg = NULL;
	time_t now = time(NULL);

	if (!req) {
		MON_ERROR("report_miner fail, NULL req\n");
		return;
	}

        for (i = 0; i < MINER_CACHE_NUM; i++) {
                if (miner_cache[i].last_report_t == 0) {
                        break;
                }
                /* 1分钟内不重复报告 */
		/* 发现重复报了2次firefox，间隔了62秒，所以把1分钟提到3分钟 */
		if (miner_cache[i].pid == req->pid) {
                        found = 1;
                        if (now - miner_cache[i].last_report_t < 60) {
                                return;
                        }
                        miner_cache[i].last_report_t = now;
                        break;
                }
        }
        if (!found) {
                i = next_miner_cache;
                miner_cache[i].pid = req->pid;
                miner_cache[i].last_report_t = now;
                next_miner_cache = (i + 1) & 0xf;
        }

	taskstat = req2taskstat(req, &tmp_taskstat);
	if (!taskstat) {
		MON_ERROR("report_miner fail, no taskstat\n");
		return;
	}

	if (not_report_process_access_minepool(taskstat)) {
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}
	msg->event_tv = req->event_tv;
	msg->event_id = PROCESS_MINERWARE;
	msg->blockip = req->pflags.locking;

	trust_event_id = is_trust_cmd(taskstat);
	if (trust_event_id & EVENT_Mining) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL;
		msg->loglevel = LOG_MIDDLE_RISK;
		if (prule.miner_kill) {
			terminate_cmd(msg, taskstat, "access minepool", 0);
		}
	}

	if (req->pflags.terminate) {
		msg->terminate = req->pflags.terminate;
		msg->terminate_result = succstr;
	}

	/* 矿池域名在请求包的尾部 */
	ptr = &req->args + req->cmdlen + req->argslen + req->cwdlen + 3;
	memcpy(msg->domain, ptr, S_DOMAIN_NAMELEN-1);

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

static void report_miner(taskreq_t *req)
{
	taskstat_t *taskstat = NULL;
	proc_msg_t *msg = NULL;

	if (!req) {
		MON_ERROR("report_miner fail, NULL req\n");
		return;
	}

	taskstat = set_taskstat_exec(req);
	if (!taskstat) {
		MON_ERROR("report_miner fail, alloc taststat fail\n");
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}
	msg->event_tv = req->event_tv;
	msg->event_id = PROCESS_MINERWARE;

	//TODO 内核里检查，并用内核里检查的结果？
	if (req->pflags.trust) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL;
		msg->loglevel = LOG_MIDDLE_RISK;
	}

	if (req->pflags.terminate) {
		msg->terminate = req->pflags.terminate;
		msg->terminate_result = succstr;
	}

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

static void report_privup(taskreq_t *req)
{
	taskstat_t *taskstat = NULL;
	taskstat_t tmp_taskstat = {0};

	if (!req) {
		MON_ERROR("report_disk_write fail, NULL req\n");
		return;
	}

	taskstat = req2taskstat(req, &tmp_taskstat);
	if (!taskstat) {
		MON_ERROR("report_miner fail, no taskstat\n");
		return;
	}
	taskstat->flags |= req->flags;

	taskstat->pflags.privup = 1;
	taskstat->pflags.privup_suid = req->pflags.privup_suid;
	taskstat->pflags.privup_notsuid = req->pflags.privup_notsuid;
	taskstat->pflags.privup_notsyssuid = req->pflags.privup_notsyssuid;
	taskstat->pflags.privup_exec = req->pflags.privup_exec;
	taskstat->pflags.privup_file = req->pflags.privup_file;

	if (req->pflags.privup_exec) {
		snprintf(taskstat->childcmd, sizeof(taskstat->childcmd), "%s", req->target_cmd);
		taskstat->childcmd[S_COMMLEN-1] = 0;
/* 为了避免重复报告，这里暂时不检测提权shell，由check_privup_shell()检测 */
#if 0
		if (is_shell(taskstat->childcmd) > 0) {
			/* 忽略su和sudo */
			if (is_su_sudo(taskstat->cmd)) {
				taskstat->flags |= TASK_SU;
				goto report;
			}
			if (strcmp(taskstat->cmd, "/sbin/sshd") == 0 ||
			    strcmp(taskstat->cmd, "/usr/sbin/sshd") == 0) {
				/* 避免误报，遇到过一次su的时候被阻断了，进程树显示sshd->bash */
				goto report;
			}

			if (is_filter_cmd(taskstat)) {
				return;
			}

			INFO("privup shell %s(%d), parent %s(%d), euid %u\n",
				taskstat->childcmd, req->root_pid,
				taskstat->args, taskstat->pid, taskstat->euid);
			report_privup_post(taskstat, NULL, PRIVUP_SHELL, &req->event_tv);

			if (taskstat->pflags.terminate && taskstat->pid != req->root_pid) {
				mykill(req->root_pid, SIGKILL);
			}
			return;
		}
report:
#endif
	}

	if (req->pflags.privup_notsuid) {
		report_privup_post(taskstat, NULL, PRIVUP_NOSUID, &req->event_tv);
	} else {
		report_privup_post(taskstat, NULL, PRIVUP_SUID, &req->event_tv);
	}
}

static void report_dirtycow(taskreq_t *req)
{
	taskstat_t *taskstat = get_taskstat_nolock(req->pid, PROCESS_GET);

	if (!taskstat) {
		taskstat = get_ptaskstat_from_pinfo(&req->pinfo);
	}
	if (!taskstat) {
		INFO("report_dirtycow %s(%d) no taskstat, build one\n", &req->args, req->pid);
		taskstat = alloc_taskstat();
		if (!taskstat) {
			MON_ERROR("report %s(%d) dirtycow fail: no memory. "
				  "%s(%d) %s(%d) %s(%d)\n",
				  &req->args + req->cmdlen + 1, req->pid,
				  req->pinfo.task[0].comm, req->pinfo.task[0].pid,
				  req->pinfo.task[1].comm, req->pinfo.task[1].pid,
				  req->pinfo.task[2].comm, req->pinfo.task[2].pid);
			return;
		}
		init_taskstat_common(req, taskstat, 0);
	}

	taskstat->pflags.dirtycow = 1;
	report_privup_post(taskstat, NULL, PRIVUP_DIRTYCOW, &req->event_tv);
}

static void report_dirtypipe(taskreq_t *req)
{
	taskstat_t *taskstat = get_taskstat_nolock(req->pid, PROCESS_GET);

	if (!taskstat) {
		taskstat = get_ptaskstat_from_pinfo(&req->pinfo);
	}
	if (!taskstat) {
		INFO("report_dirtypipe %s(%d) no taskstat, build one\n", &req->args, req->pid);
		taskstat = alloc_taskstat();
		if (!taskstat) {
			MON_ERROR("report %s(%d) dirtypipe fail: no memory. "
				"%s(%d) %s(%d) %s(%d)\n",
				&req->args + req->cmdlen + 1, req->pid,
				req->pinfo.task[0].comm, req->pinfo.task[0].pid,
				req->pinfo.task[1].comm, req->pinfo.task[1].pid,
				req->pinfo.task[2].comm, req->pinfo.task[2].pid);
			return;
		}
		init_taskstat_common(req, taskstat, 0);
	}

	taskstat->pflags.dirtypipe = 1;
	report_privup_post(taskstat, NULL, PRIVUP_DIRTYPIPE, &req->event_tv);
}

static void report_bashkill(taskreq_t *req)
{
	proc_msg_t msg0 = {{0}};
	proc_msg_t *msg = &msg0;
	taskstat_t *taskstat = NULL;
	char *cmd = NULL, *args = NULL, *cwd = NULL;

	if (!req) {
		MON_ERROR("report_bashkill fail, NULL req\n");
		return;
	}
	if (req->pid == 0) {
		MON_ERROR("report_bashkill fail, req->pid 0\n");
		return;
	}
	if (req->pid == getpid()) {
		MON_ERROR("Why sniper try to kill self? skip report_bashkill\n");
		return;
	}

	taskstat = get_taskstat_nolock(req->pid, PROCESS_GET);
	if (!taskstat) {
		MON_ERROR("report_bashkill fail, NULL bash taskstat\n");
		return;
	}

	/* 忽略过滤命令 */
	if (taskstat->flags & TASK_DROP) {
		return;
	}

	msg->event_tv = req->event_tv;
	msg->stop_tv = req->event_tv;

	msg->pid = req->pid;
	/* 对应bash的内嵌命令kill，需要加process_uuid后缀以和bash进程区分 */
	snprintf(msg->uuid, sizeof(msg->uuid), "%s-bashkill", thestring(taskstat->uuid));
	snprintf(msg->cmd, sizeof(msg->cmd), "%s", taskstat->cmd);
	cmd = &req->args;
	args = cmd + req->cmdlen + 1;
	cwd = args + req->argslen + 1;
	snprintf(msg->cmdline, sizeof(msg->cmdline), "%s", args);
	snprintf(msg->cwd, sizeof(msg->cwd), "%s", cwd);

	/* bash内嵌命令kill的父进程用bash */
	msg->ppid = taskstat->pid;
	snprintf(msg->puuid, sizeof(msg->puuid), "%s", taskstat->uuid);
	snprintf(msg->pcmd, sizeof(msg->pcmd), "%s", taskstat->cmd);
	if (taskstat->argslen > 0) {
		snprintf(msg->pcmdline, sizeof(msg->pcmdline), "%s", taskstat->args);
	} else {
		snprintf(msg->pcmdline, sizeof(msg->pcmdline), "%s", taskstat->cmd);
	}

	snprintf(msg->user, sizeof(msg->user), "%s", taskstat->user);

	snprintf(msg->ip, sizeof(msg->ip), "%s", taskstat->ip);

	snprintf(msg->md5, sizeof(msg->md5), "%s", taskstat->md5);
	snprintf(msg->sha256, sizeof(msg->sha256), "%s", taskstat->sha256);

	snprintf(msg->vendor, sizeof(msg->vendor), "%s", taskstat->vendor);
	snprintf(msg->product, sizeof(msg->product), "%s", taskstat->product);
	snprintf(msg->mem, sizeof(msg->mem), "%s", taskstat->mem);
	snprintf(msg->tty, sizeof(msg->tty), "%s", taskstat->tty);

	msg->loglevel = LOG_NORMAL;
	msg->event_id = PROCESS_NORMAL;
	msg->behavior_id = BEHAVIOR_NORMAL;

	//TODO 根据信号和目标进程是否存在，判断是否成功
	msg->result = succstr;

	if (taskstat->session_uuid[0] != 0) {
		memcpy(msg->session_uuid, taskstat->session_uuid, S_UUIDLEN);
	}

	if (taskstat->tty[0] && is_shell(taskstat->args)) {
		msg->pflags.commandline = 1;
	}

	send_process_msg(msg, taskstat, 1);
}

/* 报告非法卸载客户端事件 */
static void report_killsniper(taskreq_t *req)
{
	int bashkill = 0;
	pid_t pgid = 0;
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, user[S_NAMELEN] = {0}, desc[S_LINELEN] = {0};
	char reply[REPLY_MAX] = {0}, *post = NULL;
	char *cmd = NULL, *cmdname = NULL;
	unsigned long event_time = 0;
	struct defence_msg defmsg = {0};

	if (!req) {
		return;
	}

	/* 忽略CentOS5/6上prelink修改/sbin/sniper的动作 */
	//TODO 验证prelink的合法性，如与安装时的md5校验，避免冒充
	cmd = &req->args;
	cmdname = safebasename(cmd);
	if (req->pflags.modifysniper) {
		if (strcmp(cmd, "/usr/sbin/prelink") == 0 || strcmp(cmd, "/sbin/prelink") == 0) {
			INFO("Deny %s modify sniper, but not report event\n", cmd);
			return;
		}
	}

	if (req->pid == getpid()) {
		MON_ERROR("Why sniper try to kill self? just skip\n");
		return;
	}

	uidtoname(req->uid, user);

	event_time = (req->event_tv.tv_sec + serv_timeoff) * 1000 + req->event_tv.tv_usec / 1000;

        get_random_uuid(uuid);
        if (uuid[0] == 0) {
                return;
        }

        object = cJSON_CreateObject();
        if (object == NULL) {
                return;
        }
        arguments = cJSON_CreateObject();
        if (arguments == NULL) {
                cJSON_Delete(object);
                return;
        }

	if (req->pflags.modifysniper) {
		snprintf(desc, sizeof(desc), "%s(%d) modify sniper", cmd, req->pid);
	} else {
		snprintf(desc, sizeof(desc), "%s(%d) kill sniper", cmd, req->pid);
	}

        cJSON_AddStringToObject(object, "id", uuid);
        cJSON_AddStringToObject(object, "log_name", "ClientIllegalUninstall");
        cJSON_AddStringToObject(object, "event_category", "Client");
        cJSON_AddStringToObject(object, "log_category", "Client");
          cJSON_AddBoolToObject(object, "event", true);
        cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
        cJSON_AddNumberToObject(object, "behavior", BEHAVIOR_ABNORMAL);
        cJSON_AddNumberToObject(object, "result", MY_RESULT_FAIL);
        cJSON_AddStringToObject(object, "operating", "Uninstalled");
        cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK);
        cJSON_AddNumberToObject(object, "timestamp", event_time);

        cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
        cJSON_AddStringToObject(object, "ip_address", If_info.ip);
        cJSON_AddStringToObject(object, "mac", If_info.mac);
        cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
        cJSON_AddStringToObject(object, "user", user);
        cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
        cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
        cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

        cJSON_AddStringToObject(object, "policy_id", policy_id_cur);

        cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
        cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
        cJSON_AddStringToObject(arguments, "desc", desc); //说明非法卸载是杀进程还是删改程序

        cJSON_AddItemToObject(object, "arguments", arguments);

        post = cJSON_PrintUnformatted(object);

        client_send_msg(post, reply, sizeof(reply), LOG_URL, "process");

        cJSON_Delete(object);
        free(post);

	/* 发送防御日志 */
	defmsg.event_tv.tv_sec = req->event_tv.tv_sec;
	defmsg.event_tv.tv_usec = req->event_tv.tv_usec;
	defmsg.operation = termstr;
	defmsg.result = OPERATE_OK;

	defmsg.user = user;
	defmsg.log_name = "ClientIllegalUninstall";
	defmsg.log_id = uuid;

	if (strcmp(cmdname, "bash") == 0) {
		bashkill = 1;
		defmsg.object = "kill";
	} else {
		defmsg.object = cmd;
	}

	send_defence_msg(&defmsg, "process");

	/*
	 * 这里不考虑可信名单，因为非法卸载没有可信名单
         *
	 * 终止非法卸载进程
	 * 非终端操作：杀进程
	 * 终端kill命令操作：杀进程（因kill是bash内嵌命令，实际是杀了bash，断开了登录）
	 * 终端非kill命令操作：杀进程组和父进程组（目的也是为了断开登录）
	 */
	if (req->flags & PSR_TTY && !bashkill) {
		pgid = mygetpgid(req->pid);
		if (pgid > 0) { //pgid<=0说明进程已结束
			mykillpg(pgid, SIGKILL);
		}
		pgid = mygetpgid(req->pinfo.task[0].pid);
		if (pgid > 0) {
			mykillpg(pgid, SIGKILL);
		}
	} else {
		mykill(req->pid, SIGKILL);
	}
	INFO("%s %s(%d) illegal stop sniper, kill it\n", user, cmd, req->pid);
}

static void report_disk_write(taskreq_t *req)
{
	taskstat_t *taskstat = NULL;
	proc_msg_t *msg = NULL;
	int wflag = PSR_DISK_WRITE | PSR_WRITE_FORBIDDEN;
	int trust_event_id = 0;
	taskstat_t tmp_taskstat = {0};

	if (!req) {
		MON_ERROR("report_disk_write fail, NULL req\n");
		return;
	}

	taskstat = req2taskstat(req, &tmp_taskstat);
	if (!taskstat) {
		MON_ERROR("report_miner fail, no taskstat\n");
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}

	if (strcmp(taskstat->cmd, "/sbin/fdisk") == 0 ||
	    strcmp(taskstat->cmd, "/sbin/parted") == 0) {
		if (strstr(taskstat->args, " -l")) {
			return;
		}
	}

	/* 不重复报告 */
	if ((taskstat->flags & wflag) == (req->flags & wflag)) {
		return;
	}

	taskstat->flags |= req->flags & wflag;
	msg = build_process_msg(taskstat);

	msg->event_tv = req->event_tv;
	msg->event_id = PROCESS_MBR_PROTECT;

	trust_event_id = is_trust_cmd(taskstat);
	if (trust_event_id & EVENT_MBRAttack) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL;
		msg->loglevel = LOG_LOW_RISK;
		if (prule.mbr_kill) {
			terminate_cmd(msg, taskstat, "disk write", 0);
		}
	}

	if (req->pflags.terminate) {
		msg->terminate = req->pflags.terminate;
		msg->terminate_result = succstr;
	}

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}
#endif

/* 中间件可能会监听多个端口，获取监听的端口列表，端口之间用逗号隔开 */
static void get_middleware_listening_ports(char *ports, pid_t pid, unsigned short port)
{
	int i = 0, len = 0;

	if (!ports) {
		return;
	}
	if (pid == 0) {
		return;
	}

	pthread_rwlock_rdlock(&middleware_lock);
	for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++) {
		if (sniper_mid[i].pid == pid) {
			len = strlen(ports);
			if (len >= S_NAMELEN-4) {
				break;
			}
			snprintf(ports+len, S_NAMELEN-len, "%d,", sniper_mid[i].port);
		}
	}
	pthread_rwlock_unlock(&middleware_lock);

	len = strlen(ports);
	if (len == 0) { //没有取到端口列表的话，用参数port
		snprintf(ports, S_NAMELEN, "%d", port);
	} else if (ports[len-1] == ',') { //消除端口列表最后的逗号
		ports[len-1] = 0;
	}
}

/* 5.0.5(含)之前，报告对外服务进程异常执行日志 */
static void report_webexec_danger(taskreq_t *req)
{
	taskstat_t *taskstat = NULL;
	proc_msg_t *msg = NULL;

	if (!req) {
		return;
	}

	taskstat = get_taskstat_nolock(req->webmid_pid, PROCESS_GET);
	if (!taskstat) {
		MON_ERROR("report_webexec: %s(%d) no middleware(pid %d) ptaskstat\n",
			&req->args, req->pid, req->webmid_pid);
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		MON_ERROR("report_webexec: %s(%d) build ptaskstat %s(%d) msg fail\n",
			&req->args, req->pid, taskstat->args, taskstat->pid);
		return;
	}

	msg->event_tv = req->event_tv;
	if (req->pflags.terminate) {
		msg->terminate = 1;
		msg->result = failstr;
	} else {
		msg->terminate = 0;
		msg->result = succstr;
	}

	msg->event_id = PROCESS_MIDDLE_EXECUTION;
	if (req->trust_events & EVENT_ServiceProcess) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL;
		msg->loglevel = LOG_LOW_RISK;
	}

	snprintf(msg->dangerous_command, sizeof(msg->dangerous_command), "%s", safebasename(&req->args));
	msg->port = req->webmid_port;
	get_middleware_listening_ports(msg->listening_ports, req->webmid_pid, req->webmid_port);

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

/* 5.0.6(含)之后，报告对外服务进程异常执行日志 */
static void report_webexec(taskstat_t *taskstat, taskreq_t *req)
{
	proc_msg_t *msg = NULL;

	if (!taskstat || !req) {
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}

	if (req->pflags.terminate) {
		msg->terminate = 1;
		msg->result = failstr;
	} else {
		msg->terminate = 0;
		msg->result = succstr;
	}

	msg->event_id = PROCESS_MIDDLE_EXECUTION;
	if (req->trust_events & EVENT_ServiceProcess) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL;
		msg->loglevel = LOG_LOW_RISK;
	}

	snprintf(msg->dangerous_command, sizeof(msg->dangerous_command), "%s", safebasename(taskstat->cmd));
	snprintf(msg->middleware, sizeof(msg->middleware), "%s", safebasename(req->target_cmd));
	msg->port = req->webmid_port;
	get_middleware_listening_ports(msg->listening_ports, req->webmid_pid, req->webmid_port);

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

static void report_process(taskstat_t *taskstat, int init_stage, int trust_events)
{
	proc_msg_t *msg = NULL;

	/* 假的0进程不报 */
	if (taskstat->pid == 0) {
		return;
	}

	/* 忽略过滤命令 */
	if (taskstat->flags & TASK_DROP) {
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}

	trust_events |= is_trust_cmd(taskstat);
	choose_process_event(msg, taskstat, init_stage, trust_events);
	
	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

static void report_portforward(taskstat_t *taskstat)
{
	proc_msg_t *msg = NULL;
	int trust_events = 0;

	/* 假的0进程不报 */
	if (taskstat->pid == 0) {
		return;
	}

	/* 忽略过滤命令 */
	if (taskstat->flags & TASK_DROP) {
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}

	trust_events = is_trust_cmd(taskstat);

	msg->event_id = PROCESS_PORT_FORWARD;
	if (trust_events & EVENT_Tunnel) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL; //异常
		msg->loglevel = LOG_MIDDLE_RISK;
		if (prule.port_forward_kill) {
			terminate_cmd(msg, taskstat, "port forward", 0);
		}
	}

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

static void report_remoteshell(taskstat_t *taskstat)
{
	proc_msg_t *msg = NULL;
	int trust_events = 0;

	/* 假的0进程不报 */
	if (taskstat->pid == 0) {
		return;
	}

	/* 忽略过滤命令 */
	if (taskstat->flags & TASK_DROP) {
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}

	/* 事件时间用检测时间，否则在bash下执行exec 5<>/dev/udp/1.2.3.4/4444，
	   事件时间取bash的启动时间的话，这个时间较早，可能会比较难以理解 */
	gettimeofday(&msg->event_tv, NULL);

	trust_events = is_trust_cmd(taskstat);

	msg->event_id = PROCESS_REMOTE_EXECUTION;
	if (trust_events & EVENT_ReverseShell) {
		msg->behavior_id = BEHAVIOR_NORMAL;
		msg->loglevel = LOG_NORMAL;
	} else {
		msg->behavior_id = BEHAVIOR_ABNORMAL; //异常
		msg->loglevel = LOG_HIGH_RISK;
		if (prule.remote_execute_kill) {
			terminate_cmd(msg, taskstat, "reverse shell", 0);
			if (prule.remote_execute_lockip) {
				msg->blockip = 1;
			}
		}
	}

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

static void report_black(taskstat_t *taskstat)
{
	proc_msg_t *msg = NULL;

	/* 假的0进程不报 */
	if (taskstat->pid == 0) {
		return;
	}

	msg = build_process_msg(taskstat);
	if (!msg) {
		return;
	}

	/* 事件时间用检测时间，对于设黑名单来终止一个已经存在的进程的操作，
	   事件时间取进程的启动时间的话，这个时间较早，可能会比较难以理解 */
	gettimeofday(&msg->event_tv, NULL);

	msg->event_id = PROCESS_VIOLATION;
	msg->behavior_id = BEHAVIOR_VIOLATION; //违规
	msg->loglevel = LOG_HIGH_RISK;
	if (prule.black_kill) {
		terminate_cmd(msg, taskstat, "violation command", 0);
	}

	send_process_msg(msg, taskstat, 1);
	sniper_free(msg, sizeof(proc_msg_t), PROCESS_GET);
}

/* 检测当前进程命中的事件，及根据当前最新策略进行处理。目前只针对端口转发、反弹shell、黑名单 */
static void check_process_event(void)
{
	int ret = 0;
	DIR *procdirp = NULL;
	struct dirent *pident = NULL;

	if (!prule.remote_execute_on) {
		return;
	}
	if (!tasklist) {
		return;
	}

	procdirp = sniper_opendir("/proc", PROCESS_GET);
	if (!procdirp) {
                MON_ERROR("check_remoteshell: open /proc fail: %s\n", strerror(errno));
		return;
	}

	/*
	 * 遍历/proc获得当前进程信息
	 */
	while ((pident = readdir(procdirp))) {
		int pid = 0, trust_event_id = 0, newtask = 0, newexec = 0;
		int idx = 0, sniper_child = 0, i = 0;
		taskstat_t *taskstat = NULL, *new_taskstat = NULL;

		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue; //忽略非进程项信息
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

		newtask = 0;
		taskstat = get_taskstat_nolock(pid, PROCESS_GET);
		if (!taskstat) {
			taskstat = init_one_process(pid);
			if (!taskstat) {
				continue; //init失败视为进程已结束
			}
			newtask = 1;
		} else {
			char cmd[S_CMDLEN] = {0};
			struct stat st1 = {0}, st2 = {0};

			if (get_proc_exe(pid, cmd) < 0) {
				continue; //取不到视为进程已结束
			}
			stat(taskstat->cmd, &st1);
			stat(cmd, &st2);
			/* 如果进程命令改变了，重新初始化。链接视为同一个命令 */
			if (st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino) {
				new_taskstat = init_one_process(pid);
				if (!new_taskstat) {
					continue; //init失败视为进程已结束
				}
				newtask = 1;
				newexec = 1;
				INFO("process %s(%x, %lu)(%d, %s) changed to %s(%x, %lu)(%d, %s), reinit taskstat\n",
					taskstat->cmd, st1.st_dev, st1.st_ino, taskstat->pid, taskstat->args,
					new_taskstat->cmd, st2.st_dev, st2.st_ino, new_taskstat->pid, new_taskstat->args);

				/* 将老的taskstat从tasklist里摘掉 */
				idx = taskstat->pid % TASKMAX;
				pthread_rwlock_wrlock(&tasklist[idx].lock);
				list_del(&taskstat->list);
				pthread_rwlock_unlock(&tasklist[idx].lock);

				/* 将老的taskstat作为新的taskstat的ptaskstat */
				new_taskstat->exec_ptaskstat = taskstat;

				/* 新taskstat的exec_times加一 */
				new_taskstat->exec_times = taskstat->exec_times + 1;

				/* 设置新taskstat的uuid */
				set_taskuuid(new_taskstat->uuid, taskstat->proctime, taskstat->pid, new_taskstat->exec_times);

				/* 报告老的taskstat已结束 */
				report_taskexit(taskstat);

				taskstat = new_taskstat;
			}
		}

		/* sniper及其子进程不检查事件 */
		if (pid == sniper_pid) {
			continue;
		}
		sniper_child = 0;
		for (i = 0; i < SNIPER_PGEN; i++) {
			/* 没有父进程可找了 */
			if (taskstat->pinfo.task[i].pid == 0) {
				break;
			}
			/* 父进程是sniper */
			if (taskstat->pinfo.task[i].pid == sniper_pid) {
				sniper_child = 1;
				break;
			}
		}
		if (sniper_child) {
			continue;
		}

		if (prule.remote_execute_on) {
			if (taskstat->flags & TASK_REMOTE_EXECUTE) {
				/* 不阻断反弹shell的话，不重复报警 */
				if (!prule.remote_execute_kill || client_mode_global) {
					/* 如果标志是上面init_one_process设的，之前没处理过，不能够忽略 */
					if (!newtask) {
						continue;
					}
				}
				/* 信任的进程，不重复报警 */
				trust_event_id = is_trust_cmd(taskstat);
				if (trust_event_id & EVENT_ReverseShell) {
					continue;
				}

				report_remoteshell(taskstat);
				continue;
			}

			ret = is_remoteshell(taskstat);
			if (ret > 0) {
				if (is_filter_cmd(taskstat)) {
					continue;
				}

				if (ret == 3) {
					taskstat->flags |= TASK_MAY_REMOTE_EXECUTE;
				} else {
					taskstat->flags |= TASK_REMOTE_EXECUTE;
					report_remoteshell(taskstat);
				}
				continue;
			}
		}

		if (prule.port_forward_on) {
			if (taskstat->flags & TASK_PORT_FORWARD) {
				/* 不阻断端口转发的话，不重复报警 */
				if (!prule.port_forward_kill || client_mode_global) {
					/* 如果标志是上面init_one_process设的，之前没处理过，不能够忽略 */
					if (!newtask) {
						continue;
					}
				}
				/* 信任的进程，不重复报警 */
				trust_event_id = is_trust_cmd(taskstat);
				if (trust_event_id & EVENT_Tunnel) {
					continue;
				}

				report_portforward(taskstat);
				continue;
			}
			if (is_port_forward(taskstat, 0) && !is_filter_cmd(taskstat)) {
				taskstat->flags |= TASK_PORT_FORWARD;
				report_portforward(taskstat);
				continue;
			}
		}

		if (is_black_cmd(taskstat)) { //is_black_cmd()里会忽略学习和运维模式
			taskstat->flags |= TASK_BLACK;
			report_black(taskstat);
			continue;
		}

		/* 未命中以上事件，单独报告一下新检测到的进程 */
		/* 新fork的进程不报告，避免太多，只报告新做了exec的 */
		if (newexec) {
			INFO("report new process %s(%d, %s)\n", taskstat->cmd, taskstat->pid, taskstat->args); 
			report_process(taskstat, 0, 0);
		}
	}

	sniper_closedir(procdirp, PROCESS_GET);
}

//TODO 和老的标志比较。嵌套检查父进程。父进程加引用计数，所有子进程退出了，才释放父进程数据结构
void check_tasklist_event(void)
{
	int i = 0;
	taskstat_t *taskstat = NULL;

	if (!tasklist) {
		INFO("Warning: no tasklist, skip check tasklist, "
			"process monitor may off\n");
		return;
	}

//TODO //放开会更新不了策略？
return;
	for (i = 0; i < TASKMAX; i++) {
		pthread_rwlock_rdlock(&tasklist[i].lock);
		list_for_each_entry(taskstat, &tasklist[i].queue, list) {
			/* 已经结束的进程不重新检查事件 */
			if (taskstat->stop_tv.tv_sec != 0) {
				continue;
			}

			set_taskstat_flags(taskstat, the_ptaskstat(taskstat));
			report_process(taskstat, 1, 0);

			/* 检查当前进程，是否已有提权 */
			check_privup_init(taskstat);
		}
		pthread_rwlock_unlock(&tasklist[i].lock);
	}
	INFO("tasklist rechecked\n");
}

static int tasklist_need_report = 1;
void report_initps(void)
{
	int i = 0;
	taskstat_t *taskstat = NULL;

	if (!tasklist) {
		INFO("Warning: no tasklist, skip report init tasklist, "
			"process monitor may off\n");
		return;
	}

	for (i = 0; i < TASKMAX; i++) {
		pthread_rwlock_rdlock(&tasklist[i].lock);
		list_for_each_entry(taskstat, &tasklist[i].queue, list) {
			report_process(taskstat, 1, 0);

			/* 检查当前进程，是否已有提权 */
			check_privup_init(taskstat);
		}
		pthread_rwlock_unlock(&tasklist[i].lock);
	}
	INFO("tasklist reported\n");
}

static int is_printer_cmd(char *cmd)
{
	if (cmd) {
		if (strcmp(cmd, "/usr/bin/lp") == 0 ||
		    strcmp(cmd, "/usr/bin/lpr") == 0 ||
		    strcmp(cmd, "/bin/lp") == 0 ||
		    strcmp(cmd, "/bin/lpr") == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * process exec monitor thread
 */
void *process_monitor(void *ptr)
{
	int ret = 0;
	pid_t ppid = 0;
	taskstat_t *taskstat = NULL, *ptaskstat = NULL;
#if 0
	taskreq_t *req = NULL;
#else
	struct ebpf_taskreq_t *req = NULL;
#endif
	kexec_msg_t *exec_msg = NULL;
	int last_process_check_status = 1;
	time_t now = 0, last_check_time = 0;

	prctl(PR_SET_NAME, "process_monitor");
	save_thread_pid("process", SNIPER_THREAD_PROCESS);

	/* 如果还没注册上，等注册后再报告当前进程列表 */
	if (client_registered) {
		report_initps();
		tasklist_need_report = 0;
	}
	process_inited = 1;
	// printf("process_monitor thread starting...Online=%d\r\n",Online);

	while (Online) {
		if (exec_msg) {
			sniper_free(exec_msg->data, exec_msg->datalen, PROCESS_GET);
			sniper_free(exec_msg, sizeof(struct kexec_msg), PROCESS_GET);
		}

		/* 检查待转储的日志文件 */
		check_log_to_send("process");

		/* 如果停止防护，什么也不做 */
		if (sniper_process_loadoff == TURN_MY_ON) {
			/* get_kexec_msg里不睡眠，所以此处要睡1秒，否则会显示CPU一直忙 */
			sleep(1);
			exec_msg = (kexec_msg_t *)get_kexec_msg();
			continue;
		}

		/* 如果过期了/停止客户端工作，则什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			close_kernel_process_rules();

			sleep(STOP_WAIT_TIME);

			/* 扔掉msg queue中的数据 */
			while(1) {
				exec_msg = (kexec_msg_t *)get_kexec_msg();
				if (!exec_msg) {
					break;
				}

				sniper_free(exec_msg->data, exec_msg->datalen, PROCESS_GET);
				sniper_free(exec_msg, sizeof(struct kexec_msg), PROCESS_GET);
			}

			continue;
		}

		/* 如果功能关闭，什么也不做 */
		if (!prule.process_engine_on) {
			if (last_process_check_status) {
                        	INFO("Turn process engine off\n");
				fini_psbuf(1);
                        	last_process_check_status = 0;
							// printf("last_process_check_status=%d\r\n",last_process_check_status);
			}
			sleep(1);
			continue;
		}

		/* 如果功能重新打开，更新当前tasklist */
		if (!last_process_check_status) {
			INFO("Turn process engine on. renew tasklist\n");
			init_psbuf();
			INFO("tasklist renewed\n");
			last_process_check_status = 1;
			tasklist_need_report = 1;
		}
		if (tasklist_need_report && client_registered && !Heartbeat_fail) {
			report_initps();
			tasklist_need_report = 0;
		}

		exec_msg = (kexec_msg_t *)get_kexec_msg();
		if (!exec_msg) {
			now = time(NULL);
			if (now < last_check_time) {
				last_check_time = now;
			}
			/* 1分钟遍历一次已经结束的进程 */
			if (now >= last_check_time + 60) {
				check_exit_process();
				check_process_event();
				last_check_time = now;
			}

			sleep(1);
			continue;
		}
#if 0
		req = (taskreq_t *)exec_msg->data;
#else

		req = (struct ebpf_taskreq_t *) exec_msg->data;
		// printf("=== process.c ===\n");
		// printf("EXEC process: %s(%d), nodename: %s(%u)\n", req->cmd, req->pid, req->nodename, req->mnt_id);
		// printf("EXEC parent: %s(%d)\n", req->pinfo.task[0].comm, req->ppid);
		// printf("EXEC cwd: %s\n", req->cwd);
		// printf("EXEC tty: %s\n", req->tty);
		// printf("EXEC argc: %d\n", req->argc);
		// for (int i = 0; i < (req->argc > 2 ? 2 : req->argc) ; i++) {
		// 	printf("EXEC arg%d: %s\n", i, req->args[i]);
		// }
		// printf("====================\n");
#endif
		if (!req) {
			continue;
		}

#if 0
		// ppid = req->pinfo.task[0].pid;
		// ptaskstat = get_taskstat_nolock(ppid, PROCESS_GET);
		// if (ptaskstat && ptaskstat->flags & TASK_MAY_REMOTE_EXECUTE) {
		// 	INFO("%s exec %s, look it as remote shell\n", ptaskstat->args, taskstat->args);
		// 	ptaskstat->flags &= ~TASK_MAY_REMOTE_EXECUTE;
		// 	ptaskstat->flags |= TASK_REMOTE_EXECUTE;
		// 	report_process(ptaskstat, 0, 0);
		// }

		// if (req->pflags.privup) {
		// 	report_privup(req);
		// 	continue;
		// }

		// if (req->pflags.dirtycow) {
		// 	report_dirtycow(req);
		// 	continue;
		// }

		// if (req->pflags.dirtypipe) {
		// 	report_dirtypipe(req);
		// 	continue;
		// }

		//TODO 非法卸载还需要更多检测
		//可信是不可能的，因为可信事件没有针对非法卸载的
		//过滤名单呢？不杀进程，不报告事件？
		// if (req->pflags.killsniper) {
		// 	if (!is_halting()) {
		// 		report_killsniper(req);
		// 	} else {
		// 		INFO("skip report %s(%d) try kill sniper\n",
		// 			&req->args, req->pid);
		// 	}
		// 	continue;
		// }

		// if (req->pflags.kill) {
		// 	report_bashkill(req);
		// 	continue;
		// }

		// //TODO 可信和过滤
		// if (req->pflags.writedisk) {
		// 	report_disk_write(req);
		// 	continue;
		// }

		// if (req->pflags.minepool) {
		// 	report_minepool_access(req);
		// 	continue;
		// }
		// if (req->pflags.miner) {
		// 	report_miner(req);
		// 	continue;
		// }

		/*
		 * 5.0.5(含)之前，对外服务进程异常执行日志采用老的约定，报告的进程主体是对外服务进程
		 * 5.0.6(含)之后，报告的进程主体是对外服务进程执行的命令
		 * 5.0.5(含)之前，server_version是5.0；5.0.6(含)之后，server_version是5.0.n
		 */
		// if (req->pflags.webexec_danger && strcmp(server_version, "5.0") == 0) {
		// 	/* 报告对外服务进程执行了什么可疑命令 */
		// 	report_webexec_danger(req);

		// 	/* 被执行的可疑命令按一般进程报 */
		// 	req->pflags.webexec_danger = 0;
		// 	req->pflags.terminate = 0;
		// 	req->flags &= ~(PSR_WEBEXECUTE_DANGER|PSR_STOPED);
		// }
#else
#endif

#if 0
		// taskstat = set_taskstat_exec(req);
		if (!taskstat) {
			continue;
		}
		taskstat->repeat = exec_msg->repeat;
#else
// TODO(luoyinhong)
		taskstat = set_taskstat_exec(req);
		if (!taskstat) {
			continue;
		}
		taskstat->repeat = exec_msg->repeat;
		// taskstat->flags = 0;
#endif

		if (is_port_forward(taskstat, 0)) {
			taskstat->flags |= TASK_PORT_FORWARD;
		}

#if 0
		if (req->pflags.docker) {
			taskstat->flags |= TASK_DOCKER;
		}

		if (is_printer_cmd(taskstat->cmd) &&
		    fasten_policy_global.device.printer.enable &&
		    fasten_policy_global.device.printer.terminate) {
			printer_terminate_post_data(taskstat);
		}

		//TODO 过滤对多级exec的影响，之前报过就报结束？
		//前置exec如果在内核被过滤掉，对后继的exec是否有影响
		/* 如果是多级exec，先报告上一条命令结束 */
		if (taskstat->exec_ptaskstat) {
			report_taskexit(taskstat->exec_ptaskstat);
		}

		/* 5.0.6(含)之后，这里报告对外服务进程异常执行日志 */
		if (req->pflags.webexec_danger) {
			report_webexec(taskstat, req);
			continue;
		}

		/* 被阻断命令的事件已经确定 */
		if (req->flags & PSR_STOPED) {
			report_process(taskstat, 0, 0);
			continue;
		}

		/* docker内的进程暂不检查事件 */
		if (req->pflags.docker) {
			report_process(taskstat, 0, 0);
			continue;
		}

		ret = is_remoteshell(taskstat);
		if (ret > 0) {
			if (ret == 3) {
				taskstat->flags |= TASK_MAY_REMOTE_EXECUTE;
			} else {
				taskstat->flags |= TASK_REMOTE_EXECUTE;
			}
		}
		if (is_port_forward(taskstat, 0)) {
			taskstat->flags |= TASK_PORT_FORWARD;
		}

		/* 异常的shell：带终端、存在的、属主是不可登录的用户 */
		if (prule.abnormal_on && taskstat->pflags.shell && taskstat->tty[0] &&
		    taskstat->stop_tv.tv_sec == 0 && !(taskstat->flags & TASK_REMOTE_EXECUTE)) {
			INFO("%s(%d, %s) is a shell, user %s/%d, tty %s\n",
			     taskstat->cmd, taskstat->pid, taskstat->args,
			     taskstat->user, taskstat->uid, taskstat->tty);
			if (!can_login(taskstat->uid)) {
				INFO("%s(%d) user(%s/%d) cannot login, is an abnormal shell\n",
				     taskstat->args, taskstat->pid, taskstat->user, taskstat->uid);
				taskstat->flags |= TASK_ABNORMAL;
				taskstat->pflags.shell_nologinuser = 1;
			}
		}

		if (taskstat->flags & TASK_BLACK) {
			/* 违规进程不过滤 */
			taskstat->flags &= ~TASK_DROP;
		}
#else
		if (is_danger_cmd(taskstat->args)) {
			taskstat->flags |= TASK_DANGER;
			printf("danger taskstat %s: %s\ncwd: %s\n", taskstat->cmd, taskstat->args, taskstat->cwd);
		}
		if (is_chopper_cmd(taskstat->args)) {
			taskstat->flags |= TASK_WEBSHELL;
			printf("chopper taskstat %s: %s\ncwd: %s\n", taskstat->cmd, taskstat->args, taskstat->cwd);
		}
#endif
		set_taskstat_flags(taskstat, the_ptaskstat(taskstat));

		check_privup_exec(taskstat);

#if 0
		//TODO 先过滤。check_privup_exec合并到report_process里？
		report_process(taskstat, 0, req->trust_events);
#else

		report_process(taskstat, 0, 0);
#endif

		/* 检查提权起shell */
		// if (taskstat->pflags.shell && prule.privilege_on && taskstat->stop_tv.tv_sec == 0) {
		// 	check_privup_shell(taskstat, 0);
		// }
	}

	INFO("process thread exit\n");
	return NULL;
}
