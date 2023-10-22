/* 进程防杀（包括关机和重启时）。sniper不被杀掉并不影响关机或重启 */

#include "interface.h"

static void report_kill(pid_t pid, int signum, int killsniper)
{
	char *cmd = NULL, *args = NULL, *cwd = NULL;
	int len = 0;
	taskreq_t *req = NULL;

	req = init_taskreq(INIT_WITH_PINFO|INIT_WITH_CMD);
	if (NULL == req) {
		return;
	}

	if (killsniper) {
		req->flags |= PSR_KILLSNIPER;
		req->pflags.killsniper = 1;
	} else {
		req->pflags.kill = 1;
	}

	cmd = &req->args;

	args = cmd + req->cmdlen + 1;
	snprintf(args, S_ARGSLEN, "kill -%d %d", signum, pid);
	len = strlen(args);
	args[len] = 0;
	req->argslen = len;

	cwd = args + req->argslen + 1;
	cwd[0] = '/';
	cwd[1] = 0;
	req->cwdlen = 1;

	if (killsniper) {
		myprintk("forbid %s(%d) from stopping sniper. "
			 "uid: %d, tty %s, cwd %s. %s(%d) %s(%d) %s(%d)\n",
			 current->comm, current->pid, req->uid, req->tty, cwd,
			 req->pinfo.task[0].comm, req->pinfo.task[0].pid,
			 req->pinfo.task[1].comm, req->pinfo.task[1].pid,
			 req->pinfo.task[2].comm, req->pinfo.task[2].pid);
	}

	if (is_filter_cmd(req, NULL)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;
        send_data_to_user((char *)req, req->size, nl_exec_pid, Probe_kill);

	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
}

/*
 * bash下做kill动作，是没有独立命令的。kill是bash的内嵌命令，是调用kill()接口实现的
 * 为了还原出bash下做的kill动作，这里针对当前进程是bash进程的情况特别处理
 */
static void check_bashkill(pid_t pid, int signum)
{
	if (!process_engine_status()) { //不监控进程
		return;
	}

	if (strcmp(current->comm, "bash") == 0 || strcmp(current->comm, "sh") == 0) {
		/* 遇到SIGTTIN信号会在后面my_get_mm_exe_file时core */
		if (signum == SIGTTIN || signum == SIGTTOU) {
			return;
		}

		mypdebug("%s(%d) kill -%d %d\n", current->comm, current->pid, signum, pid);
		return report_kill(pid, signum, 0);
	}
}

static int my_task_kill(struct task_struct *p, int sig)
{
	/*
	 * centos5会在时钟中断里调用本函数，导致死机
	 * my_get_mm_exe_file()产生scheduling while atomic
	 * 忽略中断态，本来中断里进程信息也是不准确的
	 */
	if (in_interrupt()) {
		return 0;
	}

	/*
	 * 忽略内核发的信号，如定时信号
	 * swapper/0 kill -14 Xorg/3425
	 * 
	 * 忽略进程发给自己的信号，如
	 * bash/22849 kill -18 22849
	 *   SIGCHLD, Child stopped or terminated
	 * 
	 * bash/3449  kill -9 bash/16546
	 * bash/16546 kill -1 bash/16546
	 *   SIGHUP, Hangup detected on controlling terminal or death of controlling process
	 *   在一个bash窗口中kill另一个bash窗口，被kill的bash进程会给自己发SIGHUP
	 */
	if (current->pid == 0 || current->pid == p->pid) {
		return 0;
	}

	/* 报告bash命令kill非sniper进程 */
	if (p->group_leader->pid != sniper_pid) {
		check_bashkill(p->pid, sig);
		return 0;
	}

	/*
	 * 没有sniper进程
	 * 之所以在这里判断，而不是更前，目的是方便调试，
	 * 使得仅加载sniper_edr模块时，可以捕获bash内嵌命令kill的动作
	 */
	if (sniper_pid == 0) {
		return 0;
	}

	/* 报告bash命令kill向sniper发非结束信号 */
	if (sig != SIGKILL && sig != SIGSTOP && sig != SIGTERM) {
		check_bashkill(p->pid, sig);
		return 0;
	}

	if (current->group_leader->pid == sniper_pid) {
		myprintk("Why sniper try to kill self? just skip\n");
		return 0;
	}

	/*
	 * 没有捕捉到关机或重起时，1号进程结束sniper，可能此时已无法打印
	 * 但捕捉到下面的场景，登进centos8桌面，安装sniper后退出桌面，sniper进程被1号进程杀死
	 * 并报告systemd[1]: user@1000.service: Killing process 229385 (sniper) with signal SIGKILL.
	 * 鉴于此，也禁止1号进程杀sniper，但不报非法卸载
	 */
	if (current->pid != 1) {
		report_kill(p->pid, sig, 1);
		return -1;
	}

	myprintk("%s(1) send signal %d to sniper, ignore\n", current->comm, sig);
	return -1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
/* lsm 1.0 hook */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
int sniper_task_kill(struct task_struct *p, struct siginfo *info, int sig)
#else
int sniper_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid)
#endif
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_KILL]);

	ret = my_task_kill(p, sig);
	if (ret < 0) {
		atomic_dec(&sniper_usage[SNIPER_KILL]);
		return ret;
	}

	if (original_task_kill) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		ret = original_task_kill(p, info, sig);
#else
		ret = original_task_kill(p, info, sig, secid);
#endif
	}

	atomic_dec(&sniper_usage[SNIPER_KILL]);

	return ret;
}
#else
/* lsm 2.0 hook */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
int sniper_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid)
#else
int sniper_task_kill(struct task_struct *p, sniper_siginfo_t *info, int sig, const struct cred *cred)
#endif
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_KILL]);

	ret = my_task_kill(p, sig);

	atomic_dec(&sniper_usage[SNIPER_KILL]);

	return ret;
}
#endif
