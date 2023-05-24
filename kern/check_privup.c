#include "interface.h"

/* 目前只检测uid/gid提到root，不检测capable提升 */
/*
 * 目前的检测方法，对于提权后先fork子进程，然后子进程干坏事儿的情况失效，
 * 当前只在打开文件和执行程序的时刻做检查，fork不检查。fork出的子进程因为父进程是root也逃避了检查
 * 先容忍这个缺陷，为了完美可能会很复杂或开销增大，实践中看看有没有必要再完善
 */

/* 缓存最近64个提权的进程，避免重复报告提权，比如提权进程访问多个文件，只报第一次 */
static DEFINE_SPINLOCK(privup_lock);
#define MAX_PRIVUP 64
struct privup_proc {
	int flag;  //提权标志：提权执行命令，提权访问文件
	pid_t pid; //提权进程pid
	unsigned long proctime;  //提权进程的启动时间
	unsigned long jiffies;   //提权时刻，用来时间排序，淘汰最老的缓存结果
};
static struct privup_proc privup_process[MAX_PRIVUP] = {{0}};

/*
 * 检查SUID提权程序是否在系统目录下
 * 返回值：-1，错误；
 *         PRIVUP_SUID，系统路径下的suid程序；
 *         PRIVUP_NOTSYSSUID，非系统路径下的suid程序
 */
static int check_suid_exepath(struct file *exe_file)
{
	char *pathname = NULL, buf[64] = {0};

	/* 因为系统路径都很短，程序路径取前63个字符就足够判断了，不需要取全路径名 */
	pathname = get_exe_file_path(exe_file, buf, 64);
	if (sniper_badptr(pathname)) {
		return -1;
	}

	/* 罗列了一些系统路径如下，后面有缺的再补上 */
	if (strncmp(pathname, "/bin/", 5) == 0 ||
	    strncmp(pathname, "/usr/bin/", 9) == 0 ||
	    strncmp(pathname, "/sbin/", 6) == 0 ||
	    strncmp(pathname, "/usr/sbin/", 10) == 0 ||
	    strncmp(pathname, "/lib/", 5) == 0 ||
	    strncmp(pathname, "/lib64/", 7) == 0 ||
	    strncmp(pathname, "/usr/lib/", 9) == 0 ||
	    strncmp(pathname, "/usr/lib64/", 11) == 0 ||
	    strncmp(pathname, "/usr/libexec/", 13) == 0) {
		return PRIVUP_SUID;
	}

	return PRIVUP_NOTSYSSUID;
}

/*
 * 检查进程执行的是否为suid程序
 * 返回值： -1，错误；
 *          PRIVUP_SUID，suid程序；
 *          PRIVUP_NOTSYSSUID，系统路径下的suid程序：
 *          PRIVUP_NOTSUID，非suid程序
 */
/* 测试过，启动程序后删除程序，仍然能够获得exe_file的信息，但不能算md5 */
static int check_suid_exe(struct mm_struct *mm, uid_t *exeuid)
{
	struct file *exe_file = NULL;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;

	if (sniper_badptr(mm)) {
		return -1;
	}

	exe_file = my_get_mm_exe_file(mm); //用完要put
	if (sniper_badptr(exe_file)) {
		myprintk("check_suid_exe fail, bad %s(%d) exe_file %p\n", current->comm, current->pid, exe_file);
		return -1;
	}

	*exeuid = fileuid(exe_file); //获取执行程序时的uid

	dentry = exe_file->f_dentry;
	if (sniper_badptr(dentry)) {
		myprintk("check_suid_exe fail, bad %s(%d) exe_file dentry %p\n", current->comm, current->pid, dentry);
		fput(exe_file);
		return -1;
	}

	inode = dentry->d_inode;
	if (sniper_badptr(inode)) {
		myprintk("check_suid_exe fail, bad %s(%d) exe_file inode %p\n", current->comm, current->pid, inode);
		fput(exe_file);
		return -1;
	}

	/* SUID的提权视为合法提权，但要报告 */
	if (inode->i_mode & S_ISUID) {
		if (check_suid_exepath(exe_file) == PRIVUP_NOTSYSSUID) {
			fput(exe_file);
			return PRIVUP_NOTSYSSUID; //非系统路径的suid程序
		}
		fput(exe_file);
		return PRIVUP_SUID; //suid程序，且是系统路径下的suid程序
	}

	fput(exe_file);
	return PRIVUP_NOTSUID; //非suid程序
}

static int check_parent_suid_exe(pid_t pid, pid_t *ppid, uid_t *exeuid)
{
	int i = 0, ret = 0;
	struct task_struct *task = NULL, *parent = NULL;
	struct mm_struct *mm = NULL;

	parent = get_parent(current);
	if (!parent) {
		return 0;
	}

	task = parent;
	for (i = 0; i < SNIPER_PGEN; i++) {
		if (task->pid == 0) {
			my_put_task_struct(task);
			return 0;
		}

		if (task->pid == pid) {
			mm = get_task_mm(task);
			if (!mm) {
				my_put_task_struct(task);
				return 0;
			}
			ret = check_suid_exe(mm, exeuid);

			*exeuid = 0;
			parent = get_parent(task);
			my_put_task_struct(task);
			mmput(mm);

			if (parent) {
				*ppid = parent->pid;
				mm = get_task_mm(parent);
				if (mm) {
					check_suid_exe(mm, exeuid);
					my_put_task_struct(parent);
					mmput(mm);
				} else {
					my_put_task_struct(parent);
				}
			}
			return ret;
		}

		parent = get_parent(task);

		my_put_task_struct(task);

		if (!parent) {
			return 0;
		}
		task = parent;
	}

	my_put_task_struct(task);
	return 0;
}

/*
 * 检测是否存在提权，并返回提权进程的进程号
 * 提权不一定是本进程提权，也可能是祖先进程提权
 * 缓存提权进程信息，重复提权（pid相同，optype相同）不报告
 * 返回值：0，未提权
 *         pid，提权进程的进程号
 * 参数：pinfo， 祖先进程信息
 *       optype，提权行为：提权执行命令，提权访问文件
 *       olduid，保存提权前的uid
 */
static int is_privup(struct parent_info *pinfo, int optype, uid_t *olduid)
{
	int raise = 0, i = 0, oldest = 0;
	pid_t pid = 0;
	unsigned long proctime = 0;
	unsigned long last_used_time = 0;
	struct privup_proc *ptr = 0;
	char *comm = NULL;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	char *hostname = NULL, *nodename = NULL;
#endif

	/* 300以下的进程都不是用户进程，忽略 */
	if (current->pid < RESERVED_PIDS) {
		return 0;
	}

	if (currenteuid() != 0) { //本进程不是root权限
		return 0;
	}

	if (pinfo->task[0].pid == 0) { //未取到父进程信息
		return 0;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	/* 对docker里的命令暂不检查事件 */
	hostname = init_utsname()->nodename;
	nodename = utsname()->nodename;
	if (strcmp(nodename, hostname) != 0) {
		return 0; 
	}
#endif

	if (pinfo->task[0].euid != 0) {
		/* 本进程是root，父进程不是root，本进程是提权进程 */
		raise = 1;
		comm = current->comm;
		pid = current->pid;
		*olduid = pinfo->task[0].euid;
		proctime = get_process_time(current);
	} else {
		//TODO 为什么只关注fork出来的进程呢？
		/* 本进程是fork出来的，检查父进程是否系提权 */
		if (current->flags & PF_FORKNOEXEC) {
			for (i = 1; i < SNIPER_PGEN; i++) {
				if (pinfo->task[i].pid == 0) {
					break;
				}

				/* 上级父进程不是root，说明父进程有提权 */
				if (pinfo->task[i].euid != 0) {
					raise = 1;
					comm = pinfo->task[i-1].comm;
					pid = pinfo->task[i-1].pid;
					proctime = pinfo->task[i-1].proctime;
					*olduid = pinfo->task[i].euid;
					break;
				}

				/* 父进程如果也是fork出来的，继续检查上级父进程是否系提权 */

				/* 父进程如果不是fork出来的，结束检查 */
				if (pinfo->task[i-1].did_exec) {
					break;
				}
			}
		}
	}

	if (!raise) { //无提权
		return 0;
	}

	spin_lock(&privup_lock);

	/* 提权进程不重复报告 */
	for (i = 0; i < MAX_PRIVUP; i++) {
		ptr = &(privup_process[i]);
		if (ptr->pid == 0) {
			ptr->flag = optype;
			ptr->pid = pid;
			ptr->proctime = proctime;
			ptr->jiffies = jiffies;
			spin_unlock(&privup_lock);
			return pid;
		}

		if (ptr->pid == pid) {
			ptr->jiffies = jiffies;

			/* 同一个进程的同类提权不重复报告 */
			if (ptr->proctime == proctime) {
				if (ptr->flag & optype) {
					spin_unlock(&privup_lock);
					return 0;
				}

				ptr->flag |= optype;
				spin_unlock(&privup_lock);
				return pid;
			}

			/* 不是同一个进程，pid重用了，用新进程信息替换老进程信息 */
			ptr->flag = optype;
			ptr->proctime = proctime;
			spin_unlock(&privup_lock);
			return pid;
		}

		if (last_used_time == 0) {
			last_used_time = ptr->jiffies;
			oldest = i;
			continue;
		}

		if (last_used_time > ptr->jiffies) {
			last_used_time = ptr->jiffies;
			oldest = i;
		}
	}

	/* 替换掉最老的privup_process[] */
	ptr = &(privup_process[oldest]);
	ptr->flag = optype;
	ptr->pid = pid;
	ptr->proctime = proctime;
	ptr->jiffies = jiffies;

	spin_unlock(&privup_lock);
	return pid;
}

/* restoreuid会core。参考setuid()，commit_creds(new)前还需要set_user(new), fix_cred(new, old)
   restoreuid实现较复杂，目前先采用在report_privup时杀进程的方式阻断 */
#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
static void restoreuid(uid_t uid)
{
	current->uid = uid;
	current->euid = uid;
	current->suid = uid;
	current->fsuid = uid;
}
#else
static void restoreuid(uid_t uid)
{
	struct cred *new;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	struct user_namespace *ns = current_user_ns();
	kuid_t kuid;
#endif

	new = prepare_creds();
	if (!new) {
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	new->uid = uid;
	new->euid = uid;
	new->suid = uid;
	new->fsuid = uid;
#else
	kuid = make_kuid(ns, uid);

	new->uid = kuid;
	new->euid = kuid;
	new->suid = kuid;
	new->fsuid = kuid;
#endif

	commit_creds(new);
}
#endif
#endif

/* 拷贝提权后执行的命令名，使得报告日志时可报告提权执行了什么命令 */
static void copy_target(char *buf, char *target)
{
	char *ptr = NULL, *str = NULL;

	if (sniper_badptr(buf) || sniper_badptr(target)) {
		return;
	}

	ptr = strchr(target, ' ');
	if (!ptr) { //没有命令行参数
		snprintf(buf, S_COMMLEN, "%s", safebasename(target));
		return;
	}

	*ptr = 0;
	str = safebasename(target);
	snprintf(buf, S_COMMLEN, "%s", str);
	*ptr = ' ';
}

/* 提权进程是当前进程的祖先进程，从当前进程的祖先信息中，选取出提权进程的祖先进程信息 */
/* 对外服务进程异常执行命令，也需要做类似的操作 */
void copy_pinfo(taskreq_t *req, struct parent_info *pinfo)
{
	int i = 0, j = 0;

	if (!req || !pinfo) {
		return;
	}

	/* 找到父进程的位置 */
	for (i = 0; i < SNIPER_PGEN; i++) {
		if (pinfo->task[i].pid == req->pid) {
			break;
		}
	}
	i++;

	/* 拷贝父进程及祖先进程的信息 */
	for (; i < SNIPER_PGEN; i++, j++) {
		req->pinfo.task[j] = pinfo->task[i];
	}
}

/* pid是提权进程的pid，未必是当前进程，可能是当前进程的祖先进程 */
static int report_privup(struct parent_info *pinfo, pid_t pid, pid_t ppid,
			uid_t uid, int suidtype, int optype, char *target)
{
/* 20210903 保守地，只对提权起shell报警，其他提权情况报关键日志 */
#ifdef STOP_NOTSUID_PRIVUP
	int do_stop = 0;
#endif
	int trust = 0;
	taskreq_t *req = NULL;

	if (pid == current->pid) { //当前进程提权
		req = init_taskreq(INIT_WITH_CMD);
	} else {                   //祖先进程提权
		req = init_taskreq_pid(pid);
	}
	if (!req) {
		return 0;
	}

	req->pid  = pid; //提权进程
	req->tgid = ppid;
	req->uid  = uid;
	req->euid = uid;

	req->root_pid = current->pid; //使用特权的进程

	if (pid == current->pid) {
		memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	} else {
		copy_pinfo(req, pinfo);
		myprintk("%s(%d) parent %s(%d) privup from %u\n",
			current->comm, current->pid, &req->args, pid, uid);
	}

	req->flags = PSR_PRIVUP;
	req->pflags.privup = 1;
	if (suidtype == PRIVUP_SUID) {
		req->pflags.privup_suid = 1;
	} else if (suidtype == PRIVUP_NOTSUID) {
		req->pflags.privup_notsuid = 1;
	} else {
		req->pflags.privup_notsyssuid = 1;
	}

	if (is_filter_cmd(req, NULL)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;
	}

	if (suidtype != PRIVUP_SUID) {
		trust = is_trust_cmd(req, EVENT_PrivilegeEscalation, NULL, NULL);
#ifdef STOP_NOTSUID_PRIVUP
		if (!trust && sniper_prule.privilege_kill && client_mode == NORMAL_MODE) {
			do_stop = 1;
			req->flags |= PSR_STOPED;
			req->pflags.terminate = 1;
		}
#endif
	}

	if (optype == PRIVUP_EXEC) {
		req->pflags.privup_exec = 1;
		copy_target(req->target_cmd, target);
	} else {
		req->pflags.privup_file = 1;
		//TODO 也拷一下被提权访问的文件
	}

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;
        send_data_to_user((char *)req, req->size, nl_exec_pid, Probe_privup);

#ifdef STOP_NOTSUID_PRIVUP
	if (do_stop) {
		myprintk("stop %s(%d) as privup\n", &req->args, req->pid);
		send_sig(SIGKILL, current, 1);

		if (pid != current->pid) {
			struct task_struct *task = get_task_from_pid(pid);

			if (task) {
				my_put_task_struct(task);
				myprintk("stop %s(%d) as privup\n", &req->args, req->pid);
				send_sig(SIGKILL, task, 1);
			}
		}
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return -1;
	}
#endif

	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
	return 0;
}

/*
 * 检查是否提权
 * 返回值：1，提权；0，非提权
 * 参数：pinfo，祖先进程信息，用于上溯检查是否有过uid变0的变化
 *       optype，提权行为：提权执行命令，提权访问文件
 *       target，提权访问文件时被访问的文件
 */
int check_privup(struct parent_info *pinfo, int optype, char *target)
{
	int suidtype = 0;
	pid_t pid = 0, ppid = 0;
	uid_t olduid = 65535, exeuid = 0;
	struct task_struct *parent = NULL;
	char *desc = NULL, *op = NULL, *obj = "";
	struct mm_struct *mm = NULL;

	if (!process_engine_status() || !sniper_prule.privilege_on) { //不监控进程，或不监控提权
		return 0;
	}

	pid = is_privup(pinfo, optype, &olduid);
	if (pid == 0) { //未提权
		return 0;
	}

	parent = get_parent(current);
	myprintk("current %u/%u/%u/%u, parent %u/%u/%u/%u\n",
		currentuid(), currenteuid(), currentsuid(), currentfsuid(),
		taskuid(parent), taskeuid(parent), tasksuid(parent), taskfsuid(parent));
	my_put_task_struct(parent);

	if (optype == PRIVUP_EXEC) {
		op = "exec command";
	} else {
		op = "access file";
	}
	if (target) {
		obj = target;
	}

	if (pid == current->pid) {
		suidtype = check_suid_exe(current->mm, &exeuid);
		parent = get_parent(current);
		exeuid = 0;
		if (parent) {
			ppid = parent->pid;
			mm = get_task_mm(parent);
			if (mm) {
				check_suid_exe(mm, &exeuid);
				my_put_task_struct(parent);
				mmput(mm);
			} else {
				my_put_task_struct(parent);
			}
		}
	} else {
		exeuid = 0;
		suidtype = check_parent_suid_exe(pid, &ppid, &exeuid);
	}

	if (suidtype < 0) {
		myprintk("Warning: %s(%d/%d) privup %s %s from %d, get suidtype fail\n",
			current->comm, pid, current->pid, op, obj, olduid);
		report_privup(pinfo, pid, ppid, olduid, PRIVUP_SUID, optype, target);
		return PRIVUP_SUID;
	}
	if (suidtype == PRIVUP_SUID) {
		myprintk("%s(%d/%d) suid privup %s %s from %d\n",
			current->comm, pid, current->pid, op, obj, olduid);
		report_privup(pinfo, pid, ppid, olduid, PRIVUP_SUID, optype, target);
		return PRIVUP_SUID;
	}
	if (suidtype == PRIVUP_NOTSUID) {
		desc = "notsuid";
	} else {
		desc = "notsyssuid";
	}

	if (exeuid == 0) {
		myprintk("not look %s(%d) as %s privup, parent(%d) "
			"may fork it as root before change uid to %d\n",
			current->comm, current->pid, desc, ppid, olduid);
		return 0;
	}

	if (pid == current->pid) {
		myprintk("%s(%d) %s privup %s %s from %d\n",
			current->comm, current->pid, desc, op, obj, olduid);
	} else {
		myprintk("%s(%d) parent %d %s privup %s %s from %d\n",
			current->comm, current->pid, pid, desc, op, obj, olduid);
	}
	if (report_privup(pinfo, pid, ppid, olduid, suidtype, optype, target) < 0) {
		return PRIVUP_STOP;
	}
	return 0;
}
