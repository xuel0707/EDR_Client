#include <asm/param.h> // for HZ
#include "header.h"

unsigned char tasklist_ready = 0;
tasklist_t *tasklist = NULL;
taskstat_t *idle_taskstat = NULL;

static int taskstat_num = 0;
static exelist_t *exelist = NULL;
static int exehash_num = 0;

/* get_proc_stat()引用了ps的实现代码 */
int get_proc_stat(taskstat_t *taskstat)
{
	int ret = 0;
	FILE *fp = NULL;
	char path[S_PROCPATHLEN] = {0};
	char buf[S_LINELEN] = {0}, *ptr = NULL;
	proc_t P = {0};
	time_t tval1 = 0, tval2 = 0;
	struct stat st = {0};

	if (!taskstat) {
		MON_ERROR("get_proc_stat fail: NULL taskstat\n");
		return -1;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/stat", taskstat->pid);

	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			MON_ERROR("open %s fail: %s\n", path, strerror(errno));
		}
		return -1;
	}

	fgets(buf, S_LINELEN, fp);
	/* 考虑到进程名带)的情况，倒着找) */
	ptr = strrchr(buf, ')');
	if (!ptr) {
		MON_ERROR("bad %s info: %s\n", path, buf);
		sniper_fclose(fp, PROCESS_GET);
		return -1;
	}

	/* 跳过头上的两项tid, cmd */
	ptr += 2;
	ret = sscanf(ptr,
		"%c "
		"%d %d %d %d %d "
		"%lu %lu %lu %lu %lu "
		"%Lu %Lu %Lu %Lu "  /* utime stime cutime cstime */
		"%ld %ld "
		"%d "
		"%lu "
		"%lu ",
		&P.state,
		&P.ppid, &P.pgrp, &P.session, &P.tty, &P.tpgid,
		&P.flags, &P.min_flt, &P.cmin_flt, &P.maj_flt, &P.cmaj_flt,
		&P.utime, &P.stime, &P.cutime, &P.cstime,
		&P.priority, &P.nice,
		&P.nlwp,
		&tval1,
		&tval2);
			
	if (ret < 20) {
		MON_ERROR("bad %s info: %d\n", path, ret);
		sniper_fclose(fp, PROCESS_GET);
		return -1;
	}

	/* 内核3.4及之后tval1的位置固定放了个0
	   详见内核代码fs/proc/array.c中的do_task_stat()函数*/
	if (tval1 == 0) {
		P.start_time = tval2 / HZ;
		taskstat->proctime = tval2;
	} else {
		P.start_time = tval1 / HZ;
		taskstat->proctime = tval1;
	}

	taskstat->pinfo.task[0].pid = P.ppid;

	/* 对于虚拟机，P.start_time可能不准，P.start_time是进程启动时系统运行了多长时间，
	   但虚拟机会挂起，挂起的时间是不包含在系统运行了多长时间里的 */
	if (stat(path, &st) == 0) {
		taskstat->event_tv.tv_sec = st.st_mtime;
	} else {
		/* P.start_time是相对时间，taskstat->event_tv是绝对时间 */
		taskstat->event_tv.tv_sec = P.start_time + uptime_sec;
	}
	taskstat->event_tv.tv_usec = 0;

	sniper_fclose(fp, PROCESS_GET);
	return 0;
}

/* 从/proc/PID/status里读tgid(进程组号)、uid、gid */
int get_proc_status(taskstat_t *taskstat)
{
	FILE *fp = NULL;
	int len = 0, count = 0;
	pid_t tgid = 0;
	uid_t uid = 0, euid = 0, suid = 0, fsuid = 0;
	gid_t gid = 0, egid = 0, sgid = 0, fsgid = 0;
	char comm[S_COMMLEN] = {0}; //16个字节
	char line[S_LINELEN] = {0};
	char path[S_PROCPATHLEN] = {0};

	if (!taskstat) {
		MON_ERROR("get_proc_status fail: NULL taskstat\n");
		return -1;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/status", taskstat->pid);

	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			INFO("open %s fail: %s\n", path, strerror(errno));
		}
		return -1;
	}

	while (fgets(line, S_LINELEN, fp) != NULL) {
		if (count == 4) {
			break;
		}

		if (strncmp(line, "Name:", 5) == 0) {
			/* comm的长度理论上不会超过15个字节，但确实见过
			   kworker/1:1H-xfs-log/sda3这样的情况，原因不明 */
			sscanf(line, "Name: %15s\n", comm);
			count++;
			continue;
		}

		if (strncmp(line, "Tgid:", 5) == 0) {
			sscanf(line, "Tgid: %d\n", &tgid);
			count++;
			continue;
		}

		if (strncmp(line, "Uid:", 4) == 0) {
			sscanf(line, "Uid: %d %d %d %d\n",
				&uid, &euid, &suid, &fsuid);
			count++;
			continue;
		}

		if (strncmp(line, "Gid:", 4) == 0) {
			sscanf(line, "Gid: %d %d %d %d\n",
				&gid, &egid, &sgid, &fsgid);
			count++;
			continue;
		}
	}
	sniper_fclose(fp, PROCESS_GET);

	if (tgid != taskstat->pid) {
		taskstat->pinfo.task[0].pid = tgid;
	}
	taskstat->uid = uid;
	taskstat->euid = euid;
	taskstat->fsuid = fsuid;
	taskstat->gid = gid;
	taskstat->egid = egid;
	taskstat->fsgid = fsgid;

	/* CentOS 5没有/proc/PID/comm，内核线程在这里取命令名和参数 */
	len = strlen(comm);
	taskstat->cmdlen = len;
	memcpy(taskstat->cmd, comm, len);
	taskstat->cmd[len] = 0;

	if (taskstat->pid == 2 || taskstat->pinfo.task[0].pid == 2) {
		taskstat->argslen = len+2;
		snprintf(taskstat->args, S_ARGSLEN, "[%s]", comm);
		taskstat->argv0len = len+2;
	} else {
		taskstat->argslen = len;
		snprintf(taskstat->args, S_ARGSLEN, "%s", comm);
		taskstat->argv0len = len;
	}

	return 0;
}

uid_t get_proc_euid(pid_t pid)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char path[S_PROCPATHLEN] = {0};
	uid_t uid = 0, euid = 65534, suid = 0, fsuid = 0;

	snprintf(path, S_PROCPATHLEN, "/proc/%d/status", pid);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			INFO("get_proc_euid open %s fail: %s\n", path, strerror(errno));
		}
		return 65534;
	}

	while (fgets(line, S_LINELEN, fp) != NULL) {
		if (sscanf(line, "Uid: %d %d %d %d", &uid, &euid, &suid, &fsuid) == 4) {
			break;
		}
	}
	sniper_fclose(fp, PROCESS_GET);

	return euid;
}

pid_t get_proc_ppid(pid_t pid)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	char path[S_PROCPATHLEN] = {0};
	pid_t ppid = 0;

	snprintf(path, S_PROCPATHLEN, "/proc/%d/status", pid);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			INFO("get_proc_ppid open %s fail: %s\n", path, strerror(errno));
		}
		return 0;
	}

	while (fgets(line, S_LINELEN, fp)) {
		if (sscanf(line, "PPid: %d", &ppid) == 1) {
			break;
		}
	}
	sniper_fclose(fp, PROCESS_GET);

	return ppid;
}

/* 读/proc/PID/cwd链接内容 */
static int get_proc_cwd(taskstat_t *taskstat)
{
	int len = 0;
	char path[S_PROCPATHLEN] = {0};

	if (!taskstat) {
		MON_ERROR("get_proc_cwd fail, NULL taskstat\n");
		return -1;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/cwd", taskstat->pid);

	/* readlink() does not append a null byte to buf, end bufstr byself */
	len = readlink(path, taskstat->cwd, S_CWDLEN-1);
	if (len > 0) {
		taskstat->cwdlen = len;
		taskstat->cwd[len] = 0;
		return 0;
	}

	taskstat->cwd[0] = '-';
	taskstat->cwd[1] = 0;
	taskstat->cwdlen = 1;
	return 0;
}

/* 读/proc/PID/status里的进程Name，返回读到的进程名长度 */
int get_proc_comm(pid_t pid, char *comm)
{
	int len = -1;
	FILE *fp = NULL;
	char buf[16] = {0};
	char line[256] = {0};
	char path[128] = {0};

	if (pid == 0 || !comm) {
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/status", pid);

	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			INFO("get_proc_comm open %s fail: %s\n", path, strerror(errno));
		}
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "Name: %15s", buf) == 1) {
			snprintf(comm, S_COMMLEN, "%s", buf);
			len = strlen(comm);
			break;
		}
	}

	sniper_fclose(fp, PROCESS_GET);

	return len;
}

/* 读/proc/PID/exe链接内容，返回读到的命令路径名长度 */
int get_proc_exe(pid_t pid, char *cmd)
{
	int len = 0;
	char buf[S_CMDLEN] = {0};
	char path[S_PROCPATHLEN] = {0}, *ptr = NULL;

	if (!cmd) {
		MON_ERROR("get_proc_exe fail, NULL cmd buffer\n");
		return -1;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/exe", pid);

	len = readlink(path, buf, S_CMDLEN-1);
	if (len < 0) {
		return -errno;
	}
	if (len == 0) {
		return 0;
	}

	/* readlink() does not append a null byte, end byself */
	buf[len] = 0;

	/*
	 * 进程运行中程序被删除，取exe会有(deleted)标识，去掉此标识
	 * /usr/sbin/console-kit-daemon.#prelink#.BOl1wo (deleted)这样的取/usr/sbin/console-kit-daemon
	 */
	ptr = strstr(buf, ".#prelink#.");
	if (ptr) {
		*ptr = 0;
		len = ptr - buf;
	} else {
		ptr = strstr(buf, " (deleted)");
		if (ptr) {
			*ptr = 0;
			len = ptr - buf;
		}
	}

	memcpy(cmd, buf, len);
	cmd[len] = 0;

	return len;
}

/*
 * 从/proc/PID/cmdline取进程的命令行参数，存入buf[buflen]
 * 返回值：-1 错误；0 /proc/PID/cmdline内容为空，如内核线程；n 命令行的长度
 *
 * 20220228 将函数由两个参数pid, cmdline改为三个参数pid, buf, buflen
 * 之前用固定大小的cmdline[S_ARGSLEN]存命令行内容，现改为可定制的长度
 * buflen为存命令行结果的缓冲区buf的大小
 * 应用风险检查java进程命令行参数中是否带solr时，发现solr出现的位置在512字节之后，因此需要更大的缓冲区
 */
int get_proc_cmdline(pid_t pid, char *buf, int buflen)
{
	char path[S_PROCPATHLEN] = {0};
	int fd = 0, i = 0, len = 0;

	if (!buf) {
		MON_ERROR("get_proc_cmdline fail, NULL cmdline\n");
		return -1;
	}

	/* 读进程的cmdline信息 */
	snprintf(path, S_PROCPATHLEN, "/proc/%d/cmdline", pid);
	fd = sniper_open(path, 0, PROCESS_GET);
	if (fd < 0) {
		MON_ERROR("get_proc_cmdline open %s fail: %s\n", path, strerror(errno));
		return -1;
	}

	memset(buf, 0, buflen);
	len = read(fd, buf, buflen-1);
	sniper_close(fd, PROCESS_GET);
	if (len < 0) {
		MON_ERROR("get_proc_cmdline read %s fail: %s\n", path, strerror(errno));
		return -1;
	}
	if (len == 0) {
		return 0;
	}

	/* 整理取到的cmdline，把所有0转成空格, 包括最后结尾的0，如果结尾是0的话 */
	for (i = 0; i < len; i++) {
		if (buf[i] == 0) {
			buf[i] = ' ';
		}
	}
	delete_tailspace(buf);

	return strlen(buf);
}

static void get_proc_tty(taskstat_t *taskstat)
{
	int i = 0;
	char path[S_PROCPATHLEN] = {0};
	char buf[S_TTYLEN] = {0};

	if (!taskstat) {
		MON_ERROR("get_proc_tty fail, NULL taskstat\n");
		return;
	}

	for (i = 0; i < 3; i++) {
		snprintf(path, S_PROCPATHLEN, "/proc/%d/fd/%d", taskstat->pid, i);
		if (readlink(path, buf, S_TTYLEN-1) <= 0) {
			continue;
		}
		if (strncmp(buf, "/dev/tty", 8) == 0) {
			snprintf(taskstat->tty, S_TTYLEN, "%s", buf+5);
			taskstat->flags |= TASK_TTY;
			break;
		}
		if (strncmp(buf, "/dev/pts/", 9) == 0) {
			snprintf(taskstat->tty, S_TTYLEN, "pts%s", buf+9);
			taskstat->flags |= TASK_TTY;
			break;
		}
	}
}

int get_taskstat_num(void)
{
	return taskstat_num;
}
int get_exehash_num(void)
{
	return exehash_num;
}

exehash_t *get_exehash_by_inode(unsigned long ino)
{
	int idx = 0;
	exehash_t *exehash = NULL;

	if (!exelist) {
		MON_ERROR("get exehash fail, null exelist\n");
		return NULL;
	}

	idx = ino % EXEMAX;
	exehash = exelist[idx].head;
	while (exehash) {
		if (exehash->ino == ino) {
			return exehash;
		}
		exehash = exehash->next;
	}

	return NULL;
}

static exehash_t *get_exehash(char *cmd, struct stat *st)
{
	int idx = 0;
	exehash_t *exehash = NULL;
	exehash_t *prev_exehash = NULL;

	if (!st) {
		MON_ERROR("get exehash fail, null st\n");
		return NULL;
	}
	if (!exelist) {
		MON_ERROR("get exehash fail, null exelist\n");
		return NULL;
	}

	idx = st->st_ino % EXEMAX;
	exehash = exelist[idx].head;
	prev_exehash = exehash;
	while (exehash) {
		if (exehash->ino == st->st_ino && exehash->dev == st->st_dev) {
			if (exehash->size == st->st_size &&
			    exehash->mode == st->st_mode &&
			    exehash->mtime == st->st_mtime &&
			    exehash->ctime == st->st_ctime) {
				return exehash;
			}

			INFO("%s(%#lx:%lu) changed, size %lu/%lu, mtime %lu/%lu, ctime %lu/%lu, "
			     "mode %o/%o, drop old hash, count new\n",
			cmd ? cmd : "cmd", st->st_dev, st->st_ino,
			st->st_size, exehash->size, st->st_mtime, exehash->mtime,
			st->st_ctime, exehash->ctime, st->st_mode, exehash->mode);

			if (exehash == exelist[idx].head) {
				exelist[idx].head = exehash->next;
			} else {
				prev_exehash->next = exehash->next;
			}
			exehash_num--;
			sniper_free(exehash, sizeof(struct exe_hash), PROCESS_GET);

			return NULL;
		}
		prev_exehash = exehash;
		exehash = exehash->next;
	}

	return NULL;
}

static void cache_exehash(struct stat *st, taskstat_t *taskstat)
{
	int idx = 0;
	exehash_t *exehash = NULL;

	if (!st || !taskstat) {
		MON_ERROR("cache exehash fail, args: %p %p\n", st, taskstat);
		return;
	}

	exehash = sniper_malloc(sizeof(struct exe_hash), PROCESS_GET);
	if (!exehash) {
		MON_ERROR("cache exehash fail, no memory\n");
		return;
	}

	exehash_num++;

	exehash->dev = st->st_dev;
	exehash->ino = st->st_ino;
	exehash->size = st->st_size;
	exehash->mtime = st->st_mtime;
	exehash->ctime = st->st_ctime;
	exehash->mode = st->st_mode;
	memcpy(exehash->md5, taskstat->md5, sizeof(taskstat->md5));
	memcpy(exehash->sha256, taskstat->sha256, sizeof(taskstat->sha256));
	snprintf(exehash->vendor, sizeof(exehash->vendor), "%s", taskstat->vendor);
	snprintf(exehash->product, sizeof(exehash->product), "%s", taskstat->product);
	exehash->pid = taskstat->pid;

	DBG2(DBGFLAG_PROCESS, "cache %s(%#lx:%lu) exehash: %lu, %lu, %lu, %o\n",
		taskstat->cmd, exehash->dev, exehash->ino, exehash->size,
		exehash->mtime, exehash->ctime, exehash->mode);

	if (taskstat->pflags.program_changed || taskstat->flags & TASK_PROGRAM_CHANGED) {
		INFO("%s taskstat has program_changed flag\n", taskstat->cmd);
		exehash->program_changed = 1;
	}

	idx = st->st_ino % EXEMAX;
	if (!exelist[idx].head) {
		exelist[idx].head = exehash;
	} else {
		exehash->next = exelist[idx].head;
		exelist[idx].head = exehash;
	}
}

#if 0
pid_t get_orphan_process_ppid(taskreq_t *req)
#else
pid_t get_orphan_process_ppid(struct ebpf_taskreq_t *req)
#endif
{
	char path[S_PROCPATHLEN] = {0};
	taskstat_t *ptaskstat = NULL;
	exehash_t *exehash = NULL;
	struct stat st = {0};
	pid_t ppid = 0;

	ptaskstat = get_ptaskstat_from_pinfo(&req->pinfo);
	if (!ptaskstat) {
		return req->pinfo.task[0].pid;
	}
	ppid = ptaskstat->pid;

	/* 试图找回孤儿进程的父进程 */
	if (ppid == 1) {
		snprintf(path, S_PROCPATHLEN, "/proc/%d/exe", req->pid);
		if (stat(path, &st) == 0) {
#if 0
			exehash = get_exehash(&req->args, &st);
#else
			// TODO(luoyinhong)
			exehash = get_exehash(req->args[0], &st);
#endif
			if (exehash) {
				ppid = exehash->pid; //上一个执行本程序的进程
			}
		}
	}
	return ppid;
}

static char sysvendor[S_NAMELEN] = "N/A";
static void zero_md5_sha256_vendor_product(taskstat_t *taskstat)
{
	if (!taskstat) {
		return;
	}

	memset(taskstat->md5, 0, sizeof(taskstat->md5));
	memset(taskstat->sha256, 0, sizeof(taskstat->sha256));

	snprintf(taskstat->vendor, sizeof(taskstat->vendor), "%s", sysvendor);
	snprintf(taskstat->product, sizeof(taskstat->product), "kernel-%s", thestring(Sys_info.os_kernel));
}
static void x_md5_sha256_vendor_product(taskstat_t *taskstat)
{
	if (!taskstat) {
		return;
	}

	memset(taskstat->md5, 0, sizeof(taskstat->md5));
	memset(taskstat->sha256, 0, sizeof(taskstat->sha256));

	snprintf(taskstat->vendor, sizeof(taskstat->vendor), "N/A");
	snprintf(taskstat->product, sizeof(taskstat->product), "N/A");
}

int check_digest(taskstat_t *taskstat, char *install_digest, off_t *real_size)
{
	int len = 0, digest_change = 0;
	char *digest = NULL;
	char undofile[128] = {0};
	char undocmd[4096] = {0};
	char real_digest[S_SHALEN] = {0};
	struct stat st = {0};

	if (!taskstat || !install_digest || !real_size) {
		return 0;
	}

	len = strlen(install_digest);
	if (len == 0) {
		return 0;
	}

	/* CentOS5是MD5, 6/7是SHA256 */
	if (len < S_MD5LEN) {
		digest = taskstat->md5;
	} else {
		digest = taskstat->sha256;
	}

	if (strcmp(install_digest, digest) == 0) {
		return 0; //校验值没变
	}

	/* 校验值改变了，且不是prelink程序改变的 */
	if (access("/usr/sbin/prelink", X_OK) != 0) {
		printf("%s digest %s -> %s\n", taskstat->cmd, install_digest, digest);
		DBG2(DBGFLAG_PROCESS, "%s digest %s -> %s\n", taskstat->cmd, install_digest, digest);
		return 1;
	}

	//TODO prelink -u 一个没被prelink过的文件，结果如何？
	snprintf(undofile, sizeof(undofile), "/tmp/%lu.undo-prelink", time(NULL));
	snprintf(undocmd, sizeof(undocmd), "/usr/sbin/prelink -o %s -u %s", undofile, taskstat->cmd);
	system(undocmd);

	/* undo未prelink过的文件，得到的新文件，和原文件完全一样 */
	if (stat(undofile, &st) < 0) {
		INFO("Warning: %s fail\n", undocmd);
		return 0; //复原prelink失败，无法确定是否为prelink改变的
	}
	*real_size = st.st_size;

	if (len < S_MD5LEN) {
		md5_file(undofile, real_digest);
	} else {
		sha256_file(undofile, real_digest);
	}
	unlink(undofile);

	if (strcmp(install_digest, real_digest) != 0) {
		digest_change = 1;
		printf("%s digest %s -> %s\n", taskstat->cmd, install_digest, real_digest);
		DBG2(DBGFLAG_PROCESS, "%s digest %s -> %s\n", taskstat->cmd, install_digest, real_digest);
	}

	return digest_change;
}

//TODO 更新hash，报告改变
void count_file_hash(taskstat_t *taskstat)
{
	int hashok = 0, ret = 0;
	struct stat st = {0};
	exehash_t *exehash = NULL;
	char path[PATH_MAX] = {0}, *cmd = NULL;
	char rpath[PATH_MAX] = {0};
	exeinfo_t exeinfo = {0};

	if (!taskstat) {
		MON_ERROR("count_file_hash fail, NULL taskstat\n");
		return;
	}

	DBG2(DBGFLAG_PROCESSDEBUG, "count %s hash\n", taskstat->cmd);
	cmd = taskstat->cmd;
	if (cmd[0] != '/') {
		if (strncmp(cmd, "...", 3) == 0) {
			x_md5_sha256_vendor_product(taskstat);
			return;
		}
		if (cmd[0] != '.') {
			zero_md5_sha256_vendor_product(taskstat);
			return;
		}

		snprintf(path, PATH_MAX, "%s/%s", taskstat->cwd, cmd);
		if (realpath(path, rpath)) {
			cmd = rpath;
		} else {
			cmd = path;
		}

		if (cmd[0] != '/') {
			MON_ERROR("count_file_hash fail, cmd %s\n", cmd);
			x_md5_sha256_vendor_product(taskstat);
			return;
		}
	}

	if (stat(cmd, &st) < 0) {
		if (errno != ENOENT) {
			MON_ERROR("count_file_hash fail, stat %s: %s\n", cmd, strerror(errno));
		}
		x_md5_sha256_vendor_product(taskstat);
		return;
	}

	if (st.st_mode & S_ISUID) {
		taskstat->flags |= TASK_SUID;
	}
	exehash = get_exehash(cmd, &st);
	if (exehash) {
		DBG2(DBGFLAG_PROCESSDEBUG, "get %s exehash: %lu, %lu, %lu, %o\n",
			taskstat->cmd, exehash->size, exehash->mtime, exehash->ctime, exehash->mode);
		memcpy(taskstat->md5, exehash->md5, sizeof(exehash->md5));
		memcpy(taskstat->sha256, exehash->sha256, sizeof(exehash->sha256));
		snprintf(taskstat->vendor, sizeof(taskstat->vendor), "%s", exehash->vendor);
		snprintf(taskstat->product, sizeof(taskstat->product), "%s", exehash->product);
		exehash->pid = taskstat->pid;
		if (exehash->program_changed) {
			INFO("%s exehash has program_changed flag\n", taskstat->cmd);
			taskstat->pflags.program_changed = 1;
			taskstat->flags |= TASK_PROGRAM_CHANGED;
		}
		return;
	}

	if (md5_file(cmd, taskstat->md5) < 0) {
		memset(taskstat->md5, 0, sizeof(taskstat->md5));
		hashok --;
	}
	if (sha256_file(cmd, taskstat->sha256) < 0) {
		memset(taskstat->sha256, 0, sizeof(taskstat->sha256));
		hashok --;
	}

	if (hashok < 0) {
		return;
	}

#ifdef SNIPER_FOR_DEBIAN
	ret = get_fileinfo_from_dpkginfo(cmd, &exeinfo);
#else
	/* 可能有多个软件包都包含该文件的情况，比如软件升级了但没有删掉旧的版本 */
	/* 用校验值确定到底属于哪个软件包 */
	ret = get_fileinfo_from_rpmdb(cmd, &exeinfo, taskstat->md5, taskstat->sha256);
#endif
	if (ret < 0) {
		if (strcmp(cmd, SNIPER_PROG) == 0 || strncmp(cmd, WORKDIR, strlen(WORKDIR)) == 0) {
			snprintf(taskstat->vendor, sizeof(taskstat->vendor), "%s", SNIPER_VENDOR);
			snprintf(taskstat->product, sizeof(taskstat->product),
				"sniper-%s.%s", SNIPER_VERSION, SNIPER_ARCH);
		} else if (strcmp(cmd, "/usr/sbin/sniper") == 0) {
			struct stat st1 = {0}, st2 = {0};
			stat(SNIPER_PROG, &st1);
			stat("/usr/sbin/sniper", &st2);
			if (st1.st_ino == st2.st_ino) {
				snprintf(taskstat->vendor, sizeof(taskstat->vendor), "%s", SNIPER_VENDOR);
				snprintf(taskstat->product, sizeof(taskstat->product),
					"sniper-%s.%s", SNIPER_VERSION, SNIPER_ARCH);
			} else {
				//TODO 这是在冒充sniper?
				snprintf(taskstat->vendor, sizeof(taskstat->vendor), "N/A");
				snprintf(taskstat->product, sizeof(taskstat->product), "N/A");
			}
		} else {
			//printf("%s no package\n", cmd);
			snprintf(taskstat->vendor, sizeof(taskstat->vendor), "N/A");
			snprintf(taskstat->product, sizeof(taskstat->product), "N/A");
		}
	} else {
		off_t real_size = st.st_size;
		int digest_change = 0;
		int mode_change = 0;

		if (exeinfo.product[0] == 0) {
			snprintf(exeinfo.product, sizeof(exeinfo.product), "N/A");
		}
		if (exeinfo.vendor[0] == 0) {
			snprintf(exeinfo.vendor, sizeof(exeinfo.vendor), "N/A");
		}
		snprintf(taskstat->vendor, sizeof(taskstat->vendor), "%s", exeinfo.vendor);
		snprintf(taskstat->product, sizeof(taskstat->product), "%s", exeinfo.product);

		digest_change = check_digest(taskstat, exeinfo.install_digest, &real_size);

		if (exeinfo.install_fsize != real_size) {
			printf("%s : %s : %s\n", cmd, exeinfo.product, exeinfo.vendor);
			printf("fsize %lu -> %lu\n", exeinfo.install_fsize, real_size);
			INFO("%s fsize %lu -> %lu\n", taskstat->cmd, exeinfo.install_fsize, real_size);
		}

		if (exeinfo.install_fmode != st.st_mode) {
			mode_change = 1;
			printf("%s : %s : %s\n", cmd, exeinfo.product, exeinfo.vendor);
			printf("mode %o -> %o\n", exeinfo.install_fmode, st.st_mode);
			INFO("%s mode %o -> %o\n", taskstat->cmd, exeinfo.install_fmode, st.st_mode);
		}

		if (exeinfo.install_mtime != st.st_mtime) {
			printf("%s : %s : %s\n", cmd, exeinfo.product, exeinfo.vendor);
			printf("mtime %lu -> %lu\n", exeinfo.install_mtime, st.st_mtime);
			INFO("%s mtime %lu -> %lu\n", taskstat->cmd, exeinfo.install_mtime, st.st_mtime);
		}

		if (digest_change || mode_change) {
			INFO("%s digest_change %d, mode_change %d\n", taskstat->cmd, digest_change, mode_change);
			taskstat->pflags.program_changed = 1;
			taskstat->flags |= TASK_PROGRAM_CHANGED;
		}
	}

	cache_exehash(&st, taskstat);
	if (taskstat->pid == 1) {
		snprintf(sysvendor, sizeof(sysvendor), "%s", taskstat->vendor);
	}
}

void add_tasklist_tail(taskstat_t *taskstat)
{
	int idx = 0;

	if (!taskstat) {
		MON_ERROR("add_tasklist_tail fail, NULL taskstat\n");
		return;
	}

	idx = taskstat->pid % TASKMAX;
	pthread_rwlock_wrlock(&tasklist[idx].lock);
	list_add_tail(&taskstat->list, &tasklist[idx].queue);
	pthread_rwlock_unlock(&tasklist[idx].lock);
}

taskstat_t *alloc_taskstat(void)
{
	taskstat_t *taskstat = NULL;

	taskstat = sniper_malloc(sizeof(struct task_status), PROCESS_GET);
	if (!taskstat) {
		MON_ERROR("alloc taskstat fail: no memory\n");
		return NULL;
	}
	taskstat->refcount = 0;
	taskstat_num++;

	return taskstat;
}

/*
 * 为了回溯提权起shell的动作，保留多级exec_ptaskstat，
 * 提权和起shell之间可能会间杂其他命令，如sh -c
 */
void save_exec_ptaskstat(taskstat_t *taskstat)
{
	taskstat_t *exec_ptaskstat = NULL;

	if (!taskstat) {
		MON_ERROR("save_exec_ptaskstat fail, NULL taskstat\n");
		return;
	}

	exec_ptaskstat = alloc_taskstat();
	if (!exec_ptaskstat) {
		MON_ERROR("%s(%d) alloc exec_ptaskstat fail\n",
			  taskstat->args, taskstat->pid);
		return;
	}

	memcpy(exec_ptaskstat, taskstat, sizeof(struct task_status));
	taskstat->exec_ptaskstat = exec_ptaskstat;
}

static void drop_exec_ptaskstat(taskstat_t *taskstat)
{
	taskstat_t *exec_ptaskstat = taskstat->exec_ptaskstat;
	taskstat_t *next_taskstat = NULL;

	if (!exec_ptaskstat) {
		return;
	}
	if (exec_ptaskstat == taskstat) {
		taskstat->exec_ptaskstat = NULL;
		return;
	}

	while (exec_ptaskstat) {
		next_taskstat = exec_ptaskstat->exec_ptaskstat;

		sniper_free(exec_ptaskstat, sizeof(struct task_status), PROCESS_GET);
		taskstat_num--;

		exec_ptaskstat = next_taskstat;
	}
	taskstat->exec_ptaskstat = NULL;
}

#if 0
taskstat_t *get_ptaskstat_from_pinfo_rdlock(struct parent_info *pinfo)
#else
taskstat_t *get_ptaskstat_from_pinfo_rdlock(struct ebpf_parent_info *pinfo)
#endif
{
	int i = 0;
	taskstat_t *taskstat = NULL;

	if (!pinfo) {
		return NULL;
	}

	for (i = 0; i < SNIPER_PGEN; i++) {
		/* 没有父进程可找了 */
		if (pinfo->task[i].pid == 0) {
			return NULL;
		}

		/* 找到 */
		taskstat = get_taskstat_rdlock(pinfo->task[i].pid, PROCESS_GET);
		if (taskstat) {
			return taskstat;
		}
	}

	return NULL;
}

#if 0
taskstat_t *get_ptaskstat_from_pinfo(struct parent_info *pinfo)
#else
taskstat_t *get_ptaskstat_from_pinfo(struct ebpf_parent_info *pinfo)
#endif
{
	int i = 0;
	taskstat_t *taskstat = NULL;

	if (!pinfo) {
		return NULL;
	}

	for (i = 0; i < SNIPER_PGEN; i++) {
		/* 没有父进程可找了 */
		if (pinfo->task[i].pid == 0) {
			return NULL;
		}

		/* 找到 */
		taskstat = get_taskstat_nolock(pinfo->task[i].pid, PROCESS_GET);
		if (taskstat) {
			return taskstat;
		}
	}

	return NULL;
}

taskstat_t *the_ptaskstat(taskstat_t *taskstat)
{
	taskstat_t *ptaskstat = NULL;

	if (!taskstat || taskstat->pid <= 0) {
		return NULL;
	}

	/* 命令1执行了命令2，将命令1视为父进程 */
	if (taskstat->exec_ptaskstat) {
		return taskstat->exec_ptaskstat;
	}

	if (taskstat->pinfo.task[0].pid == 0 && taskstat->pid <= 2) {
		return idle_taskstat;
	}

	ptaskstat = get_ptaskstat_from_pinfo(&taskstat->pinfo);
	return ptaskstat;
}

static void free_taskstat(taskstat_t *taskstat)
{
	if (!taskstat) {
		MON_ERROR("skip free NULL taskstat\n");
		return;
	}

	if (taskstat->pid == 0) {
		return;
	}
	if (taskstat->pid < 0) {
		MON_ERROR("skip free bad taskstat, pid %d\n", taskstat->pid);
		return;
	}

	if (taskstat->refcount > 0) {
		MON_ERROR("%s(%d) taskstat inuse, refcount %d, cant free\n",
			  taskstat->args, taskstat->pid, taskstat->refcount);
		return;
	}

	drop_exec_ptaskstat(taskstat);
	sniper_free(taskstat, sizeof(struct task_status), PROCESS_GET);
	taskstat_num--;
}

/* 调用者应当持有tasklist[]的写锁 */
static void set_taskstat_exit(taskstat_t *taskstat)
{
	int i = 0;

	if (!taskstat) {
		MON_ERROR("set_taskstat_exit fail, NULL taskstat\n");
		return;
	}

	i = taskstat->pid % TASKMAX;

	list_del(&taskstat->list);
	pthread_rwlock_unlock(&tasklist[i].lock);

	report_taskexit(taskstat);
	free_taskstat(taskstat);
	pthread_rwlock_wrlock(&tasklist[i].lock);
}

#define RDLOCK 1
#define WRLOCK 2
static char gettype[GETTYPE_MAX][8] = {
	"",
	"process",
	"file",
	"network",
	"login",
	"info"
};
static taskstat_t *get_taskstat_lock(pid_t pid, int type, int lock,
				     unsigned long long proctime)
{
	int idx = 0;
	taskstat_t *taskstat = NULL, *tmp = NULL;

	if (type <= GETTYPE_MIN || type >= GETTYPE_MAX) {
		MON_ERROR("bad taskstat get type %d\n", type);
		return NULL;
	}
	if (!tasklist) {
		INFO("%s get taskstat fail, null tasklist\n",
		     gettype[type]);
		return NULL;
	}

	if (pid <= 0) {
		MON_ERROR("%s get taskstat fail, bad pid %d\n",
			  gettype[type], pid);
		return NULL;
	}
	idx = pid % TASKMAX;

	if (lock == WRLOCK) {
		pthread_rwlock_wrlock(&tasklist[idx].lock);
	} else if (lock == RDLOCK) {
		pthread_rwlock_rdlock(&tasklist[idx].lock);
	}
	list_for_each_entry_safe(taskstat, tmp, &tasklist[idx].queue, list) {
		if (taskstat->pid != pid) {
			continue;
		}

		if (lock == WRLOCK) {
			/* 进程时间也相同，是要找的进程 */
			if (taskstat->proctime == proctime) {
				/* 增加锁计数 */
				taskstat->refcount++;
				return taskstat;
			}

			/* 这是已经退出的老进程，清理老进程，并返回没找到 */
			set_taskstat_exit(taskstat);
			pthread_rwlock_unlock(&tasklist[idx].lock);
			return NULL;
		}

		if (lock == RDLOCK) {
			/* 增加锁计数 */
			taskstat->refcount++;
		}
		return taskstat;
	}

	/* 没有找到，解锁 */
	if (lock == WRLOCK || lock == RDLOCK) {
		pthread_rwlock_unlock(&tasklist[idx].lock);
	}
	return NULL;
}

taskstat_t *get_taskstat_nolock(pid_t pid, int type)
{
	return get_taskstat_lock(pid, type, 0, 0);
}
taskstat_t *get_taskstat_rdlock(pid_t pid, int type)
{
	/* 进程监控已关闭，或正在关闭，或正在打开且tasklist还没初始化好 */
	if (!tasklist || !tasklist_ready || !prule.process_engine_on) {
		return NULL;
	}
	return get_taskstat_lock(pid, type, RDLOCK, 0);
}
taskstat_t *get_taskstat_wrlock(pid_t pid, int type, unsigned long t)
{
	return get_taskstat_lock(pid, type, WRLOCK, t);
}

void put_taskstat_unlock(taskstat_t *taskstat)
{
	int idx = 0;

	if (!taskstat) {
		MON_ERROR("put NULL taskstat\n");
		return;
	}

	/* pid_t是有符号类型，unlock的进程的pid应当>0 */
	if (taskstat->pid <= 0) {
		MON_ERROR("put taskstat lock fail, bad pid %d\n", taskstat->pid);
		return;
	}
	idx = taskstat->pid % TASKMAX;

	if (taskstat->refcount <= 0) {
		MON_ERROR("%s(%d) bad taskstat refcount %d, double unlock or corruption\n",
			  taskstat->args, taskstat->pid, taskstat->refcount);
	}

	taskstat->refcount--;
	pthread_rwlock_unlock(&tasklist[idx].lock);
}

/* mem_usage = rss - shared */
void get_mem_usage(taskstat_t *taskstat)
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0};
	char path[S_PROCPATHLEN] = {0};
	unsigned long mem = 0, size = 0, resident = 0, share = 0;
	
	if (!taskstat) {
		MON_ERROR("get_mem_usage NULL taskstat\n");
		return;
	}

	if (taskstat->flags & TASK_STOPED) {
		strncpy(taskstat->mem, "0 KB", S_NAMELEN);
		return;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/statm", taskstat->pid);

	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		if (errno != ENOENT) {
			MON_ERROR("get %s(%d) memory usage fail: "
				"open %s fail: %s(%d)\n",
				taskstat->args, taskstat->pid,
				path, strerror(errno), errno);
		} else if (taskstat->stop_tv.tv_sec == 0) {
			gettimeofday(&taskstat->stop_tv, NULL);
		}

		/* 很快结束的进程，内存使用填1KB */
		strncpy(taskstat->mem, "1 KB", S_NAMELEN);
		return;
	}

	fgets(buf, sizeof(buf), fp);
	sniper_fclose(fp, PROCESS_GET);

	ret = sscanf(buf, "%lu %lu %lu", &size, &resident, &share);
	if (ret != 3) {
		if (access(path, F_OK) == 0) {
			MON_ERROR("bad %s info: %s\n", path, buf);
		}
		//strncpy(taskstat->mem, "N/A", S_NAMELEN);
		strncpy(taskstat->mem, "1 KB", S_NAMELEN);
		return;
	}

	mem = (resident - share) * 4;

	if (mem >= 1048576) {
		snprintf(taskstat->mem, S_NAMELEN, "%.1f GB", mem/1048576.0);
	} else if (mem >= 1024) {
		snprintf(taskstat->mem, S_NAMELEN, "%.1f MB", mem/1024.0);
	} else {
		if (mem < 1) {
			mem = 1;
		}
		snprintf(taskstat->mem, S_NAMELEN, "%lu KB", mem);
	}
	return;
}

#include <elf.h>
static int is_bad_elfhdr32(char *path, char *buf)
{
	int i = 0, bad = 0;
	Elf32_Ehdr *elfhdr = NULL;

	if (!path || !buf) {
		return 0;
	}

	elfhdr = (Elf32_Ehdr *)buf;
	if (strncmp((char *)elfhdr->e_ident, ELFMAG, SELFMAG) != 0) {
		return 0;
	}

	if (elfhdr->e_shentsize != sizeof(Elf32_Shdr)) {
		printf("Size of section headers %d != sizeof(Elf32_Shdr) %lu\n",
			elfhdr->e_shentsize, sizeof(Elf32_Shdr));
		bad = 1;
	} else if (elfhdr->e_phnum < 2) { // 看到easyMon程序的e_phnum是2
		printf("Number of program headers < 2\n");
		bad = 1;
#if 0 //静态编译的程序e_shoff是0
	} else if (elfhdr->e_shoff <= elfhdr->e_phoff + elfhdr->e_phentsize) {
		printf("Start of section headers %u <= "
		       "Start of program headers %u + "
		       "Size of program headers %d\n",
			elfhdr->e_shoff, elfhdr->e_phoff, elfhdr->e_phentsize);
		bad = 1;
	} else if (elfhdr->e_shstrndx == 0) {
		if (elfhdr->e_shnum < 2) {
			printf("Number of section headers < 2\n");
			bad = 1;
		}
	} else if (elfhdr->e_shnum <= elfhdr->e_shstrndx) {
		printf("Number of section headers %d <= "
		       "Section header string table index %d\n",
			elfhdr->e_shnum, elfhdr->e_shstrndx);
		bad = 1;
#endif
	}

	if (!bad) {
		return 0;
	}

	printf("%s ELFhdr(size %lu) BAD!\n", path, sizeof(Elf32_Ehdr));
	printf("Magic: ");
	for (i = 0; i < EI_NIDENT; i++) {
		printf("%x ", elfhdr->e_ident[i]);
	}
	printf("\n");
	printf("Class %d\n", elfhdr->e_ident[4]);
	printf("Data encode %d\n", elfhdr->e_ident[5]);
	printf("Version %d\n", elfhdr->e_ident[6]);

	printf("Type %d\n", elfhdr->e_type);
	printf("Machine %d\n", elfhdr->e_machine);
	printf("Version %d\n", elfhdr->e_version);
	printf("Entry %#x\n", elfhdr->e_entry);
	printf("Start of program headers %u\n", elfhdr->e_phoff);
	printf("Start of section headers %u\n", elfhdr->e_shoff);
	printf("Flags %#x\n", elfhdr->e_flags);
	printf("Size of this header %d\n", elfhdr->e_ehsize);
	printf("Size of program headers %d\n", elfhdr->e_phentsize);
	printf("Number of program headers %d\n", elfhdr->e_phnum);
	printf("Size of section headers %d\n", elfhdr->e_shentsize);
	printf("Number of section headers %d\n", elfhdr->e_shnum);
	printf("Section header string table index %d\n", elfhdr->e_shstrndx);

	return 1;
}
int is_bad_elfhdr(char *cmd, char *cwd)
{
	int i = 0, bad = 0, fd = 0, ret = 0;
	Elf64_Ehdr *elfhdr = NULL;
	char buf[PATH_MAX] = {0}, *path = cmd;

	if (!cmd || !cwd) {
		return 0;
	}

	if (cmd[0] != '/') {
		snprintf(buf, PATH_MAX, "%s/%s", cwd, cmd);
		path = buf;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (cmd[0] != '/' && cmd[0] != '.' && cwd[1] != 0) {
			MON_ERROR("open %s fail: %s. skip elf header check\n",
				path, strerror(errno));
		}
		return 0;
	}

	ret = read(fd, buf, 64);
	close(fd);
	if (ret != 64) {
		if (ret < 0) {
			MON_ERROR("read %s fail: %s. skip elf header check\n",
				path, strerror(errno));
			return 0;
		}
		MON_ERROR("read %s fail: ret %d != 64. skip elf header check\n",
			path, ret);
		return 0;
	}

	if (buf[4] == ELFCLASS32) {
		return is_bad_elfhdr32(path, buf);
	}

	elfhdr = (Elf64_Ehdr *)buf;
	if (strncmp((char *)elfhdr->e_ident, ELFMAG, SELFMAG) != 0) {
		return 0;
	}

	if (elfhdr->e_shentsize != sizeof(Elf64_Shdr)) {
		printf("Size of section headers %d != sizeof(Elf64_Shdr) %lu\n",
			elfhdr->e_shentsize, sizeof(Elf64_Shdr));
		bad = 1;
	} else if (elfhdr->e_phnum < 2) {
		printf("Number of program headers < 2\n");
		bad = 1;
#if 0 //静态编译的程序e_shoff是0
	} else if (elfhdr->e_shoff <= elfhdr->e_phoff + elfhdr->e_phentsize) {
		printf("Start of section headers %lu <= "
		       "Start of program headers %lu + "
		       "Size of program headers %d\n",
			elfhdr->e_shoff, elfhdr->e_phoff, elfhdr->e_phentsize);
		bad = 1;
	} else if (elfhdr->e_shstrndx == 0) {
		if (elfhdr->e_shnum < 2) {
			printf("Number of section headers < 2\n");
			bad = 1;
		}
	} else if (elfhdr->e_shnum <= elfhdr->e_shstrndx) {
		printf("Number of section headers %d <= "
		       "Section header string table index %d\n",
			elfhdr->e_shnum, elfhdr->e_shstrndx);
		bad = 1;
#endif
	}

	if (!bad) {
		return 0;
	}

	printf("%s ELFhdr(size %lu) BAD!\n", path, sizeof(Elf64_Ehdr));
	printf("Magic: ");
	for (i = 0; i < EI_NIDENT; i++) {
		printf("%x ", elfhdr->e_ident[i]);
	}
	printf("\n");
	printf("Class %d\n", elfhdr->e_ident[4]);
	printf("Data encode %d\n", elfhdr->e_ident[5]);
	printf("Version %d\n", elfhdr->e_ident[6]);

	printf("Type %d\n", elfhdr->e_type);
	printf("Machine %d\n", elfhdr->e_machine);
	printf("Version %d\n", elfhdr->e_version);
	printf("Entry %#lx\n", elfhdr->e_entry);
	printf("Start of program headers %lu\n", elfhdr->e_phoff);
	printf("Start of section headers %lu\n", elfhdr->e_shoff);
	printf("Flags %#x\n", elfhdr->e_flags);
	printf("Size of this header %d\n", elfhdr->e_ehsize);
	printf("Size of program headers %d\n", elfhdr->e_phentsize);
	printf("Number of program headers %d\n", elfhdr->e_phnum);
	printf("Size of section headers %d\n", elfhdr->e_shentsize);
	printf("Number of section headers %d\n", elfhdr->e_shnum);
	printf("Section header string table index %d\n", elfhdr->e_shstrndx);

	return 1;
}

static int is_rm_sysdir(char *cmd, char *dir)
{
        char *ptr = NULL;
        int len = strlen(dir);

        ptr = strstr(cmd, dir);
        /* 是中间的参数或结尾的参数 */
        if (ptr && (ptr[len] == ' ' || ptr[len] == 0)) {
                return 1;
        }

        return 0;
}

/*
 * 对危险命令的判断
 * rm对象为/,/root,/home,/boot,/etc
 * dd的目标对象为盘，如dd if=/dev/null of=/dev/sda
 * mv参数包含/dev/null
 */
int is_danger_cmd(char *cmd)
{
	char *firstblank = NULL;
	char *ptr = NULL, *devstr = NULL;
	struct stat st = {0};
	int len = 0;
	char devname[128] = {0};

	if (!cmd) {
		return 0;
	}
	firstblank = strchr(cmd, ' ');
	/* 只有命令，没有参数，这不符合预设的危险命令的用法 */
	if (!firstblank) {
		return 0;
	}

	ptr = strstr(cmd, "/dd ");
	if ((ptr && ptr + 3 == firstblank) || strncmp(cmd, "dd ", 3) == 0) {
		devstr = strstr(cmd, " of=/dev/");
		if (devstr) {
			devstr += 4;
			ptr = strchr(devstr, ' ');
			if (!ptr) {
				len = strlen(devstr);
			} else {
				len = ptr - devstr;
			}
			if (len >= 128) {
				len = 127;
			}
			memcpy(devname, devstr, len);
			devname[len] = 0;
			stat(devname, &st);
			if (S_ISBLK(st.st_mode)) {
				return 1;
			}
		}
		return 0;
	}

	ptr = strstr(cmd, "/mv ");
	if ((ptr && ptr + 3 == firstblank) || strncmp(cmd, "mv ", 3) == 0) {
		if (strstr(cmd, " /dev/null")) {
			return 1;
		}
		return 0;
	}

	ptr = strstr(cmd, "/rm ");
	if ((ptr && ptr + 3 == firstblank) || strncmp(cmd, "rm ", 3) == 0) {
		printf("task args hit rm (danger_on: %d) ..., %s\n", prule.danger_on, cmd);
		if (is_rm_sysdir(cmd, " /")     ||
		    is_rm_sysdir(cmd, " /etc")  ||
		    is_rm_sysdir(cmd, " /boot") ||
		    is_rm_sysdir(cmd, " /root") ||
		    is_rm_sysdir(cmd, " /home") ||
			is_rm_sysdir(cmd, " /home/test")) {
			return 1;
		}
		return 0;
	}

        return 0;
}

int is_chopper_cmd(char *cmd)
{
	if (strstr(cmd, "echo [S]") && strstr(cmd, "echo [E]")) {
		return 1;
	}
	return 0;
}

/* 检测是否危险命令。返回0，正常；1，危险 */
int is_danger(taskstat_t *taskstat)
{
	if (!prule.danger_on || !taskstat || taskstat->flags & TASK_DOCKER) {
		return 0;
	}
	if (taskstat->pid < RESERVED_PIDS) {
		return 0;
	}
	/* 危险：危险列表中的命令 */
	if (is_danger_cmd(taskstat->args)) {
		return 1;
	}

	return 0;
}

#define is_dir(cwd, dir, len) (strncmp(cwd, dir, len) == 0 && (cwd[len] == '/' || cwd[len] == 0))
static int in_unexec_dirs(char *cmd, char *cwd)
{
	if (!cmd || !cwd) {
		return 0;
	}

	//TODO 1、把cwd和cmd拼接起来。2、检查cmd的目录是否任意人可读写
	if (cmd[0] == '/') {
                if (strncmp(cmd, "/tmp/", 5) == 0 ||
                    strncmp(cmd, "/var/log/", 9) == 0 ||
                    strncmp(cmd, "/var/tmp/", 9) == 0) {
                        return 1;
                }
	} else {
                if (is_dir(cwd, "/tmp", 4) ||
                    is_dir(cwd, "/var/log", 8) ||
                    is_dir(cwd, "/var/tmp", 8)) {
                        return 1;
                }
	}

	return 0;
}

/* 检测是否异常命令。返回0，正常；1，异常 */
static int is_abnormal(taskstat_t *taskstat)
{
	if (!prule.abnormal_on || !taskstat || taskstat->flags & TASK_DOCKER) {
		return 0;
	}
	if (taskstat->pid < RESERVED_PIDS) {
		return 0;
	}

	/* 异常：在特殊目录下的命令 */
	if (in_unexec_dirs(taskstat->cmd, taskstat->cwd)) {
		return 1;
	}

	return 0;
}

static ino_t is_pipe(char *path)
{
	struct stat st = {0};

	if (!path) {
		return 0;
	}

	if (stat(path, &st) == 0) {
		if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
			return st.st_ino;
		}
	}

	return 0;
}

static int get_ip_by_pipe(pid_t pid, sockinfo_t *info, ino_t inode)
{
	int i = 0, start = 0, end = 0, match = 0;
	char path[S_PROCPATHLEN] = {0};
	char fdpath[S_PROCPATHLEN] = {0};
	DIR *dirp = NULL;
	struct dirent *fdent = NULL;
	struct stat st = {0};

	if (pid < RESERVED_PIDS) {
		return 0;
	}

	start = pid - 10;
	end = pid + 10;
	for (i = start; i <= end; i++) {
		/* 这里不能取taskstat的ip，如果在远程登录窗口做反弹shell，taskstat的ip可能是ssh的ip */

		snprintf(path, S_PROCPATHLEN, "/proc/%d/fd", i);
		dirp = sniper_opendir(path, INFO_GET);
		if (!dirp) {
			continue;
		}

		match = 0;
		while ((fdent = readdir(dirp)) != NULL) {
			snprintf(fdpath, S_PROCPATHLEN, "/proc/%d/fd/%s", i, fdent->d_name);
			if (stat(fdpath, &st) == 0 && st.st_ino == inode) {
				match = 1;
				break;
			}
		}
		sniper_closedir(dirp, INFO_GET);

		if (match) {
			if (get_process_socket_info(i, info, 1) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

static int check_shell_pipe(taskstat_t *taskstat, sockinfo_t *info)
{
	char path[S_PROCPATHLEN] = {0};
	char fdpath[S_PROCPATHLEN] = {0};
	DIR *dirp = NULL;
	struct dirent *fdent = NULL;
	ino_t inode = 0;
	pid_t pid = 0;

	if (!taskstat || !info)  {
		return -1;
	}

	pid = taskstat->pid;
	snprintf(path, S_PROCPATHLEN, "/proc/%d/fd", pid);
	dirp = sniper_opendir(path, INFO_GET);
	if (!dirp) {
		return -1;
	}

	while ((fdent = readdir(dirp)) != NULL) {
		snprintf(fdpath, S_PROCPATHLEN, "/proc/%d/fd/%s", pid, fdent->d_name);
		inode = is_pipe(fdpath);
		if (inode != 0 && get_ip_by_pipe(pid, info, inode)) {
			sniper_closedir(dirp, INFO_GET);
			return 0;
		}
	}

	sniper_closedir(dirp, INFO_GET);
	return -1;
}

#if 0
static void get_ip_by_pipe(pid_t pid, char *pipestr, sockinfo_t *info)
{
	int i = 0, start = 0, end = 0;

	if (pid < RESERVED_PIDS) {
		return;
	}

	start = pid - 10;
	end = pid + 10;
	for (i = start; i <= end; i++) {
		/* 这里不能取taskstat的ip，如果在远程登录窗口做反弹shell，taskstat的ip可能是ssh的ip */

		if (get_process_socket_info(i, info, 1) == 0) {
			return;
		}
	}
}

static int check_shell_stdio(pid_t pid, sockinfo_t *info)
{
	char fdpath0[S_PROCPATHLEN] = {0};
	char fdpath1[S_PROCPATHLEN] = {0};
	char path_stdin[S_PATHLEN] = {0};
	char path_stdout[S_PATHLEN] = {0};
	int count = 0;

	if (!info)  {
		return -1;
	}

	snprintf(fdpath0, S_PROCPATHLEN, "/proc/%d/fd/0", pid);
	readlink(fdpath0, path_stdin, S_PATHLEN-1);

	snprintf(fdpath1, S_PROCPATHLEN, "/proc/%d/fd/1", pid);
	readlink(fdpath1, path_stdout, S_PATHLEN-1);

	if (is_pipe(path_stdin)) {
		count++;
		get_ip_by_pipe(pid, path_stdin, info);
		if (info->dst_ip[0]) {
			INFO("reverse shell check: %s -> %s, ip: %s\n", fdpath0, path_stdin, info->dst_ip);
			return 0;
		}
	}

	if (is_pipe(path_stdout)) {
		count++;
		get_ip_by_pipe(pid, path_stdout, info);
		if (info->dst_ip[0]) {
			INFO("reverse shell check: %s -> %s, ip: %s\n", fdpath1, path_stdout, info->dst_ip);
			return 0;
		}
	}

	if (count == 2) {
		INFO("reverse shell check: %s -> %s\n", fdpath0, path_stdin);
		INFO("reverse shell check: %s -> %s\n", fdpath1, path_stdout);
		return 0;
	}

	return -1;
}
#endif

static int is_scripting_language(taskstat_t *taskstat)
{
	char *cmdname = safebasename(taskstat->cmd);

	if (!cmdname) {
		return 0;
	}

	/* 安装小皮面板过程中遇到过，对下面的命令
	   /usr/local/phpstudy/system/module/iostat | awk {print  $5 ,$6}
	   解析出了带端口127.0.0.1:8090->127.0.0.1:54104
	   为避免误报，对awk增加一个检测条件，命令行是否带getline
	 */
	if (strcmp(cmdname, "awk") == 0 || strcmp(cmdname, "gawk") == 0) {
		if (strstr(taskstat->args, "getline")) {
			return 1;
		}
		return 0;
	}

	if (strncmp(cmdname, "ruby", 4) == 0 || strcmp(cmdname, "tclsh") == 0) {
		return 1;
	}

	return 0;
}

static int is_listen_port(unsigned short port)
{
	int i = 0, match = 0;

	if (port) {
		pthread_rwlock_rdlock(&middleware_lock);
		for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++) {
			if (sniper_mid[i].pid && port == sniper_mid[i].port) {
				match = 1;
				break;
			}
		}
		pthread_rwlock_unlock(&middleware_lock);
	}

	return match;
}

/* 检查mypid是否为某个中间件进程mid_pid的子进程或兄弟线程 */
static int is_child_or_brother(pid_t mid_pid, pid_t mypid, char *name)
{
	int count = 0;
	pid_t tgid = 0, ppid = 0;
	char path[128] = {0};
	char line[S_LINELEN] = {0};
	FILE *fp = NULL;

	snprintf(path, sizeof(path), "/proc/%d/status", mypid);

	fp = fopen(path, "r");
	if (!fp) {
		DBG2(DBGFLAG_PROCESS, "check_behinder: open %s fail: %s\n", path, strerror(errno));
		return 0;
	}

	while (fgets(line, S_LINELEN, fp) != NULL) {
		if (count == 2) {
			break;
		}

		if (sscanf(line, "Tgid: %d", &tgid) == 1 ||
		    sscanf(line, "PPid: %d", &ppid) == 1) {
			count++;
			continue;
		}
	}

	fclose(fp);

	if (tgid == mid_pid) {
		DBG2(DBGFLAG_PROCESSDEBUG, "%s/%d is brother of %s/%d\n", name, mypid, name, mid_pid);
		return 1;
	}
	if (ppid == mid_pid) {
		DBG2(DBGFLAG_PROCESSDEBUG, "%s/%d is child of %s/%d\n", name, mypid, name, mid_pid);
		return 1;
	}

	return 0;
}

/* 检测冰蝎反弹shell: web服务程序有连出的网络连接 */
static int is_behinder_remoteshell(taskstat_t *taskstat, sockinfo_t *info)
{
	int i = 0;
	char *cmdname = NULL;

	if (!taskstat || !info) {
		return 0;
	}

	cmdname = safebasename(taskstat->cmd);
	for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++) {
		if (sniper_mid[i].pid == taskstat->pid) {
			break;
		}
		/*
		 * 与中间件进程的关系应当是父子进程，或兄弟线程
		 * 仅进程名会导致误报，因为同名进程可能是彼此完全无关的独立进程，特别是java进程
		 */
		if (strcmp(cmdname, sniper_mid[i].name) == 0 &&
		    is_child_or_brother(sniper_mid[i].pid, taskstat->pid, cmdname)) {
			break;
		}
	}
	if (i == SNIPER_MIDDLEWARE_NUM) { //不是中间件程序
		return 0;
	}

	/* 检测是否有连出的网络连接 */
	if (get_connout_socket_info(taskstat->pid, info, sniper_mid[i].port) < 0) {
		return 0;
	}

	/* 检测端口是否为http/https服务 */
	if (check_http_port(sniper_mid[i].port)) {
		return 1;
	}

	//TODO 中间件服务同时有外连，视为端口转发程序

	return 0;
}

int is_remoteshell(taskstat_t *taskstat)
{
	int match = 0;
	sockinfo_t info = {0};

	if (!prule.remote_execute_on || !taskstat || taskstat->flags & TASK_DOCKER) {
		return 0;
	}

	if (taskstat->pflags.shell) {
		if (get_process_socket_info(taskstat->pid, &info, 1) < 0 &&
		    check_shell_pipe(taskstat, &info) < 0) {
			return 0;
		}
		match = 1;
	} else if (is_scripting_language(taskstat)) {
		if (get_process_socket_info(taskstat->pid, &info, 1) < 0) {
			return 0;
		}
		match = 2;
	} else if (is_behinder_remoteshell(taskstat, &info)) {
		match = 3;
	}

	if (match) {
		/* 看起来不是有意义的对外连接属性 */
		if (is_listen_port(info.src_port) || info.dst_port == 0 || info.src_port < 1024 ||
		    strcmp(info.src_ip, "0.0.0.0") == 0 || strncmp(info.src_ip, "127.", 4) == 0 ||
		    strcmp(info.dst_ip, "0.0.0.0") == 0 || strncmp(info.dst_ip, "127.", 4) == 0 ||
		    strcmp(info.src_ip, info.dst_ip) == 0) {
                        return 0;
                }

		/* ZX20220420 看看还有没有java反弹shell事件的误报 */
		if (strcmp(safebasename(taskstat->cmd), "java") == 0) {
			INFO("Warning: remoteshell %s(%d) may a false positive\n", taskstat->args, taskstat->pid);
			//return 0;
		}

                strncpy(taskstat->ip, info.dst_ip, S_IPLEN-1);
                strncpy(taskstat->myip, info.src_ip, S_IPLEN-1);
		taskstat->port = info.dst_port;
		taskstat->myport = info.src_port;

		INFO("%s(%d) is remoteshell. type %d\n", taskstat->args, taskstat->pid, match);
		return match;
        }

        return 0;
}

/*
 * 用在初始化阶段，检查当前已经存在的进程
 * 事件优先级：违规、信任、过滤、webshell、webexecute、危险、远程执行、端口转发
 * 检查所有可能的不冲突的事件类型，违规、信任、过滤、危险与低级事件类型冲突
 * 发送日志时才做阻断并确定按哪种事件报，太早做阻断，会导致子进程因被init进程接管，而无法从真正的父进程继承事件类型
 */
void set_taskstat_flags(taskstat_t *taskstat, taskstat_t *ptaskstat)
{
	int ret = 0;
	unsigned long pflags = 0;

	if (ptaskstat) {
		pflags = ptaskstat->flags;
	}

	if (pflags & TASK_TTY) {
		taskstat->flags |= TASK_TTY;
	}
	if (pflags & TASK_CRON) {
		taskstat->flags |= TASK_CRON;
	}

	if (is_black_cmd(taskstat)) {
		taskstat->flags |= TASK_BLACK;
		return;
	}

	if (is_filter_cmd(taskstat)) {
		taskstat->flags |= TASK_DROP;
		return;
	}

	//if (pflags & TASK_WEBEXECUTE) {
	//	taskstat->flags |= TASK_WEBEXECUTE;
	//}

	if (is_port_forward(taskstat, 0)) {
		taskstat->flags |= TASK_PORT_FORWARD;
	}

	if (is_danger(taskstat)) {
		taskstat->flags |= TASK_DANGER;
		return;
	}

	if (is_abnormal(taskstat)) {
		taskstat->flags |= TASK_ABNORMAL;
		return;
	}

	ret = is_remoteshell(taskstat);
	if (ret > 0) {
		if (ret == 3) {
			INFO("%s may remote shell\n", taskstat->args);
			taskstat->flags |= TASK_MAY_REMOTE_EXECUTE;
		} else {
			INFO("%s remote shell type %d\n", taskstat->args, ret);
			taskstat->flags |= TASK_REMOTE_EXECUTE;
		}
	}
}

//TODO 考虑其他线程调用时，返回带锁taskstat，并在处理过程中锁ptaskstat
taskstat_t *init_one_process(pid_t pid)
{
	pid_t ppid = 0;
	taskstat_t *taskstat = NULL;
	taskstat_t *ptaskstat = NULL;

	if (pid <= 0) {
		MON_ERROR("skip alloc taskstat, bad pid %d\n", pid);
		return NULL;
	}

	taskstat = alloc_taskstat();
	if (!taskstat) {
		MON_ERROR("alloc taskstat %d fail: no memory\n", pid);
		return NULL;
	}

	taskstat->pid = pid;

	if (get_proc_stat(taskstat) < 0 || get_proc_status(taskstat) < 0) {
		free_taskstat(taskstat);
		return NULL;
	}

	get_proc_exe(pid, taskstat->cmd);
	taskstat->cmdlen = strlen(taskstat->cmd);

	get_proc_cmdline(pid, taskstat->args, S_ARGSLEN);
	if (taskstat->args[0] == 0) { //没取到命令行，用命令替代
		snprintf(taskstat->args, S_ARGSLEN, "%s", taskstat->cmd);
	}
	taskstat->argslen = strlen(taskstat->args);

	get_proc_cwd(taskstat);

	/* 如果/proc/PID/exe是/bin/bash，那么这就是一个shell
	   bash -c cmd的exe是cmd，如bash -c "sleep 60"的exe是/bin/sleep */
	if (is_shell(taskstat->args) > 0) {
		taskstat->pflags.shell = 1;
	} else if (is_bash_waiting_cmd(taskstat->cmd, taskstat->pid)) {
		INFO("init_one_process: seem %s/%d as shell\n", taskstat->args);
		taskstat->pflags.shell = 1;
	}
	//TODO taskstat_parse_pipeargs(taskstat);

	uidtoname(taskstat->uid, taskstat->user);

	ppid = taskstat->pinfo.task[0].pid;
	if (ppid == 0) {
		if (taskstat->pid > 2) {
			MON_ERROR("%s(%d) parent is 0 process\n",
				  taskstat->args, taskstat->pid);
			ptaskstat = NULL;
		} else {
			ptaskstat = idle_taskstat;
		}
	} else if (ppid == taskstat->pid) {
		if (ppid <= 2) {
			INFO("Warning: %s(%d) parent is self, set parent to 0 process\n",
			     taskstat->args, taskstat->pid);
			taskstat->pinfo.task[0].pid = 0;
			ptaskstat = idle_taskstat;
		} else {
			INFO("Warning: %s(%d) parent is self, set parent to init\n",
			     taskstat->args, taskstat->pid);
			taskstat->pinfo.task[0].pid = 1;
			ptaskstat = get_taskstat_nolock(1, PROCESS_GET);
		}
	} else {
		ptaskstat = get_taskstat_nolock(ppid, PROCESS_GET);
		if (!ptaskstat) {
			INFO("%s(%d) no parent %d taskstat, build it first\n",
			     taskstat->args, taskstat->pid, ppid);
			if (!init_one_process(ppid)) {
				INFO("build parent %d taskstat fail, "
				     "set %s(%d) parent taskstat to init\n",
				     ppid, taskstat->args, taskstat->pid);
				taskstat->pinfo.task[0].pid = 1;
			}
			ptaskstat = get_taskstat_nolock(ppid, PROCESS_GET);
		}
	}
	if (!ptaskstat) {
		MON_ERROR("init %s(%d) taskstat, no ptaskstat\n",
			  taskstat->args, taskstat->pid);
		free_taskstat(taskstat);
		return NULL;
	}

	get_proc_tty(taskstat);

	get_mem_usage(taskstat);
	count_file_hash(taskstat);

	set_taskuuid(taskstat->uuid, taskstat->proctime, taskstat->pid, 0);
	add_tasklist_tail(taskstat);

	set_taskstat_flags(taskstat, ptaskstat);

        /* 继承父进程的session_uuid，否则本进程uuid作为session_uuid */
        if (ptaskstat->session_uuid[0] != 0) {
                memcpy(taskstat->session_uuid, ptaskstat->session_uuid, S_UUIDLEN);
        } else if (taskstat->flags & TASK_TTY) {
		get_session_uuid(taskstat->tty, taskstat->session_uuid);
        }

	return taskstat;
}

/*
 * 遇到过问题：程序一启动，就接收到管控端的卸载命令，结果程序结束不了
 * 原因是死锁，进程线程正在初始化，占用着某把锁的时候，被cancel掉了，导致fini_psbuf取不到锁
 * 因此，程序退出（包括升级前退出）时，不需要管锁，这是工作线程都已经结束了。
 * 正常运行中关闭进程引擎的时候，才需要考虑锁，因为其他线程可能在使用tasklist
 */
void fini_psbuf(int lockflag)
{
	int i = 0, size = 0;
	taskstat_t *taskstat = NULL, *tmp = NULL;
	exehash_t *exehash = NULL, *hashnext = NULL;

	tasklist_ready = 0;

	if (tasklist) {
		for (i = 0; i < TASKMAX; i++) {
			if (lockflag) {
				pthread_rwlock_wrlock(&tasklist[i].lock);
			}
			list_for_each_entry_safe(taskstat, tmp, &tasklist[i].queue, list) {
				list_del(&taskstat->list);
				free_taskstat(taskstat);
			}
			if (lockflag) {
				pthread_rwlock_unlock(&tasklist[i].lock);
			}
			pthread_rwlock_destroy(&tasklist[i].lock);
		}

		size = TASKMAX * sizeof(struct task_list);
		sniper_free(tasklist, size, PROCESS_GET);
	}

	if (idle_taskstat) {
		sniper_free(idle_taskstat, sizeof(struct task_status), PROCESS_GET);
		idle_taskstat = NULL;
		taskstat_num--;
	}

	if (exelist) {
		for (i = 0; i < EXEMAX; i++) {
			hashnext = exelist[i].head;
			while (hashnext) {
				exehash = hashnext;
				hashnext = exehash->next;

				sniper_free(exehash, sizeof(struct exe_hash), PROCESS_GET);
				exehash_num--;
			}
			exelist[i].head = NULL;
		}

		size = EXEMAX * sizeof(struct exe_list);
		sniper_free(exelist, size, PROCESS_GET);
	}
}

int is_kernel_thread(pid_t pid)
{
	if (get_proc_ppid(pid) == 2) {
		return 1;
	}
	return 0;
}

//TODO 需要考虑tasklist锁，避免其他线程get_taskstat的时候，tasklist中途被释放
/* sniper启动时当前端点进程情况 */
int init_psbuf(void)
{
	int i = 0, pid = 0;
	DIR *procdirp = NULL;
	struct dirent *pident = NULL;
#ifdef INIT_PSBUF_WITH_THREAD
	DIR *taskdirp = NULL;
	struct dirent *childent = NULL;
	int childpid = 0;
	char taskdir[S_PROCPATHLEN] = {0};
#endif
	taskstat_t *taskstat = NULL;
	int tasklist_size = TASKMAX * sizeof(struct task_list);
	int exelist_size = EXEMAX * sizeof(struct exe_list);

	if (!tasklist) {
		tasklist = sniper_malloc(tasklist_size, PROCESS_GET);
		if (!tasklist) {
                	MON_ERROR("init tasklist fail: no memory\n");
			return -1;
		}
		for (i = 0; i < TASKMAX; i++) {
			pthread_rwlock_init(&tasklist[i].lock, NULL);
			INIT_LIST_HEAD(&tasklist[i].queue);
		}
	}

	if (!exelist) {
		exelist = sniper_malloc(exelist_size, PROCESS_GET);
		if (!exelist) {
                	MON_ERROR("init exelist fail: no memory\n");
			sniper_free(tasklist, tasklist_size, PROCESS_GET);
			return -1;
		}
	}

	taskstat = alloc_taskstat();
	if (!taskstat) {
		MON_ERROR("init taskstat fail: no memory\n");
		sniper_free(tasklist, tasklist_size, PROCESS_GET);
		sniper_free(exelist, exelist_size, PROCESS_GET);
		taskstat_num--;
		return -1;
	}
	taskstat->pid = 0;
	strcpy(taskstat->user, "root");
	snprintf(taskstat->uuid, S_UUIDLEN, "%lu-0", uptime_sec);
	strcpy(taskstat->cmd, "Linux-Kernel");
	strcpy(taskstat->args, "Linux-Kernel");
	strcpy(taskstat->cwd, "/");
	taskstat->cmdlen = strlen(taskstat->cmd);
	taskstat->argslen = strlen(taskstat->args);
	taskstat->cwdlen = strlen(taskstat->cwd);
	idle_taskstat = taskstat;

	procdirp = sniper_opendir("/proc", PROCESS_GET);
	if (!procdirp) {
                MON_ERROR("open /proc fail: %s\n", strerror(errno));
		fini_psbuf(0);
		return -1;
	}

	/*
	 * 遍历/proc获得当前进程信息
	 * 主进程初始化，此时还没有创建其他子线程，因此不需要锁
	 */
	while ((pident = readdir(procdirp))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue; //忽略非进程项信息
		}

		pid = atoi(pident->d_name);
		if (pid <= 0) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

#ifdef INIT_PSBUF_WITH_THREAD
		snprintf(taskdir, S_PROCPATHLEN, "/proc/%d/task", pid);
		taskdirp = sniper_opendir(taskdir, PROCESS_GET);
		if (!taskdirp) {
			/* 进程可能恰好退出了，初始化的过程中不报错 */
			continue;
		}

		/* 遍历/proc/PID/task获得该进程的所有子进程 */
		while ((childent = readdir(taskdirp))) {
			if (childent->d_name[0] < '0' ||
			    childent->d_name[0] > '9') {
				continue;
			}

			childpid = atoi(childent->d_name);
			if (childpid <= 0) {
				MON_ERROR("init_psbuf: atoi(%s) %d\n",
					  childent->d_name, childpid);
				continue;
			}
			init_one_process(childpid);
		}

		sniper_closedir(taskdirp, PROCESS_GET);
#else
		/* 不报告子进程 */
		init_one_process(pid);
#endif
	}

	sniper_closedir(procdirp, PROCESS_GET);
	tasklist_ready = 1;
	INFO("tasklist inited\n");
	return 0;
}

void check_exit_process(void)
{
	int i = 0;
	taskstat_t *taskstat = NULL, *tmp = NULL;

	if (!tasklist) {
		return;
	}

	for (i = 0; i < TASKMAX; i++) {
		pthread_rwlock_wrlock(&tasklist[i].lock);
		list_for_each_entry_safe(taskstat, tmp, &tasklist[i].queue, list) {
			if (mykill(taskstat->pid, 0) == 0) {
				continue;
			}

			if (taskstat->refcount) {
				MON_ERROR("%s(%d) exited, but ref %d, skip free\n",
					taskstat->args, taskstat->pid, taskstat->refcount);
				continue;
			}

			set_taskstat_exit(taskstat);
		}
		pthread_rwlock_unlock(&tasklist[i].lock);
	}
}

void stop_systeminformation(void)
{
	FILE *fp = NULL;
	pid_t pid = 0;
	char cmd[PATH_MAX] = {0};

	fp = fopen(SYSINFO_PIDFILE, "r");
	if (fp) {
		fscanf(fp, "%d", &pid);
		fclose(fp);
	}

	if (pid > 0) {
		get_proc_exe(pid, cmd);
		if (strcmp(cmd, "/opt/snipercli/systeminformation") == 0) {
			INFO("stop systeminformation process %d\n", pid);
			mykill(pid, SIGKILL);
		}
	}
}
