#include "interface.h"

#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/pipe_fs_i.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
#include <linux/fdtable.h>  //低版本无此文件，都包含在file.h里
#endif

#include <linux/ipv6.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
#include <net/tcp_states.h>
#endif

#if 1
#include <linux/ctype.h>
#else
int isspace(char c)
{
	/* space, form-feed, newline, carriage return, horizontal tab, vertical tab */
	if (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v') {
		return 1;
	}
	return 0;
}
#endif

#include <net/ipv6.h>
#define MY_IP6STR(addr) (addr)->s6_addr32[0],(addr)->s6_addr32[1],(addr)->s6_addr32[2],(addr)->s6_addr32[3]
void my_addr2ip(void *addr, char *ip, int family)
{
	if (family == AF_INET) {
		snprintf(ip, S_IPLEN, "%u.%u.%u.%u", myaddr2ip(addr));
	} else {
		struct in6_addr *addr6 = (struct in6_addr *)addr;
		snprintf(ip, S_IPLEN, "%08X%08X%08X%08X",
			addr6->s6_addr32[0], addr6->s6_addr32[1],
			addr6->s6_addr32[2], addr6->s6_addr32[3]);
	}
}
int sniper_ipv6_addr_loopback(const struct in6_addr *a)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
        return ((a->s6_addr32[0] | a->s6_addr32[1] |
                 a->s6_addr32[2] | (a->s6_addr32[3] ^ htonl(1))) == 0);
#else
	return ipv6_addr_loopback(a);
#endif
}

/* 消除头部的空格符 */
char *skip_headspace(char *str)
{
        char *ptr = str;

        while (isspace(*ptr)) {
                ptr++;
        }
        return ptr;
}
/* 消除尾部的空格符、回车和换行符 */
void delete_tailspace(char *str)
{
        int i = 0, len = strlen(str);

        for (i = len-1; i >= 0; i--) {
                if (!isspace(str[i])) {
                        return;
                }
                str[i] = 0;
        }
}

/* centos5没有IS_ERR_OR_NULL，仿造is_err_or_null供所有内核版本用 */
int is_err_or_null(unsigned long addr, char *desc)
{
	if (addr == 0) {
		return 1;
	}
	if (IS_ERR_VALUE(addr)) {
		myprintk("%s bad value %ld\n", desc, PTR_ERR((void *)addr));
		return 1;
	}

	/*
	 * 检测是否非法的内核虚地址
	 * x86和飞腾、龙芯的是0xffff开头，申威的是0xfff开头
	 * 故用0xfff0000000000000兼容所有CPU架构
	 */
	if ((addr & 0xfff0000000000000) != 0xfff0000000000000) {
		myprintk("%s bad value %#lx\n", desc, addr);
		return 1;
	}
	return 0;
}

/* x86取消内存写保护和恢复写保护 */
#if defined(__x86_64__) || defined(__i386__)
unsigned long original_cr0 = 0;
unsigned long my_force_order = 0;

static inline unsigned long sniper_read_cr0(void)
{
        unsigned long val = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
        val = read_cr0();
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
        asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (my_force_order));
#else
        val = read_cr0();
#endif

        return val;
}

/* 5.3以后native_write_cr0()禁止屏蔽X86_CR0_WP位，所以这里实现一个write_cr0 */
static inline void sniper_write_cr0(unsigned long val)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
	write_cr0(val);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
	asm volatile("mov %0,%%cr0": "+r" (val), "+m" (my_force_order));
#else
	asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
#endif
}

void disable_memory_write_protection(void)
{
	original_cr0 = sniper_read_cr0();
	sniper_write_cr0(original_cr0 & ~0x00010000);
}
void restore_memory_write_protection(void)
{
	sniper_write_cr0(original_cr0);
}

#elif defined(__aarch64__)
/* arm64取消内存写保护 */
/* 4.6.0以后才引入ro_after_init的内存只读保护特性 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
void disable_memory_write_protection(void)
{
}
void restore_memory_write_protection(void)
{
}
#else
int write_protection_disabled = 0;
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata = 0, end_rodata = 0;
#define section_size  (end_rodata - start_rodata)
void disable_memory_write_protection(void)
{
	if (start_rodata == 0) {
		update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
		start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
		end_rodata = (unsigned long)kallsyms_lookup_name("__end_rodata");
	}
	if (update_mapping_prot == 0 || start_rodata == 0 || end_rodata == 0) {
		myprintk("skip disable_memory_write_protection: func %p, start %#lx, end %#lx\n",
			update_mapping_prot, start_rodata, end_rodata);
		return;
	}
	write_protection_disabled = 1;
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL);
}
void restore_memory_write_protection(void)
{
	if (write_protection_disabled) {
		write_protection_disabled = 0;
		update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL_RO);
	}
}
#endif

#else //mips & sw
void disable_memory_write_protection(void)
{
}
void restore_memory_write_protection(void)
{
}
#endif

/* 内核没有export pid_max symbol */
int my_pid_max = 32768;

int interrupt_debug = 10;
void current_interrupt_status(char *str)
{
	unsigned long now_in_irq = in_irq();
	unsigned long now_in_softirq = in_softirq();
	unsigned long now_in_interrupt = in_interrupt();
	int now_in_atomic = in_atomic();

	/*
	 * 当前处于中断状态时，报告一下。
	 * 如果in_atomic，但无in_interrupt，则当前状态是禁止了进程调度。
	 * 不管是否处于中断，总是打10次，用来确认本函数确实被调用了。
	 */
	if (interrupt_debug > 0 || now_in_irq || now_in_softirq || now_in_interrupt || now_in_atomic) {
		printk("%s: %s(%d) in_irq %lu, in_softirq %lu, in_interrupt %lu, in_atomic %d\n",
			str, current->comm, current->pid,
			now_in_irq, now_in_softirq, now_in_interrupt, now_in_atomic);
		if (interrupt_debug > 0) {
			interrupt_debug--;
		}
	}
}

char *safebasename(char *path)
{
	char *ptr = NULL;

        if (!path) {
                return NULL;
        }

        ptr = strrchr(path, '/');
        if (ptr) {
                ptr++;
        } else {
                ptr = path;
        }

	return ptr;
}

/* 获取路径的目录名称 */
void safedirname(char *path, char *dir, int dir_len)
{
	char *ptr = NULL;

	if(path == NULL || dir == NULL) {
		return;
	}

	snprintf(dir, dir_len, "%s", path);
	ptr = strrchr(dir, '/');
	if (ptr) {
		*(ptr+1) = 0;  // /a -> /; /a/b/ ->/a/
	}
}

/*
 * CentOS/Redhat 6.0/6.1，__put_task_struct没输出，
 * 编译会报__put_task_struct undefined
 * insmod 6.2上编译的模块，报Unknown symbol
 * 故对内核版本2.6.32单独处理
 */
#include <linux/sched.h>
void my_put_task_struct(struct task_struct *t)
{
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	put_task_struct_t func = (put_task_struct_t)put_task_struct_addr;

	if (atomic_dec_and_test(&t->usage)) {
		func(t);
	}
#else
	put_task_struct(t);
#endif
}

struct task_struct *get_task_from_pid(pid_t pid)
{
	struct task_struct *task;

	rcu_read_lock();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	task = find_task_by_pid_type(PIDTYPE_PID, pid);
#else
	task = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
#endif
	if (task) {
		if (pid_alive(task)) {
			get_task_struct(task);
		} else {
			task = NULL;
		}
	}
	rcu_read_unlock();

	return task;
}

static unsigned long uptime_nsec(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	struct timespec ts = {0};
	do_posix_clock_monotonic_gettime(&ts);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	struct timespec ts = {0};
	get_monotonic_boottime(&ts);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
	struct timespec64 ts = {0};
	get_monotonic_boottime64(&ts);
#else
	struct timespec64 ts = {0};
	ktime_get_boottime_ts64(&ts);
#endif
	return (ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec);
}
static unsigned long currenttime_nsec(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
	struct timespec now = current_kernel_time();
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
	struct timespec64 now = current_kernel_time64();;
#else
	struct timespec64 now = {0};
	ktime_get_coarse_real_ts64(&now);
#endif
	return (now.tv_sec * NSEC_PER_SEC + now.tv_nsec);
}

/* 3.17以后，start_time是Monotonic time，不包含休眠的时间，
   real_start_time是boot time，包含休眠的时间 */
unsigned long parent_nsec(void)
{
	struct task_struct *parent = NULL;
	unsigned long parenttime = 0;                     //进程启动的时刻，相对主机开机
	unsigned long uptime = uptime_nsec();             //主机运行的时长
	unsigned long currenttime = currenttime_nsec();   //当前真实时间

        parent = current->parent;
        get_task_struct(parent);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	parenttime = parent->start_time.tv_sec * NSEC_PER_SEC + parent->start_time.tv_nsec;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	parenttime = parent->real_start_time.tv_sec * NSEC_PER_SEC + parent->real_start_time.tv_nsec;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)
	parenttime = parent->real_start_time;
#else
	parenttime = parent->start_boottime;
#endif
	my_put_task_struct(parent);

	return (currenttime - uptime + parenttime);
}

/* 真实世界时间 */
void sniper_do_gettimeofday(struct timeval *tv)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	do_gettimeofday(tv);
#else
	struct timespec64 ts = {0};
	ktime_get_real_ts64(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec/1000;
#endif
}

/* 主机运行时长，这是一个相对时间，主机时间回卷不影响这个值，
   适用于锁ip这样的场景，主机时间修改，不会导致提前误解锁 */
time_t sniper_uptime(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	struct timespec ts = {0};
	do_posix_clock_monotonic_gettime(&ts);
	return ts.tv_sec;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	struct timespec ts = {0};
	get_monotonic_boottime(&ts);
	return ts.tv_sec;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
	struct timespec64 ts = {0};
	get_monotonic_boottime64(&ts);
	return ts.tv_sec;
#else
	struct timespec64 ts = {0};
	ktime_get_boottime_ts64(&ts);
	return ts.tv_sec;
#endif
}

/* 核心没有输出这个函数，拷贝过来 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static u64 my_nsec_to_clock_t(u64 x)
{
#if (NSEC_PER_SEC % USER_HZ) == 0
        do_div(x, (NSEC_PER_SEC / USER_HZ));
#elif (USER_HZ % 512) == 0
        x *= USER_HZ/512;
        do_div(x, (NSEC_PER_SEC / 512));
#else
        /*
         * max relative error 5.7e-8 (1.8s per year) for USER_HZ <= 1024,
         * overflow after 64.99 years.
         * exact for HZ=60, 72, 90, 120, 144, 180, 300, 600, 900, ...
         */
        x *= 9;
        do_div(x, (unsigned long)((9ull * NSEC_PER_SEC + (USER_HZ/2)) /
                                  USER_HZ));
#endif
        return x;
}
#else
static u64 my_nsec_to_clock_t(u64 x)
{
#if (NSEC_PER_SEC % USER_HZ) == 0
	return div_u64(x, NSEC_PER_SEC / USER_HZ);
#elif (USER_HZ % 512) == 0
	return div_u64(x * USER_HZ / 512, NSEC_PER_SEC / 512);
#else
	/*
         * max relative error 5.7e-8 (1.8s per year) for USER_HZ <= 1024,
         * overflow after 64.99 years.
         * exact for HZ=60, 72, 90, 120, 144, 180, 300, 600, 900, ...
         */
	return div_u64(x * 9, (9ull * NSEC_PER_SEC + (USER_HZ / 2)) / USER_HZ);
#endif
}
#endif
unsigned long long get_process_time(struct task_struct *task)
{
	unsigned long long start_time = 0;

	if (!task) {
		return 0;
	}

	/* convert nsec -> ticks */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	start_time =
		(unsigned long long)task->start_time.tv_sec * NSEC_PER_SEC
				+ task->start_time.tv_nsec;
	start_time = my_nsec_to_clock_t(start_time);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	start_time =
		(unsigned long long)task->real_start_time.tv_sec * NSEC_PER_SEC
				+ task->real_start_time.tv_nsec;
	start_time = my_nsec_to_clock_t(start_time);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)
	start_time = my_nsec_to_clock_t(task->real_start_time);
#else
	start_time = my_nsec_to_clock_t(task->start_boottime);
#endif

	return start_time;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
static int count_open_files(struct fdtable *fdt)
{
	int size = fdt->max_fds;
	int i = 0;

	/* Find the last open fd */
	for (i = size/(8*sizeof(long)); i > 0; ) {
		if (fdt->open_fds->fds_bits[--i])
			break;
	}
	i = (i+1) * 8 * sizeof(long);
	return i;
}
#else
static int count_open_files(struct fdtable *fdt)
{
	int size = fdt->max_fds;
	int i = 0;

	/* Find the last open fd */
	for (i = size / BITS_PER_LONG; i > 0; ) {
		if (fdt->open_fds[--i])
			break;
	}
	i = (i + 1) * BITS_PER_LONG;
	return i;
}
#endif

struct file *my_fcheck_files(struct files_struct *files, unsigned int fd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
        return fcheck_files(files, fd);
#else
        return files_lookup_fd_locked(files, fd);
#endif
}

static int is_shell(char *comm)
{
	if (strcmp(comm, "bash") == 0 || strcmp(comm, "sh") == 0 ||
	    strcmp(comm, "csh") == 0 || strcmp(comm, "ksh") == 0 ||
	    strcmp(comm, "dash") == 0) {
		return 1;
	}
	return 0;
}
int parent_is_shell_script(void)
{
        int i = 0, script = 0, pfds = 0;
        struct task_struct *parent = NULL;
        struct files_struct *pfiles = NULL;
        struct fdtable *pfdt = NULL;
	struct file *fp = NULL;
	struct inode *inode = NULL;

        parent = current->parent;
        get_task_struct(parent);
        task_lock(parent); //保护parent->files

        pfiles = parent->files;
        if (pfiles) {
                spin_lock(&pfiles->file_lock);

                pfdt = files_fdtable(pfiles);
                if (pfdt) {
			/* 检查是否有普通文件close_on_exec，有则视其为脚本文件 */
                        pfds = count_open_files(pfdt);
                        for (i = 0; i < pfds; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
                                if (FD_ISSET(i, pfdt->close_on_exec))
#else
                                if (test_bit(i, pfdt->close_on_exec))
#endif
				{
					fp = my_fcheck_files(pfiles, i);
					if (!sniper_badptr(fp) && !sniper_badptr(fp->f_dentry)) {
						inode = fp->f_dentry->d_inode;
						if (!sniper_badptr(inode) && S_ISREG(inode->i_mode)) {
                                        		script = 1;
                                        		break;
                                		}
                                	}
                                }
                        }
                }

                spin_unlock(&pfiles->file_lock);
        }

        task_unlock(parent);
        my_put_task_struct(parent);

        return script;
}

/*
 * 与父进程比较，打开的fd是否一样多
 * 对于shell脚本ash执行命令cmd的场景；
 *     sh进程打开ash，读取ash的内容，创建子进程执行cmd。子进程在执行cmd前会关闭ash
 */
int diff_fds_from_parent(void)
{
	int diff = 1, count = 0, fds = 0, pfds = 0;
	struct task_struct *parent = NULL;
	struct files_struct *files = NULL, *pfiles = NULL;
	struct fdtable *fdt = NULL, *pfdt = NULL;

	task_lock(current); //保护current->files

	files = current->files;
	if (files) {
		spin_lock(&files->file_lock);

		fdt = files_fdtable(files);
		if (fdt) {
			parent = current->parent;
			get_task_struct(parent);
			task_lock(parent); //保护parent->files

			pfiles = parent->files;
			if (pfiles) {
				spin_lock(&pfiles->file_lock);

				pfdt = files_fdtable(pfiles);
				if (pfdt) {
					fds = count_open_files(fdt);
					pfds = count_open_files(pfdt);
					if (fds == pfds && pfdt->open_fds && fdt->open_fds) {
						count = fds / BITS_PER_BYTE;
						if (memcmp(pfdt->open_fds, fdt->open_fds, count) == 0) {
							diff = 0;
						}
					}
				}

				spin_unlock(&pfiles->file_lock);
			}

			task_unlock(parent);
			my_put_task_struct(parent);
		}

		spin_unlock(&files->file_lock);
	}

	task_unlock(current);

	return diff;
}

//TODO 从fd1取终端不准
///usr/bin/gedit --gapplication-service
/* 图形界面程序从fd1取终端，用于指示是系统启动的还是用户执行的 */
void get_tty_from_fd1(char *tty)
{
	struct files_struct *files = NULL;
	struct file *filp = NULL;
	struct inode *inode = NULL;
	int major = 0;

	/* 虽然感觉操作当前进程可以不需要锁保护，但加上似乎也没有坏处 */
	task_lock(current); //保护current->files
	files = current->files;
	if (!files) {
		task_unlock(current);
		return;
	}

	/* We don't take a ref to the file, so we must hold ->file_lock instead */
	spin_lock(&files->file_lock);

	filp = fget(1);
	if (!filp || !filp->f_dentry) {
		goto out;
	}
	inode = filp->f_dentry->d_inode;
	if (!inode) {
		goto out;
	}

	major = MAJOR(inode->i_rdev);
	if (major == PTY_SLAVE_MAJOR || major == TTY_MAJOR ||
	    (major >= UNIX98_PTY_SLAVE_MAJOR && major < UNIX98_PTY_SLAVE_MAJOR+8)) {
		strncpy(tty, filp->f_dentry->d_name.name, S_TTYLEN-1);
	}

out:
	if (filp) {
		fput(filp);
	}
	spin_unlock(&files->file_lock);
	task_unlock(current);
}

taskreq_t *init_taskreq(int flag)
{
	taskreq_t *req = NULL;

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_TASKREQ);
	if (!req) {
		myprintk("init_taskreq fail: no memory!\n");
		return NULL;
	}
	memset(req, 0, ARGS_LEN);

	sniper_do_gettimeofday(&req->event_tv);

	if (current->signal && current->signal->tty) {
		req->pflags.tty = 1;
		req->flags |= PSR_TTY;
		strncpy(req->tty, current->signal->tty->name, S_TTYLEN);
		req->tty[S_TTYLEN-1] = 0;
	} else {
		get_tty_from_fd1(req->tty);
		if (req->tty[0]) {
			req->pflags.tty = 1;
			req->flags |= PSR_TTY;
		}
	}

        req->uid = currentuid();
        req->euid = currenteuid();
	req->pid = current->pid;
	req->tgid = current->group_leader->pid;
	req->proctime = get_process_time(current);

	if (flag & INIT_WITH_PINFO) {
		get_parent_info(&req->flags, &req->pinfo);
		if (req->flags & PSR_CRON) {
			req->pflags.cron = 1;
		}
	}

	if (flag & INIT_WITH_CMD) {
		set_taskreq_cmd(req, current);
	}

	return req;
}

taskreq_t *init_taskreq_pid(pid_t pid)
{
	taskreq_t *req = NULL;
	struct task_struct *task = NULL;

	task = get_task_from_pid(pid);
	if (!task) {
		myprintk("init_taskreq_pid %d fail!\n", pid);
		return NULL;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_TASKREQ);
	if (!req) {
		myprintk("init_taskreq fail: no memory!\n");
		my_put_task_struct(task);
		return NULL;
	}
	memset(req, 0, ARGS_LEN);
	req->pid = pid;

	sniper_do_gettimeofday(&req->event_tv);

	if (task->signal && task->signal->tty) {
		req->pflags.tty = 1;
		req->flags |= PSR_TTY;
		strncpy(req->tty, task->signal->tty->name, S_TTYLEN);
		req->tty[S_TTYLEN-1] = 0;
	} else {
//TODO
#if 0
		get_tty_from_fd1_task(req->tty);
		if (req->tty[0]) {
			req->pflags.tty = 1;
			req->flags |= PSR_TTY;
		}
#endif
	}

	req->proctime = get_process_time(task);

	set_taskreq_cmd(req, task);

	my_put_task_struct(task);
	return req;
}

static void get_task_exe(taskreq_t *req, struct task_struct *task)
{
	char *cmd = NULL;
	struct file *exe_file = NULL;
	struct dentry *dentry = NULL;

	if (!req || !task) {
		return;
	}

	exe_file = my_get_mm_exe_file(task->mm);
	if (sniper_badptr(exe_file)) {
		cmd = &req->args;
//		strncpy(cmd, task->comm, S_COMMLEN);
		snprintf(cmd, S_COMMLEN, "%s", task->comm);
//		cmd[S_COMMLEN-1] = 0;
		return;
	}

	req->exe_file = exe_file;
	cmd = get_exe_file_path(exe_file, &req->args, S_CMDLEN);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dentry = exe_file->f_dentry;
#else
	dentry = exe_file->f_path.dentry;
#endif
	if (!sniper_badptr(dentry)) {
		if (!sniper_badptr(dentry->d_inode)) {
			req->exeino = dentry->d_inode->i_ino;
		}

		if (!cmd) {
			cmd = &req->args;
//			strncpy(cmd, dentry->d_name.name, S_COMMLEN);
			snprintf(cmd, S_COMMLEN, "%s", dentry->d_name.name);
//			cmd[S_COMMLEN-1] = 0;
		}
	}

	fput(exe_file);

	if (cmd) {
		if (exec_debug == PDEBUG_COMM && strcmp(safebasename(cmd), task->comm) != 0) {
			myprintk("%s(%d) exefile is %s\n", task->comm, task->pid, cmd);
		}
		return;
	}

	cmd = &req->args;
//	strncpy(cmd, task->comm, S_COMMLEN);
	snprintf(cmd, S_COMMLEN, "%s", task->comm);
//	cmd[S_COMMLEN-1] = 0;
}

void get_current_process(char *process, int len)
{
	char *cmd = NULL;
	struct file *exe_file = NULL;
	struct dentry *dentry = NULL;

	if (!process) {
		return;
	}

	exe_file = my_get_mm_exe_file(current->mm);
	if (sniper_badptr(exe_file)) {
		cmd = process;
		strncpy(cmd, current->comm, S_COMMLEN);
		cmd[S_COMMLEN-1] = 0;
		return;
	}

	cmd = get_exe_file_path(exe_file, process, len);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dentry = exe_file->f_dentry;
#else
	dentry = exe_file->f_path.dentry;
#endif
	if (!sniper_badptr(dentry)) {
		if (!cmd) {
			cmd = process;
			strncpy(cmd, dentry->d_name.name, S_COMMLEN);
			cmd[S_COMMLEN-1] = 0;
		}
	}

	fput(exe_file);

	if (cmd) {
		if (exec_debug == PDEBUG_COMM && strcmp(safebasename(cmd), current->comm) != 0) {
			myprintk("%s(%d) process is %s\n", current->comm, current->pid, cmd);
		}
		return;
	}

	cmd = process;
	strncpy(cmd, current->comm, S_COMMLEN);
	cmd[S_COMMLEN-1] = 0;
}

void get_current_comm(char *comm, unsigned long *ino)
{
	int use_exe_name = 0;
	struct file *exe_file = NULL;
	struct dentry *dentry = NULL;

	if (!comm) {
		return;
	}
	comm[S_COMMLEN-1] = 0;

	exe_file = my_get_mm_exe_file(current->mm);
	if (!sniper_badptr(exe_file)) {
		dentry = exe_file->f_dentry;
		if (!sniper_badptr(dentry)) {
			strncpy(comm, dentry->d_name.name, S_COMMLEN-1);
			use_exe_name = 1;
			if (exec_debug == PDEBUG_COMM && strcmp(comm, current->comm) != 0) {
				myprintk("%s(%d) exefile is %s\n", current->comm, current->pid, comm);
			}

			if (!sniper_badptr(ino) && !sniper_badptr(dentry->d_inode)) {
				*ino = dentry->d_inode->i_ino;
			}
		}
		fput(exe_file);
	}
	if (!use_exe_name) {
		strncpy(comm, current->comm, S_COMMLEN-1);
	}
}

//ZX20220531 浙商redhat5.3有如下死机轨迹
//may_open->ngep_inode_permission->skip_current->__fput
//推测可能是skip_current里调用get_task_cmdname，进而用到fput
//先直接用comm，不取真实程序名，看看还会不会死
#if 0
//TODO 改成comm和cmdname都取，比如对于sh，规则名单的父进程名检查的是cmdname(bash/dash)，对外服务进程异常执行事件应当检查sh更准
static void get_task_cmdname(char *comm, struct task_struct *task)
{
	int use_exe_name = 0;
	struct file *exe_file = NULL;
	struct dentry *dentry = NULL;

	if (sniper_badptr(comm) || sniper_badptr(task)) {
		return;
	}
	comm[S_COMMLEN-1] = 0;

	exe_file = my_get_mm_exe_file(task->mm);
	if (!sniper_badptr(exe_file)) {
		dentry = exe_file->f_dentry;
		if (!sniper_badptr(dentry)) {
			strncpy(comm, dentry->d_name.name, S_COMMLEN-1);
			use_exe_name = 1;
			if (exec_debug == PDEBUG_COMM && strcmp(comm, task->comm) != 0) {
				myprintk("%s(%d) exefile is %s\n", task->comm, task->pid, comm);
			}
		}
		fput(exe_file);
	}
	if (!use_exe_name) {
		strncpy(comm, task->comm, S_COMMLEN-1);
	}
}
#else
static void get_task_cmdname(char *comm, struct task_struct *task)
{
	if (sniper_badptr(comm) || sniper_badptr(task)) {
		return;
	}

	//TODO 这里是否需要像get_task_comm()里一样，拷贝前先加个锁task_lock(task)
	snprintf(comm, S_COMMLEN, task->comm);
}
#endif

void set_taskreq_cmd(taskreq_t *req, struct task_struct *task)
{
	int len = 0;
	char *cmd = NULL, *args = NULL, *cwd = NULL, *cmdname = NULL;

	if (sniper_badptr(req) || sniper_badptr(task)) {
		return;
	}

	get_task_exe(req, task);
	cmd = &(req->args);
	len = strlen(cmd);
	req->cmdlen = len;

	args = cmd + len + 1;
	cmdname = safebasename(cmd);
	len = strlen(cmdname);
	memcpy(args, cmdname, len);
	args[len] = 0;
	req->argslen = len;

	/* 这里不取当前目录，这个目录信息可以在应用层查 */
	cwd = args + len + 1;
	cwd[0] = '/';
	cwd[1] = 0;
	req->cwdlen = 1;
}

struct task_struct *get_parent(struct task_struct *task)
{
	struct task_struct *parent = NULL;

	if (!task || task->pid <= 2) {
		return NULL;
	}

	if (task->group_leader && task->group_leader != task) {
		parent = task->group_leader;
		if (pid_alive(parent)) {
			get_task_struct(parent);
			return parent;
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	parent = task->real_parent;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
	/* redhat取消了2.6.18里的real_parent */
	parent = task->parent;
#else
	rcu_read_lock();
	parent = rcu_dereference(task->real_parent);
	rcu_read_unlock();
#endif
	if (pid_alive(parent)) {
		get_task_struct(parent);
		return parent;
	}

	return NULL;
}

int skip_current(int *flags, struct parent_info *pinfo)
{
	int i = 0, exechook = 0;
	pid_t pid = current->pid;
	struct task_struct *task = NULL, *parent = NULL;
	char *comm = NULL;

	if (!flags || !pinfo) {
		return 1;
	}
	if (*flags & PSR_EXEC) {
		*flags = 0;
		exechook = 1;
	}

	if (pid > my_pid_max) {
		my_pid_max = pid;
	}

	if (pid == sniper_pid) {
		return 1;
	}
	/* 忽略定时任务sniper_chk,assist_sniper_chk及子任务 */
	if (strcmp(current->comm, "sniper_chk") == 0 ||
	    strcmp(current->comm, "assist_sniper_chk") == 0 ||
	    strcmp(current->comm, "webshell_detector") == 0 ) {
		return 1;
	}

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
		if (task->pid == sniper_pid) {
			my_put_task_struct(task);
			return 1;
		}

		/*
		 * 避免死循环：
		 * 1、祖先进程与当前进程相同，停止解析
		 *    ptrace时，取task->parent做parent会出现这种情况。取real_parent应该不会
		 * 2、设置解析的上限次数
		 */
		if (task->pid == pid) {
			if (exechook) {
				myprintk("%s(%d) ptraced? parent rollback!\n",
					current->comm, current->pid);
				for (i = 0; i < SNIPER_PGEN; i++) {
					if (pinfo->task[i].pid == 0) {
						myprintk("parent[%d] %s(%d)\n", i,
							task->comm, task->pid);
						break;
					}
					myprintk("parent[%d] %s(%d)\n", i,
						pinfo->task[i].comm,
						pinfo->task[i].pid);
				}
			}
			my_put_task_struct(task);
			return 0;
		}

		pinfo->task[i].uid = taskuid(task);
		pinfo->task[i].euid = taskeuid(task);
		pinfo->task[i].pid = task->pid;
		comm = pinfo->task[i].comm;
		get_task_cmdname(comm, task);
		if (task->flags & PF_FORKNOEXEC) {
			pinfo->task[i].did_exec = 0;
		} else {
			pinfo->task[i].did_exec = 1;
		}
		/*
		 * proctime有2个用途：
		 * 1、应用层从pinfo取出有效祖先进程，proctime用于构建父进程uuid；
		 * 2、过滤时根据pid和proctime确认是否是祖先进程
		 */
		pinfo->task[i].proctime = get_process_time(task);

		if (strcmp(comm, "crond") == 0 ||
		    strcmp(comm, "cron")  == 0 ||
		    strcmp(comm, "anacron") == 0) {
			*flags |= PSR_CRON;
		}

		parent = get_parent(task);

		my_put_task_struct(task);

		if (!parent) {
			return 0;
		}

		if (strcmp(comm, "sniper_chk") == 0 ||
		    strcmp(comm, "assist_sniper_chk") == 0) {
			my_put_task_struct(parent);
			return 1;
		}
		task = parent;
	}

	my_put_task_struct(task);
        return 0;
}
void get_parent_info(int *flags, struct parent_info *pinfo)
{
	skip_current(flags, pinfo);
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
        if (trapnr != 14) {
                myprintk("%d/%s: %s fault, trapnr %d\n",
                        current->pid, current->comm,
                        p->symbol_name, trapnr);
        }

        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
void my_bind_cpu(void)
{
        cpumask_t newmask = cpumask_of_cpu(smp_processor_id());

        set_cpus_allowed(current, newmask);
}
void my_unbind_cpu(cpumask_t *oldmask)
{
        set_cpus_allowed(current, *oldmask);
}
#else
void my_bind_cpu(void)
{
        cpumask_t *newmask = (cpumask_t *)cpumask_of(smp_processor_id());

        set_cpus_allowed_ptr(current, newmask);
}
void my_unbind_cpu(cpumask_t *oldmask)
{
        set_cpus_allowed_ptr(current, oldmask);
}
#endif

/*
 * 0,  不监控
 * 1， 监控
 * 99, 只监控不上报，用于开发调试
 */ 
int process_engine_status(void)
{
	if (nl_exec_pid && sniper_prule.process_engine_on && !sniper_exec_loadoff) {
		return 1;
	}
	if (exec_debug == PDEBUG_DEVELOP) {
		return PDEBUG_DEVELOP;
	}
	return 0;
}

char *get_exe_file_path(struct file *exe_file, char *buf, int buflen)
{
	struct dentry *dentry = NULL;
	struct vfsmount *mnt = NULL;

	if (sniper_badptr(exe_file)) {
		return NULL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dentry = exe_file->f_dentry;
	mnt = exe_file->f_vfsmnt;
#else
	dentry = exe_file->f_path.dentry;
	mnt = exe_file->f_path.mnt;
#endif
	if (sniper_getpath(dentry, mnt, buf, buflen, NULL) <= 0) {
		return NULL;
	}

	return buf;
}

/*
 * 用d_path取文件或目录的路径名，存入buf, buf的长度是buflen。flag指示文件是否已被删除
 * 返回值：<=0，失败；>0，路径名长度
 */
int sniper_getpath(struct dentry *dentry, struct vfsmount *mnt, char *buf, int buflen, int *flag)
{
	int len = 0;
	char *tmp = NULL, *ptr = NULL, *pathname = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	struct path path;

	path.mnt = mnt;
	path.dentry = dentry;
#endif

	if (sniper_badptr(dentry) || sniper_badptr(mnt) || sniper_badptr(buf)) {
		return -1;
	}

        tmp = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_GETPATH);
        if (tmp == NULL) {
                myprintk("sniper_getpath fail: no memory!\n");
		return -1;
        }
        memset(tmp, 0, PATH_MAX);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dget(dentry);
	mntget(mnt);
        pathname = d_path(dentry, mnt, tmp, PATH_MAX);
	dput(dentry);
	mntput(mnt);
#else
	path_get(&path);
        pathname = d_path(&path, tmp, PATH_MAX);
	path_put(&path);
#endif
        if (IS_ERR(pathname)) {
                myprintk("d_path error %ld\n", PTR_ERR(pathname));
		sniper_kfree(tmp, PATH_MAX, KMALLOC_GETPATH);
		return -1;
        }

	/* 已经被删除的文件，解析出的路径名尾部会带上" (deleted)"，截断之，并设置标志 */
	ptr = strstr(pathname, " (deleted)");
	if (ptr) {
		*ptr = 0;
		if (flag) {
			*flag = 1;
		}
	}

	len = strlen(pathname);
	if (len > buflen - 1) {
		snprintf(buf, S_CMDLEN, "...%s", pathname+len-buflen+4);
		myprintk("truncate %d length path to %s\n", len, buf);
		len = buflen - 1;
	} else {
		memcpy(buf, pathname, len);
		*(buf + len) = 0;
	}

	sniper_kfree(tmp, PATH_MAX, KMALLOC_GETPATH);

	return len;
}

/* 获取当前目录。返回值 <=0，失败；>0，成功 */
int getcwdpath(char *buf, int buflen)
{
	struct dentry *dentry = NULL;
	struct vfsmount *mnt = NULL;

	if (sniper_badptr(buf)) {
		return -1;
	}

	if (sniper_badptr(current->fs)) {
		/* 这种情况通常是当前进程正在退出 */
		return -1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dentry = current->fs->pwd;
	mnt = current->fs->pwdmnt;
#else
	dentry = current->fs->pwd.dentry;
	mnt = current->fs->pwd.mnt;
#endif

	return sniper_getpath(dentry, mnt, buf, buflen, NULL);
}

static int task_skip_network_check(struct task_struct *task)
{
	if (!task) {
		return 1;
	}

#if 0
	/* readdir过滤掉一些联网扫目录但不需要关注它的进程 */
	if (type == 2 && strcmp(task->comm, "sshd") == 0) {
		return 1;
	}
#endif

	/* 过滤掉一些不停扫某目录的进程 */
	if (strcmp(task->comm, "CThreadUtils::s") == 0 ||
	    strcmp(task->comm, "pkla-check-auth") == 0) {
		return 1;
	}

	/* lsof打开的文件太多了，忽略它 */
	if (strcmp(task->comm, "lsof") == 0) {
		return 1;
	}

	return 0;
}

/* 检查task是否有某连接，是返回1，否返回0 */
int check_task_peer(conninfo_t *info, struct task_struct *task)
{
	struct files_struct *files = NULL;
	struct fdtable *fdt = NULL;
	int i = 0, open_files = 0;
	struct file *filp = NULL;
	unsigned short sport = 0, dport = 0;
	u32 saddr = 0, daddr = 0;
	struct in6_addr *daddr_6 = NULL, *saddr_6 = NULL;
	struct socket *sock = NULL;
	struct inet_sock *inet = NULL;
	int ret = 0, size = sizeof(struct in6_addr);

	if (!info || !task) {
		return 0;
	}

	task_lock(task);
	if (task_skip_network_check(task)) {
		task_unlock(task);
		return 0;
	}

	files = task->files;
	if (!files) {
		task_unlock(task);
		return 0;
	}

	rcu_read_lock();

	/*
	 * We don't take a ref to the file, so we must
	 * hold ->file_lock instead.
	 */
	spin_lock(&files->file_lock);

	fdt = files_fdtable(files);
	open_files = count_open_files(fdt);
	for (i = 0; i < open_files; i++) {
		filp = my_fcheck_files(files, i);
		if (!filp || !filp->f_dentry || !filp->f_dentry->d_inode) {
			continue;
		}
		if (!S_ISSOCK(filp->f_dentry->d_inode->i_mode)) {
			continue;
		}
		sock = filp->private_data;

		if (!sock || !sock->sk || sock->sk->sk_state != TCP_ESTABLISHED) {
			continue;
		}
		inet = (struct inet_sock *)(sock->sk);

		if (sock->sk->sk_family == AF_UNIX) {
			continue;
		}

		if (sock->sk->sk_family == AF_INET && info->family == AF_INET) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
			sport = ntohs(inet->inet_sport);
			saddr = inet->inet_saddr;
			dport = ntohs(inet->inet_dport);
			daddr = inet->inet_daddr;
#else
			sport = ntohs(inet->sport);
			saddr = inet->saddr;
			dport = ntohs(inet->dport);
			daddr = inet->daddr;
#endif

			/*
			 * 进程A与B之间的网络连接，在A看来是addr1:port1 - addr2:port2，
			 * 在B看来则是addr2:port2 - addr1:port1。addr1和addr2应该是一样的
			 */
			if (sport == info->dport && saddr == info->daddr &&
			    dport == info->sport && daddr == info->saddr) {
				ret = 1;
				break;
			}
			continue;
		}

		if (sock->sk->sk_family == AF_INET6 && info->family == AF_INET6) {
#ifdef SK_V6_DADDR
			saddr_6 = &sock->sk->sk_v6_rcv_saddr;
			daddr_6 = &sock->sk->sk_v6_daddr;
#else
			struct ipv6_pinfo *np = inet6_sk(sock->sk);
			if (!np) {
				continue;
			}
			saddr_6 = &np->rcv_saddr;
			daddr_6 = &np->daddr;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
#else
			sport = ntohs(inet->sport);
			dport = ntohs(inet->dport);
#endif

			if (sport == info->dport && memcmp(saddr_6, &info->daddr_6, size) == 0 &&
			    dport == info->sport && memcmp(daddr_6, &info->saddr_6, size) == 0) {
				ret = 1;
				break;
			}
			continue;
		}
	}

	spin_unlock(&files->file_lock);
	rcu_read_unlock();
	task_unlock(task);

	return ret;
}

static int diff_conn(conninfo_t *info, u32 saddr, unsigned short sport, u32 daddr, unsigned short dport)
{
	/* 不用关心本地ip和端口，主要关心对方 */
	if (info->dport == dport && info->daddr == daddr) {
		return 0;
	}

	return 1;
}
static int diff_conn6(conninfo_t *info, struct in6_addr *saddr, unsigned short sport, struct in6_addr *daddr, unsigned short dport)
{
	int size = sizeof(struct in6_addr);
	/* 不用关心本地ip和端口，主要关心对方 */
	if (info->dport == dport && memcmp(daddr, &info->daddr_6, size) == 0) {
		return 0;
	}

	return 1;
}

char *fdtype(mode_t m)
{
	if (S_ISLNK(m)) return "link";
	if (S_ISREG(m)) return "file";
	if (S_ISDIR(m)) return "dir";
	if (S_ISCHR(m)) return "chr";
	if (S_ISBLK(m)) return "blk";
	if (S_ISFIFO(m)) return "fifo";
	if (S_ISSOCK(m)) return "socket";
	return "";
}
void print_fdname(int fd, struct dentry *dentry, mode_t mode)
{
	struct dentry *parent = NULL;
	char *buf = NULL;
	const char *name = "", *pname = "";
	struct inode *inode = NULL;
	unsigned long ino = 0;

	if (sniper_badptr(dentry)) {
		printk("fd%d: bad dentry. %s\n", fd, fdtype(mode));
		return;
	}

	inode = dentry->d_inode;
	if (!sniper_badptr(inode)) {
		ino = inode->i_ino;
        	buf = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_FDNAME);
		if (buf) {
			if (sniper_lookuppath(inode, dentry, buf, PATH_MAX, 0) == 0) {
				printk("fd%d: %s. %s. ino %lu. ctime %lu.%lu, mtime %lu.%lu\n",
					fd, buf, fdtype(mode), ino,
					(unsigned long)inode->i_ctime.tv_sec,
					(unsigned long)inode->i_ctime.tv_nsec,
					(unsigned long)inode->i_mtime.tv_sec,
					(unsigned long)inode->i_mtime.tv_nsec);
				sniper_kfree(buf, PATH_MAX, KMALLOC_FDNAME);
				return;
			}
			sniper_kfree(buf, PATH_MAX, KMALLOC_FDNAME);
		}
	}

	if (!sniper_badptr(dentry->d_name.name)) {
		name = dentry->d_name.name;
	}
	parent = dentry->d_parent;
	if (!sniper_badptr(parent)) {
		if (!sniper_badptr(parent->d_name.name)) {
			pname = parent->d_name.name;
		}
	}
	printk("fd%d: =%s/%s=. %s. ino %lu. ctime %lu.%lu, mtime %lu.%lu\n",
		fd, pname, name, fdtype(mode), ino,
		(unsigned long)inode->i_ctime.tv_sec,
		(unsigned long)inode->i_ctime.tv_nsec,
		(unsigned long)inode->i_mtime.tv_sec,
		(unsigned long)inode->i_mtime.tv_nsec);
}

void print_task_fds(struct files_struct *files)
{
	struct fdtable *fdt = NULL;
	int i = 0, open_files = 0;
	struct file *filp = NULL;
	unsigned short sport = 0, dport = 0;
	u32 saddr = 0, daddr = 0;
	struct in6_addr *daddr_6 = NULL, *saddr_6 = NULL;
	mode_t mode = 0;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	struct socket *sock = NULL;
	struct inet_sock *inet = NULL;

	if (!files) {
		return;
	}

	rcu_read_lock();

	/*
	 * We don't take a ref to the file, so we must
	 * hold ->file_lock instead.
	 */
	spin_lock(&files->file_lock);

	fdt = files_fdtable(files);
	open_files = count_open_files(fdt);
	for (i = 0; i < open_files; i++) {
		filp = my_fcheck_files(files, i);
		if (!filp || !filp->f_dentry || !filp->f_dentry->d_inode) {
			continue;
		}
		dentry = filp->f_dentry;
		inode = dentry->d_inode;
		mode = inode->i_mode & S_IFMT;
		print_fdname(i, dentry, mode);
		if (!S_ISSOCK(mode)) {
			continue;
		}
		sock = filp->private_data;

		if (!sock || !sock->sk || sock->sk->sk_state != TCP_ESTABLISHED) {
			continue;
		}
		inet = (struct inet_sock *)(sock->sk);

		if (sock->sk->sk_family == AF_UNIX) {
			printk("fd%d: unix socket\n", i);
			continue;
		}

		if (sock->sk->sk_family == AF_INET) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
			sport = ntohs(inet->inet_sport);
			saddr = inet->inet_saddr;
			dport = ntohs(inet->inet_dport);
			daddr = inet->inet_daddr;
#else
			sport = ntohs(inet->sport);
			saddr = inet->saddr;
			dport = ntohs(inet->dport);
			daddr = inet->daddr;
#endif
			myprintk("%s(%d): fd %d: sk_family %d, "
				 "my %u.%u.%u.%u:%u, peer %u.%u.%u.%u:%u\n",
				 current->comm, current->pid, i, sock->sk->sk_family,
				 myaddr2ip(saddr), sport,
				 myaddr2ip(daddr), dport);
			continue;
		}

		if (sock->sk->sk_family == AF_INET6 ) {
#ifdef SK_V6_DADDR
			saddr_6 = &sock->sk->sk_v6_rcv_saddr;
			daddr_6 = &sock->sk->sk_v6_daddr;
#else
			struct ipv6_pinfo *np = inet6_sk(sock->sk);
			if (!np) {
				continue;
			}
			saddr_6 = &np->rcv_saddr;
			daddr_6 = &np->daddr;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
#else
			sport = ntohs(inet->sport);
			dport = ntohs(inet->dport);
#endif

			myprintk("%s(%d): fd %d: sk_family %d, "
				 "my %08X%08X%08X%08X:%u, peer %08X%08X%08X%08X:%u\n",
				 current->comm, current->pid, i, sock->sk->sk_family,
				 MY_IP6STR(saddr_6), sport,
				 MY_IP6STR(daddr_6), dport);
			continue;
		}
	}

	spin_unlock(&files->file_lock);
	rcu_read_unlock();
}

static int my_used_tty(struct inode *inode)
{
	unsigned long ctime = 0, mtime = 0, ptime = 0;

	if (inode) {
		ctime = inode->i_ctime.tv_sec * NSEC_PER_SEC + inode->i_ctime.tv_nsec;
		mtime = inode->i_mtime.tv_sec * NSEC_PER_SEC + inode->i_mtime.tv_nsec;
		ptime = parent_nsec();

		/* 在终端输入命令，终端必然有回显，故mtime应当大于ctime */
		/* 父进程启动时间应比终端设备mtime小，否则说明这是继承自祖父进程的终端设备，且继承以来终端无新的回显 */
		if (ctime < mtime && ptime < mtime) {
			return 1;
		}
	}
	return 0;
}
int is_commandline(void)
{
	int match = 0;
	struct task_struct *parent = NULL;
	struct files_struct *files = NULL;
	struct file *filp0 = NULL, *filp1 = NULL, *filp2 = NULL;
	struct inode *inode = NULL;

	/* 有终端 */
	if (sniper_badptr(current->signal) || sniper_badptr(current->signal->tty)) {
		return 0;
	}

	parent = current->parent;
	get_task_struct(parent);

	if (!is_shell(parent->comm)) {
		my_put_task_struct(parent);
		return 0;
	}

	task_lock(parent); //保护parent->files
	files = parent->files;
	if (files) {
		spin_lock(&files->file_lock);

		/* 排除bash启动过程中bashrc里的动作 */
		/* 父进程的0,1,2都是同一个字符设备，且字符设备有过命令回显 */
		/* 不需要fput(filp)，fget需要fput，是因为其调用了my_fcheck_files和get_file */
		filp0 = my_fcheck_files(files, 0);
		if (!sniper_badptr(filp0) && !sniper_badptr(filp0->f_dentry)) {
			inode = filp0->f_dentry->d_inode;
		}
		if (!sniper_badptr(inode) && S_ISCHR(inode->i_mode) && my_used_tty(inode)) {
			filp1 = my_fcheck_files(files, 1);
			filp2 = my_fcheck_files(files, 2);
			if (filp1 == filp0 && filp2 == filp0) {
				match = 1;
			}
		}

		spin_unlock(&files->file_lock);
	}
	task_unlock(parent);
	my_put_task_struct(parent);

	if (match) {
		if (diff_fds_from_parent()) {	
			return 0;
		}
	}

	return match;
}

/* TODO 目前检查了与本进程有socket连接的进程，有管道/unix socket的呢？ */
/*
 * 查看task与谁连接
 *   有一个远程连接，返回1，并将对方ip保存在ipaddr
 *   有一个本机连接，返回2，并将本机ip保存在ipaddr
 *   其他情况返回0。有多个远程连接，不知道当前用的哪一个，也返回0
 * TODO 多个远程连接也上报（或者可以加个选择项），但不阻断。记录多个远程连接（比如最多记8个）
 */
int get_task_peer(conninfo_t *info, struct task_struct *task)
{
	struct files_struct *files = NULL;
	struct fdtable *fdt = NULL;
	int i = 0, open_files = 0;
	struct file *filp = NULL;
	unsigned short sport = 0, dport = 0;
	u32 saddr = 0, daddr = 0;
	struct in6_addr *daddr_6 = NULL, *saddr_6 = NULL;
	struct socket *sock = NULL;
	struct inet_sock *inet = NULL;
	unsigned char firstip = 0;
	int local_conn_num = 0;
	int peer_conn_num = 0;
	conninfo_t first_local_conn = {0};
	conninfo_t last_local_conn = {0};
	conninfo_t first_peer_conn = {0};
	conninfo_t last_peer_conn = {0};
	int infosize = sizeof(conninfo_t);

	if (!info || !task) {
		return 0;
	}

	task_lock(task);
	if (task_skip_network_check(task)) {
		task_unlock(task);
		return 0;
	}

	files = task->files;
	if (!files) {
		task_unlock(task);
		return 0;
	}

	rcu_read_lock();

	/*
	 * We don't take a ref to the file, so we must
	 * hold ->file_lock instead.
	 */
	spin_lock(&files->file_lock);

	fdt = files_fdtable(files);
	open_files = count_open_files(fdt);
	for (i = 0; i < open_files; i++) {
		filp = my_fcheck_files(files, i);
		if (!filp || !filp->f_dentry || !filp->f_dentry->d_inode) {
			continue;
		}
		if (!S_ISSOCK(filp->f_dentry->d_inode->i_mode)) {
			continue;
		}
		sock = filp->private_data;

		if (!sock || !sock->sk || sock->sk->sk_state != TCP_ESTABLISHED) {
			continue;
		}
		inet = (struct inet_sock *)(sock->sk);

		if (sock->sk->sk_family == AF_UNIX) {
			continue;
		}

		if (sock->sk->sk_family == AF_INET && info->family == AF_INET) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
			sport = ntohs(inet->inet_sport);
			saddr = inet->inet_saddr;
			dport = ntohs(inet->inet_dport);
			daddr = inet->inet_daddr;
#else
			sport = ntohs(inet->sport);
			saddr = inet->saddr;
			dport = ntohs(inet->dport);
			daddr = inet->daddr;
#endif
#if 0 //debug
			myprintk("%s(%d): fd %d: sk_family %d, "
				 "my %u.%u.%u.%u:%u, peer %u.%u.%u.%u:%u\n",
				 task->comm, task->pid, i, sock->sk->sk_family,
				 myaddr2ip(saddr), sport,
				 myaddr2ip(daddr), dport);
#endif
	
			/* 对方ip是0，或127.x.x.x，或本机ip，视为本机操作 */
			firstip = ((unsigned char *)&daddr)[0];
			if (daddr == 0 || firstip == 127 || saddr == daddr) {
				if (local_conn_num == 0) {
					first_local_conn.family = AF_INET;
					first_local_conn.saddr = saddr;
					first_local_conn.sport = sport;
					first_local_conn.daddr = daddr;
					first_local_conn.dport = dport;
					first_local_conn.inode = filp->f_dentry->d_inode;
					local_conn_num++;
				} else if (diff_conn(&first_local_conn, saddr, sport, daddr, dport) &&
					   diff_conn(&last_local_conn, saddr, sport, daddr, dport)) {
					last_local_conn.family = AF_INET;
					last_local_conn.saddr = saddr;
					last_local_conn.sport = sport;
					last_local_conn.daddr = daddr;
					last_local_conn.dport = dport;
					last_local_conn.inode = filp->f_dentry->d_inode;
					local_conn_num++;
				}
			} else {
				if (peer_conn_num == 0) {
					first_peer_conn.family = AF_INET;
					first_peer_conn.saddr = saddr;
					first_peer_conn.sport = sport;
					first_peer_conn.daddr = daddr;
					first_peer_conn.dport = dport;
					first_peer_conn.inode = filp->f_dentry->d_inode;
					peer_conn_num++;
				} else if (diff_conn(&first_peer_conn, saddr, sport, daddr, dport) &&
					   diff_conn(&last_peer_conn, saddr, sport, daddr, dport)) {
					last_peer_conn.family = AF_INET;
					last_peer_conn.saddr = saddr;
					last_peer_conn.sport = sport;
					last_peer_conn.daddr = daddr;
					last_peer_conn.dport = dport;
					last_peer_conn.inode = filp->f_dentry->d_inode;
					peer_conn_num++;
				}
			}
			continue;
		}

		if (sock->sk->sk_family == AF_INET6 && info->family == AF_INET6) {
#ifdef SK_V6_DADDR
			saddr_6 = &sock->sk->sk_v6_rcv_saddr;
			daddr_6 = &sock->sk->sk_v6_daddr;
#else
			struct ipv6_pinfo *np = inet6_sk(sock->sk);
			if (!np) {
				continue;
			}
			saddr_6 = &np->rcv_saddr;
			daddr_6 = &np->daddr;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
#else
			sport = ntohs(inet->sport);
			dport = ntohs(inet->dport);
#endif

#if 0
			myprintk("%s(%d): fd %d: sk_family %d, "
				 "my %08X%08X%08X%08X:%u, peer %08X%08X%08X%08X:%u\n",
				 current->comm, current->pid, i, sock->sk->sk_family,
				 MY_IP6STR(saddr_6), sport,
				 MY_IP6STR(daddr_6), dport);
#endif

			if (sniper_ipv6_addr_loopback(saddr_6) || sniper_ipv6_addr_loopback(daddr_6)) {
				if (local_conn_num == 0) {
					first_local_conn.family = AF_INET6;
					first_local_conn.saddr_6 = *saddr_6;
					first_local_conn.sport = sport;
					first_local_conn.daddr_6 = *daddr_6;
					first_local_conn.dport = dport;
					first_local_conn.inode = filp->f_dentry->d_inode;
					local_conn_num++;
				} else if (diff_conn6(&first_local_conn, saddr_6, sport, daddr_6, dport) &&
					   diff_conn6(&last_local_conn, saddr_6, sport, daddr_6, dport)) {
					last_local_conn.family = AF_INET6;
					last_local_conn.saddr_6 = *saddr_6;
					last_local_conn.sport = sport;
					last_local_conn.daddr_6 = *daddr_6;
					last_local_conn.dport = dport;
					last_local_conn.inode = filp->f_dentry->d_inode;
					local_conn_num++;
				}
			} else {
				if (peer_conn_num == 0) {
					first_peer_conn.family = AF_INET6;
					first_peer_conn.saddr_6 = *saddr_6;
					first_peer_conn.sport = sport;
					first_peer_conn.daddr_6 = *daddr_6;
					first_peer_conn.dport = dport;
					first_peer_conn.inode = filp->f_dentry->d_inode;
					peer_conn_num++;
				} else if (diff_conn6(&first_peer_conn, saddr_6, sport, daddr_6, dport) &&
					   diff_conn6(&last_peer_conn, saddr_6, sport, daddr_6, dport)) {
					last_peer_conn.family = AF_INET6;
					last_peer_conn.saddr_6 = *saddr_6;
					last_peer_conn.sport = sport;
					last_peer_conn.daddr_6 = *daddr_6;
					last_peer_conn.dport = dport;
					last_peer_conn.inode = filp->f_dentry->d_inode;
					peer_conn_num++;
				}
			}

			continue;
		}
	}

	spin_unlock(&files->file_lock);
	rcu_read_unlock();
	task_unlock(task);

	if (peer_conn_num == 1) {
		memcpy(info, &first_peer_conn, infosize);
		return PEER_CONN;
	}

	if (peer_conn_num > 1) {
#if 0
		myprintk("%s(%d) has %d connections, " 
			 "first %u.%u.%u.%u:%u->%u.%u.%u.%u:%u, "
			 "last %u.%u.%u.%u:%u->%u.%u.%u.%u:%u. use last\n",
			 task->comm, task->pid, peer_conn_num,
			 myaddr2ip(first_peer_conn.saddr), first_peer_conn.sport,
			 myaddr2ip(first_peer_conn.daddr), first_peer_conn.dport,
			 myaddr2ip(last_peer_conn.saddr), last_peer_conn.sport,
			 myaddr2ip(last_peer_conn.daddr), last_peer_conn.dport);
#endif
		memcpy(info, &last_peer_conn, infosize);
		return PEER_CONN;
	}

	if (local_conn_num == 1) {
		memcpy(info, &first_local_conn, infosize);
		return LOCAL_CONN;
	}

	if (local_conn_num > 1) {
#if 0 //打印太多，屏蔽
		myprintk("%s(%d) has %d local connections, " 
			 "first %u.%u.%u.%u:%u->%u.%u.%u.%u:%u, "
			 "last %u.%u.%u.%u:%u->%u.%u.%u.%u:%u. use last\n",
			 task->comm, task->pid, local_conn_num,
			 myaddr2ip(first_local_conn.saddr), first_local_conn.sport,
			 myaddr2ip(first_local_conn.daddr), first_local_conn.dport,
			 myaddr2ip(last_local_conn.saddr), last_local_conn.sport,
			 myaddr2ip(last_local_conn.daddr), last_local_conn.dport);
#endif
		memcpy(info, &last_local_conn, infosize);
		return LOCAL_CONN;
	}

	return 0;
}

/*
 * 对于类似nginx和php-fpm这样的组合，php-fpm在本地9000端口listen，
 * nginx接收到远端ip连接后，会连接php-fpm，将请求转给php-fpm处理。
 * 这是要知道php-fpm处理的是哪个远端ip的请求，遍历进程是少不了的。
 * 即使去遍历socket信息，如从/proc/sys/tcp(6)获得所有连接，
 * 可以查到nginx连接php-fpm的socket，但nginx是哪个进程，
 * 无法确定，还得遍历进程信息
 */
static int grep_task_peer(conninfo_t *info)
{
	int i = 0, ret = 0;
	struct task_struct *task = NULL;

	/* 查找本地连接的进程是哪个 TODO 进程号上限 */
	for (i = RESERVED_PIDS; i < my_pid_max; i++) {
		/* get_task_from_pid里get了task_struct，下面用完了要put */
		task = get_task_from_pid(i);
		if (!task) {
			continue;
		}

		/* 检查此进程是否连接我 */
		if (!check_task_peer(info, task)) {
			my_put_task_struct(task);
			continue;
		}

		/* 取连接进程的peerip，作为我的peerip */
		ret = get_task_peer(info, task);
		my_put_task_struct(task);
		return ret;
	}

	return 0;
}

int get_current_peer(conninfo_t *info)
{
	int ret;

	ret = get_task_peer(info, current);
	if (ret == PEER_CONN) {
		return 1;
	}

	if (ret == LOCAL_CONN) {
		if (grep_task_peer(info) == PEER_CONN) {
			return 1;
		}
	}

	return 0;
}

static char *stringpbrk(const char *cs, const char *ct)
{
	const char *sc1 = cs, *sc2;

	for (; *sc1 != '\0'; ++sc1) {
		for (sc2 = ct; *sc2 != '\0'; ++sc2) {
		if (*sc1 == *sc2)
			return (char *)sc1;
		}
	}

	return NULL;
}

/*分割字符串，会改变源字符串，调用时先拷贝一份*/
char *stringsep(char **s, const char *ct)
{
	char *sbegin = *s;
	char *end;

	if (sbegin == NULL) {
		return NULL;
	}

	end = stringpbrk(sbegin, ct);
	if (end) {
		*end++ = '\0';
	}

	*s = end;
	return sbegin;
}

int ipstr2ip(char *ipstr, struct sniper_ip *ip)
{
        int ip0 = 0, ip1 = 0, ip2 = 0, ip3 = 0;

        if (sscanf(ipstr, "%d.%d.%d.%d",
                   &ip0, &ip1, &ip2, &ip3) != 4) {
                return -1;
        }

        ip->ip[0] = ip0;
        ip->ip[1] = ip1;
        ip->ip[2] = ip2;
        ip->ip[3] = ip3;

        return 0;
}

/* 进程运行中触发事件，用下面的函数取进程命令计算MD5，与规则名单比对 */

/* 内核没有输出get_mm_exe_file，把代码复制过来 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
struct file *my_get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file = NULL;
	struct vm_area_struct *vma = NULL;

	if (sniper_badptr(mm)) {
		return NULL;
	}
	down_read(&mm->mmap_sem);

	vma = mm->mmap;
	while (!sniper_badptr(vma)) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
			exe_file = vma->vm_file;
			if (sniper_badptr(exe_file)) {
				exe_file = NULL;
			} else {
				get_file(vma->vm_file);
			}
			break;
		}
		vma = vma->vm_next;
	}

	up_read(&mm->mmap_sem);
	return exe_file;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
struct file *my_get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	if (sniper_badptr(mm)) {
		return NULL;
	}
	/* We need mmap_sem to protect against races with removal of exe_file */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (sniper_badptr(exe_file)) {
		exe_file = NULL;
	} else {
		get_file(exe_file);
	}
	up_read(&mm->mmap_sem);
	return exe_file;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
/* 4.1~5.14输出了get_mm_exe_file */
struct file *my_get_mm_exe_file(struct mm_struct *mm)
{
	if (sniper_badptr(mm)) {
		return NULL;
	}
	return get_mm_exe_file(mm);
}
#else
struct file *my_get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	if (sniper_badptr(mm)) {
		return NULL;
	}
	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
	rcu_read_unlock();
	return exe_file;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
int proc_exe_link(struct task_struct *task, struct dentry **dentry, struct vfsmount **mnt)
{
	struct vm_area_struct * vma;
	int result = -ENOENT;
	struct mm_struct * mm = NULL;

	get_task_struct(task);
	mm = get_task_mm(task);
	my_put_task_struct(task);
	if (!mm) {
		return result;
	}

	down_read(&mm->mmap_sem);

	vma = mm->mmap;
	while (vma) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
			break;
		}
		vma = vma->vm_next;
	}

	if (vma) {
		*mnt = mntget(vma->vm_file->f_vfsmnt);
		*dentry = dget(vma->vm_file->f_dentry);
		result = 0;
	}

	up_read(&mm->mmap_sem);
	mmput(mm);
	return result;
}

static int do_proc_readlink(struct dentry *dentry, struct vfsmount *mnt, char *buffer, int buflen)
{
	char *tmp = (char*)__get_free_page(GFP_KERNEL), *path;
	int len;

	if (!tmp) {
		return -ENOMEM;
	}
		
	path = d_path(dentry, mnt, tmp, PAGE_SIZE);
	len = PTR_ERR(path);
	if (IS_ERR(path))
		goto out;
	len = tmp + PAGE_SIZE - 1 - path;

	if (len >= buflen)
		len = buflen - 1;
	memcpy(buffer, path, len);
	buffer[len] = 0;
out:
	free_page((unsigned long)tmp);
	return len;
}

int get_process_program_name(struct task_struct *task, char *buf, int buflen)
{
	int error = -EACCES;
	struct dentry *de;
	struct vfsmount *mnt = NULL;

	error = proc_exe_link(task, &de, &mnt);
	if (error)
		goto out;

	error = do_proc_readlink(de, mnt, buf, buflen);
	dput(de);
	mntput(mnt);
out:
	return error;
}
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26) */
static int proc_exe_link(struct task_struct *task, struct path *exe_path)
{
	struct mm_struct *mm;
	struct file *exe_file;

	get_task_struct(task);
	mm = get_task_mm(task);
	my_put_task_struct(task);
	if (!mm)
		return -ENOENT;
	/* why get_mm_exe_file undefined when compile ? */
	exe_file = my_get_mm_exe_file(mm);
	mmput(mm);
	if (exe_file) {
		*exe_path = exe_file->f_path;
		path_get(&exe_file->f_path);
		fput(exe_file);
		return 0;
	}
	return -ENOENT;
}

static int do_proc_readlink(struct path *path, char *buffer, int buflen)
{
	char *tmp = (char*)__get_free_page(GFP_KERNEL);
	char *pathname;
	int len;

	if (!tmp)
		return -ENOMEM;

	pathname = d_path(path, tmp, PAGE_SIZE);
	len = PTR_ERR(pathname);
	if (IS_ERR(pathname))
		goto out;
	len = tmp + PAGE_SIZE - 1 - pathname;

	if (len >= buflen)
		len = buflen - 1;
	memcpy(buffer, pathname, len);
	buffer[len] = 0;
out:
	free_page((unsigned long)tmp);
	return len;
}

int get_process_program_name(struct task_struct *task, char *buffer, int buflen)
{
	int error = -EACCES;
	struct path path;

	error = proc_exe_link(task, &path);
	if (error)
		goto out;

	error = do_proc_readlink(&path, buffer, buflen);
	path_put(&path);
out:
	return error;
}

#endif

int check_loop_open(struct inode *inode)
{
	struct files_struct *files = NULL;
	struct fdtable *fdt = NULL;
	int i = 0, open_files = 0;
	struct file *filp = NULL;
	int ret = 0;

	if (!inode) {
		return 0;
	}

	files = current->files;
	if (!files) {
		return 0;
	}

	rcu_read_lock();

	spin_lock(&files->file_lock);

	fdt = files_fdtable(files);
	open_files = count_open_files(fdt);
	for (i = 0; i < open_files; i++) {
		filp = my_fcheck_files(files, i);
		if (!filp || !filp->f_dentry || !filp->f_dentry->d_inode) {
			continue;
		}

		if (filp->f_dentry->d_inode->i_ino == inode->i_ino) {
			ret = 1;
			break;
		}

	}

	spin_unlock(&files->file_lock);
        rcu_read_unlock();

	return ret;
}

int get_file_md5_from_inode(struct inode *inode, char *pathname, char *output, size_t size)
{
#if 0
	struct files_struct *files = NULL;
	struct fdtable *fdt = NULL;
	int i = 0, open_files = 0;
	struct file *filp = NULL;
	int ret = -1;
	loff_t f_pos;

	if (!inode || !output || size == 0) {
		return -1;
	}

	files = current->files;
	if (!files) {
		return -1;
	}

	rcu_read_lock();
	spin_lock(&files->file_lock);

	fdt = files_fdtable(files);
	open_files = count_open_files(fdt);
	for (i = 0; i < open_files; i++) {
		filp = my_fcheck_files(files, i);
		if (!filp || !filp->f_dentry || !filp->f_dentry->d_inode) {
			continue;
		}

		if (filp->f_dentry->d_inode->i_ino == inode->i_ino) {
			ret = 0;
			break;
		}
	}
	if (ret == 0) {
		/* 读完文件之后恢复便宜位置 */
		f_pos = filp->f_pos;
		if (md5_file(filp, output, size) < 0) {
			ret = -1;
		}
		filp->f_pos = f_pos;
	}

	spin_unlock(&files->file_lock);
	rcu_read_unlock();

	return ret;
#endif
	return -1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
ssize_t kernel_my_write(struct file *file, const char *buf, size_t count,
			    loff_t pos)
{
	mm_segment_t old_fs;
	ssize_t res;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_write(file, (const char __user *)buf, count, &pos);
	set_fs(old_fs);

	return res;
}
#endif

#if 1
/* 获取文件的ctime和文件大小 */
int get_file_stat(char *pathname, struct file_stat *stat)
{
	struct file *file = NULL;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;

	file = filp_open(pathname, O_RDONLY, 0);
	if (IS_ERR(file)){
		myprintk("get file %s inode open error\n", pathname);
		return -1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dentry = file->f_dentry;
#else
	dentry = file->f_path.dentry;
#endif

	if (sniper_badptr(dentry) || sniper_badptr(dentry->d_inode)) {
		myprintk("get file %s dentry or inode error\n", pathname);
		filp_close(file, NULL);
		return -1;
	}
	inode = dentry->d_inode;

	stat->process_ctime = inode->i_ctime.tv_sec;
	stat->process_size = i_size_read(inode);

	filp_close(file, NULL);
	return 0;
}
#else

/* 获取文件的ctime和文件大小 */
int get_file_stat(char *pathname, struct file_stat *stat)
{
	struct file *exe_file = NULL;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;

	exe_file = my_get_mm_exe_file(current->mm);
	if (sniper_badptr(exe_file)) {
		myprintk("get file %s mm exe file error\n", pathname);
		return -1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dentry = exe_file->f_dentry;
#else
	dentry = exe_file->f_path.dentry;
#endif

	if (sniper_badptr(dentry) || sniper_badptr(dentry->d_inode)) {
		myprintk("get file %s dentry or inode error\n", pathname);
		fput(exe_file);
		return -1;
	}
	inode = dentry->d_inode;

	stat->process_ctime = inode->i_ctime.tv_sec;
	stat->process_size = i_size_read(inode);

	fput(exe_file);
	return 0;
}
#endif
