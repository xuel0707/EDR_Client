/*
 * Patch for dirtycow vulnerability CVE-2016-5195
 */

#include "interface.h"

#include <linux/mman.h>

static void report_dirtycow(void)
{
	int do_stop = 0, trust = 0;
	taskreq_t *req = NULL;

	req = init_taskreq(INIT_WITH_PINFO|INIT_WITH_CMD);
	if (!req) {
		return;
	}

	req->flags = PSR_DIRTYCOW;
	req->pflags.dirtycow = 1;

	if (is_filter_cmd(req, NULL)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	trust = is_trust_cmd(req, EVENT_PrivilegeEscalation, NULL, NULL);
        if (!trust && sniper_prule.privilege_kill && client_mode == NORMAL_MODE) {
                do_stop = 1;
		req->pflags.terminate = 1;
        }

	myprintk("%s/%d(uid %d) may Dirtycow! %s\n", current->comm, current->pid,
		 req->uid, do_stop ? "forbidden" : "only warning");

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return;
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;
        send_data_to_user((char *)req, req->size, nl_exec_pid, Probe_dirtycow);

	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
}

/* 缓存madvise进程信息 */ 
#define SNIPER_MADVISE_PROCNUM 64
struct madvise_info {
	unsigned long addr;
	size_t length;
	int reported;
	int count;
	pid_t pid;
	unsigned long proctime;
	time_t first_time;
	time_t last_check_time;
};
struct madvise_info madvise_info[SNIPER_MADVISE_PROCNUM] = {{0}};
DEFINE_SPINLOCK(madvise_info_lock);

extern void my_bind_cpu(void);
extern void my_unbind_cpu(cpumask_t *oldmask);
extern int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr);

/*
 * madvise MADV_DONTNEED经常被使用，如浏览器
 * 检查地址是否对应了一个普通文件，且当前用户无权限写此文件，1秒内madvise 100次，视为意图dirtycow提权
 */
static int is_readonly_file(unsigned long addr)
{
	struct vm_area_struct *vma = NULL;
	struct file *file = NULL;
	struct inode *inode = NULL;
	uid_t uid = 0, file_uid = 0;

	vma = find_vma(current->mm, addr);
	if (sniper_badptr(vma)) {
		return 0;
	}
	file = vma->vm_file;
	if (sniper_badptr(file) || sniper_badptr(file->f_dentry)) {
		return 0;
	}
	inode = file->f_dentry->d_inode;
	if (sniper_badptr(inode) || !S_ISREG(inode->i_mode)) {
		return 0;
	}

	/* 文件所有者是当前用户，或文件任意人可写 */
	uid = currenteuid();
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	file_uid = inode->i_uid;
#else
	file_uid = inode->i_uid.val;
#endif
	if (file_uid == uid || inode->i_mode & S_IWOTH) {
		return 0;
	}

	return 1;
}

static int check_dirtycow(unsigned long addr, size_t length)
{
	int do_handle = 0;
	unsigned long min_proctime = 0;
	unsigned long my_proctime = 0;
	int i = 0, idx = 0;
	struct madvise_info *info = NULL;

	my_proctime = get_process_time(current);

	spin_lock(&madvise_info_lock);
	min_proctime = madvise_info[0].first_time;
	for (i = 0; i < SNIPER_MADVISE_PROCNUM; i++) {
		/* 取最老的格子，用来保存新的madvise行为 */
		info = &madvise_info[i];
		if (info->first_time < min_proctime) {
			min_proctime = info->first_time;
			idx = i;
		}

		/* 统计进程最近的100次madvise时间 */
		if (info->pid == current->pid && info->proctime == my_proctime) {
			if (info->reported) {
				break;
			}

			/* madvise的addr不同，重新计数 */
			if (addr != info->addr || length != info->length) {
				info->addr = addr;
				info->length = length;
				info->last_check_time = sniper_uptime();
				info->count = 0;
				break;
			}

			info->count++;
			if (info->count > 100) {
				time_t now = sniper_uptime();
				if (now - info->last_check_time <= 1) {
					myprintk("%s(%d) check_dirtycow count %d, now %ld, last %ld\n",
						current->comm, current->pid, info->count, now, info->last_check_time);
					do_handle = 1;
					info->reported = 1;
				} else {
					/* 重新开始计数 */
					info->last_check_time = now;
					info->count = 0;
				}
			}

			break;
		}
	}

	/* 保存新的madvise行为 */
	if (i == SNIPER_MADVISE_PROCNUM) {
		info = &madvise_info[idx];
		memset(info, 0, sizeof(struct madvise_info));
		info->addr = addr;
		info->length = length;
		info->pid = current->pid;
		info->proctime = my_proctime;
		info->first_time = sniper_uptime();
		info->last_check_time = info->first_time;
	}
	spin_unlock(&madvise_info_lock);

	return do_handle;
}

void check_dirtycow_selfmem(void)
{
	/* 不支持检测madvise才检测selfmem write，因此这里可以套用madvise的检测过程 */
	if (check_dirtycow(0, 0)) {
		report_dirtycow();
        }
}

static int dirtycowfix(struct kprobe *p, struct pt_regs *regs)
{
#ifdef USE_CPUSMASK
        cpumask_t *oldmask = &current->cpus_mask;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
        cpumask_t *oldmask = &current->cpus_allowed;
#else
        cpumask_t *oldmask = &current->cpus_mask;
#endif
	uid_t uid = 0;

#if defined(__x86_64__)
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
	struct pt_regs *real_regs = (struct pt_regs *)regs->di;
	unsigned long addr = (unsigned long)real_regs->di;
	size_t length = (size_t)real_regs->si;
	int advise = (int)real_regs->dx;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	unsigned long addr = (unsigned long)regs->rdi;
	size_t length = (size_t)regs->rsi;
	int advise = (int)regs->rdx;
#else
	unsigned long addr = (unsigned long)regs->di;
	size_t length = (size_t)regs->si;
	int advise = (int)regs->dx;
#endif

#elif defined(__aarch64__)
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
	struct pt_regs *real_regs = (struct pt_regs *)regs->regs[0];
	unsigned long addr = (unsigned long)real_regs->regs[0];
	size_t length = (size_t)real_regs->regs[1];
	int advise = (int)real_regs->regs[2];
#else
	unsigned long addr = (unsigned long)regs->regs[0];
	size_t length = (size_t)regs->regs[1];
	int advise = (int)regs->regs[2];
#endif

#elif defined(__sw_64__)
	unsigned long addr = (unsigned long)regs->r16;
	size_t length = (size_t)regs->r17;
	int advise = (int)regs->r18;
#else
	unsigned long addr = 0;
	size_t length = 0;
	int advise = 0;
#endif

	if (!process_engine_status() || !sniper_prule.privilege_on) {
		return 0;
	}

	if (advise != MADV_DONTNEED || addr == 0) {
		return 0;
	}

	uid = currenteuid();
	if (uid == 0) {
		return 0;
	}

	my_bind_cpu();

	if (!is_readonly_file(addr) || !check_dirtycow(addr, length)) {
		my_unbind_cpu(oldmask);
		return 0;
	}

	/* 检测可信、过滤和阻断均由应用层做 */

	report_dirtycow();

	my_unbind_cpu(oldmask);

	return 0;
}

int dirtycow_on = 0;
static struct kprobe dirtycow_kp = {{0}};
static char *dirtycow_symbolname = "sys_madvise";

int dirtycow_hook_init(void)
{
	int ret = 0;

        if (dirtycow_on) {
                return 0;
        }

        memset(&dirtycow_kp, 0, sizeof(struct kprobe));
        dirtycow_kp.symbol_name = dirtycow_symbolname;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
        dirtycow_kp.fault_handler = handler_fault;
#endif
        dirtycow_kp.pre_handler = dirtycowfix;

	ret = register_kprobe(&dirtycow_kp);
	if (ret < 0) {
/* 4.17以上，启用了CONFIG_ARCH_HAS_SYSCALL_WRAPPER，系统调用的函数名也有改变 */
#if defined(__x86_64__)
	        dirtycow_kp.symbol_name = "__x64_sys_madvise";
#endif
#if defined(__i386__)
	        dirtycow_kp.symbol_name = "__ia32_sys_madvise";
#endif
#if defined(__aarch64__)
	        dirtycow_kp.symbol_name = "__arm64_sys_madvise";
#endif
		ret = register_kprobe(&dirtycow_kp);
		if (ret < 0) {
			myprintk("dirtycowfix fail : %d\n", ret);
			return ret;
		}
	}

        myprintk("dirtycowfix on\n");
        dirtycow_on = 1;
	return 0;
}

void dirtycow_hook_exit(void)
{
        if (!dirtycow_on) {
                return;
        }

        unregister_kprobe(&dirtycow_kp);
        myprintk("dirtycowfix off\n");
        dirtycow_on = 0;
}
