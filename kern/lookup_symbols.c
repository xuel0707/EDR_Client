#include <linux/utsname.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include "interface.h"

unsigned long put_task_struct_addr = 0;
unsigned long security_ops_addr = 0;
unsigned long security_hook_heads_addr = 0;
unsigned long init_mm_addr = 0;
unsigned long mount_lock_addr = 0;
unsigned long vfsmount_lock_func_addr = 0;
unsigned long vfsmount_unlock_func_addr = 0;

/*
 * CentOS/Redhat 6.0/6.1，__put_task_struct没输出，
 * 编译会报__put_task_struct undefined
 * insmod 6.2上编译的模块，报Unknown symbol
 * 故对内核版本2.6.32单独处理
 */
/* security_ops和security_hook_heads算一个 */
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
#define SYMBOL_NUM 3	//security_xxx, mount_lock, __put_task_struct
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) && LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#define SYMBOL_NUM 3	//security_xxx, vfsmount_lock_func, vfsmount_unlock_func
#define VFSMOUNT_LOCK_FUNC 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0) && defined(__aarch64__)
#define SYMBOL_NUM 3	//security_xxx, mount_lock, init_mm
#define INIT_MM_ADDR 1
#else
#define SYMBOL_NUM 2	//security_xxx, mount_lock
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && !defined(USE_MOUNT_LOCK)
#define MOUNT_LOCK "vfsmount_lock"
#else
#define MOUNT_LOCK "mount_lock"
#endif

static int symbol_found = 0;
static unsigned long kernel_read_addr = (unsigned long)kernel_read;
static unsigned long symbol_off = 0;

#define GET_SYMBOL_ADDR(SYMBOL, ADDR)		\
	if (strcmp(symbol, SYMBOL) == 0) {	\
		ADDR = addr;			\
		symbol_found++;			\
		return;				\
	}

static void parse_line(char *line)
{
	unsigned long addr = 0;
	char type[8] = {0};
	char symbol[64] = {0};

	sscanf(line, "%lx %7s %63s", &addr, type, symbol);

	if (strcmp(symbol, "kernel_read") == 0) {
		//myprintk("kernel_read %#lx\n", addr);
		symbol_off = kernel_read_addr - addr;
		return;
	}

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	GET_SYMBOL_ADDR("__put_task_struct", put_task_struct_addr);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
	GET_SYMBOL_ADDR("security_ops", security_ops_addr);
#else
	GET_SYMBOL_ADDR("security_hook_heads", security_hook_heads_addr);
#endif

#ifdef VFSMOUNT_LOCK_FUNC
	GET_SYMBOL_ADDR("vfsmount_lock_local_lock", vfsmount_lock_func_addr);
	GET_SYMBOL_ADDR("vfsmount_lock_local_unlock", vfsmount_unlock_func_addr);
#else
	GET_SYMBOL_ADDR(MOUNT_LOCK, mount_lock_addr);
#endif

#ifdef INIT_MM_ADDR
	GET_SYMBOL_ADDR("init_mm", init_mm_addr);
#endif
}

#define ADJUST_SYMBOL(ADDR, SYMBOL)			\
	if (sniper_badptr(ADDR)) {			\
		myprintk("no symbol %s\n", SYMBOL);	\
		return -1;				\
	}						\
	ADDR += symbol_off;				\
	if (symbol_debug) {				\
		myprintk("%s %#lx\n", SYMBOL, ADDR);	\
	}

/* 在/boot/System.map-kernel_verion中获取符号地址，一次处理一行 */
int sniper_lookup_symbols(void)
{
	int i = 0, symbol_debug = 0;
	struct file *file = NULL;
	char filename[S_NAMELEN] = {0};
	char line[S_LINELEN] = {0};
	loff_t i_size = 0, pos = 0;
	ssize_t bytes = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
	snprintf(filename, S_NAMELEN, "/boot/System.map-%s", system_utsname.release);
#else
	snprintf(filename, S_NAMELEN, "/boot/System.map-%s", utsname()->release);
#endif
	file = filp_open(filename, O_RDONLY, 0);
	if (file == NULL || IS_ERR(file)) {
		myprintk("open %s fail: %ld\n", filename, PTR_ERR(file));
		return -1;
	}

	/* 3.9以后file结构里才有f_inode，才有file_inode()函数，
	   故统一用file->f_dentry->d_inode */
	i_size = i_size_read(file->f_dentry->d_inode);
	if (i_size <= 0) {
		myprintk("bad size of %s: %lld\n", filename, i_size);
		filp_close(file, 0);
		return -1;
	}

	if (symbol_debug) myprintk("===begin lookup symbol\n");
	pos = 0;
	while (pos < i_size) {
		memset(line, 0, S_LINELEN);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
		bytes = kernel_read(file, pos, line, S_LINELEN-1);
		pos += bytes;
#else
		bytes = kernel_read(file, line, S_LINELEN-1, &pos);
#endif
		if (bytes < 0) {
			myprintk("read %s error: %ld\n", filename, bytes);
			break;
		}

		/* 读到文件尾 */
		if (bytes == 0) {
			if (pos != i_size) {
				myprintk("read %s error: -EIO\n", filename);
			}
			break;
		}

		/* 找行尾的换行符 */
		for (i = 0; i < bytes; i++) {
			if (line[i] == '\n') {
				break;
			}
		}

		line[i] = 0; //i的最大值是bytes，bytes的最大值是S_LINELEN-1

		pos -= bytes-i-1; //的长度是i+1，文件偏移回退bytes-i-1字节

		/* 处理一行 */
		parse_line(line);
		if (symbol_found == SYMBOL_NUM) {
			break;
		}
	}
	if (symbol_debug) myprintk("===lookup symbol end\n");

	filp_close(file, 0);

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	ADJUST_SYMBOL(put_task_struct_addr, "__put_task_struct");
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
	ADJUST_SYMBOL(security_ops_addr, "security_ops");
#else
	ADJUST_SYMBOL(security_hook_heads_addr, "security_hook_heads");
#endif

#ifdef VFSMOUNT_LOCK_FUNC
	ADJUST_SYMBOL(vfsmount_lock_func_addr, "vfsmount_lock_local_lock");
	ADJUST_SYMBOL(vfsmount_unlock_func_addr, "vfsmount_lock_local_unlock");
#else
	ADJUST_SYMBOL(mount_lock_addr, MOUNT_LOCK);
#endif

#ifdef INIT_MM_ADDR
	ADJUST_SYMBOL(init_mm_addr, "init_mm");
#endif

	return 0;
}
