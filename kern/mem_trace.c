/*
 * 记录sniper_edr内核模块的内存使用情况，用于检查本模块是否存在内存泄漏
 */

#include "interface.h"

static int sniper_cpunum = 1;

/*
 * 如果使用一个公共的sniper_mem_usage数据结构，来统计内存使用的情况，
 * 需要加锁控制，防止多个进程同时修改数据结构的内容，统计结果不准。
 * 为了减少锁的开销，借鉴每cpu变量的思想，令每cpu对应一个数据结构，
 * 进程分配释放内存时修改其当前所在cpu的统计值，这样就不会存在同时修改的情况。
 * 至于单个cpu上进程1正在修改统计值时，时间片切换给了进程2，然后进程2也修改统计值，
 * 这种场景发生的概率极低，可以不予考虑，此精度已经足够测试时发现内存泄漏问题。
 */
struct sniper_mem_usage {
	long size[SNIPER_MALLOC_TYPES];    //占用的内存量
	long mcount[SNIPER_MALLOC_TYPES];  //malloc的次数
	long fcount[SNIPER_MALLOC_TYPES];  //free的次数
};
struct sniper_mem_usage *sniper_memuse = NULL;

/* 分配sniper_memuse结构数组 */
int alloc_sniper_memuse(void)
{
	int size = 0;

	sniper_cpunum = num_online_cpus();
	size = sniper_cpunum * sizeof(struct sniper_mem_usage);

	sniper_memuse = kmalloc(size, GFP_ATOMIC);
	if (sniper_memuse == NULL) {
		myprintk("no memory, kmalloc %d*%d=%d fail\n",
			sniper_cpunum, (int)sizeof(struct sniper_mem_usage), size);
		return -1;
	}

	memset(sniper_memuse, 0, size);
	return 0;
}

/* 释放sniper_memuse结构数组 */
void free_sniper_memuse(void)
{
	if (sniper_memuse) {
		kfree(sniper_memuse);
	}
}

/* 取得进程所在的cpu编号 */
static int sniper_cpuid(void)
{
	int id = smp_processor_id();

	if (id >= sniper_cpunum) {
		id = id % sniper_cpunum;
	}
	return id;
}

static void add_sniper_memuse(int size, int type, void *ptr, char *file, const char *func, int line)
{
	if (sniper_memuse && type >= 0 && type < SNIPER_MALLOC_TYPES) {
		sniper_memuse[sniper_cpuid()].size[type] += size;
		sniper_memuse[sniper_cpuid()].mcount[type] ++;

		if (mem_debug == type || mem_debug == SNIPER_MALLOC_TYPES) {
			myprintk("%s:%d %s malloc %#lx, size %d, type %d\n",
				safebasename(file), line, func, (unsigned long)ptr, size, type);
		}
	}

}

static void reduce_sniper_memuse(int size, int type, void *addr, char *file, const char *func, int line)
{
	if (sniper_memuse && type >= 0 && type < SNIPER_MALLOC_TYPES) {
		sniper_memuse[sniper_cpuid()].size[type] -= size;
		sniper_memuse[sniper_cpuid()].fcount[type] ++;

		if (mem_debug == type || mem_debug == SNIPER_MALLOC_TYPES) {
			myprintk("%s:%d %s free %#lx, size %d, type %d\n",
				safebasename(file), line, func, (unsigned long)addr, size, type);
		}
	}

}

/* kmalloc分配内存并统计 */
void *sniper_kmalloc_trace(int size, int flag, int type, char *file, const char *func, int line)
{
	void *ptr = NULL;

	if (size == 0) {
		return NULL;
	}

	ptr = kmalloc(size, flag);

	if (!ptr) {
		return NULL;
	}

	add_sniper_memuse(size, type, ptr, file, func, line);

	return ptr;
}

/* kfree释放内存并统计 */
void sniper_kfree_trace(void *addr, int size, int type, char *file, const char *func, int line)
{
	if (!addr) {
		return;
	}

	reduce_sniper_memuse(size, type, addr, file, func, line);

	kfree(addr);
}

/* vmalloc分配内存并统计 */
void *sniper_vmalloc_trace(int size, int type, char *file, const char *func, int line)
{
	void *ptr = NULL;

	if (size == 0) {
		return NULL;
	}

	ptr = vmalloc(size);

	if (!ptr) {
		return NULL;
	}

	add_sniper_memuse(size, type, ptr, file, func, line);

	return ptr;
}

/* vfree释放内存并统计 */
void sniper_vfree_trace(void *addr, int size, int type, char *file, const char *func, int line)
{
	if (!addr) {
		return;
	}

	reduce_sniper_memuse(size, type, addr, file, func, line);

	vfree(addr);
}

/* 打印内存使用情况 */
void show_sniper_memuse(void)
{
	int i = 0, cpu = 0;
	long total = 0;

	if (!sniper_memuse) {
		return;
	}

	/* 统计每种类型的内存分配释放情况 */
	for (i = 0; i < SNIPER_MALLOC_TYPES; i++) {
		long size = 0, mcount = 0, fcount = 0;

		/* 把每cpu的值加起来 */
		for (cpu = 0; cpu < sniper_cpunum; cpu++) {
			size += sniper_memuse[cpu].size[i];
			mcount += sniper_memuse[cpu].mcount[i];
			fcount += sniper_memuse[cpu].fcount[i];
		}
		if (size == 0 && mcount == 0 && fcount == 0) {
			continue;
		}

		total += size;
	}

	if (total == 0) {
		return;
	}

	myprintk("Warning: leak memory %ld\n", total);

	myprintk("Type: Size/malloc count/free count\n");

	/* 打印每种类型的内存分配释放情况 */
	for (i = 0; i < SNIPER_MALLOC_TYPES; i++) {
		long size = 0, mcount = 0, fcount = 0;

		/* 把每cpu的值加起来 */
		for (cpu = 0; cpu < sniper_cpunum; cpu++) {
			size += sniper_memuse[cpu].size[i];
			mcount += sniper_memuse[cpu].mcount[i];
			fcount += sniper_memuse[cpu].fcount[i];
		}
		if (size == 0 && mcount == 0 && fcount == 0) {
			continue;
		}

		myprintk("[%d]: %ld/%ld/%ld\n", i, size, mcount, fcount);
	}
}

/* 通过/proc/sys/sniper/mem_usage查看内存使用情况 */
void print_memusage(char *buffer, int buffer_len)
{
	int i = 0, cpu = 0, len = 0;
	long total = 0;
	char *buf = buffer;
	int buf_len = buffer_len;

	if (!sniper_memuse || !buf) {
		return;
	}

	memset(buf, 0, buf_len);
	snprintf(buf, buf_len, "CPU num: %d\nType: Size/malloc count/free count\n", sniper_cpunum);

	/* 报告每种类型的内存分配释放情况 */
	for (i = 0; i < SNIPER_MALLOC_TYPES; i++) {
		long size = 0, mcount = 0, fcount = 0;

		/* 把每cpu的值加起来 */
		for (cpu = 0; cpu < sniper_cpunum; cpu++) {
			size += sniper_memuse[cpu].size[i];
			mcount += sniper_memuse[cpu].mcount[i];
			fcount += sniper_memuse[cpu].fcount[i];
		}
		if (size == 0 && mcount == 0 && fcount == 0) {
			continue;
		}

		/* VMALLOC_PROCFS_MEM类型减去sniper_memusage_buf的大小，
		   sniper_print_memusage退出前会释放sniper_memusage_buf */
		if (i == VMALLOC_PROCFS_MEM) {
			size -= SNIPER_PROCFS_BUFSIZE;
			fcount++;
		}

		len = strlen(buf);
		buf += len;
		buf_len -= len;
		snprintf(buf, buf_len, "[%d]: %ld/%ld/%ld\n", i, size, mcount, fcount);
		total += size;
	}

	len = strlen(buf);
	buf += len;
	buf_len -= len;
	snprintf(buf, buf_len, "Total %ld\nPolicy types: %d-%d\n",
		total, VMALLOC_PCMDTBLMEM, VMALLOC_DNSTRUSTRULE);
}
