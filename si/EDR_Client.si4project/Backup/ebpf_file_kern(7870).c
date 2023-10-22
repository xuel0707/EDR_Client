#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "structs.h"
#include "support_function.h"

/* Encoding of the file mode.  */
#define	__S_IFMT	0170000	/* These bits determine file type.  */

/* File types.  */
#define	__S_IFDIR	0040000	/* Directory.  */
#define	__S_IFCHR	0020000	/* Character device.  */
#define	__S_IFBLK	0060000	/* Block device.  */
#define	__S_IFREG	0100000	/* Regular file.  */
#define	__S_IFIFO	0010000	/* FIFO.  */
#define	__S_IFLNK	0120000	/* Symbolic link.  */
#define	__S_IFSOCK	0140000	/* Socket.  */


//--------------Define the bpf_map data structure-------------

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct taskreq_t);
} heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 512); /* 256 KB */
} filereq_ringbuf SEC(".maps");

loff_t get_file_size(struct file *file) {
	// struct inode *inode = file->f_inode;
	// return (loff_t)inode->i_blocks * (loff_t)512;
	return file->f_inode->i_size;
}

// ------ supporting Functions-----------------

/*
Get arguments from "current->mm"
*/
int get_args_from_mm(struct filereq_t *req) {
	struct mm_struct *mm = bpf_get_current_task_btf()->mm;
	// struct vm_area_struct *vma = mm->mmap;
    char comm[16];
    // char argv[MAX_ARGS][32];
	void *p = (void *)mm->arg_start;
  int argc = 0;       // Init the value of "argc".
  int i, len;

  bpf_get_current_comm(&comm, sizeof(comm));

  if (!mm) return 0;
    
	for (i = 0; i < MAX_ARGS; i++) {
		// len = bpf_probe_read_str(&argv[i], sizeof(argv[i]), p);
		len = bpf_probe_read_str(req->args[i], sizeof(req->args[i]), p);
		bpf_printk("current arg[%s] length[%d]", p, len);

		if (len <= 0) break;
		argc++;
		p += len;

	}
	return 0;
}

//-----------------TP Functions Below---------------------

// We could use commands below to get the TP hook args.
// cat /sys/kernel/debug/tracing/events/syscalls/{sys_enter_execve}/format
/* 跟踪sys_enter_openat系统调用 */
SEC("tp/syscalls/sys_enter_openat")
int trace_inode_create(struct sys_enter_file_openat_args *ctx) {
  
  // 检查打开模式,只跟踪只写模式
  if ((ctx->flags & 1)!= 1)  
    return -1;
  
  // 打印调试信息  
  bpf_printk("One Write Only Open exec...");
   
  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();
   
  // 为请求准备环形缓冲区空间
  struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
  if (!req)
    return -1;

  // 设置请求类型 
  req->op_type = 1;
  
  // 填充基本信息
  get_base_info_filereq(req);

  // 保存打开的文件路径
  bpf_probe_read_str(req->filename, sizeof(req->filename), ctx->filename);

  // 获取进程绝对路径
  get_absolute_path(req->pro_pathname);

  // 保存打开文件模式和标志
  req->mode = ctx->mode & 0xFFFF;
  req->flags = ctx->flags & 0xFFFF;

  // 调试打印
  bpf_printk("filename is %s", ctx->filename);
  bpf_printk("flags is %d", ctx->flags);
  bpf_printk("file mode is %d", ctx->mode);

  /* 获取命名空间ID和节点名 */
  req->mnt_id = get_mnt_id();
  
  // 保存进程信息
  bpf_probe_read_str(req->comm, sizeof(req->comm), current->comm);
  bpf_probe_read_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
  bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());

  // 提交请求 
  bpf_ringbuf_submit(req, 0);
  
  return 0;
}

/* 跟踪sys_enter_rename系统调用 */
SEC("tp/syscalls/sys_enter_rename")
int trace_inode_rename(struct sys_enter_file_rename_args *ctx) {

  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();

  // 为请求准备环形缓冲区空间 
  struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
  if (!req) 
    return -1;

  // 设置请求类型为重命名
  req->op_type = 4;
  
  // 填充基本信息
  get_base_info_filereq(req);

	// bpf_d_path(&(current->mm->exe_file->f_path), req->filename, sizeof(req->filename));
	get_absolute_path(req->pro_pathname);

	bpf_probe_read_str(req->new_filename, CHAR_MAX, ctx->new_filename);
	bpf_probe_read_str(req->filename, CHAR_MAX, ctx->old_filename);
	bpf_printk("old_filename[%s] new_filename[%s] current[%s]", ctx->old_filename, ctx->new_filename, current->mm->exe_file->f_path.dentry->d_iname);

  /* 获取命名空间ID和节点名 */
  req->mnt_id = get_mnt_id();
   
  // 保存进程信息
  bpf_probe_read_str(req->comm, sizeof(req->comm), current->comm);
  bpf_probe_read_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
  bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());

  // 提交请求
  bpf_ringbuf_submit(req, 0);

  return 0;
}


//---------------- LSM Hooks Below-------------------
/* 跟踪lsm/file_ioctl钩子 */
SEC("lsm/file_ioctl")
int BPF_PROG(lsm_file_ioctl, struct file *file, unsigned int cmd, unsigned long arg, int ret) {

  // 打印参数信息
  bpf_printk("cmd is %d", cmd);
  bpf_printk("arg is %ld", arg);
  
  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();

  // 为请求准备环形缓冲区空间
  struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
  if (!req)
    return -1;

  // 打印调试信息 
  bpf_printk("comm is %s", current->comm);
  
  // 填充基本信息
  get_base_info_filereq(req);

  // 设置请求类型为打开文件
  req->op_type = 1;
  
  // 获取文件mtime
  req->mtime_sec = file->f_inode->i_mtime.tv_sec;
  req->mtime_nsec = file->f_inode->i_mtime.tv_nsec;

	bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
	bpf_printk("mtime_sec is %ld", req->mtime_sec);
	bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

  // 保存进程信息
  bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
  bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);

  // 获取文件路径
  bpf_d_path(&(file->f_path), req->filename, sizeof(req->filename));

  // 保存文件模式和标志
  req->mode = file->f_mode;
  req->flags = file->f_flags;

  // 获取进程路径
  get_absolute_path(req->pro_pathname);

  // 打印调试信息
  bpf_printk("filename is %s", req->filename);

  /* 获取命名空间ID和节点名 */
  req->mnt_id = get_mnt_id();
  bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());

  // 打印调试信息
  bpf_printk("lsm_file_ioctl Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

  // 提交请求
  bpf_ringbuf_submit(req, 0);

  return ret;
}

// 字符串操作函数  
int string_ope(char *str_1) {

  // 打印传入的字符串
  bpf_printk("string is %s", str_1); 
  
  // 打印字符串第一个字符
  bpf_printk("string[0] is %c", str_1[0]);

  return 0;
}

/* 跟踪lsm/inode_permission钩子 */
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret) {

  // 打印参数信息
  bpf_printk("mask is %d", mask);

  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();

  // 调用字符串处理函数
  string_ope(current->comm);

  return ret; 
}

/* 跟踪lsm/file_open钩子 */  
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret) {

  // 过滤只读文件
  if ((file->f_flags & 01) != 01) return 0;
  
  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();
  if(!current) return -1;

  // 为请求准备环形缓冲区
  struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
  if (!req) return -1;

  // 填充基本信息
  get_base_info_filereq(req);

  // 设置请求类型为打开文件
  req->op_type = 1;
  // 获取文件mtime
  req->mtime_sec = file->f_inode->i_mtime.tv_sec;
  req->mtime_nsec = file->f_inode->i_mtime.tv_nsec;

  bpf_printk("bpf_ktime_get_ns[%ld] mtime_sec[%ld] mtime_nsec[%ld]\n", bpf_ktime_get_ns(), req->mtime_sec,req->mtime_nsec);

  bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
  bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
  req->path_len = bpf_d_path(&(file->f_path), req->filename, sizeof(req->filename));
  req->mode = file->f_mode;
  req->flags = file->f_flags;

  // 获取进程路径
  get_absolute_path(req->pro_pathname);

  /* 获取命名空间ID和节点名 */
  req->mnt_id = get_mnt_id();
  bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());

  // 打印调试信息
  bpf_printk("lsm_file_open Mount namespace id[%u], nodename[%s], filename[%s] flags[%d]  file mode[%d]", req->mnt_id, req->nodename, req->filename, file->f_flags, file->f_mode);

  // 提交请求
  bpf_ringbuf_submit(req, 0);

  return ret;
}

/* 跟踪lsm/inode_link钩子 */
SEC("lsm/inode_link")
int BPF_PROG(lsm_file_link, struct dentry* old_dentry, struct inode* dir, struct dentry* new_dentry, int ret) {

  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();

  // 为请求准备环形缓冲区
  struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
  if (!req)
    return -1;

  // 填充基本信息
  get_base_info_filereq(req);

  // 设置请求类型为符号链接
  req->op_type = 5;

  // 获取目录inode信息
  req->file_size = dir->i_size;
  req->mtime_sec = dir->i_mtime.tv_sec;
  req->mtime_nsec = dir->i_mtime.tv_nsec;

  bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
  bpf_printk("mtime_sec is %ld", req->mtime_sec);
  bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

  // 保存进程信息
  bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
  bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);

  // 获取进程路径
  get_absolute_path(req->pro_pathname);

  // 保存旧文件名和新文件名
  req->path_len = bpf_probe_read_str(req->filename, sizeof(req->filename), old_dentry->d_iname);
  req->newpath_len = bpf_probe_read_str(req->new_filename, sizeof(req->new_filename), new_dentry->d_iname);

  // 打印调试信息
  bpf_printk("old_filename is %s", old_dentry->d_iname);
  bpf_printk("new_filename is %s", new_dentry->d_iname);

  /* 获取命名空间ID和节点名 */
  req->mnt_id = get_mnt_id();
  bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());

  // 打印调试信息
  bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

  // 提交请求
  bpf_ringbuf_submit(req, 0);

  return ret;
}
/* 跟踪lsm/inode_unlink钩子 */
SEC("lsm/inode_unlink")  
int BPF_PROG(lsm_file_unlink, struct inode* dir, struct dentry* dentry, int ret) {

  // 打印被删除的硬链接文件名
  bpf_printk("removed hard link filename is %s", dentry->d_iname);

  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();

  // 为请求准备环形缓冲区
  struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
  if (!req) 
    return -1;

  // 填充基本信息
  get_base_info_filereq(req);
  
  // 跳过当前进程信息
  skip_current(&(req->pinfo));

  // 设置请求类型为删除
  req->op_type = 3;

  // 获取目录inode信息
  req->flags = dir->i_flags; 
  req->file_size = dir->i_size;
  req->mtime_sec = dir->i_mtime.tv_sec;
  req->mtime_nsec = dir->i_mtime.tv_nsec;

  bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
  bpf_printk("mtime_sec is %ld", req->mtime_sec);
  bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

  // 保存进程信息
  bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
  bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);

  // 获取进程路径
  get_absolute_path(req->pro_pathname);

  // 保存删除的文件名
  req->path_len = bpf_probe_read_str(req->filename, sizeof(req->filename), dentry->d_iname);

  // 打印调试信息
  bpf_printk("filename is %s", dentry->d_iname);

  /* 获取命名空间ID和节点名 */
  req->mnt_id = get_mnt_id();
  bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());

  // 打印调试信息
  bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

  // 提交请求
  bpf_ringbuf_submit(req, 0);

  return 0;
  return ret;
}
/* 跟踪lsm/inode_rename钩子 */
SEC("lsm/inode_rename")
int BPF_PROG(lsm_file_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry,
             unsigned int flags) {
    
  // 获取当前任务结构
  struct task_struct *current = bpf_get_current_task_btf();

  // 为请求准备环形缓冲区
  struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
  if (!req)
    return -1;

  // 填充基本信息
  get_base_info_filereq(req);

  // 设置请求类型为重命名
  req->op_type = 4;

  // 保存flags
  req->flags = flags;

  // 保存老目录和新目录信息
  req->file_size = old_dir->i_size;
  req->newfile_size = new_dir->i_size;
  req->mtime_sec = old_dir->i_mtime.tv_sec;
  req->mtime_nsec = new_dir->i_mtime.tv_nsec;

  bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
  bpf_printk("mtime_sec is %ld", req->mtime_sec);
  bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

  // 保存进程信息
  bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
  bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);

  // 获取进程路径
  get_absolute_path(req->pro_pathname);

  // 保存旧文件名和新文件名
  req->path_len = bpf_probe_read_str(req->filename, sizeof(req->filename), old_dentry->d_iname);
  req->newpath_len = bpf_probe_read_str(req->new_filename, sizeof(req->new_filename), new_dentry->d_iname);

  // 打印调试信息
  bpf_printk("old_filename is %s", old_dentry->d_iname);
  bpf_printk("new_filename is %s", new_dentry->d_iname);

  /* 获取命名空间ID和节点名 */
  req->mnt_id = get_mnt_id();
  bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());

  // 打印调试信息
  bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

  // 提交请求
  bpf_ringbuf_submit(req, 0);

  return 0;
}

// Some eBPF programs must be GPL licensed. This depends on program types.
char _license[] SEC("license") = "GPL";
