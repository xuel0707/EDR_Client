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

/* file flags Definitions */
#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#ifndef O_CREAT
#define O_CREAT		00000100	/* not fcntl */
#endif

/* MingYan operate_file_type */
#define OP_OPEN 1
#define OP_CLOSE 2
#define OP_UNLINK 3
#define OP_RENAME 4
#define OP_LINK 5
#define OP_SYMLINK 6
#define OP_READ 7
#define OP_WRITE 8
#define OP_OPEN_W 9
#define OP_OPEN_C 10

//--------------Define the bpf_map data structure-------------

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct taskreq_t);
} heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024*1024); /* 1024 KB */
} filereq_ringbuf SEC(".maps");

loff_t get_file_size(struct file *file) {
	// struct inode *inode = file->f_inode;
	return file->f_inode->i_size;
}

// ------ supporting Functions-----------------


//-----------------TP Functions Below---------------------

// We could use commands below to get the TP hook args.
// cat /sys/kernel/debug/tracing/events/syscalls/{sys_enter_execve}/format
SEC("tp/syscalls/sys_enter_openat")
int trace_inode_create(struct sys_enter_file_openat_args *ctx) {

	if ((ctx->flags & 1)!= 1)
		return -1;

	bpf_printk("One Write Only Open exec...");
	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
	if (!req)
		return 0;

	req->op_type = 1;
	get_base_info_filereq(req);

	// struct task_struct *current = bpf_get_current_task_btf();
	// bpf_d_path(&(current->mm->exe_file->f_path), req->filename, sizeof(req->filename));
	bpf_probe_read_str(req->filename, sizeof(req->filename), ctx->filename);
	get_absolute_path(req->pro_pathname);
	req->mode = ctx->mode & 0xFFFF;
	req->flags = ctx->flags & 0xFFFF;

	bpf_printk("filename is %s", ctx->filename);
	bpf_printk("flags is %d", ctx->flags);
	bpf_printk("file mode is %d", ctx->mode);

	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	// bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);

	return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int trace_inode_rename(struct sys_enter_file_rename_args *ctx) {

	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
	if (!req)
		return 0;

	req->op_type = 4;    // 4 represents the type is rename.
	get_base_info_filereq(req);

	// bpf_d_path(&(current->mm->exe_file->f_path), req->filename, sizeof(req->filename));
	get_absolute_path(req->pro_pathname);

	bpf_probe_read_str(req->new_filename, CHAR_MAX, ctx->new_filename);
	bpf_probe_read_str(req->filename, CHAR_MAX, ctx->old_filename);
	bpf_printk("old filename is :%s", ctx->old_filename);
	bpf_printk("new filename is :%s", ctx->new_filename);

	bpf_printk("filename from current is %s", current->mm->exe_file->f_path.dentry->d_iname);

	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	// bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);

	return 0;
}


//---------------- LSM Hooks Below-------------------

SEC("lsm/file_ioctl")
int BPF_PROG(lsm_file_ioctl, struct file *file, unsigned int cmd, unsigned long arg, int ret) {

	bpf_printk("cmd is %d", cmd);
	bpf_printk("arg is %ld", arg);

	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
	if (!req)
		return 0;

	bpf_printk("comm is %s", current->comm);
	get_base_info_filereq(req);
	// skip_current(&(req->pinfo));

	req->op_type = 1;    // In the open hook, the type is "1", representing the "open operation".

	// Get the mtime.
	req->mtime_sec = file->f_inode->i_mtime.tv_sec;
	req->mtime_nsec = file->f_inode->i_mtime.tv_nsec;

	bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
	bpf_printk("mtime_sec is %ld", req->mtime_sec);
	bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

	bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
	bpf_d_path(&(file->f_path), req->filename, sizeof(req->filename));
	req->mode = file->f_mode;
	req->flags = file->f_flags;
	// bpf_printk("current file flags is %d", file->f_flags);
	// bpf_printk("current file modes is %d", file->f_mode);

	get_absolute_path(req->pro_pathname);
	bpf_printk("filename is %s", req->filename);


	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);

	return ret;
}

int string_ope(char *str_1) {

    bpf_printk("string is %s", str_1);
    bpf_printk("string[0] is %c", str_1[0]);

    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret) {
	bpf_printk("mask is %d", mask);
	struct task_struct *current = bpf_get_current_task_btf();

	string_ope(current->comm);

	return ret;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret) {

	// bpf_printk("flags is %u", file->f_flags);
	// if ((file->f_flags & 01) != 01)
	// 	return 0;

	// Judge whether the inode is legal.
	if (IS_ERR(file->f_inode))
		return 0;

	// Only to normal file.
	if (!S_ISREG(file->f_inode->i_mode)) {
		// bpf_printk("(%s) i_mode is %d, not regular (0100000) file", file->f_path.dentry->d_iname, file->f_inode->i_mode);
		return 0;
	}

	char temp[128] = {};
	bpf_d_path(&(file->f_path), temp, sizeof(temp));

	if (my_strncmp(temp, "/proc/", 6)==0 || my_strncmp(temp, "/sys/", 5)==0)
		return 0;

	/* Test Code, used to limit trigger condition. */
	// bpf_probe_read(temp, sizeof(temp), file->f_path.dentry->d_iname);
	// if (my_strcmp(temp, "test.txt")==0) {
	// 	bpf_printk("test.txt has been open...");
	// 	bpf_printk("file mode is %u", file->f_mode);
	// 	bpf_printk("inode i_mode is %u", file->f_inode->i_mode);
	// 	bpf_printk("file flags is %u", file->f_flags);
	// 	bpf_printk("inode flags is %u", file->f_inode->i_flags);
	// 	return 0;
	// }
	// else
	// 	return 0;
	bpf_printk("I'm in LSM file_open Hook...\n==============================");

	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(struct filereq_t), 0);
	if (!req)
		return 0;

	// bpf_printk("comm is %s", current->comm);
	get_base_info_filereq(req);
	skip_current(&(req->pinfo));
	get_args_from_mm(req);

	req->file_size = file->f_inode->i_size;
	req->op_type = OP_OPEN;    // In the open hook, the type is "1", representing the "open operation".

	// Get the mtime.
	req->mtime_sec = file->f_inode->i_mtime.tv_sec;
	req->mtime_nsec = file->f_inode->i_mtime.tv_nsec;

	bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
	bpf_printk("mtime_sec is %ld", req->mtime_sec);
	bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

	bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
	req->path_len = bpf_d_path(&(file->f_path), req->filename, sizeof(req->filename));
	req->mode = file->f_mode;
	req->flags = file->f_flags;
	// bpf_printk("current file flags is %d", file->f_flags);
	// bpf_printk("current file modes is %d", file->f_mode);

	get_absolute_path(req->pro_pathname);
	bpf_printk("filename is %s", req->filename);

	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);

	return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(lsm_file_create, struct inode *dir, struct dentry *dentry, umode_t mode, int ret) {

	// Only to normal file.
	if (!S_ISREG(mode)) {
		return 0;
	}

	char temp[128] = {};
	get_absolute_path_from_dentry(dentry, temp);
	if (my_strncmp(temp, "/proc/", 6)==0 || my_strncmp(temp, "/sys/", 5)==0)
		return 0;

	/* Test Code, used to limit trigger condition. */
	// bpf_probe_read(temp, sizeof(temp), dentry->d_iname);
	// if (my_strcmp(temp, "test.txt")==0) {
	// 	bpf_printk("test.txt has been open...");
	// 	bpf_printk("inode mode is %u", dentry->d_inode->i_mode);
	// 	bpf_printk("inode flags is %u", dentry->d_inode->i_flags);
	// 	bpf_printk("mode is %u", mode);
	// 	return 0;
	// }
	// else
	// 	return 0;
	bpf_printk("I'm in LSM inode create Hook...\n==============================");

	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
	if (!req)
		return 0;

	// bpf_printk("comm is %s", current->comm);
	get_base_info_filereq(req);
	skip_current(&(req->pinfo));
	get_args_from_mm(req);

	req->file_size = dentry->d_inode->i_size;
	req->op_type = OP_OPEN_C;    // In the open hook, the create type is "OP_OPN_C", representing the "open && create operation".

	// Get the mtime.
	req->mtime_sec = dentry->d_inode->i_mtime.tv_sec;
	req->mtime_nsec = dentry->d_inode->i_mtime.tv_nsec;

	bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
	bpf_printk("mtime_sec is %ld", req->mtime_sec);
	bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

	bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);
	req->path_len = get_absolute_path_from_dentry(dentry, req->filename);
	bpf_printk("filename is %s", req->filename);
	// req->mode = file->f_mode;
	// req->flags = file->f_flags;
	// bpf_printk("current file flags is %d", file->f_flags);
	// bpf_printk("current file modes is %d", file->f_mode);

	get_absolute_path(req->pro_pathname);


	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);

	return ret;
}

/*
lsm_file_link is to check the permission of the link operation
Thus new_dentry doesn't have vars "i_mode i_size i_flags"(All is equal to 0).
*/
SEC("lsm/inode_link")
int BPF_PROG(lsm_file_link, struct dentry* old_dentry, struct inode* dir, struct dentry* new_dentry, int ret) {

	// Judge whether the inode is legal.
	if (IS_ERR(dir) || IS_ERR(new_dentry))
		return 0;

	/* Test Code, used to limit trigger condition. */
	// bpf_probe_read(temp, sizeof(temp), old_dentry->d_iname);
	// if (my_strcmp(temp, "test.txt")==0) {
	// 	bpf_printk("test.txt has been linked...");
	// 	bpf_printk("old inode mode is %u", old_dentry->d_inode->i_mode);
	// 	bpf_printk("old inode flags is %u", old_dentry->d_inode->i_flags);
	// 	bpf_printk("new inode mode is %u", new_dentry->d_inode->i_mode);
	// 	bpf_printk("new inode flags is %u, size is %lld", new_dentry->d_inode->i_flags, new_dentry->d_inode->i_size);
	// 	return 0;
	// }
	// else
	// 	return 0;

	// Only to normal file.
	if (!S_ISREG(old_dentry->d_inode->i_mode))
		return 0;

	char temp[128] = {};
	get_absolute_path_from_dentry(new_dentry, temp);
	if (my_strncmp(temp, "/proc/", 6)==0 || my_strncmp(temp, "/sys/", 5)==0)
		return 0;

	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
	if (!req)
		return 0;

	// bpf_printk("comm is %s", current->comm);
	get_base_info_filereq(req);
	skip_current(&(req->pinfo));
	get_args_from_mm(req);

	req->op_type = OP_LINK;    // In the open hook, the type is "5", representing the "symlink" operation.

	// Get the size and the mtime of the file.
	req->file_size = old_dentry->d_inode->i_size;
	req->newfile_size = new_dentry->d_inode->i_size;
	req->mtime_sec = new_dentry->d_inode->i_mtime.tv_sec;
	req->mtime_nsec = new_dentry->d_inode->i_mtime.tv_nsec;

	bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
	bpf_printk("mtime_sec is %ld", req->mtime_sec);
	bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

	bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);

	get_absolute_path(req->pro_pathname);
	req->path_len = get_absolute_path_from_dentry(old_dentry, req->filename);
	req->newpath_len = get_absolute_path_from_dentry(new_dentry, req->new_filename);

	// req->path_len = bpf_probe_read_str(req->filename, sizeof(req->filename), old_dentry->d_iname);
	// req->newpath_len = bpf_probe_read_str(req->new_filename, sizeof(req->new_filename), new_dentry->d_iname);
	bpf_printk("old_filename is %s", req->filename);
	bpf_printk("new_filename is %s", req->new_filename);

	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);

	return ret;
}

SEC("lsm/inode_unlink")
int BPF_PROG(lsm_file_unlink, struct inode* dir, struct dentry* dentry, int ret) {

	if (IS_ERR(dir) || IS_ERR(dentry))
		return 0;

	/* Test Code, used to limit trigger condition. */
	// bpf_probe_read(temp, sizeof(temp), dentry->d_iname);
	// if (my_strcmp(temp, "testlink")==0) {
	// 	bpf_printk("testlink has been linked...");
	// 	bpf_printk(" inode mode is %u", dentry->d_inode->i_mode);
	// 	bpf_printk(" inode flags is %u, size is %lld", dentry->d_inode->i_flags, dentry->d_inode->i_size);
	// 	return 0;
	// }
	// else
	// 	return 0;

	// Only to normal file.
	if (!S_ISREG(dentry->d_inode->i_mode))
		return 0;

	char temp[128] = {};
	get_absolute_path_from_dentry(dentry, temp);
	if (my_strncmp(temp, "/proc/", 6)==0 || my_strncmp(temp, "/sys/", 5)==0)
		return 0;

	bpf_printk("removed hard link filename is %s", dentry->d_iname);
	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
	if (!req)
		return 0;

	// bpf_printk("comm is %s", current->comm);
	get_base_info_filereq(req);
	skip_current(&(req->pinfo));
	get_args_from_mm(req);

	req->op_type = OP_UNLINK;    // In the open hook, the type is "3", representing the "unlink" operation.
	req->flags = dentry->d_inode->i_flags;
	// bpf_printk("flags is %ld", req->flags);

	req->file_size = dentry->d_inode->i_size;
	req->mtime_sec = dentry->d_inode->i_mtime.tv_sec;
	req->mtime_nsec = dentry->d_inode->i_mtime.tv_nsec;

	bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
	bpf_printk("mtime_sec is %ld", req->mtime_sec);
	bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

	bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);

	get_absolute_path(req->pro_pathname);
	req->path_len = get_absolute_path_from_dentry(dentry, req->filename);
	bpf_printk("filename is %s", req->filename);

	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);

	return ret;
}

SEC("lsm/inode_rename")
int BPF_PROG(lsm_file_rename, struct inode *old_dir, struct dentry *old_dentry,
			    struct inode *new_dir, struct dentry *new_dentry,
			    unsigned int flags) {

	// bpf_printk("You are in rename hook!");
	bpf_printk("I'm in LSM inode rename Hook...\n==============================");

	if (IS_ERR(old_dir) || IS_ERR(old_dentry) || IS_ERR(new_dir) || IS_ERR(new_dentry))
		return 0;

	/* Test Code, used to limit trigger condition. */
	// char temp[128] = {};
	// bpf_probe_read(temp, sizeof(temp), old_dentry->d_iname);
	// if (my_strcmp(temp, "test.txt")==0) {
	// 	bpf_printk("test.txt has been renamed...");
	// 	bpf_printk("old inode mode is %u", old_dentry->d_inode->i_mode);
	// 	bpf_printk("old inode flags is %u, size is %lld", old_dentry->d_inode->i_flags, old_dentry->d_inode->i_size);
	// 	bpf_printk("new inode mode is %u", new_dentry->d_inode->i_mode);
	// 	bpf_printk("new inode flags is %u, size is %lld", new_dentry->d_inode->i_flags, new_dentry->d_inode->i_size);

	// 	return 0;
	// }
	// else
	// 	return 0;

	struct task_struct *current = bpf_get_current_task_btf();
	struct filereq_t *req = bpf_ringbuf_reserve(&filereq_ringbuf, sizeof(*req), 0);
	if (!req)
		return 0;

	// bpf_printk("comm is %s", current->comm);
	get_base_info_filereq(req);
	skip_current(&(req->pinfo));
	get_args_from_mm(req);

	req->op_type = OP_RENAME;    // In the open hook, the type is "4", representing the "rename" operation.
	req->flags = flags;
	// bpf_printk("flags is %ld", req->flags);

	req->file_size = old_dentry->d_inode->i_size;
	req->newfile_size = new_dentry->d_inode->i_size;
	req->mtime_sec = old_dir->i_mtime.tv_sec;
	req->mtime_nsec = old_dir->i_mtime.tv_nsec;

	// bpf_printk("bpf_ktime_get_ns time is %ld", bpf_ktime_get_ns());
	// bpf_printk("mtime_sec is %ld", req->mtime_sec);
	// bpf_printk("mtime_nsec is %ld", req->mtime_nsec);

	bpf_probe_read_kernel_str(req->comm, sizeof(req->comm), current->comm);
	bpf_probe_read_kernel_str(req->parent_comm, sizeof(req->parent_comm), current->real_parent->comm);

	get_absolute_path(req->pro_pathname);
	req->path_len = get_absolute_path_from_dentry(old_dentry, req->filename);
	req->newpath_len = get_absolute_path_from_dentry(new_dentry, req->new_filename);

	// req->path_len = bpf_probe_read_str(req->filename, sizeof(req->filename), old_dentry->d_iname);
	// req->newpath_len = bpf_probe_read_str(req->new_filename, sizeof(req->new_filename), new_dentry->d_iname);
	bpf_printk("old_filename is %s", req->filename);
	bpf_printk("new_filename is %s", req->new_filename);

	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	bpf_ringbuf_submit(req, 0);
	return 0;
}


// Some eBPF programs must be GPL licensed. This depends on program types.
char _license[] SEC("license") = "GPL";
