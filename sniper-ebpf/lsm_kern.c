#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "structs.h"
#include "support_function.h"

// missing defs from usr/include/linux/major.h
#define PTY_SLAVE_MAJOR		3
#define TTY_MAJOR		4

// missing defs from include/linux/kdev_t.h
#define MINORBITS 20

#define UNIX98_PTY_MASTER_MAJOR	128
#define UNIX98_PTY_MAJOR_COUNT	8
#define UNIX98_PTY_SLAVE_MAJOR	(UNIX98_PTY_MASTER_MAJOR+UNIX98_PTY_MAJOR_COUNT)

// Define the bpf_map data structure.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, long);
    __type(value, long);
    __uint(max_entries, 64);
} socket_connect_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct taskreq_t);
} heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, long);
    __type(value, struct TestStruct);
    __uint(max_entries, 64);
} book_test SEC(".maps");

struct file_policy_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, long);
    __type(value, struct kern_file_policy);
    __uint(max_entries, 64);
} file_policy_map SEC(".maps");

// send taskreq_t events using this ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} taskreq_ringbuf SEC(".maps");


int check_if_print(struct kern_file_policy *sniper_fpolicy) {
	if (!sniper_fpolicy)
		return 0;    // If sniper fpolicy doesn't exist, We think the cupsd is allowed.

	int print_on = sniper_fpolicy->printer_on;
	int terminal = sniper_fpolicy->printer_terminate;
	bpf_printk("printer_on is: %d, terminal is %d", print_on, terminal);
	if (print_on && terminal){
		return 1;
	}
	else{
		return 0;
	}
}

inline unsigned int get_mnt_id() {
    struct task_struct *current = bpf_get_current_task_btf();
    return current->nsproxy->mnt_ns->ns.inum;
}

inline char *get_uts_name() {
    struct task_struct *current = bpf_get_current_task_btf();
    return current->nsproxy->uts_ns->name.nodename;
}

// We could use commands below to get the args of the TP hook.
// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
SEC("tp/syscalls/sys_enter_execve")
int trace_enter_execve(struct sys_enter_execve_args *ctx) {
	char realpath[CHAR_MAX] = {0};
	struct task_struct *current = bpf_get_current_task_btf();
	bpf_printk("file comm is :%s", current->comm);

	struct taskreq_t *req = bpf_ringbuf_reserve(&taskreq_ringbuf, sizeof(*req), 0);
	// Check whether the req is NULL, otherwise we couldn't operate it in eBPF.
	if (!req)
		return 0;

	// __builtin_memset(req, 0, sizeof(*req)); // memset not working if the struct is too large

	/* Get the essential information of the taskreq_t */
	get_base_info_req(req);
	/* Get the parent process info and skip sniper sub-processes*/
	skip_current(&(req->pinfo));
	// set ppid
	req->ppid = req->pinfo.task[0].pid;

	/* Get cmd (executable filename of current process) */
	req->cmdlen = bpf_probe_read_str(req->cmd, sizeof(req->cmd), ctx->filename);
	bpf_printk("filename(%d): %s", req->cmdlen, req->cmd);

	/* Get the realpath of the cwd */
	get_absolute_path(realpath);
	req->cwdlen = bpf_probe_read_str(req->cwd, sizeof(req->cwd), realpath);
	bpf_printk("cwd(%d): %s", req->cwdlen, req->cwd);

	/* Get the fields with respect to arguments */
	get_args_argc(ctx->argv, req);
	bpf_printk("argc is %d", req->argc);
	bpf_printk("options is %d", req->options);

	/* Get mnt_id and nodename */
	req->mnt_id = get_mnt_id();
	bpf_probe_read_str(req->nodename, sizeof(req->nodename), get_uts_name());
	bpf_printk("Mount namespace id: %u, nodename: %s", req->mnt_id, req->nodename);

	/* Get tty */
    if (current->signal && current->signal->tty) {
        bpf_probe_read_str(req->tty, sizeof(req->tty), current->signal->tty->name);
        bpf_printk("tty: %s", req->tty);
    } else {
        bpf_printk("get tty from fd1...");
        struct file *file1 = current->files->fd_array[1];
        struct inode *inode = file1->f_path.dentry->d_inode;
        if (file1 && inode) {
            int major = (unsigned int) ((inode->i_rdev) >> MINORBITS);
            if (major == PTY_SLAVE_MAJOR || major == TTY_MAJOR ||
                (major >= UNIX98_PTY_SLAVE_MAJOR && major < UNIX98_PTY_SLAVE_MAJOR+8)) {
                bpf_probe_read_str(req->tty, sizeof(req->tty), file1->f_path.dentry->d_name.name);
                bpf_printk("tty: %s", req->tty);
            }
        }
    }

	/* Get the fd number */
	struct files_struct *files = current->files;
	int files_number = count_files_num(files);
	bpf_printk("current process has %d fd", files_number);
	bpf_ringbuf_submit(req, 0);

	return 0;
}

// SEC("lsm/bprm_check_security")
// int BPF_PROG(lsm_demo, struct linux_binprm *bprm, int ret){

//     if (ret != 0){
//         return ret;
// 	}

// 	// long key = 0;

// 	// char temp[CHAR_MAX] = {0};
// 	char current_filename[CHAR_MAX];
// 	// char realpath[CHAR_MAX];
// 	bpf_probe_read_kernel_str(current_filename, CHAR_MAX, bprm->filename);

// 	if (current_filename[0] == '\0')
// 		return 0;
// 	bpf_printk("current_filename is %s", current_filename);

// 	int zero = 0;
// 	struct taskreq_t *req = NULL;
// 	req = bpf_map_lookup_elem(&heap, &zero);

// 	if (!req)
// 		return 0;

// 	/* Check the cupsd */
// 	// // We get the flag from user-space to judge whether forbid "cupsd" operation.
// 	// struct kern_file_policy *file_policy = NULL;
// 	// file_policy = bpf_map_lookup_elem(&file_policy_map, &key);
// 	// if (check_if_print(file_policy) == 1){
// 	// 	safebasename(temp, sizeof(temp), current_filename);
// 	// 	if (my_strcmp(temp, "cupsd") == 0){
// 	// 		bpf_printk("forbid cupsd");
// 	// 		return -1;
// 	// 	}
// 	// }

// 	if (my_strcmp(current_filename, "/opt/snipercli/sniper_chk")==0){
// 		bpf_printk("The executing file is sniper_chk, Skip the check...");
// 		return 0;
// 	}
// 	if (my_strcmp(current_filename, "/opt/snipercli/assist_sniper_chk")==0){
// 		bpf_printk("The executing file is assist_sniper_chk, Skip the check...");
// 		return 0;
// 	}

// 	skip_current(&(req->pinfo));


// 	// struct TestStruct test = {0};
// 	// bpf_probe_read(test.author, 6, "CiXin");
// 	// bpf_probe_read(test.title, 6, "Earth");
// 	// test.length = 10;

// 	// bpf_map_update_elem(&book_test, &zero, &test, BPF_NOEXIST);

// 	/* Test the var "req" needed to be passed to the user-space*/
// 	// struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();



// 	// if (!req)
// 	// 	return 0;

// 	// req->pid = current_task->pid;
// 	// req->argc = bprm->argc;
// 	// req->uid = bpf_get_current_uid_gid();
// 	// req->tgid = bpf_get_current_pid_tgid() << 32;
// 	// req->proctime = current_task->start_time;
// 	// bpf_probe_read(req->buf, sizeof(req->buf), "hello");

// 	// bpf_map_update_elem(&heap, &zero, req, BPF_ANY);


// 	// bpf_printk("------------current_pid is: %d", current_task->pid);
// 	// bpf_printk("------------start_time is: %lld", current_task->start_time);
// 	// bpf_printk("------------boot_time is: %lld", current_task->start_boottime);
// 	// bpf_printk("------------current_tgid is: %d", current_task->tgid);

// 	/* Get the realpath of the filename */
// 	int cmdlen = get_absolute_path();
// 	bpf_printk("-----------cmdlen is : %d", cmdlen);

// 	struct task_struct *task = NULL;
// 	task = bpf_get_current_task_btf();

// 	struct file *file0 = task->files->fd_array[0];
// 	struct file *file1 = task->files->fd_array[1];
// 	req->pipein = file0->f_path.dentry->i_ino;
// 	req->pipeout = file1->f_path.dentry->i_ino;
// 	bpf_printk("i_ino_0 %d", file0->f_path.dentry->i_ino);
// 	bpf_printk("i_ino_1 %d", file1->f_path.dentry->i_ino);

// 	req->exe_file = task->mm->exe_file;
// 	req->exeino = req->exe_file->f_path.dentry->i_ino;
// 	bpf_printk("exe_ino_1 %d", file1->f_path.dentry->i_ino);

// 	// bprm->filename = "hello";   // Used to create a Error.

//     return 0;
// }


// Some eBPF programs must be GPL licensed. This depends on program types.
char _license[] SEC("license") = "GPL";
