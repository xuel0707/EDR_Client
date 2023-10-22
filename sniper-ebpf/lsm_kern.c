#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include <bpf/bpf_endian.h>
#include "structs.h"
#include "support_function.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} process_exc_ringbuf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    struct process_event  *e;
	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&process_exc_ringbuf, sizeof(*e), 0);
	if (!e)
		return 0;
	
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->pid = bpf_get_current_pid_tgid();
    e->tgid = bpf_get_current_pid_tgid()>>32;
    struct task_struct *current = bpf_get_current_task_btf();
	e->parent_pid=current->parent->self_exec_id;
	bpf_probe_read_kernel_str(e->parent_comm, sizeof(current->parent->comm), current->parent->comm); 
	bpf_probe_read_user_str(e->args[0], sizeof(e->args[0]), (const void*)ctx->args[0]);
    e->pinfo.task[0].pid = current->real_parent->pid;
    bpf_probe_read_kernel_str(e->pinfo.task[0].comm, sizeof(e->pinfo.task[0].comm), current->real_parent->comm);

	const char *arg_ptr;
    e->argc=0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &((const char **)ctx->args[1])[i]);
        if (!arg_ptr)
            break;

        e->argc++;
        bpf_probe_read_user_str(e->args[i], sizeof(e->args[i]), arg_ptr);
    }

    bpf_printk("sys_enter_execve: comm[%s]  argc[%d] args[0]:%s args[1]:%s args[2]:%s args[3]:%s args[4]:%s\n", e->comm, e->argc, e->args[0], e->args[1], e->args[2], e->args[3], e->args[4]);
	
	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

// Some eBPF programs must be GPL licensed. This depends on program types.
char _license[] SEC("license") = "GPL";
