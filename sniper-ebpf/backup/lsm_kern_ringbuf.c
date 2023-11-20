#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "support_function.h"
#include "structs.h"

// Define the bpf_map data structure.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, long);
    __type(value, long);
    __uint(max_entries, 64);
} socket_connect_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, long);
    __type(value, struct TestStruct);
    __uint(max_entries, 64);
} book_test SEC(".maps");

// struct
// {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __type(key, int);
//     __type(value, struct Msg);
//     __uint(max_entries, 1);
// } big_string_map SEC(".maps");

/* Used to send msg from tp to lsm */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, long);
    __type(value, struct event);
    __uint(max_entries, 64);
} argv_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

long key = 1;
long val;

struct sys_enter_execve_args{
	char buf[24];
	char **argv ;
};

// We could use commands below to get the TP hook args.
// cat /sys/kernel/debug/tracing/events/syscalls/{sys_enter_execve}/format
SEC("tp/syscalls/sys_enter_execve")
int trace_enter_execve(struct sys_enter_execve_args *ctx){
	bpf_printk("I'm in tracepoint hook!...");

	long key = 10;
	// struct event *ev = NULL;
	// ev->pid = 6666;
	// bpf_probe_read_kernel_str(ev->data, 6, "hello");
	// bpf_map_update_elem(&argv_map, &key, ev, BPF_NOEXIST);

	long val = 66;
	bpf_map_update_elem(&socket_connect_map, &key, &val, BPF_ANY);
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_demo, struct linux_binprm *bprm, int ret){

    if (ret != 0){
		bpf_printk("the last bpf return value is %d", ret);
        return ret;
	}

	struct event *e = NULL;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_kernel_str(e->data, sizeof(e->data), bprm->filename);
	bpf_ringbuf_submit(e, 0);

	long second_key = 10;
	long *value = bpf_map_lookup_elem(&socket_connect_map, &second_key);
	if(value) {
		bpf_printk("Recieve the Data from TracePoint %ld\n", *value);
	} else {
		bpf_printk("yikes, no value found at key %ld", second_key);
	}

	/* Print filename Basic Information */
	char filename[CHAR_MAX] = {0};
	int length_filename = bpf_probe_read_kernel_str(filename, CHAR_MAX, bprm->filename);
	bpf_printk("filename length is  %d", length_filename);
	// bpf_printk("filename is  %s", filename);

	// bpf_map_update_elem(&big_string_map, &key, filename, BPF_ANY);
	// struct Msg *msg = {0};
	// char *msg = bpf_map_lookup_elem(&big_string_map, &key);
	// bpf_printk("msg  is  %s", msg);

	char basename[CHAR_MAX] = {0};
	safebasename(basename, CHAR_MAX, filename);
	bpf_printk("judge %s(%s)[%s]", bprm->filename, basename, filename);

	if (my_strcmp2(basename, "cupsd") == 0) {
		bpf_printk("forbid cupsd, disable printer");
		return -1;
	}

	/* Prelink will call many times 'd-linux-x86-64.so.2' */
	if (my_strcmp2(filename, "/lib64/ld-linux-x86-64.so.2") == 0) {
		return 0;
	}



    return 0;
}

// Some eBPF programs must be GPL licensed. This depends on program types.
char _license[] SEC("license") = "GPL";
