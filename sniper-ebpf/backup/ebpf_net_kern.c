#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "structs.h"

#define AF_INET 2
#define TASK_COMM_LEN 16

// char __license[] SEC("license") = "Dual MIT/GPL";
char _license[] SEC("license") = "GPL";



/**
 * This example copies parts of struct sock_common and struct sock from
 * the Linux kernel, but doesn't cause any CO-RE information to be emitted
 * into the ELF object. This requires the struct layout (up until the fields
 * that are being accessed) to match the kernel's, and the example will break
 * or misbehave when this is no longer the case.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct sock_common reflects the start of the kernel's struct sock_common.
 * It only contains the fields up until skc_family that are accessed in the
 * program, with padding to match the kernel's declaration.
 */
// struct sock_common {
// 	union {
// 		struct {
// 			__be32 skc_daddr;
// 			__be32 skc_rcv_saddr;
// 		};
// 	};
// 	union {
// 		// Padding out union skc_hash.
// 		__u32 _;
// 	};
// 	union {
// 		struct {
// 			__be16 skc_dport;
// 			__u16 skc_num;
// 		};
// 	};
// 	short unsigned int skc_family;
// };

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
// struct sock {
// 	struct sock_common __sk_common;
// };

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} netreq_ringbuf SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct netreq_t's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */


// struct netreq_t *unused __attribute__((unused));

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}
	struct netreq_t *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&netreq_ringbuf, sizeof(struct netreq_t), 0);
	if (!tcp_info) {
		return 0;
	}

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = sk->__sk_common.skc_dport;
	tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);
	tcp_info->pid = bpf_get_current_pid_tgid() >> 32;

    // bpf_printk("source ip is %u", tcp_info->saddr);
    // bpf_printk("destination ip is %u", tcp_info->daddr);
    // bpf_printk("source port  is %d", tcp_info->sport);
    // bpf_printk("destination port is %d", tcp_info->dport);

	bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

	struct css_set *css;
	struct cgroup_subsys_state *sbs;
	struct cgroup *cg;
	struct kernfs_node *knode, *pknode;

	// css = task->cgroups;
	struct task_struct *task = (void *)bpf_get_current_task();
	bpf_probe_read_kernel(&css, sizeof(css), &task->cgroups);
	bpf_probe_read_kernel(&sbs, sizeof(sbs), &css->subsys[0]);
	bpf_probe_read_kernel(&cg, sizeof(cg), &sbs->cgroup);

	bpf_probe_read_kernel(&knode, sizeof(knode), &cg->kn);
	bpf_probe_read_kernel(&pknode, sizeof(pknode), &knode->parent);
	if(pknode != NULL) {
		char *aus;
		bpf_probe_read_kernel(&aus, sizeof(aus), &knode->name);
		bpf_printk("aus is %s", aus);
		// tcp_info->containerid = aus;
		bpf_core_read_str(tcp_info->containerid, sizeof(tcp_info->containerid), aus);
		// if (ret < 0) {
		// 	bpf_printk("could not read filename into netreq_t struct: %d", ret);
		// 	bpf_ringbuf_discard(tcp_info, 0);
		// 	return 1;
		// }
	}

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
