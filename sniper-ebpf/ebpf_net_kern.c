#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include <bpf/bpf_endian.h>
#include "structs.h"
#include "support_function.h"

#define AF_INET 2
#define ETH_P_IP 0x0800
/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256*1024);
} xdp_ringbuf SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(sample_socket_connect,struct socket *sock, struct sockaddr *address, int addrlen)
{
  // Assuming IPv4 here
  if (address->sa_family != AF_INET) 
  {  
    return 0;
  }
  struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
  
  struct sock_event  *e;
  /* reserve sample from BPF ringbuf */
  e = bpf_ringbuf_reserve(&xdp_ringbuf, sizeof(*e), 0);
  if (!e)
    return 0;

  struct task_struct *current = bpf_get_current_task_btf();
  e->sessionid=current->sessionid;
  e->start_time=current->start_time;
  e->uid = current->cred->uid.val;
  e->gid = current->cred->gid.val;
  e->dport=bpf_ntohs(addr_in->sin_port);
  e->daddr=addr_in->sin_addr.s_addr;
  e->protocol=sock->sk->sk_protocol;
  e->sport=sock->sk->__sk_common.skc_num;
  e->saddr=sock->sk->__sk_common.skc_rcv_saddr;
  bpf_probe_read_kernel_str(e->pathname, sizeof(current->fs->pwd.dentry->d_name.name),current->fs->pwd.dentry->d_name.name);
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_printk("sample_socket_connect tcp connect: src_ip[%d.%d.%d.%d] sport[%d]-> dst_ip[%d.%d.%d.%d] dport[%d] comm[%s] protocol[%d]\r",
        (u8)(e->saddr),  (u8)(e->saddr>>8), (u8)(e->saddr>>16),  (u8)(e->saddr>>24), e->sport,
          (u8)(e->daddr),  (u8)(e->daddr>>8), (u8)(e->daddr>>16),  (u8)(e->daddr>>24), e->dport,e->comm,e->protocol);     

  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("xdp")
int sample_pkt_from_xdp(struct xdp_md* ctx) 
{
  void* data_begin = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  struct ethhdr *eth = data_begin;

  //Check packet's size
  if ((void*)(eth + 1) > data_end) 
    return XDP_PASS; 

  //Check if Ethernet frame has IPv4 packet
  if (eth->h_proto == bpf_htons(ETH_P_IP))
  {
    struct iphdr *ip_head = (struct iphdr *)((void*)eth + sizeof(struct ethhdr));
    if ((void*)(ip_head + 1) > data_end) 
      return XDP_PASS;

      //Check if IPv4 packet contains a TCP segment
    if (ip_head->protocol == IPPROTO_ICMP)
    {
      struct sock_event  *e;
        /* reserve sample from BPF ringbuf */
        e = bpf_ringbuf_reserve(&xdp_ringbuf, sizeof(*e), 0);
        if (!e)
          return 0;

        struct task_struct *current = bpf_get_current_task_btf();
        e->sessionid=current->sessionid;
        e->start_time=current->start_time;
        e->uid = current->cred->uid.val;
        e->gid = current->cred->gid.val;
        e->daddr=ip_head->daddr;
        e->protocol=ip_head->protocol;
        e->saddr=ip_head->saddr;

        bpf_printk("sample_pkt_from_xdp icmp: src_ip[%d.%d.%d.%d] -> dst_ip[%d.%d.%d.%d] protocol[%d]\r",
            (u8)(ip_head->saddr),  (u8)(ip_head->saddr>>8), (u8)(ip_head->saddr>>16),  (u8)(ip_head->saddr>>24), 
              (u8)(ip_head->daddr),  (u8)(ip_head->daddr>>8), (u8)(ip_head->daddr>>16),  (u8)(ip_head->daddr>>24),e->protocol);    

        /* send data to user-space for post-processing */
        bpf_ringbuf_submit(e, 0);
    }

    //Check if IPv4 packet contains a TCP segment
    if (ip_head->protocol == IPPROTO_TCP)
    {
      struct tcphdr *tcp_head = (struct tcphdr*)((void*)ip_head + sizeof(struct iphdr));
      if ((void*)(tcp_head + 1) > data_end) 
        return XDP_PASS;

      // This is a TCP fin
      if (tcp_head->fin)
      { 
        struct sock_event  *e;
        /* reserve sample from BPF ringbuf */
        e = bpf_ringbuf_reserve(&xdp_ringbuf, sizeof(*e), 0);
        if (!e)
          return 0;

        struct task_struct *current = bpf_get_current_task_btf();
        e->sessionid=current->sessionid;
        e->start_time=current->start_time;
        e->uid = current->cred->uid.val;
        e->gid = current->cred->gid.val;
        e->dport=tcp_head->dest;
        e->daddr=ip_head->daddr;
        e->protocol=ip_head->protocol;
        e->sport=tcp_head->source;
        e->saddr=ip_head->saddr;
        e->fin=tcp_head->fin;

        bpf_printk("sample_pkt_from_xdp tcp fin: src_ip[%d.%d.%d.%d] sport[%d]-> dst_ip[%d.%d.%d.%d] dport[%d]\r",
              (u8)(ip_head->saddr),  (u8)(ip_head->saddr>>8), (u8)(ip_head->saddr>>16),  (u8)(ip_head->saddr>>24), tcp_head->source,
                (u8)(ip_head->daddr),  (u8)(ip_head->daddr>>8), (u8)(ip_head->daddr>>16),  (u8)(ip_head->daddr>>24), tcp_head->dest);     

        /* send data to user-space for post-processing */
        bpf_ringbuf_submit(e, 0);
      }
    } 
  }
  
  return XDP_PASS;
}

// Some eBPF programs must be GPL licensed. This depends on program types.
char _license[] SEC("license") = "GPL";