#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "structs.h"
#include <math.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int handle_exec_event(void *ctx, void *data, size_t data_sz) {
    const struct taskreq_t *e = data;

    printf("EXEC process: %s(%d), nodename: %s(%u)\n", e->cmd, e->pid, e->nodename, e->mnt_id);
    printf("EXEC parent: %s(%d)\n", e->pinfo.task[0].comm, e->ppid);
    printf("EXEC cwd: %s\n", e->cwd);
    printf("EXEC filename: %s\n", e->cmd);
    printf("EXEC tty: %s\n", e->tty);
    printf("EXEC argc: %d\n", e->argc);
    for (int i = 0; i < e->argc; i++) {
        printf("EXEC arg%d: %s\n", i, e->args[i]);
    }
    printf("====================\n");
    return 0;
}

int handle_file_event(void *ctx, void *data, size_t data_sz) {
    struct filereq_t *e = data;
    printf("filename is %s\n", e->filename);
    return 0;
}

/*
Transform the unsigned var into the Ip Address.
*/
void int_to_ip(unsigned int addr, char *ip) {

    memset(ip, 0, strlen(ip));
    char buf[16] = {0};
    int ip_1 = addr / pow(2, 24);
    int ip_2 = addr % (int)pow(2, 24) / pow(2, 16);
    int ip_3 = addr % (int)pow(2, 16) / pow(2, 8);
    int ip_4 = addr % (int)pow(2, 8);
    sprintf(buf, "%d", ip_4);
    strcpy(ip, buf);
    sprintf(buf, ".%d", ip_3);
    strcat(ip, buf);
    sprintf(buf, ".%d", ip_2);
    strcat(ip, buf);
    sprintf(buf, ".%d", ip_1);
    strcat(ip, buf);

}

int handle_net_event(void *ctx, void *data, size_t data_sz) {
    const struct netreq_t *e = data;

    // char daddr[32] = {0};
    // char saddr[32] = {0};
    // int_to_ip(e->daddr, daddr);
    // int_to_ip(e->saddr, saddr);

    // printf("%-15s %-6d -> %-15s %-6d\n", saddr, e->sport, daddr, e->dport);

    // printf("Net daddr ip is %s\n", daddr);
    // printf("Net saddr ip is %s\n", saddr);

    return 0;
}

struct bpf_link *tp_execve_link = NULL;
struct bpf_link *tp_file_link = NULL;
struct bpf_link *net_connect_link = NULL;
struct bpf_link *net_xdp_link = NULL;

void sig_handler(int signum) {
    int destroy_res = bpf_link__destroy(tp_execve_link);
    int destroy_res_file = bpf_link__destroy(tp_file_link);
    int destroy_res_net_connect = bpf_link__destroy(net_connect_link);
    int destroy_res_net_xdp = bpf_link__destroy(net_xdp_link);

    printf("bpf exec link destroy result: %d\n", destroy_res);
    printf("bpf file link destroy result: %d\n", destroy_res_file);
    printf("bpf net link destroy result: %d\n", destroy_res_net_connect);
    printf("bpf net link destroy result: %d\n", destroy_res_net_xdp);

    printf("the program is over......\n");
    exit(0);
}

struct bpf_object *load_exec_program(char *exec_path) {
    struct bpf_object *exec_obj;
    exec_obj = bpf_object__open(exec_path);

    printf("Ok! exec BPF bytecode open over......\n");

    int exec_load_res = bpf_object__load(exec_obj);
    if (exec_load_res != 0){
        printf("BPF Program loaded failed......\n");
        return NULL;
    }

    struct bpf_program *tp_execve_prog = bpf_object__find_program_by_name(exec_obj, "trace_enter_execve");
    tp_execve_link = bpf_program__attach(tp_execve_prog);
    return exec_obj;
}

struct bpf_object *load_file_program(char *file_path) {
    struct bpf_object *file_obj;
    file_obj = bpf_object__open(file_path);

    printf("Ok! file BPF bytecode open over......\n");

    int file_load_res = bpf_object__load(file_obj);
    if (file_load_res != 0){
        printf("file BPF Program loaded failed......\n");
        return NULL;
    }

    struct bpf_program *tp_file_prog = bpf_object__find_program_by_name(file_obj, "lsm_file_open");
    tp_file_link = bpf_program__attach(tp_file_prog);

    return file_obj;
}

struct bpf_object *load_net_program(char *net_path) {
    struct bpf_object *net_obj;
    net_obj = bpf_object__open(net_path);

    printf("Ok! net BPF bytecode open over......\n");

    int net_load_res = bpf_object__load(net_obj);
    if (net_load_res != 0){
        printf("Net BPF Program loaded failed......\n");
        return NULL;
    }

    struct bpf_program *net_connect_prog = bpf_object__find_program_by_name(net_obj, "sample_socket_connect");
    struct bpf_program *net_xdp_prog = bpf_object__find_program_by_name(net_obj, "sample_pkt_from_xdp");
    net_connect_link = bpf_program__attach(net_connect_prog);
    net_xdp_link = bpf_program__attach(net_xdp_prog);

    return net_obj;
}

int main(int argc, char **argv) {

    // char exec_path[PATH_MAX];
    // sprintf(exec_path, "%s/lsm_kern.o", dirname(argv[0]));
    // struct bpf_object* exec_obj = load_exec_program(exec_path);
    // if (!exec_obj){
    //     return -1;
    // }

    // char file_path[PATH_MAX];
    // sprintf(file_path, "%s/ebpf_file_kern.o", dirname(argv[0]));
    // struct bpf_object* file_obj = load_file_program(file_path);
    // if (!file_obj){
    //     return -1;
    // }

    char net_path[PATH_MAX];
    sprintf(net_path, "%s/ebpf_net_kern.o", dirname(argv[0]));
    struct bpf_object* net_obj = load_net_program(net_path);
    if (!net_obj){
        return -1;
    }

    // register signal handlers
    signal(SIGINT, sig_handler);    // Ctrl + C
    signal(SIGTERM, sig_handler);
    signal(SIGTSTP, sig_handler);   // Ctrl + Z

    // struct bpf_map *exec_event_ringbuf_map = bpf_object__find_map_by_name(exec_obj, "taskreq_ringbuf");
    // int ringbuf_map_fd = bpf_map__fd(exec_event_ringbuf_map);
    // struct ring_buffer *exec_event_ringbuf = NULL;
    // exec_event_ringbuf = ring_buffer__new(ringbuf_map_fd, handle_exec_event, NULL, NULL);
    // if (!exec_event_ringbuf) {
    //     printf("Failed to create ring buffer\n");
    //     return -1;
    // }

    // struct bpf_map *file_event_ringbuf_map = bpf_object__find_map_by_name(file_obj, "filereq_ringbuf");
    // int file_ringbuf_map_fd = bpf_map__fd(file_event_ringbuf_map);
    // struct ring_buffer *file_event_ringbuf = NULL;
    // file_event_ringbuf = ring_buffer__new(file_ringbuf_map_fd, handle_file_event, NULL, NULL);

    // if (!file_event_ringbuf) {
    //     printf("Failed to create ring buffer\n");
    //     return -1;
    // }

    struct bpf_map *net_event_ringbuf_map = bpf_object__find_map_by_name(net_obj, "net_event_ringbuf");
    int net_ringbuf_map_fd = bpf_map__fd(net_event_ringbuf_map);
    struct ring_buffer *net_event_ringbuf = NULL;
    net_event_ringbuf = ring_buffer__new(net_ringbuf_map_fd, handle_net_event, NULL, NULL);

    if (!net_event_ringbuf) {
        printf("Failed to create ring buffer\n");
        return -1;
    }

    printf("receive from ring buf...\n");
    printf("%-15s %-6s -> %-15s %-6s\n", "Src addr", "Port", "Dest addr", "Port");
    while(1) {
        // ring_buffer__poll(exec_event_ringbuf, 100 /* timeout, ms */);
        // ring_buffer__poll(file_event_ringbuf, 100 /* timeout, ms */);
        ring_buffer__poll(net_event_ringbuf, 100 /* timeout, ms */);
    }


    // print bpf_map info.
    // struct bpf_map *lsm_map = bpf_object__find_map_by_name(obj, "socket_connect_map");
    // int lsm_map_fd = bpf_map__fd(lsm_map);
    // long key=-1, prev_key;
    // long val;



    printf("the program is over......\n");
    return 0;
}
