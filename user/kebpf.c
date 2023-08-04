/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* file */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "header.h"

extern int cwdmod;

struct bpf_object *bpf_objects[EBPF_OBJ_NUM] = {0};
struct bpf_link *bpf_links[EBPF_PROGRAMS_NUM] = {0};

int load_ebpf_program(void)
{
    printf("[kebpf] load_ebpf_program\n");

    int fd_exec = 0;
    int fd_file = 0;
    char exec_program_file[128] = {0};
    char file_program_file[128] = {0};
    char net_program_file[128] = {0};
    char failinfo[S_LINELEN] = {0};
    struct stat st = {0};

    if (cwdmod) {
        snprintf(exec_program_file, sizeof(exec_program_file), "./%s", EBPF_EXECVE_HOOK_PROGRAM);
        snprintf(file_program_file, sizeof(file_program_file), "./%s", EBPF_FILE_HOOK_PROGRAM);
        snprintf(net_program_file, sizeof(net_program_file), "./%s", EBPF_NET_HOOK_PROGRAM);
    } else {
        printf("load ebpf program in non-cwd mode has not been implmented, return error\n");
        return -1;
    }

    errno = 0;

    /* let's call init_module */
    // Firstly open the exec ebpf Program.
    if ((fd_exec = open(exec_program_file, O_RDONLY)) < 0) {
        if (errno == ENOENT) {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 没有exec eBPF程序%s\n", exec_program_file);
        } else {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 打开exec eBPF程序%s错误: %s\n",
                exec_program_file, strerror(errno));
        }
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_exec, &st) < 0) {
        snprintf(failinfo, sizeof(failinfo),
            "load module fail. 取exec eBPF程序%s属性错误: %s\n",
            exec_program_file, strerror(errno));

        save_sniper_status(failinfo);
        close(fd_exec);
        return -1;
    }

    errno = 0;
    // Secondly open the file ebpf Program.
    if ((fd_file = open(file_program_file, O_RDONLY)) < 0) {

        if (errno == ENOENT) {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 没有file eBPF程序%s\n", file_program_file);
        } else {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 打开file eBPF程序%s错误: %s\n",
                file_program_file, strerror(errno));
        }
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_file, &st) < 0) {
        snprintf(failinfo, sizeof(failinfo),
            "load module fail. 取file eBPF程序%s属性错误: %s\n",
            file_program_file, strerror(errno));

        save_sniper_status(failinfo);
        close(fd_file);
        return -1;
    }

    errno = 0;
    // Secondly open the file ebpf Program.
    if ((fd_file = open(net_program_file, O_RDONLY)) < 0) {

        if (errno == ENOENT) {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 没有 net eBPF程序%s\n", net_program_file);
        } else {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 打开 net eBPF程序%s错误: %s\n",
                net_program_file, strerror(errno));
        }
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_file, &st) < 0) {
        snprintf(failinfo, sizeof(failinfo),
            "load module fail. 取 net eBPF程序%s属性错误: %s\n",
            net_program_file, strerror(errno));

        save_sniper_status(failinfo);
        close(fd_file);
        return -1;
    }


    struct bpf_object *obj_exec;
    struct bpf_object *obj_file;
    struct bpf_object *obj_net;
    obj_exec = bpf_object__open(exec_program_file);
    obj_file = bpf_object__open(file_program_file);
    obj_net = bpf_object__open(net_program_file);
    printf("Ok! BPF bytecode open over......\n");

    int load_exec_res = bpf_object__load(obj_exec);
    int load_file_res = bpf_object__load(obj_file);
    int load_net_res = bpf_object__load(obj_net);
    if (load_exec_res != 0){
        printf("exec BPF Program loaded failed: %s(d)\n", strerror(errno), load_exec_res);
        return -1;
    }
    if (load_file_res != 0){
        printf("file BPF Program loaded failed: %s(d)\n", strerror(errno), load_file_res);
        return -1;
    }
    if (load_net_res != 0){
        printf("file BPF Program loaded failed: %s(d)\n", strerror(errno), load_net_res);
        return -1;
    }

    printf("Ok! BPF Program loaded......\n");
    // NOTE: currently we only have execve hook
    bpf_objects[EBPF_EXECVE_OBJ] = obj_exec;
    bpf_objects[EBPF_FILE_OBJ]   = obj_file;
    bpf_objects[EBPF_NET_OBJ]    = obj_net;

    // Find the program been loaded into the kernel.
    struct bpf_program *tp_execve_prog = bpf_object__find_program_by_name(obj_exec, "trace_enter_execve");
    struct bpf_program *lsm_file_open_prog = bpf_object__find_program_by_name(obj_file, "lsm_file_open");
    struct bpf_program *lsm_file_create_prog = bpf_object__find_program_by_name(obj_file, "lsm_file_create");
    struct bpf_program *lsm_file_rename_prog = bpf_object__find_program_by_name(obj_file, "lsm_file_rename");
    struct bpf_program *lsm_file_link_prog = bpf_object__find_program_by_name(obj_file, "lsm_file_link");
    struct bpf_program *lsm_file_unlink_prog = bpf_object__find_program_by_name(obj_file, "lsm_file_unlink");
    struct bpf_program *fentry_net_prog = bpf_object__find_program_by_name(obj_net, "tcp_connect");

    // attach the program into the Hooks.
    bpf_links[EBPF_EXECVE_PROG] = bpf_program__attach(tp_execve_prog);
    bpf_links[EBPF_FILE_OPEN_PROG] = bpf_program__attach(lsm_file_open_prog);
    bpf_links[EBPF_FILE_CREATE_PROG] = bpf_program__attach(lsm_file_create_prog);
    bpf_links[EBPF_FILE_RENAME_PROG] = bpf_program__attach(lsm_file_rename_prog);
    bpf_links[EBPF_FILE_LINK_PROG] = bpf_program__attach(lsm_file_link_prog);
    bpf_links[EBPF_FILE_UNLINK_PROG] = bpf_program__attach(lsm_file_unlink_prog);
    bpf_links[EBPF_NET_PROG] = bpf_program__attach(fentry_net_prog);

    // struct bpf_map *exec_event_ringbuf_map = bpf_object__find_map_by_name(obj, "events");
    // int ringbuf_map_fd = bpf_map__fd(exec_event_ringbuf_map);
    // struct ring_buffer *exec_event_ringbuf = NULL;
    // exec_event_ringbuf = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);

    return load_exec_res + load_file_res + load_net_res;
}

int unload_ebpf_program(void)
{
    printf("[kebpf] unload_ebpf_program\n");
    int destroy_exec_res = bpf_link__destroy(bpf_links[EBPF_EXECVE_PROG]);
    int destroy_file_open_res = bpf_link__destroy(bpf_links[EBPF_FILE_OPEN_PROG]);
    int destroy_file_create_res = bpf_link__destroy(bpf_links[EBPF_FILE_CREATE_PROG]);
    int destroy_file_rename_res = bpf_link__destroy(bpf_links[EBPF_FILE_RENAME_PROG]);
    int destroy_file_link_res = bpf_link__destroy(bpf_links[EBPF_FILE_LINK_PROG]);
    int destroy_file_unlink_res = bpf_link__destroy(bpf_links[EBPF_FILE_UNLINK_PROG]);
    int destroy_net_res = bpf_link__destroy(bpf_links[EBPF_NET_PROG]);
    printf("bpf exec link destroy result: %d\n", destroy_exec_res);
    printf("bpf file link destroy result: %d\n", destroy_file_open_res);
    printf("bpf file link destroy result: %d\n", destroy_file_create_res);
    printf("bpf file link destroy result: %d\n", destroy_file_rename_res);
    printf("bpf file link destroy result: %d\n", destroy_file_link_res);
    printf("bpf file link destroy result: %d\n", destroy_file_unlink_res);
    printf("bpf net link destroy result: %d\n", destroy_net_res);

    return destroy_exec_res + destroy_file_open_res + destroy_file_create_res + destroy_file_rename_res +
        destroy_file_link_res + destroy_file_unlink_res + destroy_net_res;
}

struct bpf_object *get_bpf_object(int type)
{
    if (type < 0 || type >= EBPF_EXECVE_HOOK_PROGRAM) {
        printf("[kebpf] get_bpf_object error, invalid type: %d\n", type);
        return NULL;
    }
    return bpf_objects[type];
}