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

struct bpf_object *bpf_objects[EBPF_PROGRAMS_NUM] = {0};
struct bpf_link *bpf_links[EBPF_PROGRAMS_NUM] = {0};

int load_ebpf_program(void)
{
    printf("[kebpf] load_ebpf_program\n");

    int fd = 0;
    char program_file[128] = {0};
    char failinfo[S_LINELEN] = {0};
    struct stat st = {0};

    if (cwdmod) {
        snprintf(program_file, sizeof(program_file), "./%s", EBPF_EXECVE_HOOK_PROGRAM);
    } else {
        printf("load ebpf program in non-cwd mode has not been implmented, return error\n");
        return -1;
    }

    errno = 0;

    /* let's call init_module */
    if ((fd = open(program_file, O_RDONLY)) < 0) {
        if (errno == ENOENT) {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 没有eBPF程序%s\n", program_file);
        } else {
            snprintf(failinfo, sizeof(failinfo),
                "load ebpf program fail. 打开eBPF程序%s错误: %s\n",
                program_file, strerror(errno));
        }
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        snprintf(failinfo, sizeof(failinfo),
            "load module fail. 取eBPF程序%s属性错误: %s\n",
            program_file, strerror(errno));

        save_sniper_status(failinfo);
        close(fd);
        return -1;
    }

    struct bpf_object *obj;
    obj = bpf_object__open(program_file);
    printf("Ok! BPF bytecode open over......\n");

    int load_res = bpf_object__load(obj);
    if (load_res != 0){
        printf("BPF Program loaded failed: %s(d)\n", strerror(errno), load_res);
        return -1;
    }
    printf("Ok! BPF Program loaded......\n");
    // NOTE: currently we only have execve hook
    bpf_objects[EBPF_EXECVE] = obj;

    // Find the program been loaded into the kernel.
    struct bpf_program *tp_execve_prog = bpf_object__find_program_by_name(obj, "trace_enter_execve");

    // attach the program into the Hooks.
    bpf_links[EBPF_EXECVE] = bpf_program__attach(tp_execve_prog);

    // struct bpf_map *exec_event_ringbuf_map = bpf_object__find_map_by_name(obj, "events");
    // int ringbuf_map_fd = bpf_map__fd(exec_event_ringbuf_map);
    // struct ring_buffer *exec_event_ringbuf = NULL;
    // exec_event_ringbuf = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);

    return load_res;
}

int unload_ebpf_program(void)
{
    printf("[kebpf] unload_ebpf_program\n");
    int destroy_res = bpf_link__destroy(bpf_links[EBPF_EXECVE]);
    printf("bpf link destroy result: %d\n", destroy_res);

    return destroy_res;
}

struct bpf_object *get_bpf_object(int type)
{
    if (type < 0 || type >= EBPF_EXECVE_HOOK_PROGRAM) {
        printf("[kebpf] get_bpf_object error, invalid type: %d\n", type);
        return NULL;
    }
    return bpf_objects[type];
}