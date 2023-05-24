#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "structs.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct taskreq_t *e = data;

    printf("EXEC process: %s(%d), nodename: %s(%u)\n", e->cmd, e->pid, e->nodename, e->mnt_id);
    printf("EXEC parent: %s(%d)\n", e->pinfo.task[0].comm, e->ppid);
    printf("EXEC cwd: %s\n", e->cwd);
    printf("EXEC tty: %s\n", e->tty);
    printf("EXEC argc: %d\n", e->argc);
    for (int i = 0; i < e->argc; i++) {
        printf("EXEC arg%d: %s\n", i, e->args[i]);
    }
    printf("====================\n");
    return 0;
}

struct bpf_link *tp_execve_link = NULL;

void sig_handler(int signum) {
    int destroy_res = bpf_link__destroy(tp_execve_link);
    printf("bpf link destroy result: %d\n", destroy_res);

    printf("the program is over......\n");
    exit(0);
}

int main(int argc, char **argv) {
    // int k = 0;
    // char data_sample[CHAR_MAX] = "yeet";
    // // put some data in the map as a test
    // int success = bpf_map_update_elem(lsm_map_fd, &k, data_sample, BPF_ANY);
    // printf("Success is %d for making new element in map from user space at index %d!\n", success, k);


    // struct bpf_map *file_policy_map = bpf_object__find_map_by_name(obj, "file_policy_map");
    // int file_policy_map_fd = bpf_map__fd(file_policy_map);

    // struct kern_file_policy sniper_fpolicy;
    // memset(&sniper_fpolicy, 0, sizeof(sniper_fpolicy));
    // sniper_fpolicy.printer_on = 1;
    // sniper_fpolicy.printer_terminate = 1;

    // long f_map_key = 0;
    // int response = bpf_map_update_elem(file_policy_map_fd, &f_map_key, &sniper_fpolicy, BPF_NOEXIST);
    // printf("Add a sniper fpolicy to the map in user-space...\n");


    // int zero = 0;
    // struct bpf_map *req_map = bpf_object__find_map_by_name(obj, "heap");
    // int req_map_fd = bpf_map__fd(req_map);  // struct taskreq_t *req = NULL;

    // struct TestStruct test = {0};
    // strcpy(test.author, "CiXin");
    // strcpy(test.title, "Earth");
    // test.length = 66;
    // bpf_map_update_elem(req_map_fd, &zero, &test, BPF_NOEXIST);

    // printf("Press any key to continue...\n");
    // getchar();

    // The location of the bytecode file.
    char path[PATH_MAX];
    sprintf(path, "%s/lsm_kern.o", dirname(argv[0]));
    printf("bytecode file path: %s\n", path);

    // int prog_fd;

    // Open and Load the bytecode file.
    struct bpf_object *obj;
    obj = bpf_object__open(path);
    printf("Ok! BPF bytecode open over......\n");

    int load_res = bpf_object__load(obj);
    if (load_res != 0){
        printf("BPF Program loaded failed......\n");
        return -1;
    }
    printf("Ok! BPF Program loaded......\n");

    // Find the program been loaded into the kernel.
    // struct bpf_program *prog =
    //     bpf_object__find_program_by_name(obj, "lsm_demo");
    struct bpf_program *tp_execve_prog = bpf_object__find_program_by_name(obj, "trace_enter_execve");

    // attach the program into the Hooks.
    tp_execve_link = bpf_program__attach(tp_execve_prog);

    // register signal handlers
    signal(SIGINT, sig_handler);    // Ctrl + C
    signal(SIGTERM, sig_handler);
    signal(SIGTSTP, sig_handler);   // Ctrl + Z

    struct bpf_map *exec_event_ringbuf_map = bpf_object__find_map_by_name(obj, "taskreq_ringbuf");
    int ringbuf_map_fd = bpf_map__fd(exec_event_ringbuf_map);
    struct ring_buffer *exec_event_ringbuf = NULL;
    exec_event_ringbuf = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);

    if (!exec_event_ringbuf) {
        printf("Failed to create ring buffer\n");
        return -1;
    }
    printf("receive from ring buf...\n");
    while(1) {
        ring_buffer__poll(exec_event_ringbuf, 100 /* timeout, ms */);
    }

    // struct bpf_link *lsm_link = bpf_program__attach_lsm(prog);

    // print bpf_map info.
    // struct bpf_map *lsm_map = bpf_object__find_map_by_name(obj, "socket_connect_map");
    // int lsm_map_fd = bpf_map__fd(lsm_map);
    // long key=-1, prev_key;
    // long val;

    // TESTING PASSING STRUCT TO MAP

    // struct bpf_map *book_map = bpf_object__find_map_by_name(obj, "book_test");
    // int book_map_fd = bpf_map__fd(book_map);

    // struct TestStruct book;
    // memset(&book, 0, sizeof(book));
    // strcpy(book.title, "Waging Heavy Peace");
    // strcpy(book.author, "Neil Young");
    // book.length = 998;

    // int m = 10;
    // int attempt = bpf_map_update_elem(book_map_fd, &m, &book, BPF_ANY);
    // printf("Success is %d for adding a struct to the map.\n", attempt);

    // // TESTING PASSING
    // struct TestStruct t = {0};
    // bpf_map_lookup_elem(req_map_fd, &zero, &t);
    // struct taskreq_t req = {0};
    // bpf_map_lookup_elem(req_map_fd, &zero, &req);

    // printf("request pid is %d\n", req.pid);
    // printf("request proctime is %ld\n", req.proctime);
    // printf("request tgid is %d\n", req.tgid);

    // for (int i=0; i<4;i++){
    //     printf("current args is :%s\n", req.args[i]);
    //     printf("generation %d uid is %d\n",i, req.pinfo.task[i].uid);
    //     printf("generation %d comm is %s\n",i, req.pinfo.task[i].comm);
    // }

    // int pid = req->pid;
    // printf("pid : %d\nuid : %d\n", req->pid, req->uid);

    // Iterate over all keys in the target map.
    // while (bpf_map_get_next_key(lsm_map_fd, &prev_key, &key) == 0) {
    //   printf("The pid is : %ld\n", key);
    //   bpf_map_lookup_elem(lsm_map_fd, &key, &val);
    //   printf("The number of argument is : %ld\n", val);
    //   prev_key = key;
    // }


    // int destroy_res = bpf_link__destroy(lsm_link);
    // printf("destroy_res : %d\n", destroy_res);

    printf("the program is over......\n");
    return 0;
}
