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

#define MAX_FILENAME_LEN 128

extern int cwdmod;

struct bpf_object *bpf_objects[EBPF_PROGRAMS_NUM] = {0};
struct bpf_link *bpf_links[EBPF_PROGRAMS_NUM] = {0};
int fd_maps[EBPF_PROGRAMS_NUM] = {0};

int load_lsm(void)
{
#if 0    
    int fd_lsm=0;
    char lsm_file[MAX_FILENAME_LEN];
    char failinfo[S_LINELEN] = {0};
    struct stat st = {0};
    
    memset(lsm_file,MAX_FILENAME_LEN,0);
    snprintf(lsm_file, sizeof(lsm_file), "./%s", EBPF_EXECVE_HOOK_PROGRAM);

    // 打开lsm eBPF程序文件的文件描述符
    if ((fd_lsm = open(lsm_file, O_RDONLY)) < 0) {
        printf("open lsm failed@%s line:%d\n", __FILE__,__LINE__);
        snprintf(failinfo, sizeof(failinfo),"load module fail:%s,error: %s\n",lsm_file, strerror(errno));
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_lsm, &st) < 0) {
        printf("fstat lsm failed@%s line:%d\n", __FILE__,__LINE__);
        snprintf(failinfo, sizeof(failinfo),"load module fail:%s,error: %s\n",lsm_file, strerror(errno));
        save_sniper_status(failinfo);
        close(fd_lsm);
        return -1;
    }
#endif
    // Loading eBPF obj to kernel 
    struct bpf_object *proc_bpf_obj =   bpf_object__open(EBPF_EXECVE_HOOK_PROGRAM);
    if(!proc_bpf_obj)   printf("bpf_object_open obj_lsm failed@%s line:%d\n",__FILE__,__LINE__);
    int ret = bpf_object__load(proc_bpf_obj); 
    if (ret != 0){
        printf("exec BPF Program loaded failed: %s@%s line:%d\n", strerror(errno), __FILE__,__LINE__);
        return -1;
    }
    bpf_objects[EBPF_EXECVE] = proc_bpf_obj;
    
    // Attachment to LSM Hooks
    struct bpf_program *proc_bf_prog = bpf_object__find_program_by_name(proc_bpf_obj, "tracepoint__syscalls__sys_enter_execve");
    if(!proc_bf_prog){     
        printf("bpf_object__find_program_by_name:proc_bf_prog failed@%s line:%d\n",__FILE__,__LINE__);
        return -1;
    }
    bpf_links[EBPF_EXECVE] = bpf_program__attach(proc_bf_prog);

    return 0;
}

int load_ebpf_file(void)
{ 
#if 0
    int file_fd=0;
    char failinfo[S_LINELEN] = {0};
    struct stat st = {0};

    if ((file_fd = open(EBPF_FILE_HOOK_PROGRAM, O_RDONLY)) < 0) {
        printf("open file failed@%s line:%d\n", __FILE__,__LINE__);
        snprintf(failinfo, sizeof(failinfo),"load module fail:%s,error: %s\n",EBPF_FILE_HOOK_PROGRAM, strerror(errno));
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(file_fd, &st) < 0) {
        printf("fstat file failed@%s line:%d\n", __FILE__,__LINE__);
        snprintf(failinfo, sizeof(failinfo),"load module fail:%s,error: %s\n",EBPF_FILE_HOOK_PROGRAM, strerror(errno));
        save_sniper_status(failinfo);
        close(file_fd);
        return -1;
    }
#endif
    // Loading eBPF obj to kernel 
    struct bpf_object *file_bpf_obj =   bpf_object__open(EBPF_FILE_HOOK_PROGRAM);
    if(!file_bpf_obj)   printf("bpf_object_open exec_program_file failed@%s line:%d\n",__FILE__,__LINE__);
    int ret = bpf_object__load(file_bpf_obj); 
    if (ret != 0){
        printf("exec BPF Program loaded failed: %s@%s line:%d\n", strerror(errno), __FILE__,__LINE__);
        return -1;
    }
    bpf_objects[EBPF_FILE] = file_bpf_obj;
    
    // Attachment to LSM Hooks
    struct bpf_program *file_bf_prog = bpf_object__find_program_by_name(file_bpf_obj, "sample_file_open");
    if(!file_bf_prog){
        printf("bpf_object__find_program_by_name:lsm_file_open failed@%s line:%d\n",__FILE__,__LINE__);
        return -1;
    } 
    bpf_links[EBPF_FILE] = bpf_program__attach(file_bf_prog); 

    return 0;
}

int load_ebpf_net(void)
{
#if 0    
    int fd_net=0;
    char ebpf_net[MAX_FILENAME_LEN];
    char failinfo[S_LINELEN] = {0};
    struct stat st = {0};
    
    memset(ebpf_net,MAX_FILENAME_LEN,0);
    snprintf(ebpf_net, sizeof(ebpf_net), "./%s", EBPF_NET_HOOK_PROGRAM);

    // 打开net eBPF程序文件的文件描述符
    errno = 0;
    if ((fd_net = open(ebpf_net, O_RDONLY)) < 0) {
        printf("open file failed@%s line:%d\n", __FILE__,__LINE__);
        snprintf(failinfo, sizeof(failinfo),"load module fail:%s,error: %s\n",ebpf_net, strerror(errno));
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_net, &st) < 0) {
        printf("fstat file failed@%s line:%d\n", __FILE__,__LINE__);
        snprintf(failinfo, sizeof(failinfo),"load module fail:%s,error: %s\n",ebpf_net, strerror(errno));
        save_sniper_status(failinfo);
        close(fd_net);
        return -1;
    }
#endif
     // Loading eBPF obj to kernel 
    struct bpf_object *net_bpf_object  =   bpf_object__open(EBPF_NET_HOOK_PROGRAM);
    if(!net_bpf_object)    printf("bpf_object_open net_program_file failed@%s line:%d\n",__FILE__,__LINE__);
    int ret = bpf_object__load(net_bpf_object);
    if (ret != 0){
        printf("file BPF Program loaded failed: %s@%s line:%d\n", strerror(errno),__FILE__,__LINE__);
        return -1;
    }
    bpf_objects[EBPF_NET]   = net_bpf_object;

     // Attachment to LSM Hooks
    struct bpf_program *sample_socket_connect_bf_prog = bpf_object__find_program_by_name(net_bpf_object, "sample_socket_connect");
    if(!sample_socket_connect_bf_prog){
        printf("bpf_object__find_program_by_name:sample_socket_connect failed@%s line:%d\n",__FILE__,__LINE__);
        return -1;
    }

    bpf_links[EBPF_NET] = bpf_program__attach(sample_socket_connect_bf_prog);
    
    // Loading XDP to ifindex=2 interface
    struct bpf_program *sample_pkt_from_xdp_bf_prog = bpf_object__find_program_by_name(net_bpf_object, "sample_pkt_from_xdp");
    if(!sample_pkt_from_xdp_bf_prog){
        printf("bpf_object__find_program_by_name:sample_pkt_from_xdp failed@%s line:%d\n",__FILE__,__LINE__);
        return -1;
    }

    int ifindex=2;    
    bpf_program__attach_xdp(sample_pkt_from_xdp_bf_prog,ifindex);

    return 0;
}


int load_ebpf_program(void)
{
    printf("Loading... ebpf program\n");
    
    if (cwdmod) {
        int ret=load_lsm();
        if(ret){
            printf("Load lsm fail@%s line:%d\n", __FILE__,__LINE__);
            return -1;
        }

        ret=load_ebpf_file();
        if(ret){
            printf("Load ebpf file fail@%s line:%d\n", __FILE__,__LINE__);
            return -1;
        }

        ret=load_ebpf_net();
        if(ret){
            printf("Load ebpf net fail@%s line:%d\n", __FILE__,__LINE__);
            return -1;
        }

    } else {
        printf("load ebpf program: cwdmod[%d]@%s line:%d\n",cwdmod, __FILE__,__LINE__);
        return -1;
    }

    printf("Attach_ebpf_program OK!\n");

    return 0;
}

int unload_ebpf_program(void)
{
    int ret=0;
    printf("Unloading...ebpf_program\n");

    ret = bpf_link__destroy(bpf_links[EBPF_EXECVE]);
    if(ret) printf("bpf exec link destroy result: %d@%s line:%d\n", ret, __FILE__,__LINE__);

    ret = bpf_link__destroy(bpf_links[EBPF_FILE]);
    if(ret) printf("bpf exec link destroy result: %d@%s line:%d\n", ret, __FILE__,__LINE__);

    ret = bpf_link__destroy(bpf_links[EBPF_NET]);
    if(ret) printf("bpf exec link destroy result: %d@%s line:%d\n", ret, __FILE__,__LINE__);

    return ret;
}

struct bpf_object *get_bpf_object(int type)
{
    if (type < 0 || type >= EBPF_EXECVE_HOOK_PROGRAM) {
        printf("[kebpf] get_bpf_object error, invalid type: %d@%s line:%d\n", type,__FILE__,__LINE__);
        return NULL;
    }
    return bpf_objects[type];
}