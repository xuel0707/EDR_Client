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

int load_ebpf_program(void)
{
    int fd_exec, fd_file, fd_net;
    char exec_program_file[MAX_FILENAME_LEN], file_program_file[MAX_FILENAME_LEN], net_program_file[MAX_FILENAME_LEN];
    char failinfo[S_LINELEN] = {0};
    struct stat st = {0};
    
    printf("Loading... ebpf program@%s line:%d\n", __FILE__,__LINE__);

    fd_exec = fd_file = fd_net = 0;
    memset(exec_program_file,MAX_FILENAME_LEN,0);
    memset(file_program_file,MAX_FILENAME_LEN,0);
    memset(net_program_file,MAX_FILENAME_LEN,0);
    
    if (cwdmod) {
        snprintf(exec_program_file, sizeof(exec_program_file), "./%s", EBPF_EXECVE_HOOK_PROGRAM);
        snprintf(file_program_file, sizeof(file_program_file), "./%s", EBPF_FILE_HOOK_PROGRAM);
        snprintf(net_program_file, sizeof(net_program_file), "./%s", EBPF_NET_HOOK_PROGRAM);
        printf("exec_program_file[%s], file_program_file[%s], net_program_file[%s]@%s line:%d\n", 
			exec_program_file, file_program_file, net_program_file, __FILE__,__LINE__);
    } else {
        printf("load ebpf program: cwdmod[%d]@%s line:%d\n",cwdmod, __FILE__,__LINE__);
        return -1;
    }

    // 打开exec、file、net 3个eBPF程序文件的文件描述符
    errno = 0;
    if ((fd_exec = open(exec_program_file, O_RDONLY)) < 0) {
        if (errno == ENOENT)  nprintf(failinfo, sizeof(failinfo), "load ebpf program fail. 没有exec eBPF程序%s\n", exec_program_file);
        else snprintf(failinfo, sizeof(failinfo),"load ebpf program fail. 打开exec eBPF程序%s错误: %s\n", exec_program_file, strerror(errno));
        
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_exec, &st) < 0) {
        snprintf(failinfo, sizeof(failinfo),"load module fail. 取exec eBPF程序%s属性错误: %s\n",exec_program_file, strerror(errno));
        save_sniper_status(failinfo);
        close(fd_exec);
        return -1;
    }

    // 打开exec、file、net 3个eBPF程序文件的文件描述符
    errno = 0;
    if ((fd_file = open(file_program_file, O_RDONLY)) < 0) {
        if (errno == ENOENT) snprintf(failinfo, sizeof(failinfo),"load ebpf program fail. 没有file eBPF程序%s\n", file_program_file);
        else snprintf(failinfo, sizeof(failinfo), "load ebpf program fail. 打开file eBPF程序%s错误: %s\n", file_program_file, strerror(errno));
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_file, &st) < 0) {
        snprintf(failinfo, sizeof(failinfo), "load module fail. 取file eBPF程序%s属性错误: %s\n", file_program_file, strerror(errno));
        save_sniper_status(failinfo);
        close(fd_file);
        return -1;
    }

    // 打开exec、file、net 3个eBPF程序文件的文件描述符
    errno = 0;
    if ((fd_net = open(net_program_file, O_RDONLY)) < 0) {
        if (errno == ENOENT) snprintf(failinfo, sizeof(failinfo), "load ebpf program fail. 没有 net eBPF程序%s\n", net_program_file);
        else snprintf(failinfo, sizeof(failinfo), "load ebpf program fail. 打开 net eBPF程序%s错误: %s\n", net_program_file, strerror(errno));
        save_sniper_status(failinfo);
        return -1;
    }

    if (fstat(fd_net, &st) < 0) {
        snprintf(failinfo, sizeof(failinfo), "load module fail. 取 net eBPF程序%s属性错误: %s\n", net_program_file, strerror(errno));
        save_sniper_status(failinfo);
        close(fd_net);
        return -1;
    }

    // 通过文件描述符打开eBPF对象,加载eBPF obj到kernel 
    struct bpf_object *obj_exec =   bpf_object__open(exec_program_file);
    if(!obj_exec)   printf("bpf_object_open exec_program_file failed@%s line:%d\n",__FILE__,__LINE__);
    int load_exec_res = bpf_object__load(obj_exec); 
    if (load_exec_res != 0){
        printf("exec BPF Program loaded failed: %s(d)@%s line:%d\n", strerror(errno), load_exec_res,__FILE__,__LINE__);
        return -1;
    }
    bpf_objects[EBPF_EXECVE] = obj_exec;
    
    struct bpf_object *obj_file =   bpf_object__open(file_program_file);
    if(!obj_file)   printf("bpf_object_open file_program_file failed@%s line:%d\n",__FILE__,__LINE__);
    int load_file_res = bpf_object__load(obj_file);
    if (load_file_res != 0){
        printf("file BPF Program loaded failed: %s(d)@%s line:%d\n", strerror(errno), load_file_res,__FILE__,__LINE__);
        return -1;
    }
    bpf_objects[EBPF_FILE]   = obj_file;
    
    struct bpf_object *obj_net  =   bpf_object__open(net_program_file);
    if(!obj_net)    printf("bpf_object_open net_program_file failed@%s line:%d\n",__FILE__,__LINE__);
    int load_net_res = bpf_object__load(obj_net);
    if (load_net_res != 0){
        printf("file BPF Program loaded failed: %s(d)@%s line:%d\n", strerror(errno), load_net_res),__FILE__,__LINE__;
        return -1;
    }
    bpf_objects[EBPF_NET]   = obj_net;

    // 从eBPF对象中查找加载的BPF程序
    struct bpf_program *tp_execve_prog = bpf_object__find_program_by_name(obj_exec, "trace_enter_execve");
    if(!tp_execve_prog){     
        printf("bpf_object__find_program_by_name:trace_enter_execve failed@%s line:%d\n",__FILE__,__LINE__);
        return -1;
    }
    bpf_links[EBPF_EXECVE] = bpf_program__attach(tp_execve_prog);

    struct bpf_program *lsm_file_prog = bpf_object__find_program_by_name(obj_file, "lsm_file_open");
    if(!lsm_file_prog){
        printf("bpf_object__find_program_by_name:lsm_file_open failed@%s line:%d\n",__FILE__,__LINE__);
        return -1;
    } 
    bpf_links[EBPF_FILE] = bpf_program__attach(lsm_file_prog);     

    struct bpf_program *fentry_net_prog = bpf_object__find_program_by_name(obj_net, "tcp_connect");
    if(!fentry_net_prog){
        printf("bpf_object__find_program_by_name:tcp_connect failed@%s line:%d\n",__FILE__,__LINE__);
        return -1;
    }    
    bpf_links[EBPF_NET] = bpf_program__attach(fentry_net_prog);

    printf("Attach_ebpf_program OK!@%s line:%d\n", __FILE__,__LINE__);

    return 0;
}

int unload_ebpf_program(void)
{
    int ret=0;
    printf("Unloading...ebpf_program@%s line:%d\n", __FILE__,__LINE__);

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