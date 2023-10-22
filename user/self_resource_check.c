/*
 * 应用程序公共头文件
 * Author: zhangzhenghao, zhengxiang
 */

#include "header.h"

#define PROCESS_ITEM 14

char sniper_net_loadoff = 0;
char sniper_file_loadoff = 0;
char sniper_process_loadoff = 0;
char sniper_other_loadoff = 0;

int mem_high = 0, mem_t = 0;

/* 计算客户端CPU占用率 */
float get_client_cpu(pid_t pid)
{
    float pcpu = 0.0;
    unsigned long proc_time = 0, total_time = 0;
    unsigned long prev_proc_time = 0, prev_total_time = 0;

    prev_proc_time  = get_process_cpu(pid); //获取进程cpu时间
    prev_total_time = get_total_cpu();      //获取系统cpu时间

    usleep(200000);

    proc_time  = get_process_cpu(pid); //获取进程cpu时间
    total_time = get_total_cpu();      //获取系统cpu时间

    if (total_time != prev_total_time) {
        pcpu = 100.0 * (proc_time - prev_proc_time) / (total_time - prev_total_time);
        pcpu = pcpu * Sys_info.cpu_count;
    }

    return pcpu;
}

/* 客户端退出 */
void myexit(void)
{
    if (Online) {
        send_client_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Stoped");
        Online = 0;          //设置离线结束标志
	selfexit = 1;        //标记客户端进程是自愿退出的，不是因为卸载

        // TODO(luoyinhong): unregister_ebpf
        // unregister_module(); //使内核钩子失效，取消对客户端进程的保护
        unload_ebpf_program();
        sleep(5);            //给5秒让工作线程尽量结束
    }
    exit(0); //客户端直接结束，不走完整退出流程，避免意外挂住
}
/* 客户端重起：客户端结束后，由cron任务重起 */
void myrestart(void)
{
    system("cp /opt/snipercli/sniper_cron /etc/cron.d/");
    myexit();
}

/* 客户端程序持续高CPU时，按网络、文件、进程、其他的顺序，关闭一项监控功能 */
static void close_monitor(void)
{
#if 0
    if (sniper_net_loadoff == 0) {
        sniper_net_loadoff = 1;
        INFO("close net monitor\n");
        send_data_to_kern(NLMSG_NET_LOADOFF, (char *)&sniper_net_loadoff, sizeof(char));
        return;
    }
    if (sniper_file_loadoff == 0) {
        sniper_file_loadoff = 1;
        INFO("close file monitor\n");
        send_data_to_kern(NLMSG_FILE_LOADOFF, (char *)&sniper_file_loadoff, sizeof(char));
        return;
    }
    if (sniper_process_loadoff == 0) {
        sniper_process_loadoff = 1;
        INFO("close process monitor\n");
        send_data_to_kern(NLMSG_EXEC_LOADOFF, (char *)&sniper_process_loadoff, sizeof(char));
        return;
    }
#else
    // NOTE(luoyinhong): nothing to send to kernel
#endif

    if (sniper_other_loadoff == 0) {
        INFO("close other monitor\n");
        sniper_other_loadoff = 1;
        return;
    }

    INFO("all monitor closed, still busy, restart sniper...\n");
    INFO("已关闭所有监控项，客户端仍然忙，重新启动客户端...\n");
    myrestart();
}

/* 客户端程序CPU降下来后，开启之前关闭的监控功能 */
static void open_monitor(void)
{
    if (sniper_other_loadoff == 1) {
        INFO("open other monitor\n");
        sniper_other_loadoff = 0;
        return;
    }
    if (sniper_process_loadoff == 1) {
        INFO("open process monitor\n");
        sniper_process_loadoff = 0;
        send_data_to_kern(NLMSG_EXEC_LOADOFF, (char *)&sniper_process_loadoff, sizeof(char));
        return;
    }
    if (sniper_file_loadoff == 1) {
        INFO("open file monitor\n");
        sniper_file_loadoff = 0;
        send_data_to_kern(NLMSG_FILE_LOADOFF, (char *)&sniper_file_loadoff, sizeof(char));
        return;
    }
    if (sniper_net_loadoff == 1) {
        INFO("open net monitor\n");
        sniper_net_loadoff = 0;
        send_data_to_kern(NLMSG_NET_LOADOFF, (char *)&sniper_net_loadoff, sizeof(char));
        return;
    }
}

#define CHECK_INTERVAL 10  //每10秒检测一次
#define CHECK_COUNT 6      //连续检测一分钟，即连续检测6次
#define MEM_CHECK_COUNT 60 //连续检测十分钟，即连续检测60次

static void self_cpu_check(void)
{
    int cpu = 0, mem = 0, i = 0, netflow = 0;
    int pid = 0, cpu_low = 0, cpu_high = 0, net_low = 0, net_high = 0;

    pid = getpid();

    for (i = 0; i < CHECK_COUNT; i++) {
        if (conf_global.agent_cpu_limit != 0) {
            cpu = (int)(get_client_cpu(pid) + 0.5);
            if (cpu < conf_global.agent_cpu_limit) {
                cpu_low++;
            } else {
                cpu_high++;
            }
        }

        if (conf_global.agent_memory_limit != 0) {
            mem = get_proc_mem(pid) / 1024;
            mem_t++;
#ifdef USE_AVIRA 
            /* 计算的时候加上小红伞引擎的内存空间 */
            if (mem > conf_global.agent_memory_limit + get_antivirus_mem()) {
#else
            if (mem > conf_global.agent_memory_limit) {
#endif
                mem_high++;
                DBG2(DBGFLAG_RESCHECK, "limit: %d  mem:%d  mem_t:%d  mem_high:%d\n",
                     conf_global.agent_memory_limit, mem, mem_t, mem_high);
            }
        }

        if (conf_global.agent_network_limit != 0) {
            netflow = (upload_bytes / 1024) / CHECK_INTERVAL;
            if (netflow < conf_global.agent_network_limit) {
                net_low++;
            } else {
                net_high++;
            }
        }
        upload_bytes = 0;
        sleep(CHECK_INTERVAL);
    }

    /*
     * 客户端程序的cpu或网络流量连续超限，关闭一类监控
     * 客户端程序的cpu和网络流量在检测周期内都不超限，才重新打开之前关闭的监控
     * 正常情况下，客户端程序的cpu和网络流量都应该远低于阈值
     */
    if (cpu_high == CHECK_COUNT) {
        INFO("cpu %d > %d, close monitor\n", cpu, conf_global.agent_cpu_limit);
        close_monitor(); // close_monitor里会打印关闭哪类监控
    } else if (net_high == CHECK_COUNT) {
        INFO("netflow %d > %d, close monitor\n", netflow, conf_global.agent_network_limit);
        close_monitor(); // close_monitor里会打印关闭哪类监控
    } else if (cpu_low == CHECK_COUNT && net_low == CHECK_COUNT) {
        open_monitor(); // open_monitor里会打印打开哪类监控
    }

    DBG2(DBGFLAG_RESCHECK, "check: limit: %d  mem:%d  mem_t:%d  mem_high:%d\n",
         conf_global.agent_memory_limit, mem, mem_t, mem_high);
    if (mem_t == MEM_CHECK_COUNT) {
        if (mem_high == MEM_CHECK_COUNT) {
            INFO("Mem %d overload %d, restart sniper...\n", mem, conf_global.agent_memory_limit);
            INFO("客户端内存持续十分钟超过规定阈值，重新启动客户端...\n");
            myexit();
        }
        mem_t = 0;
        mem_high = 0;
    }
}

/* echo n > /tmp/cpubusy.df，让程序忙n分钟，用于测试高负载时关闭部分监控的功能 */
static void *test_cpubusy(void *arg)
{
    int i = 0, j = 0;
    int busytime = 10; //默认忙10分钟
    time_t t1 = 0, t2 = 0;
    FILE *fp = NULL;

    /* 与父线程脱钩，避免子线程未回收，内存泄露 */
    pthread_detach(pthread_self());

    fp = fopen(DBGFLAG_CPUBUSY, "r");
    if (fp) {
        fscanf(fp, "%d", &busytime);
        fclose(fp);
        unlink(DBGFLAG_CPUBUSY); //删除标志文件，避免反复进行测试
    }

    busytime *= 60;
    INFO("== begin busy %ds for test\n", busytime);

    t1 = time(NULL);
    while (1) {
        j = 1;
        for (i = 0; i < 10000; i++) {
            j = j * 100;
        }
        t2 = time(NULL);
        if ((t2 - t1) > busytime) {
            break;
        }
    }

    INFO("== busy test over\n");

    return NULL;
}

static void self_openfds_check(void)
{
    int fd_overhead = 0;
    DIR *dirp = NULL;
    struct dirent *ent = NULL;
    char path[S_SHORTPATHLEN] = {0};

    snprintf(path, sizeof(path), "/proc/%d/fd", getpid());
    dirp = sniper_opendir(path, OTHER_GET);
    if (dirp) {
        while ((ent = readdir(dirp))) {
            if ('.' == ent->d_name[0]) {
                continue;
            }

            if (atoi(ent->d_name) >= 1000) {
                fd_overhead = 1;
                break;
            }
        }
        sniper_closedir(dirp, OTHER_GET);
    } else {
        if (EMFILE != errno) {
            MON_ERROR("self_openfds_check: open %s fail: %s\n", path, strerror(errno));
            return;
        }
        fd_overhead = 1;
    }

    if (fd_overhead) {
        INFO("too many files opened (>1000), restart sniper...\n");
        INFO("客户端打开了太多的文件，重新启动客户端...\n");
        myrestart();
    }
}

void *resource_check(void *ptr)
{
    pthread_t thread_id = 0;

    prctl(PR_SET_NAME, "selfcheck");
    save_thread_pid("rescheck", SNIPER_THREAD_RESCHECK);

    while (Online) {

        /* 如果过期了，则什么也不做 */
        if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
            sleep(STOP_WAIT_TIME);
            continue;
        }

        if (access(DBGFLAG_CPUBUSY, F_OK) == 0) {
            pthread_create(&thread_id, NULL, test_cpubusy, NULL);
        }

        self_cpu_check();

        self_openfds_check();
    }

    INFO("rescheck thread exit\n");
    return NULL;
}
