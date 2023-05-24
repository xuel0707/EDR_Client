#include "header.h"
#include <sys/vfs.h>

#define TRIMz(x) ((tz = (SIC_t)(x)) < 0 ? 0 : tz)

typedef unsigned long long TIC_t;
typedef long long SIC_t;
typedef struct CPU_t {
    TIC_t u, n, s, i, w, x, y, z;
} CPU_t;

time_t last_highload_warntime_cpu = 0;
time_t last_highload_warntime_disk = 0;
time_t last_highload_warntime_mem = 0;
double resource_disk_used = 0.0;

int disk_is_overload = 0, disk_count = 0;
int total_download_time = 0, total_send_time = 0, netflow_count = 0;
int cpu_overload_count = 0, mem_overload_count = 0;

int client_disable = TURN_MY_OFF;

#include <linux/major.h>
static int is_harddisk(char *name)
{
    int major = 0;
    struct stat st = {0};
    char classpath[512] = {0}, linkpath[S_PATHLEN] = {0};

    if (stat(name, &st) < 0) {
        INFO("Warning: check %s whether harddisk error: %s\n",
             name, strerror(errno));
        return 1;
    }

    major = st.st_rdev >> 8;
    /* Documentation/devices.txt: 8,9,65-71,128-135,240-254 */
    if (major == SCSI_DISK0_MAJOR || major == MD_MAJOR ||
        (major >= SCSI_DISK1_MAJOR && major <= SCSI_DISK7_MAJOR) ||
        (major >= SCSI_DISK8_MAJOR && major <= SCSI_DISK15_MAJOR) ||
        (major >= 240 && major <= 254)) {
        /* u盘不视为硬盘 */
        // TODO 后面出现误报看设备是否为可移除/sys/class/block/sda/removable
        snprintf(classpath, sizeof(classpath), "/sys/class/block/%s", name + 5);
        if (readlink(classpath, linkpath, 4095) > 0) {
            if (strstr(linkpath, "usb") || strstr(linkpath, "DVD") || strstr(linkpath, "CDROM")) {
                return 0;
            }
        }

        return 1;
    }
    return 0;
}

static void check_partition_info(char *name, char *path, cJSON *partition_info, long unsigned *all_total, long unsigned *all_used, char *cc)
{
    long all = 0;
    long free_to_root = 0;
    long p_used = 0;
    char used[24];

    long a_total = *all_total;
    long a_used = *all_used;

    double usedsize = 0;
    double percent = 0;

    struct statfs stat;
    cJSON *object = NULL;

    object = cJSON_CreateObject();
    if (object == NULL) {
        return;
    }

    memset(&stat, 0, sizeof(struct statfs));
    statfs(path, &stat);

    all = stat.f_bsize * stat.f_blocks / 1024;
    if (all == 0) {
        return;
    }

    free_to_root = stat.f_bsize * stat.f_bfree / 1024;
    p_used = all - free_to_root;

    //	p_free = stat.f_bsize * stat.f_bavail/1024;

    //	cJSON *object = cJSON_CreateObject();

    /*因为获取的是Kb,所以虽然用的是MB的宏,但是最后的数据是GB的大小*/
    //	cJSON_AddStringToObject(object, "name", name);
    //	snprintf(total, 16, "%0.2f", (double)all/MB_SIZE);
    //	cJSON_AddStringToObject(object, "total", total);
    usedsize = (double)p_used / MB_SIZE;
    if (usedsize < 0.01 && p_used != 0) {
        usedsize = 0.01;
    }

    /*获取每个分区的使用率*/
    percent = (double)p_used / (double)all * 100.00;

    /* 获取分区的最大使用率，排除/boot分区、u盘、光盘 */
    if (resource_disk_used < percent && strcmp(path, "/boot") != 0 && is_harddisk(name)) {
        resource_disk_used = percent;
    }

    if (fasten_policy_global.resource.sys.disk.limit != 0) {
        if (percent >= fasten_policy_global.resource.sys.disk.limit) {
            // snprintf(used, 24, "%s:%0.2f%%:%s,", name, percent, "true");
            disk_is_overload = 1;
            cJSON_AddStringToObject(object, "partition_name", name);
            cJSON_AddNumberToObject(object, "total_size", all);
            cJSON_AddNumberToObject(object, "used_size", p_used);
            cJSON_AddNumberToObject(object, "used_percentage", (int)(percent + 0.5));
            cJSON_AddBoolToObject(object, "partition_overload", true);
        } else {
            cJSON_AddStringToObject(object, "partition_name", name);
            cJSON_AddNumberToObject(object, "total_size", all);
            cJSON_AddNumberToObject(object, "used_size", p_used);
            cJSON_AddNumberToObject(object, "used_percentage", (int)(percent + 0.5));
            cJSON_AddBoolToObject(object, "partition_overload", false);
        }
    } else {
        cJSON_AddStringToObject(object, "partition_name", name);
        cJSON_AddNumberToObject(object, "total_size", all);
        cJSON_AddNumberToObject(object, "used_size", p_used);
        cJSON_AddNumberToObject(object, "used_percentage", (int)(percent + 0.5));
        cJSON_AddBoolToObject(object, "partition_overload", false);
    }

    cJSON_AddItemToArray(partition_info, object);
    strcat(cc, used);

    *all_total = a_total + all;
    *all_used = a_used + p_used;
}

static void get_partition_packed(cJSON *partition_info, cJSON *object)
{
    char line[S_LINELEN] = {0};
    char name[S_NAMELEN] = {0};
    char path[S_LINELEN] = {0};
    FILE *fp = NULL;
    unsigned long all_total = 0;
    unsigned long all_used = 0;
    double percent = 0.0;
    char disk_used_percent[16] = {0};
    char cc[2048] = {0};
    char partitions[4096] = {0}, partstr[128] = {0};
    int len = 0;

    fp = fopen(MOUNT_PATH, "r");
    if (fp == NULL) {
        return;
    }

    while (fgets(line, S_LINELEN, fp)) {
        if (sscanf(line, "%63s %s", name, path) != 2) {
            continue;
        }

        if (strncmp(name, "/dev/loop", 9) == 0 || strncmp(name, "/dev/sr", 7) == 0) {
            continue;
        }

        /* 过滤重复的分区 */
        snprintf(partstr, sizeof(partstr), "%s ", name);
        if (strstr(partitions, partstr)) { //如strstr("/dev/sda1 /dev/sda2 ", "/dev/sda2 ")
            continue;
        }
        len = strlen(partitions);
        snprintf(partitions + len, sizeof(partitions) - len, "%s", partstr);

        if (strncmp(name, "/dev/", 5) == 0) {
            check_partition_info(name, path, partition_info, &all_total, &all_used, cc);
        }
    }
    // cc[strlen(cc) - 1] = '\0';
    cJSON_AddItemToObject(object, "partition_list", partition_info);
    fclose(fp);

    if (all_total == 0 || all_total < all_used) {
        return;
    }

    percent = (double)all_used / (double)all_total * 100.00;
    snprintf(disk_used_percent, sizeof(disk_used_percent), "%0.1f", percent);
}

void debug_vmrss(char *str)
{
    FILE *fp = NULL;
    pid_t pid;
    int count = 0;
    unsigned long vmrss = 0, vmsize = 0, vmdata = 0;
    char path[64] = {0};
    char line[S_LINELEN] = {0};

    if (access(DBGFLAG_VMRSS, F_OK) != 0) {
        return;
    }

    pid = getpid();
    sprintf(path, "/proc/%d/status", pid);

    if ((fp = fopen(path, "r")) == NULL) {
        MON_ERROR("open %s fail: %s\n", path, strerror(errno));
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "VmSize:\t%8lu kB\n", &vmsize) == 1) {
            count++;
        } else if (sscanf(line, "VmRSS:\t%8lu kB\n", &vmrss) == 1) {
            count++;
        } else if (sscanf(line, "VmData:\t%8lu kB\n", &vmdata) == 1) {
            count++;
        }
        if (count == 3) {
            break;
        }
    }
    fclose(fp);

    INFO("%s: VmSize: %luK, VmRSS: %luK, VmData: %luK\n", str, vmsize, vmrss, vmdata);
}

unsigned long get_self_mem(void)
{
    FILE *fp = NULL;
    pid_t pid;

    unsigned long mem = 0;
    unsigned long rss = 0;
    char path[64] = {0};
    char line[S_LINELEN] = {0};

    pid = getpid();
    sprintf(path, "/proc/%d/status", pid);

    if ((fp = fopen(path, "r")) == NULL) {
        MON_ERROR("open %s fail: %s\n", path, strerror(errno));
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (!strstr(line, "VmRSS:")) {
            continue;
        }

        if (sscanf(line, "VmRSS:\t%8lu kB\n", &rss) == 1) {
            break;
        }
    }

    mem = rss * 1024;

    fclose(fp);

    return mem;
}

static void get_memoccupy(float *resource_memory_used)
{
    FILE *fp = NULL;
    char line[S_LINELEN] = {0};
    unsigned long value = 0;
    float used_percent = 0.00;

    unsigned long total = 0;
    unsigned long free = 0;
    unsigned long available = 0;
    unsigned long buffers = 0;
    unsigned long cached = 0;
    unsigned long used = 0;

    char key[S_NAMELEN] = {0};

    fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        MON_ERROR("get_memoccupy fail, open /proc/meminfo error: %s\n", strerror(errno));
        return;
    }

    while (fgets(line, S_LINELEN, fp)) {
        sscanf(line, "%63s %lu", key, &value);
        if (strcmp(key, "SwapCached:") == 0) {
            break;
        }

        if (strcmp(key, "MemTotal:") == 0) {
            total = value;
        } else if (strcmp(key, "MemFree:") == 0) {
            free = value;
        } else if (strcmp(key, "MemAvailable:") == 0) {
            available = value;
        } else if (strcmp(key, "Buffers:") == 0) {
            buffers = value;
        } else if (strcmp(key, "Cached:") == 0) {
            cached = value;
        }
    }

    fclose(fp);

    if (total == 0) {
        return;
    }

    /* centos5/6没有MemAvailable，按MemFree+Buffers+Cached计算 */
    if (available == 0) {
        available = free + buffers + cached;
    }

    used = total - available; //已用内存=总内存-可用的内存

    used_percent = (float)used / (float)total * 100.00;
    DBG2(DBGFLAG_SELFCHECK, "SYSTEM MEM: %.2f\n", used_percent);
    *resource_memory_used = used_percent;
}

static void cal_cpuoccupy(CPU_t *cpu_f, CPU_t *cpu_s, float *resource_cpu_used)
{
    SIC_t u_frme, s_frme, n_frme, i_frme, w_frme, x_frme, y_frme, z_frme, tot_frme, tz;
    float id, used, scale;

    u_frme = cpu_s->u - cpu_f->u;
    s_frme = cpu_s->s - cpu_f->s;
    n_frme = cpu_s->n - cpu_f->n;
    i_frme = TRIMz(cpu_s->i - cpu_f->i);
    w_frme = cpu_s->w - cpu_f->w;
    x_frme = cpu_s->x - cpu_f->x;
    y_frme = cpu_s->y - cpu_f->y;
    z_frme = cpu_s->z - cpu_f->z;

    tot_frme = u_frme + s_frme + n_frme + i_frme + w_frme + x_frme + y_frme + z_frme;
    if (tot_frme < 1) {
        tot_frme = 1;
    }

    scale = 100.0 / (float)tot_frme;

    id = (float)i_frme * scale;

    used = 100.0 - id;

    /* 不需要乘cpu个数，/proc/stat里已经考虑多cpu因素了 */
    //*resource_cpu_used = used * Sys_info.cpu_count;
    *resource_cpu_used = used;
}

static int get_cpuoccupy(CPU_t *cpus)
{
    FILE *fp;
    char buff[S_LINELEN];
    int ret = 0;

    fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        MON_ERROR("open /proc/stat failed\n");
        return -1;
    }
    if (!fgets(buff, sizeof(buff), fp)) {
        MON_ERROR("read /proc/stat failed\n");
    };

    ret = sscanf(buff, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
                 &cpus->u, &cpus->n, &cpus->s, &cpus->i, &cpus->w, &cpus->x, &cpus->y, &cpus->z);
    if (ret != 8) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int get_cpu_packed(float *resource_cpu_used)
{
    int ret = 0;
    CPU_t cpu_stat1 = {0};
    CPU_t cpu_stat2 = {0};

    /*第1次获取cpu使用情况*/
    ret = get_cpuoccupy(&cpu_stat1);
    if (ret < 0) {
        MON_ERROR("first get cpu error\n");
        return -1;
    }

    sleep(3);

    /*第2次获取cpu使用情况*/
    ret = get_cpuoccupy(&cpu_stat2);
    if (ret < 0) {
        MON_ERROR("second get cpu error\n");
        return -1;
    }

    cal_cpuoccupy(&cpu_stat1, &cpu_stat2, resource_cpu_used);

    return 0;
}

#define WAIT_SECOND 1
static void get_network_packed(void)
{
    long start_download_rates; //保存开始时的流量计数
    long end_download_rates;   //保存结果时的流量计数
    long start_send_rates;
    long end_send_rates;
    long download_rates, send_rates;
    unsigned long event_time = 0;
    struct timeval tv = {0};
    char uuid[64] = {0};
    char *post = NULL;
    char reply[REPLY_MAX] = {0};
    cJSON *object = NULL, *arguments = NULL;
    int up = fasten_policy_global.resource.sys.netflow.down * 1024 * 1024;  //入网流量
    int down = fasten_policy_global.resource.sys.netflow.up * 1024 * 1024;  //出网流量

    getNetRates(&start_download_rates, &start_send_rates); //获取当前流量，并保存在start_download_rates里
    sleep(WAIT_SECOND); //休眠多少秒，这个值根据宏定义中的WAIT_SECOND的值来确定

    getNetRates(&end_download_rates, &end_send_rates); //获取当前流量，并保存在end_download_rates里

    download_rates = end_download_rates - start_download_rates;
    send_rates = end_send_rates - start_send_rates;
    DBG2(DBGFLAG_SELFCHECK, "+++++++++%ld, %ld\n", send_rates, download_rates);
    netflow_count++;
    if (download_rates > up) {
        total_download_time += 1;
    }

    if (send_rates > down) {
        total_send_time += 1;
    }

    if (netflow_count == fasten_policy_global.resource.sys.netflow.interval) { //报告网络流量异常
        gettimeofday(&tv, NULL);
        event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

        get_random_uuid(uuid);
        if (uuid[0] == 0) {
            return;
        }

        object = cJSON_CreateObject();
        if (object == NULL) {
            return;
        }
        arguments = cJSON_CreateObject();
        if (arguments == NULL) {
            cJSON_Delete(object);
            return;
        }

        cJSON_AddStringToObject(object, "id", uuid);

        cJSON_AddStringToObject(object, "log_category", "SystemResource");
        cJSON_AddStringToObject(object, "event_category", "SystemMonitor");

        cJSON_AddNumberToObject(object, "result", MY_HANDLE_NO);
        cJSON_AddStringToObject(object, "operating", "");

        cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
        cJSON_AddStringToObject(object, "ip_address", If_info.ip);
        cJSON_AddStringToObject(object, "mac", If_info.mac);
        cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
        cJSON_AddStringToObject(object, "user", "root");
        cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
        cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
        cJSON_AddNumberToObject(object, "timestamp", event_time);
        cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
        cJSON_AddStringToObject(object, "source", "Agent");
        cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

        if (total_download_time == fasten_policy_global.resource.sys.netflow.interval || total_send_time == fasten_policy_global.resource.sys.netflow.interval) {
            cJSON_AddStringToObject(object, "log_name", "HighNetworkUsage");
            cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
            cJSON_AddBoolToObject(object, "event", true);
            cJSON_AddNumberToObject(object, "level", MY_LOG_LOW_RISK);
            cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
            cJSON_AddNumberToObject(arguments, "inbound", download_rates);
            cJSON_AddNumberToObject(arguments, "inbound_threshold", up);

            if (total_download_time == fasten_policy_global.resource.sys.netflow.interval) {
                cJSON_AddBoolToObject(arguments, "inbound_overload", true);
            } else {
                cJSON_AddBoolToObject(arguments, "inbound_overload", false);
            }

            cJSON_AddNumberToObject(arguments, "inbound_overload_duration", fasten_policy_global.resource.sys.netflow.interval);

            cJSON_AddNumberToObject(arguments, "outbound", send_rates);
            cJSON_AddNumberToObject(arguments, "outbound_threshold", down);

            if (total_send_time == fasten_policy_global.resource.sys.netflow.interval) {
                cJSON_AddBoolToObject(arguments, "outbound_overload", true);
            } else {
                cJSON_AddBoolToObject(arguments, "outbound_overload", false);
            }

            cJSON_AddNumberToObject(arguments, "outbound_overload_duration", fasten_policy_global.resource.sys.netflow.interval);
        } else {
            cJSON_AddStringToObject(object, "log_name", "NetworkUsage");
            cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);
            cJSON_AddBoolToObject(object, "event", false);
            cJSON_AddNumberToObject(object, "level", MY_LOG_NORMAL);
            cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
            cJSON_AddNumberToObject(arguments, "inbound", download_rates);
            cJSON_AddNumberToObject(arguments, "inbound_threshold", up);
            cJSON_AddBoolToObject(arguments, "inbound_overload", false);
            cJSON_AddNumberToObject(arguments, "inbound_overload_duration", fasten_policy_global.resource.sys.netflow.interval);

            cJSON_AddNumberToObject(arguments, "outbound", send_rates);
            cJSON_AddNumberToObject(arguments, "outbound_threshold", down);
            cJSON_AddBoolToObject(arguments, "outbound_overload", false);
            cJSON_AddNumberToObject(arguments, "outbound_overload_duration", fasten_policy_global.resource.sys.netflow.interval);
        }

        netflow_count = 0;
        total_download_time = 0;
        total_send_time = 0;

        cJSON_AddItemToObject(object, "arguments", arguments);
        post = cJSON_PrintUnformatted(object);
        client_send_msg(post, reply, sizeof(reply), LOG_URL, "selfcheck");

        DBG2(DBGFLAG_SELFCHECK, "net_packed post:%s, reply:%s\n", post, reply);
        // printf("net_packed post:%s, reply:%s\n", post, reply);

        cJSON_Delete(object);
        free(post);
    }
    // printf("download is : %ld Bytes\n", download_rates);
    // printf("send is : %ld Bytes\n", end_send_rates);//打印结果
}

int getNetRates(long *download_rates, long *send_rates)
{
    FILE *net_dev_file;                //文件指针
    char buffer[1024], name[64] = {0}; //文件中的内容暂存在字符缓冲区里
    long total_download = 0, total_send = 0, download1 = 0, send1 = 0;

    if ((net_dev_file = fopen("/proc/net/dev", "r")) == NULL) {
        printf("open file /proc/net/dev/ error!\n");
        return -1;
    }

    fgets(buffer, 1024, net_dev_file);
    fgets(buffer, 1024, net_dev_file);
    while (fgets(buffer, 1024, net_dev_file)) {
        sscanf(buffer, "%s", name);
        if (strcmp(name, "lo:") == 0) {
            continue;
        }
        sscanf(buffer, "%s %ld %*s %*s %*s %*s %*s %*s %*s %ld", name, &total_download, &total_send);

        download1 += total_download;
        send1 += total_send;
    }
    *download_rates = download1;
    *send_rates = send1;
    fclose(net_dev_file);
    return 0;
}

/* 一小时警告一次，避免警告太多 */
#define HIGHLOAD_WARN_INTERVAL 3600
static int highload_cpu_warn(int resource_cpu_used)
{
    time_t now = time(NULL);
    if (resource_cpu_used >= fasten_policy_global.resource.sys.cpu.limit) {
        DBG2(DBGFLAG_SELFCHECK, "cpu highload at %d, last time %d\n", now, last_highload_warntime_cpu);
        last_highload_warntime_cpu = now;
        return 1;
    }
    return 0;
}

static int highload_mem_warn(int resource_memory_used)
{
    time_t now = time(NULL);
    if (resource_memory_used >= fasten_policy_global.resource.sys.memory.limit) {
        DBG2(DBGFLAG_SELFCHECK, "mem highload at %d, last time %d\n", now, last_highload_warntime_mem);
        last_highload_warntime_mem = now;
        return 1;
    }
    return 0;
}

void check_sys_cpu(void)
{
    struct timeval tv = {0};
    char *post = NULL;
    char reply[REPLY_MAX] = {0};
    char uuid[64] = {0};
    unsigned long event_time = 0;
    cJSON *object = NULL, *arguments = NULL;
    int interval = 0;
    float resource_cpu_used = 0.0;

    gettimeofday(&tv, NULL);
    event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

    object = cJSON_CreateObject();
    if (object == NULL) {
        return;
    }
    arguments = cJSON_CreateObject();
    if (arguments == NULL) {
        cJSON_Delete(object);
        return;
    }

    get_random_uuid(uuid);
    if (uuid[0] == 0) {
        cJSON_Delete(object);
        return;
    }

    if (get_cpu_packed(&resource_cpu_used) < 0) {
        MON_ERROR("get_cpu_packed error\n");
    }

    if (highload_cpu_warn((int)resource_cpu_used)) {
        cpu_overload_count += 1;
    } else {
        cpu_overload_count = 0;
    }

    cJSON_AddStringToObject(object, "id", uuid);
    cJSON_AddNumberToObject(object, "result", MY_HANDLE_NO);
    cJSON_AddStringToObject(object, "operating", "");
    cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
    cJSON_AddStringToObject(object, "ip_address", If_info.ip);
    cJSON_AddStringToObject(object, "mac", If_info.mac);
    cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
    cJSON_AddStringToObject(object, "user", "root");
    cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
    cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
    cJSON_AddNumberToObject(object, "timestamp", event_time);
    cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
    cJSON_AddStringToObject(object, "source", "Agent");
    cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

    /* 记录cpu超限次数，用于在管控查看日志详情，排查问题 */
    cJSON_AddNumberToObject(arguments, "cpu_overload_count", cpu_overload_count);

    interval = fasten_policy_global.resource.sys.cpu.interval;
    if (interval > 0 && cpu_overload_count >= interval) {
        cpu_overload_count = 0; //报告超限后，重置次数，重新开始计数

        cJSON_AddStringToObject(object, "log_name", "HighCpuUsage");
        cJSON_AddStringToObject(object, "log_category", "SystemResource");
        cJSON_AddBoolToObject(object, "event", true);
        cJSON_AddStringToObject(object, "event_category", "SystemMonitor");
        cJSON_AddNumberToObject(object, "level", MY_LOG_LOW_RISK);
        cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
        cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);

        cJSON_AddBoolToObject(arguments, "cpu_overload", true);

    } else {
        cJSON_AddStringToObject(object, "log_name", "CpuUsage");
        cJSON_AddStringToObject(object, "log_category", "SystemResource");
        cJSON_AddBoolToObject(object, "event", false);
        cJSON_AddStringToObject(object, "event_category", "SystemMonitor");
        cJSON_AddNumberToObject(object, "level", MY_LOG_NORMAL);
        cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
        cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);

        cJSON_AddBoolToObject(arguments, "cpu_overload", false);
    }

    cJSON_AddNumberToObject(arguments, "cpu", (int)(resource_cpu_used + 0.5));
    cJSON_AddNumberToObject(arguments, "cpu_threshold", fasten_policy_global.resource.sys.cpu.limit);
    cJSON_AddNumberToObject(arguments, "cpu_overload_duration", interval);

    cJSON_AddItemToObject(object, "arguments", arguments);
    post = cJSON_PrintUnformatted(object);
    client_send_msg(post, reply, sizeof(reply),  LOG_URL, "selfcheck");

    cJSON_Delete(object);
    free(post);
}

void check_sys_mem(void)
{
    struct timeval tv = {0};
    char *post = NULL;
    char reply[REPLY_MAX] = {0};
    char uuid[64] = {0};
    unsigned long event_time = 0;
    cJSON *object = NULL, *arguments = NULL;
    int interval = 0;
    float resource_memory_used = 0.0;

    gettimeofday(&tv, NULL);
    event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

    object = cJSON_CreateObject();
    if (object == NULL) {
        return;
    }
    arguments = cJSON_CreateObject();
    if (arguments == NULL) {
        cJSON_Delete(object);
        return;
    }

    get_random_uuid(uuid);
    if (uuid[0] == 0) {
        cJSON_Delete(object);
        cJSON_Delete(arguments);
        return;
    }

    get_memoccupy(&resource_memory_used);

    if (highload_mem_warn((int)resource_memory_used)) {
        mem_overload_count += 1;
    } else {
        mem_overload_count = 0;
    }

    cJSON_AddStringToObject(object, "id", uuid);
    cJSON_AddNumberToObject(object, "result", MY_HANDLE_NO);
    cJSON_AddStringToObject(object, "operating", "");
    cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
    cJSON_AddStringToObject(object, "ip_address", If_info.ip);
    cJSON_AddStringToObject(object, "mac", If_info.mac);
    cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
    cJSON_AddStringToObject(object, "user", "root");
    cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
    cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
    cJSON_AddNumberToObject(object, "timestamp", event_time);
    cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
    cJSON_AddStringToObject(object, "source", "Agent");
    cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

    /* 记录内存超限次数，用于在管控查看日志详情，排查问题 */
    cJSON_AddNumberToObject(arguments, "mem_overload_count", mem_overload_count);

    interval = fasten_policy_global.resource.sys.memory.interval;

    if (interval > 0 && mem_overload_count >= interval) {
        mem_overload_count = 0; //报告超限后，重置次数，重新开始计数

        cJSON_AddStringToObject(object, "log_name", "HighMemoryUsage");
        cJSON_AddStringToObject(object, "log_category", "SystemResource");
        cJSON_AddBoolToObject(object, "event", true);
        cJSON_AddStringToObject(object, "event_category", "SystemMonitor");
        cJSON_AddNumberToObject(object, "level", MY_LOG_LOW_RISK);
        cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
        cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);

        cJSON_AddBoolToObject(arguments, "memory_overload", true);

    } else {
        cJSON_AddStringToObject(object, "log_name", "MemoryUsage");
        cJSON_AddStringToObject(object, "log_category", "SystemResource");
        cJSON_AddBoolToObject(object, "event", false);
        cJSON_AddStringToObject(object, "event_category", "SystemMonitor");
        cJSON_AddNumberToObject(object, "level", MY_LOG_NORMAL);
        cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
        cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);

        cJSON_AddBoolToObject(arguments, "memory_overload", false);
    }

    cJSON_AddNumberToObject(arguments, "memory", (int)(resource_memory_used + 0.5)); //加0.5达到四舍五入的效果
    cJSON_AddNumberToObject(arguments, "memory_threshold", fasten_policy_global.resource.sys.memory.limit);
    cJSON_AddNumberToObject(arguments, "memory_overload_duration", interval);

    cJSON_AddItemToObject(object, "arguments", arguments);
    post = cJSON_PrintUnformatted(object);
    client_send_msg(post, reply, sizeof(reply), LOG_URL, "selfcheck");

    cJSON_Delete(object);
    free(post);
}

void check_sys_disk(void)
{
    struct timeval tv = {0};
    char *post = NULL;
    char reply[REPLY_MAX] = {0};
    char uuid[64] = {0};
    unsigned long event_time = 0;
    cJSON *object = NULL, *arguments = NULL;

    gettimeofday(&tv, NULL);
    event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

    object = cJSON_CreateObject();
    if (object == NULL) {
        return;
    }
    arguments = cJSON_CreateObject();
    if (arguments == NULL) {
        cJSON_Delete(object);
        return;
    }

    get_random_uuid(uuid);
    if (uuid[0] == 0) {
        cJSON_Delete(object);
        return;
    }

    disk_count += 1;

    cJSON_AddStringToObject(object, "id", uuid);
    cJSON_AddStringToObject(object, "log_category", "SystemResource");
    cJSON_AddStringToObject(object, "event_category", "SystemMonitor");
    cJSON_AddNumberToObject(object, "result", MY_HANDLE_NO);
    cJSON_AddStringToObject(object, "operating", "");

    cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
    cJSON_AddStringToObject(object, "ip_address", If_info.ip);
    cJSON_AddStringToObject(object, "mac", If_info.mac);
    cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
    cJSON_AddStringToObject(object, "user", "root");
    cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
    cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
    cJSON_AddNumberToObject(object, "timestamp", event_time);
    cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
    cJSON_AddStringToObject(object, "source", "Agent");
    cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

    cJSON *partition = cJSON_CreateArray();
    get_partition_packed(partition, arguments);

    if (disk_is_overload) {
        cJSON_AddStringToObject(object, "log_name", "HighDiskUsage");
        cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_WARNING);
        cJSON_AddBoolToObject(object, "event", true);
        cJSON_AddNumberToObject(object, "level", MY_LOG_LOW_RISK);
        cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_ABNORMAL);
    } else {
        cJSON_AddStringToObject(object, "log_name", "DiskUsage");
        cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);
        cJSON_AddBoolToObject(object, "event", false);
        cJSON_AddNumberToObject(object, "level", MY_LOG_NORMAL);
        cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
    }

    cJSON_AddNumberToObject(arguments, "partition_threshold", fasten_policy_global.resource.sys.disk.limit);
    cJSON_AddNumberToObject(arguments, "partition_overload_duration", fasten_policy_global.resource.sys.disk.interval);

    cJSON_AddItemToObject(object, "arguments", arguments);
    post = cJSON_PrintUnformatted(object);
    if (disk_count == fasten_policy_global.resource.sys.disk.interval * 60) {
        client_send_msg(post, reply, sizeof(reply), LOG_URL, "selfcheck");
        disk_count = 0;
    }
    disk_is_overload = 0;

    cJSON_Delete(object);
    free(post);
}

static void send_client_operation_msg(char *operate)
{
	struct timeval tv = {0};
	char *post = NULL;
	char reply[REPLY_MAX] = {0};
	char uuid[64] = {0};
	unsigned long event_time = 0;
	bool event = false;
	cJSON *object = NULL, *arguments = NULL;

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientStartOrStop");
	cJSON_AddStringToObject(object, "log_category", "Client");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", MY_LOG_KEY);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
	cJSON_AddNumberToObject(object, "result", MY_RESULT_OK);
	cJSON_AddStringToObject(object, "operating", operate);
        cJSON_AddNumberToObject(object, "terminate", 0);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddItemToObject(object, "arguments", arguments);
	post = cJSON_PrintUnformatted(object);

	client_send_msg(post, reply, sizeof(reply), SINGLE_LOG_URL, "selfcheck");
	DBG2(DBGFLAG_SELFCHECK, "send client operation msg post:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
}

static void clean_expired_rulefile(void)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	struct stat st = {0};
	time_t now = time(NULL);
	char path[512] = {0};

	dirp = sniper_opendir(SNIPER_TMPDIR, OTHER_GET);
	if (!dirp) {
		if (errno != ENOENT) {
			MON_ERROR("clean_expired_rulefile open %s fail: %s\n", SNIPER_TMPDIR, strerror(errno));
		}
		return;
	}

	while ((ent = readdir(dirp))) {
		snprintf(path, sizeof(path), "%s/%s", SNIPER_TMPDIR, ent->d_name);
		if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
			if (st.st_mtime < now - 600) {
				unlink(path); //清理10分钟前的临时文件
			}
		}
	}

	sniper_closedir(dirp, OTHER_GET);
}

extern unsigned long snipermem[GETTYPE_MAX];
static void dump_snipermem(void)
{
        DBG2(DBGFLAG_VMRSS,
                 "proc:%lu(task %d, msg %d, cmd %d), file:%lu, net:%lu, "
		 "login:%lu, info:%lu, strategy:%lu, policy:%lu, other:%lu, VmRSS:%lu\n",
                 snipermem[PROCESS_GET]/1024, get_taskstat_num(),
                 get_kexec_msg_count(), get_exehash_num(),
                 snipermem[FILE_GET]/1024, snipermem[NETWORK_GET]/1024,
                 snipermem[LOGIN_GET]/1024, snipermem[INFO_GET]/1024,
		 snipermem[POLICY_GET]/1024, snipermem[OTHER_GET]/1024,
		 get_self_mem());
}

#define SYSINFO_FILE "/tmp/sysinfojson.txt"
/*
 * 运行成功，上传成功返回 0
 * 运行成功，上传失败返回 -1
 * 运行失败，不上传返回   -2
 * sync 1,全量采集; 0,按模块采集
 */
int upload_sysinfo(int sync)
{
	int ret = 0;
	char cmd[S_LINELEN] = {0};

        if (sniper_other_loadoff == 1) {
		return -3;
	}

    pthread_rwlock_rdlock(&conf_asset.lock);
    if (sync == 1) { /* 全量采集 */
            snprintf(cmd, sizeof(cmd), "%s/systeminformation -b %s -s %u >/dev/null 2>&1", WORKDIR, SYSINFO_FILE, (int)~0);
    } else { /* 按模块采集 */
            snprintf(cmd, sizeof(cmd), "%s/systeminformation -b %s -s %u >/dev/null 2>&1", WORKDIR, SYSINFO_FILE, conf_asset.module_st);
    }
    pthread_rwlock_unlock(&conf_asset.lock);

	if (my_system(cmd, 0) == 0) {
		INFO("upload systeminfomation %s\n", SYSINFO_FILE);
		ret = upload_file(SYSINFO_FILE, ASSET_URL);
        if (!ret) { /* 上传成功返回0，失败返回-1 */
                is_sync_once = 0;
        }
        return ret;
	}

    return -2;
}

/* selfcheck thread */
void *self_check(void *ptr)
{
    int i = 0;

    /* 生成今天0点0时0分时间 */
    time_t start_seconds;
    time(&start_seconds);
    struct tm *p_tm = localtime(&start_seconds);
    p_tm->tm_hour = 0;
    p_tm->tm_min = 0;
    p_tm->tm_sec = 0;
    /* 当前时间减去已过的秒数，即为当天0点的秒数 */
    start_seconds = mktime(p_tm);
    long day_seconds = 24 * 60 * 60;
    char reason[S_LINELEN] = {0};

    prctl(PR_SET_NAME, "sysstat_monitor");
    save_thread_pid("selfcheck", SNIPER_THREAD_SELFCHECK);

    while (Online) {
        dump_snipermem();

        /* 检查待转储的日志文件 */
        check_log_to_send("selfcheck");

	/* 
	 * 检查客户端是否需要关闭或启动
	 * 重新启动的时候需要更新内核策略
	 * 关闭的时候内核策略在进程/文件/网络的线程里面去关
	 */
	if (access(CLIENT_DISABLE, F_OK) == 0) {
		if (client_disable == TURN_MY_OFF) {
			INFO("stop client work\n");
			send_client_operation_msg(stopstr);
			client_disable = TURN_MY_ON;
		}
	} else {
		if (client_disable == TURN_MY_ON) {
			INFO("start client work\n");

			send_client_operation_msg(startstr);
			client_disable = TURN_MY_OFF;

			/* 拉取配置和策略，防止关停之后有更新 */
			get_conf(reason, sizeof(reason));
		}
	}

	/* 如果过期/停止客户端工作，什么也不做 */
	if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
		sleep(STOP_WAIT_TIME);
		continue;
	}

        /* 1分钟检查做一次资源监控 */
        if (i % 2 == 0) {
            /* 不依赖负载监控开关，cpu负载总要检查的，以在高负载时暂停sniper监控 */
            pthread_rwlock_rdlock(&fasten_policy_global.lock);

            if (fasten_policy_global.resource.sys.cpu.enable) {
                check_sys_cpu();
            }

            if (fasten_policy_global.resource.sys.memory.enable) {
                check_sys_mem();
            }

            if (fasten_policy_global.resource.sys.disk.enable) {
                check_sys_disk();
            }

            if (fasten_policy_global.resource.sys.netflow.enable) {
                get_network_packed();
            }

            if (fasten_policy_global.resource.process.enable) {
                check_pid_status();
            }

            pthread_rwlock_unlock(&fasten_policy_global.lock);
            i = 0;
        }
        i++;

        if (net_connect_status()) {
            check_conn_status();
        }

        // TODO 优化考虑，如果网络监控开了，结合起来，不重复做
        update_kernel_pmiddleware();

        check_lockedip(0);

        /* 资产清点,以天为单位每天零点周期执行 */
        // INFO("==day_seconds:%ld==conf_asset.cycle:%ld==%ld\n", day_seconds, conf_asset.cycle, conf_asset.cycle);
        time_t curr_seconds;
        time(&curr_seconds);
        if (conf_asset.cycle > 0 && curr_seconds - start_seconds >= (day_seconds * conf_asset.cycle)) {
            upload_sysinfo(0); /* 按模块采集 */
            /* 加一个周期 */
            start_seconds += day_seconds * conf_asset.cycle;
        }

	clean_expired_rulefile();

        mysleep(30);
    }
    conn_db_release();
    location_db_release();
    cpu_db_release();

    INFO("selfcheck thread exit\n");
    return NULL;
}
