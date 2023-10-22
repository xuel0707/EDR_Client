/*
 * cc pcpu.c -o pcpu
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* CPU时间=user+nice+system+idle+iowait+irq+softirq+stolen */
unsigned long get_total_cpu(void)
{
    int ret = 0;
    FILE *fp = NULL;
    unsigned long user = 0, nice = 0, system = 0, idle = 0;
    unsigned long iowait = 0, irq = 0, softirq = 0, stolen = 0;

    fp = fopen("/proc/stat", "r");
    if (fp) {
        ret = fscanf(fp, "%*s %lu %lu %lu %lu %lu %lu %lu %lu",
                     &user, &nice, &system, &idle, &iowait, &irq, &softirq, &stolen);
        fclose(fp);
    }

    if (ret < 4) {
        return 0;
    }
    return (user + nice + system + idle + iowait + irq + softirq+ stolen);
}

//获取进程的CPU时间
unsigned long get_process_cpu(pid_t pid)
{
    int ret = 0;
    FILE *fp = NULL;
    char path[256] = {0};
    unsigned long utime = 0, stime = 0, cutime = 0, cstime = 0;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (fp) {
        ret = fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu %lu %lu",
                     &utime, &stime, &cutime, &cstime);
        fclose(fp);
    }

    if (ret < 4) {
        return 0;
    }
    return (utime + stime + cutime + cstime);
}

void get_pcpu(pid_t pid, int cpu_num)
{
    unsigned long total1 = 0, total2 = 0;
    unsigned long mycpu1 = 0, mycpu2 = 0;
    float pcpu = 0.0;

    total1 = get_total_cpu();
    mycpu1 = get_process_cpu(pid);

    usleep(1250000);

    total2 = get_total_cpu();
    mycpu2 = get_process_cpu(pid);

    if (total1 == 0 || total2 == 0 || total1 == total2 ||
        mycpu1 == 0 || mycpu2 == 0) {
        return;
    }

    pcpu = (float)(mycpu2 - mycpu1) / (float)(total2 - total1) * (float)cpu_num * 100.0;
    printf("%f\n", pcpu);
}

int main(int argc, char **argv)
{
    int cpu_num = 0;
    char line[256] = {0};
    FILE *fp = NULL;

    if (argc == 1) {
        printf("Usage: %s pid\n", argv[0]);
        return 0;
    }

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        perror("fopen /proc/cpuinfo");
        return 1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "processor", 9) == 0) {
            cpu_num++;
        }
    }
    fclose(fp);
    printf("cpu_num %d\n", cpu_num);

    while (1) {
        get_pcpu(atoi(argv[1]), cpu_num);
        usleep(150000);
    }

    return 0;
}
