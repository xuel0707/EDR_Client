#define _GNU_SOURCE //for strcasestr

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>


#include "../cJSON.h"
#include "sys_info.h"

#define LINE_LEN        4096

// extern char sys_vendor[64];

/* JSON main_board */
void *sys_main_board(sys_info_t *data)
{
    char line[LINE_LEN] = {0};
    const char *board_name    = "/sys/class/dmi/id/board_name";
    const char *board_vendor  = "/sys/class/dmi/id/board_vendor";
    const char *board_serial  = "/sys/class/dmi/id/board_serial";
    const char *board_version = "/sys/class/dmi/id/board_version";
    cJSON *main_board = NULL;

    if (!data->object) {
        return NULL;
    }

    main_board = cJSON_CreateObject();
    if (!main_board) {
        return NULL;
    }

    memset(line, 0, sizeof(line));
    return_file_first_line(board_name, line, sizeof(line));
    if (line[0] != 0 || strcmp(line, "None") == 0) {
        snprintf(line, sizeof(line), "%s", "Mainboard");
    }
    cJSON_AddStringToObject(main_board, "board_name", line);

    memset(line, 0, sizeof(line));
    return_file_first_line(board_vendor, line, sizeof(line));
    if (line[0] != 0 || strcmp(line, "None") == 0) {
        snprintf(line, sizeof(line), "%s", sys_vendor);
    }
    cJSON_AddStringToObject(main_board, "vendor", line);

    memset(line, 0, sizeof(line));
    return_file_first_line(board_version, line, sizeof(line));
    if (line[0] != 0 || strcmp(line, "None") == 0) {
        snprintf(line, sizeof(line), "%s", "N1"); //None
    }
    cJSON_AddStringToObject(main_board, "version", line);

    memset(line, 0, sizeof(line));
    return_file_first_line(board_serial, line, sizeof(line));
    if (line[0] != 0 || strcmp(line, "None") == 0) {
        snprintf(line, sizeof(line), "%s", "ZB4e6f6e65"); //None
    }
    cJSON_AddStringToObject(main_board, "serial_id", line);

    cJSON_AddStringToObject(main_board, "issue_date", "None");

    cJSON_AddItemToArray(data->object, main_board); 

    return NULL;
}
void *sys_main_board_destroy(sys_info_t *data)
{
    return NULL;
}

/* JSON cpu */
void *sys_cpu_info(sys_info_t *data)
{
    char line[LINE_LEN] = {0};
    char cpu_mode[LINE_LEN] = {0};
    char cpu_vendor[LINE_LEN] = {0};
    char main_frequency[LINE_LEN] = {0};
    char cpu_family[LINE_LEN] = {0};
    char cache_size[32] = {0};
    int cpu_count = 0;
    int len = 0;
    FILE *fp = NULL;
    char *ptr = NULL;
    cJSON *cpu = NULL;

    if (!data->object) {
        return NULL;
    }

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        elog("open /proc/cpuinfo fail: %s", strerror(errno));
        return NULL;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char key[S_LINELEN] = {0};
        char value[S_LINELEN] = {0};

        if (get_key_value_from_line(line, key, sizeof(key),
                                    value, sizeof(value), ':') < 0) {
            continue;
        }

        if (strcmp(key, "model name") == 0) {
            snprintf(cpu_mode, sizeof(cpu_mode), "%s", value);
            continue;
        }

        if (strcmp(key, "cpu family") == 0) {
            snprintf(cpu_family, sizeof(cpu_family), "%s", value);
            continue;
        }

        if (strcmp(key, "cpu MHz") == 0) {
            snprintf(main_frequency, sizeof(main_frequency), "%s", value);
            continue;
        }

        if (strcmp(key, "vendor_id") == 0) {
            snprintf(cpu_vendor, sizeof(cpu_vendor), "%s", value);
            continue;
        }

        if (strcmp(key, "cache size") == 0) {
            snprintf(cache_size, sizeof(cache_size), "%s", value);
            ptr = strchr(cache_size, ' ');
            if (ptr) {
                *ptr = 0;
            }
            continue;
        }

        if (strcmp(key, "processor") == 0) {
            cpu_count = atoi(value);
            continue;
        }
    }

    fclose(fp);

    ++cpu_count;

    cpu = cJSON_CreateObject();
    if (cpu) {
        cJSON_AddStringToObject(cpu, "cpu_model", cpu_mode);
        cJSON_AddStringToObject(cpu, "vendor", cpu_vendor);
        cJSON_AddStringToObject(cpu, "family_code", cpu_family);
        cJSON_AddNumberToObject(cpu, "core_number", cpu_count);
        cJSON_AddStringToObject(cpu, "main_frequency", main_frequency);
        cJSON_AddStringToObject(cpu, "cache_size", cache_size);

        cJSON_AddItemToArray(data->object, cpu);
    }

    return NULL;
}
void *sys_cpu_info_destroy(sys_info_t *data)
{
    return NULL;
}

/* JSON memory */
extern int get_dmi_memory(cJSON *object);
void *sys_memory_info(sys_info_t *data)
{
    char line[LINE_LEN] = {0};
    char mem_size[LINE_LEN] = {0};
    FILE *fp = NULL;
    cJSON *mem = NULL;

    if (!data->object) {
        return NULL;
    }

    /* 通过dmi取内存条信息 */
    if (get_dmi_memory(data->object)) {
        return NULL;
    }

    /* 通过dmi取内存条信息失败，取内存总量，并按虚拟内存报告 */
    fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        elog("open /proc/meminfo fail: %s", strerror(errno));
        return NULL;
    }

    while (fgets(line, LINE_LEN, fp) != NULL) {
        char key[S_LINELEN] = {0};
        char value[S_LINELEN] = {0};

        if (get_key_value_from_line(line, key, sizeof(key),
                                    value, sizeof(value), ':') < 0) {
            continue;
        }

        if (strcmp(key, "MemTotal") == 0) {
            snprintf(mem_size, sizeof(mem_size), "%ld", atol(value)/1024);
            break;
        }
    }
    fclose(fp);

    mem = cJSON_CreateObject();
    if (mem) {
        cJSON_AddStringToObject(mem, "memory_name", "Memory");
        cJSON_AddStringToObject(mem, "vendor", sys_vendor);
        cJSON_AddStringToObject(mem, "size", mem_size);
        cJSON_AddStringToObject(mem, "slot", "RAM slot #0");
        cJSON_AddStringToObject(mem, "serial_id", "NC4e6f6e65T"); //None

        cJSON_AddItemToArray(data->object, mem);
    }

    return NULL;
}
void *sys_memory_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

/* JSON disk */
extern void get_disks_info(cJSON *disk_info);
void *sys_disk_info(sys_info_t *data)
{
    if (data) {
        get_disks_info(data->object);
    }

    return NULL;
}
void *sys_disk_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static char *get_gateway_info(void)
{
    char buff[LINE_LEN];
    unsigned long dest_addr;
    unsigned long gate_addr;
    FILE *fp;
    int ret = 0;

    fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        return NULL;
    }

    memset(buff, 0x00, sizeof(buff));
    fgets(buff, sizeof(buff), fp);
    while (fgets(buff, sizeof(buff), fp)) {
        ret = sscanf(buff, "%*s\t%lX\t%lX", &dest_addr, &gate_addr);
        if(ret != 2 || dest_addr != 0) {
            continue;
        }
        break;
    }
    fclose(fp);

    if (gate_addr) {
        struct in_addr addr;
        memcpy(&addr, &gate_addr, sizeof(struct in_addr));
        memset(buff, 0x00, sizeof(buff));
        snprintf(buff, sizeof(buff), "%s", inet_ntoa(addr));
        return strdup(buff);
    }

    return NULL;
}

static void paste_dns(char *dnslist, int size, char *newdns)
{
    int len = 0;
    char str[4096] = {0};
    char substr[128] = {0};

    if (!dnslist || !newdns || *newdns == 0) {
        return;
    }

    len = strlen(dnslist);
    if (len == 0) {
        snprintf(dnslist, size, "%s", newdns);
        return;
    }

    /* 忽略重复的dns */
    snprintf(str, sizeof(str), ",%s,", dnslist);
    snprintf(substr, sizeof(substr), ",%s,", newdns);
    if (strstr(str, substr)) {
        return;
    }

    snprintf(dnslist+len, size-len, ",%s", newdns);
}

//TODO 如果取到的nameserver是127.0.0.53，可能要查看systemd-resolved服务的配置
//nameserver是127.0.0.1的话，可能是本机有dns服务，如dnsmasq
static char *get_dns_info(void)
{
    char dns[LINE_LEN] = {0};
    char line[LINE_LEN] = {0};
    FILE *fp = NULL;

    fp = fopen("/etc/resolv.conf", "r");
    if (fp == NULL) {
        return NULL;
    }
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *ptr = NULL;
        char val[64] = {0};

        ptr = skip_headspace(line);
        if (ptr[0] == '#') { //注释行
            continue;
        }
        delete_tailspace(ptr);

        /* 关键字必须是nameserver，Nameserver这样的是无效的 */
        if (sscanf(ptr, "nameserver %s", val) == 1) { //nameserver x.x.x.x
            paste_dns(dns, sizeof(dns), val);
        }
    }
    fclose(fp);

    if (dns[0]) {
        return strdup(dns);
    }

    return NULL;
}

static void get_ipv4_addr(struct ifreq *ifr, char *ip)
{
    unsigned char *addr = NULL;
    struct sockaddr_in *sa = NULL;

    sa = (struct sockaddr_in *)&ifr->ifr_addr;
    addr = (unsigned char *)&sa->sin_addr;
    snprintf(ip, 64, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
}

//TODO 未来考虑一个网卡配了多个ipv6地址的情况
static char *get_ipv6_addr(const char *iface)
{
    char dname[IFNAMSIZ] = {0};
    char address[INET6_ADDRSTRLEN] = {0};
    unsigned char ipv6[16] = {0};
    FILE *f = NULL;
    int ret = 0;
    int scope = 0;
    int prefix = 0;

    f = fopen("/proc/net/if_inet6", "r");
    if (f == NULL) {
        return strdup("None");
    }

    while (fscanf(f, " %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %x %x %*x %s",
                    &ipv6[0], &ipv6[1], &ipv6[2], &ipv6[3], &ipv6[4], &ipv6[5], &ipv6[6], &ipv6[7], &ipv6[8], &ipv6[9],
                    &ipv6[10], &ipv6[11], &ipv6[12], &ipv6[13], &ipv6[14], &ipv6[15], &prefix, &scope, dname) == 19) {

        if (strcmp(iface, dname) != 0) {
            continue;
        }

        if (inet_ntop(AF_INET6, ipv6, address, sizeof(address)) == NULL) {
            continue;
        }

        dlog("IPv6 address: %s, prefix: %d\n", address, prefix);
    }
    fclose(f);

    if (address[0] != 0) {
        return strdup(address);
    }
    
    return strdup("None");
}

static char *get_nic_dns(const char *nic_name, const char *sys_dns) 
{
    char path[PATH_MAX] = {0};
    char dns[LINE_LEN] = {0};
    char line[LINE_LEN] = {0};
    FILE *fp = NULL;

    if (sys_dns) {
        snprintf(dns, sizeof(dns), "%s", sys_dns);
    }

    if (nic_name == NULL) {
        return strdup(dns);
    }
    
    snprintf(path, sizeof(path), "/etc/sysconfig/network-scripts/ifcfg-%s", nic_name);
    fp = fopen(path, "r");
    if (!fp) {
        return strdup(dns);
    }

    /* 解析DNSn=x.x.x.x */
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *ptr = NULL, *val = NULL;

        val = skip_headspace(line);
        if (strncasecmp(val, "dns", 3) != 0) { //TODO dns=x.x.x.x是有效条目吗
            continue;
        }

        delete_tailspace(val);
        ptr = strchr(val, '=');
        ptr++;

        val = skip_headspace(ptr); //TODO DNS= x.x.x.x是有效条目吗
        //TODO DNS=x.x.x.x y.y.y.y是有效条目吗

        paste_dns(dns, sizeof(dns), val);
    }
    fclose(fp);

    return strdup(dns);
}

//TODO 要考察/etc/network/interface.d/*吗？/etc/NetworkManager/system-connections/*里的dns是当前生效的dns吗
static char *get_nic_dns_nm(const char *nic_name, const char *sys_dns) 
{
    char dns[LINE_LEN] = {0};
    char line[LINE_LEN] = {0};
    FILE *fp = NULL;
    int len = 0;
    char *ptr = NULL, *val = NULL, *list = NULL;

    if (sys_dns) {
        snprintf(dns, sizeof(dns), "%s", sys_dns);
    }

    if (nic_name == NULL) {
        return strdup(dns);
    }
    
    fp = fopen("/etc/network/interfaces", "r");
    if (!fp) {
        return strdup(dns);
    }

    /*
     * 解析如下内容
     * iface eth0 inet static
     *   dns-nameservers 114.114.114.114 8.8.8.8
     */
    while (fgets(line, sizeof(line), fp) != NULL) {
        char nic[64] = {0};

        /* 定位目标网卡的配置块 */
        ptr = skip_headspace(line);
        if (sscanf(ptr, "iface %63s", nic) == 1 && strcmp(nic, nic_name) == 0) {
            break;
        }
    }

    len = strlen("dns-nameservers");
    /* 处理目标网卡的配置 */
    while (fgets(line, sizeof(line), fp) != NULL) {
        ptr = skip_headspace(line);
        if (strncmp(ptr, "iface", 5) == 0) { //本网卡配置已读完，下面是另一块网卡
            break;
        }

        /* 定位dns-nameservers行 */
        if (strncmp(ptr, "dns-nameservers", len) != 0) {
            continue;
        }
        ptr += len;
        if (!isspace(*ptr)) {
            continue;
        }

        /* 处理dns列表 */
        list = skip_headspace(ptr);
        delete_tailspace(list);
        while (*list) {
            /* 获取一个dns */
            val = list;
            ptr = list;
            while (1) {
                if (*ptr == 0) { //到列表尾
                    list = ptr;
                    break;
                }
                if (isspace(*ptr)) { //到dns尾
                    *ptr = 0;
                    list = ptr + 1;
                    break;
                }
                ptr++;
            }

            paste_dns(dns, sizeof(dns), val);
        }
    }

    fclose(fp);

    return strdup(dns);
}

/* 获取网卡类型: 1 有线网卡 2 无线网卡 3 虚拟网卡 */
static int get_nic_type(const char *nic_name) 
{
    char path[PATH_MAX] = {0}, realpath[PATH_MAX] = {0};
    DIR *dirp = NULL;
    struct dirent *ent = NULL;

    if (nic_name == NULL) {
        return 1; //默认有线
    }
 
    /*
     * 虚拟网卡的设备指向虚拟设备，如
     * virbr0 -> ../../devices/virtual/net/virbr0
     * eth0 -> ../../devices/pci0000:00/0000:00:16.0/0000:0b:00.0/net/eth0
     */
    snprintf(path, sizeof(path), "/sys/class/net/%s", nic_name);
    readlink(path, realpath, sizeof(realpath) - 1);
    if (strstr(realpath, "virtual")) {
        return 3; //虚拟网卡
    } else if (realpath[0] == 0) {
        /* centos5的/sys/class/net/DEV是目录，有/sys/class/net/DEV/device的是物理网卡，没有的是虚拟网卡 */
        snprintf(realpath, sizeof(realpath), "/sys/class/net/%s/device", nic_name);
        if (access(realpath, F_OK) != 0) {
            return 3; //虚拟网卡
        }
    }

    //TODO 待验证
    /* 无线网卡的/sys/class/net/DEV/目录下有wireless或phy80211 */
    dirp = opendir(path);
    if (dirp) {
        while ((ent = readdir(dirp))) {
            if (strstr(ent->d_name, "wireless") || strstr(ent->d_name, "80211")) {
                closedir(dirp);
                return 2; //无线网卡
            }
        }
    }

    closedir(dirp);
    return 1; //默认有线
}
/* SIOCGIFCONF只能取配置了ipv4地址的网卡信息 */
static void *get_nic_info_by_siocgifconf(sys_info_t *data, char *niclist, int niclist_len)
{
    int sockfd = 0, size = 0, count = 0;
    int numreqs = 32;
    struct ifconf ifc = {0};
    char *gateway = NULL;
    char *dns = NULL;
    struct ifreq *it = NULL, *end = NULL;
    cJSON *nic_info = NULL;

    if (!data->object || !niclist) {
        return NULL;
    }
    nic_info = data->object;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sockfd < 0) {
        elog("socket error\n");
        return NULL;
    }
 
    /* 取所有网卡 */
    while (1) {
        size = sizeof(struct ifreq) * numreqs;
        ifc.ifc_len = size;
        if (ifc.ifc_buf) {
            free(ifc.ifc_buf);
        }
        ifc.ifc_buf = malloc(size);
        if (!ifc.ifc_buf) {
            elog("get current ip fail, no memory\n");
            close(sockfd);
            return NULL;
        }

        if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
            elog("get current ip fail, ioctl %s\n", strerror(errno));
            close(sockfd);
            free(ifc.ifc_buf);
            return NULL;
        }

        if (ifc.ifc_len == size) {
            /* assume it overflowed and try again */
            numreqs += 10;
            continue;
        }
        break;
    }

    it = ifc.ifc_req;
    end = it + (ifc.ifc_len / sizeof(struct ifreq));

    dns = get_dns_info();
    if (!dns) {
        dns = strdup("");
    }

    gateway = get_gateway_info();
    if (!gateway) {
        gateway = strdup("None");
    }

    /* 初始化网卡列表为"|" */
    memset(niclist, 0, niclist_len);
    niclist[0] = '|';

    for (; it != end; ++it) {
        int len = 0;
        char nic_item[64] = {0};
        char ip[64] = {0}, *ipv6 = NULL;
        char szMac[64] = {0};
        struct ifreq ifr = {{{0}}};
        unsigned char *ptr = NULL;
        char *nic_dns = NULL, *tmp_nic_dns = NULL;
        cJSON *object = NULL;

        if (strcmp(it->ifr_name, "lo") == 0) { //不报lo
            continue;
        }

        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", it->ifr_name);

        /* 如果网卡不在列表中，则添加到网卡列表的尾部 */
        snprintf(nic_item, sizeof(nic_item), "|%s|", it->ifr_name);
        if (!strstr(niclist, nic_item)) {
            len = strlen(niclist);
            snprintf(niclist+len, niclist_len-len, "%s|", it->ifr_name);
        }

        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
            continue;
        }

        ptr = (unsigned char *) &ifr.ifr_ifru.ifru_hwaddr.sa_data[0];
        snprintf(szMac, sizeof(szMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4), *(ptr + 5));

        object = cJSON_CreateObject();
        if (!object) {
            continue;
        }

        cJSON_AddStringToObject(object, "card_name", ifr.ifr_name);
        /* 网卡类型，有线/无线/虚拟 */
        cJSON_AddNumberToObject(object, "card_type", get_nic_type(ifr.ifr_name));
        cJSON_AddStringToObject(object, "mac", szMac);

        get_ipv4_addr(it, ip);
        cJSON_AddStringToObject(object, "ipv4_addr", ip);

        count++;
        dlog("%d,Interface : %s , Mac : %s, ip : %s\n", count, ifr.ifr_name, szMac, ip);

        /* get_ipv6_addr总是返回非NULL的ipv6 */
        ipv6 = get_ipv6_addr(ifr.ifr_name);
        cJSON_AddStringToObject(object, "ipv6_addr", ipv6);
        free(ipv6);

        cJSON_AddStringToObject(object, "default_gateway", gateway);

        tmp_nic_dns = get_nic_dns(ifr.ifr_name, dns);
        if (tmp_nic_dns) {
            nic_dns = get_nic_dns_nm(ifr.ifr_name, tmp_nic_dns);
            free(tmp_nic_dns);
        }

        if (nic_dns && nic_dns[0] != 0) {
            cJSON_AddStringToObject(object, "dns_server", nic_dns);
        } else {
            cJSON_AddStringToObject(object, "dns_server", "None");
        }
        if (nic_dns) {
            free(nic_dns);
        }

        cJSON_AddItemToArray(nic_info, object);
    }

    free(dns);
    free(gateway);
    free(ifc.ifc_buf);
    close(sockfd);

    return NULL;
}
/* 参考ifconfig的实现，从/proc/net/dev里取网卡设备 */
static void *get_nic_info_by_netdev(sys_info_t *data, char *niclist)
{
    int sockfd = 0, size = 0, count = 0;
    int sockfd6 = 0;
    FILE *fp = NULL;
    char line[S_LINELEN] = {0};
    char *gateway = NULL;
    char *dns = NULL;
    cJSON *nic_info = NULL;

    if (!data->object) {
        return NULL;
    }
    nic_info = data->object;

    sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sockfd < 0) {
        elog("socket error\n");
        return NULL;
    }

    /* ifconfig从sockfd6取flags和mac，但实测从sockfd也可以，
       不明白ifconfig这么做的原因，但保留其做法 */
    sockfd6 = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
 
    dns = get_dns_info();
    if (!dns) {
        dns = strdup("");
    }

    gateway = get_gateway_info();
    if (!gateway) {
        gateway = strdup("None");
    }

    fp = fopen("/proc/net/dev", "r");
    if (!fp) {
        free(dns);
        free(gateway);
        close(sockfd);
    }

    while (fgets(line, sizeof(line), fp)) {
        int len = 0, is_up = 0, no_mac = 0;
        char nic_item[64] = {0};
        char ip[64] = {0}, *ipv6 = NULL;
        char szMac[64] = {0};
        struct ifreq ifr = {{{0}}};
        unsigned char *ptr = NULL;
        char *nic_dns = NULL, *tmp_nic_dns = NULL;
        cJSON *object = NULL;

        if (sscanf(line, "%15s", ifr.ifr_name) != 1) { //IFNAMSIZ是16
            continue;
        }
        if (strcmp(ifr.ifr_name, "Inter-|") == 0 || strcmp(ifr.ifr_name, "face") == 0) {
            continue; //忽略/proc/net/dev的头两行的标题
        }

        len = strlen(ifr.ifr_name);
        if (ifr.ifr_name[len-1] == ':') {
            ifr.ifr_name[len-1] = 0;
        }

        if (strcmp(ifr.ifr_name, "lo") == 0) {
            continue; //不报lo
        }

        /* 如果网卡已经在列表中，说明已经取过信息，不需要重复取 */
        snprintf(nic_item, sizeof(nic_item), "|%s|", ifr.ifr_name);
        if (niclist && strstr(niclist, nic_item)) {
            continue;
        }

        /*
         * IFF_UP表示网卡已启用
         * 没有UP标志的视为非网卡，如virbr0-nic
         * ifdown操作不会改变网卡的UP标志
         */
        if (sockfd6 < 0 || ioctl(sockfd6, SIOCGIFFLAGS, &ifr) < 0) {
            ioctl(sockfd, SIOCGIFFLAGS, &ifr);
        }
        is_up = ifr.ifr_flags & IFF_UP;
        if (!is_up) {
            continue;
        }

        if (sockfd6 < 0 || ioctl(sockfd6, SIOCGIFHWADDR, &ifr) < 0) {
            if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
                no_mac = 1;
            }
        }
        if (no_mac) {
            continue; //没有MAC的视为非网卡
        }

        ptr = (unsigned char *) &ifr.ifr_ifru.ifru_hwaddr.sa_data[0];
        snprintf(szMac, sizeof(szMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4), *(ptr + 5));

        object = cJSON_CreateObject();
        if (!object) {
            continue;
        }

        cJSON_AddStringToObject(object, "card_name", ifr.ifr_name);
        cJSON_AddStringToObject(object, "mac", szMac);

        /* 网卡类型，有线/无线/虚拟 */
        cJSON_AddNumberToObject(object, "card_type", get_nic_type(ifr.ifr_name));

        if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {
            get_ipv4_addr(&ifr, ip);
        }
        if (ip[0] == 0) {
            cJSON_AddStringToObject(object, "ipv4_addr", "None");
        } else {
            cJSON_AddStringToObject(object, "ipv4_addr", ip);
        }

        count++;
        dlog("%d: Interface %s, Mac %s, ipv4 %s\n", count, ifr.ifr_name, szMac, ip);

        ipv6 = get_ipv6_addr(ifr.ifr_name);
        if (ipv6) {
            if (ipv6[0] == 0) {
                cJSON_AddStringToObject(object, "ipv6_addr", "None");
            } else {
                cJSON_AddStringToObject(object, "ipv6_addr", ipv6);
            }
            free(ipv6);
        } else {
            cJSON_AddStringToObject(object, "ipv6_addr", "None");
        }

        cJSON_AddStringToObject(object, "default_gateway", gateway);

        tmp_nic_dns = get_nic_dns(ifr.ifr_name, dns);
        if (tmp_nic_dns) {
            nic_dns = get_nic_dns_nm(ifr.ifr_name, tmp_nic_dns);
            free(tmp_nic_dns);
        }

        if (nic_dns) {
            if (nic_dns[0] == 0) {
                cJSON_AddStringToObject(object, "dns_server", "None");
            } else {
                cJSON_AddStringToObject(object, "dns_server", nic_dns);
            }
            free(nic_dns);
        } else {
            cJSON_AddStringToObject(object, "dns_server", "None");
        }

        cJSON_AddItemToArray(nic_info, object);
    }

    fclose(fp);

    free(dns);
    free(gateway);
    close(sockfd);

    if (sockfd6 > 0) {
        close(sockfd6);
    }

    return NULL;
}
/* JSON network_card */
void *sys_nic_info(sys_info_t *data)
{
    char niclist[PATH_MAX] = {0};

    /*
     * 两种取取网卡设备的方法各有缺陷，因此组合使用
     * 1、SIOCGIFCONF方法只能取配了ipv4地址的网卡，但如果一块网卡有多个ip，可以都取到
     * 2、/proc/dev/net能取到所有的网卡，但如果一块网卡有多个ip，只能取到1个
     * SIOCGIFCONF处理过的网卡放在网卡列表里，/proc/dev/net不重复处理
     */
    //TODO 研究ip命令通过netlink取到的是否全的，是否各Linux版本均支持

    get_nic_info_by_siocgifconf(data, niclist, sizeof(niclist));

    get_nic_info_by_netdev(data, niclist);
}
void *sys_nic_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

struct device_config_header {
	unsigned short vendor_id;
	unsigned short device_id;
	unsigned short command;
	unsigned short status;
	unsigned char revision;
	unsigned char class_prog;
	unsigned char class_device;
};
static void get_device_model(char *path, char *model, int model_len, char *vendor, int vendor_len)
{
	char line[S_LINELEN] = {0};
	char revision_str[8] = {0};
	char vendor_id_str[8] = {0};
	char device_id_str[8] = {0};
	char *value = NULL, *device = NULL, *ptr = NULL;
	struct device_config_header header = {0};
	int fd = 0, size = sizeof(header);
	FILE *fp = NULL;

	if (!path || !model || !vendor) {
		return;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return;
	}

	/* 从/sys/class/DEVTYPE/DEVICE/device/config里读设备型号ID信息 */
	if (read(fd, &header, size) != size) {
		close(fd);
		return;
	}
	close(fd);

	snprintf(vendor_id_str, 8, "%04x", header.vendor_id);
	snprintf(device_id_str, 8, "%04x", header.device_id);
	snprintf(revision_str,  8, "%02x", header.revision);

	/* 从pci.ids文件里解析厂商和设备型号 */
	fp = fopen("/usr/share/hwdata/pci.ids", "r");
	if (!fp) {
		fp = fopen("/usr/share/misc/pci.ids", "r");
		if (!fp) {
			return;
		}
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, vendor_id_str, 4) != 0) {
			continue;
		}

		ptr = strchr(line, ' ');
		if (!ptr) {
			continue;
		}

		/* 找到以vendor_id开头的行 */
		value = skip_headspace(ptr+1);
		delete_tailspace(value);

		snprintf(vendor, vendor_len, "%s", value);

		while (fgets(line, sizeof(line), fp)) {
			/* 非空格符开头的行，说明已到其他厂家，解析设备失败 */
			if (!isspace(line[0])) {
				break;
			}

			device = skip_headspace(line);
			if (strncmp(device, device_id_str, 4) != 0) {
				continue;
			}

			ptr = strchr(device, ' ');
			if (!ptr) {
				continue;
			}

			/* 找到device_id的行 */
			device = skip_headspace(ptr+1);
			delete_tailspace(device);

			snprintf(model, model_len, "%s (rev %s)", device, revision_str);
			break;
		}

		/* vendor_id的厂家的设备已找完，结束查找 */
		break;
	}

	fclose(fp);
}

/* JSON sound_card */
static void *get_sound_card_info_bylspci(sys_info_t *data)
{
    char line[LINE_LEN] = {0};
    /* 调整与服务端长度一致防止入库失败报错 */
    char audio_model[512] = {0};
    char vendor[128] = {0};
    FILE *fp = NULL;
    char *str1 = NULL, *str2 = NULL;
    char *ptr = NULL, *model = NULL;
    cJSON *audio_info = NULL;

    if (!data->object) {
        return NULL;
    }

    fp = popen("lspci", "r");
    if (!fp) {
        /* 没有lspci命令，按无声卡处理 */
        return NULL;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        str2 = strstr(line, "Multimedia audio controller:");
        str1 = strstr(line, "Audio device:");
        if (str2) {
            ptr = strchr(str2, ':');
        } else if (str1) {
            ptr = strchr(str1, ':');
        } else {
            continue;
        }

        ptr++;
        model = skip_headspace(ptr);
        delete_tailspace(model);

        if (*model == 0) {
            continue;
        }

        audio_info = cJSON_CreateObject();
        if (!audio_info) {
            continue;
        }

        cJSON_AddItemToArray(data->object, audio_info);

        snprintf(audio_model, sizeof(audio_model), "%s", model);
        cJSON_AddStringToObject(audio_info, "card_name", audio_model);

        /* 厂商信息 */
        snprintf(vendor, sizeof(vendor), "%s", model);
        ptr = strchr(vendor, ' ');
        if (ptr) {
            *ptr = 0;
            cJSON_AddStringToObject(audio_info, "vendor", vendor);
        } else {
            cJSON_AddStringToObject(audio_info, "vendor", sys_vendor);
        }
    }

    pclose(fp);
    
    return NULL;
}
void *sys_sound_card_info(sys_info_t *data)
{
    int i = 0, count = 0;
    char path[PATH_MAX] = {0};
    char line[LINE_LEN] = {0};
    /* 调整与服务端长度一致防止入库失败报错 */
    char audio_model[512] = {0};
    char vendor[128] = {0};
    cJSON *audio_info = NULL;

    if (!data->object) {
        return NULL;
    }

    for (i = 0; i < 16; i++) {
        snprintf(path, sizeof(path), "/sys/class/sound/card%d/device/config", i);
        if (access(path, F_OK) < 0) {
            break;
        }

        get_device_model(path, audio_model, sizeof(audio_model), vendor, sizeof(vendor));
        if (audio_model[0] != 0) {
            count++;
            audio_info = cJSON_CreateObject();
            if (audio_info) {
                cJSON_AddStringToObject(audio_info, "card_name", audio_model);
                cJSON_AddStringToObject(audio_info, "vendor", vendor);
                cJSON_AddItemToArray(data->object, audio_info);
            }
        }
    }

    if (count == 0) {
        get_sound_card_info_bylspci(data);
    }

    return NULL;
}
void *sys_sound_card_info_destroy(sys_info_t *data)
{
    return NULL;
}

/* JSON bios */
void *sys_bios_info(sys_info_t *data)
{
    char line[PATH_MAX];
    const char *bios_data = "/sys/class/dmi/id/bios_date";
    const char *bios_vendor = "/sys/class/dmi/id/bios_vendor";
    const char *bios_version = "/sys/class/dmi/id/bios_version";
    int len = 0;

    if (data->object == NULL) return NULL;
    
    cJSON *bios_info = data->object;
    cJSON *object = cJSON_CreateObject();

    len = 0;
    memset(line, 0x00, sizeof(line));
    if (return_file_first_line(bios_data, line, sizeof(line)) == 0) {
        len = strlen(line);
    }
    if (len > 0) {
        cJSON_AddStringToObject(object, "issue_date", line);
    } else {
        cJSON_AddStringToObject(object, "issue_date", "None");
    }

    len = 0;
    memset(line, 0x00, sizeof(line));
    if (return_file_first_line(bios_vendor, line, sizeof(line)) == 0) {
        len = strlen(line);
    }
    if (len > 0) {
        cJSON_AddStringToObject(object, "vendor", line);
    } else {
        cJSON_AddStringToObject(object, "vendor", sys_vendor);
    }

    len = 0;
    memset(line, 0x00, sizeof(line));
    if (return_file_first_line(bios_version, line, sizeof(line)) == 0) {
        len = strlen(line);
    }
    if (len > 0) {
        cJSON_AddStringToObject(object, "version", line);
    } else {
        cJSON_AddStringToObject(object, "version", "N1"); //None
    }

    cJSON_AddStringToObject(object, "name", "BIOS");

    cJSON_AddItemToArray(bios_info, object);

    return NULL;
}
void *sys_bios_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

/* JSON display_card */
static void *get_display_card_info_bylspci(sys_info_t *data)
{
    char line[LINE_LEN];
    char cmd[LINE_LEN];
    char bus[64];
    const char *key = "VGA compatible controller:";
    char *ptr = NULL;
    int len = 0;

    if (data->object == NULL) return NULL;

    cJSON *display_info = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, display_info);

    memset(bus, 0x00, sizeof(bus));
    if (popen_filter_one_keystr("lspci", key, line, sizeof(line)) == 0) {
        ptr = strstr(line, key);
        if (ptr == NULL) {
            cJSON_AddStringToObject(display_info, "card_name", "None");
        } else {
            ptr += strlen(key);
            
            while (*ptr == ' ') ++ptr;

            len = strlen(line);
            if (line[len-1] == '\n') {
                line[len-1] = 0;
            }
            len = strlen(ptr);
            if (len > 512) {
                ptr[512] = '\0';
            }
            cJSON_AddStringToObject(display_info, "card_name", ptr);

            len = 0;
            while (line[len] != ' ') {
                bus[len] = line[len];
                ++len;
            }
        }
    }
    else {
        cJSON_AddStringToObject(display_info, "card_name", "None");
    }
    cJSON_AddStringToObject(display_info, "vendor", sys_vendor);

    /* 显存大小 */
    ptr = NULL;
    memset(cmd, 0x00, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "lspci -v -s %s", bus);
    if (popen_filter_one_keystr(cmd, "Memory at", line, sizeof(line)) == 0) {
        ptr = strstr(line, "size=");
        if (ptr == NULL) {
            cJSON_AddStringToObject(display_info, "size", "128");
        } else {
            ptr += 5;

            len = 0;
            memset(cmd, 0x00, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "%s", ptr);
            while (1) {
                if (len >= 6) break;
                if (cmd[len] == 'M') {
                    cmd[len] = '\0';
                    break;
                }
                ++ len;
            }
            if (len < 6) {
                cJSON_AddStringToObject(display_info, "size", cmd);
            }
            else {
                cJSON_AddStringToObject(display_info, "size", "128");
            }
        }
    }
    else {
        cJSON_AddStringToObject(display_info, "size", "128");
    }

    return NULL;
}
/* 把显卡sysfs目录下的resource的大小加起来，可得显存大小 */
static int get_display_card_memory(char *dir)
{
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    struct stat st = {0};
    off_t size = 0;
    char path[PATH_MAX] = {0};

    if (!dir) {
        return 0;
    }

    dirp = opendir(dir);
    if (!dirp) {
        elog("Open dir %s fail: %s\n", dir, strerror(errno));
        return 0;
    }

    /* 计算resource[n]的和 */
    while ((dent = readdir(dirp)) != NULL) {
        if (strncmp(dent->d_name, "resource", 8) != 0) {
            continue;
        }
        if (dent->d_name[8] == 0 || strchr(dent->d_name, '_')) {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", dir, dent->d_name);
        if (stat(path, &st) == 0) {
            size += st.st_size / 1048576;
        }
    }

    closedir(dirp);

    return (int)size;
}
/*
 * 通过nvidia-smi命令取GPU的型号
 * nvidia-smi -L
 * GPU 0: Tesla T4 (UUID: GPU-60e1c0df-5aad-abbf-5298-09cd2c2eeca2)
 * GPU 1: Tesla T4 (UUID: GPU-e93d0cb9-ec0b-e427-f3e2-2e423809b0e7)
 * GPU 2: Tesla T4 (UUID: GPU-87d87138-3187-7859-0191-fb96247013cc)
 * GPU 3: Tesla T4 (UUID: GPU-2ba89f85-52aa-17ae-eaaa-a77fb8e503b0)
 */
#define GPULIST "/opt/snipercli/nvidia-gpulist"
static void get_model_from_gpulist(char *model, int model_len, int num)
{
    int i = 0;
    char cmd[128] = {0};
    char line[S_LINELEN] = {0};
    char *ptr = NULL, *buf = NULL;
    FILE *fp = NULL;

    /* 没有GPU列表文件，则产生一个 */
    if (access(GPULIST, F_OK) < 0) {
        snprintf(cmd, sizeof(cmd), "%s > %s", "nvidia-smi -L", GPULIST);
        system(cmd);
    }

    fp = fopen(GPULIST, "r");
    if (fp) {
        for (i = 0; i <= num; i++) {
            fgets(line, sizeof(line), fp); //读到第num行
        }
        fclose(fp);

        /* 从GPU 0: Tesla T4 (UUID: ...)中截取出型号Tesla T4 */
        ptr = strchr(line, '(');
        if (ptr) {
            *ptr = 0;
        }
        ptr = strchr(line, ':');
        if (ptr) {
            buf = ptr + 1;
        } else {
            buf = line;
        }
        ptr = skip_headspace(buf);
        delete_tailspace(ptr);
        snprintf(model, model_len, "%s", ptr);
    }

    if (model[0] == 0) {
        snprintf(model, model_len, "%s", "NVIDIA GPU"); //没取到型号，设个默认值
    }
}
static int get_display_card_model(char *path, cJSON *object, int num)
{
    int len = 0, size = 0;
    char size_str[64] = {0};
    /* 调整与服务端长度一致防止入库失败报错 */
    char model[512] = {0};
    char vendor[128] = {0};
    cJSON *display_info = NULL;

    if (!path || !object) {
        return 0;
    }

    get_device_model(path, model, sizeof(model), vendor, sizeof(vendor));
    if (model[0] == 0 && strcasestr(vendor, "nvidia")) {
        /* 如果没取到NVIDIA显卡的型号，用nvidia-smi命令获取 */
        get_model_from_gpulist(model, sizeof(model), num);
    }
    if (model[0] == 0) {
        return 0; //忽略取不到型号的显卡
    }

    display_info = cJSON_CreateObject();
    if (display_info) {
        cJSON_AddStringToObject(display_info, "card_name", model);
        cJSON_AddStringToObject(display_info, "vendor", vendor);

        len = strlen(path);
        path[len-7] = 0; // DIR/config -> DIR
        size = get_display_card_memory(path);
        snprintf(size_str, sizeof(size_str), "%d", size ? size : 128); //默认128M
        cJSON_AddStringToObject(display_info, "size", size_str);

        cJSON_AddItemToArray(object, display_info);
    }

    return 1;
}
void *sys_display_card_info(sys_info_t *data)
{
    int i = 0, count = 0;
    char path[PATH_MAX] = {0};
    DIR *dirp = NULL;
    struct dirent *dent = NULL;

    if (!data->object) {
        return NULL;
    }

    /* 最多取16块显卡的信息 */
    for (i = 0; i < 16; i++) {
        snprintf(path, sizeof(path), "/sys/class/graphics/fb%d/device/config", i);
        if (access(path, F_OK) < 0) {
            break;
        }

        count += get_display_card_model(path, data->object, i);
    }

    /* 取所有GPU卡的信息 */
    dirp = opendir("/sys/class/mdev_bus/");
    if (dirp) {
        i = 0;
        while ((dent = readdir(dirp)) != NULL) {
            if (dent->d_name[0] == '.') {
                continue;
            }

            snprintf(path, sizeof(path), "/sys/class/mdev_bus/%s/config", dent->d_name);
            count += get_display_card_model(path, data->object, i);
            i++;
        }
        closedir(dirp);
    }
    unlink(GPULIST); //删除get_display_card_model()里创建的临时文件

    if (count == 0) {
        get_display_card_info_bylspci(data);
    }

    return NULL;
}
void *sys_display_card_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static int get_edid(unsigned char *edid, char *path)
{
        int fd = 0, ret = 0, i = 0;
        unsigned char sum = 0;

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                dlog("open %s fail: %s\n", path, strerror(errno));
                return -1;
        }

        ret = read(fd, edid, 128);
        close(fd);

        if (ret == 0) { //此edid文件内容为空
                return -1;
        }
        if (ret < 0) {
                dlog("read edid from %s fail: %s. ret %d\n", path, strerror(errno), ret);
                return -1;
        }
        if (ret != 128) {
                dlog("read edid from %s fail. read %d types\n", path, ret);
                return -1;
        }

        /* check the checksum */
        for (i = 0; i<128; i++) {
                sum += edid[i];
        }
        if (sum) {
                dlog("Warning: edid Checksum failed\n");
        }

        /* check header */
        for (i = 0; i < 8; i++) {
                //0x00 0xff 0xff 0xff 0xff 0xff 0x00
                if (!(((i == 0 || i == 7) && edid[i] == 0x00) || (edid[i] == 0xff))) {
                        dlog("Header incorrect. Probably not an edid\n");
                        return -1;
                }
        }

        return 0;
}

#define DRMCARD0 "/sys/class/drm/card0/"
#define DRMCARD1 "/sys/class/drm/card1/"
static int get_monitor_model(char *drmpath, char *name, char *vendor, char *resolution)
{
        int i = 0, j = 0, has_edid = 0, ret = 0, a = 0, b = 0;
        unsigned char edid[128] = {0};
        char modelname[16] = {0};
        char vendor_head[8] = {0};
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
        char path[1024] = {0};
	char line[LINE_LEN] = {0};
	FILE *fp = NULL;
	char *ptr = NULL;

	if (!drmpath || !name || !vendor || !resolution) {
		return -1;
	}

	dirp = opendir(drmpath); //打开目录
	if (!dirp) {
		/* 不打印DRMCARD1不存在的错误，它一般都没有 */
		if (strcmp(drmpath, DRMCARD0) == 0) {
                	dlog("open dir %s fail: %s\n", drmpath, strerror(errno));
		}
		return -1;
	}

	while ((ent = readdir(dirp))) {
		if (strncmp(ent->d_name, "card", 4) != 0) {
			continue;
		}

		snprintf(path, 1024, "%s/%s/edid", drmpath, ent->d_name);
		if (get_edid(edid, path) == 0) {
			has_edid = 1;

			snprintf(path, 1024, "%s/%s/modes", drmpath, ent->d_name);
			fp = fopen(path, "r"); //打开文件
			if (fp) {
				while (fgets(line, LINE_LEN, fp)) {
					ret = sscanf(line, "%dx%d", &a, &b); //如1024x768
					if (ret == 2) {
						/* 第一个分辨率即最大分辨率 */
						snprintf(resolution, 64, "%dx%d", a, b);
						break;
					}
				}
				fclose(fp);   //关闭文件
			}

			break;
		}
	}

	closedir(dirp); //关闭目录

	if (!has_edid) {
                return -1;
        }

        //Product Identification
        /* Model Name: Only thing I do out of order of edid, to comply with X standards... */
        for (i = 0x36; i < 0x7E; i += 0x12) { //read through descriptor blocks...
                if (edid[i] == 0x00) { //not a timing descriptor
                        if (edid[i+3] == 0xfc) { //Model Name tag
                                for (j = 0; j < 13; j++) {
                                        if (edid[i+5+j] == 0x0a) {
                                                modelname[j] = 0x00;
                                        } else {
                                                modelname[j] = edid[i+5+j];
                                        }
                                }
                        }
                }
        }

	strncpy(name, modelname, LINE_LEN);

        /* Vendor Name: 3 characters, standardized by microsoft, somewhere.
         * bytes 8 and 9: f e d c b a 9 8  7 6 5 4 3 2 1 0
         * Character 1 is e d c b a
         * Character 2 is 9 8 7 6 5
         * Character 3 is 4 3 2 1 0
         * Those values start at 0 (0x00 is 'A', 0x01 is 'B', 0x19 is 'Z', etc.)
         */

        vendor_head[0] = (edid[8] >> 2 & 0x1f) + 'A' - 1;
        vendor_head[1] = (((edid[8] & 0x3) << 3) | ((edid[9] & 0xe0) >> 5)) + 'A' - 1;
        vendor_head[2] = (edid[9] & 0x1f) + 'A' - 1;

        if (strcasecmp(vendor_head, "LEN") == 0) {
		strncpy(vendor, "Lenovo", LINE_LEN);
        } else if (strcasecmp(vendor_head, "SAM") == 0) {
		strncpy(vendor, "SAMSUNG", LINE_LEN);
        } else if (strcasecmp(vendor_head, "DEL") == 0) {
		strncpy(vendor, "DELL", LINE_LEN);
	} else if (strncasecmp(vendor_head, modelname, 3) == 0) {
		/* 如果厂家名前3个字符与型号的前3个字符相同，将型号的第一个单词作为厂家名 */
		ptr = strchr(modelname, ' ');
		if (ptr) {
			*ptr = 0;
		}
		strncpy(vendor, modelname, LINE_LEN);
        } else {
		strncpy(vendor, vendor_head, LINE_LEN);
	}

	return 0;
}

static int get_monitor_resolution(char *drmpath, char *resolution)
{
	char line[LINE_LEN] = {0}, path[1024] = {0};
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	char *ptr = NULL;
	int ret = 0, a = 0, b = 0;
	FILE *fp = NULL;

	if (!drmpath || !resolution) {
		return -1;
	}

	dirp = opendir(drmpath);
	if (!dirp) {
		/* 不打印DRMCARD1不存在的错误，它一般都没有 */
		if (strcmp(drmpath, DRMCARD0) == 0) {
                	dlog("open dir %s fail: %s\n", drmpath, strerror(errno));
		}
		return -1;
	}

	while ((ent = readdir(dirp))) {
		if (strncmp(ent->d_name, "card", 4) != 0) {
			continue;
		}

		snprintf(path, 1024, "%s/%s/modes", drmpath, ent->d_name);
		fp = fopen(path, "r");
		if (!fp) {
			continue;
		}

		while (fgets(line, LINE_LEN, fp)) {
			ret = sscanf(line, "%dx%d", &a, &b); //如1024x768
			if (ret == 2) {
				/* 第一个分辨率即最大分辨率 */
				snprintf(resolution, 64, "%dx%d", a, b);
				fclose(fp);
				closedir(dirp);
				return 0;
			}
		}
		fclose(fp);
	}

	closedir(dirp);
	return -1;
}

/* JSON display_device */
void *sys_display_device_info(sys_info_t *data)
{
    char line[LINE_LEN] = {0};
    char tmp[64] = {0};
    char name[LINE_LEN] = "None", vendor[LINE_LEN] = "None", resolution[64] = "None";
    char *ptr = NULL;
    int i = 0;

    if (data->object == NULL) return NULL;

    /* 通过DRM图形显示框架取显示器信息，Direct Rendering Manager
       显示器0没取到，尝试显示器1，最多尝试2个显示器 */
    if (get_monitor_model(DRMCARD0, name, vendor, resolution) < 0) {
        get_monitor_model(DRMCARD1, name, vendor, resolution);
    }

    /* 上面没有取到分辨率，单独再取一遍分辨率，比如虚拟机取不到显示器型号，但可以取分辨率 */
    if (strcmp(resolution, "None") == 0) {
        if (get_monitor_resolution(DRMCARD0, resolution) < 0) {
            get_monitor_resolution(DRMCARD1, resolution);
        }
    }

    cJSON *display_info = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, display_info);

    /* 上面没取到分辨率，再尝试用xrandr命令取一下，xrandr是从/tmp/.X11-unix/Xnnnn里取的 */
    if (strcmp(resolution, "None") == 0) {
        if (popen_filter_one_keystr("xrandr", NULL, line, sizeof(line)) == 0) {
            ptr = strstr(line, "current");
            if (ptr) {
                ptr += 8;
                for (i = 0; *ptr != ',' && i<sizeof(tmp)-1; i++) {
                    tmp[i] = *ptr;
                    ++ ptr;
                }
                strncpy(resolution, tmp, 64);
            }
        }
    }

    if (strcmp(name, "None") == 0) {
    	cJSON_AddStringToObject(display_info, "device_name", "Monitor");
    } else {
    	cJSON_AddStringToObject(display_info, "device_name", name);
    }
    cJSON_AddStringToObject(display_info, "resolution", resolution);
    cJSON_AddStringToObject(display_info, "vendor", vendor);
}
void *sys_display_device_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}
