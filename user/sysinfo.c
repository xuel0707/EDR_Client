#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h> //uname
#include <utmp.h>
#include <sys/statfs.h>
#include <ifaddrs.h>
#include <scsi/scsi.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

/* our header */
#include "header.h"

#define CS_INS_FILE1 "/root/install.log"        /* centos/redhat5-6系统安装时生成的文件*/
#define CS_INS_FILE2 "/root/anaconda-ks.cfg"    /* centos7系统安装时生成的文件*/
#define UB_INS_FILE "/root/installer"   /* ubuntu系统安装时生成的文件*/

char sysname[16] = "Linux";
pthread_rwlock_t ethinfo_lock;

sysinfo_t Sys_info = {{0}};
ifinfo_t If_info = {{0}};

/* return -1 error, 0 success */
static int get_release_from_file(const char *filename, sysinfo_t *sysinfo, const char *keystr)
{
	char *line = NULL;
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0};
	int len = 0, keylen = 0, found = 0;

	DBG("get release from %s\n", filename);

	strcpy(sysinfo->os_dist, "Linux");

	fp = fopen(filename, "r");
	if (!fp) {
		INFO("open %s error: %s\n", filename, strerror(errno));
		return -1;
	}

	while (fgets(buf, S_LINELEN, fp)) {
		line = skip_headspace(buf);
		if (*line == '#' || *line == 0) { //忽略空行和注释行
			continue;
		}

		if (!keystr) {
			found = 1;
			break;
		}
		keylen = strlen(keystr);
		if (strncmp(buf, keystr, keylen) == 0) {
			line += keylen;
			found = 1;
			break;
		}
	}
	fclose(fp);

	if (!found) {
		return -1;
	}

	delete_tailspace(line);

	/* 消除头部的无效字符 */
	while (*line != 0) {
		if (*line == ' ' || *line == '\t' || *line == '"' || *line == '=') {
			line++;
			continue;
		}

		break;
	}

	/* 消除尾部的双引号 */
	len = strlen(line);
	if (len == 0) {
		return -1;
	}
	if (line[len-1] == '"') {
		line[len-1] = 0;
	}

	/* 再次消除尾部的空格 */
	delete_tailspace(line);
	len = strlen(line);
	if (len == 0) {
		return -1;
	}

#ifdef KYLIN
	/* 管控中心显式发行版信息，做了处理，使CentOS x.y显式为CentOSx，目的是为了便于统计操作系统类型
	   对于Kylin 4.0.2这样的，就显示成了Kylin4，客户希望还是显示Kylin 4.0.2，故做此临时处理 */
	//TODO 针对不同os类型处理，或为管控中心增加一个os类型字段，或管控中心自行增加一个os类型字段
	int i = 0;
	while (*line != 0) {
		if (*line != ' ') {
			sysinfo->os_dist[i] = *line;
			i++;
		}
		line++;
	}
#else
	/* 如果发行版信息中未带Linux字样，则添加Linux，以显式表明这是Linux系统 */
	if (!strstr(line, "linux") && !strstr(line, "Linux") && !strstr(line, "LINUX")) {
		snprintf(sysinfo->os_dist, S_NAMELEN, "%s %s", line, sysname);
	} else {
		snprintf(sysinfo->os_dist, S_NAMELEN, "%s", line);
	}
#endif

	DBG("os dist: %s\n", sysinfo->os_dist);

	return 0;
}

static int get_os_release(sysinfo_t *sysinfo)
{
	if (access("/etc/neokylin-release", F_OK) == 0 &&
	    get_release_from_file("/etc/neokylin-release", sysinfo, NULL) == 0) {
		return 0;
	}

	if (access("/etc/system-release", F_OK) == 0 &&
	    get_release_from_file("/etc/system-release", sysinfo, NULL) == 0) {
		return 0;
	}

	if (access("/etc/centos-release", F_OK) == 0 &&
	    get_release_from_file("/etc/centos-release", sysinfo, NULL) == 0) {
		sysinfo->pkgmanage = PKGM_RPM;
		return 0;
	}

	if (access("/etc/redhat-release", F_OK) == 0 &&
	    get_release_from_file("/etc/redhat-release", sysinfo, NULL) == 0) {
		sysinfo->pkgmanage = PKGM_RPM;
		return 0;
	}

	if (access("/etc/lsb-release", F_OK) == 0 &&
	    get_release_from_file("/etc/lsb-release", sysinfo, "DISTRIB_DESCRIPTION=") == 0) {
		return 0;
	}

	if (access("/etc/os-release", F_OK) == 0 &&
	    get_release_from_file("/etc/os-release", sysinfo, "PRETTY_NAME=") == 0) {
		return 0;
	}

	return -1;
}

int get_mem_from_line(char *line, char *result)
{
	char memstr[16] = {0};
	int i, j, len;
	char *ptr = NULL;

	len = strlen(line);
	for (i = 0; i < len; i++) {
		if (line[i] >= '0' && line[i] <= '9')
			break;
	}

	/* 没取到数字 */
	if (i == len)
		return 0;

	/* 取连续的数字 */
	for (j = 0; i < len; i++, j++) {
		if (line[i] >= '0' && line[i] <= '9') {
			/* 值太大了，肯定是取到的信息不对 */
			if (j == 15)
				return 0;
			memstr[j] = line[i];
			continue;
		}

		break;
	}

	ptr = line + i;
	if (strchr(ptr, 'k') || strchr(ptr, 'K')) {
		if (j <= 3) {
			return 0;
		}
		strncpy(result, memstr, j-3);
		result[j-3] = 0;
		return 1;
	}
	if (strchr(ptr, 'm') || strchr(ptr, 'M')) {
		strncpy(result, memstr, j);
		result[j] = 0;
		return 1;
	}

	return 0;
}

void get_meminfo(sysinfo_t *sysinfo)
{
	FILE *fp;
        char line[S_LINELEN] = {0};

        fp = fopen("/proc/meminfo","r");
        if (fp == NULL) {
                MON_ERROR("open /proc/meminfo fail : %s\n", strerror(errno));
		return;
	}

	while (fgets(line, S_LINELEN, fp) != NULL) {
		if(strstr(line, "MemTotal")) {
			get_mem_from_line(line, sysinfo->memtotal);
			break;
		}
	}
	fclose(fp);
}

void get_sys_serial_number(sysinfo_t *sysinfo)
{
	int len = 0;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	fp = sniper_fopen("/etc/.kylin", "r", PROCESS_GET);
	if (fp) {
		while (fgets(line, S_LINELEN, fp)) {
			if (strncmp(line, "key=", 4) == 0) {
				len = strlen(line);
				if (line[len-1] == '\n') {
					line[len-1] = 0;
				}
				strncpy(sysinfo->os_sn, line+4, S_NAMELEN-1);
				break;
			}
		}
		sniper_fclose(fp, PROCESS_GET);
	}
	else {/* 获取系统序列号，与dmidecode -s system-serial-number内容一致 */
		fp = fopen("/sys/class/dmi/id/product_serial", "r");
		if (fp == NULL) {
			MON_ERROR("open /sys/class/dmi/id/product_serial fail : %s\n", strerror(errno));
		} else {
			if (fgets(line, S_LINELEN, fp)) {
				len = strlen(line);
				if (len > 0 && line[len-1] == '\n') {
					line[len-1] = 0;
					len--;
				}
				if (len >= S_NAMELEN) {
					len = S_NAMELEN-1;
				}
				strncpy(sysinfo->os_sn, line, len);
				sysinfo->os_sn[len] = '\0';
			}
			fclose(fp);
		}
	}

	if (sysinfo->os_sn[0] == 0) {
		strncpy(sysinfo->os_sn, "N/A", S_NAMELEN-1);
	}
}

#if 0
void sys_install_time(sysinfo_t *sysinfo)
{
        struct stat st = {0};

	if (stat(CS_INS_FILE1, &st) == 0 ||
	    stat(CS_INS_FILE2, &st) == 0 ||
	    stat(UB_INS_FILE, &st) == 0) {
		sysinfo->os_install_time = st.st_ctime;
		return;
	}

	/* 确实有可能3个文件都没有，有也不能排除没改动 */
	MON_ERROR("get os install time fail, stat %s, %s, %s error: %s\n",
		CS_INS_FILE1, CS_INS_FILE2, UB_INS_FILE, strerror(errno));	
}
#endif

time_t uptime_sec = 0;
/*
 * 取1号进程的启动时间作为系统启动时间
 *
 * 不能用算法：系统启动时间=系统当前时间-系统运行时长
 * 如果虚拟机曾经挂起过，由于系统运行时长不包括挂起时长，
 * 导致算出来的系统启动时间会比真实的系统启动时间要晚
 */
static void get_boot_time(void)
{
	char boottime[64] = {0}, nowtime[64] = {0};
	struct stat st = {0};

	if (stat("/proc/1", &st) < 0) {
		time_t now = time(NULL);

		ctime_r(&now, nowtime);    //1643376605 -> "Fri Jan 28 21:30:05 2022\n"
		nowtime[63] = 0;
		delete_tailspace(nowtime); //去掉尾部的换行符

		MON_ERROR("get_boot_time stat /proc/1 error: %s\n", strerror(errno));
		INFO("use now time %s(%d) as boot time\n", nowtime, now);

		uptime_sec = now;
		return;
	}

	uptime_sec = st.st_mtime;

	ctime_r(&uptime_sec, boottime);
	boottime[63] = 0;
	delete_tailspace(boottime);

	INFO("boot at %s(%d)\n", boottime, uptime_sec);
}

/* 取本次启动时间和上次关机时间 */
void sys_boot_time(sysinfo_t *sysinfo)
{
	struct utmp *u = NULL;
	char halttime[64] = {0};

	get_boot_time();
	sysinfo->boot_time = uptime_sec;

	//TODO 上次关机时间可能不准，比如突然死机，比如
	//halt -w / reboot -w不关机，只写wtmp
	//reboot -d不写wtmp

	/* 从文件头遍历到文件尾，最后取的值就是最新的 */
        utmpname("/var/log/wtmp");
        setutent();
        while ((u = getutent())) {
		if (u->ut_type == RUN_LVL && strcmp(u->ut_user, "shutdown") == 0) {
			sysinfo->last_shutdown_time = u->ut_tv.tv_sec;
                }
        }
        endutent();

	/* 关机时间没取到，再试试wtmp.1 */
	if (sysinfo->last_shutdown_time == 0 && access("/var/log/wtmp.1", F_OK) == 0) {
        	utmpname("/var/log/wtmp.1");
	        setutent();
	        while ((u = getutent())) {
			if (u->ut_type == RUN_LVL && strcmp(u->ut_user, "shutdown") == 0) {
				sysinfo->last_shutdown_time = u->ut_tv.tv_sec;
	                }
	        }
	        endutent();
	}

	if (sysinfo->last_shutdown_time == 0) {
		INFO("not get last shutdown time, use 1min before boot time\n");
		sysinfo->last_shutdown_time = sysinfo->boot_time - 60;
	} else if (sysinfo->last_shutdown_time > sysinfo->boot_time) {
		INFO("Warning: last shutdown time %d later than boot time %d, use 1min before boot time\n",
			sysinfo->last_shutdown_time, sysinfo->boot_time);
		sysinfo->last_shutdown_time = sysinfo->boot_time - 60;
	}

	ctime_r(&sysinfo->last_shutdown_time, halttime);
	halttime[63] = 0;
	delete_tailspace(halttime);
	INFO("last shutdown at %s(%d)\n", halttime, sysinfo->last_shutdown_time);
}

void sniper_addr2ip(struct sniper_ip *ip, unsigned char *addr)
{
	ip->ip[0] = addr[0];
	ip->ip[1] = addr[1];
	ip->ip[2] = addr[2];
	ip->ip[3] = addr[3];
}
int ethinfo_num = 0;
struct sniper_ethinfo *ethinfo = NULL;
struct sniper_ethinfo *get_current_ethinfo(int *num)
{
	int i = 0, j = 0, sockfd = 0, count = 0, size = 0, ethnum = 0;
	int numreqs = 30;
	struct ifconf ifc = {0};
	struct ifreq *ifr = NULL;
	struct sniper_ethinfo *info = NULL;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		MON_ERROR("check ip create socket failed!\n");
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
			MON_ERROR("get current ip fail, no memory\n");
			close(sockfd);
			return NULL;
		}

		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			MON_ERROR("get current ip fail, ioctl %s\n", strerror(errno));
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

	count = ifc.ifc_len / sizeof(struct ifreq);

	/* 算网卡数目 */
	ethnum = 0;
	ifr = ifc.ifc_req;
	for (i = 0; i < count; i++) {
		if (strcmp(ifr[i].ifr_name, "lo") == 0) {
			continue;
		}
		ethnum++;
	}

	/* 没有网卡 */
	if (ethnum == 0) {
		free(ifc.ifc_buf);
		close(sockfd);
		return NULL;
	}

	*num = ethnum;
	size = ethnum * sizeof(struct sniper_ethinfo);
	info = (struct sniper_ethinfo *)malloc(size);
	if (!info) {
		MON_ERROR("get current ip fail, no memory. "
			"eth device num: %d\n", ethnum);
		free(ifc.ifc_buf);
		close(sockfd);
		return NULL;
	}
	/* 清零，否则后面比较新老ethinfo时，虽然有效信息一致，但memcmp可能会认为不同 */
	memset(info, 0, size);

	/* 取网卡详细信息 */
	ifr = ifc.ifc_req;
	for (i = 0; i < count; i++) {
		struct ifreq hwifr = {{{0}}};
		struct ifreq maskifr = {{{0}}};
		struct sockaddr_in *sa = NULL;

		if (strcmp(ifr[i].ifr_name, "lo") == 0) {
			continue;
		}

		strncpy(info[j].name, ifr[i].ifr_name, IFNAMSIZ-1);

		sa = (struct sockaddr_in *)&ifr[i].ifr_addr;
		sniper_addr2ip(&info[j].ip, (unsigned char *)&sa->sin_addr);

		strncpy(hwifr.ifr_name, ifr[i].ifr_name, IFNAMSIZ-1);
		if (ioctl(sockfd, SIOCGIFHWADDR, &hwifr) < 0) {
			MON_ERROR("get %s mac error: %s\n", hwifr.ifr_name);
		} else {
			memcpy(info[j].mac, hwifr.ifr_hwaddr.sa_data, 6);
		}

		strncpy(maskifr.ifr_name, ifr[i].ifr_name, IFNAMSIZ-1);
		if (ioctl(sockfd, SIOCGIFNETMASK, &maskifr) < 0) {
			MON_ERROR("get %s netmask error: %s\n", maskifr.ifr_name);
		} else {
			sa = (struct sockaddr_in *)&maskifr.ifr_addr;
			sniper_addr2ip(&info[j].netmask, (unsigned char *)&sa->sin_addr);
		}

		DBG2(DBGFLAG_HEARTBEAT, "[%d] %s, %d.%d.%d.%d, %d.%d.%d.%d, %02X-%02X-%02X-%02X-%02X-%02X\n",
		     j, info[j].name, IPSTR(&info[j].ip), IPSTR(&info[j].netmask), MACSTR(info[j].mac));
		j++;
	}

	free(ifc.ifc_buf);
	close(sockfd);

	return info;
}

/* 从mtabfile里查找根文件系统的设备名，mtabfile可以是/etc/mtab和/proc/mounts */
static void get_rootdisk_devname(char devname[S_NAMELEN], char *mtabfile)
{
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0};
	char mountpoint[S_NAMELEN] = {0};

	if (!mtabfile || !devname) {
		return;
	}

	fp = fopen(mtabfile, "r");
	if (!fp) {
		MON_ERROR("get root disk device name fail, "
			"open %s error: %s\n", mtabfile, strerror(errno));
		devname[0] = 0;
		return;
	}

	while (fgets(buf, S_LINELEN, fp)) {
		devname[0] = 0;
		sscanf(buf, "%63s %63s %*s", devname, mountpoint);
		/*
		 * 可能同时存在两条记录，如centos7上看到
		 * rootfs / rootfs rw 0 0
		 * /dev/mapper/centos-root / xfs rw,relatime,attr2,inode64,noquota 0 0
		 * 忽略rootfs行
		 */
		if (strcmp(devname, "rootfs") == 0) {
			continue;
		}
		if (strcmp(mountpoint, "/") == 0) {
			break;
		}
	}
	fclose(fp);
}

/* 拷贝str到buf中，特殊字符delim不拷。最多拷buflen-1个字符到buf里 */
static void strncpy_nodelimiter(char *buf, char *str, char delim, int buflen)
{
	int i = 0, j = 0;

	while (str[i] != 0) {
		if (str[i] == delim) {
			i++;
			continue;
		}
		buf[j] = str[i];
		i++;
		j++;
		if (j == buflen-1) {
			break;
		}
	}
}

static int get_lvuuid(char *vgname, char *lvname, char serial[S_SNLEN+1])
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	FILE *fp = NULL;
	char *ptr = NULL;
	char buf[S_LINELEN] = {0};
	char path[S_SHORTPATHLEN] = {0};
	int len = strlen(vgname), found = 0;

	dirp = sniper_opendir("/etc/lvm/archive", INFO_GET);
	if (!dirp) {
		MON_ERROR("open /etc/lvm/archive error: %s\n", strerror(errno));
		return -1;
	}

	while ((ent = readdir(dirp))) {
		if (strncmp(ent->d_name, vgname, len) == 0) {
			found = 1;
			break;
		}
	}
	sniper_closedir(dirp, INFO_GET);

	if (!found) {
		INFO("no vg match %s in /etc/lvm/archive\n", vgname);
		return -1;
	}

	snprintf(path, S_SHORTPATHLEN, "/etc/lvm/archive/%s", ent->d_name);
	fp = sniper_fopen(path, "r", INFO_GET);
	if (!fp) {
		MON_ERROR("open %s error: %s\n", path, strerror(errno));
		return -1;
	}

	while (fgets(buf, S_LINELEN, fp)) {
		if (!strstr(buf, lvname)) {
			continue;
		}

		fgets(buf, S_LINELEN, fp);
		ptr = strstr(buf, "id = ");
		if (!ptr) {
			continue;
		}

		strncpy_nodelimiter(serial, ptr+6, '-', S_SNLEN+1);

		sniper_fclose(fp, INFO_GET);
		return 0;
	}
	sniper_fclose(fp, INFO_GET);
	return -1;
}

static char *get_lvname(char *name, char *lvname)
{
	char *str = name, *ptr = NULL;
	char pvpath[S_SHORTPATHLEN] = {0};

	/* 格式是vgname-lvname，考虑到vgname里可能含有-,
	   将-依次换成/，检查/dev下是否有vgname/lvname */
	while ((ptr = strchr(str, '-'))) {
		*ptr = '/';
		snprintf(pvpath, S_SHORTPATHLEN, "/dev/%s", name);
		if (access(pvpath, F_OK) == 0) {
			*ptr = 0;
			strncpy(lvname, ptr+1, S_NAMELEN-1);
			return lvname;
		}

		*ptr = '-';
		str = ptr + 1;
	}
	return NULL;
}

static int get_lvsn(char *devname, void *serial)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	char path[S_SHORTPATHLEN] = {0};
	char lvdevname[S_NAMELEN] = {0};
	char *name = safebasename(devname);
	char lvname[S_NAMELEN] = {0};
	char vgname[S_NAMELEN] = {0};

	dirp = sniper_opendir("/dev/mapper", INFO_GET);
	if (!dirp) {
		MON_ERROR("open /dev/mapper fail: %s\n", strerror(errno));
		return -1;
	}

	while ((ent = readdir(dirp))) {
		if (ent->d_name[0] == '.' ||
		    strcmp(ent->d_name, "control") == 0) {
			continue;
		}

		snprintf(path, S_SHORTPATHLEN, "/dev/mapper/%s", ent->d_name);
		if (readlink(path, lvdevname, S_NAMELEN-1) > 0 &&
		    strcmp(safebasename(lvdevname), name) == 0) {
			sniper_closedir(dirp, INFO_GET);
			if (!get_lvname(ent->d_name, lvname)) {
				return -1;
			}

			strncpy(vgname, ent->d_name, S_NAMELEN-1);
			/* 这里不能直接把ent->d_name作为get_lvuuid的参数，
			   因为get_lvuuid里也做了readdir，会冲掉ent的值 */
			return get_lvuuid(vgname, lvname, serial);
		}
	}

	sniper_closedir(dirp, INFO_GET);
	return -1;
}

static int get_serial(int fd, void *buf, size_t buf_len)
{
	unsigned char inq_cmd[] = {INQUIRY, 1, 0x80, 0, buf_len, 0};
	unsigned char sense[32];
	struct sg_io_hdr io_hdr;
 
	memset(&io_hdr, 0, sizeof(io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.cmdp = inq_cmd;
	io_hdr.cmd_len = sizeof(inq_cmd);
	io_hdr.dxferp = buf;
	io_hdr.dxfer_len = buf_len;
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.sbp = sense;
	io_hdr.mx_sb_len = sizeof(sense);
	io_hdr.timeout = 5000;
 
	return ioctl(fd, SG_IO, &io_hdr);
}
 
static void get_disksn(char *devname, char serial[S_SNLEN+1])
{
	unsigned char scsi_serial[S_LINELEN] = {0}; //>=255
	int fd = 0, i = 0, len = 0, rsp_len = 0, err = 0;
	char *dest = NULL;
	char *src = NULL;
	char *rsp_buf = NULL;
 
	fd = open(devname, O_RDONLY);
	if (fd < 0) {
		MON_ERROR("get %s sn fail, open it error: %s\n", devname, strerror(errno)); 
		return;
	}

	//TODO 物理机上lv uuid是否可以作为唯一标识，dd复制的系统是否能感知换盘了
	//lvm raid1是否可以dd后直接使用？lvm raid1是否可以拆开来装在2台机器上用？
	if (get_serial(fd, scsi_serial, S_LINELEN) < 0) {
		close(fd);
		err = errno;
		if (get_lvsn(devname, serial) < 0) {
			/* 取不到disk sn无妨，不报MON_ERROR */
			INFO("get %s sn fail, ioctl error: %s\n", devname, strerror(err)); 
			//INFO("try get %s sn as lvm, fail yet\n", devname); 
		}
		return;
	}
	close(fd);
 
	rsp_len = scsi_serial[3];
	if (!rsp_len) {
		if (get_lvsn(devname, serial) < 0) {
			INFO("not get %s sn, scsi_serial[3]: %d\n", devname, scsi_serial[3]);
			//INFO("try get %s sn as lvm, fail yet\n", devname); 
		}
		return;
	}
	rsp_buf = (char *) &scsi_serial[4];
 
	/* trim all whitespace and non-printable characters and convert
	 * ':' to ';'
	 */
	for (i = 0, dest = rsp_buf; i < rsp_len; i++) {
		src = &rsp_buf[i];
		if (*src > 0x20) {
			/* ':' is reserved for use in placeholder serial
			 * numbers for missing disks
			 */
			if (*src == ':')
				*dest++ = ';';
			else
				*dest++ = *src;
		}
	}
	len = dest - rsp_buf;
	dest = rsp_buf;
 
	/* truncate leading characters */
	if (len > S_SNLEN) {
		dest += len - S_SNLEN;
		len = S_SNLEN;
	}
 
	INFO("get_disksn %s, scsi_serial[3]: %d, serial [%s]\n", devname, scsi_serial[3], dest);
	strncpy_nodelimiter(serial, dest, '-', len+1);
}

/* 取字符startc和endc之间的字符串，并排除字符串首尾的空格符 */
static char *parse_blkid_string(char *buf, char startc, char endc)
{
	char *ptr1 = NULL, *ptr2 = NULL;

	ptr1 = strchr(buf, startc);
	if (!ptr1) {
		return NULL;
	}
	ptr1++;

	ptr2 = strchr(ptr1, endc);
	if (!ptr2) {
		return NULL;
	}
	*ptr2 = 0;

	delete_tailspace(ptr1);
	return skip_headspace(ptr1);
}

/*
 * 从blkid.tab中取设备uuid
 * 下面是一个blkid.tab文件的示例
 * <device DEVNO="0xfd00" TIME="1514979037.556702" UUID="46fb51f6-2210-4dd9-8c01-d0b7d3c8ae10" TYPE="ext4">/dev/mapper/VolGroup-lv_root</device>
 * <device DEVNO="0x0801" TIME="1567488987.650691" UUID="4ad77398-e295-49a1-bf89-d125745660c8" TYPE="ext4">/dev/sda1</device>
 */
static void get_blkid_uuid(char *devname, char rootfs_uuid[S_SNLEN+1])
{
	int usefirstdev = 0;
	char *dev = NULL, *uuid = NULL, *ptr = NULL;
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0};

	if (!rootfs_uuid) {
		return;
	}
	if (!devname || devname[0] == 0) {
		usefirstdev = 1; //如果没有设备名参数，则取第一个设备的uuid
	}

	/* 较老版本的blkid，如centos5的blkid 1.0用/etc/blkid/blkid.tab，后面用/run/blkid/blkid.tab */
	fp = fopen("/etc/blkid/blkid.tab", "r");
	if (!fp) {
		fp = fopen("/run/blkid/blkid.tab", "r");
		if (!fp) {
			return;
		}
	}

	while (fgets(buf, S_LINELEN, fp)) {
		dev = parse_blkid_string(buf, '>', '<');
		/* 有设备名参数，则设备名需匹配。否则用第一个设备的uuid */
		if (!usefirstdev) {
			if (!dev || strcmp(devname, dev) != 0) {
				continue;
			}
		}

		ptr = strstr(buf, "UUID");
		uuid = parse_blkid_string(ptr, '"', '"');
		if (!uuid) {
			continue;
		}

		strncpy_nodelimiter(rootfs_uuid, uuid, '-', S_NAMELEN+1);
		if (usefirstdev) {
			INFO("use %s uuid %s as rootfs uuid\n", dev ? dev : "", rootfs_uuid);
		}
		break;
	}
	fclose(fp);
}

#define DISKUUID_PATH "/dev/disk/by-uuid"
/*
 * 从/dev/disk/by-uuid目录里查根文件系统的uuid
 * 参数：输出devname，存放根盘设备名
 *       输出rootfs_uuid，存放根文件系统的uuid
 *       输入rootdev，根盘设备号
 * 一个例子：
 * # ls -l /dev/disk/by-uuid
 * lrwxrwxrwx 1 root root 10 Nov 13 04:22 41ce6cf0-3b57-4904-964f-d3d7bd3e0b4b -> ../../dm-0
 * lrwxrwxrwx 1 root root 10 Nov 13 04:22 a203b0f9-6ac7-4e0d-9630-53bdc1cde19f -> ../../sda1
 */
static void get_rootfs_uuid_bydiskuuid(char *devname, char rootfs_uuid[S_SNLEN+1], dev_t rootdev)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	char path[S_SHORTPATHLEN] = {0}, name[S_NAMELEN] = {0};
	char *ptr = NULL;

	dirp = sniper_opendir(DISKUUID_PATH, INFO_GET);
	if (!dirp) {
		if (errno != ENOENT) {
			INFO("get rootfs uuid fail, open DISKUUID_PATH error: %s\n", strerror(errno));
		}
		return;
	}

	while ((ent = readdir(dirp))) {
		struct stat devst = {0};

		if (ent->d_name[0] == '.') {
			continue;
		}

		snprintf(path, S_SHORTPATHLEN, "%s/%s", DISKUUID_PATH, ent->d_name);
		/* lstat读链接文件属性，stat读链接文件指向的目标文件属性 */
		if (stat(path, &devst) < 0) {
			INFO("get rootfs uuid: stat %s fail: %s\n", path, strerror(errno));
			continue;
		}
		if (devst.st_rdev != rootdev) {
			continue;
		}

		/* 设备号相同，找到根设备 */

		/* 将41ce6cf0-3b57-4904-964f-d3d7bd3e0b4b的-消除后，作为根文件系统uuid */
		strncpy_nodelimiter(rootfs_uuid, ent->d_name, '-', S_NAMELEN+1);

		/*
		 * 拷贝或修订设备名，例如
		 * 传入的devname为空，返回/dev/sda1或/dev/dm-0的形式
		 * 传入的devname是/dev/sda1，返回的也是/dev/sda1
		 * 传入的devname是lvm设备名/dev/mapper/system-root，返回/dev/dm-0的形式
		 */
		readlink(path, name, S_NAMELEN-1);
		ptr = safebasename(name);
		snprintf(devname, S_NAMELEN, "/dev/%s", ptr);

		break;
	}
	sniper_closedir(dirp, INFO_GET);
}

static void get_rootfs_uuid(char *devname, char rootfs_uuid[S_SNLEN+1])
{
	struct stat st = {0};

	/* 通过根目录获取根盘设备号st_dev，即根目录在哪个盘上，这个盘即为根盘 */
	if (stat("/", &st) < 0) {
		INFO("get rootfs uuid stat / error: %s\n", strerror(errno));
	} else {
		get_rootfs_uuid_bydiskuuid(devname, rootfs_uuid, st.st_dev);
		if (rootfs_uuid[0] != 0) {
			return;
		}
	}

	/* 有时候通过根目录获取的根盘设备号不对（在suse12.5上遇到过），则通过根盘设备名获取设备号 */
	get_rootdisk_devname(devname, "/etc/mtab");
	if (devname[0] == 0) {
		get_rootdisk_devname(devname, "/proc/mounts");
	}
	if (devname[0] != 0) {
		if (stat(devname, &st) < 0) {
			INFO("get rootfs uuid stat %s error: %s\n", devname, strerror(errno));
		} else {
			/* 通过根盘设备名获取设备号，则rdev表示根盘设备号 */
			get_rootfs_uuid_bydiskuuid(devname, rootfs_uuid, st.st_rdev);
			if (rootfs_uuid[0] != 0) {
				return;
			}
		}
	}

	/*
	 * 如果根盘是lvm设备，centos5不能用上面的方法找
	 * 其在/dev/disk/by-uuid/里只有物理盘，没有lvm盘
	 * 通过blkid来取
	 */
	system("blkid");
	get_blkid_uuid(devname, rootfs_uuid);

	if (rootfs_uuid[0] != 0) {
		return;
	}

	/* 前面取rootfs_uuid都失败了，设置一个假的。没有rootfs_uuid，sku太短，客户端注册会失败 */
	memcpy(rootfs_uuid, "123456abcdefghijklmnopqrstuvwxyz", S_SNLEN);
	rootfs_uuid[S_SNLEN] = 0;
}

/* sku优先用rootfs uuid + eth mac */
/* ZX20200730 银河麒麟的dmiuuid有可能是固定的，即所有机器都一样 */
static void build_sku(char sku[S_UUIDLEN+1])
{
	char *ptr = NULL, buf[S_UUIDLEN+1] = {0};

	/* rootfs uuid + eth mac */
	if (ethinfo_num > 0) {
		snprintf(buf, S_UUIDLEN+1, "%s%02x%02x%02x%02x%02x%02x",
			Sys_info.rootfs_uuid, MACSTR(ethinfo[0].mac));
	}

	/* 虚拟机用rootfs uuid + dmi uuid */
	else if (Sys_info.vmtype[0] && Sys_info.dmi_uuid[0]) {
		snprintf(buf, S_UUIDLEN+1, "%s%s",
			Sys_info.rootfs_uuid, Sys_info.dmi_uuid);
	}

	/* 物理机用rootfs uuid + disk sn */
	else if (Sys_info.disk_sn[0]) {
		snprintf(buf, S_UUIDLEN+1, "%s%s",
			Sys_info.rootfs_uuid, Sys_info.disk_sn);
	}

	/* 前面不行则用rootfs uuid + dmi uuid */
	else if (Sys_info.dmi_uuid[0]) {
		snprintf(buf, S_UUIDLEN+1, "%s%s",
			Sys_info.rootfs_uuid, Sys_info.dmi_uuid);
	}

	/* 构造sku失败，程序停止运行 */
	else {
		exit(1);
	}

	ptr = skip_headspace(buf);
	delete_tailspace(ptr);
	memset(sku, 0, S_UUIDLEN+1);
	strncpy(sku, ptr, S_UUIDLEN);
}

/* 检查是否为clone的系统，对于clone的系统应当rebuild sku，否则会和被clone的系统冲突 */
int check_sku_clone(char sku[S_UUIDLEN+1])
{
	/* rootfs的uuid不同，是克隆/拷贝的系统 */
	if (strncmp(sku, Sys_info.rootfs_uuid, S_SNLEN) != 0) {
		MON_ERROR("sku %s, rootfs uuid %s diff, rebuild sku\n",
			sku, Sys_info.rootfs_uuid);
		return 1;
	}

	/* 虚拟机的dmi_uuid不同，是克隆的系统 */
	if (Sys_info.vmtype[0]) {
		if (Sys_info.dmi_uuid[0]) {
			if (strncmp(sku+S_SNLEN, Sys_info.dmi_uuid, S_SNLEN) != 0) {
				MON_ERROR("sku %s, dmi uuid %s diff, rebuild sku\n",
					sku, Sys_info.dmi_uuid);
				return 1;
			}
			return 0;
		}
		return 0;
	}

	/* 物理机的disk_sn不同，是克隆的系统 */
	if (Sys_info.disk_sn[0]) {
		int len = strlen(Sys_info.disk_sn);
		if (strncmp(sku+S_SNLEN, Sys_info.disk_sn, len) != 0) {
			MON_ERROR("sku %s, disk sn %s diff, rebuild sku\n",
				sku, Sys_info.disk_sn);
			return 1;
		}
		return 0;
	}

	/* 其他情况可能是硬件环境变化了，不能百分百确定是clone，
	   冲突的时候删掉/etc/sniper-sku，重起sniepr */
	return 0;
}

static void save_sku(char sku[S_UUIDLEN+1])
{
	int fd = 0, ret = 0;

	/* 没有sku文件，则存一个 */
	fd = open(SKUFILE, O_WRONLY|O_CREAT, 0644);
	if (fd < 0) {
		INFO("create %s error: %s\n", SKUFILE, strerror(errno)); 
		return;
	}
	fchmod(fd, 0644); //防止umask屏蔽掉0044

	ret = write(fd, sku, S_UUIDLEN);
	close(fd);
	if (ret == S_UUIDLEN) {
		return;
	}

	INFO("write %s fail: %s. write %d < %d. delete %s\n",
		SKUFILE, strerror(errno), ret, S_UUIDLEN); 
	/* 写失败，删了，下次再重写 */
	unlink(SKUFILE);
}

/* 读老的sku，如果没有则算一个，并存下来 */
/*
 * ZX20200723
 * 在河南联通项目中遇到sku重复问题，两台克隆的机器，根盘是lvm卷，卷uuid和rootfs uuid都相同。
 * 因为sku的生成规则(优先用disk sn + rootfs uuid，但当disk是lvm时，sn实际取的是lvm uuid)，
 * 且启动时检查sku是否相符，不相符则重新生成sku，导致即使想手工处理sku也无法解决问题。
 *
 * 为此，将sku机制改为有sku则直接用，不检查sku是否相符。如果没有才生成sku，且优先用dmi uuid。
 * 这样能兼容已经部出去的系统
 *
 * 以后如果遇到sku重复的问题，首先找出/etc/sniper-sku的内容未包含当前dmi uuid的机器，
 * 删除其/etc/sniper-sku，再重启sniper，
 * 如还不能解决，则手工修改/etc/sniper-sku，再重启sniper
 *
 * 查看dmi uuid的方法是cat /sys/class/dmi/id/product_uuid，或dmidecode -s system-uuid
 */
void get_sku(char sku[S_UUIDLEN+1])
{
	int fd = 0, ret = 0, size = S_UUIDLEN;
	struct stat st = {0};

	fd = open(SKUFILE, O_RDONLY);
	if (fd < 0) {
		build_sku(sku);

		/*
		 * 文件存在，但打开失败，可能是磁盘故障或文件损坏，
		 * 简单地处理，临时算一个，不去管文件是不是损坏
		 */
		if (errno != ENOENT) {
			INFO("get_sku open %s error: %s. build sku temporarily\n",
				SKUFILE, strerror(errno));
			return;
		}

		save_sku(sku);
		return;
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		MON_ERROR("get_sku stat %s error: %s\n", SKUFILE, strerror(errno));
	} else if (st.st_mode != 0644 && fchmod(fd, 0644) < 0) {
		MON_ERROR("get_sku chmod %s error: %s\n", SKUFILE, strerror(errno));
	}

	if (st.st_size < 33) {
		size = 32;
	}
	ret = read(fd, sku, size);
	close(fd);

	if (ret == size) {
#if 0 //ZX20200723 不检查sku是否相符，详见本函数前的注释
		//检查sku是否相符，对于clone的盘或虚拟机自动调整sku
		if (check_sku_clone(sku)) {
			build_sku(sku);
			save_sku(sku);
		}
#endif
		return;
	}

	INFO("get_sku read from %s fail: %s. read %d < %d. build sku\n",
		SKUFILE, strerror(errno), ret, size); 

	build_sku(sku);
	save_sku(sku);
}

static void get_token(char token[TOKEN_LEN+1])
{
	FILE *fp = NULL;
	char buf[S_LINELEN]= {0};

	fp = fopen(TOKENFILE, "r");
	if (!fp) {
		return;
	}

	fgets(buf, S_LINELEN, fp);
	fclose(fp);

	/* 正确的文件里面包含32个字节的token数据和拼接的installtoken关键字 */
	if (strstr(buf, "installtoken") == NULL)  {
		return;
	}

	strncpy(token, buf, TOKEN_LEN);
	token[TOKEN_LEN] = '\0';
	return;
}

/* ipv6_addr长度为S_IPLEN */
static void get_ipv6_addr(char *ipv6_addr)
{
	char dname[IFNAMSIZ] = {0};
	char address[INET6_ADDRSTRLEN] = {0};
	unsigned char ipv6[16] = {0};
	char buf[S_LINELEN] = {0};
	FILE *fp = NULL;
	int ret = 0;
	int scope = 0;
	int prefix = 0;

	fp = fopen("/proc/net/if_inet6", "r");
	if (fp == NULL) {
		return;
	}

	while (fgets(buf, S_LINELEN, fp)) {
		ret = sscanf(buf, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %x %x %*x %s",
				&ipv6[0], &ipv6[1], &ipv6[2], &ipv6[3], &ipv6[4], &ipv6[5], &ipv6[6], &ipv6[7], &ipv6[8], &ipv6[9],
				&ipv6[10], &ipv6[11], &ipv6[12], &ipv6[13], &ipv6[14], &ipv6[15], &prefix, &scope, dname);
		if (ret != 19) {
			continue;
		}

		if (strcmp(dname, "lo") == 0) {
			continue;
		}

		if (inet_ntop(AF_INET6, ipv6, address, sizeof(address)) == NULL) {
			continue;
		}

		/* 此处先取第一个匹配的 */
		strncpy(ipv6_addr, address, S_IPLEN);
		ipv6_addr[S_IPLEN - 1] = '\0';
		break;
		
	}
	fclose(fp);

	return;
}

void init_systeminfo(sysinfo_t *sysinfo)
{
	struct utsname uts;
	int len = 0, i = 0;
	FILE *cpuinfo_fp;
        char line[S_LINELEN] = {0};
        char *cpuinfo;
	char devname[S_NAMELEN] = {0};

	/* hostname */
	gethostname(sysinfo->hostname, S_NAMELEN);

        /* get cpuinfo */
        cpuinfo_fp = fopen("/proc/cpuinfo","r");
        if (cpuinfo_fp == NULL) {
                MON_ERROR("open /proc/cpuinfo fail : %s\n", strerror(errno));
        } else {
                while (fgets(line, S_LINELEN, cpuinfo_fp) != NULL) {
                        if (strncmp(line, "model name", 10) == 0) {
                                cpuinfo = strstr(line, ":");
				strncpy(sysinfo->cpu_model, cpuinfo+2, S_NAMELEN-1);
                        }
                        if (strncmp(line, "processor", 9) == 0) {
                                cpuinfo = strstr(line, ":");
				sysinfo->cpu_count = atoi(cpuinfo+2);
                        }
                        if (strncmp(line, "physical id", 11) == 0) {
                                cpuinfo = strstr(line, ":");
				sysinfo->core_count = atoi(cpuinfo+2);
                        }
                }
                fclose(cpuinfo_fp);
		sysinfo->cpu_count++;
		if (sysinfo->core_count == 0) {
			sysinfo->core_count = sysinfo->cpu_count;
		}
		len = strlen(sysinfo->cpu_model);
		if (sysinfo->cpu_model[len-1] == '\n') {
			sysinfo->cpu_model[len-1] = 0;
		}
        }

	get_meminfo(sysinfo);

        strncpy(sysinfo->version, SNIPER_VERSION, 16);

	/* get kernel info. uname也可以取domainname */
	uname(&uts);
	strncpy(sysname, uts.sysname, 16);
	strncpy(sysinfo->os_arch, uts.machine, 16);
	strncpy(sysinfo->os_kernel, uts.release, S_NAMELEN-1);

	/* get package management */
	if (access("/usr/bin/dpkg", X_OK) == 0) {
		sysinfo->pkgmanage = PKGM_DPKG;
	} else {
		sysinfo->pkgmanage = PKGM_RPM;
	}
	/* get os_release */
        get_os_release(sysinfo);

	INFO("distribution: %s, kernel: %s, sniper_ver: %s\n",
	     sysinfo->os_dist, sysinfo->os_kernel, sysinfo->version);
	INFO("package management is %s\n",
		sysinfo->pkgmanage == PKGM_DPKG ? "dpkg" : "rpm");

	get_machine_model(sysinfo->machine_model, sysinfo->vmtype,
		sysinfo->dmi_sn, sysinfo->dmi_uuid, 0);
	INFO("machine model: %s, %s\n", sysinfo->machine_model,
		sysinfo->vmtype[0] ? sysinfo->vmtype : "Physical Machine");
	INFO("machine sn: %s, uuid: %s\n",
		sysinfo->dmi_sn, sysinfo->dmi_uuid);

	/* get system network interface , skip lo */
	pthread_rwlock_init(&ethinfo_lock, 0);

	ethinfo_num = 0;
	ethinfo = get_current_ethinfo(&ethinfo_num);
	if (ethinfo) {
		for (i = 0; i < ethinfo_num; i++) {
			INFO("[%d] %s, %d.%d.%d.%d, %02X-%02X-%02X-%02X-%02X-%02X\n",
				i, ethinfo[i].name, IPSTR(&ethinfo[i].ip), MACSTR(ethinfo[i].mac));
		}
		snprintf(If_info.mac, S_IPLEN, "%02X-%02X-%02X-%02X-%02X-%02X", MACSTR(ethinfo[0].mac));
		snprintf(If_info.ip, S_IPLEN, "%d.%d.%d.%d", IPSTR(&ethinfo[0].ip));
		INFO("my work ip %s, mac %s\n", If_info.ip, If_info.mac);
	}

	get_ipv6_addr(If_info.ipv6);
//	printf("If_info.ipv6:%s\n", If_info.ipv6);

#if 0
	/* 后面用早的软件安装时间作为系统安装时间 */
	/* get system install time */
	sys_install_time(sysinfo);
#endif

	/* get system boot/shutdown time */
	sys_boot_time(sysinfo);

	get_rootfs_uuid(devname, sysinfo->rootfs_uuid);
	if (sysinfo->vmtype[0] == 0 && devname[0]) {
		if (strncmp(devname, "/dev/mapper/", 12) == 0) {
			char *ptr = NULL;
			char lvname[S_NAMELEN] = {0};
			char vgname[S_NAMELEN] = {0};

			strncpy(vgname, devname+12, S_NAMELEN-1);
			ptr = strchr(vgname, '-');
			if (ptr) {
				*ptr = 0;
				strncpy(lvname, ptr+1, S_NAMELEN-1);
				get_lvuuid(vgname, lvname, sysinfo->disk_sn);
			}
		} else { /* /dev/sda1, /dev/dm-0, ... */
			get_disksn(devname, sysinfo->disk_sn);
		}
	}

	if (sysinfo->disk_sn[0]) {
		INFO("rootdisk: %s, disk sn: %s, rootfs uuid: %s\n",
		     devname, sysinfo->disk_sn, sysinfo->rootfs_uuid);
	} else {
		INFO("rootdisk: %s, rootfs uuid: %s\n", devname, sysinfo->rootfs_uuid);
	}

	get_sku(sysinfo->sku);
	get_token(sysinfo->token);
	INFO("sku: %s\n", sysinfo->sku);
}
