#include <sys/types.h>
#include <linux/fd.h>
#include <sys/mount.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <scsi/scsi_ioctl.h>
#include <linux/kdev_t.h>
#include <linux/major.h>

#include "header.h"

struct _usb_packed{
        int capacity;
        short warn_reported;
        short disabled;
        char name[S_NAMELEN];
        char uuid[S_UUIDLEN];
        char model[S_NAMELEN];
        char vendor[S_NAMELEN];
        char type[S_NAMELEN];
        char partition[S_NAMELEN];
        char path[PATH_MAX];
        char format[S_NAMELEN];
        char user[S_NAMELEN];
};

int old_unum = 0;
struct _usb_packed old_usb[USB_MAX];
int mount_num = 0;
struct _mount_info mount_info[USB_MAX];

static void read_first_line(char *path, char *buf, int buflen)
{
	FILE *fp = NULL;
	char *ptr = NULL;
	int i = 0;

	if (!path || !buf) {
		return;
	}

	fp = fopen(path, "r");
	if (!fp) {
		return;
	}

	if (fgets(buf, buflen-1, fp) == NULL) {
		fclose(fp);
		return;
	}
	fclose(fp);

	delete_tailspace(buf);           //截断尾部的空格符，包括回车换行

	ptr = skip_headspace(buf);
	if (ptr == buf) { //头部没有空格符
		return;
	}

	/* 将头部空格符之后的内容前移 */
	while (*ptr != 0) {
		buf[i] = *ptr;
		i++;
		ptr++;
	}
	buf[i] = 0;
}

/*
 * 遍历/dev/disk/by-id目录取设备的序列号
 * 返回-1，没找到设备，认为不是usb设备     //TODO 有其他的方式用设备名作参数来检测是否u盘吗
 * 返回0，没取到序列号
 * 返回1，取到了序列号
 */
static int get_usb_uuid(char *name, struct _usb_packed *packed) 
{
	int len = 0;
	char path[PATH_MAX] = {0}, realpath[PATH_MAX] = {0};
	char *ptr = NULL, *uuid = NULL;
	DIR *dirp = NULL;
	struct dirent *ent = NULL;

	if (!name || !packed) {
		return -1;
	}

	/* suse11.4上可能没有/dev/disk/by-id目录，但挂载u盘后会出现此目录 */
	dirp = opendir("/dev/disk/by-id");
	if (dirp == NULL) {
		return -1;
	}

	packed->uuid[0] = '-';
	packed->uuid[1] = 0;

	len = sizeof(path);
	while ((ent = readdir(dirp)) != NULL) {
		DBG2(DBGFLAG_USBDEBUG, "/dev/disk/by-id: %s\n", ent->d_name);

		/* 只考察u盘设备 */
		if (strncmp(ent->d_name, "usb-", 4) != 0 || strstr(ent->d_name, "-part")) {
			continue;
		}

		snprintf(path, len, "/dev/disk/by-id/%s", ent->d_name);
		if (readlink(path, realpath, len-1) <= 0) {  //未取到链接内容
			continue;
		}
		DBG2(DBGFLAG_USBDEBUG, "/dev/disk/by-id: %s -> %s\n", ent->d_name, realpath);

		ptr = strrchr(realpath, '/');
		if (!ptr || strcmp(ptr+1, name) != 0) { //链接指向的非目标u盘
			continue;
		}

		closedir(dirp);

		ptr = strrchr(ent->d_name, '_');
		if (!ptr) {                                  //未取到序列号
			return 0;
		}

		uuid = ptr + 1;

		/* 去除usb磁盘尾部的-0:0，如usb-Generic_Flash_Disk_BAF80BF4-0:0 */
		ptr = strchr(uuid, '-');
		if (ptr) {
			*ptr = 0;
		}

		/* 处理usb-USB_Flash_Disk-0:0，长度不够的uuid视为非法uuid */
		if (strlen(uuid) > 4) {
			strncpy(packed->uuid, uuid, S_UUIDLEN-1);
			packed->uuid[S_UUIDLEN - 1] = 0;
			return 1;
		}
		return 0;
	}

	closedir(dirp);
	return -1;      //未找到设备，视其为非u盘
}

/* 取u盘挂载的分区、挂载点目录、文件系统格式。如果u盘有多个分区并挂载，取第一个挂载的目录 */
static void get_usb_mntpath(char *name, struct _usb_packed *packed)
{
	char line[S_LINELEN] = {0};
	char dev_path[S_NAMELEN] = {0};
	char mnt_path[S_LINELEN] = {0};
	char format[S_NAMELEN] = {0};
	FILE *fp = NULL;
	int ret = 0, len = 0, match = 0;
	char *ptr = NULL;
	struct stat st = {0};

	if (!name || !packed) {
		return;
	}
	packed->partition[0] = '-';
	packed->partition[1] = 0;
	packed->path[0] = '-';
	packed->path[1] = 0;
	packed->format[0] = '-';
	packed->format[1] = 0;
	strncpy(packed->user, "root", sizeof(packed->user)-1);

	fp = fopen(MOUNT_PATH, "r");
	if (fp == NULL) {
		MON_ERROR("open %s failed: %s\n", MOUNT_PATH, strerror(errno));
		return;
	}

	len = strlen(name);

	while (fgets(line, sizeof(line), fp) != NULL) {
		ptr = skip_headspace(line);
		delete_tailspace(ptr);

		if (*ptr == '#' || *ptr == 0) {
			continue;
		}

		if (strncmp(ptr, "/dev/", 5) == 0 && strncmp(ptr+5, name, len) == 0) {
			/* S_LINELEN 512, S_NAMELEN 64 */
			ret = sscanf(ptr, "%63s %511s %63s", dev_path, mnt_path, format);
			if (ret == 3) {
				match = 1;
				break;
			}
		}
	}
	fclose(fp);

	if (match) {
		strncpy(packed->partition, dev_path, sizeof(packed->partition)-1);
		strncpy(packed->path, mnt_path, sizeof(packed->path)-1);
		strncpy(packed->format, format, sizeof(packed->format)-1);

		if (stat(packed->path, &st) == 0) {
			uidtoname(st.st_uid, packed->user);
		}
	}
}

/*
 * ZX20211216
 * 之前是通过遍历/sys/class/scsi_device目录来获取u盘，
 * 换成遍历/sys/block目录来获取u盘，代码更容易理解
 */
static void get_usb_info(struct _usb_packed *packed, int *unum)
{
        DIR *dir = NULL;
        struct dirent *dent = NULL;
	int count = 0;
	char path[PATH_MAX] = {0};
	char buf[S_LINELEN] = {0};
	char *name = NULL;
	struct _usb_packed *usbinfo = NULL;

	DBG2(DBGFLAG_USB, "get_usb_info\n");
	if (!packed || !unum) {
		return;
	}

	dir = opendir("/sys/block");
	if (dir == NULL) {
		DBG2(DBGFLAG_USB, "open dir /sys/block fail : %s\n", strerror(errno));
		*unum = 0;
		return;
	}
		
	while ((dent = readdir(dir)) != NULL) {
		DBG2(DBGFLAG_USBDEBUG, "/sys/block : %s\n", dent->d_name);

		if (strncmp(dent->d_name, "sd", 2) != 0) {
			continue;
		}
		name = dent->d_name;
		usbinfo = &packed[count];

		/* 取u盘序列号 */
		if (get_usb_uuid(name, usbinfo) < 0) { //不是u盘
			continue;
		}
		strncpy(usbinfo->name, name, sizeof(usbinfo->name)-1);

		/* 取u盘厂商 */
		usbinfo->vendor[0] = '-';
		usbinfo->vendor[1] = 0;
		snprintf(path, sizeof(path), "/sys/block/%s/device/vendor", name);
		read_first_line(path, usbinfo->vendor, sizeof(usbinfo->vendor));
		/* 修正厂商，忽略一看就不是厂商名的 */
		if (strcmp(usbinfo->vendor, "USB") == 0 ||
		    strncasecmp(usbinfo->vendor, "Generic", 7) == 0) {
			usbinfo->vendor[0] = '-';
			usbinfo->vendor[1] = 0;
		}

		/* 取u盘型号 */
		usbinfo->model[0] = '-';
		usbinfo->model[1] = 0;
		snprintf(path, sizeof(path), "/sys/block/%s/device/model", name);
		read_first_line(path, usbinfo->model, sizeof(usbinfo->model));

		/* 取u盘大小 */
		memset(buf, 0, sizeof(buf));
		snprintf(path, sizeof(path), "/sys/block/%s/size", name);
		read_first_line(path, buf, sizeof(buf));
		if (buf[0] == 0 || strcmp(buf, "0") == 0) {
			usbinfo->capacity = 0;
		} else {
			/* /sys/block/DEV/size的单位是512字节。硬盘的KB按1000算 */
			usbinfo->capacity = atol(buf)*512/(1000*1000*1000);  //转成GB;
		}

		/* 取u盘类型：U盘或移动硬盘。有观察到U盘的removable值是1，移动硬盘是0 */
		memset(buf, 0, sizeof(buf));
		snprintf(path, sizeof(path), "/sys/block/%s/removable", name);
		read_first_line(path, buf, sizeof(buf));
		if (buf[0] == '1') {
			strcpy(usbinfo->type, "USB");
		} else {
			strcpy(usbinfo->type, "MHD");
		}

		/* 取u盘安装路径 */
		get_usb_mntpath(name, usbinfo);

		DBG2(DBGFLAG_USB, "%d: %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %d\n", count,
			usbinfo->name, usbinfo->uuid, usbinfo->model, usbinfo->vendor, usbinfo->type,
			usbinfo->partition, usbinfo->path, usbinfo->format, usbinfo->user,
			usbinfo->capacity, usbinfo->warn_reported);
		count++;
		if (count == USB_MAX) { //u盘数量太多，超过预想的最大数量。几乎不可能发生
			break;
		}
	}
	*unum = count;

        closedir(dir);
}

static void terminate_usb_post_data(struct _usb_packed *info, int ejected)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	int result = 0, terminate = 0, defence_result = 0;
	bool event = true;
	unsigned long event_time = 0;
	struct timeval tv = {0};
	struct defence_msg defmsg = {0};

	if (!info) {
		return;
	}

	/* 运维和学习模式下不重复报告非法u盘日志 */
	if (client_mode_global != NORMAL_MODE && info->warn_reported) {
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
		
	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		cJSON_Delete(object);
		cJSON_Delete(arguments);
		return;
	}

	info->warn_reported = 1;

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec+serv_timeoff)*1000 + (int)tv.tv_usec/1000;

	if (client_mode_global == OPERATION_MODE) {
		terminate = MY_HANDLE_WARNING;
		event = false;
		result = MY_RESULT_OK;
	} else if (client_mode_global == LEARNING_MODE) {
		terminate = MY_HANDLE_WARNING;
		event = true;
		result = MY_RESULT_OK;
	} else if (ejected) {
		terminate = MY_HANDLE_BLOCK_OK;
		event = true;
		result = MY_RESULT_OK;
		defence_result = MY_RESULT_OK;
	} else {
		terminate = MY_HANDLE_BLOCK_FAIL;
		event = true;
		result = MY_RESULT_FAIL;
		defence_result = MY_RESULT_FAIL;
	}

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "IllegalUSBStorage");
	cJSON_AddStringToObject(object, "log_category", "USBStorage");
	  cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", "Fasten");
	cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_VIOLATION);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "In");
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", info->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "process_uuid", "");
	cJSON_AddStringToObject(arguments, "process_name", "");
	cJSON_AddNumberToObject(arguments, "process_id", 0);
	cJSON_AddNumberToObject(arguments, "thread_id", 1);
	cJSON_AddStringToObject(arguments, "process_path", "");
	cJSON_AddStringToObject(arguments, "process_commandline", "");
	cJSON_AddStringToObject(arguments, "md5", "");
	cJSON_AddStringToObject(arguments, "device_model", info->model);
	cJSON_AddStringToObject(arguments, "device_name",  info->name);
	cJSON_AddStringToObject(arguments, "device_type",  info->type);
	cJSON_AddStringToObject(arguments, "device_uuid",  info->uuid);
	cJSON_AddStringToObject(arguments, "device_vendor",info->vendor);
	cJSON_AddStringToObject(arguments, "mount_partition", info->partition);
	cJSON_AddStringToObject(arguments, "mount_path", info->path);
	cJSON_AddStringToObject(arguments, "mount_partition_format", info->format);
	cJSON_AddNumberToObject(arguments, "capacity", info->capacity);

	cJSON_AddItemToObject(object, "arguments", arguments);
	post = cJSON_PrintUnformatted(object);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "uevent");
	
	DBG2(DBGFLAG_USB, "terminate usb event post:%s\n", post);
	cJSON_Delete(object);
	free(post);

	if (terminate <= MY_HANDLE_WARNING) {
		return; //未做阻断，不报防御日志
	}

	defmsg.event_tv.tv_sec = 0;
	defmsg.operation = termstr;
	defmsg.result = defence_result;

	defmsg.user = info->user;
	defmsg.log_name = "IllegalUSBStorage";
	defmsg.log_id = uuid;
	defmsg.object = info->uuid;
	
	send_defence_msg(&defmsg, "uevent");
}

static void post_usb_data(struct _usb_packed *info, char *operating)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	struct timeval tv = {0};

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

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec+serv_timeoff) *1000 + (int)tv.tv_usec/1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "USBStorage");
	cJSON_AddStringToObject(object, "log_category", "USBStorage");
	  cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", MY_LOG_KEY);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_NO);
	cJSON_AddNumberToObject(object, "result", MY_RESULT_OK);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_NO);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", info->user);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	/* 不需要报告进程信息，没有关联的进程 */
	cJSON_AddStringToObject(arguments, "process_uuid", "");
	cJSON_AddStringToObject(arguments, "process_name", "");
	cJSON_AddNumberToObject(arguments, "process_id", 0);
	cJSON_AddNumberToObject(arguments, "thread_id", 1);
	cJSON_AddStringToObject(arguments, "process_path", "");
	cJSON_AddStringToObject(arguments, "process_commandline", "");
	cJSON_AddStringToObject(arguments, "md5", "");

	cJSON_AddStringToObject(arguments, "device_model", info->model);
	cJSON_AddStringToObject(arguments, "device_name",  info->name);
	cJSON_AddStringToObject(arguments, "device_type",  info->type);
	cJSON_AddStringToObject(arguments, "device_uuid",  info->uuid);
	cJSON_AddStringToObject(arguments, "device_vendor",info->vendor);
	cJSON_AddStringToObject(arguments, "mount_partition", info->partition);
	cJSON_AddStringToObject(arguments, "mount_path", info->path);
	cJSON_AddStringToObject(arguments, "mount_partition_format", info->format);
	cJSON_AddNumberToObject(arguments, "capacity", info->capacity);

	cJSON_AddItemToObject(object, "arguments", arguments);
	post = cJSON_PrintUnformatted(object);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "uevent");
	
	DBG2(DBGFLAG_USB, "usb event post:%s, reply:%s\n", post, reply);
	cJSON_Delete(object);
	free(post);
}

int eject_usb(char *device) 
{
	int fd = 0;
	int status, k;
	sg_io_hdr_t io_hdr;
	unsigned char allowRmBlk[6] = {ALLOW_MEDIUM_REMOVAL, 0, 0, 0, 0, 0};
	unsigned char startStop1Blk[6] = {START_STOP, 0, 0, 0, 1, 0};
	unsigned char startStop2Blk[6] = {START_STOP, 0, 0, 0, 2, 0};
	unsigned char inqBuff[2];
	unsigned char sense_buffer[32];

	if ((fd = open(device, O_RDONLY|O_NONBLOCK)) < 0) {
		MON_ERROR("eject %s fail, open device error: %s\n", device, strerror(errno));
		return -1;
	}

	if ((ioctl(fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
		MON_ERROR("eject %s fail, not an sg device, or old sg driver\n", device);
		close(fd);
		return -1;
	}

	memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = 6;
	io_hdr.mx_sb_len = sizeof(sense_buffer);
	io_hdr.dxfer_direction = SG_DXFER_NONE;
	io_hdr.dxfer_len = 0;
	io_hdr.dxferp = inqBuff;
	io_hdr.sbp = sense_buffer;
	io_hdr.timeout = 10000;
	io_hdr.cmdp = allowRmBlk;

	status = ioctl(fd, SG_IO, (void *)&io_hdr);
	if (status < 0) {
		MON_ERROR("eject %s fail, allowRmBlk error: %s\n", device, strerror(errno));
		close(fd);
		return -1;
	}

	io_hdr.cmdp = startStop1Blk;
	status = ioctl(fd, SG_IO, (void *)&io_hdr);
	if (status < 0) {
		MON_ERROR("eject %s fail, startStop1Blk error: %s\n", device, strerror(errno));
		close(fd);
		return -1;
	}

	io_hdr.cmdp = startStop2Blk;
	status = ioctl(fd, SG_IO, (void *)&io_hdr);
	if (status < 0) {
		MON_ERROR("eject %s fail, startStop2Blk error: %s\n", device, strerror(errno));
		close(fd);
		return -1;
	}

	/* force kernel to reread partition table when new disc inserted */
	status = ioctl(fd, BLKRRPART);
	close(fd);
	return 0;
}

static void disable_usb(struct _usb_packed *info) 
{
	int ejected = 0;
	char device[S_PATHLEN] = {0};

	if (client_mode_global == NORMAL_MODE) {
		snprintf(device, S_PATHLEN, "/dev/%s", info->name);
		if (eject_usb(device) == 0) {
			ejected = 1;
			info->disabled = 1;
		}
	}

	if (info->partition[0] == '-') {
		return;
	}

	terminate_usb_post_data(info, ejected);
}

static void sync_usbinfo(struct _usb_packed *info1, struct _usb_packed *info2)
{
	if (!info1 || !info2) {
		return;
	}

	if (info1->path[0] == 0 && info2->path[0] != 0) {
		strncpy(info1->path, info2->path, sizeof(info1->path)-1);
		strncpy(info1->user, info2->user, sizeof(info1->user)-1);
		strncpy(info1->partition, info2->partition, sizeof(info1->partition)-1);
		strncpy(info1->format, info2->format, sizeof(info1->format)-1);
		info1->capacity = info2->capacity;
		return;
	}

	if (info2->path[0] == 0 && info1->path[0] != 0) {
		strncpy(info2->path, info1->path, sizeof(info2->path)-1);
		strncpy(info2->user, info1->user, sizeof(info2->user)-1);
		strncpy(info2->partition, info1->partition, sizeof(info2->partition)-1);
		strncpy(info2->format, info1->format, sizeof(info2->format)-1);
		info2->capacity = info1->capacity;
		return;
	}
}

int check_usb_exist(char *uuid)
{
	DIR *dir = NULL;
	struct dirent *dent = NULL;

	dir = opendir("/dev/disk/by-id");
	if (dir == NULL) {
		DBG2(DBGFLAG_USB, "open /dev/disk/by-id fail : %s\n", strerror(errno));
		return 1;
	}

	while ((dent = readdir(dir)) != NULL) {
		if (strstr(dent->d_name, uuid)) {
			closedir(dir);
			return 1;
		}
	}

	closedir(dir);
	return 0;
}

void check_usb_info(int init)
{
	int unum = 0, i = 0, j = 0, found = 0, terminate = 0, count = 0;
	struct _usb_packed new_usb[USB_MAX] = {{0}};
	char *uuid = NULL;

	get_usb_info(new_usb, &unum);

	/* 初始化时，或监控开关关闭时，仅更新u盘信息 */
	if (init || fasten_policy_global.device.usb.enable == 0) {
		old_unum = unum;
		memcpy(&old_usb, &new_usb, sizeof(struct _usb_packed)*USB_MAX);
		return;
	}

	DBG2(DBGFLAG_USBDEBUG, "check usb out\n");
	/* 检查拔出 */
	for (i = 0; i < old_unum; i++) {
		found = 0;
		for (j = 0; j < unum; j++) {
			DBG2(DBGFLAG_USBDEBUG, "old[%d] %s, new[%d] %s\n", i, old_usb[i].name, j, new_usb[j].name);
			if (strcmp(old_usb[i].name, new_usb[j].name) == 0) {
				found = 1;
				/* 保留已经报过警的标志 */
				new_usb[j].warn_reported = old_usb[i].warn_reported;
				new_usb[j].disabled = old_usb[i].disabled;
				/* 之前或本次取的信息可能有缺失，如挂载目录，通过同步尝试补齐 */
				sync_usbinfo(&new_usb[j], &old_usb[i]);
				break;
			}
		}

		/* 在新的u盘信息中没有找到，这是拔出的u盘 */
		/* 不宜用j == unum来判断未找到，在unum为0时有漏报 */
		if (!found) {
			post_usb_data(&old_usb[i], "Out");
		}
	}

	DBG2(DBGFLAG_USBDEBUG, "check usb in\n");
	/* 检查插入 */
	for (i = 0; i < unum; i++) {
		found = 0;
		for (j = 0; j < old_unum; j++) {
			DBG2(DBGFLAG_USBDEBUG, "new[%d] %s, old[%d] %s\n", i, new_usb[i].name, j, old_usb[j].name);
			if (strcmp(new_usb[i].name, old_usb[j].name) == 0) {
				found = 1;
				/* 保留已经报过警的标志 */
				new_usb[i].warn_reported = old_usb[j].warn_reported;
				new_usb[i].disabled = old_usb[j].disabled;
				/* 之前或本次取的信息可能有缺失，如挂载目录，通过同步尝试补齐 */
				sync_usbinfo(&new_usb[i], &old_usb[j]);
				break;
			}
		}

		/* 在老的u盘信息中没有找到，这是新插入的u盘 */
		if (!found) {
			post_usb_data(&new_usb[i], "In");
		}
	}

	/* 检查是否禁用当前的u盘 */
	pthread_rwlock_rdlock(&fasten_policy_global.lock);

	terminate = fasten_policy_global.device.usb.terminate;
	count = fasten_policy_global.device.usb.exclude_num;

	for (i = 0; i < unum; i++) {
		int flag = 0;
		flag = check_usb_exist(new_usb[i].uuid);
		if (new_usb[i].disabled && !flag) { //避免重复禁用
			continue;
		}

		found = 0;
		if (terminate) { //禁用u盘
			for (j = 0; j < count; j++) {
				uuid = fasten_policy_global.device.usb.exclude[j].list;
				if (strcmp(new_usb[i].uuid, uuid) == 0) { //是例外允许的u盘
					found = 1;
					break;
				}
			}
			if (!found) { //不是例外允许的u盘
				disable_usb(&new_usb[i]);
			}
		} else {         //允许u盘
			for (j = 0; j < count; j++) {
				uuid = fasten_policy_global.device.usb.exclude[j].list;
				if (strcmp(new_usb[i].uuid, uuid) == 0) { //是例外要禁止的u盘
					disable_usb(&new_usb[i]);
					break;
				}
			}
		}
	}

	pthread_rwlock_unlock(&fasten_policy_global.lock);

	old_unum = unum;
	memcpy(&old_usb, &new_usb, sizeof(struct _usb_packed)*USB_MAX);

	get_mount_info();
}

//TODO 检查挂载卸载情况
/* 获取当前u盘的设备号信息, 更新到内核 */
void get_mount_info(void)
{
	DIR *dir = NULL;
	struct dirent *dent = NULL;
	int num = 0, len = 0, size = 0;
	struct _mount_info mount_new[USB_MAX] = {{0}};
	char path[S_PATHLEN] = {0}, realpath[PATH_MAX] = {0};
	char *ptr = NULL;
	struct stat st = {0};

	dir = opendir("/dev/disk/by-id");
	if (dir == NULL) {
		DBG2(DBGFLAG_USB, "open /dev/disk/by-id fail : %s\n", strerror(errno));
		return;
	}

	len = sizeof(realpath);
	while ((dent = readdir(dir)) != NULL) {
		/* 只考察u盘设备 */
		if (strncmp(dent->d_name, "usb-", 4) != 0 || strstr(dent->d_name, "part")) {
			continue;
		}

		snprintf(path, S_PATHLEN, "/dev/disk/by-id/%s", dent->d_name);
		memset(realpath, 0, len);
		if (readlink(path, realpath, len-1) <= 0) {  //未取到链接内容
			continue;
		}

		ptr = strrchr(realpath, '/');
		if (!ptr) {
			continue;
		}

		snprintf(path, S_PATHLEN, "/dev/%s", ptr+1);
		if (stat(path, &st) == 0) {
			mount_new[num].major = MAJOR(st.st_rdev);
			mount_new[num].minor = MINOR(st.st_rdev);;
			num++;

			if (num == USB_MAX) { //u盘数量太多，超过预想的最大数量。几乎不可能发生
				break;
			}
		}
	}
	closedir(dir);

	size = sizeof(struct _mount_info) * USB_MAX;
	if (num == mount_num && memcmp(&mount_new, &mount_info, size) == 0) {
		return; //u盘信息没变化，不用更新内核中的u盘信息
	}

	mount_num = num;
	memcpy(&mount_info, &mount_new, size);

	DBG2(DBGFLAG_USB, "当前挂载的usb设备号数量:%d\n", mount_num);
	/* 发送文件防护策略, 涉及usb挂载路径变更 */
	update_kernel_file_policy();
}
