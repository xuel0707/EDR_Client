#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#include "../cJSON.h"
#include "sys_info.h"

int disknum = 0;

/*
 * 硬盘类型：
 * hd: IDE硬盘
 * sd：SCSI/STAT/SAS硬盘/SSD
 * vd: kvm虚拟机的virtio虚拟磁盘，主设备号是253
 * nvme: NVME SSD
 */
static int is_harddisk(char *name, int minor)
{
	if (!name) {
		return 0;
	}

	if (strncmp(name, "sd", 2) == 0 || strncmp(name, "vd", 2) == 0) {
		/* sd和vd盘设备的次设备号是16的倍数，如sda 0, sdb 16, sdc 32,
		   分区设备剩下的次设备号，如sda1 1, sdb1 17, sdc1 33 */
		if ((minor % 16) != 0) {
			return 0;
		}
		return 1;
	}

	if (strncmp(name, "hd", 2) == 0) {
		/* hd盘设备的次设备号是64的倍数，如hda 0, hdb 64, hdc 128,
		   分区设备剩下的次设备号，如hda1 1, hdb1 65, hdc1 127 */
		if ((minor % 64) != 0) {
			return 0;
		}
		return 1;

		/* IDE光驱设备名也用hd，做get_disk_uuid()时排除光驱设备 */
	}

	if (strncmp(name, "nvme", 4) == 0) {
		/* nvme设备的次设备号没有规律，因此根据设备名来判断，带p的表示分区 */
		if (strchr(name, 'p')) {
			return 0;
		}
		return 1;
	}

	return 0;
}

static int is_disk_uuid_type(char *str)
{
	/* 忽略分区，如ata-ST1000DM010-2EP102_ZN1GGF59-part1 -> ../../sda1，只考察整块盘 */
	if (!str || strstr(str, "-part")) {
		return 0;
	}

	/*
	 * ata-ST1000DM010-2EP102_ZN1GGF59 -> ../../sda
	 * usb-Kingston_DataTraveler_3.0_E0D55EA574E9E491E8810207-0:0 -> ../../sdb
	 * wwn-0x600605b00f2ae3c0291a180514c95c40 -> ../../sdm
	 */
	if (strstr(str, "ata-") || strstr(str, "usb-") || strstr(str, "wwn-")) {
		return 1;
	}

	/* 处理nvme-KXG60ZNV256G_NVMe_TOSHIBA_256GB_Z8AA8153KZZP -> ../../nvme0n1
	   排除nvme-eui.00000000000000018ce38e030003168f -> ../../nvme0n1 */
	if (strstr(str, "nvme-") && !strstr(str, "eui")) {
		return 1;
	}

	return 0;
}

static int disk_model_to_vendor(char *model, char *vendor)
{
	if (!model || !vendor) {
		return 0;
	}

	if (strncmp(model, "ST", 2) == 0) {
        	strncpy(vendor, "Seagate", 63);
		return 1;
	}

	if (strncmp(model, "WD", 2) == 0) {
        	strncpy(vendor, "Western Digital", 63);
		return 1;
	}

	if (strncmp(model, "DT", 2) == 0 || strncmp(model, "KXG", 3) == 0) {
        	strncpy(vendor, "TOSHIBA", 63);
		return 1;
	}

	if (model[0] == 'S') {
        	strncpy(vendor, "SAMSUNG", 63);
		return 1;
	}

	if (model[0] == 'H' || strncmp(model, "IC", 2) == 0) {
        	strncpy(vendor, "HITACHI", 63);
		return 1;
	}

	return 0;
}

#define IS_CDROM 2
/* 返回-1，取序列号出错；返回0，没取到序列号；返回1，取到序列号；返回2，是光驱设备 */
/* 结果应和lsblk --nodeps -no serial /dev/xxx一致 */
static int get_disk_uuid(char *disk_name, char *disk_uuid, int uuid_len)
{
	int ret = -1, len = 0;
	char path[PATH_MAX] = {0}, realpath[PATH_MAX] = {0};
	char *ptr = NULL, *uuid = NULL;
	DIR *dirp = NULL;
	struct dirent *ent = NULL;

	if (!disk_name || !disk_uuid) {
		return -1;
	}

	dirp = opendir("/dev/disk/by-id");
	if (dirp == NULL) {
		return -1;
	}

	len = sizeof(path);
	while ((ent = readdir(dirp)) != NULL) {
		if (!is_disk_uuid_type((char *)ent->d_name)) {
			continue;
		}

		snprintf(path, len, "/dev/disk/by-id/%s", ent->d_name);
		if (readlink(path, realpath, len-1) <= 0) {  //未取到链接内容
			continue;
		}

		ptr = strrchr(realpath, '/');
		if (!ptr || strcmp(ptr+1, disk_name) != 0) { //链接指向的非目标磁盘
			continue;
		}

		if (strstr(ent->d_name, "DVD") || strstr(ent->d_name, "CDROM")) {
			closedir(dirp);
			return IS_CDROM;
		}

	 	/* wwn-0x600605b00f2ae3c0291a180514c95c40去掉wwn-0x */
		if (strncmp(ent->d_name, "wwn-", 4) == 0) {
			uuid = ent->d_name + 4;
			if (*uuid == '0' && (*(uuid+1) == 'x' || *(uuid+1) == 'X')) {
				uuid += 2;
			}
			snprintf(disk_uuid, uuid_len, "%s", uuid);
			closedir(dirp);
			return 1;
		}

		ptr = strrchr(ent->d_name, '_');
		if (!ptr) {                                  //未取到序列号
			continue;
		}

		uuid = ptr + 1;

		/* 去除usb磁盘尾部的-0:0，如usb-Generic_Flash_Disk_BAF80BF4-0:0 */
		ptr = strchr(uuid, '-');
		if (ptr) {
			*ptr = 0;
		}

		/* 处理usb-USB_Flash_Disk-0:0，长度不够的uuid视为非法uuid */
		if (strlen(uuid) > 4) {
			snprintf(disk_uuid, uuid_len, "%s", uuid);
			closedir(dirp);
			return 1;
		}
        }

	closedir(dirp);
	return 0;
}

/* 对于大小为0的磁盘，在型号尾部附加"介质不可用"的提示信息 */
static char mymodel[64] = {0};
static char *model_padding(char *model, unsigned long size)
{
	int len = sizeof(mymodel);

	memset(mymodel, 0, len);
	if (size == 0) {
		snprintf(mymodel, len, "%s (medium unavailable)", model);
	} else {
		snprintf(mymodel, len, "%s", model);
	}

	return mymodel;
}
/* 获取一个磁盘设备的信息，name磁盘设备名，object存放磁盘设备信息 */
static int get_disk_info(char *name, cJSON *object)
{
	int is_hdd = 0;
	char path[128] = {0};
	char disk_vendor[64] = {0};
	char disk_model[64] = {0};
	char disk_type[64] = {0};
	char disk_size[64] = {0};
	char disk_uuid[64] = {0}; 
	char *ptr = NULL;
	unsigned long size = 0;
	double size_g = 0.0;

	if (!name || !object) {
		return 0;
	}

	/* 取硬盘厂商 */
	snprintf(path, sizeof(path), "/sys/block/%s/device/vendor", name);
	if (return_file_first_line(path, disk_vendor, sizeof(disk_vendor)) < 0) {
		/* /sys/block/DEV和/sys/class/block/DEV都是链接，指向同一个对象，这里保险起见，失败时再尝试一次 */
		snprintf(path, sizeof(path), "/sys/class/block/%s/device/vendor", name);
		return_file_first_line(path, disk_vendor, sizeof(disk_vendor));
        }

	/* 取硬盘型号 */
	snprintf(path, sizeof(path), "/sys/block/%s/device/model", name);
	if (return_file_first_line(path, disk_model, sizeof(disk_model)) < 0) {
		snprintf(path, sizeof(path), "/sys/class/block/%s/device/model", name);
		return_file_first_line(path, disk_model, sizeof(disk_model));
        }

	/* 取硬盘大小 */
	snprintf(path, sizeof(path), "/sys/block/%s/size", name);
	if (return_file_first_line(path, disk_size, sizeof(disk_size)) < 0) {
		snprintf(path, sizeof(path), "/sys/class/block/%s/size", name);
		return_file_first_line(path, disk_size, sizeof(disk_size));
        }
	if (disk_size[0] == 0 || strcmp(disk_size, "0") == 0) { //大小为0的磁盘是不可用的磁盘
		size = 0;
		snprintf(disk_size, sizeof(disk_size), "0");
	} else {
		/* /sys/block/DEV/size的单位是512字节。硬盘的KB按1000算 */
		size = atol(disk_size);
		size_g = (double)size*512/(1000*1000*1000);  //转成GB
		snprintf(disk_size, sizeof(disk_size), "%.2f", size_g);
	}

	/* 取硬盘序列号，忽略光驱设备 */
	if (get_disk_uuid(name, disk_uuid, sizeof(disk_uuid)) == IS_CDROM) {
		return 0;
	}
	if (disk_uuid[0] == 0 || strcmp(disk_uuid, "None") == 0) {
		snprintf(disk_uuid, sizeof(disk_uuid), "C4e6f6e65P%d", disknum);
		disknum++;
	}

	/* 取硬盘类型，没有/sys/block/DEV/queue/rotational视为HDD，如centos5 */
	snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", name);
	if (return_file_first_line(path, disk_type, sizeof(disk_type)) < 0) {
		snprintf(path, sizeof(path), "/sys/class/block/%s/queue/rotational", name);
		if (return_file_first_line(path, disk_type, sizeof(disk_type)) < 0) {
			is_hdd = 1;
		}
	}
	if (is_hdd || disk_type[0] == '1') {
		snprintf(disk_type, sizeof(disk_type), "%s", "HDD");
	} else if (disk_type[0] == '0') {
		snprintf(disk_type, sizeof(disk_type), "%s", "SSD");
	}

	/* 不统计磁盘的已用可见和可用空间，概念有歧义，且实现麻烦。看分区的已用空间和可用空间即可 */
	cJSON_AddStringToObject(object, "used_size", "-");
	cJSON_AddStringToObject(object, "free_size", "-");

	/* 上传未修正过的型号和厂商，用于出错时回溯 */
	cJSON_AddStringToObject(object, "raw_disk_model", disk_model);
	cJSON_AddStringToObject(object, "raw_vendor", disk_vendor);

	cJSON_AddStringToObject(object, "disk_name", name);
	cJSON_AddStringToObject(object, "serial_id", disk_uuid);
	cJSON_AddStringToObject(object, "disk_type", disk_type);
	cJSON_AddStringToObject(object, "total_size", disk_size);

	/* 修正虚拟磁盘的型号和厂商 */
	if (strstr(disk_model, "VMware") != NULL || strstr(disk_model, "Virtual") != NULL) {
		cJSON_AddStringToObject(object, "disk_model", model_padding("Virtual Disk", size));
		cJSON_AddStringToObject(object, "vendor", sys_vendor);
		return 1;
	}

	/* 修正硬盘和nvme ssd设备的型号和厂商
	   硬盘的厂商可能是ATA，nvme的厂商可能是空 */
	if (strcasecmp(disk_vendor, "ATA") == 0 || disk_vendor[0] == 0) {
		if (disk_model_to_vendor(disk_model, disk_vendor)) {
			/* 处理型号是KXG60ZNV256G NVMe TOSHIBA 256GB的情况 */
			ptr = strchr(disk_model, ' ');
			if (ptr) {
				*ptr = 0;
			}
			cJSON_AddStringToObject(object, "disk_model", model_padding(disk_model, size));
			cJSON_AddStringToObject(object, "vendor", disk_vendor);
			return 1;
		}

		/* 处理型号是TOSHIBA DT01ACA2情况 */
		ptr = strchr(disk_model, ' ');
		if (ptr && disk_model_to_vendor(ptr+1, disk_vendor)) {
			char *model = ptr+1;
			ptr = strchr(model, ' ');
			if (ptr) {
				*ptr = 0;
			}
			cJSON_AddStringToObject(object, "disk_model", model_padding(model, size));
			cJSON_AddStringToObject(object, "vendor", disk_vendor);
			return 1;
		}

		cJSON_AddStringToObject(object, "disk_model", model_padding(disk_model, size));
		cJSON_AddStringToObject(object, "vendor", "-");
		return 1;
	}

	cJSON_AddStringToObject(object, "disk_model", model_padding(disk_model, size));

	/* 修正u盘厂商 */
	if (strcasecmp(disk_vendor, "USB") == 0 || strncasecmp(disk_vendor, "Generic", 7) == 0) {
		cJSON_AddStringToObject(object, "vendor", "-");
	} else {
		cJSON_AddStringToObject(object, "vendor", disk_vendor);
	}

	return 1;
}

static int get_disk_from_sys_block(cJSON *disk_info)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	cJSON *object = NULL;

	if (!disk_info) {
		return -1;
	}

	dirp = opendir("/sys/block");
	if (dirp == NULL) {
		return -1;
	}

	/* /sys/block下都是磁盘设备，/sys/class/block下是磁盘设备和磁盘分区设备 */
	while ((ent = readdir(dirp)) != NULL) {
		if (strncmp(ent->d_name, "hd", 2) != 0 &&
		    strncmp(ent->d_name, "sd", 2) != 0 &&
		    strncmp(ent->d_name, "vd", 2) != 0 &&
		    strncmp(ent->d_name, "nvme", 4) != 0) {
			continue;
		}

		object = cJSON_CreateObject();
		if (object) {
			if (get_disk_info(ent->d_name, object)) {
				cJSON_AddStringToObject(object, "method", "sys_block"); //记录实现方法
				cJSON_AddItemToArray(disk_info, object);
			} else {
				cJSON_Delete(object);
			}
		}
	}

	closedir(dirp);
	return 0;
}

static void get_disk_from_proc_partition(cJSON *disk_info)
{
	char line[256] = {0}, name[64] = {0};
	FILE *fp = NULL;
	int major = 0, minor = 0;
	unsigned long size = 0;
	cJSON *object = NULL;

	if (!disk_info) {
		return;
	}

	fp = fopen("/proc/partitions", "r");
	if (fp == NULL) {
		elog("open /proc/partitions failed!\n");
		return;
	}

	while ((fgets(line, sizeof(line), fp)) != NULL) {
		if (sscanf(line, "%d %d %lu %63s", &major, &minor, &size, name) != 4) {
			continue;
		}

		if (!is_harddisk(name, minor)) {
			continue;
		}

		object = cJSON_CreateObject();
		if (object) {
			if (get_disk_info(name, object)) {
				cJSON_AddStringToObject(object, "method", "proc_partitions"); //记录实现方法
				cJSON_AddItemToArray(disk_info, object);
			} else {
				cJSON_Delete(object);
			}
		}
	}

	fclose(fp);
}

void get_disks_info(cJSON *disk_info)
{
	/*
	 * /proc/partition里的设备可能不全，如ubuntu16.04.6上，插入的u盘没有。
	 * partition里未列出的原因，可能是磁盘无法使用，如识别到不支持的u盘
	 * 为了完备性，也免得费口舌解释，比如用户插了一个u盘说咋没看到
	 * 还是从/sys/block目录下取磁盘设备，这个方法失败，才从/proc/partition里取
	 */
	if (get_disk_from_sys_block(disk_info) < 0) {
		get_disk_from_proc_partition(disk_info);
	}

#if 0 //调试
	if (disk_info) {
		char *str = cJSON_PrintUnformatted(disk_info);
		printf("disk_info: %s\n", str);
		free(str);
	}
#endif
}
