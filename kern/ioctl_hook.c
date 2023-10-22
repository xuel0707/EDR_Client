/* 禁止非法刻录 */
#include "interface.h"
#include <scsi/sg.h>

static int is_cdrom_device(struct inode *inode)
{
	int major = 0;

	/* 不是块设备或字符设备 */
	if (!S_ISBLK(inode->i_mode) && !S_ISCHR(inode->i_mode)) {
		return 0;
	}

	/*
	 * 设备的组id是否为cdrom，识别下面/dev/sg2这样的情况
	 * ls -l /dev | grep cdrom
	 * lrwxrwxrwx  1 root       root           3 Nov 16 10:36 cdrom -> sr0
	 * crw-rw----+ 1 root       cdrom    21,   2 Nov 16 10:36 sg2
	 * brw-rw----+ 1 root       cdrom    11,   0 Nov 16 10:36 sr0
	 * sg2的主设备号是21(SCSI_GENERIC_MAJOR)
	 */
	if (sniper_cdrom_gid) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
		if (inode->i_gid == sniper_cdrom_gid)
#else
		if (inode->i_gid.val == sniper_cdrom_gid)
#endif
			return 1;
	}

	major = MAJOR(inode->i_rdev);
	if (major == SCSI_CDROM_MAJOR || major == MITSUMI_X_CDROM_MAJOR ||
	    (major >= CDU31A_CDROM_MAJOR && major <= SANYO_CDROM_MAJOR) ||
	    (major >= MITSUMI_CDROM_MAJOR && major <= AZTECH_CDROM_MAJOR) ||
	    major == CM206_CDROM_MAJOR) {
		return 1;
	}
	return 0;
}

static int my_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = NULL;
	struct sg_io_hdr hdr;

	/*
	 * sniper程序运行起来总会设置nl_file_pid，退出前复位，所以为0表示停止监控
	 * sniper_file_loadoff表示负载过高，禁止文件类监控
	 */
	if (nl_file_pid == 0 || sniper_file_loadoff) {
		return 0;
	}

	/* 只处理禁止刻录的情况 */
	if (!sniper_fpolicy.cdrom_on || !sniper_fpolicy.cdrom_terminate) {
		return 0;
	}

	/* 刻盘的ioctl命令是SG_IO */
	if (cmd != SG_IO || arg == 0 || IS_ERR_VALUE(arg)) {
		return 0;
	}

	if (sniper_badptr(file) || sniper_badptr(file->f_dentry)) {
		return 0;
	}
	inode = file->f_dentry->d_inode;
	if (sniper_badptr(inode)) {
		return 0;
	}

	if (!is_cdrom_device(inode)) {
		return 0;
	}

	/* 获取ioctl真正要做的scsi命令信息 */
	if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr))) {
		return 0; //拷数据失败
	}
	/* 不需要传数据，或只是从设备读数据，说明不是刻盘 */
	if (hdr.dxfer_direction == SG_DXFER_NONE || hdr.dxfer_direction == SG_DXFER_FROM_DEV) {
		return 0;
	}

	report_illegal_burning();

	if (client_mode == NORMAL_MODE) {
		return -1;
	}

	return 0; //运维或学习模式不阻断
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_IOCTL]);

	ret = my_file_ioctl(file, cmd, arg);
	if (ret < 0) {
        	atomic_dec(&sniper_usage[SNIPER_IOCTL]);
		return ret;
	}

	if (original_file_ioctl) {
		ret = original_file_ioctl(file, cmd, arg);
	}

        atomic_dec(&sniper_usage[SNIPER_IOCTL]);

	return ret;
}
#else
int sniper_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

        atomic_inc(&sniper_usage[SNIPER_IOCTL]);

	ret = my_file_ioctl(file, cmd, arg);

        atomic_dec(&sniper_usage[SNIPER_IOCTL]);

	return ret;
}
#endif
