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

/* netlink */
#include <sys/socket.h>
#include <linux/netlink.h>

#include "header.h"

extern int cwdmod;

int init_module(void *module_image, unsigned long len, const char *param_values);
int delete_module(const char *name, int flags);


#ifdef SMALL_MEMORY_MODE
/*
 * ZX20200812
 * 706项目要求sniper占用内存小于15MB，这里调用insmod命令来加载sniper_edr.ko，能减少点内存占用
 * 另，在28所遇到过init_module() core的情况，可能是安全上阻止了init_module()，此时可改用下面的实现
 */
int load_module(void)
{
       char modfile[128] = {0};
       char failinfo[S_LINELEN] = {0};
       char insmod_cmd[256] = {0};
 
       if (cwdmod) {
               snprintf(modfile, sizeof(modfile), "./%s", MODULE_FILE_NAME);
       } else {
               snprintf(modfile, sizeof(modfile),
                        "/lib/modules/%s/kernel/kernel/%s",
                        Sys_info.os_kernel, MODULE_FILE_NAME);
       }
       snprintf(insmod_cmd, sizeof(insmod_cmd), "insmod %s", modfile);
 
       errno = 0;
 
       system(insmod_cmd);
 
       if (check_module(MODULE_NAME) == 0) {
               if (errno == ENOEXEC) {
                       snprintf(failinfo, sizeof(failinfo),
                               //"Load module fail. mismatch between %s and kernel\n",
                               "load module fail. 模块%s版本与内核版本不匹配\n",
                               MODULE_NAME);
               } else {
                       snprintf(failinfo, sizeof(failinfo),
                               "load module fail. %s\n", strerror(errno));
               }
               //MON_ERROR(failinfo);
               save_sniper_status(failinfo);
               return -1;
       }
 
       //printf("load module %s %s\n", modfile, param);
 
       return 0;
}
#else
/*
 * load kernel module and tell kernel we're running now.
 * return 0 if successful, -1 if failed.
 */
int load_module(void)
{
	int fd = 0;
	char *module = NULL;
	char modfile[128] = {0};
	char param[S_LINELEN] = {0};
	char failinfo[S_LINELEN] = {0};
	struct stat st = {0};

	if (cwdmod) {
		snprintf(modfile, sizeof(modfile), "./%s", MODULE_FILE_NAME);
	} else {
		snprintf(modfile, sizeof(modfile),
			 "/lib/modules/%s/kernel/kernel/%s",
			 Sys_info.os_kernel, MODULE_FILE_NAME);
	}

	errno = 0;

	/* let's call init_module */
	if ((fd = open(modfile, O_RDONLY)) < 0) {
		if (errno == ENOENT) {
			snprintf(failinfo, sizeof(failinfo),
				//"load module fail. no %s\n", modfile);
				"load module fail. 没有模块文件%s\n", modfile);
		} else {
			snprintf(failinfo, sizeof(failinfo),
				//"load module fail. open %s error: %s\n",
				"load module fail. 打开模块文件%s错误: %s\n",
				modfile, strerror(errno));
		}
		//MON_ERROR(failinfo);
		save_sniper_status(failinfo);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		snprintf(failinfo, sizeof(failinfo),
			//"load module fail. get %s size error: %s\n",
			"load module fail. 取模块文件%s属性错误: %s\n",
			modfile, strerror(errno));
		//MON_ERROR(failinfo);
		save_sniper_status(failinfo);
		close(fd);
		return -1;
	}

	module = malloc(st.st_size);
	if (!module){
		snprintf(failinfo, sizeof(failinfo),
			//"load module fail. No Memory\n");
			"load module fail. 内存耗尽\n");
		//MON_ERROR(failinfo);
		save_sniper_status(failinfo);
		close(fd);
		return -1;
	}

	if (read(fd, module, st.st_size) < 0) {
		snprintf(failinfo, sizeof(failinfo),
			//"Load module fail. read %s error: %s\n",
			"load module fail. 读模块文件%s错误: %s\n",
			modfile, strerror(errno));
		//MON_ERROR(failinfo);
		save_sniper_status(failinfo);
		close(fd);
		free(module);
		return -1;
	}

	if (init_module(module, st.st_size, param) < 0) {
		if (errno == ENOEXEC) {
			snprintf(failinfo, sizeof(failinfo),
				//"Load module fail. mismatch between %s and kernel\n",
				"load module fail. 模块%s版本与内核版本不匹配\n",
				MODULE_NAME);
		} else {
			snprintf(failinfo, sizeof(failinfo),
				"load module fail. %s\n", strerror(errno));
		}
		//MON_ERROR(failinfo);
		save_sniper_status(failinfo);
		close(fd);
		free(module);
		return -1;
	}

	free(module);
	close(fd);

	//printf("load module %s %s\n", modfile, param);

	return 0;
}
#endif

int register_module(void)
{
	struct nlmsghdr *nlh = NULL;
	int ret = 0;

        nlh = (struct nlmsghdr *)malloc(NLMSGLEN);
        if (!nlh) {
                MON_ERROR("register_module: no memory\n");
                return -1;
        }

	ret = init_engine(NLMSG_REG, nlh);
	if (ret < 0) {
		MON_ERROR("register_module fail\n");
	}

	free(nlh);
	return ret;
}

void unregister_module(void)
{
	struct nlmsghdr *nlh = NULL;

        nlh = (struct nlmsghdr *)malloc(NLMSGLEN);
        if (!nlh) {
                MON_ERROR("unregister_module: no memory\n");
                return;
        }

	fini_engine(NLMSG_REG, nlh);

	free(nlh);
}

/*
 * delete kernel module 
 * return 0 if successful, -1 if failed.
 */
int del_module(char *module_name)
{
	int i;

	for (i = 0; i < 15; i++) {
		if (!check_module(module_name)) {
			return 0;
		}
		if (delete_module(module_name, O_NONBLOCK | O_TRUNC) < 0) {
			if (errno == ENOENT) {
				return 0;
			}
			if (errno == EAGAIN) {
				sleep(1);
				continue;
			}

			MON_ERROR("unload module %s fail : %s\n",
				  module_name, strerror(errno));
			return -1;
		}
		return 0;
	}

	return -1;
}
