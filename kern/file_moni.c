#include "interface.h"

/* 存放勒索进程 */
int next_encidx = 0;
struct _encrypt_info encrypt_info[ENC_CACHE_NUM] = {{{0}}};

int global_terminate = 0;

/* 过滤不需要监控的临时文件。返回1，不监控；0，监控 */
int skip_file(const char *filename)
{
	char *suffix = NULL;

	if (sniper_badptr(filename)) {
		return 1; //没有文件名，或文件名异常的不监控
	}

	/* 忽略vim产生的临时文件 */
	if (strcmp(current->comm, "vim") == 0 || strcmp(current->comm, "vi") == 0) {
		/* .viminfo或.viminf*.tmp */
		if (strncmp(filename, ".viminf", 7) == 0) {
			return 1;
		}
		/* vi通过创建名为4913的临时文件，来检测目录是否可写 */
		if (strcmp(filename, "4913") == 0) {
			return 1;
		}

		suffix = strrchr(filename, '.');
		if (suffix) {
			/* .xxxx.sw* */
			if (filename[0] == '.' && strncmp(suffix, ".sw", 3) == 0) {
				return 1;
			}


/* 此处不能屏蔽此类临时文件，vim操作文件会被过滤掉, 放到check_vim_change中处理 */
#if 0
			/* xxxx~ */
			len = strlen(suffix);
			if (suffix[len-1] == '~') {
				return 1;
			}
#endif
		}
	}

	/*
	 * bash有三种输入重定向：<，<<，<<<
	 * <<称为here-documents，<<<称为here-strings
	 * 这两种重定向方式会产生临时文件/tmp/sh-thd-168841984或/tmp/sh-thd.EkN7Sr
	 * 命令ls -l /proc/self/fd <<< 'TEST'可以演示此临时文件
	 */
	if (strncmp(filename, "/tmp/sh-thd", 11) == 0) {
			return 1;
	}

	return 0;
}

/* 检查是不是vi操作调用的rename, 将file变为file~。返回1，是；0，不是 */
int check_vim_change(char *oldfile, char*newfile)
{

	int oldlen = 0;
	int newlen = 0;

	if (sniper_badptr(oldfile) || sniper_badptr(newfile)) {
		return 0; //没有文件名，或文件名异常的不监控
	}

	oldlen = strlen(oldfile);
	newlen = strlen(newfile);

	/* 暂时只检测vi和vim */
	if (strcmp(current->comm, "vim") == 0 || strcmp(current->comm, "vi") == 0) {

		/* 要考虑没有后缀名的文件 */
		if (newlen == oldlen + 1 &&
		   strncmp(oldfile, newfile, oldlen) == 0 &&
		   newfile[newlen-1] == '~') {
			return 1;
		}
	}

	return 0;
}

/*
 * 对部分目录不做检测,
 * 不同的文件监控功能适用于不同的目录
 * 完善后再调用
 */
int skip_dir(char *filename)
{
	if (filename == NULL) {
		return 0;
	}

	/* u盘自动挂载会默认挂载在/run/media/下, 这个路径不过滤 */
	if (strncmp(filename, "/run/media/", 11) == 0) {
		return 0;
	}

	/* 根据实际需要添加删除*/
	if (strncmp(filename, "/run/", 5) == 0 ||
	    strncmp(filename, "/var/", 5) == 0) {
		return 1;
	}

	return 0;
}

/* 对部分系统进程不做检测 */
int skip_process(char *process)
{
	char *cmd = NULL;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	char *hostname = NULL, *nodename = NULL;
#endif

	if (process == NULL) {
		return 0;
	}
	cmd = safebasename(process);

	/* 屏蔽系统自身类进程，减少日志 */
	if (strcmp(cmd, "rsyslogd") == 0 ||
	    strcmp(cmd, "anacron") == 0 ||
	    strcmp(cmd, "dhclient") == 0 ||
	    strcmp(cmd, "chronyd") == 0 ||
	    strcmp(cmd, "gsd-color") == 0 ||
	    strcmp(cmd, "gvfsd-metadata") == 0 ||
	    strcmp(cmd, "dconf-service") == 0 ||
	    strcmp(cmd, "gnome-shell") == 0 ||
	    strcmp(cmd, "systemd") == 0 ||
	    strcmp(cmd, "systemd-logind") == 0 ||
	    strcmp(cmd, "systemd-journald") == 0 ||
	    strcmp(cmd, "systemd-udevd") == 0) {
		return 1;
	}

	/* 屏蔽防病毒程序 */
	if (strcmp(cmd, "sniper_antivirus") == 0) {
		return 1;
	}

#if 0
	/*
	 * xftp5的进程路径为/usr/libexec/openssh/sftp-server,
	 * 上传文件在此处会被过滤，
	 * 先不对/usr/libexec/下的进程操作过滤
	 */

	/*
	 * 此目录为用户运行库目录，
	 * 屏蔽此目录下的进程有一定风险, 可能造成漏报，
	 * 先做屏蔽处理，后面再通过其他方式过滤
	 */
	if (strncmp(process, "/usr/libexec/", 13) == 0) {
		return 1;
	}
#endif

	/*
	 * 过滤系统logrotate进程操作备份日志的行为
	 * 观察是否对其他功能造成影响，单独过滤
	 */
	if (strcmp(cmd, "logrotate") == 0) {
		return 1;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	/* 对docker里的文件操作过滤 */
	hostname = init_utsname()->nodename;
	nodename = utsname()->nodename;
	if (strcmp(nodename, hostname) != 0) {
		return 1;
	}
#endif
	return 0;
}

/* 检测勒索进程缓存中是否已存在此进程 */
int check_encrypt_cache(char *process, char *md5)
{
	int i = 0, match = 0;

	for (i = 0; i < ENC_CACHE_NUM; i++) {
		if (strcmp(process, encrypt_info[i].encrypt_cmd) != 0) {
			continue;
		}

		match = 1;
		break;
	}

	return match;
}

/* 在勒索缓存中添加此勒索进程路径和md5 */
void add_encrypt_record(char *process, char *md5)
{
	if (!process || !md5) {
		return;
	}

	snprintf(encrypt_info[next_encidx].md5,\
			sizeof(encrypt_info[next_encidx].md5), "%s", md5);
	snprintf(encrypt_info[next_encidx].encrypt_cmd,\
			sizeof(encrypt_info[next_encidx].encrypt_cmd), "%s", process);
	next_encidx = (next_encidx + 1) % ENC_CACHE_NUM;

	return;
}

/* 检测勒索进程缓存中是否已存在此进程 */
void check_delete_encrypt_record(char *process, char *md5)
{
	int i = 0;

	for (i = 0; i < ENC_CACHE_NUM; i++) {
		if (strcmp(process, encrypt_info[i].encrypt_cmd) != 0) {
			continue;
		}
		encrypt_info[i].encrypt_cmd[0] = 0;
		encrypt_info[i].md5[0] = 0;
	}

	return;
}

/* 检查是否是可信名单进程, 是返回1, 否返回0 */
static int check_trust_encrypt_process(char *process, char *md5)
{
	char *comm = NULL;
	sniper_plist_t *plist = NULL;
	int i = 0;
	int ret = 0;
	int count = 0;

	/* 学习和运维模式下规则名单不生效 */
	if (client_mode != NORMAL_MODE) {
		return ret;
	}

	comm = safebasename(process);
	read_lock(&sniper_ptrust_lock);

	if (sniper_ptrust_count == 0 || !sniper_ptrust) {
		read_unlock(&sniper_ptrust_lock);
		return ret;
	}

	plist = (sniper_plist_t *)sniper_ptrust;
	count = sniper_ptrust_count;

	for (i = 0; i < count; i++, plist++) {
		/* 检查应用模块是否是防勒索 */
		if (!(plist->event_flag & EVENT_Ransomeware)) {
			continue;
		}

		/* 检查进程路径是否正确 */
		if (plist->cmdpath[0] != 0 &&
		    strcmp(plist->cmdpath, process) != 0) {
			continue;
		}

		/* 检查进程名称是否正确 */
		if (plist->cmdname[0] != 0 &&
		    strcmp(plist->cmdname, comm) != 0) {
			continue;
		}

		/* 检查进程md5值是否正确 */
		if (plist->md5[0] != 0 &&
		    strcmp(plist->md5, md5) != 0) {
			continue;
		}

		ret = 1;
		break;
	}

	read_unlock(&sniper_ptrust_lock);
	return ret;
}

/* 获取匹配文件列表的结果，匹配返回0，不匹配返回-1 */
static int get_match_files_result(int num, struct sniper_my_file_list *list, char *pathname)
{
	int i = 0;

	if (num == 0 ||
	    pathname == NULL ||
	    list == NULL) {
		return -1;
	}

	for (i = 0; i < num; i++) {
		if(strcmp(list[i].file, pathname) == 0) {
			return 0;
		}
	}

	return -1;
}

/* 获取匹配文件防篡改进程的结果, 没有匹配到返回-1，匹配到返回0 */
static int get_match_fsafe_pro_result(char *fsafe_pro, char *pro)
{
	/* 策略进程为空时，都是未授权的*/
	if (fsafe_pro[0] == '\0') {
		return -1;
	}

	/*
	 * 对echo的单独处理会造成其他bash内置命令也过滤,
	 * 考虑到实际使用场景，不对bash命令不做特殊处理
	 */
#if 0
	/* echo 命令实际获取到的进程是bash */
	if (strcmp(pro, "|bash|") == 0) {
		if (strstr(fsafe_pro, "|echo|") != NULL ||
		    strstr(fsafe_pro, "|bash|") != NULL) {
			return 0;
		}
	} else {
		if (strstr(fsafe_pro, pro) != NULL) {
			return 0;
		}
	}
#else
	if (strstr(fsafe_pro, pro) != NULL) {
		return 0;
	}

#endif
	return -1;
}

/* 获取匹配文件防篡改的结果, 没有匹配到返回-1，匹配到返回0 */
static int get_match_fsafe_result(int num, struct sniper_file_safe *fsafe,
				  char *pathname, int op_type, char *comm)
{
	int i = 0;
	char dirname[S_DIRLEN] = {0};
	char *name = NULL;
	char tmp_name[F_NAME_MAX] = {0};
	char *ext = NULL;
	char tmp_ext[F_NAME_MAX] = {0};
	char tmp_process[F_CMD_MAX] = {0};
	char operation[F_OP_MAX] = {0};

	if (num == 0 ||
	    pathname == NULL ||
	    fsafe == NULL ||
	    comm == NULL) {
		return -1;
	}

	safedirname(pathname, dirname, S_DIRLEN);
	name = safebasename(pathname);
	if (name == NULL) {
		return -1;
	}

	/*
	 * 有后缀的匹配后缀，例如|*.txt|
	 * 没有后缀名的用||||匹配，
	 * 如果只匹配||，防止策略中后缀名为空，
	 * 传到内核拼接的字符串为||，反而匹配上了
	 */
	ext = strrchr(pathname, '.');
	if (ext && strlen(ext) > 2) {
		snprintf(tmp_ext, sizeof(tmp_ext), "|*%s|", ext);
	} else {
		snprintf(tmp_ext, sizeof(tmp_ext), "||||");
	}

	snprintf(tmp_name, sizeof(tmp_name), "|%s|", name);
	snprintf(tmp_process, sizeof(tmp_process), "|%s|", comm);

	/* vfs_write 无法判断为创建还是修改，因此 2个动作有一个监控，都报 */
	if (op_type == OP_OPEN_W) {
		snprintf(operation, sizeof(operation), "|modify|");
	} else if (op_type == OP_OPEN_C || op_type == OP_LINK){
		snprintf(operation, sizeof(operation), "|add|");
	} else if (op_type == OP_UNLINK){
		snprintf(operation, sizeof(operation), "|delete|");
	} else if (op_type == OP_RENAME){
		snprintf(operation, sizeof(operation), "|modify|");
	}

	for (i = 0; i < num; i++) {

		/* 没有匹配路径 */
		if (strcmp(fsafe[i].path, dirname) != 0 &&
		    strcmp(fsafe[i].real_path, dirname) != 0) {
			continue;
		}

		/*
		 * 文件名为空和*时均表示所有
		 * 文件名可以全名匹配也可以类似*.ext这种通配符+后缀名匹配
		 */
		if (fsafe[i].name[0] != '\0' &&
		    strstr(fsafe[i].name, "|*|") == NULL &&
		    strstr(fsafe[i].name, tmp_name) == NULL &&
		    strstr(fsafe[i].name, tmp_ext) == NULL) {
			continue;
		}

		if (strstr(fsafe[i].operation, operation) == NULL) {
			continue;
		}


		/* 进程名的匹配与其他条件相反，匹配到授权的进程不报，没有匹配到才报 */
		if (get_match_fsafe_pro_result(fsafe[i].process, tmp_process) == 0) {
			continue;
		}

		if (client_mode == NORMAL_MODE) {
			global_terminate = fsafe[i].status;
		} else {
			global_terminate = 0;
		}

		return 0;
	}

	return -1;
}

/* 获取匹配日志异常删除的结果, 没有匹配到返回-1，匹配到返回0 */
int get_match_flogcollector_result(int num,
				   struct sniper_file_logcollector *flogcollector,
				   char *pathname)
{
	int i = 0;
	char dirname[S_DIRLEN] = {0};
	char *suffix = NULL;
	char tmp_suffix[32] = {0};

	if (num == 0 ||
	    pathname == NULL ||
	    flogcollector == NULL) {
		return -1;
	}

	safedirname(pathname, dirname, S_DIRLEN);
	suffix = strrchr(pathname, '.');

	/* 比较目录和后缀名，|*|表示全检查 */
	for (i = 0; i < num; i++) {
		if(strcmp(flogcollector[i].filepath, dirname) == 0 ||
		   strcmp(flogcollector[i].real_path, dirname) == 0) {
			if (strstr(flogcollector[i].extension, "|*|") != NULL) {
				return 0;
			}

			if (suffix && strlen(suffix) > 1) {
				snprintf(tmp_suffix, sizeof(tmp_suffix), "|%s|", suffix+1);
				if (strstr(flogcollector[i].extension, tmp_suffix) != NULL) {
					return 0;
				}
			}
		}
	}

	return -1;
}

/* 获取匹配usb文件监控的结果, 没有匹配到返回-1，匹配到返回0 */
static int get_match_fusb_result(int num, struct sniper_file_usb *fusb,
				 char *pathname, int op_type, struct _usb_dev *dev)
{
	char *suffix = NULL;
	char tmp_suffix[32] = {0};
	int i = 0, major = 0, minor = 0;

	if (num == 0 || pathname == NULL || fusb == NULL) {
		return -1;
	}

	suffix = strrchr(pathname, '.');

	/* 获取主、次设备号 */
	if (op_type == OP_RENAME) {
		major = dev->new_major;
		minor = dev->new_minor;
	} else {
		major = dev->major;
		minor = dev->minor;
	}
	for (i = 0; i < num; i++) {
		/* 主设备号相同，次设备号除以16相同，表示同一个u盘 */
		if (fusb[i].major == major && (fusb[i].minor/16) == (minor/16)) {

			/* 比较后缀名，|*|表示全检查 */
			if (strstr(fusb[i].extension, "|*|") != NULL) {
				return 0;
			}

			if (suffix && strlen(suffix) > 1) {
				snprintf(tmp_suffix, sizeof(tmp_suffix), "|%s|", suffix+1);
				if (strstr(fusb[i].extension, tmp_suffix) != NULL) {
					return 0;
				}
			}
			break;
		}
	}

	return -1;
}

/* 获取匹配非法脚本监控的结果, 没有匹配到返回-1，匹配到返回0 */
static int get_match_fillegal_script_result(int num,
					    struct sniper_file_illegal_script *fillegal_script,
					    char *pathname)
{
	int i = 0;
	char dirname[S_DIRLEN] = {0};
	char *suffix = NULL;
	char tmp_suffix[32] = {0};

	if (num == 0 ||
	    pathname == NULL ||
	    fillegal_script == NULL) {
		return -1;
	}

	safedirname(pathname, dirname, S_DIRLEN);
	suffix = strrchr(pathname, '.');

	/* 非法脚本检测目录及其子目录, 目录*代表全部监控 */
	for (i = 0; i < num; i++) {
		if((strcmp(fillegal_script[i].filepath, "*") == 0) ||
		   (fillegal_script[i].filepath != NULL &&
		    fillegal_script[i].filepath[0] != '\0' &&
		    strncmp(fillegal_script[i].filepath,
				dirname, strlen(fillegal_script[i].filepath)) == 0) ||
		   (fillegal_script[i].real_path != NULL &&
		    fillegal_script[i].real_path[0] != '\0' &&
		    strncmp(fillegal_script[i].real_path,
				dirname, strlen(fillegal_script[i].real_path)) == 0)) {
#if 0
			/* 路径为*时, 后缀名也为*意味着所有文件都监控,负载会很高, 此处不允许后缀名为* */
			if (strstr(fillegal_script[i].extension, "|*|") != NULL) {
				return 0;
			}
#endif

			/* 检测后缀名, 没有*通配符 */
			if (suffix && strlen(suffix) > 1) {
				snprintf(tmp_suffix, sizeof(tmp_suffix), "|%s|", suffix+1);
				if (strstr(fillegal_script[i].extension, tmp_suffix) != NULL) {
					if (client_mode == NORMAL_MODE) {
						global_terminate = sniper_fpolicy.file_illegal_script_terminate;
					} else {
						global_terminate = 0;
					}
					return 0;
				}
			}
		}
	}

	return -1;
}

/* 获取匹配webshell识别的结果, 没有匹配到返回-1，匹配到返回0 */
static int get_match_fwebshell_detect_result(int num,
					     struct sniper_file_webshell_detect *fwebshell_detect,
					     char *pathname)
{
	int i = 0;
	char dirname[S_DIRLEN] = {0};
	char *suffix = NULL;
	char tmp_suffix[32] = {0};

	if (num == 0 ||
	    pathname == NULL ||
	    fwebshell_detect == NULL) {
		return -1;
	}

	safedirname(pathname, dirname, S_DIRLEN);
	suffix = strrchr(pathname, '.');

	/* webshell检测目录及其子目录, 目录*代表全部监控 */
	for (i = 0; i < num; i++) {
		if((strcmp(fwebshell_detect[i].filepath, "*") == 0) ||
		   (fwebshell_detect[i].filepath != NULL &&
		    fwebshell_detect[i].filepath[0] != '\0' &&
		    strncmp(fwebshell_detect[i].filepath,
				dirname, strlen(fwebshell_detect[i].filepath)) == 0) ||
		   (fwebshell_detect[i].real_path != NULL &&
		    fwebshell_detect[i].real_path[0] != '\0' &&
		    strncmp(fwebshell_detect[i].real_path,
				dirname, strlen(fwebshell_detect[i].real_path)) == 0)) {

			/* 检测后缀名, 没有*通配符 */
			if (suffix && strlen(suffix) > 1) {
				snprintf(tmp_suffix, sizeof(tmp_suffix), "|%s|", suffix+1);
				if (strstr(fwebshell_detect[i].extension, tmp_suffix) != NULL) {
					if (client_mode == NORMAL_MODE) {
						global_terminate = sniper_fpolicy.file_webshell_detect_terminate;
					} else {
						global_terminate = 0;
					}
					return 0;
				}
			}
		}
	}

	return -1;
}

/* 获取匹配黑名单的结果, 没有匹配到返回-1，匹配到返回0 */
static int get_match_fblack_after_result(int num, struct sniper_file_black *fblack,
					 struct inode *inode, char *pathname)
{
	int i = 0;
	char *name = NULL;
	char tmp_name[F_NAME_MAX] = {0};
	char *ext = NULL;
	int ret = -1;

	if (num == 0 ||
	    pathname == NULL ||
	    inode == NULL ||
	    fblack == NULL) {
		return -1;
	}

	name = safebasename(pathname);
	if (name == NULL) {
		return -1;
	}

	ext = strrchr(pathname, '.');
	if (ext && strlen(ext) > 2) {
		snprintf(tmp_name, sizeof(tmp_name), "*%s", ext);
	} else {
		snprintf(tmp_name, sizeof(tmp_name), "|.|");
	}

	for (i = 0; i < num; i++, fblack++) {

		/* 有路径且不匹配 */
		if (fblack->filepath[0] != '\0' &&
		    strcmp(fblack->filepath, pathname) != 0) {
			continue;
		}

		/* 文件名匹配或者名称带通配符不匹配 */
		if (fblack->filename[0] != '\0' &&
		    (strcmp(fblack->filename, name) == 0 ||
		    strcmp(fblack->filename, tmp_name) == 0)) {
			ret = 0;
			break;
		}

	}

	return ret;

}

/* 发送给用户的消息结构体，填充共通成员的值 */
static int set_send_msg(char *pathname, char *new_pathname,
			filereq_t *req, int type,
			int op_type, char *process_path)
{
	int args_len = 0;
	int max_path_len = 0, max_newpath_len = 0, max_pro_len = 0;
	int path_len = 0, newpath_len = 0, pro_len = 0;
	char *path = NULL;

	if (pathname == NULL || req == NULL) {
		return -1;
	}

	/*
	 * 重命名和勒索备份的情况下
	 * new_pathname如果为空说明之前调用的地方出错了、
	 */
	if (op_type == OP_RENAME ||
	    type == F_ENCRYPT_BACKUP) {
		if (new_pathname == NULL) {
			return -1;
		}
	}

	/*
	 * 全部设置为1, 防止重定向时,子进程还没有替换父进程
	 * 如果看PF_FORKNOEXEC赋值did_exec为0,那用户层取的就是父进程的进程uuid
	 */
	req->did_exec = 1;

	req->type = type;
	req->op_type = op_type;
	req->uid = currentuid();
	req->pid = current->pid;
	req->proctime = get_process_time(current);
	req->peerip = 0;
	req->newpath_len = 0;
	sniper_do_gettimeofday(&req->event_tv);
	snprintf(req->parent_comm, sizeof(req->parent_comm),
			"%s", current->parent->comm);
	/* 操作进程所在的终端信息 */
	if (current->signal && current->signal->tty) {
		snprintf(req->tty, sizeof(req->tty),
				"%s", current->signal->tty->name);
	} else {
		get_tty_from_fd1(req->tty);
	}

	/*
	 * 拼接的顺序为进程路径，文件路径
	 * 如果是重命名和勒索备份的情况下
	 * 后面再拼接上新文件夹路径
	 * 中间有\0分隔
	 */
	path = &(req->args);
	args_len = ARGS_LEN - sizeof(filereq_t) - 1;
	pro_len = strlen(process_path);
	max_pro_len = pro_len < args_len ? pro_len : args_len;
	memcpy(path, process_path, max_pro_len);
	req->pro_len = max_pro_len;
	req->size = sizeof(filereq_t) + max_pro_len + 1;

	path_len = strlen(pathname);
	args_len = ARGS_LEN - sizeof(filereq_t) - max_pro_len -2;
	max_path_len = path_len < args_len ? path_len : args_len;
	memcpy(path + max_pro_len + 1, pathname, max_path_len);
	req->path_len = max_path_len;
	req->size = sizeof(filereq_t) + max_pro_len + max_path_len + 2;

	if (op_type == OP_RENAME || type == F_ENCRYPT_BACKUP) {
		newpath_len = strlen(new_pathname);
		args_len = ARGS_LEN - sizeof(filereq_t) - max_pro_len - max_path_len - 3;
		max_newpath_len = newpath_len < args_len ? newpath_len : args_len;
		memcpy(path + max_pro_len + max_path_len + 2, new_pathname, max_newpath_len);
		req->newpath_len = max_newpath_len;
		req->size = sizeof(filereq_t) + max_pro_len + max_path_len + max_newpath_len + 3;
	}

	return 0;
}

/* 检查是否匹配文件列表, 匹配返回0，不匹配返回-1 */
int check_match_files(int num, struct sniper_my_file_list *list, char *pathname)
{
	int ret = 0;

	if (num == 0 ||
	    pathname == NULL ||
	    list == NULL) {
		return -1;
	}

	ret = get_match_files_result(num, list, pathname);

	return ret;

}

/* 检测是否匹配文件防篡改, 没有匹配到返回-1，匹配到返回0 */
int check_match_fsafe(int num,
		      struct sniper_file_safe *fsafe, char *pathname,
		      int op_type, char *comm)
{
	int ret = 0;

	if (num == 0 ||
	    pathname == NULL ||
	    fsafe == NULL ||
	    comm == NULL) {
		return -1;
	}

	ret = get_match_fsafe_result(num, fsafe, pathname, op_type, comm);

	return ret;

}

/* 检测是否匹配日志异常删除, 没有匹配到返回-1，匹配到返回0 */
int check_match_flogcollector(int num,
			      struct sniper_file_logcollector *flogcollector,
			      char *pathname)
{
	int ret = 0;

	if (num == 0 ||
	    pathname == NULL ||
	    flogcollector == NULL) {
		return -1;
	}

	ret = get_match_flogcollector_result(num, flogcollector, pathname);

	return ret;

}

/* 检测是否匹配usb文件监控, 没有匹配到返回-1，匹配到返回0 */
int check_match_fusb(int num, struct sniper_file_usb *fusb,
		     char *pathname, int op_type, struct _usb_dev *dev)
{
	int ret = 0;

	if (num == 0 ||
	    pathname == NULL ||
	    dev == NULL ||
	    fusb == NULL) {
		return -1;
	}

	ret = get_match_fusb_result(num, fusb, pathname, op_type, dev);

	return ret;

}

/* 检测是否匹配中间件可执行文件识别, 没有匹配到返回-1，匹配到返回0 */
static int check_match_middle_binary(char *pathname)
{
	int match = 0;
	char *suffix = NULL;
	char tmp_suffix[32] = {0};

	suffix = strrchr(pathname, '.');

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_middle_binary_on == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return -1;
	}

	/* 过滤开关开启后，不可以选择后缀名，全部要报 */
	if (sniper_fpolicy.file_middle_binary_exclude == 0) {
		read_unlock(&sniper_fpolicy_lock);
		if (client_mode == NORMAL_MODE) {
			global_terminate = sniper_fpolicy.file_middle_binary_terminate;
		} else {
			global_terminate = 0;
		}
		return 0;
	}

	read_lock(&sniper_fmiddle_binary_lock);
	if (sniper_fmiddle_binary != NULL) {

		/* 过滤开启后, 无后缀的文件始终报 */
		if (suffix == NULL) {
			match = 1;
			if (client_mode == NORMAL_MODE) {
				global_terminate = sniper_fpolicy.file_middle_binary_terminate;
			} else {
				global_terminate = 0;
			}
		} else if (strlen(suffix) > 1) {
			/* 检测后缀名, 没有*通配符 */
			snprintf(tmp_suffix, sizeof(tmp_suffix), "|%s|", suffix+1);
			if (strstr(sniper_fmiddle_binary, tmp_suffix) == NULL) {
				match = 1;
				if (client_mode == NORMAL_MODE) {
					global_terminate = sniper_fpolicy.file_middle_binary_terminate;
				} else {
					global_terminate = 0;
				}
			}
		}

	}
	read_unlock(&sniper_fmiddle_binary_lock);
	read_unlock(&sniper_fpolicy_lock);

	if (match == 1) {
		return 0;
	}

	return -1;
}

/* 检测是否匹配中间件脚本文件识别, 没有匹配到返回-1，匹配到返回0 */
static int check_match_middle_script(char *pathname)
{
	int match = 0;
	char *suffix = NULL;
	char tmp_suffix[32] = {0};

	suffix = strrchr(pathname, '.');

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_middle_script_on == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return -1;
	}

	read_lock(&sniper_fmiddle_script_lock);
	if (sniper_fmiddle_script != NULL) {

		if (strstr(sniper_fmiddle_script, "|*|") != NULL) {
			read_unlock(&sniper_fmiddle_script_lock);
			read_unlock(&sniper_fpolicy_lock);
			return 0;
		}

		if (suffix && strlen(suffix) > 1) {
			/* 检测后缀名, 没有*通配符 */
			snprintf(tmp_suffix, sizeof(tmp_suffix), "|%s|", suffix+1);
			if (strstr(sniper_fmiddle_script, tmp_suffix) != NULL) {
				match = 1;
				if (client_mode == NORMAL_MODE) {
					global_terminate = sniper_fpolicy.file_middle_script_terminate;
				} else {
					global_terminate = 0;
				}
			}
		}

	}
	read_unlock(&sniper_fmiddle_script_lock);
	read_unlock(&sniper_fpolicy_lock);

	if (match == 1) {
		return 0;
	}

	return -1;
}

/* 检测是否匹配非法脚本, 没有匹配到返回-1，匹配到返回0 */
static int check_match_fillegal_script(int num,
				       struct sniper_file_illegal_script *fillegal_script,
				       char *pathname)
{
	int ret = 0;

	if (num == 0 ||
	    pathname == NULL ||
	    fillegal_script == NULL) {
		return -1;
	}

	ret = get_match_fillegal_script_result(num, fillegal_script, pathname);

	return ret;

}

/* 检测是否匹配webshell, 没有匹配到返回-1，匹配到返回0 */
static int check_match_fwebshell_detect(int num,
					struct sniper_file_webshell_detect *fwebshell_detect,
					char *pathname)
{
	int ret = 0;

	if (num == 0 ||
	    pathname == NULL ||
	    fwebshell_detect == NULL) {
		return -1;
	}

	ret = get_match_fwebshell_detect_result(num, fwebshell_detect, pathname);

	return ret;

}

/* 查看勒索进程缓存里面是不是为空, 是返回0，不为空返回1*/
static int check_encrypt_cache_pro(void)
{
	int i = 0, match = 0;

	for (i = 0; i < ENC_CACHE_NUM; i++) {
		if (encrypt_info[i].encrypt_cmd[0] == 0) {
			continue;
		}

		match = 1;
		break;
	}

	return match;
}

/* 检查是否是勒索进程异常修改文件，是返回1，否返回0*/
static int check_match_abnormal_change(char *process)
{
	int i = 0, match = 0;

	for (i = 0; i < ENC_CACHE_NUM; i++) {
		if (encrypt_info[i].encrypt_cmd[0] == 0) {
			continue;
		}

		if (strcmp(encrypt_info[i].encrypt_cmd, process) == 0) {
			match = 1;
		}
	}

	return match;
}

/* 敏感文件识别 */
int check_sensitive_file(char *pathname, char *new_pathname,
			 struct parent_info *pinfo, int op_type,
			 struct inode *inode)
{

	/* 敏感文件操作功能暂时取消，此处先直接返回0 */
#if 0
	int ret = 0, num =0;
	filereq_t *req = NULL;
	struct sniper_my_file_list *fsensitive = NULL;
	int terminate = 0;
	struct timeval tv = {0};

	if (!pathname || !pinfo || (!inode && op_type != OP_OPEN_C && op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME && new_pathname == NULL) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_sensitive_on == 0 ||
		sniper_fpolicy.sensitive_count == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	num = sniper_fpolicy.sensitive_count;
	if (client_mode == NORMAL_MODE) {
		terminate = sniper_fpolicy.file_sensitive_kill;
	} else {
		terminate = 0;
	}
	read_lock(&sniper_fsensitive_lock);
	fsensitive = (struct sniper_my_file_list *)sniper_fsensitive;
	ret = check_match_files(num, fsensitive, pathname);
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_files(num, fsensitive, new_pathname);
	}
	read_unlock(&sniper_fsensitive_lock);

	read_unlock(&sniper_fpolicy_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_SENSITIVEFILE);
	if (req == NULL) {
		myprintk("sensitive: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	req->terminate = terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname, req, F_SENSITIVE, op_type) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_SENSITIVEFILE);
		return 0;
	}

	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size, nl_file_pid, Probe_file);

	sniper_kfree(req, ARGS_LEN, KMALLOC_SENSITIVEFILE);
	if (ret == 0 && terminate == 1) {
		return -1;
	} else {
		return 0;
	}
#else
	return 0;
#endif
}

/* 日志异常删除 */
int check_log_delete(char *pathname, char *new_pathname,
		     struct parent_info *pinfo, int op_type,
		     struct inode *inode)
{
	int ret = 0, num =0;
	filereq_t *req = NULL;
	char process_path[S_CMDLEN] = {0};
	struct sniper_my_file_list *flog_delete = NULL;

	if (!pathname || !pinfo || !inode) {
		return 0;
	}

	if (op_type == OP_RENAME && new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_log_delete == 0 ||
		sniper_fpolicy.log_delete_count == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	num = sniper_fpolicy.log_delete_count;
	read_lock(&sniper_flog_delete_lock);
	flog_delete = (struct sniper_my_file_list *)sniper_flog_delete;
	if (sniper_badptr(flog_delete)) {
		read_unlock(&sniper_flog_delete_lock);
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}
	ret = check_match_files(num, flog_delete, pathname);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_files(num, flog_delete, new_pathname);
	}
	read_unlock(&sniper_flog_delete_lock);

	read_unlock(&sniper_fpolicy_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_LOGDELETE);
	if (req == NULL) {
		myprintk("log_delete: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	req->file_size = i_size_read(inode);
	if (set_send_msg(pathname, new_pathname,
				req, F_LOG_DELETE, op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_LOGDELETE);
		return 0;
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);
	myfdebug("log_delete: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);

	sniper_kfree(req, ARGS_LEN, KMALLOC_LOGDELETE);
	return 0;
}

/* 文件防篡改 */
int check_safe(char *pathname, char *new_pathname,
	       struct parent_info *pinfo, int op_type,
	       struct inode *inode)
{
	int ret = 0, num =0;
	filereq_t *req = NULL;
	struct sniper_file_safe *fsafe = NULL;
	struct timeval tv = {0};
	char process_path[S_CMDLEN] = {0};
	char *comm = NULL;

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	comm = safebasename(process_path);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_safe_on == 0 ||
		sniper_fpolicy.safe_count == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	num = sniper_fpolicy.safe_count;
	read_lock(&sniper_fsafe_lock);
	fsafe = (struct sniper_file_safe *)sniper_fsafe;
	if (sniper_badptr(fsafe)) {
		read_unlock(&sniper_fsafe_lock);
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	global_terminate = 0;
	ret = check_match_fsafe(num, fsafe, pathname, op_type, comm);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_fsafe(num, fsafe,
				new_pathname, op_type, comm);
	}
	read_unlock(&sniper_fsafe_lock);

	read_unlock(&sniper_fpolicy_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_FILESAFE);
	if (req == NULL) {
		myprintk("file safe: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	req->terminate = global_terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_SAFE, op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_FILESAFE);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);
	myfdebug("fsafe: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);

	sniper_kfree(req, ARGS_LEN, KMALLOC_FILESAFE);
	if (ret == 0 && global_terminate == 1) {
		return -1;
	} else {
		return 0;
	}
}

/* 文件行文采集 */
int check_logcollector(char *pathname, char *new_pathname,
		       struct parent_info *pinfo, int op_type,
		       struct inode *inode)
{
	int ret = 0, num =0;
	filereq_t *req = NULL;
	struct sniper_file_logcollector *flogcollector = NULL;
	struct timeval tv = {0};
	char process_path[S_CMDLEN] = {0};

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_logcollector_on == 0 ||
		sniper_fpolicy.logcollector_count == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	num = sniper_fpolicy.logcollector_count;
	read_lock(&sniper_flogcollector_lock);
	flogcollector = (struct sniper_file_logcollector *)sniper_flogcollector;
	if (sniper_badptr(flogcollector)) {
		read_unlock(&sniper_flogcollector_lock);
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}
	ret = check_match_flogcollector(num, flogcollector, pathname);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_flogcollector(num, flogcollector, new_pathname);
	}
	read_unlock(&sniper_flogcollector_lock);

	read_unlock(&sniper_fpolicy_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_LOGCOLLECT);
	if (req == NULL) {
		myprintk("logcollector: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_LOGCOLLECTOR,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_LOGCOLLECT);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("logcollector: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_LOGCOLLECT);
	return 0;
}

/* usb文件监控 */
int check_usb_path(char *pathname, char *new_pathname,
		   struct parent_info *pinfo, int op_type,
		   struct inode *inode, struct _usb_dev *dev)
{
	int ret = 0, num =0;
	filereq_t *req = NULL;
	struct sniper_file_usb *fusb = NULL;
	struct timeval tv = {0};
	char process_path[S_CMDLEN] = {0};

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.usb_file_on == 0 ||
		sniper_fpolicy.usb_count == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	num = sniper_fpolicy.usb_count;
	read_lock(&sniper_fusb_lock);
	fusb = (struct sniper_file_usb *)sniper_fusb;
	if (sniper_badptr(fusb)) {
		read_unlock(&sniper_fusb_lock);
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}
	ret = check_match_fusb(num, fusb, pathname, op_type, dev);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_fusb(num, fusb, new_pathname, op_type, dev);
	}
	read_unlock(&sniper_fusb_lock);

	read_unlock(&sniper_fpolicy_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_USB);
	if (req == NULL) {
		myprintk("usb: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_USB, op_type,
				process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_USB);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("usb: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_USB);
	return 0;
}

/* 中间件可执行文件识别检测 */
static int check_middle_binary(char *pathname, char *new_pathname,
			       struct parent_info *pinfo, int op_type,
			       struct inode *inode, char *process_path)
{
	int ret = 0;
	filereq_t *req = NULL;
	struct timeval tv = {0};

	/* 中间件的阻断是在用户层*/
	global_terminate = 0;
	ret = check_match_middle_binary(pathname);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_middle_binary(new_pathname);
	}

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_MIDBINARY);
	if (req == NULL) {
		myprintk("middle_script: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	req->terminate = global_terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_BINARY_FILTER,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_MIDBINARY);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("middle_binary: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_MIDBINARY);
	return 0;
}

/* 中间件脚本文件识别检测 */
static int check_middle_script(char *pathname, char *new_pathname,
			       struct parent_info *pinfo, int op_type,
			       struct inode *inode, char *process_path)
{
	int ret = 0;
	filereq_t *req = NULL;
	struct timeval tv = {0};

	/* 中间件的阻断是在用户层*/
	global_terminate = 0;
	ret = check_match_middle_script(pathname);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_middle_script(new_pathname);
	}

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_MIDSCRIPT);
	if (req == NULL) {
		myprintk("middle_script: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	req->terminate = global_terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_MIDDLE_SCRIPT,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_MIDSCRIPT);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("middle_script: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_MIDSCRIPT);
	return 0;
}

/* 中间件识别检测 */
int check_middle_target(char *pathname, char *new_pathname,
			struct parent_info *pinfo, int op_type,
			struct inode *inode)
{
	int ret = 0;
	char tmp_process[F_CMD_MAX] = {0};
	char process_path[S_CMDLEN] = {0};
	char *comm = NULL;

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	comm = safebasename(process_path);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	snprintf(tmp_process, sizeof(tmp_process), "|%s|", comm);

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_middle_on == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	read_lock(&sniper_fmiddle_target_lock);
	if (sniper_fmiddle_target != NULL &&
		strstr(sniper_fmiddle_target, tmp_process) == NULL) {
		ret = 1;
	}
	read_unlock(&sniper_fmiddle_target_lock);
	read_unlock(&sniper_fpolicy_lock);

	/* 没有匹配中间件退出*/
	if (ret == 1) {
		return 0;
	}

	check_middle_binary(pathname, new_pathname,
				pinfo, op_type,
				inode, process_path);
	check_middle_script(pathname, new_pathname,
				pinfo, op_type,
				inode, process_path);

	return 0;
}


/* 非法脚本文件识别检测 */
int check_illegal_script(char *pathname, char *new_pathname,
			 struct parent_info *pinfo, int op_type,
			 struct inode *inode)
{
	int ret = 0, num =0;
	filereq_t *req = NULL;
	struct sniper_file_illegal_script *fillegal_script = NULL;
	struct timeval tv = {0};
	char process_path[S_CMDLEN] = {0};

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_illegal_script_on == 0 ||
		sniper_fpolicy.illegal_script_count == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	num = sniper_fpolicy.illegal_script_count;
	read_lock(&sniper_fillegal_script_lock);
	fillegal_script = (struct sniper_file_illegal_script *)sniper_fillegal_script;
	if (sniper_badptr(fillegal_script)) {
		read_unlock(&sniper_fillegal_script_lock);
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}
	/* 非法脚本的阻断是在用户层*/
	global_terminate = 0;
	ret = check_match_fillegal_script(num, fillegal_script, pathname);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_fillegal_script(num, fillegal_script, new_pathname);
	}
	read_unlock(&sniper_fillegal_script_lock);

	read_unlock(&sniper_fpolicy_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_ILLSCRIPT);
	if (req == NULL) {
		myprintk("illegal_script: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	req->terminate = global_terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_ILLEGAL_SCRIPT,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_ILLSCRIPT);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);
	printk("illegal_script: [%d]path:%s, process:%s @%s line:%d\r\n",op_type, pathname, process_path,__FILE__,__LINE__);
	myfdebug("illegal_script: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_ILLSCRIPT);
	return 0;
}

/* webshell文件识别检测 */
int check_webshell_detect(char *pathname, char *new_pathname,
			  struct parent_info *pinfo, int op_type,
			  struct inode *inode)
{
	int ret = 0, num =0;
	filereq_t *req = NULL;
	struct sniper_file_webshell_detect *fwebshell_detect = NULL;
	struct timeval tv = {0};
	char process_path[S_CMDLEN] = {0};

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.file_webshell_detect_on == 0 ||
		sniper_fpolicy.webshell_detect_count == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	num = sniper_fpolicy.webshell_detect_count;
	read_lock(&sniper_fwebshell_detect_lock);
	fwebshell_detect = (struct sniper_file_webshell_detect *)sniper_fwebshell_detect;
	if (sniper_badptr(fwebshell_detect)) {
		read_unlock(&sniper_fwebshell_detect_lock);
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}
	/* 非法脚本的阻断是在用户层*/
	global_terminate = 0;
	ret = check_match_fwebshell_detect(num, fwebshell_detect, pathname);
	/* 如果是重命名的情况，也要检测新的文件名 */
	if (op_type == OP_RENAME && ret < 0) {
		ret = check_match_fwebshell_detect(num, fwebshell_detect, new_pathname);
	}
	read_unlock(&sniper_fwebshell_detect_lock);

	read_unlock(&sniper_fpolicy_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_WEBSHELL);
	if (req == NULL) {
		myprintk("webshell_detect: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	req->terminate = global_terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_WEBSHELL_DETECT,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_WEBSHELL);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("webshell_detect: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_WEBSHELL);
	return 0;
}

time_t last_illegal_printer_time = 0;
/* 非法打印检测 */
void report_illegal_printer(void)
{
	int flags = 0;
	filereq_t *req = NULL;
	time_t now = sniper_uptime();
	time_t last = last_illegal_printer_time;
	char process_path[S_CMDLEN] = {0};

	/* 每次都更新上次打印时间，不重复报告连续1秒内的打印行为 */
	last_illegal_printer_time = now;

	if (now == last || now == last + 1) {
		return;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_ILLPRINTER);
	if (req == NULL) {
		myprintk("report_illegal_printer fail, no memory\n");
		return;
	}
	memset(req, 0, ARGS_LEN);

	get_current_process(process_path, S_CMDLEN);

	get_parent_info(&flags, &req->pinfo);
	if (set_send_msg("", NULL, req,
				F_PRINTER, OP_READ, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_ILLPRINTER);
		return;
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);
	sniper_kfree(req, ARGS_LEN, KMALLOC_ILLPRINTER);
}

time_t last_illegal_burning_time = 0;
/* 非法刻录 */
void report_illegal_burning(void)
{
	int flags = 0;
	filereq_t *req = NULL;
	time_t now = sniper_uptime();
	time_t last = last_illegal_burning_time;
	char process_path[S_CMDLEN] = {0};

	/* 每次都更新上次刻录时间，不重复报告连续1秒内的刻录行为 */
	last_illegal_burning_time = now;

	if (now == last || now == last + 1) {
		return;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_ILLBURNING);
	if (req == NULL) {
		myprintk("report_illegal_burning fail, no memory\n");
		return;
	}
	memset(req, 0, ARGS_LEN);

	get_current_process(process_path, S_CMDLEN);

	get_parent_info(&flags, &req->pinfo);
	if (set_send_msg("", NULL, req,
				F_CDROM, OP_READ, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_ILLBURNING);
		return;
	}

	if (client_mode == NORMAL_MODE) {
		req->terminate = 1;
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);
	sniper_kfree(req, ARGS_LEN, KMALLOC_ILLBURNING);
}

/* 备份文件 */
int copy_file_backup(char *pathname, size_t size,
		     struct parent_info *pinfo, int op_type,
		     struct inode *inode)
{
	char md5[S_MD5LEN] = {0}, newpath[S_SHORTPATHLEN] = {0};
	struct file *oldfile = NULL, *newfile = NULL;
	size_t tmp_size = 0;
	int oldlen = 0, newlen = 0, error = 0;
	off_t oldoff = 0;
	void *buf = NULL;
	char *ext = NULL, tmp_ext[F_NAME_MAX] = {0};
	struct sniper_file_encrypt *fencrypt = NULL;
	filereq_t *req = NULL;
	unsigned int neglect_min = 0, neglect_size = 0, space_full = 0;
	struct timeval now_tv;
	char process_path[S_CMDLEN] = {0};
	char *comm = NULL;
	off_t newoff = 0;

	if (!pathname || !pinfo || !inode) {
		return 0;
	}

	/* 诱捕文件不用备份, /run/和/tmp/目录下不备份 */
	if (strstr(pathname, TRAP_FILE_NOHIDE) != NULL ||
	    strncmp(pathname, "/run/", 5) == 0 ||
	    strncmp(pathname, "/tmp/", 5) == 0) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	comm = safebasename(process_path);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	/*
	 * 备份文件单独对systemd-*的系统进程进行补充过滤
	 * 备份工具备份时，如果原文件存在,
	 * 会删除原文件, 导致再次备份，此处过滤这种情况
	 */
	if (strncmp(comm, "systemd-", 8) == 0 || strcmp(comm, "sniper_docrestore") == 0) {
		return 0;
	}

	if (size <= 0) {
		return 0;
	}

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.encrypt_on == 0 ||
		sniper_fpolicy.encrypt_backup_on == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return 0;
	}

	neglect_min = sniper_fpolicy.neglect_min;
	neglect_size = sniper_fpolicy.neglect_size;
	space_full = sniper_fpolicy.encrypt_space_full;
	read_unlock(&sniper_fpolicy_lock);

	if (space_full) {
		/* 空间满了，不备份的开关打开后，直接返回*/
		return 0;
	}

	/* 大于策略规定大小的文件不备份*/
	if (size > neglect_size*MB_SIZE ) {
//		myprintk("file:%s size is too large; size:%d[%d] neglect_size:%d[%d] \n",
//				pathname, size, size/MB_SIZE, neglect_size*MB_SIZE, neglect_size);
		return 0;
	}

	sniper_do_gettimeofday(&now_tv);
	if (now_tv.tv_sec - inode->i_mtime.tv_sec <= neglect_min *60) {
//		myprintk("file:%s change time :%lu, now time:%lu, neglect_min:%u min\n",
//				pathname, inode->i_mtime.tv_sec, now_tv.tv_sec, neglect_min);
		return 0;
	}

	ext = strrchr(pathname, '.');
	if (ext && strlen(ext) > 2) {
		snprintf(tmp_ext, sizeof(tmp_ext), "|%s|", ext+1);
	} else {
		snprintf(tmp_ext, sizeof(tmp_ext), "|.|");
	}

	read_lock(&sniper_fencrypt_lock);
	fencrypt = (struct sniper_file_encrypt *)sniper_fencrypt;
	if (sniper_badptr(fencrypt)) {
		read_unlock(&sniper_fencrypt_lock);
		return -1;
	}
	if (fencrypt->extension == NULL ||
	    strstr(fencrypt->extension, tmp_ext) == NULL) {
		read_unlock(&sniper_fencrypt_lock);
		return -1;
	}
	read_unlock(&sniper_fencrypt_lock);

	if (md5_string(pathname, md5) < 0) {
		return -1;
	}

	myfdebug2(SNIPER_OPEN, "backup1: open %s\n", pathname);

	/*
	 * 4,5,0以下版本内核中vfs_unlink会执行mutex_lock(&dentry->d_inode->i_mutex),
	 * (2.6.39.y~3.17.y范围)如果此时用filp_open,
	 * 调用到ima_rdwr_violation_check会再执行一次mutex_lock(&inode->i_mutex)，会导致死锁
	 * 其他版本无法验证，也同样在filp_open前后保守的做一次解锁再加锁的动作
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) && LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
	mutex_unlock(&inode->i_mutex);
	oldfile = filp_open(pathname, O_RDONLY, 0);
	mutex_lock(&inode->i_mutex);
#else
	oldfile = filp_open(pathname, O_RDONLY, 0);
#endif
	if (IS_ERR(oldfile)){
		myprintk("backup open file %s error\n", pathname);
		return -1;
	}

	snprintf(newpath, sizeof(newpath), "%s/%s", BACKUP_DIR, md5);

	myfdebug2(SNIPER_OPEN, "backup2: open %s\n", newpath);
	newfile = filp_open(newpath, O_RDWR | O_CREAT |O_TRUNC, 0644);
	if (IS_ERR(newfile)){
		/*
		 * 看到内核有不定时打开新文件失败的情况,
		 * 错误显示没有权限，目录的权限是0707，增加调试信息
		 */
		myprintk("backup create file %s error:%ld, euid:%d, oldpath:%s\n",
				newpath, PTR_ERR(newfile), currenteuid(), pathname);
		filp_close(oldfile, NULL);
		return -1;
	}

	buf = sniper_kmalloc(PAGE_SIZE, GFP_ATOMIC, KMALLOC_FILEBUF);
	if (!buf) {
		myprintk("backup malloc buf fail, no memory\n");
		filp_close(oldfile, NULL);
		filp_close(newfile, NULL);
		return -1;
	}
	memset(buf, 0, PAGE_SIZE);

	myfdebug2(SNIPER_OPEN, "backup3: copy %s to %s\n", pathname, newpath);
	tmp_size = size;
	while (tmp_size > 0) {

/* SUSE12.5的内核版本是4.12，但使用了4.14以后的kernel_write()参数形式，
   不好用内核版本来区分使用的参数形式，改用宏变量来指示该用何种参数 */
#ifdef KERNEL_READ_OFF_POINTER
		oldlen = kernel_read(oldfile, buf, PAGE_SIZE, (loff_t *)&oldoff);
#else
		oldlen = kernel_read(oldfile, oldoff, buf, PAGE_SIZE);
		oldoff += oldlen;
#endif
		if (oldlen <= 0) {
			error = 1;
			break;
		}

#ifdef KERNEL_WRITE_OFF_POINTER
		newlen = kernel_write(newfile, buf, oldlen, (loff_t *)&newoff);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		/*
		 * 低版本内核中的kernel_write没有导出，不可以外部调用,
		 * 只能先在代码中同样的方式实现kernel_my_write再调用
		 */
		newlen = kernel_my_write(newfile, buf, oldlen, newoff);
#else
		newlen = kernel_write(newfile, buf, oldlen, newoff);
#endif
		newoff += newlen;
		if(newlen < oldlen) {
			error = 1;
			break;
		}

		tmp_size-= newlen;
	}
	sniper_kfree(buf, PAGE_SIZE, KMALLOC_FILEBUF);
	filp_close(oldfile, NULL);
	filp_close(newfile, NULL);
	myfdebug2(SNIPER_OPEN, "backup4: copy %s to %s end\n",
			pathname, newpath);

	if (error == 1) {
		return -1;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_BACKUPFILE);
	if (req == NULL) {
		myprintk("encrypt: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, newpath,
				req, F_ENCRYPT_BACKUP,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_BACKUPFILE);
		return 0;
	}

	req->mtime_sec = inode->i_mtime.tv_sec;
	req->mtime_nsec = inode->i_mtime.tv_nsec;
	req->file_size = size;

	send_data_to_user((char *)req, req->size, nl_file_pid, Probe_file);

	myfdebug("backup: [%d]path:%s, file_size:%lld, process:%s\n",
			op_type, pathname, req->file_size, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_BACKUPFILE);

	return 0;
}

/*
 * 检测是否为勒索进程，并通过返回值控制修复诱捕文件和阻断
 * 返回0不是勒索进程且不阻断
 * 返回-1，是勒索进程，不阻断
 * 返回-2，是勒索进程，阻断
 */
int check_encrypt(char *pathname, char *new_pathname,
		  struct parent_info *pinfo, int op_type,
		  struct inode *inode)
{
	int match = 0;
	int terminate = 0;
	filereq_t *req = NULL;
	char process_path[S_CMDLEN] = {0};
	char *comm = NULL;
	char md5[S_MD5LEN] = {0};
	int ret = 0;
	int retal = 0;
	int is_trust = 0;
	struct file_stat filestat = {0};

	if (!pathname || !pinfo || !inode) {
		return ret;
	}

	if (op_type == OP_RENAME && new_pathname == NULL) {
		return ret;
	}

	get_current_process(process_path, S_CMDLEN);
	comm = safebasename(process_path);

	read_lock(&sniper_fpolicy_lock);
	if (sniper_fpolicy.encrypt_on == 0) {
		read_unlock(&sniper_fpolicy_lock);
		return ret;
	}
	if (client_mode == NORMAL_MODE) {
		terminate = sniper_fpolicy.encrypt_terminate;
	} else {
		terminate = 0;
	}
	read_unlock(&sniper_fpolicy_lock);

	if ((pathname != NULL &&
	     strstr(pathname, TRAP_FILE_NOHIDE) != NULL) ||
	    (new_pathname != NULL &&
	     strstr(new_pathname, TRAP_FILE_NOHIDE) != NULL)) {
		match = 1;
	}

	if(match == 0) {
		return ret;
	}

	/* 过滤系统进程, 需要在匹配文件是诱捕文件之后, 方便恢复诱捕文件 */
	if (skip_process(process_path)) {
		ret = -1;
		return ret;
	}

	/* 对于手动执行rm,mv,vim,touch及图形界面操作诱捕文件 均做阻断不报日志处理 */
	if (((strcmp(comm, "rm") == 0 ||
	      strcmp(comm, "mv") == 0 ||
	      strcmp(comm, "sed") == 0 ||
	      strcmp(comm, "tar") == 0 ||
	      strcmp(comm, "rename") == 0 ||
	      strcmp(comm, "unlink") == 0 ||
	      strcmp(comm, "vim") == 0 ||
	      strcmp(comm, "userdel") == 0 ||
	      strcmp(comm, "touch") == 0) &&
	      strcmp(current->parent->comm, "bash") == 0) ||
	     (strcmp(current->parent->comm, "systemd") == 0) ||
	     (strcmp(comm, "nautilus") == 0)) {
		ret = -1;
		return ret;
	}

	/* 进程文件inode获取失败，不再继续匹配，返回-1，恢复诱捕文件 */
	if (get_file_stat(process_path, &filestat) < 0) {
		ret = -1;
		return ret;
	}

	/* md5获取失败, 不再继续匹配，返回-1，恢复诱捕文件 */
	retal = md5_path(process_path, md5, filestat.process_size);
	if (retal < 0) {
		ret = -1;
		return ret;
	}

	/*
	 * vsftpd,mounted,smbd为ftp,nfs,samba的守护进程,以及wine,
	 * 遇到这几个进程操作先全部报日志，待优化
	 */
	if (strncmp(comm, "vsftpd", 6) != 0 &&
	    strncmp(comm, "mounted", 7) != 0 &&
	    strncmp(comm, "smbd", 4) != 0 &&
	    strncmp(comm, "wine", 4) != 0) {

		/* 没有获取到进程文件的ctime, 不报告 */
		if (sniper_ctime == 0 || filestat.process_ctime == 0) {
			ret = -1;
			return ret;
		}

		/* 在sniper之前安装的进程判断为非勒索进程 */
		if (filestat.process_ctime < sniper_ctime) {
			ret = -1;
			return ret;
		}
	}

	if (terminate == 1) {
		ret = -2;
	} else {
		ret = -1;
	}

	/* 更新勒索缓存 */
	if (check_encrypt_cache(process_path, md5) == 0) {
		add_encrypt_record(process_path, md5);
	}

	/*
	 * 检查是否是可信名单进程，如果是则不报事件报普通日志,
	 * 并将勒索缓存进程中此进程记录删除
	 */
	if (check_trust_encrypt_process(process_path, md5) > 0) {
		check_delete_encrypt_record(process_path, md5);
		is_trust = 1;
		ret = -1;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_ENCRYPT);
	if (req == NULL) {
		myprintk("encrypt: malloc req buffer failed!\n");
		ret = -1;
		return ret;
	}
	memset(req, 0, ARGS_LEN);

	req->terminate = terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_ENCRYPT, op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_ENCRYPT);
		ret = -1;
		return ret;
	}

	req->mtime_sec = inode->i_mtime.tv_sec;
	req->mtime_nsec = inode->i_mtime.tv_nsec;
	req->file_size = i_size_read(inode);
	req->is_trust = is_trust;

	send_data_to_user((char *)req, req->size, nl_file_pid, Probe_file);

	myfdebug("ret:%d, encrypt: [%d]path:%s, process:%s\n",
			ret, op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_ENCRYPT);

	/* 杀死勒索进程 */
	if (ret == -2) {
		send_sig(SIGKILL, current, 1);
	}
	return ret;
}

/* 允许修改诱捕文件, 被修改后通知用户层，再重新创建 */
int report_trap_file_change(char *pathname, char *new_pathname,
			    struct parent_info *pinfo, int op_type,
			    struct inode *inode)
{
	int match = 0;
	filereq_t *req = NULL;
	char process_path[S_CMDLEN] = {0};

	if (!pathname || !pinfo || !inode) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);

	if ((pathname != NULL &&
	     strstr(pathname, TRAP_FILE_NOHIDE) != NULL) ||
	    (new_pathname != NULL &&
	     strstr(new_pathname, TRAP_FILE_NOHIDE) != NULL)) {
		match = 1;
	}

	if(match == 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_TRAPFILE);
	if (req == NULL) {
		myprintk("report trap file: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	if (set_send_msg(pathname, new_pathname,
				req, F_ENCRYPT_REPORT,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TRAPFILE);
		return 0;
	}

	req->mtime_sec = inode->i_mtime.tv_sec;
	req->mtime_nsec = inode->i_mtime.tv_nsec;
	req->file_size = i_size_read(inode);

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("report trap file: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_TRAPFILE);
	return 0;
}

/* 异常文件修改检测 */
int check_abnormal_change(char *pathname, char *new_pathname,
			  struct parent_info *pinfo, int op_type,
			  struct inode *inode)
{
	filereq_t *req = NULL;
	struct timeval tv = {0};
	char process_path[S_CMDLEN] = {0};
	char *comm = NULL;

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	comm = safebasename(process_path);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	/* 诱捕文件不报异常修改, /run/和/tmp/目录下不报异常修改 */
	if (strstr(pathname, TRAP_FILE_NOHIDE) != NULL ||
	    (strncmp(pathname, "/run/", 5) == 0 &&
	    strncmp(pathname, "/run/media/", 11) != 0) ||
	    strncmp(pathname, "/tmp/", 5) == 0) {
		return 0;
	}

	/* 查看缓存中是否有进程，如果空不用继续匹配 */
	if (check_encrypt_cache_pro() == 0) {
		return 0;
	}

	/* 匹配当前进程是否和缓存中进程 */
	if (check_match_abnormal_change(process_path) == 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_ABNORMALCHANGE);
	if (req == NULL) {
		myprintk("abnormal change: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_ABNORMAL,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_ABNORMALCHANGE);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("abnormal change: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_ABNORMALCHANGE);
	return 0;
}

/* 黑名单文件检测 */
int check_black_file_after(char *pathname, char *new_pathname,
			   struct parent_info *pinfo, int op_type,
			   struct inode *inode)
{
	int ret = 0, num =0;
	filereq_t *req = NULL;
	struct sniper_file_black *fblack = NULL;
	int terminate = 0;
	char *path = NULL;
	char process_path[S_CMDLEN] = {0};

	if (!pathname || !pinfo || !inode) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	/* 学习模式下规则不生效 */
	if (client_mode == LEARNING_MODE) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	if (op_type == OP_RENAME) {
		path = new_pathname;
	} else {
		path = pathname;
	}

	read_lock(&sniper_fblack_lock);

	if (sniper_fblack_count == 0 || !sniper_fblack) {
		read_unlock(&sniper_fblack_lock);
		return 0;
	}
	num = sniper_fblack_count;
	fblack = (struct sniper_file_black *)sniper_fblack;
	if (sniper_badptr(fblack)) {
		read_unlock(&sniper_fblack_lock);
		return 0;
	}

	ret = get_match_fblack_after_result(num, fblack, inode, path);

	read_unlock(&sniper_fblack_lock);

	if(ret < 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_BLACKFILE);
	if (req == NULL) {
		myprintk("file black: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	if (client_mode == OPERATION_MODE) {
		terminate = 0;
	} else {
		terminate = 1;
	}
	req->terminate = terminate;
	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_BLACK_AFTER,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_BLACKFILE);
		return 0;
	}

	req->mtime_sec = inode->i_mtime.tv_sec;
	req->mtime_nsec = inode->i_mtime.tv_nsec;
	req->file_size = i_size_read(inode);

	send_data_to_user((char *)req, req->size,
				nl_file_pid, Probe_file);

	myfdebug("file black after: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_BLACKFILE);

	return 0;
}

/* 病毒文件消息 */
int send_virus_file_msg(char *pathname, char *new_pathname,
			struct parent_info *pinfo, int op_type,
			struct inode *inode)
{
	filereq_t *req = NULL;
	struct timeval tv = {0};
	char process_path[S_CMDLEN] = {0};
	char *comm = NULL;

	/* antivirus thread not ready or monitor off */
	if (nl_virus_pid == 0 ||
	    !sniper_fpolicy.antivirus_on) {
		return 0;
	}

	if (!pathname ||
	    !pinfo ||
	    (!inode &&
	     op_type != OP_OPEN_C &&
	     op_type != OP_LINK)) {
		return 0;
	}

	if (op_type == OP_RENAME &&
	    new_pathname == NULL) {
		return 0;
	}

	get_current_process(process_path, S_CMDLEN);
	comm = safebasename(process_path);
	/* 过滤系统进程 */
	if (skip_process(process_path)) {
		return 0;
	}

	/* 诱捕文件不报病毒, /proc/和/sys/目录下不报病毒消息 */
	if (strstr(pathname, TRAP_FILE_NOHIDE) != NULL ||
	    strncmp(pathname, "/proc/", 6) == 0 ||
	    strncmp(pathname, "/sys/", 5) == 0) {
		return 0;
	}

	req = sniper_kmalloc(ARGS_LEN, GFP_ATOMIC, KMALLOC_VIRUS);
	if (req == NULL) {
		myprintk("virus: malloc req buffer failed!\n");
		return 0;
	}
	memset(req, 0, ARGS_LEN);

	memcpy(&req->pinfo, pinfo, sizeof(struct parent_info));
	if (set_send_msg(pathname, new_pathname,
				req, F_VIRUS,
				op_type, process_path) < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_VIRUS);
		return 0;
	}

	/* 创建打开或者硬链接的情况下获取当前的时间 */
	if (op_type == OP_OPEN_C || op_type == OP_LINK) {
		sniper_do_gettimeofday(&tv);
		req->mtime_sec = tv.tv_sec;
		req->mtime_nsec = tv.tv_usec*1000;
		req->file_size = 0;
	} else {
		req->mtime_sec = inode->i_mtime.tv_sec;
		req->mtime_nsec = inode->i_mtime.tv_nsec;
		req->file_size = i_size_read(inode);
	}

	send_data_to_user((char *)req, req->size,
				nl_virus_pid, Probe_file);

	myvdebug("virus: [%d]path:%s, process:%s\n",
			op_type, pathname, process_path);
	sniper_kfree(req, ARGS_LEN, KMALLOC_VIRUS);
	return 0;
}
