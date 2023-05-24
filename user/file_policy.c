#include "header.h"

struct kern_file_policy fpolicy = {0};

static int file_sensitive_mem_size = 0;
static int file_log_delete_mem_size = 0;
static int file_safe_mem_size = 0;
static int file_logcollector_mem_size = 0;
static int file_illegal_script_mem_size = 0;
static int file_webshell_detect_mem_size = 0;
static int file_black_mem_size = 0;
static int file_filter_mem_size = 0;
static int file_usb_mem_size = 0;
static int file_middleware_target_size = 0;
static int file_middleware_binary_size = 0;
static int file_middleware_script_size = 0;
static int file_encrypt_mem_size = 0;

static char *file_sensitive_mem = NULL;
static char *file_log_delete_mem = NULL;
static char *file_safe_mem = NULL;
static char *file_logcollector_mem = NULL;
static char *file_illegal_script_mem = NULL;
static char *file_webshell_detect_mem = NULL;
static char *file_black_mem = NULL;
static char *file_filter_mem = NULL;
static char *file_usb_mem = NULL;
static char *file_middleware_target_men = NULL;
static char *file_middleware_binary_men = NULL;
static char *file_middleware_script_men = NULL;
static char *file_encrypt_mem = NULL;

/* 根据策略启停cupsd */
void check_cupsd(int do_start)
{
	FILE *fp = NULL;
	pid_t pid = 0;
	char cmd[S_LINELEN] = {0};

	/* 检查cupsd进程是否在运行 */
	fp = fopen("/var/run/cups/cupsd.pid", "r");
	if (fp) {
		fscanf(fp, "%d", &pid);
		fclose(fp);
		get_proc_comm(pid, cmd);
		if (strcmp(cmd, "cupsd") != 0) {
			pid = 0; //没有cupsd
		}
	} else {
		pid = search_proc("cupsd", FULL_MATCH);
	}

	/* 禁止打印 */
	if (!do_start && fpolicy.printer_on && fpolicy.printer_terminate) {

		/* 运维模式下保持不变，不禁止打印功能 */
		if (client_mode_global == OPERATION_MODE) {
			return;
		}

		if (pid == 0) {
			INFO("disable printer. dont stop cupsd, cupsd not running\n");
			return;
		}

		INFO("disable printer, stop cupsd\n");
		system("service cups stop  2>/dev/null");
		system("service cupsd stop 2>/dev/null"); //打印服务应该是cups，保险起见也试一下cupsd
		kill(pid, SIGKILL);
		fp = fopen(CUPSD_FLAGFILE, "w");
		if (fp) {
			fclose(fp);
			INFO("create cupsd flag file %s\n", CUPSD_FLAGFILE);
			return;
		}

		MON_ERROR("create cupsd flag file %s fail: %s\n", CUPSD_FLAGFILE, strerror(errno));
		return;
	}

	/* 允许打印 */
	if (pid == 0) {
		if (access(CUPSD_FLAGFILE, F_OK) == 0) {
			system("service cups start  2>/dev/null");
			system("service cupsd start 2>/dev/null");
			INFO("start cupsd which stopped by me\n");
		} else {
			INFO("cupsd not running, dont start it, as it was not stopped by me\n");
		}
	}

	if (access(CUPSD_FLAGFILE, F_OK) == 0) {
		unlink(CUPSD_FLAGFILE);
		INFO("delete cupsd flag file %s\n", CUPSD_FLAGFILE);
	}
}

void dbg_record_to_file(char *flagfile, char *path, char *buf, int size)
{
	FILE *fp = NULL;

	if (!flagfile || access(flagfile, F_OK) != 0) {
		return;
	}

	if (!path || !buf || size == 0) {
		return;
	}

	fp = sniper_fopen(path, "w+", FILE_GET);
	if (fp == NULL) {
		printf("dbg open file %s failed\n", path);
		return;
	}

	if (fwrite(buf, size, 1, fp) != 1) {
		MON_ERROR("dbg write file %s failed\n", path);
		sniper_fclose(fp, FILE_GET);
		unlink(path);
		return ;
	}
	fflush(fp);
        sniper_fclose(fp, FILE_GET);

	return;
}

static int get_file_safe_size(void)
{
	int len = 0, num = 0;
	int i = 0, size = 0;

	num = protect_policy_global.sensitive_info.file_safe.list_num;
	for (i = 0; i < num; i++) {
		/* 路径 */
		len = strlen(protect_policy_global.sensitive_info.file_safe.list[i].path) + 1;
		size += len;

		/* 绝对路径 */
                if (protect_policy_global.sensitive_info.file_safe.list[i].real_path != NULL) {
                        len = strlen(protect_policy_global.sensitive_info.file_safe.list[i].real_path) + 1;
                        size += len;
                } else {
                        size += 1;
                }

		/* 文件 */
		len = strlen(protect_policy_global.sensitive_info.file_safe.list[i].name) + 1;
		size += len;

		/* 授权进程 */
		len = strlen(protect_policy_global.sensitive_info.file_safe.list[i].process) + 1;
		size += len;

		/* 检测动作 */
		len = strlen(protect_policy_global.sensitive_info.file_safe.list[i].operation) + 1;
		size += len;

		/* 是否阻断 */
		size += 4;
	}
	return size;
}

static int get_file_list_size(int num, POLICY_LIST *policy)
{
	int len = 0, size = 0;
	int i = 0;

	if (num == 0 || policy == NULL) {
		return 0;
	}

	for (i = 0; i < num; i++) {
		len = strlen(policy[i].list) + 1;
		size += len;
	}

	return size;
}

static int get_file_logcollector_size(void)
{
	int len = 0, size = 0;
	int num = 0;
	int i = 0;

	num = protect_policy_global.logcollector.file_list_num;
	for (i = 0; i < num; i++) {
		/* 路径 */
		len = strlen(protect_policy_global.logcollector.file_list[i].filepath) + 1;
		size += len;

		/* 绝对路径 */
		if (protect_policy_global.logcollector.file_list[i].real_path != NULL) {
			len = strlen(protect_policy_global.logcollector.file_list[i].real_path) + 1;
			size += len;
		} else {
			size += 1;
		}

		/* 文件类型 */
		len = strlen(protect_policy_global.logcollector.file_list[i].extension) + 1;
		size += len;
	}
	return size;
}

static int get_file_illegal_script_size(void)
{
	int len = 0, size = 0;
	int num = 0;
	int i = 0;

	num = protect_policy_global.sensitive_info.illegal_script.target_num;
	for (i = 0; i < num; i++) {
		/* 路径 */
		len = strlen(protect_policy_global.sensitive_info.illegal_script.target[i].path) + 1;
		size += len;

		/* 绝对路径 */
		if (protect_policy_global.sensitive_info.illegal_script.target[i].real_path != NULL) {
			len = strlen(protect_policy_global.sensitive_info.illegal_script.target[i].real_path) + 1;
			size += len;
		} else {
			size += 1;
		}

		/* 文件类型 */
		len = strlen(protect_policy_global.sensitive_info.illegal_script.target[i].extension) + 1;
		size += len;
	}
	return size;
}

static int get_file_webshell_detect_size(void)
{
	int len = 0, size = 0;
	int num = 0;
	int i = 0;

	num = protect_policy_global.sensitive_info.webshell_detect.target_num;
	for (i = 0; i < num; i++) {
		/* 路径 */
		len = strlen(protect_policy_global.sensitive_info.webshell_detect.target[i].path) + 1;
		size += len;

		/* 绝对路径 */
		if (protect_policy_global.sensitive_info.webshell_detect.target[i].real_path != NULL) {
			len = strlen(protect_policy_global.sensitive_info.webshell_detect.target[i].real_path) + 1;
			size += len;
		} else {
			size += 1;
		}

		/* 文件类型 */
		len = strlen(protect_policy_global.sensitive_info.webshell_detect.target[i].extension) + 1;
		size += len;
	}
	return size;
}

static int get_file_black_size(void)
{
	int len = 0, size = 0;
	int num = 0;
	int i = 0;

	num = rule_black_global.file_num;
	for (i = 0; i < num; i++) {
		/* 文件名 */
		len = strlen(rule_black_global.file[i].filename) + 1;
		size += len;

		/* 路径 */
		len = strlen(rule_black_global.file[i].filepath) + 1;
		size += len;

		/* md5 */
		len = strlen(rule_black_global.file[i].md5) + 1;
		size += len;
	}
	return size;
}

static int get_file_filter_size(void)
{
	int len = 0, size = 0;
	int num = 0;
	int i = 0;

	num = rule_filter_global.file_num;
	for (i = 0; i < num; i++) {
		/* 文件名 */
		len = strlen(rule_filter_global.file[i].filename) + 1;
		size += len;

		/* 路径 */
		len = strlen(rule_filter_global.file[i].filepath) + 1;
		size += len;

		/* md5 */
		len = strlen(rule_filter_global.file[i].md5) + 1;
		size += len;
	}
	return size;
}

static int get_file_usb_size(void)
{
	int len = 0, size = 0;
	int num = 0;
	int i = 0;

	num = mount_num;
	for (i = 0; i < num; i++) {
		/* 主设备号 */
		size += 4;

		/* 副设备号 */
		size += 4;

		/* 后缀名 */
		/* num不是策略中获取的，和extension没有绑定关系，因此要对extension做检查
 		*  如其他获取大小的函数中，num和字符串都是从策略中获取，如果字符串为空，在获取策略时会返回错误，而不会产生core
		*/
		if (protect_policy_global.sensitive_info.file_usb.extension == NULL) {
			size = 0;
			break;
		}

		len = strlen(protect_policy_global.sensitive_info.file_usb.extension) + 1;
		size += len;
	}
	return size;
}

static int get_file_encrypt_size(void)
{
	int len = 0, size = 0;

	/* 后缀名 */
	if (protect_policy_global.behaviour.ransomware.encrypt.my_linux.ext.list == NULL) {
		return 0;
	}

	len = strlen(protect_policy_global.behaviour.ransomware.encrypt.my_linux.ext.list) + 1;
	size += len;

	return size;
}

void update_kernel_file_sensitive_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_sensitive_mem_size;
	int num = protect_policy_global.sensitive_info.sensitive_file.list_num;
	POLICY_LIST *rule = NULL;

	size = get_file_list_size(num, protect_policy_global.sensitive_info.sensitive_file.list);
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file sensitive fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.sensitive_info.sensitive_file.list[i];
		ptr = copy_stringvalue(ptr, rule->list);
	}

	if (file_sensitive_mem && old_size == size &&
		memcmp(file_sensitive_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file sensitive, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_SENSITIVE_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_SENSITIVE, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file sensitive fail\n");
		return;
	}

out:
	sniper_free(file_sensitive_mem, old_size, FILE_GET);
	file_sensitive_mem_size = size;
	file_sensitive_mem = buf;
}

void update_kernel_log_delete_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_log_delete_mem_size;
	int num = protect_policy_global.sensitive_info.log_delete.list_num;
	POLICY_LIST *rule = NULL;

	size = get_file_list_size(num, protect_policy_global.sensitive_info.log_delete.list);
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file log_delete fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.sensitive_info.log_delete.list[i];
		ptr = copy_stringvalue(ptr, rule->list);
	}

	if (file_log_delete_mem && old_size == size &&
		memcmp(file_log_delete_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file log_delete, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_LOGDELETE_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_LOG_DELETE, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file log_delete fail\n");
		return;
	}

out:
	sniper_free(file_log_delete_mem, old_size, FILE_GET);
	file_log_delete_mem_size = size;
	file_log_delete_mem = buf;

}

void update_kernel_file_safe_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_safe_mem_size;
	int num = protect_policy_global.sensitive_info.file_safe.list_num;
	SAFE_FILE_LIST *rule = NULL;


	size = get_file_safe_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file safe fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.sensitive_info.file_safe.list[i];
		ptr = copy_stringvalue(ptr, rule->path);

		if (rule->real_path != NULL) {
			ptr = copy_stringvalue(ptr, rule->real_path);
		} else {
			*ptr = 0;
			ptr++;
		}

		ptr = copy_stringvalue(ptr, rule->name);
		ptr = copy_stringvalue(ptr, rule->process);
		ptr = copy_stringvalue(ptr, rule->operation);

		*ptr = rule->status;
		ptr += 4;
	}

	if (file_safe_mem && old_size == size &&
		memcmp(file_safe_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file safe, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_SAFE_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_SAFE, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file safe fail\n");
		return;
	}

out:
	sniper_free(file_safe_mem, old_size, FILE_GET);
	file_safe_mem_size = size;
	file_safe_mem = buf;
}

void update_kernel_file_logcollector_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_logcollector_mem_size;
	int num = protect_policy_global.logcollector.file_list_num;
	LOGCOLLECTOR_FILE_LIST *rule = NULL;


	size = get_file_logcollector_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file logcollector fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.logcollector.file_list[i];
		ptr = copy_stringvalue(ptr, rule->filepath);

		if (rule->real_path != NULL) {
			ptr = copy_stringvalue(ptr, rule->real_path);
		} else {
			*ptr = 0;
			ptr++;
		}

		ptr = copy_stringvalue(ptr, rule->extension);
	}

	if (file_logcollector_mem && old_size == size &&
		memcmp(file_logcollector_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file logcollector, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_LOGCOLLECTOR_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_LOGCOLLECTOR, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file logcollector fail\n");
		return;
	}

out:
	sniper_free(file_logcollector_mem, old_size, FILE_GET);
	file_logcollector_mem_size = size;
	file_logcollector_mem = buf;
}

void update_kernel_file_illegal_script_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_illegal_script_mem_size;
	int num = protect_policy_global.sensitive_info.illegal_script.target_num;
	ILLEGAL_SCRIPT_TARGET *rule = NULL;


	size = get_file_illegal_script_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file illegal_script fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.sensitive_info.illegal_script.target[i];
		ptr = copy_stringvalue(ptr, rule->path);

		if (rule->real_path != NULL) {
			ptr = copy_stringvalue(ptr, rule->real_path);
		} else {
			*ptr = 0;
			ptr++;
		}

		ptr = copy_stringvalue(ptr, rule->extension);
	}

	if (file_illegal_script_mem && old_size == size &&
		memcmp(file_illegal_script_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file illegal_script, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_ILLEGAL_SCRIPT_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_ILLEGAL_SCRIPT, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file illegal_script fail\n");
		return;
	}

out:
	sniper_free(file_illegal_script_mem, old_size, FILE_GET);
	file_illegal_script_mem_size = size;
	file_illegal_script_mem = buf;
}

void update_kernel_file_webshell_detect_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_webshell_detect_mem_size;
	int num = protect_policy_global.sensitive_info.webshell_detect.target_num;
	WEBSHELL_DETECT_TARGET *rule = NULL;


	size = get_file_webshell_detect_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file webshell_detect fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.sensitive_info.webshell_detect.target[i];
		ptr = copy_stringvalue(ptr, rule->path);

		if (rule->real_path != NULL) {
			ptr = copy_stringvalue(ptr, rule->real_path);
		} else {
			*ptr = 0;
			ptr++;
		}

		ptr = copy_stringvalue(ptr, rule->extension);
	}

	if (file_webshell_detect_mem && old_size == size &&
		memcmp(file_webshell_detect_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file webshell_detect, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_WEBSHELL_DETECT_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_WEBSHELL_DETECT, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file webshell_detect fail\n");
		return;
	}

out:
	sniper_free(file_webshell_detect_mem, old_size, FILE_GET);
	file_webshell_detect_mem_size = size;
	file_webshell_detect_mem = buf;
}

void update_kernel_file_black_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_black_mem_size;
	int num = rule_black_global.file_num;
	BLACK_FILE *rule = NULL;


	size = get_file_black_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file black fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &rule_black_global.file[i];
		ptr = copy_stringvalue(ptr, rule->filename);
		ptr = copy_stringvalue(ptr, rule->filepath);
		ptr = copy_stringvalue(ptr, rule->md5);
	}

	if (file_black_mem && old_size == size &&
		memcmp(file_black_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file black, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_FILEBLACK_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_BLACK, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file black fail\n");
		return;
	}

out:
	sniper_free(file_black_mem, old_size, FILE_GET);
	file_black_mem_size = size;
	file_black_mem = buf;
}

void update_kernel_file_filter_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_filter_mem_size;
	int num = rule_filter_global.file_num;
	FILTER_FILE *rule = NULL;


	size = get_file_filter_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file filter fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		rule = &rule_filter_global.file[i];
		ptr = copy_stringvalue(ptr, rule->filename);
		ptr = copy_stringvalue(ptr, rule->filepath);
		ptr = copy_stringvalue(ptr, rule->md5);
	}

	if (file_filter_mem && old_size == size &&
		memcmp(file_filter_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
 //               printf("skip update kernel file filter, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_FILEFILTER_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_FILTER, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file filter fail\n");
		return;
	}

out:
	sniper_free(file_filter_mem, old_size, FILE_GET);
	file_filter_mem_size = size;
	file_filter_mem = buf;
}

void update_kernel_file_usb_policy(void)
{
	int i = 0;
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_usb_mem_size;
	int num = mount_num;

	size = get_file_usb_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file usb path fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	for (i = 0; i < num; i++) {
		*ptr = mount_info[i].major;
		ptr += 4;
		*ptr = mount_info[i].minor;
		ptr += 4;
		ptr = copy_stringvalue(ptr, protect_policy_global.sensitive_info.file_usb.extension);
	}

	if (file_usb_mem && old_size == size &&
		memcmp(file_usb_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
 //               printf("skip update kernel file usb path, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_FILEUSB_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_USB, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file usb fail\n");
		return;
	}

out:
	sniper_free(file_usb_mem, old_size, FILE_GET);
	file_usb_mem_size = size;
	file_usb_mem = buf;
}

static void update_kernel_file_middleware_target_policy(void)
{
	int size = 0;
	char *buf = NULL, *target = NULL;

	target = protect_policy_global.sensitive_info.middleware.target;
	if (target == NULL) {
		return;
	}

	if (file_middleware_target_men && strcmp(file_middleware_target_men, target) == 0) {
		return;
	}

	size = strlen(target) + 1;
	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
		MON_ERROR("update_kernel_file_middleware_target_policy fail, no memory %d\n", size);
		return;
	}

	strncpy(buf, target, size);
	if (send_data_to_kern(NLMSG_FILE_MIDDLE_TARGET, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update_kernel_file_middleware_target_policy fail\n");
		return;
	}

	sniper_free(file_middleware_target_men, file_middleware_target_size, FILE_GET);
	file_middleware_target_size = size;
	file_middleware_target_men = buf;
}

static void update_kernel_file_middleware_binary_policy(void)
{
	int size = 0;
	char *buf = NULL, *ext = NULL;

	ext = protect_policy_global.sensitive_info.middleware.executable_files.ext;
	if (ext == NULL) {
		return;
	}

	if (file_middleware_binary_men && strcmp(file_middleware_binary_men, ext) == 0) {
		return;
	}

	size = strlen(ext) + 1;
	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
		MON_ERROR("update_kernel_file_middleware_binary_policy fail, no memory %d\n", size);
		return;
	}

	strncpy(buf, ext, size);
	if (send_data_to_kern(NLMSG_FILE_BINARY_FILTER, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update_kernel_file_middleware_binary_policy fail\n");
		return;
	}

	sniper_free(file_middleware_binary_men, file_middleware_binary_size, FILE_GET);
	file_middleware_binary_size = size;
	file_middleware_binary_men = buf;
}

static void update_kernel_file_middleware_script_policy(void)
{
	int size = 0;
	char *buf = NULL, *ext = NULL;

	ext = protect_policy_global.sensitive_info.middleware.script_files.ext;
	if (ext == NULL) {
		return;
	}

	if (file_middleware_script_men && strcmp(file_middleware_script_men, ext) == 0) {
		return;
	}

	size = strlen(ext) + 1;
	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
		MON_ERROR("update_kernel_file_middleware_script_policy fail, no memory %d\n", size);
		return;
	}

	strncpy(buf, ext, size);
	if (send_data_to_kern(NLMSG_FILE_MIDDLE_SCRIPT, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update_kernel_file_middleware_script_policy fail\n");
		return;
	}

	sniper_free(file_middleware_script_men, file_middleware_script_size, FILE_GET);
	file_middleware_script_size = size;
	file_middleware_script_men = buf;
}

void update_kernel_file_encrypt_policy(void)
{
	char *buf = NULL, *ptr = NULL;
	int size = 0;
	int old_size = file_encrypt_mem_size;
	RANSOMWARE_ENCRYPT *rule = NULL;


	size = get_file_encrypt_size();
	if (size == 0) {
		goto out;
	}

	buf = sniper_malloc(size, FILE_GET);
	if (!buf) {
               MON_ERROR("update kernel file encrypt fail, "
                        "no memory %d\n", size);
                return;
        }

        ptr = buf;
	rule = &protect_policy_global.behaviour.ransomware.encrypt;
	ptr = copy_stringvalue(ptr, rule->my_linux.ext.list);

	if (file_encrypt_mem && old_size == size &&
		memcmp(file_encrypt_mem, buf, size) == 0) {
                sniper_free(buf, size, FILE_GET);
//                printf("skip update kernel file encrypt, no change\n");
                return;
        }

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_ENCRYPT_TXT, buf, size);

	if (send_data_to_kern(NLMSG_FILE_ENCRYPT, buf, size) < 0) {
		sniper_free(buf, size, FILE_GET);
		MON_ERROR("update kernel file encrypt fail\n");
		return;
	}

out:
	sniper_free(file_encrypt_mem, old_size, FILE_GET);
	file_encrypt_mem_size = size;
	file_encrypt_mem = buf;
}

/* 关闭内核文件监控 */
void close_kernel_file_policy(void)
{
	int size = sizeof(struct kern_file_policy);
	struct kern_file_policy policy = {0};

	if (fpolicy.file_engine_on == 0) { //内核文件监控已关闭
		return;
	}

	if (send_data_to_kern(NLMSG_FILE_POLICY, (char *)&policy, size) < 0) {
		MON_ERROR("set kernel file policy off fail\n");
		return;
	}

	pthread_rwlock_wrlock(&protect_policy_global.lock);

	memset(&fpolicy, 0, size); //内核策略更新成功再清应用层策略
	/* TODO 策略空间释放,参照进程 */

	pthread_rwlock_unlock(&protect_policy_global.lock);
}

void update_kernel_file_policy(void)
{
	int size = sizeof(struct kern_file_policy);
	struct kern_file_policy new_fpolicy = {0};

	if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
                goto tellkern;
        }

	/* 文件行为采集等管控策略更新再赋值 */
	new_fpolicy.file_safe_on = protect_policy_global.sensitive_info.file_safe.enable;
	new_fpolicy.file_log_delete = protect_policy_global.sensitive_info.log_delete.enable;
	new_fpolicy.file_sensitive_on = protect_policy_global.sensitive_info.sensitive_file.enable;
	new_fpolicy.file_sensitive_kill = protect_policy_global.sensitive_info.sensitive_file.terminate;
	new_fpolicy.file_logcollector_on = protect_policy_global.logcollector.file_enable;
	new_fpolicy.file_middle_on = protect_policy_global.sensitive_info.middleware.enable;
	new_fpolicy.file_middle_binary_on = protect_policy_global.sensitive_info.middleware.executable_files.enable;
	new_fpolicy.file_middle_binary_exclude = protect_policy_global.sensitive_info.middleware.executable_files.exclude;
	new_fpolicy.file_middle_binary_terminate = protect_policy_global.sensitive_info.middleware.executable_files.terminate;
	new_fpolicy.file_middle_script_on = protect_policy_global.sensitive_info.middleware.script_files.enable;
	new_fpolicy.file_middle_script_terminate = protect_policy_global.sensitive_info.middleware.script_files.terminate;
	new_fpolicy.file_illegal_script_on = protect_policy_global.sensitive_info.illegal_script.enable;
	new_fpolicy.file_illegal_script_terminate = protect_policy_global.sensitive_info.illegal_script.terminate;
	new_fpolicy.file_webshell_detect_on = protect_policy_global.sensitive_info.webshell_detect.enable;
	new_fpolicy.file_webshell_detect_terminate = protect_policy_global.sensitive_info.webshell_detect.terminate;
	new_fpolicy.printer_on = fasten_policy_global.device.printer.enable;
	new_fpolicy.printer_terminate = fasten_policy_global.device.printer.terminate;
	new_fpolicy.cdrom_on = fasten_policy_global.device.cdrom.enable;
	new_fpolicy.cdrom_terminate = fasten_policy_global.device.cdrom.terminate;
	new_fpolicy.encrypt_on = protect_policy_global.behaviour.ransomware.encrypt.enable;
	new_fpolicy.encrypt_terminate = protect_policy_global.behaviour.ransomware.encrypt.terminate;
	new_fpolicy.encrypt_backup_on = protect_policy_global.behaviour.ransomware.encrypt.backup.enable;
	new_fpolicy.encrypt_space_full = backup_space_full;
	new_fpolicy.encrypt_hide_on = protect_policy_global.behaviour.ransomware.encrypt.hide;
	new_fpolicy.usb_file_on = protect_policy_global.sensitive_info.file_usb.enable;

#ifdef USE_AVIRA
	/* 病毒防护的开关先放在文件的策略里 */
	new_fpolicy.antivirus_on = antivirus_policy_global.real_time_check.enable;
#else
	new_fpolicy.antivirus_on = TURN_MY_OFF;
#endif

	if (new_fpolicy.file_safe_on ||
	    new_fpolicy.file_log_delete ||
	    new_fpolicy.file_logcollector_on ||
	    new_fpolicy.file_middle_on ||
	    new_fpolicy.file_illegal_script_on ||
	    new_fpolicy.file_webshell_detect_on ||
	    new_fpolicy.encrypt_on ||
	    new_fpolicy.usb_file_on ||
	    new_fpolicy.antivirus_on) {
		new_fpolicy.file_engine_on = TURN_MY_ON;
	}


	new_fpolicy.sensitive_count = protect_policy_global.sensitive_info.sensitive_file.list_num;
	new_fpolicy.log_delete_count = protect_policy_global.sensitive_info.log_delete.list_num;
	new_fpolicy.safe_count = protect_policy_global.sensitive_info.file_safe.list_num;
	new_fpolicy.logcollector_count = protect_policy_global.logcollector.file_list_num;
	new_fpolicy.illegal_script_count = protect_policy_global.sensitive_info.illegal_script.target_num;
	new_fpolicy.webshell_detect_count = protect_policy_global.sensitive_info.webshell_detect.target_num;
	new_fpolicy.printer_count = fasten_policy_global.device.printer.ext_num;
	new_fpolicy.cdrom_count = fasten_policy_global.device.cdrom.ext_num;
	new_fpolicy.black_count = rule_black_global.file_num;
	new_fpolicy.filter_count = rule_filter_global.file_num;
	new_fpolicy.usb_count = mount_num;
	new_fpolicy.neglect_min = protect_policy_global.behaviour.ransomware.encrypt.backup.neglect_min;
	new_fpolicy.neglect_size = protect_policy_global.behaviour.ransomware.encrypt.backup.neglect_size;

tellkern:
	if (memcmp(&new_fpolicy, &fpolicy, size) != 0) {
                if (send_data_to_kern(NLMSG_FILE_POLICY,
                                (char *)&new_fpolicy, size) < 0) {
//                        MON_ERROR("set kern file policy fail\n");
                        return;
                }
                fpolicy = new_fpolicy;
        }
	check_cupsd(0);

	if (!new_fpolicy.file_engine_on) {
		/* TODO 策略空间释放,参照进程 */
		return;
	}

	if (new_fpolicy.sensitive_count) {
		update_kernel_file_sensitive_policy();
	}

	if (new_fpolicy.log_delete_count) {
		update_kernel_log_delete_policy();
	}

	if (new_fpolicy.safe_count) {
		update_kernel_file_safe_policy();
	}

	if (new_fpolicy.logcollector_count) {
		update_kernel_file_logcollector_policy();
	}

	if (new_fpolicy.illegal_script_count) {
		update_kernel_file_illegal_script_policy();
	}

	if (new_fpolicy.webshell_detect_count) {
		update_kernel_file_webshell_detect_policy();
	}

	if (new_fpolicy.black_count) {
		update_kernel_file_black_policy();
	}

	if (new_fpolicy.filter_count) {
		update_kernel_file_filter_policy();
	}

	if (new_fpolicy.usb_count) {
		update_kernel_file_usb_policy();
	}

	update_kernel_file_middleware_target_policy();
	update_kernel_file_middleware_binary_policy();
	update_kernel_file_middleware_script_policy();

	update_kernel_file_encrypt_policy();
}
