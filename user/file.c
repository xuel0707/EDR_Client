/* std */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <dirent.h>
#include <pcre.h>

/* netlink */
#include <sys/socket.h>
#include <linux/netlink.h>

#include <pwd.h>
#include <linux/limits.h>
#include <libgen.h>

#include "header.h"
#include "file.h"

#define MAX_FILE_SIZE (1048576)  /*1MB */
#define MAX_KEYWORD_LEN 50
#define MAX_RENAME_LEN		400
#define RENAME_FILE_LEN		199
#define INI_FILES_NUM		2
/*ini_file_type*/
#define INI_FILE_USER	0
#define INI_FILE_GROUP	1
#define INI_FILE_HOSTS	4

#define FILE_EXTENSION_TYPE		9
#define FILE_CONTENT_TYPE		8
#define RECORD_MAX			1024*1024
#define FILE_DEFENSE_POST_MAX		2048
#define FILE_SIZE_STR_MAX		128

#define MAX_PATH_LEN  			512
#define MAX_LINE_LEN  			3000

#define OVECCOUNT 30 /* should be a multiple of 3 */

#define PASSWD_FILE	"/etc/passwd"
#define GROUP_FILE	"/etc/group"
#define INITD_FILE	"/etc/rc.d/rc.local"
#define TRASH_DIR "/opt/snipercli/.mondb/.backup/"

int backup_size = 0;

char none_extension[4]="";

#define WF_CACHE_NUM 16
static int next_wfidx = 0;
struct written_file_info {
        ino_t inode;
        unsigned long mtime_sec;
        unsigned long mtime_nsec;
} wfinfo[WF_CACHE_NUM] = {{0}};

char* get_path_types(char *path)
{
	char* postfix = NULL;

	if (path == NULL) {
		return NULL;
	}

	postfix = strrchr(path, '.');
	
	
	if (postfix != NULL && strlen(postfix) > 1) {
		postfix++;
		return postfix;
	}

	return none_extension;
}

int file_monitor_mk_trashdir(void)
{
	int ret=0;

	ret = mkdir(TRASH_DIR, 0700);
	if (ret < 0) {
		if (errno == EEXIST) {
			struct stat buf;
			ret = stat(TRASH_DIR, &buf);
			if (ret == 0 && !S_ISDIR(buf.st_mode)) {
				ret = unlink(TRASH_DIR);
				if (ret == 0) {
					ret = mkdir(TRASH_DIR, 0700);
				}
			}
		}
	}

	if (ret < 0) {
		MON_ERROR("make file_monitor trashdir failed!\n");
	}

	return ret;
}

int get_report_file_path(char *path, int len, char* file)
{
	if (!path) {
		return -1;
	}

	int namelen = 0, tmplen = 0;
	char *pstr = NULL;
	char *qstr = NULL;

	namelen = strlen(file);
	if (namelen <= len) {
		strncpy(file, path, len);
		file[len-1] = 0;
		return 0;
	}

	tmplen = namelen - len;
	qstr = file + tmplen + 3;

	pstr = strchr(qstr, '/');
	if (pstr == NULL) {
		snprintf(file, len, "...%s", qstr);
	} else {
		snprintf(file, len, "...%s", pstr);
	}
	return 0;
}

int check_dir_maxsize(char *path, unsigned long maxsize)
{
	DIR *dp = NULL;
	DIR *child_dp = NULL;
	struct dirent *dirp;
	struct dirent *child_dirp;
	unsigned long size = 0;
	struct stat st = {0};
	char name[PATH_MAX] = {0};
	char child_name[PATH_MAX] = {0};
	int ret = 0;

	dp = opendir(path);
	if (dp == NULL) {
		MON_ERROR("open %s failed!\n", path);
		return -1;
	}

	while ((dirp = readdir(dp))) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0) {
			continue;
		}

		snprintf(name, PATH_MAX, "%s/%s", path, dirp->d_name);

		child_dp = opendir(name);
		if (child_dp == NULL) {
			DBG2(DBGFLAG_POST_LEVEL2, "open dir %s fail: %s\n",
				name, strerror(errno));
			/* 计算普通文件大小 */
			if(stat(name, &st) < 0) {
				continue;
			}

			/* 累计的空间大于设定的大小不再继续检测后续的目录和文件大小 */
			size += st.st_size;
			if(size >= maxsize) {
				ret = -1;
				break;
			}
			continue;
		}

		/* 计算子日志目录下的文件大小，不考虑还会出现目录的情况 */
		while ((child_dirp = readdir(child_dp))) {
			if (strcmp(child_dirp->d_name, ".") == 0 ||
				strcmp(child_dirp->d_name, "..") == 0) {
				continue;
			}

			snprintf(child_name, PATH_MAX, "%s/%s/%s", path, dirp->d_name, child_dirp->d_name);

			if (stat(child_name, &st) < 0) {
				continue;
			}

			/* 累计的空间大于设定的大小不再继续检测后续的文件大小 */
			size += st.st_size;
			if (size >= maxsize) {
				ret = -1;
				break;
			}

			continue;
		}
		closedir(child_dp);

		/* 已经检测到空间大小超过，退出循环检测 */
		if (ret == -1) {
			break;
		}

	}
	closedir(dp);

	return ret;
}

void get_file_event_operating(int type, char *operating)
{
	if (type == OP_OPEN) {
		strncpy(operating, "Access", OP_LEN_MAX);
	} else if (type == OP_OPEN_W) {
		strncpy(operating, "Change", OP_LEN_MAX);
	} else if (type == OP_OPEN_C || type == OP_LINK) {
		strncpy(operating, "Created", OP_LEN_MAX);
	} else if (type == OP_CLOSE) {
		strncpy(operating, "Created;Write", OP_LEN_MAX);
	} else if (type == OP_WRITE) {
		strncpy(operating, "Created;Write", OP_LEN_MAX);
	} else if (type == OP_READ) {
		strncpy(operating, "Read", OP_LEN_MAX);
	} else if (type == OP_UNLINK) {
		strncpy(operating, "Deleted", OP_LEN_MAX);
	} else if (type == OP_RENAME) {
		strncpy(operating, "Rename", OP_LEN_MAX);
	} else {
		strncpy(operating, "Unkown", OP_LEN_MAX);
	}
	operating[OP_LEN_MAX - 1] = '\0';

	return;
}

static int is_illegal_script(char *filename, char *keyword, off_t size)
{
	FILE *fp = NULL;
	char *buf = NULL, *str = NULL;
	int i = 0, ret = 0, rule_len = 0;
	off_t bufsize = 0;

	if (!filename || !keyword) {
		return 0;
	}

	if (size < MAX_FILE_SIZE) {
		bufsize = size;
	} else {
		bufsize = MAX_FILE_SIZE;
	}

	fp = sniper_fopen(filename, "r", FILE_GET);
	if (fp == NULL) {
		return 0;
	}

	buf = calloc(bufsize, 1);
	if (buf == NULL) {
		sniper_fclose(fp, FILE_GET);
		return 0;
	}

	if ((fread(buf, bufsize, 1, fp) < 0) && !feof(fp)) {
		free(buf);
		sniper_fclose(fp, FILE_GET);
		return 0;
	}
	sniper_fclose(fp, FILE_GET);

	pthread_rwlock_rdlock(&protect_policy_global.lock);
	/* 匹配系统默认审查库 */
	for (i = 0; i < protect_policy_global.sensitive_info.illegal_script.default_keyword_num; i++) {
		str = protect_policy_global.sensitive_info.illegal_script.default_keyword[i].list;
		rule_len  = strlen(str);
		if (rule_len > 0 && rule_len < MAX_KEYWORD_LEN && strstr(buf, str)) {
			strncpy(keyword, str, rule_len);
			keyword[rule_len] = 0;
			ret = 1;
			break;
		}
	}

	/* 匹配自定义关键字 */
	if (ret != 1) {
		for (i = 0; i < protect_policy_global.sensitive_info.illegal_script.keyword_num; i++) {
			str = protect_policy_global.sensitive_info.illegal_script.keyword[i].list;
			rule_len  = strlen(str);
			if (rule_len > 0 && rule_len < MAX_KEYWORD_LEN && strstr(buf, str)) {
				strncpy(keyword, str, rule_len);
				keyword[rule_len] = 0;
				ret = 1;
				break;
			}
		}
	}

	pthread_rwlock_unlock(&protect_policy_global.lock);

	free(buf);
	return ret;
}

int match_webshell_rule(char *str, char *buf, struct file_msg_args *msg, int id)
{
	pcre *re;
	const char *error;
	int erroffset;
	int ovector[OVECCOUNT];
	int rc;
	int len = 0;

	re = pcre_compile(str, PCRE_CASELESS|PCRE_MULTILINE, &error, &erroffset, NULL);
	if (re == NULL) {
		MON_ERROR("webshell compile id:%d rule(%s) failed at offset %d: %s\n", id, str, erroffset, error);
		return -1;
	}

	rc = pcre_exec(re, NULL, buf, strlen(buf), 0, 0, ovector, OVECCOUNT);
	if (rc < 0) {
		free(re);
		return -1;
	}

	len = ovector[1] - ovector[0];
	if (len > STRLEN_MAX) {
		len = STRLEN_MAX - 1;
	}
	memcpy(msg->webshell_match_content, buf + ovector[0], len);
	msg->webshell_match_content[len] = '\0';
	INFO("msg->webshell_match_content:%s\n", msg->webshell_match_content);
	free(re);
	return 1;	
}

static int is_regex_match(char *filename, off_t size, struct file_msg_args *msg)
{
	FILE *fp = NULL;
	char *buf = NULL, *str = NULL;
	int i = 0, is_match = 0;
	int level = 0;
	off_t bufsize = 0;

	if (!filename) {
		return 0;
	}

	if (size < MAX_FILE_SIZE) {
		bufsize = size;
	} else {
		bufsize = MAX_FILE_SIZE;
	}

	fp = sniper_fopen(filename, "r", FILE_GET);
	if (fp == NULL) {
		return 0;
	}

	buf = calloc(bufsize, 1);
	if (buf == NULL) {
		sniper_fclose(fp, FILE_GET);
		return 0;
	}

	if ((fread(buf, bufsize, 1, fp) < 0) && !feof(fp)) {
		free(buf);
		sniper_fclose(fp, FILE_GET);
		return 0;
	}
	sniper_fclose(fp, FILE_GET);

	pthread_rwlock_rdlock(&webshell_detect_global.lock);
	/* 匹配webshell库 */
	for (i = 0; i < webshell_detect_global.rule_num; i++) {
		str = webshell_detect_global.webshell_rule[i].regex;
		is_match = match_webshell_rule(str, buf, msg, webshell_detect_global.webshell_rule[i].id);
		if (is_match > 0) {
			DBG2(DBGFLAG_WEBSHELL, "id:%d, level:%d, desc:(%s),str:(%s)\n", 
				webshell_detect_global.webshell_rule[i].id,
				webshell_detect_global.webshell_rule[i].level,
				webshell_detect_global.webshell_rule[i].description, str);
			msg->webshell_rule_id = webshell_detect_global.webshell_rule[i].id;
			msg->webshell_rule_level = webshell_detect_global.webshell_rule[i].level;
			strncpy(msg->webshell_rule_regex, str, STRLEN_MAX);
			msg->webshell_rule_regex[STRLEN_MAX-1] = '\0';
			strncpy(msg->webshell_rule_desc, webshell_detect_global.webshell_rule[i].description, STRLEN_MAX);
			msg->webshell_rule_desc[STRLEN_MAX-1] = '\0';
			level = msg->webshell_rule_level > level ? msg->webshell_rule_level : level;
			if (level >= WEBSHELL_HIGH_LEVEL) {
				break;
			}
		}
	}

	pthread_rwlock_unlock(&webshell_detect_global.lock);

	free(buf);
	return level;
}

int check_filter_after(char *pathname, char *md5, char *process_path) 
{
	int ret = -1;
	int i = 0, num = 0;
	char *name = NULL;
	char *process_name = NULL;
	int name_match = 0;
	int md5_match = 0;

	if (!pathname || !md5 || !process_path) {
		return -1;
	}

	/* 学习和运维模式下不匹配规则 */
	if (client_mode_global == LEARNING_MODE ||
	    client_mode_global == OPERATION_MODE) {
		return -1;
	}

	name = safebasename(pathname);
	if (name == NULL) {
		return -1;
	}

	process_name = safebasename(process_path);
	if (process_name == NULL) {
		return -1;
	}

	pthread_rwlock_rdlock(&rule_filter_global.lock);
	num = rule_filter_global.file_num;
	for (i = 0; i < num; i++) {
		name_match = 0;
		md5_match = 0;

		/* 有进程路径且不匹配 */
		if (rule_filter_global.file[i].process_path[0] != '\0' &&
		    strcmp(rule_filter_global.file[i].process_path, process_path) != 0) {
			continue;
		}

		/* 有进程名称且不匹配 */
		if (rule_filter_global.file[i].process_name[0] != '\0' &&
		    strcmp(rule_filter_global.file[i].process_name, process_name) != 0) {
			continue;
		}

		/* 有文件路径且不匹配 */
		if (rule_filter_global.file[i].filepath[0] != '\0' &&
		    !wildcard_string_match(rule_filter_global.file[i].filepath, pathname)) {
			continue;
		}

		/*
		 * 管控处文件名和md5至少需要一个，将这两个放在最后比较，
		 * 如果没填则认为匹配，必须两个都匹配才算真的匹配 
		 */

		/* 有文件名(包含通配符)且不匹配时进行下一个比较，否则算作匹配 */
		if (rule_filter_global.file[i].filename[0] != '\0' &&
		    !wildcard_string_match(rule_filter_global.file[i].filename, name)) {
                        continue;
                } else {
			name_match = 1;
		}

		/* 有md5且不匹配时进行下一个比较，否则算作匹配 */
		if (rule_filter_global.file[i].md5[0] != '\0' &&
			strcmp(rule_filter_global.file[i].md5, md5) != 0) {
			continue;
		} else {
			md5_match = 1;
		}

		if (name_match == 1 && md5_match ==1) {
			ret = 0;
		}

	}
	pthread_rwlock_unlock(&rule_filter_global.lock);	

	return ret;
}

int check_trust_after(char *pathname, char *md5, int type, char *process_path) 
{
	int i = 0, num = 0;
	char *name = NULL;
	char *process_name = NULL;
	int trust_flag = 0;
	int name_match = 0;
	int md5_match = 0;

	/* 学习和运维模式下不匹配规则 */
	if (client_mode_global == LEARNING_MODE ||
	    client_mode_global == OPERATION_MODE) {
		return 0;
	}

	name = safebasename(pathname);
	if (name == NULL) {
		return 0;
	}

	process_name = safebasename(process_path);
	if (process_name == NULL) {
		return 0;
	}

	pthread_rwlock_rdlock(&rule_trust_global.lock);
	num = rule_trust_global.file_num;
	for (i = 0; i < num; i++) {
		name_match = 0;
		md5_match = 0;
		/*匹配应用的模块, */
		if ((type == F_BINARY_FILTER && !(rule_trust_global.file[i].event_flags & EVENT_ExecutableFiles)) ||
		    (type == F_MIDDLE_SCRIPT && !(rule_trust_global.file[i].event_flags & EVENT_ScriptFiles)) ||
		    (type == F_ILLEGAL_SCRIPT && !(rule_trust_global.file[i].event_flags & EVENT_IllegalScriptFiles)) ||
		    (type == F_WEBSHELL_DETECT && !(rule_trust_global.file[i].event_flags & EVENT_Webshell_detect))) {
			continue;	
		}

		/* 有进程路径且不匹配 */
		if (rule_trust_global.file[i].process_path[0] != '\0' &&
		    strcmp(rule_trust_global.file[i].process_path, process_path) != 0) {
			continue;
		}

		/* 有进程名称且不匹配 */
		if (rule_trust_global.file[i].process_name[0] != '\0' &&
		    strcmp(rule_trust_global.file[i].process_name, process_name) != 0) {
			continue;
		}

		/* 有文件路径且不匹配 */
		if (rule_trust_global.file[i].filepath[0] != '\0' &&
		    !wildcard_string_match(rule_trust_global.file[i].filepath, pathname)) {
			continue;
		}

		/*
		 * 管控处文件名和md5至少需要一个，将这两个放在最后比较，
		 * 如果没填则认为匹配，必须两个都匹配才算真的匹配 
		 */

		/* 有文件名(包含通配符)且不匹配时进行下一个比较，否则算作匹配 */
		if (rule_trust_global.file[i].filename[0] != '\0' &&
		    !wildcard_string_match(rule_trust_global.file[i].filename, name)) {
                        continue;
                } else {
			name_match = 1;
		}

		/* 有md5且不匹配时进行下一个比较，否则算作匹配 */
		if (rule_trust_global.file[i].md5[0] != '\0' &&
			strcmp(rule_trust_global.file[i].md5, md5) != 0) {
			continue;
		} else {
			md5_match = 1;
		}

		if (name_match == 1 && md5_match == 1) {
			if (type == F_BINARY_FILTER) {
				trust_flag |= EVENT_ExecutableFiles;
			} else if (type == F_MIDDLE_SCRIPT) {
				trust_flag |= EVENT_ScriptFiles;
			} else if (type == F_ILLEGAL_SCRIPT) {
				trust_flag |= EVENT_IllegalScriptFiles;
			} else if (type == F_WEBSHELL_DETECT) {
				trust_flag |= EVENT_Webshell_detect;
			}
		}
	}
	pthread_rwlock_unlock(&rule_trust_global.lock);	

	return trust_flag;
}

static int check_black_after(char *md5) 
{
	int ret = -1;
	int i = 0, num = 0;

	if (md5 == NULL || md5[0] == '\0') {
		return -1;
	}

	pthread_rwlock_rdlock(&rule_black_global.lock);
	num = rule_black_global.file_num;
	for (i = 0; i < num; i++) {
		/* 有md5且匹配 */
		if (rule_black_global.file[i].md5[0] != '\0' &&
			strcmp(rule_black_global.file[i].md5, md5) == 0) {
			ret = 0;
			break;
		}


	}
	pthread_rwlock_unlock(&rule_black_global.lock);	

	return ret;
}

/* 检查规则中的过滤进程，是返回1，否返回0, 适用于所有文件消息 */
int check_process_filter_pro(char *process, char*md5)
{
	char *cmd = NULL;
	int num = 0;
	int i = 0;
	FILTER_PROCESS *rule = NULL;
	int match = 0;

	cmd = safebasename(process);
	pthread_rwlock_rdlock(&rule_filter_global.lock);
	num = rule_filter_global.process_num;
	for (i = 0; i < num; i++) {
		rule = &rule_filter_global.process[i];

		/* 检查进程路径是否正确 */
		if (rule->process_path[0] != 0 &&
		    strcmp(rule->process_path, process) != 0) {
			continue;
		}

		/* 检查进程名称是否正确 */
		if (rule->process_name[0] != 0 &&
		    strcmp(rule->process_name, cmd) != 0) {
			continue;
		}

		/* 检查进程md5值是否正确 */
		if (rule->md5[0] != 0 &&
		    strcmp(rule->md5, md5) != 0) {
			continue;
		}
		
		match = 1;
		break;
	}
	pthread_rwlock_unlock(&rule_filter_global.lock);
	
	return match;
}
#if 0
static int check_middle_binary(filereq_t *rep, struct file_msg_args *msg)
#else 
static int check_middle_binary(struct ebpf_filereq_t *rep, struct file_msg_args *msg)
#endif
{
	int match = 0;

	if (get_file_type(msg->pathname) == EXEC_FILE) {
		match = 1;
	}

	if (!match && rep->op_type == OP_RENAME) {

		/*部分机器move新文件没有这边处理的快，读不到新文件。睡眠100毫秒*/
		usleep(100000);

		if (get_file_type(msg->pathname_new) == EXEC_FILE) {
			match = 1;
		}
	}

	return match;
}
#if 0
static int check_illegal_script(filereq_t *rep, struct file_msg_args *msg, char *keyword)
#else
static int check_illegal_script(struct ebpf_filereq_t *rep, struct file_msg_args *msg, char *keyword)
#endif
{
	int match = 0;

	if (is_illegal_script(msg->pathname, keyword, msg->file_size)) {
		match = 1;
	}

	if (!match && rep->op_type == OP_RENAME) {

		/*部分机器move新文件没有这边处理的快，读不到新文件。睡眠100毫秒*/
		usleep(100000);

		if (is_illegal_script(msg->pathname_new, keyword, msg->file_size)) {
			match = 1;
		}
	}

	return match;
}

#if 0
static int regex_detect(filereq_t *rep, struct file_msg_args *msg)
#else
static int regex_detect(struct ebpf_filereq_t *rep, struct file_msg_args *msg)
#endif
{
	int ret = 0;

	ret = is_regex_match(msg->pathname, msg->file_size, msg);

	if (!ret && rep->op_type == OP_RENAME) {

		/*部分机器move新文件没有这边处理的快，读不到新文件。睡眠100毫秒*/
		usleep(100000);

		ret = is_regex_match(msg->pathname_new, msg->file_size, msg);
	}

	return ret;
}

/* 解析长亭webshell引擎的得分，获取匹配的规则信息添加到描述中 */
static void add_cloudwalker_detect_desc(int score, char *desc) 
{
	int tmp = 0, num = 0;
	char *p= NULL;
	char *statistics_str = "匹配统计规则;";
	char *hash_str = "匹配模糊哈希规则;";
	char *machine_learn_str = "匹配机器学习规则;";
	int max_len = 0;
	int len = 0;

	if (desc == NULL) {
		return;
	}

	tmp = score;
	p = desc;

	/* 个十百千位分别对应引擎的正则，统计，哈希，机器学习规则，1代表命中，0代表没有命中 */
	/* 例如1001，代表只匹配了机器学习和正则 */

	/* 检测千位是否为1 */
	num = tmp/1000;
	if (num == 1) {
		len = strlen(machine_learn_str);
		max_len += len;
		if (max_len >= STRLEN_MAX) {
			return;
		} 
		strncpy(p, machine_learn_str, len);
		p += len;
	}
	tmp %= 1000;

	/* 检测百位是否为1 */
	num = tmp/100;
	if (num == 1) {
		len = strlen(hash_str);
		max_len += len;
		if (max_len >= STRLEN_MAX) {
			return;
		} 
		strncpy(p, hash_str, len);
		p += len;
	}
	tmp %= 100;

	/* 检测十位是否为1 */
	num = tmp/10;
	if (num == 1) {
		len = strlen(statistics_str);
		max_len += len;
		if (max_len >= STRLEN_MAX) {
			return;
		}
		strncpy(p, statistics_str, len);
		p += len;
	}

	return;
}

/* 调用go webshell引擎检测(cloudwalker)获取返回值, -1为检测错误，0为判定不是webshell, 个十百千位分别对应引擎的正则，统计，哈希，机器学习规则 */
static int get_cloudwalker_exec_value(char *path)
{
	FILE *pp = NULL;
	char command[PATH_MAX + 40] = {0};
	char line[S_LINELEN] = {0};
	int score = 0;

	snprintf(command, sizeof(command), "/opt/snipercli/webshell_detector %s", path);

	pp = popen(command, "r");
	if (pp == NULL) {
		return -1;
	}

	if (fgets(line, sizeof(line), pp) == NULL) {
		pclose(pp);
		return -1;
	}
	pclose(pp);

	score = atoi(line);	
	DBG2(DBGFLAG_WEBSHELL, "webshell strictly detect socre:%d\n", score);
	if (score < -1 || score > 1111) {
		return -1;
	}

	return score;
}

/* 用长亭的webshell引擎检测，返回值为引擎执行的得分 */
#if 0
static int cloudwalker_detect(filereq_t *rep, struct file_msg_args *msg, char *desc)
#else
static int cloudwalker_detect(struct ebpf_filereq_t *rep, struct file_msg_args *msg, char *desc)
#endif
{
	int ret = 0;

	ret = get_cloudwalker_exec_value(msg->pathname);
	if (ret > 1) {
		add_cloudwalker_detect_desc(ret, desc);
	}

	if (ret <= 1 && rep->op_type == OP_RENAME) {

		/*部分机器move新文件没有这边处理的快，读不到新文件。睡眠100毫秒*/
		usleep(100000);

		ret = get_cloudwalker_exec_value(msg->pathname_new);
		if (ret > 1) {
			add_cloudwalker_detect_desc(ret, desc);
		}
	}

	return ret;
}

/* 根据异常检测的得分添加对应的描述信息 */
static void add_abnormal_detect_desc(int score, char *desc) 
{
	char *long_line_str = "格式不规范，单行过长";
	char *same_len_line_str = "格式不规范，大量连续相同长度行";
	if (score == 1) {
		snprintf(desc, STRLEN_MAX, "%s", long_line_str);
	} else if (score == 2) {
		snprintf(desc, STRLEN_MAX, "%s", same_len_line_str);
	}
	
	return;
}

/* 检测文件并返回结果，-1为错误，0为正常，1为位单行过长(大于3000个字节), 2为连续相同长度的行(至少300行) */
static int get_abnormal_file_value(char *path)
{
	int ret = 0;
	FILE *fp = NULL;
	char line[MAX_LINE_LEN+1] = {0};
	int len = 0, lastlen = 0, maxlen = 0, minlen = 30;
	int count = 0, min_count = 0, basic_count = 300;

	if (!path) {
		return -1;
	}

	fp = sniper_fopen(path, "r", FILE_GET);
        if (!fp) {
                return -1;
        }

	/* 
	 * 编码绕过的一种类型webshell特征是转码的部分写在一行中(长度超过3000)，
	 * 或者拆分成连续相同长度的很多行(单行超过30，且连续相同长度行至少300行)
	 * 这种类型的webshell通过c正则检测接口cpu持续负载过高导
	 */
	while (fgets(line, sizeof(line), fp)) {

		len = strlen(line);

		/* 单行过长的情况 */
		maxlen = maxlen > len? maxlen : len;
		if (maxlen >= MAX_LINE_LEN) {
			ret = 1;
			break;
		}

		/* 计算连续相同长度行的计数 */
		if (len != lastlen) {
			lastlen = len;
			count = 0;
		} else {
			count++;
		}

		/* 连续相同长度行的情况 */
		if (len > minlen) {
			/* 
 			* 单行长度不一的时候, 比较的连续相同长度行计数应该不一样 
 			* 此处设置了一个300行作为判断的基本条件，防止误报
 			*/
			min_count = MAX_LINE_LEN / len;
			if (count > min_count && count > basic_count) {
				ret = 2;
				break;
			}
		}
	}
	sniper_fclose(fp, FILE_GET);

	return ret;
}

/* 检测文件是否为异常文件(单行过长或连续相同长度的行), 返回值为检测的得分 */
#if 0
static int abnormal_file_detect(filereq_t *rep, struct file_msg_args *msg, char *desc)
#else
static int abnormal_file_detect(struct ebpf_filereq_t *rep, struct file_msg_args *msg, char *desc)
#endif
{
	int ret = 0;

	ret = get_abnormal_file_value(msg->pathname);
	if (ret >= 1) {
		add_abnormal_detect_desc(ret, desc);
	}

	if (ret < 1 && rep->op_type == OP_RENAME) {

		/*部分机器move新文件没有这边处理的快，读不到新文件。睡眠100毫秒*/
		usleep(100000);

		ret = get_abnormal_file_value(msg->pathname_new);
		if (ret > 1) {
			add_abnormal_detect_desc(ret, desc);
		}
	}

	return ret;
}

void send_file_upload_sample_log(struct file_msg_args *msg, char *pathname, char *log_name, char *log_id, int result, char*md5)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	char size_str[64] = {0};
	unsigned long event_time = 0;
	struct stat st = {0};

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

	event_time = (msg->start_tv.tv_sec + serv_timeoff) * 1000 + msg->start_tv.tv_usec / 1000;

        cJSON_AddStringToObject(object, "id", uuid);
        cJSON_AddStringToObject(object, "log_name", "ClientSimpleUpload");
        cJSON_AddStringToObject(object, "event_category", "");
        cJSON_AddStringToObject(object, "log_category", "Client");
        cJSON_AddBoolToObject(object, "event", false);
        cJSON_AddNumberToObject(object, "level", 1);
        cJSON_AddNumberToObject(object, "behavior", 0);
        cJSON_AddNumberToObject(object, "result", result);
        cJSON_AddStringToObject(object, "operating", "Upload");
        cJSON_AddNumberToObject(object, "terminate", 0);
        cJSON_AddNumberToObject(object, "timestamp", event_time);

        cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
        cJSON_AddStringToObject(object, "ip_address", If_info.ip);
        cJSON_AddStringToObject(object, "mac", If_info.mac);
        cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
        cJSON_AddStringToObject(object, "user", msg->username);
        cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
        cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
        cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

        cJSON_AddStringToObject(object, "policy_id", policy_id_cur);

        cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
        cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
        cJSON_AddStringToObject(arguments, "policy_id", policy_id_cur);
        cJSON_AddStringToObject(arguments, "policy_name", policy_name_cur);
        cJSON_AddStringToObject(arguments, "policy_time", policy_time_cur);
        cJSON_AddStringToObject(arguments, "md5", md5);
        cJSON_AddStringToObject(arguments, "file_path", pathname);
        cJSON_AddStringToObject(arguments, "file_name", safebasename(pathname));
        cJSON_AddStringToObject(arguments, "process_uuid", msg->taskuuid);
        cJSON_AddStringToObject(arguments, "log_name", log_name);
        cJSON_AddStringToObject(arguments, "log_id", log_id);

	if (stat(pathname, &st) < 0) {
        	cJSON_AddBoolToObject(arguments, "file_exists", false);
        	cJSON_AddStringToObject(arguments, "size", "0");
	} else {
        	cJSON_AddBoolToObject(arguments, "file_exists", true);
		snprintf(size_str, 64, "%ld", st.st_size);
        	cJSON_AddStringToObject(arguments, "size", size_str);
	}

        cJSON_AddItemToObject(object, "arguments", arguments);

        post = cJSON_PrintUnformatted(object);

        client_send_msg(post, reply, sizeof(reply), LOG_URL, "file");
	DBG2(DBGFLAG_FILE, "file send upload sample:%s\n", post);

        cJSON_Delete(object);
        free(post);
}

/* return 0，不上传；1，上传成功；-1，上传失败 */
int upload_file_sample(struct file_msg_args *msg, char *log_name, char *log_id, int type, char*md5)
{
	int ret = 0, result = MY_RESULT_OK;
	char *pathname = NULL;
	struct stat st = {0};

	/* 学习模式下总是要上传样本的, 运维模式总是不上传样本 */
	if ((!conf_global.allow_upload_sample &&
	     client_mode_global != LEARNING_MODE) ||
	     client_mode_global == OPERATION_MODE) {
		return 0;
	}

	if (!msg || !log_name || !log_id) {
		return 0;
	}

	if (type == OP_RENAME && stat(msg->pathname_new, &st) == 0) {
		pathname = msg->pathname_new;
	} else {
		pathname = msg->pathname;
	}

	/* 防勒索上传改动样本是进程本身 */
	if (strcmp(log_name, "Ransomeware") == 0) {
		pathname = msg->cmd;
	}

	ret = http_upload_sample(pathname, msg->start_tv.tv_sec, log_name, log_id, msg->username, md5);
	if (ret < 0) {
		result = MY_RESULT_FAIL;
	}

	send_file_upload_sample_log(msg, pathname, log_name, log_id, result, md5);

	return ret;
}
#if 0
static void send_file_msg(filereq_t *rep, struct file_msg_args *msg)
#else
static void send_file_msg(struct ebpf_filereq_t *rep, struct file_msg_args *msg)
#endif
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	int behavior = 0, level = 0, result = MY_RESULT_OK;
	int defence_result = MY_RESULT_OK;
	char *extension = NULL;
	char operating[OP_LEN_MAX] = {0};
	char md5[S_MD5LEN] = {0};
	char process_md5[S_MD5LEN] = {0};
	char *path = NULL;
	int ret = 0;
	struct stat st;
	bool event = false;
	char log_name[LOG_NAME_MAX] = {0};
	char event_category[EVENT_NAME_MAX] = {0};
	int terminate = 0;
	char file_tmp[PATH_MAX] = {0};
	struct defence_msg defmsg = {0};
	char keyword[MAX_KEYWORD_LEN] = {0};
	int trust_flag = 0;
	int cloudwalker_result = 0;
	int abnormal_result = 0;
	int regex_revel = 0;
	char cloudwalker_desc[STRLEN_MAX] = {0};
	char abnormal_desc[STRLEN_MAX] = {0};
	int webshell_detect_mode = 0;

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	if (rep->op_type == OP_RENAME) {
		path = msg->pathname_new;
	} else {
		path = msg->pathname;
	}

	/* 阻断成功的时候算旧的文件md5值 */
	if (md5_filter_large_file(path, md5) < 0) {
		if (rep->op_type == OP_RENAME ||
		    rep->op_type == OP_UNLINK) {
			if (md5_filter_large_file(msg->pathname, md5) < 0) {
				memset(md5, 0, S_MD5LEN);
			}
		} else {
			memset(md5, 0, S_MD5LEN);
		}
	}

	/* 计算进程的md5, 用于匹配进程过滤规则 */
	md5_filter_large_file(msg->cmd, process_md5);

	/* 匹配过滤规则 */
	if (check_filter_after(path, md5, msg->cmd) == 0 || check_process_filter_pro(msg->cmd, process_md5)) {
		return;
	}

	/* 如果是重命名，原文件一样过滤 */
	if (rep->op_type == OP_RENAME && 
		check_filter_after(msg->pathname, md5, msg->cmd) == 0) {
			return;
	}

	/* 匹配可信规则*/
	trust_flag = check_trust_after(path, md5, rep->type, msg->cmd);

	memset(&st, 0, sizeof(struct stat));
	/* 阻断成功的时候算旧的文件大小 */
	ret = stat(path, &st);
	if (ret < 0) {
		if (rep->op_type == OP_RENAME &&
		    stat(msg->pathname, &st) < 0) {
			msg->file_size = rep->file_size;
		} else {
			msg->file_size = st.st_size;
		}
	} else {
		msg->file_size = st.st_size;
	}
	if (rep->op_type == OP_UNLINK) {
		msg->file_size = rep->file_size;
	}

	/* 匹配可执行文件识别 */
	if (rep->type == F_BINARY_FILTER && 
		check_middle_binary(rep, msg) == 0) {
		return;
	}

	/* 匹配非法脚本 */
	if (rep->type == F_ILLEGAL_SCRIPT &&
		check_illegal_script(rep, msg, keyword) == 0) {
		return;
	}

	/* 匹配webshell文件检测 */
	if (rep->type == F_WEBSHELL_DETECT) {

		/* 
		 * 严格检测必须要匹配webshell引擎(哈希，统计，机器学习其中一个),
		 * 或者匹配异常文件(单行过长，连续相同长度行)
		 * 或者高等级(level >=5)的正则规则
		 * 宽松检测包含严格检测的规则和level <5的正则规则 
		 * 调用c正则接口可能会造成cpu负载过高，检测的顺序是1.webshell引擎检测
		 * 2.异常文件检测 3.正则规则检测。
		 * 其中一步匹配命中不再继续下一步检测
		 */

		webshell_detect_mode = protect_policy_global.sensitive_info.webshell_detect.detect_mode;

		/* 
		 * 调用c正则接口可能会造成cpu负载过高，检测的顺序是1.webshell引擎检测
		 * 2.异常文件检测 3.正则规则检测。
		 * 其中一步匹配命中不再继续下一步检测
		 */

		/* webshell引擎 */
		cloudwalker_result = cloudwalker_detect(rep, msg, cloudwalker_desc);
		/* webshell引擎的正则命中为1，不检测引擎的webshell */
		if (cloudwalker_result <= 1) {
			/* 异常文件检测 */
			abnormal_result = abnormal_file_detect(rep, msg, abnormal_desc);
			if (abnormal_result < 1) {
				/* 正则规则匹配 */
				regex_revel = regex_detect(rep, msg);
				if (webshell_detect_mode == WEBSHELL_HARD_MOD) {
					if (regex_revel < WEBSHELL_HIGH_LEVEL) {
						return;
					}
				} else {
					if (regex_revel == 0) {
						return;
					}
				}
			} else {
				snprintf(msg->webshell_rule_desc, STRLEN_MAX, "%s", thestring(abnormal_desc));
			}
		} else {
			snprintf(msg->webshell_rule_desc, STRLEN_MAX, "%s", thestring(cloudwalker_desc));
		}
	}

	switch (rep->type) {
		case F_SENSITIVE:
			strncpy(log_name, "SensitiveFile", LOG_NAME_MAX);
			strncpy(event_category, "SensitiveBehavior", EVENT_NAME_MAX);
			level = MY_LOG_MIDDLE_RISK;
			behavior = MY_BEHAVIOR_ABNORMAL;
			event = true;
			if (rep->terminate == 1) {
				terminate = MY_HANDLE_BLOCK_OK;
				result = MY_RESULT_FAIL;
				defence_result = MY_RESULT_OK;
			} else {
				terminate = MY_HANDLE_WARNING;
				result = MY_RESULT_OK;
				defence_result = MY_RESULT_FAIL;
			}
			break;

		case F_LOG_DELETE:
			strncpy(log_name, "IllegalDeleteLog", LOG_NAME_MAX);
			strncpy(event_category, "SensitiveBehavior", EVENT_NAME_MAX);
			level = MY_LOG_LOW_RISK;
			behavior = MY_BEHAVIOR_ABNORMAL;
			event = true;
			terminate = MY_HANDLE_WARNING;
			break;

		case F_SAFE:
			strncpy(log_name, "IllegalFileOperation", LOG_NAME_MAX);
			strncpy(event_category, "FileProtection", EVENT_NAME_MAX);
			level = MY_LOG_HIGH_RISK;
			behavior = MY_BEHAVIOR_ABNORMAL;
			event = true;
			if (rep->terminate == 1) {
				terminate = MY_HANDLE_BLOCK_OK;
				result = MY_RESULT_FAIL;
				defence_result = MY_RESULT_OK;
			} else {
				terminate = MY_HANDLE_WARNING;
				result = MY_RESULT_OK;
				defence_result = MY_RESULT_FAIL;
			}
			break;

		case F_USB:
			strncpy(log_name, "USBFileMonitor", LOG_NAME_MAX);
			strncpy(event_category, "", EVENT_NAME_MAX);
			level = MY_LOG_KEY;
			behavior = MY_BEHAVIOR_NO;
			event = false;
			terminate = MY_HANDLE_NO;
			break;

		case F_ABNORMAL:
			strncpy(log_name, "EncryptedFile", LOG_NAME_MAX);
			strncpy(event_category, "", EVENT_NAME_MAX);
			level = MY_LOG_KEY;
			behavior = MY_BEHAVIOR_NO;
			event = false;
			terminate = MY_HANDLE_NO;
			break;

		case F_BINARY_FILTER:
			strncpy(log_name, "ExecutableFiles", LOG_NAME_MAX);
			strncpy(event_category, "SensitiveBehavior", EVENT_NAME_MAX);
			/* 可信规则下日志只报普通日志 */
			if (trust_flag & EVENT_ExecutableFiles) {
				level = MY_LOG_NORMAL;
			} else {
				level = MY_LOG_MIDDLE_RISK;
			}

			/* 可信规则和运维模式下不报事件 */
			if (trust_flag & EVENT_ExecutableFiles ||
			    client_mode_global == OPERATION_MODE) {
				event = false;
			} else {
				event = true;
				upload_file_sample(msg, log_name, uuid, rep->op_type, md5);
			}

			/* 可信，运维，学习下均不阻断，运维和学习在内核修改了terminate的值 */
			if (rep->terminate == 1 &&
				!(trust_flag & EVENT_ExecutableFiles)) {
				if (unlink(path) == 0) {
					terminate = MY_HANDLE_BLOCK_OK;
					result = MY_RESULT_FAIL;
					defence_result = MY_RESULT_OK;
				} else {
					terminate = MY_HANDLE_BLOCK_FAIL;
					result = MY_RESULT_OK;
					defence_result = MY_RESULT_FAIL;
				}
			} else {
				terminate = MY_HANDLE_WARNING;
			}
			behavior = MY_BEHAVIOR_ABNORMAL;
			break;

		case F_MIDDLE_SCRIPT:
			strncpy(log_name, "ScriptFiles", LOG_NAME_MAX);
			strncpy(event_category, "SensitiveBehavior", EVENT_NAME_MAX);
			/* 可信规则下日志只报普通日志 */
			if (trust_flag & EVENT_ScriptFiles) {
				level = MY_LOG_NORMAL;
			} else {
				level = MY_LOG_MIDDLE_RISK;
			}

			/* 可信规则和运维模式下不报事件 */
			if (trust_flag & EVENT_ScriptFiles ||
			    client_mode_global == OPERATION_MODE) {
				event = false;
			} else{
				event = true;
				upload_file_sample(msg, log_name, uuid, rep->op_type, md5);
			}

			/* 可信，运维，学习下均不阻断，运维和学习在内核修改了terminate的值 */
			if (rep->terminate == 1 &&
				!(trust_flag & EVENT_ScriptFiles)) {
				if (unlink(path) == 0) {
					terminate = MY_HANDLE_BLOCK_OK;
					result = MY_RESULT_FAIL;
					defence_result = MY_RESULT_OK;
				} else {
					terminate = MY_HANDLE_BLOCK_FAIL;
					result = MY_RESULT_OK;
					defence_result = MY_RESULT_FAIL;
				}
			} else {
				terminate = MY_HANDLE_WARNING;
			}
			behavior = MY_BEHAVIOR_ABNORMAL;
			break;

		case F_ILLEGAL_SCRIPT:
			strncpy(log_name, "IllegalScriptFiles", LOG_NAME_MAX);
			strncpy(event_category, "SensitiveBehavior", EVENT_NAME_MAX);
			/* 可信规则下日志只报普通日志 */
			if (trust_flag & EVENT_IllegalScriptFiles) {
				level = MY_LOG_NORMAL;
			} else {
				level = MY_LOG_MIDDLE_RISK;
			}

			/* 可信规则和运维模式下不报事件 */
			if (trust_flag & EVENT_IllegalScriptFiles ||
			    client_mode_global == OPERATION_MODE) {
				event = false;
			} else {
				event = true;
				upload_file_sample(msg, log_name, uuid, rep->op_type, md5);
			}

			/* 可信，运维，学习下均不阻断，运维和学习在内核修改了terminate的值 */
			if (rep->terminate == 1 &&
				!(trust_flag & EVENT_IllegalScriptFiles)) {
				if (unlink(path) == 0) {
					terminate = MY_HANDLE_BLOCK_OK;
					result = MY_RESULT_FAIL;
					defence_result = MY_RESULT_OK;
				} else {
					terminate = MY_HANDLE_BLOCK_FAIL;
					result = MY_RESULT_OK;
					defence_result = MY_RESULT_FAIL;
				}
			} else {
				terminate = MY_HANDLE_WARNING;
			}
			behavior = MY_BEHAVIOR_ABNORMAL;
			break;

		case F_WEBSHELL_DETECT:
			strncpy(log_name, "Webshell_detect", LOG_NAME_MAX);
			strncpy(event_category, "SensitiveBehavior", EVENT_NAME_MAX);
			/* 可信规则下日志只报普通日志 */
			if (trust_flag & EVENT_Webshell_detect) {
				level = MY_LOG_NORMAL;
			} else {
				level = MY_LOG_LOW_RISK;
			}

			/* 可信规则和运维模式下不报事件 */
			if (trust_flag & EVENT_Webshell_detect ||
			    client_mode_global == OPERATION_MODE) {
				event = false;
			} else {
				event = true;
				upload_file_sample(msg, log_name, uuid, rep->op_type, md5);
			}

			/* 可信，运维，学习下均不阻断，运维和学习在内核修改了terminate的值 */
			if (rep->terminate == 1 &&
				!(trust_flag & EVENT_Webshell_detect)) {
				if (unlink(path) == 0) {
					terminate = MY_HANDLE_BLOCK_OK;
					result = MY_RESULT_FAIL;
					defence_result = MY_RESULT_OK;
				} else {
					terminate = MY_HANDLE_BLOCK_FAIL;
					result = MY_RESULT_OK;
					defence_result = MY_RESULT_FAIL;
				}
			} else {
				terminate = MY_HANDLE_WARNING;
			}
			behavior = MY_BEHAVIOR_ABNORMAL;
			break;

		default:
			strncpy(log_name, "FileMonitor", LOG_NAME_MAX);
			strncpy(event_category, "", EVENT_NAME_MAX);
			/* 其余均为文件行为采集 */
			level = MY_LOG_KEY;
			behavior = MY_BEHAVIOR_NO;
			event = false;
			terminate = MY_HANDLE_NO;
	}
	log_name[LOG_NAME_MAX - 1] = '\0';
	event_category[EVENT_NAME_MAX - 1] = '\0';


	extension = get_path_types(msg->pathname);
	event_time = (msg->start_tv.tv_sec + serv_timeoff) * 1000 + (int)msg->start_tv.tv_usec / 1000;
	get_file_event_operating(rep->op_type, operating);

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
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "File");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->username);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

        cJSON_AddStringToObject(arguments, "process_uuid", msg->taskuuid);
        cJSON_AddStringToObject(arguments, "process_name", msg->cmdname);
	cJSON_AddNumberToObject(arguments, "process_id", msg->pid);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
        cJSON_AddStringToObject(arguments, "process_path", msg->cmd);
        cJSON_AddStringToObject(arguments, "process_commandline", msg->args);
        cJSON_AddStringToObject(arguments, "filename", safebasename(msg->pathname));
        cJSON_AddStringToObject(arguments, "filepath", msg->pathname);
	cJSON_AddNumberToObject(arguments, "size", msg->file_size);
        cJSON_AddStringToObject(arguments, "extension", extension);
        cJSON_AddStringToObject(arguments, "file_md5", md5);
        cJSON_AddStringToObject(arguments, "new_filepath", msg->pathname_new);
        cJSON_AddNumberToObject(arguments, "operate_file_count", 1);
	cJSON_AddStringToObject(arguments, "user", msg->username);
	cJSON_AddStringToObject(arguments, "session_uuid", msg->session_uuid);
	if (rep->type == F_ILLEGAL_SCRIPT) {
		cJSON_AddStringToObject(arguments, "keyword", keyword);
	} else if (rep->type == F_WEBSHELL_DETECT) {
        	cJSON_AddNumberToObject(arguments, "webshell_rule_id", msg->webshell_rule_id);
		cJSON_AddStringToObject(arguments, "webshell_rule_desc", msg->webshell_rule_desc);
		cJSON_AddStringToObject(arguments, "webshell_rule_regex", msg->webshell_rule_regex);
		cJSON_AddStringToObject(arguments, "webshell_match_content", msg->webshell_match_content);
	}

        cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_FILE, "file post:%s\n", post);
//	printf("file post:%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "file");

	cJSON_Delete(object);
	free(post);

	/* 阻断或者可信模式下不报告防御日志*/
	if (rep->terminate != 1 || trust_flag) {
		return;
	}

	defmsg.event_tv.tv_sec = msg->start_tv.tv_sec;
	defmsg.event_tv.tv_usec = msg->start_tv.tv_usec;
	defmsg.operation = termstr;
	defmsg.result = defence_result;

	defmsg.user = msg->username;
	defmsg.log_name = log_name;
	defmsg.log_id = uuid;
	if (rep->op_type == OP_RENAME) {
		snprintf(file_tmp, PATH_MAX, "%s->%s", thestring(msg->pathname), thestring(msg->pathname_new));
		defmsg.object = file_tmp;
	} else {
		defmsg.object = msg->pathname;
	}
	
	send_defence_msg(&defmsg, "file");
	return;
}

#if 0
static void black_after_post_data(filereq_t *rep, struct file_msg_args *msg)
#else
static void black_after_post_data(struct ebpf_filereq_t *rep, struct file_msg_args *msg)
#endif
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	int behavior = 0, level = 0, result = MY_RESULT_OK;
	int defence_result = MY_RESULT_OK;
	char *extension = NULL;
	char operating[OP_LEN_MAX] = {0};
	char *path = NULL;
	int ret = 0;
	struct stat st;
	bool event = false;
	char log_name[LOG_NAME_MAX] = {0};
	char event_category[EVENT_NAME_MAX] = {0};
	int terminate = 0;
	char file_tmp[PATH_MAX] = {0};
	struct defence_msg defmsg = {0};
	char md5[S_MD5LEN] = {0};
	task_recv_t quarantine_msg = {0};

	/* 学习和运维模式下不匹配规则 */
	if (client_mode_global == LEARNING_MODE ||
	    client_mode_global == OPERATION_MODE) {
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	/* 运维模式时文件文件不阻断, 算修改后的大小*/	
	if (rep->op_type == OP_RENAME) {
		path = msg->pathname_new;
	} else {
		path = msg->pathname;
	}

	/* 阻断成功的时候算旧的文件md5值 */
	if (md5_filter_large_file(path, md5) < 0) {
		if (rep->op_type == OP_RENAME ||
		    rep->op_type == OP_UNLINK) {
			if (md5_filter_large_file(msg->pathname, md5) < 0) {
				return;
			}
		} else {
			return;
		}
	}

	if (check_black_after(md5) < 0) {
		return;
	}


	memset(&st, 0, sizeof(struct stat));
	/* 阻断成功的时候算旧的文件大小 */
	ret = stat(path, &st);
	if (ret < 0) {
		if (rep->op_type == OP_RENAME &&
		    stat(msg->pathname, &st) < 0) {
			msg->file_size = rep->file_size;
		} else {
			msg->file_size = st.st_size;
		}
	} else {
		msg->file_size = st.st_size;
	}
	if (rep->op_type == OP_UNLINK) {
		msg->file_size = rep->file_size;
	}

	level = MY_LOG_HIGH_RISK;
	behavior = MY_BEHAVIOR_VIOLATION;
	event = true;
	if (rep->terminate == 1) {
		terminate = MY_HANDLE_BLOCK_OK;
	} else {
		terminate = MY_HANDLE_WARNING;
	}
	strncpy(log_name, "MaliciousFile", LOG_NAME_MAX);
	log_name[LOG_NAME_MAX - 1] = '\0';
	strncpy(event_category, "SensitiveBehavior", EVENT_NAME_MAX);
	event_category[EVENT_NAME_MAX - 1] = '\0';

	// upload_file_sample(msg, log_name, uuid, rep->op_type, rep->md5);

	extension = get_path_types(msg->pathname);
	event_time = (msg->start_tv.tv_sec + serv_timeoff) * 1000 + (int)msg->start_tv.tv_usec / 1000;
	get_file_event_operating(rep->op_type, operating);
	if (msg->tty[0] != 0) {
		get_session_uuid(msg->tty, msg->session_uuid);
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
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "File");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->username);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

        cJSON_AddStringToObject(arguments, "process_uuid", msg->taskuuid);
        cJSON_AddStringToObject(arguments, "process_name", msg->cmdname);
	cJSON_AddNumberToObject(arguments, "process_id", msg->pid);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
        cJSON_AddStringToObject(arguments, "process_path", msg->cmd);
        cJSON_AddStringToObject(arguments, "process_commandline", msg->args);
        cJSON_AddStringToObject(arguments, "filename", safebasename(msg->pathname));
        cJSON_AddStringToObject(arguments, "filepath", msg->pathname);
	cJSON_AddNumberToObject(arguments, "size", msg->file_size);
        cJSON_AddStringToObject(arguments, "extension", extension);
        // cJSON_AddStringToObject(arguments, "md5", rep->md5);
        cJSON_AddStringToObject(arguments, "new_filepath", msg->pathname_new);
        cJSON_AddNumberToObject(arguments, "operate_file_count", 1);
	cJSON_AddStringToObject(arguments, "user", msg->username);
	cJSON_AddStringToObject(arguments, "session_uuid", msg->session_uuid);

        cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_FILE, "black file post:%s\n", post);
//	printf("black after post:%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "file");

	cJSON_Delete(object);
	free(post);

	if (rep->terminate != 1) {
		return;
	}

	defmsg.event_tv.tv_sec = msg->start_tv.tv_sec;
	defmsg.event_tv.tv_usec = msg->start_tv.tv_usec;
	defmsg.operation = termstr;
	defmsg.result = defence_result;

	defmsg.user = msg->username;
	defmsg.log_name = log_name;
	defmsg.log_id = uuid;
	if (rep->op_type == OP_RENAME) {
		snprintf(file_tmp, PATH_MAX, "%s->%s", thestring(msg->pathname), thestring(msg->pathname_new));
		defmsg.object = file_tmp;
	} else {
		defmsg.object = msg->pathname;
	}
	
	send_defence_msg(&defmsg, "file");

	/* 主动隔离 */
	snprintf(quarantine_msg.cmd_id, sizeof(quarantine_msg.cmd_id), "nottask"); //共用任务处理函数，但不发任务应答消息
	quarantine_msg.cmd_type = TASK_FILE_QUARANTINE;
	snprintf(quarantine_msg.md5, sizeof(quarantine_msg.md5), "%s", md5);
	snprintf(quarantine_msg.filepath, sizeof(quarantine_msg.filepath), "%s", path);
	file_quarantine(&quarantine_msg);
}

#if 0
int check_to_report(char *path, filereq_t *req)
#else
int check_to_report(char *path, struct ebpf_filereq_t *req)
#endif
{
	int i = 0, found = 0, to_report = 0;
	struct stat st = {0};

	if (!path || !req) {
		return 0;
	}

	if (stat(path, &st) < 0) {
		return 0;
	}

	/* 文件内容没有改变 */
	if (st.st_mtim.tv_sec == req->mtime_sec &&
	    st.st_mtim.tv_nsec == req->mtime_nsec) {
		return 0;
	}

	/* 文件已经报告过被改变了 */
	for (i = 0; i < WF_CACHE_NUM; i++) {
		if (st.st_ino == wfinfo[i].inode) {
			found = 1;
			if (st.st_mtim.tv_sec != wfinfo[i].mtime_sec ||
			    st.st_mtim.tv_nsec != wfinfo[i].mtime_nsec) {
				/* 更新已缓存的文件的时间戳 */
				wfinfo[i].mtime_sec = st.st_mtim.tv_sec;
				wfinfo[i].mtime_nsec = st.st_mtim.tv_nsec;
				to_report = 1;
			}
			break;
		}
	}
	if (found) {
		if (!to_report) {
			return 0;
		}
		return 1;
	}

	/* 缓存新的被改变的文件及其被改变的时间戳 */
	wfinfo[next_wfidx].inode = st.st_ino;
	wfinfo[next_wfidx].mtime_sec = st.st_mtim.tv_sec;
	wfinfo[next_wfidx].mtime_nsec = st.st_mtim.tv_nsec;
	next_wfidx = (next_wfidx + 1) % WF_CACHE_NUM;

	return 1;
}

void *file_monitor(void *ptr)
{
#if 0
	filereq_t *rep = NULL;
#else
	struct ebpf_filereq_t *rep = NULL;
#endif
	struct file_msg_args msg = {0};
	kfile_msg_t *kfile_msg = NULL;
	struct stat sbuf = {0};
	taskstat_t *taskstat = NULL;

	get_job_list(print_job_old, &job_count_old);
        printer_filesize = 0;
        if (stat(LP_PATH, &sbuf) < 0) {
                DBG2(DBGFLAG_FILE, "printer log file:%s is not exist\n", LP_PATH);
        } else {
                printer_filesize = sbuf.st_size;
                printer_fileinode = sbuf.st_ino;
        }

	prctl(PR_SET_NAME, "file_monitor");
	save_thread_pid("file", SNIPER_THREAD_FILEMON);

//	backup_size = check_dir_size(TRASH_DIR);
	while (Online) {
		if (kfile_msg) {
			sniper_free(kfile_msg->data, kfile_msg->datalen, FILE_GET);
			sniper_free(kfile_msg, sizeof(struct kfile_msg), FILE_GET);
		}

		/* 检查待转储的日志文件 */
		check_log_to_send("file");

		/* 如果停止防护，什么也不做 */
		if (sniper_file_loadoff == TURN_MY_ON) {
			/* get_kfile_msg里不睡眠，所以此处要睡1秒，否则会显示CPU一直忙 */
			sleep(1);
			kfile_msg = (kfile_msg_t *)get_kfile_msg();
			continue;
	  	}

		/* 如果过期了/停止客户端工作，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
			close_kernel_file_policy();

                        sleep(STOP_WAIT_TIME);

			/* 扔掉msg queue中的数据 */
			while(1) {
				kfile_msg = (kfile_msg_t *)get_kfile_msg();
				if (!kfile_msg) {
					break;
				}

				sniper_free(kfile_msg->data, kfile_msg->datalen, FILE_GET);
				sniper_free(kfile_msg, sizeof(struct kfile_msg), FILE_GET);
			}

                        continue;
                }

		kfile_msg = (kfile_msg_t *)get_kfile_msg();
		if (!kfile_msg) {
			sleep(1);
			continue;
		}
#if 0
		rep = (filereq_t *)kfile_msg->data;
#else
		rep = (struct ebpf_filereq_t *)kfile_msg->data;
#endif
		if (rep == NULL) {
			continue;
		}

		DBG2(DBGFLAG_FILEDEBUG, "file msg pid:%d, process:%s, path:%s, rep->type:%d,rep->op_type:%d,rep->uid:%d\n", 
			rep->pid, &(rep->args), &(rep->args) + rep->pro_len + 1, rep->type,rep->op_type,rep->uid);
		printf("file msg pid:%d, process:%s, path:%s, rep->type:%d,rep->op_type:%d,rep->uid:%d\n", 
			rep->pid, rep->comm, rep->filename , rep->type,rep->op_type,rep->uid);
		memset(&msg, 0, sizeof(struct file_msg_args));
		strncpy(msg.tty, rep->tty, S_TTYLEN);
		msg.tty[S_TTYLEN-1] = 0;

		/* 从进程获取不到task时，不用取父进程的task，自己赋值成员的值，以防后面用到process时不一致 */
		taskstat = get_taskstat_rdlock(rep->pid, FILE_GET);
		if (!taskstat) {
			strncpy(msg.cmd, &rep->args, rep->pro_len);
			msg.cmd[S_CMDLEN-1] = 0;
			if (msg.tty[0] != 0) {
				get_session_uuid(msg.tty, msg.session_uuid);
			}
		} else {
			strncpy(msg.cmd, taskstat->cmd, S_CMDLEN);
			msg.cmd[S_CMDLEN - 1] = '\0';
			strncpy(msg.args, taskstat->args, S_ARGSLEN);
			msg.args[S_ARGSLEN - 1] = '\0';
			strncpy(msg.session_uuid, taskstat->session_uuid, S_UUIDLEN);
			msg.args[S_UUIDLEN - 1] = '\0';

			put_taskstat_unlock(taskstat);
		}

		msg.pid = rep->pid;
		msg.proctime = rep->proctime;
		memcpy(&msg.start_tv, &rep->event_tv, sizeof(struct timeval));
#if 0
		if (rep->type != F_PRINTER && rep->type != F_CDROM) {
			strncpy(msg.pathname, &rep->args + rep->pro_len + 1, rep->path_len);
			msg.pathname[PATH_MAX-1] = 0;
			strncpy(msg.pathname_new, &rep->args + rep->pro_len + rep->path_len + 2, rep->newpath_len);
			msg.pathname_new[PATH_MAX-1] = 0;
			if ((msg.pathname[0] == '\0') || (rep->path_len == 0)){
//				MON_ERROR("filename is NULL\n");
				continue;
			}
		}
#else
		if (rep->type != F_PRINTER && rep->type != F_CDROM) {
			strncpy(msg.pathname, rep->filename, 64);
			msg.pathname[PATH_MAX-1] = 0;
			strncpy(msg.pathname_new, rep->new_filename, 64);
			msg.pathname_new[PATH_MAX-1] = 0;
			if ((msg.pathname[0] == '\0') || (rep->path_len == 0)){
//				MON_ERROR("filename is NULL\n");
				continue;
			}
		}
#endif
		strncpy(msg.cmdname, safebasename(msg.cmd), S_CMDLEN);
		msg.cmdname[S_CMDLEN-1] = 0;
		strncpy(msg.p_cmdname, rep->parent_comm, S_COMMLEN);
		msg.p_cmdname[S_COMMLEN-1] = 0;
		strncpy(msg.username, "N/A", 4);
		uidtoname(rep->uid, msg.username);

		if (rep->op_type == OP_RENAME || rep->type == F_ENCRYPT_BACKUP) {
			if ((msg.pathname_new[0] == '\0') || (rep->newpath_len == 0)){
				DBG2(DBGFLAG_FILE, "newfilename is NULL\n");
				continue;
			}
		}

		/* 文件防篡改非授权进程创建文件日志会在此处被过滤，此处排除文件防篡改 */
		/* 不能过滤 OP_OPEN_C和OP_LINK, 否则同一个文件只报第一个功能 */
		if (rep->op_type == OP_OPEN_W && 
		   (rep->type != F_BLACK_AFTER &&
		    rep->type != F_SAFE &&
		    rep->type != F_ENCRYPT)) {
			if (!check_to_report(msg.pathname, rep)) {
				DBG2(DBGFLAG_FILE, "check file msg to report, op_type:%d, type:%d\n", rep->op_type, rep->type);
				continue;
			}
		}

		// if (rep->did_exec) {
		// 	set_taskuuid(msg.taskuuid, rep->proctime, rep->pid, 0);
		// } else {
		// 	int i = 0;
		// 	struct task_simple_info *tinfo = NULL;

		// 	for (i = 0; i < SNIPER_PGEN; i++) {
		// 		tinfo = &(rep->pinfo.task[i]);
		// 		if (tinfo->did_exec) {
		// 			set_taskuuid(msg.taskuuid,
		// 				tinfo->proctime, tinfo->pid, 0);
		// 			break;
		// 		}
		// 	}
		// }

		if (rep->type == F_CDROM) {
			cdrom_terminate_post_data(&msg);
		} else if (rep->type == F_BLACK_AFTER) {
			black_after_post_data(rep,&msg);
		} else if (rep->type == F_ENCRYPT) {
			report_encrypt_msg(rep, &msg);
			/* 恢复被删的诱捕文件 */
			if (strstr(msg.pathname, TRAP_FILE_NOHIDE) != NULL) {
				create_file(msg.pathname);
			}

			if (strstr(msg.pathname_new, TRAP_FILE_NOHIDE) != NULL) {
				create_file(msg.pathname_new);
			}
		} else if (rep->type == F_ENCRYPT_BACKUP) {
			DBG2(DBGFLAG_ENCRYPT, "encrypt backup file:%s, md5:%s\n", msg.pathname, msg.pathname_new);;
			add_record_to_encrypt_db(rep, &msg);
		} else if (rep->type == F_ENCRYPT_REPORT) {
			/* 恢复被删的诱捕文件 */
			if (strstr(msg.pathname, TRAP_FILE_NOHIDE) != NULL) {
				create_file(msg.pathname);
			}

			if (strstr(msg.pathname_new, TRAP_FILE_NOHIDE) != NULL) {
				create_file(msg.pathname_new);
			}
		} else {
			send_file_msg(rep, &msg);
		}

	}

	INFO("file thread exit\n");

	return NULL;
}
