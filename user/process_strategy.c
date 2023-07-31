#include "header.h"
#include "rule.h"

int intsize = sizeof(int);
int uidsize = sizeof(uid_t);

struct kern_process_rules prule = {0};

static int black_process_mem_size = 0;
static int filter_process_mem_size = 0;
static int trust_process_mem_size = 0;
static int command_table_mem_size = 0;
static int mine_pool_mem_size = 0;

static char *black_process_mem = NULL;
static char *filter_process_mem = NULL;
static char *trust_process_mem = NULL;
static char *command_table_mem = NULL;
static char *mine_pool_mem = NULL;

char *copy_stringvalue(char *buf, char *str)
{
	int len = strlen(str);

	memcpy(buf, str, len);
	buf += len;
	*buf = 0;
	buf++;

	return buf;
}

/*
 * 更新内核里的进程黑名单，忽略无法解析用户条件的规则
 * 为了避免内核中不必要的开销，无法解析用户条件的规则不传入内核
 * 比如只有一条针对xxx用户的黑名单全局规则，本机没有这个用户但把规则传入内核的话，
 * 本来不需要做黑名单检查的，现在所有命令都要做检查了，完全是额外的开销
 */
static void update_kernel_black_process(void)
{
	int i = 0, size = 0, valid_num = 0, flag = 0;
	int cmdline_match_pattern = 0;
	int old_size = black_process_mem_size;
	int num = rule_black_global.process_num;
	char *buf = NULL, *ptr = NULL;
	BLACK_PROCESS *rule = NULL;
	uid_t uid = 0;

	/*
	 * black_process memory content:
	 *    totalsize | num | process0 info | process1 info | ...
	 * process info:
	 *    name | path | cmdline | md5 | parent_name | remote_ip | flag | uid | event_flag 
	 */
	size += 2 * intsize;
	for (i = 0; i < num; i++) {
		rule = &rule_black_global.process[i];

		/* 忽略本机没有的用户名和无法解析的用户名 */
		if (rule->process_user && rule->process_user[0] != 0 &&
		    nametouid(&uid, rule->process_user) < 0) {
			MON_ERROR("Invalid black process rule %dth\n", i+1);
			continue;
		}
		valid_num++; //有效的规则加1

		size += strlen(rule->process_name) + 1;
		size += strlen(rule->process_path) + 1;
		size += strlen(rule->process_commandline) + 1;
		size += strlen(rule->md5) + 1;
		size += strlen(rule->parent_process_name) + 1;
		size += strlen(rule->remote_ip) + 1;

		size += 1 + uidsize + intsize;
	}

	buf = sniper_malloc(size, PROCESS_GET);
	if (!buf) {
		MON_ERROR("update kernel black process fail, "
			  "alloc %d bytes fail, no memory\n", size);
		return;
	}
	ptr = buf;

	*(int *)ptr = size;
	ptr += intsize;
	*(int *)ptr = valid_num;
	ptr += intsize;

	for (i = 0; i < num; i++) {
		flag = 0;
		rule = &rule_black_global.process[i];

		if (rule->process_user && rule->process_user[0] != 0) {
			/* 忽略本机没有的用户名和无法解析的用户名 */
			if (nametouid(&uid, rule->process_user) < 0) {
				continue;
			}

			/* 有用户名条件，且解析成功 */
			flag = RULE_FLAG_UID;
		}

		ptr = copy_stringvalue(ptr, rule->process_name);
		ptr = copy_stringvalue(ptr, rule->process_path);
		ptr = copy_stringvalue(ptr, rule->process_commandline);
		ptr = copy_stringvalue(ptr, rule->md5);
		ptr = copy_stringvalue(ptr, rule->parent_process_name);
		ptr = copy_stringvalue(ptr, rule->remote_ip);

		cmdline_match_pattern = atoi(rule->param);
		if (cmdline_match_pattern < 0 || cmdline_match_pattern > 2) {
			cmdline_match_pattern = 0;
		}
		*ptr |= 1 << cmdline_match_pattern;

		if (flag == 0) { //这条规则里没有用户条件
			ptr += uidsize + 1;
		} else {
			*ptr |= RULE_FLAG_UID;
			ptr++;
			*(uid_t *)ptr = uid;
			ptr += uidsize;
		}

		*(int *)ptr = rule->event_flags;
		ptr += intsize;

		valid_num--;
		if (valid_num == 0) { //有效的规则已经解析完就结束，避免内存越界
			break;
		}
	}

	if (black_process_mem && old_size == size &&
	    memcmp(black_process_mem, buf, size) == 0) {
		sniper_free(buf, size, PROCESS_GET);
		printf("skip update kernel black process, no change\n");
		return;
	}

	if (send_data_to_kern(NLMSG_BLACK_PROCESS, buf, size) < 0) {
		sniper_free(buf, size, PROCESS_GET);
		MON_ERROR("update kernel black process fail\n");
		return;
	}

	sniper_free(black_process_mem, old_size, PROCESS_GET);
	black_process_mem_size = size;
	black_process_mem = buf;
}

/* 更新内核里的进程过滤名单，忽略无法解析用户条件的规则 */
static void update_kernel_filter_process(void)
{
	int i = 0, size = 0, valid_num = 0, flag = 0;
	int cmdline_match_pattern = 0;
	int old_size = filter_process_mem_size;
	int num = rule_filter_global.process_num;
	char *buf = NULL, *ptr = NULL;
	FILTER_PROCESS *rule = NULL;
	uid_t uid = 0;

	/*
	 * filter_process memory content:
	 *    totalsize | num | process0 info | process1 info | ...
	 * process info:
	 *    name | path | cmdline | md5 | parent_name | remote_ip | flag | uid | event_flag 
	 */
	size += 2 * intsize;
	for (i = 0; i < num; i++) {
		rule = &rule_filter_global.process[i];

		/* 忽略本机没有的用户名和无法解析的用户名 */
		if (rule->process_user && rule->process_user[0] != 0 &&
		    nametouid(&uid, rule->process_user) < 0) {
			MON_ERROR("Invalid filter process rule %dth\n", i+1);
			continue;
		}
		valid_num++; //有效的规则加1

		size += strlen(rule->process_name) + 1;
		size += strlen(rule->process_path) + 1;
		size += strlen(rule->process_commandline) + 1;
		size += strlen(rule->md5) + 1;
		size += strlen(rule->parent_process_name) + 1;
		size += strlen(rule->remote_ip) + 1;

		size += 1 + uidsize + intsize;
	}

	buf = sniper_malloc(size, PROCESS_GET);
	if (!buf) {
		MON_ERROR("update kernel filter process fail, "
			  "alloc %d bytes fail, no memory\n", size);
		return;
	}
	ptr = buf;

	*(int *)ptr = size;
	ptr += intsize;
	*(int *)ptr = valid_num;
	ptr += intsize;

	for (i = 0; i < num; i++) {
		flag = 0;
		rule = &rule_filter_global.process[i];

		if (rule->process_user && rule->process_user[0] != 0) {
			/* 忽略本机没有的用户名和无法解析的用户名 */
			if (nametouid(&uid, rule->process_user) < 0) {
				continue;
			}

			/* 有用户名条件，且解析成功 */
			flag = RULE_FLAG_UID;
		}

		ptr = copy_stringvalue(ptr, rule->process_name);
		ptr = copy_stringvalue(ptr, rule->process_path);
		ptr = copy_stringvalue(ptr, rule->process_commandline);
		ptr = copy_stringvalue(ptr, rule->md5);
		ptr = copy_stringvalue(ptr, rule->parent_process_name);
		ptr = copy_stringvalue(ptr, rule->remote_ip);

		cmdline_match_pattern = atoi(rule->param);
		if (cmdline_match_pattern < 0 || cmdline_match_pattern > 2) {
			cmdline_match_pattern = 0;
		}
		*ptr |= 1 << cmdline_match_pattern;

		if (flag == 0) { //这条规则里没有用户条件
			ptr += uidsize + 1;
		} else {
			*ptr |= RULE_FLAG_UID;
			ptr++;
			*(uid_t *)ptr = uid;
			ptr += uidsize;
		}

		*(int *)ptr = rule->event_flags;
		ptr += intsize;

		valid_num--;
		if (valid_num == 0) { //有效的规则已经解析完就结束，避免内存越界
			break;
		}
	}

	if (filter_process_mem && old_size == size &&
	    memcmp(filter_process_mem, buf, size) == 0) {
		sniper_free(buf, size, PROCESS_GET);
		printf("skip update kernel filter process, no change\n");
		return;
	}

	if (send_data_to_kern(NLMSG_FILTER_PROCESS, buf, size) < 0) {
		sniper_free(buf, size, PROCESS_GET);
		MON_ERROR("update kernel filter process fail\n");
		return;
	}

	sniper_free(filter_process_mem, old_size, PROCESS_GET);
	filter_process_mem_size = size;
	filter_process_mem = buf;
}

/* 更新内核里的进程可信名单，忽略无法解析用户条件的规则 */
static void update_kernel_trust_process(void)
{
	int i = 0, size = 0, valid_num = 0, flag = 0;
	int cmdline_match_pattern = 0;
	int old_size = trust_process_mem_size;
	int num = rule_trust_global.process_num;
	char *buf = NULL, *ptr = NULL;
	TRUST_PROCESS *rule = NULL;
	uid_t uid = 0;

	/*
	 * trust_process memory content:
	 *    totalsize | num | process0 info | process1 info | ...
	 * process info:
	 *    name | path | cmdline | md5 | parent_name | remote_ip | flag | uid | event_flag 
	 */
	size += 2 * intsize;
	for (i = 0; i < num; i++) {
		rule = &rule_trust_global.process[i];

		/* 忽略本机没有的用户名和无法解析的用户名 */
		if (rule->process_user && rule->process_user[0] != 0 &&
		    nametouid(&uid, rule->process_user) < 0) {
			MON_ERROR("Invalid trust process rule %dth\n", i+1);
			continue;
		}
		valid_num++; //有效的规则加1

		size += strlen(rule->process_name) + 1;
		size += strlen(rule->process_path) + 1;
		size += strlen(rule->process_commandline) + 1;
		size += strlen(rule->md5) + 1;
		size += strlen(rule->parent_process_name) + 1;
		size += strlen(rule->remote_ip) + 1;

		size += 1 + uidsize + intsize;
	}

	buf = sniper_malloc(size, PROCESS_GET);
	if (!buf) {
		MON_ERROR("update kernel trust process fail, "
			  "alloc %d bytes fail, no memory\n", size);
		return;
	}
	ptr = buf;

	*(int *)ptr = size;
	ptr += intsize;
	*(int *)ptr = valid_num;
	ptr += intsize;

	for (i = 0; i < num; i++) {
		flag = 0;
		rule = &rule_trust_global.process[i];

		if (rule->process_user && rule->process_user[0] != 0) {
			/* 忽略本机没有的用户名和无法解析的用户名 */
			if (nametouid(&uid, rule->process_user) < 0) {
				continue;
			}

			/* 有用户名条件，且解析成功 */
			flag = RULE_FLAG_UID;
		}

		ptr = copy_stringvalue(ptr, rule->process_name);
		ptr = copy_stringvalue(ptr, rule->process_path);
		ptr = copy_stringvalue(ptr, rule->process_commandline);
		ptr = copy_stringvalue(ptr, rule->md5);
		ptr = copy_stringvalue(ptr, rule->parent_process_name);
		ptr = copy_stringvalue(ptr, rule->remote_ip);

		cmdline_match_pattern = atoi(rule->param);
		if (cmdline_match_pattern < 0 || cmdline_match_pattern > 2) {
			cmdline_match_pattern = 0;
		}
		*ptr |= 1 << cmdline_match_pattern;

		if (flag == 0) { //这条规则里没有用户条件
			ptr += uidsize + 1;
		} else {
			*ptr |= RULE_FLAG_UID;
			ptr++;
			*(uid_t *)ptr = uid;
			ptr += uidsize;
		}

		*(int *)ptr = rule->event_flags;
		ptr += intsize;

		valid_num--;
		if (valid_num == 0) { //有效的规则已经解析完就结束，避免内存越界
			break;
		}
	}

	if (trust_process_mem && old_size == size &&
	    memcmp(trust_process_mem, buf, size) == 0) {
		sniper_free(buf, size, PROCESS_GET);
		printf("skip update kernel trust process, no change\n");
		return;
	}

	if (send_data_to_kern(NLMSG_TRUST_PROCESS, buf, size) < 0) {
		sniper_free(buf, size, PROCESS_GET);
		MON_ERROR("update kernel trust process fail\n");
		return;
	}

	sniper_free(trust_process_mem, old_size, PROCESS_GET);
	trust_process_mem_size = size;
	trust_process_mem = buf;
}

static void update_kernel_command_table(void)
{
	int i = 0, size = 0;
	int old_size = command_table_mem_size;
	int num = protect_policy_global.process.command_num;
	char *buf = NULL, *ptr = NULL;
	POLICY_LIST *rule = NULL;

	size += 2 * intsize;
	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.process.command_table_list[i];
		size += strlen(rule->list) + 1;
	}

	buf = sniper_malloc(size, PROCESS_GET);
	if (!buf) {
		MON_ERROR("update kernel command table fail, "
			  "alloc %d bytes fail, no memory\n", size);
		return;
	}
	ptr = buf;

	*(int *)ptr = size;
	ptr += intsize;
	*(int *)ptr = num;
	ptr += intsize;

	for (i = 0; i < num; i++) {
		rule = &protect_policy_global.process.command_table_list[i];
		ptr = copy_stringvalue(ptr, rule->list);
	}

	if (command_table_mem && old_size == size &&
	    memcmp(command_table_mem, buf, size) == 0) {
		sniper_free(buf, size, PROCESS_GET);
		printf("skip update kernel command table, no change\n");
		return;
	}

	if (send_data_to_kern(NLMSG_COMMAND_TABLE, buf, size) < 0) {
		sniper_free(buf, size, PROCESS_GET);
		MON_ERROR("update kernel command table fail\n");
		return;
	}

	sniper_free(command_table_mem, old_size, PROCESS_GET);
	command_table_mem_size = size;
	command_table_mem = buf;
}

static void update_kernel_mine_pool(void)
{
	int i = 0, size = 0;
	int old_size = mine_pool_mem_size;
	int num = rule_global_global.black.minner_num;
	char *buf = NULL, *ptr = NULL;
	POLICY_LIST *rule = NULL;
	struct rulefile_info rfinfo;

//	size += 2 * intsize;
	for (i = 0; i < num; i++) {
		rule = &rule_global_global.black.minner[i];
		size += strlen(rule->list) + 1;
	}

	if (size == 0) {
		sniper_free(mine_pool_mem, old_size, PROCESS_GET);
		mine_pool_mem_size = 0;
		mine_pool_mem = NULL;
		return;
	}

	buf = sniper_malloc(size, PROCESS_GET);
	if (!buf) {
		MON_ERROR("update kernel mine pool fail, no memory!\n");
		return;
	}
	ptr = buf;

#if 0
	*(int *)ptr = size;
	ptr += intsize;
	*(int *)ptr = num;
	ptr += intsize;
#endif

	pthread_rwlock_rdlock(&rule_global_global.lock);

	for (i = 0; i < num; i++) {
		rule = &rule_global_global.black.minner[i];
		ptr = copy_stringvalue(ptr, rule->list);
	}

	pthread_rwlock_unlock(&rule_global_global.lock);

	if (mine_pool_mem && old_size == size &&
	    memcmp(mine_pool_mem, buf, size) == 0) {
		sniper_free(buf, size, PROCESS_GET);
		printf("skip update mine pool, no change\n");
		return;
	}

	if (prepare_rulefile(buf, size, "mine pool", &rfinfo) < 0) {
		sniper_free(buf, size, PROCESS_GET);
		MON_ERROR("skip update mine pool, prepare rulefile fail\n");
		return;
	}

	if (send_data_to_kern(NLMSG_MINE_POOL, (char *)&rfinfo, sizeof(rfinfo)) < 0) {
		sniper_free(buf, size, PROCESS_GET);
		MON_ERROR("update kernel mine pool fail\n");
		return;
	}

	printf("update mine pool ok\n");
	sniper_free(mine_pool_mem, old_size, PROCESS_GET);
	mine_pool_mem_size = size;
	mine_pool_mem = buf;
}

static void free_process_rules_mem(void)
{
	sniper_free(black_process_mem, black_process_mem_size, PROCESS_GET);
	sniper_free(filter_process_mem, filter_process_mem_size, PROCESS_GET);
	sniper_free(trust_process_mem, trust_process_mem_size, PROCESS_GET);
	sniper_free(command_table_mem, command_table_mem_size, PROCESS_GET);
	sniper_free(mine_pool_mem, mine_pool_mem_size, PROCESS_GET);
	black_process_mem_size = 0;
	filter_process_mem_size = 0;
	trust_process_mem_size = 0;
	command_table_mem_size = 0;
	mine_pool_mem_size = 0;
}

/* 关闭内核进程监控 */
void close_kernel_process_rules(void)
{
	int size = sizeof(struct kern_process_rules);
	struct kern_process_rules rule = {0};

	if (prule.process_engine_on == 0) { //内核进程监控已关闭
		return;
	}

	if (send_data_to_kern(NLMSG_PROCESS_RULES, (char *)&rule, size) < 0) {
		MON_ERROR("set kernel process rules off fail\n");
		return;
	}

	pthread_rwlock_wrlock(&protect_policy_global.lock);

	memset(&prule, 0, size); //内核策略更新成功再清应用层策略
	free_process_rules_mem();

	pthread_rwlock_unlock(&protect_policy_global.lock);
}

/* 更新内核模块的进程监控策略。调用者负责加进程策略写锁 */
void update_kernel_process_rules(void)
{
	printf("Start to Update the kernel Rule...\n");
	int enable = 0, terminate = 0, locking = 0, locking_time = 0;
	int size = sizeof(struct kern_process_rules);
	struct kern_process_rules new_prule = {0};

	if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
		goto tellkern;
	}

	/* 进程日志采集 */
	if (protect_policy_global.logcollector.process_enable) {
		new_prule.process_engine_on = 1;
		new_prule.normal_on = 1;
	}

	/* 危险命令 */
	if (protect_policy_global.process.risk_command.enable) {
		new_prule.process_engine_on = 1;
		new_prule.danger_on = 1;
		if (protect_policy_global.process.risk_command.terminate) {
			new_prule.danger_kill = 1;
		}
	}

	/* 异常程序 */
	if (protect_policy_global.process.abnormal_process.enable) {
		new_prule.process_engine_on = 1;
		new_prule.abnormal_on = 1;
		if (protect_policy_global.process.abnormal_process.terminate) {
			new_prule.abnormal_kill = 1;
		}
	}

	/* 提权 */
	if (protect_policy_global.process.privilege.enable) {
		new_prule.process_engine_on = 1;
		new_prule.privilege_on = 1;
		if (protect_policy_global.process.privilege.terminate) {
			new_prule.privilege_kill = 1;
		}
	}

	/* 反弹shell */
	enable = protect_policy_global.process.reverse_shell.enable;
	if (TURN_MY_ON == enable) {
		new_prule.process_engine_on = 1;
		new_prule.remote_execute_on = 1;
		terminate = protect_policy_global.process.reverse_shell.terminate;
		if (TURN_MY_ON == terminate) {
			new_prule.remote_execute_kill = 1;
			locking = protect_policy_global.process.reverse_shell.locking;
			if (TURN_MY_ON == locking) {
				new_prule.remote_execute_lockip = 1;
				locking_time = protect_policy_global.process.reverse_shell.locking_time;
				new_prule.remote_execute_lockip_seconds = locking_time * 60;
			}
		}
	}

	/* 中国菜刀/webshll */
	if (protect_policy_global.process.webshell.enable) {
		new_prule.process_engine_on = 1;
		new_prule.webshell_on = 1;
		if (protect_policy_global.process.webshell.terminate) {
			new_prule.webshell_kill = 1;
		}
	}

	/* 对外服务进程异常执行/中间件 */
	if (protect_policy_global.process.service_process.enable) {
		new_prule.process_engine_on = 1;
		new_prule.webexecute_on = 1;
		new_prule.danger_webexecute_on = 1;

		if (protect_policy_global.process.service_process.terminate) {
			new_prule.danger_webexecute_kill = 1;
		}
	}

        /* MBR策略，即分区表保护 */
	if (protect_policy_global.process.mbr.enable) {
		new_prule.process_engine_on = 1;
                new_prule.mbr_on = 1;
		if (protect_policy_global.process.mbr.terminate) {
                        new_prule.mbr_kill = 1;
                }
        }

	/* 挖矿策略 */
	if (protect_policy_global.behaviour.pool.enable) {
		new_prule.process_engine_on = 1;
                new_prule.miner_on = 1;
		if (protect_policy_global.behaviour.pool.terminate) {
                        new_prule.miner_kill = 1;
			if (protect_policy_global.behaviour.pool.locking) {
	                        new_prule.miner_lockip = 1;
	                        new_prule.miner_lockip_seconds = protect_policy_global.behaviour.pool.locking_time * 60;
	                }
                }
        }
	/* 总是取矿池数量，否则sniper启动时如果初始策略是不监控挖矿，内核里没有矿池，
	   后面再开监控挖矿，下面更新矿池时，认为矿池没变化，也不会更新内核里的矿池 */
	new_prule.minepool_count = rule_global_global.black.minner_num;

        /* 端口转发策略 */
	if (protect_policy_global.process.tunnel.enable) {
		new_prule.process_engine_on = 1;
                new_prule.port_forward_on = 1;
		if (protect_policy_global.process.tunnel.terminate) {
                        new_prule.port_forward_kill = 1;
                }
        }

	/* 伪造系统进程 */
	if (protect_policy_global.process.fake_sys_process.enable) {
		new_prule.process_engine_on = 1;
                new_prule.fake_sysprocess_on = 1;
		if (protect_policy_global.process.fake_sys_process.terminate) {
                        new_prule.fake_sysprocess_kill = 1;
                }
        }

	if (rule_black_global.process_num) {
		new_prule.process_engine_on = 1;
		new_prule.black_count = rule_black_global.process_num;
		new_prule.black_kill = 1;
	}
	/* 可信过滤名单不独立触发进程引擎，可信过滤需要和进程事件相配合 */
	new_prule.trust_count = rule_trust_global.process_num;
	new_prule.filter_count = rule_filter_global.process_num;

	/* 中间件：遍历当前监听端口及程序，自识别中间件（最多64个）*/
	new_prule.webmiddle_count = SNIPER_MIDDLEWARE_NUM;

	new_prule.command_count = protect_policy_global.process.command_num;

tellkern:
	if (memcmp(&new_prule, &prule, size) != 0) {
		if (send_data_to_kern(NLMSG_PROCESS_RULES, (char *)&new_prule, size) < 0) {
			MON_ERROR("set kern_process_rules fail\n");
			return;
		}
		prule = new_prule;
	}

	if (!new_prule.process_engine_on) {
		free_process_rules_mem();
		return;
	}

	update_kernel_pmiddleware();

	pthread_rwlock_rdlock(&rule_black_global.lock);
	update_kernel_black_process();
	pthread_rwlock_unlock(&rule_black_global.lock);

	pthread_rwlock_rdlock(&rule_filter_global.lock);
	update_kernel_filter_process();
	pthread_rwlock_unlock(&rule_filter_global.lock);

	pthread_rwlock_rdlock(&rule_trust_global.lock);
	update_kernel_trust_process();
	pthread_rwlock_unlock(&rule_trust_global.lock);

	pthread_rwlock_rdlock(&protect_policy_global.lock);
	update_kernel_command_table();
	pthread_rwlock_unlock(&protect_policy_global.lock);

	update_kernel_mine_pool();

	if (!conf_global.licence_expire && client_disable == TURN_MY_OFF) {
		check_tasklist_event();
	}

	//TODO 扫描已经存在的过滤进程，并传给内核
}

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

//TODO 也许放到taskstat里做
static void get_raw_md5(char *cmd, char *md5)
{
}

/* return 1, match; 0, not match */
static int cmdname_match(char *pattern, char *name)
{
	int len1 = 0, len2 = 0;
	char *ptr = NULL, str[256] = {0};

	if (!pattern || !name) {
		return 0;
	}

	ptr = strchr(str, '*');
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

	strncpy(str, pattern, 255);	// xxx*yyy
	*ptr = 0;
	len1 = strlen(pattern);
	if (strncmp(name, pattern, len1) == 0) { //以xxx开头
		ptr++;
		len1 = strlen(ptr);
		len2 = strlen(name);
		if (strcmp(name+len2-len1, ptr) == 0) { //以yyy结尾
			return 1;
		}
	}

	return 0;
}

//TODO md5相同时，cmdline里的命令名可以忽略
/* return 1, match; 0, not match */
static int cmdline_match(char *pattern, char *cmdline, char *match_type)
{
	int type = RULE_FLAG_PARAM_EQUAL;

	if (!pattern || !cmdline) {
		return 0;
	}

	if (match_type) {
		if (strcmp(match_type, "1") == 0) {
			type = RULE_FLAG_PARAM_INCLUDE;
		} else if (strcmp(match_type, "2") == 0) {
			type = RULE_FLAG_PARAM_EXCLUDE;
		}
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

/* return 0, not black; 1, black */
int is_black_cmd(taskstat_t *taskstat)
{
	int i = 0, num = 0;
	char *cmdname = NULL, *pcmdname = "";
	char raw_md5[S_MD5LEN] = {0};
	BLACK_PROCESS *rule = NULL;
	taskstat_t *ptaskstat = NULL;

	/* 学习和运维模式下规则名单不生效 */
	if (client_mode_global != NORMAL_MODE) {
		return 0;
	}

	if (!taskstat) {
		return 0;
	}

	cmdname = safebasename(taskstat->cmd);

	ptaskstat = the_ptaskstat(taskstat);
	if (ptaskstat) {
		pcmdname = safebasename(ptaskstat->cmd);
	}

	pthread_rwlock_rdlock(&rule_black_global.lock);

	num = rule_black_global.process_num;
	if (num == 0) {
		pthread_rwlock_unlock(&rule_black_global.lock);
		return 0;
	}

	get_raw_md5(taskstat->cmd, raw_md5);

	for (i = 0; i < num; i++) {
		int checked = 0, md5_match = 0;

		rule = &rule_black_global.process[i];

		if (is_valid_str(rule->md5)) {
			checked = 1;
			if (strcmp(rule->md5, taskstat->md5) != 0) {
				continue;
			}
			md5_match = 1;
		}

		if (!md5_match) { //md5匹配，则不用检查进程名和路径
			if (is_valid_str(rule->process_name)) {
				checked = 1;
				if (!cmdname_match(rule->process_name, cmdname)) {
					continue;
				}
			}

			if (is_valid_str(rule->process_path)) {
				checked = 1;
				if (strcmp(rule->process_path, taskstat->cmd) != 0) {
					continue;
				}
			}
		}

		if (is_valid_str(rule->process_commandline)) {
			checked = 1;
			if (!cmdline_match(rule->process_commandline, taskstat->args, rule->param)) {
				continue;
			}
		}

		if (is_valid_str(rule->process_user)) {
			checked = 1;
			if (strcmp(rule->process_user, taskstat->user) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->remote_ip)) {
			checked = 1;
			if (strcmp(rule->remote_ip, taskstat->ip) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->parent_process_name)) {
			checked = 1;
			if (!cmdname_match(rule->parent_process_name, pcmdname)) {
				continue;
			}
		}

		/* 这是一条全空的规则，忽略 */
		if (!checked) {
			continue;
		}

		pthread_rwlock_unlock(&rule_black_global.lock);
		return 1;
	}

	pthread_rwlock_unlock(&rule_black_global.lock);
	return 0;
}

/* return 0, not trust; not 0, trust event_flags */
int is_trust_cmd(taskstat_t *taskstat)
{
	int i = 0, num = 0;
	char *cmdname = NULL, *pcmdname = "";
	char raw_md5[S_MD5LEN] = {0};
	TRUST_PROCESS *rule = NULL;
	taskstat_t *ptaskstat = NULL;

	/* 学习和运维模式下规则名单不生效 */
	if (client_mode_global != NORMAL_MODE) {
		return 0;
	}

	if (!taskstat) {
		return 0;
	}

	cmdname = safebasename(taskstat->cmd);

	ptaskstat = the_ptaskstat(taskstat);
	if (ptaskstat) {
		pcmdname = safebasename(ptaskstat->cmd);
	}

	pthread_rwlock_rdlock(&rule_trust_global.lock);

	num = rule_trust_global.process_num;
	if (num == 0) {
		pthread_rwlock_unlock(&rule_trust_global.lock);
		return 0;
	}

	get_raw_md5(taskstat->cmd, raw_md5);

	for (i = 0; i < num; i++) {
		int checked = 0;

		rule = &rule_trust_global.process[i];

		if (is_valid_str(rule->md5)) {
			checked = 1;
			if (strcmp(rule->md5, taskstat->md5) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->process_name)) {
			checked = 1;
			if (!cmdname_match(rule->process_name, cmdname)) {
				continue;
			}
		}

		if (is_valid_str(rule->process_path)) {
			checked = 1;
			if (strcmp(rule->process_path, taskstat->cmd) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->process_commandline)) {
			checked = 1;
			if (!cmdline_match(rule->process_commandline, taskstat->args, rule->param)) {
				continue;
			}
		}

		if (is_valid_str(rule->process_user)) {
			checked = 1;
			if (strcmp(rule->process_user, taskstat->user) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->remote_ip)) {
			checked = 1;
			if (strcmp(rule->remote_ip, taskstat->ip) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->parent_process_name)) {
			checked = 1;
			if (!cmdname_match(rule->parent_process_name, pcmdname)) {
				continue;
			}
		}

		/* 这是一条全空的规则，忽略 */
		if (!checked) {
			continue;
		}

		pthread_rwlock_unlock(&rule_trust_global.lock);
		return rule->event_flags;
	}

	pthread_rwlock_unlock(&rule_trust_global.lock);
	return 0;
}

/* return 0, not filter; not 0, filter event_flags */
int is_filter_cmd(taskstat_t *taskstat)
{
	int i = 0, num = 0;
	char *cmdname = NULL, *pcmdname = "";
	char raw_md5[S_MD5LEN] = {0};
	FILTER_PROCESS *rule = NULL;
	taskstat_t *ptaskstat = NULL;

	/* 学习和运维模式下规则名单不生效 */
	if (client_mode_global != NORMAL_MODE) {
		return 0;
	}

	if (!taskstat) {
		return 0;
	}

	cmdname = safebasename(taskstat->cmd);

	ptaskstat = the_ptaskstat(taskstat);
	if (ptaskstat) {
		pcmdname = safebasename(ptaskstat->cmd);
	}

	pthread_rwlock_rdlock(&rule_filter_global.lock);

	num = rule_filter_global.process_num;
	if (num == 0) {
		pthread_rwlock_unlock(&rule_filter_global.lock);
		return 0;
	}

	get_raw_md5(taskstat->cmd, raw_md5);

	for (i = 0; i < num; i++) {
		int checked = 0;

		rule = &rule_filter_global.process[i];

		if (is_valid_str(rule->md5)) {
			checked = 1;
			if (strcmp(rule->md5, taskstat->md5) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->process_name)) {
			checked = 1;
			if (!cmdname_match(rule->process_name, cmdname)) {
				continue;
			}
		}

		if (is_valid_str(rule->process_path)) {
			checked = 1;
			if (strcmp(rule->process_path, taskstat->cmd) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->process_commandline)) {
			checked = 1;
			if (!cmdline_match(rule->process_commandline, taskstat->args, rule->param)) {
				continue;
			}
		}

		if (is_valid_str(rule->process_user)) {
			checked = 1;
			if (strcmp(rule->process_user, taskstat->user) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->remote_ip)) {
			checked = 1;
			if (strcmp(rule->remote_ip, taskstat->ip) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->parent_process_name)) {
			checked = 1;
			if (!cmdname_match(rule->parent_process_name, pcmdname)) {
				continue;
			}
		}

		/* 这是一条全空的规则，忽略 */
		if (!checked) {
			continue;
		}

		pthread_rwlock_unlock(&rule_filter_global.lock);
		return 1;
	}

	pthread_rwlock_unlock(&rule_filter_global.lock);
	return 0;
}

#if 0
int is_filter_cmd(proc_msg_t *msg)
{
	int i = 0, num = 0;
	char *cmdname = NULL, *pcmdname = NULL;
	FILTER_PROCESS *rule = NULL;

	/* 学习模式下过滤名单不生效 */
	if (client_mode_global == LEARNING_MODE) {
		return 0;
	}

	if (!msg) {
		return 0;
	}

	cmdname = safebasename(msg->cmd);
	pcmdname = safebasename(msg->pcmd);

	pthread_rwlock_rdlock(&rule_filter_global.lock);

	num = rule_filter_global.process_num;
	if (num == 0) {
		pthread_rwlock_unlock(&rule_filter_global.lock);
		return 0;
	}

	for (i = 0; i < num; i++) {
		int checked = 0;

		rule = &rule_filter_global.process[i];

		if (is_valid_str(rule->md5)) {
			checked = 1;
			if (strcmp(rule->md5, msg->md5) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->process_name)) {
			checked = 1;
			if (!cmdname_match(rule->process_name, cmdname)) {
				continue;
			}
		}

		if (is_valid_str(rule->process_path)) {
			checked = 1;
			if (strcmp(rule->process_path, msg->cmd) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->process_commandline)) {
			checked = 1;
			if (!cmdline_match(rule->process_commandline, msg->cmdline, rule->param)) {
				continue;
			}
		}

		if (is_valid_str(rule->process_user)) {
			checked = 1;
			if (strcmp(rule->process_user, msg->user) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->remote_ip)) {
			checked = 1;
			if (strcmp(rule->remote_ip, msg->ip) != 0) {
				continue;
			}
		}

		if (is_valid_str(rule->parent_process_name)) {
			checked = 1;
			if (!cmdname_match(rule->parent_process_name, pcmdname)) {
				continue;
			}
		}

		/* 这是一条全空的规则，忽略 */
		if (!checked) {
			continue;
		}

		pthread_rwlock_unlock(&rule_filter_global.lock);
		return 1;
	}

	pthread_rwlock_unlock(&rule_filter_global.lock);
	return 0;
}
#endif

static unsigned short get_listen_socket_port(char *filename, unsigned long ino)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	sockinfo_t info = {0};
	unsigned short port = 0;

	fp = sniper_fopen(filename, "r", PROCESS_GET);
	if (!fp) {
		return 0;
	}
	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		if (get_socket_info(line, &info) < 0) {
			continue;
		}
		if (info.inode == ino) {
			port = info.src_port;
			break;
		}
	}
	sniper_fclose(fp, PROCESS_GET);
	return port;
}

static void get_listen_sockets(char *filename, int *midnum, struct sniper_middleware *mid)
{
	int i = 0, num = *midnum;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};
	sockinfo_t info = {0};

	fp = sniper_fopen(filename, "r", PROCESS_GET);
	if (!fp) {
		return;
	}
	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		if (get_socket_info(line, &info) < 0) {
			continue;
		}
		if (info.state != TCP_LISTEN) {
			continue;
		}
		if (strncmp(info.src_ip, "127", 3) == 0) {
			continue;
		}
		for (i = 0; i < num; i++) {
			if (mid[i].port == info.src_port) {
				break;
			}
		}
		if (i < num) {
			continue; //此端口已经记录
		}

		mid[num].port = info.src_port;
		mid[num].ino = info.inode;

		num++;
		if (num == SNIPER_MIDDLEWARE_NUM) {
			MON_ERROR("too many middlewares > %d, "
				"should increase SNIPER_MIDDLEWARE_NUM\n",
				SNIPER_MIDDLEWARE_NUM);
			break;
		}
	}
	sniper_fclose(fp, PROCESS_GET);
	*midnum = num;
}

/* 检查进程是否打开了某个inode的socket，是返回打开的文件描述符，否返回-1 */
static int proc_open_inode(pid_t pid, unsigned long ino)
{
	int fd = 0;
	DIR *fddirp = NULL;
	struct dirent *fdent = NULL;
	char fddir[128] = {0}, fdpath[512] = {0};

	snprintf(fddir, sizeof(fddir), "/proc/%d/fd", pid);
	fddirp = sniper_opendir(fddir, PROCESS_GET);
	if (!fddirp) {
		if (errno != ENOENT) {
			MON_ERROR("open %s error: %s\n", fddir, strerror(errno));
		}
		return -1;
	}

	/* 遍历进程的fd */
	while ((fdent = readdir(fddirp))) {
		unsigned long tmp_ino = 0;
		char linkname[S_NAMELEN] = {0};

		if (fdent->d_name[0] < '0' || fdent->d_name[0] > '9') {
			continue;
		}

		snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%s", pid, fdent->d_name);
		/* readlink不加0结尾加，因此使用前必须清linkname，否则上一次的值会干扰 */
		readlink(fdpath, linkname, sizeof(linkname)-1);
		sscanf(linkname, "socket:[%lu]", &tmp_ino);
		if (tmp_ino == ino) {
			fd = atoi(fdent->d_name);
			sniper_closedir(fddirp, PROCESS_GET);
			return fd;
		}
	}
	sniper_closedir(fddirp, PROCESS_GET);
	return -1;
}

/* 检查父进程是否也打开了该端口，如果是，说明子进程是继承自父进程，真正打开端口的是父进程 */
/* ino为端口socket的inode号 */
static pid_t get_real_listen_process(pid_t pid, unsigned long ino, int *fd)
{
	int pfd = 0;
	pid_t ppid = 0, target = pid;

	while (target > 0) {
		ppid = get_proc_ppid(target);
		if (ppid < 300) {
			break;
		}

		pfd = proc_open_inode(ppid, ino); //检查父进程是否打开端口
		if (pfd < 0) {
			break; //父进程没有打开端口，则本进程为真正打开该端口的进程
		}

		/* 父进程打开了端口，继续查是否上级父进程打开的端口 */
		target = ppid;
		*fd = pfd;
	}

	return target;
}

//TODO 处理一个进程监听多个端口的情况。如果这里处理了，进程监控里就不需要在做get_middleware_listening_ports
/* 将监听端口与中间件名称关联起来 */
static void get_real_middleware(struct sniper_middleware *mid, int midnum)
{
	int i = 0, found = 0, fd = 0;
	DIR *procdirp = NULL, *fddirp = NULL;
	struct dirent *pident = NULL, *fdent = NULL;
	char fddir[128] = {0}, fdpath[512] = {0};
	pid_t pid = 0;

	procdirp = sniper_opendir("/proc", PROCESS_GET);
	if (!procdirp) {
		MON_ERROR("get_real_middleware fail, "
			"open /proc error: %s\n", strerror(errno));
		return;
	}

	/* 遍历所有进程 */
	while ((pident = readdir(procdirp))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue;
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) { //1号2号进程不可能是对外服务进程
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

		snprintf(fddir, sizeof(fddir), "/proc/%d/fd", pid);
		fddirp = sniper_opendir(fddir, PROCESS_GET);
		if (!fddirp) {
			if (errno != ENOENT) {
				MON_ERROR("open %s error: %s\n", fddir, strerror(errno));
			}
			continue;
		}

		/* 遍历进程的fd */
		while ((fdent = readdir(fddirp))) {
			unsigned long tmp_ino = 0;
			char linkname[S_NAMELEN] = {0};
			char cmd[S_CMDLEN] = {0};

			if (fdent->d_name[0] < '0' || fdent->d_name[0] > '9') {
				continue; //不是文件描述符
			}

			snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%s", pid, fdent->d_name);
			/* readlink不加0结尾加，因此使用前必须清linkname， 否则上一次的值会干扰 */
			readlink(fdpath, linkname, sizeof(linkname)-1);
			if (sscanf(linkname, "socket:[%lu]", &tmp_ino) != 1) {
				continue; //不是socket文件
			}

			/* 对进程的每个文件，检查是否为监听的端口 */
			for (i = 0; i < midnum; i++) {
				if (mid[i].pid) {
					continue; //此中间件的进程已经解析过了
				}
				if (tmp_ino != mid[i].ino) {
					continue; //inode号与中间件不匹配
				}

				/* 是监听的端口 */
				fd = atoi(fdent->d_name);
				mid[i].pid = get_real_listen_process(pid, mid[i].ino, &fd);
				mid[i].action = MID_SET;
				mid[i].fd = fd;
				found++;

				/* 优先取命令名，进程可能会修改进程名 */
				if (get_proc_exe(mid[i].pid, cmd) > 0) {
					snprintf(mid[i].name, sizeof(mid[i].name), "%s", safebasename(cmd));
				} else {
					get_proc_comm(mid[i].pid, mid[i].name);
				}

				break;
			}

			/* 所有监听端口都解析完毕 */
			if (found == midnum) {
				break;
			}
		}
		sniper_closedir(fddirp, PROCESS_GET);

		/* 所有监听端口都解析完毕 */
		if (found == midnum) {
			break;
		}
	}
	sniper_closedir(procdirp, PROCESS_GET);
}

//TODO 改成灵活的
pthread_rwlock_t middleware_lock;
struct sniper_middleware sniper_mid[SNIPER_MIDDLEWARE_NUM] = {{{0}}};
void init_kernel_pmiddleware(void)
{
	int midsize = 0, midnum = 0;
	struct sniper_middleware mid[SNIPER_MIDDLEWARE_NUM];

	pthread_rwlock_init(&middleware_lock, 0);

	midsize = sizeof(struct sniper_middleware) * SNIPER_MIDDLEWARE_NUM;
	memset(mid, 0, midsize);

	get_listen_sockets("/proc/net/tcp", &midnum, mid);
	get_listen_sockets("/proc/net/tcp6", &midnum, mid);

	if (midnum == 0) {
		return;
	}

	get_real_middleware(mid, midnum);

	pthread_rwlock_wrlock(&middleware_lock);
	memcpy(sniper_mid, mid, midsize);
	pthread_rwlock_unlock(&middleware_lock);

	midsize = midnum * sizeof(struct sniper_middleware);
	if (send_data_to_kern(NLMSG_PMIDDLEWARE, (char *)mid, midsize) < 0) {
		MON_ERROR("init kernel process middleware fail\n");
	}
}

/* 为了减少写锁的时间，独立出来，不在update_kernel_process_rules()里做 */
/* 进程中间件执行，和网络连入连出黑白名单用到了这个 */
void update_kernel_pmiddleware(void)
{
	FILE *fp = NULL;
	int size = sizeof(struct sniper_middleware);
	int midsize = 0, i = 0, j = 0, found = 0, ret = 0;
	int port = 0;
	struct sniper_middleware mid[SNIPER_MIDDLEWARE_NUM];
	char line[S_LINELEN] = {0};
	DIR *fddirp = NULL;
	struct dirent *fdent = NULL;
	char fddir[128] = {0}, fdpath[512] = {0};

	fp = fopen("/proc/sys/sniper/middleware", "r");
	if (!fp) {
		return;
	}

	midsize = size * SNIPER_MIDDLEWARE_NUM;
	memset(mid, 0, midsize);
	midsize = 0;

	pthread_rwlock_wrlock(&middleware_lock);

	while (fgets(line, sizeof(line), fp)) {
		memset(&mid[i], 0, size);
		ret = sscanf(line, "%*s %15s %d port %d fd %d ino %lu",
				mid[i].name, &mid[i].pid, &port, &mid[i].fd, &mid[i].ino);
		if (ret != 5) {
			continue;
		}

		if (mid[i].pid <= 0) {
			continue; //无效的条目
		}
		mid[i].port = port;

		if (mid[i].fd >= 0) { //检查端口是否已经关闭
			unsigned long tmp_ino = 0;
			char linkname[S_NAMELEN] = {0};

			snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%d", mid[i].pid, mid[i].fd);
			readlink(fdpath, linkname, sizeof(linkname)-1);
			sscanf(linkname, "socket:[%lu]", &tmp_ino);
			if (tmp_ino != mid[i].ino) {
				/* 端口已关闭，通知内核 */
				mid[i].action = MID_CLOSE;
				midsize += size;
				i++;
			} else {
				/* 端口仍开着，存入sniper_mid */
				memcpy(&sniper_mid[j], &mid[i], size);
				j++;
			}

			continue;
		}

		/* 检查端口是否已经关闭，或补足端口信息 */
		found = 0;
		snprintf(fddir, sizeof(fddir), "/proc/%d/fd", mid[i].pid);
		fddirp = sniper_opendir(fddir, PROCESS_GET);
		if (fddirp) {
			while ((fdent = readdir(fddirp))) {
				unsigned long tmp_ino = 0;
				char linkname[S_NAMELEN] = {0};

				if (fdent->d_name[0] < '0' || fdent->d_name[0] > '9') {
					continue; //不是文件描述符
				}

				snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%s", mid[i].pid, fdent->d_name);
				readlink(fdpath, linkname, sizeof(linkname)-1);
				sscanf(linkname, "socket:[%lu]", &tmp_ino);
				if (tmp_ino != mid[i].ino) {
					continue;
				}

				found = 1;
				break;
			}
			sniper_closedir(fddirp, PROCESS_GET);
		}

		if (!found) {
			/* 端口已关闭，通知内核 */
			mid[i].action = MID_CLOSE;
			midsize += size;
			i++;
		} else {
			/* 更新补足内核的中间件信息 */
			mid[i].action = MID_SET;
			mid[i].fd = atoi(fdent->d_name);
			if (mid[i].port == 0) {
				mid[i].port = get_listen_socket_port("/proc/net/tcp", mid[i].ino);
				if (mid[i].port == 0) {
					mid[i].port = get_listen_socket_port("/proc/net/tcp6", mid[i].ino);
				}
			}
			midsize += size;
			i++;

			/* 端口仍开着，存入sniper_mid */
			memcpy(&sniper_mid[j], &mid[i], size);
			j++;
		}
	}

	pthread_rwlock_unlock(&middleware_lock);

	fclose(fp);

	if (midsize) {
		if (send_data_to_kern(NLMSG_PMIDDLEWARE, (char *)mid, midsize) < 0) {
			MON_ERROR("update kernel process middleware fail\n");
		}
	}
}
