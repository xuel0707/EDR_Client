#include "header.h"

char *policy_on = "开启";
char *policy_on_en = "open";
char *policy_off = "关闭";
char *policy_off_en = "close";
char *policy_permit = "允许";
char *policy_permit_en = "allow";
char *policy_deny = "禁止";
char *policy_deny_en = "terminate";
char *policy_yes = "是";
char *policy_yes_en = "yes";
char *policy_no = "否";
char *policy_no_en = "no";
char *policy_logout_next = "下次注销";
char *policy_logout_next_en = "next logout";
char *policy_logout_now = "立即注销";
char *policy_logout_now_en = "log out now";
char *easy_mode = "宽松检测";
char *easy_mode_en = "loose detection";
char *hard_mode = "严格检测";
char *hard_mode_en = "Strict detection";
char *full_scan = "全盘扫描";
char *full_scan_en = "full scan";
char *quick_scan = "快速扫描";
char *quick_scan_en = "quick scan";
char *ask_me = "询问我";
char *ask_me_en = "ask me";
char *auto_process = "自动处理";
char *auto_process_en = "auto process";

char policy_id_cur[POLICY_ID_LEN_MAX] = {0};
char policy_name_cur[POLICY_NAME_LEN_MAX] = {0};
char policy_time_cur[POLICY_TIME_LEN_MAX] = {0};

PROTECT_POLICY protect_policy_global = {{{0}}};
FASTEN_POLICY fasten_policy_global = {{0}};
OTHER_POLICY other_policy_global = {{0}};

PROTECT_POLICY old_protect_policy_global = {{{0}}};
FASTEN_POLICY old_fasten_policy_global = {{0}};
OTHER_POLICY old_other_policy_global = {{0}};

int protect_count = 0;
int fasten_count = 0;
int other_count = 0;

/* 送到内核的数据需要判断病毒防护开关，此变量保留 */
ANTIVIRUS_POLICY antivirus_policy_global = {0};
int antivirus_count = 0;
#ifdef USE_AVIRA
ANTIVIRUS_POLICY old_antivirus_policy_global = {0};
#endif

pthread_mutex_t policy_update_lock;

char *check_my_switch_logout(int type)
{
	if (type == LOGOUT_NEXT) {
		return policy_logout_next;
	}

	return policy_logout_now;
}

char *check_my_switch_logout_en(int type)
{
	if (type == LOGOUT_NEXT) {
		return policy_logout_next_en;
	}

	return policy_logout_now_en;
}

char *check_my_switch(int type)
{
	if (type == MY_TURNON) {
		return policy_on;
	}

	return policy_off;
}

char *check_my_switch_en(int type)
{
	if (type == MY_TURNON) {
		return policy_on_en;
	}

	return policy_off_en;
}

char *check_my_switch_permit(int type)
{
        if (type == MY_TURNON) {
                return policy_deny;
        }

	return policy_permit;
}

char *check_my_switch_permit_en(int type)
{
        if (type == MY_TURNON) {
                return policy_deny_en;
        }

	return policy_permit_en;
}

char *check_my_switch_yes(int type)
{
	if (type == MY_TURNON) {
		return policy_yes;
	}

	return policy_no;
}

char *check_my_switch_yes_en(int type)
{
	if (type == MY_TURNON) {
		return policy_yes_en;
	}

	return policy_no_en;
}

char *check_antivirus_scan_type(int type)
{
	if (type == 1) {
		return full_scan;
	}

	return quick_scan;
}

char *check_antivirus_scan_type_en(int type)
{
	if (type == 1) {
		return full_scan_en;
	}

	return quick_scan_en;
}

char *check_antivirus_process_type(int type)
{
	if (type == 0) {
		return ask_me;
	}

	return auto_process;
}

char *check_antivirus_process_type_en(int type)
{
	if (type == 0) {
		return ask_me_en;
	}

	return auto_process_en;
}

char *check_webshell_mode(int mode)
{
	if (mode == 1) {
		return easy_mode;
	}

	return hard_mode;
}

char *check_webshell_mode_en(int mode)
{
	if (mode == 1) {
		return easy_mode_en;
	}

	return hard_mode_en;
}

static inline void DoXOR(unsigned long key, char *data, int len)
{
	if (len) {
		while (len--) {
			*(data++) ^= key;
		}
	}
}

static int display_file(char *filename)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	fp = sniper_fopen(filename, "r", POLICY_GET);
	if (!fp) {
		return -1;
	}

	while (fgets(line, S_LINELEN, fp)) {
		printf("%s", line);
	}
	printf("\n");

	sniper_fclose(fp, POLICY_GET);
	return 0;
}

int list_policy(void)
{
	if (access(POLICY_SELFINFO_FILE, F_OK) < 0 ||
	    access(POLICY_PROTECT_FILE, F_OK) < 0 ||
	    access(POLICY_FASTEN_FILE, F_OK) < 0 ||
	    access(POLICY_OTHER_FILE, F_OK) < 0) {
		printf("策略未生效\n");
		return -1;
	}

	if (access(AVIRA_ENABLE, F_OK) == 0) {
		if (access(POLICY_ANTIVIRUS_FILE, F_OK) < 0) {
			printf("病毒防护策略未生效\n");
			return -1;
		}
	}


	if (display_file(POLICY_SELFINFO_FILE) < 0) {
		printf("防护策略显示失败");
		return -1;
	}

	if (display_file(POLICY_PROTECT_FILE) < 0) {
		printf("防护策略显示失败");
		return -1;
	}

	if (display_file(POLICY_FASTEN_FILE) < 0) {
		printf("加固策略显示失败");
		return -1;
	}

	if (access(AVIRA_ENABLE, F_OK) == 0) {
		if (display_file(POLICY_ANTIVIRUS_FILE) < 0) {
			printf("病毒防护显示失败");
			return -1;
		}
	}

	if (display_file(POLICY_OTHER_FILE) < 0) {
		printf("其他策略显示失败");
		return -1;
	}

	return 0;
}

/* 获取json字符串的valuestring */
char *get_my_valuestring(cJSON *item)
{
	int len = 0;
	char *buf = NULL;

	if (item->valuestring == NULL) {
		MON_ERROR("Item json valuestring is NULL\n");
		return NULL;
	}

	len = strlen(item->valuestring) + 1;
	buf = (char*)sniper_malloc(len, POLICY_GET);
	if (buf == NULL) {
		MON_ERROR("value malloc failed\n");
		return NULL;
	}
	strcpy(buf, item->valuestring);

	return buf;
}

/*
 * 对于新增加的策略/规则/配置字段, json解析时没有找到该字段时，可以调用此函数
 * 函数统一为这些字段的指针开辟一个字节的空间
 * 目的是统一后续的空间释放和防止对这些指针的使用不当误操作了空指针导致程序core掉
 */
char *get_customize_valuestring(void)
{
	int len = 1;
	char *buf = NULL;

	buf = (char*)sniper_malloc(len, POLICY_GET);
	if (buf == NULL) {
		MON_ERROR("value malloc failed\n");
		return NULL;
	}
	buf[0] = '\0';

	return buf;
}

/* 取列表，例如后缀名并拼接成|php||php5||asp||asa|这种形式 */
static char *get_name(cJSON *object, char *namestr)
{
	cJSON *arrayExt = NULL, *name = NULL;
	int i = 0, count = 0, buflen = 0;
	char *buf = NULL, *ext = NULL, *str = NULL, *ptr = NULL, *val = NULL;

        name = cJSON_GetObjectItem(object, namestr);
        if (!name) {
                MON_ERROR("get_name %s: cJSON_GetObjectItem error\n", namestr);
                return NULL;
        }

	count = cJSON_GetArraySize(name);
	/* 没有内容，视为* */
	if (count == 0) {
		buf = sniper_malloc(4, POLICY_GET);
		if (buf == NULL) {
			MON_ERROR("get_name %s fail, no memory\n", namestr);
			return NULL;
		}
		strcpy(buf, "|*|");
		return buf;
	}

	str = cJSON_PrintUnformatted(name);
	buflen = strlen(str);
	free(str);

	/* 例如extjson的格式是["php","php5","asp","asa"]，长度超过|php||php5||asp||asa|，
	   所以按extjson的长度给exlist分空间，是足够的 */
	buf = sniper_malloc(buflen, POLICY_GET);
	if (!buf) {
		MON_ERROR("get_name %s fail, no memory\n", namestr);
		return NULL;
	}

	ptr = buf;
	for (i = 0; i < count; i++) {
		arrayExt = cJSON_GetArrayItem(name, i);
		if (!arrayExt) {
			str = cJSON_PrintUnformatted(name);
			MON_ERROR("get_name %s cJSON_GetArrayItem error, array is %s.\n", namestr, str);
			free(str);
			sniper_free(buf, buflen, POLICY_GET);
			return NULL;
		}

		val = skip_headspace(arrayExt->valuestring);
		delete_tailspace(val);

		*ptr = '|';
		ptr++;
		strcpy(ptr, val);
		ptr += strlen(val);
		*ptr = '|';
		ptr++;
	}
	*ptr = 0;

	ext = sniper_malloc(strlen(buf)+1, POLICY_GET);
	if (!ext) {
		MON_ERROR("get_name %s fail, no memory\n", namestr);
		sniper_free(buf, buflen, POLICY_GET);
		return NULL;
	}

	strcpy(ext, buf);
	sniper_free(buf, buflen, POLICY_GET);
	return ext;
}

static int get_policy_protect_behaviour_pool(cJSON *pool, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *locking, *locking_time;

	enable = cJSON_GetObjectItem(pool, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect behaviour pool enable error\n");
                return -1;
        }
	protect_policy->behaviour.pool.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(pool, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect behaviour pool terminate error\n");
                return -1;
        }
	protect_policy->behaviour.pool.terminate = terminate->valueint;

	locking = cJSON_GetObjectItem(pool, "locking");
        if (!locking) {
		MON_ERROR("policy cJSON_Parse protect behaviour pool locking error\n");
                return -1;
        }
	protect_policy->behaviour.pool.locking = locking->valueint;

	locking_time = cJSON_GetObjectItem(pool, "locking_time");
        if (!locking_time) {
		MON_ERROR("policy cJSON_Parse protect behaviour pool locking_time error\n");
                return -1;
        }
	protect_policy->behaviour.pool.locking_time = locking_time->valueint;

	return 0;
}

static int get_policy_protect_behaviour_ransomware_track(cJSON *track, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;
	char *ext = NULL;

	enable = cJSON_GetObjectItem(track, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware track enable error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.track.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(track, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware track terminate error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.track.terminate = terminate->valueint;

	ext = get_name(track, "extension");
	if (ext == NULL) {
		MON_ERROR("get track extension error\n");
	} else {
		protect_policy->behaviour.ransomware.track.ext.list = ext;
	}

	return 0;
}

static int get_policy_protect_behaviour_ransomware_encrypt_my_linux(cJSON *my_linux, struct _PROTECT_POLICY *protect_policy)
{
	char *ext = NULL;

	ext = get_name(my_linux, "extension");
	if (ext == NULL) {
		MON_ERROR("get encrypt linux extension error\n");
		return -1;
	}
	protect_policy->behaviour.ransomware.encrypt.my_linux.ext.list = ext;

	return 0;
}

static int get_policy_protect_behaviour_ransomware_encrypt(cJSON *encrypt, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;
	cJSON *my_linux, *hide, *backup;
	cJSON *neglect_min, *neglect_size, *backup_size;
	char *ext = NULL;

	enable = cJSON_GetObjectItem(encrypt, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt enable error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.encrypt.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(encrypt, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt terminate error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.encrypt.terminate = terminate->valueint;

	ext = get_name(encrypt, "extension");
	if (ext == NULL) {
		MON_ERROR("get encrypt extension error\n");
	} else {
		protect_policy->behaviour.ransomware.encrypt.ext.list = ext;
	}

	my_linux = cJSON_GetObjectItem(encrypt, "linux");
        if (!my_linux) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt linux error\n");
        } else {
		get_policy_protect_behaviour_ransomware_encrypt_my_linux(my_linux, protect_policy);
	}

	hide = cJSON_GetObjectItem(encrypt, "hide");
        if (!hide) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt hide error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.encrypt.hide = hide->valueint;

	backup = cJSON_GetObjectItem(encrypt, "backup");
        if (!backup) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt backup error\n");
                return -1;
        }

	enable = cJSON_GetObjectItem(backup, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt backup enable error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.encrypt.backup.enable = enable->valueint;

	neglect_min = cJSON_GetObjectItem(backup, "neglect_min");
        if (!neglect_min) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt backup neglect_min error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.encrypt.backup.neglect_min = neglect_min->valueint;

	neglect_size = cJSON_GetObjectItem(backup, "neglect_size");
        if (!neglect_size) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt backup neglect_size error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.encrypt.backup.neglect_size = neglect_size->valueint;

	backup_size = cJSON_GetObjectItem(backup, "backup_size");
        if (!backup_size) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt backup backup_size error\n");
                return -1;
        }
	protect_policy->behaviour.ransomware.encrypt.backup.backup_size = backup_size->valueint;

	return 0;
}

static int get_policy_protect_behaviour_ransomware(cJSON *ransomware, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *track, *encrypt;

	/* 追踪防护引擎 */
	track = cJSON_GetObjectItem(ransomware, "track");
        if (!track) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware track error\n");
        } else {
		if (get_policy_protect_behaviour_ransomware_track(track, protect_policy) < 0) {
			protect_policy->behaviour.ransomware.track.enable = 0;
		}
	}

	/* 加密防护引擎 */
	encrypt = cJSON_GetObjectItem(ransomware, "encrypt");
        if (!encrypt) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware encrypt error\n");
	} else {
		if (get_policy_protect_behaviour_ransomware_encrypt(encrypt, protect_policy) < 0) {
			protect_policy->behaviour.ransomware.encrypt.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_behaviour(cJSON *behaviour, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *pool, *ransomware;	

	/* 挖矿行为 */
	pool = cJSON_GetObjectItem(behaviour, "pool");
        if (!pool) {
		MON_ERROR("policy cJSON_Parse protect behaviour pool error\n");
        } else {
		if (get_policy_protect_behaviour_pool(pool, protect_policy) < 0) {
			protect_policy->behaviour.pool.enable = 0;
		}
	}

	/* 勒索行为 */
	ransomware = cJSON_GetObjectItem(behaviour, "ransomware");
        if (!ransomware) {
		MON_ERROR("policy cJSON_Parse protect behaviour ransomware error\n");
        } else {
		get_policy_protect_behaviour_ransomware(ransomware, protect_policy);
	}

	return 0;
}

static int get_policy_protect_process_reverse_shell(cJSON *reverse_shell, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *locking, *locking_time;

	enable = cJSON_GetObjectItem(reverse_shell, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process reverse_shell enable error\n");
                return -1;
        }
	protect_policy->process.reverse_shell.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(reverse_shell, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process reverse_shell terminate error\n");
                return -1;
        }
	protect_policy->process.reverse_shell.terminate = terminate->valueint;

	/* 不阻断，则不锁ip */
	if (TURN_MY_ON != protect_policy->process.reverse_shell.terminate) {
		protect_policy->process.reverse_shell.locking = 0;
		protect_policy->process.reverse_shell.locking_time = 0;
		return 0;
	}

	locking = cJSON_GetObjectItem(reverse_shell, "locking");
        if (!locking) {
		MON_ERROR("policy cJSON_Parse protect process reverse_shell locking error\n");
                return -1;
        }
	protect_policy->process.reverse_shell.locking = locking->valueint;

	if (TURN_MY_ON != protect_policy->process.reverse_shell.locking) {
		protect_policy->process.reverse_shell.locking_time = 0;
		return 0;
	}

	locking_time = cJSON_GetObjectItem(reverse_shell, "locking_time");
        if (!locking_time) {
		MON_ERROR("policy cJSON_Parse protect process reverse_shell locking_time error\n");
                return -1;
        }
	protect_policy->process.reverse_shell.locking_time = locking_time->valueint;

	return 0;
}

static int get_policy_protect_process_privilege(cJSON *privilege, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(privilege, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process privilege enable error\n");
                return -1;
        }
	protect_policy->process.privilege.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(privilege, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process privilege terminate error\n");
                return -1;
        }
	protect_policy->process.privilege.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_mbr(cJSON *mbr, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(mbr, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process mbr enable error\n");
                return -1;
        }
	protect_policy->process.mbr.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(mbr, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process mbr terminate error\n");
                return -1;
        }
	protect_policy->process.mbr.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_dangerous_command(cJSON *dangerous_command, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(dangerous_command, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process dangerous_command enable error\n");
                return -1;
        }
	protect_policy->process.dangerous_command.enable = enable->valueint;

	return 0;
}

static int get_policy_protect_process_webshell(cJSON *webshell, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(webshell, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process webshell enable error\n");
                return -1;
        }
	protect_policy->process.webshell.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(webshell, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process webshell terminate error\n");
                return -1;
        }
	protect_policy->process.webshell.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_service_process(cJSON *service_process, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(service_process, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process service_process enable error\n");
                return -1;
        }
	protect_policy->process.service_process.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(service_process, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process service_process terminate error\n");
                return -1;
        }
	protect_policy->process.service_process.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_fake_sys_process(cJSON *fake_sys_process, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(fake_sys_process, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process fake_sys_process enable error\n");
                return -1;
        }
	protect_policy->process.fake_sys_process.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(fake_sys_process, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process fake_sys_process terminate error\n");
                return -1;
        }
	protect_policy->process.fake_sys_process.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_tunnel(cJSON *tunnel, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(tunnel, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process tunnel enable error\n");
                return -1;
        }
	protect_policy->process.tunnel.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(tunnel, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process tunnel terminate error\n");
                return -1;
        }
	protect_policy->process.tunnel.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_risk_command(cJSON *risk_command, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(risk_command, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process risk_command enable error\n");
                return -1;
        }
	protect_policy->process.risk_command.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(risk_command, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process risk_command terminate error\n");
                return -1;
        }
	protect_policy->process.risk_command.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_abnormal_process(cJSON *abnormal_process, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(abnormal_process, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect process abnormal_process enable error\n");
                return -1;
        }
	protect_policy->process.abnormal_process.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(abnormal_process, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect process abnormal_process terminate error\n");
                return -1;
        }
	protect_policy->process.abnormal_process.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_process_command_table_list(cJSON *command_table_list, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *arrayItem;
	int i = 0, j = 0, num = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(command_table_list);
	protect_policy->process.command_num = num;

	protect_policy->process.command_table_list = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (protect_policy->process.command_table_list == NULL) {
		MON_ERROR("policy cJSON_Parse protect process command_table_list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(command_table_list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect process command_table_list[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->process.command_table_list[j].list);
			}
			sniper_free(protect_policy->process.command_table_list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("protect_policy->process.command_table_list[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->process.command_table_list[j].list);
			}
			sniper_free(protect_policy->process.command_table_list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->process.command_table_list[i].list = buf;

	}

	return 0;
}

static int get_policy_protect_process(cJSON *process, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *privilege, *mbr, *dangerous_command, *reverse_shell;
	cJSON *webshell, *service_process, *fake_sys_process, *tunnel, *risk_command, *abnormal_process;
	cJSON *command_table_list;

	/* 反弹shell */
	reverse_shell = cJSON_GetObjectItem(process, "reverse_shell");
        if (!reverse_shell) {
		MON_ERROR("policy cJSON_Parse protect process reverse_shell error\n");
	} else {
		if (get_policy_protect_process_reverse_shell(reverse_shell, protect_policy) < 0) {
			protect_policy->process.reverse_shell.enable = 0;
		}
	}

	/* 非法提权 */
	privilege = cJSON_GetObjectItem(process, "privilege");
        if (!privilege) {
		MON_ERROR("policy cJSON_Parse protect process privilege error\n");
	} else {
		if (get_policy_protect_process_privilege(privilege, protect_policy) < 0) {
			protect_policy->process.privilege.enable = 0;
		}
	}

	/* MBR防护 */
	mbr = cJSON_GetObjectItem(process, "mbr");
        if (!mbr) {
		MON_ERROR("policy cJSON_Parse protect process mbr error\n");
	} else {
		if (get_policy_protect_process_mbr(mbr, protect_policy) < 0) {
			protect_policy->process.mbr.enable = 0;
		}
	}

	/* 可疑命令执行 */
	dangerous_command = cJSON_GetObjectItem(process, "dangerous_command");
        if (!dangerous_command) {
		MON_ERROR("policy cJSON_Parse protect process dangerous_command error\n");
	} else {
		if (get_policy_protect_process_dangerous_command(dangerous_command, protect_policy) < 0) {
			protect_policy->process.dangerous_command.enable = 0;
		}
	}

	/* 中国菜刀命令执行 */
	webshell = cJSON_GetObjectItem(process, "webshell");
        if (!webshell) {
		MON_ERROR("policy cJSON_Parse protect process webshell error\n");
	} else {
		if (get_policy_protect_process_webshell(webshell, protect_policy) < 0) {
			protect_policy->process.webshell.enable = 0;
		}
        }

	/* 对外服务进程异常执行 */
	service_process = cJSON_GetObjectItem(process, "service_process");
        if (!service_process) {
		MON_ERROR("policy cJSON_Parse protect process service_process error\n");
	} else {
		if (get_policy_protect_process_service_process(service_process, protect_policy) < 0) {
			protect_policy->process.service_process.enable = 0;
		}
        }

	/* 伪造系统进程运行 */
	fake_sys_process = cJSON_GetObjectItem(process, "fake_sys_process");
        if (!fake_sys_process) {
		MON_ERROR("policy cJSON_Parse protect process fake_sys_process error\n");
	} else {
		if (get_policy_protect_process_fake_sys_process(fake_sys_process, protect_policy) < 0) {
			protect_policy->process.fake_sys_process.enable = 0;
		}
        }

	/* 隧道搭建 */
	tunnel = cJSON_GetObjectItem(process, "tunnel");
        if (!tunnel) {
		MON_ERROR("policy cJSON_Parse protect process tunnel error\n");
	} else {
		if (get_policy_protect_process_tunnel(tunnel, protect_policy) < 0) {
			protect_policy->process.tunnel.enable = 0;
		}
        }

	/* 危险命令 */
	risk_command = cJSON_GetObjectItem(process, "risk_command");
        if (!risk_command) {
		MON_ERROR("policy cJSON_Parse protect process risk_command error\n");
	} else {
		if (get_policy_protect_process_risk_command(risk_command, protect_policy) < 0) {
			protect_policy->process.risk_command.enable = 0;
		}
        }

	/* 异常进程 */
	abnormal_process = cJSON_GetObjectItem(process, "abnormal_process");
        if (!abnormal_process) {
		MON_ERROR("policy cJSON_Parse protect process abnormal_process error\n");
	} else {
		if (get_policy_protect_process_abnormal_process(abnormal_process, protect_policy) < 0) {
			protect_policy->process.abnormal_process.enable = 0;
		}
        }

	/* 命令列表 */
	command_table_list = cJSON_GetObjectItem(process, "command_table_list");
        if (!command_table_list) {
		MON_ERROR("policy cJSON_Parse protect process command_table_list error\n");
		protect_policy->process.command_num = 0;
	} else {
		if (get_policy_protect_process_command_table_list(command_table_list, protect_policy) < 0) {
			protect_policy->process.command_num = 0;
		}
        }

	return 0;
}

static int get_policy_protect_network_domain(cJSON *domain, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;

	enable = cJSON_GetObjectItem(domain, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network domain enable error\n");
                return -1;
        }
	protect_policy->network.domain.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(domain, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect network domain terminate error\n");
                return -1;
        }
	protect_policy->network.domain.terminate = terminate->valueint;

	return 0;
}

static int get_policy_protect_network_illegal_connect_address(cJSON *address, struct _PROTECT_POLICY *protect_policy)
{
	int i = 0, j = 0, num = 0;
	char *buf = NULL;

	/* 目前策略只有一个，考虑到以后的扩展，先按照固定数组大小1个设置*/
	protect_policy->network.illegal_connect.addr_num = 1;
	num = protect_policy->network.illegal_connect.addr_num;

	protect_policy->network.illegal_connect.address = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (protect_policy->network.illegal_connect.address == NULL) {
		MON_ERROR("policy cJSON_Parse protect network illegal_connect address malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		buf = get_my_valuestring(address);
		if (buf == NULL) {
			MON_ERROR("protect_policy->network.illegal_connect.address[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->network.illegal_connect.address[j].list);
			}
			sniper_free(protect_policy->network.illegal_connect.address, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->network.illegal_connect.address[i].list = buf;

	}

	return 0;
}

static int get_policy_protect_network_illegal_connect(cJSON *illegal_connect, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *address, *interval;

	enable = cJSON_GetObjectItem(illegal_connect, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network illegal_connect enable error\n");
                return -1;
        }
	protect_policy->network.illegal_connect.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(illegal_connect, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect network illegal_connect terminate error\n");
                return -1;
        }
	protect_policy->network.illegal_connect.terminate = terminate->valueint;

	address = cJSON_GetObjectItem(illegal_connect, "address");
        if (!address) {
		MON_ERROR("policy cJSON_Parse protect network illegal_connect address error\n");
		protect_policy->network.illegal_connect.addr_num = 0;
        } else {
		if (get_policy_protect_network_illegal_connect_address(address, protect_policy) < 0) {
			protect_policy->network.illegal_connect.addr_num = 0;
		}
	}

	interval = cJSON_GetObjectItem(illegal_connect, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse protect network illegal_connect interval error\n");
                return -1;
        }
	protect_policy->network.illegal_connect.interval = interval->valueint;

	return 0;
}

static int get_policy_protect_network_port_sensitive_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{

	int i = 0, num = 0;
	cJSON *arrayItem;

	num = cJSON_GetArraySize(list);
	protect_policy->network.port.sensitive.list_num = num;

	protect_policy->network.port.sensitive.list = (struct _SENSITIVE_LIST*)sniper_malloc(sizeof(struct _SENSITIVE_LIST)*num, POLICY_GET);
	if (protect_policy->network.port.sensitive.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect network port sensitive list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect network port sensitive list[%d].port error\n", i);
			sniper_free(protect_policy->network.port.sensitive.list, sizeof(struct _SENSITIVE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->network.port.sensitive.list[i].port = arrayItem->valueint;
	}

	return 0;
}

static int get_policy_protect_network_port_sensitive(cJSON *sensitive, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *list;

	enable = cJSON_GetObjectItem(sensitive, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network port sensitive enable error\n");
                return -1;
        }
	protect_policy->network.port.sensitive.enable = enable->valueint;

	list = cJSON_GetObjectItem(sensitive, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect network port sensitive list error\n");
		protect_policy->network.port.sensitive.list_num = 0;
        } else {
		if (get_policy_protect_network_port_sensitive_list(list, protect_policy) < 0) {
			protect_policy->network.port.sensitive.list_num = 0;
		}
	}

	return 0;
}

static int get_policy_protect_network_port(cJSON *port, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *request_period, *count, *locking_time, *sensitive;

	enable = cJSON_GetObjectItem(port, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network port enable error\n");
                return -1;
        }
	protect_policy->network.port.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(port, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect network port terminate error\n");
                return -1;
        }
	protect_policy->network.port.terminate = terminate->valueint;

	request_period = cJSON_GetObjectItem(port, "request_period");
        if (!request_period) {
		MON_ERROR("policy cJSON_Parse protect network port request_period error\n");
                return -1;
        }
	protect_policy->network.port.request_period = request_period->valueint;

	count = cJSON_GetObjectItem(port, "count");
        if (!count) {
		MON_ERROR("policy cJSON_Parse protect network port count error\n");
                return -1;
        }
	protect_policy->network.port.count = count->valueint;

	locking_time = cJSON_GetObjectItem(port, "locking_time");
        if (!locking_time) {
		MON_ERROR("policy cJSON_Parse protect network port locking_time error\n");
                return -1;
        }
	protect_policy->network.port.locking_time = locking_time->valueint;

	sensitive = cJSON_GetObjectItem(port, "sensitive");
        if (!sensitive) {
		MON_ERROR("policy cJSON_Parse protect network port sensitive error\n");
		protect_policy->network.port.sensitive.enable = 0;
        } else {
		if (get_policy_protect_network_port_sensitive(sensitive, protect_policy) < 0) {
			protect_policy->network.port.sensitive.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_network_sensitive_port_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{

	int i = 0, num = 0;
	cJSON *arrayItem;

	num = cJSON_GetArraySize(list);
	protect_policy->network.sensitive_port.list_num = num;

	protect_policy->network.sensitive_port.list = (struct _SENSITIVE_LIST*)sniper_malloc(sizeof(struct _SENSITIVE_LIST)*num, POLICY_GET);
	if (protect_policy->network.sensitive_port.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect network sensitive_port list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect network sensitive_port list[%d].port error\n", i);
			sniper_free(protect_policy->network.sensitive_port.list, sizeof(struct _SENSITIVE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->network.sensitive_port.list[i].port = arrayItem->valueint;
	}

	return 0;
}

static int get_policy_protect_network_sensitive_port(cJSON *sensitive_port, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *locking_time, *list;

	enable = cJSON_GetObjectItem(sensitive_port, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network sensitive_port enable error\n");
                return -1;
        }
	protect_policy->network.sensitive_port.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(sensitive_port, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect network sensitive_port terminate error\n");
                return -1;
        }
	protect_policy->network.sensitive_port.terminate = terminate->valueint;

	locking_time = cJSON_GetObjectItem(sensitive_port, "locking_time");
        if (!locking_time) {
		MON_ERROR("policy cJSON_Parse protect network sensitive_port locking_time error\n");
                return -1;
        }
	protect_policy->network.sensitive_port.locking_time = locking_time->valueint;

	list = cJSON_GetObjectItem(sensitive_port, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect network sensitive_port list error\n");
		protect_policy->network.port.sensitive.list_num = 0;
        } else {
		if (get_policy_protect_network_sensitive_port_list(list, protect_policy) < 0) {
			protect_policy->network.sensitive_port.list_num = 0;
		}
	}

	return 0;
}

static int get_policy_protect_network_login_local(cJSON *local, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(local, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network login local enable error\n");
                return -1;
        }
	protect_policy->network.login.local_enable = enable->valueint;
	return 0;
}

static int get_policy_protect_network_login_remote(cJSON *remote, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(remote, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network login remote enable error\n");
                return -1;
        }
	protect_policy->network.login.remote_enable = enable->valueint;

	return 0;
}

static int get_policy_protect_network_login(cJSON *login, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *local, *remote;

	enable = cJSON_GetObjectItem(login, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect network login enable error\n");
                return -1;
        }
	protect_policy->network.login.enable = enable->valueint;

	local = cJSON_GetObjectItem(login, "local");
        if (!local) {
		MON_ERROR("policy cJSON_Parse protect network login local error\n");
        } else {
		if (get_policy_protect_network_login_local(local, protect_policy) < 0) {
			protect_policy->network.login.local_enable = 0;
		}
	}

	remote = cJSON_GetObjectItem(login, "remote");
        if (!remote) {
		MON_ERROR("policy cJSON_Parse protect network login remote error\n");
        } else {
		if (get_policy_protect_network_login_remote(remote, protect_policy) < 0) {
			protect_policy->network.login.remote_enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_network(cJSON *network, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *domain, *illegal_connect, *port, *sensitive_port, *login;

	/* 访问恶意域名 */
	domain = cJSON_GetObjectItem(network, "domain");
        if (!domain) {
		MON_ERROR("policy cJSON_Parse protect network domain error\n");
	} else {
		if (get_policy_protect_network_domain(domain, protect_policy) < 0) {
			protect_policy->network.domain.enable = 0;
		}
        }

	/* 非法连接互联网 */
	illegal_connect = cJSON_GetObjectItem(network, "illegal_connect");
	if (!illegal_connect) {
		MON_ERROR("policy cJSON_Parse protect network illegal_connect error\n");
	} else {
		if (get_policy_protect_network_illegal_connect(illegal_connect, protect_policy) < 0) {
			protect_policy->network.illegal_connect.enable = 0;
		}
	}

	/* 端口扫描防护 */
	port = cJSON_GetObjectItem(network, "port");
	if (!port) {
		MON_ERROR("policy cJSON_Parse protect network port error\n");
	} else {
		if (get_policy_protect_network_port(port, protect_policy) < 0) {
			protect_policy->network.port.enable = 0;
		}
	}

	/* 端口诱捕 */
	sensitive_port = cJSON_GetObjectItem(network, "sensitive_port");
	if (!sensitive_port) {
		MON_ERROR("policy cJSON_Parse protect network sensitive_port error\n");
	} else {
		if (get_policy_protect_network_sensitive_port(sensitive_port, protect_policy) < 0) {
			protect_policy->network.sensitive_port.enable = 0;
		}
	}

	/* 登录 */
	login = cJSON_GetObjectItem(network, "login");
	if (!login) {
		MON_ERROR("policy cJSON_Parse protect network login error\n");
	} else {
		if (get_policy_protect_network_login(login, protect_policy) < 0) {
			protect_policy->network.login.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_account_login_local_time_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *arrayItem, *start_time, *end_time;
	int i = 0, j = 0, num = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(list);
	protect_policy->account.login.local.time.list_num = num;

	protect_policy->account.login.local.time.list = (struct _TIME_LIST*)sniper_malloc(sizeof(struct _TIME_LIST)*num, POLICY_GET);
	if (protect_policy->account.login.local.time.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect account login local time list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect account login local time list[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.local.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.local.time.list[j].end_time);
			}
			sniper_free(protect_policy->account.login.local.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
			return -1;
		}

		start_time = cJSON_GetObjectItem(arrayItem, "start_time");
		if (!start_time) {
                        MON_ERROR("policy cJSON_Parse protect account login local time list[%d].start_time error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.local.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.local.time.list[j].end_time);
			}
			sniper_free(protect_policy->account.login.local.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
                        return -1;
                }

		buf = get_my_valuestring(start_time);
		if (buf == NULL) {
			MON_ERROR("protect_policy->account.login.local.time.list[%d].start_time get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.local.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.local.time.list[j].end_time);
			}
			sniper_free(protect_policy->account.login.local.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->account.login.local.time.list[i].start_time = buf;

		end_time = cJSON_GetObjectItem(arrayItem, "end_time");
		if (!end_time) {
                        MON_ERROR("policy cJSON_Parse protect account login local time list[%d].end_time error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.local.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.local.time.list[j].end_time);
			}
			free_valuestring(protect_policy->account.login.local.time.list[i].start_time);
			sniper_free(protect_policy->account.login.local.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
                        return -1;
                }

		buf = get_my_valuestring(end_time);
		if (buf == NULL) {
			MON_ERROR("protect_policy->account.login.local.time.list[%d].end_time get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.local.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.local.time.list[j].end_time);
			}
			free_valuestring(protect_policy->account.login.local.time.list[i].start_time);
			sniper_free(protect_policy->account.login.local.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->account.login.local.time.list[i].end_time = buf;

	}

	return 0;
}

static int get_policy_protect_account_login_local_time(cJSON *time, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *list;

	enable = cJSON_GetObjectItem(time, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account login local time enable error\n");
		return -1;
        }
	protect_policy->account.login.local.time.enable = enable->valueint;

	list = cJSON_GetObjectItem(time, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect account login local time list error\n");
		protect_policy->account.login.local.time.list_num = 0;
	} else {
		if (get_policy_protect_account_login_local_time_list(list, protect_policy) < 0) {
			protect_policy->account.login.local.time.list_num = 0;
		}
	}
	return 0;
}

static int get_policy_protect_account_login_local(cJSON *local, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *time, *terminate, *terminate_mode;

	enable = cJSON_GetObjectItem(local, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account login local enable error\n");
		return -1;
        }
	protect_policy->account.login.local.enable = enable->valueint;

	/* 830之前版本没有terminate参数, 默认关闭处理 */
	terminate = cJSON_GetObjectItem(local, "terminate");
        if (!terminate) {
		INFO("policy cJSON_Parse protect account login local terminate not found\n");
		protect_policy->account.login.local.terminate = MY_TURNOFF;
        } else {
		protect_policy->account.login.local.terminate = terminate->valueint;
	}

	/* 930之前版本没有terminate_mode参数, 默认下次注销处理 */
	terminate_mode = cJSON_GetObjectItem(local, "terminate_mode");
        if (!terminate_mode) {
		INFO("policy cJSON_Parse protect account login local terminate_mode not found\n");
		protect_policy->account.login.local.terminate_mode = LOGOUT_NEXT;
        } else {
		protect_policy->account.login.local.terminate_mode = terminate_mode->valueint;
	}

	time = cJSON_GetObjectItem(local, "time");
        if (!time) {
		MON_ERROR("policy cJSON_Parse protect account login local time error\n");
	} else {
		if (get_policy_protect_account_login_local_time(time, protect_policy) < 0) {
			protect_policy->account.login.local.time.enable = 0;
		}
	}
	return 0;
}

static int get_policy_protect_account_login_remote_time_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *arrayItem, *start_time, *end_time;
	int i = 0, j = 0, num = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(list);
	protect_policy->account.login.remote.time.list_num = num;

	protect_policy->account.login.remote.time.list = (struct _TIME_LIST*)sniper_malloc(sizeof(struct _TIME_LIST)*num, POLICY_GET);
	if (protect_policy->account.login.remote.time.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect account login remote time list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect account login remote time list[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.remote.time.list[j].end_time);
			}
			sniper_free(protect_policy->account.login.remote.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
			return -1;
		}

		start_time = cJSON_GetObjectItem(arrayItem, "start_time");
		if (!start_time) {
                        MON_ERROR("policy cJSON_Parse protect account login remote time list[%d].start_time error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.remote.time.list[j].end_time);
			}
			sniper_free(protect_policy->account.login.remote.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
                        return -1;
                }

		buf = get_my_valuestring(start_time);
		if (buf == NULL) {
			MON_ERROR("protect_policy->account.login.remote.time.list[%d].start_time get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.remote.time.list[j].end_time);
			}
			sniper_free(protect_policy->account.login.remote.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->account.login.remote.time.list[i].start_time = buf;

		end_time = cJSON_GetObjectItem(arrayItem, "end_time");
		if (!end_time) {
                        MON_ERROR("policy cJSON_Parse protect account login remote time list[%d].end_time error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.remote.time.list[j].end_time);
			}
			free_valuestring(protect_policy->account.login.remote.time.list[i].start_time);
			sniper_free(protect_policy->account.login.remote.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
                        return -1;
                }

		buf = get_my_valuestring(end_time);
		if (buf == NULL) {
			MON_ERROR("protect_policy->account.login.remote.time.list[%d].end_time get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.time.list[j].start_time);
				free_valuestring(protect_policy->account.login.remote.time.list[j].end_time);
			}
			free_valuestring(protect_policy->account.login.remote.time.list[i].start_time);
			sniper_free(protect_policy->account.login.remote.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->account.login.remote.time.list[i].end_time = buf;

	}

	return 0;
}

static int get_policy_protect_account_login_remote_time(cJSON *time, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *list;

	enable = cJSON_GetObjectItem(time, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account login remote time enable error\n");
		return -1;
        }
	protect_policy->account.login.remote.time.enable = enable->valueint;

	list = cJSON_GetObjectItem(time, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect account login remote time list error\n");
		protect_policy->account.login.remote.time.list_num = 0;
	} else {
		if (get_policy_protect_account_login_remote_time_list(list, protect_policy) < 0) {
			protect_policy->account.login.remote.time.list_num = 0;
		}
	}
	return 0;
}

static int get_policy_protect_account_login_remote_location_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *arrayItem, *city, *province;
	int i = 0, j = 0, num = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(list);
	protect_policy->account.login.remote.location.list_num = num;

	protect_policy->account.login.remote.location.list = (struct _LOCATION_LIST*)sniper_malloc(sizeof(struct _LOCATION_LIST)*num, POLICY_GET);
	if (protect_policy->account.login.remote.location.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect account login remote location list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect account login remote location list[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.location.list[j].city);
				free_valuestring(protect_policy->account.login.remote.location.list[j].province);
			}
			sniper_free(protect_policy->account.login.remote.location.list, sizeof(struct _LOCATION_LIST)*num, POLICY_GET);
			return -1;
		}

		city = cJSON_GetObjectItem(arrayItem, "city");
		if (!city) {
                        MON_ERROR("policy cJSON_Parse protect account login remote location list[%d].city error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.location.list[j].city);
				free_valuestring(protect_policy->account.login.remote.location.list[j].province);
			}
			sniper_free(protect_policy->account.login.remote.location.list, sizeof(struct _LOCATION_LIST)*num, POLICY_GET);
                        return -1;
                }

		buf = get_my_valuestring(city);
		if (buf == NULL) {
			MON_ERROR("protect_policy->account.login.remote.location.list[%d].city get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.location.list[j].city);
				free_valuestring(protect_policy->account.login.remote.location.list[j].province);
			}
			sniper_free(protect_policy->account.login.remote.location.list, sizeof(struct _LOCATION_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->account.login.remote.location.list[i].city = buf;

		province = cJSON_GetObjectItem(arrayItem, "province");
		if (!province) {
                        MON_ERROR("policy cJSON_Parse protect account login remote location list[%d].province error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.location.list[j].city);
				free_valuestring(protect_policy->account.login.remote.location.list[j].province);
			}
			free_valuestring(protect_policy->account.login.remote.location.list[i].city);
			sniper_free(protect_policy->account.login.remote.location.list, sizeof(struct _LOCATION_LIST)*num, POLICY_GET);
                        return -1;
                }

		buf = get_my_valuestring(province);
		if (buf == NULL) {
			MON_ERROR("protect_policy->account.login.remote.location.list[%d].province get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->account.login.remote.location.list[j].city);
				free_valuestring(protect_policy->account.login.remote.location.list[j].province);
			}
			free_valuestring(protect_policy->account.login.remote.location.list[i].city);
			sniper_free(protect_policy->account.login.remote.location.list, sizeof(struct _LOCATION_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->account.login.remote.location.list[i].province = buf;

	}

	return 0;
}

static int get_policy_protect_account_login_remote_location(cJSON *location, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *list;

	enable = cJSON_GetObjectItem(location, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account login remote location enable error\n");
		return -1;
        }
	protect_policy->account.login.remote.location.enable = enable->valueint;

	list = cJSON_GetObjectItem(location, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect account login remote location list error\n");
		protect_policy->account.login.remote.location.list_num = 0;
	} else {
		if (get_policy_protect_account_login_remote_location_list(list, protect_policy) < 0) {
			protect_policy->account.login.remote.location.list_num = 0;
		}
	}
	return 0;
}

static int get_policy_protect_account_login_remote(cJSON *remote, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *time, *location, *terminate, *terminate_mode;

	enable = cJSON_GetObjectItem(remote, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account login remote enable error\n");
		return -1;
        }
	protect_policy->account.login.remote.enable = enable->valueint;

	/* 830之前版本没有terminate参数, 默认关闭处理 */
	terminate = cJSON_GetObjectItem(remote, "terminate");
        if (!terminate) {
		INFO("policy cJSON_Parse protect account login remote terminate not found\n");
		protect_policy->account.login.remote.terminate = MY_TURNOFF;
        } else {
		protect_policy->account.login.remote.terminate = terminate->valueint;
	}

	/* 930之前版本没有terminate_mode参数, 默认关闭处理 */
	terminate_mode = cJSON_GetObjectItem(remote, "terminate_mode");
        if (!terminate_mode) {
		INFO("policy cJSON_Parse protect account login remote terminate_mode not found\n");
		protect_policy->account.login.remote.terminate_mode = LOGOUT_NEXT;
        } else {
		protect_policy->account.login.remote.terminate_mode = terminate_mode->valueint;
	}

	time = cJSON_GetObjectItem(remote, "time");
        if (!time) {
		MON_ERROR("policy cJSON_Parse protect account login remote time error\n");
	} else {
		if (get_policy_protect_account_login_remote_time(time, protect_policy) < 0) {
			protect_policy->account.login.remote.time.enable = 0;
		}
	}

	location = cJSON_GetObjectItem(remote, "location");
        if (!location) {
		MON_ERROR("policy cJSON_Parse protect account login remote location error\n");
	} else {
		if (get_policy_protect_account_login_remote_location(location, protect_policy) < 0) {
			protect_policy->account.login.remote.location.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_account_login_crack(cJSON *crack, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *interval, *limit, *locking_time, *terminate;

	enable = cJSON_GetObjectItem(crack, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account login crack enable error\n");
		return -1;
        }
	protect_policy->account.login.crack.enable = enable->valueint;

	interval = cJSON_GetObjectItem(crack, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse protect account login crack interval error\n");
		return -1;
        }
	protect_policy->account.login.crack.interval = interval->valueint;

	limit = cJSON_GetObjectItem(crack, "limit");
        if (!limit) {
		MON_ERROR("policy cJSON_Parse protect account login crack limit error\n");
		return -1;
        }
	protect_policy->account.login.crack.limit = limit->valueint;

	/* 830之前版本没有terminate参数, 默认关闭处理 */
	terminate = cJSON_GetObjectItem(crack, "terminate");
        if (!terminate) {
		INFO("policy cJSON_Parse protect account login crack terminate not found\n");
		protect_policy->account.login.crack.terminate = MY_TURNOFF;
        } else {
		protect_policy->account.login.crack.terminate = terminate->valueint;
	}

	locking_time = cJSON_GetObjectItem(crack, "locking_time");
        if (!locking_time) {
		MON_ERROR("policy cJSON_Parse protect account login crack locking_time error\n");
		return -1;
        }
	protect_policy->account.login.crack.locking_time = locking_time->valueint;

	return 0;
}

static int get_policy_protect_account_login(cJSON *login, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *local, *remote, *crack;

	enable = cJSON_GetObjectItem(login, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account login enable error\n");
		return -1;
        }
	protect_policy->account.login.enable = enable->valueint;

	/* 本地用户登录监控 */
	local = cJSON_GetObjectItem(login, "local");
	if (!local) {
		MON_ERROR("policy cJSON_Parse protect account login local error\n");
	} else {
		if (get_policy_protect_account_login_local(local, protect_policy) < 0) {
			protect_policy->account.login.local.enable = 0;
		}
	}

	/* 远程登录监控 */
	remote = cJSON_GetObjectItem(login, "remote");
	if (!remote) {
		MON_ERROR("policy cJSON_Parse protect account login remote error\n");
	} else {
		if (get_policy_protect_account_login_remote(remote, protect_policy) < 0) {
			protect_policy->account.login.remote.enable = 0;
		}
	}

	/* 暴力密码破解防护 */
	crack = cJSON_GetObjectItem(login, "crack");
	if (!crack) {
		MON_ERROR("policy cJSON_Parse protect account login crack error\n");
	} else {
		if (get_policy_protect_account_login_crack(crack, protect_policy) < 0) {
			protect_policy->account.login.crack.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_account_abnormal_user(cJSON *abnormal_user, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(abnormal_user, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account abnormal_user enable error\n");
		return -1;
        }
	protect_policy->account.abnormal_user.enable = enable->valueint;

	return 0;
}

static int get_policy_protect_account_user_change(cJSON *user_change, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *user, *group;

	enable = cJSON_GetObjectItem(user_change, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account user_change enable error\n");
		return -1;
        }
	protect_policy->account.user_change.enable = enable->valueint;

	user = cJSON_GetObjectItem(user_change, "user");
        if (!user) {
		MON_ERROR("policy cJSON_Parse protect account user_change user error\n");
		return -1;
        }
	enable = cJSON_GetObjectItem(user, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account user_change user enable error\n");
		return -1;
        }
	protect_policy->account.user_change.user.enable = enable->valueint;

	group = cJSON_GetObjectItem(user_change, "user_group");
        if (!group) {
		MON_ERROR("policy cJSON_Parse protect account user_change group error\n");
		return -1;
        }
	enable = cJSON_GetObjectItem(group, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect account user_change group enable error\n");
		return -1;
        }
	protect_policy->account.user_change.group.enable = enable->valueint;

	return 0;
}

static int get_policy_protect_account(cJSON *account, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *login, *abnormal_user, *user_change;

	/* 异常登录 */
	login = cJSON_GetObjectItem(account, "login");
	if (!login) {
		MON_ERROR("policy cJSON_Parse protect account login error\n");
	} else {
		if (get_policy_protect_account_login(login, protect_policy) < 0) {
			protect_policy->account.login.enable = 0;
		}
	}

	/* 异常账号 */
	abnormal_user = cJSON_GetObjectItem(account, "abnormal_user");
	if (!abnormal_user) {
		MON_ERROR("policy cJSON_Parse protect account abnormal_user error\n");
	} else {
		if (get_policy_protect_account_abnormal_user(abnormal_user, protect_policy) < 0) {
			protect_policy->account.abnormal_user.enable = 0;
		}
	}

	/* 用户变更监控 */
	user_change = cJSON_GetObjectItem(account, "user_change");
	if (!user_change) {
		MON_ERROR("policy cJSON_Parse protect account user_change error\n");
	} else {
		if (get_policy_protect_account_user_change(user_change, protect_policy) < 0) {
			protect_policy->account.user_change.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_file_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{
	int i = 0, j = 0, num = 0;	
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(list);
	protect_policy->sensitive_info.sensitive_file.list_num = num;

	protect_policy->sensitive_info.sensitive_file.list = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (protect_policy->sensitive_info.sensitive_file.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info sensitive_file list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info sensitive_file list[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.sensitive_file.list[j].list);
			}
			sniper_free(protect_policy->sensitive_info.sensitive_file.list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("protect_policy->sensitive_info.sensitive_file.list[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.sensitive_file.list[j].list);
			}
			sniper_free(protect_policy->sensitive_info.sensitive_file.list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.sensitive_file.list[i].list = buf;

	}

	return 0;
}

static int get_policy_protect_sensitive_file(cJSON *sensitive_file, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *list;

	enable = cJSON_GetObjectItem(sensitive_file, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info sensitive_file enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.sensitive_file.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(sensitive_file, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info sensitive_file terminate error\n");
                return -1;
        }
	protect_policy->sensitive_info.sensitive_file.terminate = terminate->valueint;

	list = cJSON_GetObjectItem(sensitive_file, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info sensitive_file list error\n");
		protect_policy->sensitive_info.sensitive_file.list_num = 0;
        } else {
		if (get_policy_protect_sensitive_file_list(list, protect_policy) < 0) {
			protect_policy->sensitive_info.sensitive_file.list_num = 0;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_info_log_delete_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{
	int i = 0, j = 0, num = 0;	
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(list);
	protect_policy->sensitive_info.log_delete.list_num = num;

	protect_policy->sensitive_info.log_delete.list = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (protect_policy->sensitive_info.log_delete.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info log_delete list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info log_delete list[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.log_delete.list[j].list);
			}
			sniper_free(protect_policy->sensitive_info.log_delete.list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("protect_policy->sensitive_info.log_delete.list[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.log_delete.list[j].list);
			}
			sniper_free(protect_policy->sensitive_info.log_delete.list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.log_delete.list[i].list = buf;

	}

	return 0;
}

static int get_policy_protect_sensitive_info_log_delete(cJSON *log_delete, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *list;

	enable = cJSON_GetObjectItem(log_delete, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info log_delete enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.log_delete.enable = enable->valueint;

	list = cJSON_GetObjectItem(log_delete, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info log_delete list error\n");
		protect_policy->sensitive_info.log_delete.list_num = 0;
        } else {
		if (get_policy_protect_sensitive_info_log_delete_list(list, protect_policy) < 0) {
			protect_policy->sensitive_info.log_delete.list_num = 0;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_info_file_safe_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *arrayItem, *path, *status;
	char *name = NULL, *process = NULL, *operation = NULL;
	int i = 0, j = 0;
	int num = 0, len = 0;
	char *dirpath = NULL;
	char real_path[PATH_MAX] = {0};

	num = cJSON_GetArraySize(list);
	protect_policy->sensitive_info.file_safe.list_num = num;

	protect_policy->sensitive_info.file_safe.list = (struct _SAFE_FILE_LIST*)sniper_malloc(sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
	if (protect_policy->sensitive_info.file_safe.list == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		memset(real_path, 0, PATH_MAX);

		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list[%d] error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
			}
			sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
			return -1;
		}

		path = cJSON_GetObjectItem(arrayItem, "path");
		if (!path) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list[%d].path error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
			}
			sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
			return -1;
		}

		dirpath = get_my_valuestring(path);
		if (dirpath == NULL) {
			MON_ERROR("protect_policy->sensitive_info.file_safe.list[%d].path get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
			}
			sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
			return -1;
		}
                protect_policy->sensitive_info.file_safe.list[i].path = dirpath;

		/* 如果关键目录是链接，取真正的目录 */
		len = strlen(dirpath);
		if (realpath(dirpath, real_path) &&
		    (strncmp(dirpath, real_path, len-1) != 0 || strcmp(dirpath+len-1, "/") != 0)) {
			len = strlen(real_path) + 2;
			dirpath = sniper_malloc(len, POLICY_GET);
			protect_policy->sensitive_info.file_safe.list[i].real_path = dirpath;
			if (!dirpath) {
				printf("protect_policy->sensitive_info.file_safe.list[%d].real_path malloc failed\n", i);
				for (j = 0; j < i; j++) {
					free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
					free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
					free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
					free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
					free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
				}
				free_valuestring(protect_policy->sensitive_info.file_safe.list[i].path);
				sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
				return -1;
			}
			snprintf(dirpath, len, "%s/", real_path);
		} else {
			/* 没有取到真正的目录，或真正的目录是一样的 */
			protect_policy->sensitive_info.file_safe.list[i].real_path = NULL;
		}

		name = get_name(arrayItem, "name");
		if (name == NULL) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list[%d].name error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
			}
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].path);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].real_path);
			sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.file_safe.list[i].name = name;

		process = get_name(arrayItem, "process");
		if (process == NULL) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list[%d].process error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
			}
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].path);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].real_path);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].name);
			sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.file_safe.list[i].process = process;

		operation = get_name(arrayItem, "operation");
		if (operation == NULL) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list[%d].operation error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
			}
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].path);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].real_path);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].name);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].process);
			sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.file_safe.list[i].operation = operation;

		status = cJSON_GetObjectItem(arrayItem, "status");
		if (!status) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list[%d].status error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].real_path);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].name);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].process);
				free_valuestring(protect_policy->sensitive_info.file_safe.list[j].operation);
			}
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].path);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].real_path);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].name);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].process);
			free_valuestring(protect_policy->sensitive_info.file_safe.list[i].operation);
			sniper_free(protect_policy->sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.file_safe.list[i].status = status->valueint;
	}

	return 0;
}

static int get_policy_protect_sensitive_info_file_safe(cJSON *file_safe, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *list;

	enable = cJSON_GetObjectItem(file_safe, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.file_safe.enable = enable->valueint;

	list = cJSON_GetObjectItem(file_safe, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe list error\n");
        } else {
		if (get_policy_protect_sensitive_info_file_safe_list(list, protect_policy) < 0) {
			protect_policy->sensitive_info.file_safe.list_num = 0;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_info_file_usb(cJSON *file_usb, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable;
	char *extension = NULL;

	enable = cJSON_GetObjectItem(file_usb, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info file_usb enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.file_usb.enable = enable->valueint;

	extension = get_name(file_usb, "extension");
	if (extension == NULL) {
		MON_ERROR("protect_policy->sensitive_info.file_usb.extension get value failed\n");
		return -1;
	}
	protect_policy->sensitive_info.file_usb.extension = extension;
	return 0;
}

static int get_policy_protect_sensitive_info_middleware_script_files(cJSON *script_files, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate;
	char *extension = NULL;

	enable = cJSON_GetObjectItem(script_files, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware script_files enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.middleware.script_files.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(script_files, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware script_files terminate error\n");
                return -1;
        }
	protect_policy->sensitive_info.middleware.script_files.terminate = terminate->valueint;

	extension = get_name(script_files, "extension");
	if (extension == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware script_files extension error\n");
		return -1;
	}
	protect_policy->sensitive_info.middleware.script_files.ext = extension;

	return 0;
}

static int get_policy_protect_sensitive_info_middleware_executable_files(cJSON *executable_files, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *exclude;
	char *extension = NULL;

	enable = cJSON_GetObjectItem(executable_files, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware executable_files enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.middleware.executable_files.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(executable_files, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware executable_files terminate error\n");
                return -1;
        }
	protect_policy->sensitive_info.middleware.executable_files.terminate = terminate->valueint;

	exclude = cJSON_GetObjectItem(executable_files, "exclude");
        if (!exclude) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware executable_files exclude error\n");
                return -1;
        }
	protect_policy->sensitive_info.middleware.executable_files.exclude = exclude->valueint;

	extension = get_name(executable_files, "exclude_extension");
	if (extension == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware executable_files extension error\n");
		return -1;
	}
	protect_policy->sensitive_info.middleware.executable_files.ext = extension;

	return 0;
}

static int get_policy_protect_sensitive_info_middleware(cJSON *middleware, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *script_files, *executable_files;
	char *target = NULL;

	enable = cJSON_GetObjectItem(middleware, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.middleware.enable = enable->valueint;

	target = get_name(middleware, "target");
	if (target == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware target error\n");
		return -1;
	}
	protect_policy->sensitive_info.middleware.target = target;

	script_files = cJSON_GetObjectItem(middleware, "script_files");
        if (!script_files) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware script_files error\n");
		protect_policy->sensitive_info.middleware.script_files.enable = 0;
        } else {
		if (get_policy_protect_sensitive_info_middleware_script_files(script_files, protect_policy) < 0) {
			protect_policy->sensitive_info.middleware.script_files.enable = 0;
		}
	}

	executable_files = cJSON_GetObjectItem(middleware, "executable_files");
        if (!executable_files) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware executable_files error\n");
		protect_policy->sensitive_info.middleware.executable_files.enable = 0;
        } else {
		if (get_policy_protect_sensitive_info_middleware_executable_files(executable_files, protect_policy) < 0) {
			protect_policy->sensitive_info.middleware.executable_files.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_info_illegal_script_target(cJSON *target, struct _PROTECT_POLICY *protect_policy)
{
	int i = 0, j = 0, num = 0, len = 0;	
	cJSON *arrayItem, *path;
	char *extension = NULL;
	char *dirpath = NULL;
	char real_path[PATH_MAX] = {0};

	num = cJSON_GetArraySize(target);
	protect_policy->sensitive_info.illegal_script.target_num = num;

	protect_policy->sensitive_info.illegal_script.target = (struct _ILLEGAL_SCRIPT_TARGET*)sniper_malloc(sizeof(struct _ILLEGAL_SCRIPT_TARGET)*num, POLICY_GET);
	if (protect_policy->sensitive_info.illegal_script.target == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script target malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		memset(real_path, 0, PATH_MAX);

		arrayItem = cJSON_GetArrayItem(target,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script target[%d] error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].extension);
			}
			sniper_free(protect_policy->sensitive_info.illegal_script.target, sizeof(struct _ILLEGAL_SCRIPT_TARGET)*num, POLICY_GET);
			return -1;
		}

		path = cJSON_GetObjectItem(arrayItem, "path");
		if (!path) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script target[%d].path error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].extension);
			}
			sniper_free(protect_policy->sensitive_info.illegal_script.target, sizeof(struct _ILLEGAL_SCRIPT_TARGET)*num, POLICY_GET);
			return -1;
		}

		dirpath = get_my_valuestring(path);
		if (dirpath == NULL) {
			MON_ERROR("protect_policy->sensitive_info.illegal_script.target[%d].path get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].extension);
			}
			sniper_free(protect_policy->sensitive_info.illegal_script.target, sizeof(struct _ILLEGAL_SCRIPT_TARGET)*num, POLICY_GET);
			return -1;
		}
                protect_policy->sensitive_info.illegal_script.target[i].path = dirpath;

		/* 如果关键目录是链接，取真正的目录 */
		len = strlen(dirpath);
		if (realpath(dirpath, real_path) &&
		    (strncmp(dirpath, real_path, len-1) != 0 || strcmp(dirpath+len-1, "/") != 0)) {
			len = strlen(real_path) + 2;
			dirpath = sniper_malloc(len, POLICY_GET);
			protect_policy->sensitive_info.illegal_script.target[i].real_path = dirpath;
			if (!dirpath) {
				printf("protect_policy->sensitive_info.illegal_script.target[%d].real_path malloc failed\n", i);
				for (j = 0; j < i; j++) {
					free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].path);
					free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].real_path);
					free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].extension);
				}
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[i].path);
				sniper_free(protect_policy->sensitive_info.illegal_script.target, sizeof(struct _ILLEGAL_SCRIPT_TARGET)*num, POLICY_GET);
				return -1;
			}
			snprintf(dirpath, len, "%s/", real_path);
		} else {
			/* 没有取到真正的目录，或真正的目录是一样的 */
			protect_policy->sensitive_info.illegal_script.target[i].real_path = NULL;
		}

		extension = get_name(arrayItem, "extension");
                if (extension == NULL) {
                        MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script target[%d].extension error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.illegal_script.target[j].extension);
			}
			free_valuestring(protect_policy->sensitive_info.illegal_script.target[i].path);
			free_valuestring(protect_policy->sensitive_info.illegal_script.target[i].real_path);
			sniper_free(protect_policy->sensitive_info.illegal_script.target, sizeof(struct _ILLEGAL_SCRIPT_TARGET)*num, POLICY_GET);
                        return -1;
                }
                protect_policy->sensitive_info.illegal_script.target[i].extension = extension;
	}

	return 0;
}

static int get_policy_protect_sensitive_info_illegal_script_keyword(cJSON *keyword, struct _PROTECT_POLICY *protect_policy)
{
	int i = 0, j = 0, num = 0;	
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(keyword);
	protect_policy->sensitive_info.illegal_script.keyword_num = num;

	protect_policy->sensitive_info.illegal_script.keyword = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (protect_policy->sensitive_info.illegal_script.keyword == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script keyword malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(keyword,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script keyword[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.keyword[j].list);
			}
			sniper_free(protect_policy->sensitive_info.illegal_script.keyword, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("protect_policy->sensitive_info.illegal_script.keyword[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.keyword[j].list);
			}
			sniper_free(protect_policy->sensitive_info.illegal_script.keyword, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.illegal_script.keyword[i].list = buf;

	}

	return 0;
}

static int get_policy_protect_sensitive_info_illegal_script_default_keyword(cJSON *default_keyword, struct _PROTECT_POLICY *protect_policy)
{
	int i = 0, j = 0, num = 0;	
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(default_keyword);
	protect_policy->sensitive_info.illegal_script.default_keyword_num = num;

	protect_policy->sensitive_info.illegal_script.default_keyword = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (protect_policy->sensitive_info.illegal_script.default_keyword == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script default_keyword malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(default_keyword,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script default_keyword[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.default_keyword[j].list);
			}
			sniper_free(protect_policy->sensitive_info.illegal_script.default_keyword, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("protect_policy->sensitive_info.illegal_script.default_keyword[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.illegal_script.default_keyword[j].list);
			}
			sniper_free(protect_policy->sensitive_info.illegal_script.default_keyword, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->sensitive_info.illegal_script.default_keyword[i].list = buf;

	}

	return 0;
}

static int get_policy_protect_sensitive_info_illegal_script(cJSON *illegal_script, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *use_default_keyword, *keyword, *default_keyword, *target;

	enable = cJSON_GetObjectItem(illegal_script, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.illegal_script.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(illegal_script, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script terminate error\n");
                return -1;
        }
	protect_policy->sensitive_info.illegal_script.terminate = terminate->valueint;

	use_default_keyword = cJSON_GetObjectItem(illegal_script, "use_default_keyword");
        if (!use_default_keyword) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script use_default_keyword error\n");
                return -1;
        }
	protect_policy->sensitive_info.illegal_script.use_default_keyword = use_default_keyword->valueint;

	target = cJSON_GetObjectItem(illegal_script, "target");
        if (!target) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script target error\n");
		protect_policy->sensitive_info.illegal_script.target_num = 0;
		return -1;
        } else {
		if (get_policy_protect_sensitive_info_illegal_script_target(target, protect_policy) < 0) {
			protect_policy->sensitive_info.illegal_script.target_num = 0;
			return -1;
		}
	}

	keyword = cJSON_GetObjectItem(illegal_script, "keyword");
        if (!keyword) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script keyword error\n");
		protect_policy->sensitive_info.illegal_script.keyword_num = 0;
        } else {
		if (get_policy_protect_sensitive_info_illegal_script_keyword(keyword, protect_policy) < 0) {
			protect_policy->sensitive_info.illegal_script.keyword_num = 0;
		}
	}

	default_keyword = cJSON_GetObjectItem(illegal_script, "default_keyword");
        if (!default_keyword) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script default_keyword error\n");
		protect_policy->sensitive_info.illegal_script.default_keyword_num = 0;
        } else {
		if (get_policy_protect_sensitive_info_illegal_script_default_keyword(default_keyword, protect_policy) < 0) {
			protect_policy->sensitive_info.illegal_script.default_keyword_num = 0;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_info_webshell_detect_target(cJSON *target, struct _PROTECT_POLICY *protect_policy)
{
	int i = 0, j = 0, num = 0, len = 0;	
	cJSON *arrayItem, *path;
	char *extension = NULL;
	char *dirpath = NULL;
	char real_path[PATH_MAX] = {0};

	num = cJSON_GetArraySize(target);
	protect_policy->sensitive_info.webshell_detect.target_num = num;

	protect_policy->sensitive_info.webshell_detect.target = (struct _WEBSHELL_DETECT_TARGET*)sniper_malloc(sizeof(struct _WEBSHELL_DETECT_TARGET)*num, POLICY_GET);
	if (protect_policy->sensitive_info.webshell_detect.target == NULL) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect target malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		memset(real_path, 0, PATH_MAX);

		arrayItem = cJSON_GetArrayItem(target,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect target[%d] error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].extension);
			}
			sniper_free(protect_policy->sensitive_info.webshell_detect.target, sizeof(struct _WEBSHELL_DETECT_TARGET)*num, POLICY_GET);
			return -1;
		}

		path = cJSON_GetObjectItem(arrayItem, "path");
		if (!path) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect target[%d].path error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].extension);
			}
			sniper_free(protect_policy->sensitive_info.webshell_detect.target, sizeof(struct _WEBSHELL_DETECT_TARGET)*num, POLICY_GET);
			return -1;
		}

		dirpath = get_my_valuestring(path);
		if (dirpath == NULL) {
			MON_ERROR("protect_policy->sensitive_info.webshell_detect.target[%d].path get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].extension);
			}
			sniper_free(protect_policy->sensitive_info.webshell_detect.target, sizeof(struct _WEBSHELL_DETECT_TARGET)*num, POLICY_GET);
			return -1;
		}
                protect_policy->sensitive_info.webshell_detect.target[i].path = dirpath;

		/* 如果关键目录是链接，取真正的目录 */
		len = strlen(dirpath);
		if (realpath(dirpath, real_path) &&
		    (strncmp(dirpath, real_path, len-1) != 0 || strcmp(dirpath+len-1, "/") != 0)) {
			len = strlen(real_path) + 2;
			dirpath = sniper_malloc(len, POLICY_GET);
			protect_policy->sensitive_info.webshell_detect.target[i].real_path = dirpath;
			if (!dirpath) {
				printf("protect_policy->sensitive_info.webshell_detect.target[%d].real_path malloc failed\n", i);
				for (j = 0; j < i; j++) {
					free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].path);
					free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].real_path);
					free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].extension);
				}
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[i].path);
				sniper_free(protect_policy->sensitive_info.webshell_detect.target, sizeof(struct _WEBSHELL_DETECT_TARGET)*num, POLICY_GET);
				return -1;
			}
			snprintf(dirpath, len, "%s/", real_path);
		} else {
			/* 没有取到真正的目录，或真正的目录是一样的 */
			protect_policy->sensitive_info.webshell_detect.target[i].real_path = NULL;
		}

		extension = get_name(arrayItem, "extension");
                if (extension == NULL) {
                        MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect target[%d].extension error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].real_path);
				free_valuestring(protect_policy->sensitive_info.webshell_detect.target[j].extension);
			}
			free_valuestring(protect_policy->sensitive_info.webshell_detect.target[i].path);
			free_valuestring(protect_policy->sensitive_info.webshell_detect.target[i].real_path);
			sniper_free(protect_policy->sensitive_info.webshell_detect.target, sizeof(struct _WEBSHELL_DETECT_TARGET)*num, POLICY_GET);
                        return -1;
                }
                protect_policy->sensitive_info.webshell_detect.target[i].extension = extension;
	}

	return 0;
}

static int get_policy_protect_sensitive_info_webshell_detect(cJSON *webshell_detect, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *terminate, *use_default_rule, *detect_mode, *target;

	enable = cJSON_GetObjectItem(webshell_detect, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.webshell_detect.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(webshell_detect, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect terminate error\n");
                return -1;
        }
	protect_policy->sensitive_info.webshell_detect.terminate = terminate->valueint;

	use_default_rule = cJSON_GetObjectItem(webshell_detect, "use_default_rule");
        if (!use_default_rule) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect use_default_rule error\n");
                return -1;
        }
	protect_policy->sensitive_info.webshell_detect.use_default_rule = use_default_rule->valueint;

	detect_mode = cJSON_GetObjectItem(webshell_detect, "detect_mode");
        if (!detect_mode) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect detect_mode error\n");
		/* 旧的版本没有这个开关, 默认用严格模式*/
		protect_policy->sensitive_info.webshell_detect.detect_mode = WEBSHELL_HARD_MOD;
        } else {
		protect_policy->sensitive_info.webshell_detect.detect_mode = detect_mode->valueint;
	}

	target = cJSON_GetObjectItem(webshell_detect, "target");
        if (!target) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect target error\n");
		protect_policy->sensitive_info.webshell_detect.target_num = 0;
		return -1;
        } else {
		if (get_policy_protect_sensitive_info_webshell_detect_target(target, protect_policy) < 0) {
			protect_policy->sensitive_info.webshell_detect.target_num = 0;
			return -1;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_info_backdoor(cJSON *backdoor, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable, *illegal_script_files, *webshell_detect;

	enable = cJSON_GetObjectItem(backdoor, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info backdoor enable error\n");
                return -1;
        }
	protect_policy->sensitive_info.backdoor.enable = enable->valueint;

	/* 非法脚本识别 */
	illegal_script_files = cJSON_GetObjectItem(backdoor, "illegal_script_files");
	if (!illegal_script_files) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script_files error\n");
	} else {
		if (get_policy_protect_sensitive_info_illegal_script(illegal_script_files, protect_policy) < 0) {
			protect_policy->sensitive_info.illegal_script.enable = 0;
		}
	}

	/* webshell文件检测 */
	webshell_detect = cJSON_GetObjectItem(backdoor, "webshell_detect");
	if (!webshell_detect) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info webshell_detect error\n");
	} else {
		if (get_policy_protect_sensitive_info_webshell_detect(webshell_detect, protect_policy) < 0) {
			protect_policy->sensitive_info.webshell_detect.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_sensitive_info(cJSON *sensitive_info, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *sensitive_file, *log_delete, *file_safe, *file_usb, *middleware, *illegal_script_files, *backdoor;

	/* 敏感信息防护 */
	sensitive_file = cJSON_GetObjectItem(sensitive_info, "sensitive_file");
        if (!sensitive_file) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info sensitive_file error\n");
        } else {
		if (get_policy_protect_sensitive_file(sensitive_file, protect_policy) < 0) {
			protect_policy->sensitive_info.sensitive_file.enable = 0;
		}
	}

	/* 日志异常删除 */
	log_delete = cJSON_GetObjectItem(sensitive_info, "log_delete");
        if (!log_delete) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info log_delete error\n");
        } else {
		if (get_policy_protect_sensitive_info_log_delete(log_delete, protect_policy) < 0) {
			protect_policy->sensitive_info.log_delete.enable = 0;
		}
	}

	/* 文件防篡改 */
	file_safe = cJSON_GetObjectItem(sensitive_info, "file_safe");
        if (!file_safe) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info file_safe error\n");
        } else {
		if (get_policy_protect_sensitive_info_file_safe(file_safe, protect_policy) < 0) {
			protect_policy->sensitive_info.file_safe.enable = 0;
		}
	}

	/* usb文件监控 */
	file_usb = cJSON_GetObjectItem(sensitive_info, "file_usb");
        if (!file_usb) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info file_usb error\n");
        } else {
		if (get_policy_protect_sensitive_info_file_usb(file_usb, protect_policy) < 0) {
			protect_policy->sensitive_info.file_usb.enable = 0;
		}
	}

	/* 中间件识别 */
	middleware = cJSON_GetObjectItem(sensitive_info, "middleware");
        if (!middleware) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info middleware error\n");
        } else {
		if (get_policy_protect_sensitive_info_middleware(middleware, protect_policy) < 0) {
			protect_policy->sensitive_info.middleware.enable = 0;
		}
	}

	/* 930版本非法脚本识别和webshell检测字段在backdoor下面 */
	backdoor = cJSON_GetObjectItem(sensitive_info, "backdoor");
        if (!backdoor) {
		INFO("policy cJSON_Parse protect sensitive_info backdoor not found\n");
		/* 低版本backdoor开关默认打开 */
		protect_policy->sensitive_info.backdoor.enable = TURN_MY_ON;
		/* 非法脚本识别 */
		illegal_script_files = cJSON_GetObjectItem(sensitive_info, "illegal_script_files");
		if (!illegal_script_files) {
			MON_ERROR("policy cJSON_Parse protect sensitive_info illegal_script_files error\n");
		} else {
			if (get_policy_protect_sensitive_info_illegal_script(illegal_script_files, protect_policy) < 0) {
				protect_policy->sensitive_info.illegal_script.enable = 0;
			}
		}
        } else {
		if (get_policy_protect_sensitive_info_backdoor(backdoor, protect_policy) < 0) {
			protect_policy->sensitive_info.backdoor.enable = 0;
		}
	}

	return 0;
}

static int get_policy_protect_logcollector_process(cJSON *process, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(process, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect logcollector process enable error\n");
                return -1;
        }
	protect_policy->logcollector.process_enable = enable->valueint;

	return 0;
}

static int get_policy_protect_logcollector_file_list(cJSON *list, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *arrayItem;
	cJSON *filepath;
	int i = 0, j =0;
	int num = 0, len = 0;
	char *ext = NULL, *dirpath = NULL;
	char real_path[PATH_MAX] = {0};

	num = cJSON_GetArraySize(list);
	protect_policy->logcollector.file_list_num = num;

	protect_policy->logcollector.file_list = (struct _LOGCOLLECTOR_FILE_LIST *)sniper_malloc(sizeof(struct _LOGCOLLECTOR_FILE_LIST)*num, POLICY_GET);
	if (protect_policy->logcollector.file_list == NULL) {
		MON_ERROR("policy cJSON_Parse protect logcollector file_list malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		memset(real_path, 0, PATH_MAX);
		arrayItem = cJSON_GetArrayItem(list,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse protect logcollector file_list[%d] error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->logcollector.file_list[j].filepath);
				free_valuestring(protect_policy->logcollector.file_list[j].real_path);
				free_valuestring(protect_policy->logcollector.file_list[j].extension);
			}
			sniper_free(protect_policy->logcollector.file_list, sizeof(struct _LOGCOLLECTOR_FILE_LIST)*num, POLICY_GET);
			return -1;
		}

		filepath = cJSON_GetObjectItem(arrayItem, "filepath");
		if (!filepath) {
			MON_ERROR("protect_policy->logcollector.file_list[%d].filepath malloc failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->logcollector.file_list[j].filepath);
				free_valuestring(protect_policy->logcollector.file_list[j].real_path);
				free_valuestring(protect_policy->logcollector.file_list[j].extension);
			}
			sniper_free(protect_policy->logcollector.file_list, sizeof(struct _LOGCOLLECTOR_FILE_LIST)*num, POLICY_GET);
			return -1;
		}

		dirpath = get_my_valuestring(filepath);
		if (dirpath == NULL) {
			MON_ERROR("protect_policy->logcollector.file_list[%d].filepath get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->logcollector.file_list[j].filepath);
				free_valuestring(protect_policy->logcollector.file_list[j].real_path);
				free_valuestring(protect_policy->logcollector.file_list[j].extension);
			}
			sniper_free(protect_policy->logcollector.file_list, sizeof(struct _LOGCOLLECTOR_FILE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->logcollector.file_list[i].filepath = dirpath;

		/* 如果关键目录是链接，取真正的目录 */
		len = strlen(dirpath);
		if (realpath(dirpath, real_path) &&
		    (strncmp(dirpath, real_path, len-1) != 0 || strcmp(dirpath+len-1, "/") != 0)) {
			len = strlen(real_path) + 2;
			dirpath = sniper_malloc(len, POLICY_GET);
			protect_policy->logcollector.file_list[i].real_path = dirpath;
			if (!dirpath) {
				MON_ERROR("protect_policy->logcollector.file_list[%d].real_path malloc failed\n", i);
				for (j = 0; j < i; j++) {
					free_valuestring(protect_policy->logcollector.file_list[j].filepath);
					free_valuestring(protect_policy->logcollector.file_list[j].real_path);
					free_valuestring(protect_policy->logcollector.file_list[j].extension);
				}
				free_valuestring(protect_policy->logcollector.file_list[i].filepath);
				sniper_free(protect_policy->logcollector.file_list, sizeof(struct _LOGCOLLECTOR_FILE_LIST)*num, POLICY_GET);
				return -1;
			}
			snprintf(dirpath, len, "%s/", real_path);
		} else {
			/* 没有取到真正的目录，或真正的目录是一样的 */
			protect_policy->logcollector.file_list[i].real_path = NULL;
		}

		ext = get_name(arrayItem, "extension");
		if (ext == NULL) {
			MON_ERROR("get logcollector file_list extension error\n");
			for (j = 0; j < i; j++) {
				free_valuestring(protect_policy->logcollector.file_list[j].filepath);
				free_valuestring(protect_policy->logcollector.file_list[j].real_path);
				free_valuestring(protect_policy->logcollector.file_list[j].extension);
			}
			free_valuestring(protect_policy->logcollector.file_list[i].filepath);
			free_valuestring(protect_policy->logcollector.file_list[i].real_path);
			sniper_free(protect_policy->logcollector.file_list, sizeof(struct _LOGCOLLECTOR_FILE_LIST)*num, POLICY_GET);
			return -1;
		}
		protect_policy->logcollector.file_list[i].extension = ext;
	}

	return 0;
}

static int get_policy_protect_logcollector_file(cJSON *file, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable ,*list;

	enable = cJSON_GetObjectItem(file, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect logcollector file enable error\n");
                return -1;
        }
	protect_policy->logcollector.file_enable = enable->valueint;

	list = cJSON_GetObjectItem(file, "list");
        if (!list) {
		MON_ERROR("policy cJSON_Parse protect logcollector file list error\n");
		protect_policy->logcollector.file_list_num = 0;
        } else {
		if (get_policy_protect_logcollector_file_list(list, protect_policy) < 0) {
			protect_policy->logcollector.file_list_num = 0;
		}
	}

	return 0;
}

static int get_policy_protect_logcollector_network(cJSON *network, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable; 

	enable = cJSON_GetObjectItem(network, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect logcollector network enable error\n");
                return -1;
        }
	protect_policy->logcollector.network_enable = enable->valueint;

	return 0;
}

static int get_policy_protect_logcollector_dnsquery(cJSON *dnsquery, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(dnsquery, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse protect logcollector dnsquery enable error\n");
                return -1;
        }
	protect_policy->logcollector.dnsquery_enable = enable->valueint;

	return 0;
}

/* 日志采集域名 */
static int get_policy_protect_logcollector(cJSON *logcollector, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *process, *file, *network, *dnsquery;

	/* 进程 */
	process = cJSON_GetObjectItem(logcollector, "process");
        if (!process) {
		MON_ERROR("policy cJSON_Parse protect logcollector process error\n");
        } else {
		if (get_policy_protect_logcollector_process(process, protect_policy) < 0) {
			protect_policy->logcollector.process_enable = 0;
		}
	}

	/* 文件 */
	file = cJSON_GetObjectItem(logcollector, "file");
        if (!file) {
		MON_ERROR("policy cJSON_Parse protect logcollector file error\n");
        } else {
		if (get_policy_protect_logcollector_file(file, protect_policy) < 0) {
			protect_policy->logcollector.file_enable = 0;
		}
	}

	/* 网络 */
	network = cJSON_GetObjectItem(logcollector, "network");
	if (!network) {
		MON_ERROR("policy cJSON_Parse protect logcollector network error\n");
        } else {
		if (get_policy_protect_logcollector_network(network, protect_policy) < 0) {
			protect_policy->logcollector.network_enable = 0;
		}
	}

	/* 域名 */
	dnsquery = cJSON_GetObjectItem(logcollector, "dnsquery");
        if (!dnsquery) {
		MON_ERROR("policy cJSON_Parse protect logcollector dnsquery error\n");
        } else {
		if (get_policy_protect_logcollector_dnsquery(dnsquery, protect_policy) < 0) {
			protect_policy->logcollector.dnsquery_enable = 0;
		}
	}

	return 0;
}

/* 防护策略 */
static int get_policy_protect(cJSON *json, struct _PROTECT_POLICY *protect_policy)
{
	cJSON *protect;
	cJSON *behaviour, *process, *network, *account, *sensitive_info, *logcollector;

	protect = cJSON_GetObjectItem(json, "protect");
	if (!protect) {
		MON_ERROR("policy cJSON_Parse protect error\n");
		return -1;
	}

	behaviour = cJSON_GetObjectItem(protect, "behaviour");
	if (!behaviour) {
		MON_ERROR("policy cJSON_Parse protect behaviour error\n");
	} else {
		get_policy_protect_behaviour(behaviour, protect_policy);
	}

	process = cJSON_GetObjectItem(protect, "process");
	if (!process) {
		MON_ERROR("policy cJSON_Parse protect process error\n");
	} else {
		get_policy_protect_process(process, protect_policy);
	}

	network = cJSON_GetObjectItem(protect, "network");
	if (!network) {
		MON_ERROR("policy cJSON_Parse protect network error\n");
	} else {
		get_policy_protect_network(network, protect_policy);
	}

	account = cJSON_GetObjectItem(protect, "account");
	if (!account) {
		MON_ERROR("policy cJSON_Parse protect account error\n");
	} else {
		get_policy_protect_account(account, protect_policy);
	}

	sensitive_info = cJSON_GetObjectItem(protect, "sensitive_info");
        if (!sensitive_info) {
		MON_ERROR("policy cJSON_Parse protect sensitive_info error\n");
        } else {
		get_policy_protect_sensitive_info(sensitive_info, protect_policy);
	}

	logcollector = cJSON_GetObjectItem(protect, "logcollector");
        if (!logcollector) {
		MON_ERROR("policy cJSON_Parse protect logcollector error\n");
                return -1;
        }
	if (get_policy_protect_logcollector(logcollector, protect_policy) < 0) {
		return -1;
	}

	return 0;
}

static int get_policy_fasten_system_load(cJSON *load, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *cpu, *memory, *disk;
	
	enable = cJSON_GetObjectItem(load, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten system load enable error\n");
                return -1;
        }
	fasten_policy->system.load_enable = enable->valueint;

	cpu = cJSON_GetObjectItem(load, "cpu");
        if (!cpu) {
		MON_ERROR("policy cJSON_Parse fasten system load cpu error\n");
                return -1;
        }
	fasten_policy->system.load_cpu = cpu->valueint;

	memory = cJSON_GetObjectItem(load, "memory");
        if (!memory) {
		MON_ERROR("policy cJSON_Parse fasten system load memory error\n");
                return -1;
        }
	fasten_policy->system.load_memory = memory->valueint;

	disk = cJSON_GetObjectItem(load, "disk");
        if (!disk) {
		MON_ERROR("policy cJSON_Parse fasten system load disk error\n");
                return -1;
        }
	fasten_policy->system.load_disk = disk->valueint;

	return 0;
}

/* 加固系统策略 */
static int get_policy_fasten_system(cJSON *system, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *load;

	load = cJSON_GetObjectItem(system, "load");
        if (!load) {
		MON_ERROR("policy cJSON_Parse fasten system load error\n");
        } else {
		if (get_policy_fasten_system_load(load, fasten_policy) < 0) {
			fasten_policy->system.load_enable = 0;
		}
	}

	return 0;
}

static int get_policy_fasten_resource_sys_cpu(cJSON *cpu, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *interval, *limit;

	enable = cJSON_GetObjectItem(cpu, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource sys cpu enable error\n");
		return -1;
	}
	fasten_policy->resource.sys.cpu.enable = enable->valueint;

	interval = cJSON_GetObjectItem(cpu, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse fasten resource sys cpu interval error\n");
		return -1;
	}
	fasten_policy->resource.sys.cpu.interval = interval->valueint;

	limit = cJSON_GetObjectItem(cpu, "limit");
        if (!limit) {
		MON_ERROR("policy cJSON_Parse fasten resource sys cpu limit error\n");
		return -1;
	}
	fasten_policy->resource.sys.cpu.limit = limit->valueint;

	return 0;
}

static int get_policy_fasten_resource_sys_memory(cJSON *memory, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *interval, *limit;

	enable = cJSON_GetObjectItem(memory, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource sys memory enable error\n");
		return -1;
	}
	fasten_policy->resource.sys.memory.enable = enable->valueint;

	interval = cJSON_GetObjectItem(memory, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse fasten resource sys memory interval error\n");
		return -1;
	}
	fasten_policy->resource.sys.memory.interval = interval->valueint;

	limit = cJSON_GetObjectItem(memory, "limit");
        if (!limit) {
		MON_ERROR("policy cJSON_Parse fasten resource sys memory limit error\n");
		return -1;
	}
	fasten_policy->resource.sys.memory.limit = limit->valueint;

	return 0;
}

static int get_policy_fasten_resource_sys_disk(cJSON *disk, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *interval, *limit;

	enable = cJSON_GetObjectItem(disk, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource sys disk enable error\n");
		return -1;
	}
	fasten_policy->resource.sys.disk.enable = enable->valueint;

	interval = cJSON_GetObjectItem(disk, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse fasten resource sys disk interval error\n");
		return -1;
	}
	fasten_policy->resource.sys.disk.interval = interval->valueint;

	limit = cJSON_GetObjectItem(disk, "limit");
        if (!limit) {
		MON_ERROR("policy cJSON_Parse fasten resource sys disk limit error\n");
		return -1;
	}
	fasten_policy->resource.sys.disk.limit = limit->valueint;

	return 0;
}

static int get_policy_fasten_resource_sys_netflow(cJSON *netflow, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *interval, *up, *down;

	enable = cJSON_GetObjectItem(netflow, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource sys netflow enable error\n");
		return -1;
	}
	fasten_policy->resource.sys.netflow.enable = enable->valueint;

	interval = cJSON_GetObjectItem(netflow, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse fasten resource sys netflow interval error\n");
		return -1;
	}
	fasten_policy->resource.sys.netflow.interval = interval->valueint;

	up = cJSON_GetObjectItem(netflow, "up");
        if (!up) {
		MON_ERROR("policy cJSON_Parse fasten resource sys netflow up error\n");
		return -1;
	}
	fasten_policy->resource.sys.netflow.up = up->valueint;

	down = cJSON_GetObjectItem(netflow, "down");
        if (!down) {
		MON_ERROR("policy cJSON_Parse fasten resource sys netflow down error\n");
		return -1;
	}
	fasten_policy->resource.sys.netflow.down = down->valueint;

	return 0;
}

static int get_policy_fasten_resource_sys(cJSON *sys, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *cpu, *memory, *disk, *netflow;

	enable = cJSON_GetObjectItem(sys, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource sys enable error\n");
		return -1;
	}
	fasten_policy->resource.sys.enable = enable->valueint;

	cpu = cJSON_GetObjectItem(sys, "cpu");
        if (!cpu) {
		MON_ERROR("policy cJSON_Parse fasten resource sys cpu error\n");
        } else {
		if (get_policy_fasten_resource_sys_cpu(cpu, fasten_policy) < 0) {
			fasten_policy->resource.sys.cpu.enable = 0;
		}
	}

	memory = cJSON_GetObjectItem(sys, "memory");
        if (!memory) {
		MON_ERROR("policy cJSON_Parse fasten resource sys memory error\n");
        } else {
		if (get_policy_fasten_resource_sys_memory(memory, fasten_policy) < 0) {
			fasten_policy->resource.sys.memory.enable = 0;
		}
	}

	disk = cJSON_GetObjectItem(sys, "disk");
        if (!disk) {
		MON_ERROR("policy cJSON_Parse fasten resource sys disk error\n");
        } else {
		if (get_policy_fasten_resource_sys_disk(disk, fasten_policy) < 0) {
			fasten_policy->resource.sys.disk.enable = 0;
		}
	}

	netflow = cJSON_GetObjectItem(sys, "netflow");
        if (!netflow) {
		MON_ERROR("policy cJSON_Parse fasten resource sys netflow error\n");
        } else {
		if (get_policy_fasten_resource_sys_netflow(netflow, fasten_policy) < 0) {
			fasten_policy->resource.sys.netflow.enable = 0;
		}
	}

	return 0;
}

static int get_policy_fasten_resource_process_cpu(cJSON *cpu, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *interval, *limit;

	enable = cJSON_GetObjectItem(cpu, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource process cpu enable error\n");
		return -1;
	}
	fasten_policy->resource.process.cpu.enable = enable->valueint;

	interval = cJSON_GetObjectItem(cpu, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse fasten resource process cpu interval error\n");
		return -1;
	}
	fasten_policy->resource.process.cpu.interval = interval->valueint;

	limit = cJSON_GetObjectItem(cpu, "limit");
        if (!limit) {
		MON_ERROR("policy cJSON_Parse fasten resource process cpu limit error\n");
		return -1;
	}
	fasten_policy->resource.process.cpu.limit = limit->valueint;

	return 0;
}

static int get_policy_fasten_resource_process_memory(cJSON *memory, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *interval, *limit;

	enable = cJSON_GetObjectItem(memory, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource process memory enable error\n");
		return -1;
	}
	fasten_policy->resource.process.memory.enable = enable->valueint;

	interval = cJSON_GetObjectItem(memory, "interval");
        if (!interval) {
		MON_ERROR("policy cJSON_Parse fasten resource process memory interval error\n");
		return -1;
	}
	fasten_policy->resource.process.memory.interval = interval->valueint;

	limit = cJSON_GetObjectItem(memory, "limit");
        if (!limit) {
		MON_ERROR("policy cJSON_Parse fasten resource process memory limit error\n");
		return -1;
	}
	fasten_policy->resource.process.memory.limit = limit->valueint;

	return 0;
}

static int get_policy_fasten_resource_process(cJSON *process, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *cpu, *memory, *enable;

	enable = cJSON_GetObjectItem(process, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten resource process enable error\n");
		return -1;
	}
	fasten_policy->resource.process.enable = enable->valueint;

	cpu = cJSON_GetObjectItem(process, "cpu");
        if (!cpu) {
		MON_ERROR("policy cJSON_Parse fasten resource process cpu error\n");
        } else {
		if (get_policy_fasten_resource_process_cpu(cpu, fasten_policy) < 0) {
			fasten_policy->resource.process.cpu.enable = 0;
		}
	}

	memory = cJSON_GetObjectItem(process, "memory");
        if (!memory) {
		MON_ERROR("policy cJSON_Parse fasten resource process memory error\n");
        } else {
		if (get_policy_fasten_resource_process_memory(memory, fasten_policy) < 0) {
			fasten_policy->resource.process.memory.enable = 0;
		}
	}

	return 0;
}

/* 加固资源策略 */
static int get_policy_fasten_resource(cJSON *resource, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *sys, *process;

	sys = cJSON_GetObjectItem(resource, "sys");
        if (!sys) {
		MON_ERROR("policy cJSON_Parse fasten resource sys error\n");
        } else {
		if (get_policy_fasten_resource_sys(sys, fasten_policy) < 0) {
			fasten_policy->resource.sys.enable = 0;
		}
	}

	process = cJSON_GetObjectItem(resource, "process");
        if (!process) {
		MON_ERROR("policy cJSON_Parse fasten resource process error\n");
        } else {
		if (get_policy_fasten_resource_process(process, fasten_policy) < 0) {
			fasten_policy->resource.process.enable = 0;
		}
	}

	return 0;
}

static int get_policy_fasten_usb_exclude(cJSON *exclude, struct _FASTEN_POLICY *fasten_policy)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(exclude);
	fasten_policy->device.usb.exclude_num = num;

	fasten_policy->device.usb.exclude = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (fasten_policy->device.usb.exclude == NULL) {
		MON_ERROR("policy cJSON_Parse fasten device usb exclude malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(exclude,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse fasten device usb exclude[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.usb.exclude[j].list);
			}
			sniper_free(fasten_policy->device.usb.exclude, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("fasten_policy->device.usb.exclude[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.usb.exclude[j].list);
			}
			sniper_free(fasten_policy->device.usb.exclude, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		fasten_policy->device.usb.exclude[i].list = buf;

	}
	return 0;
}

/* USB存储接入 */
static int get_policy_fasten_usb(cJSON *usb, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *terminate, *exclude;

	enable = cJSON_GetObjectItem(usb, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten device usb enable error\n");
                return -1;
        }
	fasten_policy->device.usb.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(usb, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse fasten device usb terminate error\n");
                return -1;
        }
	fasten_policy->device.usb.terminate = terminate->valueint;

	exclude = cJSON_GetObjectItem(usb, "exclude");
        if (!exclude) {
		MON_ERROR("policy cJSON_Parse fasten device usb exclude error\n");
		fasten_policy->device.usb.exclude_num = 0;
        } else {
		if (get_policy_fasten_usb_exclude(exclude, fasten_policy) < 0) {
			fasten_policy->device.usb.exclude_num = 0;
		}
	}

	return 0;
}

static int get_policy_fasten_printer_extension(cJSON *extension, struct _FASTEN_POLICY *fasten_policy)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(extension);
	fasten_policy->device.printer.ext_num = num;

	fasten_policy->device.printer.ext = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (fasten_policy->device.printer.ext == NULL) {
		MON_ERROR("policy cJSON_Parse fasten device printer extension malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(extension,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse fasten device printer extension[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.printer.ext[j].list);
			}
			sniper_free(fasten_policy->device.printer.ext, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("fasten_policy->device.printer.ext[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.printer.ext[j].list);
			}
			sniper_free(fasten_policy->device.printer.ext, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		fasten_policy->device.printer.ext[i].list = buf;

	}

	return 0;
}

/* 打印机监控 */
static int get_policy_fasten_printer(cJSON *printer, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *terminate, *extension;

	enable = cJSON_GetObjectItem(printer, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten device printer enable error\n");
                return -1;
        }
	fasten_policy->device.printer.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(printer, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse fasten device printer terminate error\n");
                return -1;
        }
	fasten_policy->device.printer.terminate = terminate->valueint;

	extension = cJSON_GetObjectItem(printer, "extension");
        if (!extension) {
		MON_ERROR("policy cJSON_Parse fasten device printer extension error\n");
		fasten_policy->device.printer.ext_num = 0;
        } else {
		if (get_policy_fasten_printer_extension(extension, fasten_policy) < 0) {
			fasten_policy->device.printer.ext_num = 0;
		}
	}

	return 0;
}

static int get_policy_fasten_cdrom_extension(cJSON *extension, struct _FASTEN_POLICY *fasten_policy)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(extension);
	fasten_policy->device.cdrom.ext_num = num;

	fasten_policy->device.cdrom.ext = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (fasten_policy->device.cdrom.ext == NULL) {
		MON_ERROR("policy cJSON_Parse fasten device cdrom extension malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(extension,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse fasten device cdrom extension[%d].list error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.cdrom.ext[j].list);
			}
			sniper_free(fasten_policy->device.cdrom.ext, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("fasten_policy->device.cdrom.ext[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.cdrom.ext[j].list);
			}
			sniper_free(fasten_policy->device.cdrom.ext, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		fasten_policy->device.cdrom.ext[i].list = buf;

	}

	return 0;
}

/* 刻录机监控 */
static int get_policy_fasten_cdrom(cJSON *cdrom, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *enable, *terminate, *extension;

	enable = cJSON_GetObjectItem(cdrom, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse fasten device cdrom enable error\n");
                return -1;
        }
	fasten_policy->device.cdrom.enable = enable->valueint;

	terminate = cJSON_GetObjectItem(cdrom, "terminate");
        if (!terminate) {
		MON_ERROR("policy cJSON_Parse fasten device cdrom terminate error\n");
                return -1;
        }
	fasten_policy->device.cdrom.terminate = terminate->valueint;

	extension = cJSON_GetObjectItem(cdrom, "extension");
        if (!extension) {
		MON_ERROR("policy cJSON_Parse fasten device cdrom extension error\n");
		fasten_policy->device.cdrom.ext_num = 0;
        } else {
		if (get_policy_fasten_cdrom_extension(extension, fasten_policy) < 0) {
			fasten_policy->device.cdrom.ext_num = 0;
		}
	}

	return 0;
}

/* 例外主机 */
static int get_policy_fasten_exclude_uuid(cJSON *exclude_uuid, struct _FASTEN_POLICY *fasten_policy)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(exclude_uuid);
	fasten_policy->device.exclude_num = num;

	fasten_policy->device.exclude_uuid = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (fasten_policy->device.exclude_uuid == NULL) {
		MON_ERROR("policy cJSON_Parse fasten device exclude_uuid malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(exclude_uuid,i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse fasten device exclude_uuid[%d] error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.exclude_uuid[j].list);
			}
			sniper_free(fasten_policy->device.exclude_uuid, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("fasten_policy->device.exclude_uuid[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(fasten_policy->device.exclude_uuid[j].list);
			}
			sniper_free(fasten_policy->device.exclude_uuid, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		fasten_policy->device.exclude_uuid[i].list = buf;

	}

	return 0;
}

/* 加固设备策略 */
static int get_policy_fasten_device(cJSON *device, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *usb, *printer, *cdrom, *exclude_uuid;

	usb = cJSON_GetObjectItem(device, "usb");
        if (!usb) {
		MON_ERROR("policy cJSON_Parse fasten device usb error\n");
        } else {
		if (get_policy_fasten_usb(usb, fasten_policy) < 0) {
			fasten_policy->device.usb.enable = 0;
		}
	}

	printer = cJSON_GetObjectItem(device, "printer");
        if (!printer) {
		MON_ERROR("policy cJSON_Parse fasten device printer error\n");
        } else {
		if (get_policy_fasten_printer(printer, fasten_policy) < 0) {
			fasten_policy->device.printer.enable = 0;
		}
	}

	cdrom = cJSON_GetObjectItem(device, "cdrom");
        if (!cdrom) {
		MON_ERROR("policy cJSON_Parse fasten device cdrom error\n");
        } else {
		if (get_policy_fasten_cdrom(cdrom, fasten_policy) < 0) {
			fasten_policy->device.cdrom.enable = 0;
		}
	}

	exclude_uuid = cJSON_GetObjectItem(device, "exclude_uuid");
        if (!exclude_uuid) {
		MON_ERROR("policy cJSON_Parse fasten device exclude_uuid error\n");
		fasten_policy->device.exclude_num = 0;
        } else {
		if (get_policy_fasten_exclude_uuid(exclude_uuid, fasten_policy) < 0) {
			fasten_policy->device.exclude_num = 0;
		}
	}

	return 0;
}

/* 加固策略 */
static int get_policy_fasten(cJSON *json, struct _FASTEN_POLICY *fasten_policy)
{
	cJSON *fasten;
	cJSON *system, *resource, *device;

	fasten = cJSON_GetObjectItem(json, "fasten");
        if (!fasten) {
		MON_ERROR("policy cJSON_Parse fasten error\n");
                return -1;
        }

	system = cJSON_GetObjectItem(fasten, "system");
        if (!system) {
		MON_ERROR("policy cJSON_Parse fasten system error\n");
        } else {
		get_policy_fasten_system(system, fasten_policy); 
	}

	resource = cJSON_GetObjectItem(fasten, "resource");
        if (!resource) {
		MON_ERROR("policy cJSON_Parse fasten resource error\n");
        } else {
		get_policy_fasten_resource(resource, fasten_policy); 
	}

	device = cJSON_GetObjectItem(fasten, "device");
        if (!device) {
		MON_ERROR("policy cJSON_Parse fasten device error\n");
        } else {
		get_policy_fasten_device(device, fasten_policy);
	}

	return 0;
}

#ifdef USE_AVIRA
static int get_policy_antivirus_real_time_check(cJSON *json, struct _ANTIVIRUS_POLICY *antivirus_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(json, "enable");
	if (!enable) {
		MON_ERROR("policy cJSON_Parse antivirus real_time_check enable error\n");
		return -1;
	}
	antivirus_policy->real_time_check.enable = enable->valueint;

	return 0;
}


static int get_policy_antivirus_scanning_kill_cron(cJSON *json, struct _ANTIVIRUS_POLICY *antivirus_policy)
{
	cJSON *enable, *scanning_way, *time_type, *day, *time;
	char *buf = NULL;

	enable = cJSON_GetObjectItem(json, "enable");
	if (!enable) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron enable error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.cron.enable = enable->valueint;

	scanning_way = cJSON_GetObjectItem(json, "scanning_way");
	if (!scanning_way) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron scanning_way error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.cron.scanning_way = scanning_way->valueint;

	time_type = cJSON_GetObjectItem(json, "time_type");
	if (!time_type) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron time_type error\n");
		return -1;
	}

	buf = get_my_valuestring(time_type);
        if (buf == NULL) {
                MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron time_type malloc error\n");
                return -1;
        }
        antivirus_policy->scanning_kill.cron.time_type = buf;

	day = cJSON_GetObjectItem(json, "day");
	if (!day) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron day error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.cron.day = day->valueint;

	time = cJSON_GetObjectItem(json, "time");
	if (!time) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron time error\n");
		return -1;
	}

	buf = get_my_valuestring(time);
        if (buf == NULL) {
                MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron time malloc error\n");
		sniper_free(antivirus_policy->scanning_kill.cron.time_type, strlen(antivirus_policy->scanning_kill.cron.time_type), POLICY_GET);
                return -1;
        }
        antivirus_policy->scanning_kill.cron.time = buf;

	return 0;
}

static int get_policy_antivirus_scanning_kill(cJSON *json, struct _ANTIVIRUS_POLICY *antivirus_policy)
{
	cJSON *enable, *cron;

	enable = cJSON_GetObjectItem(json, "enable");
	if (!enable) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill enable error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.enable = enable->valueint;

	cron = cJSON_GetObjectItem(json, "cron");
	if (!cron) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill cron error\n");
		return -1;
	} else {
		if (get_policy_antivirus_scanning_kill_cron(cron, antivirus_policy) < 0) {
			return -1;
		}
	}

	return 0;
}

static int get_policy_antivirus_trust_list(cJSON *trust_list, struct _ANTIVIRUS_POLICY *antivirus_policy)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(trust_list);
	antivirus_policy->list_num = num;

	antivirus_policy->trust_list = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
        if (antivirus_policy->trust_list == NULL) {
                MON_ERROR("policy cJSON_Parse antivirus trust_list malloc failed\n");
                return -1;
        }

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(trust_list, i);
		if (!arrayItem) {
			MON_ERROR("policy cJSON_Parse antivirus trust list[%d] error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(antivirus_policy->trust_list[j].list);
			}
			sniper_free(antivirus_policy->trust_list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("policy cJSON_Parse antivirus trust list[%d].list get value failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(antivirus_policy->trust_list[j].list);
			}
			sniper_free(antivirus_policy->trust_list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		antivirus_policy->trust_list[i].list = buf;
	}
	
	return 0;
}

/* 病毒防护 */
static int get_policy_antivirus(cJSON *json, struct _ANTIVIRUS_POLICY *antivirus_policy)
{
	cJSON *antivirus;
	cJSON *reserved_space, *scanning_kill, *real_time_check, *trust_list, *automate, *neglect_size;

	antivirus = cJSON_GetObjectItem(json, "antivirus");
	if (!antivirus) {
		MON_ERROR("policy cJSON_Parse antivirus error\n");
		return -1;
	}

	real_time_check = cJSON_GetObjectItem(antivirus, "real_time_check");
	if (!real_time_check) {
		MON_ERROR("policy cJSON_Parse antivirus real_time_check error\n");
		return -1;
	} else {
		if (get_policy_antivirus_real_time_check(real_time_check, antivirus_policy) < 0) {
			antivirus_policy->real_time_check.enable = 0;
			return -1;
		}
	}

	scanning_kill = cJSON_GetObjectItem(antivirus, "scanning_kill");
	if (!scanning_kill) {
		MON_ERROR("policy cJSON_Parse antivirus scanning_kill error\n");
		return -1;
	} else {
		if (get_policy_antivirus_scanning_kill(scanning_kill, antivirus_policy) < 0) {
			antivirus_policy->scanning_kill.enable = 0;
			return -1;
		}
	}

	automate = cJSON_GetObjectItem(antivirus, "automate");
	if (!automate) {
		MON_ERROR("policy cJSON_Parse antivirus automate error\n");
		return -1;
	}
	antivirus_policy->automate = automate->valueint;

	reserved_space = cJSON_GetObjectItem(antivirus, "reserved_space");
	if (!reserved_space) {
		MON_ERROR("policy cJSON_Parse antivirus reserved_space error\n");
		return -1;
	}
	antivirus_policy->reserved_space = reserved_space->valueint;

	neglect_size = cJSON_GetObjectItem(antivirus, "neglect_size");
	if (!neglect_size) {
		MON_ERROR("policy cJSON_Parse antivirus neglect_size error\n");
		return -1;
	}
	antivirus_policy->neglect_size = neglect_size->valueint;

	trust_list = cJSON_GetObjectItem(antivirus, "trust_list");
	if (!trust_list) {
		MON_ERROR("policy cJSON_Parse antivirus trust_list error\n");
		return -1;
	} else {
		if (get_policy_antivirus_trust_list(trust_list, antivirus_policy) < 0) {
			antivirus_policy->list_num = 0;
			return -1;
		}
	}
	return 0;
}
#endif

static int get_policy_other_allow_uninstall(cJSON *allow_uninstall, struct _OTHER_POLICY *other_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(allow_uninstall, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse other allow_uninstall enable error\n");
                return -1;
	}
	other_policy->allow_uninstall.enable = enable->valueint;

	return 0;
}

static int get_policy_other_allow_ui_tray(cJSON *allow_ui_tray, struct _OTHER_POLICY *other_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(allow_ui_tray, "enable");
        if (!enable) {
		MON_ERROR("policy cJSON_Parse other allow_ui_tray enable error\n");
                return -1;
	}
	other_policy->allow_ui_tray.enable = enable->valueint;

	return 0;
}

/* 其他配置 */
static int get_policy_other(cJSON *json, struct _OTHER_POLICY *other_policy)
{
	cJSON *other;
	cJSON *allow_uninstall, *allow_ui_tray;

	other = cJSON_GetObjectItem(json, "other");
        if (!other) {
		MON_ERROR("policy cJSON_Parse other error\n");
                return -1;
        }

	allow_uninstall = cJSON_GetObjectItem(other, "allow_uninstall");
        if (!allow_uninstall) {
		MON_ERROR("policy cJSON_Parse other allow_uninstall error\n");
	} else {
		if (get_policy_other_allow_uninstall(allow_uninstall, other_policy) < 0) {
			other_policy->allow_uninstall.enable = 0;
		}
	}

	allow_ui_tray = cJSON_GetObjectItem(other, "allow_ui_tray");
        if (!allow_ui_tray) {
		MON_ERROR("policy cJSON_Parse other allow_ui_tray error\n");
	} else {
		if (get_policy_other_allow_ui_tray(allow_ui_tray, other_policy) < 0) {
			other_policy->allow_ui_tray.enable = 0;
		}
	}

	return 0;
}

/* 回收防护策略资源 */
static void free_policy_protect_behaviour(PROTECT_BEHAVIOUR *policy)
{
	free_valuestring(policy->ransomware.track.ext.list);

	free_valuestring(policy->ransomware.encrypt.ext.list);
	free_valuestring(policy->ransomware.encrypt.my_linux.ext.list);
}

static void free_policy_protect_process(PROTECT_PROCESS *policy)
{
	int i = 0, num = 0, len = 0;

        num = policy->command_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->command_table_list[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(policy->command_table_list, len, POLICY_GET);
        policy->command_num = 0;
}

static void free_policy_protect_network(PROTECT_NETWORK *policy)
{
	int i = 0, num = 0, len = 0;

        num = policy->illegal_connect.addr_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->illegal_connect.address[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(policy->illegal_connect.address, len, POLICY_GET);
        policy->illegal_connect.addr_num = 0;

	num = policy->port.sensitive.list_num;
        len = sizeof(struct _SENSITIVE_LIST) * num;
        sniper_free(policy->port.sensitive.list, len, POLICY_GET);
        policy->port.sensitive.list_num = 0;

	num = policy->sensitive_port.list_num;
        len = sizeof(struct _SENSITIVE_LIST) * num;
        sniper_free(policy->sensitive_port.list, len, POLICY_GET);
        policy->sensitive_port.list_num = 0;
	
}

static void free_policy_protect_account(PROTECT_ACCOUNT *policy)
{
	int i = 0, num = 0, len = 0;

        num = policy->login.local.time.list_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->login.local.time.list[i].start_time);
                free_valuestring(policy->login.local.time.list[i].end_time);
        }
        len = sizeof(struct _TIME_LIST) * num;
        sniper_free(policy->login.local.time.list, len, POLICY_GET);
        policy->login.local.time.list_num = 0;

        num = policy->login.remote.time.list_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->login.remote.time.list[i].start_time);
                free_valuestring(policy->login.remote.time.list[i].end_time);
        }
        len = sizeof(struct _TIME_LIST) * num;
        sniper_free(policy->login.remote.time.list, len, POLICY_GET);
        policy->login.remote.time.list_num = 0;

        num = policy->login.remote.location.list_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->login.remote.location.list[i].city);
                free_valuestring(policy->login.remote.location.list[i].province);
        }
        len = sizeof(struct _LOCATION_LIST) * num;
        sniper_free(policy->login.remote.location.list, len, POLICY_GET);
        policy->login.remote.location.list_num = 0;

}

static void free_policy_protect_sensitive_info(PROTECT_SENSITIVE *policy)
{
	int i = 0, num = 0;
	int len = 0;

	num = policy->sensitive_file.list_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->sensitive_file.list[i].list);
	}
	len = sizeof(struct _POLICY_LIST) * num;
	sniper_free(policy->sensitive_file.list, len, POLICY_GET);
	policy->sensitive_file.list_num = 0;

	num = policy->log_delete.list_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->log_delete.list[i].list);
	}
	len = sizeof(struct _POLICY_LIST) * num;
	sniper_free(policy->log_delete.list, len, POLICY_GET);
	policy->log_delete.list_num = 0;

        num = policy->file_safe.list_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->file_safe.list[i].path);
		if (policy->file_safe.list[i].real_path) {
			free_valuestring(policy->file_safe.list[i].real_path);
		}
		free_valuestring(policy->file_safe.list[i].name);
		free_valuestring(policy->file_safe.list[i].process);
		free_valuestring(policy->file_safe.list[i].operation);
	}
	len = sizeof(struct _SAFE_FILE_LIST) * num;
	sniper_free(policy->file_safe.list, len, POLICY_GET);
	policy->file_safe.list_num = 0;

	free_valuestring(policy->file_usb.extension);

	if (policy->middleware.script_files.ext) {
		free_valuestring(policy->middleware.script_files.ext);
	}

	if (policy->middleware.executable_files.ext) {
		free_valuestring(policy->middleware.executable_files.ext);
	}

	if (policy->middleware.target) {
		free_valuestring(policy->middleware.target);
	}

	num = policy->illegal_script.keyword_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->illegal_script.keyword[i].list);
	}
	len = sizeof(struct _POLICY_LIST) * num;
	sniper_free(policy->illegal_script.keyword, len, POLICY_GET);
	policy->illegal_script.keyword_num = 0;

	num = policy->illegal_script.default_keyword_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->illegal_script.default_keyword[i].list);
	}
	len = sizeof(struct _POLICY_LIST) * num;
	sniper_free(policy->illegal_script.default_keyword, len, POLICY_GET);
	policy->illegal_script.default_keyword_num = 0;

	num = policy->illegal_script.target_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->illegal_script.target[i].path);
		if (policy->illegal_script.target[i].real_path != NULL) {
			free_valuestring(policy->illegal_script.target[i].real_path);
		}
		free_valuestring(policy->illegal_script.target[i].extension);
	}
	len = sizeof(struct _ILLEGAL_SCRIPT_TARGET) * num;
	sniper_free(policy->illegal_script.target, len, POLICY_GET);
	policy->illegal_script.target_num = 0;

	num = policy->webshell_detect.target_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->webshell_detect.target[i].path);
		if (policy->webshell_detect.target[i].real_path != NULL) {
			free_valuestring(policy->webshell_detect.target[i].real_path);
		}
		free_valuestring(policy->webshell_detect.target[i].extension);
	}
	len = sizeof(struct _WEBSHELL_DETECT_TARGET) * num;
	sniper_free(policy->webshell_detect.target, len, POLICY_GET);
	policy->webshell_detect.target_num = 0;

}

static void free_policy_protect_logcollector(PROTECT_LOGCOLLECTOR *policy)
{
	int i = 0, num = 0;
	int len = 0;

        num = policy->file_list_num;
        for (i = 0; i < num; i++) {
		free_valuestring(policy->file_list[i].filepath);
		if (policy->file_list[i].real_path != NULL) {
			free_valuestring(policy->file_list[i].real_path);
		} 
		free_valuestring(policy->file_list[i].extension);
	}
	len = sizeof(struct _LOGCOLLECTOR_FILE_LIST) * num;
	sniper_free(policy->file_list, len, POLICY_GET);
	policy->file_list_num = 0;
}

void free_policy_protect_ptr(PROTECT_POLICY *ptr)
{
        free_policy_protect_behaviour(&ptr->behaviour);
        free_policy_protect_process(&ptr->process);
        free_policy_protect_network(&ptr->network);
        free_policy_protect_account(&ptr->account);
        free_policy_protect_sensitive_info(&ptr->sensitive_info);
        free_policy_protect_logcollector(&ptr->logcollector);
}

static void save_old_protect_policy(void)
{
	
        free_policy_protect_ptr(&old_protect_policy_global);
        old_protect_policy_global = protect_policy_global;
}

static int get_protect_policy(struct _PROTECT_POLICY *protect_policy)
{
        protect_policy_global.behaviour = protect_policy->behaviour;
        protect_policy_global.process = protect_policy->process;
        protect_policy_global.network = protect_policy->network;
        protect_policy_global.account = protect_policy->account;
        protect_policy_global.sensitive_info = protect_policy->sensitive_info;
        protect_policy_global.logcollector = protect_policy->logcollector;

        return 0;
}

/* 回收加固策略资源 */
static void free_policy_fasten_device_usb(DEVICE_MY_USB *policy)
{
	int i = 0, num = 0, len = 0;

        num = policy->exclude_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->exclude[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(policy->exclude, len, POLICY_GET);
        policy->exclude_num = 0;
}

static void free_policy_fasten_device_printer(DEVICE_MY_PRINTER *policy)
{
	int i = 0, num = 0, len = 0;

        num = policy->ext_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->ext[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(policy->ext, len, POLICY_GET);
        policy->ext_num = 0;
}

static void free_policy_fasten_device_cdrom(DEVICE_MY_CDROM *policy)
{
	int i = 0, num = 0, len = 0;

        num = policy->ext_num;
        for (i = 0; i < num; i++) {
                free_valuestring(policy->ext[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(policy->ext, len, POLICY_GET);
        policy->ext_num = 0;
}

void free_policy_fasten_device_ptr(FASTEN_DEVICE *ptr)
{
	int i = 0, num = 0, len = 0;

        free_policy_fasten_device_usb(&ptr->usb);
        free_policy_fasten_device_printer(&ptr->printer);
        free_policy_fasten_device_cdrom(&ptr->cdrom);

        num = ptr->exclude_num;
        for (i = 0; i < num; i++) {
                free_valuestring(ptr->exclude_uuid[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(ptr->exclude_uuid, len, POLICY_GET);
        ptr->exclude_num = 0;
}

void free_policy_fasten_ptr(FASTEN_POLICY *ptr)
{
	free_policy_fasten_device_ptr(&ptr->device);	
}

static void save_old_fasten_policy(void)
{
	
        free_policy_fasten_ptr(&old_fasten_policy_global);
        old_fasten_policy_global = fasten_policy_global;
}

static int get_fasten_policy(struct _FASTEN_POLICY *fasten_policy)
{
        fasten_policy_global.system = fasten_policy->system;
        fasten_policy_global.resource = fasten_policy->resource;
        fasten_policy_global.device = fasten_policy->device;

        return 0;
}

#ifdef USE_AVIRA
void free_policy_antivirus_scanning_kill_cron(struct _SCANNING_CRON *ptr)
{
	free_valuestring(ptr->time_type);
	free_valuestring(ptr->time);
}

void free_policy_antivirus_ptr(struct _ANTIVIRUS_POLICY *ptr)
{
	int i = 0, num = 0;
	num = ptr->list_num;
	for (i = 0; i < num; i++) {
		free_valuestring(ptr->trust_list[i].list);
	}
	ptr->list_num = 0;
	free_policy_antivirus_scanning_kill_cron(&ptr->scanning_kill.cron);	
}

static void save_old_antivirus_policy(void)
{	
        free_policy_antivirus_ptr(&old_antivirus_policy_global);
        old_antivirus_policy_global = antivirus_policy_global;
}

static int get_antivirus_policy(struct _ANTIVIRUS_POLICY *antivirus_policy)
{
        antivirus_policy_global.reserved_space = antivirus_policy->reserved_space;
        antivirus_policy_global.automate = antivirus_policy->automate;
        antivirus_policy_global.neglect_size = antivirus_policy->neglect_size;
        antivirus_policy_global.list_num = antivirus_policy->list_num;
        antivirus_policy_global.real_time_check = antivirus_policy->real_time_check;
        antivirus_policy_global.scanning_kill = antivirus_policy->scanning_kill;
        antivirus_policy_global.trust_list = antivirus_policy->trust_list;

        return 0;
}
#endif

static void save_old_other_policy(void)
{
	
	/* nothing to free */
        old_other_policy_global = other_policy_global;
}

static int get_other_policy(struct _OTHER_POLICY *other_policy)
{
        other_policy_global.allow_uninstall = other_policy->allow_uninstall;
        other_policy_global.allow_ui_tray = other_policy->allow_ui_tray;

        return 0;
}

static void dump_policy_protect(FILE *fp, FILE *fp_en)
{
	int i = 0, num = 0;
	int enable = 0, terminate = 0, locking = 0, locking_time = 0;

	fprintf(fp, "[防护策略]\n");
	fprintf(fp_en, "[protection strategy]\n");

	if (protect_policy_global.behaviour.pool.enable == TURN_MY_ON ||
	    protect_policy_global.behaviour.ransomware.encrypt.enable == TURN_MY_ON) {
		fprintf(fp, "--恶意行为防护--\n");
		fprintf(fp_en, "--malicious behavior protection--\n");
	}

	enable = protect_policy_global.behaviour.pool.enable;
	if (enable == TURN_MY_ON) {
		terminate = protect_policy_global.behaviour.pool.terminate;
		fprintf(fp, "[%d]挖矿行为:%s----阻断:%s",
				protect_count+1,
				check_my_switch(enable), check_my_switch(terminate));
		fprintf(fp_en, "[%d]mining behavior :%s----terminate:%s",
				protect_count+1,
				check_my_switch_en(enable), check_my_switch_en(terminate));
		if (terminate == TURN_MY_ON) {
			locking = protect_policy_global.behaviour.pool.locking;
			fprintf(fp, "----锁定IP:%s", check_my_switch(locking));
			fprintf(fp_en, "----lock IP:%s", check_my_switch_en(locking));
			if (locking == TURN_MY_ON) {
				locking_time = protect_policy_global.behaviour.pool.locking_time;
				fprintf(fp, "----锁定时长[%d]分钟", locking_time);
				fprintf(fp_en, "----[%d]minutes lock time", locking_time);
			}
		}
		fprintf(fp, "\n");
		fprintf(fp_en, "\n");
		protect_count++;
	}

	/* 不显示是否采用诱捕文件，不显示几分钟内的修改不备份 */
	if (protect_policy_global.behaviour.ransomware.encrypt.enable == TURN_MY_ON) {
		fprintf(fp, "[%d]勒索行为:开启----加密防护引擎:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.behaviour.ransomware.encrypt.enable),
				check_my_switch(protect_policy_global.behaviour.ransomware.encrypt.terminate));
		fprintf(fp_en, "[%d]extortion:open----cryptographic protection engine :%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.behaviour.ransomware.encrypt.enable),
				check_my_switch_en(protect_policy_global.behaviour.ransomware.encrypt.terminate));

		enable = protect_policy_global.behaviour.ransomware.encrypt.backup.enable;
		fprintf(fp, "   文件备份:%s", check_my_switch(enable));
		fprintf(fp_en, "   file backup:%s", check_my_switch_en(enable));
		if (enable == TURN_MY_ON) {
			fprintf(fp, "----大于(%d)MB文件不备份----备份保留空间(%d)GB",
					protect_policy_global.behaviour.ransomware.encrypt.backup.neglect_size,
					protect_policy_global.behaviour.ransomware.encrypt.backup.backup_size);
			fprintf(fp_en, "----no backup if larger then (%d)MB----backup reserved space(%d)GB",
					protect_policy_global.behaviour.ransomware.encrypt.backup.neglect_size,
					protect_policy_global.behaviour.ransomware.encrypt.backup.backup_size);
		}
		fprintf(fp, "\n");
		fprintf(fp_en, "\n");

		if (enable == TURN_MY_ON) {
			if (protect_policy_global.behaviour.ransomware.encrypt.my_linux.ext.list == NULL) {
				fprintf(fp, "   备份文件类型:(无)\n");
				fprintf(fp_en, "   backup file type:(null)\n");
			} else {
				fprintf(fp, "   备份文件类型:%s\n", protect_policy_global.behaviour.ransomware.encrypt.my_linux.ext.list);
				fprintf(fp_en, "   backup file type:%s\n", protect_policy_global.behaviour.ransomware.encrypt.my_linux.ext.list);
			}
		}
		protect_count++;
	}

	if (protect_policy_global.process.reverse_shell.enable == TURN_MY_ON ||
	    protect_policy_global.process.privilege.enable == TURN_MY_ON ||
	    protect_policy_global.process.mbr.enable == TURN_MY_ON ||
	    protect_policy_global.process.webshell.enable == TURN_MY_ON ||
	    protect_policy_global.process.service_process.enable == TURN_MY_ON ||
	    protect_policy_global.process.tunnel.enable == TURN_MY_ON ||
	    protect_policy_global.process.risk_command.enable == TURN_MY_ON ||
	    protect_policy_global.process.abnormal_process.enable == TURN_MY_ON) {
		fprintf(fp, "--进程异常防护--\n");
		fprintf(fp_en, "--process exception protection--\n");
	}

	enable = protect_policy_global.process.reverse_shell.enable;
	if (enable == TURN_MY_ON) {
		terminate = protect_policy_global.process.reverse_shell.terminate;
		fprintf(fp, "[%d]反弹shell:%s----阻断:%s",
				protect_count+1,
				check_my_switch(enable), check_my_switch(terminate));
		fprintf(fp_en, "[%d]reverse shell:%s----terminate:%s",
				protect_count+1,
				check_my_switch_en(enable), check_my_switch_en(terminate));
		if (TURN_MY_ON == terminate) {
			locking = protect_policy_global.process.reverse_shell.locking;
			fprintf(fp, "----锁定IP:%s", check_my_switch(locking));
			fprintf(fp_en, "----lock IP:%s", check_my_switch_en(locking));
			if (TURN_MY_ON == locking) {
				locking_time = protect_policy_global.process.reverse_shell.locking_time;
				fprintf(fp, "----锁定时长[%d]分钟", locking_time);
				fprintf(fp_en, "----[%d]minutes lock time", locking_time);
			}
		}
		fprintf(fp, "\n");
		fprintf(fp_en, "\n");
		protect_count++;
	}

	enable = protect_policy_global.process.privilege.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]非法提权:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.process.privilege.enable),
				check_my_switch(protect_policy_global.process.privilege.terminate));
		fprintf(fp_en, "[%d]illegal escalation:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.process.privilege.enable),
				check_my_switch_en(protect_policy_global.process.privilege.terminate));
		protect_count++;
	}

	enable = protect_policy_global.process.mbr.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]MBR防护:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.process.mbr.enable),
				check_my_switch(protect_policy_global.process.mbr.terminate));
		fprintf(fp_en, "[%d]MBR protection:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.process.mbr.enable),
				check_my_switch_en(protect_policy_global.process.mbr.terminate));
		protect_count++;
	}

	enable = protect_policy_global.process.webshell.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]中国菜刀命令执行:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.process.webshell.enable),
				check_my_switch(protect_policy_global.process.webshell.terminate));
		fprintf(fp_en, "[%d]Chinese kitchen knife command execution:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.process.webshell.enable),
				check_my_switch_en(protect_policy_global.process.webshell.terminate));
		protect_count++;
	}

	enable = protect_policy_global.process.service_process.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]对外服务进程异常执行:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.process.service_process.enable),
				check_my_switch(protect_policy_global.process.service_process.terminate));
		fprintf(fp_en, "[%d]abnormal execution of external service process:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.process.service_process.enable),
				check_my_switch_en(protect_policy_global.process.service_process.terminate));
		protect_count++;
	}

	enable = protect_policy_global.process.tunnel.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]隧道搭建:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.process.tunnel.enable),
				check_my_switch(protect_policy_global.process.tunnel.terminate));
		fprintf(fp_en, "[%d]tunnel construction:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.process.tunnel.enable),
				check_my_switch_en(protect_policy_global.process.tunnel.terminate));
		protect_count++;
	}

	enable = protect_policy_global.process.risk_command.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]危险命令:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.process.risk_command.enable),
				check_my_switch(protect_policy_global.process.risk_command.terminate));
		fprintf(fp_en, "[%d]risk command:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.process.risk_command.enable),
				check_my_switch_en(protect_policy_global.process.risk_command.terminate));
		protect_count++;
	}

	enable = protect_policy_global.process.abnormal_process.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]异常进程:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.process.abnormal_process.enable),
				check_my_switch(protect_policy_global.process.abnormal_process.terminate));
		fprintf(fp_en, "[%d]abnormal process:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.process.abnormal_process.enable),
				check_my_switch_en(protect_policy_global.process.abnormal_process.terminate));
		protect_count++;
	}

#if 0
	/* 可疑命令的库，暂时用不到了 */
	fprintf(fp, "命令列表:");
	num = protect_policy_global.process.command_num;
	for (i = 0; i < num; i++) {
		fprintf(fp, "%s;", protect_policy_global.process.command_table_list[i].list);
	}
	fprintf(fp, "\n");
#endif

	if (protect_policy_global.network.domain.enable == TURN_MY_ON ||
	    protect_policy_global.network.illegal_connect.enable == TURN_MY_ON ||
	    protect_policy_global.network.port.enable == TURN_MY_ON ||
	    protect_policy_global.network.sensitive_port.enable == TURN_MY_ON) {
		fprintf(fp, "--异常网络防护--\n");
		fprintf(fp_en, "--abnormal network protection--\n");
	}

	/* Note: 恶意域名策略取消了，管控下发的总是disable，恶意域名相关代码基本都删除了，
	   这里作为遗迹保留曾经有过的痕迹，因为总是disable，永远不会打印恶意策略策略 */
	enable = protect_policy_global.network.domain.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]访问恶意域名:%s----阻断:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.network.domain.enable),
				check_my_switch(protect_policy_global.network.domain.terminate));
		fprintf(fp_en, "[%d]access malicious domains:%s----terminate:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.network.domain.enable),
				check_my_switch_en(protect_policy_global.network.domain.terminate));
		protect_count++;
	}

	enable = protect_policy_global.network.illegal_connect.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]非法连接互联网:%s----隔离主机:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.network.illegal_connect.enable),
				check_my_switch(protect_policy_global.network.illegal_connect.terminate));
		fprintf(fp_en, "[%d]internet connection illegally:%s----quarantine host:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.network.illegal_connect.enable),
				check_my_switch_en(protect_policy_global.network.illegal_connect.terminate));

#if 0 //不显示检测规则
		fprintf(fp, "连接间隔(%d)分钟:\n", protect_policy_global.network.illegal_connect.interval);
		num = protect_policy_global.network.illegal_connect.addr_num;
		if (num > 0) {
			fprintf(fp, "探测地址:");
			for (i = 0; i < num; i++) {
				fprintf(fp, "%s;", protect_policy_global.network.illegal_connect.address[i].list);
			}
			fprintf(fp, "\n");
		}
#endif
		protect_count++;
	}

	/* 不显示检测规则：单个IP请求访问时间范围(%d)秒内，最大扫描端口数量(%d)个 */
	enable = protect_policy_global.network.port.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]端口扫描防护:%s----锁定IP:%s",
			protect_count+1,
			check_my_switch(protect_policy_global.network.port.enable),
			check_my_switch(protect_policy_global.network.port.terminate));
		fprintf(fp_en, "[%d]port scan protection:%s----lock IP:%s",
			protect_count+1,
			check_my_switch_en(protect_policy_global.network.port.enable),
			check_my_switch_en(protect_policy_global.network.port.terminate));
		if (protect_policy_global.network.port.terminate == TURN_MY_ON) {
			fprintf(fp, "----锁定时长[%d]分钟", protect_policy_global.network.port.locking_time);
		}
		if (protect_policy_global.network.port.terminate == TURN_MY_ON) {
			fprintf(fp_en, "----[%d]minutes lock time", protect_policy_global.network.port.locking_time);
		}
		fprintf(fp, "\n");
		fprintf(fp_en, "\n");
		protect_count++;
	}

	enable = protect_policy_global.network.sensitive_port.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]端口诱捕:%s----锁定IP:%s",
			protect_count+1,
			check_my_switch(protect_policy_global.network.sensitive_port.enable),
			check_my_switch(protect_policy_global.network.sensitive_port.terminate));
		fprintf(fp_en, "[%d]port trapping:%s----lock IP:%s",
			protect_count+1,
			check_my_switch_en(protect_policy_global.network.sensitive_port.enable),
			check_my_switch_en(protect_policy_global.network.sensitive_port.terminate));
		if (protect_policy_global.network.sensitive_port.terminate == TURN_MY_ON) {
			fprintf(fp, "----锁定时长[%d]分钟",protect_policy_global.network.sensitive_port.locking_time);
			fprintf(fp_en, "----[%d]minutes lock time",protect_policy_global.network.sensitive_port.locking_time);
		}
		fprintf(fp, "\n");
		fprintf(fp_en, "\n");
#if 0 //不显示检测规则
		num = protect_policy_global.network.sensitive_port.list_num;
		if (num > 0) {
			fprintf(fp, "端口列表:");
			for (i = 0; i < num; i++) {
				fprintf(fp, "%d;", protect_policy_global.network.sensitive_port.list[i].port);
			}
			fprintf(fp, "\n");
		}
#endif
		protect_count++;
	}

	if (protect_policy_global.account.login.enable == TURN_MY_ON ||
	    protect_policy_global.account.abnormal_user.enable == TURN_MY_ON ||
	    protect_policy_global.account.user_change.enable == TURN_MY_ON) {
		fprintf(fp, "--系统账号防护--\n");
		fprintf(fp_en, "--system account protection--\n");
	}

	if (protect_policy_global.account.login.enable == TURN_MY_ON && 
	   (protect_policy_global.account.login.local.enable == TURN_MY_ON ||
	    protect_policy_global.account.login.remote.enable == TURN_MY_ON ||
	    protect_policy_global.account.login.crack.enable == TURN_MY_ON)) {
		fprintf(fp, "[%d]异常登录:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]abnormal login:open\n", protect_count+1);
		protect_count++;
	}

	enable = protect_policy_global.account.login.local.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "本地用户登录监控:开启\n");
		fprintf(fp_en, "local user login monitoring:open\n");

		enable = protect_policy_global.account.login.local.time.enable;
		num = protect_policy_global.account.login.local.time.list_num;
		if (enable == TURN_MY_ON && num > 0) {
			fprintf(fp, "常用本地登录时间:\n");
			fprintf(fp_en, "common local login time:\n");
			for (i = 0; i < num; i++) {
				fprintf(fp, "  ----[%d] %s 至 %s\n",
					i+1,
					protect_policy_global.account.login.local.time.list[i].start_time,
					protect_policy_global.account.login.local.time.list[i].end_time);
				fprintf(fp_en, "  ----[%d] %s to %s\n",
					i+1,
					protect_policy_global.account.login.local.time.list[i].start_time,
					protect_policy_global.account.login.local.time.list[i].end_time);
			}
			terminate = protect_policy_global.account.login.local.terminate;
			fprintf(fp, "阻断非法本地登录:%s", check_my_switch(terminate));
			fprintf(fp_en, "block illegal local login:%s", check_my_switch_en(terminate));
			if (terminate == TURN_MY_ON) {
				fprintf(fp, "----注销方式:%s", 
					check_my_switch_logout(protect_policy_global.account.login.local.terminate_mode));
				fprintf(fp_en, "----logout mode:%s", 
					check_my_switch_logout_en(protect_policy_global.account.login.local.terminate_mode));
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	enable = protect_policy_global.account.login.remote.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "远程登录监控:开启\n");
		fprintf(fp_en, "remote login monitoring:open\n");
		enable = protect_policy_global.account.login.remote.time.enable;
		num = protect_policy_global.account.login.remote.time.list_num;
		if (enable == TURN_MY_ON && num > 0) {
			fprintf(fp, "常用远程登录时间:\n");
			fprintf(fp_en, "common remote login time:\n");
			for (i = 0; i < num; i++) {
				fprintf(fp, "----[%d] %s 至 %s\n",
					i+1,
					protect_policy_global.account.login.remote.time.list[i].start_time,
					protect_policy_global.account.login.remote.time.list[i].end_time);
				fprintf(fp_en, "----[%d] %s to %s\n",
					i+1,
					protect_policy_global.account.login.remote.time.list[i].start_time,
					protect_policy_global.account.login.remote.time.list[i].end_time);
			}
		}

		enable = protect_policy_global.account.login.remote.location.enable;
		num = protect_policy_global.account.login.remote.location.list_num;
		if (enable == TURN_MY_ON && num > 0) {
			fprintf(fp, "常用远程登录地点:\n");
			fprintf(fp_en, "common remote login locations:\n");
			for (i = 0; i < num; i++) {
				fprintf(fp, "----[%d] %s省/%s市\n",
					i+1,
					protect_policy_global.account.login.remote.location.list[i].province,
					protect_policy_global.account.login.remote.location.list[i].city);
				fprintf(fp_en, "----[%d] %s province/%s city\n",
					i+1,
					protect_policy_global.account.login.remote.location.list[i].province,
					protect_policy_global.account.login.remote.location.list[i].city);
			}
		}

		if (protect_policy_global.account.login.remote.time.enable == TURN_MY_ON ||
		    protect_policy_global.account.login.remote.location.enable == TURN_MY_ON) {
			terminate = protect_policy_global.account.login.remote.terminate;
			fprintf(fp, "阻断非法远程登录:%s", check_my_switch(terminate));
			fprintf(fp_en, "block illegal remote login:%s", check_my_switch_en(terminate));
			if (terminate == TURN_MY_ON) {
				fprintf(fp, "----注销方式:%s", 
					check_my_switch_logout(protect_policy_global.account.login.remote.terminate_mode));
				fprintf(fp_en, "----logout mode:%s", 
					check_my_switch_logout_en(protect_policy_global.account.login.remote.terminate_mode));
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}

	}

	/* 不显示检测规则 */
	enable = protect_policy_global.account.login.crack.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "暴力密码破解防护:%s----锁定IP:%s",
				check_my_switch(protect_policy_global.account.login.crack.enable),
				check_my_switch(protect_policy_global.account.login.crack.terminate));
		fprintf(fp_en, "brute force key protection:%s----lock IP:%s",
				check_my_switch_en(protect_policy_global.account.login.crack.enable),
				check_my_switch_en(protect_policy_global.account.login.crack.terminate));
		if (protect_policy_global.account.login.crack.terminate == TURN_MY_ON) {
			fprintf(fp, "----锁定时长[%d]分钟\n",
					protect_policy_global.account.login.crack.locking_time);
			fprintf(fp_en, "----[%d]minutes lock time\n",
					protect_policy_global.account.login.crack.locking_time);
		}
		fprintf(fp, "\n");
		fprintf(fp_en, "\n");
	}

	enable = protect_policy_global.account.abnormal_user.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]异常账号:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.account.abnormal_user.enable));
		fprintf(fp_en, "[%d]abnormal account:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.account.abnormal_user.enable));
		protect_count++;
	}

	enable = protect_policy_global.account.user_change.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]用户变更监控:%s, 用户组变更:%s, 用户变更:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.account.user_change.enable),
				check_my_switch(protect_policy_global.account.user_change.group.enable),
				check_my_switch(protect_policy_global.account.user_change.user.enable));
		fprintf(fp_en, "[%d]user change monitoring:%s, user group change:%s, user change:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.account.user_change.enable),
				check_my_switch_en(protect_policy_global.account.user_change.group.enable),
				check_my_switch_en(protect_policy_global.account.user_change.user.enable));
		protect_count++;
	}

	if (protect_policy_global.sensitive_info.log_delete.enable == TURN_MY_ON ||
	    protect_policy_global.sensitive_info.file_safe.enable == TURN_MY_ON ||
	    protect_policy_global.sensitive_info.file_usb.enable == TURN_MY_ON ||
	    protect_policy_global.sensitive_info.middleware.enable == TURN_MY_ON ||
	    protect_policy_global.sensitive_info.illegal_script.enable == TURN_MY_ON) {
		fprintf(fp, "--敏感信息防护--\n");
		fprintf(fp_en, "--sensitive information protection--\n");
	}
/*
	fprintf(fp, "敏感文件:%s----阻断:%s\n",
			check_my_switch(protect_policy_global.sensitive_info.sensitive_file.enable),
			check_my_switch(protect_policy_global.sensitive_info.sensitive_file.terminate));

	fprintf(fp, " 文件列表:");
	num = protect_policy_global.sensitive_info.sensitive_file.list_num;
	if (num <= 0) {
		fprintf(fp, "(无)\n");
	}
	for (i = 0; i < num; i++) {
		fprintf(fp, "%s;", protect_policy_global.sensitive_info.sensitive_file.list[i].list);
	}
	fprintf(fp, "\n");
*/

	enable = protect_policy_global.sensitive_info.log_delete.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]日志异常删除:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]log abnormal deletion:open\n", protect_count+1);
#if 0 //不显示检测规则
		num = protect_policy_global.sensitive_info.log_delete.list_num;
		if (num > 0) {
			fprintf(fp, "文件列表:");
		}
		for (i = 0; i < num; i++) {
			fprintf(fp, "%s;", protect_policy_global.sensitive_info.log_delete.list[i].list);
		}
		if (num > 0) {
			fprintf(fp, "\n");
		}
#endif
		protect_count++;
	}

	enable = protect_policy_global.sensitive_info.file_safe.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]文件防篡改:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]File tamper proof:open\n", protect_count+1);
#if 0 //不显示检测规则
		num = protect_policy_global.sensitive_info.file_safe.list_num;
		if (num > 0) {
			fprintf(fp, "文件列表:");
		}
		for (i = 0; i < num; i++) {
			path = protect_policy_global.sensitive_info.file_safe.list[i].path;
			real_path = protect_policy_global.sensitive_info.file_safe.list[i].real_path;

			if (protect_policy_global.sensitive_info.file_safe.list[i].real_path) {
				fprintf(fp, "  文件路径:%s(->%s)\n", path, real_path);
			} else {
				fprintf(fp, "  文件路径:%s\n", path);
			}

			fprintf(fp, "  文件:%s\n", protect_policy_global.sensitive_info.file_safe.list[i].name);
			fprintf(fp, "  授权进程:%s\n", protect_policy_global.sensitive_info.file_safe.list[i].process);
			fprintf(fp, "  检测动作:%s\n", protect_policy_global.sensitive_info.file_safe.list[i].operation);

			fprintf(fp, "  状态:%d\n", protect_policy_global.sensitive_info.file_safe.list[i].status);
		}
#endif
		protect_count++;
	}

	enable = protect_policy_global.sensitive_info.file_usb.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]USB文件监控:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]USB file monitoring:open\n", protect_count+1);
		if (protect_policy_global.sensitive_info.file_usb.extension != NULL) {
			fprintf(fp, "    USB监控文件类型:%s\n", protect_policy_global.sensitive_info.file_usb.extension);
			fprintf(fp_en, "    USB monitor file type:%s\n", protect_policy_global.sensitive_info.file_usb.extension);
		}

		protect_count++;
	}

	enable = protect_policy_global.sensitive_info.middleware.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]中间件识别:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]middleware identification:open\n", protect_count+1);
#if 0 //不显示检测规则
		fprintf(fp, "  中间件进程:");
		fprintf(fp, "%s\n", protect_policy_global.sensitive_info.middleware.target);
#endif

		enable = protect_policy_global.sensitive_info.middleware.executable_files.enable;
		if (enable == TURN_MY_ON) {
			fprintf(fp, "  可执行文件识别:%s----阻断:%s\n",
				check_my_switch(protect_policy_global.sensitive_info.middleware.executable_files.enable),
				check_my_switch(protect_policy_global.sensitive_info.middleware.executable_files.terminate));
			fprintf(fp_en, "  executable file identification:%s----terminate:%s\n",
				check_my_switch_en(protect_policy_global.sensitive_info.middleware.executable_files.enable),
				check_my_switch_en(protect_policy_global.sensitive_info.middleware.executable_files.terminate));
#if 0 //不显示检测规则
			enable = protect_policy_global.sensitive_info.middleware.executable_files.exclude;
			if (enable == TURN_MY_ON) {
				fprintf(fp, "过滤文件类型:%s\n", protect_policy_global.sensitive_info.middleware.executable_files.ext);
			}
#endif
		}

		enable = protect_policy_global.sensitive_info.middleware.script_files.enable;
		if (enable == TURN_MY_ON) {
			fprintf(fp, "  脚本文件识别:%s----阻断:%s\n",
				check_my_switch(protect_policy_global.sensitive_info.middleware.script_files.enable),
				check_my_switch(protect_policy_global.sensitive_info.middleware.script_files.terminate));
			fprintf(fp_en, "  script file identification:%s----terminate:%s\n",
				check_my_switch_en(protect_policy_global.sensitive_info.middleware.script_files.enable),
				check_my_switch_en(protect_policy_global.sensitive_info.middleware.script_files.terminate));
#if 0 //不显示检测规则
			enable = protect_policy_global.sensitive_info.middleware.script_files.enable;
			if (enable == TURN_MY_ON) {
				fprintf(fp, "过滤文件类型:%s\n", protect_policy_global.sensitive_info.middleware.script_files.ext);
			}
#endif
		}

		protect_count++;
	}

	enable = protect_policy_global.sensitive_info.backdoor.enable;
	if (enable == TURN_MY_ON &&
	   (protect_policy_global.sensitive_info.illegal_script.enable == TURN_MY_ON ||
	    protect_policy_global.sensitive_info.webshell_detect.enable == TURN_MY_ON)) {
		fprintf(fp, "[%d]后门检测:%s\n",
				protect_count+1,
				check_my_switch(protect_policy_global.sensitive_info.backdoor.enable));
		fprintf(fp_en, "[%d]Backdoor detection:%s\n",
				protect_count+1,
				check_my_switch_en(protect_policy_global.sensitive_info.backdoor.enable));

		protect_count++;
	}
	enable = protect_policy_global.sensitive_info.illegal_script.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "  非法脚本识别:%s----阻断:%s\n",
				check_my_switch(protect_policy_global.sensitive_info.illegal_script.enable),
				check_my_switch(protect_policy_global.sensitive_info.illegal_script.terminate));
		fprintf(fp_en, "  illegal script identification:%s----terminate:%s\n",
				check_my_switch_en(protect_policy_global.sensitive_info.illegal_script.enable),
				check_my_switch_en(protect_policy_global.sensitive_info.illegal_script.terminate));

#if 0 //不显示检测规则
		num = protect_policy_global.sensitive_info.illegal_script.target_num;
		for (i = 0; i < num; i++) {
			path = protect_policy_global.sensitive_info.illegal_script.target[i].path;
			real_path = protect_policy_global.sensitive_info.illegal_script.target[i].real_path;
			if (real_path) {
				fprintf(fp, "    文件路径: %s(->%s)\n", path, real_path);
			} else {
				fprintf(fp, "    文件路径: %s\n", path);
			}
			fprintf(fp, "      文件类型: %s\n", protect_policy_global.sensitive_info.illegal_script.target[i].extension);
		}

#if 0 //仅内部调试临时用，用完即关闭，发布时不显示系统审查库内容
		num = protect_policy_global.sensitive_info.illegal_script.default_keyword_num;
		if (num > 0) {
			fprintf(fp, "    系统审查库:");
		}
		for (i = 0; i < num; i++) {
			fprintf(fp, "%s;", protect_policy_global.sensitive_info.illegal_script.default_keyword[i].list);
		}
		if (num > 0) {
			fprintf(fp, "\n");
		}
#endif

		num = protect_policy_global.sensitive_info.illegal_script.keyword_num;
		if (num > 0) {
			fprintf(fp, "    关键字:");
		}
		for (i = 0; i < num; i++) {
			fprintf(fp, "%s;", protect_policy_global.sensitive_info.illegal_script.keyword[i].list);
		}
		if (num > 0) {
			fprintf(fp, "\n");
		}
#endif
	}

	enable = protect_policy_global.sensitive_info.webshell_detect.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "  webshell文件检测:%s----阻断:%s,检测模式:%s\n",
				check_my_switch(protect_policy_global.sensitive_info.webshell_detect.enable),
				check_my_switch(protect_policy_global.sensitive_info.webshell_detect.terminate),
				check_webshell_mode(protect_policy_global.sensitive_info.webshell_detect.detect_mode));
		fprintf(fp_en, "  webshell file detection:%s----terminate:%s,detect mode:%s\n",
				check_my_switch_en(protect_policy_global.sensitive_info.webshell_detect.enable),
				check_my_switch_en(protect_policy_global.sensitive_info.webshell_detect.terminate),
				check_webshell_mode_en(protect_policy_global.sensitive_info.webshell_detect.detect_mode));
#if 0 //不显示检测规则
		num = protect_policy_global.sensitive_info.webshell_detect.target_num;
		if (num > 0) {
			fprintf(fp, "    监控路径:");
		}
		for (i = 0; i < num; i++) {
			path = protect_policy_global.sensitive_info.webshell_detect.target[i].path;
			real_path = protect_policy_global.sensitive_info.webshell_detect.target[i].real_path;
			if (real_path) {
				fprintf(fp, "    文件路径: %s(->%s)\n", path, real_path);
			} else {
				fprintf(fp, "    文件路径: %s\n", path);
			}

			fprintf(fp, "      文件类型: %s\n", protect_policy_global.sensitive_info.webshell_detect.target[i].extension);
		}
#endif
	}

	if (protect_policy_global.logcollector.process_enable == TURN_MY_ON ||
	    protect_policy_global.logcollector.file_enable == TURN_MY_ON ||
	    protect_policy_global.logcollector.network_enable == TURN_MY_ON ||
	    protect_policy_global.logcollector.dnsquery_enable == TURN_MY_ON) { 
		fprintf(fp, "--日志采集--\n");
		fprintf(fp_en, "--log collection--\n");
	}

	enable = protect_policy_global.logcollector.process_enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]进程行为采集:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]process behavior collection:open\n", protect_count+1);
		protect_count++;
	}

	enable = protect_policy_global.logcollector.file_enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]文件行为采集:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]file behavior collection:open\n", protect_count+1);
#if 0 //不显示检测规则
		num = protect_policy_global.logcollector.file_list_num;
        	for (i = 0; i < num; i++) {
			path = protect_policy_global.logcollector.file_list[i].filepath;
			real_path = protect_policy_global.logcollector.file_list[i].real_path;
			if (real_path) {
				fprintf(fp, "  文件路径: %s(->%s)\n", path, real_path);
			} else {
				fprintf(fp, "  文件路径: %s\n", path);
			}
			fprintf(fp, "    文件类型: %s\n", protect_policy_global.logcollector.file_list[i].extension);
		}
#endif

		protect_count++;
	}

	enable = protect_policy_global.logcollector.network_enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]网络行为采集:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]network behavior collection:open\n", protect_count+1);
		protect_count++;
	}
	enable = protect_policy_global.logcollector.dnsquery_enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]域名查询行为采集:开启\n", protect_count+1);
		fprintf(fp_en, "[%d]dns query behavior collection:open\n", protect_count+1);
		protect_count++;
	}
}

static void dump_policy_fasten(FILE *fp, FILE *fp_en)
{       
	int num = 0, i = 0;
	int enable = 0;
	fprintf(fp, "[资源监控]\n");
	fprintf(fp_en, "[resource monitoring]\n");

	if (fasten_policy_global.resource.sys.enable == TURN_MY_ON) {
		fprintf(fp, "--系统负载监控--\n");
		fprintf(fp_en, "--system load monitoring--\n");
	}
	if (fasten_policy_global.resource.sys.enable == TURN_MY_ON ||
	    fasten_policy_global.resource.sys.memory.enable == TURN_MY_ON ||
	    fasten_policy_global.resource.sys.disk.enable == TURN_MY_ON ||
	    fasten_policy_global.resource.sys.netflow.enable == TURN_MY_ON) {
		fprintf(fp, "[%d]系统负载监控:%s\n",
				fasten_count+1,
				check_my_switch(fasten_policy_global.resource.sys.enable));
		fprintf(fp_en, "[%d]system load monitoring:%s\n",
				fasten_count+1,
				check_my_switch_en(fasten_policy_global.resource.sys.enable));
		fasten_count++; 
	}

	enable = fasten_policy_global.resource.sys.cpu.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "CPU监控:%s\n", 
				check_my_switch(fasten_policy_global.resource.sys.cpu.enable));
		fprintf(fp_en, "CPU monitoring:%s\n", 
				check_my_switch_en(fasten_policy_global.resource.sys.cpu.enable));
		fprintf(fp, "  在[%d]分钟内,CPU持续使用超过[%d]%%报警\n",
				fasten_policy_global.resource.sys.cpu.interval,
				fasten_policy_global.resource.sys.cpu.limit);
		fprintf(fp_en, "  in [%d] minutes, the CPU continued to use more than [%d]%% alarm\n",
				fasten_policy_global.resource.sys.cpu.interval,
				fasten_policy_global.resource.sys.cpu.limit);

	}

	enable = fasten_policy_global.resource.sys.memory.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "内存监控:%s\n",
				check_my_switch(fasten_policy_global.resource.sys.memory.enable));
		fprintf(fp_en, "memory monitoring :%s\n",
				check_my_switch_en(fasten_policy_global.resource.sys.memory.enable));
		fprintf(fp, "  在[%d]分钟内,内存占用持续超过[%d]%%报警\n",
				fasten_policy_global.resource.sys.memory.interval,
				fasten_policy_global.resource.sys.memory.limit);
		fprintf(fp_en, "  In [%d] minutes, the memory usage continues to exceed [%d]%% alarm\n",
				fasten_policy_global.resource.sys.memory.interval,
				fasten_policy_global.resource.sys.memory.limit);
	}

	enable = fasten_policy_global.resource.sys.disk.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "磁盘使用监控:%s\n", 
				check_my_switch(fasten_policy_global.resource.sys.disk.enable));
		fprintf(fp_en, "disk usage monitoring:%s\n", 
				check_my_switch_en(fasten_policy_global.resource.sys.disk.enable));
		fprintf(fp, "  监控频率[%d]小时,单个磁盘使用率超过[%d]%%报警\n",
				fasten_policy_global.resource.sys.disk.interval,
				fasten_policy_global.resource.sys.disk.limit);
		fprintf(fp_en, "  monitoring frequency [%d] hours, single disk usage exceeds [%d]%% alarm\n",
				fasten_policy_global.resource.sys.disk.interval,
				fasten_policy_global.resource.sys.disk.limit);
	}

	enable = fasten_policy_global.resource.sys.netflow.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "网络流量监控:%s\n",
				check_my_switch(fasten_policy_global.resource.sys.netflow.enable));
		fprintf(fp_en, "network traffic monitoring:%s\n",
				check_my_switch_en(fasten_policy_global.resource.sys.netflow.enable));
		fprintf(fp, "  在[%d]分钟内,出网流量持续超过[%d]MB/S或入网流量持续超过[%d]MB/S报警\n",
				fasten_policy_global.resource.sys.netflow.interval,
				fasten_policy_global.resource.sys.netflow.up,
				fasten_policy_global.resource.sys.netflow.down);
		fprintf(fp_en, "  in [%d] minutes, the outgoing network traffic continuously exceeds [%d]MB/S or the incoming network traffic continuously exceeds [%d]MB/S alarm\n",
				fasten_policy_global.resource.sys.netflow.interval,
				fasten_policy_global.resource.sys.netflow.up,
				fasten_policy_global.resource.sys.netflow.down);
	}

	if (fasten_policy_global.resource.process.enable == TURN_MY_ON) {
		fprintf(fp, "--进程负载监控--\n");
		fprintf(fp_en, "--process load monitoring--\n");
	}

	if (fasten_policy_global.resource.process.enable == TURN_MY_ON ||
		fasten_policy_global.resource.process.memory.enable == TURN_MY_ON) {
		fprintf(fp, "[%d]进程负载监控:%s\n",
				fasten_count+1,
				check_my_switch(fasten_policy_global.resource.process.enable));
		fprintf(fp_en, "[%d]process load monitoring:%s\n",
				fasten_count+1,
				check_my_switch_en(fasten_policy_global.resource.process.enable));
		fasten_count++; 
	}

	enable = fasten_policy_global.resource.process.cpu.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "CPU监控:%s\n", check_my_switch(fasten_policy_global.resource.process.cpu.enable));
		fprintf(fp_en, "CPU monitoring:%s\n", check_my_switch_en(fasten_policy_global.resource.process.cpu.enable));
		fprintf(fp, "  在[%d]分钟内,单一进程CPU持续使用超过[%d]%%报警\n",
				fasten_policy_global.resource.process.cpu.interval,
				fasten_policy_global.resource.process.cpu.limit);
		fprintf(fp_en, "  in [%d] minutes, the CPU usage of a single process exceeds [%d]%% continuously\n",
				fasten_policy_global.resource.process.cpu.interval,
				fasten_policy_global.resource.process.cpu.limit);
	}

	enable = fasten_policy_global.resource.process.memory.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "内存监控:%s\n",
				check_my_switch(fasten_policy_global.resource.process.memory.enable));
		fprintf(fp_en, "memory monitoring:%s\n",
				check_my_switch_en(fasten_policy_global.resource.process.memory.enable));
		fprintf(fp, "  在[%d]分钟内,单一进程内存占用持续超过[%d]%%报警\n",
				fasten_policy_global.resource.process.memory.interval,
				fasten_policy_global.resource.process.memory.limit);
		fprintf(fp_en, "  in [%d] minutes, the memory usage of a single process continues to exceed [%d]%% alarm\n",
				fasten_policy_global.resource.process.memory.interval,
				fasten_policy_global.resource.process.memory.limit);
	}

	fprintf(fp, "[外设管理]\n");
	fprintf(fp_en, "[I/O management]\n");
	if (fasten_policy_global.device.usb.enable == TURN_MY_ON ||
	    fasten_policy_global.device.printer.enable == TURN_MY_ON ||
	    fasten_policy_global.device.cdrom.enable == TURN_MY_ON) {
		fprintf(fp, "--外设管理--\n");
		fprintf(fp_en, "--I/O management--\n");
	}

	enable = fasten_policy_global.device.usb.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]USB存储接入:%s----%s\n",
				fasten_count+1,
				check_my_switch(fasten_policy_global.device.usb.enable),
				check_my_switch_permit(fasten_policy_global.device.usb.terminate));
		fprintf(fp_en, "[%d]USB storage access:%s----%s\n",
				fasten_count+1,
				check_my_switch_en(fasten_policy_global.device.usb.enable),
				check_my_switch_permit_en(fasten_policy_global.device.usb.terminate));
		num = fasten_policy_global.device.usb.exclude_num;
		if (num > 0) {
			fprintf(fp, "  例外USB:");
			fprintf(fp_en, "  exception usb:");
		}
		for (i = 0; i < num; i++) {
			fprintf(fp, "%s;", fasten_policy_global.device.usb.exclude[i].list);
			fprintf(fp_en, "%s;", fasten_policy_global.device.usb.exclude[i].list);
		}
		if (num > 0) {
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
		fasten_count++; 
	}

	enable = fasten_policy_global.device.printer.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]打印机监控:%s----%s\n",
				fasten_count+1,
				check_my_switch(fasten_policy_global.device.printer.enable),
				check_my_switch_permit(fasten_policy_global.device.printer.terminate));
		fprintf(fp_en, "[%d]printer monitoring:%s----%s\n",
				fasten_count+1,
				check_my_switch_en(fasten_policy_global.device.printer.enable),
				check_my_switch_permit_en(fasten_policy_global.device.printer.terminate));
		num = fasten_policy_global.device.printer.ext_num;
		if (num > 0) {
			fprintf(fp, "  监控打印类型:");
			fprintf(fp_en, "  monitor print types:");
		}
		for (i = 0; i < num; i++) {
			fprintf(fp, "%s;", fasten_policy_global.device.printer.ext[i].list);
			fprintf(fp_en, "%s;", fasten_policy_global.device.printer.ext[i].list);
		}
		if (num > 0) {
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
		fasten_count++; 
	}

	enable = fasten_policy_global.device.cdrom.enable;
	if (enable == TURN_MY_ON) {
		fprintf(fp, "[%d]刻录机监控:%s----%s\n",
				fasten_count+1,
				check_my_switch(fasten_policy_global.device.cdrom.enable),
				check_my_switch_permit(fasten_policy_global.device.cdrom.terminate));
		fprintf(fp_en, "[%d]burner monitoring:%s----%s\n",
				fasten_count+1,
				check_my_switch_en(fasten_policy_global.device.cdrom.enable),
				check_my_switch_permit_en(fasten_policy_global.device.cdrom.terminate));
		num = fasten_policy_global.device.cdrom.ext_num;
		if (num > 0) {
			fprintf(fp, "  监控刻录类型:");
			fprintf(fp_en, "  monitor burn type:");
		}
		for (i = 0; i < num; i++) {
			fprintf(fp, "%s;", fasten_policy_global.device.cdrom.ext[i].list);
			fprintf(fp_en, "%s;", fasten_policy_global.device.cdrom.ext[i].list);
		}
		if (num > 0) {
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
		fasten_count++; 
	}

	if (fasten_policy_global.device.usb.enable == TURN_MY_ON ||
	    fasten_policy_global.device.printer.enable == TURN_MY_ON ||
	    fasten_policy_global.device.cdrom.enable == TURN_MY_ON) {
		num = fasten_policy_global.device.exclude_num;
		if (num > 0) {
			fprintf(fp, "  例外主机:");
			fprintf(fp_en, "  exception host:");
		}
		for (i = 0; i < num; i++) {
			fprintf(fp, "主机UUID:%s;", fasten_policy_global.device.exclude_uuid[i].list);
			fprintf(fp_en, "host UUID:%s;", fasten_policy_global.device.exclude_uuid[i].list);
		}
		if (num > 0) {
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

}

static void dump_policy_antivirus(FILE *fp, FILE *fp_en)
{       
	fprintf(fp, "[病毒防护]\n");
	fprintf(fp_en, "[virus protection]\n");

#ifdef USE_AVIRA
	if (antivirus_policy_global.real_time_check.enable == TURN_MY_ON ||
		antivirus_policy_global.scanning_kill.enable == TURN_MY_ON) {
		fprintf(fp, "病毒检测\n");
		fprintf(fp_en, "virus detection\n");
	}

	if (antivirus_policy_global.real_time_check.enable == TURN_MY_ON) {
		fprintf(fp, "[%d]实时检测:%s\n", antivirus_count+1,
				check_my_switch_yes(antivirus_policy_global.real_time_check.enable));
		fprintf(fp_en, "[%d]real-time detection:%s\n", antivirus_count+1,
				check_my_switch_yes_en(antivirus_policy_global.real_time_check.enable));
		antivirus_count++;
	}

	if (antivirus_policy_global.scanning_kill.enable == TURN_MY_ON) {
		fprintf(fp, "[%d]扫描查杀:%s\n", antivirus_count+1,
				check_my_switch_yes(antivirus_policy_global.scanning_kill.enable));
		fprintf(fp_en, "[%d]scan and kill :%s\n", antivirus_count+1, 
				check_my_switch_yes_en(antivirus_policy_global.scanning_kill.enable));
		fprintf(fp, "  定时扫描:%s\n",
				check_my_switch_yes(antivirus_policy_global.scanning_kill.cron.enable));
		fprintf(fp_en, "  Timed scan:%s\n",
				check_my_switch_yes_en(antivirus_policy_global.scanning_kill.cron.enable));
		fprintf(fp, "  扫描方式:%s\n",
				check_antivirus_scan_type(antivirus_policy_global.scanning_kill.cron.scanning_way));
		fprintf(fp_en, "  scan type:%s\n",
				check_antivirus_scan_type_en(antivirus_policy_global.scanning_kill.cron.scanning_way));
		fprintf(fp, "  扫描周期:%s\n",antivirus_policy_global.scanning_kill.cron.time_type);
		fprintf(fp_en, "  scan cycle:%s\n",antivirus_policy_global.scanning_kill.cron.time_type);
		fprintf(fp, "  选择时间: day(%d) time(%s)\n",
				antivirus_policy_global.scanning_kill.cron.day,
				antivirus_policy_global.scanning_kill.cron.time);
		fprintf(fp_en, "  selection period: day(%d) time(%s)\n",
				antivirus_policy_global.scanning_kill.cron.day,
				antivirus_policy_global.scanning_kill.cron.time);
		antivirus_count++;
	}

	if (antivirus_policy_global.real_time_check.enable == TURN_MY_ON ||
		antivirus_policy_global.scanning_kill.enable == TURN_MY_ON) {
		fprintf(fp, "病毒查杀配置\n");
		fprintf(fp_en, "virus scanning configuration\n");
		fprintf(fp, "  处理方式:%s\n",
				check_antivirus_process_type(antivirus_policy_global.automate));
		fprintf(fp_en, "  process type:%s\n",
				check_antivirus_process_type_en(antivirus_policy_global.automate));
		fprintf(fp, "  隔离区设置：隔离区所在磁盘保留空间[%d]GB\n",
				antivirus_policy_global.reserved_space);
		fprintf(fp_en, "  quarantine settings: Quarantine disk reserved space [%d]GB\n",
				antivirus_policy_global.reserved_space);
		fprintf(fp, "  例外设置：忽略大于[%d]MB文件\n",
				antivirus_policy_global.neglect_size);
		fprintf(fp_en, "  exception setting: ignore files larger than [%d]MB\n",
				antivirus_policy_global.neglect_size);
	}
#else
	fprintf(fp, "本系统不支持病毒防护功能\n");
	fprintf(fp_en, "This system does not support virus protection function\n");
#endif
}

static void dump_policy_other(FILE *fp, FILE *fp_en)
{       
	fprintf(fp, "[其他配置]\n");
	fprintf(fp_en, "[other configuration]\n");

	fprintf(fp, "[%d]是否允许卸载客户端:%s\n",
			other_count+1,
			check_my_switch_yes(other_policy_global.allow_uninstall.enable));
	fprintf(fp_en, "[%d]allow uninstall of the client:%s\n",
			other_count+1,
			check_my_switch_yes_en(other_policy_global.allow_uninstall.enable));
	other_count++; 

	fprintf(fp, "[%d]是否显示客户端托盘:%s\n",
			other_count+1,
			check_my_switch_yes(other_policy_global.allow_ui_tray.enable));
	fprintf(fp_en, "[%d]show the client tray:%s\n",
			other_count+1,
			check_my_switch_yes_en(other_policy_global.allow_ui_tray.enable));
	other_count++; 
}

static void dump_policy_selfinfo(FILE *fp, FILE *fp_en)
{       
	fprintf(fp, "策略信息\n");
	fprintf(fp_en, "policy information\n");

	fprintf(fp, "策略id:%s\n", policy_id_cur);
	fprintf(fp_en, "policy id:%s\n", policy_id_cur);
	fprintf(fp, "策略名称:%s\n", policy_name_cur);
	fprintf(fp_en, "policy name:%s\n", policy_name_cur);
	fprintf(fp, "策略时间:%s\n", policy_time_cur);
	fprintf(fp_en, "policy time:%s\n", policy_time_cur);
}

static void protect_policy_to_file(void)
{
	FILE *fp = NULL;
	FILE *fp_en = NULL;

	fp = sniper_fopen(POLICY_PROTECT_FILE, "w+", POLICY_GET);
	if(fp == NULL) {
		MON_ERROR("Update protect lst to file failed\n");
		return;
	}

	fp_en = sniper_fopen(POLICY_PROTECT_FILE_EN, "w+", POLICY_GET);
	if(fp_en == NULL) {
		MON_ERROR("Update protect lst to file_en failed\n");
		sniper_fclose(fp, POLICY_GET);
		return;
	}

	dump_policy_protect(fp, fp_en);
	fprintf(fp, "防护策略共监控[%d]项策略\n", protect_count);
	fprintf(fp_en, "The protection strategy monitors a total of [%d] strategies\n", protect_count);

	sniper_fclose(fp, POLICY_GET);
	sniper_fclose(fp_en, POLICY_GET);
}

static void fasten_policy_to_file(void)
{
	FILE *fp = NULL;
	FILE *fp_en = NULL;

	fp = sniper_fopen(POLICY_FASTEN_FILE, "w+", POLICY_GET);
	if(fp == NULL) {
		MON_ERROR("Update fasten lst to file failed\n");
		return;
	}

	fp_en = sniper_fopen(POLICY_FASTEN_FILE_EN, "w+", POLICY_GET);
	if(fp_en == NULL) {
		MON_ERROR("Update fasten lst to file_en failed\n");
		sniper_fclose(fp, POLICY_GET);
		return;
	}

	dump_policy_fasten(fp, fp_en);
	fprintf(fp, "外设/资源监控策略共监控[%d]项策略\n", fasten_count);
	fprintf(fp_en, "I/O and resource monitors a total of [%d] strategies\n", fasten_count);

	sniper_fclose(fp, POLICY_GET);
	sniper_fclose(fp_en, POLICY_GET);
}

static void antivirus_policy_to_file(void)
{
	FILE *fp = NULL;
	FILE *fp_en = NULL;

	fp = sniper_fopen(POLICY_ANTIVIRUS_FILE, "w+", POLICY_GET);
	if(fp == NULL) {
		MON_ERROR("Update antivirus lst to file failed\n");
		return;
	}

	fp_en = sniper_fopen(POLICY_ANTIVIRUS_FILE_EN, "w+", POLICY_GET);
	if(fp_en == NULL) {
		MON_ERROR("Update antivirus lst to file_en failed\n");
		sniper_fclose(fp, POLICY_GET);
		return;
	}

	dump_policy_antivirus(fp, fp_en);
	fprintf(fp, "病毒防护策略共监控[%d]项策略\n", antivirus_count);
	fprintf(fp_en, "virus protection monitors a total of [%d] strategies\n", antivirus_count);

	sniper_fclose(fp, POLICY_GET);
	sniper_fclose(fp_en, POLICY_GET);
}

static void other_policy_to_file(void)
{
	FILE *fp = NULL;
	FILE *fp_en = NULL;

	fp = sniper_fopen(POLICY_OTHER_FILE, "w+", POLICY_GET);
	if(fp == NULL) {
		MON_ERROR("Update other lst to file failed\n");
		return;
	}

	fp_en = sniper_fopen(POLICY_OTHER_FILE_EN, "w+", POLICY_GET);
	if(fp_en == NULL) {
		MON_ERROR("Update other lst to file_en failed\n");
		sniper_fclose(fp, POLICY_GET);
		return;
	}

	dump_policy_other(fp, fp_en);
	fprintf(fp, "其他策略共监控[%d]项策略\n", other_count);
	fprintf(fp_en, "other policy monitors a total of [%d] strategies\n", other_count);

	sniper_fclose(fp, POLICY_GET);
	sniper_fclose(fp_en, POLICY_GET);
}

static void selfinfo_policy_to_file(void)
{
	FILE *fp = NULL;
	FILE *fp_en = NULL;

	fp = sniper_fopen(POLICY_SELFINFO_FILE, "w+", POLICY_GET);
	if(fp == NULL) {
		MON_ERROR("Update selfinfo lst to file failed\n");
		return;
	}

	fp_en = sniper_fopen(POLICY_SELFINFO_FILE_EN, "w+", POLICY_GET);
	if(fp_en == NULL) {
		MON_ERROR("Update selfinfo lst to file_en failed\n");
		sniper_fclose(fp, POLICY_GET);
		return;
	}

	dump_policy_selfinfo(fp, fp_en);

	sniper_fclose(fp, POLICY_GET);
	sniper_fclose(fp_en, POLICY_GET);
}

void record_policy_to_file(void)
{
	protect_count = 0;
	fasten_count = 0;
	antivirus_count = 0;
	other_count = 0;

	protect_policy_to_file();
	fasten_policy_to_file();
	antivirus_policy_to_file();
	other_policy_to_file();
	selfinfo_policy_to_file();
}

void revise_device_exclude_uuid(void)
{
	int i = 0;
	int num = 0;
	int is_match = 0;

	num = fasten_policy_global.device.exclude_num;
	for (i = 0; i < num; i++) {
		if(strcmp(fasten_policy_global.device.exclude_uuid[i].list, Sys_info.sku) == 0) {
			is_match = 1;
			break;
		}
	}

	if (is_match == 1) {
		/* 如果选择的是允许，那么对于非例外主机来说就是只允许使用配置的usb，对于例外主机来说都不允许使用  */
		if (fasten_policy_global.device.usb.terminate == TURN_MY_ON) {
			fasten_policy_global.device.usb.terminate = TURN_MY_OFF;
		} else {
			fasten_policy_global.device.usb.terminate = TURN_MY_ON;
		}
		/* 匹配上例外主机时都不再看例外的usb, 数量清0 */
		num = fasten_policy_global.device.usb.exclude_num;
		for (i = 0; i < num; i++) {
			free_valuestring(fasten_policy_global.device.usb.exclude[i].list);
		}
		sniper_free(fasten_policy_global.device.usb.exclude, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		fasten_policy_global.device.usb.exclude_num = 0;

		if (fasten_policy_global.device.usb.terminate == TURN_MY_OFF) {
			num = fasten_policy_global.device.usb.exclude_num;
			for (i = 0; i < num; i++) {
				free_valuestring(fasten_policy_global.device.usb.exclude[i].list);
			}
			sniper_free(fasten_policy_global.device.usb.exclude, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			fasten_policy_global.device.usb.exclude_num = 0;
		}

		if (fasten_policy_global.device.printer.terminate == TURN_MY_ON) {
			fasten_policy_global.device.printer.terminate = TURN_MY_OFF;
		}

		if (fasten_policy_global.device.cdrom.terminate == TURN_MY_ON) {
			fasten_policy_global.device.cdrom.terminate = TURN_MY_OFF;
		}
	}

	return;
}

static void revise_behaviour(void)
{
	if (protect_policy_global.behaviour.pool.enable == TURN_MY_OFF) {
		protect_policy_global.behaviour.pool.terminate = TURN_MY_OFF;
		protect_policy_global.behaviour.pool.locking = TURN_MY_OFF;
		protect_policy_global.behaviour.pool.locking_time = 0;
	}

	if (protect_policy_global.behaviour.ransomware.track.enable == TURN_MY_OFF) {
		protect_policy_global.behaviour.ransomware.track.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.behaviour.ransomware.encrypt.enable == TURN_MY_OFF) {
		protect_policy_global.behaviour.ransomware.encrypt.terminate = TURN_MY_OFF;
		protect_policy_global.behaviour.ransomware.encrypt.hide = TURN_MY_OFF;
		protect_policy_global.behaviour.ransomware.encrypt.backup.enable = TURN_MY_OFF;
	}

	/* linux 诱捕文件强制隐藏 */
	protect_policy_global.behaviour.ransomware.encrypt.hide = TURN_MY_ON;

	if (protect_policy_global.behaviour.ransomware.encrypt.backup.enable == TURN_MY_OFF) {
		protect_policy_global.behaviour.ransomware.encrypt.backup.neglect_min = 0;
		protect_policy_global.behaviour.ransomware.encrypt.backup.neglect_size = 0;
		protect_policy_global.behaviour.ransomware.encrypt.backup.backup_size = 0;
	}
}

static void revise_process(void)
{
	if (protect_policy_global.process.reverse_shell.enable == TURN_MY_OFF) {
		protect_policy_global.process.reverse_shell.terminate = TURN_MY_OFF;
		protect_policy_global.process.reverse_shell.locking = TURN_MY_OFF;
		protect_policy_global.process.reverse_shell.locking_time = 0;
	}

	if (protect_policy_global.process.privilege.enable == TURN_MY_OFF) {
		protect_policy_global.process.privilege.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.mbr.enable == TURN_MY_OFF) {
		protect_policy_global.process.mbr.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.dangerous_command.enable == TURN_MY_OFF) {
		protect_policy_global.process.dangerous_command.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.webshell.enable == TURN_MY_OFF) {
		protect_policy_global.process.webshell.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.service_process.enable == TURN_MY_OFF) {
		protect_policy_global.process.service_process.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.fake_sys_process.enable == TURN_MY_OFF) {
		protect_policy_global.process.fake_sys_process.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.tunnel.enable == TURN_MY_OFF) {
		protect_policy_global.process.tunnel.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.risk_command.enable == TURN_MY_OFF) {
		protect_policy_global.process.risk_command.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.process.abnormal_process.enable == TURN_MY_OFF) {
		protect_policy_global.process.abnormal_process.terminate = TURN_MY_OFF;
	}

}

static void revise_network(void)
{
	int num = 0, i = 0;

	if (protect_policy_global.network.domain.enable == TURN_MY_OFF) {
		protect_policy_global.network.domain.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.network.illegal_connect.enable == TURN_MY_OFF) {
		protect_policy_global.network.illegal_connect.terminate = TURN_MY_OFF;
		num = protect_policy_global.network.illegal_connect.addr_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.network.illegal_connect.address[i].list);
		}
		sniper_free(protect_policy_global.network.illegal_connect.address, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		protect_policy_global.network.illegal_connect.addr_num = 0;
		protect_policy_global.network.illegal_connect.interval = 0;
	}

	if (protect_policy_global.network.port.enable == TURN_MY_OFF) {
		protect_policy_global.network.port.terminate = TURN_MY_OFF;
		protect_policy_global.network.port.request_period = 0;
		protect_policy_global.network.port.count = 0;
		protect_policy_global.network.port.locking_time = 0;
		protect_policy_global.network.port.sensitive.enable = TURN_MY_OFF;
	}

	if (protect_policy_global.network.port.terminate == TURN_MY_OFF) {
		protect_policy_global.network.port.locking_time = 0;
	}

	if (protect_policy_global.network.sensitive_port.enable == TURN_MY_OFF) {
		protect_policy_global.network.sensitive_port.terminate = TURN_MY_OFF;
		protect_policy_global.network.sensitive_port.locking_time = 0;
		protect_policy_global.network.sensitive_port.list_num = 0;
	}

	if (protect_policy_global.network.sensitive_port.terminate == TURN_MY_OFF) {
		protect_policy_global.network.sensitive_port.locking_time = 0;
	}

	if (protect_policy_global.network.port.sensitive.enable == TURN_MY_OFF) {
		num = protect_policy_global.network.sensitive_port.list_num;
		sniper_free(protect_policy_global.network.port.sensitive.list, sizeof(struct _SENSITIVE_LIST)*num, POLICY_GET);
		protect_policy_global.network.port.sensitive.list_num = 0;
	}

	if (protect_policy_global.network.login.enable == TURN_MY_OFF) {
		protect_policy_global.network.login.local_enable = TURN_MY_OFF;
		protect_policy_global.network.login.remote_enable = TURN_MY_OFF;
	}

}

static void revise_account(void)
{
	int num = 0, i = 0;
	if (protect_policy_global.account.login.enable == TURN_MY_OFF) {
		protect_policy_global.account.login.local.enable = TURN_MY_OFF;
		protect_policy_global.account.login.remote.enable = TURN_MY_OFF;
		protect_policy_global.account.login.crack.enable = TURN_MY_OFF;
	}

	if (protect_policy_global.account.login.local.enable == TURN_MY_OFF) {
		protect_policy_global.account.login.local.terminate = TURN_MY_OFF;
		protect_policy_global.account.login.local.terminate_mode = LOGOUT_NEXT;
		protect_policy_global.account.login.local.time.enable = TURN_MY_OFF;
	}
	if (protect_policy_global.account.login.local.time.enable == TURN_MY_OFF) {
		num = protect_policy_global.account.login.local.time.list_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.account.login.local.time.list[i].start_time);
			free_valuestring(protect_policy_global.account.login.local.time.list[i].end_time);
		}
		sniper_free(protect_policy_global.account.login.local.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
		protect_policy_global.account.login.local.time.list_num = 0;
	}

	if (protect_policy_global.account.login.remote.enable == TURN_MY_OFF) {
		protect_policy_global.account.login.remote.terminate = TURN_MY_OFF;
		protect_policy_global.account.login.remote.terminate_mode = LOGOUT_NEXT;
		protect_policy_global.account.login.remote.time.enable = TURN_MY_OFF;
		protect_policy_global.account.login.remote.location.enable = TURN_MY_OFF;
	}
	if (protect_policy_global.account.login.remote.time.enable == TURN_MY_OFF) {
		num = protect_policy_global.account.login.remote.time.list_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.account.login.remote.time.list[i].start_time);
			free_valuestring(protect_policy_global.account.login.remote.time.list[i].end_time);
		}
		sniper_free(protect_policy_global.account.login.remote.time.list, sizeof(struct _TIME_LIST)*num, POLICY_GET);
		protect_policy_global.account.login.remote.time.list_num = 0;
	}
	if (protect_policy_global.account.login.remote.location.enable == TURN_MY_OFF) {
		num = protect_policy_global.account.login.remote.location.list_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.account.login.remote.location.list[i].city);
			free_valuestring(protect_policy_global.account.login.remote.location.list[i].province);
		}
		sniper_free(protect_policy_global.account.login.remote.location.list, sizeof(struct _LOCATION_LIST)*num, POLICY_GET);
		protect_policy_global.account.login.remote.location.list_num = 0;
	}

	if (protect_policy_global.account.user_change.enable == TURN_MY_OFF) {
		protect_policy_global.account.user_change.group.enable = TURN_MY_OFF;
		protect_policy_global.account.user_change.user.enable = TURN_MY_OFF;
	}

	if (protect_policy_global.account.login.crack.enable == TURN_MY_OFF) {
		protect_policy_global.account.login.crack.interval = 0;	
		protect_policy_global.account.login.crack.limit = 0;	
		protect_policy_global.account.login.crack.terminate = TURN_MY_OFF;	
	}

	if (protect_policy_global.account.login.crack.terminate == TURN_MY_OFF) {
		protect_policy_global.account.login.crack.locking_time = 0;
	}

}

static void revise_sensitive_info(void)
{
	int num = 0, i = 0;
	if (protect_policy_global.sensitive_info.sensitive_file.enable == TURN_MY_OFF) {
		protect_policy_global.sensitive_info.sensitive_file.terminate = TURN_MY_OFF;
		num = protect_policy_global.sensitive_info.sensitive_file.list_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.sensitive_info.sensitive_file.list[i].list);
		}
		sniper_free(protect_policy_global.sensitive_info.sensitive_file.list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		protect_policy_global.sensitive_info.sensitive_file.list_num = 0;
	}

	if (protect_policy_global.sensitive_info.log_delete.enable == TURN_MY_OFF) {
		num = protect_policy_global.sensitive_info.log_delete.list_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.sensitive_info.log_delete.list[i].list);
		}
		sniper_free(protect_policy_global.sensitive_info.log_delete.list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		protect_policy_global.sensitive_info.log_delete.list_num = 0;
	}

	if (protect_policy_global.sensitive_info.file_safe.enable == TURN_MY_OFF) {
		num = protect_policy_global.sensitive_info.file_safe.list_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.sensitive_info.file_safe.list[i].path);
			free_valuestring(protect_policy_global.sensitive_info.file_safe.list[i].real_path);
			free_valuestring(protect_policy_global.sensitive_info.file_safe.list[i].name);
			free_valuestring(protect_policy_global.sensitive_info.file_safe.list[i].process);
			free_valuestring(protect_policy_global.sensitive_info.file_safe.list[i].operation);
		}
		sniper_free(protect_policy_global.sensitive_info.file_safe.list, sizeof(struct _SAFE_FILE_LIST)*num, POLICY_GET);
		protect_policy_global.sensitive_info.file_safe.list_num = 0;
	}

	if (protect_policy_global.sensitive_info.middleware.enable == TURN_MY_OFF) {
		protect_policy_global.sensitive_info.middleware.script_files.enable = TURN_MY_OFF;
		protect_policy_global.sensitive_info.middleware.executable_files.enable = TURN_MY_OFF;
	}

	if (protect_policy_global.sensitive_info.middleware.script_files.enable == TURN_MY_OFF) {
		protect_policy_global.sensitive_info.middleware.script_files.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.sensitive_info.middleware.executable_files.enable == TURN_MY_OFF) {
		protect_policy_global.sensitive_info.middleware.executable_files.exclude = TURN_MY_OFF;
		protect_policy_global.sensitive_info.middleware.executable_files.terminate = TURN_MY_OFF;
	}

	if (protect_policy_global.sensitive_info.backdoor.enable == TURN_MY_OFF) {
		protect_policy_global.sensitive_info.illegal_script.enable = TURN_MY_OFF;
		protect_policy_global.sensitive_info.webshell_detect.enable = TURN_MY_OFF;
	}

	if (protect_policy_global.sensitive_info.illegal_script.enable == TURN_MY_OFF) {
		protect_policy_global.sensitive_info.illegal_script.terminate = TURN_MY_OFF;
		protect_policy_global.sensitive_info.illegal_script.use_default_keyword = TURN_MY_OFF;

		num = protect_policy_global.sensitive_info.illegal_script.target_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.sensitive_info.illegal_script.target[i].path);
			free_valuestring(protect_policy_global.sensitive_info.illegal_script.target[i].real_path);
			free_valuestring(protect_policy_global.sensitive_info.illegal_script.target[i].extension);
		}
		sniper_free(protect_policy_global.sensitive_info.illegal_script.target, sizeof(struct _ILLEGAL_SCRIPT_TARGET)*num, POLICY_GET);
		protect_policy_global.sensitive_info.illegal_script.target_num = 0;

		num = protect_policy_global.sensitive_info.illegal_script.keyword_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.sensitive_info.illegal_script.keyword[i].list);
		}
		sniper_free(protect_policy_global.sensitive_info.illegal_script.keyword, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		protect_policy_global.sensitive_info.illegal_script.keyword_num = 0;

		num = protect_policy_global.sensitive_info.illegal_script.default_keyword_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.sensitive_info.illegal_script.default_keyword[i].list);
		}
		sniper_free(protect_policy_global.sensitive_info.illegal_script.default_keyword, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		protect_policy_global.sensitive_info.illegal_script.default_keyword_num = 0;
	}

	if (protect_policy_global.sensitive_info.webshell_detect.enable == TURN_MY_OFF) {
		protect_policy_global.sensitive_info.webshell_detect.terminate = TURN_MY_OFF;
		protect_policy_global.sensitive_info.webshell_detect.use_default_rule = TURN_MY_OFF;
		num = protect_policy_global.sensitive_info.webshell_detect.target_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.sensitive_info.webshell_detect.target[i].path);
			free_valuestring(protect_policy_global.sensitive_info.webshell_detect.target[i].real_path);
			free_valuestring(protect_policy_global.sensitive_info.webshell_detect.target[i].extension);
		}
		sniper_free(protect_policy_global.sensitive_info.webshell_detect.target, sizeof(struct _WEBSHELL_DETECT_TARGET)*num, POLICY_GET);
		protect_policy_global.sensitive_info.webshell_detect.target_num = 0;
	}

}

static void revise_logcollector(void)
{
	int num = 0, i = 0;
	if (protect_policy_global.logcollector.file_enable == TURN_MY_OFF) {
		num = protect_policy_global.logcollector.file_list_num;
		for (i = 0; i < num; i++) {
			free_valuestring(protect_policy_global.logcollector.file_list[i].filepath);
			free_valuestring(protect_policy_global.logcollector.file_list[i].real_path);
			free_valuestring(protect_policy_global.logcollector.file_list[i].extension);
		}
		sniper_free(protect_policy_global.logcollector.file_list, sizeof(struct _LOGCOLLECTOR_FILE_LIST)*num, POLICY_GET);
		protect_policy_global.logcollector.file_list_num = 0;
	}
}

static void revise_protect(void)
{
	revise_behaviour();
	revise_process();
	revise_network();
	revise_account();
	revise_sensitive_info();
	revise_logcollector();
}

static void revise_fasten(void)
{
	int num = 0, i = 0;
	if (fasten_policy_global.resource.sys.enable == TURN_MY_OFF) {
		fasten_policy_global.resource.sys.cpu.enable = TURN_MY_OFF;
		fasten_policy_global.resource.sys.memory.enable = TURN_MY_OFF;
		fasten_policy_global.resource.sys.disk.enable = TURN_MY_OFF;
		fasten_policy_global.resource.sys.netflow.enable = TURN_MY_OFF;
	}

	if (fasten_policy_global.resource.process.enable == TURN_MY_OFF) {
		fasten_policy_global.resource.process.cpu.enable = TURN_MY_OFF;
		fasten_policy_global.resource.process.memory.enable = TURN_MY_OFF;
	}

	if (fasten_policy_global.system.load_enable == TURN_MY_OFF) {
		fasten_policy_global.system.load_cpu = 0;
		fasten_policy_global.system.load_memory = 0;
		fasten_policy_global.system.load_disk = 0;
	}

	if (fasten_policy_global.device.usb.enable == TURN_MY_OFF) {
		fasten_policy_global.device.usb.terminate = TURN_MY_OFF;
		num = fasten_policy_global.device.usb.exclude_num;
		for (i = 0; i < num; i++) {
			free_valuestring(fasten_policy_global.device.usb.exclude[i].list);
		}
		sniper_free(fasten_policy_global.device.usb.exclude, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		fasten_policy_global.device.usb.exclude_num = 0;
	}

	if (fasten_policy_global.device.printer.enable == TURN_MY_OFF) {
		fasten_policy_global.device.printer.terminate = TURN_MY_OFF;
		num = fasten_policy_global.device.printer.ext_num;
		for (i = 0; i < num; i++) {
			free_valuestring(fasten_policy_global.device.printer.ext[i].list);
		}
		sniper_free(fasten_policy_global.device.printer.ext, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		fasten_policy_global.device.printer.ext_num = 0;
	}

	if (fasten_policy_global.device.cdrom.enable == TURN_MY_OFF) {
		fasten_policy_global.device.cdrom.terminate = TURN_MY_OFF;
		num = fasten_policy_global.device.cdrom.ext_num;
		for (i = 0; i < num; i++) {
			free_valuestring(fasten_policy_global.device.cdrom.ext[i].list);
		}
		sniper_free(fasten_policy_global.device.cdrom.ext, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		fasten_policy_global.device.cdrom.ext_num = 0;
	}

}

void check_encrypt_hide(void)
{
	int hide = protect_policy_global.behaviour.ransomware.encrypt.hide;
	int encrypt_enable = protect_policy_global.behaviour.ransomware.encrypt.enable;

	/* 防护引擎功能关闭，删除诱捕文件*/
	if (encrypt_enable == TURN_MY_OFF) {
		operate_encrypt_trap_files(hide, OP_DELETE);
		last_encrypt_enable = encrypt_enable;
		/* 功能关闭时不用记录隐藏诱捕文件的开关状态，下次功能开关打开，必然会重新创建 */
		return;
	}

	/* 隐藏诱捕文件开关是否有改变*/
	if (hide_mode == hide && last_encrypt_enable == encrypt_enable) {
		return;
	}

	if (hide_mode != hide) {
		operate_encrypt_trap_files(hide, OP_DELETE);
	}

	/* 开关改变重新生成诱捕文件，并记录开关状态 */
	operate_encrypt_trap_files(hide, OP_CREATE);
	hide_mode = hide;
	last_encrypt_enable = encrypt_enable;

	return;
}

static void revise_policy(void)
{
	/* 修正防护策略	*/
	revise_protect();

	/* 修正加固策略 */
	revise_fasten();

	/* 加密引擎诱捕文件是否更改隐藏 */
	check_encrypt_hide();

	/*其他策略暂时只有2个开关，不需要修正*/
}

void update_kernel_policy(void)
{
	/* 发送进程策略 */
	update_kernel_process_rules();

	/* 发送文件防护策略 */
	update_kernel_file_policy();

	/* 发送网络配置策略 */
	update_kernel_net_policy();

}

/* 用文件指示是否隐藏托盘程序 */
#define NOTSHOWTRAY "/opt/snipercli/lst.conf.notshowtray"
static void hide_tray(void)
{
	FILE *fp = NULL;

	/* 无指示文件，显示 */
	if (other_policy_global.allow_ui_tray.enable) {
		if (unlink(NOTSHOWTRAY) < 0) {
			if (errno == ENOENT) {
				errno = 0;
				return;
			}
			MON_ERROR("enable tray fail: %s\n", strerror(errno));
		}
		return;
	}

	/* 有指示文件，隐藏 */
	if (access(NOTSHOWTRAY, F_OK) == 0) {
		return;
	}

	fp = fopen(NOTSHOWTRAY, "w");
	if (fp) {
		INFO("disable snipertray\n");
		fclose(fp);
		return;
	}

	MON_ERROR("disable tray fail: %s\n", strerror(errno));
}

/* 用文件指示是否允许卸载 */
static void disable_uninstall(void)
{
	FILE *fp = NULL;

	if (other_policy_global.allow_uninstall.enable) {
		if (unlink(UNINSTALL_DISABLE) < 0) {
			if (errno == ENOENT) {
				errno = 0;
				return;
			}
			MON_ERROR("enable uninstall fail: %s\n", strerror(errno));
		}
		return;
	}

	if (access(UNINSTALL_DISABLE, F_OK) == 0) {
		return;
	}

	fp = fopen(UNINSTALL_DISABLE, "w");
	if (fp) {
		INFO("disable uninstall\n");
		fclose(fp);
		return;
	}

	MON_ERROR("disable uninstall fail: %s\n", strerror(errno));
}

int record_policy_name(char *name) 
{
	FILE *fp;

	fp = sniper_fopen(LST_NAME_FILE, "w+", POLICY_GET);
        if (fp == NULL) {
		return -1;
	}

	fprintf(fp, "%s\n", name);
	sniper_fclose(fp, POLICY_GET);

	return 0;
}

int parse_policy(char *buff)
{
	PROTECT_POLICY protect_policy = {{{0}}};
	FASTEN_POLICY fasten_policy = {{0}};
	OTHER_POLICY other_policy = {{0}};
#ifdef USE_AVIRA
	ANTIVIRUS_POLICY antivirus_policy = {0};
#endif

	cJSON *json = NULL;
	cJSON *id, *name, *time;

	json = cJSON_Parse(buff);
        if (!json) {
                MON_ERROR("update policy fail: %s\n", buff);
                return -1;
        }

	id = cJSON_GetObjectItem(json, "policy_id");
	if (id == NULL || id->valuestring == NULL) {
		MON_ERROR("update policy fail: get policy_id error: %s\n",
			cJSON_GetErrorPtr());
	} else {
		strncpy(policy_id_cur, id->valuestring, POLICY_ID_LEN_MAX);
		policy_id_cur[POLICY_ID_LEN_MAX - 1] = '\0';
	}

	name = cJSON_GetObjectItem(json, "policy_name");
	if (name == NULL || name->valuestring == NULL) {
		MON_ERROR("update policy fail: get policy_name error: %s\n",
			cJSON_GetErrorPtr());
	} else {
		strncpy(policy_name_cur, name->valuestring, POLICY_NAME_LEN_MAX);
		policy_name_cur[POLICY_NAME_LEN_MAX - 1] = '\0';

		record_policy_name(policy_name_cur);
	}

	time = cJSON_GetObjectItem(json, "policy_time");
	if (time == NULL || time->valuestring == NULL) {
		MON_ERROR("update policy fail: get policy_time error: %s\n",
			cJSON_GetErrorPtr());
	} else {
		strncpy(policy_time_cur, time->valuestring, POLICY_TIME_LEN_MAX);
		policy_time_cur[POLICY_TIME_LEN_MAX - 1] = '\0';
	}

	/*赋值到全局变量中*/
	get_policy_protect(json, &protect_policy);
        save_old_protect_policy();
        pthread_rwlock_wrlock(&protect_policy_global.lock);
        get_protect_policy(&protect_policy);
        pthread_rwlock_unlock(&protect_policy_global.lock);

	get_policy_fasten(json, &fasten_policy);
        save_old_fasten_policy();
        pthread_rwlock_wrlock(&fasten_policy_global.lock);
        get_fasten_policy(&fasten_policy);
        pthread_rwlock_unlock(&fasten_policy_global.lock);

#ifdef USE_AVIRA
	get_policy_antivirus(json, &antivirus_policy);
        save_old_antivirus_policy();
        pthread_rwlock_wrlock(&antivirus_policy_global.lock);
        get_antivirus_policy(&antivirus_policy);
        pthread_rwlock_unlock(&antivirus_policy_global.lock);
#endif

	get_policy_other(json, &other_policy);
        save_old_other_policy();
        pthread_rwlock_wrlock(&other_policy_global.lock);
        get_other_policy(&other_policy);
        pthread_rwlock_unlock(&other_policy_global.lock);

	/* 修正策略,大开关关闭的情况下,小开关,阻断,锁定开关均关闭 */
	revise_policy();

	/* 每次更新策略成功后记录到文件中 */
	record_policy_to_file();

	/* 调整设备监控例外主机*/
	revise_device_exclude_uuid();

	/* 检测已有的usb是否需要禁止 */
	check_usb_info(0);

	/* 检测备份空间是否已满 */
	check_backup_free_size();

#if 0
	/* 发送所有内核需要的策略 */
	update_kernel_policy();
#else
	// NOTE(luoyinhong): no policy need to send to ebpf for now
#endif

	/* 用文件指示是否显示托盘程序 */
	hide_tray();
	disable_uninstall();

	INFO("update policy[%s]:%s success\n", policy_id_cur, policy_name_cur);
	is_update_task = 1;

	cJSON_Delete(json);
	return 0;
}

static int get_policy(char *rule, int len)
{
	int ret = 0;

	/* 异或解密 */
	DoXOR(0x10298, (char *)rule, len);

	dbg_record_to_file(DBGFLAG_POLICY, POLICY_JSON, rule, len);

	rule[len-1] = 0;
	ret = parse_policy(rule);

	return ret;
}

int update_policy(char *reason)
{
	buffer_t buffer = {0};
	buffer_t unzip_buffer = {0};
	FILE *bakfp = NULL;
	int ret = 0;

	buffer.len = FILE_MAX;
	buffer.data = sniper_malloc(FILE_MAX, POLICY_GET);
	buffer.pos = 0;
	if (!buffer.data) {
		MON_ERROR("malloc lst zip buffer failed!\n");
		strncpy(reason, "malloc lst zip buffer failed!", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		return -1;
	}

	/* download policy file and backup */
        if (download(&buffer) < 0) {
                MON_ERROR("download policy file failed!\n");
                sniper_free(buffer.data, FILE_MAX, POLICY_GET);
		strncpy(reason, "download policy file failed!", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
                return -1;
        }

	if (strstr(buffer.data, "404 Not Found")) {
		MON_ERROR("download policy file failed! 404\n");
		sniper_free(buffer.data, FILE_MAX, POLICY_GET);
		strncpy(reason, "download policy file failed! 404", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		return -1;
	}

	if (buffer.pos > buffer.len) {
		MON_ERROR("Bad policy size %d > %d\n",
			buffer.pos, buffer.len);
		sniper_free(buffer.data, FILE_MAX, POLICY_GET);
		strncpy(reason, "Bad policy size", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		return -1;
	}

	if (buffer.pos < buffer.len) {
		bakfp = sniper_fopen(POLICY_ZIP_FILEBAK, "w+", POLICY_GET);
		if (!bakfp) {
			MON_ERROR("open bakfile failed!\n");
			sniper_free(buffer.data, FILE_MAX, POLICY_GET);
			strncpy(reason, "open bakfile failed!", S_LINELEN);
			reason[S_LINELEN - 1] = '\0';
			return -1;
		}

		if (fwrite(buffer.data, buffer.pos, 1, bakfp) != 1) {
			MON_ERROR("policy read to file failed!\n");
			sniper_fclose(bakfp, POLICY_GET);
			unlink(POLICY_ZIP_FILEBAK);
			sniper_free(buffer.data, FILE_MAX, POLICY_GET);
			strncpy(reason, "policy read to file failed!", S_LINELEN);
			reason[S_LINELEN - 1] = '\0';
			return -1;
		}

		fflush(bakfp);
		sniper_fclose(bakfp, POLICY_GET);
	}

	/* unzip data, then update */
	unzip_buffer.len = FILE_MAX;
	unzip_buffer.data = sniper_malloc(FILE_MAX, POLICY_GET);
	if (!unzip_buffer.data) {
		MON_ERROR("malloc lst unzip buffer failed!\n");
		unlink(POLICY_ZIP_FILEBAK);
		sniper_free(buffer.data, FILE_MAX, POLICY_GET);
		strncpy(reason, "malloc lst unzip buffer failed!", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		return -1;
	}

	ret = uncompress((Bytef *)unzip_buffer.data,
			&unzip_buffer.len,
			(Bytef *)buffer.data,
			buffer.pos);
	if (ret != Z_OK) {
		MON_ERROR("unzip lst error %d, size %d\n",
			ret, buffer.pos);
		unlink(POLICY_ZIP_FILEBAK);
		sniper_free(buffer.data, FILE_MAX, POLICY_GET);
		sniper_free(unzip_buffer.data, FILE_MAX, POLICY_GET);
		strncpy(reason, "unzip lst error", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		return -1;
	}

	unzip_buffer.pos = unzip_buffer.len;
	unzip_buffer.len = FILE_MAX;
	unzip_buffer.data[unzip_buffer.pos] = 0;

	if (get_policy(unzip_buffer.data, unzip_buffer.len) < 0) {
		MON_ERROR("update policy fail\n");
		unlink(POLICY_ZIP_FILEBAK);
		sniper_free(buffer.data, FILE_MAX, POLICY_GET);
		sniper_free(unzip_buffer.data, FILE_MAX, POLICY_GET);
		strncpy(reason, "policy date error", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		return -1;
	}

	unlink(POLICY_ZIP_FILE);
	rename(POLICY_ZIP_FILEBAK, POLICY_ZIP_FILE);

	sniper_free(buffer.data, FILE_MAX, POLICY_GET);
	sniper_free(unzip_buffer.data, FILE_MAX, POLICY_GET);

	return 0;
}

void send_policy_update_post(int result)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	unsigned long event_time = 0;
	bool event = false;
	int behavior = 0, level = 1, terminate = 0;
	struct timeval tv;

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

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec+serv_timeoff) *1000 + (int)tv.tv_usec/1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientPolicyUpdate");
	cJSON_AddStringToObject(object, "log_category", "Client");
	  cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "Updated");
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

        cJSON_AddStringToObject(arguments, "client_version", Sys_info.version);
        cJSON_AddStringToObject(arguments, "client_dir", "/opt/snipercli/");
        cJSON_AddStringToObject(arguments, "policy_id", policy_id_cur);
        cJSON_AddStringToObject(arguments, "policy_name", policy_name_cur);
        cJSON_AddStringToObject(arguments, "policy_time", policy_time_cur);

        cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
//	printf("client change post:%s\n", post);
	DBG("client change post:%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "task");

	cJSON_Delete(object);
	free(post);
}

int update_policy_my(task_recv_t *msg) 
{
	char reason[S_LINELEN] = {0};
	int ret = 0;

	pthread_mutex_lock(&policy_update_lock);
	ret = update_policy(reason);
	pthread_mutex_unlock(&policy_update_lock);
	if (ret < 0) {
		send_policy_update_post(OPERATE_FAIL);
		send_task_resp(msg, RESULT_FAIL, reason);
	} else {
		send_policy_update_post(OPERATE_OK);
		send_task_resp(msg, RESULT_OK, "Policy Update");
	}
	
	return 0;
}

int init_policy(void)
{
	int fd = 0, bytes_read = 0, ret = 0;
        size_t len = FILE_MAX;
        char *buffer = NULL, *file_buffer = NULL;

	/* 如果在init_conf里面做会下发到内核失败 */
	load_last_local_conf();

	pthread_rwlock_init(&protect_policy_global.lock, 0);
        pthread_rwlock_init(&fasten_policy_global.lock, 0);
        pthread_rwlock_init(&antivirus_policy_global.lock, 0);
        pthread_rwlock_init(&other_policy_global.lock, 0);

	pthread_mutex_init(&policy_update_lock, NULL);

	fd = sniper_open(POLICY_ZIP_FILE, O_RDONLY, POLICY_GET);
	if (fd < 0) {
		INFO("no local policy\n");
		return -1;
	}

	file_buffer = (char*)sniper_malloc(FILE_MAX, POLICY_GET);
	if (!file_buffer) {
		MON_ERROR("init_policy malloc fail: no memory\n");
		sniper_close(fd, POLICY_GET);
		return -1;
	}

	buffer = sniper_malloc(FILE_MAX, POLICY_GET);
	if (!buffer) {
		MON_ERROR("init_policy malloc fail: no memory\n");
		sniper_close(fd, POLICY_GET);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		return -1;
	}

	bytes_read = read(fd, file_buffer, FILE_MAX);
	if (bytes_read < 0) {
		MON_ERROR("Read policy %s fail: %s\n", POLICY_FILE, strerror(errno));
		sniper_close(fd, POLICY_GET);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
		return -1;
	}
	sniper_close(fd, POLICY_GET);

	if (bytes_read > len) {
                MON_ERROR("Bad policy size: %d > %d\n", bytes_read, len);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
                return -1;
        }

	file_buffer[bytes_read] = '\0';

	ret = uncompress((Bytef *)buffer, &len, (Bytef *)file_buffer, bytes_read);
	if (ret != Z_OK) {
		MON_ERROR("Uncompress policy %s fail: ret %d\n", POLICY_FILE, ret);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
		return -1;
	}

	if (get_policy(buffer, FILE_MAX) < 0) {
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
                return -1;
        }

	INFO("init local policy success!\n");
	sniper_free(file_buffer, FILE_MAX, POLICY_GET);
	sniper_free(buffer, FILE_MAX, POLICY_GET);
	return 0;
}

void fini_policy(void)
{
	pthread_rwlock_destroy(&protect_policy_global.lock);
        pthread_rwlock_destroy(&fasten_policy_global.lock);
        pthread_rwlock_destroy(&antivirus_policy_global.lock);
        pthread_rwlock_destroy(&other_policy_global.lock);

	pthread_mutex_destroy(&policy_update_lock);
}
