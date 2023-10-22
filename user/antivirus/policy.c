#include "header.h"
#include "policy.h"

#define MY_TURNON       1
#define MY_TURNOFF      0

char *policy_yes_en = "yes";
char *policy_no_en = "no";
char *full_scan_en = "full scan";
char *quick_scan_en = "quick scan";
char *ask_me_en = "ask me";
char *auto_process_en = "auto process";

char policy_id_cur[POLICY_ID_LEN_MAX] = {0};
char policy_name_cur[POLICY_NAME_LEN_MAX] = {0};
char policy_time_cur[POLICY_TIME_LEN_MAX] = {0};

ANTIVIRUS_POLICY antivirus_policy_global = {0};
ANTIVIRUS_POLICY old_antivirus_policy_global = {0};

int client_mode_global = 0;

GLOBAL_CONF conf_global = {0};
GLOBAL_CONF old_conf_global = {0};

char *check_my_switch_yes_en(int type)
{
	if (type == MY_TURNON) {
		return policy_yes_en;
	}

	return policy_no_en;
}

char *check_antivirus_scan_type_en(int type)
{
	if (type == 1) {
		return full_scan_en;
	}

	return quick_scan_en;
}

char *check_antivirus_process_type_en(int type)
{
	if (type == 0) {
		return ask_me_en;
	}

	return auto_process_en;
}

void free_valuestring(char *str)
{
	if (str) {
		sniper_free(str, strlen(str)+1, POLICY_GET);
	}
}

/* 获取json字符串的valuestring */
char *get_my_valuestring(cJSON *item)
{
	int len = 0;
	char *buf = NULL;

	if (item->valuestring == NULL) {
		MON_DBG("Item json valuestring is NULL\n");
		return NULL;
	}

	len = strlen(item->valuestring) + 1;
	buf = (char*)sniper_malloc(len, POLICY_GET);
	if (buf == NULL) {
		MON_DBG("value malloc failed\n");
		return NULL;
	}
	strcpy(buf, item->valuestring);

	return buf;
}

void dump_policy_antivirus(void)
{       
	printf("[virus protection]\n");

	printf("virus detection\n");
	printf("real-time detection:%s\n",
			check_my_switch_yes_en(antivirus_policy_global.real_time_check.enable));

	printf("scan and kill :%s\n",
			check_my_switch_yes_en(antivirus_policy_global.scanning_kill.enable));
	printf("  Timed scan:%s\n",
			check_my_switch_yes_en(antivirus_policy_global.scanning_kill.cron.enable));
	printf("  scan type:%s\n",
			check_antivirus_scan_type_en(antivirus_policy_global.scanning_kill.cron.scanning_way));
	printf("  scan cycle:%s\n",antivirus_policy_global.scanning_kill.cron.time_type);
	printf("  selection period: day(%d) time(%s)\n",
			antivirus_policy_global.scanning_kill.cron.day,
			antivirus_policy_global.scanning_kill.cron.time);

	printf("virus scanning configuration\n");
	printf("  process type:%s\n",
			check_antivirus_process_type_en(antivirus_policy_global.automate));
	printf("  quarantine settings: Quarantine disk reserved space [%d]GB\n",
			antivirus_policy_global.reserved_space);
	printf("  exception setting: ignore files larger than [%d]MB\n",
			antivirus_policy_global.neglect_size);
	return;
}

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

static int get_policy_antivirus_real_time_check(cJSON *json, struct _ANTIVIRUS_POLICY *antivirus_policy)
{
	cJSON *enable;

	enable = cJSON_GetObjectItem(json, "enable");
	if (!enable) {
		MON_DBG("policy cJSON_Parse antivirus real_time_check enable error\n");
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
		MON_DBG("policy cJSON_Parse antivirus scanning_kill cron enable error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.cron.enable = enable->valueint;

	scanning_way = cJSON_GetObjectItem(json, "scanning_way");
	if (!scanning_way) {
		MON_DBG("policy cJSON_Parse antivirus scanning_kill cron scanning_way error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.cron.scanning_way = scanning_way->valueint;

	time_type = cJSON_GetObjectItem(json, "time_type");
	if (!time_type) {
		MON_DBG("policy cJSON_Parse antivirus scanning_kill cron time_type error\n");
		return -1;
	}

	buf = get_my_valuestring(time_type);
        if (buf == NULL) {
                MON_DBG("policy cJSON_Parse antivirus scanning_kill cron time_type malloc error\n");
                return -1;
        }
        antivirus_policy->scanning_kill.cron.time_type = buf;

	day = cJSON_GetObjectItem(json, "day");
	if (!day) {
		MON_DBG("policy cJSON_Parse antivirus scanning_kill cron day error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.cron.day = day->valueint;

	time = cJSON_GetObjectItem(json, "time");
	if (!time) {
		MON_DBG("policy cJSON_Parse antivirus scanning_kill cron time error\n");
		return -1;
	}

	buf = get_my_valuestring(time);
        if (buf == NULL) {
                MON_DBG("policy cJSON_Parse antivirus scanning_kill cron time malloc error\n");
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
		MON_DBG("policy cJSON_Parse antivirus scanning_kill enable error\n");
		return -1;
	}
	antivirus_policy->scanning_kill.enable = enable->valueint;

	cron = cJSON_GetObjectItem(json, "cron");
	if (!cron) {
		MON_DBG("policy cJSON_Parse antivirus scanning_kill cron error\n");
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
                MON_DBG("policy cJSON_Parse antivirus trust_list malloc failed\n");
                return -1;
        }

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(trust_list, i);
		if (!arrayItem) {
			MON_DBG("policy cJSON_Parse antivirus trust list[%d] error\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(antivirus_policy->trust_list[j].list);
			}
			sniper_free(antivirus_policy->trust_list, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_DBG("policy cJSON_Parse antivirus trust list[%d].list get value failed\n", i);
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
		MON_DBG("policy cJSON_Parse antivirus error\n");
		return -1;
	}

	real_time_check = cJSON_GetObjectItem(antivirus, "real_time_check");
	if (!real_time_check) {
		MON_DBG("policy cJSON_Parse antivirus real_time_check error\n");
		return -1;
	} else {
		if (get_policy_antivirus_real_time_check(real_time_check, antivirus_policy) < 0) {
			antivirus_policy->real_time_check.enable = 0;
			return -1;
		}
	}

	scanning_kill = cJSON_GetObjectItem(antivirus, "scanning_kill");
	if (!scanning_kill) {
		MON_DBG("policy cJSON_Parse antivirus scanning_kill error\n");
		return -1;
	} else {
		if (get_policy_antivirus_scanning_kill(scanning_kill, antivirus_policy) < 0) {
			antivirus_policy->scanning_kill.enable = 0;
			return -1;
		}
	}

	automate = cJSON_GetObjectItem(antivirus, "automate");
	if (!automate) {
		MON_DBG("policy cJSON_Parse antivirus automate error\n");
		return -1;
	}
	antivirus_policy->automate = automate->valueint;

	reserved_space = cJSON_GetObjectItem(antivirus, "reserved_space");
	if (!reserved_space) {
		MON_DBG("policy cJSON_Parse antivirus reserved_space error\n");
		return -1;
	}
	antivirus_policy->reserved_space = reserved_space->valueint;

	neglect_size = cJSON_GetObjectItem(antivirus, "neglect_size");
	if (!neglect_size) {
		MON_DBG("policy cJSON_Parse antivirus neglect_size error\n");
		return -1;
	}
	antivirus_policy->neglect_size = neglect_size->valueint;

	trust_list = cJSON_GetObjectItem(antivirus, "trust_list");
	if (!trust_list) {
		MON_DBG("policy cJSON_Parse antivirus trust_list error\n");
		return -1;
	} else {
		if (get_policy_antivirus_trust_list(trust_list, antivirus_policy) < 0) {
			printf("get_policy_antivirus_trust_list < 0\n");
			antivirus_policy->list_num = 0;
			return -1;
		}
	}
	return 0;
}

static inline void DoXOR(unsigned long key, char *data, int len)
{
	if (len) {
		while (len--) {
			*(data++) ^= key;
		}
	}
}

int parse_policy(char *buff)
{
	ANTIVIRUS_POLICY antivirus_policy = {0};

	cJSON *json = NULL;
	cJSON *id, *name, *time;

	json = cJSON_Parse(buff);
        if (!json) {
                MON_DBG("update policy fail: %s\n", buff);
                return -1;
        }

	id = cJSON_GetObjectItem(json, "policy_id");
	if (id == NULL || id->valuestring == NULL) {
		MON_DBG("update policy fail: get policy_id error: %s\n",
			cJSON_GetErrorPtr());
	} else {
		strncpy(policy_id_cur, id->valuestring, POLICY_ID_LEN_MAX);
		policy_id_cur[POLICY_ID_LEN_MAX - 1] = '\0';
	}

	name = cJSON_GetObjectItem(json, "policy_name");
	if (name == NULL || name->valuestring == NULL) {
		MON_DBG("update policy fail: get policy_name error: %s\n",
			cJSON_GetErrorPtr());
	} else {
		strncpy(policy_name_cur, name->valuestring, POLICY_NAME_LEN_MAX);
		policy_name_cur[POLICY_NAME_LEN_MAX - 1] = '\0';
	}

	time = cJSON_GetObjectItem(json, "policy_time");
	if (time == NULL || time->valuestring == NULL) {
		MON_DBG("update policy fail: get policy_time error: %s\n",
			cJSON_GetErrorPtr());
	} else {
		strncpy(policy_time_cur, time->valuestring, POLICY_TIME_LEN_MAX);
		policy_time_cur[POLICY_TIME_LEN_MAX - 1] = '\0';
	}

	/*赋值到全局变量中*/
	get_policy_antivirus(json, &antivirus_policy);
        save_old_antivirus_policy();
        pthread_rwlock_wrlock(&antivirus_policy_global.lock);
        get_antivirus_policy(&antivirus_policy);
        pthread_rwlock_unlock(&antivirus_policy_global.lock);

	MON_DBG2(DBGFLAG_ANTIVIRUS_SCAN, "update policy[%s]:%s success\n", policy_id_cur, policy_name_cur);

	cJSON_Delete(json);
	return 0;
}

static int get_policy(char *rule, int len)
{
	int ret = 0;

	/* 异或解密 */
	DoXOR(0x10298, (char *)rule, len);

	rule[len-1] = 0;
	ret = parse_policy(rule);

	return ret;
}

int load_local_policy(void)
{
	int fd = 0, bytes_read = 0, ret = 0;
        size_t len = FILE_MAX;
        char *buffer = NULL, *file_buffer = NULL;

	fd = sniper_open(POLICY_ZIP_FILE, O_RDONLY, POLICY_GET);
	if (fd < 0) {
		MON_DBG("no policy\n");
		return -1;
	}

	file_buffer = (char*)sniper_malloc(FILE_MAX, POLICY_GET);
	if (!file_buffer) {
		MON_DBG("load policy malloc fail: no memory\n");
		sniper_close(fd, POLICY_GET);
		return -1;
	}

	buffer = sniper_malloc(FILE_MAX, POLICY_GET);
	if (!buffer) {
		MON_DBG("load policy malloc fail: no memory\n");
		sniper_close(fd, POLICY_GET);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		return -1;
	}

	bytes_read = read(fd, file_buffer, FILE_MAX);
	if (bytes_read < 0) {
		MON_DBG("Read policy %s fail: %s\n", POLICY_FILE, strerror(errno));
		sniper_close(fd, POLICY_GET);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
		return -1;
	}
	sniper_close(fd, POLICY_GET);

	if (bytes_read > len) {
                MON_DBG("Bad policy size: %d > %d\n", bytes_read, len);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
                return -1;
        }

	file_buffer[bytes_read] = '\0';

	ret = uncompress((Bytef *)buffer, &len, (Bytef *)file_buffer, bytes_read);
	if (ret != Z_OK) {
		MON_DBG("Uncompress policy %s fail: ret %d\n", POLICY_FILE, ret);
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
		return -1;
	}

	if (get_policy(buffer, FILE_MAX) < 0) {
		sniper_free(file_buffer, FILE_MAX, POLICY_GET);
		sniper_free(buffer, FILE_MAX, POLICY_GET);
                return -1;
        }

	sniper_free(file_buffer, FILE_MAX, POLICY_GET);
	sniper_free(buffer, FILE_MAX, POLICY_GET);
	return 0;
}

void free_conf_global_ptr(struct _GLOBAL_CONF *global_conf)
{
	int i = 0, num = 0, len = 0;
	num = global_conf->module_num;
        for (i = 0; i < num; i++) {
                free_valuestring(global_conf->licence_module[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(global_conf->licence_module, len, POLICY_GET);
	global_conf->module_num = 0;

	num = global_conf->server_num;
        for (i = 0; i < num; i++) {
                free_valuestring(global_conf->server_ip[i].list);
        }
        len = sizeof(struct _POLICY_LIST) * num;
        sniper_free(global_conf->server_ip, len, POLICY_GET);
	global_conf->server_num = 0;
}

static void save_old_global_conf(void)
{
        free_conf_global_ptr(&old_conf_global);
        old_conf_global = conf_global;
}

static int get_global_conf(struct _GLOBAL_CONF *global_conf)
{
        conf_global.agent_cpu_limit = global_conf->agent_cpu_limit;
        conf_global.agent_memory_limit = global_conf->agent_memory_limit;
        conf_global.agent_network_limit = global_conf->agent_network_limit;
        conf_global.offline_space_size = global_conf->offline_space_size;
        conf_global.heartbeat_interval = global_conf->heartbeat_interval;
        conf_global.log_collect_mode = global_conf->log_collect_mode;
        conf_global.log_collect_interval = global_conf->log_collect_interval;
        conf_global.licence_expire = global_conf->licence_expire;
        conf_global.allow_upload_sample = global_conf->allow_upload_sample;
        conf_global.isolation_space_size = global_conf->isolation_space_size;
        conf_global.module_num = global_conf->module_num;
        conf_global.server_num = global_conf->server_num;
        conf_global.licence_module = global_conf->licence_module;
        conf_global.server_ip = global_conf->server_ip;

        return 0;
}

static int get_conf_global_licence_module(cJSON *licence_module, struct _GLOBAL_CONF *global_conf)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(licence_module);
	global_conf->module_num = num;
	global_conf->licence_module = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (global_conf->licence_module == NULL) {
		MON_DBG("global_conf->licence_module malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(licence_module, i);
		if (!arrayItem) {
			MON_DBG( "cJSON_GetObjectItem global_conf licence_module[%d] array error\n",i);
			for (j = 0; j < i; j++) {
				free_valuestring(global_conf->licence_module[j].list);
			}
			sniper_free(global_conf->licence_module, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_DBG("global_conf->licence_module[%d].list malloc failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(global_conf->licence_module[j].list);
			}
			sniper_free(global_conf->licence_module, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		global_conf->licence_module[i].list = buf;
	}

	return 0;
}

static int get_conf_global_server_ip(cJSON *server_ip, struct _GLOBAL_CONF *global_conf)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(server_ip);
	global_conf->server_num = num;
	global_conf->server_ip = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (global_conf->server_ip == NULL) {
		MON_DBG("global_conf->server_ip malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(server_ip, i);
		if (!arrayItem) {
			MON_DBG("cJSON_GetObjectItem global_conf server_ip[%d] array error\n",i);
			for (j = 0; j < i; j++) {
				free_valuestring(global_conf->server_ip[j].list);
			}
			sniper_free(global_conf->server_ip, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_DBG("global_conf->server_ip[%d].list malloc failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(global_conf->server_ip[j].list);
			}
			sniper_free(global_conf->server_ip, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}
		global_conf->server_ip[i].list = buf;

	}

	return 0;
}

static int get_conf_global(cJSON *data, struct _GLOBAL_CONF *global_conf)
{
	cJSON *global;
	cJSON *agent_cpu_limit, *offline_space_size, *heartbeat_interval;
	cJSON *log_collect_mode, *licence_expire, *log_collect_interval, *allow_upload_sample, *isolation_space_size;
	cJSON *agent_memory_limit, *agent_network_limit, *server_ip, *licence_module;

	global = cJSON_GetObjectItem(data, "global");
        if (!global) {
		MON_DBG("conf cJSON_Parse global error\n");
                return -1;
        }

	agent_cpu_limit = cJSON_GetObjectItem(global, "agent_cpu_limit");
        if (!agent_cpu_limit) {
		MON_DBG("conf cJSON_Parse global agent_cpu_limit error\n");
        } else {
		global_conf->agent_cpu_limit = agent_cpu_limit->valueint;
	}

	agent_memory_limit = cJSON_GetObjectItem(global, "agent_memory_limit");
        if (!agent_memory_limit) {
		MON_DBG("conf cJSON_Parse global agent_memory_limit error\n");
        } else {
		global_conf->agent_memory_limit = agent_memory_limit->valueint;
	}

	agent_network_limit = cJSON_GetObjectItem(global, "agent_network_limit");
        if (!agent_network_limit) {
		MON_DBG("conf cJSON_Parse global agent_network_limit error\n");
        } else {
		global_conf->agent_network_limit = agent_network_limit->valueint;
	}

	offline_space_size = cJSON_GetObjectItem(global, "offline_space_size");
        if (!offline_space_size) {
		MON_DBG("conf cJSON_Parse global offline_space_size error\n");
        } else {
		global_conf->offline_space_size = offline_space_size->valueint;
	}

	heartbeat_interval = cJSON_GetObjectItem(global, "heartbeat_interval");
        if (!heartbeat_interval) {
		MON_DBG("conf cJSON_Parse global heartbeat_interval error\n");
        } else {
		global_conf->heartbeat_interval = heartbeat_interval->valueint;
	}

	log_collect_mode = cJSON_GetObjectItem(global, "log_collect_mode");
        if (!log_collect_mode) {
		MON_DBG("conf cJSON_Parse global log_collect_mode error\n");
        } else {
		global_conf->log_collect_mode = log_collect_mode->valueint;
	}

	log_collect_interval = cJSON_GetObjectItem(global, "log_collect_interval");
        if (!log_collect_interval) {
		MON_DBG("conf cJSON_Parse global log_collect_interval error\n");
        } else {
		global_conf->log_collect_interval = log_collect_interval->valueint;
	}

	licence_expire = cJSON_GetObjectItem(global, "licence_expire");
        if (!licence_expire) {
		MON_DBG("conf cJSON_Parse global licence_expire error\n");
        } else {
		global_conf->licence_expire = licence_expire->valueint;
	}

	allow_upload_sample = cJSON_GetObjectItem(global, "allow_upload_sample");
        if (!allow_upload_sample) {
		MON_DBG("conf cJSON_Parse global allow_upload_sample error\n");
        } else {
		global_conf->allow_upload_sample = allow_upload_sample->valueint;
	}

	isolation_space_size = cJSON_GetObjectItem(global, "isolation_space_size");
        if (!isolation_space_size) {
		MON_DBG("conf cJSON_Parse global isolation_space_size error\n");
        } else {
		global_conf->isolation_space_size = isolation_space_size->valueint;
	}

	server_ip = cJSON_GetObjectItem(global, "server_ip");
        if (!server_ip) {
		MON_DBG("conf cJSON_Parse global server_ip error\n");
		global_conf->server_num = 0;
        } else {
		if (get_conf_global_server_ip(server_ip, global_conf) < 0) {
			global_conf->server_num = 0;
		}
	}

	licence_module = cJSON_GetObjectItem(global, "licence_module");
        if (!licence_module) {
		MON_DBG("conf cJSON_Parse global licence_module error\n");
		global_conf->module_num = 0;
        } else {
		if (get_conf_global_licence_module(licence_module, global_conf) < 0) {
			global_conf->module_num = 0;
		}
	}

	return 0;
}

int parse_conf_local(char *string)
{
	cJSON *json, *data;
	cJSON *operation;

	int operation_mode = 0;

	GLOBAL_CONF global_conf = {0};

	json = cJSON_Parse(string);
	if (!json) {
		MON_DBG("parse conf reply fail: %s\n", cJSON_GetErrorPtr());
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_DBG("conf reply get data error: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(json);
		return -1;
	}

	operation = cJSON_GetObjectItem(data, "operation_mode");
	if (!operation) {
		MON_DBG("conf reply get data operation_mode error: %s\n", cJSON_GetErrorPtr());
        } else {
		operation_mode = operation->valueint;
		client_mode_global = operation_mode;
	}

	/* 赋值到全局变量中 */
	get_conf_global(data, &global_conf);
	save_old_global_conf();
        pthread_rwlock_wrlock(&conf_global.lock);
        get_global_conf(&global_conf);
        pthread_rwlock_unlock(&conf_global.lock);
	/* 在配置下发的时候控制学习模式下始终允许上传样本，判断的时候只看上传样本的值就可以了 */
	if (LEARNING_MODE == client_mode_global) {
		conf_global.allow_upload_sample = 1;
	}

	cJSON_Delete(json);
	return 0;
}

void load_local_conf(void)
{
	char *buff = NULL;
	int fd = 0, bytes_read = 0;

	fd = sniper_open(CONF_JSON, O_RDONLY, POLICY_GET);
	if (fd < 0) {
		MON_DBG("no local conf\n");
		return;
	}

	buff = (char*)sniper_malloc(CONF_MAX, POLICY_GET);
	if (!buff) {
		MON_DBG("init_conf malloc fail: no memory\n");
		sniper_close(fd, POLICY_GET);
		return;
	}

	bytes_read = read(fd, buff, CONF_MAX);
	if (bytes_read < 0) {
		MON_DBG("Read policy %s fail: %s\n", POLICY_FILE, strerror(errno));
		sniper_close(fd, POLICY_GET);
		sniper_free(buff, CONF_MAX, POLICY_GET);
		return;
	}
	sniper_close(fd, POLICY_GET);
	buff[bytes_read] = '\0';

	if (parse_conf_local(buff) < 0) {
		MON_DBG("init local conf failed!\n");
		sniper_free(buff, CONF_MAX, POLICY_GET);
		return;
	}

	sniper_free(buff, CONF_MAX, POLICY_GET);
	return;
}
