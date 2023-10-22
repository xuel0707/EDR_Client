#include "header.h"
#include "cJSON.h"

/* 下载的各个库的版本号 */
char client_ver_global[VER_LEN_MAX] = {0};
char collect_ver_global[VER_LEN_MAX] = {0};
char vuln_ver_global[VER_LEN_MAX] = {0};
char baseline_ver_global[VER_LEN_MAX] = {0};
char crack_ver_global[VER_LEN_MAX] = {0};
char webshell_ver_global[VER_LEN_MAX] = {0};
char weak_passwd_ver_global[VER_LEN_MAX] = {0};
char ipwry_ver_global[VER_LEN_MAX] = {0};
char virus_lib_ver_global[VER_LEN_MAX] = {0};
char antivirus_ver_global[VER_LEN_MAX] = {0};

/* 配置信息的4个结构体成员 */
GLOBAL_CONF conf_global = {0};
ASSET_CONF conf_asset = {0};
POLICY_CONF conf_policy = {0};
WEBSHELL_DETECT webshell_detect_global = {0};

/* 旧的配置信息的4个结构体成员，更新配置的时候用来保存上一次获取的 */
static GLOBAL_CONF old_conf_global = {0};
static ASSET_CONF old_conf_asset = {0};
static POLICY_CONF old_conf_policy = {0};
static WEBSHELL_DETECT old_webshell_detect_global = {0};

/* 更新配置信息时的互斥锁 */
static pthread_mutex_t conf_update_lock;

/* 客户端模式 */
int client_mode_global = 0;

#define SQLITE_OPEN_MODE SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_SHAREDCACHE|SQLITE_OPEN_READONLY

/*
 * 5.0.9之前的管控下发的病毒库版本号为anti-5.0.8.0705-lib.zip
 * 下发的防病毒程序版本号为anti-5.0.8.0705-linux.zip
 * 提取中间的版本号5.0.8.0705
 */
void extract_virus_version(char *zipname, char *version)
{
	if (!zipname || !version) {
		return;
	}

	/* 39的长度是VER_LEN_MAX - 1的值*/
	sscanf(zipname, "%*[^-]-%39[^-]-*", version);
}

/* 封装释放字符串开辟的空间 */
void free_valuestring(char *str)
{
	if (str) {
		sniper_free(str, strlen(str)+1, POLICY_GET);
	}
}

/* 释放webshell正则规则结构体开辟的空间 */
static void free_webshell_rule_ptr(struct _WEBSHELL_DETECT *ptr)
{
	int i = 0, num = 0, len = 0;

	/* 结构体中的字符串指针一次回收空间 */
	num = ptr->rule_num;
	for (i = 0; i < num; i++) {
		free_valuestring(ptr->webshell_rule[i].regex);
		free_valuestring(ptr->webshell_rule[i].description);
	}
	len = sizeof(struct _WEBSHELL_RULE) * num;
	sniper_free(ptr->webshell_rule, len, POLICY_GET);
	ptr->rule_num = 0;
}

/* 保存当前的webshell正则规则给旧的全局变量 */
static void save_old_webshell_rule(void)
{
	free_webshell_rule_ptr(&old_webshell_detect_global);
	old_webshell_detect_global = webshell_detect_global;
}

/* 把获取的webshell正则规则赋值给新的全局变量*/
static void get_webshell_rule(struct _WEBSHELL_DETECT *ptr)
{
	webshell_detect_global.rule_num = ptr->rule_num;
	webshell_detect_global.webshell_rule = ptr->webshell_rule;
}

/* 计算webshell正则规则的条数 */
static int count_webshell_rule(sqlite3 *db)
{
	sqlite3_stmt* stmt = NULL;
	const char *sql = "SELECT Count(*) FROM webshell;";
	int count = 0;
	int rc = 0;

	/* 查询数据库中的记录数 */
	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		MON_ERROR("connect webshell rule db failed: %s\n", sqlite3_errstr(rc));
		return -1;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		count = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	return count;
}

/* 更新webshell正则规则的信息 */
static int update_webshell_info(char *path)
{
	sqlite3 *db = NULL;
	sqlite3_stmt* stmt = NULL;
	const char *sql = "SELECT id,enable,level,regex,description FROM webshell;";
	int j = 0, m = 0, count = 0;
	int id;
	int enable;
	int level;
	char description[STRLEN_MAX];
	char regex[STRLEN_MAX];
	const unsigned char *description_tmp;
	const unsigned char *regex_tmp;
	int rc = 0;
	int len = 0;
	WEBSHELL_DETECT webshell_detect = {0};
	char *ptr = NULL;
	int ptr_len = 0;

	/* 打开数据库 */
	rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_MODE, NULL);
	if (rc != SQLITE_OK) {
		MON_ERROR("open webshell rule db failed:%s\n", sqlite3_errstr(rc));
		return -1;
	}

	/* 获取规则的条数 */
	count = count_webshell_rule(db);
	if (count <= 0) {
		MON_ERROR("count webshell rule failed:%d\n", count);
		sqlite3_close_v2(db);
		return -1;
	}

	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		MON_ERROR("connect webshell rule db failed: %s\n", sqlite3_errstr(rc));
		sqlite3_close_v2(db);
		return -1;
	}

	/* 根据规则条数来开辟多个结构体的空间 */
	webshell_detect.webshell_rule = (struct _WEBSHELL_RULE*)sniper_malloc(sizeof(struct _WEBSHELL_RULE)*count, POLICY_GET);
	if (webshell_detect.webshell_rule == NULL) {
		MON_ERROR("webshell_detect.webshell_rule malloc failed\n");
		sqlite3_close_v2(db);
		return -1;
	}

	/* 从数据库中获取的每条规则赋值给结构体 */
	j = 0;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		id = sqlite3_column_int(stmt, 0);
		webshell_detect.webshell_rule[j].id = id;

		/* 根据规则的enable字段决定是否启用该规则 */
		enable = sqlite3_column_int(stmt, 1);
		if(enable == 0) {
			continue;
		}

		level = sqlite3_column_int(stmt, 2);
		webshell_detect.webshell_rule[j].level = level;

		regex_tmp = sqlite3_column_text(stmt, 3);
		if (regex_tmp == NULL) {
			continue;
		}
		snprintf(regex, sizeof(regex), "%s", regex_tmp);
		len = strlen(regex) + 1;
		webshell_detect.webshell_rule[j].regex = (char*)sniper_malloc(len, POLICY_GET);
		if (webshell_detect.webshell_rule[j].regex == NULL) {
			continue;
		}
		ptr = webshell_detect.webshell_rule[j].regex;
		ptr_len = len;
		snprintf(ptr, ptr_len, "%s", regex);

		description_tmp = sqlite3_column_text(stmt, 4);
		if (description_tmp == NULL) {
			free_valuestring(webshell_detect.webshell_rule[j].regex);
			continue;
		}
		snprintf(description, sizeof(description), "%s", description_tmp);
		len = strlen(description) + 1;
		webshell_detect.webshell_rule[j].description = (char*)sniper_malloc(len, POLICY_GET);
		if (webshell_detect.webshell_rule[j].description == NULL) {
			free_valuestring(webshell_detect.webshell_rule[j].regex);
			continue;
		}
		ptr = webshell_detect.webshell_rule[j].description;
		ptr_len = len;
		snprintf(ptr, ptr_len, "%s", description);
		j++;
	}

	/* 数目不一致时说明更新错误，释放空间 */
	if (count != j) {
		MON_ERROR("update webshell info failed\n");
		for (m = 0; m < j ;m++) {
			free_valuestring(webshell_detect.webshell_rule[m].regex);
			free_valuestring(webshell_detect.webshell_rule[m].description);
		}
		sniper_free(webshell_detect.webshell_rule, sizeof(struct _WEBSHELL_RULE)*count, POLICY_GET);
		sqlite3_finalize(stmt);
		sqlite3_close_v2(db);
		return -1;
	}

	/* 更新新的规则信息到新的结构体 */
	webshell_detect.rule_num = count;

	save_old_webshell_rule();
	pthread_rwlock_wrlock(&webshell_detect_global.lock);
	get_webshell_rule(&webshell_detect);
	pthread_rwlock_unlock(&webshell_detect_global.lock);

	INFO("update webshell info success\n");
	sqlite3_finalize(stmt);
	sqlite3_close_v2(db);
	return 0;
}

/* 下载规则文件 */
int download_rule_file(char *url, char *name, char *path)
{
	FILE *fp = NULL;
	int ret = 0;
	char down_url[S_LINELEN] = {0};
	int ipv6_url = 0;

	fp = fopen(path, "w");
	if (!fp) {
		MON_ERROR("fopen file %s failed:%s\n", path, strerror(errno));
		return -1;
	}

	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}
	if (ipv6_url == 1) {
		snprintf(down_url, sizeof(down_url), "%s://[%s]:%u/%s/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, url, name);
	} else {
		snprintf(down_url, sizeof(down_url), "%s://%s:%u/%s/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, url, name);
	}

	ret = download_file(down_url, fp);
	fflush(fp);
	fclose(fp);

	return ret;
}

/* 获取客户端模式 */
void get_client_mode_global(void)
{
	int ret = 0;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	/* 读取记录客户端模式的一行信息 */
	fp = sniper_fopen(CONF_INFO_FILE, "r", OTHER_GET);
	if (fp == NULL) {
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		line[S_LINELEN - 1] = 0;
		ret = sscanf(line, "客户端模式:%d", &client_mode_global);
		if (ret == 1) {
			break;
		}
	}
	sniper_fclose(fp, OTHER_GET);
}

/* 客户端模式字符串中文描述 */
static char *client_mode_global_desc(void)
{
	if (LEARNING_MODE == client_mode_global) {
		return "学习模式";
	}
	if (OPERATION_MODE == client_mode_global) {
		return "运维模式";
	}
	return "监控模式";
}

/* 客户端模式字符串英文描述 */
static char *client_mode_global_desc_en(void)
{
	if (LEARNING_MODE == client_mode_global) {
		return "learning mode";
	}
	if (OPERATION_MODE == client_mode_global) {
		return "operation and maintenance mode";
	}
	return "monitor mode";
}

/* 根据病毒防护许可删除或创建标志文件 */
static void record_avira_enable_to_file(void)
{
	int i = 0, num = 0;
	int match = 0;
	FILE *fp = NULL;

	/*
	 * 没有病毒防护许可授权时，不允许使用扫描查杀软件
	 * 通过扫描查杀软件检查文件时候存在来控制使用
	 */
	num = conf_global.module_num;
	for (i = 0; i < num; i++) {
		if (strcmp(conf_global.licence_module[i].list, "antivirus") == 0) {
			match = 1;
			break;
		}
	}

	/* 没有授权时要删除上一次记录的 */
	if (!match) {
		unlink(AVIRA_ENABLE);
		return;
	}

	fp = sniper_fopen(AVIRA_ENABLE, "w", POLICY_GET);
	if (!fp) {
		MON_ERROR("record avira enable file failed: %s\n", strerror(errno));
		return;
	}

	sniper_fclose(fp, POLICY_GET);
	return;
}

/* 记录配置信息到文件中 */
static void record_conf_to_file(void)
{
	int i = 0, num = 0;
	FILE *fp = NULL;
	FILE *fp_en = NULL;

	/* 记录中文和英文的两份文件 */
	fp = sniper_fopen(CONF_INFO_FILE, "w+", OTHER_GET);
	if (fp == NULL) {
		MON_ERROR("Update conf info to file failed\n");
		return;
	}

	fp_en = sniper_fopen(CONF_INFO_FILE_EN, "w+", OTHER_GET);
	if (fp_en == NULL) {
		MON_ERROR("Update conf info to file_en failed\n");
		sniper_fclose(fp, OTHER_GET);
		return;
	}

	fprintf(fp, "/* global */\n");
	fprintf(fp_en, "/* global */\n");
	fprintf(fp, "客户端CPU限制百分比:%d\n", conf_global.agent_cpu_limit);
	fprintf(fp_en, "client CPU limit percentage:%d\n", conf_global.agent_cpu_limit);
	fprintf(fp, "客户端内存限制(MB):%d\n", conf_global.agent_memory_limit);
	fprintf(fp_en, "client memory limit(MB):%d\n", conf_global.agent_memory_limit);
	fprintf(fp, "客户端网络限制(KB/s):%d\n", conf_global.agent_network_limit);
	fprintf(fp_en, "client network limit(KB/s):%d\n", conf_global.agent_network_limit);
	fprintf(fp, "离线日志空间大小 (默认MB单位):%d\n", conf_global.offline_space_size);
	fprintf(fp_en, "offline log space size(default MB unit):%d\n", conf_global.offline_space_size);
	fprintf(fp, "心跳间隔时长:%d\n", conf_global.heartbeat_interval);
	fprintf(fp_en, "heartbeat interval:%d\n", conf_global.heartbeat_interval);
	fprintf(fp, "日志采集模式:%d %s\n", conf_global.log_collect_mode,
		conf_global.log_collect_mode == BATCH_LOG_MODE ? "批量" : "单发");
	fprintf(fp_en, "log collection interval:%d %s\n", conf_global.log_collect_mode,
		conf_global.log_collect_mode == BATCH_LOG_MODE ? "batch" : "single");
	fprintf(fp, "批量日志发送时间间隔:%d\n", conf_global.log_collect_interval);
	fprintf(fp_en, "log collection interval:%d\n", conf_global.log_collect_interval);
	fprintf(fp, "许可是否过期:%s\n", check_my_switch_yes(conf_global.licence_expire));
	fprintf(fp_en, "license expired:%s\n", check_my_switch_yes_en(conf_global.licence_expire));
	fprintf(fp, "是否允许上传样本:%s\n", check_my_switch_yes(conf_global.allow_upload_sample));
	fprintf(fp_en, "allow uploading of samples:%s\n", check_my_switch_yes_en(conf_global.allow_upload_sample));
	fprintf(fp, "隔离文件保留空间:%d\n", conf_global.isolation_space_size);
	fprintf(fp_en, "quarantine file reserve space:%d\n", conf_global.isolation_space_size);
	fprintf(fp, "许可模块:");
	fprintf(fp_en, "licensing Module:");
	num = conf_global.module_num;
	if (num <= 0) {
		fprintf(fp, "(无)");
		fprintf(fp_en, "(null)");
	}
	for (i = 0; i < num; i++) {
		fprintf(fp, "%s;", conf_global.licence_module[i].list);
		fprintf(fp_en, "%s;", conf_global.licence_module[i].list);
	}
	fprintf(fp, "\n");
	fprintf(fp_en, "\n");

	fprintf(fp, "服务器IP:");
	fprintf(fp_en, "Server IP:");
	num = conf_global.server_num;
	if (num <= 0) {
		fprintf(fp, "(无)");
		fprintf(fp_en, "(null)");
	}
	for (i = 0; i < num; i++) {
		fprintf(fp, "%s;", conf_global.server_ip[i].list);
		fprintf(fp_en, "%s;", conf_global.server_ip[i].list);
	}
	fprintf(fp, "\n");
	fprintf(fp_en, "\n");

	fprintf(fp, "/* asset */\n");
	fprintf(fp_en, "/* asset */\n");
	fprintf(fp, "周期 默认按天为单位:%d\n", conf_asset.cycle);
	fprintf(fp_en, "cycle Default is days:%d\n", conf_asset.cycle);
	fprintf(fp, "  采集项:");
	fprintf(fp_en, "  collection item:");
	num = conf_asset.num;
	if (num <= 0) {
		fprintf(fp, "(无)");
		fprintf(fp_en, "(null)");
	}
	for (i = 0; i < conf_asset.num; i++) {
		fprintf(fp, "%s;", conf_asset.collect_items[i].name);
		fprintf(fp_en, "%s;", conf_asset.collect_items[i].name);
	}
	fprintf(fp, "\n");
	fprintf(fp_en, "\n");

	fprintf(fp, "/* policy */\n");
	fprintf(fp_en, "/* policy */\n");
	fprintf(fp, "策略ID:%s\n", conf_policy.policy_id);
	fprintf(fp_en, "policy ID:%s\n", conf_policy.policy_id);
	fprintf(fp, "策略名称:%s\n", conf_policy.policy_name);
	fprintf(fp_en, "policy name:%s\n", conf_policy.policy_name);
	fprintf(fp, "策略更新时间:%s\n", conf_policy.policy_time);
	fprintf(fp_en, "policy update time:%s\n", conf_policy.policy_time);

	fprintf(fp, "/* other */\n");
	fprintf(fp_en, "/* other */\n");
	fprintf(fp, "客户端版本号:%s\n", client_ver_global);
	fprintf(fp_en, "client version:%s\n", client_ver_global);
	fprintf(fp, "客户端EDR采集器版本号:%s\n", collect_ver_global);
	fprintf(fp_en, "client EDR collector version:%s\n", collect_ver_global);
#ifdef USE_AVIRA
	fprintf(fp, "病毒库版本号:%s\n", virus_lib_ver_global);
	fprintf(fp_en, "virus database version:%s\n", virus_lib_ver_global);
	fprintf(fp, "防病毒程序版本号:%s\n", antivirus_ver_global);
	fprintf(fp_en, "antivirus process version:%s\n", antivirus_ver_global);
#endif
	fprintf(fp, "漏洞平台版本号:%s\n", vuln_ver_global);
	fprintf(fp_en, "vulnerable platform version:%s\n", vuln_ver_global);
	fprintf(fp, "基线版本号:%s\n", baseline_ver_global);
	fprintf(fp_en, "baseline version:%s\n", baseline_ver_global);
	fprintf(fp, "webshell版本号:%s\n", webshell_ver_global);
	fprintf(fp_en, "webshell version:%s\n", webshell_ver_global);
	fprintf(fp, "弱口令版本号:%s\n", weak_passwd_ver_global);
	fprintf(fp_en, "weak password version:%s\n", weak_passwd_ver_global);
	fprintf(fp, "ip库版本号:%s\n", ipwry_ver_global);
	fprintf(fp_en, "ip database version:%s\n", ipwry_ver_global);
	fprintf(fp, "暴力密码库版本号:%s\n", crack_ver_global);
	fprintf(fp_en, "linux crack database version:%s\n", crack_ver_global);
	fprintf(fp, "客户端模式:%d %s\n", client_mode_global, client_mode_global_desc());
	fprintf(fp_en, "client mode:%d %s\n", client_mode_global, client_mode_global_desc_en());
	fprintf(fp, "卸载状态:%d\n", is_uninstall_global);
	fprintf(fp_en, "uninstall status:%d\n", is_uninstall_global);
	fprintf(fp, "隔离状态:%d\n", qr_status_global);
	fprintf(fp_en, "quarantine status:%d\n", qr_status_global);
	fprintf(fp, "同步状态:%d\n", is_sync_global);
	fprintf(fp_en, "sync status:%d\n", is_sync_global);

	fflush(fp);
	fflush(fp_en);
	sniper_fclose(fp, OTHER_GET);
	sniper_fclose(fp_en, OTHER_GET);
}

/* 释放配置信息中global结构体开辟的空间 */
static void free_conf_global_ptr(struct _GLOBAL_CONF *global_conf)
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

/* 释放配置信息中asset结构体开辟的空间 */
static void free_conf_asset_ptr(struct _ASSET_CONF *asset_conf)
{
	int i = 0, num = 0, len = 0;

	num = asset_conf->num;
	for (i = 0; i < num; i++) {
		free_valuestring(asset_conf->collect_items[i].name);
	}
	len = sizeof(struct _CONF_COLLECT_ITEMS) * num;
	sniper_free(asset_conf->collect_items, len, POLICY_GET);
	asset_conf->num = 0;
}

/* 释放配置信息中policy信息开辟的空间 */
static void free_conf_policy_ptr(struct _POLICY_CONF *policy_conf)
{
	free_valuestring(policy_conf->policy_id);
	free_valuestring(policy_conf->policy_name);
	free_valuestring(policy_conf->policy_time);
}

/* 保存当前的配置信息中的global信息给旧的全局变量 */
static void save_old_global_conf(void)
{
	free_conf_global_ptr(&old_conf_global);
	old_conf_global = conf_global;
}

/* 把当前获取的配置信息中的global信息赋值给新的全局变量 */
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

/* 保存当前的配置信息中的asset信息给旧的全局变量 */
static void save_old_asset_conf(void)
{
	free_conf_asset_ptr(&old_conf_asset);
	old_conf_asset = conf_asset;
}

/* 把当前获取的配置信息中的asset信息赋值给新的全局变量 */
static int get_asset_conf(struct _ASSET_CONF *asset_conf)
{
	conf_asset.cycle = asset_conf->cycle;
	conf_asset.num = asset_conf->num;
	conf_asset.collect_items = asset_conf->collect_items;

	return 0;
}

/* 保存当前的配置信息中的policy信息给旧的全局变量 */
static void save_old_policy_conf(void)
{
	free_conf_policy_ptr(&old_conf_policy);
	old_conf_policy = conf_policy;
}

/* 把当前获取的配置信息中的policy信息赋值给新的全局变量 */
static int get_policy_conf(struct _POLICY_CONF *policy_conf)
{
	conf_policy.policy_id = policy_conf->policy_id;
	conf_policy.policy_name = policy_conf->policy_name;
	conf_policy.policy_time = policy_conf->policy_time;

	return 0;
}

/* 获取配置信息中licence信息 */
static int get_conf_global_licence_module(cJSON *licence_module, struct _GLOBAL_CONF *global_conf)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(licence_module);
	global_conf->module_num = num;
	global_conf->licence_module = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (global_conf->licence_module == NULL) {
		MON_ERROR("global_conf->licence_module malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(licence_module, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem global_conf licence_module[%d] array error\n",i);
			for (j = 0; j < i; j++) {
				free_valuestring(global_conf->licence_module[j].list);
			}
			sniper_free(global_conf->licence_module, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("global_conf->licence_module[%d].list malloc failed\n", i);
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

/* 获取配置信息中server ip信息 */
static int get_conf_global_server_ip(cJSON *server_ip, struct _GLOBAL_CONF *global_conf)
{
	int i = 0, j = 0, num = 0;
	cJSON *arrayItem;
	char *buf = NULL;

	num = cJSON_GetArraySize(server_ip);
	global_conf->server_num = num;
	global_conf->server_ip = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (global_conf->server_ip == NULL) {
		MON_ERROR("global_conf->server_ip malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(server_ip, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem global_conf server_ip[%d] array error\n",i);
			for (j = 0; j < i; j++) {
				free_valuestring(global_conf->server_ip[j].list);
			}
			sniper_free(global_conf->server_ip, sizeof(struct _POLICY_LIST)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("global_conf->server_ip[%d].list malloc failed\n", i);
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

/* 获取配置信息中global信息 */
static int get_conf_global(cJSON *data, struct _GLOBAL_CONF *global_conf)
{
	cJSON *global;
	cJSON *agent_cpu_limit, *offline_space_size, *heartbeat_interval;
	cJSON *log_collect_mode, *licence_expire, *log_collect_interval, *allow_upload_sample, *isolation_space_size;
	cJSON *agent_memory_limit, *agent_network_limit, *server_ip, *licence_module;

	global = cJSON_GetObjectItem(data, "global");
	if (!global) {
		MON_ERROR("conf cJSON_Parse global error\n");
		return -1;
	}

	/* 客户端CPU限制百分比 */
	agent_cpu_limit = cJSON_GetObjectItem(global, "agent_cpu_limit");
	if (!agent_cpu_limit) {
		MON_WARNING("conf cJSON_Parse global agent_cpu_limit error\n");
	} else {
		global_conf->agent_cpu_limit = agent_cpu_limit->valueint;
	}

	/* 客户端内存限制(MB) */
	agent_memory_limit = cJSON_GetObjectItem(global, "agent_memory_limit");
	if (!agent_memory_limit) {
		MON_WARNING("conf cJSON_Parse global agent_memory_limit error\n");
	} else {
		global_conf->agent_memory_limit = agent_memory_limit->valueint;
	}

	/* 客户端网络限制(KB/s) */
	agent_network_limit = cJSON_GetObjectItem(global, "agent_network_limit");
	if (!agent_network_limit) {
		MON_WARNING("conf cJSON_Parse global agent_network_limit error\n");
	} else {
		global_conf->agent_network_limit = agent_network_limit->valueint;
	}

	/* 离线日志空间大小 (默认MB单位) */
	offline_space_size = cJSON_GetObjectItem(global, "offline_space_size");
	if (!offline_space_size) {
		MON_WARNING("conf cJSON_Parse global offline_space_size error\n");
	} else {
		global_conf->offline_space_size = offline_space_size->valueint;
	}

	/* 心跳间隔时长 */
	heartbeat_interval = cJSON_GetObjectItem(global, "heartbeat_interval");
	if (!heartbeat_interval) {
		MON_WARNING("conf cJSON_Parse global heartbeat_interval error\n");
	} else {
		global_conf->heartbeat_interval = heartbeat_interval->valueint;
	}

	/* 日志采集模式 */
	log_collect_mode = cJSON_GetObjectItem(global, "log_collect_mode");
	if (!log_collect_mode) {
		MON_WARNING("conf cJSON_Parse global log_collect_mode error\n");
	} else {
		global_conf->log_collect_mode = log_collect_mode->valueint;
	}

	/* 批量日志发送时间间隔 */
	log_collect_interval = cJSON_GetObjectItem(global, "log_collect_interval");
	if (!log_collect_interval) {
		MON_WARNING("conf cJSON_Parse global log_collect_interval error\n");
	} else {
		global_conf->log_collect_interval = log_collect_interval->valueint;
	}

	/* 许可是否过期 */
	licence_expire = cJSON_GetObjectItem(global, "licence_expire");
	if (!licence_expire) {
		MON_WARNING("conf cJSON_Parse global licence_expire error\n");
	} else {
		global_conf->licence_expire = licence_expire->valueint;
	}

	/* 是否允许上传样本 */
	allow_upload_sample = cJSON_GetObjectItem(global, "allow_upload_sample");
	if (!allow_upload_sample) {
		MON_WARNING("conf cJSON_Parse global allow_upload_sample error\n");
	} else {
		global_conf->allow_upload_sample = allow_upload_sample->valueint;
	}

	/* 客户端隔离文件保留空间 */
	isolation_space_size = cJSON_GetObjectItem(global, "isolation_space_size");
	if (!isolation_space_size) {
		MON_WARNING("conf cJSON_Parse global isolation_space_size error\n");
	} else {
		global_conf->isolation_space_size = isolation_space_size->valueint;
	}

	/* 多管控ip */
	server_ip = cJSON_GetObjectItem(global, "server_ip");
	if (!server_ip) {
		MON_WARNING("conf cJSON_Parse global server_ip error\n");
		global_conf->server_num = 0;
	} else {
		if (get_conf_global_server_ip(server_ip, global_conf) < 0) {
			global_conf->server_num = 0;
		}
	}

	/* 许可模块 */
	licence_module = cJSON_GetObjectItem(global, "licence_module");
	if (!licence_module) {
		MON_WARNING("conf cJSON_Parse global licence_module error\n");
		global_conf->module_num = 0;
	} else {
		if (get_conf_global_licence_module(licence_module, global_conf) < 0) {
			global_conf->module_num = 0;
		}
	}

	return 0;
}

/* 获取配置信息中asset信息 */
static int get_conf_asset(cJSON *data, struct _ASSET_CONF *asset_conf)
{
	cJSON *asset;
	cJSON *cycle, *collect_items, *arrayItem;
	int i = 0, j = 0, num = 0;
	char *buf = NULL;

	asset = cJSON_GetObjectItem(data, "asset");
	if (!asset) {
		MON_ERROR("conf cJSON_Parse asset error\n");
		return -1;
	}

	/* 周期 */
	cycle = cJSON_GetObjectItem(asset, "cycle");
	if (!cycle) {
		MON_ERROR("conf cJSON_Parse asset cycle error\n");
		return -1;
	}
	asset_conf->cycle = cycle->valueint;

	/* 采集项 */
	collect_items = cJSON_GetObjectItem(asset, "collect_items");
	if (!collect_items) {
		MON_ERROR("conf cJSON_Parse global collect_items error\n");
		return -1;
	}

	num = cJSON_GetArraySize(collect_items);
	asset_conf->num = num;
	asset_conf->collect_items = (struct _CONF_COLLECT_ITEMS*)sniper_malloc(sizeof(struct _CONF_COLLECT_ITEMS)*num, POLICY_GET);
	if (asset_conf->collect_items == NULL) {
		MON_ERROR("asset_conf->collect_items malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(collect_items, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem asset_conf collect_items[%d] array error\n",i);
			for (j = 0; j < i; j++) {
				free_valuestring(asset_conf->collect_items[j].name);
			}
			sniper_free(asset_conf->collect_items, sizeof(struct _CONF_COLLECT_ITEMS)*num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("asset_conf->collect_items[%d].name malloc failed\n", i);
			for (j = 0; j < i; j++) {
				free_valuestring(asset_conf->collect_items[j].name);
			}
			sniper_free(asset_conf->collect_items, sizeof(struct _CONF_COLLECT_ITEMS)*num, POLICY_GET);
			return -1;
		}
		asset_conf->collect_items[i].name = buf;

	}

	return 0;
}

/* 获取配置信息中policy信息 */
static int get_conf_policy(cJSON *data, struct _POLICY_CONF *policy_conf)
{
	cJSON *policy ;
	cJSON *policy_id, *policy_name, *policy_time;
	char *buf = NULL;

	policy = cJSON_GetObjectItem(data, "policy");
	if (!policy) {
		MON_ERROR("conf cJSON_Parse policy error\n");
		return -1;
	}

	/* 策略ID */
	policy_id = cJSON_GetObjectItem(policy, "policy_id");
	if (!policy_id) {
		MON_ERROR("conf cJSON_Parse policy policy_id error\n");
		return -1;
	}

	buf = get_my_valuestring(policy_id);
	if (buf == NULL) {
		MON_ERROR("policy_conf->policy_id malloc failed\n");
		return -1;
	}
	policy_conf->policy_id = buf;

	/* 策略名称 */
	policy_name = cJSON_GetObjectItem(policy, "policy_name");
	if (!policy_name) {
		MON_ERROR("conf cJSON_Parse policy policy_name error\n");
		return -1;
	}

	buf = get_my_valuestring(policy_name);
	if (buf == NULL) {
		MON_ERROR("policy_conf->policy_name malloc failed\n");
		return -1;
	}
	policy_conf->policy_name = buf;

	/* 策略更新时间 */
	policy_time = cJSON_GetObjectItem(policy, "policy_time");
	if (!policy_time) {
		MON_ERROR("conf cJSON_Parse policy policy_time error\n");
		return -1;
	}

	buf = get_my_valuestring(policy_time);
	if (buf == NULL) {
		MON_ERROR("policy_conf->policy_time malloc failed\n");
		return -1;
	}
	policy_conf->policy_time = buf;

	return 0;
}

/* 获取配置信息中md5信息 */
static int get_conf_md5(cJSON *data, struct _MD5_CONF *md5_conf)
{
	cJSON *md5 ;
	cJSON *weak_passwd_ver_md5, *ipwry_ver_md5;
	cJSON *baseline_ver_md5, *webshell_ver_md5, *virus_lib_ver_md5, *conf_ver_md5;

	md5 = cJSON_GetObjectItem(data, "md5");
	if (!md5) {
		MON_ERROR("conf cJSON_Parse md5 error\n");
		return -1;
	}

	/* 弱口令MD5 */
	weak_passwd_ver_md5 = cJSON_GetObjectItem(md5, "weak_passwd_ver_md5");
	if (!weak_passwd_ver_md5) {
		MON_WARNING("conf cJSON_Parse md5 weak_passwd_ver_md5 error\n");
	} else {
		snprintf(md5_conf->weak_passwd_md5, sizeof(md5_conf->weak_passwd_md5), "%s", weak_passwd_ver_md5->valuestring);
	}

	/* ip库MD5*/
	ipwry_ver_md5 = cJSON_GetObjectItem(md5, "ipwry_ver_md5");
	if (!ipwry_ver_md5) {
		MON_WARNING("conf cJSON_Parse md5 ipwry_ver_md5 error\n");
	} else {
		snprintf(md5_conf->ipwry_ver_md5, sizeof(md5_conf->ipwry_ver_md5), "%s", ipwry_ver_md5->valuestring);
	}

	/* 基线库MD5 */
	baseline_ver_md5 = cJSON_GetObjectItem(md5, "baseline_ver_md5");
	if (!baseline_ver_md5) {
		MON_WARNING("conf cJSON_Parse md5 baseline_ver_md5 error\n");
	} else {
		snprintf(md5_conf->baseline_ver_md5, sizeof(md5_conf->baseline_ver_md5), "%s", baseline_ver_md5->valuestring);
	}

	/* 暴力破解配置库MD5 */
	conf_ver_md5 = cJSON_GetObjectItem(md5, "crack_conf_ver");
	if (!conf_ver_md5) {
		MON_WARNING("conf cJSON_Parse md5 crack_conf_ver error\n");
	} else {
		snprintf(md5_conf->crack_ver_md5, sizeof(md5_conf->crack_ver_md5), "%s", conf_ver_md5->valuestring);
	}

	/* webshell正则规则库MD5 */
	webshell_ver_md5 = cJSON_GetObjectItem(md5, "webshell_ver_md5");
	if (!webshell_ver_md5) {
		MON_WARNING("conf cJSON_Parse md5 webshell_ver_md5 error\n");
	} else {
		snprintf(md5_conf->webshell_ver_md5, sizeof(md5_conf->webshell_ver_md5), "%s", webshell_ver_md5->valuestring);
	}

	/* 病毒库MD5 */
	virus_lib_ver_md5 = cJSON_GetObjectItem(md5, "virus_lib_ver_md5");
	if (!virus_lib_ver_md5) {
		MON_WARNING("conf cJSON_Parse md5 virus_lib_ver_md5 error\n");
	} else {
		snprintf(md5_conf->virus_lib_ver_md5, sizeof(md5_conf->virus_lib_ver_md5), "%s", virus_lib_ver_md5->valuestring);
	}

	return 0;
}

/* 发送客户端模式给内核 */
static void update_kernel_client_mode(void)
{
	int data = 0;

	if (client_mode_global < NORMAL_MODE || client_mode_global > LEARNING_MODE) {
		MON_ERROR("bad client mode %d\n", client_mode_global);
		return;
	}

	data = client_mode_global;

	if (send_data_to_kern(NLMSG_CLIENT_MODE, (char *)&data, sizeof(int)) < 0) {
		MON_ERROR("set kern client mode to %d fail\n", client_mode_global);
	}
}

#ifdef USE_AVIRA
/* 安装病毒库 */
void install_virus_lib(char *virus_lib_ver, MD5_CONF *conf)
{
	FILE *fp = NULL;
	int ret = 0;

	/* md5值或版本号缺一不可 */
	if (conf->virus_lib_ver_md5[0] == 0 || virus_lib_ver[0] == 0) {
		return;
	}

	/*
	 * 第一次启动没有文件可读，后面比较就会从管控下载
	 * 已经更新过病毒库后客户端重新上线，读取之前的记录再检查是否需要下载
	 */
	if (virus_lib_ver_global[0] == 0) {
		fp = fopen(VIRUSLIB_VERSION_FILE, "r");
		if (fp) {
			fgets(virus_lib_ver_global, sizeof(virus_lib_ver_global), fp);
			virus_lib_ver_global[VER_LEN_MAX - 1] = 0;
			fclose(fp);
		}
	}

	/* 防止重复下载 */
	if (strcmp(virus_lib_ver_global, virus_lib_ver) == 0) {
		send_sync_info(SYNC_VIRUS_LIB_VER, virus_lib_ver_global);
		return;
	}

	ret = update_virus_lib(virus_lib_ver, conf->virus_lib_ver_md5);
	if (ret == 0) {
		send_sync_info(SYNC_VIRUS_LIB_VER, virus_lib_ver_global);
	}
}

/* 获取防病毒程序的版本 */
void get_antivirus_ver(void)
{
	FILE *fp = NULL;

	if (antivirus_ver_global[0] == 0) {
		fp = fopen(ANTIVIRUS_VERSION_FILE, "r");
		if (fp) {
			fgets(antivirus_ver_global, sizeof(antivirus_ver_global), fp);
			antivirus_ver_global[VER_LEN_MAX - 1] = 0;
			fclose(fp);
		} else {
			snprintf(antivirus_ver_global, sizeof(antivirus_ver_global), "%s", ANTIVIRUS_VER);
		}
	}

	send_sync_info(SYNC_ANTIVIRUS_VER, antivirus_ver_global);
}
#endif

/* 校验版本号，下载库文件, 0表示成功，-1表示失败*/
int check_download_lib(cJSON *data, struct _lib_info *info, char *global_ver, int global_ver_len)
{
	cJSON *version;

	char ver[VER_LEN_MAX] = {0};
	char file[PATH_MAX] = {0};
	char file_bak[PATH_MAX] = {0};
	char download_name[S_NAMELEN] = {0};
	char md5[S_MD5LEN] = {0};
	int ret = 0;
	int first_match = 0;
	FILE *fp = NULL;
	struct stat st = {0};

	if (!data || !info || !global_ver) {
		return -1;
	}

	version = cJSON_GetObjectItem(data, info->key);
	if (version == NULL || version->valuestring == NULL) {
		MON_ERROR("conf reply get %s version data error: not found\n", info->key);
		return -1;
	}

	snprintf(ver, sizeof(ver), "%s", version->valuestring);

	/* 缺少MD5或者版本号则不下载 */
	if (ver[0] == '\0' || info->md5[0] == '\0') {
		MON_ERROR("%s version or md5 is empty \n", info->name);
		return -1;
	}

	if (global_ver[0] == '\0') {
		fp = sniper_fopen(info->ver_file, "r", POLICY_GET);
		if (fp) {
			fgets(global_ver, sizeof(global_ver), fp);
			global_ver[VER_LEN_MAX - 1] = 0;
			sniper_fclose(fp, POLICY_GET);
			first_match = 1;
		}
	}

	/* 第一次获取本地文件记录到的版本号返回成功 */
	if (strcmp(global_ver, ver) == 0) {
		if (first_match == 1) {
			save_lib_version(info->ver_file, ver);
			send_sync_info(info->type, global_ver);
			return 0;
		}
		return -1;
	}


	INFO("download %s lib with version %s\n", info->name, ver);
	snprintf(download_name, sizeof(download_name), "%s%s%s",
			thestring(info->name), thestring(ver), thestring(info->suffix));
	snprintf(file, sizeof(file), "%s%s.dat", DOWNLOAD_DIR, info->name);
	snprintf(file_bak, sizeof(file_bak), "%s.bak", thestring(file));

	ret = download_rule_file(info->url, download_name, file_bak);
	if (ret < 0) {
		MON_ERROR("download %s lib failed\n", info->name);
		return -1;
	}

	if (stat(file_bak, &st) < 0) {
		MON_ERROR("get %s lib stat failed\n", info->name);
		return -1;
	}

	if (md5_file(file_bak, md5) < 0) {
		MON_ERROR("get %s lib md5 failed\n", info->name);
		return -1;
	}

	/* 下载的地址不对，返回的错误信息会生成文件 */
	if (strcmp(md5, "597ba0d4396e9c906225140ce907092c") == 0) {
		MON_ERROR("download %s lib url error\n", info->name);
		return -1;
	}

	/* 下载的文件小于200字节, 小于库文件大小(暴力密码破解配置文件可能会很小)，报下载报错 */
	if (st.st_size < 200 &&
	    strcmp(info->name, "linux-crack") != 0) {
		MON_ERROR("incorrect %s lib downloaded\n", info->name);
		return -1;
	}

	if (strcmp(md5, info->md5) != 0) {
		MON_ERROR("%s lib md5(%s) check error\n", info->name, md5);
		return -1;
	}

	if (rename(file_bak, file) < 0) {
		MON_ERROR("%s file rename error\n", info->name);
		return -1;
	}

	save_lib_version(info->ver_file, ver);
	snprintf(global_ver, global_ver_len, "%s", ver);
	send_sync_info(info->type, global_ver);

	return 0;
}

/* 解析配置返回的信息 */
static int parse_conf_resp(char *reply)
{
	cJSON *json, *data;
	cJSON *client_version, *collect_version, *vuln_version;
	cJSON *uninstall, *status, *sync, *operation;

	task_recv_t msg = {0};
	int is_uninstall = 0, qr_status = 0, is_sync = 0, operation_mode = 0;
	char client_ver[VER_LEN_MAX] = {0};
	char collect_ver[VER_LEN_MAX] = {0};
	char vuln_ver[VER_LEN_MAX] = {0};

	struct _lib_info webshell_lib = {{0}};
	struct _lib_info baseline_lib = {{0}};
	struct _lib_info ipwry_lib = {{0}};
	struct _lib_info weakpasswd_lib = {{0}};
	struct _lib_info crack_lib = {{0}};

#ifdef USE_AVIRA
	char virus_lib_ver[VER_LEN_MAX] = {0};
	cJSON *virus_version;
	cJSON *virus_lib_version;
#endif

	GLOBAL_CONF global_conf = {0};
	ASSET_CONF asset_conf = {0};
	POLICY_CONF policy_conf = {0};
	MD5_CONF md5_conf = {{0}};

	snprintf(msg.cmd_id, sizeof(msg.cmd_id), "nottask"); //共用任务处理函数，但不发任务应答消息

	json = cJSON_Parse(reply);
	if (!json) {
		MON_ERROR("parse conf reply fail: %s\n", cJSON_GetErrorPtr());
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("conf reply get data error: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(json);
		return -1;
	}

	uninstall = cJSON_GetObjectItem(data, "is_uninstall");
	if (!uninstall) {
		MON_WARNING("conf reply get data is_uninstall error\n");
	} else {
		is_uninstall = uninstall->valueint;
		is_uninstall_global = is_uninstall;
	}

	/* 根据配置上的策略信息决定是否卸载 */
	if (is_uninstall_global == 1) {
		INFO("conf uninstall client\n");
		msg.cmd_type = TASK_UNINSTALL;
		uninstall_sniper(&msg);
	}

	client_version = cJSON_GetObjectItem(data, "client_ver");
	if (client_version == NULL || client_version->valuestring == NULL) {
		MON_WARNING("conf reply get data client_ver error\n");
	} else {
		snprintf(client_ver, sizeof(client_ver), "%s", client_version->valuestring);
		snprintf(client_ver_global, sizeof(client_ver_global), "%s", client_ver);
	}

	/* 根据配置上的版本信息决定是否升级 */
	if (strcmp(client_ver_global, Sys_info.version) != 0) {
		INFO("conf update client to %s\n", client_ver_global);
		msg.cmd_type = TASK_UPDATE_CLIENT;
		snprintf(msg.new_version, sizeof(msg.new_version), "%s", client_ver_global);
		update_client(&msg);
		cJSON_Delete(json);
		return 0;
	}

	collect_version = cJSON_GetObjectItem(data, "collect_ver");
	if (collect_version == NULL || collect_version->valuestring == NULL) {
		MON_WARNING("conf reply get data collect_ver error\n");
	} else {
		snprintf(collect_ver, sizeof(collect_ver), "%s", collect_version->valuestring);
	}

	/* 获取要下载的库文件的md5, 用于校验*/
	get_conf_md5(data, &md5_conf);

	vuln_version = cJSON_GetObjectItem(data, "vuln_ver");
	if (vuln_version == NULL || vuln_version->valuestring == NULL) {
		MON_WARNING("conf reply get data vuln_ver error\n");
	} else {
		snprintf(vuln_ver, sizeof(vuln_ver), "%s", vuln_version->valuestring);
		snprintf(vuln_ver_global, sizeof(vuln_ver_global), "%s", vuln_ver);
	}

	/* 弱密码库 */
	snprintf(weakpasswd_lib.name, sizeof(weakpasswd_lib.name), "%s", "weakpwd");
	snprintf(weakpasswd_lib.suffix, sizeof(weakpasswd_lib.suffix), "%s", ".dat");
	snprintf(weakpasswd_lib.url, sizeof(weakpasswd_lib.url), "%s", DOWNLOAD_RULE_URL);
	snprintf(weakpasswd_lib.md5, sizeof(weakpasswd_lib.md5), "%s", md5_conf.weak_passwd_md5);
	snprintf(weakpasswd_lib.key, sizeof(weakpasswd_lib.key), "%s", "weak_passwd_ver");
	snprintf(weakpasswd_lib.ver_file, sizeof(weakpasswd_lib.ver_file), "%s", WEAKPASSWD_VERSION_FILE);
	weakpasswd_lib.type = SYNC_WEAK_PASSWD_VER;
	check_download_lib(data, &weakpasswd_lib, weak_passwd_ver_global, sizeof(weak_passwd_ver_global));

	/* IP库 */
	snprintf(ipwry_lib.name, sizeof(ipwry_lib.name), "%s", "ipwry");
	snprintf(ipwry_lib.suffix, sizeof(ipwry_lib.suffix), "%s", ".dat");
	snprintf(ipwry_lib.url, sizeof(ipwry_lib.url), "%s", DOWNLOAD_RULE_URL);
	snprintf(ipwry_lib.md5, sizeof(ipwry_lib.md5), "%s", md5_conf.ipwry_ver_md5);
	snprintf(ipwry_lib.key, sizeof(ipwry_lib.key), "%s", "ipwry_ver");
	snprintf(ipwry_lib.ver_file, sizeof(ipwry_lib.ver_file), "%s", IPWRY_VERSION_FILE);
	ipwry_lib.type = SYNC_IPWRY_VER;
	check_download_lib(data, &ipwry_lib, ipwry_ver_global, sizeof(ipwry_ver_global));

	/* 基线库 */
	snprintf(baseline_lib.name, sizeof(baseline_lib.name), "%s", "baseline");
	snprintf(baseline_lib.suffix, sizeof(baseline_lib.suffix), "%s", ".dat");
	snprintf(baseline_lib.url, sizeof(baseline_lib.url), "%s", DOWNLOAD_RULE_URL);
	snprintf(baseline_lib.md5, sizeof(baseline_lib.md5), "%s", md5_conf.baseline_ver_md5);
	snprintf(baseline_lib.key, sizeof(baseline_lib.key), "%s", "baseline_ver");
	snprintf(baseline_lib.ver_file, sizeof(baseline_lib.ver_file), "%s", BASELINE_VERSION_FILE);
	baseline_lib.type = SYNC_BASELINE_VER;
	check_download_lib(data, &baseline_lib, baseline_ver_global, sizeof(baseline_ver_global));

	/* 930之前版本没有webshell库, 默认不处理 */
	snprintf(webshell_lib.name, sizeof(webshell_lib.name), "%s", "webshell");
	snprintf(webshell_lib.suffix, sizeof(webshell_lib.suffix), "%s", ".dat");
	snprintf(webshell_lib.url, sizeof(webshell_lib.url), "%s", DOWNLOAD_RULE_URL);
	snprintf(webshell_lib.md5, sizeof(webshell_lib.md5), "%s", md5_conf.webshell_ver_md5);
	snprintf(webshell_lib.key, sizeof(webshell_lib.key), "%s", "webshell_ver");
	snprintf(webshell_lib.ver_file, sizeof(webshell_lib.ver_file), "%s", WEBSHELL_VERSION_FILE);
	webshell_lib.type = SYNC_WEBSHELL_VER;
	if(check_download_lib(data, &webshell_lib, webshell_ver_global, sizeof(webshell_ver_global)) == 0) {
		update_webshell_info(WEBSHELL_FILE);
	}

#ifdef USE_AVIRA
	virus_version = cJSON_GetObjectItem(data, "virus_ver");
	if (virus_version == NULL || virus_version->valuestring == NULL) {
		MON_WARNING("conf reply get data virus_ver error\n");
	} else {

		/* 防病毒程序是安装包自带，无需安装 */
		get_antivirus_ver();
	}

	virus_lib_version = cJSON_GetObjectItem(data, "virus_lib_ver");
	if (virus_lib_version == NULL || virus_lib_version->valuestring == NULL) {
		MON_WARNING("conf reply get data virus_lib_ver error\n");
	} else {
		/*
		 * 版本号分为两种情况，5.0.9之前为anti-5.0.8.0705-lib.zip
		 * 5.0.9及之后为5.0.8.0705
		 * 兼容旧的管控，统一提取为5.0.8.0705
		 */
		if (strstr(virus_lib_version->valuestring, "anti-") != NULL) {
			extract_virus_version(virus_lib_version->valuestring, virus_lib_ver);
		} else {
			snprintf(virus_lib_ver, sizeof(virus_lib_ver), "%s", virus_lib_version->valuestring);
		}

		/* 安装病毒库 */
		install_virus_lib(virus_lib_ver, &md5_conf);
	}
#endif

	/* 暴力密码库 */
	snprintf(crack_lib.name, sizeof(crack_lib.name), "%s", "linux-crack");
	snprintf(crack_lib.suffix, sizeof(crack_lib.suffix), "%s", ".zip");
	snprintf(crack_lib.url, sizeof(crack_lib.url), "%s", DOWNLOAD_CONF_URL);
	snprintf(crack_lib.md5, sizeof(crack_lib.md5), "%s", md5_conf.crack_ver_md5);
	snprintf(crack_lib.key, sizeof(crack_lib.key), "%s", "crack_conf_ver");
	snprintf(crack_lib.ver_file, sizeof(crack_lib.ver_file), "%s", CRACK_VERSION_FILE);
	crack_lib.type = SYNC_CRACK_VER;
	check_download_lib(data, &crack_lib, crack_ver_global, sizeof(crack_ver_global));

	operation = cJSON_GetObjectItem(data, "operation_mode");
	if (!operation) {
		MON_WARNING("conf reply get data operation_mode error\n");
	} else {
		operation_mode = operation->valueint;
		client_mode_global = operation_mode;
	}

	status = cJSON_GetObjectItem(data, "qr_status");
	if (!status) {
		MON_WARNING("conf reply get data qr_status error\n");
	} else {
		qr_status = status->valueint;
		qr_status_global = qr_status;
	}

	sync = cJSON_GetObjectItem(data, "is_sync");
	if (!sync) {
		MON_WARNING("conf reply get data is_sync error\n");
	} else {
		is_sync = sync->valueint;
		is_sync_global = is_sync;
	}

	/*赋值到全局变量中*/
	get_conf_global(data, &global_conf);
	save_old_global_conf();
	pthread_rwlock_wrlock(&conf_global.lock);
	get_global_conf(&global_conf);
	pthread_rwlock_unlock(&conf_global.lock);
	/* 在配置下发的时候控制学习模式下始终允许上传样本，判断的时候只看上传样本的值就可以了 */
	if (LEARNING_MODE == client_mode_global) {
		conf_global.allow_upload_sample = 1;
	}

	if (get_conf_asset(data, &asset_conf) < 0) {
		asset_conf.num = 0;
	}
	save_old_asset_conf();
	pthread_rwlock_wrlock(&conf_asset.lock);
	get_asset_conf(&asset_conf);
	pthread_rwlock_unlock(&conf_asset.lock);

	get_conf_policy(data, &policy_conf);
	save_old_policy_conf();
	pthread_rwlock_wrlock(&conf_policy.lock);
	get_policy_conf(&policy_conf);
	pthread_rwlock_unlock(&conf_policy.lock);

	//* 有病毒防护许可模块，记录病毒防护标志文件*/
	record_avira_enable_to_file();

	/* 每次更新配置成功后记录到文件中 */
	record_conf_to_file();

	/* 更新资产清点配置 */
	update_asset_conf();

	/* 发送客户端模式至内核 */
#if 0
	update_kernel_client_mode();
#else
	// NOTE(luoyinhong): nothing to send to kernel
#endif

	/* 根据配置上的策略信息决定是否更新策略 */
	if (conf_policy.policy_time != NULL &&
	    strcmp(conf_policy.policy_time, policy_time_cur) != 0) {
		msg.cmd_type = TASK_UPDATE_POLICY;
		update_policy_my(&msg);
	}

	cJSON_Delete(json);
	return 0;
}

/* 解析本地记录的配置信息(上一次成功返回的) */
static int parse_conf_local(char *string)
{
	cJSON *json, *data;
	cJSON *operation;

	int operation_mode = 0;

	GLOBAL_CONF global_conf = {0};

	json = cJSON_Parse(string);
	if (!json) {
		MON_ERROR("parse conf reply fail: %s\n", cJSON_GetErrorPtr());
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("conf reply get data error: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(json);
		return -1;
	}

	if (access(WEBSHELL_FILE, F_OK) == 0) {
		update_webshell_info(WEBSHELL_FILE);
	}

	operation = cJSON_GetObjectItem(data, "operation_mode");
	if (!operation) {
		MON_ERROR("conf reply get data operation_mode error: %s\n", cJSON_GetErrorPtr());
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

	/* 每次更新配置成功后记录到文件中 */
	record_conf_to_file();

	/* 发送客户端模式至内核 */
#if 0
	update_kernel_client_mode();
#else
	// NOTE(luoyinhong): nothing to send to kernel
#endif
	cJSON_Delete(json);
	return 0;
}

/*
 * 有4个场景会拉取配置：
 * 1、客户端注册时拉取最新配置
 * 2、管控下发更新配置的任务
 * 3、心跳回答里指示更新配置
 * 4、从心跳不通变成心跳通的时候强制拉取最新配置
 */
static int get_conf_nolock(char *reason, int reason_len)
{
	cJSON *object = NULL;
	char *string = NULL;
	int ret = 0;

	if (!reason) {
		return -1;
	}

	INFO("get conf info\n");

	buffer_t buffer = {0};
	buffer.len = CONF_MAX;
	buffer.data = sniper_malloc(CONF_MAX, POLICY_GET);
	buffer.pos = 0;
	if (!buffer.data) {
		snprintf(reason, reason_len, "malloc conf buffer failed!");
		MON_ERROR("malloc rule buffer failed!\n");
		return -1;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		snprintf(reason, reason_len, "cjson create object failed!");
		sniper_free(buffer.data, CONF_MAX, POLICY_GET);
		return -1;
	}

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	string = cJSON_PrintUnformatted(object);


	if (get_large_data_resp(CONF_URL, string,  &buffer) < 0) {
		snprintf(reason, reason_len, "get conf resp failed!");
		MON_ERROR("get conf resp failed!\n");
		cJSON_Delete(object);
		free(string);
		sniper_free(buffer.data, CONF_MAX, POLICY_GET);
		return -1;
	}

	if (strstr(buffer.data, "\"code\":0") != NULL) {
		/* 每次新的配置保留到文件，上线时加载本地配置需要读取 */
		dbg_record_to_file(LOGFILE, CONF_JSON, buffer.data, strlen(buffer.data));
		ret = parse_conf_resp(buffer.data);
		if (ret < 0) {
			snprintf(reason, reason_len, "conf date error");
		}
	} else {
		ret = -1;
		snprintf(reason, reason_len, "get conf info failed!");
		MON_ERROR("get conf info failed:%s\n", buffer.data);
	}

	cJSON_Delete(object);
	free(string);
	sniper_free(buffer.data, CONF_MAX, POLICY_GET);
	return ret;
}

/* 获取配置信息 */
int get_conf(char *reason, int reason_len)
{
	int ret = 0;

	pthread_mutex_lock(&conf_update_lock);
	ret = get_conf_nolock(reason, reason_len);
	pthread_mutex_unlock(&conf_update_lock);

	return ret;
}

/* 更新明焰配置 */
void update_conf_my(task_recv_t *msg)
{
	char reason[S_LINELEN] = {0};

	if (get_conf(reason, sizeof(reason)) < 0) {
		send_task_resp(msg, RESULT_FAIL, reason);
	} else {
		send_task_resp(msg, RESULT_OK, "Config Update");
	}
}

/* 加栽上一次的本地配置 */
void load_last_local_conf(void)
{
	char *buff = NULL;
	int fd = 0, bytes_read = 0;

	INFO("init local conf start\n");

	fd = sniper_open(CONF_JSON, O_RDONLY, POLICY_GET);
	if (fd < 0) {
		INFO("no local conf\n");
		return;
	}

	buff = (char*)sniper_malloc(CONF_MAX, POLICY_GET);
	if (!buff) {
		MON_ERROR("init_conf malloc fail: no memory\n");
		sniper_close(fd, POLICY_GET);
		return;
	}

	bytes_read = read(fd, buff, CONF_MAX);
	if (bytes_read < 0) {
		MON_ERROR("Read policy %s fail: %s\n", POLICY_FILE, strerror(errno));
		sniper_close(fd, POLICY_GET);
		sniper_free(buff, CONF_MAX, POLICY_GET);
		return;
	}
	sniper_close(fd, POLICY_GET);
	buff[bytes_read] = '\0';

	if (parse_conf_local(buff) < 0) {
		INFO("init local conf failed!\n");
		sniper_free(buff, CONF_MAX, POLICY_GET);
		return;
	}

	INFO("init local conf success!\n");
	sniper_free(buff, CONF_MAX, POLICY_GET);
	return;
}

/* 初始化配置结构体 */
void init_conf(void)
{
	pthread_rwlock_init(&conf_global.lock, 0);
	pthread_rwlock_init(&conf_asset.lock, 0);
	pthread_rwlock_init(&conf_policy.lock, 0);

	pthread_rwlock_init(&webshell_detect_global.lock, 0);

	pthread_mutex_init(&conf_update_lock, NULL);
}

/* 回收配置结构通开辟的资源 */
void fini_conf(void)
{
	pthread_rwlock_destroy(&conf_global.lock);
	pthread_rwlock_destroy(&conf_asset.lock);
	pthread_rwlock_destroy(&conf_policy.lock);

	pthread_rwlock_destroy(&webshell_detect_global.lock);

	pthread_mutex_destroy(&conf_update_lock);
}
