#include "header.h"
#include "net.h"
time_t last_lockip_time = 0;
struct sniper_ip last_honeyport_ip = {{0}};

static int ipstr2ip(char *ipstr, struct sniper_ip *ip)
{
	int ip0 = 0, ip1 = 0, ip2 = 0, ip3 = 0;

	if (sscanf(ipstr, "%d.%d.%d.%d", &ip0, &ip1, &ip2, &ip3) != 4) {
		return -1;
	}

	ip->ip[0] = ip0;
	ip->ip[1] = ip1;
	ip->ip[2] = ip2;
	ip->ip[3] = ip3;

	return 0;
}

/*
 * 保存被锁定ip的信息
 *  ip        被锁的对象
 *  lock_time 锁多长时间，单位秒。保存下来的值是解封的时间点now+lock_time
 *  log_name  锁ip的事件名称
 *  log_id    锁ip的事件id
 * 报告解锁日志时，要求报告触发锁定的事件名称和id，所以这里存下来
 */
static void save_lockip(char *ip, int lock_time, char *log_name, char *log_id)
{
	char dir[128] = {0};
	char ippath[512] = {0};
	FILE *fp = NULL;
	time_t now = time(NULL);

	snprintf(ippath, sizeof(ippath), "%s/%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR, ip);
	/* 忽略已经被锁的ip */
	if (access(ippath, F_OK) == 0) {
		return;
	}

	fp = fopen(ippath, "w");
	if (!fp) {
		mkdir("/opt", 0755);
		mkdir(WORKDIR, 0755);
		snprintf(dir, sizeof(dir), "%s/%s/", WORKDIR, DBDIR);
		mkdir(dir, 0700);
		snprintf(dir, sizeof(dir), "%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR);
		mkdir(dir, 0700);
		fp = fopen(ippath, "w");
		if (!fp) {
			MON_ERROR("save lockip %s fail: %s\n", ippath, strerror(errno));
			return;
		}
	}

	/*
	 * 例/opt/snipercli/.mondb/.denyip/192.168.58.150的内容如下
	 *   HoneyPort
	 *   82fa5c45-0146-409c-a382-eeef92e81d5f
	 *   1658824495
	 */
	fprintf(fp, "%s\n%s\n%lu", log_name, log_id, now+lock_time);
	fflush(fp);
	fclose(fp);
	INFO("lockip %s saved\n", ip);
}

/*
 * 下列事件会锁ip：暴力密码破解，反弹shell，端口扫描，端口诱捕
 * reason 锁ip的事件号
 */
int lock_ip(char *ip, int reason, int lock_time, char *log_name, char *log_id)
{
	struct sniper_lockip rule;
	int size = sizeof(rule);

	if (!ip) {
		return -1;
	}

	if (ipstr2ip(ip, &rule.ip) < 0) {
		MON_ERROR("lock_ip fail, invalid ip %s\n", ip);
		return -1;
	}

	INFO("lock %s, reason %s, duration %ds\n", ip, log_name, lock_time);
	save_lockip(ip, lock_time, log_name, log_id);

	rule.reason = reason;
	rule.lock_time = lock_time;

	if (send_data_to_kern(NLMSG_NET_LOCKIP, (char *)&rule, size) < 0) {
		MON_ERROR("lock ip %s fail, set kernel rule error\n");
		return -1;
	}

	return 0;
}

int unlock_ip(char *ip)
{
	struct sniper_lockip rule;
	int size = sizeof(rule), result = OPERATE_OK, ret = 0;

	if (!ip) {
		MON_ERROR("NULL ip to unlock\n");
		printf("NULL ip to unlock\n");
		return -1;
	}

	if (ipstr2ip(ip, &rule.ip) < 0) {
		MON_ERROR("unlock_ip fail, invalid ip %s\n", ip);
		printf("unlock_ip fail, invalid ip %s\n", ip);
		return -1;
	}

	rule.reason = 0;
	if (send_data_to_kern(NLMSG_NET_LOCKIP, (char *)&rule, size) < 0) {
		MON_ERROR("unlock ip %s fail, clear kernel rule error\n", ip);
		printf("unlock ip %s fail, clear kernel rule error\n", ip);
		result = OPERATE_FAIL;
		ret = -1;
	}

	send_unlockip_msg(ip, result); //发送解锁日志后再删被锁ip的记录文件

	return ret;
}

/* firstip > secondip, return 1; < return -1; = return 0 */
int sniper_ipcmp(struct sniper_ip *firstip, struct sniper_ip *secondip)
{
	int i = 0;

	for (i = 0; i < 4; i++) {
		if (firstip->ip[i] < secondip->ip[i]) {
			return -1;
		}
		if (firstip->ip[i] > secondip->ip[i]) {
			return 1;
		}
	}

	return 0;
}

#if 0
/* 端口扫描是远程发起的，本机是取不到对方的用户和进程信息的 */
static void report_portscan(netreq_t *req)
{
	char *post = NULL;
	char reply[REPLY_MAX] = {0};
	char ipv6_str[INET6_ADDRSTRLEN];
	int level = MY_LOG_LOW_RISK;
	int behavior_id = MY_BEHAVIOR_ABNORMAL;
	int event = 1, terminate = 0, result = 0, locking = 0;
	int scan_duration = 0, lock_duration = 0;
	unsigned long event_time = 0;
	char myip[S_IPLEN] = {0};
	char peerip[S_IPLEN] = {0};
	char ports[4096] = {0};
	char *log_name = NULL;
	char uuid[S_UUIDLEN] = {0};
	cJSON *object = NULL, *arguments = NULL;

	if (req == NULL) {
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) { //没取到uuid
		return;
	}

	if (req->flags.trust) {
		behavior_id = MY_BEHAVIOR_NO;
		level = MY_LOG_NORMAL;
		event = 0;
	}

	locking = req->flags.locking;
	event_time = (req->event_tv.tv_sec + serv_timeoff) * 1000 + req->event_tv.tv_usec / 1000;
	scan_duration = req->effective_time;

	lock_duration = req->portscan_lockip_time;

	object = cJSON_CreateObject();
	arguments = cJSON_CreateObject();

	cJSON_AddStringToObject(object, "id", uuid);
	if (req->flags.honeyport) {
		log_name = "HoneyPort";
	} else {
		log_name = "PortScan";
	}

	if (req->flags.terminate) {
		terminate = MY_HANDLE_BLOCK_OK_LOCKIP_OK; /* 阻断+锁定 */
		result = MY_RESULT_FAIL;
	} else {
		terminate = MY_HANDLE_WARNING; /* 不阻断只告警 */
		result = MY_RESULT_OK;
	}

	if (client_mode_global) { /* 当前是运维或学习模式 */
		terminate = MY_HANDLE_WARNING; /* 只告警 */
		result = MY_RESULT_OK;
		locking = 0;   /* 不锁定 */
	}

	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Network");

	if (event) {
		cJSON_AddBoolToObject(object, "event", true);
	} else {
		cJSON_AddBoolToObject(object, "event", false);
	}
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior_id);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "event_category", "IllegalNetwork");
	cJSON_AddStringToObject(object, "operating", "Connect");
	cJSON_AddNumberToObject(object, "terminate", terminate); /* 策略配置的阻断开关 */

	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", "remote");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur); /* 策略ID */
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	if (req->srcip.ip[0]) { /* ipv4 */
		snprintf(peerip, sizeof(peerip), "%u.%u.%u.%u", IPSTR(&req->srcip));
		snprintf(myip, sizeof(myip), "%u.%u.%u.%u", IPSTR(&req->dstip));
		cJSON_AddStringToObject(arguments, "attack_ip", peerip);
		cJSON_AddStringToObject(arguments, "scan_ip", myip);
	} else { /* ipv6 */
		if (inet_ntop(AF_INET6, req->srcipv6.ipv6, ipv6_str, INET6_ADDRSTRLEN) == NULL) {
			MON_ERROR("net IPv6 inet_ntop fail\n");
			memset(ipv6_str, '0', sizeof(ipv6_str)-1);
			ipv6_str[INET6_ADDRSTRLEN-1] = 0;
		}
		cJSON_AddStringToObject(arguments, "attack_ip", ipv6_str);
		if (inet_ntop(AF_INET6, req->dstipv6.ipv6, ipv6_str, INET6_ADDRSTRLEN) == NULL) {
			MON_ERROR("net IPv6 inet_ntop fail\n");
			memset(ipv6_str, '0', sizeof(ipv6_str)-1);
			ipv6_str[INET6_ADDRSTRLEN-1] = 0;
		}
		cJSON_AddStringToObject(arguments, "scan_ip", ipv6_str);
	}

	/* arguments */
	if (req->flags.portscan) {
		/* 端口列表采用xxxx,yyyy-zzzz的形式 */
		snprintf(ports, sizeof(ports), "%s", (char *)req + sizeof(netreq_t));
		cJSON_AddNumberToObject(arguments, "scan_count", req->ports_count);
	} else {
		snprintf(ports, sizeof(ports), "%d", req->dport);
		cJSON_AddNumberToObject(arguments, "scan_count", 1);
	}

	cJSON_AddStringToObject(arguments, "scan_port", ports);
	cJSON_AddNumberToObject(arguments, "lock_duration", lock_duration);
	if (locking) {
		cJSON_AddBoolToObject(arguments, "is_lock", true);
		if (req->srcip.ip[0]) { /* ipv4 */
			snprintf(peerip, sizeof(peerip), "%u.%u.%u.%u", IPSTR(&req->srcip));
			cJSON_AddStringToObject(arguments, "lock_ip", peerip);
		} else {
			if (inet_ntop(AF_INET6, req->srcipv6.ipv6, ipv6_str, INET6_ADDRSTRLEN)) {
				cJSON_AddStringToObject(arguments, "lock_ip", ipv6_str);
			}
		}
	} else {
		cJSON_AddBoolToObject(arguments, "is_lock", false);
	}
	cJSON_AddNumberToObject(arguments, "scan_duration", scan_duration);

	cJSON_AddStringToObject(arguments, "country", "");
	cJSON_AddStringToObject(arguments, "province", "");
	cJSON_AddStringToObject(arguments, "city", "");
	cJSON_AddStringToObject(arguments, "location", "");
	cJSON_AddBoolToObject  (arguments, "intranet", false);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_NET, "portscan: %s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "network");
	cJSON_Delete(object);
	free(post);

	/* 正常模式下阻断，发防御日志，运维或学习模式不发防御日志 */
	if (client_mode_global == NORMAL_MODE && locking) {
		if (req->flags.trust) { /* 可信IP不发防御日志 */
			return;
		}
		if (req->flags.honeyport) {
			save_lockip(peerip, lock_duration*60, "HoneyPort", uuid);
		} else {
			save_lockip(peerip, lock_duration*60, "PortScan", uuid);
		}

		/* 发送防御日志 */
		struct defence_msg defmsg = {0};
		defmsg.event_tv.tv_sec = req->event_tv.tv_sec + serv_timeoff;
		defmsg.event_tv.tv_usec = req->event_tv.tv_usec;
		defmsg.operation = lockstr;
		defmsg.result = 1;
		defmsg.user = "root";
		defmsg.log_name = log_name;
		defmsg.log_id = uuid;
		if (req->srcip.ip[0]) {
			defmsg.object = peerip;
		} else {
			defmsg.object = ipv6_str;
		}

		send_defence_msg(&defmsg, "network");
	}
}
#endif

#define DOMAIN_CACHE_NUM 256
int next_domain_cache = 0;
struct domain_cache {
	char domain[S_DOMAIN_NAMELEN];
	char ip[S_IPLEN];
	time_t last_report_t;
} domain_cache[DOMAIN_CACHE_NUM] = {{{0}}};

char *search_domain_cache_ip(char *domain)
{
	int i = 0;

	for (i = 0; i < DOMAIN_CACHE_NUM; i++) {
		if (strcmp(domain_cache[i].domain, domain) == 0) {
			return domain_cache[i].ip;
		}
	}
	return NULL;
}

#if 0
static void report_domain(netreq_t *req)
{
	int i = 0, found = 0;
	char *post = NULL;
	char path[PATH_MAX] = {0};
	char line[PATH_MAX] = {0};
	char md5[S_MD5LEN] = {0};
	char sha256[S_SHALEN] = {0};
	char reply[REPLY_MAX] = {0};
	char process_uuid[64] = {0};
	time_t now = time(NULL);
	unsigned long event_time = 0;
	int event = 0;
	int terminate = 0;
	int behavior_id = MY_BEHAVIOR_NO;
	int level = 0;
	int result = MY_RESULT_OK;
	char *log_name = NULL;
	char *operating = NULL;
	char *event_category = NULL;
	FILE *fp = NULL;
	unsigned long start_time = 0;
	taskstat_t *taskstat = NULL;
	char name[S_NAMELEN] = {0};
	char uuid[S_UUIDLEN] = {0};
	char query_type[8] = {0};

	if (req == NULL) {
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) { //没取到uuid
		return;
	}

	uidtoname(req->uid, name);

	terminate = req->flags.terminate;
	if (req->flags.blackdomain) { /* 恶意域名事件 */
		event_category = "MaliciousDomain";
		log_name = "RequestMaliciousDomain";
		level = MY_LOG_HIGH_RISK;
		event = 1;
		behavior_id = MY_BEHAVIOR_VIOLATION;
		operating = "Resolve";
		if (terminate || req->flags.blackdomain_terminate) {
			result = MY_RESULT_FAIL;
			terminate = MY_HANDLE_BLOCK_OK;
		} else {
			result = MY_RESULT_OK;
			terminate = MY_HANDLE_WARNING;
		}
	} else { /* 域名查询日志 */
		event_category = "";
		log_name = "DNSQuery";
		level = MY_LOG_NORMAL;
		event = 0;
		behavior_id = MY_BEHAVIOR_NO;
		operating = "Resolve";
		result = MY_RESULT_OK;
		terminate = MY_HANDLE_NO;
	}

	/* 普通日志，日志采集未开，不上报 */
	if (!event && !protect_policy_global.logcollector.dnsquery_enable) {
		return;
	}

	for (i = 0; i < DOMAIN_CACHE_NUM; i++) {
		if (domain_cache[i].last_report_t == 0) {
			break;
		}
		/* 1分钟内不重复报告 */
		if (strcmp(domain_cache[i].domain, req->domain) == 0 &&
		    strcmp(domain_cache[i].ip, req->ip) == 0) {
			found = 1;
			/* 未解析的域名10分钟内不重复报告 */
			if (strcmp(req->ip, "0.0.0.0") == 0) {
				if (now - domain_cache[i].last_report_t < 600) {
					return;
				}
			} else if (now - domain_cache[i].last_report_t < 60) {
				return;
			}
			domain_cache[i].last_report_t = now;
			break;
		}
	}
	if (!found) {
		i = next_domain_cache;
		snprintf(domain_cache[i].domain, sizeof(domain_cache[i].domain), "%s", req->domain);
		snprintf(domain_cache[i].ip, sizeof(domain_cache[i].ip), "%s", req->ip);
		domain_cache[i].last_report_t = now;
		next_domain_cache = (i + 1) & 0xff;
	}

	/* 为解析出ip的域名，解析结果为失败 */
	if (req->ip[0] == 0 || strcmp(req->ip, "0.0.0.0") == 0) {
		result = MY_RESULT_FAIL;
	}

	event_time = (req->event_tv.tv_sec + serv_timeoff) * 1000 + req->event_tv.tv_usec / 1000;
	/*
	 *查询类型：DNS 查询请求的资源类型。通常查询类型为 A 类型，表示由域名获取对应的 IP 地址。
	 * 1 - A        : 由域名获得IPv4地址
	 * 2 - NS       : 查询授权的域名服务器
	 * 5 - CNAME    : 查询规范名称（别名）
	 * 6 - SOA      : 开始授权
	 * 11 - WKS     : 熟知服务
	 * 12 - PTR     : 把IP地址转换成域名（指针记录，反向查询）
	 * 13 - HINFO   : 主机信息
	 * 15 - MX      : 邮件交换记录
	 * 28 - AAAA    : 由域名获得IPv6地址
	 * 252 - AXFR   : 对区域转换的请求，传送整个区的请求。
	 * 255 - ANY    : 对所有记录的请求 *
	 */
	switch (req->domain_query_type) {
	case 1:
		snprintf(query_type, sizeof(query_type), "A");
		break;
	case 2:
		snprintf(query_type, sizeof(query_type), "NS");
		break;
	case 5:
		snprintf(query_type, sizeof(query_type), "CNAME");
		break;
	case 6:
		snprintf(query_type, sizeof(query_type), "SOA");
		break;
	case 11:
		snprintf(query_type, sizeof(query_type), "WKS");
		break;
	case 12:
		snprintf(query_type, sizeof(query_type), "PTR");
		break;
	case 13:
		snprintf(query_type, sizeof(query_type), "HINFO");
		break;
	case 15:
		snprintf(query_type, sizeof(query_type), "MX");
		break;
	case 28:
		snprintf(query_type, sizeof(query_type), "AAAA");
		break;
	case 252:
		snprintf(query_type, sizeof(query_type), "AXFR");
		break;
	case 255:
		snprintf(query_type, sizeof(query_type), "ANY");
		break;
	default:
		snprintf(query_type, sizeof(query_type), "None");
		break;
	}

	taskstat = get_taskstat_rdlock(req->pid, NETWORK_GET);
	if (!taskstat) {
		taskstat = get_ptaskstat_from_pinfo_rdlock(&req->pinfo);
	}
	if (!taskstat) {
		snprintf(path, sizeof(path), "/proc/%d/stat", req->pid);
		fp = fopen(path, "r");
		if (fp) {
			fgets(line, sizeof(line), fp);
			sscanf(line, "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s %lu", &start_time);
			fclose(fp);
			fp = NULL;
		}
		if (start_time == req->proctime) {
			memset(path, 0, sizeof(path));
			snprintf(path, sizeof(path), "/proc/%d/cmdline", req->pid);
			fp = fopen(path, "r");
			if (fp) {
				fgets(line, sizeof(line), fp);
				fclose(fp);

				memset(path, 0, sizeof(path));
				snprintf(path, sizeof(path), "%s", line);
				if (sha256_file(line, sha256) < 0) {
					sha256[0] = 'X';
					sha256[1] = '\0';
				}
				if (md5_file(line, md5) < 0) {
					md5[0] = 'X';
					md5[1] = '\0';
				}
			} else {
				memset(path, 0, sizeof(path));
				snprintf(path, sizeof(path), "%s", req->comm);
			}
		} else {
			md5[0] = 'X';
			md5[1] = '\0';
			sha256[0] = 'X';
			sha256[1] = '\0';
			/* 未获取到程序路径，填充程序名 */
			snprintf(path, sizeof(path), "%s", req->comm);
		}
		set_taskuuid(process_uuid, req->proctime, req->pid, 0);
	}

	/* 事件: 域名访问，非法域名访问 */
	if (client_mode_global) { /* 当前是运维或学习模式 */
		terminate = MY_HANDLE_WARNING;
	}

	cJSON *object = cJSON_CreateObject();
	cJSON *arguments = cJSON_CreateObject();
	cJSON_AddItemToObject(object, "arguments", arguments);

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Domain");
	if (event) {
		cJSON_AddBoolToObject(object, "event", true);
	} else {
		cJSON_AddBoolToObject(object, "event", false);
	}
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior_id);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating); /* 先默认为1 */
	cJSON_AddNumberToObject(object, "terminate", terminate); /* 策略配置的阻断开关 */
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", name);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time); /* 毫秒 */
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur); /* 策略ID */
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	/* arguments */
	if (taskstat) {
		cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);
		cJSON_AddStringToObject(arguments, "process_name", req->comm);
		cJSON_AddNumberToObject(arguments, "process_id", req->pid);
		cJSON_AddNumberToObject(arguments, "thread_id", req->tgid);
		cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
		cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);
		cJSON_AddStringToObject(arguments, "md5", taskstat->md5);
		cJSON_AddStringToObject(arguments, "sha256", taskstat->sha256);
		put_taskstat_unlock(taskstat);
	} else {
		cJSON_AddStringToObject(arguments, "process_uuid", process_uuid);
		cJSON_AddStringToObject(arguments, "process_name", req->comm);
		cJSON_AddNumberToObject(arguments, "process_id", req->pid);
		cJSON_AddNumberToObject(arguments, "thread_id", req->tgid);
		cJSON_AddStringToObject(arguments, "process_path", path);
		cJSON_AddStringToObject(arguments, "process_commandline", req->comm);
		cJSON_AddStringToObject(arguments, "md5", md5);
		cJSON_AddStringToObject(arguments, "sha256", sha256);
	}
	cJSON_AddStringToObject(arguments, "domain", req->domain);
	cJSON_AddStringToObject(arguments, "destination_ip", (char *)req->ip);
	cJSON_AddStringToObject(arguments, "domain_query_type", query_type);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_NET, "domain: %s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "network");
	cJSON_Delete(object);
	free(post);

	/* 正常模式下阻断，发防御日志，运维或学习模式不发防御日志 */
	if (client_mode_global == NORMAL_MODE && req->flags.terminate) {
		struct defence_msg defmsg = {0};
		defmsg.event_tv.tv_sec = req->event_tv.tv_sec + serv_timeoff;
		defmsg.event_tv.tv_usec = req->event_tv.tv_usec;
		defmsg.operation = termstr;
		defmsg.result = OPERATE_OK;
		defmsg.user = "root";
		defmsg.log_name = log_name;
		defmsg.log_id = uuid;
		defmsg.object = req->domain;

		send_defence_msg(&defmsg, "network");
	}
}
#endif

/* 仅在初始化时，锁sniper上次运行时残留的，未到期的非法ip */
void check_lockedip(int dolock)
{
	char dir[128] = {0};
	char ippath[512] = {0};
	DIR *dirp = NULL;
	struct dirent *dent = NULL;
	time_t now = time(NULL);

	snprintf(dir, sizeof(dir), "%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR);
	dirp = sniper_opendir(dir, NETWORK_GET);
	if (!dirp) {
		DBG("check denied ips fail: open dir %s : %s\n", dir, strerror(errno));
		return;
	}

	while ((dent = readdir(dirp))) {
		char *ip = dent->d_name;
		char buf1[S_LINELEN] = "", *log_name = buf1;
		char buf2[S_LINELEN] = "", *log_id = buf2;
		char buf3[S_LINELEN] = "", *timestr = buf3;
		FILE *fp = NULL;
		time_t unlock_time = 0;

		if (ip[0] == '.') {
			continue;
		}

		snprintf(ippath, sizeof(ippath), "%s/%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR, ip);
		fp = fopen(ippath, "r");
		if (!fp) {
			continue;
		}

		fgets(buf1, sizeof(buf1), fp); //log_name
		fgets(buf2, sizeof(buf2), fp); //log_id
		fgets(buf3, sizeof(buf3), fp); //unlock_time，解锁的时刻/时间点
		fclose(fp);

		log_name = skip_headspace(buf1);
		delete_tailspace(log_name);

		log_id = skip_headspace(buf2);
		delete_tailspace(log_id);

		timestr = skip_headspace(buf3);
		delete_tailspace(timestr);

		unlock_time = atol(timestr);
		if (unlock_time <= 0) {
			/* 没取到unlock_time，删除ippath，避免以后创建不了ippath */
			unlink(ippath);
			continue;
		}

		//TODO 解锁时间超过当前策略的最大值的，视为异常，将其解锁
		if (now >= unlock_time) {
			unlock_ip(ip);
			continue;
		}

		/* 仅在初始化时，锁sniper上次运行时残留的，未到期的非法ip */
		if (!dolock) {
			continue;
		}

		lock_ip(ip, NET_ILLEGAL_CONNECTION, unlock_time-now, log_name, log_id);
	}
	sniper_closedir(dirp, NETWORK_GET);
}

#define PACKETSIZE  64
struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

static unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result = 0;

	for (sum = 0; len > 1; len -= 2) {
		sum += *buf++;
	}
	if (len == 1) {
		sum += *(unsigned char*)buf;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;

	return result;
}

/* 成功 0，失败 -1 */
static int sniper_ping(char *address)
{
	int i = 0, loop = 0, sd = 0, cnt = 1;
	int ttl = 255; //time to live，IP数据包可以经过最大的路由器数量
	pid_t pid = 0;
	struct packet pckt;
	struct sockaddr_in r_addr;
	struct hostent *hname = NULL;
	struct sockaddr_in addr_ping,*addr;
	struct protoent *proto = NULL;

	if (!address) {
		return -1;
	}

	pid = getpid();
	proto = getprotobyname("ICMP");
	hname = gethostbyname(address);
	if (!hname) {
		return -1;
	}
	bzero(&addr_ping, sizeof(addr_ping));
	addr_ping.sin_family = hname->h_addrtype;
	addr_ping.sin_port = 0;
	addr_ping.sin_addr.s_addr = *(long*)hname->h_addr;

	addr = &addr_ping;

	sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sd < 0) {
		DBG("socket");
		return -1;
	}
	if (setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
		close(sd);
		DBG("Set TTL option");
		return -1;
	}
	if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
		close(sd);
		DBG("Request nonblocking I/O");
		return -1;
	}

	for (loop = 0; loop < 10; loop++) {
		unsigned int len=sizeof(r_addr);

		if (recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &len) > 0) {
			close(sd);
			return 0;
		}

		bzero(&pckt, sizeof(pckt));
		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = pid;
		for (i = 0; i < sizeof(pckt.msg) - 1; i++) {
			pckt.msg[i] = i + '0';
		}
		pckt.msg[i] = 0;
		pckt.hdr.un.echo.sequence = cnt++;
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
		if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0) {
			DBG("sendto failed");
		}

		usleep(300000);
	}
	close(sd);

	return -1;
}

#if 0
static void report_illegal_connect_internet(char *remote_ip, unsigned int is_terminate)
{
	char reply[REPLY_MAX] = {0};
	char uuid[S_UUIDLEN] = {0};
	unsigned long event_time = 0;
	struct timeval tv;
	int terminate = 0;
	char *daddr = "-";
	char *domain = "-";
	char *log_name = "IllegalConnectInternet";

	if (remote_ip == NULL) {
		return;
	}

	/* 事件: 非法互联网访问 */
	get_random_uuid(uuid);
	if (uuid[0] == 0) { //没取到uuid
		return;
	}

	gettimeofday(&tv,NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + tv.tv_usec / 1000;

	if (is_terminate) {
		terminate = MY_HANDLE_BLOCK_OK;
	} else {
		terminate = MY_HANDLE_WARNING;
	}

	cJSON *object = cJSON_CreateObject();
	cJSON *arguments = cJSON_CreateObject();
	cJSON_AddItemToObject(object, "arguments", arguments);

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Network");
	  cJSON_AddBoolToObject(object, "event", true);
	cJSON_AddStringToObject(object, "event_category", "IllegalNetwork");
	cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_VIOLATION);
	cJSON_AddNumberToObject(object, "result", 0); //该事件没有结果，传0代表无结果
	cJSON_AddStringToObject(object, "operating", "Connect");
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);/* 毫秒 */
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur); /* 策略ID */
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	/* arguments */
	/* 此处只报远程IP/域名 及端口号，其它信息可以为空 */
	if (check_isip(remote_ip)) {
		daddr = remote_ip;
	} else {
		domain = remote_ip;
	}

	cJSON_AddStringToObject(arguments, "saddr", If_info.ip);
	cJSON_AddStringToObject(arguments, "sport", "");
	cJSON_AddStringToObject(arguments, "daddr", daddr);
	cJSON_AddStringToObject(arguments, "dport", "");
	cJSON_AddStringToObject(arguments, "domain", domain);

	char *post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_NET, "illegal conn: %s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "network");
	cJSON_Delete(object);
	free(post);

	if (is_terminate) {
		struct defence_msg defmsg = {0};

		defmsg.event_tv.tv_sec = tv.tv_sec + serv_timeoff;
		defmsg.event_tv.tv_usec = tv.tv_usec;
		defmsg.operation = termstr;
		defmsg.result = OPERATE_OK;
		defmsg.user = "root";
		defmsg.log_name = log_name;
		defmsg.log_id = uuid;
		defmsg.object = "";

		send_defence_msg(&defmsg, "network");
	}
}

/* 事件: 非法网络连接 */
static void report_illegal_connection(netreq_t *req)
{
	char reply[REPLY_MAX] = {0};
	char username[S_NAMELEN] = {0};
	char uuid[S_UUIDLEN] = {0};
	char src_ip[64] = {0};
	char dst_ip[64] = {0};
	char src_port[64] = {0};
	char dst_port[64] = {0};
	char process_uuid[64] = {0};
	char connection[512] = {0};
	char *post = NULL;
	unsigned long event_time = 0;
	struct timeval tv;
	int direction = 0; //连接方向 1 连入 2 连出
	char *log_name = "IllegalNetwork";
	taskstat_t *taskstat = NULL;
	struct defence_msg defmsg = {0};
	cJSON *object = NULL;
	cJSON *arguments = NULL;

	if (req == NULL) {
		return;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) { //没取到uuid
		return;
	}

	gettimeofday(&tv,NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + tv.tv_usec / 1000;

	object = cJSON_CreateObject();
	arguments = cJSON_CreateObject();
	cJSON_AddItemToObject(object, "arguments", arguments);

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Network");
	  cJSON_AddBoolToObject(object, "event", true);
	cJSON_AddStringToObject(object, "event_category", "IllegalNetwork");
	cJSON_AddNumberToObject(object, "level", MY_LOG_HIGH_RISK);
	cJSON_AddNumberToObject(object, "behavior", MY_BEHAVIOR_VIOLATION);
	cJSON_AddNumberToObject(object, "result", MY_RESULT_FAIL); //因为被阻断了，从连接的角度看是失败了
	cJSON_AddStringToObject(object, "operating", "Connect");
	cJSON_AddNumberToObject(object, "terminate", MY_HANDLE_BLOCK_OK);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	if (req->flags.blackin || req->flags.notwhitein) {
		direction = CONN_IN;

		snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d", IPSTR(&req->srcip));
		snprintf(dst_port, sizeof(dst_port), "%d", req->sport);

		snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d", IPSTR(&req->dstip));
		snprintf(src_port, sizeof(src_port), "%d", req->dport);

		snprintf(connection, sizeof(connection), "%s:%s -> %s:%s",
			dst_ip, dst_port, src_ip, src_port);

		/* 连入在网络层就阻断了，那时无法获知对方的身份和本机的服务进程 */
		cJSON_AddStringToObject(object, "user", "remote");

		cJSON_AddStringToObject(arguments, "process_name", "");
		cJSON_AddNumberToObject(arguments, "process_id", 0);
		cJSON_AddStringToObject(arguments, "process_path", "");
		cJSON_AddStringToObject(arguments, "process_commandline", "");
		cJSON_AddStringToObject(arguments, "process_uuid", "-"); //非空，在管控上查看事件详情才显示关联日志
		cJSON_AddStringToObject(arguments, "md5", "");
		cJSON_AddStringToObject(arguments, "sha256", "");

		cJSON_AddStringToObject(arguments, "session_uuid", "");

	} else if (req->flags.blackout || req->flags.notwhiteout) {
		direction = CONN_OUT;

		snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d", IPSTR(&req->dstip));
		snprintf(dst_port, sizeof(dst_port), "%d", req->dport);

		snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d", IPSTR(&req->srcip));
		snprintf(src_port, sizeof(src_port), "%d", req->sport);

		snprintf(connection, sizeof(connection), "%s:%s -> %s:%s",
			src_ip, src_port, dst_ip, dst_port);

		taskstat = get_taskstat_rdlock(req->pid, NETWORK_GET);
		if (!taskstat) {
			taskstat = get_ptaskstat_from_pinfo_rdlock(&req->pinfo);
		}
		if (!taskstat) {
		}

		if (taskstat) {
			cJSON_AddStringToObject(object, "user", taskstat->user);

			cJSON_AddStringToObject(arguments, "process_name", safebasename(taskstat->cmd));
			cJSON_AddNumberToObject(arguments, "process_id", taskstat->pid);
			cJSON_AddStringToObject(arguments, "process_path", taskstat->cmd);
			cJSON_AddStringToObject(arguments, "process_commandline", taskstat->args);

			cJSON_AddStringToObject(arguments, "process_uuid", taskstat->uuid);

			cJSON_AddStringToObject(arguments, "md5", taskstat->md5);
			cJSON_AddStringToObject(arguments, "sha256", taskstat->sha256);

			cJSON_AddStringToObject(arguments, "session_uuid", taskstat->session_uuid);

			put_taskstat_unlock(taskstat);
		} else {
			uidtoname(req->uid, username);
			cJSON_AddStringToObject(object, "user", username);

			cJSON_AddStringToObject(arguments, "process_name", req->comm);
			cJSON_AddNumberToObject(arguments, "process_id", req->pid);
			cJSON_AddStringToObject(arguments, "process_path", req->comm);
			cJSON_AddStringToObject(arguments, "process_commandline", req->comm);

			set_taskuuid(process_uuid, req->proctime, req->pid, 0);
			cJSON_AddStringToObject(arguments, "process_uuid", process_uuid);

			cJSON_AddStringToObject(arguments, "md5", "");
			cJSON_AddStringToObject(arguments, "sha256", "");

			cJSON_AddStringToObject(arguments, "session_uuid", "");
		}
	}

	cJSON_AddNumberToObject(arguments, "thread_id", 0);

	cJSON_AddStringToObject(arguments, "source_ip", src_ip);
	cJSON_AddStringToObject(arguments, "source_port", src_port);
	cJSON_AddStringToObject(arguments, "source_portname", "");
	cJSON_AddStringToObject(arguments, "destination_ip", dst_ip);
	cJSON_AddStringToObject(arguments, "destination_port", dst_port);
	cJSON_AddStringToObject(arguments, "destination_portname", "");
	cJSON_AddStringToObject(arguments, "destination_hostname", "");
	cJSON_AddNumberToObject(arguments, "direction", direction);
	cJSON_AddStringToObject(arguments, "country", "");
	cJSON_AddStringToObject(arguments, "province", "");
	cJSON_AddStringToObject(arguments, "city", "");
	cJSON_AddStringToObject(arguments, "location", "");

	cJSON_AddNumberToObject(arguments, "intranet", !is_internet_ip(dst_ip)); //0 外网，1 内网

	if (req->flags.notwhitein || req->flags.notwhiteout) {
		cJSON_AddStringToObject(arguments, "detection_rule", "WhiteAccessControl");
	} else if (req->flags.blackin || req->flags.blackout) {
		cJSON_AddStringToObject(arguments, "detection_rule", "BlackAccessControl");
	}

	if (req->flags.tcp) {
		cJSON_AddStringToObject(arguments, "protocol", "TCP");
	} else if (req->flags.udp) {
		cJSON_AddStringToObject(arguments, "protocol", "UDP");
	}

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_NET, "illegal conn: %s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "network");
	cJSON_Delete(object);
	free(post);

	defmsg.event_tv.tv_sec = tv.tv_sec + serv_timeoff;
	defmsg.event_tv.tv_usec = tv.tv_usec;
	defmsg.operation = termstr;
	defmsg.result = OPERATE_OK;
	defmsg.user = "root";
	defmsg.log_name = log_name;
	defmsg.log_id = uuid;
	defmsg.object = connection;

	send_defence_msg(&defmsg, "network");
}
#endif

/*
Turn the __u32 ipv4 address into Decimal ipv4 address.
@Args:
addr : __u32 ipv4 address.
ip   : Decimal ipv4 address.
*/
static void int_to_ip(unsigned int addr, char *ip) {

    memset(ip, 0, strlen(ip));
    char buf[16] = {0};
    int ip_1 = addr / pow(2, 24);
    int ip_2 = addr % (int)pow(2, 24) / pow(2, 16);
    int ip_3 = addr % (int)pow(2, 16) / pow(2, 8);
    int ip_4 = addr % (int)pow(2, 8);
    sprintf(buf, "%d", ip_4);
    strcpy(ip, buf);
    sprintf(buf, ".%d", ip_3);
    strcat(ip, buf);
    sprintf(buf, ".%d", ip_2);
    strcat(ip, buf);
    sprintf(buf, ".%d", ip_1);
    strcat(ip, buf);

}


static void send_net_msg(struct ebpf_netreq_t *req, struct net_msg_args *msg)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	
	unsigned long event_time = 0;
	int behavior = 0, level = 0, result = MY_RESULT_ZERO;

	bool event = false;
	char log_name[LOG_NAME_MAX] = {0};
	char event_category[EVENT_NAME_MAX] = {0};
	char log_category[LOG_NAME_MAX] = {0};
	int terminate = 0;
	char ipaddr_str[64];
	char port_str[64] = {0};
	if ((req->protocol==6)&&(strcmp(req->comm,"bash")==0))
	{
		req->type=NET_TCP_CONNECT_BASH;
	}
	if (req->protocol==1)
	{
		req->type=NET_ILLEGAL_CONNECT;
	}
	if ((req->protocol==6)&&(req->fin))
	{
		req->type=NET_MPORT_SCAN;
	}

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		printf("cJSON Create Object failed@%s line:%d\r\n",__FILE__,__LINE__);
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		printf("cJSON Create Object failed@%s line:%d\r\n",__FILE__,__LINE__);
		cJSON_Delete(object);
		return;
	}
	
	switch (req->type) {

		case NET_TCP_CONNECT_BASH:
			strncpy(log_name, "ReverseShell", LOG_NAME_MAX);
			strncpy(event_category, "Process", EVENT_NAME_MAX);
			strncpy(log_category, "Process", LOG_NAME_MAX);
			level = MY_LOG_HIGH_RISK;
			behavior = MY_BEHAVIOR_ABNORMAL;
			event = true;
			terminate = MY_HANDLE_WARNING;

			cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
			cJSON_AddStringToObject(object, "ip_address", If_info.ip);
			cJSON_AddStringToObject(object, "mac", If_info.mac);
			
			snprintf(ipaddr_str, sizeof(ipaddr_str), "%u.%u.%u.%u", 
					(unsigned char)req->daddr,(unsigned char)((req->daddr)>>8),
					(unsigned char)((req->daddr)>>16),(unsigned char)((req->daddr)>>24));
			cJSON_AddStringToObject(arguments, "remote_ip", ipaddr_str);
			snprintf(port_str, sizeof(port_str), "%u", req->dport);
			cJSON_AddStringToObject(arguments, "remote_port", port_str);

			snprintf(ipaddr_str, sizeof(ipaddr_str), "%u.%u.%u.%u", 
					(unsigned char)req->saddr,(unsigned char)((req->saddr)>>8),
					(unsigned char)((req->saddr)>>16),(unsigned char)((req->saddr)>>24));
			cJSON_AddStringToObject(arguments, "local_ip", ipaddr_str);

			snprintf(port_str, sizeof(port_str), "%u", req->sport);
			cJSON_AddStringToObject(arguments, "local_port", port_str);

			char uuid_str[64];
			snprintf(uuid_str, sizeof(uuid_str), "%u", req->uid);
			cJSON_AddStringToObject(arguments, "process_uuid", uuid_str);
			cJSON_AddStringToObject(arguments, "process_name", req->comm);
			cJSON_AddNumberToObject(arguments, "process_id", req->pid);
			cJSON_AddNumberToObject(arguments, "parent_process_id", req->parent_pid);
			cJSON_AddStringToObject(arguments, "parent_process_name", req->parent_comm);

			char sessionid_str[64];
			snprintf(sessionid_str, sizeof(sessionid_str), "%u", req->sessionid);
			cJSON_AddStringToObject(arguments, "session_id", sessionid_str);
			cJSON_AddStringToObject(arguments, "process_path", req->pathname);
			cJSON_AddStringToObject(arguments, "parent_process_path", req->parent_pathname);

			break;

		case NET_ILLEGAL_CONNECT:
			strncpy(log_name, "IllegalConnectInternet", LOG_NAME_MAX);
			strncpy(event_category, "IllegalNetwork", EVENT_NAME_MAX);
			strncpy(log_category, "Network", LOG_NAME_MAX);
			level = MY_LOG_HIGH_RISK;
			behavior = MY_BEHAVIOR_VIOLATION;
			event = true;
			terminate = MY_HANDLE_WARNING;

			cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
			cJSON_AddStringToObject(object, "ip_address", If_info.ip);
			cJSON_AddStringToObject(object, "mac", If_info.mac);
			cJSON_AddStringToObject(object, "log_type", log_name);
			cJSON_AddStringToObject(object, "operating",  "Connect");
			cJSON_AddNumberToObject(object, "event_type", 40);

			snprintf(ipaddr_str, sizeof(ipaddr_str), "%u.%u.%u.%u", 
					(unsigned char)req->daddr,(unsigned char)((req->daddr)>>8),
					(unsigned char)((req->daddr)>>16),(unsigned char)((req->daddr)>>24));
			cJSON_AddStringToObject(arguments, "local_ip", ipaddr_str);

			snprintf(ipaddr_str, sizeof(ipaddr_str), "%u.%u.%u.%u", 
					(unsigned char)req->saddr,(unsigned char)((req->saddr)>>8),
					(unsigned char)((req->saddr)>>16),(unsigned char)((req->saddr)>>24));
			cJSON_AddStringToObject(arguments, "remote_ip", ipaddr_str);
			break;

		case NET_MPORT_SCAN:
			strncpy(log_name, "HoneyPort", LOG_NAME_MAX);
			strncpy(event_category, "IllegalNetwork", EVENT_NAME_MAX);
			strncpy(log_category, "Network", LOG_NAME_MAX);
			level = MY_LOG_LOW_RISK;
			behavior = MY_BEHAVIOR_ABNORMAL;
			event = true;
			terminate = MY_HANDLE_WARNING;

			cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
			cJSON_AddStringToObject(object, "ip_address", If_info.ip);
			cJSON_AddStringToObject(object, "mac", If_info.mac);

			snprintf(ipaddr_str, sizeof(ipaddr_str), "%u.%u.%u.%u", 
					(unsigned char)req->saddr,(unsigned char)((req->saddr)>>8),
					(unsigned char)((req->saddr)>>16),(unsigned char)((req->saddr)>>24));
			cJSON_AddStringToObject(arguments, "attack_ip", ipaddr_str);

			snprintf(ipaddr_str, sizeof(ipaddr_str), "%u.%u.%u.%u", 
					(unsigned char)req->daddr,(unsigned char)((req->daddr)>>8),
					(unsigned char)((req->daddr)>>16),(unsigned char)((req->daddr)>>24));
			cJSON_AddStringToObject(arguments, "scan_ip", ipaddr_str);
			cJSON_AddNumberToObject(arguments, "scan_port", req->dport);
			cJSON_AddNumberToObject(arguments, "scan_count", 1);
			cJSON_AddBoolToObject(arguments, "is_lock", true);
			cJSON_AddNumberToObject(arguments, "lock_time", 60);
			cJSON_AddNumberToObject(arguments, "scan_duration", 30);
			cJSON_AddNumberToObject(arguments, "direction", 2);
			cJSON_AddBoolToObject(arguments, "intranet", false);

			break;
			
		default:
			strncpy(log_name, "NetMonitor", LOG_NAME_MAX);
			strncpy(event_category, "", EVENT_NAME_MAX);
			/* 其余均为文件行为采集 */
			level = MY_LOG_KEY;
			behavior = MY_BEHAVIOR_ABNORMAL;
			event = false;
			terminate = MY_HANDLE_NO;
	}

	event_time = (msg->event_tv.tv_sec + serv_timeoff) * 1000 + (int)msg->event_tv.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", log_category);
	cJSON_AddStringToObject(object, "log_type", log_category);
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "source", "Agent");

    cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	if (!post) {
		cJSON_Delete(object);
		printf("cJSON_PrintUnformatted fail@%s line:%d\n",__FILE__,__LINE__);
		return;
	}

	client_send_msg(post, reply, sizeof(reply), LOG_URL, "process");
	// if (strcmp(log_name,"lllegalConnectInternet")==0)
	// 	printf("post=%s,reply:[%s]\n",post,reply);
	
	cJSON_Delete(object);
	free(post);

	return;
}

/* net net monitor thread */
void *net_monitor(void *ptr)
{
	struct ebpf_netreq_t *req = NULL;
	struct net_msg_args msg = {0};
	knet_msg_t *net_msg = NULL;
	time_t last_internet_check_time = time(NULL);
    char daddr[32] = {0};
    char saddr[32] = {0};

	prctl(PR_SET_NAME, "network_monitor");
	save_thread_pid("network", SNIPER_THREAD_NETWORK);

	check_lockedip(1);

	while (Online) {

		if (net_msg) {
			sniper_free(net_msg->data, net_msg->datalen, NETWORK_GET);
			sniper_free(net_msg, sizeof(struct knet_msg), NETWORK_GET);
		}

		/* 检查待转储的日志文件 */
		check_log_to_send("network");

		/* 如果停止防护，什么也不做 */
		if (sniper_net_loadoff == TURN_MY_ON) {
			/* get_knet_msg里不睡眠，所以此处要睡1秒，否则会显示CPU一直忙 */
			sleep(1);
			net_msg = (knet_msg_t *)get_knet_msg();
			continue;
		}

		/* 如果过期/停止客户端工作，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {

			close_kernel_net_rules();

			sleep(STOP_WAIT_TIME);

			while(1) {
				net_msg = (knet_msg_t *)get_knet_msg();
				if (!net_msg) {
					break;
				}

				sniper_free(net_msg->data, net_msg->datalen, NETWORK_GET);
				sniper_free(net_msg, sizeof(struct knet_msg), NETWORK_GET);
			}
			continue;
		}

		/* 如果功能关闭，什么也不做 */
		if (net_rule.enable != TURNON) {
			sleep(1);
			continue;
		}

		/* 非法连接互联网 */
#if 0
		if (protect_policy_global.network.illegal_connect.enable) {
			time_t now = time(NULL);
			time_t interval = protect_policy_global.network.illegal_connect.interval * 60;

			if (now - last_internet_check_time >= interval) {
				char address[256] = {0};
				int terminate = 0;
				task_recv_t msg = {0};

				pthread_rwlock_rdlock(&protect_policy_global.lock);

				/* 探测地址(IP/domain)只有一个 */
				snprintf(address, sizeof(address), "%s", protect_policy_global.network.illegal_connect.address[0].list);
				/* 普通和运维模式下，可隔离主机。学习模式下，不隔离 */
				if (client_mode_global != LEARNING_MODE) {
					terminate = protect_policy_global.network.illegal_connect.terminate;
				}

				pthread_rwlock_unlock(&protect_policy_global.lock);

				//TODO
				//1、检测目标address是域名时，取其ip，填充日志字段remote_ip
				//2、检测目标address是域名时，可能存在误报和漏报
				//   误报：如hosts文件里或内部DNS恰好给了该域名一个本机或内部ip
				//   漏报：大网是通的，但没有配DNS，解析不出域名，甚至配了DNS，但遇见过个别域名解析不出
				//   解决办法：增加一个或若干ip确认，如114.114.114.114
				//   检测目标是ip时，理论上也可能漏报，比如防火墙拦了此ip
				//   这个功能点先天就有缺陷
				//3、根据隔离的结果上报日志
				if (sniper_ping(address) == 0) {
					if (terminate) {
						update_kernel_net_host_quarantine(1); //隔离

						snprintf(msg.cmd_id, sizeof(msg.cmd_id), "notcareid");
						msg.cmd_type = TASK_HOSTS_QUARANTINE;
						send_task_resp(&msg, RESULT_FAIL, "Quarantine"); //上报隔离状态
					}
					report_illegal_connect_internet(address, terminate);
				}
				last_internet_check_time = now;
			}
		}
#endif

		net_msg = (knet_msg_t *)get_knet_msg();
		if (!net_msg) {
			sleep(1);
			continue;
		}

		req = (struct ebpf_netreq_t *)net_msg->data;
		if (!req) {
			continue;
		}
		int_to_ip(req->daddr, daddr);
		int_to_ip(req->saddr, saddr);
		printf("%-15s %-6d -> %-15s %-6d\n", saddr, req->sport, daddr, req->dport);

#if 0
		if (req->flags.unlockip) {
			send_unlockip_msg(req->ip, OPERATE_OK);
			continue;
		}

		if (req->flags.lockip) {
//			save_lockip(req->ip, req->reason);
			continue;
		}

		if (req->flags.portscan || req->flags.honeyport) {
			report_portscan(req);
			continue;
		}

		if (req->flags.domain) {
			report_domain(req);
			continue;
		}
		if (req->flags.blackin || req->flags.blackout ||
		    req->flags.notwhitein || req->flags.notwhiteout) {
			report_illegal_connection(req);
			continue;
		}
#else
#endif
		
		send_net_msg(req,&msg);
	}
	INFO("net thread exit\n");
	return NULL;
}
