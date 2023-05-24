/*
 * sniper主程序
 * Author: zhengxiang
 * Modified by:xuelei
 * Data: 2023/5/22
 */

#include <signal.h>
#include <pthread.h>
#include <getopt.h>           //getopt_long_only
#include <malloc.h>           //mallopt
#include <sys/syscall.h>      //syscall
#include <sys/utsname.h>      //uname
#include <sys/resource.h>     //setrlimit
#include <sys/sysmacros.h>    //major, minor

#include "header.h"

int selfexit = 0; //客户端主动退出时，设置此标志

/* global val */
char *logsender = "1"; //"1"表示sniper主程序，"2"表示辅助小程序
pid_t sniper_pid = 0;

//TODO 移到conf.c里
int is_uninstall_global = 0;
int qr_status_global = 0;
int is_sync_global = 0;
int is_sync_once = 0;

char *succstr = "Success";
char *failstr = "Failed";
char *termstr = "Terminate";
char *lockstr = "LockIp";
char *qurstr = "Qurantine"; //TODO 移到antivirus.c里
char *startstr = "Startd";
char *stopstr = "Stoped";
int cwdmod = 0;

//TODO 移到policy.c里
/* 加密防护诱捕文件功能开关默认为关 */
int last_encrypt_enable = MY_TURNOFF;
/* 加密防护诱捕文件是否隐藏默认为开 */
int hide_mode = HIDE_TURNON;

//TODO 删除
/*在策略更新过程中判断模式以current为准，策略更新后以last为准*/
unsigned char current_operation_mode = 0;
unsigned char current_learning_mode = 0;

NET_MONITOR net_rule = {0};
FILTER_MONITOR filter_rule = {0};
TRUST_MONITOR trust_rule = {0};
WHITE_MONITOR white_rule = {0};
BLACK_MONITOR black_rule = {0};

unsigned char client_registered = 0;
unsigned char Online = 1;
unsigned char Protect_switch = TURNON; //TODO 移到task.c里
unsigned char tool_mode = 1;            //工具模式，此模式下，不发送离线日志

unsigned char Heartbeat_fail = 0;

time_t mondb_create_time = 0;

char hmac_key[HMAC_MAX] = {0}; //TODO 似乎目前没用上？
char server_version[VER_LEN_MAX] = {0};
char ws_ip[S_IPLEN] = {0};
char ws_path[URL_MAX] = {0};
int ws_port = 0;

int sniper_fd = -1; // /var/run/antiapt.pid fd

/* 计算与管控的时间偏差值serv_timeoff，用于同步日志时间 */
long serv_timeoff = 0;
static void check_server_time(time_t server_time)
{
	long offset = 0;
	time_t my_time = time(NULL);

	if (server_time <= 0) {
		return; //忽略无效的管控时间
	}

	offset = server_time - my_time;

	/* 一分钟内的时间偏差不调整 */
	if (offset > MIN_SERV_TIMEOFF || offset < -MIN_SERV_TIMEOFF) {
		serv_timeoff = offset;
	} else {
		serv_timeoff = 0;
	}
	DBG2(DBGFLAG_HEARTBEAT, "serv_timeoff: %ld\n", serv_timeoff);
}

/* 解析心跳应答包 */
static void parse_heartbeat_reply(char *reply)
{
	cJSON *json, *data, *server_time, *conf, *restart, *sync_log;
	int time_sec = 0;
	char reason[S_LINELEN] = {0};

	if (!reply) {
		return;
	}

	json = cJSON_Parse(reply);
	if (!json) {
		MON_ERROR("parse heartbeat reply %s fail\n", reply);
		return;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("get data from heartbeat reply %s fail\n", reply);
		cJSON_Delete(json);
		return;
	}

	server_time = cJSON_GetObjectItem(data, "server_time");
	if (!server_time) {
		MON_ERROR("get server_time from heartbeat reply %s fail\n", reply);
	} else {
		time_sec = server_time->valueint;
		check_server_time(time_sec); //获取与管控的时间偏差，用于同步日志时间
	}

	restart = cJSON_GetObjectItem(data, "restart");
	if (restart && restart->valueint == 1) {
		INFO("server notify me restart ...\n");
		INFO("管控通知客户端重起 ...\n");
		myrestart();
	}

	conf = cJSON_GetObjectItem(data, "conf");
	if (conf && conf->valueint == 1) {
		INFO("heartbeat update conf ...\n");
		if (get_conf(reason, sizeof(reason)) < 0) {
			MON_ERROR("heartbeat update conf fail: %s\n", reason);
		} else {
			INFO("heartbeat update conf success\n");
		}
	}

	sync_log = cJSON_GetObjectItem(data, "sync_log");
	if (sync_log && sync_log->valueint == 1) {
		INFO("heartbeat upload runlog %s ...\n", LOGFILE);
		if (access(LOGFILE1, F_OK) == 0) {
			if (upload_file(LOGFILE1, DEBUG_LOG_URL) < 0) {
				MON_ERROR("heartbeat upload log %s fail\n", LOGFILE1);
			} else {
				INFO("heartbeat upload log %s success\n", LOGFILE1);
			}
		}
		if (upload_file(LOGFILE, DEBUG_LOG_URL) < 0) {
			MON_ERROR("heartbeat upload log %s fail\n", LOGFILE);
		} else {
			INFO("heartbeat upload log %s success\n", LOGFILE);
		}
	}

	cJSON_Delete(json);
}

/*
 * sniper工具和病毒扫描程序使用了此函数
 * 另外，sniper -t还用此函数来检测与管控的通信是否正常。返回值-1，异常；0，正常
 */
int sniper_adjust_time(void)
{
	int time_sec = 0;
	char *post, reply[REPLY_MAX] = {0};
	cJSON *object, *json, *data, *server_time;

	object = cJSON_CreateObject();
	if (!object) {
		return -1;
	}

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	post = cJSON_PrintUnformatted(object);
	if (!post) {
		cJSON_Delete(object);
		return -1;
	}

	if (http_post("api/client/heartbeat", post, reply, sizeof(reply)) <= 0) {
		cJSON_Delete(object);
		free(post);
		return -1;
	}

	cJSON_Delete(object);
	free(post);

	json = cJSON_Parse(reply);
	if (!json) {
		MON_ERROR("parse heartbeat reply %s fail\n", reply);
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("get data from heartbeat reply %s fail\n", reply);
		cJSON_Delete(json);
		return -1;
	}

	server_time = cJSON_GetObjectItem(data, "server_time");
	if (!server_time) {
		MON_ERROR("get server_time from heartbeat reply %s fail\n", reply);
		cJSON_Delete(json);
		return -1;
	}

	time_sec = server_time->valueint;
	check_server_time(time_sec);

	cJSON_Delete(json);
	return 0;
}

/*
 * 解析出websocket通信参数：服务端ip、端口、地址。如
 * url:  ws://192.168.10.200:8000/ws/task
 * ip:   192.168.10.200
 * port: 8000
 * path: /ws/task
 */
static int parse_websocket_url(char *ws_url)
{
	int ret = 0, port = 0;
	char ip[64] = {0};    //S_IPLEN
	char path[128] = {0}; //URL_MAX

	ret = sscanf(ws_url, "%*[^/]//%63[^:]:%d%127[^-]", ip, &port, path);
	if (ret != 3) {
		return -1;
	}

	if (port <= 0 || port > 65535) {
		return -1;
	}

	snprintf(ws_ip, sizeof(ws_ip), "%s", ip);
	ws_port = port;
	snprintf(ws_path, sizeof(ws_path), "%s", path);
	return 0;
}

void save_hmac(void)
{
	FILE *fp = NULL;

	fp = sniper_fopen("/opt/snipercli/.hmac", "w", FILE_GET);
	if (fp == NULL) {
		MON_ERROR("save hmac fail: %s\n", strerror(errno));
		return;
	}

	if (fwrite(hmac_key, HMAC_MAX, 1, fp) != 1) {
		MON_ERROR("save hmac fail: %s\n", strerror(errno));
		sniper_fclose(fp, FILE_GET);
		return;
	}
	fflush(fp);
	sniper_fclose(fp, FILE_GET);
}

/*
 * 解析注册应答消息
 * 返回值-1，注册失败；0，注册成功
 * ws_ok标志记录websocket通信参数是否解析成功，-1失败，0成功
 */
static int parse_register_resp(char *reply, int *ws_ok)
{
	cJSON *json, *code, *message, *data, *hmac, *ws, *server_time, *server_ver;
	int time_sec = 0;
	char ws_url[URL_MAX] = {0};

	if (reply == NULL) {
		return -1;
	}

	if (strstr(reply, "502 Bad Gateway")) {
		MON_ERROR("register server fail: 502 Bad Gateway\n");
		return -1;
	}

	json = cJSON_Parse(reply);
	if (!json) {
		MON_ERROR("parse register reply %s fail\n", reply);
		return -1;
	}

	code = cJSON_GetObjectItem(json, "code");
	if (!code) {
		MON_ERROR("get code from register reply %s fail\n", reply);
		cJSON_Delete(json);
		return -1;
	}

	/* 注册失败 */
	if (code->valueint != 0) {
		/* 许可不足 */
		if (code->valueint == 1001) {
			conf_global.licence_expire = 1; //借用许可过期，使客户端啥也不做
			MON_ERROR("register fail, license exceeded\n");
		} else {
			MON_ERROR("register fail, error code %d\n", code->valueint);
		}

		cJSON_Delete(json);
		return -1;
	}

	/* 注册成功 */

	/* 如果注册成功，但取websocket通信参数失败，设ws_ok标志-1，后面将按默认规则设置参数。
	   取其他内容失败，目前仅记antiapt.log日志，没有额外的处理 */

	message = cJSON_GetObjectItem(json, "message");
	if (!message) {
		MON_ERROR("get message from register reply %s fail\n", reply);
	} else if (strcmp(message->valuestring, "success") != 0) {
		MON_ERROR("message value not success, register reply %s\n", reply);
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("get data from register reply %s fail\n", reply);
	} else {
		hmac = cJSON_GetObjectItem(data, "hmac");
		if (!hmac) {
			MON_ERROR("get hmac from register reply %s fail\n", reply);
		} else {
			snprintf(hmac_key, sizeof(hmac_key), "%s", hmac->valuestring);
			//save_hmac();
		}

		server_time = cJSON_GetObjectItem(data, "server_time");
		if (!server_time) {
			MON_ERROR("get server_time from register reply %s fail\n", reply);
		} else {
			time_sec = server_time->valueint;
			check_server_time(time_sec);
		}

		ws = cJSON_GetObjectItem(data, "ws");
		if (!ws) {
			MON_ERROR("get ws from register reply %s fail\n", reply);
		} else {
			snprintf(ws_url, sizeof(ws_url), "%s", ws->valuestring);
			*ws_ok = parse_websocket_url(ws_url);
		}

		/* 注册返回信息中如果没有server_ver，默认为1.0.0.20210630或之前的版本 */
		server_ver = cJSON_GetObjectItem(data, "server_ver");
		if (!server_ver) {
			snprintf(server_version, sizeof(server_version), "1.0.0.20210630");
		} else {
			snprintf(server_version, sizeof(server_version), "%s", server_ver->valuestring);
		}
	}

	cJSON_Delete(json);
	return 0;
}

static int send_register_msg(char *webproto, char *ip, unsigned short port, char *post)
{
	char reply[REPLY_MAX] = {0};
	char url[S_LINELEN] = {0};
	int ipv6_url = 0, ws_ok = 0;

	if (!webproto || !ip || !post) {
		return -1;
	}

	if (strchr(ip, ':') != NULL) {
		ipv6_url = 1;
	}

	if (ipv6_url) {
		snprintf(url, sizeof(url), "%s://[%s]:%u/api/client/register/", webproto, ip, port);
	} else {
		snprintf(url, sizeof(url), "%s://%s:%u/api/client/register/", webproto, ip, port);
	}

	if (http_post_data(url, post, reply, sizeof(reply)) < 0) {
		DBG2(DBGFLAG_HEARTBEAT, "register %s fail, sendmsg error\n", url);
		return -1;
	}

	snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "%s", webproto);
	if (strstr(reply, "HTTPS")) {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "https");
		if (ipv6_url) {
			snprintf(url, sizeof(url), "https://[%s]:%u/api/client/register/", ip, port);
		} else {
			snprintf(url, sizeof(url), "https://%s:%u/api/client/register/", ip, port);
		}
		if (http_post_data(url, post, reply, sizeof(reply)) < 0) {
			DBG2(DBGFLAG_HEARTBEAT, "register %s fail, sendmsg error\n", url);
			return -1;
		}
	}

	if (parse_register_resp(reply, &ws_ok) < 0) {
		DBG2(DBGFLAG_HEARTBEAT, "register %s fail, parse reply %s error\n", url, reply);
		return -1;
	}

	/* 如果注册成功，但获取websocket参数失败，按默认规则设置参数 */
	if (ws_ok < 0) {
		snprintf(ws_ip, sizeof(ws_ip), "%s", ip);
		ws_port = 8000;
		snprintf(ws_path, sizeof(ws_path), "/ws/task");
	}

	return 0;
}

/* 检测管控是否可连接，并用与管控连接的本机ip修正If_info.ip */
static int try_to_connect(char *serverip, unsigned short serverport)
{
	int sockfd = 0, i = 0;
	socklen_t len = sizeof(struct sockaddr_in);
	struct sockaddr_in serv_addr = {0}, my_addr = {0};
	char myip[S_IPLEN] = {0}, ethip[S_IPLEN] = {0};
	struct timeval timeout = { 10, 0 };

	if (!serverip) {
		return -1;
	}

	/* try to make a connection to determine which if will be used */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		DBG2(DBGFLAG_HEARTBEAT, "connect server %s fail, "
			"create socket error: %s\n", serverip, strerror(errno));
		return -1;
	}

	/* 设置连接超时时间 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)) < 0) {
		DBG2(DBGFLAG_HEARTBEAT, "set connect timeout fail: %s\n", strerror(errno));
	} else {
		DBG2(DBGFLAG_HEARTBEAT, "set connect timeout %ds\n", timeout.tv_sec);
	}

	inet_pton(AF_INET, serverip, &serv_addr.sin_addr);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(serverport);

	if (connect(sockfd, (struct sockaddr *)&serv_addr, len) < 0) {
		DBG2(DBGFLAG_HEARTBEAT, "connect server %s:%d fail: %s\n",
		       serverip, serverport, strerror(errno));
		close(sockfd);
		return -1;
	}

	if (getsockname(sockfd, (struct sockaddr *)&my_addr, &len) < 0) {
		DBG2(DBGFLAG_HEARTBEAT, "get ip connected to server fail, "
			"getsocktname error: %s\n", strerror(errno));
		close(sockfd);
		return 0;
	}

	inet_ntop(AF_INET, &my_addr.sin_addr, myip, S_IPLEN);
	DBG2(DBGFLAG_HEARTBEAT, "my connect ip: %s, port: %d\n", myip, my_addr.sin_port);

	close(sockfd);

	/* 连接管控的ip和If_info.ip相同，不需要改变If_info.ip */
	if (strcmp(myip, If_info.ip) == 0) {
		return 0;
	}

	/* 修正If_info.ip */
	snprintf(If_info.ip, sizeof(If_info.ip), "%s", myip);

	/* 取对应的mac */
	for (i = 0; i < ethinfo_num; i++) {
		snprintf(ethip, sizeof(ethip), "%d.%d.%d.%d", IPSTR(&ethinfo[i].ip));
		if (strcmp(myip, ethip) == 0) {
			snprintf(If_info.mac, sizeof(If_info.mac),
				"%02X-%02X-%02X-%02X-%02X-%02X", MACSTR(ethinfo[i].mac));
			break;
		}
	}

	INFO("Change my work ip to %s, mac to %s\n", If_info.ip, If_info.mac);

	return 0;
}

/*
 * 注册客户端
 * 注册失败返回-1, 注册成功返回0，并在状态文件中记录注册成功
 *
 * upload_sysinfo()比较慢，用sysinfo_flag控制是否在注册时上报
 */
static int register_client_v5(char *ip, unsigned short port, int sysinfo_flag)
{
	int fail = 0;
	char *post = NULL;
	cJSON *object = NULL;
	task_recv_t msg = {0};
	char portstr[8] = {0};
	struct stat st = {0};
	struct timeval tv = {0};

	if (!ip || ip[0] == 0) {
		return -1;
	}
	if (try_to_connect(ip, port) < 0) { //管控不可连接则不必白白尝试注册
		return -1;
	}

	object = cJSON_CreateObject();
	cJSON_AddStringToObject(object, "ip", If_info.ip);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "hostname", Sys_info.hostname);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "os", Sys_info.os_dist);
	cJSON_AddStringToObject(object, "machine_model", Sys_info.machine_model);
	cJSON_AddStringToObject(object, "client_ver", Sys_info.version);
	cJSON_AddStringToObject(object, "virus_ver", "");
	cJSON_AddStringToObject(object, "vuln_ver", "");
	cJSON_AddStringToObject(object, "login_user", login_users);
	cJSON_AddStringToObject(object, "ipv6", If_info.ipv6);
	cJSON_AddStringToObject(object, "install_token", Sys_info.token);

	post = cJSON_PrintUnformatted(object);

	if (port == 0) {
		/* 如果没有指定与管控的通信端口，尝试443和8000 */
		if (send_register_msg("https", ip, 443, post) == 0) {
			port = 443;
			snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "https");
		} else if (send_register_msg("http", ip, 8000, post) == 0) {
			port = 8000;
			snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "http");
		} else {
			fail = 1;
		}
	} else {
		/* 端口带443，如18443，4430，都视为用https协议 */
		snprintf(portstr, sizeof(portstr), "%d", port);
		if (strstr(portstr, "443")) {
			snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "https");
			if (send_register_msg("https", ip, port, post) < 0) {
				fail = 1;
			}
		} else {
			snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "http");
			if (send_register_msg("http", ip, port, post) < 0) {
				fail = 1;
			}
		}
	}

	cJSON_Delete(object);
	free(post);

	if (fail) {
		return -1; //注册失败
	}

	INFO("register to %s://%s:%d success. server version: %s\n",
		Serv_conf.webproto, ip, port, server_version);
	client_registered = 1;
	save_sniper_status("register client ok\n");

	Serv_conf.port = port;
	snprintf(Serv_conf.ip, sizeof(Serv_conf.ip), "%s", ip);

	get_client_mode_global();

	/* sniper程序一分钟内有修改，视为是新安装的程序 */
	if (stat("/sbin/sniper", &st) == 0) {
		gettimeofday(&tv, NULL);
		if (tv.tv_sec - st.st_ctime < 60) {
			send_client_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Installed");
		}
	}

	send_client_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Startd");

	curr_servport = port;
	if (ip != curr_servip) {
		snprintf(curr_servip, sizeof(curr_servip), "%s", ip);
	}
	if (save_servaddr(port, ip, CURRENT_SERVER) < 0) {
		MON_ERROR("save %s:%u into %s fail: %s\n",
			ip, port, CURRENT_SERVER, strerror(errno));
	}

	/* 注册成功后，更新客户端配置和规则 */
	snprintf(msg.cmd_id, sizeof(msg.cmd_id), "nottask"); //共用任务处理函数，但不发任务应答消息
	msg.cmd_type = TASK_UPDATE_CONF;
	update_conf_my(&msg);
	msg.cmd_type = TASK_UPDATE_RULE;
	update_rule_my(&msg);

	/* 此处检测是因为上线时默认加载上次策略，相同不会再次拉策略，同时client_registered=0不会报告日志，不发送内核是因为不需要 */
	check_backup_free_size();

	if (sysinfo_flag) {
		upload_sysinfo(1);
	}

	return 0;
}

/* 卸载sniper时清理安装文件和数据，保留antiapt.log，用于查错 */
void sniper_cleanup(void)
{
	struct utsname uts;
	char modfile[S_FILENAMELEN] = {0};

	/* 取消开机自启动设置 */
	if (access("/etc/rc.d/rc.local", F_OK) == 0) {
		system("sed -i '/sniper/d' /etc/rc.d/rc.local");
	}
	if (access("/etc/rc.local", F_OK) == 0) {
		system("sed -i '/sniper/d' /etc/rc.local");
	}


	system("rm -rf /opt/snipercli"); //删除安装文件和数据

	unlink(SNIPER_CONF);     //删除管控ip和端口配置文件
	unlink(VERSION_FILE);    //删除版本文件
	unlink(PIDFILE);         //删除客户端pid文件
	unlink(ASSIST_PIDFILE);  //删除小程序pid文件
	unlink(SNIPER_PROG);     //删除客户端程序
	unlink(ANTIVIRUS_PROG);  //删除辅助小程序
	unlink("/etc/cron.d/sniper_cron");               //删除定时任务
	unlink("/etc/xdg/autostart/snipertray.desktop"); //取消托盘开机自启

	operate_encrypt_trap_files(HIDE_TURNON, OP_DELETE); //删除防勒索蜜罐文件

	/* 删除内核模块 */
	uname(&uts);
	snprintf(modfile, sizeof(modfile), "/lib/modules/%s/kernel/kernel/%s",
		uts.release, MODULE_FILE_NAME);
	unlink(modfile);

	kill_snipertray(); //停止托盘程序

	//TODO 考虑删除备份数据
}

static void cleanup(int uninstall)
{
	INFO("cleanup\n");

	if (uninstall) {
		INFO("uninstall sniper\n");
		sniper_cleanup();
	}
	// TODO(luoyinhong): del_ebpf
#if 0
	// del_module(MODULE_NAME);
#else
	unload_ebpf_program();
#endif
}

/* 如果客户端程序启动时未注册成功，则由心跳线程调用此函数进行注册 */
static void init_register_client(void)
{
	int i = 0;
	char *ip = NULL;
	unsigned short port = 0;
	int hb_interval = 30;    //30~240, default 30s

	while (Online) {
		init_serverconf(); //每次尝试注册前都获取管控配置信息，以免之前的配置有误导致注册失败

		if (If_info.ip[0] == 0) {
			/* 主机之前未配置网络，检查当前是否新配置了网络 */
			ethinfo_num = 0;
			ethinfo = get_current_ethinfo(&ethinfo_num);
			if (ethinfo) {
				snprintf(If_info.mac, sizeof(If_info.mac),
					"%02X-%02X-%02X-%02X-%02X-%02X", MACSTR(ethinfo[0].mac));
				snprintf(If_info.ip, sizeof(If_info.ip),
					"%d.%d.%d.%d", IPSTR(&ethinfo[0].ip));
			}

			/* 没有配ip则不必白白尝试注册 */
			if (If_info.ip[0] == 0) {
				DBG2(DBGFLAG_HEARTBEAT, "no ip configed, run in localmode\n");
				sleep(hb_interval);
				continue;
			}
		}

		/* 尝试注册的顺序：管控下发的服务器ip列表、上次使用的管控ip、安装时设置的管控ip */

		port = curr_servport ? curr_servport : orig_servport;

		pthread_rwlock_rdlock(&conf_global.lock);
		for (i = 0; i < conf_global.server_num; i++) {
			ip = conf_global.server_ip[i].list;
			if (register_client_v5(ip, port, 1) == 0) {
				pthread_rwlock_unlock(&conf_global.lock);
				return;
			}
		}
		pthread_rwlock_unlock(&conf_global.lock);

		if (register_client_v5(curr_servip, curr_servport, 1) == 0 ||
		    register_client_v5(orig_servip, orig_servport, 1) == 0) {
			return;
		}

		sleep(hb_interval);
	}
}

/* 心跳正常时检查是否要切换到优先服务器 */
static void switch_priority_server(int server_num, struct _ip_list *server_ip)
{
	char *ip = NULL;

	/* 优先连接服务器列表的第一个服务器 */

	/* 服务器列表为空 */
	if (server_num <= 0) {
		return;
	}

	ip = server_ip[0].ip;
	/* 当前使用的正是第一个服务器 */
	if (strcmp(curr_servip, ip) == 0) {
		return;
	}

	/* 切换到第一个服务器。 如果切换失败，仍然使用当前服务器 */
	DBG2(DBGFLAG_HEARTBEAT,"try to register to priority server %s:%d\n", ip, curr_servport);
	register_client_v5(ip, curr_servport, 1);
}

/* 心跳失败时选择其他可用服务器 */
static void switch_server(int server_num, struct _ip_list *server_ip)
{
	int i = 0;
	char *ip = NULL;

	for (i = 0; i < server_num; i++) {
		ip = server_ip[i].ip;

		/* 就是当前使用的服务器不通，不用再尝试 */
		if (strcmp(curr_servip, ip) == 0) {
			continue;
		}

		DBG2(DBGFLAG_HEARTBEAT,"try to register to another server %s:%d\n", ip, curr_servport);
		if (register_client_v5(ip, curr_servport, 1) == 0) {
			return;
		}
	}
}

/*
 * heartbeat thread
 * post:  {"uuid":"360705ccaab56f5698bdc5f8a692551a"}
 * reply: {"code":0,"message":"success","data":{"server_time":1645532585,"conf":0,"restart":0,"sync_log":0}}
 */
static void *heartbeat_send(void *ptr)
{
	int ret = 0;
	int hb_interval = 30;    //default 30 sec, can set value: 30-240
	char *post = NULL;
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL;
	struct _ip_list *server = NULL;
	int ip_num = 0;
	int size = 0;
	int i = 0;
	char reason[S_LINELEN] = {0};

	prctl(PR_SET_NAME, "heartbeat");
	save_thread_pid("heartbeat", SNIPER_THREAD_HEARTBEAT);

	if (client_registered) {
		/* upload_sysinfo很耗时间，程序启动时不在主进程register_client时做，在心跳线程里做 */
		/* 启动资产清点，默认全部采集 */
		printf("upload_sysinfo ...\n");
		// upload_sysinfo(1);
		printf("upload_sysinfo done\n");
	} else {
		init_register_client(); //注册成功会做upload_sysinfo
	}

	object = cJSON_CreateObject();
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	post = cJSON_PrintUnformatted(object);
	
	while (Online) {
		/* 如果停止客户端工作，什么也不做 */
		if (client_disable == TURN_MY_ON) {
			sleep(STOP_WAIT_TIME);
			continue;
		}

		pthread_rwlock_rdlock(&conf_global.lock);

		hb_interval = conf_global.heartbeat_interval;
		if (hb_interval < 30) {
			hb_interval = 30;
		}

		ip_num = conf_global.server_num;
		size = sizeof(struct _ip_list) * ip_num;
		server = (struct _ip_list *)malloc(size); //TODO 是否没必要总是malloc/free
		if (!server) {
			ip_num = 0;
		} else {
			for (i = 0; i < ip_num; i++) {
				snprintf(server[i].ip, sizeof(server[i].ip), "%s", conf_global.server_ip[i].list);
			}
		}

		pthread_rwlock_unlock(&conf_global.lock);

		// ret = http_post("api/client/heartbeat", post, reply, sizeof(reply));
		DBG2(DBGFLAG_HEARTBEAT,"heartbeat to %s:%d ret %d, reply: %s\n",
					Serv_conf.ip, Serv_conf.port, ret, reply);
		if (ret < 0) {
			MON_ERROR("heartbeat fail, reply:%s\n", reply);
			Heartbeat_fail = 1;
			switch_server(ip_num, server); //心跳失败，尝试连接其他可用的服务器
			mysleep(hb_interval);
			if (server) {
				free(server);
			}
			continue;
		}

		/*
		 * 通常ret>0
		 * ret为0表示管控没有识别到客户端的uuid,需要重新注册
		 * 旧版本在升级的情况下会=0，现在管控已经储存了客户端的uuid, 不再复现
		 * 现在重新安装管控会出现此情况
		 */
		if (ret == 0) {
			register_client_v5(curr_servip, curr_servport, 1);

			mysleep(hb_interval);
			if (server) {
				free(server);
			}
			continue;
		}

		switch_priority_server(ip_num, server); //总是尝试与主服务器连接

		/* 恢复心跳时，拉取最新的配置信息 */
		if (Heartbeat_fail == 1) {
			memset(reason, 0, sizeof(reason));
			get_conf(reason, sizeof(reason));
		}
		Heartbeat_fail = 0;

		parse_heartbeat_reply(reply);

		mysleep(hb_interval);
		if (server) {
			free(server);
		}
	}

	cJSON_Delete(object);
	free(post);

	INFO("heartbeat thread exit\n");
	return NULL;
}

/*
 * ZX20200821 使用libssl-dev-1.1时，不需要下面的函数
 * /usr/include/openssl/crypto.h里说对OPENSSL_API_COMPAT < 0x10100000L的，
 * CRYPTO_set_id_callback()和CRYPTO_set_locking_callback() no longer used
 * 没有定义OPENSSL_API_COMPAT，说明用的是libssl-dev-1.0.2
 */
#ifndef OPENSSL_API_COMPAT
#include <openssl/crypto.h>
static pthread_mutex_t *openssl_lockarray;

static void openssl_lock_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(openssl_lockarray[type]));
	} else {
		pthread_mutex_unlock(&(openssl_lockarray[type]));
	}
}

static unsigned long thread_id(void)
{
	unsigned long ret;

	ret = (unsigned long)pthread_self();
	return(ret);
}

static void init_openssl_locks(void)
{
	int i;

	openssl_lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(openssl_lockarray[i]), NULL);
	}

	CRYPTO_set_id_callback(thread_id);
	CRYPTO_set_locking_callback(openssl_lock_callback);
}


static void kill_openssl_locks(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(openssl_lockarray[i]));
	}

	OPENSSL_free(openssl_lockarray);
}
#endif

/* 顺序要和header.h里SNIPER_THREAD_XXX的内容一致 */
pthread_t heartbeat_tr = {0}; //心跳
pthread_t kexecmsg_tr  = {0}; //收取内核进程消息
pthread_t kfilemsg_tr  = {0}; //收取内核文件消息
pthread_t knetmsg_tr   = {0}; //收取内核网络消息
pthread_t websocket_tr = {0}; //接收管控下发的任务
pthread_t logsend_tr   = {0}; //发送客户端日志
pthread_t rescheck_tr  = {0}; //客户端程序自身负载监控
pthread_t process_tr   = {0}; //处理进程消息
pthread_t filemon_tr   = {0}; //处理文件消息
pthread_t network_tr   = {0}; //处理网络消息
pthread_t login_tr     = {0}; //处理登录事件
pthread_t crack_tr     = {0}; //处理爆破事件
pthread_t task_tr      = {0}; //处理管控下发的任务
pthread_t cdrom_tr     = {0}; //刻录监控
pthread_t inotify_tr   = {0}; //处理inotify事件，目前仅监控打印日志
pthread_t uevent_tr    = {0}; //处理设备事件，目前仅监控u盘拔插
pthread_t selfcheck_tr = {0}; //系统整体的负载监控，和各进程的负载是否超限
#ifdef USE_AVIRA
pthread_t kvirusmsg_tr = {0}; //收取内核病毒文件消息
pthread_t virusfilter_tr = {0}; //过滤病毒文件线程
pthread_t antivirus_tr  = {0}; //防病毒线程
#endif
struct sniper_thread_struct sniper_thread[SNIPER_THREAD_MAX] = {
	{ 0, &heartbeat_tr,  heartbeat_send,      "heartbeat" },
	{ 0, &kexecmsg_tr,   kexec_msgd,          "kexec_msgd" },
	// { 0, &kfilemsg_tr,   kfile_msgd,          "kfile_msgd" },
	// { 0, &knetmsg_tr,    knet_msgd,           "knet_msgd" },
	{ 0, &websocket_tr,  websocket_monitor,   "websocket" },
	{ 0, &logsend_tr,    log_send,            "logsend" },
	// { 0, &rescheck_tr,   resource_check,      "rescheck" },
	{ 0, &process_tr,    process_monitor,     "process" },    //以下这些线程会产生批量日志
	// { 0, &filemon_tr,    file_monitor,        "file" },
	// { 0, &network_tr,    net_monitor,         "network" },
	// { 0, &login_tr,      login_monitor,       "login" },
	// { 0, &crack_tr,      crack_monitor,       "crack" },
	// { 0, &task_tr,       task_monitor,        "task" },
	// { 0, &cdrom_tr,      burn_mgr,            "cdrom" },
	// { 0, &inotify_tr,    inotify_monitor,     "inotify" },
	// { 0, &uevent_tr,     uevent_monitor,      "uevent" },
	// { 0, &selfcheck_tr,  self_check,          "selfcheck" },
#ifdef USE_AVIRA
	// { 0, &kvirusmsg_tr,  kvirus_msgd,         "kvirus_msgd" },
	// { 0, &virusfilter_tr,virusfilter_monitor, "virusfilter" },
	// { 0, &antivirus_tr,  antivirus_monitor,   "antivirus" },
#endif
	{ 0, NULL, NULL, "" }
};

/* 记录工作线程的pid和活跃时刻 */
void save_thread_pid(char *thread_name, unsigned int thread_seq)
{
	pid_t tid = 0;
	char info[256] = {0};

	if (!thread_name || thread_seq >= SNIPER_THREAD_NUMS) {
		return;
	}

	tid = syscall(SYS_gettid);
	sniper_thread[thread_seq].pid = tid;

	snprintf(info, sizeof(info), "%s thread id %d\n", thread_name, tid);
	save_sniper_status(info);
}

static void show_usage(void)
{
	printf("\nUsage:  sniper [options]\n\n");
	printf("  --version, -v\n	Print sniper version.\n\n");
	printf("  --list,    -l\n	Show policy.\n\n");
	printf("  --post,    -p\n       Post host infomation.\n\n");
	printf("  --status,  -t\n	Report sniper status.\n\n");
	printf("  --random,  -r\n	Create random number string.\n\n");
	printf("  --stop  [token],    -s\n	Stop sniper.\n\n");
	printf("  --unlockip [ip],    -i\n	Unlock ip.\n\n");
	printf("  --display_backup,   -D\n	Display backup files.\n\n");
	printf("  --recovery_file [path],    -R\n	Restore the file to its original location\n\n");
	printf("  --force_unintsall [code],  -f\n	Force uninstall client.\n\n");

	/* 不公开的用法 */
	//printf("  --listloop,      -L\n	Watch policy update.\n\n");
	//printf("  --runtime [n],   -n\n	Only run n minutes for test.\n\n");
	//printf("  --wtmp [path],   -w\n	Show records in log file.\n\n");

	fflush(stdout);
}

static void init_create_file(char *name, mode_t mode)
{
	int fd = 0;
	char path[256] = {0};
	struct stat st = {0};

	snprintf(path, sizeof(path), "%s/%s", WORKDIR, name);
	if (stat(path, &st) == 0) {
		if (st.st_mode == mode) {
			return;
		}
		if (chmod(path, mode) == 0) {
			return;
		}
		MON_ERROR("init_create_file: set %s mode %o -> %o fail: %s\n",
			path, st.st_mode, mode, strerror(errno));
		return;
	}

	if (errno != ENOENT) {
		MON_ERROR("init_create_file: stat %s fail: %s\n", path, strerror(errno));
		return;
	}

	fd = open(path, O_CREAT|O_RDWR, mode);
	if (fd < 0) {
		MON_ERROR("init_create_file: open %s fail: %s\n", path, strerror(errno));
		return;
	}

	/* 受umask影响，创建的文件的权限可能变小，强制再设置一下mode */
	if (fchmod(fd, mode) < 0) {
		MON_ERROR("init_create_file: set %s mode %o fail: %s\n", path, mode, strerror(errno));
	}
	close(fd);
}

static void init_dbdir(void)
{
	int ret = 0, i = 0;
	char dirname[256] = {0};
	struct stat sbuf = {0};

	/* sniper托盘程序要访问/opt/snipercli目录，故设目录权限0755 */
	/* mondb_create_time = min(dbtime, dbstamp); 如果取不到这两个时间，则用workdirtime */
	mkdir("/opt", 0755); //在ubuntu 1604发现过无/opt
	mkdir(WORKDIR, 0755);
	ret = stat(WORKDIR, &sbuf);
	if (ret < 0) {
		MON_ERROR("stat %s fail : %s\n", WORKDIR, strerror(errno));
	} else {
		if (sbuf.st_mode != 0755 && chmod(WORKDIR, 0755) < 0) {
			MON_ERROR("chmod %s fail : %s\n", WORKDIR, strerror(errno));
		}
		mondb_create_time = sbuf.st_mtime;
	}

	/* .nodeinfo保存主机信息，任意用户都可能设置或修改，故权限设为0666 */
	init_create_file(NODEINFO, 0666);

	/* .language保存中英文语言选择，任意用户都可能设置或修改，故权限设为0666 */
	init_create_file(LANGINFO, 0666);

	snprintf(dirname, sizeof(dirname), "%s/%s", WORKDIR, DBDIR);
	mkdir(dirname, 0700);
	ret = stat(dirname, &sbuf);
	if (ret < 0) {
		MON_ERROR("stat %s fail : %s\n", dirname, strerror(errno));
	} else {
		mondb_create_time = sbuf.st_mtime;
	}

	snprintf(dirname, sizeof(dirname), "%s/%s/%s", WORKDIR, DBDIR, DBSTAMP);
	mkdir(dirname, 0700);
	ret = stat(dirname, &sbuf);
	if (ret < 0) {
		MON_ERROR("stat %s fail : %s\n", dirname, strerror(errno));
	} else if (mondb_create_time == 0 ||
		mondb_create_time > sbuf.st_mtime) {
		mondb_create_time = sbuf.st_mtime;
	}

	snprintf(dirname, sizeof(dirname), "%s/%s/%s", WORKDIR, DBDIR, SSHDIR);
	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
	}

	snprintf(dirname, sizeof(dirname), "%s/%s/%s", WORKDIR, DBDIR, CMDDIR);
	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
	}

	snprintf(dirname, sizeof(dirname), "%s/%s/%s", WORKDIR, DBDIR, DENYIPDIR);
	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
	}

	snprintf(dirname, sizeof(dirname), "%s/%s/%s", WORKDIR, DBDIR, BACKUP);
	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
	}

	if (mkdir(BACKUP_DIR, 0707) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", BACKUP_DIR, strerror(errno));
	}
	chmod(BACKUP_DIR, 0707);

	snprintf(dirname, sizeof(dirname), "%s/%s/%s", WORKDIR, DBDIR, CONFIGDIR);
	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
	}

	/* 备份恢复图形界面不能删除数据库，这边不用给777权限 */
	snprintf(dirname, sizeof(dirname), "%s/%s", WORKDIR, FILEDB);
	if (mkdir(dirname, 0755) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
	}

	/* 病毒数据库需要普通用户也能删除记录，必须777权限，和其他数据库分开存放，可以设置目录不同的权限 */
	snprintf(dirname, sizeof(dirname), "%s/%s", WORKDIR, VIRUSDB);
	if (mkdir(dirname, 0777) < 0 && errno != EEXIST) {
		MON_ERROR("create %s fail : %s\n", dirname, strerror(errno));
	}
	chmod(dirname, 0777);

	/* 创建批量日志目录 */
	if (mkdir(LOCALLOG_DIR, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", LOCALLOG_DIR, strerror(errno));
	}

	/* 为每个工作线程创建批量日志子目录 */
	for (i = 0; i < SNIPER_THREAD_NUMS; i++) {
		if (sniper_thread[i].desc[0] == 0) {
			continue;
		}

		snprintf(dirname, sizeof(dirname), "%s/%s", LOCALLOG_DIR, sniper_thread[i].desc);
		if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
			MON_ERROR("create dir %s fail : %s\n", dirname, strerror(errno));
		}
	}

	if (mkdir(LOG_SEND_DIR, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", LOG_SEND_DIR, strerror(errno));
	}

	if (mkdir(SAMPLE_DIR, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", SAMPLE_DIR, strerror(errno));
	}

	if (mkdir(DOWNLOAD_DIR, 0700) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", DOWNLOAD_DIR, strerror(errno));
	}

	/* 备份恢复错误信息如果无法记录到/tmp下会记录到此目录下，权限改为777 */
	if (mkdir(SNIPER_TMPDIR, 0777) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", SNIPER_TMPDIR, strerror(errno));
	}
	chmod(SNIPER_TMPDIR, 0777);

	/* 创建防病毒程序日志目录，存放起防病毒程序的log */
	if (mkdir(ANTIVIRUS_LOGDIR, 0777) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", ANTIVIRUS_LOGDIR, strerror(errno));
	}

	/* 权限只能777, 否则普通用户fopen失败*/
	chmod(ANTIVIRUS_LOGDIR, 0777);

	/* 创建防病毒程序通知目录，存放起防病毒程序的uid, 通过inotify线程创建对应用户的隔离目录 */
	if (mkdir(INOTIFY_QUARANTINE_DIR, 0777) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", INOTIFY_QUARANTINE_DIR, strerror(errno));
	}
	/* 权限只能777, 否则普通用户fopen失败*/
	chmod(INOTIFY_QUARANTINE_DIR, 0777);

	/* 创建防病毒程序pid目录，用来限制一个用户同一时间只能启动一次 */
	if (mkdir(ANTIVIRUS_PIDDIR, 0777) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", ANTIVIRUS_PIDDIR, strerror(errno));
	}
	/* 权限只能777, 否则普通用户fopen失败*/
	chmod(ANTIVIRUS_PIDDIR, 0777);

	/* 创建病毒隔离目录 */
	snprintf(dirname, sizeof(dirname), "%s/%s", WORKDIR, QUARANTINE);
	if (mkdir(dirname, 0755) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", dirname, strerror(errno));
	}
	chmod(dirname, 0755);

	/* 用于存放root扫描出来的病毒隔离文件 */
	if (mkdir(ROOT_QUARANTINE_DIR, 0755) < 0 && errno != EEXIST) {
		MON_ERROR("create dir %s fail : %s\n", ROOT_QUARANTINE_DIR, strerror(errno));
	}

	/*
	 * 解决redhat6.1 reboot失败的问题
	 *
	 * reboot失败原因如下：
	 * 1) sniper在redhat6.1上运行会创建/var/tmp/etilqs_lJRDfmNE3wChMhU这样的文件
	 *    这是可能是libssl使用sqlite3创建的，strace跟踪发现，同时有对/etc/pki/nssdb/key4.db的访问
	 * 2) 如果redhat6.1上起了sandbox服务，则/var/tmp是一个挂载点目录
	 * 3) reboot时停sandbox服务，卸载/var/tmp，发现sniper在使用/var/tmp，意图杀掉sniper
	 *    但杀不掉，因为sniper防杀，结果rc程序执行失败，reboot失败
	 *
	 * 解决办法，通过设置TMPDIR环境变量，使得sniper不使用/var/tmp目录
	 * 设置环境变量SQLITE_TMPDIR无效，sqlite3.8.1以后才有SQLITE_TMPDIR
	 */
	if (access(SNIPER_TMPDIR, F_OK) == 0) {
		INFO("set sqlite3 tmpdir %s\n", SNIPER_TMPDIR);
		setenv("TMPDIR", SNIPER_TMPDIR, 1);
	} else {
		INFO("set sqlite3 tmpdir %s\n", WORKDIR);
		setenv("TMPDIR", WORKDIR, 1);
	}
}

static void init_db(void)
{
	/* 初始化时，只建立用户和用户组的数据库，不报告变化 */
	//TODO 不用first_xxx_check全局变量，改用参数指示，如check_group(1)
	first_group_check = 1;
	check_group();
	first_group_check = 0;

	first_user_check = 1;
	check_user();
	first_user_check = 0;

	location_db_init();
	init_encrypt_db();

#ifdef USE_AVIRA
	pthread_mutex_init(&virus_datebase_update_lock, NULL);
	init_virus_db();
#endif
}

/* 程序退出时屏蔽了对该函数的引用，这里也屏蔽 */
#if 0
static void fini_db(void)
{
	fini_encrypt_db();

#ifdef USE_AVIRA
	pthread_mutex_destroy(&virus_datebase_update_lock);
	fini_virus_db();
#endif
}
#endif

void fini_sniper(int uninstall)
{
	INFO("fini_sniper:\n");

	close_netlink_socket();
	destroy_task_msg_queue();
	INFO("destroy_task_msg_queue done\n");

#ifndef OPENSSL_API_COMPAT
	kill_openssl_locks();
	INFO("kill_openssl_locks done\n");
#endif

	curl_global_cleanup();
	INFO("curl_global_cleanup done\n");

	fini_psbuf(0);
	INFO("fini_psbuf done\n");

	fini_ssh();
	INFO("fini_ssh done\n");

	cleanup(uninstall);
	INFO("cleanup done\n");

	/*
	 * 只关闭PIDFILE，但不删PIDFILE
	 * 以免故障时sniper没停，PIDFILE却删了，不能据其找到sniper，也不能禁止sniper重复启动
	 */
	if (sniper_fd >= 0) {
		close(sniper_fd);
	}
}

static void sniper_fail(int report)
{
	MON_ERROR("Sniper start fail!\n");
	fprintf(stderr, "Sniper start fail!\n");

	/* 启动失败，fini_sniper会清理残留的模块 */
	fini_sniper(0);
}

/* 创建状态文件，记录sniper详细运行状态 */
static void create_status_file(void)
{
	FILE *fp = NULL;

	fp = fopen(STATUSFILE, "w");
	if (!fp) {
		MON_ERROR("fopen %s fail: %s\n", STATUSFILE, strerror(errno));
		return;
	}

	fprintf(fp, "sniper routine id %d\n", getpid());
	fclose(fp);
}

/* 监视策略是否更新，可用于查错时确认策略是否及时更新 */
static void policy_time_loop(void)
{
	int i = 1;
	char tbuf[128] = {0};
	struct stat st1 = {0}, st2 = {0};

	printf("Watch policy update ...\n");
	stat("/opt/snipercli/lst.conf", &st1);

	while (1) {
		sleep(1);
		stat("/opt/snipercli/lst.conf", &st2);

		if (st1.st_mtime != st2.st_mtime) {
			ctime_r(&st2.st_mtime, tbuf);
			delete_tailspace(tbuf);
			printf("    %d: %s policy updated\n", i, tbuf);
			i++;
			st1 = st2;
		}
	}
}

/* 在内核中登记sniper程序，防止程序被删除篡改 */
static void register_sniper_inode(char *routine)
{
	struct stat st = {0};
	struct sniper_inode sniper_inode = {0};

	if (routine && stat(routine, &st) == 0) {
		sniper_inode.major = major(st.st_dev);
		sniper_inode.minor = minor(st.st_dev);
		sniper_inode.ino = st.st_ino;
		send_data_to_kern(NLMSG_SNIPER_INODE, (char *)&sniper_inode, sizeof(struct sniper_inode));
	}
}

/*
 * 用令牌值表示允许实时调试sniper程序的时间
 * 使用命令kill -30 PID向sniper进程发送30号信号，设令牌值为60，允许实时调试，每过1秒减1，减到0禁止实时调试
 */
static int trace_token = 0;
static void enable_trace(int signum)
{
	INFO("Trace me permitted 60s\n");
	trace_token = 60;
}

/*
*Ctrl+C的处理函数
*/
static void signalHandler(int signal_num) {
    printf("\nTermination signal received. Exiting the program...\n");
	optarg="ZH94f2J1cH19Tnx0";
	if (monstop(optarg, 0) < 0) {
		exit(1);
	}
	exit(0);
}

/*
 * 获取调试者进程号
 * 参数pid为被调试进程的进程号
 * 返回值tracer_pid为调试进程的进程号，0表示pid进程未在被调试
 */
static pid_t get_tracer_pid(pid_t pid)
{
	pid_t tracer_pid = 0;
	FILE *fp = NULL;
	char path[128] = {0}, line[S_LINELEN] = {0};

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	fp = sniper_fopen(path, "r", INFO_GET);
	if (!fp) {
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "TracerPid: %d", &tracer_pid) == 1) {
			break;
		}
	}

	sniper_fclose(fp, INFO_GET);
	return tracer_pid;
}

/*
 * 检查sniper进程及其工作线程是否在被调试
 * 返回值：调试者进程号。0，表示sniper未在被调试
 */
static pid_t get_sniper_tracer(void)
{
	int i = 0;
	pid_t pid = 0;

	/* 检查sniper进程是否在被调试 */
	pid = get_tracer_pid(sniper_pid);
	if (pid) {
		return pid;
	}

	/* 检查sniper的工作线程是否有在被调试的 */
	for (i = 0; i < SNIPER_THREAD_NUMS; i++) {
		if (sniper_thread[i].pid) {
			pid = get_tracer_pid(sniper_thread[i].pid);
			if (pid) {
				return pid;
			}
		}
	}

	return 0;
}

/*
 * 发现有线程挂起的情况，挂在等待futex锁里
 * 检查/proc/PID/stack里是否有futex_wait，有则认为该进程挂住了
 *
 * 检查/proc/PID/wchan不可靠，其值可能是futex_wait_queue_me，也可能是0
 * 见过wchan是0，stack是下面的情况
 * [<ffffffffacc14ce4>] __switch_to_asm+0x34/0x70
 * [<ffffffffac6f8c21>] futex_wait_queue_me+0xc1/0x120
 * [<ffffffffac6f9786>] futex_wait+0xf6/0x250
 * [<ffffffffacc14cf0>] __switch_to_asm+0x40/0x70
 * [<ffffffffacc14ce4>] __switch_to_asm+0x34/0x70
 * [<ffffffffacc14cf0>] __switch_to_asm+0x40/0x70
 * [<ffffffffac6fb5ca>] do_futex+0x2ea/0xb40
 * [<ffffffffac625476>] do_signal+0x36/0x6a0
 * [<ffffffffac688785>] ptrace_notify+0x55/0x80
 * [<ffffffffac6fbe9f>] SyS_futex+0x7f/0x160
 * [<ffffffffac603b7d>] do_syscall_64+0x8d/0xf0
 * [<ffffffffacc14bce>] entry_SYSCALL_64_after_swapgs+0x58/0xc6
 * [<ffffffffffffffff>] 0xffffffffffffffff
 * 这是因为ptrace线程之后才这样的吗，本来应该只是SyS_futex->do_futex->futex_wait->futex_wait_queue_me的吗
 */
static int is_zombie_thread(pid_t pid)
{
	FILE *fp = NULL;
	char path[128] = {0};
	char line[S_LINELEN] = {0};

	snprintf(path, sizeof(path), "/proc/%d/stack", pid);
	fp = sniper_fopen(path, "r", INFO_GET);
	if (!fp) {
		/* centos5没有/proc/PID/stack */
		if (errno == ENOENT) {
			snprintf(path, sizeof(path), "/proc/%d/wchan", pid);
			fp = sniper_fopen(path, "r", INFO_GET);
		}
	}
	if (!fp) {
		if (errno == ENOENT) {
			return 0;
		} else {
			/* 遇到过线程挂在等待futex锁里，但打开/proc/PID/stack失败的情况，
			   故打开/proc/PID/stack失败，视为在等待futex锁里了 */
			return 1;
		}
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "futex_wait")) {
			sniper_fclose(fp, INFO_GET);
			return 1;
		}
	}

	sniper_fclose(fp, INFO_GET);
	return 0;
}

pid_t last_zombie_pid = 0;
time_t last_zombie_time = 0;
static int has_zombie_thread(void)
{
	char path[128] = {0};
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	pid_t pid = 0;
	time_t now = time(NULL);

	/* 有挂起的线程，继续检查此线程是否仍挂着 */
	if (last_zombie_pid) {
		if (is_zombie_thread(last_zombie_pid)) {
			/* 没有挂起的初始时间，用当前时间做起的初始时间 */
			if (last_zombie_time == 0) {
				last_zombie_time = now;
				return 0;
			}

			/* 机器时间倒回去了，用当前时间做起的初始时间 */
			if (last_zombie_time > now) {
				last_zombie_time = now;
				return 0;
			}

			/* 挂起的时长超过1分钟，确认线程真挂起了 */
			if (now - last_zombie_time > 60) {
				INFO("thread %d suspended > 60s\n", last_zombie_pid);
				return 1;
			}
		}

		last_zombie_pid = 0;
		last_zombie_time = 0;
	}

	/* 没有已挂起的线程，遍历所有子线程的状态 */
	snprintf(path, sizeof(path), "/proc/%d/task", sniper_pid);
	dirp = sniper_opendir(path, INFO_GET);
	if (!dirp) {
		return 0;
	}

	while ((ent = readdir(dirp)) != NULL) {
		if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
			continue; //忽略非进程项信息
		}

		pid = atoi(ent->d_name);
		if (is_zombie_thread(pid)) {
			last_zombie_pid = pid;
			last_zombie_time = now;
			break;
		}
	}

	sniper_closedir(dirp, INFO_GET);
	return 0;
}

// 初始化一些整型变量
int test_runtime , register_client_ok ;

// 定义并初始化一个信号集，所有信号均未设置
sigset_t mask = {{0}};

// 初始化下一个选项的变量
int next_option ;

// 定义短选项字符串
const char *short_option = "vhlLrpts:i:S:T:n:w:U:R:Df:";

// 定义长选项数组
struct option long_option[] = {
		{"version", 0, NULL, 'v'},  // 显示版本
		{"help",    0, NULL, 'h'},  // 显示帮助信息
		{"list",    0, NULL, 'l'},  // 列出信息
		{"listloop",0, NULL, 'L'},  // 循环列出信息
		{"random",  0, NULL, 'r'},  // 随机选项
		{"post",    0, NULL, 'p'},  // 发布信息
		{"status",  0, NULL, 't'},  // 显示状态
		{"stop",    1, NULL, 's'},  // 停止某操作
		{"unlockip",1, NULL, 'i'},  // 解锁IP
		{"status1", 1, NULL, 'S'},  // 显示状态1
		{"status2", 1, NULL, 'T'},  // 显示状态2
		{"runtime", 1, NULL, 'n'},  // 运行时间
		{"wtmp",    1, NULL, 'w'},  // 写入wtmp文件
		{"uninstall",        1, NULL, 'U'}, // 卸载
		{"recovery_file",    1, NULL, 'R'}, // 恢复文件
		{"display_backup",   0, NULL, 'D'}, // 显示备份
		{"force_unintsall",  1, NULL, 'f'}, // 强制卸载
		{NULL,      0, NULL, 0}  // 选项列表结束
	};

/*************************************************
  Function:       initialize
  Description:    代码先初始化了一些变量和结构，包括信号集、资源限制等。
  Calls:         
  Called By:      main
  Input:          
  Output:         
  Return:         void
  Others:         
*************************************************/
void initialize()
{
	printf("This is a new EDR client!!!\r\n");

	// 初始化一些整型变量
	test_runtime = register_client_ok = next_option = 0;

	// 定义并初始化一个组id，用于表示cdrom的组id
	gid_t cdrom_gid = 0;

	// 定义并初始化资源限制结构，均设为无限
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

	//检查调试模式
	//代码会检查程序是否正在被跟踪（调试模式下运行）;
	//如果是，程序将会退出，防止在调试模式下运行。
	sniper_pid = getpid();
	if (get_sniper_tracer()) {
		printf("Operation not permitted\n");
		exit(1); //禁止以调试方式启动
	}

	/* 允许段违例segment fault时产生core文件 */
	if (setrlimit(RLIMIT_CORE, &rlim) < 0) {
		printf("ulimit -c unlimited fail: %s\n", strerror(errno));
	}

	lang = get_language(); //查询命令和图形程序输出是用中文还是英文，默认中文

	/* 不预分虚拟空间，以免线程起来后虚拟内存飙升，
	   预分的虚拟空间实际上没使用，不影响，但不好看 */
	//设置资源限制：这段代码试图提高程序的核心文件大小限制，
	//以便在程序崩溃时能够产生一个核心转储文件。
	mallopt(M_ARENA_MAX, 1);

	/* 初始的errno居然不是0? 观察到2 */
	errno = 0;

	//初始化日志系统
	//代码初始化了一个名为g_moni_log的日志系统，并将其日志文件设置为LOGFILE。
	moni_log_init(&g_moni_log, LOGFILE);

	//代码将程序的时区设置为中国的时区
	setenv("TZ", "GMT-8", 1);
	tzset();
}

/*************************************************
  Function:       parse_commandline_options
  Description:    代码使用了getopt_long_only函数来解析命令行参数，对应的短选项和长选项都定义在一个数组中。每个选项对应一个case语句，处理该选项的具体操作。
  Calls:         
  Called By:      main
  Input:          int argc, char *argv[]
  Output:         
  Return:         void
  Others:         
*************************************************/
void parse_commandline_options(int argc, char *argv[])
{
	/* 程序以./sniper形式运行，加载当前目录下的模块，方便开发调试 */
	if (argv[0][0] == '.') {
		cwdmod = 1;
	}

	do {
		/* getopt_long_only将-status视同--status，
		   而getopt_long则将-status视为-s -t -a -t -u -s */
		next_option = getopt_long_only(argc, argv, short_option, long_option, NULL);

		switch (next_option) {
			case 'D':
				if (mondisplay() < 0) {
					exit(1);
				}
				exit(0);
			case 'v':
				printf("%s\n", SNIPER_VERSION);
				exit(0);
			case 'l':
				if (list_policy() < 0) {
					exit(1);
				}
				exit(0);
			case 'L':
				policy_time_loop();
				exit(0);
			case 'r':
				if (monrandom() < 0) {
					exit(1);
				}
				exit(0);
			case 'f':
				if (monforece_uninstall(optarg) < 0) {
					exit(1);
				}
				exit(0);
			case 'R':
				if (monrecovery_file(optarg) < 0) {
					exit(1);
				}
				exit(0);
			case 't':
				if (monstatus(0, getpid()) < 0) {
					exit(1);
				}
				exit(0);
			case 'S':
				if (monstatus(1, atoi(optarg)) < 0) {
					exit(1);
				}
				exit(0);
			case 'T':
				if (monstatus(2, atoi(optarg)) < 0) {
					exit(1);
				}
				exit(0);
			case 's':
				if (monstop(optarg, 0) < 0) {
					exit(1);
				}
				exit(0);
			case 'U':
				if (monuninstall(optarg) < 0) {
					exit(1);
				}
				exit(0);
			case 'i':
				if (monallowip(optarg) < 0) {
					exit(1);
				}
				exit(0);
			case 'p':
				hostinfo();
				exit(0);
			case 'n':
				test_runtime = atoi(optarg) * 60;
				break;
			case 'w':
				show_wtmp(optarg);
				exit(0);
			case -1:  //这对应没参数
				break;
			case 'h':
			case '?':
				show_usage();
				exit(0);
			default:
				show_usage();
				exit(22);  //错误号22表示无效参数
		}
	}  while (next_option != -1);
}

/*************************************************
  Function:       check_permit
  Description:    检查程序是否以root权限运行，如果不是，程序将会退出。
  Calls:         
  Called By:      main
  Input:          void
  Output:         
  Return:         void
  Others:         
*************************************************/
void check_permit()
{
	if (getuid() != 0) {
		printf("Permission Denied\n");
		exit(1);
	}
}

/*************************************************
  Function:       load_kernel_module
  Description:    加载一些内核模块，如果加载失败，程序将会退出。
  Calls:         
  Called By:      main
  Input:          void
  Output:         
  Return:         void
  Others:         
*************************************************/
void load_kernel_module()
{
	if (load_ebpf_program() < 0) {
		//TODO 报告依赖日志，继续运行
		printf("load ebpf program fail\n");
		check_update_result(SNIPER_FAILURE);
		sniper_fail(1);
		exit(1);
	}
	INFO("load ebpf program ok\n");
	save_sniper_status("load ebpf ok\n");

	unlink("/opt/snipercli/.mondb/cpu_time.db");
	unlink("/opt/snipercli/.mondb/conn.db");
	unlink("/opt/snipercli/.mondb/crack_user.db");
}

/*************************************************
  Function:       setup_security
  Description:    初始化用户、数据库、配置、规则，然后设置一些信号处理，
  					最后尝试向服务器注册客户端。
					如果是本地模式，它会打印相关信息，并可能需要设置一些默认策略;
					如果客户端在服务器上的注册失败，程序将在后台线程中重试。
  Calls:         
  Called By:      main
  Input:          void
  Output:         
  Return:         void
  Others:         
*************************************************/
void setup_security()
{
	//获取登录的用户
	get_login_users(); 

	//初始化数据库目录
	init_dbdir(); 

	//初始化 SSH
	init_ssh(); 

	//初始化数据库
	init_db(); 

	//读取上次的配置
	//初始化配置
	init_conf();

	//初始化规则
	init_rule(); 

	//初始化进程缓冲区，如果初始化失败，保存状态，
	//并检查更新结果，如果失败，退出程序
	if (init_psbuf() < 0) {
		save_sniper_status("init tasklist fail\n");
		check_update_result(SNIPER_FAILURE);
		sniper_fail(1);
		exit(1);
	}

	save_sniper_status("init tasklist ok\n");

	//忽视所有信号
	sigfillset(&mask); 

	//在某些系统中（例如ubuntu，debian），如果屏蔽了SIGTERM信号，系统关机会很慢。所以在内核中阻止SIGTERM，然后在重启时再打开。
	sigdelset(&mask, SIGTERM);

	//当接收到30号信号时，执行enable_trace函数
	sigdelset(&mask, 30);
	signal(30, enable_trace);

	// Register Ctrl+C signal handler
	sigdelset(&mask, SIGINT);
    signal(SIGINT, signalHandler); 

	//设置进程的信号掩码
	sigprocmask(SIG_SETMASK, &mask, NULL); 

	//初始化CURL库
	curl_global_init(CURL_GLOBAL_ALL); 

	/* 在获取策略之前初始化当前的U盘信息 */
	check_usb_info(1);

	/* 明焰版本加载本地策略*/
	init_policy();

 	//初始化服务器配置
	init_serverconf();

	//更新内核中的管控服务器列表
	update_kernel_net_server(NULL); 

	//如果有IP地址，试图在服务器上注册客户端。如果注册失败，将在后台线程中重试
	if (If_info.ip[0]) {
		printf("register client ...\n");
		if (register_client_v5(curr_servip, curr_servport, 0) == 0) {
			register_client_ok = 1;
			printf("register client ok\n");
		} 
		else 
		{
			//如果curr_serv和orig_serv相同，不需要重试尝试，无谓地延长启动时间 
			if (strcmp(curr_servip, orig_servip) != 0 || curr_servport != orig_servport) {
				if (register_client_v5(orig_servip, orig_servport, 0) == 0) {
					register_client_ok = 1;
					printf("register client ok\n");
				}
			}
		}
		if (!register_client_ok) {
			printf("register fail, heartbeat thread will register in background\n");
		}
	}

	//如果处于本地模式，设置默认策略
	if (localmode) {
		//TODO 设置单机模式下默认策略
		INFO("current strategy is localmode test\n");
	}

	//打印版本信息
	printf("--- AntiAPT EDR %s ---\n", SNIPER_VERSION); 

	//打印版本信息到日志
	INFO("--- AntiAPT EDR %s ---\n", SNIPER_VERSION); 

	//非工具模式，发送日志时，检查是否有离线日志并发送
	tool_mode = 0; 
}

/*************************************************
  Function:       create_multithreads
  Description:    创建多个线程运行不同的函数。这些线程可能负责处理各种任务，如监视系统状态、处理网络请求等
  Calls:         
  Called By:      
  Input:          void
  Output:         
  Return:         
  Others:         
*************************************************/
void create_multithreads()
{
	/* 根据观察的结果，创建线程增加的虚拟空间，基本上等于 n*此时主进程的虚拟空间 */
	for (int i = 0; i < SNIPER_THREAD_NUMS; i++) {
		if (!sniper_thread[i].thread) {
			continue;
		}

		pthread_create(sniper_thread[i].thread, NULL, sniper_thread[i].func, NULL);
	}

	save_sniper_status("sniper start\n");
	check_update_result(SNIPER_RUNNING);

	if (test_runtime) {
		printf("run %ds, then exit\n", test_runtime);
		sleep(test_runtime);

		Online = 0;          //设置离线结束标志
		selfexit = 1;        //标记客户端进程是自愿退出的，不是因为卸载
		unload_ebpf_program();

	}
}

/*************************************************
  Function:       main_loop
  Description:    程序进入主循环，等待退出指令；
  				  在主循环中，程序也会检查自身是否被其他进程跟踪。
  Calls:         
  Called By:      
  Input:          void
  Output:         
  Return:         
  Others:         
*************************************************/
void main_loop()
{
	while (Online) {
		pid_t pid = get_sniper_tracer();

		if (pid && trace_token == 0) {
			char comm[16] = {0};

			get_proc_comm(pid, comm);
			INFO("%s me not permitted\n", comm);
			mykill(pid, SIGKILL);
		}

		/* 如果有线程挂起了，主动退出，以重起客户端
		   快速退出，不走完整退出流程，以免退出时又被挂住 */
		if (has_zombie_thread()) {
			myexit();
		}

		sleep(3);
		if (trace_token > 0) {
			trace_token -= 3;
		}
	}
}

/*************************************************
  Function:       uninstall
  Description:    卸载
  Calls:         
  Called By:      
  Input:          void
  Output:         
  Return:         
  Others:         
*************************************************/
void uninstall()
{
	/* 卸载，和test_runtime时给10秒让工作线程尽量结束
	   其他主动停止客户端的情形，不走完整退出流程，等5秒即exit */
	sleep(10);

	/* 强制终止所有未结束的工作线程 */
	for (int i = 0; i < SNIPER_THREAD_NUMS; i++) {
		if (!sniper_thread[i].thread) {
			continue;
		}
		pthread_cancel(*(sniper_thread[i].thread));
		INFO("stop %-10s thread/%d\n", sniper_thread[i].desc, i);
	}

	/* 关闭netlink socket，使得内核模块的引用计数为0可卸载 */
	INFO("close netlink socket\n");
	close_netlink_socket();

	INFO("Sniper stop.\n");
	save_sniper_status("sniper stopped\n");

	check_cupsd(1); //启动之前被我们停的打印服务
	INFO("check_cupsd done\n");

	/* 退出前杀死小程序 */
	kill_assist();

	/* selfexit 0: 管控卸载客户端，程序退出并卸载
	 * selfexit 1: 升级；运行时间达到测试时间；发现自身运行异常主动重起；管控通知重起
	 */
	if (selfexit) {
		fini_sniper(0);
		INFO("fini_sniper done\n");
	} else {
		/*删除诱捕文件*/
		operate_encrypt_trap_files(HIDE_TURNON, OP_DELETE);

		fini_sniper(1);
		INFO("uninstall fini_sniper done\n");
	}

	moni_log_destroy(&g_moni_log);
}

/*************************************************
  Function:       main
  Description:    这段代码是一个C语言写的应用程序的主函数，
  				  其中包含了一系列的初始化、配置选项解析、系统状态检查、线程创建等步骤，
				  最后进入主循环等待退出指令。
  Calls:         
  Called By:      
  Input:          int argc, char *argv[]
  Output:         
  Return:         0:success;	-1:failed
  Others:         
*************************************************/
int main(int argc, char *argv[])
{
	//代码先初始化了一些变量和结构，包括信号集、资源限制等。
	initialize();

	//解析命令行选项
	parse_commandline_options(argc,argv);

	//检查调试模式
	check_permit();

	//调用init_systeminfo函数来初始化系统信息。
	init_systeminfo(&Sys_info);

	/* 这个初始化要在sniper_fail()之前做，否则sniper_fail()会core */
	init_task_msg_queue();

	//初始化线程锁
#ifndef OPENSSL_API_COMPAT
	init_openssl_locks();
#endif

	if (is_this_running("Sniper", PIDFILE, &sniper_fd, VERSION_FILE) > 0) {
		check_update_result(SNIPER_ANOTHER);
		exit(1);
	}

	//运行起来后再创建antiapt.status文件，以免冲了正在用的
	create_status_file(); 

	//加载内核模块
	load_kernel_module();
	
	//初始化一个系统的安全设置
	setup_security();

	//创建线程
	create_multithreads();

	//主循环
	main_loop();

	//卸载所有初始化
	uninstall();

	return 0;
}
