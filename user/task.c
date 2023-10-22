#include <sys/syscall.h>      //syscall

#include "header.h"
#include "cJSON.h"

int is_update_task = 0, is_update_conf = 0;

/* 客户端收到任务消息后回应管控表示收到 */
void send_task_msg_resp(char *task_uuid)
{
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL;
	char *post = NULL;

	/* 旧的管控没有task_uuid字段, 不用回复 */
	if (!task_uuid) {
		return;
	}

	/* 拼接json字符串 */
	object = cJSON_CreateObject();
	if (!object) {
		MON_ERROR("send_task_msg_resp fail, no memory\n");
		return;
	}

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "task_uuid", task_uuid);
	post = cJSON_PrintUnformatted(object);
	if (!post) {
		MON_ERROR("send_task_msg_resp fail, no memory\n");
	} else {
		/* 任务消息回复需要及时，故单条发送 */
		http_post(TASK_ACK_URL, post, reply, sizeof(reply));
//		printf("task_msg_resp post:%s, reply:%s\n", post, reply);
		free(post);
	}

	cJSON_Delete(object);
}

/* 任务执行完成之后恢复管控任务执行的情况 */
void send_task_resp(task_recv_t *msg, int result, char *reason)
{
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL, *data = NULL, *info = NULL;
	char *post = NULL, *datastr = NULL;

	/* nottask表示不是管控下发的任务，故不需要发任务应答 */
	if (!msg || strcmp(msg->cmd_id, "nottask") == 0) {
		return;
	}

	/* 拼接json字符串 */
	object = cJSON_CreateObject();
	if (!object) {
		MON_ERROR("send_task_resp fail, no memory\n");
		return;
	}

	/* data作为1级子json存在object下 */
	data = cJSON_CreateObject();
	if (!data) {
		MON_ERROR("send_task_resp fail, no memory\n");
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(data, "cmd_id", msg->cmd_id);
	cJSON_AddNumberToObject(data, "cmd_type", msg->cmd_type);
	cJSON_AddNumberToObject(data, "result", result);
	cJSON_AddStringToObject(data, "reason", reason ? reason : "");

	/* 文件隔离和取消隔离比其他任务多了几个特殊参数 */
	if (msg->cmd_type == TASK_FILE_QUARANTINE ||
	    msg->cmd_type == TASK_CANCEL_FILE_QUARANTINE) {
		info = cJSON_CreateObject();
		if (!info) {
			MON_ERROR("send_task_resp fail, no memory\n");
			cJSON_Delete(object);
			cJSON_Delete(data);
			return;
		}

		cJSON_AddStringToObject(info, "md5", msg->md5);
		cJSON_AddStringToObject(info, "filepath", msg->filepath);
		cJSON_AddStringToObject(info, "log_id", msg->log_id);
		cJSON_AddNumberToObject(info, "process_id", msg->process_id);

		cJSON_AddItemToObject(data, "data", info);
	}

	datastr = cJSON_PrintUnformatted(data);
	if (!datastr) {
		MON_ERROR("send_task_resp fail, no memory\n");
		cJSON_Delete(object);
		cJSON_Delete(data);
		return;
	}

	cJSON_AddStringToObject(object, "data", datastr);

	cJSON_Delete(data);
	free(datastr);

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	post = cJSON_PrintUnformatted(object);
	if (!post) {
		MON_ERROR("send_task_resp fail, no memory\n");
		cJSON_Delete(object);
		return;
	}

	client_send_msg(post, reply, sizeof(reply), NOTIFY_URL, "task");

	cJSON_Delete(object);
	free(post);
}

/* 客户端升级任务回复 */
void send_update_client_task_resp(task_recv_t *msg, int result, char *old_version, char *new_version)
{
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL, *data = NULL, *info = NULL;
	char *post = NULL, *datastr = NULL;

	/* nottask表示不是管控下发的任务，故不需要发任务应答 */
	if (!msg || strcmp(msg->cmd_id, "nottask") == 0) {
		return;
	}

	/* 拼接json字符串 */
	object = cJSON_CreateObject();
	if (!object) {
		MON_ERROR("send_task_resp fail, no memory\n");
		return;
	}

	/* data作为1级子json存在object下 */
	data = cJSON_CreateObject();
	if (!data) {
		MON_ERROR("send_task_resp fail, no memory\n");
		cJSON_Delete(object);
		return;
	}

	/* info作为2级子json存在data下 */
	info = cJSON_CreateObject();
	if (!info) {
		MON_ERROR("send_task_resp fail, no memory\n");
		cJSON_Delete(object);
		cJSON_Delete(data);
		return;
	}

	cJSON_AddStringToObject(data, "cmd_id", msg->cmd_id);
	cJSON_AddNumberToObject(data, "cmd_type", msg->cmd_type);
	cJSON_AddNumberToObject(data, "result", result);
	cJSON_AddStringToObject(data, "reason", "ClientUpdate");

	cJSON_AddStringToObject(info, "old_client_ver", old_version);
	cJSON_AddStringToObject(info, "new_client_ver", new_version);

	cJSON_AddItemToObject(data, "data", info);

	datastr = cJSON_PrintUnformatted(data);
	if (!datastr) {
		MON_ERROR("send_task_resp fail, no memory\n");
		cJSON_Delete(object);
		cJSON_Delete(data);
		return;
	}

	cJSON_AddStringToObject(object, "data", datastr);

	cJSON_Delete(data);
	free(datastr);

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	post = cJSON_PrintUnformatted(object);
	if (!post) {
		MON_ERROR("send_task_resp fail, no memory\n");
		cJSON_Delete(object);
		return;
	}

	client_send_msg(post, reply, sizeof(reply), NOTIFY_URL, "task");

	cJSON_Delete(object);
	free(post);
}

/* 启动防护任务取消防护任务 两个功能取消了 */
#if 0
/* 任务接口下发的启动防护始终报告成功 */
void start_protect(task_recv_t *recv_msg)
{
	INFO("task start protect!\n");

	Protect_switch = TURNON;
	save_sniper_status("task start protect\n");

	send_client_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Startd");
	send_task_resp(recv_msg, RESULT_OK, "Start Protect");
}

/* 任务接口下发的停止防护始终报告成功 */
void stop_protect(task_recv_t *recv_msg)
{
	INFO("task stop protect!\n");

	Protect_switch = TURNOFF;
	save_sniper_status("task stop protect\n");

	send_client_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Stoped");
	send_task_resp(recv_msg, RESULT_OK, "Stop Protect");
}
#endif

/* 任务接口下发的卸载始终报告成功 */
void uninstall_sniper(task_recv_t *recv_msg)
{
	Online = 0;
	// TODO(luoyinhong): unregister_ebpf
	// unregister_module();
	unload_ebpf_program();
	save_sniper_status("uninstall sniper\n");

	send_client_change_resp(SNIPER_VERSION, SNIPER_VERSION, OPERATE_OK, "Uninstalled");
	send_task_resp(recv_msg, RESULT_OK, "Uninstall");
}

//TODO 举具体的例子说明隔离的算法、存在的问题及选择此算法的原因
/* 隔离文件 */
void file_quarantine(task_recv_t *msg)
{
	char path[PATH_MAX] = {0};
	char real_path[PATH_MAX] = {0};
	int ret = 0, len = 0, quarantine_maxsize = 0;
	long maxsize = 0;

	/* 检查隔离空间是否满了 */
	quarantine_maxsize = conf_global.offline_space_size;
	if (quarantine_maxsize < 1024) {
		quarantine_maxsize = 1024;
	}
	maxsize = quarantine_maxsize * MB_SIZE;

	if (check_dir_maxsize(SAMPLE_DIR, maxsize) < 0) {
		report_dependency_msg("LogStorageSpaceIsFull");
		return;
	}

	snprintf(path, sizeof(path), "%s%s", SAMPLE_DIR, msg->md5);

	len = strlen(msg->filepath);
	if (realpath(msg->filepath, real_path) &&
	    (strncmp(msg->filepath, real_path, len-1) != 0 ||
	     strcmp(msg->filepath+len-1, "/") != 0)) {

		/*
		 * 如果是软连接文件，指向的文件是否需要一起隔离 TODO
		 * 此处先隔离链接文件，
		 * 获取软件类指向的文件，并对指向文件在隔离箱备份链接文件
		 */
		unlink(path);
		ret = symlink(real_path, path);
	} else {

		/* 不同文件系统rename会失败，失败后再尝试读写操作 */
		ret = rename(msg->filepath, path);
		if (ret < 0) {
			ret = copy_file(msg->filepath, path);
		}
	}
	if (ret < 0) {
		send_task_resp(msg, RESULT_FAIL, "File Quarantine");
	} else {
		send_task_resp(msg, RESULT_OK, "File Quarantine");
		unlink(msg->filepath);
	}
}

/* 通过一边读取旧文件，一边把读到的内容写到新文件，达到复制文件的目的 */
int copy_file(char *old_file, char *new_file)
{
	FILE *oldfp = NULL;
	FILE *newfp = NULL;
	struct stat st = {0};
	off_t old_len = 0, new_len = 0;
	char buf[512] = {0};
	int size = 0, len = 0;
	int ret = 0;

	if (stat(old_file, &st) < 0) {
		return -1;
	}

	old_len = st.st_size;

	oldfp = sniper_fopen(old_file, "r", FILE_GET);
	if (!oldfp) {
		MON_ERROR("copy file open oldfile %s failed:%s\n", old_file, strerror(errno));
		return -1;
	}

	newfp = sniper_fopen(new_file, "w", FILE_GET);
	if (!newfp) {
		MON_ERROR("copy file open newfile %s failed:%s\n", new_file, strerror(errno));
		sniper_fclose(oldfp, FILE_GET);
		return -1;
	}

	while ((len = fread(buf, 1, sizeof(buf), oldfp)) > 0) {
		size = fwrite(buf, 1, len, newfp);
		if (size != len) {
			ret = -1;
			MON_ERROR("write file len less then read\n");
			break;
		}
		new_len += size;
	}

	if (ret == 0 && new_len != old_len) {
		ret = -1;
		MON_ERROR("new file size less then old file\n");
	}

	if (ret < 0) {
		unlink(new_file);
	}

	sniper_fclose(oldfp, FILE_GET);
	sniper_fclose(newfp, FILE_GET);
	return ret;
}

/* 取消对文件的隔离 */
void file_cancel_quarantine(task_recv_t *msg)
{
	char path[PATH_MAX] = {0};
	char real_path[PATH_MAX] = {0};
	int ret = 0, len = 0;

	snprintf(path, sizeof(path), "%s%s", SAMPLE_DIR, msg->md5);

	len = strlen(path);
	if (realpath(path, real_path) &&
	    (strncmp(path, real_path, len-1) != 0 || strcmp(path+len-1, "/") != 0)) {

		/*
		 * 隔离原文件是软连接的情况，只是在隔离区对实际文件做了一个软链接,
		 * 并删除了原来的链接文件
		 * 恢复时获取隔离文件指向的文件，并对指向文件在目标位置生成链接文件
		 */
		unlink(msg->filepath);
		ret = symlink(real_path, msg->filepath);
	} else {

		/* 不同文件系统rename会失败，失败后再尝试读写操作 */
		ret = rename(path, msg->filepath);
		if (ret < 0) {
			ret = copy_file(path, msg->filepath);
		}
	}

	if (ret < 0) {
		send_task_resp(msg, RESULT_FAIL, "Cancel File Quarantine");
	} else {
		send_task_resp(msg, RESULT_OK, "Cancel File Quarantine");
		unlink(path);
	}
}

/* 回复病毒库/病毒程序升级任务消息 */
void send_update_virus_database_task_resp(task_recv_t *recv_msg, int result, char *old_version, char *new_version)
{
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL, *data = NULL, *data_second = NULL;
	char *post = NULL;

	/* 拼接json字符串 */
	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}

	/* data作为1级子json存在object下 */
	data = cJSON_CreateObject();
	if (data == NULL) {
		cJSON_Delete(object);
		return;
	}

	/* data_second作为2级子json存在data下 */
	data_second = cJSON_CreateObject();
	if (data_second == NULL) {
		cJSON_Delete(data);
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(data, "cmd_id", recv_msg->cmd_id);
	cJSON_AddNumberToObject(data, "cmd_type", recv_msg->cmd_type);
	cJSON_AddNumberToObject(data, "result", result);

	cJSON_AddNumberToObject(data_second, "upgrade_type", recv_msg->upgrade_type);
	cJSON_AddStringToObject(data_second, "old_virus_ver", old_version);
	cJSON_AddStringToObject(data_second, "new_virus_ver", new_version);
	cJSON_AddStringToObject(data_second, "md5", recv_msg->md5);
	cJSON_AddItemToObject(data, "data", data_second);

	post = cJSON_PrintUnformatted(data);
	cJSON_AddStringToObject(object, "data", post);
	cJSON_Delete(data);
	free(post);
	post = NULL;

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	post = cJSON_PrintUnformatted(object);
	client_send_msg(post, reply, sizeof(reply), NOTIFY_URL, "task");
	DBG2(DBGFLAG_TASK, "post:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
}

/* 客户端信息同步, 单个信息同步或者全部信息同步 */
void send_sync_info(int type, char *string)
{
	char reply[REPLY_MAX] = {0};
	cJSON *object = NULL;
	char *post = NULL;

	/* 单个信息同步，具体信息不能为空 */
	if (string == NULL && type != SYNC_ALL) {
		return;
	}

	/* 拼接json字符串 */
	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}

	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);

	switch (type) {
		case SYNC_IP:
			cJSON_AddStringToObject(object, "ip", string);
			break;
		case SYNC_BASELINE_VER:
			cJSON_AddStringToObject(object, "baseline_ver", string);
			break;
		case SYNC_CRACK_VER:
			cJSON_AddStringToObject(object, "client_conf_ver", string);
			break;
		case SYNC_WEBSHELL_VER:
			cJSON_AddStringToObject(object, "webshell_ver", string);
			break;
		case SYNC_WEAK_PASSWD_VER:
			cJSON_AddStringToObject(object, "weak_passwd_ver", string);
			break;
		case SYNC_VIRUS_LIB_VER:
			cJSON_AddStringToObject(object, "virus_lib_ver", string);
			break;
		case SYNC_ANTIVIRUS_VER:
			cJSON_AddStringToObject(object, "virus_ver", string);
			break;
		case SYNC_IPWRY_VER:
			cJSON_AddStringToObject(object, "ipwry_ver", string);
			break;
		case SYNC_ALL:
			cJSON_AddStringToObject(object, "ip", If_info.ip);
			cJSON_AddStringToObject(object, "baseline_ver", baseline_ver_global);
			cJSON_AddStringToObject(object, "webshell_ver", webshell_ver_global);
			cJSON_AddStringToObject(object, "weak_passwd_ver", weak_passwd_ver_global);
#ifdef USE_AVIRA
			cJSON_AddStringToObject(object, "virus_lib_ver", virus_lib_ver_global);
			cJSON_AddStringToObject(object, "virus_ver", antivirus_ver_global);
#endif
			cJSON_AddStringToObject(object, "ipwry_ver", ipwry_ver_global);
			break;
		default:
			MON_ERROR("sync info type is error: %d\n", type);
			break;
	}

	post = cJSON_PrintUnformatted(object);

	http_put(SYNC_INFO_URL, post, reply, sizeof(reply));

	cJSON_Delete(object);
	free(post);
}

/* 解析任务信息并处理 */
static int parse_server_task(cJSON *json)
{
	int i = 0, array_size = 0, ret = 0;
	cJSON *code = NULL, *cmd_id = NULL, *cmd_type = NULL, *data = NULL, *subdata = NULL;
	cJSON *new_client_ver = NULL, *md5 = NULL, *filepath = NULL, *log_id = NULL, *ip = NULL;
	cJSON *process_id = NULL, *category_id = NULL, *whitelist_id = NULL, *pSub = NULL;
	cJSON *new_virus_ver = NULL, *old_virus_ver = NULL, *upgrade_type = NULL, *new_conf_ver = NULL;
	cJSON *task_uuid = {0};
	task_recv_t msg = {0};
	char *ptr = NULL;
	pid_t tid = 0;

	int *whitelist = 0, *rule_id = 0;
	int white_size = 0, rule_size = 0;

	if (!json) {
		return -1;
	}

	/* 例{"code":0,"msg":"","data":{"cmd_id":"0","cmd_type":16,"task_uuid":"2c7f43e7-2121-48ef-97dc-1fcd922a404e","data":{...}}} */

	code = cJSON_GetObjectItem(json, "code");
	if (!code || code->valueint != 0) {
		MON_ERROR("bad task msg, code item invalid\n");
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("bad task msg, data item invalid\n");
		return -1;
	}

	cmd_id = cJSON_GetObjectItem(data, "cmd_id");
	if (!cmd_id) {
		MON_ERROR("bad task msg, cmd_id item invalid\n");
		return -1;
	}

	snprintf(msg.cmd_id, sizeof(msg.cmd_id), "%s", cmd_id->valuestring);

	cmd_type = cJSON_GetObjectItem(data, "cmd_type");
	if (!cmd_type) {
		MON_ERROR("bad task msg, cmd_type item invalid\n");
		return -1;
	}
	msg.cmd_type = cmd_type->valueint;

	/*
	 * 5.0.9及之后版本下发的任务会附带任务id，相同表示重复任务
	 * 客户端收到任务后回复管控已收到，否则管控一段时间没收到回复
	 * 会重复下发该任务
	 */
	task_uuid = cJSON_GetObjectItem(data, "task_uuid");
	if (task_uuid && task_uuid->valuestring) {
		send_task_msg_resp(task_uuid->valuestring);
	}

	/* 过期了只更新配置 */
	if ((conf_global.licence_expire ||
	     client_disable == TURN_MY_ON) &&
	     msg.cmd_type != TASK_UPDATE_CONF) {
		return 0;
	}

	/* "data":{"md5":"84fef82f824775e78977caff426f66e6","filepath":"/tmp/test","log_id":"","process_id":0} */
	/* 非共通部分，按同样key的类型分类处理 */
	if (msg.cmd_type == TASK_FILE_QUARANTINE ||
	    msg.cmd_type == TASK_CANCEL_FILE_QUARANTINE) {
		subdata = cJSON_GetObjectItem(data, "data");
		if (!subdata) {
			MON_ERROR("bad task msg, subdata item invalid\n");
			return -1;
		}

		md5 = cJSON_GetObjectItem(subdata, "md5");
		if (!md5) {
			MON_ERROR("bad task msg, md5 item invalid\n");
			return -1;
		}
		snprintf(msg.md5, sizeof(msg.md5), "%s", md5->valuestring);

		filepath = cJSON_GetObjectItem(subdata, "filepath");
		if (!filepath) {
			MON_ERROR("bad task msg, filepath item invalid\n");
			return -1;
		}
		snprintf(msg.filepath, sizeof(msg.filepath), "%s", filepath->valuestring);

		log_id = cJSON_GetObjectItem(subdata, "log_id");
		if (!log_id) {
			MON_ERROR("bad task msg, log_id item invalid\n");
			return -1;
		}
		snprintf(msg.log_id, sizeof(msg.log_id), "%s", log_id->valuestring);

		process_id = cJSON_GetObjectItem(subdata, "process_id");
		if (!process_id) {
			MON_ERROR("bad task msg, process_id item invalid\n");
			return -1;
		}
		msg.process_id = process_id->valueint;
	}

	/* "data":{"old_client_ver": "4.0.0","new_client_ver": "5.0.0","md5": ""} */
	if (msg.cmd_type == TASK_UPDATE_CLIENT) {
		subdata = cJSON_GetObjectItem(data, "data");
		if (!subdata) {
			MON_ERROR("bad task msg, subdata item invalid\n");
			return -1;
		}

		new_client_ver = cJSON_GetObjectItem(subdata, "new_client_ver");
		if (!new_client_ver) {
			MON_ERROR("bad task msg, new_client_ver item invalid\n");
			return -1;
		}
		snprintf(msg.new_version, sizeof(msg.new_version), "%s", new_client_ver->valuestring);
	}

	/* "data":{"filename":"/api/client/download/conf/linux-crack20220516.dat","md5":"d8fcd8ef06c0399bde3d5ec8f9adc1ba"} */
	if (msg.cmd_type == TASK_UPDATE_CRACK_CONF) {
		subdata = cJSON_GetObjectItem(data, "data");
		if (!subdata) {
			MON_ERROR("bad task msg, subdata item invalid\n");
			return -1;
		}

		new_conf_ver = cJSON_GetObjectItem(subdata, "filename");
		if (!new_conf_ver) {
			MON_ERROR("bad task msg, new_conf_ver item invalid\n");
			return -1;
		}
		ptr = strstr(new_conf_ver->valuestring, "/api/client/download/conf/");
		if (!ptr) {
			MON_ERROR("NO crack conf msg\n");
			return -1;
		}

		ptr += strlen("/api/client/download/conf/");
		snprintf(msg.new_version, sizeof(msg.new_version), "%s", ptr);
	}

	/* "data":{"whitelist":[7,8,9],"category_id":[1,2,3,4]} */
	if (msg.cmd_type == TASK_BASELINE_CHECK) {
		subdata = cJSON_GetObjectItem(data, "data");
		if (!subdata) {
			MON_ERROR("bad task msg, data_second item invalid\n");
			return -1;
		}
		whitelist_id = cJSON_GetObjectItem(subdata, "whitelist");
		if (whitelist_id != NULL) {
			array_size = cJSON_GetArraySize(whitelist_id);
			white_size = array_size;
			whitelist = (int *)malloc(white_size * (sizeof(int)));
			if (!whitelist) {
				return -1;
			}
			memset(whitelist, 0, white_size);
			for (i = 0; i < array_size; i++) {
				pSub = cJSON_GetArrayItem(whitelist_id, i);
				if (NULL == pSub) {
					continue;
				}
				whitelist[i] = pSub->valueint;
			}
		}

		category_id = cJSON_GetObjectItem(subdata, "category_id");
		if (category_id != NULL) {
			array_size = cJSON_GetArraySize(category_id);
			rule_size = array_size;
			rule_id = (int *)malloc(rule_size * (sizeof(int)));
			if (!rule_id) {
				return -1;
			}
			memset(rule_id, 0, rule_size);
			for (i = 0; i < array_size; i++) {
				pSub = cJSON_GetArrayItem(category_id, i);
				if (NULL == pSub) {
					continue;
				}
				rule_id[i] = pSub->valueint;
			}
		}
	}

	/* "data":{"log_id":"faf6f207-ee8f-4ae0-baca-1a3533f121a0","log_name":"HoneyPort","ip":"192.168.58.150"} */
	if (msg.cmd_type == TASK_UNLOCK_IP) {
		subdata = cJSON_GetObjectItem(data, "data");
		if (!subdata) {
			MON_ERROR("bad task msg, subdata item invalid\n");
			return -1;
		}

		ip = cJSON_GetObjectItem(subdata, "ip");
		if (!ip) {
			MON_ERROR("bad task msg, ip item invalid\n");
			return -1;
		}
		snprintf(msg.ip, sizeof(msg.ip), "%s", ip->valuestring);
	}

	/* "data":{"upgrade_type":1,"old_virus_ver":"5.0.8.0705","new_virus_ver":"5.0.9.0725":"md5":"da88c975915cfe0bf18854b9872536cb"} */
	if (msg.cmd_type == TASK_UPDATE_VIRUS_DATABASE) {
		subdata = cJSON_GetObjectItem(data, "data");
		if (!subdata) {
			MON_ERROR("bad task msg, subdata item invalid\n");
			return -1;
		}

		upgrade_type = cJSON_GetObjectItem(subdata, "upgrade_type");
		if (!upgrade_type) {
			MON_ERROR("bad task msg, upgrade_type item invalid\n");
			return -1;
		}
		msg.upgrade_type = upgrade_type->valueint;

		/*
		 * 版本号分为两种情况，5.0.9之前为anti-5.0.8.0705-lib.zip
		 * 5.0.9及之后为5.0.8.0705
		 * 兼容旧的管控，统一提取为5.0.8.0705
		 */
		old_virus_ver = cJSON_GetObjectItem(subdata, "old_virus_ver");
		if (!old_virus_ver) {
			MON_ERROR("bad task msg, old_virus_ver item invalid\n");
			return -1;
		}
		if (strstr(old_virus_ver->valuestring, "anti-") != NULL) {
			extract_virus_version(old_virus_ver->valuestring, msg.old_version);
		} else {
			snprintf(msg.old_version, sizeof(msg.old_version), "%s", old_virus_ver->valuestring);
		}

		new_virus_ver = cJSON_GetObjectItem(subdata, "new_virus_ver");
		if (!new_virus_ver) {
			MON_ERROR("bad task msg, new_virus_ver item invalid\n");
			return -1;
		}
		if (strstr(new_virus_ver->valuestring, "anti-") != NULL) {
			extract_virus_version(new_virus_ver->valuestring, msg.new_version);
		} else {
			snprintf(msg.new_version, sizeof(msg.new_version), "%s", new_virus_ver->valuestring);
		}

		md5 = cJSON_GetObjectItem(subdata, "md5");
		if (!md5) {
			MON_ERROR("bad task msg, md5 item invalid\n");
			return -1;
		}
		snprintf(msg.md5, sizeof(msg.md5), "%s", md5->valuestring);
	}

	tid = syscall(SYS_gettid); //取线程的pid
	INFO("task thread id %d\n", tid);

	switch (msg.cmd_type) {
		/* 主机隔离 */
		case TASK_HOSTS_QUARANTINE:
			INFO("Quarantine task\n");
			update_kernel_net_host_quarantine(1);
			send_task_resp(&msg, RESULT_OK, "Quarantine");
			break;

		/* 取消主机隔离 */
		case TASK_CANCEL_HOSTS_QUARANTINE:
			INFO("Quarantine Cancel task\n");
			update_kernel_net_host_quarantine(0);
			send_task_resp(&msg, RESULT_OK, "Cancel Quarantine");
			break;

		/* 允许和禁止防护，未使用，似乎意义不大 */
		case TASK_STOP_PROTECT:
			INFO("Protect Stop task\n");
			//stop_protect(&msg);
			break;

		case TASK_START_PROTECT:
			INFO("Protect Start task\n");
			//start_protect(&msg);
			break;

		/* 重启主机 */
		case TASK_REBOOT_HOSTS:
			INFO("Reboot Host task\n");
			break;

		/* 更新策略 */
		case TASK_UPDATE_POLICY:
			INFO("Policy Update task\n");
			update_policy_my(&msg);
			break;

		/* 更新配置 */
		case TASK_UPDATE_CONF:
			INFO("Config Update task\n");
			update_conf_my(&msg);
			break;

		/* 更新主机信息 */
		case TASK_SYNC_HOST_INFO:
			INFO("Asset Update task\n");
			ret = upload_sysinfo(0); /* 按模块采集 */
			if (ret == -1) {
				send_task_resp(&msg, RESULT_FAIL, "Upload asset fail");
			} else if (ret == -2) {
				send_task_resp(&msg, RESULT_FAIL, "Run asset program fail");
			} else if (ret == -3) {
				send_task_resp(&msg, RESULT_FAIL, "No memory to update asset");
			} else {
				send_task_resp(&msg, RESULT_OK, "Update Asset");
			}
			break;

		/* 卸载主机 */
		case TASK_UNINSTALL:
			INFO("Uninstall task\n");
			uninstall_sniper(&msg);
			break;

		/* 获取进程列表 */
		case TASK_GET_PROCESS:
			INFO("Get Processes List task\n");
			break;

		/* 结束进程 */
		case TASK_KILL_PROCESS:
			INFO("Kill Process task\n");
			break;

		/* 隔离进程 */
		case TASK_PROCESS_QUARANTINE:
			INFO("Process Quarantine task\n");
			break;

		/* 隔离文件 */
		case TASK_FILE_QUARANTINE:
			INFO("File Quarantine task\n");
			file_quarantine(&msg);
			break;

		/* 取消文件隔离 */
		case TASK_CANCEL_FILE_QUARANTINE:
			INFO("File Quarantine Cancel task\n");
			file_cancel_quarantine(&msg);
			break;

		/* 解锁ip */
		case TASK_UNLOCK_IP:
			INFO("Unlock IP task\n");
			if (msg.ip[0]) {
				if (unlock_ip(msg.ip) == 0) {
					send_task_resp(&msg, RESULT_OK, "Unlock IP");
				} else {
					send_task_resp(&msg, RESULT_FAIL, "Unlock IP");
				}
			} else {
				send_task_resp(&msg, RESULT_FAIL, "Unlock Null");
			}
			break;

		/* 更新规则 */
		case TASK_UPDATE_RULE:
			INFO("Rule Update task\n");
			is_update_task = 1;
			update_rule_my(&msg);
			break;

		/* 杀毒 */
		case TASK_ANTIVIRUS:
			INFO("Antivirus task\n");
			break;

		/* webshell扫描 */
		case TASK_WEBSHELL_SCAN:
			INFO("Webshell Scan task\n");
			break;

		/* 基线检查 */
		case TASK_BASELINE_CHECK:
			INFO("Baseline Check task\n");
			ret = RESULT_OK;
			for (i = 0; i < rule_size; i++) {
				if (rule_id[i] != 0 &&
				    parse_baseline_database(&msg, rule_id[i], whitelist, white_size) < 0) {
					ret = RESULT_FAIL;
				}
			}
			send_task_resp(&msg, ret, "Baseline Check");
			if (whitelist) {
				free(whitelist);
			}
			if (rule_id) {
				free(rule_id);
			}
			break;

		/* 升级客户端 */
		case TASK_UPDATE_CLIENT:
			INFO("Client Update task\n");
			update_client(&msg);
			break;

		/* 病毒库/防病毒程序升级 */
		case TASK_UPDATE_VIRUS_DATABASE:
#ifdef USE_AVIRA
			INFO("Virusbase Update task\n");
			update_virus_database_my(&msg);
#endif
			break;

		/* 弱口令扫描 */
		case TASK_DETECT_WEAK_ACCOUNT_PWD:
			/*
			 * TODO 弱密码检测很占CPU，如何改善
			 * 如果拉长处理时间，比如中间增加睡眠，能降低cpu，但任务时间拉长，降低了体验
			 * 尝试过fork子进程来做弱密码检测，这样不把cpu开销记到sniper头上
			 * 但遇到2个问题
			 * 1、做弱密码检测时，出现2个sniper程序，让人困惑
			 * 2、弱密码检测进程挂在futex锁里时（原因不明），不方便自动检测到这个异常情况并处理
			 */
			INFO("Weak Password Detect task\n");
			prctl(PR_SET_NAME, "chkweakpwd"); //设置线程名，使知道是谁在忙
			check_user_weakpwd(&msg); //TODO 弱密码检测很占CPU，如何改善
			break;

		/* 风险账号扫描 */
		case TASK_DETECT_RISK_ACCOUNT:
			INFO("Risk account Detect task\n");
			detect_risk_account(&msg);
			break;

		/* 系统风险扫描 */
		case TASK_SYS_DANGEROUS:
			INFO("System Risk Detect task\n");
			prctl(PR_SET_NAME, "chksysrisk"); //设置线程名，使知道是谁在忙
			check_sys_danger(&msg); //TODO 涉及到弱密码检测，弱密码检测很占CPU，如何改善
			break;

		/* 基线检查停止 */
		case TASK_BASELINE_STOP:
			INFO("Stop Baseline Check task\n");
			if (baseline_stop(&msg) == 0) {
				send_task_resp(&msg, RESULT_OK, "Stop Baseline Check");
			} else {
				send_task_resp(&msg, RESULT_FAIL, "Stop Baseline Check");
			}
			break;

		/* 客户端信息同步 */
		case TASK_INFO_SYNC:
			INFO("Misc Databases Sync task\n");
			send_sync_info(SYNC_ALL, NULL);
			break;

		/* 暴力密码破解配置文件更新 */
		case TASK_UPDATE_CRACK_CONF:
			INFO("Crack Config Update task\n");
			download_crack_conf(&msg);
			is_update_conf = 1;
			break;

		default:
			MON_ERROR("task cmd type error: %d\n", msg.cmd_type);
			return -1;
	}

	INFO("task over. thread id %d, taskid %s\n", tid, msg.cmd_id);
	return 0;
}

/* task_monitor在p_msg->post_data有效时，才会调用task_handle */
static void *task_handle(void *arg)
{
	cJSON *json = NULL;
	log_msg_t *p_msg = (log_msg_t *)arg;

	/*
	 * 与父线程分离，避免异步处理的子线程未回收，内存泄露
	 *
	 * 一般情况下，线程终止后，其终止状态一直保留，
	 * 直到其它线程调用pthread_join获取它的状态，或进程终止被回收
	 * 而线程主动与主控线程断开关系后，线程一旦终止就立刻回收它占用的所有资源，不保留终止状态
	 */
	pthread_detach(pthread_self());

	DBG2(DBGFLAG_TASK, "task data: %s\n", p_msg->post_data);

	json = cJSON_Parse(p_msg->post_data);
	if (!json) {
		MON_ERROR("parse task data %s fail: %s\n", p_msg->post_data, cJSON_GetErrorPtr());
	} else {
		if (parse_server_task(json) < 0) {
			MON_ERROR("parse task data %s fail\n", p_msg->post_data);
		}
		cJSON_Delete(json);
	}

	free(p_msg->post_data);
	free(p_msg);

	return NULL;
}

/* 处理管控下发的任务 */
void *task_monitor(void *ptr)
{
	int i = 0, msg_cnt = 0;
	log_msg_t *p_msg = NULL;
	pthread_t thread_id = 0;

	prctl(PR_SET_NAME, "task_handler");
	save_thread_pid("task", SNIPER_THREAD_TASK);

	while (Online) {
		/* 此处过期或停止防护仍工作，否则接收不到开启防护的任务和拉取配置 */
		msg_cnt = msg_queue_count(task_msg_queue);

		/* 检查待转储的日志文件 */
		check_log_to_send("task");

		if (msg_cnt <= 0) {
			sleep(5);
			continue;
		}

		for (i = 0; i< msg_cnt; i++) {
			p_msg = msg_queue_pop(task_msg_queue);
			if (p_msg == NULL) {
				break; //未取到任务消息
			}

			if (p_msg->post_data == NULL) {
				free(p_msg);
				continue;
			}

			/* 客户端在websocket连接上发送心跳包，检测连接是否正常，
			   管控回复{"msg":"","code":0}，这个回复不需要处理，直接丢弃就好 */
			if (strstr(p_msg->post_data, "{\"msg\":\"\",\"code\":0}") != NULL) {
				free(p_msg->post_data);
				free(p_msg);
				continue;
			}

			/* 创建新的线程去处理任务,实现并行 */
			pthread_create(&thread_id, NULL, task_handle, p_msg);
		}
	}

	INFO("task thread exit\n");
	return NULL;
}
