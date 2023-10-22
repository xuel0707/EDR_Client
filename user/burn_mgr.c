#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/inotify.h>

#include "header.h"

#define BRASERO_TMP "/tmp/snp_brasero.rdd"
#define BRASERO_MD5 "/tmp/snp_brasero.md5"
#define BURN_FILE_NUM 8

struct burn_file {
	char name[64];
	char path[256];
	int size;
	char ext[16];
	char md5[64];
};

struct burn_dev
{
	char name[64];
	char vendor[64];
	char model[64];
	char type[8];
	char uuid[64];
};

void cdrom_terminate_post_data(struct file_msg_args *msg)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	int behavior = 0, level = 0, result = 0;
	int defence_result = MY_RESULT_OK;
	char operating[OP_LEN_MAX] = {0};
	bool event = true;
	int terminate = 0;
	unsigned long event_time = 0;
	struct timeval tv;
	struct defence_msg defmsg = {0};

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

	if (client_mode_global == OPERATION_MODE) {
		terminate = MY_HANDLE_WARNING;
		event = false;
        } else {
		terminate = MY_HANDLE_BLOCK_OK;
		event = true;
        }

	level = MY_LOG_HIGH_RISK;
	behavior = MY_BEHAVIOR_VIOLATION;
	result = MY_RESULT_FAIL;

	strncpy(operating, "Burning", OP_LEN_MAX);
	operating[OP_LEN_MAX - 1] = '\0';

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;
	if (msg->tty[0] != 0) {
		get_session_uuid(msg->tty, msg->session_uuid);
	}

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "IllegalCDROM");
	cJSON_AddStringToObject(object, "log_category", "CDROM");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", "Fasten");
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

	cJSON_AddStringToObject(arguments, "process_uuid", "");
	cJSON_AddStringToObject(arguments, "process_name", msg->cmdname);
	cJSON_AddNumberToObject(arguments, "process_id", 0);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
	cJSON_AddStringToObject(arguments, "process_path", "");
	cJSON_AddStringToObject(arguments, "process_commandline", "");
	cJSON_AddStringToObject(arguments, "md5", "");
	cJSON_AddStringToObject(arguments, "drive_name", "");
	cJSON_AddStringToObject(arguments, "medie_type", "");
	cJSON_AddStringToObject(arguments, "file_name", "");
	cJSON_AddStringToObject(arguments, "file_path", "");
	cJSON_AddStringToObject(arguments, "extension", "");
	cJSON_AddNumberToObject(arguments, "file_size", 0);
	cJSON_AddStringToObject(arguments, "session_uuid", msg->session_uuid);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_CDROM, "terminate burning post:%s\n", post);

	client_send_msg(post, reply, sizeof(reply), LOG_URL, "file"); //禁止刻录由file线程处理

	cJSON_Delete(object);
	free(post);

	if (client_mode_global == OPERATION_MODE) {
		return;
	}

	defmsg.event_tv.tv_sec = 0;
	defmsg.operation = termstr;
	defmsg.result = defence_result;

	defmsg.user = msg->username;
	defmsg.log_name = "IllegalCDROM";
	defmsg.log_id = uuid;
	defmsg.object = msg->cmdname;

	send_defence_msg(&defmsg, "file"); //禁止刻录由file线程处理
}

void post_burn_event(struct burn_dev *dev, struct burn_file file, int burn_ret, char *user)
{       
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	int behavior = 0, level = 0, result = 0;
	char operating[OP_LEN_MAX] = {0};
	bool event = false;
	int terminate = 0;
	unsigned long event_time = 0;
	struct timeval tv;

	int i = 0, num = 0;
	int flag = 0;

	if (fasten_policy_global.device.cdrom.enable == 0 &&
		fasten_policy_global.device.cdrom.terminate == 1) {
		return;
	}

	pthread_rwlock_rdlock(&fasten_policy_global.lock);
	num = fasten_policy_global.device.cdrom.ext_num; 
	for (i = 0; i < num; i++) {
		if (strcmp(fasten_policy_global.device.cdrom.ext[i].list, "*") == 0
			|| strcmp(fasten_policy_global.device.cdrom.ext[i].list, file.ext) == 0) {
			flag = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&fasten_policy_global.lock);

	/* 监控的类型为空 */
	if (num == 0) {
		flag = 1;
	}

	if (flag == 0) {
		return;
	}	

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

	level = MY_LOG_KEY;
	behavior = MY_BEHAVIOR_NO;
	terminate = MY_HANDLE_NO;

	if (burn_ret == OPERATE_OK) {
		result = MY_RESULT_OK;
	} else {
		result = MY_RESULT_FAIL;
	}

	strncpy(operating, "Burning", OP_LEN_MAX);
	operating[OP_LEN_MAX - 1] = '\0';

	gettimeofday(&tv, NULL);
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "CDROM");
	cJSON_AddStringToObject(object, "log_category", "CDROM");
	cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", user ? user: "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "process_uuid", "");
	cJSON_AddStringToObject(arguments, "process_name", "");
	cJSON_AddNumberToObject(arguments, "process_id", 0);
	cJSON_AddNumberToObject(arguments, "thread_id", 0);
	cJSON_AddStringToObject(arguments, "process_path", "");
	cJSON_AddStringToObject(arguments, "process_commandline", "");
	cJSON_AddStringToObject(arguments, "md5", file.md5);
	cJSON_AddStringToObject(arguments, "drive_name", dev->name);
	cJSON_AddStringToObject(arguments, "medie_type", dev->type);
	cJSON_AddStringToObject(arguments, "file_name", file.name);
	cJSON_AddStringToObject(arguments, "file_path", file.path);
	cJSON_AddStringToObject(arguments, "extension", file.ext);
	cJSON_AddNumberToObject(arguments, "file_size", file.size);
	cJSON_AddStringToObject(arguments, "session_uuid", "");

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_CDROM, "cdrom post:%s\n", post);

	client_send_msg(post, reply, sizeof(reply), LOG_URL, "cdrom"); //刻录日志由cdrom线程自己处理

	cJSON_Delete(object);
	free(post);
}

int get_devinfo(char *dev_name, struct burn_dev *dev)
{       
	FILE *fp = NULL;

	char dev_model[64] = {0};
	char dev_vendor[64] = {0};
	char dev_uuid[64] = {0};
	char dev_type[8] = {0};

	strcpy(dev_model, "Unknown");
	strcpy(dev_uuid, "Unknown");
	strcpy(dev_type, "cd");

	fp = fopen("/sys/class/block/sr0/device/model", "r");
	if (fp != NULL) {
		fscanf(fp, "%s", dev_model);
		fclose(fp);
	}

	fp = fopen("/sys/class/block/sr0/device/vendor", "r");
	if (fp != NULL) {
		fscanf(fp, "%s", dev_vendor);
		fclose(fp);
	}
	
	DIR *dp = opendir("/dev/disk/by-id");
	if (dp == NULL) {
                return 0;
	}
	
        struct dirent *dirp;
        while ((dirp = readdir(dp)) != NULL) {
		if (strstr(dirp->d_name, dev_vendor)) {
			char *ptr = strrchr(dirp->d_name, '_');
			if (ptr != NULL && strlen(ptr) > 1) {
				strncpy(dev_uuid, ptr + 1 , 64);
				break;
			}
		}
	}
	closedir(dp);

	DBG2(DBGFLAG_CDROM, "DVD device, name:%s, model:%s, type:%s, uuid:%s\n", dev_name, dev_model, dev_type, dev_uuid);

	if (strlen(dev_uuid) > 0) {
		strncpy(dev->name, dev_name, 64);
		strncpy(dev->vendor, dev_vendor, 64);
		strncpy(dev->model, dev_model, 64);
		strncpy(dev->type, dev_type, 8);
		strncpy(dev->uuid, dev_uuid, 64);
	}

	return 0;
}

int parse_brasero_tmp_file(int burn_ret, char *user)
{
	int i = 0;
	int len = 0;
	int file_num = 0;
	char *p_str = NULL;
	FILE *fp = NULL;
	char dev_name[8] = {0};
	char line[S_LINELEN] = {0};

	char name[S_NAMELEN] = {0};
	char path[256] = {0};

	struct burn_dev dev;
	struct burn_file file[8];

	memset(&dev, 0, sizeof(struct burn_dev));
	memset(file, 0, sizeof(struct burn_file) * 8);

	fp = fopen(BRASERO_TMP, "r");
	if (fp == NULL) {
		MON_ERROR("open /tmp/snp_brasero.rdd failed!\n");
		return -1;
	}

	i = 0;
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, "disc path = /") && strstr(line, "URI = file") && i < BURN_FILE_NUM) {

			if (strstr(line, ".md5") != NULL) {
				//printf("line:%s \n", line);
				continue;
			}
		
			p_str = strstr(line, "URI = file://");
			len = strlen(p_str);
			if (p_str != NULL && len > 14) {
				strncpy(path, p_str + 13, 256);
				len = strlen(path);
				path[len-1] = '\0';
			}

			p_str = strstr(line, "disc path = /");
			len = strlen(p_str);
			if (p_str != NULL && len > 28) {
				strncpy(name, p_str + 13, len - strlen(path) - 29);
			}

			if (strlen(name) > 0 || strlen(path) > 0) {
				strncpy(file[i].name, name, 64);
				strncpy(file[i].path, path, 256);

				char *postfix = strrchr(path,'.');
				if (postfix != NULL && strlen(postfix) > 1) {
					postfix++;
					strncpy(file[i].ext, postfix, 16);
				}

				i++;
			}
		}

		if (strstr(line, "init result = 1") != NULL) {
			p_str = strstr(line, "Drive (/dev/sr");
			if (p_str) {
				strncpy(dev_name, p_str+12, 3);
			}
			get_devinfo(dev_name, &dev);
		}
	
		if (strstr(line, "output set (IMAGE)") != NULL) {
			p_str = strstr(line, "image =");
			if (p_str) {
				sscanf(p_str, "image = %s %*s", dev.name);
			}
			
			strcpy(dev.model, "iso");
			strcpy(dev.type, "file");
			strcpy(dev.uuid, "000001");
		}
	}
	fclose(fp);

	unlink(BRASERO_TMP);

	file_num = i;
	struct stat statbuf; 
	for (i = 0; i < file_num; i++) {
		//get file size 
		char *file_name = url_decode(file[i].path);
		strncpy(file[i].path, file_name, 256);

		stat(file[i].path, &statbuf); 
		file[i].size = statbuf.st_size;
		free(file_name);

		//get the file md5
		md5_filter_large_file(file[i].path, file[i].md5);
		post_burn_event(&dev, file[i], burn_ret, user);		
	}

	return 0;
}

void *burn_mgr(void *ptr)
{
	int len = 0;
	int fd, wd = -1;
	struct timeval tv = {0};
	char buffer[256] = {0};
	char brasero_file[64] = {0};

	fd = inotify_init();
	if (fd == -1) {
		MON_ERROR("----inotify_init(burn) failed!\n");
		return NULL;
	}

	prctl(PR_SET_NAME, "burn_monitor");
	save_thread_pid("cdrom", SNIPER_THREAD_CDROM);

	wd = inotify_add_watch(fd, "/tmp/", IN_CREATE);
	if (wd < 0) {
		MON_ERROR("burn_mgr inotify_add_watch /tmp fail: %s\n", strerror(errno));
	}

        while (Online) {
                fd_set fds;
                struct inotify_event *event;
                int ret;
                int is_done = 0;
                int time = 0;
                char line[S_LINELEN]= {0};
                uid_t uid = 0;
                struct stat st = {0};
                char user[S_NAMELEN] = {0};
		FILE *fp = NULL;

		/* 检查待转储的日志文件 */
		check_log_to_send("cdrom");

		/* 如果停止防护，什么也不做 */
		if (sniper_other_loadoff == 1) {
                        DBG2(DBGFLAG_CDROM, "Stop protect, watch nothing\n");
			sleep(STOP_WAIT_TIME);
			continue;
		}

                /* 如果过期/停止客户端工作，什么也不做 */
                if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
                        DBG2(DBGFLAG_CDROM, "Expired or stop protect, watch nothing\n");
                        sleep(STOP_WAIT_TIME);
                        continue;
                }

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		tv.tv_sec = 5;
                tv.tv_usec = 0;

		if (fasten_policy_global.device.cdrom.enable == 0) {
			sleep(5);
			continue;
		}

		ret = select(fd + 1, &fds, NULL, NULL, &tv);
		if (ret > 0 && FD_ISSET(fd, &fds)) {
			len = read(fd, buffer, 256);
			if (len <= 0) {
				continue;
			}

			event = (struct inotify_event *)buffer;
                        if (strncmp(event->name, "brasero_tmp_", 12) != 0 ||
                            strstr(event->name, ".md5") ||
                            strstr(event->name, ".bin")) {
                                continue;
                        }

                        if(!(event->mask & IN_CREATE)) {
                                continue;
                        }


			snprintf(brasero_file, 63, "/tmp/%s", event->name);

			if (stat(brasero_file, &st) < 0) {
				MON_ERROR("stat %s fail: %s\n",
					brasero_file, strerror(errno));
			} else {
				uid = st.st_uid;
			}

			unlink(BRASERO_TMP);
			link(brasero_file, BRASERO_TMP);

			do {
				sleep(3);

				fp = fopen(BRASERO_TMP, "r");
				if (fp != NULL) {
					while (fgets(line, sizeof(line), fp) != NULL) {
						if (strstr(line, "Session cancelled")) {
							is_done = OPERATE_FAIL;
							break;
						}
						if (strstr(line, "Session successfully finished")) {
							is_done = OPERATE_OK;
							break;
						}
					}
					fclose(fp);
				}

				time++;
			} while (is_done == 0 && time < 400);

			if (is_done > 0) {
				uidtoname(uid, user);
				parse_brasero_tmp_file(is_done, user);
			}
					
			unlink(BRASERO_TMP);
		}
	}

	inotify_rm_watch(fd, wd);
	close(fd);

	INFO("cdrom thread exit\n");

	return NULL;
}
