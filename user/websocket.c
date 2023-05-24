#include "header.h"
#include "cJSON.h"

#define SHAKE_KEY_LEN		128
#define RESP_KEY_LEN		256
#define RNADOM_KEY_LEN		16
#define WEBSOCKET_GUID		"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

int websocket_heartbeat = 1;

extern int32_t ws_enPackage(
    uint8_t *data,
    uint32_t dataLen,
    uint8_t *package,
    uint32_t packageMaxLen,
    bool mask,
    WsData_Type type);
extern int ws_send(int fd, char *data, int dataLen, bool mask, WsData_Type type);

/* websocket数据收发阶段的数据打包, client发server的数据都要mask(掩码)处理 */
int build_websocket_package(uint8_t *data, unsigned int data_len, uint8_t *package,
			    unsigned int max_len, bool mask, WsData_Type type)
{
	unsigned int i = 0, pkg_len = 0;
	uint8_t mask_key[4] = {0};
	unsigned int mask_count = 0;

	/* 最小长度检查 */
	if (max_len < 2) {
		return -1;
	}

	/* 根据包类型设置头字节 */
	if (type == WDT_MINDATA) {
		*package++ = 0x80;
	} else if (type == WDT_TXTDATA) {
		*package++ = 0x81;
	} else if (type == WDT_BINDATA) {
		*package++ = 0x82;
	} else if (type == WDT_DISCONN) {
		*package++ = 0x88;
	} else if (type == WDT_PING) {
		*package++ = 0x89;
	} else if (type == WDT_PONG) {
		*package++ = 0x8A;
	} else {
		return -1;
	}

	pkg_len += 1;

	if (mask) {
		*package = 0x80;
	}

	if (data_len < 126) {
		/* 半字节记录长度 */
		*package++ |= (data_len & 0x7F);
		pkg_len += 1;
	} else if (data_len < 65536) {
		/* 2字节记录长度 */
		if (max_len < 4) {
			return -1;
		}

		*package++ |= 0x7E;
		*package++ = (uint8_t)((data_len >> 8) & 0xFF);
		*package++ = (uint8_t)((data_len >> 0) & 0xFF);
		pkg_len += 3;
	} else {
		/* 8字节记录长度 */
		if (max_len < 10) {
			return -1;
		}
	
		*package++ |= 0x7F;
		*package++ = 0;
		*package++ = 0;
		*package++ = 0;
		*package++ = 0;
		*package++ = (uint8_t)((data_len >> 24) & 0xFF);
		*package++ = (uint8_t)((data_len >> 16) & 0xFF);
		*package++ = (uint8_t)((data_len >> 8) & 0xFF);
		*package++ = (uint8_t)((data_len >> 0) & 0xFF);
		pkg_len += 9;
	}

	if (mask) {
		/* 长度不足 */
		if (max_len < pkg_len + data_len + 4) {
			return -1;
		}

		/* 随机生成掩码 */
		creat_random_string((char *)mask_key, sizeof(mask_key));
		*package++ = mask_key[0];
		*package++ = mask_key[1];
		*package++ = mask_key[2];
		*package++ = mask_key[3];
		pkg_len += 4;

		for (i = 0, mask_count = 0; i < data_len; i++, mask_count++) {
			/* mask_key[4]循环使用 */
			if (mask_count == 4) {
				mask_count = 0;
			}

			/* 异或运算后得到数据 */
			*package++ = mask_key[mask_count] ^ data[i];
		}

		pkg_len += i;
		*package = '\0';
	} else {
		/* 数据没使用掩码, 直接复制数据段 */

		/* 长度不足 */
		if (max_len < pkg_len + data_len) {
			return -1;
		}

		for (i = 0; i < data_len; i++) {
			*package++ = data[i];
		}

		pkg_len += i;
		*package = '\0';
	}

	return pkg_len;
}

int parse_websocket_package(uint8_t *data, unsigned int len, unsigned int *ret_data_len,
			    unsigned int *ret_head_len, WsData_Type *pkg_type)
{
	int ret = 0, i = 0, j = 0;
	uint8_t type = 0;

	/* 数据段长度 */
	unsigned int data_len = 0;
	/* 数据段起始位置 */
	unsigned int offset = 2;

	/* 掩码 */
	uint8_t mask_key[4] = {0};
	bool mask = false;
	unsigned int mask_count = 0;


	/* 数据过短 */
	if (len < 2) {
		return 0;
	}

	/* 解析包类型 */
	if ((data[0] & 0x80) == 0x80) {
		type = data[0] & 0x0F;
		if (type == 0x00) {
			*pkg_type = WDT_MINDATA;
		} else if (type == 0x01) {
			 *pkg_type = WDT_TXTDATA;
		} else if (type == 0x02) {
			*pkg_type = WDT_BINDATA;
		} else if (type == 0x08) {
			*pkg_type = WDT_DISCONN;
		} else if (type == 0x09) {
			*pkg_type = WDT_PING;
		} else if (type == 0x0A) {
			*pkg_type = WDT_PONG;
		} else {
			return 0;
		}
	} else {
		return 0;
	}

	/* 是否掩码,及长度占用字节数 */
	if ((data[1] & 0x80) == 0x80) {
		mask = true;
		mask_count = 4;
	}

	data_len = data[1] & 0x7F;
	if (data_len == 126) {
		/* 2字节记录长度 */

		/* 数据长度不足以包含长度信息 */
		if (len < 4) {
			return 0;
		}

		/* 2字节记录长度 */
		data_len = data[2];
		data_len = (data_len << 8) + data[3];

		/* 转储长度信息 */
		*ret_data_len = data_len;
		*ret_head_len = 4 + mask_count;

		/* 数据长度不足以包含掩码 */
		if (len < mask_count + 4) {
			ret = -(int)(mask_count + 4 + data_len -len);
			return ret;
		}

		if (mask) {
			mask_key[0] = data[4];
			mask_key[1] = data[5];
			mask_key[2] = data[6];
			mask_key[3] = data[7];
			offset = 8;
		} else {
			offset = 4;
		}
	} else if (data_len == 127) {
		/* 8字节记录长度 */

		/* 数据长度不足以包含长度信息 */
		if (len < 8) {
			return 0;
		}

		/* 使用8个字节存储长度时,前4位必须为0,装不下那么多数据 */
		if (data[2] != 0 ||
		    data[3] != 0 ||
		    data[4] != 0 ||
		    data[5] != 0) {
			return 0;
		}

		/* 8字节记录长度 */
		data_len = data[6];
		data_len = (data_len << 8) | data[7];
		data_len = (data_len << 8) | data[8];
		data_len = (data_len << 8) | data[9];

		/* 转储长度信息 */
		*ret_data_len = data_len;
		*ret_head_len = 10 + mask_count;

		/* 数据长度不足以包含掩码 */
		if (len < mask_count + 10) {
			ret = -(int)(mask_count + 10 + data_len -len);
			return ret;
		}

		if (mask) {
			mask_key[0] = data[10];
			mask_key[1] = data[11];
			mask_key[2] = data[12];
			mask_key[3] = data[13];
			offset = 14;
		} else {
			offset = 10;
		}
	} else {
		/* 半字节记录长度 */

		/* 转储长度信息 */
		*ret_data_len = data_len;
		*ret_head_len = 2 + mask_count;

		/* 数据长度不足以包含掩码 */
		if (len < mask_count + 2) {
			ret = -(int)(mask_count + 2 + data_len -len);
			return ret;
		}

		if (mask) {
			mask_key[0] = data[2];
			mask_key[1] = data[3];
			mask_key[2] = data[4];
			mask_key[3] = data[5];
			offset = 6;
		} else {
			offset = 2;
		}

	}

	/* 数据长度不足以包含完整数据段 */
	if (len < data_len + offset) {
		ret = -(int)(data_len + offset -len);
		return ret;
	}
	
	if (mask) {
		/* 使用掩码时, 使用异或解码, maskKey[4]依次和数据异或运算 */

		j = offset;
		mask_count = 0;
		for (i = 0; i < data_len; i++, j++, mask_count++) {

			/* mask_key[4]循环使用 */
			if (mask_count == 4) {
				mask_count = 0;
			}

			/* 异或运算后得到数据 */
			data[i] = mask_key[mask_count] ^ data[j];

		}

		data[j] = '\0';
	} else {
		/* 没使用掩码, 直接复制数据段 */

		j = offset;
		for (i = 0; i < data_len; i++, j++) {
			data[i] = data[j];
		}

		data[data_len] = '\0';
	}

	/* 有些特殊包数据段长度可能为0,这里为区分格式错误返回,置为1 */
	if (data_len == 0) {
		data_len = 1;
	}

	return data_len;
}

/* server端在接收client端的key后,构建回应用的key */
static int build_resp_shake_key(char *client_key, unsigned client_key_len, char *server_key)
{
	char *key = NULL;
	char *ptr = NULL;
	char *sha1_data_temp = NULL;
	char *sha1_data = NULL;
	int i = 0, ret = 0;
	int len = 0, guid_len = 0, data_len = 0;

	if (client_key == NULL) {
		return 0;
	}

	guid_len = strlen(WEBSOCKET_GUID);
	len = client_key_len + guid_len + 10;

	key = (char *)malloc(len);
	if (key == NULL) {
		MON_ERROR("malloc respond shake key failed\n");
		return -1;
	}
	memset(key, 0, len);

	memcpy(key, client_key, client_key_len);
	ptr = key;
	ptr += client_key_len;
	memcpy(ptr, WEBSOCKET_GUID, guid_len);
	key[client_key_len + guid_len] = '\0';

	sha1_data_temp = sha1_hash(key);
	data_len = strlen(sha1_data_temp);
	len = data_len / 2 + 1;
    	sha1_data = (char *)malloc(len);
	if (sha1_data == NULL) {
		MON_ERROR("malloc respond sha1 data failed\n");
		free(sha1_data_temp);
		free(key);
		return -1;
	}
	memset(sha1_data, 0, len);

	for (i = 0; i < data_len; i += 2) {
		sha1_data[i / 2] = htoi(sha1_data_temp, i, 2);
	}

	ret = ws_base64_encode((const uint8_t *)sha1_data, server_key, data_len / 2);

	free(sha1_data_temp);
	free(sha1_data);
	free(key);
	return ret;
}

/* client端使用随机数构建握手用的key */
static int build_shake_key(char *key)
{
	int ret = 0;
	char random_key[RNADOM_KEY_LEN] = {0};

	creat_random_string(random_key, RNADOM_KEY_LEN);
	ret = ws_base64_encode((const uint8_t *)random_key, key, RNADOM_KEY_LEN);

	return ret;
}

/* client端收到来自服务器回应的key后进行匹配,以验证握手成功 */
static int match_shake_key(char *sendkey, unsigned int sendkey_len, char *acceptkey, unsigned int acceptkey_len)
{
	int len = 0;
	char key[RESP_KEY_LEN] = {0};

	len = build_resp_shake_key(sendkey, sendkey_len, key);
	if (len <= 0) {
		return -1;
	}

	if (len != acceptkey_len) {
		MON_ERROR("match shake key len error: %s:%s:%s\n", sendkey, key, acceptkey);
		return -1;
	} else if (strcmp(key, acceptkey) != 0) {
		MON_ERROR("match shake key str error: %s:%s\n", key, acceptkey);
		return -1;
	}

	return 0;
}

/* 向websocket服务器发送http(携带握手key), 以和服务器构建连接, 非阻塞模式 */
int websocket_connect_to_server(char *ip, int port, char *path, int timeout_ms)
{
	int fd = 0, ret = 0, flags = 0, len = 0;
	int timeout_count = 0;
	char buff[S_LINELEN] = {0};
	char http_head[S_LINELEN] = {0};
	char shake_key[SHAKE_KEY_LEN] = {0};
	char key[RESP_KEY_LEN] = {0};
	char *ptr = NULL;
	struct sockaddr_in report_addr;

	memset(&report_addr, 0, sizeof(report_addr));
	report_addr.sin_family = AF_INET;
	report_addr.sin_port = htons(port);
	report_addr.sin_addr.s_addr = inet_addr(ip);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		MON_ERROR("websocket socket fail: %s\n", strerror(errno));
		return -1;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		MON_ERROR("get websocket flag fail: %s\n", strerror(errno));
		close(fd);
		return -1;
	};

	/* 设置非阻塞 */
	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret < 0) {
		MON_ERROR("set websocket nonblock fail: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	/* 建立连接 */
	timeout_count = 0;
	while (connect(fd, (struct sockaddr *)&report_addr, sizeof(struct sockaddr)) != 0) {
		
		timeout_count++;
		if (timeout_count > timeout_ms) {
			/* 连续不通的情况下，只报一次 */
			if (websocket_heartbeat == 1) {
				MON_ERROR("websocket connect %s:%d timeout:%d, timeout_ms:%d\n", ip, port, timeout_count, timeout_ms);
			}
			DBG2(DBGFLAG_WEBSOCKET2, "websocket connect %s:%d timeout:%d, timeout_ms:%d\n", ip, port, timeout_count, timeout_ms);
			websocket_heartbeat = 0;
			close(fd);
			return -1;
		}

		usleep(100000);
	}

	DBG2(DBGFLAG_WEBSOCKET2, "websocket connect %s:%d success\n", ip, port);

	/* 发送http协议头 */
	build_shake_key(shake_key);
	snprintf(http_head, S_LINELEN,
		"GET %s HTTP/1.1\n"
		"Connection: Upgrade\n"
		"Host: %s:%d\n"
		"Sec-WebSocket-Key: %s\n"
		"Sec-WebSocket-Version: 13\n"
		"Upgrade: websocket\n\n",
		path, ip, port, shake_key);
	send(fd, http_head, strlen(http_head), MSG_NOSIGNAL);
//printf("http_head: %s\n", http_head);

	while (1) {
		memset(buff, 0, sizeof(buff));

		ret = recv(fd, buff, sizeof(buff), MSG_NOSIGNAL);
		if (ret > 0) {
//printf("buff: %s\n", buff);
			if (strncmp(buff, "HTTP", 4) == 0) {
				/* 定位握手字符串 */
				ptr = strstr(buff, "sec-websocket-accept: ");
				if (ptr != NULL) {
					len = strlen("sec-websocket-accept: ");
					ptr +=len;
					sscanf(ptr, "%s\n", key);

					/* 匹配握手信息 */
					ret = match_shake_key(shake_key, strlen(shake_key), key, strlen(key));
					if (ret == 0) {
						DBG2(DBGFLAG_WEBSOCKET2, "timeout check success. timeout_count:%d, timeout_ms:%d\n", timeout_count, timeout_ms);
						return fd;
					}
					DBG2(DBGFLAG_WEBSOCKET2, "shake_key:%s, rec_key:%s\n", shake_key, key);
				}
				/* 重发协议包 */
				send(fd, http_head, strlen(http_head), MSG_NOSIGNAL);
			}
		}

		/* 超时检查 */
		usleep(100000);
		timeout_count++;
		if (timeout_count > timeout_ms*2) {
			DBG2(DBGFLAG_WEBSOCKET2, "timeout check. timeout_count:%d, timeout_ms:%d\n", timeout_count, timeout_ms);
			break;
		}
	}

	close(fd);
	return -1;
}

/* websocket数据打包和发送 */
int websocket_send(int fd, char *data, int datalen, bool mask, WsData_Type type)
{
	uint8_t *pkg = NULL;
	int ret = 0, len = 0, retlen = 0;

	if (datalen < 0) {
		return 0;
	}

	if (type == WDT_NULL) {
		ret = send(fd, data, datalen, MSG_NOSIGNAL);
		return ret;
	}

	len = datalen + 14;
	pkg = (uint8_t *)malloc(sizeof(uint8_t) * len);
	if (pkg == NULL) {
		MON_ERROR("websocket_send pkg malloc failed\n");
		return 0;
	}
	memset(pkg, 0, sizeof(uint8_t) * len);

	retlen = build_websocket_package((uint8_t *)data, datalen, pkg, len, mask, type);
	if (retlen <= 0) {
		free(pkg);
		return 0;
	}
	
	ret = send(fd, pkg, retlen, MSG_NOSIGNAL);
	free(pkg);

	return ret;
}

/* websocket数据接收和解包 */
int websocket_recv(int fd, char *data, int max_len, WsData_Type *type)
{
	int ret = 0, result = 0, len = 0;
	int recv_ret = 0, depkg_ret = 0;
	unsigned int ret_head_len = 0, ret_data_len = 0;
	char tmp[16] = {0};
	unsigned int timeout = 0;
	WsData_Type pkg_type = WDT_NULL;

	if (data == NULL || max_len < 1) {
		/* 数据丢掉 */
		while (1) {
			len = recv(fd, tmp, sizeof(tmp), MSG_NOSIGNAL);
			if (len <= 0) {
				break;
			}
		}
	} else {
		if (max_len < 16) {
			MON_ERROR("max_len mast be >= 16\n");
		} else {
			/* 先接收数据头部,头部最大2+4+8=14字节 */
			recv_ret = recv(fd, data, 14, MSG_NOSIGNAL);
		}
	}

	if (recv_ret > 0) {
		depkg_ret = parse_websocket_package((uint8_t *)data, recv_ret, &ret_data_len, &ret_head_len, &pkg_type);
		/* 1.返回值为0的时候，非标准数据包，再接收一次，防止数据丢失，返回-len */
		/* 2.数据过大，当做非标准数据，能收多少收多少 */
		if (depkg_ret == 0 || (depkg_ret < 0 && recv_ret - depkg_ret > max_len)) {
			/* 能收多少收多少 */
			recv_ret += recv(fd, &data[recv_ret], max_len -recv_ret, MSG_NOSIGNAL);

			/* 数据过大，丢弃数据包，以免影响后续收包 */
			if (depkg_ret < 0) {
				while (1) {
					len = recv(fd, tmp, sizeof(tmp), MSG_NOSIGNAL);
					if (len <= 0) {
						break;
					}
				}
			}

			result = -recv_ret;
		} else {
			/* 检查是否需要续传 */
			if (depkg_ret < 0) {

				/* 再接收一次 */
				ret = recv(fd, &data[recv_ret], -depkg_ret, MSG_NOSIGNAL);
				if (ret > 0) {
					recv_ret += ret;
					depkg_ret += ret;
				}

				//数据量上百K时需要多次recv,无数据200ms超时,继续接收
				for (timeout = 0; timeout < 200 && depkg_ret < 0;) {
					usleep(5);
					timeout += 5;

					ret = recv(fd, &data[recv_ret], -depkg_ret, MSG_NOSIGNAL);
					if (ret > 0) {
						timeout = 0;
						recv_ret += ret;
						depkg_ret += ret;
					}
				}

				/* 二次解包 */
				depkg_ret = parse_websocket_package((uint8_t *)data, recv_ret, &ret_data_len, &ret_head_len, &pkg_type);
			} 
			if (depkg_ret > 0) {
				if (pkg_type == WDT_PING) {
					websocket_send(fd, NULL, 0, false, WDT_PONG);
					result = 0;
				} else if (pkg_type == WDT_PONG) {
					result = 0;
				} else if (pkg_type == WDT_DISCONN) {
					result = 0;
				} else {
					result = depkg_ret;
				}
			} else {
				result = -recv_ret;
			}
		}
	}

	if (type) {
		*type = pkg_type;
	}
	
	return result;
}

static void check_ip_change(int fd)
{
	socklen_t len = sizeof(struct sockaddr_in);
	struct sockaddr_in my_addr = {0};
	char myip[S_IPLEN] = {0};

	if (getsockname(fd, (struct sockaddr *)&my_addr, &len) < 0) {
		DBG2(DBGFLAG_WEBSOCKET, "getsocktname error: %s\n", strerror(errno));
		return;
	}

	inet_ntop(AF_INET, &my_addr.sin_addr, myip, S_IPLEN);
	DBG2(DBGFLAG_WEBSOCKET, "check connect ip: %s, port: %d\n", myip, my_addr.sin_port);

	/* 连接管控的ip和If_info.ip相同，不需要改变If_info.ip */
	if (strcmp(myip, If_info.ip) == 0) {
		return;
	}

	/* 修正If_info.ip */
	snprintf(If_info.ip, S_IPLEN, "%s", myip);

	send_sync_info(SYNC_IP, If_info.ip);
	INFO("change connect ip to %s\n", If_info.ip);
	return;
}

void *websocket_monitor(void *ptr)
{
	int fd = 0, ret = 0;
	char *recv_buff = NULL;
	char send_buff[SEND_PKG_MIN] = {0};
	WsData_Type pkg_type;
	int i = 0;
	int connect_num = 0;
	int send_num = 0;
	int recv_num = 0;
	int recv_flag = 0;

	recv_buff = sniper_malloc(RECV_PKG_MAX, OTHER_GET);
	if (!recv_buff) {
		MON_ERROR("task monitor malloc recv_buff failed\n");
		return NULL;
	}

	prctl(PR_SET_NAME, "websocket");
	save_thread_pid("websocket", SNIPER_THREAD_WEBSOCKET);

	while (Online) {
		/* 停止客户端工作，什么也不做, 过期了还需要通过websocket拉取配置 */
		if (client_disable == TURN_MY_ON) {
			sleep(STOP_WAIT_TIME);
		}

		if(ws_ip[0] == '\0' ||
		   ws_path[0] == '\0' ||
		   ws_port < 0 ||
		   ws_port > 65535) {
			/* 等待注册获取的websocket参数 */
			sleep(1);
			continue;
		}

		fd = websocket_connect_to_server(ws_ip, ws_port, ws_path, 30);
		connect_num++;
		if (fd < 0) {
			DBG2(DBGFLAG_WEBSOCKET, "第(%d)次连接, 连接失败 %s:%d path:%s\n", connect_num, ws_ip, ws_port, ws_path);
			sleep(3);
			continue;
		}
		check_ip_change(fd);
		websocket_heartbeat = 1;
		DBG2(DBGFLAG_WEBSOCKET, "第(%d)次连接, 连接成功\n", connect_num);

		INFO("websocket connect %s:%d success, path:%s\n", ws_ip, ws_port, ws_path);

		snprintf(send_buff, SEND_PKG_MIN, "{\"uuid\": \"%s\"}", Sys_info.sku);
		ret = websocket_send(fd, send_buff, strlen(send_buff), true, WDT_TXTDATA);
		send_num++;
		if (ret <= 0) {
			MON_ERROR("websocket 发送心跳失败\n");
			DBG2(DBGFLAG_WEBSOCKET, "第(%d)次发送心跳, 发送失败, ret:%d\n", send_num, ret);
			sleep(1);
			continue;
		}
		DBG2(DBGFLAG_WEBSOCKET, "第(%d)次发送心跳, 发送成功, ret:%d\n", send_num, ret);

		/* 用于后续判端连接是否正常 */
		recv_flag = 0;
		/* 管控切换和长连接断开，都需要重新连接 */
		while (Online) {
			/* 如果停止客户端工作，停止接收并退出循环, fd循坏外回收 */
			if (client_disable == TURN_MY_ON) {
				break;
			}

			//接收管控任务
			memset(recv_buff, 0, RECV_PKG_MAX);
			ret = websocket_recv(fd, recv_buff, RECV_PKG_MAX, &pkg_type);
			if (ret > 0 && pkg_type == WDT_TXTDATA) {
				recv_num++;
				DBG2(DBGFLAG_WEBSOCKET, "第(%d)次接收数据, Websocket recv data:%s\n", recv_num, recv_buff);
				http_post_mq(recv_buff, task_msg_queue);
				recv_flag = 1;
			}

			if (ret < 0 || (ret == 0 && i >=60)) {
				/* 管控升级会出现连接失败，但是发送成功的情况 */
				if (recv_flag == 0 && ret == 0 && i >=60) {
					i = 0;
					DBG2(DBGFLAG_WEBSOCKET, "连接不正常，重新连接\n");
					break;
				}

				/* 心跳检查连接是否断开 */
				i = 0;
				ret = websocket_send(fd, send_buff, strlen(send_buff), true, WDT_TXTDATA);
				send_num++;
				if (ret <= 0) {
					/* 发送失败，退出循环重新连接 */
					MON_ERROR("发送心跳失败\n");
					DBG2(DBGFLAG_WEBSOCKET, "第(%d)次发送心跳, 发送失败,ret:%d\n", send_num, ret);
					break;
				}
				DBG2(DBGFLAG_WEBSOCKET, "第(%d)次发送心跳, 发送成功,ret:%d\n", send_num, ret);
				recv_flag = 0;
			}
			i++;
			sleep(1);
		}

		close(fd);
		sleep(1);
	}

	sniper_free(recv_buff, RECV_PKG_MAX, OTHER_GET);

	INFO("websocket thread exit\n");
	return NULL;
}
