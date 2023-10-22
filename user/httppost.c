#include <curl/curl.h>
#include "header.h"

unsigned long upload_bytes = 0;
char sku_info[S_UUIDLEN+1] = {0};

/* 检查管控返回的数据中code的值，判断是否通信正常，正常返回0，异常返回-1 */
static int check_resp_key(char *reply)
{
	cJSON *json = NULL, *code = NULL;
	int ret = 0;

	if (reply == NULL) {
		return -1;
	}

	json = cJSON_Parse(reply);
	if (!json) {
		return -1;
	}

	code = cJSON_GetObjectItem(json, "code");
	if (!code) {
		cJSON_Delete(json);
		return -1;
	}

	/*
	 * code的值 0表示成功，其余表示失败
	 * 示例1:{"code":0,"message":"操作成功"}
	 * 示例2:{"msg":"客户端未注册","code":1}
	 */
	if (code->valueint == 0) {
		ret = 0;
	} else {
		ret = -1;
	}

	cJSON_Delete(json);
	return ret;
}

#define NO_MD5	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#if LIBCURL_VERSION_NUM > 0x070f05
int sockopt_cb(void *clientp, curl_socket_t curlfd, curlsocktype purpose)
{
	struct linger lig;
	int iLen;

	lig.l_onoff = 1;
	lig.l_linger = 0;
	iLen = sizeof(struct linger);

	setsockopt(curlfd, SOL_SOCKET, SO_LINGER, (char *)&lig, iLen);
	return 0;
}
#endif

struct reply_struct {
	char *reply;
	int reply_len;
};

/* reply data callback */
static size_t get_reply(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct reply_struct *data = (struct reply_struct *)userp;

	if (realsize >= data->reply_len) {
		realsize = data->reply_len - 1;
	}
	memcpy(data->reply, contents, realsize);
	return realsize;
}

/*
 * post data to a url and store reply data to reply
 * return 0 if success, -1 if failed.
 */
int http_post_data(char *url, char *post, char *reply, int reply_len)
{
	int ret = 0;
	CURL *curl = NULL;
	CURLcode rc = 0;
	struct curl_slist *headerlist = NULL;
	struct reply_struct data = { .reply = reply, .reply_len = reply_len };

	if (!url || !post || !reply) {
		return -1;
	}

	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("init post curl failed!\n");
		snprintf(reply, reply_len, "curl_easy_init fail");
		return -1;
	}

	/* 以json的格式传输数据 */
	headerlist = curl_slist_append(headerlist,"Content-Type: application/json;charset=UTF-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	//set USERAGENT
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT");

	//clear CLOSE_WAIT state
	curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post));
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

#if LIBCURL_VERSION_NUM > 0x070f05
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_cb);
#endif

	/*todo: SSL support https */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		if (client_registered && !Heartbeat_fail) {
			MON_ERROR("curl %s error(%d): %s. %s\n", url, rc,
				curl_easy_strerror(rc), rc == CURLE_COULDNT_CONNECT ? "" : post);
		}
		snprintf(reply, reply_len, "curl %s error: %s", url, curl_easy_strerror(rc));

		ret = -1;
	} else {
		/* 与管控中心不通时，curl http://ip:8000会报错，
		   但curl https://ip:443不会报错，而是返回一个换行符 */
		if (strlen(reply) <= 1) {
			if (client_registered && !Heartbeat_fail) {
				MON_ERROR("curl %s error: NULL reply\n", url);
			}
			snprintf(reply, reply_len, "curl %s error: NULL reply", url);

			ret = -1;
		}
	}

	upload_bytes += strlen(post);

	curl_slist_free_all(headerlist);
	curl_easy_cleanup(curl);

	return ret;
}

/* 调试打印post消息 */
void zxprint(char *url, char *post, char *reply)
{
	if (access(DBGFLAG_POST, F_OK) == 0) {
		INFO("url: %s, post: %s, reply: %s\n",
			url   ?   url : "-",
			post  ?  post : "-",
			reply ? reply : "-");
	}
}

/* 设置默认的协议字段 */
void set_default_webproto(void)
{
	char portstr[8] = {0};

	if (Serv_conf.webproto[0] == 'h') {
		return;
	}
	snprintf(portstr, sizeof(portstr), "%d", Serv_conf.port);
	if (strstr(portstr, "443")) {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "https");
	} else {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "http");
	}
}

/*
 * post发送消息方法
 * return <0 failed
 *         0 need regist client again
 *        >0 success
 */
int http_post(char *api_str, char *post, char *reply, int reply_len)
{
	char url[S_LINELEN] = {0};
	int ipv6_url = 0;

	if (localmode) {
		snprintf(reply, reply_len, "success");
		return 0;
	}
	if (!client_registered) {
		snprintf(reply, reply_len, "client not registered");
		return -1;
	}

	if (!api_str || !post || !reply) {
		return -1;
	}

	memset(reply, 0, reply_len);

	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	/* 根据是否是ipv6，拼接url地址 */
	set_default_webproto();
	if (ipv6_url == 1) {
		snprintf(url, sizeof(url), "%s://[%s]:%u/%s/",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(url, sizeof(url), "%s://%s:%u/%s/",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}

	if (http_post_data(url, post, reply, reply_len) < 0) {
		DBG2(DBGFLAG_POST, "post %s to %s fail. reply %s\n", post, url, reply);
		snprintf(reply, reply_len, "http post error");
		return -1;
	}

	/* 400 The plain HTTP request was sent to HTTPS port */
	if (strstr(reply, "HTTPS")) {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "%s", "https");
		if (http_post_data(url, post, reply, reply_len) < 0) {
			DBG2(DBGFLAG_POST, "post %s to %s fail. reply %s\n", post, url, reply);
			snprintf(reply, reply_len, "http post error");
			return -1;
		}
	}
	zxprint(url, post, reply);

	/*
	 * 避免打印太多，如url给错时，或web服务器故障时
	 * 一般的回复不会超过512个字节
	 * 之前当api_str为CONF_URL时，reply[1023] = 0,
	 * 是因为获取配置的返回信息比较长，所以特殊处理
	 * 现在获取配置信息不再通过http_post，改用get_large_data_resp
	 * 因此只要reply[511] = 0就可以了
	 */
#if 0
	if (strcmp(api_str, CONF_URL) == 0) {
		if (1024 < reply_len) {
			reply[1023] = 0;
		}
	} else {
		if (512 < reply_len) {
			reply[511] = 0;
		}
	}
#else
	if (512 < reply_len) {
		reply[511] = 0;
	}

#endif

	/* 针对特殊的几种错误，错误信息内容过长，返回固定报错信息 */
	if (strstr(reply, "502 Bad Gateway")) {
		snprintf(reply, reply_len, "502 Bad Gateway");
		return -1;
	}
	if (strstr(reply, "404 Not Found")) {
		snprintf(reply, reply_len, "404 Not Found");
		return -1;
	}

	/* 重装: {"code":404,"message":"客户端不存在"} */
	if (strstr(reply, "\"code\":404") ||
	    strstr(reply, "\"code\": 404") ||
	    strstr(reply, "客户端不存在") ||
	    strstr(reply, "主机未注册")) {
		/*主机未注册*/
		printf("unregisterd client. %s. %s. %s\n", url, post, reply);
		return 0;
	}

	if (check_resp_key(reply) < 0) {
		return -1;
	}

	return 1;
}

/* 小程序post发送消息，和主程序区分开独立使用 */
int http_assist_post(char *api_str, char *post, char *reply, int reply_len)
{
	char url[S_LINELEN] = {0};
	int ipv6_url = 0;

	if (!api_str || !post || !reply) {
		return -1;
	}

	memset(reply, 0, reply_len);

	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	/* 根据是否是ipv6，拼接url地址 */
	set_default_webproto();
	if (ipv6_url == 1) {
		snprintf(url, sizeof(url), "%s://[%s]:%u/%s/",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(url, sizeof(url), "%s://%s:%u/%s/",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}

	if (http_post_data(url, post, reply, reply_len) < 0) {
		DBG2(DBGFLAG_POST, "post %s to %s fail. reply %s\n", post, url, reply);
		snprintf(reply, reply_len, "http post error");
		return -1;
	}
	/* 400 The plain HTTP request was sent to HTTPS port */
	if (strstr(reply, "HTTPS")) {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "%s", "https");
		if (http_post_data(url, post, reply, reply_len) < 0) {
			DBG2(DBGFLAG_POST, "post %s to %s fail. reply %s\n", post, url, reply);
			snprintf(reply, reply_len, "http post error");
			return -1;
		}
	}

	if (512 < reply_len) {
		reply[511] = 0;
	}

	/* 针对特殊的几种错误，错误信息内容过长，返回固定报错信息 */
	if (strstr(reply, "502 Bad Gateway")) {
		snprintf(reply, reply_len, "502 Bad Gateway");
		return -1;
	}
	if (strstr(reply, "404 Not Found")) {
		snprintf(reply, reply_len, "404 Not Found");
		return -1;
	}
	if (strstr(reply, "\"code\":404") ||
	    strstr(reply, "\"code\": 404") ||
	    strstr(reply, "主机未注册")) {
		/*主机未注册*/
		MON_ERROR("unregisterd client. %s. %s. %s\n", url, post, reply);
		return -1;
	}

	if (check_resp_key(reply) < 0) {
		return -1;
	}

	return 1;
}

/* 上传文件(资产，日志文件) */
int http_upload_file(char *file, char *api_str)
{
	CURL *curl = NULL;
	CURLcode rc = 0;
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;
	char reply[REPLY_MAX] = {0};
	char upload_url[S_LINELEN] = {0};
	int ret = 0;
	time_t event_time = time(NULL);
	char event_time_str[64] = {0};
	int ipv6_url = 0;
	struct stat st = {0};
	struct reply_struct data = { .reply = reply, .reply_len = sizeof(reply) };

	if (!file || !api_str) {
		return -1;
	}

	if (stat(file, &st) < 0) {
		MON_ERROR("upload file %s fail: %s\n", file, strerror(errno));
		return -1;
	}

	set_default_webproto();
	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	/* 根据是否是ipv6，拼接url地址 */
	if (ipv6_url == 1) {
		snprintf(upload_url, sizeof(upload_url), "%s://[%s]:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(upload_url, sizeof(upload_url), "%s://%s:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}

	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("upload file %s fail: curl_easy_init fail\n", file);
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, upload_url);
	/* 资产上传可能比较慢，30s不够，延长超时时间为3分钟 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	/* clear TIME_WAIT */
	//curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

	/* get the reply */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

	/* send all data to this function  */
	headerlist = curl_slist_append(headerlist,"Content-Type: multipart/form-data");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	/* Fill in the file upload field */
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "file",
		     CURLFORM_FILE, file,
		     CURLFORM_END);

	if (strcmp(api_str, DEBUG_LOG_URL) == 0) {
		curl_formadd(&formpost,
			     &lastptr,
			     CURLFORM_COPYNAME, "type",
			     CURLFORM_COPYCONTENTS, logsender, //"1"表示sniper主程序，"2"表示辅助小程序
			     CURLFORM_END);
	}

	/* 主程序的sku用Sys_info.sku， 小程序的sku用sku_info */
	if (strcmp(logsender, "1") == 0) {
		curl_formadd(&formpost,
			     &lastptr,
			     CURLFORM_COPYNAME, "uuid",
			     CURLFORM_COPYCONTENTS, Sys_info.sku,
			     CURLFORM_END);
	} else {
		curl_formadd(&formpost,
			     &lastptr,
			     CURLFORM_COPYNAME, "uuid",
			     CURLFORM_COPYCONTENTS, sku_info,
			     CURLFORM_END);
	}

	if (strcmp(api_str, ASSET_URL) == 0) {
		snprintf(event_time_str, sizeof(event_time_str), "%lu", event_time+serv_timeoff);
		curl_formadd(&formpost,
			     &lastptr,
			     CURLFORM_COPYNAME, "event_time",
			     CURLFORM_COPYCONTENTS, event_time_str,
			     CURLFORM_END);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

	/*todo: SSL support https */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		MON_ERROR("upload file:%s fail: %s\n", file, curl_easy_strerror(rc));

		ret = -1;
		goto out;
	}

	if (strstr(reply, "502 Bad Gateway") != NULL) {
		MON_ERROR("upload file:%s fail: 502 Bad Gateway\n", file);

		ret = -1;
		goto out;
	}

	if (strstr(reply, "500 Internal Server Error") != NULL) {
		MON_ERROR("upload file:%s fail: 500 Internal Server Error\n", file);

		ret = -1;
		goto out;
	}

	if (check_resp_key(reply) < 0) {
		MON_ERROR("upload file:%s, reply failed:%s\n", file, reply);
		ret = -1;
	}

	upload_bytes += st.st_size;

out:
	curl_easy_cleanup(curl);
	curl_formfree(formpost);
	curl_slist_free_all(headerlist);

	return ret;
}

/* 压缩文件 */
static off_t my_zip(char *file, char *gzpath, int gzpath_len)
{
	int len = 0;
	off_t size = 0;
	char *filename = NULL;
	FILE *fp = NULL;
	gzFile gzfp;
	char buf[512] = {0};
	struct stat st = {0};

	if (!file || !gzpath) {
		return 0;
	}

	if (stat(file, &st) < 0) {
		MON_ERROR("my_zip stat %s: %s\n", file, strerror(errno));
		return 0;
	}

	if (st.st_size == 0) {
		unlink(file);
		return 0;
	}

	fp = fopen(file, "rb");
	if (!fp) {
		MON_ERROR("my_zip open %s: %s\n", file, strerror(errno));
		return 0;
	}

	/* 压缩的文件存放在tmp下 */
	filename = safebasename(file);
	snprintf(gzpath, gzpath_len, "/tmp/%s.gz", filename);
	gzfp = gzopen(gzpath, "wb");
	if (!gzfp) {
		fclose(fp);
		return 0;
	}

	while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		size += len;
		gzwrite(gzfp, buf, len);
	}

	if (size != st.st_size) {
		INFO("Warning! %s size %lu, my_zip %lu\n", file, st.st_size, size);
	}

	fclose(fp);
	gzclose(gzfp);

	return st.st_size;
}

/* 上传样本 */
int http_upload_sample(char *file, time_t event_time, char *log_name, char *log_id, char *user, char *md5_input)
{
	CURL *curl = NULL;
	CURLcode rc = 0;
	off_t size = 0;
	int ret = 0, do_upload = 0;
	char *name = NULL;
	struct stat st = {0};
	struct stat st_gz = {0};
	int ipv6_url = 0;
	char *md5 = md5_input, md5_buf[S_MD5LEN] = {0};
	char upload_url[S_LINELEN] = {0};
	char gzpath[PATH_MAX] = {0};
	char reply[REPLY_MAX] = {0};
	char event_time_str[64] = {0};
	char size_str[64] = {0};
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;
	struct reply_struct data = { .reply = reply, .reply_len = sizeof(reply) };

	if (file == NULL) {
		return -1;
	}

	if (stat(file, &st) < 0) {
		MON_ERROR("upload sample %s fail: %s\n", file, strerror(errno));
		return -1;
	}
	size = st.st_size;
	snprintf(size_str, sizeof(size_str), "%lu", size);

	name = safebasename(file);

	set_default_webproto();

	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	/* 根据是否是ipv6，拼接url地址 */
	if (ipv6_url == 1) {
		snprintf(upload_url, sizeof(upload_url), "%s://[%s]:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, SAMPLE_URL);
	} else {
		snprintf(upload_url, sizeof(upload_url), "%s://%s:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, SAMPLE_URL);
	}

	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("upload file %s fail: curl_easy_init fail\n", file);
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, upload_url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	/* clear TIME_WAIT */
	//curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

	/* get the reply */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

	/* send all data to this function  */
	headerlist = curl_slist_append(headerlist,"Content-Type: multipart/form-data");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	/* Fill form field */
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "uuid",
		     CURLFORM_COPYCONTENTS, Sys_info.sku,
		     CURLFORM_END);

	/* 样本时间戳改为毫秒 */
	snprintf(event_time_str, sizeof(event_time_str), "%lu%s", event_time + serv_timeoff, "000");
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "event_time",
		     CURLFORM_COPYCONTENTS, event_time_str,
		     CURLFORM_END);

	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "filename",
		     CURLFORM_COPYCONTENTS, name,
		     CURLFORM_END);

	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "filepath",
		     CURLFORM_COPYCONTENTS, file,
		     CURLFORM_END);

	/* 没有有效的md5，算一个 */
	if (!md5) {
		md5 = md5_buf;
	}
	if (md5[31] == 0 || md5[31] == 'X') {
		md5_file(file, md5);
	}
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "md5",
		     CURLFORM_COPYCONTENTS, md5,
		     CURLFORM_END);

	/* 管控中心若已有该样本，不上传文件 */
	if (!query_sample_exist(file, md5)) {
		if (!my_zip(file, gzpath, sizeof(gzpath))) {
			MON_ERROR("upload sample: zip %s fail\n", file);
			ret = -1;
			goto out;
		}
		curl_formadd(&formpost,
			     &lastptr,
			     CURLFORM_COPYNAME, "file",
			     CURLFORM_FILE, gzpath,
			     CURLFORM_END);

		if (stat(gzpath, &st_gz) < 0) {
			MON_ERROR("upload %s fail: %s\n", gzpath, strerror(errno));
			goto out;
		}
		do_upload = 1;
	}

	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "log_id",
		     CURLFORM_COPYCONTENTS, log_id,
		     CURLFORM_END);

	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "log_name",
		     CURLFORM_COPYCONTENTS, log_name,
		     CURLFORM_END);

	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "user",
		     CURLFORM_COPYCONTENTS, user,
		     CURLFORM_END);

	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "size",
		     CURLFORM_COPYCONTENTS, size_str,
		     CURLFORM_END);

	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

	/*todo: SSL support https */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		MON_ERROR("upload sample:%s fail: %s\n", file, curl_easy_strerror(rc));

		ret = -1;
		goto out;
	}

	if (strstr(reply, "502 Bad Gateway") != NULL) {
		MON_ERROR("upload sample:%s fail: 502 Bad Gateway\n", file);

		ret = -1;
		goto out;
	}

	if (check_resp_key(reply) < 0) {
		MON_ERROR("upload sample:%s, reply failed:%s\n", file, reply);
		ret = -1;
	}

	INFO("upload sample %s success\n", file);
	if (do_upload) {
		upload_bytes += st_gz.st_size;
	}

out:
	/* 不管成功失败，都删除样本临时压缩文件 */
	unlink(gzpath);

	curl_easy_cleanup(curl);
	curl_formfree(formpost);
	curl_slist_free_all(headerlist);

	return ret;
}

/* 上传文件 */
int upload_file(char *file, char *url)
{
	char gzpath[PATH_MAX] = {0};

	/* 压缩文件为gz格式 */
	if (!my_zip(file, gzpath, sizeof(gzpath))) {
		return -1;
	}

	/* 上传压缩文件, 无论失败均删除压缩文件 */
	if (http_upload_file(gzpath, url) < 0) {
		unlink(gzpath);
		return -1;
	}

	unlink(gzpath);

	/* 批量日志上传的，原文件也要删除 */
	if (strcmp(url, LOG_URL) == 0) {
		unlink(file);
	}

	return 0;
}

/* 用curl get方法验证端口是否为http/https服务，url=http(s)://127.0.0.1:port */
static int is_http_service(char *url)
{
	CURL *curl = NULL;
	CURLcode rc = 0;
	struct curl_slist *headerlist = NULL;
	char reply[REPLY_MAX] = {0};
	char *useragent = "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0";
	struct reply_struct data = { .reply = reply, .reply_len = sizeof(reply) };

	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("is_http_service %s fail, init curl fail\n", url);
		return 0;
	}

	/* 以json的格式传输数据 */
	headerlist = curl_slist_append(headerlist,"Content-Type: application/json;charset=UTF-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* CURLOPT_CONNECTTIMEOUT是连接阶段的超时值，CURLOPT_TIMEOUT是整个通信从开始到结束的超时值
	   但也有人说光设CURLOPT_TIMEOUT还是会有延迟和卡顿，故都设上 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);

	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); //支持多线程

	/* 设置一个假的useragent */
	curl_easy_setopt(curl, CURLOPT_USERAGENT, useragent);

	/* clear CLOSE_WAIT state */
	curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

#if LIBCURL_VERSION_NUM > 0x070f05
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_cb);
#endif

	/* 不验证ssl证书 */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(curl);

	curl_slist_free_all(headerlist);
	curl_easy_cleanup(curl);

	if (rc != CURLE_OK && rc != CURLE_WRITE_ERROR) {
		DBG2(DBGFLAG_POST, "curl %s error(%d): %s. not http/https\n",
			url, rc, curl_easy_strerror(rc));
		return 0;
	}

	if (strlen(reply) <= 1) {
		DBG2(DBGFLAG_POST, "curl %s error: NULL reply. not http/https\n", url);
		return 0;
	}

	return 1;
}

int check_http_port(int port)
{
	char url[128] = {0};

	snprintf(url, sizeof(url), "http://127.0.0.1:%d", port);
	if (is_http_service(url)) {
		DBG2(DBGFLAG_POST, "port %d is http service\n", port);
		return 1;
	}

	snprintf(url, sizeof(url), "https://127.0.0.1:%d", port);
	if (is_http_service(url)) {
		DBG2(DBGFLAG_POST, "port %d is https service\n", port);
		return 1;
	}

	return 0;
}

int http_get_data(char *url, char *reply, int reply_len)
{
	int ret = 0;
	CURLcode rc = 0;
	CURL *curl = NULL;
	struct reply_struct data = { .reply = reply, .reply_len = reply_len };

	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("init get curl failed!\n");
		snprintf(reply, reply_len, "curl_easy_init fail");
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT");

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_easy_setopt(curl, CURLOPT_HEADER, 0);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		MON_ERROR("curl get %s error(%d): %s\n", url, rc, curl_easy_strerror(rc));
		snprintf(reply, reply_len, "curl %s error: %s", url, curl_easy_strerror(rc));

		ret = -1;
	}

	curl_easy_cleanup(curl);

	return ret;
}

/* get方式获取数据 */
int http_get(char *api_str, char *get_data, char *reply, int reply_len)
{
	char url[S_LINELEN] = {0};
	int ipv6_url = 0, len = 0;
	char *ptr = NULL;
	int ptr_len = 0;

	if (!api_str || !get_data || !reply) {
		return -1;
	}

	if (localmode) {
		snprintf(reply, reply_len, "success");
		return 0;
	}

	/* api/client/test用于检测与管控的服务端口是否可连通 */
	if (!client_registered && strcmp(api_str, "api/client/test") != 0) {
		snprintf(reply, reply_len, "client not registered");
		return -1;
	}

	memset(reply, 0, reply_len);

	set_default_webproto();
	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	/* 根据是否是ipv6，拼接url地址 */
	if (ipv6_url == 1) {
		snprintf(url, sizeof(url), "%s://[%s]:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(url, sizeof(url), "%s://%s:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}

	/* get方式后面需要拼接参数 */
	if (*get_data != 0) {
		len = strlen(url);
		ptr = url+len;
		ptr_len = sizeof(url)-len;
		snprintf(ptr, ptr_len, "?%s", get_data);
	}

	if (http_get_data(url, reply, reply_len) < 0) {
		DBG2(DBGFLAG_POST, "get %s fail. reply %s\n", url, reply);
		snprintf(reply, reply_len, "http get error");
		return -1;
	}
	zxprint(url, get_data, reply);

	if (check_resp_key(reply) < 0) {
		return -1;
	}

	return 0;
}

struct _update_ctx{
	char *data;
	char *pos;
	char *last;
} update_ctx;

/* 读取put方式更新数据后的返回的内容 */
size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
	struct _update_ctx *ctx = (struct _update_ctx *)stream;
	size_t len = 0;

	if (ctx->pos >= ctx->last) {
		return 0;
	}

	if (size == 0 || nmemb == 0 || ((size * nmemb) < 1)) {
		return 0;
	}

	len = ctx->last - ctx->pos;
	if (len > size * nmemb) {
		len = size * nmemb;
	}

	memcpy(ptr, ctx->pos, len);
	ctx->pos += len;

	return len;
}

int http_put_data(char *url, char *put_data, char *reply, int reply_len)
{
	int ret = 0;
	CURLcode rc = 0;
	CURL *curl = NULL;
	struct curl_slist *headerlist = NULL;
	struct _update_ctx *info = NULL;
	struct reply_struct data = { .reply = reply, .reply_len = reply_len };

	if (!url || !put_data || !reply) {
		return -1;
	}

	info = (struct _update_ctx *)malloc(sizeof(struct _update_ctx));
	if (info == NULL) {
		MON_ERROR("malloc put info failed!\n");
		return -1;
	}

	info->data = put_data;
	info->pos = put_data;
	info->last = info->pos + strlen(put_data);

	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("init put curl failed!\n");
		snprintf(reply, reply_len, "curl_easy_init fail");
		free(info);
		return -1;
	}

	/* 以json的格式传输数据 */
	headerlist = curl_slist_append(headerlist,"Content-Type: application/json;charset=UTF-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L) ;
	curl_easy_setopt(curl, CURLOPT_PUT, 1L);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	//set USERAGENT
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT");

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_easy_setopt(curl, CURLOPT_READDATA, info);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)(info->last - info->pos));
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		MON_ERROR("curl put %s error(%d): %s\n", url, rc, curl_easy_strerror(rc));
		snprintf(reply, reply_len, "curl %s error: %s", url, curl_easy_strerror(rc));
		ret = -1;
	}

	curl_easy_cleanup(curl);
	free(info);
	return ret;
}

/* put方式更新数据 */
int http_put(char *api_str, char *put_data, char *reply, int reply_len)
{
	char url[S_LINELEN] = {0};
	int ipv6_url = 0;

	if (!api_str || !put_data || !reply) {
		return -1;
	}

	if (localmode) {
		snprintf(reply, reply_len, "success");
		return 0;
	}

	if (!client_registered) {
		snprintf(reply, reply_len, "client not registered");
		return -1;
	}

	memset(reply, 0, reply_len);

	set_default_webproto();
	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	/* 根据是否是ipv6，拼接url地址 */
	if (ipv6_url == 1) {
		snprintf(url, sizeof(url), "%s://[%s]:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(url, sizeof(url), "%s://%s:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}

	if (http_put_data(url, put_data, reply, reply_len) < 0) {
		DBG2(DBGFLAG_POST, "put %s fail. reply %s\n", url, reply);
		snprintf(reply, reply_len, "http put error");
		return -1;
	}

	/* 400 The plain HTTP request was sent to HTTPS port */
	if (strstr(reply, "HTTPS")) {
		snprintf(Serv_conf.webproto, sizeof(Serv_conf.webproto), "%s", "https");
		if (http_put_data(url, put_data, reply, reply_len) < 0) {
			DBG2(DBGFLAG_POST, "put %s to %s fail. reply %s\n", put_data, url, reply);
			snprintf(reply, reply_len, "http put error");
			return -1;
		}
	}

	if (check_resp_key(reply) < 0) {
		return -1;
	}

	return 0;
}

/* 查询管控中心是否已有该样本，有则不用重复上传 */
int query_sample_exist(char *file, char *md5_input)
{
	int ret = 0;
	char query_str[S_LINELEN] = {0}, reply[REPLY_MAX] = {0};
	char *md5 = md5_input, md5_buf[S_MD5LEN] = {0};
	cJSON *object = NULL, *data = NULL, *exists = NULL;

	if (!file) {
		return 0;
	}
	/* 没有有效的md5，算一个 */
	if (!md5_input) {
		md5 = md5_buf;
	}
	if (md5[31] == 0 || md5[31] == 'X') {
		md5_file(file, md5);
	}

	snprintf(query_str, sizeof(query_str), "md5=%s", md5);
	ret = http_get(QUERY_URL, query_str, reply, sizeof(reply));

	if (ret < 0) {
		MON_ERROR("query sample %s(md5 %s) fail\n", file, md5);
		return 0;
	}

	/* 解析查询结果：{"msg":"...","data":{"exists":1},"code":nnn} */
	object = cJSON_Parse(reply);
	if (object == NULL) {
		MON_ERROR("query sample %s(md5 %s): parse reply %s fail: %s\n",
			file, md5, reply, cJSON_GetErrorPtr());
		return 0;
	}

	data = cJSON_GetObjectItem(object, "data");
	if (data == NULL) {
		MON_ERROR("query sample %s(md5 %s): parse reply %s fail: %s\n",
			file, md5, reply, cJSON_GetErrorPtr());
		cJSON_Delete(object);
		return 0;
	}

	/* exists的值为1时表示该样本在管控中已经存在 */
	exists = cJSON_GetObjectItem(data, "exists");
	if (exists == NULL) {
		MON_ERROR("query sample %s(md5 %s): parse reply %s fail: %s\n",
			file, md5, reply, cJSON_GetErrorPtr());
		cJSON_Delete(object);
		return 0;
	}

	if (exists->valueint != 1) {
		INFO("sample %s(md5 %s) not exists on server\n", file, md5);
		DBG2(DBGFLAG_POST, "query sample %s(md5 %s) on server, not exists: %s\n",
			file, md5, reply);
		cJSON_Delete(object);
		return 0;
	}

	//INFO("sample %s(md5 %s) exists on server\n", file, md5);
	cJSON_Delete(object);
	return 1;
}
