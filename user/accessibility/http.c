#include <zlib.h>
#include "header.h"

unsigned long upload_bytes = 0;

/* 解析上传文件的返回数据 */
int parse_upload_resp(char *string){
	cJSON *json, *code;
	int ret = 0;

	if(string == NULL) {
		return -1;
	}

	json = cJSON_Parse(string);
	if (!json) {
		MON_ERROR("parse upload reply fail: %s\n", cJSON_GetErrorPtr());
		return -1;
	}

	code = cJSON_GetObjectItem(json, "code");
	if (!code) {
		MON_ERROR("regist upload get code error: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(json);
		return -1;
	}

	if (code->valueint == 0) {
		ret = 0;
	} else {
		ret = -1;
	}

	cJSON_Delete(json);
	return ret;	
}

void set_default_webproto(void)
{
	char portstr[8] = {0};

	if (Serv_conf.webproto[0] == 'h') {
		return;
	}
	snprintf(portstr, 8, "%d", Serv_conf.port);
	if (strstr(portstr, "443")) {
		strncpy(Serv_conf.webproto, "https", S_PROTOLEN-1);
	} else {
		strncpy(Serv_conf.webproto, "http", S_PROTOLEN-1);
	}
}

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

/*
 * reply data callback
 */
static size_t get_reply(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	char *buf = (char *)userp;

	if (realsize >= REPLY_MAX) {
		realsize = REPLY_MAX - 1;
	}
	memcpy(buf, contents, realsize);
	return realsize;
}

/*
 * post post_data to a url and store reply data to reply_data
 * return 0 if success, -1 if failed.
 */
int http_post_data(char *url, char *post_data, char *reply_data)
{
	int ret = 0;
	CURL *curl = NULL;
	CURLcode res = 0;
	struct curl_slist *headerlist = NULL;

	curl = curl_easy_init();
	if (!curl) {
		MON_ERROR("init post curl failed!\n");
		strncpy(reply_data, "curl_easy_init fail", REPLY_MAX);
		return -1;
	}

	//DBG("url: %s (%ld)\n", url,strlen(post_data));
	//DBG("post_data: %s\n", post_data);

	/* 以json的格式传输数据 */
	headerlist = curl_slist_append(headerlist,"Content-Type: application/json;charset=UTF-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	//printf("http_post url:%s, post:%s\n", url, post);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	//set USERAGENT
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT");

	//clear CLOSE_WAIT state
	curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L); 

	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_data));
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)reply_data);

#if LIBCURL_VERSION_NUM > 0x070f05
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_cb);
#endif

	/*todo: SSL support https */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		MON_ERROR("curl %s error(%d): %s. %s\n",
			url, res, curl_easy_strerror(res),
			res == CURLE_COULDNT_CONNECT ? "" : post_data);
		snprintf(reply_data, REPLY_MAX, "curl %s error: %s",
			url, curl_easy_strerror(res));

		ret = -1;
	} else {
//		printf("http_post reply_data:%s\n", reply_data);
		/* 与管控中心不通时，curl http://ip:8000会报错，
		   但curl https://ip:443不会报错，而是返回一个换行符 */
		if (strlen(reply_data) <= 1) {
			MON_ERROR("curl %s error: NULL reply\n", url);
			snprintf(reply_data, REPLY_MAX, "curl %s error: NULL reply", url);

			ret = -1;
		}
	}

	upload_bytes += strlen(post_data);

	curl_slist_free_all(headerlist);
	curl_easy_cleanup(curl);

	return ret;
}

int http_post(char *api_str, char *post_data, char *reply_data)
{
	char url[S_LINELEN] = {0};
	int ipv6_url = 0;

	memset(reply_data, 0, REPLY_MAX);

	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	set_default_webproto();
	if (ipv6_url == 1) {
		snprintf(url, S_LINELEN, "%s://[%s]:%u/%s/",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(url, S_LINELEN, "%s://%s:%u/%s/",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}
		
	if (http_post_data(url, post_data, reply_data) < 0) {
		DBG2(DBGFLAG_POST, "post %s to %s fail. reply %s\n", post_data, url, reply_data);
		strcpy(reply_data, "http post error");
		return -1;
	}
	/* 400 The plain HTTP request was sent to HTTPS port */
	if (strstr(reply_data, "HTTPS")) {
		strncpy(Serv_conf.webproto, "https", S_PROTOLEN-1);
		if (http_post_data(url, post_data, reply_data) < 0) {
			DBG2(DBGFLAG_POST, "post %s to %s fail. reply %s\n", post_data, url, reply_data);
			strcpy(reply_data, "http post error");
			return -1;
		}
	}

	reply_data[511] = 0;

	if (strstr(reply_data, "502 Bad Gateway")) {
		strcpy(reply_data, "502 Bad Gateway");
		return 0;
        }
	if (strstr(reply_data, "404 Not Found")) {
		strcpy(reply_data, "404 Not Found");
		return 0;
        }
	if (strstr(reply_data, "\"code\":404") ||
	    strstr(reply_data, "\"code\": 404") ||
            strstr(reply_data, "主机未注册")) {
		/*主机未注册*/
		MON_ERROR("unregisterd client. %s. %s. %s\n", url, post_data, reply_data);
		return 0;
	}

	return 1;
}

/* 上传文件 */
int http_upload_file(char *file, char *api_str)
{
        CURL *curl;
        CURLcode res;
	struct curl_httppost *formpost = NULL;  
	struct curl_httppost *lastptr = NULL;  
	struct curl_slist *headerlist = NULL;  
	char reply_data[REPLY_MAX] = {0};
        char upload_url[S_LINELEN] = {0};
        int ret = 0;
	int ipv6_url = 0;
	struct stat st = {0};

	if (file == NULL) {
		return -1;
	}

	if (stat(file, &st) < 0) {
		MON_ERROR("upload file %s fail: %s\n", file, strerror(errno));
                return -1;
        }
	
//	DBG("---upload file:%s---\n",file);

	set_default_webproto();
	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	if (ipv6_url == 1) {
		snprintf(upload_url, S_LINELEN, "%s://[%s]:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(upload_url, S_LINELEN, "%s://%s:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}
//	DBG("---upload file URL:%s---\n",upload_url);
	
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
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)reply_data);

        /* send all data to this function  */
	headerlist = curl_slist_append(headerlist,"Content-Type: multipart/form-data");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	/* Fill in the file upload field */  
	curl_formadd(&formpost,  
			&lastptr,  
			CURLFORM_COPYNAME, "file",  
			CURLFORM_FILE, file,  
			CURLFORM_END);  

	curl_formadd(&formpost,  
			&lastptr,  
			CURLFORM_COPYNAME, "uuid",  
			CURLFORM_COPYCONTENTS, sku_info,  
			CURLFORM_END);  

	if (strcmp(api_str, DEBUG_LOG_URL) == 0) {
		curl_formadd(&formpost,  
				&lastptr,  
				CURLFORM_COPYNAME, "type",  
				CURLFORM_COPYCONTENTS, ASSIST_TYPE,  
				CURLFORM_END);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);  

	/*todo: SSL support https */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
		MON_ERROR("upload file:%s fail: %s\n",
			  file, curl_easy_strerror(res));

		ret = -1;
		goto out;
        }

	if (strstr(reply_data, "502 Bad Gateway") != NULL) {
		MON_ERROR("upload file:%s fail: %s\n",
			  file, "502 Bad Gateway");

		ret = -1;
		goto out;
	}

	if (strstr(reply_data, "500 Internal Server Error") != NULL) {
		MON_ERROR("upload file:%s fail: %s\n",
			  file, "500 Internal Server Error");

		ret = -1;
		goto out;
	}

	if (parse_upload_resp(reply_data) != 0) {
		MON_ERROR("upload file:%s, reply failed:%s\n", file, reply_data);
		ret = -1;
	}

	upload_bytes += st.st_size;
	//printf("upload bytes%lu\n", upload_bytes);
out:
        curl_easy_cleanup(curl);
	curl_formfree(formpost);  
	curl_slist_free_all(headerlist);  

        return ret;
}

int upload_file(char *filepath, char* url)
{
	char gz_path[S_SHORTPATHLEN] = {0};
	if (!my_zip(filepath, gz_path)) {
		return -1;
	}

	printf("Starting upload the log information....\n");
	if (http_upload_file(gz_path, url) < 0) {
		unlink(gz_path);
		return -1;
	}

	unlink(gz_path);

	return 0;
}

