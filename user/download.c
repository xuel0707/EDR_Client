/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* curl */
#include <curl/curl.h>

/* our header */
#include "header.h"

/*
 * write downloaded data.
 * memory is allocated here, so caller needs to free it.
 */
static size_t write_data(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	int write_size = 0;
	buffer_t *buf = (buffer_t *)userp;

	if (buf->pos + realsize > buf->len)
		write_size = buf->len - buf->pos;
	else
		write_size = realsize;

	memcpy(buf->data+buf->pos, contents, write_size);
	buf->pos += write_size;
	return write_size;
}

/*
 * given a url, download it to buffer.
 * return 0 if success, -1 if failed.
 */
int download(buffer_t *buffer)
{
	CURL *curl = NULL;
	CURLcode res = 0;
	char down_url[S_LINELEN]={0};
	int ipv6_url = 0;
	
	curl = curl_easy_init();
	if(!curl) {
		MON_ERROR("init download curl failed!\n");
		return -1;
	}

	if (Serv_conf.webproto[0] != 'h') {
		char portstr[8] = {0};
		snprintf(portstr, 8, "%d", Serv_conf.port);
		if (strstr(portstr, "443")) {
			strncpy(Serv_conf.webproto, "https", S_PROTOLEN-1);
		} else {
			strncpy(Serv_conf.webproto, "http", S_PROTOLEN-1);
		}
	}

	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	if (ipv6_url == 1) {
		snprintf(down_url, S_LINELEN, "%s://[%s]:%u/%s/%s.lst",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, DOWNLOAD_URL, Sys_info.sku);
	} else {
		snprintf(down_url, S_LINELEN, "%s://%s:%u/%s/%s.lst",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, DOWNLOAD_URL, Sys_info.sku);
	}

	DBG2(DBGFLAG_POST, "download url: %s(len:%ld)\n", down_url,strlen(down_url));

	// set URL
	curl_easy_setopt(curl, CURLOPT_URL, down_url);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	
	// set agent
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT");

	// clear TIME_WAIT
	curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L); 	

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)buffer);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

	/* SSL support https */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	res = curl_easy_perform(curl);
	if (res == CURLE_OK) {
		curl_easy_cleanup(curl);
		return 0;
	}

	if (!Heartbeat_fail) {
		MON_ERROR("download %s fail: %s\n",
			down_url, curl_easy_strerror(res));
	}

	if (strstr(buffer->data, "404 Not Found")) {
		MON_ERROR("download %s fail: 404\n", down_url);
	}

	curl_easy_cleanup(curl);
	return -1;
}

int get_large_data_resp(char *api_str, char *post, buffer_t *buffer)
{
	CURL *curl = NULL;
	CURLcode res = 0;
	char url[S_LINELEN]={0};
	struct curl_slist *headerlist = NULL;
	int ipv6_url = 0;

	if (api_str == NULL ||
	    post == NULL ||
	    buffer == NULL ||
	    buffer->data == NULL) {
		return -1;
	}

	curl = curl_easy_init();
	if(!curl) {
		MON_ERROR("init get_large_data_resp curl failed!\n");
		return -1;
	}

	if (Serv_conf.webproto[0] != 'h') {
		char portstr[8] = {0};
		snprintf(portstr, 8, "%d", Serv_conf.port);
		if (strstr(portstr, "443")) {
			strncpy(Serv_conf.webproto, "https", S_PROTOLEN-1);
		} else {
			strncpy(Serv_conf.webproto, "http", S_PROTOLEN-1);
		}
	}
	if (strchr(Serv_conf.ip, ':') != NULL) {
		ipv6_url = 1;
	}

	if (ipv6_url == 1) {
		snprintf(url, S_LINELEN, "%s://[%s]:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	} else {
		snprintf(url, S_LINELEN, "%s://%s:%u/%s",
			Serv_conf.webproto, Serv_conf.ip, Serv_conf.port, api_str);
	}

//	printf("get_large_data_resp url: %s(len:%ld)\n", url,strlen(url));

	// set URL
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	
	// set agent
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT");

	// clear TIME_WAIT
	curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L); 	

	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)buffer);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

	headerlist = curl_slist_append(headerlist,"Content-Type: application/json;charset=UTF-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

	/* SSL support https */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	res = curl_easy_perform(curl);
	if (res == CURLE_OK) {
		curl_easy_cleanup(curl);
		curl_slist_free_all(headerlist);
		return 0;
	}

	if (!Heartbeat_fail) {
		MON_ERROR("get_large_data_resp %s fail: %s\n",
			url, curl_easy_strerror(res));
	}

	if (strstr(buffer->data, "404 Not Found")) {
		MON_ERROR("get_large_data_resp %s fail: 404\n", url);
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(headerlist);
	return -1;
}
