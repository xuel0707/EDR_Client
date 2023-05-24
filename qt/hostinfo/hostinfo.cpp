#include "hostinfo.h"
#include "cJSON.h"
#include <QApplication>
#include <QMessageBox>
#include <stdio.h>
#include <errno.h>
#include <curl/curl.h>
#include "../language.h"

#define POST_MAX        4096
#define REPLY_MAX       1024
#define S_PROTOLEN	16

#define WORKDIR     "/opt/snipercli"
#define SKUFILE     "/etc/sniper-sku"

const char *hostinfor_str[2] = { "主机信息", "Host information" };
const char *username_str[2] = { "姓名:", "Username:" };
const char *phone_str[2] = { "电话:", "Phone:" };
const char *depart_str[2] = { "部门:", "Department:" };
const char *company_str[2] = { "单位:", "Company:" };
const char *email_str[2] = { "邮箱:", "Email:" };
const char *assets_number_str[2] = { "资产编号:", "Assets_number:" };
const char *location_str[2] = { "机房位置:", "Location:" };
const char *remark_str[2] = { "备注:", "Remarks:" };
const char *send_str[2] = { "上报", "Send" };
const char *cancel_str[2] = { "取消", "Cancel" };
const char *error_str[2] = { "错误", "Error" };
const char *pointout_str[2] = { "提示", "Information" };
const char *sendfail_str[2] = { "上报主机信息失败", "Failed to send host information" };
const char *sendsuccess_str[2] = { "上报主机信息成功", "Send host information successfully" };
const char *outmemory_str[2] = { "上报主机信息失败:\n内存不足", "Failed to send host information:\nOut of memory " };
const char *getidfail_str[2] = { "上报主机信息失败:\n获取本地唯一标识失败", "Failed to send host information:\nFailed to get host uuid" };
const char *resolvefail_str[2] = { "上报主机信息失败:\n解析服务器地址失败", "Failed to send host information:\nFailed to resolve server address" };
const char *invaildinfor_str[2] = { "上报主机信息失败:\n无效参数", "Failed to send host information:\nInvalid argument" };
const char *cjsonfail_str[2] = { "上报主机信息失败:\n拼接json数据失败", "Failed to send host information:\nFailed create cJSON Object" };


char sku[S_UUIDLEN+1] = {0};
char serv_ip[64] = {0}; //S_IPLEN
unsigned int serv_port = 0;
char serv_webproto[S_PROTOLEN] = {0};

int get_sku(void)
{
	FILE *fp = NULL;

	fp = fopen(SKUFILE, "r");
	if (!fp) {
		printf("open %s fail: %s\n", SKUFILE, strerror(errno));
		return -1;
	}

	/* 下面的fgets最多S_UUIDLEN，最后填0 */
	if (!fgets(sku, sizeof(sku), fp)) {
		printf("read %s fail: %s\n", SKUFILE, strerror(errno));
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

int get_server_ip(void)
{
        FILE *fp = NULL;
        int ret = 0;
	char buf[S_LINELEN] = {0};

        fp = fopen(SNIPER_CONF, "r");
	if (!fp) {
		printf("open %s fail: %s\n", SNIPER_CONF, strerror(errno));
		return -1;
	}

        while (fgets(buf, sizeof(buf), fp)) {
                if (buf[0] < '0' || buf[0] > '9') {
                        continue;
                }
                fclose(fp);

		ret = sscanf(buf, "%63[^:]:%u", serv_ip, &serv_port);
		if (ret == 2) {
                	return 0;
		}
		printf("bad server config in %s\n", SNIPER_CONF);
                return -1;
        }

        fclose(fp);
	printf("bad server config in %s\n", SNIPER_CONF);
        return -1;
}

static size_t get_reply(void *contents, size_t size, size_t nmemb, void *userp)
{
        size_t realsize = size * nmemb;
        char *buf = (char *)userp;
        memcpy(buf, contents, realsize > REPLY_MAX ? REPLY_MAX : realsize);

        return realsize;
}

static int http_post(const char *api_str, char *post, char *reply)
{
        CURL *curl = NULL;
        CURLcode res;
        char url[S_LINELEN]={0};
	struct curl_slist *headerlist = NULL;
	int ipv6_url = 0;

        memset(reply, 0, REPLY_MAX);

	if (strchr(serv_ip, ':') != NULL) {
		ipv6_url = 1;
	}

	if (ipv6_url == 1) {
		snprintf(url, sizeof(url), "%s://[%s]:%u/%s/",
			serv_webproto, serv_ip, serv_port, api_str);
	} else {
		snprintf(url, sizeof(url), "%s://%s:%u/%s/",
			serv_webproto, serv_ip, serv_port, api_str);
	}
        curl = curl_easy_init();
        if (!curl) {
                printf("init post curl fail\n");
                return -1;
        }

	/* 以json的格式传输数据 */
	headerlist = curl_slist_append(headerlist,"Content-Type: application/json;charset=UTF-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

        curl_easy_setopt(curl, CURLOPT_USERAGENT, "ANTIAPT");
        curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_reply);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)reply);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        res = curl_easy_perform(curl);
        curl_slist_free_all(headerlist);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK) {
                printf("curl fail: %s\n", curl_easy_strerror(res));
		return -1;
        }

        return 0;
}

/* Converts an integer value to its hex character*/
static char to_hex(char code) {
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str)
{
	char *pstr = str;
	char *buf = NULL, *pbuf = NULL;

	buf = (char *)malloc(strlen(str) * 3 + 1);
	if (!buf) {
		return NULL;
	}
	pbuf = buf;

	while (*pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
			*pbuf++ = *pstr;
		else if (*pstr == ' ')
			*pbuf++ = '+';
		else
			*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
		pstr++;
	}
	*pbuf = '\0';
	return buf;
}

static int send_hostinfo(QLineEdit *usernameLineEdit,
			 QLineEdit *phoneLineEdit,
			 QLineEdit *departmentLineEdit,
			 QLineEdit *companyLineEdit,
			 QLineEdit *emailLineEdit,
			 QLineEdit *assets_numberLineEdit,
			 QLineEdit *locationLineEdit)
{
        char reply[REPLY_MAX] = {0}, portstr[8] = {0};
	char *post = NULL, *datastr = NULL;
	cJSON *object = NULL, *data = NULL;

	if (get_sku() < 0) {
		return -1;
	}

	if (get_server_ip() < 0) {
		//TODO
		if (errno == ENOENT) {
			return 0;
		}
		return -2;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return -4;
	}

	data = cJSON_CreateObject();
	if (data == NULL) {
		cJSON_Delete(object);
		return -4;
	}

	cJSON_AddStringToObject(object, "uuid", sku);

	cJSON_AddStringToObject(data, "name", usernameLineEdit->text().toUtf8().data());
	cJSON_AddStringToObject(data, "phone", phoneLineEdit->text().toUtf8().data());
	cJSON_AddStringToObject(data, "department", departmentLineEdit->text().toUtf8().data());
	cJSON_AddStringToObject(data, "company", companyLineEdit->text().toUtf8().data());
	cJSON_AddStringToObject(data, "email", emailLineEdit->text().toUtf8().data());
	cJSON_AddStringToObject(data, "assets_number", assets_numberLineEdit->text().toUtf8().data());
	cJSON_AddStringToObject(data, "location", locationLineEdit->text().toUtf8().data());

	datastr = cJSON_PrintUnformatted(data);
	cJSON_Delete(data);

	cJSON_AddItemToObject(object, "data", cJSON_CreateString(datastr));
	free(datastr);
	post = cJSON_PrintUnformatted(object);
	printf("post %s\n", post);

	curl_global_init(CURL_GLOBAL_ALL);

	snprintf(portstr, sizeof(portstr), "%d", serv_port);
	if (strstr(portstr, "443")) {
		snprintf(serv_webproto, sizeof(serv_webproto), "https");
	} else {
		snprintf(serv_webproto, sizeof(serv_webproto), "http");
	}
        if (http_post("api/client/asset/reg", post, reply) < 0) {
		if (!strstr(reply, "HTTPS")) {
			curl_global_cleanup();
			cJSON_Delete(object);
			free(post);
			return -5;
		}

		/* http失败，服务器端提示https协议，重试 */
		snprintf(serv_webproto, sizeof(serv_webproto), "https");
        	if (http_post("api/client/asset/reg", post, reply) < 0) {
			curl_global_cleanup();
			cJSON_Delete(object);
			free(post);
			return -5;
		}
	}
	curl_global_cleanup();

	cJSON_Delete(object);
	free(post);

	printf("reply: %s\n", reply);

	if (strstr(reply, "\"code\":0")) {
        	return 0;
	}
	return -6;
}

int init_line_text(char *buf, const char *headstr, QLineEdit *line)
{
	int headlen = 0, len = 0;

	if (!buf || !headstr || !line) {
		return 0;
	}

	headlen = strlen(headstr);
	if (strncmp(buf, headstr, headlen) != 0) {
		return 0;
	}

	len = strlen(buf);
	if (buf[len-1] == '\n') {
		buf[len-1] = 0;
	}
	line->setText(QString::fromUtf8(buf+headlen));

	return 1;
}

HostInfo::HostInfo(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{
	lang = get_language();

	setWindowTitle(QString::fromUtf8(hostinfor_str[lang]));
	setWindowIcon(QIcon("/opt/snipercli/sniper.png"));

	usernameLabel = new QLabel(QString::fromUtf8(username_str[lang]));
	usernameLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	usernameLineEdit = new QLineEdit;
	phoneLabel = new QLabel(QString::fromUtf8(phone_str[lang]));
	phoneLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	phoneLineEdit = new QLineEdit;
	departmentLabel = new QLabel(QString::fromUtf8(depart_str[lang]));
	departmentLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	departmentLineEdit = new QLineEdit;
	companyLabel = new QLabel(QString::fromUtf8(company_str[lang]));
	companyLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	companyLineEdit = new QLineEdit;
	emailLabel = new QLabel(QString::fromUtf8(email_str[lang]));
	emailLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	emailLineEdit = new QLineEdit;
	assets_numberLabel = new QLabel(QString::fromUtf8(assets_number_str[lang]));
	assets_numberLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	assets_numberLineEdit = new QLineEdit;
	locationLabel = new QLabel(QString::fromUtf8(location_str[lang]));
	locationLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	locationLineEdit = new QLineEdit;
	sendBtn = new QPushButton(QString::fromUtf8(send_str[lang]));
	cancelBtn = new QPushButton(QString::fromUtf8(cancel_str[lang]));

	/* 两个按钮的布局 */
	btnLayout = new QHBoxLayout();
	/* 在两个按钮前插入一个占位符，使两个按钮能靠右对齐 */
	btnLayout->addStretch();
	btnLayout->addWidget(sendBtn);
	btnLayout->addWidget(cancelBtn);

	infoLayout = new QGridLayout();
	infoLayout->addWidget(usernameLabel, 0, 0);
	infoLayout->addWidget(usernameLineEdit, 0, 1);
	infoLayout->addWidget(phoneLabel, 1, 0);
	infoLayout->addWidget(phoneLineEdit, 1, 1);
	infoLayout->addWidget(departmentLabel, 2, 0);
	infoLayout->addWidget(departmentLineEdit, 2, 1);
	infoLayout->addWidget(companyLabel, 3, 0);
	infoLayout->addWidget(companyLineEdit, 3, 1);
	infoLayout->addWidget(emailLabel, 4, 0);
	infoLayout->addWidget(emailLineEdit, 4, 1);
	infoLayout->addWidget(assets_numberLabel, 5, 0);
	infoLayout->addWidget(assets_numberLineEdit, 5, 1);
	infoLayout->addWidget(locationLabel, 6, 0);
	infoLayout->addWidget(locationLineEdit, 6, 1);

	/* 为了使第1列输入列比第0列标签栏宽，设置第1列的最小宽度。
	   试了其他方法不管用，比如通过addWidget设置对象占用的列数 */
	infoLayout->setColumnMinimumWidth(1, 200);

	/* 设置两列的宽度拉伸比例是1:10，使得实际拉伸窗口时，第0列不变，第1列变宽 */
	infoLayout->setColumnStretch(0, 1);
	infoLayout->setColumnStretch(1, 10);

	mainLayout = new QVBoxLayout(this);
	mainLayout->addLayout(infoLayout);
	mainLayout->addLayout(btnLayout);

	/* 允许改变窗口的大小 */
	//mainLayout->setSizeConstraint(QLayout::SetFixedSize);

	connect(sendBtn, SIGNAL(clicked()), this, SLOT(slotSend()));
	connect(cancelBtn, SIGNAL(clicked()), qApp, SLOT(quit()));

	FILE *fp = NULL;
	char buf[S_LINELEN];

	fp = fopen("/opt/snipercli/.nodeinfo", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (init_line_text(buf, "username=", usernameLineEdit)) {
				continue;
			}
			if (init_line_text(buf, "phone=", phoneLineEdit)) {
				continue;
			}
			if (init_line_text(buf, "department=", departmentLineEdit)) {
				continue;
			}
			if (init_line_text(buf, "company=", companyLineEdit)) {
				continue;
			}
			if (init_line_text(buf, "email=", emailLineEdit)) {
				continue;
			}
			if (init_line_text(buf, "assets_number=", assets_numberLineEdit)) {
				continue;
			}
			if (init_line_text(buf, "location=", locationLineEdit)) {
				continue;
			}
		}
		fclose(fp);
	}
}

void HostInfo::slotSend()
{
	FILE *fp = NULL;
	int ret = 0;

	ret = send_hostinfo(usernameLineEdit,
			  phoneLineEdit,
			  departmentLineEdit,
			  companyLineEdit,
			  emailLineEdit,
			  assets_numberLineEdit,
			  locationLineEdit);
	if (ret < 0) {
		if (ret == -1) {
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
				QString::fromUtf8(getidfail_str[lang]));
		} else if (ret == -2) {
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
				QString::fromUtf8(resolvefail_str[lang]));
		} else if (ret == -3) {
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
				QString::fromUtf8(outmemory_str[lang]));
		} else if (ret == -4) {
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
				QString::fromUtf8(cjsonfail_str[lang]));
		} else if (ret == -5) {
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
				QString::fromUtf8(sendfail_str[lang]));
		} else if (ret == -6) {
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
				QString::fromUtf8(invaildinfor_str[lang]));
		} else {
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
				QString::fromUtf8(sendfail_str[lang]));
		}
		return;
	}

	fp = fopen("/opt/snipercli/.nodeinfo", "w");
	if (fp) {
		fprintf(fp, "username=%s\nphone=%s\ndepartment=%s\ncompany=%s\n"
			"email=%s\nassets_number=%s\nlocation=%s",
			usernameLineEdit->text().toUtf8().data(),
			phoneLineEdit->text().toUtf8().data(),
			departmentLineEdit->text().toUtf8().data(),
			companyLineEdit->text().toUtf8().data(),
			emailLineEdit->text().toUtf8().data(),
			assets_numberLineEdit->text().toUtf8().data(),
			locationLineEdit->text().toUtf8().data());
		fclose(fp);
	}

	QMessageBox::information(this, QString::fromUtf8(pointout_str[lang]), QString::fromUtf8(sendsuccess_str[lang]));
	QApplication::quit();
}

HostInfo::~HostInfo()
{
}
