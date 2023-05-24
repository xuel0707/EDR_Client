#include "force_uninstall.h"
#include <QApplication>
#include <QMessageBox>
#include <QTimer>
#include <QProcess>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <QtDebug>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "../language.h"

#define RANDOM_NUMBER_LEN	8
#define UNINSTALL_KEY  "Akj6578w*aPLas3w"

const char *Uninstall_force_str[2] = { "强制卸载", "Uninstall" };
const char *No_str[2] = { "取消", "No" };
const char *Yes_str[2] = { "确定", "Yes" };
const char *Error_str[2] = { "错误", "Error" };
const char *Uninstall_str[2] = { "卸载", "Uninstall" };
const char *Uninstall_sniper_str[2] = { "您确定要卸载Sniper客户端吗？", "Are you sure uninstall?" };
const char *Uninstall_client_str[2] = { "卸载Sniper客户端……", "Uninstall ..." };
const char *Client_deleted_str[2] = { "客户端程序已被删除", "Sniper already deleted" };
const char *Reboot_finish_str[2] = { "请重新启动电脑完成卸载", "Please reboot to complete uninstall" };
const char *Mark_failed_str[2] = { "标记允许卸载失败", "Failed to mark uninstallable" };
const char *Log_out_str[2] = { "请注销当前用户，并用root用户重新登录后，尝试卸载", "Please log out and relogin as root, then try uninstall again" };
const char *Error_uninstall_str[2] = { "卸载客户端程序错误，卸载失败", "Error: uninstall failed" };
const char *Login_again_str[2] = { "请注销当前用户并重新登录后，尝试卸载", "Please log out and relogin, and try uninstall again" };
const char *Stop_program_str[2] = { "    停止sniper程序……", "    Stop sniper ..." };
const char *Uninstall_failed_str[2] = { "客户端卸载失败：", "Uninstall failed:" };
const char *Wether_allow_str[2] = { "查询管控中心是否允许卸载本客户端失败", "Failed to get server permission" };
const char *Prohibits_str[2] = { "管控中心禁止卸载客户端", "Uninstall denied by server" };
const char *Sniper_stopped_str[2] = { "    sniper程序已停止", "    Sniper already stopped" };
const char *Uninstall_module_str[2] = { "    卸载sniper_edr模块……", "    Uninstall sniper_edr module ..." };
const char *Failed_stop_str[2] = { "    停止sniper程序失败，请重新启动电脑完成卸载", "    Stop sniper failed. Please reboot to finish uninstall" };
const char *Module_uninstall_str[2] = { "    sniper_edr模块已卸载", "    Sniper_edr module has been uninstalled" };
const char *Delete_data_str[2] = { "    删除客户端数据……", "    Delete client data ..." };
const char *Failed_module_str[2] = { "    卸载sniper_edr模块失败，请重新启动电脑完成卸载", "    Failed to remove sniper_edr module. Please reboot to complete uninstall" };
const char *Delete_client_str[2] = { "    删除客户端数据失败，请手工删除文件/sbin/sniper", "    Failed to delete client data. Please delete file /sbin/sniper manually" };
const char *Delete_directory_str[2] = { "    删除客户端数据失败，请手工删除目录/opt/snipercli", "    Failed to Delete client data, please delete directory /opt/snipercli manually" };
const char *Data_deleted_str[2] = { "    客户端数据已删除", "    Client data has been deleted" };
const char *Banquan_str[2] ={ SNIPER_COPYRIGHT, SNIPER_COPYRIGHT_EN };
const char *End_client_str[2] = { "卸载客户端结束", "Uninstall over" };
const char *Get_code_str[2] = { "获取请求码", "Get request code" };
const char *input_str[2] = { "输入卸载码:", "Input uninstall code" };
const char *ok_str[2] = { "卸载", "Ok" };
const char *cancel_str[2] = { "取消", "Cancel" };
const char *uninstall_complete_str[2] = { "已卸载完成", "uninstall complete" };
const char *invalid_uninstall_code_str[2] = { "无效的卸载码", "invalid uninstall code" };


SniperForceUninstall::SniperForceUninstall(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{

        lang = get_language();

	setWindowTitle(QString::fromUtf8(Uninstall_force_str[lang]));
	setWindowIcon(QIcon("/opt/snipercli/sniper.png"));
	resize(1000, 400);

	/* 网格布局 */
	codeBtn = new QPushButton(QString::fromUtf8(Get_code_str[lang]));
	inputLabel = new QLabel(QString::fromUtf8(input_str[lang]));
	inputLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

	codeLineEdit = new QLineEdit;
	codeLineEdit->setReadOnly(true);
	inputLineEdit = new QLineEdit;

	infoLayout = new QGridLayout();
	infoLayout->addWidget(codeBtn, 0, 0);
	infoLayout->addWidget(codeLineEdit, 0, 1);

	infoLayout->addWidget(inputLabel, 1, 0);
	infoLayout->addWidget(inputLineEdit, 1, 1);

	/* 垂直布局 */
	btnLayout = new QHBoxLayout();
	okBtn = new QPushButton(QString::fromUtf8(ok_str[lang]));
	cancelBtn = new QPushButton(QString::fromUtf8(cancel_str[lang]));
	/* 在两个按钮前插入一个占位符，是两个按钮能靠右对齐 */
	btnLayout->addStretch();
	btnLayout->addWidget(okBtn);
	btnLayout->addWidget(cancelBtn);

	statusTextBrowser = new QTextBrowser;
	statusTextBrowser->setText(QString::fromUtf8(Uninstall_client_str[lang]));

	copyrightLabel = new QLabel(QString::fromUtf8(Banquan_str[lang]));
	copyrightLabel->setAlignment(Qt::AlignCenter);

	mainLayout = new QVBoxLayout(this);
        mainLayout->addStretch();
	mainLayout->addLayout(infoLayout);
	mainLayout->addWidget(statusTextBrowser);
	mainLayout->addLayout(btnLayout);
#ifndef HIDE_COPYRIGHT
	mainLayout->addWidget(copyrightLabel);
#endif

	/* 使用户无法改变窗口的大小 */
	mainLayout->setSizeConstraint(QLayout::SetFixedSize);

	connect(codeBtn, SIGNAL(clicked()), this, SLOT(getcode()));
	connect(okBtn, SIGNAL(clicked()), this, SLOT(codeuninstall()));
        connect(cancelBtn, SIGNAL(clicked()), qApp, SLOT(quit()));

}

/* 生成随机数字字符串 */
void creat_random_number(char *buff, unsigned int len)
{
        unsigned int i = 0;
        int temp = 0;

        srand((int)time(0));
        for (i = 0; i < len; i++) {
                temp = (rand() % 10);

                buff[i] = '0' + temp;
        }

        return;
}

void SniperForceUninstall::getcode()
{
	char number_str[10] = {0};

	creat_random_number(number_str, 8);

	codeLineEdit->setText(number_str);

}

void SniperForceUninstall::SniperUninstall()
{
	QMessageBox box;

        lang = get_language();

	box.setWindowTitle(QString::fromUtf8(Uninstall_force_str[lang]));
	box.setWindowIcon(QIcon("/opt/snipercli/sniper.png"));
	cancelBtn = box.addButton(QString::fromUtf8(No_str[lang]), QMessageBox::ActionRole);
	okBtn = box.addButton(QString::fromUtf8(Yes_str[lang]), QMessageBox::ActionRole);
	box.setText(QString::fromUtf8(Uninstall_sniper_str[lang]));
	box.setIcon(QMessageBox::Warning);

	box.exec();
	if (box.clickedButton() == cancelBtn) {
		//QApplication::exit(0)或quit()会留下一个空白窗口
		exit(0);
	}

	QApplication::processEvents(); //刷新显示的文字内容

	QTimer *timer = new QTimer();
	timer->singleShot(100, this, SLOT(slotUninstall())); //等100毫秒主动做一次Uninstall
}

int aes_128_ecb_pkcs5padding(char *data, const unsigned char *key, char *en_data)
{
	int len = 0, dlen = 0;
	unsigned char encrypt[100] = {0};
	EVP_CIPHER_CTX *ctx;
	int mlen = 0, flen = 0;
	int i = 0, ret = 0;
	char *ptr = NULL;

	if (data == NULL) {
		return -1;
	}

	/*加密的数据如果是整AES_BLOCK_SIZE倍，需要补上AES_BLOCK_SIZE长度的padding*/
	len = strlen(data);
	dlen = len/AES_BLOCK_SIZE + AES_BLOCK_SIZE;

	/*初始化ctx*/
	ctx = EVP_CIPHER_CTX_new();

	/*指定加密算法及key和iv(此处IV没有用)*/
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	if (ret != 1) {
		printf("EVP_EncryptInit_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	/*进行加密操作*/
	ret = EVP_EncryptUpdate(ctx, encrypt, &mlen, (const unsigned char *)data, strlen(data));
	if(ret != 1) {
		printf("EVP_EncryptUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
        }

	/*结束加密操作*/
	ret = EVP_EncryptFinal_ex(ctx, encrypt+mlen, &flen);
	if(ret != 1) {
		printf("EVP_EncryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	ret = EVP_CIPHER_CTX_cleanup(ctx);
	if(ret != 1) {
		printf("EVP_CIPHER_CTX_cleanup failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	EVP_CIPHER_CTX_free(ctx);

//	printf("encrypt: ");
	ptr = en_data;
	for(i = 0; i < dlen; i ++){
//		printf("%.2x", encrypt[i]);
		/*每个字节用2个十六进制表示*/
		snprintf(ptr, 3, "%.2x", encrypt[i]);
		ptr +=2;
	}
//	printf("\n");

	return 0;
}

int get_uninstall_code(char *data, char *code)
{
	char *en_data = NULL;
	int len = 0;
	if (data == NULL) {
		return -1;
	}

	len = (strlen(data)/AES_BLOCK_SIZE + AES_BLOCK_SIZE)*4 + 1;
	en_data = (char *)malloc(len);
        if (en_data == NULL) {
                return -1;
        }
        memset(en_data, 0, len);
	
	if (aes_128_ecb_pkcs5padding(data, (const unsigned char*)UNINSTALL_KEY, en_data) < 0) {
		free(en_data);
		return -1;
	}

//	printf("(%lu)en_data:%s\n", strlen(en_data), en_data);
	len = strlen(en_data);
	code[0] = en_data[0];
	code[1] = en_data[1];
	code[2] = en_data[2];
	code[3] = en_data[len - 3];
	code[4] = en_data[len - 2];
	code[5] = en_data[len - 1];

//	printf("code:%s\n", code);
	free(en_data);
	return 0;
}

int SniperForceUninstall::compare_uninstall_code(char *token)
{
	QString code;
	char uninstall_str[8] = {0};

	if (token == NULL) {
		return -1;
	}

	code = codeLineEdit->text();

	if (strlen(code.toUtf8().data()) != RANDOM_NUMBER_LEN) {
		return -1;
	}

	if (get_uninstall_code(code.toUtf8().data(), uninstall_str) < 0) {
		return -1;
	}

	if (strcmp(token, uninstall_str) != 0) {
		return -1;
	}

	return 0;
}

void SniperForceUninstall::codeuninstall()
{
	QString token;

	lang = get_language();

	if (access("/sbin/sniper", F_OK) != 0 &&
	    access("/opt/snipercli", F_OK) != 0) {
		QMessageBox::warning(this, QString::fromUtf8(Uninstall_str[lang]),
					QString::fromUtf8(uninstall_complete_str[lang]));
		close();
		return;
	}

	token = inputLineEdit->text();

	if (compare_uninstall_code(token.toUtf8().data()) < 0) {
		QMessageBox::warning(this, QString::fromUtf8(Error_str[lang]),
                                        QString::fromUtf8(invalid_uninstall_code_str[lang]));
		return;
	}
	SniperUninstall();

}

#include <pwd.h>
static char *get_myhome(uid_t uid)
{
        struct passwd *mypwd = NULL;

        mypwd = getpwuid(uid);
        if (!mypwd) {
                return NULL;
        }

        return mypwd->pw_dir;
}

int get_snipertray_pid(uid_t uid)
{
	char *myhome = NULL;
	char pidfile[S_SHORTPATHLEN] = {0};
	char buf[S_NAMELEN] = {0};
	int pid = 0;
	FILE *fp = NULL;

        myhome = get_myhome(uid);
        if (!myhome) {
                myhome = getenv("HOME");
        }
	if (!myhome) {
		return 0;
	}

	snprintf(pidfile, S_SHORTPATHLEN, "%s/%s", myhome, TRAY_PIDFILE);
	fp = fopen(pidfile, "r");
	if (!fp) {
		printf("open %s fail: %s\n", pidfile, strerror(errno));
		return -1;
	}
	if (fgets(buf, S_NAMELEN, fp)) {
		pid = atoi(buf);
	}
	fclose(fp);

	return pid;
}

/* 检查sniper是否rpm安装 */
static int sniper_installed_by_rpm(void)
{
#if 0
	proc.stat("rpm -qf /sbin/sniper | grep -v ' ' > /tmp/query_sniper_rmp");

	int i = 0;
	while (false == proc.waitForFinished(1000)) {
		i++;
		if (i > 60) {
			break;
		}
	}

	struct stat st;
	stat("/tmp/query_sniper_rmp", &st);
	if (st.st_size > 0) {
		return 1;
	}
	return 0;
#endif
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	fp = popen("rpm -qf /sbin/sniper", "r");
	if (!fp) {
		return 0;
	}

	if (!fgets(line, S_LINELEN, fp)) {
		pclose(fp);
		return 0;
	}
	pclose(fp);

	/* 不是rpm安装的会报file /sbin/sniper is not owned by any package */
	if (line[0] == 0 || strchr(line, ' ')) {
		return 0;
	}

	return 1;
}

void SniperForceUninstall::slotUninstall()
{
	uid_t uid = getuid();
	char listfile[128] = {0}, cmd[128] = {0};
	FILE *fp = NULL;

	setsid();

	QApplication::processEvents(); //发现ok键显示不出来，这里加一句确保正常显示

	QProcess proc;

	//startDetached的话，取不到进程状态，如waitForxxx，state都无效
	//if (proc.startDetached("/usr/bin/pkexec /sbin/sniper --uninstall") == false) {
	//	statusTextBrowser->setText(QString::fromUtf8("卸载客户端程序错误，卸载失败"));
	//	QApplication::processEvents(); //刷新显示的文字内容
	//	return;
	//}

	if (access("/sbin/sniper", F_OK) < 0) {
		statusTextBrowser->setText(QString::fromUtf8(Client_deleted_str[lang]));
		//TODO 根据sniper进程在不在，提示重启或重新登录
		statusTextBrowser->append(QString::fromUtf8(Reboot_finish_str[lang]));
		QApplication::processEvents(); //刷新显示的文字内容
		return;
	}

	/* 创建允许强制卸载的临时标志文件 */
	fp = fopen(FORCE_UNINSTALL, "w");
	if (!fp) {
		statusTextBrowser->setText(QString::fromUtf8(Mark_failed_str[lang]));
		QApplication::processEvents();
		return;
	}
	fclose(fp);

	snprintf(listfile, 128, "/var/lib/dpkg/info/%s.list", SNIPER_PACKAGE);
	if (uid == 0) {
		if (access(listfile, F_OK) == 0) {
			snprintf(cmd, 128, "dpkg --purge %s", SNIPER_PACKAGE);
		} else if (sniper_installed_by_rpm()) {
			snprintf(cmd, 128, "rpm -e %s", SNIPER_PACKAGE);
		} else {
			snprintf(cmd, 128, "/sbin/sniper --uninstall ZH94f2J1cH19Tnx0");
		}
	} else {
		if (access("/usr/bin/pkexec", F_OK) < 0) {
			statusTextBrowser->setText(QString::fromUtf8(Log_out_str[lang]));
			QApplication::processEvents(); //刷新显示的文字内容

			/* 失败返回前删除临时文件 */
			unlink(FORCE_UNINSTALL);
			return;
		}
		if (access(listfile, F_OK) == 0) {
			snprintf(cmd, 128, "/usr/bin/pkexec dpkg --purge %s", SNIPER_PACKAGE);
		} else if (sniper_installed_by_rpm()) {
			snprintf(cmd, 128, "/usr/bin/pkexec rpm -e %s", SNIPER_PACKAGE);
		} else {
			snprintf(cmd, 128, "/usr/bin/pkexec /sbin/sniper --uninstall ZH94f2J1cH19Tnx0");
		}
	}
	proc.start(cmd);

	while (proc.waitForReadyRead(1000) == false) {
		if (proc.state() == QProcess::NotRunning) {
			statusTextBrowser->setText(QString::fromUtf8(Error_uninstall_str[lang]));
			if (getuid()) {
				statusTextBrowser->append(QString::fromUtf8(Login_again_str[lang]));
			}
			QApplication::processEvents(); //刷新显示的文字内容

			/* 失败返回前删除临时文件 */
			unlink(FORCE_UNINSTALL);
			return;
		}
	}

	int clean_error = 0;

	statusTextBrowser->append(QString::fromUtf8(Stop_program_str[lang]));
	QApplication::processEvents(); //刷新显示的文字内容
	while (proc.atEnd() == false) {
		QByteArray data = proc.readAllStandardOutput();
		QString str = data;

		if (strstr(str.toUtf8().data(), "stopped")) {
			statusTextBrowser->append(QString::fromUtf8(Sniper_stopped_str[lang]));
			statusTextBrowser->append(QString::fromUtf8(""));
			statusTextBrowser->append(QString::fromUtf8(Uninstall_module_str[lang]));
		} else if (strstr(str.toUtf8().data(), "Stop sniper process fail")) {
			statusTextBrowser->append(QString::fromUtf8(Failed_stop_str[lang]));
			statusTextBrowser->append(QString::fromUtf8(""));
			statusTextBrowser->append(QString::fromUtf8(Uninstall_module_str[lang]));
		}

		if (strstr(str.toUtf8().data(), "unloaded")) {
			statusTextBrowser->append(QString::fromUtf8(Module_uninstall_str[lang]));
			statusTextBrowser->append(QString::fromUtf8(""));
			statusTextBrowser->append(QString::fromUtf8(Delete_data_str[lang]));
		} else if (strstr(str.toUtf8().data(), "Stop sniper process fail")) {
			statusTextBrowser->append(QString::fromUtf8(Failed_module_str[lang]));
			statusTextBrowser->append(QString::fromUtf8(""));
			statusTextBrowser->append(QString::fromUtf8(Delete_data_str[lang]));
		}
		QApplication::processEvents(); //刷新显示的文字内容
	}

	//等卸载结束，每次等1秒，最多等5秒
	//避免报QProcess: Destroyed while process is still running
	//避免报删除客户端数据失败
	int i = 0;
	while (false == proc.waitForFinished(1000)) {
		i++;
		if (i > 5) {
			break;
		}
	}

	if (access("/sbin/sniper", F_OK) == 0) {
		statusTextBrowser->append(QString::fromUtf8(Delete_client_str[lang]));
		QApplication::processEvents(); //刷新显示的文字内容
		clean_error = 1;
	}
	if (access("/opt/snipercli", F_OK) == 0) {
		statusTextBrowser->append(QString::fromUtf8(Delete_directory_str[lang]));
		QApplication::processEvents(); //刷新显示的文字内容
		clean_error = 1;
	}
	if (!clean_error) {
		statusTextBrowser->append(QString::fromUtf8(Data_deleted_str[lang]));
	}

	statusTextBrowser->append(QString::fromUtf8(End_client_str[lang]));
	QApplication::processEvents(); //刷新显示的文字内容

	
	/* 删除临时文件 */
	unlink(FORCE_UNINSTALL);

	//停止托盘程序
	int pid = get_snipertray_pid(uid);

	if (pid > 0) {
		kill(pid, SIGKILL);
	}

}

SniperForceUninstall::~SniperForceUninstall()
{
}
