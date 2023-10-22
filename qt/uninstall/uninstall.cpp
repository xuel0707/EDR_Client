#include "uninstall.h"
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
#include "../language.h"


const char *Uninstall_str[2] = { "卸载", "Uninstall" };
const char *No_str[2] = { "取消", "No" };
const char *Yes_str[2] = { "确定", "Yes" };
const char *Uninstall_sniper_str[2] = { "您确定要卸载Sniper客户端吗？", "Are you sure uninstall?" };
const char *Uninstall_client_str[2] = { "卸载Sniper客户端……", "Uninstall ..." };
const char *Client_deleted_str[2] = { "客户端程序已被删除", "Sniper already deleted" };
const char *Reboot_finish_str[2] = { "请重新启动电脑完成卸载", "Please reboot to complete uninstall" };
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
const char *End_client_str[2] = { "卸载客户端结束", "Uninstall over" };


SniperUninstall::SniperUninstall(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{
	QMessageBox box;

        lang = get_language();

	box.setWindowTitle(QString::fromUtf8(Uninstall_str[lang]));
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

	setWindowTitle(QString::fromUtf8(Uninstall_str[lang]));
	setWindowIcon(QIcon("/opt/snipercli/sniper.png"));
	resize(400, 300);

	btnLayout = new QHBoxLayout;
	btnLayout->addStretch();
	btnLayout->addWidget(okBtn);
	connect(okBtn, SIGNAL(clicked()), qApp, SLOT(quit()));

	statusTextBrowser = new QTextBrowser;
	statusTextBrowser->setText(QString::fromUtf8(Uninstall_client_str[lang]));

	mainLayout = new QVBoxLayout(this);
	mainLayout->addWidget(statusTextBrowser);
	mainLayout->addLayout(btnLayout);
	QApplication::processEvents(); //刷新显示的文字内容

	QTimer *timer = new QTimer();
	timer->singleShot(100, this, SLOT(slotUninstall())); //等100毫秒主动做一次Uninstall
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

void SniperUninstall::slotUninstall()
{
	uid_t uid = getuid();
	char listfile[128] = {0}, cmd[128] = {0};

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
			return;
		}
	}

	int clean_error = 0;
	int uninstall_fail = 0;

	statusTextBrowser->append(QString::fromUtf8(Stop_program_str[lang]));
	QApplication::processEvents(); //刷新显示的文字内容
	while (proc.atEnd() == false) {
		QByteArray data = proc.readAllStandardOutput();
		QString str = data;

		if (strstr(str.toUtf8().data(), "Get uninstall strategy error")) {
			statusTextBrowser->setText(QString::fromUtf8(Uninstall_failed_str[lang]));
			statusTextBrowser->append(QString::fromUtf8(Wether_allow_str[lang]));
			uninstall_fail = 1;
		} else if (strstr(str.toUtf8().data(), "Uninstall permission denied")) {
			statusTextBrowser->setText(QString::fromUtf8(Uninstall_failed_str[lang]));
			statusTextBrowser->append(QString::fromUtf8(Prohibits_str[lang]));
			uninstall_fail = 1;
		}

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

	if (uninstall_fail) {
		return;
	}
	if (access(UNINSTALL_DISABLE, F_OK) == 0) {
		statusTextBrowser->setText(QString::fromUtf8(Uninstall_failed_str[lang]));
		statusTextBrowser->append(QString::fromUtf8(Prohibits_str[lang]));
		return;
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

	//停止托盘程序
	int pid = get_snipertray_pid(uid);

	if (pid > 0) {
		kill(pid, SIGKILL);
	}
}

SniperUninstall::~SniperUninstall()
{
}
