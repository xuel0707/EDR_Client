#include "servaddr.h"
#include <QApplication>
#include <QMessageBox>
#include <QProcess>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "../language.h"

const char *title_str[2] = { "管控中心服务器设置", "Server Settings" };
const char *ip_str[2] = { "服务器名称或IP ", "Server Name or IP " };
const char *port_str[2] = { "服务器端口 ", "Server Port " };
const char *lang_str[2] = { "语言 ", "Language " };
const char *ok_str[2] = { "确定", "Ok" };
const char *cancel_str[2] = { "取消", "Cancel" };
const char *warn_str[2] = { "警告", "Warning" };
const char *error_str[2] = { "错误", "Error" };
const char *nullip_str[2] = { "服务器名称或IP不能为空", "NULL Server" };
const char *nullport_str[2] = { "服务器端口不能为空", "NULL Port" };
const char *wrongip_str[2] = { "无效的服务器名称或IP", "Invalid Server" };
const char *wrongport_str[2] = { "无效的服务器端口", "Invalid Port" };
const char *savefail_str[2] = { "保存服务器设置失败", "Failed to save settings" };
const char *Information_str[2] = { "提示", "Information" };
const char *Config_succeeded_str[2] = { "配置成功", "Config success" };

ServAddr::ServAddr(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{
	lang = get_language();

	setWindowTitle(QString::fromUtf8(title_str[lang]));
	setWindowIcon(QIcon("/opt/snipercli/sniper.png"));

	serveripLabel = new QLabel(QString::fromUtf8(ip_str[lang]));
	serveripLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	serveripLineEdit = new QLineEdit;
	serverportLabel = new QLabel(QString::fromUtf8(port_str[lang]));
	serverportLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	serverportLineEdit = new QLineEdit;

	blankLabel = new QLabel();

	langLabel = new QLabel(QString::fromUtf8(lang_str[lang]));
	langLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
	langComboBox = new QComboBox;
	/* 下拉菜单默认显示当前语言 */	
	if (lang == 0) {
		langComboBox->addItem(QString::fromUtf8("Chinese"));
		langComboBox->addItem(QString::fromUtf8("English"));
	} else {
		langComboBox->addItem(QString::fromUtf8("English"));
		langComboBox->addItem(QString::fromUtf8("Chinese"));
	}

	okBtn = new QPushButton(QString::fromUtf8(ok_str[lang]));
	cancelBtn = new QPushButton(QString::fromUtf8(cancel_str[lang]));

	/*
	 * QGridLayout：格栅布局，也被称作网格布局（多行多列）
	 * 将空间划分成行和列，并把每个窗口部件插入到一个或多个单元格
	 *
	 * void addWidget(QWidget *, int row, int column, int rowSpan, int columnSpan, Qt::Alignment = 0);
	 * 从第row行第column列开始，占用rowSpan行columnSpan列
	 *
	 * 下面是按3行3列的布局，3列的目的是使得okBtn和cancelBtn同宽
	 */
	mainLayout = new QGridLayout(this);
	mainLayout->addWidget(serveripLabel, 0, 0, 1, 1);
	mainLayout->addWidget(serveripLineEdit, 0, 1, 1, 2);
	mainLayout->addWidget(serverportLabel, 1, 0, 1, 1);
	mainLayout->addWidget(serverportLineEdit, 1, 1, 1, 2);
	mainLayout->addWidget(langLabel, 2, 0, 1, 1);
	mainLayout->addWidget(langComboBox, 2, 1, 1, 2);
	mainLayout->addWidget(blankLabel, 3, 0, 1, 1);
	mainLayout->addWidget(okBtn, 4, 1, 1, 1);
	mainLayout->addWidget(cancelBtn, 4, 2, 1, 1);

	connect(okBtn, SIGNAL(clicked()), this, SLOT(slotOk()));
	connect(cancelBtn, SIGNAL(clicked()), qApp, SLOT(quit()));
	connect(langComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(slotTrans()));

	unsigned short port = 0;
	char server[S_HOSTNAMELEN] = {0};

	read_servaddr(&port, server, sizeof(server), (char *)SNIPER_CONF);
	if (port) {
		serverip.sprintf("%s", server);
		serverport.sprintf("%d", port);
		serveripLineEdit->setText(serverip);
		serverportLineEdit->setText(serverport);
	}
}

void ServAddr::slotTrans()
{
	if(langComboBox->currentText() == "Chinese") {
		lang = 0;
		remember_language("Chinese");
	} else {
		lang = 1;
		remember_language("English");
	}

	setWindowTitle(QString::fromUtf8(title_str[lang]));
	serveripLabel->setText(QString::fromUtf8(ip_str[lang]));
	serverportLabel->setText(QString::fromUtf8(port_str[lang]));
	langLabel->setText(QString::fromUtf8(lang_str[lang]));
	okBtn->setText(QString::fromUtf8(ok_str[lang]));
	cancelBtn->setText(QString::fromUtf8(cancel_str[lang]));
}

void ServAddr::slotOk()
{
	int ret = 0, port = 0, newserver = 0;
	char server[S_HOSTNAMELEN] = {0};
	char errstr[S_LINELEN] = {0};
	char ip[S_IPLEN] = {0};
	char str[8] = {0};
	QString newip, newport;

	newip = serveripLineEdit->text();
	if (newip.isEmpty()) {
		QMessageBox::warning(this, QString::fromUtf8(warn_str[lang]), QString::fromUtf8(nullip_str[lang]));
		return; 
	}

	newport = serverportLineEdit->text();
	if (newport.isEmpty()) {
		QMessageBox::warning(this, QString::fromUtf8(warn_str[lang]), QString::fromUtf8(nullport_str[lang]));
		return; 
	}

	if (QString::compare(serverip, newip) != 0) {
		newserver = 1;
	} else if (QString::compare(serverport, newport) != 0) {
		newserver = 1;
	}

	if (newserver) {
		ret = sscanf(newport.toStdString().data(), "%d%1s", &port, str);
		if (ret != 1 || port < 1  || port > 65535) {
			QMessageBox::warning(this, QString::fromUtf8(warn_str[lang]),
					QString::fromUtf8(wrongport_str[lang]));
			return; 
		}

		snprintf(server, sizeof(server), "%s", newip.toStdString().data());
		if (hostname_to_ip(server, ip, sizeof(ip)) < 0) {
			QMessageBox::warning(this, QString::fromUtf8(warn_str[lang]),
					QString::fromUtf8(wrongip_str[lang]));
			return; 
		}

		/* 在UOS上让普通用户可以设置管控中心ip和端口 */
		/* UOS要求deb包安装，且安装包里不允许执行脚本 */
                if (getuid() != 0) {
                        int i = 0;
                        char cmd[S_LINELEN] = {0};
                        struct stat st1, st2;
                        QProcess proc;
 
                        stat(SNIPER_CONF, &st1);

                        snprintf(cmd, sizeof(cmd), "/usr/bin/pkexec %s %s:%d", PROG_SERVADDR, server, port);
                        proc.start(cmd);
                        while (proc.waitForReadyRead(1000) == false) {
                                if (proc.state() == QProcess::NotRunning) {
                                        break;
                                }
                        }
                        while (false == proc.waitForFinished(1000)) {
                                i++;
                                if (i > 5) {
                                        break;
                                }
                        }

                        stat(SNIPER_CONF, &st2);
 
                        if (st2.st_mtime == st1.st_mtime) {
                                snprintf(errstr, 256, "%s: %s", savefail_str[lang], strerror(errno));
                                QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
                                                        QString::fromUtf8(errstr));
                        } else {
                                QMessageBox::information(this, QString::fromUtf8(Information_str[lang]),
                                                        QString::fromUtf8(Config_succeeded_str[lang]));
                        }
                        QApplication::quit();
                        return;
                }

		if (save_servaddr(port, server, (char *)SNIPER_CONF) < 0) {
			snprintf(errstr, sizeof(errstr), "%s: %s", savefail_str[lang], strerror(errno));
			QMessageBox::warning(this, QString::fromUtf8(error_str[lang]),
						QString::fromUtf8(errstr));
			return;
                }
                QMessageBox::information(this, QString::fromUtf8(Information_str[lang]),
                                         QString::fromUtf8(Config_succeeded_str[lang]));
	}

	QApplication::quit();
}

ServAddr::~ServAddr()
{
}
