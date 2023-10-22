#include "status.h"
#include <QApplication>
#include <QMessageBox>
#include <QTimer>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "../language.h"


const char *Health_str[2] = { "运行状况", "Running status" };
const char *Time_str[2] = { "生成时间", "Time" };
const char *Report_str[2] = { "报告内容", "Content" };
const char *Export_str[2] = { "导出", "Export" };
const char *Check_str[2] = { "检查", "Check" };
const char *Close_str[2] = { "关闭", "Close" };
const char *Failed_status_str[2] = { "获取sniper运行状况失败", "Failed to get sniper running status" };
const char *Check_control_str[2] = { "检查与管控中心的网络连接状态……", "Check connection with server ......"};
const char *Failed_control_str[2] = { "检查与管控中心的网络连接状态失败", "Failed to connect server"};
const char *Save_str[2] = { "另存为", "Save as" };
const char *Select_str[2] = { "文档(*.txt);;所有文件(*.*)", "File(*.txt);;All documents(*.*)" };
const char *Information_str[2] = { "提示", "Information" };
const char *Export_failed_str[2] = { "导出失败", "Export failed" };
const char *Export_succeeded_str[2] ={ "导出成功", "Export success" };
const char *Banquan_str[2] ={ SNIPER_COPYRIGHT, SNIPER_COPYRIGHT_EN };


int readinfo(int stage, char *buf)
{
	int ret = 0, status = 0;
	FILE *fp;
	char path[64] = {0};
	char cmd[128] = {0};
	pid_t pid = getpid();

	if (access("/sbin/sniper", F_OK) < 0) {
		printf("no /sbin/sniper\n");
		return -1;
	}
	if (access("/sbin/sniper", X_OK) < 0) {
		printf("/sbin/sniper not executable\n");
		return -1;
	}

	snprintf(cmd, 128, "/sbin/sniper --status%d %d >/dev/null 2>&1", stage, pid);
	status = system(cmd);
	if (status < 0) {
		printf("%s fail: %s\n", cmd, strerror(errno));
		return -1;
	}
	ret = WEXITSTATUS(status);
	if (ret != 0) {
		return -1;
	}

	snprintf(path, 64, "/dev/shm/sniperstatus.%d", pid);
	fp = fopen(path, "r");
	if (!fp) {
		printf("open %s fail: %s\n", path, strerror(errno));
		snprintf(path, 64, "/tmp/sniperstatus.%d", pid);
		fp = fopen(path, "r");
		if (!fp) {
			printf("open %s fail: %s\n", path, strerror(errno));
			return -1;
		}
	}
	ret = fread(buf, 1023, 1, fp);
	if (ret == 0 && ferror(fp)) {
		fclose(fp);
		printf("read %s fail: %s\n", path, strerror(errno));
		return -1;
	}
	fclose(fp);

	unlink(path);
	return 0;
}

SniperStatus::SniperStatus(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{

        lang = get_language();

	setWindowTitle(QString::fromUtf8(Health_str[lang]));
	setWindowIcon(QIcon("/opt/snipercli/sniper.png"));
	resize(600, 400);

	infoLayout = new QGridLayout();

        timeLabel = new QLabel(QString::fromUtf8(Time_str[lang]));


        infoLabel = new QLabel(QString::fromUtf8(Report_str[lang]));


	infoLabel->setAlignment(Qt::AlignTop);


	nowLabel = new QLabel();
	statusTextEdit = new QTextEdit;
	statusTextEdit->setReadOnly(true);

	infoLayout->addWidget(timeLabel, 0, 0);
	infoLayout->addWidget(nowLabel, 0, 1);
	infoLayout->addWidget(infoLabel, 1, 0);
	infoLayout->addWidget(statusTextEdit, 1, 1);

	copyrightLabel = new QLabel(QString::fromUtf8(Banquan_str[lang]));
	copyrightLabel->setAlignment(Qt::AlignCenter);

	blankLabel = new QLabel();

	saveBtn = new QPushButton(QString::fromUtf8(Export_str[lang]));
	checkBtn = new QPushButton(QString::fromUtf8(Check_str[lang]));
	closeBtn = new QPushButton(QString::fromUtf8(Close_str[lang]));


	/* 按钮的布局 */
	btnLayout = new QHBoxLayout();
	/* 在按钮前插入一个占位符，是按钮能靠右对齐 */
	btnLayout->addStretch();
	btnLayout->addWidget(saveBtn);
	btnLayout->addWidget(checkBtn);
	btnLayout->addWidget(closeBtn);

	mainLayout = new QVBoxLayout(this);
	mainLayout->addLayout(infoLayout);
	mainLayout->addLayout(btnLayout);
	mainLayout->addWidget(blankLabel);
#ifndef HIDE_COPYRIGHT
	mainLayout->addWidget(copyrightLabel);
#endif


	connect(saveBtn, SIGNAL(clicked()), this, SLOT(slotSave()));
	connect(checkBtn, SIGNAL(clicked()), this, SLOT(slotCheck()));
	connect(closeBtn, SIGNAL(clicked()), qApp, SLOT(quit()));


	QDateTime current_date_time = QDateTime::currentDateTime();
	QString now = current_date_time.toString("yyyy.MM.dd hh:mm:ss");
	nowLabel->setText(now);

	//防止检测网络连接长时间挂住，先仅显示进程运行状态，再更新完整状态
	char sniper_status[1024] = {0};
	if (readinfo(1, sniper_status) < 0) {
		statusTextEdit->setText(QString::fromUtf8(Failed_status_str[lang]));
		return;
	}
	statusTextEdit->setText(QString::fromUtf8(sniper_status));
	statusTextEdit->append(QString::fromUtf8(Check_control_str[lang]));

	QTimer *timer = new QTimer();
	timer->singleShot(100, this, SLOT(slotCheck())); //等100毫秒主动做一次check
}


void SniperStatus::slotCheck()
{
	char sniper_status[1024] = {0};
	char network_status[1024] = {0};

	QDateTime current_date_time = QDateTime::currentDateTime();
	QString now = current_date_time.toString("yyyy.MM.dd hh:mm:ss");
	nowLabel->setText(now);
	QApplication::processEvents(); //刷新显示的文字内容

	if (readinfo(1, sniper_status) < 0) {
		statusTextEdit->setText(QString::fromUtf8(Failed_status_str[lang]));
		return;
	}
	statusTextEdit->setText(QString::fromUtf8(sniper_status));
	statusTextEdit->append(QString::fromUtf8(Check_control_str[lang]));
	QApplication::processEvents(); //刷新显示的文字内容

	if (readinfo(2, network_status) < 0) {
		statusTextEdit->append(QString::fromUtf8(Failed_control_str[lang]));
		return;
	}
	statusTextEdit->append(QString::fromUtf8(network_status));
	QApplication::processEvents(); //刷新显示的文字内容
}

void SniperStatus::slotSave()
{
	QString defaultFile;
	QString fileName;
	char desktopdir[1024] = {0};
	char *homedir = getenv("HOME");

	snprintf(desktopdir, 1024, "%s/Desktop", homedir);
	if (access(desktopdir, F_OK) < 0) {
		snprintf(desktopdir, 1024, "%s/桌面", homedir);
		if (access(desktopdir, F_OK) < 0) {
			snprintf(desktopdir, 1024, "%s", homedir);
		}
	}
	defaultFile.sprintf("%s/sniper_status.txt", desktopdir); 
	//defaultFile.sprintf("%s/sniper_status.txt", getenv("HOME"));
	//QFileDialog会自动询问是否覆盖已存在的文件
	fileName = QFileDialog::getSaveFileName(this,
						QString::fromUtf8(Save_str[lang]),
						defaultFile,
						QString::fromUtf8(Select_str[lang]));

	if (fileName.isEmpty()) {
		return;
	}

	QFile file(fileName);

	if (!file.open(QFile::WriteOnly | QFile::Text)) {
		QMessageBox::information(this, QString::fromUtf8(Information_str[lang]),
				QString::fromUtf8(Export_failed_str[lang]));
		return;
	}

	QTextStream out(&file);
	out.setCodec("UTF-8");
	out << nowLabel->text();
	out << "\n\n";
	out << statusTextEdit->toPlainText();
	out << "\n";
	file.close();

	QMessageBox::information(this, QString::fromUtf8(Information_str[lang]),
			QString::fromUtf8(Export_succeeded_str[lang]));
}

SniperStatus::~SniperStatus()
{
}
