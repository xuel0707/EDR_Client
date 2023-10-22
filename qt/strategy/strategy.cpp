#include "strategy.h"
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QDateTime>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <QtDebug>
#include <QFile>
#include "../language.h"

const char *View_str[2] = { "查看策略", "Strategy" };
const char *Time_str[2] = { "获取时间:", "Time:" };
const char *Policy_name_str[2] = { "策略名称:", "Strategy name:" };
const char *Policy_category_str[2] = { "策略类别:", "Strategy type:" };
const char *Strategy_content_str[2] = { "策略内容:", "Strategy content:" };
const char *Missing_policy_str[2] = { "缺省策略", "Default strategy" };
const char *Process_strategy_str[2] = { "进程策略", "Process strategy" };
const char *File_policy_str[2] = { "文件策略", "File strategy" };
const char *Network_protection_str[2] = { "网络防护", "Network strategy" };
const char *System_monitoring_str[2] = { "系统监控", "System strategy" };
const char *Equipment_monitoring_str[2] = { "设备监控", "Device strategy" };
const char *Rule_matching_str[2] = { "规则匹配", "Rule strategy" };
const char *Other_config_str[2] = { "其他配置", "Other strategy" };
const char *All_conf_str[2] = { "配置", "All conf" };
const char *Protect_policy_str[2] = { "防护策略", "Protect strategy" };
const char *Resource_policy_str[2] = { "资源外设策略", "Resource strategy" };
const char *Antivirus_policy_str[2] = { "病毒防护策略", "Antivirus strategy" };
const char *Other_policy_str[2] = { "其他策略", "Other strategy" };
const char *All_rule_str[2] = { "规则", "All rule" };
const char *Export_str[2] = { "导出", "Export" };
const char *Refresh_str[2] = { "刷新", "Refresh" };
const char *Close_str[2] = { "关闭", "Close" };
#if 0
const char *Process_str[2] = { "一）进程策略：", "1) Process strategy:" };
const char *File_str[2] = { "二）文件策略：", "2) File strategy:" };
const char *Network_str[2] = { "三）网络防护：", "3) Network strategy:" };
const char *System_str[2] = { "四）系统监控：", "4) System strategy:" };
const char *Equipment_str[2] = { "五）设备监控：", "5) Device strategy:" };
//const char *Rule_str[2] = { "六）规则匹配：", "6) Rule strategy:" };
const char *Other_str[2] = { "七）其他配置：", "7) Other strategy:" };
#endif
const char *Conf_str[2] = { "一）配置：", "1) All conf:" };
const char *Policy_protect_str[2] = { "二）防护策略：", "2) Protcet policy:" };
const char *Policy_resource_str[2] = { "三）资源/外设策略：", "3) Resource/Input policy:" };
const char *Policy_antivirus_str[2] = { "四）病毒防护策略：", "4) Virus protection policy:" };
const char *Policy_other_str[2] = { "五）其他策略：", "5) Other policy:" };
const char *Rule_str[2] = { "六）规则：", "6) All rule:" };
const char *Policy_acquisition_str[2] = { "策略获取失败", "Get strategy failed" };
const char *Save_str[2] = { "另存为", "Save as" };
const char *Select_str[2] = { "文档（*.txt）;;所有文件（*.*）", "File(*.txt);;All document(*.*)" };
const char *Information_str[2] = { "提示", "Information" };
const char *Export_failed_str[2] = { "导出失败", "Export failed" };
const char *Export_succeeded_str[2] = { "导出成功", "Export success" };
const char *Banquan_str[2] ={ SNIPER_COPYRIGHT, SNIPER_COPYRIGHT_EN };
const char *conf_filename_str[2] = { "/opt/snipercli/conf.info", "/opt/snipercli/conf.info_en" };
const char *protect_filename_str[2] = { "/opt/snipercli/protect.lst.file", "/opt/snipercli/protect.lst.file_en" };
const char *fasten_filename_str[2] = { "/opt/snipercli/fasten.lst.file", "/opt/snipercli/fasten.lst.file_en" };
const char *antivirus_filename_str[2] = { "/opt/snipercli/antivirus.lst.file", "/opt/snipercli/antivirus.lst.file_en" };
const char *other_filename_str[2] = { "/opt/snipercli/other.lst.file", "/opt/snipercli/other.lst.file_en" };
const char *rule_filename_str[2] = { "/opt/snipercli/rule.info", "/opt/snipercli/rule.info_en" };


void get_strategy_name(QLabel *nameValueLabel)
{
	QFile file("/opt/snipercli/lst.conf.name");

	if (file.open(QIODevice::ReadOnly)) {
		QTextStream in(&file);
		in.setCodec("UTF-8");
		nameValueLabel->setText(in.readLine());
		file.close();
	}
}


SniperStrategy::SniperStrategy(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{
        lang = get_language();

	setWindowTitle(QString::fromUtf8(View_str[lang]));
	setWindowIcon(QIcon("/opt/snipercli/sniper.png"));
	resize(600, 400);

	infoLayout = new QGridLayout();
	timeLabel = new QLabel(QString::fromUtf8(Time_str[lang]));
	nameLabel = new QLabel(QString::fromUtf8(Policy_name_str[lang]));
	typeLabel = new QLabel(QString::fromUtf8(Policy_category_str[lang]));
	infoLabel = new QLabel(QString::fromUtf8(Strategy_content_str[lang]));
	infoLabel->setAlignment(Qt::AlignTop);

	nameValueLabel = new QLabel;
	nameValueLabel->setText(QString::fromUtf8(Missing_policy_str[lang]));

	QDateTime current_date_time = QDateTime::currentDateTime();
	QString now = current_date_time.toString("yyyy.MM.dd hh:mm:ss");
	timeValueLabel = new QLabel;
	timeValueLabel->setText(now);

	infoTextEdit = new QTextEdit;
	infoTextEdit->setReadOnly(true);

	typeComboBox = new QComboBox;
/*
	typeComboBox->addItem(QString::fromUtf8(Process_strategy_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(File_policy_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(Network_protection_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(System_monitoring_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(Equipment_monitoring_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(Rule_matching_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(Other_config_str[lang]));
*/
	typeComboBox->addItem(QString::fromUtf8(All_conf_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(Protect_policy_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(Resource_policy_str[lang]));
	/* 没有病毒许可不显示病毒策略 */
	if (access(AVIRA_ENABLE, F_OK) == 0) {
		typeComboBox->addItem(QString::fromUtf8(Antivirus_policy_str[lang]));
	}
	typeComboBox->addItem(QString::fromUtf8(Other_policy_str[lang]));
	typeComboBox->addItem(QString::fromUtf8(All_rule_str[lang]));

	//避免combobox长度扩展到和textbrowser一样长
	typeComboBox->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

	infoLayout->addWidget(timeLabel, 0, 0);
	infoLayout->addWidget(timeValueLabel, 0, 1);
	infoLayout->addWidget(nameLabel, 1, 0);
	infoLayout->addWidget(nameValueLabel, 1, 1);
	infoLayout->addWidget(typeLabel, 2, 0);
	infoLayout->addWidget(typeComboBox, 2, 1);
	infoLayout->addWidget(infoLabel, 3, 0);
	infoLayout->addWidget(infoTextEdit, 3, 1);

	copyrightLabel = new QLabel(QString::fromUtf8(Banquan_str[lang]));
	copyrightLabel->setAlignment(Qt::AlignCenter);
	blankLabel = new QLabel;

	saveBtn = new QPushButton(QString::fromUtf8(Export_str[lang]));
	checkBtn = new QPushButton(QString::fromUtf8(Refresh_str[lang]));
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

	connect(typeComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(slotShow()));

	connect(saveBtn, SIGNAL(clicked()), this, SLOT(slotSave()));
	connect(checkBtn, SIGNAL(clicked()), this, SLOT(slotCheck()));
	connect(closeBtn, SIGNAL(clicked()), qApp, SLOT(quit()));
/*
	strategyInfo[0].desc = QString::fromUtf8(Process_str[lang]);
	strategyInfo[1].desc = QString::fromUtf8(File_str[lang]);
	strategyInfo[2].desc = QString::fromUtf8(Network_str[lang]);
	strategyInfo[3].desc = QString::fromUtf8(System_str[lang]);
	strategyInfo[4].desc = QString::fromUtf8(Equipment_str[lang]);
	strategyInfo[5].desc = QString::fromUtf8(Rule_str[lang]);
	strategyInfo[6].desc = QString::fromUtf8(Other_str[lang]);

	strategyInfo[0].filename = "/opt/snipercli/lst.conf.process";
	strategyInfo[1].filename = "/opt/snipercli/lst.conf.file";
	strategyInfo[2].filename = "/opt/snipercli/lst.conf.network";
	strategyInfo[3].filename = "/opt/snipercli/lst.conf.system";
	strategyInfo[4].filename = "/opt/snipercli/lst.conf.device";
	strategyInfo[5].filename = "/opt/snipercli/lst.conf.rule";
	strategyInfo[6].filename = "/opt/snipercli/lst.conf.other";
*/
	strategyInfo[0].desc = QString::fromUtf8(Conf_str[lang]);
	strategyInfo[1].desc = QString::fromUtf8(Policy_protect_str[lang]);
	strategyInfo[2].desc = QString::fromUtf8(Policy_resource_str[lang]);
	/* 没有病毒许可不显示病毒策略 */
	if (access(AVIRA_ENABLE, F_OK) == 0) {
		strategyInfo[3].desc = QString::fromUtf8(Policy_antivirus_str[lang]);
		strategyInfo[4].desc = QString::fromUtf8(Policy_other_str[lang]);
		strategyInfo[5].desc = QString::fromUtf8(Rule_str[lang]);
	} else {
		strategyInfo[3].desc = QString::fromUtf8(Policy_other_str[lang]);
		strategyInfo[4].desc = QString::fromUtf8(Rule_str[lang]);
	}

	strategyInfo[0].filename = QString::fromUtf8(conf_filename_str[lang]);
	strategyInfo[1].filename = QString::fromUtf8(protect_filename_str[lang]);
	strategyInfo[2].filename = QString::fromUtf8(fasten_filename_str[lang]);
	/* 没有病毒许可不显示病毒策略 */
	if (access(AVIRA_ENABLE, F_OK) == 0) {
		strategyInfo[3].filename = QString::fromUtf8(antivirus_filename_str[lang]);
		strategyInfo[4].filename = QString::fromUtf8(other_filename_str[lang]);
		strategyInfo[5].filename = QString::fromUtf8(rule_filename_str[lang]);
	} else {
		strategyInfo[3].filename = QString::fromUtf8(other_filename_str[lang]);
		strategyInfo[4].filename = QString::fromUtf8(rule_filename_str[lang]);
	}
	slotCheck();
}

void SniperStrategy::slotShow()
{
	int i = typeComboBox->currentIndex();

	infoTextEdit->setText(strategyInfo[i].strategy);
	QApplication::processEvents(); //刷新显示的文字内容
}

void SniperStrategy::slotCheck()
{
	int i;
	QFile file;

	get_strategy_name(nameValueLabel);

	for (i = 0; i < STRATEGYNUM; i++) {
		file.setFileName(strategyInfo[i].filename);
		if (!file.open(QIODevice::ReadOnly)) {
			strategyInfo[i].strategy = QString::fromUtf8(Policy_acquisition_str[lang]);
			continue;
		}

		QTextStream in(&file);
		in.setCodec("UTF-8");

		strategyInfo[i].strategy = "";
		while(!in.atEnd()) {
			QString str = in.readLine();

			strategyInfo[i].strategy.append(str);
			strategyInfo[i].strategy.append(tr("\n"));
		}
//		qDebug() << strategyInfo[i].strategy;

		file.close();
	}

	QDateTime current_date_time = QDateTime::currentDateTime();
	QString now = current_date_time.toString("yyyy.MM.dd hh:mm:ss");
	timeValueLabel->setText(now);

	slotShow();
}

void SniperStrategy::slotSave()
{
	int i;
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
	defaultFile.sprintf("%s/sniper_strategy.txt", desktopdir);
	//defaultFile.sprintf("%s/sniper_strategy.txt", getenv("HOME"));
	fileName = QFileDialog::getSaveFileName(this,
						QString::fromUtf8(Save_str[lang]),
						defaultFile,
						//QString::fromUtf8("文档(*.txt);;所有文件(*.*)"));
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

	out << timeValueLabel->text();
	out << "\n";
	out << QString::fromUtf8(Policy_name_str[lang]) << nameValueLabel->text();
	out << "\n\n";

	for (i = 0; i < STRATEGYNUM; i++) {
		out << strategyInfo[i].desc;
		out << "\n";
		out << strategyInfo[i].strategy;
		out << "\n\n";
	}

	file.close();

	QMessageBox::information(this, QString::fromUtf8(Information_str[lang]),
			QString::fromUtf8(Export_succeeded_str[lang]));
}

SniperStrategy::~SniperStrategy()
{
}
