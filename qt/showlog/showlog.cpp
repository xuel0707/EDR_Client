#include "showlog.h"
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QHeaderView>
#include <QTimer>
#include <QTextStream>
#include <QFile>
#include "../language.h"
#include <unistd.h>

const char *time_str[2] = { "时间", "Time" };
const char *outline_str[2] = { "概要", "Content" };
const char *alarmlog_str[2] = { "告警日志", "Alarm log" };
const char *date_str[2] = { "日期:", "Date:" };
const char *to_str[2] = { "至", "-" };
const char *loading_str[2] = { "读取中......", "Loading......" };
const char *export_str[2] = { "导出", "Export" };
const char *clear_str[2] = { "清空", "Clear" };
const char *refresh_str[2] = { "刷新", "Refresh" };
const char *close_str[2] = { "关闭", "Close" };
const char *nofile_str[2] = { "文件不存在", "No such file" };
const char *item_str[2] = { "共0项", " 0 item" };
const char *inall_str[2] = { "共", " " };
const char *items_str[2] = { "项", "items" };
const char *information_str[2] = { "提示", "Information" };
const char *queryfails_str[2] = { "查询失败", "Query failed" };
const char *clearsuccess_str[2] = { "清空成功", "Clear success" };
const char *clearfailed_str[2] = { "清空失败", "Clear failed" };
const char *logreading_str[2] = { "日志读取中，请稍后重试", "Log not ready, please try again later" };
const char *saveas_str[2] = { "另存为", "Save as" };
const char *document_str[2] = { "文档（*.txt）;;所有文件（*.*）", "Document (*.txt);; All files (*.*)" };
const char *exportfail_str[2] = { "导出失败", "Export failed" };
const char *exportsuccess_str[2] = { "导出成功", "Export success" };
const char *Banquan_str[2] ={ SNIPER_COPYRIGHT, SNIPER_COPYRIGHT_EN };

void init_dataModel(QTableView *logTableView, QStandardItemModel *dataModel)
{
	dataModel->setColumnCount(2);
	dataModel->setHeaderData(0, Qt::Horizontal, QString::fromUtf8(time_str[lang]));
	dataModel->setHeaderData(1, Qt::Horizontal, QString::fromUtf8(outline_str[lang]));
	logTableView->setModel(dataModel);  //绑定数据模型
	//行高列宽要在绑定模型后设置才有效
	logTableView->setColumnWidth(0, 150); //对第0列设置固定宽度
	logTableView->horizontalHeader()->setStretchLastSection(true); //第1列填充最后的空白位置
	logTableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents); //自动调整行高
}

SniperShowlog::SniperShowlog(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{
	lang = get_language();

	setWindowTitle(QString::fromUtf8(alarmlog_str[lang]));
	setWindowIcon(QIcon("/opt/snipercli/sniper.png"));
	resize(600, 400);

	//时间组件
	timeLayout = new QHBoxLayout();
	timeLabel = new QLabel(QString::fromUtf8(date_str[lang]));
	toLabel = new QLabel(QString::fromUtf8(to_str[lang]));
	beginDateTimeEdit = new QDateTimeEdit(QDateTime::currentDateTime());
	endDateTimeEdit = new QDateTimeEdit(QDateTime::currentDateTime().addDays(+1));

	beginDateTimeEdit->setCalendarPopup(true);
	endDateTimeEdit->setCalendarPopup(true);
	beginDateTimeEdit->setDisplayFormat("yyyy-MM-dd 00:00:00");
	endDateTimeEdit->setDisplayFormat("yyyy-MM-dd 00:00:00");

	timeLayout->addWidget(timeLabel);
	timeLayout->addWidget(beginDateTimeEdit);
	timeLayout->addWidget(toLabel);
	timeLayout->addWidget(endDateTimeEdit);
	timeLayout->addStretch(); //在最后插入一个占位符，使控件都靠左对齐

	//日志组件
	logNumLabel = new QLabel(QString::fromUtf8(loading_str[lang]));
	logTableView = new QTableView;
	logTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置表格只读，不能进行编辑
	logTableView->setShowGrid(false);   //不显示网格线
	logTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft); //表头信息显示居左
	logTableView->verticalHeader()->hide();  //隐藏行表头（行表头即行号）
	logTableView->setAlternatingRowColors(true); //行背景色交替（默认白和灰）

	dataModel = new QStandardItemModel();
	init_dataModel(logTableView, dataModel);

	copyrightLabel = new QLabel(QString::fromUtf8(Banquan_str[lang]));
	copyrightLabel->setAlignment(Qt::AlignCenter);
	blankLabel = new QLabel;

	saveBtn = new QPushButton(QString::fromUtf8(export_str[lang]));
	cleanBtn = new QPushButton(QString::fromUtf8(clear_str[lang]));
	checkBtn = new QPushButton(QString::fromUtf8(refresh_str[lang]));
	closeBtn = new QPushButton(QString::fromUtf8(close_str[lang]));

	/* 按钮的布局 */
	btnLayout = new QHBoxLayout();
	btnLayout->addStretch(); //在按钮前插入一个占位符，使按钮能靠右对齐
	btnLayout->addWidget(saveBtn);
	btnLayout->addWidget(cleanBtn);
	btnLayout->addWidget(checkBtn);
	btnLayout->addWidget(closeBtn);

	mainLayout = new QVBoxLayout(this);
	mainLayout->addLayout(timeLayout);
	mainLayout->addWidget(logTableView);
	mainLayout->addWidget(logNumLabel);
	mainLayout->addLayout(btnLayout);
	mainLayout->addWidget(blankLabel);
#ifndef HIDE_COPYRIGHT
	mainLayout->addWidget(copyrightLabel);
#endif

	connect(saveBtn, SIGNAL(clicked()), this, SLOT(slotSave()));
	connect(cleanBtn, SIGNAL(clicked()), this, SLOT(slotClean()));
	connect(checkBtn, SIGNAL(clicked()), this, SLOT(slotCheck()));
	connect(closeBtn, SIGNAL(clicked()), qApp, SLOT(quit()));
	connect(beginDateTimeEdit, SIGNAL(dateTimeChanged(QDateTime)), this, SLOT(slotCheck()));
	connect(endDateTimeEdit, SIGNAL(dateTimeChanged(QDateTime)), this, SLOT(slotCheck()));

	QTimer *timer = new QTimer();
	timer->singleShot(100, this, SLOT(slotCheck())); //等100毫秒主动做一次check
}

void SniperShowlog::slotCheck()
{
	quint64 time_start = 0;
	quint64 time_end = 0;
	ulong seconds = 0;
	quint64 times = 0;

	if(beginDateTimeEdit->dateTime().toTime_t() >= endDateTimeEdit->dateTime().toTime_t()) {
		logNumLabel->setText(QString::fromUtf8(item_str[lang]));
		return;
	}

	time_start = (quint64)beginDateTimeEdit->dateTime().toTime_t()*1000000;
	time_end = (quint64)endDateTimeEdit->dateTime().toTime_t()*1000000;

	if (dataModel != NULL) {
		delete dataModel;
		dataModel = NULL;
	}
	lognum = 0;
	reading = 1;

	dataModel = new QStandardItemModel();
	init_dataModel(logTableView, dataModel);
	logNumLabel->setText(QString::fromUtf8(loading_str[lang]));
	QApplication::processEvents(); //刷新显示的文字内容

	QFile file;
	file.setFileName("/opt/snipercli/event.log");
	if (!file.exists(file.fileName())) {
//		qDebug()<<QString::fromUtf8(nofile_str[lang]);
		QString numstr;
                numstr.sprintf("%d", lognum);
                QString str = QString::fromUtf8(inall_str[lang]) + numstr + QString::fromUtf8(items_str[lang]);
                logNumLabel->setText(str);
		reading = 0;
		return;
	}

	if (!file.open(QIODevice::ReadOnly)) {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]), QString::fromUtf8(queryfails_str[lang]));
		return;
	}
	QTextStream in(&file);
	in.setCodec("UTF-8");

	while(!in.atEnd()) {
		QString	line = in.readLine();
		if(!line.contains("endflag", Qt::CaseSensitive)) {
			qDebug()<<QString::fromUtf8("Line is error:%1").arg(line);
			continue;
		}
		QString time = line.section(' ', 0, 0);
		QString strevent = line.section(' ', 1, -2);
		times = time.toULong();
		if(times< time_start || times > time_end) {
			continue;
		}
		seconds = times/1000000;
		QDateTime dt = QDateTime::fromTime_t(seconds);
		QString strDate = dt.toString("yyyy-MM-dd hh:mm:ss");

		dataModel->setItem(lognum, 0, new QStandardItem(strDate));
		dataModel->setItem(lognum, 1, new QStandardItem(strevent));
		lognum++;
//		qDebug()<<QString("time:%1  strevent:%2").arg(strDate).arg(strevent);
		QApplication::processEvents(); //刷新显示的文字内容
	}
	file.close();

	QString numstr;
	numstr.sprintf("%d", lognum);
	QString str = QString::fromUtf8(inall_str[lang]) + numstr + QString::fromUtf8(items_str[lang]);
	logNumLabel->setText(str);

	reading = 0;
}

void SniperShowlog::slotClean()
{
	if(QFile::remove("/opt/snipercli/event.log")) {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]), QString::fromUtf8(clearsuccess_str[lang]));
	} else {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]), QString::fromUtf8(clearfailed_str[lang]));
	}

	QFile file;
	file.setFileName("/opt/snipercli/event.log");
	if(!file.open(QIODevice::ReadWrite)) {
//		qDebug()<<QString("open file event.log error");
		return;
	}
	file.close();

	QTimer *timer = new QTimer();
	timer->singleShot(0, this, SLOT(slotCheck()));

}

void SniperShowlog::slotSave()
{
	int i;
	QString defaultFile;
	QString fileName;
	QFile file;

	if (reading) {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]), QString::fromUtf8(logreading_str[lang]));
		return;
	}

	char desktopdir[1024] = {0};
	char *homedir = getenv("HOME");

	snprintf(desktopdir, 1024, "%s/Desktop", homedir);
	if (access(desktopdir, F_OK) < 0) {
		snprintf(desktopdir, 1024, "%s/桌面", homedir);
		if (access(desktopdir, F_OK) < 0) {
			snprintf(desktopdir, 1024, "%s", homedir);
		}
	}
	defaultFile.sprintf("%s/sniper_eventlog.txt", desktopdir);
	//defaultFile.sprintf("%s/sniper_eventlog.txt", getenv("HOME"));
	fileName = QFileDialog::getSaveFileName(this,
						QString::fromUtf8(saveas_str[lang]),
						defaultFile,
						//QString::fromUtf8("文档(*.txt);;所有文件(*.*)"));
						QString::fromUtf8(document_str[lang]));

	if (fileName.isEmpty()) {
		return;
	}

	file.setFileName(fileName);
	if (!file.open(QIODevice::WriteOnly|QIODevice::Truncate)) {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]),
				QString::fromUtf8(exportfail_str[lang]));
		return;
	}

	QTextStream out(&file);
	out.setCodec("UTF-8");
	QModelIndex index;
	for (i = 0; i < lognum; i++) {
		index = dataModel->index(i,0);
		out << dataModel->data(index).toString();
		out << " ";
		index = dataModel->index(i,1);
		out << dataModel->data(index).toString();
		out << "\n";

	}
	file.close();

	QMessageBox::information(this, QString::fromUtf8(information_str[lang]),
			QString::fromUtf8(exportsuccess_str[lang]));
}

SniperShowlog::~SniperShowlog()
{
}
