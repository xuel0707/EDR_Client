#include "docrestore.h"
#include <QApplication>
#include <QMessageBox>
#include <QHeaderView>
#include <QTimer>
#include <QTextStream>
#include <QFile>
#include "../language.h"
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sqlite3.h"

const char *backuptime_str[2] = { "备份时间", "Backup time" };
const char *original_str[2] = { "原文件路径", "Original file path" };
const char *backpath_str[2] = { "备份路径", "Backup path" };
const char *backuprecovery_str[2] = { "备份恢复", "Restore" };
const char *date_str[2] = { "日期:", "Date:" };
const char *to_str[2] = { "至", "-" };
const char *read_str[2] = { "读取中...", "Reading..." };
const char *recovery_str[2] = { "恢复", "Restore" };
const char *refresh_str[2] = { "刷新", "Refresh" };
const char *close_str[2] = { "关闭", "Close" };
const char *total_str[2] = { "共0项", " 0 item" };
const char *nofile_str[2] = { "文件不存在", "No such file" };
const char *intotal_str[2] = { "共", "all of " };
const char *items_str[2] = { "项", " items" };
const char *information_str[2] = { "提示", "Information" };
const char *queryfail_str[2] = { "查询失败", "Query failed" };
const char *functobeimpl_str[2] = { "恢复功能待实现", "Restore not implemented" };
const char *norecover_str[2] = { "没有需要恢复的文件", "No file to restore" };
const char *open_log_failed_str[2] = { "打开日志文件失败", "Open log file failed" };
const char *open_database_failed_str[2] = { "打开数据库失败", "Open database failed" };
const char *query_datebase_failed_str[2] = { "查询数据库失败", "Query datebase failed" };
const char *recoversucc_str[2] = { "恢复成功", "Restore success" };
const char *totalfailure_str[2] = { "共失败", "Failed" };
const char *item_str[2] = { "条", "item" };
const char *logrecord_str[2] = { "日志记录在", "log is recorded in" };
const char *Banquan_str[2] ={ SNIPER_COPYRIGHT, SNIPER_COPYRIGHT_EN };

#define BACKUP_LOG_TMPDIR      "/tmp/.backup.tmp"
#define SQLITE_OPEN_MODE SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_SHAREDCACHE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE

sqlite3* encrypt_db = NULL;
const char crt_encrypt_tbl_sql[1024] =
{
	"CREATE TABLE IF NOT EXISTS encryptbackup( "
	"id integer PRIMARY KEY AUTOINCREMENT,"
	"mtime int,"                                 //上次备份时间
	"md5   varchar(4096),"                       //备份新文件名
	"path  varchar(4096));"                      //备份原文件名
};

const char* encrypt_query_sql = "select mtime, path, md5 from encryptbackup where mtime >=? and mtime <=? order by mtime desc;";
sqlite3_stmt* encrypt_query_stmt = NULL;

/* 实现QToolTip
1.设置鼠标跟随
table_view->setMouseTracking(true);
2.实现自定义槽函数
void TableView::showToolTip(const QModelIndex &index)
{
	if(!index.isValid())
		return;

	int row = index.row();
	QString file_name = list_file.at(row);

	if(file_name.isEmpty())
		return;

	QToolTip::showText(QCursor::pos(), file_name);
}
3.连接信号与槽
connect(this, &TableView::entered, this, &TableView::showToolTip);
*/

static int init_encrypt_db(void)
{
	int rc = 0;

	rc = sqlite3_open_v2(SNIPER_DB, &encrypt_db, SQLITE_OPEN_MODE, NULL);
	if (rc != SQLITE_OK) {
		return -1;
	}

	sqlite3_prepare_v2(encrypt_db, encrypt_query_sql, -1, &encrypt_query_stmt, NULL);
	return 0;
}

void fini_encrypt_db(void)
{
	if (encrypt_db == NULL) {
		return;
	}

	sqlite3_finalize(encrypt_query_stmt);
	sqlite3_close_v2(encrypt_db);
}

void init_dataModel(QTableView *docTableView, QStandardItemModel *dataModel)
{
	dataModel->setColumnCount(4);
	dataModel->setHeaderData(0, Qt::Horizontal, QString(""));
	dataModel->setHeaderData(1, Qt::Horizontal, QString::fromUtf8(backuptime_str[lang]));
	dataModel->setHeaderData(2, Qt::Horizontal, QString::fromUtf8(original_str[lang]));
	dataModel->setHeaderData(3, Qt::Horizontal, QString::fromUtf8(backpath_str[lang]));
	docTableView->setModel(dataModel);  //绑定数据模型
	//行高列宽要在绑定模型后设置才有效
	//QHeaderView::Stretch不管用，所以给每列先设个初始宽度
	docTableView->setColumnWidth(0, 30); //对第0列设置固定宽度
	docTableView->setColumnWidth(1, 160); //对第1列设置固定宽度
	docTableView->setColumnWidth(2, 160); //对第2列设置固定宽度
	docTableView->setColumnWidth(3, 160); //对第3列设置固定宽度
	docTableView->horizontalHeader()->setStretchLastSection(true); //最后一列填充最后的空白位置
	//docTableView->horizontalHeader()->setResizeMode(QHeaderView::Stretch);
	//docTableView->horizontalHeader()->setResizeMode(0, QHeaderView::Fixed);
	//docTableView->horizontalHeader()->setResizeMode(1, QHeaderView::Fixed);
	//docTableView->resizeColumnsToContents();
	//docTableView->verticalHeader()->setResizeMode(QHeaderView::ResizeToContents); //自动调整行高
}

SniperDocrestore::SniperDocrestore(QWidget *parent, Qt::WindowFlags f)
   : QDialog(parent, f)
{

	lang = get_language();

	setWindowTitle(QString::fromUtf8(backuprecovery_str[lang]));
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
	docNumLabel = new QLabel(QString::fromUtf8(read_str[lang]));
	docTableView = new QTableView;
	docTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置表格只读，不能进行编辑
	docTableView->setShowGrid(false);   //不显示网格线
	docTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft); //表头信息显示居左
	docTableView->verticalHeader()->hide();  //隐藏行表头（行表头即行号）
	docTableView->setAlternatingRowColors(true); //行背景色交替（默认白和灰）

	dataModel = new QStandardItemModel();
	init_dataModel(docTableView, dataModel);

	copyrightLabel = new QLabel(QString::fromUtf8(Banquan_str[lang]));
	copyrightLabel->setAlignment(Qt::AlignCenter);
	blankLabel = new QLabel;

	restoreBtn = new QPushButton(QString::fromUtf8(recovery_str[lang]));
	checkBtn = new QPushButton(QString::fromUtf8(refresh_str[lang]));
	closeBtn = new QPushButton(QString::fromUtf8(close_str[lang]));

	/* 按钮的布局 */
	btnLayout = new QHBoxLayout();
	btnLayout->addStretch(); //在按钮前插入一个占位符，使按钮能靠右对齐
	btnLayout->addWidget(restoreBtn);
	btnLayout->addWidget(checkBtn);
	btnLayout->addWidget(closeBtn);

	mainLayout = new QVBoxLayout(this);
	mainLayout->addLayout(timeLayout);
	mainLayout->addWidget(docTableView);
	mainLayout->addWidget(docNumLabel);
	mainLayout->addLayout(btnLayout);
	mainLayout->addWidget(blankLabel);
#ifndef HIDE_COPYRIGHT
	mainLayout->addWidget(copyrightLabel);
#endif

	if (init_encrypt_db() < 0) {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]), QString::fromUtf8(open_database_failed_str[lang]));
		qDebug()<<"open db failed";
	} else {
		qDebug()<<"open db success";
	}

	connect(restoreBtn, SIGNAL(clicked()), this, SLOT(slotRestore()));
	connect(checkBtn, SIGNAL(clicked()), this, SLOT(slotCheck()));
	connect(closeBtn, SIGNAL(clicked()), qApp, SLOT(quit()));
//	connect(beginDateTimeEdit, SIGNAL(dateTimeChanged(QDateTime)), this, SLOT(slotCheck()));
//	connect(endDateTimeEdit, SIGNAL(dateTimeChanged(QDateTime)), this, SLOT(slotCheck()));

	QTimer *timer = new QTimer();
	timer->singleShot(100, this, SLOT(slotCheck())); //等100毫秒主动做一次check
}

void SniperDocrestore::slotCheck()
{
	quint64 sec_start = 0;
	quint64 sec_end = 0;
	int mtime = 0;

	if(beginDateTimeEdit->dateTime().toTime_t() >= endDateTimeEdit->dateTime().toTime_t()) {
		docNumLabel->setText(QString::fromUtf8(total_str[lang]));
		return;
	}

	sec_start = (quint64)beginDateTimeEdit->dateTime().toTime_t();
	sec_end = (quint64)endDateTimeEdit->dateTime().toTime_t();


//	qDebug()<<"begindatetime"<<"==="<<(quint64)beginDateTimeEdit->dateTime().toTime_t();
//	qDebug()<<"enddatetime"<<"==="<<(quint64)endDateTimeEdit->dateTime().toTime_t();


	if (dataModel != NULL) {
		delete dataModel;
		dataModel = NULL;
	}
	docnum = 0;

	dataModel = new QStandardItemModel();
	init_dataModel(docTableView, dataModel);
	docNumLabel->setText(QString::fromUtf8(read_str[lang]));
	QApplication::processEvents(); //刷新显示的文字内容

	//查询时间和事件
	sqlite3_reset(encrypt_query_stmt);
	sqlite3_bind_int(encrypt_query_stmt, 1, sec_start);
	sqlite3_bind_int(encrypt_query_stmt, 2, sec_end);
	docnum = 0;
	while (sqlite3_step(encrypt_query_stmt) == SQLITE_ROW) {
		mtime = sqlite3_column_int(encrypt_query_stmt,0);
		const char *path = (const char *)sqlite3_column_text(encrypt_query_stmt,1);
		const char *md5 = (const char *)sqlite3_column_text(encrypt_query_stmt,2);
		QDateTime dt = QDateTime::fromTime_t(mtime);
		QString strDate = dt.toString("yyyy-MM-dd hh:mm:ss");

		//显示数据库事件
		QStandardItem *item = new QStandardItem();
		item->setCheckable(true);
		item->setCheckState(Qt::Unchecked);
		dataModel->setItem(docnum, 0, item);
		dataModel->setItem(docnum, 1, new QStandardItem(strDate));
		dataModel->setItem(docnum, 2, new QStandardItem(QString::fromUtf8(path)));
		dataModel->setItem(docnum, 3, new QStandardItem(QString::fromUtf8(md5)));
		docnum++;
		qDebug()<<QString("time:%1,oldfile:%2,newfile:%3 ").arg(strDate).arg(QString::fromUtf8(path)).arg(QString::fromUtf8(md5));
		QApplication::processEvents();
	}

	QString numstr;
	numstr.sprintf("%d", docnum);
	QString str = QString::fromUtf8(intotal_str[lang]) + numstr + QString::fromUtf8(items_str[lang]);
	docNumLabel->setText(str);
}

/* fp可能为NULL, 注意使用时的处理, fp为NULL时就不记录到文件 */
/* oldfile是备份前的文件，newfile是备份后的文件，恢复备份是把newfile恢复 */
/* 错误信息不输出备份后的文件，防止备份目录泄漏 */
int restore_file(int num, char *oldfile, char *newfile, FILE *fp)
{
	int ret = 0;
	struct stat st;
	off_t old_len = 0, new_len = 0;
	FILE *oldfp = NULL;
	FILE *newfp = NULL;
	char buf[512] = {0};
	int size = 0, len = 0;
	int i = num + 1;

	if (!oldfile || !newfile) {
		return -1;
	}

	if (stat(newfile, &st) < 0) {
		if (fp) {
			fprintf(fp, "Failed to restore %d item. reason:can not open backup file for (%s)\n", i, strerror(errno));
		}
		return -1;
	}

	new_len = st.st_size;

	newfp = fopen(newfile, "r");
	if (!newfp) {
		if (fp) {
			fprintf(fp, "Failed to restore %d item. reason:open backup file failed for (%s)\n", i, strerror(errno));
		}
		return -1;
	}

	oldfp = fopen(oldfile, "w+");
	if (!oldfp) {
		if (fp) {
			fprintf(fp, "Failed to restore %d item. reason:open %s failed for (%s)\n", i, oldfile, strerror(errno));
		}
		fclose(newfp);
		return -1;
	}

	while ((len = fread(buf, 1, sizeof(buf), newfp)) > 0) {
		size = fwrite(buf, 1, len, oldfp);
		if (size != len) {
			ret = -1;
			if (fp) {
				fprintf(fp, "Failed to restore %d item. reason:write %s len less then read backup file\n", i, oldfile);
			}
			break;
		}
		old_len += size;
	}
	fclose(oldfp);
	fclose(newfp);

	if (ret == 0 && old_len != new_len) {
		ret = -1;
		if (fp) {
			fprintf(fp, "Failed to restore %d item. reason:write %s size less then read backup file\n", i, oldfile);
		}
	}

	return ret;
}

void SniperDocrestore::slotRestore()
{
//	QMessageBox::information(this, QString::fromUtf8(information_str[lang]), QString::fromUtf8(functobeimpl_str[lang]));
	int row = docTableView->model()->rowCount();

	int i = 0;
	QModelIndex oldpath_index;
	QModelIndex newpath_index;
	QString oldpath;
	QString newpath;
	QFile file;
	int macth = 0;
	QString errstr;
	FILE *fp = NULL;
	char log_path[256] = {0};
	QString str;

	int ret = 0;
	int errnum = 0;

	snprintf(log_path, sizeof(log_path), "%s.%d", BACKUP_LOG_TMPDIR, getuid());
	fp = fopen(BACKUP_LOG_TMPDIR, "w+");

	for(i = 0; i < row; i++) {
		if(dataModel->item(i, 0)->checkState() == Qt::Checked) {
			macth = 1;
			oldpath_index = dataModel->index(i,2);
			oldpath = dataModel->data(oldpath_index).toString();

			newpath_index = dataModel->index(i,3);
			newpath = dataModel->data(newpath_index).toString();

			ret = restore_file(i, oldpath.toLocal8Bit().data(), newpath.toLocal8Bit().data(), fp);
			if (ret < 0) {
				errnum++;
			}
		}
	}
	if (fp) {
		fclose(fp);
	}

	if(row == 0 || macth == 0) {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]),
						QString::fromUtf8(norecover_str[lang]));
		return;
	}

	if(errnum == 0) {
		QMessageBox::information(this, QString::fromUtf8(information_str[lang]),
						QString::fromUtf8(recoversucc_str[lang]));
		return;
	}

	errstr.sprintf("%d", errnum);
	if (log_path[0] != 0) {
		str = QString::fromUtf8(totalfailure_str[lang]) + errstr + QString::fromUtf8(item_str[lang]) + \
		      QString::fromUtf8(logrecord_str[lang]) + QString::fromUtf8(log_path);
	} else {
		str = QString::fromUtf8(totalfailure_str[lang]) + errstr + QString::fromUtf8(item_str[lang]);
	}
	QMessageBox::information(this, QString::fromUtf8(information_str[lang]), str);
}

SniperDocrestore::~SniperDocrestore()
{
	fini_encrypt_db();
}
