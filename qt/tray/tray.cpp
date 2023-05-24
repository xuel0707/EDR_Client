#include "tray.h"
#include <QMenu>
#include <QCursor>
#include <QMessageBox>
#include <QProcess>
#include <QTimer>
#include <unistd.h>
#include <stdio.h>
#include <QtDebug>
#include "../language.h"

const char *alarm_str[2] = { "告警日志", "Alarm log" };
const char *strategy_str[2] = { "安全策略", "Security strategy" };
const char *status_str[2] = { "运行状况", "Running status" };
const char *restore_str[2] = { "恢复文档", "Restore document" };
const char *user_str[2] = { "用户注册", "User register" };
const char *uninstall_str[2] = { "软件卸载", "Uninstall" };
const char *force_uninstall_str[2] = { "强制卸载", "Force uninstall" };
const char *error_str[2] = { "错误", "Error" };
const char *alarmerror_str[2] = { "告警日志程序错误", "Alarmlog program error" };
const char *strategyerror_str[2] = { "安全策略程序错误", "Strategy program error" };
const char *statuserror_str[2] = { "运行状况程序错误", "Status program error" };
const char *restoreerror_str[2] = { "恢复文档程序错误", "Restore program error" };
const char *usererror_str[2] = { "用户注册程序错误", "Register program error" };
const char *uninstallerror_str[2] = { "软件卸载程序错误", "Uninstall program error" };
const char *force_uninstallerror_str[2] = { "强制卸载程序错误", "Force uninstall program error" };
const char *product_name_str[2] = { SNIPER_PRODUCT, SNIPER_PRODUCT_EN };

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    //托盘菜单

    lang = get_language();
    systray = new QSystemTrayIcon(this);
    systray->setToolTip(QString::fromUtf8(product_name_str[lang]));
    systray->setIcon(QIcon("/opt/snipercli/sniper.png"));
    systray->setVisible(false);


    traymenu = new QMenu(this);
    traymenu->setMinimumWidth(130); //协调菜单界面长宽比例，使得菜单界面不显得太瘦窄

    action_alarm = new QAction(QString::fromUtf8(alarm_str[lang]),traymenu);
    action_strategy = new QAction(QString::fromUtf8(strategy_str[lang]),traymenu);
    action_status = new QAction(QString::fromUtf8(status_str[lang]),traymenu);
    action_restore = new QAction(QString::fromUtf8(restore_str[lang]),traymenu);
    action_user = new QAction(QString::fromUtf8(user_str[lang]),traymenu);
    action_uninstall = new QAction(QString::fromUtf8(uninstall_str[lang]),traymenu);
    action_force_uninstall = new QAction(QString::fromUtf8(force_uninstall_str[lang]),traymenu);

    action_chinese = new QAction(QString::fromUtf8("中文"),traymenu);
    action_english = new QAction(QString::fromUtf8("English"),traymenu);

    actiongroup = new QActionGroup(this);

    action_chinese->setCheckable(true);
    action_english->setCheckable(true);

//  traymenu->addAction(action_alarm);
    traymenu->addAction(action_strategy);
    traymenu->addAction(action_status);
    traymenu->addAction(action_restore);
    traymenu->addAction(action_user);
    traymenu->addAction(action_uninstall);
    traymenu->addAction(action_force_uninstall);

    //action_separator = new QAction(QString::fromUtf8(""),traymenu);
    //action_separator->setSeparator(true);
    //traymenu->addAction(action_separator);
    traymenu->addSeparator(); //用addSeparator替代addAction(action_separator)

    traymenu->addAction(actiongroup->addAction(action_chinese));
    traymenu->addAction(actiongroup->addAction(action_english));
    if (lang == 0) {
        action_chinese->setChecked(true);
    } else {
        action_english->setChecked(true);
    }

    systray->setContextMenu(traymenu);
    /* kylin7遇到登录后看不到托盘图标的问题。延迟5秒起托盘程序 */
    //systray->show();


    connect(action_alarm, SIGNAL(triggered(bool)), this, SLOT(showlog()));
    connect(action_strategy, SIGNAL(triggered(bool)), this, SLOT(strategy()));
    connect(action_status, SIGNAL(triggered(bool)), this, SLOT(status()));
    connect(action_restore, SIGNAL(triggered(bool)), this, SLOT(docrestore()));
    connect(action_user, SIGNAL(triggered(bool)), this, SLOT(hostinfo()));
    connect(action_uninstall, SIGNAL(triggered(bool)), this, SLOT(uninstall()));
    connect(action_force_uninstall, SIGNAL(triggered(bool)), this, SLOT(force_uninstall()));

    connect(action_chinese, SIGNAL(triggered(bool)), this, SLOT(chinese()));
    connect(action_english, SIGNAL(triggered(bool)), this, SLOT(english()));

    connect(systray, SIGNAL(activated(QSystemTrayIcon::ActivationReason)), this, SLOT(showmenu()));

    QTimer *timer = new QTimer();
    connect(timer, SIGNAL(timeout()), this, SLOT(hidetray()));
    timer->start(5000); //5秒检测一次
}

void MainWindow::chinese()
{
	lang = 0;
	remember_language("Chinese");
	action_alarm->setText(QString::fromUtf8(alarm_str[lang]));
	action_strategy->setText(QString::fromUtf8(strategy_str[lang]));
	action_status->setText(QString::fromUtf8(status_str[lang]));
	action_restore->setText(QString::fromUtf8(restore_str[lang]));
	action_user->setText(QString::fromUtf8(user_str[lang]));
	action_uninstall->setText(QString::fromUtf8(uninstall_str[lang]));
	action_force_uninstall->setText(QString::fromUtf8(force_uninstall_str[lang]));
	action_chinese->setText(QString::fromUtf8("中文"));
}

void MainWindow::english()
{
	lang = 1;
	remember_language("English");
	action_alarm->setText(QString::fromUtf8(alarm_str[lang]));
	action_strategy->setText(QString::fromUtf8(strategy_str[lang]));
	action_status->setText(QString::fromUtf8(status_str[lang]));
	action_restore->setText(QString::fromUtf8(restore_str[lang]));
	action_user->setText(QString::fromUtf8(user_str[1]));
	action_uninstall->setText(QString::fromUtf8(uninstall_str[lang]));
	action_force_uninstall->setText(QString::fromUtf8(force_uninstall_str[lang]));
	action_chinese->setText(QString::fromUtf8("Chinese"));
}

/* 默认地，显示托盘程序，除非策略指示不显示 */
/* 考虑到启动托盘程序的复杂性，主要是环境变量要求，总是启动托盘程序，只是根据策略隐藏或显示 */
void MainWindow::hidetray()
{
	/* /opt/snipercli不存在，隐藏托盘 */
	if (access("/opt/snipercli", F_OK) < 0) {
		if (systray->isVisible()) {
			systray->hide(); //和setVisible(false)同样效果
		}
		return;
	}

	/* 策略指示不显示托盘，隐藏托盘 */
	if (access("/opt/snipercli/lst.conf.notshowtray", F_OK) == 0) {
		if (systray->isVisible()) {
			systray->hide();
		}
		return;
	}

	if (!systray->isVisible()) {
		if (access("/opt/snipercli/sniper.png", F_OK) < 0) {
			return;
		}
		/* 目前升级时不重启托盘，但sniper.png文件已改变，重新setIcon */
		//TODO
    		systray->setIcon(QIcon("/opt/snipercli/sniper.png"));
		systray->show();
	}
}

void MainWindow::showmenu()
{
	traymenu->popup(mapToGlobal(QCursor::pos()));
}

void MainWindow::showlog()
{
	QProcess proc;

	if (proc.startDetached(PROG_SHOWLOG) == false) {
		QMessageBox::critical(this, QString::fromUtf8(error_str[lang]),
			QString::fromUtf8(alarmerror_str[lang]));
	}
}

void MainWindow::strategy()
{
	QProcess proc;

	if (proc.startDetached(PROG_STRATEGY) == false) {
		QMessageBox::critical(this, QString::fromUtf8(error_str[lang]),
			QString::fromUtf8(strategyerror_str[lang]));
	}
}

void MainWindow::status()
{
	QProcess proc;

	if (proc.startDetached(PROG_STATUS) == false) {
		QMessageBox::critical(this, QString::fromUtf8(error_str[lang]),
			QString::fromUtf8(statuserror_str[lang]));
	}
}

void MainWindow::docrestore()
{
	QProcess proc;

	if (proc.startDetached(PROG_DOCRESTORE) == false) {
		QMessageBox::critical(this, QString::fromUtf8(error_str[lang]),
			QString::fromUtf8(restoreerror_str[lang]));
	}
}

void MainWindow::hostinfo()
{
	QProcess proc;

	if (proc.startDetached(PROG_HOSTINFO) == false) {
		QMessageBox::critical(this, QString::fromUtf8(error_str[lang]),
			QString::fromUtf8(usererror_str[lang]));
	}
}

void MainWindow::uninstall()
{
	QProcess proc;

	if (proc.startDetached(PROG_UNINSTALL) == false) {
		QMessageBox::critical(this, QString::fromUtf8(error_str[lang]),
			QString::fromUtf8(uninstallerror_str[lang]));
	}
}

void MainWindow::force_uninstall()
{
	QProcess proc;

	if (proc.startDetached(PROG_FORCE_UNINSTALL) == false) {
		QMessageBox::critical(this, QString::fromUtf8(error_str[lang]),
			QString::fromUtf8(force_uninstallerror_str[lang]));
	}
}
