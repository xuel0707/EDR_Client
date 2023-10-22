#ifndef TRAY_H
#define TRAY_H

#include "../common.h"

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QAction>
#include <QActionGroup>

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = 0);

private:
    QSystemTrayIcon *systray;
    QMenu *traymenu;
    QAction *action_alarm;
    QAction *action_strategy;
    QAction *action_status;
    QAction *action_restore;
    QAction *action_user;
    QAction *action_uninstall;
    QAction *action_force_uninstall;
    QAction *action_separator;
    QAction *action_chinese;
    QAction *action_english;
    QActionGroup *actiongroup;

private slots:
    void hidetray();
    void showmenu();
    void showlog();
    void strategy();
    void status();
    void docrestore();
    void hostinfo();
    void uninstall();
    void force_uninstall();
    void chinese();
    void english();
};

#endif // TRAY_H
