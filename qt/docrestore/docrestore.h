#include "../common.h"
#include <QDialog>
#include <QDateTimeEdit>
#include <QTableView>
#include <QStandardItemModel>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QtDebug>
#include <QtSql>

#define TIME_DIFF	57600
#define DAY_SECOND	86400

#define SNIPER_DB               "/opt/snipercli/.filedb/encrypt.db"

class SniperDocrestore : public QDialog
{
    Q_OBJECT

public:
    explicit SniperDocrestore(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~SniperDocrestore();

private:
    QLabel *timeLabel;
    QDateTimeEdit *beginDateTimeEdit;
    QDateTimeEdit *endDateTimeEdit;
    QLabel *toLabel;
    QTableView *docTableView;
    QStandardItemModel* dataModel;
    QLabel *docNumLabel;
    QLabel *copyrightLabel;
    QLabel *blankLabel;
    QPushButton *restoreBtn;
    QPushButton *checkBtn;
    QPushButton *closeBtn;
    QVBoxLayout *mainLayout;
    QHBoxLayout *timeLayout;
    QHBoxLayout *btnLayout;
    int docnum;
    const char* encrypt_query_sql;

private slots:
    void slotRestore();
    void slotCheck();
};
