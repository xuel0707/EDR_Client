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

class SniperShowlog : public QDialog
{
    Q_OBJECT

public:
    explicit SniperShowlog(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~SniperShowlog();

private:
    QLabel *timeLabel;
    QDateTimeEdit *beginDateTimeEdit;
    QDateTimeEdit *endDateTimeEdit;
    QLabel *toLabel;
    QTableView *logTableView;
    QStandardItemModel* dataModel;
    QLabel *logNumLabel;
    QLabel *copyrightLabel;
    QLabel *blankLabel;
    QPushButton *saveBtn;
    QPushButton *checkBtn;
    QPushButton *cleanBtn;
    QPushButton *closeBtn;
    QVBoxLayout *mainLayout;
    QHBoxLayout *timeLayout;
    QHBoxLayout *btnLayout;
    int lognum;
    int reading;

private slots:
    void slotSave();
    void slotCheck();
    void slotClean();
};

