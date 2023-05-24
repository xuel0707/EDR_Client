#include "../common.h"
#include <QDialog>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>

#define STRATEGYNUM 6

class SniperStrategy : public QDialog
{
    Q_OBJECT

public:
    explicit SniperStrategy(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~SniperStrategy();

private:
    QLabel *timeLabel;
    QLabel *timeValueLabel;
    QLabel *nameLabel;
    QLabel *nameValueLabel;
    QLabel *typeLabel;
    QComboBox *typeComboBox;
    QLabel *infoLabel;
    QTextEdit *infoTextEdit;
    QLabel *copyrightLabel;
    QLabel *blankLabel;
    QPushButton *saveBtn;
    QPushButton *checkBtn;
    QPushButton *closeBtn;
    QVBoxLayout *mainLayout;
    QGridLayout *infoLayout;
    QHBoxLayout *btnLayout;
    struct strategyinfo {
        QString desc;
        QString filename;
        QString strategy;
        int desclen;
        int strategylen;
    } strategyInfo[STRATEGYNUM];

private slots:
    void slotSave();
    void slotCheck();
    void slotShow();
};
