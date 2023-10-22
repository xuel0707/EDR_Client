#include "../common.h"
#include <QDialog>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>

class SniperStatus : public QDialog
{
    Q_OBJECT

public:
    explicit SniperStatus(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~SniperStatus();

private:
    QLabel *timeLabel;
    QLabel *nowLabel;
    QLabel *infoLabel;
    QTextEdit *statusTextEdit;
    QLabel *copyrightLabel;
    QLabel *blankLabel;
    QPushButton *saveBtn;
    QPushButton *checkBtn;
    QPushButton *closeBtn;
    QVBoxLayout *mainLayout;
    QGridLayout *infoLayout;
    QHBoxLayout *btnLayout;

public slots:
    void slotSave();
    void slotCheck();
};
