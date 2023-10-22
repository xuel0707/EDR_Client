#include "../common.h"
#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QIcon>
#include <QTextBrowser>

class SniperUninstall : public QDialog
{
    Q_OBJECT

public:
    explicit SniperUninstall(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~SniperUninstall();

private:
    QLabel *infoLabel;
    QLabel *blankLabel;
    QIcon *infoIcon;
    QPushButton *okBtn;
    QPushButton *cancelBtn;
    QHBoxLayout *infoLayout;
    QHBoxLayout *btnLayout;
    QVBoxLayout *mainLayout;
    QTextBrowser *statusTextBrowser;

private slots:
    void slotUninstall();
};
