#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QIcon>
#include <QTextBrowser>
#include <QLineEdit>

#include <stdlib.h>
#include "../common.h"

class SniperForceUninstall : public QDialog
{
    Q_OBJECT

public:
    explicit SniperForceUninstall(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~SniperForceUninstall();

private:
    QPushButton *codeBtn;
    QLabel *inputLabel;
    QLineEdit *codeLineEdit;
    QLineEdit *inputLineEdit;
    QGridLayout *infoLayout;

    QTextBrowser *statusTextBrowser;

    QPushButton *okBtn;
    QPushButton *cancelBtn;

    QLabel *copyrightLabel;
    QVBoxLayout *mainLayout;
    QHBoxLayout *btnLayout;

private slots:
    void slotUninstall();
    void SniperUninstall();
    void getcode();
    void codeuninstall();
    int compare_uninstall_code(char *token);

};
