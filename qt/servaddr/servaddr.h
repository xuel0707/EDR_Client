#include "../common.h"
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QGridLayout>

extern int hostname_to_ip(char *hostname, char *ip, int ip_len);
extern void read_servaddr(unsigned short *port, char *server, int server_len, char *file);
extern int save_servaddr(unsigned short port, char *server, char *file);

class ServAddr : public QDialog
{
    Q_OBJECT

public:
    explicit ServAddr(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~ServAddr();

private:
    QLabel *serveripLabel;
    QLineEdit *serveripLineEdit;
    QLabel *serverportLabel;
    QLineEdit *serverportLineEdit;
    QLabel *langLabel;
    QComboBox *langComboBox;
    QLabel *blankLabel;
    QPushButton *okBtn;
    QPushButton *cancelBtn;
    QGridLayout *mainLayout;

    QString serverip;
    QString serverport;

public slots:
    void slotOk();
    void slotTrans();
};
