#include "../common.h"
#include <QDialog>
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>

class HostInfo : public QDialog
{
    Q_OBJECT

public:
    explicit HostInfo(QWidget *parent = 0, Qt::WindowFlags f = 0);
    ~HostInfo();

private:
    QLabel *usernameLabel;
    QLineEdit *usernameLineEdit;
    QLabel *phoneLabel;
    QLineEdit *phoneLineEdit;
    QLabel *departmentLabel;
    QLineEdit *departmentLineEdit;
    QLabel *companyLabel;
    QLineEdit *companyLineEdit;
    QLabel *emailLabel;
    QLineEdit *emailLineEdit;
    QLabel *assets_numberLabel;
    QLineEdit *assets_numberLineEdit;
    QLabel *locationLabel;
    QLineEdit *locationLineEdit;
    QPushButton *sendBtn;
    QPushButton *cancelBtn;

    QVBoxLayout *mainLayout;
    QGridLayout *infoLayout;
    QHBoxLayout *btnLayout;

    QString username;
    QString phone;
    QString department;
    QString company;
    QString email;
    QString assets_number;
    QString location;

public slots:
    void slotSend();
};
