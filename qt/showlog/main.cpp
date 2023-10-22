#include "showlog.h"
#include <QApplication>
#include <stdlib.h>
#include "../single.h"

int main(int argc, char *argv[])
{
    if (is_this_running("showlog") > 0) {
        return 1;
    }

    QApplication a(argc, argv);
    SniperShowlog w;
    w.show();

    return a.exec();
}
