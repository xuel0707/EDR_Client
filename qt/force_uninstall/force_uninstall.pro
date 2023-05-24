QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniper_force_uninstall
TEMPLATE = app


SOURCES += main.cpp force_uninstall.cpp

HEADERS  += force_uninstall.h

LIBS += -lcrypto
