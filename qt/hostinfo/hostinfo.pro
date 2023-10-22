QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniper_hostinfo
TEMPLATE = app


SOURCES += main.cpp hostinfo.cpp cJSON.c

HEADERS  += hostinfo.h cJSON.h

LIBS += -lcurl -lssl -lcrypto
