QT       += core gui sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniper_docrestore
TEMPLATE = app


SOURCES += main.cpp docrestore.cpp sqlite3.c

HEADERS  += docrestore.h sqlite3.h

LIBS += -ldl
