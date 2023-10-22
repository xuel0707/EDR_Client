#
# make编译出的程序带内存越界和内存泄露检查（要求gcc版本>4.8.x）
# 如果执行程序不起来，试试LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.3 ./sniper -n 10
# 其中，/usr/lib/x86_64-linux-gnu/libasan.so.3是libasan库的路径，10是让sniper运行10分钟
#
# 正式发布时make RELEASE=1
#

CC = gcc
CFLAGS = -Wall -Wredundant-decls -Wundef -Wcast-align -Wpointer-arith -Wcast-qual -Winline -Wstrict-prototypes -I. -I./lib/zlib
SQLITE_CFLAGS = -Wall -Wredundant-decls -Wundef -Wcast-align -Wpointer-arith -Winline -Wstrict-prototypes -I.

LIBBPF_DIR = ../sniper-ebpf/libbpf
LIBBPF_DIST_DIR = $(LIBBPF_DIR)/dist
LIBBPF_DIST_LIB_DIR = $(LIBBPF_DIST_DIR)/usr/lib64

CFLAGS += -I$(LIBBPF_DIST_DIR)/usr/include -Wl,-rpath=$(LIBBPF_DIST_LIB_DIR)

ifeq ($(TEST), 1)
	CFLAGS += -DTEST
endif
ifeq ($(LOCAL), 1)
	CFLAGS += -DLOCAL
endif

#LIBS =  -lcurl -lpthread -lssl -lcrypto -lz -lresolv -lsqlite3
LIBS =  -L$(LIBBPF_DIST_LIB_DIR) -lcurl -lpthread -lssl -lcrypto -lz -lresolv -ldl -lcrypt -lbpf -lelf
#LIBS = -Wl,-dn -L/root -lcurl -lpcap -Wl,-dy -lpthread -lcrypto -lz -lresolv -lssl -lrt
LDFLAG = ${LIBS}

ifeq ($(RELEASE), 1)
	CFLAGS += -g
else
	CFLAGS += -fsanitize=address -fsanitize=leak -g
	SQLITE_CFLAGS += -fsanitize=address -fsanitize=leak -g
	LDFLAG += -lasan
endif

# for redhat5
FILE = /usr/lib64/libresolv.a
ifeq ($(FILE), $(wildcard $(FILE)))
	LIBRESV = /usr/lib64/libresolv.a
endif

SNIPER_FILE = main.o
TARGET = sniper

# NOTE(luoyinhong): deleted kmod.o
OBJ =  sysinfo.o serverconf.o strcodec.o msg_queue.o \
	kexec_msg_queue.o kfile_msg_queue.o knet_msg_queue.o \
	net.o net_strategy.o \
	httppost.o download.o update.o selfcheck.o cJSON.o \
	file_type.o logger.o get_process_status.o hash_file.o \
	dmidecode.o common.o process.o tools.o \
	get_fileinfo_from_dpkginfo.o process_strategy.o \
	file.o login.o port_forwarding.o burn_mgr.o usb.o \
	sqlutil.o inotify.o check_group.o check_user.o check_app_user.o uevent.o \
	task.o websocket.o ws_comm.o conf.o policy.o file_policy.o rule.o printer.o check_conn.o  check_pid_stat.o \
	check_sys_danger.o blackmail_protect.o baseline.o self_resource_check.o check_application_risk.o log_send.o kebpf.o

ASSIST_FILE = assist.o
ASSIST = assist_sniper
ASSIST_OBJ = cJSON.o logger.o httppost.o common.o serverconf.o hash_file.o sysinfo.o dmidecode.o

ANTIVIRUS_IFNO = antivirus
ANTIVIRUS_FILE = antivirus/sniper_antivirus.o
ANTIVIRUS = sniper_antivirus
ANTIVIRUS_OBJ = cJSON.o \
	    $(ANTIVIRUS_IFNO)/scan.o $(ANTIVIRUS_IFNO)/logger.o $(ANTIVIRUS_IFNO)/virus_msg_queue.o \
	    $(ANTIVIRUS_IFNO)/common.o $(ANTIVIRUS_IFNO)/hash_file.o $(ANTIVIRUS_IFNO)/sqlutil.o \
	    $(ANTIVIRUS_IFNO)/trust.o $(ANTIVIRUS_IFNO)/policy.o $(ANTIVIRUS_IFNO)/handle_msg_queue.o \
	    $(ANTIVIRUS_IFNO)/sysinfo.o $(ANTIVIRUS_IFNO)/http.o $(ANTIVIRUS_IFNO)/operate.o

SYS_INFO = system_info
ASSET_FILE = system_info/asset_list.o
ASSET = systeminformation
ASSET_OBJ = cJSON.o \
            $(SYS_INFO)/sys_hardware.c $(SYS_INFO)/sys_system.c $(SYS_INFO)/sys_web_info.c \
            $(SYS_INFO)/sys_db_op.c $(SYS_INFO)/process_info.c $(SYS_INFO)/database_info.c \
	    $(SYS_INFO)/sys_get_rpm_info.c $(SYS_INFO)/sys_get_deb_info.c \
	    $(SYS_INFO)/sys_memory.c $(SYS_INFO)/sys_disk.c $(SYS_INFO)/dmi.c $(SYS_INFO)/cron.c

ZLIB_INFO = lib/zlib
ZLIB_OBJ = $(ZLIB_INFO)/ioapi.o $(ZLIB_INFO)/unzip.o $(ZLIB_INFO)/miniunz.o

# 如果开发机禁止sh执行非白名单脚本，把sh script改为cat script | sh
DEBIAN := $(shell sh make_system_type_header)
ifeq ($(DEBIAN), 0)
	LIBS += -ldb
	OBJ += get_fileinfo_from_rpmdb.o
endif

AVIRA_LIBS_DIR = ./lib
AVIRA := $(shell sh make_avira)
ifeq ($(AVIRA), 1)
	LIBS += -Wl,-rpath-link,$(AVIRA_LIBS_DIR) -L$(AVIRA_LIBS_DIR) -lsavapi
	OBJ += virusfilter.o antivirus.o kvirus_msg_queue.o virus_msg_queue.o
endif

ifeq ($(AVIRA), 1)
all: sniper asset assist sniper_antivirus
else
all: sniper asset assist
endif
	dd if=/dev/zero of=sniper.a bs=2 count=1
ifeq ($(AVIRA), 1)
	tar jcf tmp.tar.bz2 ${TARGET} ${ASSET} ${ASSIST} ${ANTIVIRUS}
else
	tar jcf tmp.tar.bz2 ${TARGET} ${ASSET} ${ASSIST}
endif
	cat tmp.tar.bz2 >> sniper.a
	rm -f tmp.tar.bz2
ifeq ($(RELEASE), 1)
ifeq ($(AVIRA), 1)
	strip -s ${TARGET} ${ASSET} ${ASSIST} ${ANTIVIRUS}
else
	strip -s ${TARGET} ${ASSET} ${ASSIST}
endif
endif

sniper: ${SNIPER_FILE} ${OBJ} ${ZLIB_OBJ} sqlite3.o
	${CC} ${SNIPER_FILE} ${OBJ} ${ZLIB_OBJ} sqlite3.o libpcre.a ${LDFLAG} ${LIBRESV} -o ${TARGET} -Wl,-rpath-link,$(LIBS_DIR) -L$(LIBS_DIR) -lsavapi
ifeq ($(AVIRA), 0)
	@echo "Warning: avira not supported"
endif
	@echo "sniper generated"
	@echo ""

asset: ${ASSET_FILE} sqlite3.o
	${CC} ${ASSET_FILE} ${ASSET_OBJ} sqlite3.o libpcre.a ${LDFLAG} ${LIBRESV} -I./ -o ${ASSET}
	@echo "systeminfomation generated"
	@echo ""

assist: ${ASSIST_FILE} ${ASSIST_OBJ}
	${CC} ${ASSIST_FILE} ${ASSIST_OBJ} ${LDFLAG} ${LIBRESV} -o ${ASSIST}
	@echo "sniper_assist generated"
	@echo ""

sniper_antivirus: ${ANTIVIRUS_FILE} ${ANTIVIRUS_OBJ} sqlite3.o
	${CC} ${ANTIVIRUS_FILE} ${ANTIVIRUS_OBJ} ${ZLIB_OBJ} sqlite3.o ${LDFLAG} ${LIBRESV} -o ${ANTIVIRUS}
	@echo "sniper_antivirus generated"
	@echo ""

sqlite3.o:
	${CC} ${SQLITE_CFLAGS} -c -o sqlite3.o sqlite3.c

clean:
	-rm -f system_type.h avira.h 2> /dev/null
	-rm -f *.o sniper.a 2> /dev/null
	-rm -f ${TARGET} ${SNIPER_FILE} 2> /dev/null
	-rm -f ${ASSET} ${ASSET_FILE} 2> /dev/null
	-rm -f ${ASSIST} ${ASSIST_FILE} 2> /dev/null
	-rm -f ${ANTIVIRUS} ${ANTIVIRUS_FILE} ${ANTIVIRUS_OBJ} ${ZLIB_OBJ} 2> /dev/null

.PHONY: all clean
