USER_DIR = user
KERNEL_DIR = kern
DIST_DIR = dist
TOOLS_DIR = tools
LIBS_DIR = libs
QT_DIR = qt
HYDRA = external/hydra_9.2

EBPF_DIR = sniper-ebpf
EBPF_EXECVE_HOOK_PROGRAM = lsm_kern.o
EBPF_FILE_HOOK_PROGRAM = ebpf_file_kern.o

# 如果开发机禁止sh执行非白名单脚本，把sh script改为cat script | sh

# NOTE(luoyinhong): disabled avira
# AVIRA := $(shell cd user/;sh make_avira)

all: ebpf user hydra
	mkdir -p ${DIST_DIR}
	cp user/sniper ${DIST_DIR}
	cp user/assist_sniper ${DIST_DIR}
	cp sniper-ebpf/${EBPF_EXECVE_HOOK_PROGRAM} ${DIST_DIR}
ifeq ($(AVIRA), 1)
	cp user/sniper_antivirus ${DIST_DIR}
endif
	cp user/systeminformation ${DIST_DIR}
	cp user/sniper.a ${DIST_DIR}
	cp tools/sniper_cron ${DIST_DIR}
	cp tools/sniper_chk ${DIST_DIR}
	cp tools/assist_sniper_chk ${DIST_DIR}
	cp external/hydra_9.2/hydra ${DIST_DIR}/sniper_chkweakpasswd
	strip -s ${DIST_DIR}/sniper_chkweakpasswd
	@/bin/sh check_sniper_strip

nokern: user tray hydra
	mkdir -p ${DIST_DIR}
	cp user/sniper ${DIST_DIR}
	cp user/assist_sniper ${DIST_DIR}
ifeq ($(AVIRA), 1)
	cp user/sniper_antivirus ${DIST_DIR}
endif
	cp user/systeminformation ${DIST_DIR}
	cp user/sniper.a ${DIST_DIR}
	cp tools/sniper_cron ${DIST_DIR}
	cp tools/sniper_chk ${DIST_DIR}
	cp tools/assist_sniper_chk ${DIST_DIR}
	cp ${QT_DIR}/dist/* ${DIST_DIR}
	cp external/hydra_9.2/hydra ${DIST_DIR}/sniper_chkweakpasswd
	strip -s ${DIST_DIR}/sniper_chkweakpasswd
	@/bin/sh check_sniper_strip

libs:
	make -C ${LIBS_DIR}

libs-clean:
	make -C ${LIBS_DIR} clean

user: 
	@/bin/sh remove_user_makefile_lz
	make -C ${USER_DIR}
	@echo "user service is generated"

user-clean:
	make -C ${USER_DIR} clean

ebpf:
	make -C ${EBPF_DIR}
	@echo "ebpf program is generated"	

ebpf-clean:
	make -C ${EBPF_DIR} clean
	@echo "TODO: impl. ebpf-clean"

kernel:
	make -C ${KERNEL_DIR}
	@echo "kernel module is generated"

kernel-clean:
	make -C ${KERNEL_DIR} clean

tools: 
	make -C ${TOOLS_DIR}
	@echo "tools is generated"

tools-clean:
	make -C ${TOOLS_DIR} clean

tray:
	make -C ${QT_DIR}
	@echo "qt tray is generated"

tray-clean:
	make -C ${QT_DIR} clean

hydra:
	make -C ${HYDRA}
	@echo "hydra is generated"

hydra-clean:
	make -C ${HYDRA} clean

clean: user-clean ebpf-clean hydra-clean
	-rm -rf ${DIST_DIR} avira.h 2> /dev/null
	rm -rf deb/sniper/etc  deb/sniper/lib  deb/sniper/opt  deb/sniper/sbin
	make -C ${QT_DIR} clean

.PHONY: all clean user user-clean kernel kernel-clean tools tools-clean libs libs-clean
