CONFIG_MODULE_SIG=n

obj-m	:= sniper_edr.o
sniper_edr-objs := mem_trace.o entry.o msg.o common.o md5.o lookup_symbols.o procfs.o \
		check_privup.o lsm_hooks.o execve_hook.o antikill.o dirtycow_hook.o\
		dns.o netfilter_custom.o netfilter_custom_ipv6.o file_moni.o get_vfsmount.o \
		write_hook.o open_hook.o create_hook.o rename_hook.o link_hook.o unlink_hook.o ioctl_hook.o \
		setattr_hook.o send_recv_hook.o listen_hook.o radix.o

KERNELDIR := /lib/modules/$(shell uname -r)/build
#ZX20200812 交叉编译时指定内核头文件目录 cross compiling，如在银河麒麟4.0.2sp2上为sp4编译
#KERNELDIR := /usr/src/kylin-headers-4.4.131-20200529-generic
ifeq ($(KYLIN7), 1)
	KERNELDIR := /usr/src/kernels/4.4.13-200.nd7.1.x86_64
endif
ifeq ($(KYLIN6), 1)
	KERNELDIR := /usr/src/kernels/3.12.11-201.nk.1.x86_64
endif
PWD := $(shell pwd)

# Be careful that we shall let gcc use our own header files
# in directory @include IF and ONLY IF the target kernel does not
# already have them.

# 如果开发机禁止sh执行非白名单脚本，把sh script改为cat script | sh

all:
	@/bin/sh prepare_make
	@echo "building kernel module ..."
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	@echo "kernel module is generated."
	strip --strip-debug sniper_edr.ko

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@/bin/rm -f $(PWD)/monitor.*
	@/bin/rm -f netfilter_custom.c netfilter_custom_ipv6.c netfilter.o netfilter_ipv6.o 2>/dev/null
	@/bin/rm -f system_call.h nf_hookfn.h sniper_siginfo.h myipv6.h sniper_custom.h 2>/dev/null
	@/bin/rm -f *.o.ur-safe
