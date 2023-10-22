TARGET := sniper-ebpf
USER := lsm_user
KERN := lsm_kern ebpf_file_kern ebpf_net_kern  # Fill the target kern files name in this VAR.
KERN_C_FILES = $(foreach kern_file, $(KERN), $(kern_file).c)

SRC_DIR = $(shell realpath .)
LIBBPF_DIR = $(SRC_DIR)/libbpf
LIBBPF_SRC_DIR = $(LIBBPF_DIR)/src
LIBBPF_DIST_DIR = $(LIBBPF_DIR)/dist
LIBBPF_DIST_LIB_DIR = $(LIBBPF_DIST_DIR)/usr/lib64

CFLAGS ?= -I$(LIBBPF_DIST_DIR)/usr/include
LDFLAGS ?= -L$(LIBBPF_DIST_LIB_DIR)
LIBS = -lbpf -lelf

all: libbpf vmlinux.h $(TARGET) kern.o

$(TARGET): %: $(USER).c Makefile
	gcc $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(USER).c -Wl,-rpath=$(LIBBPF_DIST_LIB_DIR) $(LIBS)

kern.o: $(KERN_C_FILES)
	for x in $(KERN); do \
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-D __TARGET_ARCH_x86 \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g $$x.c; \
	llc -march=bpf -filetype=obj -o $$x.o $$x.ll ;\
	done

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

libbpf:
	$(MAKE) --directory=$(LIBBPF_SRC_DIR) all
	DESTDIR=$(LIBBPF_DIST_DIR) $(MAKE) --directory=$(LIBBPF_SRC_DIR) install

clean:
	rm -f $(TARGET)
	rm -f *.o
	rm -f *.ll

cleanvm:
	rm -f vmlinux.h


.PHONY: libbpf clean all