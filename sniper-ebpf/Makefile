TARGET := sniper-ebpf
USER := lsm_user
KERN := lsm_kern

SRC_DIR = $(shell realpath .)
LIBBPF_DIR = $(SRC_DIR)/libbpf
LIBBPF_SRC_DIR = $(LIBBPF_DIR)/src
LIBBPF_DIST_DIR = $(LIBBPF_DIR)/dist
LIBBPF_DIST_LIB_DIR = $(LIBBPF_DIST_DIR)/usr/lib64

CFLAGS ?= -I$(LIBBPF_DIST_DIR)/usr/include
LDFLAGS ?= -L$(LIBBPF_DIST_LIB_DIR)
LIBS = -lbpf -lelf

all: libbpf vmlinux.h $(TARGET) $(KERN).o

$(TARGET): %: $(USER).c Makefile
	gcc $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(USER).c -Wl,-rpath=$(LIBBPF_DIST_LIB_DIR) $(LIBS)

$(KERN).o: $(KERN).c
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g $(KERN).c
	llc -march=bpf -filetype=obj -o $(KERN).o $(KERN).ll

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