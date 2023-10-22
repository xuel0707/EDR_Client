STRIP=strip
XDEFINES= -DLIBOPENSSL -DHAVE_PCRE -DHAVE_ZLIB -DHAVE_GCRYPT -DHAVE_MATH_H -DHAVE_SYS_PARAM_H
XLIBS= -lz -lssl -lcrypto libpcre.a
#-lpcre
#-lgcrypt
XLIBPATHS=-L/usr/lib -L/usr/local/lib -L/lib -L/lib64
XIPATHS= -I/usr/include
PREFIX=/usr/local
XHYDRA_SUPPORT=
STRIP=strip

HYDRA_LOGO=
PWI_LOGO=
SEC=-pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2

#
# Makefile for Hydra - (c) 2001-2020 by van Hauser / THC <vh@thc.org>
#
WARN_CLANG=-Wformat-nonliteral -Wstrncat-size -Wformat-security -Wsign-conversion -Wconversion -Wfloat-conversion -Wshorten-64-to-32 -Wuninitialized -Wmissing-variable-declarations  -Wmissing-declarations
WARN_GCC=-Wformat=2 -Wformat-overflow=2 -Wformat-nonliteral -Wformat-truncation=2 -Wnull-dereference -Wstrict-overflow=2 -Wstringop-overflow=4 -Walloca-larger-than=4096 -Wtype-limits -Wconversion -Wtrampolines -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -fno-common -Wcast-align
CFLAGS ?= -g
OPTS=-I. -O3 $(CFLAGS) -fcommon
# -Wall -g -pedantic
LIBS=-lm
DESTDIR ?=
BINDIR = /bin
MANDIR = /man/man1/
DATADIR = /etc

SRC = hydra-ssh.c hydra-sshkey.c hydra-ftp.c hydra-redis.c hydra-mod.c bfg.c hydra-xmpp.c hydra-time.c ntlm.c sasl.c
OBJ = hydra-ssh.o hydra-sshkey.o hydra-ftp.o hydra-redis.o hydra-mod.o bfg.o hydra-xmpp.o hydra-time.o ntlm.o sasl.o
BINS = hydra pw-inspector

EXTRA_DIST = README README.arm README.palm CHANGES TODO INSTALL LICENSE \
             hydra-mod.h hydra.h crc32.h d3des.h

all:	pw-inspector hydra $(XHYDRA_SUPPORT) 
	@echo

hydra:	hydra.c $(OBJ)
	$(CC) $(OPTS) $(SEC) $(LIBS) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o hydra $(HYDRA_LOGO) hydra.c $(OBJ) $(LIBS) $(XLIBS) $(XLIBPATHS) $(XIPATHS) $(XDEFINES)
	@echo
	@echo If men could get pregnant, abortion would be a sacrament
	@echo

pw-inspector: pw-inspector.c
	-$(CC) $(OPTS) $(SEC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o pw-inspector $(PWI_LOGO) pw-inspector.c

.c.o:	
	$(CC) $(OPTS) $(SEC) $(CFLAGS) $(CPPFLAGS) -c $< $(XDEFINES) $(XIPATHS)

strip:	all
	strip $(BINS)

clean:
	rm -rf xhydra pw-inspector hydra *.o core *.core *.stackdump *~ dev_rfc hydra.restore arm/*.ipk arm/ipkg/usr/bin/*

