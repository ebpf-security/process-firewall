#
# $Id: Makefile,v 1.1.1.1 2024/01/12 21:31:20  Exp $

srcdir          = .

install_prefix  =
prefix          = /usr/local
exec_prefix	= ${prefix}
sbindir         = ${exec_prefix}/sbin
mandir		= ${prefix}/man

CC	= gcc
CFLAGS	= -c -g -O2  -DHAVE_NET_ETHERNET_H -DLIBNET_LIL_ENDIAN  -I./libbpf/ 
LDFLAGS	= 

PCAPINC = 
PCAPLIB = -lpthread  ./libbpf/libbpf.a -lelf -lz -lpcap

ifneq ($(use_pfring),)
PCAPLIB =  -lpcap -lrt  -lpfring
endif

LNETINC = 
LNETLIB = 

NIDSINC = 
NIDSLIB = 

DBINC	= 
DBLIB	= 

X11INC	=  -I/usr/X11R6/include
X11LIB	=  -L/usr/X11R6/lib  -lSM -lICE -lXmu -lX11 

INCS	= $(NIDSINC) $(PCAPINC) $(LNETINC) $(DBINC) -I$(srcdir)/missing $(X11INC)
LIBS	= $(NIDSLIB) $(PCAPLIB) $(LNETLIB) -lm

INSTALL	= /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA	= ${INSTALL} -m 644

HDRS	=           

SRCS	= main.c

OBJS =  $(SRCS:.c=.o)

PROGS = ebpf-dump

ebpf-dump:                 main.o 
	$(CC) $(LDFLAGS) -o $@  main.o  $(LIBS) 

install:
	$(INSTALL) -d $(install_prefix)$(sbindir)
	$(INSTALL_PROGRAM) -m 755 $(PROGS) $(install_prefix)$(sbindir)
	$(INSTALL) -d $(install_prefix)$(mandir)/man8
	$(INSTALL_DATA) *.8 $(install_prefix)$(mandir)/man8

clean:
	rm -f *.o *~ $(PROGS)

distclean: clean
	rm -f Makefile config.h \
	      config.cache config.log config.status confdefs.h

# EOF
