CC = g++
CFLAGS = -g -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)
COMMON = checksum.c smartalloc.c

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  dns_server-$(EXEC_SUFFIX)

dns_server-$(EXEC_SUFFIX): dns_server.cpp dns_packet.cpp udp_server.cpp server.cpp $(COMMON)
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ $^

handin: README
	handin bellardo p1 README smartalloc.c smartalloc.h checksum.c checksum.h trace.c Makefile

clean:
	rm -rf dns_server-* dns_server-*.dSYM
