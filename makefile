#
# The goal is to keep as much per-system stuff autodetected in plan9.h
# as possible.  Still, sometimes you can't help it.  Look for your system.
#

# SGI
#
# To correctly handle 64-bit files and offsets, add -64 to CFLAGS and LDFLAGS
# On Irix 5.X, add -DIRIX5X to hack around their own #include problems (see plan9.h).
#
# SunOS
#
# SunOS 5.5.1 does not provide inttypes.h; add -lsunos to CFLAGS and
# change CC and LD to gcc.  Add -lsocket, -lnsl to LDTAIL.
# If you need <inttypes.h> copy sun-inttypes.h to inttypes.h.
#
CC=g++
# CFLAGS=-O -I.
CFLAGS=-g -I.
LD=g++
LDFLAGS= -g -lstdc++ -lpthread
LDTAIL=
DESTROOT=/usr/local

OFILES=\
	Fid.o \
	IDes.o \
	Logging.o \
	P9Common.o \
	PosixUserOps.o \
	Conv.o \
	Fcall.o \
	Users.o \
	P9Any.o \
	TCPTransport.o \
	Server.o \
	Main.o

HFILES=\
	Fid.h \
	IAuth.h \
	IDes.h \
	IFileSystemUserOps.h \
	ITransport.h \
	Logging.h \
	P9Common.h \
	PosixUserOps.h \
	Server.h \
	TCPTransport.h

u9fs: $(OFILES)
	$(LD) $(LDFLAGS) -o u9fs $(OFILES) $(LDTAIL)

%.o: %.cpp $(HFILES)
	$(CC) $(CFLAGS) -c $*.cpp

clean:
	rm -f *.o u9fs

install: u9fs
	install u9fs $(DESTROOT)/bin

.PHONY: clean install
