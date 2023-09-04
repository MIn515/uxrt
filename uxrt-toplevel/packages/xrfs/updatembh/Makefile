
# Makefile for the updatembh program.

all: updatembh

PACKAGE = updatembh
VERSION = 0.0.1
CC = gcc
CFLAGS = -O2 -Wall -DVERSION=\"$(VERSION)\" -g
LDFLAGS = -g

ifeq ($(PREFIX),)
	PREFIX = /usr/local
endif
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

updatembh: updatembh.o
	$(CC) $(LDFLAGS) updatembh.o -o updatembh

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@ 

clean:
	rm -f updatembh *.o

install: all install-bin install-man

install-bin:
	mkdir -p $(INSTALLPREFIX)$(BINDIR)
	install -m 755 updatembh $(INSTALLPREFIX)$(BINDIR)/

install-man:
	mkdir -p $(INSTALLPREFIX)$(MANDIR)/man8
	install -m 644 updatembh.8 $(INSTALLPREFIX)$(MANDIR)/man8/

install-bin-local:
	install -m 755 updatembh $(TOOLS_INSTALL_ROOT)/

install-local: install-bin-local
