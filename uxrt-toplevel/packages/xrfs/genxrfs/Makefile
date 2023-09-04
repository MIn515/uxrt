
# Makefile for the genxrfs program.

all: genxrfs

CARGO = cargo
PACKAGE = genxrfs
VERSION = 1.0

ifeq ($(PREFIX),)
	PREFIX = /usr/local
endif
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

build:
	$(CARGO) build --offline --release

genxrfs: build
	install -m 755 target/release/genxrfs $(PWD)

clean:
	rm -f genxrfs *.o

install: all install-bin install-man

install-bin:
	mkdir -p $(INSTALLPREFIX)$(BINDIR)
	install -m 755 genxrfs $(INSTALLPREFIX)$(BINDIR)/
	install -m 755 gencxrfs $(INSTALLPREFIX)$(BINDIR)/
	install -m 755 xrfsaddr $(INSTALLPREFIX)$(BINDIR)/

install-man:
	mkdir -p $(INSTALLPREFIX)$(MANDIR)/man8
	install -m 644 genxrfs.8 $(INSTALLPREFIX)$(MANDIR)/man8/

install-bin-local:
	install -m 755 genxrfs $(TOOLS_INSTALL_ROOT)/
	install -m 755 gencxrfs $(TOOLS_INSTALL_ROOT)/
	install -m 755 xrfsaddr $(TOOLS_INSTALL_ROOT)/

install-local: install-bin-local
