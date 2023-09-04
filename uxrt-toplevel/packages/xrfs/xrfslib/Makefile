# Makefile for the XRFS library.

CFLAGS := -I./include $(CFLAGS)

ifeq ($(BUILDPREFIX),)
	BUILDPREFIX := .
endif 

LIB := $(BUILDPREFIX)/libxrfs.a
TARGETS := $(BUILDPREFIX)/xrfs_core.o

all: $(LIB)

$(LIB): $(TARGETS)
	ar rc $@ $^

$(BUILDPREFIX)/%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@ 

clean:
	rm -f $(LIB) $(TARGETS)
