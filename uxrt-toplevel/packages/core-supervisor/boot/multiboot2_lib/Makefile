# Makefile for the Multiboot2 library.

CFLAGS := -I./include $(CFLAGS)

ifeq ($(BUILDPREFIX),)
	BUILDPREFIX := .
endif 

LIB := $(BUILDPREFIX)/libmultiboot.a
TARGETS := $(BUILDPREFIX)/xrfs.o $(BUILDPREFIX)/multiboot.o

all: $(LIB)

$(LIB): $(TARGETS)
	ar rcs $@ $^

$(BUILDPREFIX)/%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@ 

clean:
	rm -f $(LIB) $(TARGETS)
