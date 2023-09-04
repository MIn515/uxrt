ifeq ($(LIBPAYLOAD_BIN_DIR),)
	LIBPAYLOAD_BIN_DIR = $(EXTERNAL_PKG_ROOT)/libpayload
endif

LF_BARE = -m32 -nostdlib
BARE_CC	= gcc
CC	= $(LIBPAYLOAD_BIN_DIR)/bin/lpgcc
AS	= $(LIBPAYLOAD_BIN_DIR)/bin/lpas

#FIXME: make sure that libpayload gets built if it hasn't already been built
