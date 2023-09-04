LOADER_DIR := startup
STARTUP0 := $(LOADER_DIR)/obj/pc-x86_32/platform/startup0
STARTUP1 := $(LOADER_DIR)/obj/pc-x86_32/platform/startup1
LIBPAYLOAD_DIR := libpayload

all: $(STARTUP0) $(STARTUP1)

$(LIBPAYLOAD_DIR)/.config:
	(cd $(LIBPAYLOAD_DIR) && $(MAKE) defconfig)

libpayload: $(LIBPAYLOAD_DIR)/.config
	(cd $(LIBPAYLOAD_DIR) && $(MAKE))

$(STARTUP0): libpayload
	(cd $(LOADER_DIR) && $(MAKE))
$(STARTUP1): $(STARTUP0)
	(cd $(LOADER_DIR) && $(MAKE))

install-local: $(STARTUP0) $(STARTUP1)
	install -m 644 $(STARTUP0) "$(INSTALL_ROOT)/@startup0,`xrfsaddr $(STARTUP0)`,m"
	strip "$(INSTALL_ROOT)/@startup0,`xrfsaddr $(STARTUP0)`,m"
	install -m 644 $(STARTUP1) "$(INSTALL_ROOT)/@startup1,auto,1,auto,m"
	strip "$(INSTALL_ROOT)/@startup1,auto,1,auto,m"

clean:
	rm -rf $(LOADER_DIR)/obj
	(cd $(LIBPAYLOAD_DIR) && $(MAKE) clean)
	rm -rf $(LIBPAYLOAD_DIR)/build

