VERSION := 0.0

all: iso
	
#temporary targets to build an ISO and a boot image
#TODO: these should be removed once a proper installer has been implemented

.PHONY: all iso build_packages dirs simulate clean

BUILD_DIR := build
TOOLS_DIR := $(BUILD_DIR)/tools
ISO_BUILD_DIR := $(BUILD_DIR)/iso
BOOTIMG_BUILD_DIR := $(BUILD_DIR)/bootimg
ISO := $(BUILD_DIR)/uxrt-test.iso
BOOTIMG := $(ISO_BUILD_DIR)/uxrt.boot
GENCXRFS := $(TOOLS_DIR)/gencxrfs

BOOTIMG_PACKAGES := xrfs/genxrfs xrfs/updatembh core-supervisor/fel4/selfe-sys core-supervisor
ISO_PACKAGES := test-iso-toplevel

dirs:
	mkdir -p $(ISO_BUILD_DIR) $(BOOTIMG_BUILD_DIR) $(TOOLS_DIR)

iso: $(ISO)

install_bootimg_packages: dirs
	export PATH="$$PWD/$(TOOLS_DIR):$$PATH"; \
	export INSTALL_ROOT=$$PWD/$(BOOTIMG_BUILD_DIR); \
	export TOOLS_INSTALL_ROOT=$$PWD/$(TOOLS_DIR); \
	for dir in $(BOOTIMG_PACKAGES); do \
		(cd packages/$$dir && $(MAKE) && $(MAKE) install-local) \
	done

install_iso_packages: dirs
	export PATH="$$PWD/$(TOOLS_DIR):$$PATH"; \
	export INSTALL_ROOT=$$PWD/$(ISO_BUILD_DIR); \
	export TOOLS_INSTALL_ROOT=$$PWD/$(TOOLS_DIR); \
	for dir in $(ISO_PACKAGES); do \
		(cd packages/$$dir && $(MAKE) && $(MAKE) install-local) \
	done

$(ISO): dirs install_iso_packages $(BOOTIMG)
	genisoimage -o $@ -b limine-cd.bin -c boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -l build/iso

$(BOOTIMG): dirs install_bootimg_packages
	export PATH="$$PWD/$(TOOLS_DIR):$$PATH"; \
	$(GENCXRFS) -v -o "UX/RT" -r "$(VERSION) (Git revision: `git log --pretty=format:'%h' -n 1`)"  $(BOOTIMG) $(BOOTIMG_BUILD_DIR)

.PHONY: simulate clean clean-all
#TODO: set the options based on the actual configuration
simulate:
	qemu-system-x86_64 -m 512 -enable-kvm -cdrom $(ISO) -serial mon:stdio -smp 2
simulate-cpuemu:
	qemu-system-x86_64 -cpu Nehalem,-vme,+pdpe1gb,-xsave,-xsaveopt,-xsavec,-fsgsbase,-invpcid,enforce -m 512 -cdrom $(ISO) -serial mon:stdio
simulate-gdb-cpuemu:
	qemu-system-x86_64 -cpu Nehalem,-vme,+pdpe1gb,-xsave,-xsaveopt,-xsavec,-fsgsbase,-invpcid,enforce -m 512 -cdrom $(ISO) -serial mon:stdio -s -S
simulate-gdb:
	qemu-system-x86_64 -enable-kvm -m 512 -cdrom $(ISO) -serial mon:stdio -s -S

clean:
	rm -rf $(BUILD_DIR)
clean-all: clean
	for dir in $(ISO_PACKAGES) $(BOOTIMG_PACKAGES); do \
		(cd packages/$$dir && $(MAKE) clean) \
	done

