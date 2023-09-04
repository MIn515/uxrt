TARGETS := genxrfs-build xrfslib-build updatembh-build
ifeq ($(shell uname -s), UXRT)
	TARGETS += mount_xrfs-build
endif


.PHONY: genxrfs-build mount_xrfs-build xrfslib-build updatembh-build
all: $(TARGETS)

genxrfs-build:
	cd genxrfs && $(MAKE)
updatembh-build:
	cd updatembh && $(MAKE)
xrfslib-build:
	cd xrfslib && $(MAKE)
mount_xrfs-build:
	cd mount_xrfs_uxrt && $(MAKE)


