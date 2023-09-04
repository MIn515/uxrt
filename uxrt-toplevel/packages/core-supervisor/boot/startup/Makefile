# Note: this design uses target-specific flags, because it's the only
# way to get the value of a variable that's different for each
# subdirectory, $(d), into the build recipes. Once you go that way,
# you can as well use the feature to specify (extra) objects and 
# libraries to be linked or archived.

include config.mk

ifeq ($(PLATFORM),)
	PLATFORM := $(DEFAULTPLATFORM)
endif
ifeq ($(CPU),)
	CPU := $(DEFAULTCPU)
endif
ifeq ($(COMPILER),)
	COMPILER := $(DEFAULTCOMPILER)
endif

SCRIPTS = scripts
EXTERNAL_PKG_ROOT = $(abspath ..)
MULTIBOOT_LIB_DIR := $(EXTERNAL_PKG_ROOT)/multiboot2_lib

PLATFORM_ROOT = platform/$(PLATFORM)
CPU_ROOT = cpu/$(CPU)

SRC = src
PLATFORM_SRC = $(PLATFORM_ROOT)/src
CPU_SRC = $(CPU_ROOT)/src

OBJ = obj/$(PLATFORM)-$(CPU)
PLATFORM_OBJ = $(OBJ)/platform
CPU_OBJ = $(OBJ)/cpu

MK = mk
PLATFORM_MK = $(PLATFORM_ROOT)/mk
CPU_MK = $(CPU_ROOT)/mk

# Standard stuff

VERSION	:= 0.0

.SUFFIXES:
.SUFFIXES:	.S .c .o

all:	objdirs targets
tests:	objdirs test_targets

# General directory independent rules 
# Separate rules for code common to multiple subprojects are provided, because
# it may be built differently for different subprojects

include $(PLATFORM_MK)/$(CPU)-$(COMPILER).mk
include $(CPU_MK)/$(COMPILER).mk

CPU_INCLUDES := $(CPU_INCLUDES) $(CPU_SRC)/include
PLATFORM_INCLUDES := $(PLATFORM_INCLUDES) $(PLATFORM_SRC)/include

INCLUDES := $(INCLUDES) $(MULTIBOOT_LIB_DIR)/include $(SRC)/include/compiler/$(COMPILER) $(SRC)/include $(CPU_INCLUDES) $(PLATFORM_INCLUDES)

MKOBJDIR = [ ! -d $(@D) ] && mkdir -p $(@D) 

$(OBJ)/%.o: $(SRC)/%.c
	$(MKOBJDIR); $(COMP)
$(PLATFORM_OBJ)/%.o:	$(PLATFORM_SRC)/%.c
	$(MKOBJDIR); $(COMP)
$(CPU_OBJ)/%.o: $(CPU_SRC)/%.c
	$(MKOBJDIR); $(COMP)

%:	%.o
	$(LINK)

%:	%.c
	$(COMPLINK)

.PHONY:	targets

.PHONY: test_targets

# These targets merely contain commands to be executed, i.e. they collect
# only .PHONY targets, even if they're not explicitly marked as such. 

.PHONY:	clean
clean:
	rm -f $(CLEAN)
.PHONY:	test_clean
test_clean:
	rm -f $(TEST_CLEAN)

.PHONY: objdirs
objdirs:
	mkdir -p $(sort $(OBJDIRS))


# Prevent make from removing any build targets, including intermediate ones

.SECONDARY:	$(CLEAN)

d := .


# Dependencies outside of this subproject. cpu should come before platform.
# Directory-specific rules are optional here.

MULTIBOOT_OBJ_DIR = $(OBJ)/multiboot

MULTIBOOT_LIB := $(MULTIBOOT_OBJ_DIR)/libmultiboot.a

OBJDIRS := $(OBJDIRS) $(MULTIBOOT_OBJ_DIR)

dir	:= $(SRC)
include	$(dir)/Rules.mk
dir	:= $(CPU_SRC)
include	$(dir)/Rules.mk
dir	:= $(PLATFORM_SRC)
include	$(dir)/Rules.mk

$(MULTIBOOT_OBJ_DIR)/libmultiboot.a:
	cd $(MULTIBOOT_LIB_DIR) && BUILDPREFIX="$(abspath $(MULTIBOOT_OBJ_DIR))" CFLAGS="$(CF_ALL) $(CF_MULTIBOOT)" $(MAKE)

CLEAN := $(CLEAN) $(MULTIBOOT_OBJ_DIR)/libmultiboot.a

targets: $(TARGETS) 

test_targets: $(TEST_TARGETS)
