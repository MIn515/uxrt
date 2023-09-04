# Standard things

sp              := $(sp).x
dirstack_$(sp)  := $(d)
d               := $(dir)

dir := $(d)/tests
include $(dir)/Rules.mk

# Local variables

OBJS_$(d)    := $(PLATFORM_OBJ)/main.o \
             $(PLATFORM_OBJ)/load.o
ALL_OBJS_$(d)    := $(OBJS_$(d)) $(STAGE0_OBJS_$(d))
DEPS_$(d)    := $(ALL_OBJS_$(d):%=%.d)

# Global variables
CLEAN        := $(CLEAN) $(OBJS_$(d)) $(DEPS_$(d)) $(PLATFORM_OBJ)/mb2_img_loader
OBJDIRS      := $(OBJDIRS) $(PLATFORM_OBJ) $(PLATFORM_OBJ)/stage0

# Local rules

$(PLATFORM_OBJ)/stage0/head.o: $(d)/stage0/head.S
	$(ASSEMBLE)

$(PLATFORM_OBJ)/startup0: $(PLATFORM_OBJ)/stage0/head.o $(STAGE0_LIBS) $(CPU_STAGE0_OBJS) 
	$(BARE_LINK) -Wl,-T,$(PLATFORM_SRC)/stage0/startup0.ldscript

$(PLATFORM_OBJ)/startup1: $(CPU_OBJS) $(OBJS_$(d)) $(STAGE1_LIBS)
	$(LINK)

TARGETS	:= $(TARGETS) $(PLATFORM_OBJ)/startup0 $(PLATFORM_OBJ)/startup1
# Standard things

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))

