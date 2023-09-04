# Standard things
sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

# Local variables

OBJS_$(d)   := $(OBJ)/boot.o $(OBJ)/error.o 

DEPS_$(d)   := $(OBJS_$(d):%=%.d)

CLEAN       := $(CLEAN) $(OBJS_$(d)) $(DEPS_$(d)) $(OBJ)/stage1.a
OBJDIRS     := $(OBJDIRS) $(OBJ)

# Local rules

$(OBJ)/stage1.a:	$(OBJS_$(d))
	$(ARCH)

STAGE1_LIBS := $(STAGE1_LIBS) $(OBJ)/stage1.a $(MULTIBOOT_LIB)

dir	:= $(d)/stage0
include	$(dir)/Rules.mk


# Standard things

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
