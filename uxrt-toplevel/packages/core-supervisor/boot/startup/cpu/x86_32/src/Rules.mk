# Standard things

sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

# Subdirectories
# Directory-specific rules are optional here.

dir := $(X86_SRC)
include $(dir)/Rules.mk

# Local variables

OBJS_$(d)	:= $(CPU_OBJ)/asm_support.o $(CPU_OBJ)/support.o
DEPS_$(d)	:= $(OBJS_$(d):%=%.d)

# Global variables
CPU_OBJS	:= $(CPU_OBJS) $(OBJS_$(d))
CLEAN		:= $(CLEAN) $(OBJS_$(d)) $(DEPS_$(d))
OBJDIRS		:= $(OBJDIRS) $(CPU_OBJ)

# Local rules

$(CPU_OBJ)/asm_support.o: $(d)/asm_support.S $(CPU_OBJ)
	$(ASSEMBLE)

# Standard things

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
