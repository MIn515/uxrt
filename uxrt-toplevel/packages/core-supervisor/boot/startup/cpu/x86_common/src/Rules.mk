# Standard things

sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

# Local variables

OBJDIRS := $(OBJDIRS) $(X86_OBJ)

OBJS_$(d)	:= $(X86_OBJ)/cpuid.o
#OBJS_$(d)	:= $(CPU_COMMON_LIB_OBJ)/cpuid/cpuid.o $(CPU_COMMON_LIB_OBJ)/cpuid/cpuid_asm.o
DEPS_$(d)	:= $(OBJS_$(d):%=%.d)

# Global variables

CPU_OBJS	:= $(CPU_OBJS) $(OBJS_$(d))
CLEAN		:= $(CLEAN) $(OBJS_$(d)) $(DEPS_$(d))

# Local rules

#$(CPU_COMMON_LIB_OBJ)/cpuid/cpuid_asm.o: $(d)/cpuid_asm.S
#	cd $(CPU_COMMON_LIB_OBJ) && $(ASSEMBLE)

# Standard things

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))

