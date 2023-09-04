X86_ROOT := cpu/x86_common
X86_SRC := $(X86_ROOT)/src
X86_OBJ := $(OBJ)/x86_common

$(X86_OBJ)/%.o: $(X86_SRC)/%.c
	$(COMP)

CPU_INCLUDES := $(CPU_INCLUDES) $(X86_SRC)/include

include $(X86_ROOT)/mk/$(COMPILER).mk
