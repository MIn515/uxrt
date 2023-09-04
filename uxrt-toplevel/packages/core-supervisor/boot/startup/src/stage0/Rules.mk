# Standard things
sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

# Local variables

OBJS_$(d)   := $(OBJ)/stage0/main.o

DEPS_$(d)   := $(OBJS_$(d):%=%.d)

CLEAN       := $(CLEAN) $(OBJS_$(d)) $(DEPS_$(d)) $(OBJ)/stage0.a
OBJDIRS     := $(OBJDIRS) $(OBJ)

# Local rules

$(OBJ)/stage0.a:	$(OBJS_$(d))
	$(ARCH)

STAGE0_LIBS := $(STAGE0_LIBS) $(OBJ)/stage0.a

# Standard things

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
