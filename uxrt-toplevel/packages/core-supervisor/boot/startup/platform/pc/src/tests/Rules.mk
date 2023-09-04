# Standard things

sp              := $(sp).x
dirstack_$(sp)  := $(d)
d               := $(dir)

dir := $(d)/dummy_kernels
include $(dir)/Rules.mk

# Standard things

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))

