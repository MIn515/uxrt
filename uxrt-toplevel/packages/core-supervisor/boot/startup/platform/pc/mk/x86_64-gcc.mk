include $(RTXH_MK)/$(COMPILER).mk
include $(RTXH_PLATFORM_MK)/common.mk

#Only the base hypervisor is 64-bit on x86_64 PCs (the same loader is used for
#both 32- and 64-bit builds of the hypervisor, and BOS wouldn't really benefit
#from being 64-bit).
LOADER_CPU       = x86_32
BOS_CPU          = x86_32

