CC		= gcc
export CC
### Build flags for all targets
#

WERROR      = -Werror

CF_ALL		= $(CF_EXTERNAL_PREPEND) -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pic -g -Wall $(WERROR) -D__STANDALONE_LOADER_INC__ -nostdlib -nostdinc $(foreach i, $(INCLUDES), -I$(abspath $(i))) $(CF_EXTERNAL_APPEND)
LF_ALL		= $(LF_EXTERNAL_PREPEND) $(LF_EXTERNAL_APPEND)

LL_ALL		=


### Build tools
# 
# The C compiler named here must output full (header) dependencies in $(@).d.
# It may be necessary to create a script similar to ccd-gcc for your compiler.
#
INCLUDE_OPTION = -I
INCLUDE_SYSTEM_OPTION = -isystem

#CMPLR		= $(RTXH_ROOT)/scripts/ccd-gcc
CMPLR		= $(CC)
GETARCH		= scripts/getarch-gcc
DEFHDR		= scripts/hdr
ARCH		= ar rc $@ $^
#
COMP		= CC=$(CC) $(CMPLR) $(CF_ALL) $(CF_TGT) -DLOADER_VERSION=$(VERSION) -o $@ -c $< 
#ASSEMBLE	= $(AS) -o $@ $<
ASSEMBLE	= $(COMP) -D__ASSEMBLY__
LINK		= CC=$(CC) $(CMPLR) $(LF_ALL) $(LF_TGT) -o $@ $^ $(LL_TGT) $(LL_ALL)
BARE_LINK		= $(BARE_CC) $(LF_BARE) $(LF_ALL) $(LF_TGT) -no-pie -o $@ $^ $(LL_TGT) $(LL_ALL)
COMPLINK	= CC=$(CC) $(CMPLR) $(CF_ALL) $(CF_TGT) $(LF_ALL) $(LF_TGT) -o $@ $< $(LL_TGT) $(LL_ALL)
