include $(CPU_MK)/common.mk

KERNEL_LDSCRIPT32 := $(PLATFORM_SRC)/tests/dummy_kernels/dummykernel32.ld
KERNEL_LDSCRIPT64 := $(PLATFORM_SRC)/tests/dummy_kernels/dummykernel64.ld
MODULE_LDSCRIPT32 := $(PLATFORM_SRC)/tests/dummy_kernels/dummymodule32.ld
MODULE_LDSCRIPT64 := $(PLATFORM_SRC)/tests/dummy_kernels/dummymodule64.ld

TEST_KERNEL_ASSEMBLE32 = gcc -D__ASSEMBLY__ -Wl,-T,$(KERNEL_LDSCRIPT32) -nostdlib -nostdinc -m32 $(CF_ALL) -ffreestanding -static -nostdlib -nostdinc -o $@ $<
TEST_KERNEL_ASSEMBLE64 = gcc -D__ASSEMBLY__ -Wl,-T,$(KERNEL_LDSCRIPT64) -nostdlib -nostdinc -m64 $(CF_ALL) -ffreestanding -static -nostdlib -nostdinc -o $@ $<
TEST_MODULE_ASSEMBLE32 = gcc -D__ASSEMBLY__ -Wl,-T,$(MODULE_LDSCRIPT32) -nostdlib -nostdinc -m32 $(CF_ALL) -ffreestanding -static -nostdlib -nostdinc -o $@ $<
TEST_MODULE_ASSEMBLE64 = gcc -D__ASSEMBLY__ -Wl,-T,$(MODULE_LDSCRIPT64) -nostdlib -nostdinc -m64 $(CF_ALL) -ffreestanding -static -nostdlib -nostdinc -o $@ $<
#COMP64 := $(COMP) -m64
