#define STAGE0_ELF32 1
extern void stage0_putchar(char c);
extern void hang(void);
extern void start_stage1(void);
extern unsigned long _img_start;
extern unsigned long _img_end;
extern unsigned long _end;
unsigned long loader_eax;
unsigned long loader_ebx;
unsigned long entry;
static inline struct multiboot_info *get_multiboot_info()
{
	if (loader_eax == MULTIBOOT2_BOOTLOADER_MAGIC){
		return ((struct multiboot_info *)loader_ebx);
	}else{
		return ((struct multiboot_info *)0);
	}
}
static void mbi_moved(unsigned long addr)
{
	loader_ebx = addr;
}
