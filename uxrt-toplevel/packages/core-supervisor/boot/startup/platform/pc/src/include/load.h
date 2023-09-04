#ifndef __PLATFORM_PC_LOAD_H
#define __PC_LOAD_H

#define LOADER_TYPE_MULTIBOOT1 0

extern int loaded_into_ram;

int init_mbi(struct multiboot_exec_params *params);

#endif /*__PLATFORM_PC_LOAD_H*/
