#ifndef __CPU_SUPPORT_H
#define __CPU_SUPPORT_H

#define PAGE_SIZE 4096

#define PAGE_ALIGN(addr)(((unsigned long)addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define PAGE_TABLE_SIZE PAGE_SIZE
#define LARGE_PAGE_SIZE_32 PAGE_SIZE * 1024

#define PAGE_ALIGN_LARGE_32(addr)(((unsigned long)addr + LARGE_PAGE_SIZE_32 - 1) & ~(LARGE_PAGE_SIZE_32 - 1))
#define PAGE_ALIGN_LARGE_64(addr)(((unsigned long)addr + L2_LARGE_PAGE_SIZE_64 - 1) & ~(L2_LARGE_PAGE_SIZE_64 - 1))

#define NUM_PAGE_TABLES_32 1024
/* Mask for the part of the address that selects a legacy x86-32 PDE */
#define PDE_MASK_32 0xffc00000
#define PDE_SHIFT_32 22

#define PTE_SHIFT_32 12
#define PTE_MASK_32 ~PDE_MASK_32

/* Mask that selects the address part of a PTE */
#define ADDR_MASK_32 0xfffff000

#define PDE_INDEX_32(address) ((address & PDE_MASK_32) >> PDE_SHIFT_32)
#define PTE_INDEX_32(address) ((address & PTE_MASK_32) >> PTE_SHIFT_32)

#define PAGE_PRESENT 1
#define PAGE_WRITABLE 2
#define PAGE_LARGE 0x80
#define DEFAULT_PAGE_FLAGS_32 PAGE_WRITABLE | PAGE_PRESENT

#define DEFAULT_PAGE_FLAGS_64 PAGE_WRITABLE | PAGE_PRESENT
#define ADDR_MASK_64 0xfffffffffffff000ULL

#define L3_LARGE_PAGE_SIZE_64 2147483648ULL
#define L2_LARGE_PAGE_SIZE_64 2097152

#define PML4E_MASK_64 0xff8000000000ULL
#define PML4E_SHIFT_64 (PDPTE_SHIFT_64 + 9)

#define PDPTE_MASK_64 0x7fc0000000ULL
#define PDPTE_SHIFT_64 (PDE_SHIFT_64 + 9)

#define PDE_MASK_64 0x3fe00000
#define PDE_SHIFT_64 (PTE_SHIFT_64 + 9)

#define PTE_MASK_64 0x1ff000
#define PTE_SHIFT_64 12

#define PML4E_INDEX_64(address) ((address & PML4E_MASK_64) >> PML4E_SHIFT_64)
#define PDPE_INDEX_64(address) ((address & PDPTE_MASK_64) >> PDPTE_SHIFT_64)
#define PDE_INDEX_64(address) ((address & PDE_MASK_64) >> PDE_SHIFT_64)
#define PTE_INDEX_64(address) ((address & PTE_MASK_64) >> PTE_SHIFT_64)

#define PAGE_4K 0
#define PAGE_2M 1
#define PAGE_1G 2

#endif /*__CPU_SUPPORT_H */
