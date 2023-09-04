#ifndef __COMMON_CPU_CPUID_H
#define __COMMON_CPU_CPUID_H

#define CPUID_NUM_REGS 4

#define CPUID_REG_EAX 0
#define CPUID_REG_EBX 1
#define CPUID_REG_ECX 2
#define CPUID_REG_EDX 3

#define CPUID_LEVEL_VENDOR_ID 0
#define CPUID_LEVEL_PROCESSOR_INFO 1
#define CPUID_LEVEL_CACHE_AND_TLB_INFO 2
#define CPUID_LEVEL_SERIAL_NUMBER 3
#define CPUID_LEVEL_HIGHEST_EXT_LEVEL 0x80000000
#define CPUID_LEVEL_AMD_EXT_PROCESSOR_INFO 0x80000001
#define CPUID_LEVEL_BRAND_STRING_1 0x80000002
#define CPUID_LEVEL_BRAND_STRING_2 0x80000003
#define CPUID_LEVEL_BRAND_STRING_3 0x80000004
#define CPUID_LEVEL_L1_CACHE_AND_TLB_IDS 0x80000005
#define CPUID_LEVEL_EXT_L2_CACHE_FEATURES 0x80000006
#define CPUID_LEVEL_POWER_MANAGEMENT 0x80000007
#define CPUID_LEVEL_ADDRESS_SIZES 0x80000008
#define CPUID_LEVEL_TMEXTINFO 0x80860001
#define CPUID_LEVEL_AMDEXTINFO 0xC0000001

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
#define cpuid(_op,_eax,_ebx,_ecx,_edx)          \
    asm ( "cpuid"                               \
          : "=a" (*(int *)(_eax)),              \
            "=b" (*(int *)(_ebx)),              \
            "=c" (*(int *)(_ecx)),              \
            "=d" (*(int *)(_edx))               \
          : "0" (_op), "2" (0) )

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(
    int op,
    int count,
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx)
{
    asm ( "cpuid"
          : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
          : "0" (op), "c" (count) );
}

/*
 * CPUID functions returning a single datum
 */
static always_inline unsigned int cpuid_eax(unsigned int op)
{
    unsigned int eax;

    asm ( "cpuid"
          : "=a" (eax)
          : "0" (op)
          : "bx", "cx", "dx" );
    return eax;
}

static always_inline unsigned int cpuid_ebx(unsigned int op)
{
    unsigned int eax, ebx;

    asm ( "cpuid"
          : "=a" (eax), "=b" (ebx)
          : "0" (op)
          : "cx", "dx" );
    return ebx;
}

static always_inline unsigned int cpuid_ecx(unsigned int op)
{
    unsigned int eax, ecx;

    asm ( "cpuid"
          : "=a" (eax), "=c" (ecx)
          : "0" (op)
          : "bx", "dx" );
    return ecx;
}

static always_inline unsigned int cpuid_edx(unsigned int op)
{
    unsigned int eax, edx;

    asm ( "cpuid"
          : "=a" (eax), "=d" (edx)
          : "0" (op)
          : "bx", "cx" );
    return edx;
}

int cpuid_check_features(uint32_t level, uint32_t reg, uint32_t feature_flags);

#endif /* __COMMON_CPU_CPUID_H */
