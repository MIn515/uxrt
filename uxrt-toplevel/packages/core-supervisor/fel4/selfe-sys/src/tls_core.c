/*
 * TLS support for static binaries
 *
 * Copyright 2022 Andrew Warkentin
 *
 * Based on code from sel4runtime:
 *
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/types.h>
#include <sel4/bootinfo.h>
#include <autoconf.h>
#include <sel4/sel4.h>
#include <selfe/gen_config.h>

#include "selfe_types.h"
#include "util.h"
#include "thread_arch.h"

// Minimum alignment across all platforms.
#define MIN_ALIGN_BYTES 16
#define MIN_ALIGNED __attribute__((aligned (MIN_ALIGN_BYTES)))

extern char _tdata_start[];
extern char _tdata_end[];
extern char _tbss_end[];

// Static TLS for initial thread.
static char static_tls[CONFIG_SELFE_STATIC_TLS] MIN_ALIGNED = {};

// Thread lookup pointers.
typedef struct {
    selfe_uintptr_t tls_base;
} thread_lookup_t;

// The seL4 runtime environment.
static struct {
    /*
     * The initial thread object is initially set to a static thread
     * object. It is only used until a TLS is set up for the first
     * thread.
     *
     * Once the TLS has been initialised for the first thread, this is
     * then set to NULL and the thread local reference should be used.
     */
    selfe_uintptr_t initial_thread_tls_base;
    seL4_CPtr initial_thread_tcb;
    seL4_IPCBuffer *initial_thread_ipc_buffer;

    // TLS images
    struct {
        // The location of the initial image in memory.
        void *image;
        // The size of the initial image in memory.
        selfe_size_t image_size;
        // The size needed to store the full TLS.
        selfe_size_t memory_size;
        // The size needed to store the TLS and the thread structure.
        selfe_size_t region_size;
        // Alignment needed for the TLS data.
        selfe_size_t align;
        // Offset of the TLS data from the thread pointer.
        selfe_size_t offset;
    } tls;
} env = {
    /*
     * Initialise the initial thread as referring to the global thread
     * object.
     */

    .initial_thread_tls_base = (selfe_uintptr_t)SELFE_NULL,
};

static void load_tls_data_root(void);
static void try_init_static_tls(void);
static void copy_tls_data(unsigned char *tls);
static selfe_uintptr_t tls_base_from_tls_region(unsigned char *tls_region);
static unsigned char *tls_from_tls_base(selfe_uintptr_t tls_base);
static unsigned char *tls_from_tls_region(unsigned char *tls_region);
static thread_lookup_t *thread_lookup_from_tls_region(unsigned char *tls_region);
static selfe_size_t tls_region_size(selfe_size_t mem_size, selfe_size_t align);
static void empty_tls(void);

selfe_size_t selfe_get_tls_size(void)
{
    return env.tls.region_size;
}

int selfe_initial_tls_enabled(void)
{
    /*
     * If the TLS for the initial process has been activated, the thread
     * object in the TLS will be used rather than the static thread
     * object.
     */
    return env.initial_thread_tls_base != (selfe_uintptr_t)SELFE_NULL;
}

selfe_uintptr_t selfe_write_tls_image(void *tls_memory)
{
    if (tls_memory == SELFE_NULL) {
        return (selfe_uintptr_t)SELFE_NULL;
    }

    copy_tls_data(tls_memory);

    return tls_base_from_tls_region(tls_memory);
}

int selfe_write_tls_variable(
    selfe_uintptr_t dest_tls_base,
    unsigned char *local_tls_dest,
    unsigned char *src,
    selfe_size_t bytes
);

#define selfe_set_tls_variable(thread_pointer, variable, value) ({\
    _Static_assert(\
        sizeof(variable) == sizeof(value), \
        "Set value of same size" \
    ); \
    typeof (variable) typed_value = value; \
    selfe_write_tls_variable( \
        thread_pointer, \
        (unsigned char *)&(variable), \
        (unsigned char *)&(typed_value), \
        sizeof(typed_value) \
    ); \
})

selfe_uintptr_t selfe_write_tls_image_with_ipcbuf(void *tls_memory, seL4_IPCBuffer *ipcbuf)
{
    selfe_uintptr_t tp = (selfe_uintptr_t)selfe_write_tls_image((void *)tls_memory);
    selfe_set_tls_variable(tp, __sel4_ipc_buffer, ipcbuf);
    return tp;
}

selfe_uintptr_t selfe_move_initial_tls(void *tls_memory)
{
    if (tls_memory == SELFE_NULL) {
        return (selfe_uintptr_t)SELFE_NULL;
    }

    selfe_uintptr_t tls_base = selfe_write_tls_image(tls_memory);
    if (tls_base == (selfe_uintptr_t)SELFE_NULL) {
        return (selfe_uintptr_t)SELFE_NULL;
    }

    selfe_set_tls_base(tls_base);

    if (env.initial_thread_ipc_buffer != SELFE_NULL) {
        seL4_SetIPCBuffer(env.initial_thread_ipc_buffer);
    }

    env.initial_thread_tls_base = tls_base;

    return env.initial_thread_tls_base;
}

int selfe_write_tls_variable(
    selfe_uintptr_t dest_tls_base,
    unsigned char *local_tls_dest,
    unsigned char *src,
    selfe_size_t bytes
)
{
    selfe_uintptr_t local_tls_base = selfe_get_tls_base();
    unsigned char *local_tls = tls_from_tls_base(local_tls_base);
    selfe_size_t offset = local_tls_dest - local_tls;
    selfe_size_t tls_size = env.tls.memory_size;

    // Write must not go past end of TLS.
    if (offset > tls_size || offset + bytes > tls_size) {
        return -1;
    }

    unsigned char *dest_tls = tls_from_tls_base(dest_tls_base);
    unsigned char *dest_addr = dest_tls + offset;

    memcpy(dest_addr, src, bytes);

    return 0;
}

#if 0
static void parse_phdrs()
{
    for (selfe_size_t h = 0; h < env.program_header.count; h++) {
        Elf_Phdr *header = program_header.headers[h];
        switch (header->p_type) {
        case PT_TLS:
            load_tls_data(header);
            break;  
        default:    
            break;  
        }
    }
}

static void load_tls_data_from_phdr(Elf_Phdr *header)
{
    env.tls.image = (void *) header->p_vaddr;
    if (header->p_align > MIN_ALIGN_BYTES) {
        env.tls.align = header->p_align;
    } else {
        env.tls.align = MIN_ALIGN_BYTES;
    }
    env.tls.image_size = header->p_filesz;
    env.tls.memory_size = ROUND_UP(header->p_memsz, header->p_align);
    env.tls.region_size = tls_region_size(
                              env.tls.memory_size,
                              env.tls.align
                          );
}
#endif

void selfe_tls_init_root(seL4_BootInfo *boot_info)
{
    env.initial_thread_ipc_buffer = boot_info->ipcBuffer; 
    empty_tls();
    load_tls_data_root();
    try_init_static_tls();
}

static void load_tls_data_root()
{
    env.tls.image = (void *) _tdata_start;
    env.tls.align = sizeof (seL4_Word);
    env.tls.image_size = _tdata_end - _tdata_start;
    selfe_size_t memsz = _tbss_end - _tdata_start;
    env.tls.memory_size = ROUND_UP(memsz, env.tls.align);
    env.tls.region_size = tls_region_size(
                              env.tls.memory_size,
                              env.tls.align
                          );
}


static void try_init_static_tls(void)
{
    if (env.tls.region_size <= sizeof(static_tls)) {
        selfe_move_initial_tls(static_tls);
    }
}

static void copy_tls_data(unsigned char *tls_region)
{
    unsigned char *tls = tls_from_tls_region(tls_region);
    memcpy(tls, env.tls.image, env.tls.image_size);
    unsigned char *tbss = &tls[env.tls.image_size];
    memset(tbss, 0, env.tls.memory_size - env.tls.image_size);

    thread_lookup_t *lookup = thread_lookup_from_tls_region(tls_region);
    if (lookup != SELFE_NULL) {
        lookup->tls_base = tls_base_from_tls_region(tls_region);
    }
}

static selfe_uintptr_t tls_base_from_tls_region(unsigned char *tls_region)
{
    selfe_uintptr_t tls_base = (selfe_uintptr_t)tls_region;
#if !defined(TLS_ABOVE_TP)
    tls_base += env.tls.memory_size;
#endif
    return ROUND_UP(tls_base, env.tls.align);
}

static unsigned char *tls_from_tls_base(selfe_uintptr_t tls_base)
{
    selfe_uintptr_t tls_addr = tls_base;
#if !defined(TLS_ABOVE_TP)
    tls_addr -= env.tls.memory_size;
#endif
#if defined(GAP_ABOVE_TP)
    tls_addr +=  GAP_ABOVE_TP;
#endif
    return (unsigned char *)tls_addr;
}

static unsigned char *tls_from_tls_region(unsigned char *tls_region)
{
    return tls_from_tls_base(tls_base_from_tls_region(tls_region));
}

static thread_lookup_t *thread_lookup_from_tls_region(
    unsigned char *tls_region
)
{
#if !defined(TLS_ABOVE_TP)
    return (thread_lookup_t *)tls_base_from_tls_region(tls_region);
#else
    return SELFE_NULL;
#endif
}

static selfe_size_t tls_region_size(selfe_size_t mem_size, selfe_size_t align)
{
    return align
           + ROUND_UP(sizeof(thread_lookup_t), align)
#if defined(GAP_ABOVE_TP)
           + ROUND_UP(GAP_ABOVE_TP, align)
#endif
           + ROUND_UP(mem_size, align);
}

static void empty_tls(void)
{
    env.tls.image = SELFE_NULL;
    env.tls.align = MIN_ALIGN_BYTES;
    env.tls.image_size = 0;
    env.tls.memory_size = 0;
    env.tls.region_size = tls_region_size(
                              env.tls.memory_size,
                              env.tls.align
                          );
}
