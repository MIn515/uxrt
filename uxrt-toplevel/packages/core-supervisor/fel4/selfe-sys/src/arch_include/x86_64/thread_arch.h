/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <autoconf.h>
#include "util.h"

#ifdef CONFIG_FSGSBASE_INST
static inline selfe_uintptr_t selfe_read_fs_base(void)
{
    selfe_uintptr_t reg;
    __asm__ __volatile__("rdfsbase %0" : "=r"(reg));
    return reg;
}

static inline void selfe_write_fs_base(selfe_uintptr_t reg)
{
    __asm__ __volatile__("wrfsbase %0" :: "r"(reg));
}

static inline selfe_uintptr_t selfe_read_gs_base(void)
{
    selfe_uintptr_t reg;
    __asm__ __volatile__("rdgsbase %0" : "=r"(reg));
    return reg;
}

static inline void selfe_write_gs_base(selfe_uintptr_t reg)
{
    __asm__ __volatile__("wrgsbase %0" :: "r"(reg));
}

/*
 * Obtain the value of the TLS base for the current thread.
 */
static inline selfe_uintptr_t selfe_get_tls_base(void)
{
    return selfe_read_fs_base();
}

/*
 * Set the value of the TLS base for the current thread.
 */
static inline void selfe_set_tls_base(selfe_uintptr_t tls_base)
{
    selfe_write_fs_base(tls_base);
}

#else

/*
 * Obtain the value of the TLS base for the current thread.
 */
static inline selfe_uintptr_t selfe_get_tls_base(void)
{
    selfe_uintptr_t tp;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tp));
    return tp;
}

#ifdef CONFIG_SET_TLS_BASE_SELF
#include <interfaces/sel4_client.h>

/*
 * Set the value of the TLS base for the current thread.
 */
static inline void selfe_set_tls_base(selfe_uintptr_t tls_base)
{
    seL4_SetTLSBase(tls_base);
}
#else
#error "Set TLS for x86_64 w/o FSGSBASE_INST not implemented"
#endif /* CONFIG_SET_TLS_BASE_SELF */

#endif

