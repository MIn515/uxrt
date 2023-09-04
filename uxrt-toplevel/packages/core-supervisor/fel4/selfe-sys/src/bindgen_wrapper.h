#include <sel4/arch/syscalls.h>
#include <sel4/invocation.h>
#include <sel4/sel4_arch/invocation.h>
#include <sel4/arch/invocation.h>
#include <interfaces/sel4_client.h>
#include <sel4/bootinfo.h>
#include <sel4/bootinfo_types.h>
#include <sel4/arch/bootinfo_types.h>
#include <sel4/faults.h>
#include <sel4/sel4_arch/constants.h>
#include <sel4/arch/constants.h>
#include <sel4/plat/api/constants.h>
#include <selfe/gen_config.h>

#ifdef seL4_MsgMaxExtraCaps
const unsigned long _seL4_MsgMaxExtraCaps = seL4_MsgMaxExtraCaps;
#undef seL4_MsgMaxExtraCaps
const unsigned long seL4_MsgMaxExtraCaps = _seL4_MsgMaxExtraCaps;
#endif
