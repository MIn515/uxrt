// Copyright (c) 2018-2019 The UX/RT Project Developers
//
// Based on code from Robigalia:
//
// Copyright (c) 2015 The Robigalia Project Developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

#[cfg(target_arch = "x86")]
mod x86_32;
#[cfg(target_arch = "x86")]
pub use self::x86_32::*;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
mod arm;
#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
pub use self::arm::*;

#[cfg(target_arch = "x86")]
pub use sel4_sys::seL4_X86_VMAttributes;
#[cfg(target_arch = "x86_64")]
pub use sel4_sys::seL4_X86_VMAttributes;
#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
pub use sel4_sys::seL4_ARM_VMAttributes;
